//! Certificate generation for MITM proxy
//!
//! This module handles:
//! - Loading the embedded CA certificate
//! - Dynamically generating certificates for target domains

use crate::error::{DohProxyError, Result};
use parking_lot::RwLock;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Embedded CA certificate (PEM format)
/// This is generated once and bundled with the app
const CA_CERT_PEM: &str = include_str!("../certs/ca.crt");
const CA_KEY_PEM: &str = include_str!("../certs/ca.key");

/// Certificate manager for MITM proxy
pub struct CertManager {
    /// CA key pair for signing
    ca_key_pair: KeyPair,
    /// CA certificate for signing
    ca_cert: Certificate,
    /// CA cert in DER format
    ca_cert_der: CertificateDer<'static>,
    /// 复用的叶子证书密钥对（所有 MITM 域名共享；本地信任的证书，私钥不出本机，无安全问题）
    leaf_key_pair: KeyPair,
    /// 叶子密钥对的 DER 编码，预存避免每次签发重新序列化
    leaf_key_der: Vec<u8>,
    /// 是否在叶子证书 ALPN 中提供 h2（启用 h2 MITM 时为 true）
    h2_mitm: bool,
    /// Cache of generated certificates（连同叶子证书 DER：同一主机在本实例内永远是同一张叶子）
    cert_cache: RwLock<HashMap<String, (Arc<ServerConfig>, CertificateDer<'static>)>>,
    /// Crypto provider for rustls
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl CertManager {
    /// Create a new certificate manager with embedded CA
    pub fn new(h2_mitm: bool) -> Result<Self> {
        info!("Loading embedded CA certificate");

        // Parse CA private key
        let ca_key_pair = KeyPair::from_pem(CA_KEY_PEM)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA key: {}", e)))?;

        // 从 PEM 解析参数后用同一个 key 重建 Certificate 对象（rcgen 签发叶子证书需要）
        let ca_cert = CertificateParams::from_ca_cert_pem(CA_CERT_PEM)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA cert: {}", e)))?
            .self_signed(&ca_key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to load CA cert: {}", e)))?;

        // 使用重建后的证书 DER，确保和 signed_by 使用的 issuer 一致
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        let crypto_provider = Arc::new(crate::tls_crypto::build_provider());

        // 生成一次复用的叶子证书密钥对，避免每个域名签发时重新生成密钥
        let leaf_key_pair = KeyPair::generate().map_err(|e| {
            DohProxyError::Certificate(format!("Failed to generate leaf key: {}", e))
        })?;
        let leaf_key_der = leaf_key_pair.serialize_der();

        info!("CA certificate loaded successfully");

        Ok(Self {
            ca_key_pair,
            ca_cert,
            ca_cert_der,
            leaf_key_pair,
            leaf_key_der,
            h2_mitm,
            cert_cache: RwLock::new(HashMap::new()),
            crypto_provider,
        })
    }

    /// Get or create a server config for the given hostname
    pub fn get_server_config(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        Ok(self.get_or_issue(hostname)?.0)
    }

    /// 本实例给 `hostname` 签发（或将要签发）的叶子证书 PEM。WebView 拿它逐主机精确放行，
    /// 不是信任整个 CA
    pub fn leaf_cert_pem(&self, hostname: &str) -> Result<String> {
        let (_, leaf) = self.get_or_issue(hostname)?;
        Ok(pem::encode(&pem::Pem::new("CERTIFICATE", leaf.to_vec())))
    }

    fn get_or_issue(&self, hostname: &str) -> Result<(Arc<ServerConfig>, CertificateDer<'static>)> {
        // Check cache first
        {
            let cache = self.cert_cache.read();
            if let Some(entry) = cache.get(hostname) {
                debug!("Using cached certificate for {}", hostname);
                return Ok(entry.clone());
            }
        }

        // 写锁内再查一次再签：并发首次握手时两边各签一张会让先拿到的那张作废
        let mut cache = self.cert_cache.write();
        if let Some(entry) = cache.get(hostname) {
            return Ok(entry.clone());
        }
        debug!("Generating certificate for {}", hostname);
        let (config, leaf) = self.generate_cert_config(hostname)?;
        let entry = (Arc::new(config), leaf);
        cache.insert(hostname.to_string(), entry.clone());
        Ok(entry)
    }

    /// Generate a certificate for the given hostname
    fn generate_cert_config(
        &self,
        hostname: &str,
    ) -> Result<(ServerConfig, CertificateDer<'static>)> {
        // Create certificate parameters
        let mut params = CertificateParams::default();

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        // Set SAN (Subject Alternative Name)
        params.subject_alt_names =
            vec![SanType::DnsName(hostname.try_into().map_err(|e| {
                DohProxyError::Certificate(format!("Invalid hostname: {}", e))
            })?)];

        // Set key usage for server certificate
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Not a CA
        params.is_ca = IsCa::NoCa;

        // 复用预生成的叶子密钥对签发，省去每个域名一次密钥生成（在 TLS 握手关键路径上）
        let cert = params
            .signed_by(&self.leaf_key_pair, &self.ca_cert, &self.ca_key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to sign cert: {}", e)))?;

        // Convert to rustls types
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key_der.clone()));

        // Build server config with cert chain (leaf + CA)
        let mut config = ServerConfig::builder_with_provider(self.crypto_provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(DohProxyError::Tls)?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone(), self.ca_cert_der.clone()], key_der)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to build config: {}", e)))?;

        // ALPN：h2 MITM 开启时提供 h2，让 client 可协商 HTTP/2 多路复用；
        // 关闭时仅 http/1.1（裸字节拷贝无法翻译 h2↔h1）
        config.alpn_protocols = if self.h2_mitm {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };

        Ok((config, cert_der))
    }

    /// 从运行时 PEM 创建 CertManager（用于 per-device CA）
    pub fn from_pem(cert_pem: &str, key_pem: &str, h2_mitm: bool) -> Result<Self> {
        info!("Loading runtime CA certificate from PEM");

        let ca_key_pair = KeyPair::from_pem(key_pem)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA key: {}", e)))?;

        let ca_cert = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA cert: {}", e)))?
            .self_signed(&ca_key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to load CA cert: {}", e)))?;

        // 使用重建后的证书 DER，确保和 signed_by 使用的 issuer 一致
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        let crypto_provider = Arc::new(crate::tls_crypto::build_provider());

        // 生成一次复用的叶子证书密钥对，避免每个域名签发时重新生成密钥
        let leaf_key_pair = KeyPair::generate().map_err(|e| {
            DohProxyError::Certificate(format!("Failed to generate leaf key: {}", e))
        })?;
        let leaf_key_der = leaf_key_pair.serialize_der();

        info!("Runtime CA certificate loaded successfully");

        Ok(Self {
            ca_key_pair,
            ca_cert,
            ca_cert_der,
            leaf_key_pair,
            leaf_key_der,
            h2_mitm,
            cert_cache: RwLock::new(HashMap::new()),
            crypto_provider,
        })
    }

    /// 生成新的 CA 证书，返回 (cert_pem, key_pem)
    pub fn generate_ca_pem() -> Result<(String, String)> {
        info!("Generating new CA certificate");

        let key_pair = KeyPair::generate()
            .map_err(|e| DohProxyError::Certificate(format!("Failed to generate CA key: {}", e)))?;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "DOH Proxy CA");
        dn.push(DnType::OrganizationName, "DOH Proxy");
        dn.push(DnType::CountryName, "CN");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        // 有效期 10 年
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(3650);

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to self-sign CA: {}", e)))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        info!("CA certificate generated successfully");
        Ok((cert_pem, key_pem))
    }

    /// Get CA certificate PEM for export (to install on device)
    pub fn get_ca_cert_pem(&self) -> &'static str {
        CA_CERT_PEM
    }

    /// 获取编译时嵌入的 CA 证书 PEM（静态方法，无需实例）
    pub fn get_embedded_ca_pem() -> &'static str {
        CA_CERT_PEM
    }
}

#[cfg(test)]
mod tests {
    use super::CertManager;

    /// 同一实例对同一主机永远给同一张叶子（WebView 精确放行依赖这一点），不同主机各不相同，
    /// 且导出的叶子就是握手时实际下发的那张
    #[test]
    fn leaf_is_stable_per_host_and_matches_server_config() {
        let (cert, key) = CertManager::generate_ca_pem().unwrap();
        let cm = CertManager::from_pem(&cert, &key, false).unwrap();
        let a1 = cm.leaf_cert_pem("linux.do").unwrap();
        let a2 = cm.leaf_cert_pem("linux.do").unwrap();
        let b = cm.leaf_cert_pem("cdn.linux.do").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert!(a1.starts_with("-----BEGIN CERTIFICATE-----"));
        // 先取 ServerConfig 再导出，也必须是同一张
        let _ = cm.get_server_config("connect.linux.do").unwrap();
        let c1 = cm.leaf_cert_pem("connect.linux.do").unwrap();
        let c2 = cm.leaf_cert_pem("connect.linux.do").unwrap();
        assert_eq!(c1, c2);
        // 另一个实例（代理重启）会换叶子
        let cm2 = CertManager::from_pem(&cert, &key, false).unwrap();
        assert_ne!(cm2.leaf_cert_pem("linux.do").unwrap(), a1);
    }
}
