//! Cloudflare 公开网段表与候选抽样。
//!
//! 网段来自 Cloudflare 官方公布的列表（https://www.cloudflare.com/ips-v4 、 /ips-v6），
//! 属于公开信息，可以内置。这里只做归属判断、投毒检查和随机抽样，不含任何自有节点。

use ring::rand::SecureRandom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

/// 把点分 IPv4 拼成 u32（编译期）
const fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

/// 把 IPv6 的前 4 个 16 位段拼成 u128（编译期），后面补零
const fn v6(a: u16, b: u16, c: u16, d: u16) -> u128 {
    ((a as u128) << 112) | ((b as u128) << 96) | ((c as u128) << 80) | ((d as u128) << 64)
}

/// Cloudflare 公布的 IPv4 网段：(网络号, 前缀长)
pub const CF_V4: &[(u32, u8)] = &[
    (v4(173, 245, 48, 0), 20),
    (v4(103, 21, 244, 0), 22),
    (v4(103, 22, 200, 0), 22),
    (v4(103, 31, 4, 0), 22),
    (v4(141, 101, 64, 0), 18),
    (v4(108, 162, 192, 0), 18),
    (v4(190, 93, 240, 0), 20),
    (v4(188, 114, 96, 0), 20),
    (v4(197, 234, 240, 0), 22),
    (v4(198, 41, 128, 0), 17),
    (v4(162, 158, 0, 0), 15),
    (v4(104, 16, 0, 0), 13),
    (v4(104, 24, 0, 0), 14),
    (v4(172, 64, 0, 0), 13),
    (v4(131, 0, 72, 0), 22),
];

/// Cloudflare 公布的 IPv6 网段：(网络号, 前缀长)
pub const CF_V6: &[(u128, u8)] = &[
    (v6(0x2400, 0xcb00, 0, 0), 32),
    (v6(0x2606, 0x4700, 0, 0), 32),
    (v6(0x2803, 0xf800, 0, 0), 32),
    (v6(0x2405, 0xb500, 0, 0), 32),
    (v6(0x2405, 0x8100, 0, 0), 32),
    (v6(0x2a06, 0x98c0, 0, 0), 29),
    (v6(0x2c0f, 0xf248, 0, 0), 32),
];

/// 抽样时跳过的 IPv4 网段：104.16.0.0/15 是 Cloudflare 自家资产段，实测不服务其他 zone，
/// 握手会被拒，白白浪费一次探测额度
pub const SKIP_V4: &[(u32, u8)] = &[(v4(104, 16, 0, 0), 15)];

/// 本机出站地址族支持情况
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FamilySupport {
    pub v4: bool,
    pub v6: bool,
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}

fn v4_in(ip: Ipv4Addr, ranges: &[(u32, u8)]) -> bool {
    let bits = u32::from(ip);
    ranges
        .iter()
        .any(|(net, prefix)| bits & v4_mask(*prefix) == *net)
}

fn v6_in(ip: Ipv6Addr, ranges: &[(u128, u8)]) -> bool {
    let bits = u128::from(ip);
    ranges
        .iter()
        .any(|(net, prefix)| bits & v6_mask(*prefix) == *net)
}

/// 地址是否落在 Cloudflare 公布的网段里
pub fn is_cloudflare(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => v4_in(ip, CF_V4),
        IpAddr::V6(ip) => v6_in(ip, CF_V6),
    }
}

/// 地址是否落在抽样跳过表里（只对 IPv4 有跳过表）
pub fn is_skipped(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => v4_in(ip, SKIP_V4),
        IpAddr::V6(_) => false,
    }
}

/// 投毒检查：答案非空且全部落在 Cloudflare 网段。国内部分解析器会给 Cloudflare 域名
/// 塞 Twitter/Facebook 段的假地址，这里一刀切。
pub fn all_cloudflare(ips: &[IpAddr]) -> bool {
    !ips.is_empty() && ips.iter().all(|ip| is_cloudflare(*ip))
}

/// 取一个 [0, bound) 的随机数（bound > 0）
fn random_below(rng: &dyn SecureRandom, bound: u64) -> u64 {
    let mut buf = [0u8; 8];
    if rng.fill(&mut buf).is_err() {
        return 0;
    }
    u64::from_le_bytes(buf) % bound
}

/// 按网段大小加权随机抽 `n` 个 IPv4：每个 /24 最多一个，主机位取 [1, 254]，
/// 跳过 `SKIP_V4`。抽不满（n 过大或随机数源故障）就返回已有的。
pub fn sample_v4_one_per_24(n: usize, rng: &dyn SecureRandom) -> Vec<IpAddr> {
    // 每个网段含多少个 /24
    let weights: Vec<u64> = CF_V4
        .iter()
        .map(|(_, prefix)| 1u64 << (24u32.saturating_sub(*prefix as u32)))
        .collect();
    let total: u64 = weights.iter().sum();
    let mut seen_24: Vec<u32> = Vec::with_capacity(n);
    let mut out = Vec::with_capacity(n);
    // 拒绝采样有上限，避免 n 过大时死循环
    let mut attempts = 0usize;
    while out.len() < n && attempts < n * 16 {
        attempts += 1;
        let mut pick = random_below(rng, total);
        let mut index = 0usize;
        for (i, weight) in weights.iter().enumerate() {
            if pick < *weight {
                index = i;
                break;
            }
            pick -= *weight;
        }
        let (net, _) = CF_V4[index];
        let subnet = net + ((pick as u32) << 8);
        if seen_24.contains(&subnet) {
            continue;
        }
        let host = 1 + random_below(rng, 254) as u32;
        let ip = Ipv4Addr::from(subnet | host);
        if v4_in(ip, SKIP_V4) {
            continue;
        }
        seen_24.push(subnet);
        out.push(IpAddr::V4(ip));
    }
    out
}

/// 按网段大小加权随机抽 `n` 个 IPv6：每个 /64 最多一个，接口标识随机（非零）
pub fn sample_v6(n: usize, rng: &dyn SecureRandom) -> Vec<IpAddr> {
    // 每个网段含多少个 /64（/29 → 2^35，够用但不要溢出 u64）
    let weights: Vec<u64> = CF_V6
        .iter()
        .map(|(_, prefix)| 1u64 << (64u32.saturating_sub(*prefix as u32)))
        .collect();
    let total: u64 = weights.iter().sum();
    let mut seen_64: Vec<u128> = Vec::with_capacity(n);
    let mut out = Vec::with_capacity(n);
    let mut attempts = 0usize;
    while out.len() < n && attempts < n * 16 {
        attempts += 1;
        let mut pick = random_below(rng, total);
        let mut index = 0usize;
        for (i, weight) in weights.iter().enumerate() {
            if pick < *weight {
                index = i;
                break;
            }
            pick -= *weight;
        }
        let (net, _) = CF_V6[index];
        let subnet = net | ((pick as u128) << 64);
        if seen_64.contains(&subnet) {
            continue;
        }
        let mut iid = [0u8; 8];
        if rng.fill(&mut iid).is_err() {
            break;
        }
        let iid = u64::from_le_bytes(iid).max(1) as u128;
        seen_64.push(subnet);
        out.push(IpAddr::V6(Ipv6Addr::from(subnet | iid)));
    }
    out
}

/// 探测本机是否有 v4 / v6 出站路由：UDP socket 上 connect 只查路由表，不发任何包
pub fn local_family_support() -> FamilySupport {
    let v4 = UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| socket.connect("1.1.1.1:443"))
        .is_ok();
    let v6 = UdpSocket::bind("[::]:0")
        .and_then(|socket| socket.connect("[2606:4700:4700::1111]:443"))
        .is_ok();
    FamilySupport { v4, v6 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn cloudflare_v4_boundaries() {
        assert!(is_cloudflare(ip("104.16.0.0")));
        assert!(is_cloudflare(ip("104.23.255.255")));
        assert!(is_cloudflare(ip("104.24.0.0")));
        assert!(is_cloudflare(ip("104.27.255.255")));
        assert!(!is_cloudflare(ip("104.28.0.0")));
        assert!(is_cloudflare(ip("172.64.0.1")));
        assert!(is_cloudflare(ip("172.71.255.255")));
        assert!(!is_cloudflare(ip("172.72.0.0")));
        assert!(is_cloudflare(ip("162.159.0.1")));
        assert!(is_cloudflare(ip("198.41.128.1")));
        assert!(!is_cloudflare(ip("198.41.127.255")));
        assert!(!is_cloudflare(ip("8.8.8.8")));
        assert!(!is_cloudflare(ip("1.1.1.1")));
    }

    #[test]
    fn cloudflare_v6_boundaries() {
        assert!(is_cloudflare(ip("2606:4700::1")));
        assert!(is_cloudflare(ip("2606:4700:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert!(!is_cloudflare(ip("2606:4701::1")));
        assert!(is_cloudflare(ip("2a06:98c0::1")));
        assert!(is_cloudflare(ip("2a06:98c7:ffff::1")));
        assert!(!is_cloudflare(ip("2a06:98c8::1")));
        assert!(!is_cloudflare(ip("2001:4860:4860::8888")));
    }

    #[test]
    fn skip_table_covers_only_104_16_slash_15() {
        assert!(is_skipped(ip("104.16.1.1")));
        assert!(is_skipped(ip("104.17.255.254")));
        assert!(!is_skipped(ip("104.18.0.1")));
        assert!(!is_skipped(ip("104.21.58.192")));
        assert!(!is_skipped(ip("2606:4700::1")));
    }

    #[test]
    fn poison_check_requires_non_empty_all_cloudflare() {
        assert!(!all_cloudflare(&[]));
        assert!(all_cloudflare(&[ip("104.21.58.192"), ip("2606:4700::1")]));
        assert!(!all_cloudflare(&[ip("104.21.58.192"), ip("31.13.94.36")]));
    }

    #[test]
    fn v4_samples_are_distinct_cloudflare_and_not_skipped() {
        let rng = ring::rand::SystemRandom::new();
        let ips = sample_v4_one_per_24(12, &rng);
        assert_eq!(ips.len(), 12);
        let mut subnets: Vec<u32> = ips
            .iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => u32::from(*v4) & 0xffff_ff00,
                _ => panic!("expected v4"),
            })
            .collect();
        subnets.sort_unstable();
        subnets.dedup();
        assert_eq!(subnets.len(), 12);
        for ip in &ips {
            assert!(is_cloudflare(*ip), "{} not in CF", ip);
            assert!(!is_skipped(*ip), "{} in skip table", ip);
            let IpAddr::V4(v4) = ip else { unreachable!() };
            let host = v4.octets()[3];
            assert!((1..=254).contains(&host));
        }
    }

    #[test]
    fn v6_samples_are_distinct_cloudflare() {
        let rng = ring::rand::SystemRandom::new();
        let ips = sample_v6(4, &rng);
        assert_eq!(ips.len(), 4);
        let mut prefixes: Vec<u128> = ips
            .iter()
            .map(|ip| match ip {
                IpAddr::V6(v6) => u128::from(*v6) >> 64,
                _ => panic!("expected v6"),
            })
            .collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 4);
        assert!(ips.iter().all(|ip| is_cloudflare(*ip)));
    }

    #[test]
    fn family_support_does_not_panic() {
        let _ = local_family_support();
    }
}
