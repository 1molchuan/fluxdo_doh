//! 按 key 合并并发查询：同一 key 同时只有一个领头者真正去查，其余跟随者等它的结果。
//!
//! 结果经 `watch` 通道下发，跟随者无论何时开始等都能拿到（没有「通知早于注册」的竞态）。
//! 领头者的 future 被丢弃（请求取消）时 [`Leader`] 的 Drop 撤销登记，跟随者醒来后重新排队，
//! 其中一个接任领头者——不会白等到超时，也不会留下永远等不到结果的登记。

use crate::stats::STATS;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::watch;

type Outcome<T> = Option<Result<T, String>>;

pub(crate) struct SingleFlight<T> {
    flights: Mutex<HashMap<String, watch::Receiver<Outcome<T>>>>,
    wait_timeout: Duration,
}

pub(crate) enum Joined<'a, T> {
    Leader(Leader<'a, T>),
    Follower(watch::Receiver<Outcome<T>>),
}

/// 领头者凭证：[`Leader::finish`] 下发结果并撤销登记；没 finish 就被丢弃也会撤销登记
pub(crate) struct Leader<'a, T> {
    owner: &'a SingleFlight<T>,
    key: String,
    tx: watch::Sender<Outcome<T>>,
    finished: bool,
}

/// 跟随者等到的结果
pub(crate) enum Waited<T> {
    Done(Result<T, String>),
    /// 领头者被取消，没有结果：重新排队
    Abandoned,
    TimedOut,
}

impl<T: Clone + Send + Sync> SingleFlight<T> {
    pub(crate) fn new(wait_timeout: Duration) -> Self {
        Self {
            flights: Mutex::new(HashMap::new()),
            wait_timeout,
        }
    }

    pub(crate) fn join(&self, key: &str) -> Joined<'_, T> {
        let mut flights = self.flights.lock();
        if let Some(rx) = flights.get(key) {
            return Joined::Follower(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        flights.insert(key.to_string(), rx);
        Joined::Leader(Leader {
            owner: self,
            key: key.to_string(),
            tx,
            finished: false,
        })
    }

    pub(crate) async fn wait(&self, mut rx: watch::Receiver<Outcome<T>>) -> Waited<T> {
        let start = Instant::now();
        let waited = tokio::time::timeout(self.wait_timeout, async {
            match rx.wait_for(Option::is_some).await {
                Ok(outcome) => outcome.clone(),
                Err(_) => None,
            }
        })
        .await;
        STATS.dns_follower_wait.record(start.elapsed());
        match waited {
            Ok(Some(result)) => Waited::Done(result),
            Ok(None) => Waited::Abandoned,
            Err(_) => {
                STATS.dns_inflight_timeout.inc();
                Waited::TimedOut
            }
        }
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.flights.lock().len()
    }
}

impl<T> Leader<'_, T> {
    /// 下发结果（错误只传文字）并撤销登记。先发后撤：撤销前新来的跟随者也能直接拿到结果
    pub(crate) fn finish<E: std::fmt::Display>(mut self, result: &Result<T, E>)
    where
        T: Clone,
    {
        let outcome = match result {
            Ok(value) => Ok(value.clone()),
            Err(error) => Err(error.to_string()),
        };
        let _ = self.tx.send(Some(outcome));
        self.owner.flights.lock().remove(&self.key);
        self.finished = true;
    }
}

impl<T> Drop for Leader<'_, T> {
    fn drop(&mut self) {
        // 没 finish 时登记一定还是自己的：登记在时别人只能当跟随者，插不进新的
        if !self.finished {
            self.owner.flights.lock().remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn followers_get_the_leaders_result() {
        let flight = Arc::new(SingleFlight::<u32>::new(Duration::from_secs(5)));
        let Joined::Leader(leader) = flight.join("a") else {
            panic!("first joiner leads");
        };
        let Joined::Follower(rx) = flight.join("a") else {
            panic!("second joiner follows");
        };
        let follower = {
            let flight = flight.clone();
            tokio::spawn(async move { flight.wait(rx).await })
        };
        leader.finish::<String>(&Ok(7));
        assert!(matches!(follower.await.unwrap(), Waited::Done(Ok(7))));
        assert_eq!(flight.in_flight(), 0);
    }

    #[tokio::test]
    async fn result_sent_before_follower_starts_waiting_is_not_lost() {
        let flight = SingleFlight::<u32>::new(Duration::from_millis(200));
        let Joined::Leader(leader) = flight.join("a") else {
            panic!("first joiner leads");
        };
        let Joined::Follower(rx) = flight.join("a") else {
            panic!("second joiner follows");
        };
        leader.finish(&Err::<u32, _>("boom"));
        assert!(matches!(flight.wait(rx).await, Waited::Done(Err(msg)) if msg == "boom"));
    }

    /// 领头者被取消：登记撤销，跟随者立即醒来而不是等满超时，下一个来的人成为新领头者
    #[tokio::test]
    async fn cancelled_leader_releases_followers_immediately() {
        let flight = Arc::new(SingleFlight::<u32>::new(Duration::from_secs(15)));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let leader_task = {
            let flight = flight.clone();
            tokio::spawn(async move {
                let Joined::Leader(_leader) = flight.join("a") else {
                    panic!("first joiner leads");
                };
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
        };
        started_rx.await.unwrap();
        let Joined::Follower(rx) = flight.join("a") else {
            panic!("second joiner follows");
        };
        leader_task.abort();
        let start = Instant::now();
        assert!(matches!(flight.wait(rx).await, Waited::Abandoned));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(flight.in_flight(), 0);
        assert!(matches!(flight.join("a"), Joined::Leader(_)));
    }
}
