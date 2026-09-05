//! Explicit opt-in reconnect. Every new attachment begins with a reset event.
use crate::{Error, FastpathClient, FastpathStream, ResolvedFilter, ResolvedTransaction};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ReconnectConfig {
    pub initial_delay: Duration,
    pub maximum_delay: Duration,
    pub maximum_attempts: u32,
}
impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            maximum_delay: Duration::from_secs(10),
            maximum_attempts: 5,
        }
    }
}
pub enum FastpathEvent {
    /// A new live attachment; missed intervals are never replayed.
    StreamReset {
        attachment: u64,
    },
    Transaction(ResolvedTransaction),
}
pub struct ReconnectingStream {
    client: FastpathClient,
    filter: ResolvedFilter,
    config: ReconnectConfig,
    stream: Option<FastpathStream>,
    attachment: u64,
    terminal: bool,
}
impl ReconnectingStream {
    pub fn new(
        client: FastpathClient,
        filter: ResolvedFilter,
        config: ReconnectConfig,
    ) -> Result<Self, Error> {
        if config.initial_delay.is_zero()
            || config.maximum_delay < config.initial_delay
            || config.maximum_attempts == 0
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            client,
            filter,
            config,
            stream: None,
            attachment: 0,
            terminal: false,
        })
    }
    /// Dropping this future cancels a pending connection or backoff. Dropping the
    /// wrapper cancels the stream; no detached tasks or hidden queues exist.
    pub async fn next(&mut self) -> Option<Result<FastpathEvent, Error>> {
        if self.terminal {
            return None;
        }
        if let Some(stream) = &mut self.stream {
            match stream.next().await {
                Some(Ok(tx)) => return Some(Ok(FastpathEvent::Transaction(tx))),
                Some(Err(error)) if !retryable(&error) => {
                    self.terminal = true;
                    return Some(Err(error));
                }
                _ => self.stream = None,
            }
        }
        for attempt in 0..self.config.maximum_attempts {
            if self.attachment > 0 || attempt > 0 {
                tokio::time::sleep(delay(&self.config, attempt)).await;
            }
            match self.client.subscribe(self.filter.clone()).await {
                Ok(stream) => {
                    self.stream = Some(stream);
                    self.attachment += 1;
                    return Some(Ok(FastpathEvent::StreamReset {
                        attachment: self.attachment,
                    }));
                }
                Err(error) if !retryable(&error) || attempt + 1 == self.config.maximum_attempts => {
                    self.terminal = true;
                    return Some(Err(error));
                }
                Err(_) => {}
            }
        }
        unreachable!("positive attempt count")
    }
}
fn delay(config: &ReconnectConfig, attempt: u32) -> Duration {
    config
        .initial_delay
        .saturating_mul(2u32.saturating_pow(attempt))
        .min(config.maximum_delay)
}
fn retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::EndOfStream
            | Error::SubscribeTimeout
            | Error::Status(tonic::Code::Unavailable | tonic::Code::DeadlineExceeded)
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_is_bounded_and_permissions_are_terminal() {
        let config = ReconnectConfig::default();
        assert_eq!(delay(&config, 0), Duration::from_millis(250));
        assert_eq!(delay(&config, 100), Duration::from_secs(10));
        assert!(!retryable(&Error::Status(tonic::Code::PermissionDenied)));
        assert!(!retryable(&Error::Status(tonic::Code::Unauthenticated)));
        assert!(retryable(&Error::EndOfStream));
    }
}
