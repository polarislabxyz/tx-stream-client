//! Bounded TLS transport with explicit errors for gaps, resets and EOF.
use polaris_tx_stream_protocol::{CanonicalFrameRef, StreamValidator};
use std::time::Duration;
use tonic::{
    metadata::{Ascii, MetadataValue},
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request,
};

pub mod v1 {
    tonic::include_proto!("polaris.solana.fastpath.v1");
}
pub mod filter;
pub mod reconnect;
pub use filter::ResolvedFilter;
pub use polaris_tx_stream_protocol as protocol;
type WireClient = v1::solana_transaction_fastpath_client::SolanaTransactionFastpathClient<Channel>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid API key metadata")]
    InvalidApiKey,
    #[error("invalid endpoint: HTTPS is required")]
    InvalidEndpoint,
    #[error("invalid transport configuration")]
    InvalidConfig,
    #[error("invalid filter: {0}")]
    InvalidFilter(&'static str),
    #[error("transport connection failed: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("gRPC request failed ({0:?})")]
    Status(tonic::Code),
    #[error("subscription request timed out")]
    SubscribeTimeout,
    #[error("invalid stream: {0}")]
    Stream(#[from] protocol::stream::CanonicalStreamError),
    #[error("stream ended; resubscribe explicitly and reconcile the missing interval")]
    EndOfStream,
}

/// Never exposes a key through Debug or error messages.
#[derive(Clone)]
pub struct ApiKey(MetadataValue<Ascii>);
impl ApiKey {
    pub fn new(value: &str) -> Result<Self, Error> {
        if value.is_empty() {
            return Err(Error::InvalidApiKey);
        }
        let mut metadata = MetadataValue::try_from(value).map_err(|_| Error::InvalidApiKey)?;
        metadata.set_sensitive(true);
        Ok(Self(metadata))
    }
}
impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey([REDACTED])")
    }
}

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub connect_timeout: Duration,
    pub subscribe_timeout: Duration,
    pub http2_keepalive: Duration,
    pub keepalive_timeout: Duration,
    pub tcp_keepalive: Duration,
    pub max_message_bytes: usize,
}
impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            subscribe_timeout: Duration::from_secs(10),
            http2_keepalive: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(10),
            tcp_keepalive: Duration::from_secs(30),
            max_message_bytes: 16 * 1024,
        }
    }
}

#[derive(Clone)]
pub struct FastpathClient {
    wire: WireClient,
    key: ApiKey,
    config: TransportConfig,
}
impl FastpathClient {
    pub async fn connect(
        endpoint: &str,
        key: ApiKey,
        config: TransportConfig,
    ) -> Result<Self, Error> {
        if !endpoint.starts_with("https://") {
            return Err(Error::InvalidEndpoint);
        }
        if config.max_message_bytes < 12_300
            || config.max_message_bytes > 512 * 1024
            || config.connect_timeout.is_zero()
            || config.subscribe_timeout.is_zero()
            || config.http2_keepalive.is_zero()
            || config.keepalive_timeout.is_zero()
            || config.tcp_keepalive.is_zero()
        {
            return Err(Error::InvalidConfig);
        }
        let endpoint = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|_| Error::InvalidEndpoint)?
            .tls_config(ClientTlsConfig::new().with_webpki_roots())?
            .connect_timeout(config.connect_timeout)
            .tcp_nodelay(true)
            .tcp_keepalive(Some(config.tcp_keepalive))
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(config.http2_keepalive)
            .keep_alive_timeout(config.keepalive_timeout);
        Ok(Self::from_channel(endpoint.connect().await?, key, config))
    }
    /// Advanced callers own TLS and connection settings for this channel.
    pub fn from_channel(channel: Channel, key: ApiKey, config: TransportConfig) -> Self {
        Self {
            wire: WireClient::new(channel)
                .max_decoding_message_size(config.max_message_bytes)
                .max_encoding_message_size(512 * 1024),
            key,
            config,
        }
    }
    pub async fn subscribe(&mut self, filter: ResolvedFilter) -> Result<FastpathStream, Error> {
        let mode = filter.mode();
        let mut request = Request::new(filter.into_request());
        request
            .metadata_mut()
            .insert("x-api-key", self.key.0.clone());
        let stream = tokio::time::timeout(
            self.config.subscribe_timeout,
            self.wire.subscribe_resolved_transactions(request),
        )
        .await
        .map_err(|_| Error::SubscribeTimeout)?
        .map_err(|status| Error::Status(status.code()))?
        .into_inner();
        Ok(FastpathStream {
            stream,
            validator: StreamValidator::new(mode),
            failed: false,
        })
    }
}

pub struct ResolvedTransaction {
    bytes: Vec<u8>,
}
impl ResolvedTransaction {
    pub fn frame(&self) -> CanonicalFrameRef<'_> {
        // Only successfully validated, immutable bytes can enter this type.
        CanonicalFrameRef::parse(&self.bytes).expect("validated immutable canonical frame")
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct FastpathStream {
    stream: tonic::Streaming<v1::ResolvedTransactionFrame>,
    validator: StreamValidator,
    failed: bool,
}
impl FastpathStream {
    /// No application queue. Errors terminate this attachment permanently.
    pub async fn next(&mut self) -> Option<Result<ResolvedTransaction, Error>> {
        if self.failed {
            return None;
        }
        let result = match self.stream.message().await {
            Ok(Some(frame)) => match self
                .validator
                .validate_resolved(&frame.canonical_v1)
                .map(|_| ())
            {
                Ok(()) => Ok(ResolvedTransaction {
                    bytes: frame.canonical_v1,
                }),
                Err(error) => Err(error.into()),
            },
            Ok(None) => Err(Error::EndOfStream),
            Err(status) => Err(Error::Status(status.code())),
        };
        self.failed = result.is_err();
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_is_redacted_and_validated() {
        assert!(ApiKey::new("").is_err());
        assert!(ApiKey::new("abc\nsecret").is_err());
        assert_eq!(
            format!("{:?}", ApiKey::new("secret").unwrap()),
            "ApiKey([REDACTED])"
        );
    }
}
