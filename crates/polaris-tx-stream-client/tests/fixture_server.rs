use polaris_tx_stream_client::{
    v1::*, ApiKey, Error, FastpathClient, ResolvedFilter, TransportConfig,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

#[derive(Clone)]
struct Fixture {
    frames: Vec<Vec<u8>>,
    reject: bool,
}
#[tonic::async_trait]
impl solana_transaction_fastpath_server::SolanaTransactionFastpath for Fixture {
    type SubscribeResolvedTransactionsStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<ResolvedTransactionFrame, Status>>>;
    async fn subscribe_resolved_transactions(
        &self,
        request: Request<SubscribeResolvedTransactionsRequest>,
    ) -> Result<Response<Self::SubscribeResolvedTransactionsStream>, Status> {
        assert_eq!(request.metadata().get("x-api-key").unwrap(), "test-secret");
        if self.reject {
            return Err(Status::permission_denied(
                "test-secret must not escape in client error",
            ));
        }
        assert!(
            request.get_ref().filters.is_empty()
                || request.get_ref().filters[0].vote == Some(false)
        );
        Ok(Response::new(tokio_stream::iter(
            self.frames
                .iter()
                .map(|bytes| {
                    Ok(ResolvedTransactionFrame {
                        canonical_v1: bytes.clone(),
                    })
                })
                .collect::<Vec<_>>(),
        )))
    }
}

async fn client(
    frames: Vec<Vec<u8>>,
    reject: bool,
) -> (FastpathClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                solana_transaction_fastpath_server::SolanaTransactionFastpathServer::new(Fixture {
                    frames,
                    reject,
                }),
            )
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (
        FastpathClient::from_channel(
            channel,
            ApiKey::new("test-secret").unwrap(),
            TransportConfig::default(),
        ),
        server,
    )
}
fn frame() -> Vec<u8> {
    include_bytes!("../../../fixtures/canonical-v1-legacy.bin").to_vec()
}

#[tokio::test]
async fn valid_transaction_then_eof_is_visible_and_terminal() {
    let (mut client, server) = client(vec![frame()], false).await;
    let mut stream = client.subscribe(ResolvedFilter::match_all()).await.unwrap();
    let tx = stream.next().await.unwrap().unwrap();
    assert_eq!(tx.frame().header().slot, 424200);
    assert!(matches!(stream.next().await, Some(Err(Error::EndOfStream))));
    assert!(stream.next().await.is_none());
    server.abort();
}

#[tokio::test]
async fn corrupt_gap_and_epoch_are_terminal() {
    for (offset, value) in [(104, 13u64), (96, 8), (64, 0)] {
        let mut bad = frame();
        bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        let (mut client, server) = client(vec![frame(), bad, frame()], false).await;
        let mut stream = client.subscribe(ResolvedFilter::match_all()).await.unwrap();
        stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.next().await, Some(Err(Error::Stream(_)))));
        assert!(stream.next().await.is_none());
        server.abort();
    }
}

#[tokio::test]
async fn filtered_sequence_gaps_are_expected() {
    let mut later = frame();
    later[104..112].copy_from_slice(&13u64.to_le_bytes());
    let (mut client, server) = client(vec![frame(), later], false).await;
    let mut stream = client
        .subscribe(
            ResolvedFilter::match_all()
                .rule(Some(false), &[], &[], &[])
                .unwrap(),
        )
        .await
        .unwrap();
    stream.next().await.unwrap().unwrap();
    stream.next().await.unwrap().unwrap();
    server.abort();
}

#[tokio::test]
async fn status_propagates_without_server_supplied_secret() {
    let (mut client, server) = client(vec![], true).await;
    let error = client
        .subscribe(ResolvedFilter::match_all())
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error,
        Error::Status(tonic::Code::PermissionDenied)
    ));
    assert!(!error.to_string().contains("test-secret"));
    server.abort();
}

#[tokio::test]
async fn reconnect_always_emits_reset_before_transaction() {
    use polaris_tx_stream_client::reconnect::{FastpathEvent, ReconnectConfig, ReconnectingStream};
    let (client, server) = client(vec![frame()], false).await;
    let config = ReconnectConfig {
        initial_delay: std::time::Duration::from_millis(1),
        ..ReconnectConfig::default()
    };
    let mut stream = ReconnectingStream::new(client, ResolvedFilter::match_all(), config).unwrap();
    assert!(matches!(
        stream.next().await,
        Some(Ok(FastpathEvent::StreamReset { attachment: 1 }))
    ));
    assert!(matches!(
        stream.next().await,
        Some(Ok(FastpathEvent::Transaction(_)))
    ));
    assert!(matches!(
        stream.next().await,
        Some(Ok(FastpathEvent::StreamReset { attachment: 2 }))
    ));
    assert!(matches!(
        stream.next().await,
        Some(Ok(FastpathEvent::Transaction(_)))
    ));
    server.abort();
}

#[tokio::test]
async fn oversized_server_message_is_rejected_before_decoding_frame() {
    let (mut client, server) = client(vec![vec![0; 32 * 1024]], false).await;
    let mut stream = client.subscribe(ResolvedFilter::match_all()).await.unwrap();
    assert!(matches!(stream.next().await, Some(Err(Error::Status(_)))));
    assert!(stream.next().await.is_none());
    server.abort();
}

#[derive(Clone)]
struct ObservationFixture(Vec<TransactionFrame>);
#[tonic::async_trait]
impl transaction_stream_server::TransactionStream for ObservationFixture {
    type SubscribeTransactionsStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<TransactionFrame, Status>>>;
    async fn subscribe_transactions(
        &self,
        request: Request<SubscribeResolvedTransactionsRequest>,
    ) -> Result<Response<Self::SubscribeTransactionsStream>, Status> {
        assert_eq!(request.metadata().get("x-api-key").unwrap(), "test-secret");
        Ok(Response::new(tokio_stream::iter(
            self.0.clone().into_iter().map(Ok).collect::<Vec<_>>(),
        )))
    }
}

#[tokio::test]
async fn broader_stream_delivers_raw_bytes_and_terminates_on_duplicate_identity() {
    use polaris_tx_stream_client::TransactionObservation;
    let canonical = frame();
    let epoch = polaris_tx_stream_client::protocol::CanonicalFrameRef::parse(&canonical)
        .unwrap()
        .header()
        .producer_epoch;
    let raw = UnresolvedTransaction {
        producer_epoch: epoch,
        structural_sequence: 99,
        slot: 424200,
        transaction: include_bytes!("../../../fixtures/transactions/v0_multi_lut.bin").to_vec(),
        reason: "table_missing".into(),
    };
    let observation = TransactionFrame {
        payload: Some(transaction_frame::Payload::Unresolved(raw.clone())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(transaction_stream_server::TransactionStreamServer::new(
                ObservationFixture(vec![
                    TransactionFrame {
                        payload: Some(transaction_frame::Payload::CanonicalV1(canonical)),
                    },
                    observation.clone(),
                    observation,
                ]),
            ))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = FastpathClient::from_channel(
        channel,
        ApiKey::new("test-secret").unwrap(),
        TransportConfig::default(),
    );
    let mut stream = client
        .subscribe_transactions(ResolvedFilter::match_all())
        .await
        .unwrap();
    assert!(matches!(
        stream.next().await,
        Some(Ok(TransactionObservation::Resolved(_)))
    ));
    let Some(Ok(TransactionObservation::Unresolved(received))) = stream.next().await else {
        panic!("expected unresolved");
    };
    assert_eq!(received.transaction_bytes(), raw.transaction);
    assert_eq!(received.slot(), 424200);
    assert_eq!(received.reason(), "table_missing");
    assert!(received.transaction().num_address_table_lookups() > 0);
    assert!(matches!(
        stream.next().await,
        Some(Err(Error::InvalidObservation(_)))
    ));
    assert!(stream.next().await.is_none());
    server.abort();
}
