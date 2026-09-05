use polaris_tx_stream_client::{ApiKey, FastpathClient, ResolvedFilter, TransportConfig};
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help") {
        println!("subscribe-resolved [ACCOUNT_BASE58 ...]\nRequired: POLARIS_API_KEY, POLARIS_TX_STREAM_ENDPOINT (https URL)\nOptional: POLARIS_TX_STREAM_MAX_FRAMES (positive integer). Accounts form one include-any filter.\nErrors end the stream; reconnect starts live and cannot replay missed transactions.");
        return Ok(());
    }
    let key = ApiKey::new(&std::env::var("POLARIS_API_KEY").map_err(|_| "set POLARIS_API_KEY")?)?;
    let endpoint = std::env::var("POLARIS_TX_STREAM_ENDPOINT")
        .map_err(|_| "set POLARIS_TX_STREAM_ENDPOINT")?;
    let maximum = std::env::var("POLARIS_TX_STREAM_MAX_FRAMES")
        .ok()
        .map(|s| s.parse::<u64>())
        .transpose()?;
    if maximum == Some(0) {
        return Err("POLARIS_TX_STREAM_MAX_FRAMES must be positive".into());
    }
    let filter = if args.is_empty() {
        ResolvedFilter::match_all()
    } else {
        ResolvedFilter::match_all().rule(
            None,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            &[],
            &[],
        )?
    };
    let mut client = FastpathClient::connect(&endpoint, key, TransportConfig::default()).await?;
    let mut stream = client.subscribe(filter).await?;
    let mut count = 0;
    while let Some(result) = stream.next().await {
        let tx = result?;
        let frame = tx.frame();
        let header = frame.header();
        println!("slot={} sequence={} epoch={} version={:?} signature={} loaded_writable={} loaded_readonly={}",
            header.slot, header.canonical_sequence, header.producer_epoch, header.message_version,
            bs58::encode(frame.transaction_view().signatures()[0]).into_string(), header.loaded_writable_count, header.loaded_readonly_count);
        count += 1;
        if maximum == Some(count) {
            break;
        }
    }
    Ok(())
}
