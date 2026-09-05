use polaris_tx_stream_client::{
    ApiKey, FastpathClient, ResolvedFilter, TransactionObservation, TransportConfig,
};
use std::{collections::BTreeMap, time::Duration};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help") {
        println!("subscribe-transactions [--summary] [ACCOUNT_BASE58 ...]\nRequired: POLARIS_API_KEY, POLARIS_TX_STREAM_ENDPOINT (HTTPS).\nOptional: POLARIS_TX_STREAM_DURATION_SECS (default 60), POLARIS_HTTP2_ADAPTIVE (true/false).\nEmpty accounts deliver all observations. Unresolved filters match static keys only.\n--summary avoids per-transaction formatting and prints counts on completion.");
        return Ok(());
    }
    let summary = args.iter().any(|a| a == "--summary");
    let accounts: Vec<_> = args
        .iter()
        .filter(|a| a.as_str() != "--summary")
        .map(String::as_str)
        .collect();
    let key = ApiKey::new(&std::env::var("POLARIS_API_KEY").map_err(|_| "set POLARIS_API_KEY")?)?;
    let endpoint = std::env::var("POLARIS_TX_STREAM_ENDPOINT")
        .map_err(|_| "set POLARIS_TX_STREAM_ENDPOINT")?;
    let seconds = std::env::var("POLARIS_TX_STREAM_DURATION_SECS")
        .unwrap_or_else(|_| "60".into())
        .parse::<u64>()?;
    if seconds == 0 {
        return Err("duration must be positive".into());
    }
    let mut config = TransportConfig::default();
    if let Ok(adaptive) = std::env::var("POLARIS_HTTP2_ADAPTIVE") {
        config.http2_adaptive_window = adaptive.parse()?;
    }
    let mut client = FastpathClient::connect(&endpoint, key, config).await?;
    let filter = if accounts.is_empty() {
        ResolvedFilter::match_all()
    } else {
        ResolvedFilter::match_all().rule(None, &accounts, &[], &[])?
    };
    let mut stream = client.subscribe_transactions(filter).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let mut resolved = 0_u64;
    let mut unresolved = 0_u64;
    let mut reasons = BTreeMap::<String, u64>::new();
    loop {
        let result = match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) => break,
            Ok(Some(result)) => result?,
            Ok(None) => return Err("stream ended".into()),
        };
        match result {
            TransactionObservation::Resolved(tx) => {
                resolved += 1;
                if !summary {
                    let frame = tx.frame();
                    println!(
                        "resolved slot={} signature={} loaded_writable={} loaded_readonly={}",
                        frame.header().slot,
                        bs58::encode(frame.transaction_view().signatures()[0]).into_string(),
                        frame.header().loaded_writable_count,
                        frame.header().loaded_readonly_count
                    );
                }
            }
            TransactionObservation::Unresolved(tx) => {
                unresolved += 1;
                *reasons.entry(tx.reason().into()).or_default() += 1;
                if !summary {
                    println!(
                        "unresolved slot={} signature={} reason={}",
                        tx.slot(),
                        bs58::encode(tx.transaction().signatures()[0]).into_string(),
                        tx.reason()
                    );
                }
            }
        }
    }
    println!(
        "duration_seconds={seconds} resolved={resolved} unresolved={unresolved} total={}",
        resolved + unresolved
    );
    for (reason, count) in reasons {
        println!("unresolved_reason={reason} count={count}");
    }
    Ok(())
}
