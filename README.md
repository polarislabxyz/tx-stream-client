# Polaris TX Stream client

Standalone Rust client and decoder for Polaris Lab's transaction stream.
`TransactionStream/SubscribeTransactions` delivers immediate resolved transactions
and raw transactions whose lookup tables could not be resolved. The existing
`SolanaTransactionFastpath/SubscribeResolvedTransactions` RPC remains available
for exact-resolved transactions. Both use package `polaris.solana.fastpath.v1`.
Version `0.1.0-rc.2` is a release candidate; your API key needs TX Stream access.

## Run

Install stable Rust and `protoc` (Ubuntu: `protobuf-compiler`), then:

```bash
git clone https://github.com/polarislabxyz/tx-stream-client.git
cd tx-stream-client
git checkout v0.1.0-rc.2
export POLARIS_TX_STREAM_ENDPOINT=https://amsterdam.grpc.rpcedge.com
read -rs POLARIS_API_KEY
export POLARIS_API_KEY
cargo run --locked -p subscribe-transactions -- --help
cargo run --locked -p subscribe-transactions -- --summary
```

The broader example runs for 60 seconds by default; set
`POLARIS_TX_STREAM_DURATION_SECS` to change it. Omit `--summary` to print signatures
and resolution states. Positional base58 accounts form one include-any filter.
`subscribe-resolved` remains available, with `POLARIS_TX_STREAM_MAX_FRAMES` as its
optional bound. The client sends `x-api-key` metadata; keep keys out of source,
command arguments and bug reports.

## Library

Pin the Git tag until a registry release is available:

```toml
polaris-tx-stream-client = { git = "https://github.com/polarislabxyz/tx-stream-client", tag = "v0.1.0-rc.2" }
```

```rust,no_run
use polaris_tx_stream_client::{ApiKey, FastpathClient, ResolvedFilter, TransportConfig};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let key = ApiKey::new(&std::env::var("POLARIS_API_KEY")?)?;
let endpoint = std::env::var("POLARIS_TX_STREAM_ENDPOINT")?;
let mut client = FastpathClient::connect(&endpoint, key, TransportConfig::default()).await?;
let mut stream = client.subscribe(ResolvedFilter::match_all()).await?;
while let Some(result) = stream.next().await {
    let tx = result?;
    let frame = tx.frame();
    println!("slot {}", frame.header().slot);
    let original_transaction_bytes = frame.transaction_bytes();
    let writable_keys = frame.loaded_writable_bytes().chunks_exact(32);
    let readonly_keys = frame.loaded_readonly_bytes().chunks_exact(32);
    // Decode instructions through frame.transaction_view().instructions_iter().
}
# Ok(()) }
```

For all observed transactions, use `client.subscribe_transactions(filter)` and
match `TransactionObservation::Resolved(tx)` / `TransactionObservation::Unresolved(tx)`.
The unresolved variant exposes `transaction_bytes()`, `transaction()` (static
accounts, instructions and LUT descriptors), `slot()`, `producer_epoch()`,
`structural_sequence()` and `reason()`. It never fabricates loaded addresses.
The broader server currently supports Legacy/V0 structural observations; the
exact-resolved decoder also supports V1 when enabled by the producer.

`polaris-tx-stream-protocol` has no Tonic, Tokio, mmap or validator dependency.
`CanonicalFrameRef::parse` borrows bytes without allocation. The client owns
one bounded frame at a time; there is no application prefetch queue.

## Semantics

These are provisional transactions observed from shreds.
They are not execution results, success confirmations, finality proofs or
historical replay. Forks and transactions that never execute are possible.
The stream has no Yellowstone execution metadata or inner instructions.
Transaction Sender is a separate product. Yellowstone clients cannot decode
this custom service's `canonical_v1` payload.

Frames preserve original Legacy, V0 and V1 transaction bytes and loaded writable
then readonly address groups. Embedded stage timestamps are producer-local
monotonic values; do not compare them directly with another host's clock.
Frame flags describe producer observations, not client-side signature checking.

Empty filters mean match-all. Rules are ORed. Each rule supports vote selection,
include-any, exclude-any and required-all accounts. The helper accepts at most
16 rules and 256 keys per rule; server entitlement limits may be stricter.
Invalid or duplicate keys are rejected locally.

Canonical match-all sequences must be contiguous. Filtered canonical sequences may skip but must
increase. Duplicate/regressed sequences, epoch changes, malformed frames and
EOF are explicit terminal errors. Re-subscribing starts live and cannot recover
the missing interval. Authentication and permission errors must be corrected
before retrying.

The broader stream has two sequence domains: canonical sequence for resolved
frames, structural sequence for unresolved frames. Do not compare them or assume
slot order. Unresolved structural sequences increase but are normally sparse.
Empty filters deliver all observed transactions, subject to explicit source or
transport errors. For unresolved frames, filters match **static keys only**:
unknown loaded keys cannot satisfy include/required predicates or exclude a
transaction. Use match-all for coverage and resolve/filter locally if needed.
There is one immediate observation per producer transaction, with no later
replacement or resolution retry on this API. It is a live feed, not a guarantee
of receiving every transaction on the network or recovering disconnects.

Opt-in `reconnect::ReconnectingStream` retries transient transport status and
EOF with capped backoff (250 ms to 10 s, five subscription attempts). Every
attachment begins with `FastpathEvent::StreamReset`; reconcile before accepting
subsequent transactions. Corrupt/discontinuous streams and authorization errors
remain terminal. Dropping the wrapper cancels it; no background task survives.

Transport defaults: HTTPS certificate verification, 10 s connection and initial
subscription timeouts, 30 s HTTP/2 and TCP keepalive, 10 s keepalive timeout,
TCP_NODELAY, adaptive HTTP/2 windows, and a 16 KiB decoded-message cap. No idle
transaction timeout is imposed. `TransportConfig` exposes these settings.
`http2_adaptive_window`, `initial_stream_window_size` and
`initial_connection_window_size` permit controlled transport experiments. Hyper's
adaptive mode overrides initial windows; disable it to test fixed windows.
The example accepts `POLARIS_HTTP2_ADAPTIVE=false`. No fixed-window speedup is
assumed. The advanced `from_channel` API delegates TLS configuration to its caller.

## Contract sync and releases

`fixtures/manifest.json` records the upstream source commit and hashes for the
proto, exported public decoder code, transaction fixtures and canonical frames.
The upstream exporter reads immutable committed Git objects through an explicit
allowlist. No private Git dependency or source checkout is needed to use this repo.
Generated files must be updated together through a contract-sync PR. CI rejects
any mismatch, and the upstream drift job fails until the public contract matches.

```bash
bash scripts/check-public-contract.sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo doc --locked --workspace --no-deps
cargo deny --locked check
```

Release tags are immutable. A candidate tag must match all package versions and
pass the same CI. Stable `v0.1.0` additionally requires a real entitled subscriber
against the production endpoint. Registry publication is disabled in this RC.
