//! Explicit resolution state without fabricated loaded addresses or implicit retry.
use crate::{
    protocol::{self, transaction::SanitizedTransactionView, StreamMode, StreamValidator},
    v1, Error, ResolvedTransaction,
};

pub enum TransactionObservation {
    Resolved(ResolvedTransaction),
    Unresolved(UnresolvedTransaction),
}

pub struct UnresolvedTransaction {
    wire: v1::UnresolvedTransaction,
}
impl UnresolvedTransaction {
    pub fn producer_epoch(&self) -> u64 {
        self.wire.producer_epoch
    }
    pub fn structural_sequence(&self) -> u64 {
        self.wire.structural_sequence
    }
    pub fn slot(&self) -> u64 {
        self.wire.slot
    }
    pub fn reason(&self) -> &str {
        &self.wire.reason
    }
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.wire.transaction
    }
    /// Static accounts, instructions and LUT descriptors remain available.
    /// Loaded keys are intentionally absent until independently resolved.
    pub fn transaction(&self) -> SanitizedTransactionView<'_> {
        SanitizedTransactionView::try_new(&self.wire.transaction)
            .expect("validated immutable transaction")
    }
}

struct ObservationValidator {
    canonical: StreamValidator,
    epoch: Option<u64>,
    structural_sequence: u64,
}
impl ObservationValidator {
    fn new(mode: StreamMode) -> Self {
        Self {
            canonical: StreamValidator::new(mode),
            epoch: None,
            structural_sequence: 0,
        }
    }
    fn validate(&mut self, frame: v1::TransactionFrame) -> Result<TransactionObservation, Error> {
        use v1::transaction_frame::Payload;
        let (epoch, observation) = match frame.payload {
            Some(Payload::CanonicalV1(bytes)) => {
                let frame = self.canonical.validate_resolved(&bytes)?;
                (
                    frame.header().producer_epoch,
                    TransactionObservation::Resolved(ResolvedTransaction { bytes }),
                )
            }
            Some(Payload::Unresolved(raw)) => {
                if raw.producer_epoch == 0
                    || raw.structural_sequence == 0
                    || raw.structural_sequence <= self.structural_sequence
                    || raw.reason.is_empty()
                    || raw.reason.len() > 128
                {
                    return Err(Error::InvalidObservation("invalid unresolved identity"));
                }
                SanitizedTransactionView::try_new(&raw.transaction)
                    .map_err(|_| Error::InvalidObservation("invalid raw transaction"))?;
                self.structural_sequence = raw.structural_sequence;
                (
                    raw.producer_epoch,
                    TransactionObservation::Unresolved(UnresolvedTransaction { wire: raw }),
                )
            }
            None => return Err(Error::InvalidObservation("missing payload")),
        };
        if self.epoch.is_some_and(|previous| previous != epoch) {
            return Err(protocol::stream::CanonicalStreamError::ProducerEpochChanged.into());
        }
        self.epoch = Some(epoch);
        Ok(observation)
    }
}

pub struct TransactionStream {
    stream: tonic::Streaming<v1::TransactionFrame>,
    validator: ObservationValidator,
    failed: bool,
}
impl TransactionStream {
    pub(crate) fn new(stream: tonic::Streaming<v1::TransactionFrame>, mode: StreamMode) -> Self {
        Self {
            stream,
            validator: ObservationValidator::new(mode),
            failed: false,
        }
    }
    /// No application queue; malformed data, gaps, epoch changes and EOF terminate attachment.
    pub async fn next(&mut self) -> Option<Result<TransactionObservation, Error>> {
        if self.failed {
            return None;
        }
        let result = match self.stream.message().await {
            Ok(Some(frame)) => self.validator.validate(frame),
            Ok(None) => Err(Error::EndOfStream),
            Err(status) => Err(Error::Status(status.code())),
        };
        self.failed = result.is_err();
        Some(result)
    }
}
