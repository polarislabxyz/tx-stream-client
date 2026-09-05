//! Transport-independent validation for canonical resolved-transaction streams.

use {
    crate::frame::{FrameFlags, FrameValidationError, ValidatedFrame},
    thiserror::Error,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalStreamMode {
    /// Every canonical frame is expected, so sequence gaps are data loss.
    MatchAll,
    /// Server-side filters may omit frames, but order must remain monotonic.
    Filtered,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CanonicalStreamError {
    #[error("invalid canonical frame: {0}")]
    InvalidFrame(FrameValidationError),
    #[error("canonical frame has trailing bytes")]
    TrailingBytes,
    #[error("canonical frame is not sanitized and LUT-resolved")]
    NotResolved,
    #[error("producer epoch changed within one attachment")]
    ProducerEpochChanged,
    #[error("canonical sequence is exhausted")]
    SequenceExhausted,
    #[error("canonical sequence duplicated or regressed")]
    SequenceRegressed,
    #[error("canonical sequence has a gap on a match-all stream")]
    SequenceGap,
}

impl CanonicalStreamError {
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::InvalidFrame(_) => "invalid_canonical_frame",
            Self::TrailingBytes => "canonical_trailing_bytes",
            Self::NotResolved => "canonical_not_resolved",
            Self::ProducerEpochChanged => "producer_epoch_changed",
            Self::SequenceExhausted => "sequence_exhausted",
            Self::SequenceRegressed => "sequence_regressed",
            Self::SequenceGap => "sequence_gap",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalStreamValidator {
    producer_epoch: Option<u64>,
    last_sequence: Option<u64>,
    mode: CanonicalStreamMode,
}

impl CanonicalStreamValidator {
    pub const fn new(mode: CanonicalStreamMode) -> Self {
        Self {
            producer_epoch: None,
            last_sequence: None,
            mode,
        }
    }

    pub fn validate_resolved<'a>(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<ValidatedFrame<'a>, CanonicalStreamError> {
        let frame = ValidatedFrame::parse(bytes).map_err(CanonicalStreamError::InvalidFrame)?;
        if frame.bytes().len() != bytes.len() {
            return Err(CanonicalStreamError::TrailingBytes);
        }
        let header = frame.header();
        if !header.flags.contains(FrameFlags::TRANSACTION_SANITIZED)
            || !header.flags.contains(FrameFlags::LUT_RESOLVED)
        {
            return Err(CanonicalStreamError::NotResolved);
        }
        self.observe(header.producer_epoch, header.canonical_sequence)?;
        Ok(frame)
    }

    fn observe(&mut self, producer_epoch: u64, sequence: u64) -> Result<(), CanonicalStreamError> {
        if self
            .producer_epoch
            .is_some_and(|observed| observed != producer_epoch)
        {
            return Err(CanonicalStreamError::ProducerEpochChanged);
        }
        if let Some(previous) = self.last_sequence {
            let expected = previous
                .checked_add(1)
                .ok_or(CanonicalStreamError::SequenceExhausted)?;
            if sequence <= previous {
                return Err(CanonicalStreamError::SequenceRegressed);
            }
            if self.mode == CanonicalStreamMode::MatchAll && sequence != expected {
                return Err(CanonicalStreamError::SequenceGap);
            }
        }
        self.producer_epoch = Some(producer_epoch);
        self.last_sequence = Some(sequence);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalStreamError, CanonicalStreamMode, CanonicalStreamValidator};

    #[test]
    fn match_all_requires_exact_continuity() {
        let mut validator = CanonicalStreamValidator::new(CanonicalStreamMode::MatchAll);
        validator.observe(7, 100).unwrap();
        validator.observe(7, 101).unwrap();

        assert_eq!(
            validator.observe(7, 103),
            Err(CanonicalStreamError::SequenceGap)
        );
    }

    #[test]
    fn filtered_allows_gaps_but_not_regression_or_epoch_change() {
        let mut validator = CanonicalStreamValidator::new(CanonicalStreamMode::Filtered);
        validator.observe(7, 100).unwrap();
        validator.observe(7, 103).unwrap();
        assert_eq!(
            validator.observe(7, 103),
            Err(CanonicalStreamError::SequenceRegressed)
        );
        assert_eq!(
            validator.observe(8, 104),
            Err(CanonicalStreamError::ProducerEpochChanged)
        );
    }

    #[test]
    fn exhausted_sequence_fails_closed() {
        let mut validator = CanonicalStreamValidator::new(CanonicalStreamMode::Filtered);
        validator.observe(7, u64::MAX).unwrap();

        assert_eq!(
            validator.observe(7, u64::MAX),
            Err(CanonicalStreamError::SequenceExhausted)
        );
    }

    #[test]
    fn empty_payload_is_not_a_canonical_frame() {
        let mut validator = CanonicalStreamValidator::new(CanonicalStreamMode::MatchAll);
        assert!(matches!(
            validator.validate_resolved(&[]),
            Err(CanonicalStreamError::InvalidFrame(_))
        ));
    }
}
