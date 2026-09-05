//! Allocation-free Solana transaction wire version and size contracts.
//!
//! This crate deliberately does not deserialize transactions. It owns only the
//! stable facts needed at admission boundaries: how to distinguish the three
//! supported wire versions and the maximum representation size for each one.

const MESSAGE_VERSION_PREFIX: u8 = 0x80;
const V1_PREFIX: u8 = MESSAGE_VERSION_PREFIX | 1;
const SIGNATURE_BYTES: usize = 64;
const MAX_SIGNATURES: u8 = 12;

const LEGACY_V0_RAW_LIMIT: usize = 1_232;
const V1_RAW_LIMIT: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransactionWireVersion {
    Legacy,
    V0,
    V1,
}

impl TransactionWireVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::V0 => "v0",
            Self::V1 => "v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionSizeBucket {
    LegacyLimit,
    V1Extended,
    Oversize,
}

impl TransactionSizeBucket {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegacyLimit => "le_1232",
            Self::V1Extended => "1233_4096",
            Self::Oversize => "gt_4096",
        }
    }
}

#[must_use]
pub const fn raw_size_bucket(actual: usize) -> TransactionSizeBucket {
    if actual <= LEGACY_V0_RAW_LIMIT {
        TransactionSizeBucket::LegacyLimit
    } else if actual <= V1_RAW_LIMIT {
        TransactionSizeBucket::V1Extended
    } else {
        TransactionSizeBucket::Oversize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireClassificationError {
    Empty,
    InvalidSignatureCount,
    TruncatedSignatures,
    MissingMessagePrefix,
    UnsupportedVersion(u8),
}

/// Classify exact transaction bytes without deserializing or allocating.
///
/// V1 is message-first and starts with `0x81`. Legacy and V0 are
/// signature-first, so their message prefix is read after the bounded
/// signature vector.
pub fn classify(bytes: &[u8]) -> Result<TransactionWireVersion, WireClassificationError> {
    let first = *bytes.first().ok_or(WireClassificationError::Empty)?;
    if first == V1_PREFIX {
        return Ok(TransactionWireVersion::V1);
    }
    if first & MESSAGE_VERSION_PREFIX != 0 {
        return Err(WireClassificationError::UnsupportedVersion(
            first & !MESSAGE_VERSION_PREFIX,
        ));
    }
    if first == 0 || first > MAX_SIGNATURES {
        return Err(WireClassificationError::InvalidSignatureCount);
    }

    let message_offset = 1usize
        .checked_add(usize::from(first) * SIGNATURE_BYTES)
        .ok_or(WireClassificationError::TruncatedSignatures)?;
    if bytes.len() < message_offset {
        return Err(WireClassificationError::TruncatedSignatures);
    }
    let message_prefix = *bytes
        .get(message_offset)
        .ok_or(WireClassificationError::MissingMessagePrefix)?;
    if message_prefix & MESSAGE_VERSION_PREFIX == 0 {
        Ok(TransactionWireVersion::Legacy)
    } else if message_prefix == MESSAGE_VERSION_PREFIX {
        Ok(TransactionWireVersion::V0)
    } else {
        Err(WireClassificationError::UnsupportedVersion(
            message_prefix & !MESSAGE_VERSION_PREFIX,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodedTransactionFormat {
    Raw,
    Base64,
    Base58,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireSizeError {
    pub version: TransactionWireVersion,
    pub actual: usize,
    pub maximum: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestLimitError {
    EmptyBundle,
    Overflow,
}

#[must_use]
pub const fn raw_limit(version: TransactionWireVersion) -> usize {
    match version {
        TransactionWireVersion::Legacy | TransactionWireVersion::V0 => LEGACY_V0_RAW_LIMIT,
        TransactionWireVersion::V1 => V1_RAW_LIMIT,
    }
}

#[must_use]
pub const fn encoded_limit(
    version: TransactionWireVersion,
    format: EncodedTransactionFormat,
) -> usize {
    match (version, format) {
        (
            TransactionWireVersion::Legacy | TransactionWireVersion::V0,
            EncodedTransactionFormat::Raw,
        ) => LEGACY_V0_RAW_LIMIT,
        (
            TransactionWireVersion::Legacy | TransactionWireVersion::V0,
            EncodedTransactionFormat::Base64,
        ) => 1_644,
        (
            TransactionWireVersion::Legacy | TransactionWireVersion::V0,
            EncodedTransactionFormat::Base58,
        ) => 1_683,
        (TransactionWireVersion::V1, EncodedTransactionFormat::Raw) => V1_RAW_LIMIT,
        (TransactionWireVersion::V1, EncodedTransactionFormat::Base64) => 5_464,
        (TransactionWireVersion::V1, EncodedTransactionFormat::Base58) => 5_594,
    }
}

pub const fn validate_raw_size(
    version: TransactionWireVersion,
    actual: usize,
) -> Result<(), WireSizeError> {
    let maximum = raw_limit(version);
    if actual <= maximum {
        Ok(())
    } else {
        Err(WireSizeError {
            version,
            actual,
            maximum,
        })
    }
}

pub const fn request_limit(
    version: TransactionWireVersion,
    format: EncodedTransactionFormat,
    bundle_count: usize,
    fixed_overhead: usize,
) -> Result<usize, RequestLimitError> {
    if bundle_count == 0 {
        return Err(RequestLimitError::EmptyBundle);
    }
    let Some(payload_bytes) = encoded_limit(version, format).checked_mul(bundle_count) else {
        return Err(RequestLimitError::Overflow);
    };
    let Some(request_bytes) = payload_bytes.checked_add(fixed_overhead) else {
        return Err(RequestLimitError::Overflow);
    };
    Ok(request_bytes)
}
