//! Canonical resolved-transaction frames.

use {
    crate::{
        layout::{FRAME_BODY_CAPACITY, FRAME_HEADER_BYTES, LAYOUT_VERSION_V1},
        transaction::SanitizedTransactionView,
    },
    std::{
        fmt,
        ops::{BitOr, BitOrAssign},
    },
    thiserror::Error,
};

pub const FRAME_MAGIC_V1: [u8; 8] = *b"STFPFRM1";
pub const FRAME_SCHEMA_VERSION_V1: u16 = 1;
pub const KEY_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageVersion {
    Legacy = 0,
    V0 = 1,
    V1 = 2,
}

impl MessageVersion {
    fn decode(value: u8) -> Result<Self, FrameValidationError> {
        match value {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::V0),
            2 => Ok(Self::V1),
            _ => Err(FrameValidationError::UnsupportedMessageVersion(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrameFlags(u32);

impl FrameFlags {
    pub const NATURAL_READY: Self = Self(1 << 0);
    pub const FEC_RECOVERED: Self = Self(1 << 1);
    pub const LEADER_SIGNATURE_VERIFIED: Self = Self(1 << 2);
    pub const MERKLE_PROOF_VERIFIED: Self = Self(1 << 3);
    pub const TRANSACTION_SANITIZED: Self = Self(1 << 4);
    pub const LUT_RESOLVED: Self = Self(1 << 5);
    pub const DATA_SET_START_VALID: Self = Self(1 << 6);
    pub const DATA_SET_END_VALID: Self = Self(1 << 7);
    pub const ALL: Self = Self((1 << 8) - 1);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn from_bits(bits: u32) -> Result<Self, FrameValidationError> {
        if bits & !Self::ALL.bits() == 0 {
            Ok(Self(bits))
        } else {
            Err(FrameValidationError::UnknownFlags(bits))
        }
    }
}

impl BitOr for FrameFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FrameFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeaderV1 {
    pub message_version: MessageVersion,
    pub earliest_source: u8,
    pub flags: FrameFlags,
    pub body_length: u32,
    pub atomic_word_count: u32,
    pub producer_epoch: u64,
    pub canonical_sequence: u64,
    pub slot: u64,
    pub prefix_generation: u64,
    pub contributing_source_mask: u64,
    pub first_data_shred_index: u32,
    pub last_data_shred_index: u32,
    pub data_set_starting_shred_index: u32,
    pub completed_data_set_ending_shred_index_exclusive: u32,
    pub entry_ordinal: u32,
    pub transaction_ordinal: u32,
    pub transaction_offset: u32,
    pub transaction_length: u32,
    pub loaded_writable_offset: u32,
    pub loaded_writable_length: u32,
    pub loaded_readonly_offset: u32,
    pub loaded_readonly_length: u32,
    pub loaded_writable_count: u16,
    pub loaded_readonly_count: u16,
    pub final_padding_bytes: u8,
    pub first_shred_receive_ns: u64,
    pub transaction_complete_ns: u64,
    pub lut_resolution_complete_ns: u64,
    pub publication_start_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameMetadataV1 {
    pub message_version: MessageVersion,
    pub earliest_source: u8,
    pub flags: FrameFlags,
    pub producer_epoch: u64,
    pub canonical_sequence: u64,
    pub slot: u64,
    pub prefix_generation: u64,
    pub contributing_source_mask: u64,
    pub first_data_shred_index: u32,
    pub last_data_shred_index: u32,
    pub data_set_starting_shred_index: u32,
    pub completed_data_set_ending_shred_index_exclusive: u32,
    pub entry_ordinal: u32,
    pub transaction_ordinal: u32,
    pub first_shred_receive_ns: u64,
    pub transaction_complete_ns: u64,
    pub lut_resolution_complete_ns: u64,
    pub publication_start_ns: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct FrameParts<'a> {
    pub transaction: &'a [u8],
    pub loaded_writable: &'a [[u8; KEY_BYTES]],
    pub loaded_readonly: &'a [[u8; KEY_BYTES]],
}

pub struct FrameEncoder;

pub struct ValidatedFrame<'a> {
    header: FrameHeaderV1,
    frame: &'a [u8],
    transaction_view: SanitizedTransactionView<'a>,
    loaded_writable: &'a [u8],
    loaded_readonly: &'a [u8],
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FrameValidationError {
    #[error("frame header is truncated")]
    TruncatedHeader,
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("unsupported frame schema {0}")]
    UnsupportedSchema(u16),
    #[error("unsupported frame layout {0}")]
    UnsupportedLayout(u16),
    #[error("invalid frame header length {0}")]
    InvalidHeaderLength(u16),
    #[error("unsupported message version {0}")]
    UnsupportedMessageVersion(u8),
    #[error("frame has unknown flags 0x{0:08x}")]
    UnknownFlags(u32),
    #[error("frame readiness flags are contradictory")]
    InvalidReadiness,
    #[error("frame boundary validity fields are inconsistent")]
    InvalidBoundaryValidity,
    #[error("frame body exceeds its fixed slot")]
    FrameTooLarge,
    #[error("frame atomic word count is invalid")]
    InvalidAtomicWordCount,
    #[error("frame body regions are reordered, overlap, or do not cover the body")]
    InvalidBodyRegions,
    #[error("loaded-key byte length does not equal count times 32")]
    InvalidLoadedKeyLength,
    #[error("message version cannot carry the declared loaded keys")]
    InvalidLoadedKeysForVersion,
    #[error("frame final atomic-word padding is invalid")]
    InvalidPadding,
    #[error("frame monotonic-raw timestamps are invalid")]
    InvalidTimestamps,
    #[error("frame identity fields use reserved zero values")]
    InvalidIdentity,
    #[error("frame header contains nonzero reserved bytes")]
    NonzeroReserved,
    #[error("encoded frame is truncated")]
    TruncatedFrame,
    #[error("destination cannot hold the encoded frame")]
    OutputTooSmall,
    #[error("signed transaction bytes fail pinned sanitization")]
    TransactionParse,
    #[error("frame message version disagrees with the signed transaction")]
    MessageVersionMismatch,
    #[error("loaded address counts disagree with transaction lookup descriptors")]
    LoadedAddressCountMismatch,
    #[error("frame has nonzero bytes in final atomic-word padding")]
    NonzeroFinalPadding,
}

pub fn checked_frame_body_length(
    transaction_length: usize,
    loaded_writable_count: usize,
    loaded_readonly_count: usize,
) -> Result<usize, FrameValidationError> {
    let loaded_count = loaded_writable_count
        .checked_add(loaded_readonly_count)
        .ok_or(FrameValidationError::FrameTooLarge)?;
    let loaded_bytes = loaded_count
        .checked_mul(KEY_BYTES)
        .ok_or(FrameValidationError::FrameTooLarge)?;
    let body_length = transaction_length
        .checked_add(loaded_bytes)
        .ok_or(FrameValidationError::FrameTooLarge)?;
    if body_length > FRAME_BODY_CAPACITY {
        Err(FrameValidationError::FrameTooLarge)
    } else {
        Ok(body_length)
    }
}

impl FrameEncoder {
    pub fn encode_into(
        metadata: &FrameMetadataV1,
        parts: FrameParts<'_>,
        output: &mut [u8],
    ) -> Result<usize, FrameValidationError> {
        let transaction_view = SanitizedTransactionView::try_new(parts.transaction)
            .map_err(|_| FrameValidationError::TransactionParse)?;
        if transaction_view.message_version() != metadata.message_version {
            return Err(FrameValidationError::MessageVersionMismatch);
        }
        if usize::from(transaction_view.total_writable_lookup_accounts())
            != parts.loaded_writable.len()
            || usize::from(transaction_view.total_readonly_lookup_accounts())
                != parts.loaded_readonly.len()
        {
            return Err(FrameValidationError::LoadedAddressCountMismatch);
        }
        let transaction_length = parts.transaction.len();
        let writable_length = parts
            .loaded_writable
            .len()
            .checked_mul(KEY_BYTES)
            .ok_or(FrameValidationError::FrameTooLarge)?;
        let readonly_length = parts
            .loaded_readonly
            .len()
            .checked_mul(KEY_BYTES)
            .ok_or(FrameValidationError::FrameTooLarge)?;
        let body_length = checked_frame_body_length(
            transaction_length,
            parts.loaded_writable.len(),
            parts.loaded_readonly.len(),
        )?;
        let unpadded_frame_length = FRAME_HEADER_BYTES
            .checked_add(body_length)
            .ok_or(FrameValidationError::FrameTooLarge)?;
        let frame_length = unpadded_frame_length
            .checked_add(7)
            .ok_or(FrameValidationError::FrameTooLarge)?
            & !7;
        if output.len() < frame_length {
            return Err(FrameValidationError::OutputTooSmall);
        }
        let final_padding_bytes = frame_length - unpadded_frame_length;
        let header = FrameHeaderV1 {
            message_version: metadata.message_version,
            earliest_source: metadata.earliest_source,
            flags: metadata.flags,
            body_length: u32::try_from(body_length)
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            atomic_word_count: u32::try_from(frame_length / 8)
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            producer_epoch: metadata.producer_epoch,
            canonical_sequence: metadata.canonical_sequence,
            slot: metadata.slot,
            prefix_generation: metadata.prefix_generation,
            contributing_source_mask: metadata.contributing_source_mask,
            first_data_shred_index: metadata.first_data_shred_index,
            last_data_shred_index: metadata.last_data_shred_index,
            data_set_starting_shred_index: metadata.data_set_starting_shred_index,
            completed_data_set_ending_shred_index_exclusive: metadata
                .completed_data_set_ending_shred_index_exclusive,
            entry_ordinal: metadata.entry_ordinal,
            transaction_ordinal: metadata.transaction_ordinal,
            transaction_offset: 0,
            transaction_length: u32::try_from(transaction_length)
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            loaded_writable_offset: u32::try_from(transaction_length)
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            loaded_writable_length: u32::try_from(writable_length)
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            loaded_readonly_offset: u32::try_from(transaction_length + writable_length)
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            loaded_readonly_length: u32::try_from(readonly_length)
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            loaded_writable_count: u16::try_from(parts.loaded_writable.len())
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            loaded_readonly_count: u16::try_from(parts.loaded_readonly.len())
                .map_err(|_| FrameValidationError::FrameTooLarge)?,
            final_padding_bytes: u8::try_from(final_padding_bytes)
                .map_err(|_| FrameValidationError::InvalidPadding)?,
            first_shred_receive_ns: metadata.first_shred_receive_ns,
            transaction_complete_ns: metadata.transaction_complete_ns,
            lut_resolution_complete_ns: metadata.lut_resolution_complete_ns,
            publication_start_ns: metadata.publication_start_ns,
        };
        header.validate()?;

        output[..frame_length].fill(0);
        output[..FRAME_HEADER_BYTES].copy_from_slice(&header.encode());
        let mut offset = FRAME_HEADER_BYTES;
        output[offset..offset + transaction_length].copy_from_slice(parts.transaction);
        offset += transaction_length;
        for key in parts.loaded_writable {
            output[offset..offset + KEY_BYTES].copy_from_slice(key);
            offset += KEY_BYTES;
        }
        for key in parts.loaded_readonly {
            output[offset..offset + KEY_BYTES].copy_from_slice(key);
            offset += KEY_BYTES;
        }
        debug_assert_eq!(offset, unpadded_frame_length);
        ValidatedFrame::parse(&output[..frame_length])?;
        Ok(frame_length)
    }
}

impl<'a> ValidatedFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FrameValidationError> {
        let header = FrameHeaderV1::decode(bytes)?;
        let atomic_bytes = usize::try_from(header.atomic_word_count)
            .ok()
            .and_then(|words| words.checked_mul(8))
            .ok_or(FrameValidationError::TruncatedFrame)?;
        let frame = bytes
            .get(..atomic_bytes)
            .ok_or(FrameValidationError::TruncatedFrame)?;
        let body_length =
            usize::try_from(header.body_length).map_err(|_| FrameValidationError::FrameTooLarge)?;
        let body_end = FRAME_HEADER_BYTES
            .checked_add(body_length)
            .ok_or(FrameValidationError::FrameTooLarge)?;
        let body = frame
            .get(FRAME_HEADER_BYTES..body_end)
            .ok_or(FrameValidationError::TruncatedFrame)?;
        if frame[body_end..].iter().any(|byte| *byte != 0) {
            return Err(FrameValidationError::NonzeroFinalPadding);
        }
        let transaction = body
            .get(region(
                header.transaction_offset,
                header.transaction_length,
            )?)
            .ok_or(FrameValidationError::InvalidBodyRegions)?;
        let loaded_writable = body
            .get(region(
                header.loaded_writable_offset,
                header.loaded_writable_length,
            )?)
            .ok_or(FrameValidationError::InvalidBodyRegions)?;
        let loaded_readonly = body
            .get(region(
                header.loaded_readonly_offset,
                header.loaded_readonly_length,
            )?)
            .ok_or(FrameValidationError::InvalidBodyRegions)?;
        let transaction_view = SanitizedTransactionView::try_new(transaction)
            .map_err(|_| FrameValidationError::TransactionParse)?;
        if transaction_view.message_version() != header.message_version {
            return Err(FrameValidationError::MessageVersionMismatch);
        }
        if transaction_view.total_writable_lookup_accounts() != header.loaded_writable_count
            || transaction_view.total_readonly_lookup_accounts() != header.loaded_readonly_count
        {
            return Err(FrameValidationError::LoadedAddressCountMismatch);
        }
        Ok(Self {
            header,
            frame,
            transaction_view,
            loaded_writable,
            loaded_readonly,
        })
    }

    pub const fn header(&self) -> &FrameHeaderV1 {
        &self.header
    }

    pub const fn bytes(&self) -> &'a [u8] {
        self.frame
    }

    pub const fn transaction_view(&self) -> &SanitizedTransactionView<'a> {
        &self.transaction_view
    }

    pub fn transaction_bytes(&self) -> &[u8] {
        self.transaction_view.data()
    }

    pub const fn loaded_writable_bytes(&self) -> &'a [u8] {
        self.loaded_writable
    }

    pub const fn loaded_readonly_bytes(&self) -> &'a [u8] {
        self.loaded_readonly
    }
}

impl fmt::Debug for ValidatedFrame<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedFrame")
            .field("header", &self.header)
            .field("transaction_bytes", &self.transaction_view.data())
            .field("loaded_writable", &self.loaded_writable)
            .field("loaded_readonly", &self.loaded_readonly)
            .finish()
    }
}

impl PartialEq for ValidatedFrame<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.transaction_view.data() == other.transaction_view.data()
            && self.loaded_writable == other.loaded_writable
            && self.loaded_readonly == other.loaded_readonly
    }
}

impl Eq for ValidatedFrame<'_> {}

fn region(offset: u32, length: u32) -> Result<std::ops::Range<usize>, FrameValidationError> {
    let start = usize::try_from(offset).map_err(|_| FrameValidationError::InvalidBodyRegions)?;
    let length = usize::try_from(length).map_err(|_| FrameValidationError::InvalidBodyRegions)?;
    let end = start
        .checked_add(length)
        .ok_or(FrameValidationError::InvalidBodyRegions)?;
    Ok(start..end)
}

impl FrameHeaderV1 {
    pub fn encode(&self) -> [u8; FRAME_HEADER_BYTES] {
        let mut bytes = [0_u8; FRAME_HEADER_BYTES];
        bytes[64..72].copy_from_slice(&FRAME_MAGIC_V1);
        write_u16(&mut bytes, 72, FRAME_SCHEMA_VERSION_V1);
        write_u16(&mut bytes, 74, LAYOUT_VERSION_V1);
        write_u16(&mut bytes, 76, FRAME_HEADER_BYTES as u16);
        bytes[78] = self.message_version as u8;
        bytes[79] = self.earliest_source;
        write_u32(&mut bytes, 80, self.flags.bits());
        write_u32(&mut bytes, 84, self.body_length);
        write_u32(&mut bytes, 88, self.atomic_word_count);
        write_u64(&mut bytes, 96, self.producer_epoch);
        write_u64(&mut bytes, 104, self.canonical_sequence);
        write_u64(&mut bytes, 112, self.slot);
        write_u64(&mut bytes, 120, self.prefix_generation);
        write_u64(&mut bytes, 128, self.contributing_source_mask);
        write_u32(&mut bytes, 136, self.first_data_shred_index);
        write_u32(&mut bytes, 140, self.last_data_shred_index);
        write_u32(&mut bytes, 144, self.data_set_starting_shred_index);
        write_u32(
            &mut bytes,
            148,
            self.completed_data_set_ending_shred_index_exclusive,
        );
        write_u32(&mut bytes, 152, self.entry_ordinal);
        write_u32(&mut bytes, 156, self.transaction_ordinal);
        write_u32(&mut bytes, 160, self.transaction_offset);
        write_u32(&mut bytes, 164, self.transaction_length);
        write_u32(&mut bytes, 168, self.loaded_writable_offset);
        write_u32(&mut bytes, 172, self.loaded_writable_length);
        write_u32(&mut bytes, 176, self.loaded_readonly_offset);
        write_u32(&mut bytes, 180, self.loaded_readonly_length);
        write_u16(&mut bytes, 184, self.loaded_writable_count);
        write_u16(&mut bytes, 186, self.loaded_readonly_count);
        bytes[188] = self.final_padding_bytes;
        write_u64(&mut bytes, 192, self.first_shred_receive_ns);
        write_u64(&mut bytes, 200, self.transaction_complete_ns);
        write_u64(&mut bytes, 208, self.lut_resolution_complete_ns);
        write_u64(&mut bytes, 216, self.publication_start_ns);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameValidationError> {
        let bytes = bytes
            .get(..FRAME_HEADER_BYTES)
            .ok_or(FrameValidationError::TruncatedHeader)?;
        if bytes[64..72] != FRAME_MAGIC_V1 {
            return Err(FrameValidationError::InvalidMagic);
        }
        let schema = read_u16(bytes, 72);
        if schema != FRAME_SCHEMA_VERSION_V1 {
            return Err(FrameValidationError::UnsupportedSchema(schema));
        }
        let layout = read_u16(bytes, 74);
        if layout != LAYOUT_VERSION_V1 {
            return Err(FrameValidationError::UnsupportedLayout(layout));
        }
        let header_length = read_u16(bytes, 76);
        if usize::from(header_length) != FRAME_HEADER_BYTES {
            return Err(FrameValidationError::InvalidHeaderLength(header_length));
        }
        if bytes[8..64].iter().any(|byte| *byte != 0)
            || bytes[92..96].iter().any(|byte| *byte != 0)
            || bytes[189..192].iter().any(|byte| *byte != 0)
            || bytes[224..].iter().any(|byte| *byte != 0)
        {
            return Err(FrameValidationError::NonzeroReserved);
        }
        let header = Self {
            message_version: MessageVersion::decode(bytes[78])?,
            earliest_source: bytes[79],
            flags: FrameFlags::from_bits(read_u32(bytes, 80))?,
            body_length: read_u32(bytes, 84),
            atomic_word_count: read_u32(bytes, 88),
            producer_epoch: read_u64(bytes, 96),
            canonical_sequence: read_u64(bytes, 104),
            slot: read_u64(bytes, 112),
            prefix_generation: read_u64(bytes, 120),
            contributing_source_mask: read_u64(bytes, 128),
            first_data_shred_index: read_u32(bytes, 136),
            last_data_shred_index: read_u32(bytes, 140),
            data_set_starting_shred_index: read_u32(bytes, 144),
            completed_data_set_ending_shred_index_exclusive: read_u32(bytes, 148),
            entry_ordinal: read_u32(bytes, 152),
            transaction_ordinal: read_u32(bytes, 156),
            transaction_offset: read_u32(bytes, 160),
            transaction_length: read_u32(bytes, 164),
            loaded_writable_offset: read_u32(bytes, 168),
            loaded_writable_length: read_u32(bytes, 172),
            loaded_readonly_offset: read_u32(bytes, 176),
            loaded_readonly_length: read_u32(bytes, 180),
            loaded_writable_count: read_u16(bytes, 184),
            loaded_readonly_count: read_u16(bytes, 186),
            final_padding_bytes: bytes[188],
            first_shred_receive_ns: read_u64(bytes, 192),
            transaction_complete_ns: read_u64(bytes, 200),
            lut_resolution_complete_ns: read_u64(bytes, 208),
            publication_start_ns: read_u64(bytes, 216),
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(&self) -> Result<(), FrameValidationError> {
        let natural = self.flags.contains(FrameFlags::NATURAL_READY);
        let fec = self.flags.contains(FrameFlags::FEC_RECOVERED);
        if natural == fec {
            return Err(FrameValidationError::InvalidReadiness);
        }
        if self.producer_epoch == 0
            || self.canonical_sequence == 0
            || self.prefix_generation == 0
            || self.contributing_source_mask == 0
        {
            return Err(FrameValidationError::InvalidIdentity);
        }
        let start_valid = self.flags.contains(FrameFlags::DATA_SET_START_VALID);
        let end_valid = self.flags.contains(FrameFlags::DATA_SET_END_VALID);
        if (!start_valid && self.data_set_starting_shred_index != 0)
            || (!end_valid && self.completed_data_set_ending_shred_index_exclusive != 0)
            || (end_valid && !start_valid)
            || (start_valid && self.data_set_starting_shred_index > self.first_data_shred_index)
            || self.first_data_shred_index > self.last_data_shred_index
            || (end_valid
                && self.last_data_shred_index
                    >= self.completed_data_set_ending_shred_index_exclusive)
        {
            return Err(FrameValidationError::InvalidBoundaryValidity);
        }
        let body_length =
            usize::try_from(self.body_length).map_err(|_| FrameValidationError::FrameTooLarge)?;
        if body_length == 0 || body_length > FRAME_BODY_CAPACITY {
            return Err(FrameValidationError::FrameTooLarge);
        }
        let frame_length = FRAME_HEADER_BYTES
            .checked_add(body_length)
            .ok_or(FrameValidationError::FrameTooLarge)?;
        let expected_words = frame_length
            .checked_add(7)
            .ok_or(FrameValidationError::FrameTooLarge)?
            / 8;
        if usize::try_from(self.atomic_word_count).ok() != Some(expected_words) {
            return Err(FrameValidationError::InvalidAtomicWordCount);
        }
        let expected_padding = (8 - frame_length % 8) % 8;
        if usize::from(self.final_padding_bytes) != expected_padding {
            return Err(FrameValidationError::InvalidPadding);
        }
        let transaction_offset = usize::try_from(self.transaction_offset)
            .map_err(|_| FrameValidationError::InvalidBodyRegions)?;
        let transaction_length = usize::try_from(self.transaction_length)
            .map_err(|_| FrameValidationError::InvalidBodyRegions)?;
        let writable_offset = usize::try_from(self.loaded_writable_offset)
            .map_err(|_| FrameValidationError::InvalidBodyRegions)?;
        let writable_length = usize::try_from(self.loaded_writable_length)
            .map_err(|_| FrameValidationError::InvalidBodyRegions)?;
        let readonly_offset = usize::try_from(self.loaded_readonly_offset)
            .map_err(|_| FrameValidationError::InvalidBodyRegions)?;
        let readonly_length = usize::try_from(self.loaded_readonly_length)
            .map_err(|_| FrameValidationError::InvalidBodyRegions)?;
        let transaction_end = transaction_offset
            .checked_add(transaction_length)
            .ok_or(FrameValidationError::InvalidBodyRegions)?;
        let writable_end = writable_offset
            .checked_add(writable_length)
            .ok_or(FrameValidationError::InvalidBodyRegions)?;
        let readonly_end = readonly_offset
            .checked_add(readonly_length)
            .ok_or(FrameValidationError::InvalidBodyRegions)?;
        if transaction_length == 0
            || transaction_offset != 0
            || writable_offset != transaction_end
            || readonly_offset != writable_end
            || readonly_end != body_length
        {
            return Err(FrameValidationError::InvalidBodyRegions);
        }
        let expected_writable_length = usize::from(self.loaded_writable_count)
            .checked_mul(KEY_BYTES)
            .ok_or(FrameValidationError::InvalidLoadedKeyLength)?;
        let expected_readonly_length = usize::from(self.loaded_readonly_count)
            .checked_mul(KEY_BYTES)
            .ok_or(FrameValidationError::InvalidLoadedKeyLength)?;
        if writable_length != expected_writable_length
            || readonly_length != expected_readonly_length
        {
            return Err(FrameValidationError::InvalidLoadedKeyLength);
        }
        if matches!(
            self.message_version,
            MessageVersion::Legacy | MessageVersion::V1
        ) && (self.loaded_writable_count != 0 || self.loaded_readonly_count != 0)
        {
            return Err(FrameValidationError::InvalidLoadedKeysForVersion);
        }
        if self.first_shred_receive_ns == 0
            || self.first_shred_receive_ns > self.transaction_complete_ns
            || self.transaction_complete_ns > self.lut_resolution_complete_ns
            || self.lut_resolution_complete_ns > self.publication_start_ns
        {
            return Err(FrameValidationError::InvalidTimestamps);
        }
        Ok(())
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
