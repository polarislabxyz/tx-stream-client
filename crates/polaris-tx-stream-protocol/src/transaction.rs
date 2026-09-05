//! Allocation-free borrowed validation for legacy, v0, and v1 transactions.
//!
//! The accepted wire format and sanitize rules are pinned to
//! `agave-transaction-view` 4.2.1. The implementation intentionally stores
//! only offsets and scalar metadata; instruction and lookup iteration reparses
//! the already-validated compact fields instead of allocating per-item frames.

use {
    crate::frame::MessageVersion,
    crate::wire::{raw_limit, TransactionWireVersion},
    std::{fmt, mem::size_of},
    thiserror::Error,
};

const SIGNATURE_BYTES: usize = 64;
const PUBKEY_BYTES: usize = 32;
const BLOCKHASH_BYTES: usize = 32;
const MESSAGE_VERSION_PREFIX: u8 = 0x80;
const V1_PREFIX: u8 = MESSAGE_VERSION_PREFIX | 1;
const MAX_SIGNATURES_PER_PACKET: u8 = 12;
const MAX_STATIC_ACCOUNTS_PER_PACKET: u8 = 38;
const MAX_V1_STATIC_ACCOUNTS: u8 = 64;
const MAX_ADDRESS_TABLE_LOOKUPS_PER_PACKET: u8 = 31;
const MAX_INSTRUCTIONS: u16 = 64;
const MAX_ACCOUNTS_PER_INSTRUCTION: u16 = 255;
const V1_INSTRUCTION_HEADER_BYTES: usize = 4;
const V1_CONFIG_PRIORITY_FEE: u32 = 0b11;
const V1_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 0b100;
const V1_CONFIG_LOADED_ACCOUNTS_DATA_SIZE: u32 = 0b1000;
const V1_CONFIG_HEAP_SIZE: u32 = 0b1_0000;
const V1_CONFIG_KNOWN_BITS: u32 = V1_CONFIG_PRIORITY_FEE
    | V1_CONFIG_COMPUTE_UNIT_LIMIT
    | V1_CONFIG_LOADED_ACCOUNTS_DATA_SIZE
    | V1_CONFIG_HEAP_SIZE;
const MIN_V1_HEAP_SIZE: u32 = 32 * 1024;
const MAX_V1_HEAP_SIZE: u32 = 256 * 1024;

/// Agave's packet limit for serialized legacy and v0 transactions.
pub const MAX_LEGACY_V0_TRANSACTION_BYTES: usize = raw_limit(TransactionWireVersion::Legacy);
/// Agave's SIMD-0296 limit for serialized v1 transactions.
pub const MAX_V1_TRANSACTION_BYTES: usize = raw_limit(TransactionWireVersion::V1);

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TransactionViewError {
    #[error("transaction wire format is malformed, truncated, or has trailing bytes")]
    Parse,
    #[error("transaction violates pinned Agave sanitization rules")]
    Sanitize,
    #[error("unsupported transaction wire version")]
    UnsupportedVersion,
}

/// A fully parsed and sanitized view over exact legacy, v0, or v1 transaction bytes.
///
/// Construction performs no heap allocation. All fields are private so callers
/// cannot manufacture a validation token for different transaction bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SanitizedTransactionView<'a> {
    bytes: &'a [u8],
    message_version: MessageVersion,
    num_signatures: u8,
    signatures_offset: usize,
    num_required_signatures: u8,
    num_readonly_signed_static_accounts: u8,
    num_readonly_unsigned_static_accounts: u8,
    num_static_account_keys: u8,
    static_account_keys_offset: usize,
    recent_blockhash_offset: usize,
    num_instructions: u16,
    instructions_offset: usize,
    instruction_payloads_offset: usize,
    instruction_layout: InstructionLayout,
    num_address_table_lookups: u8,
    address_table_lookups_offset: usize,
    total_writable_lookup_accounts: u16,
    total_readonly_lookup_accounts: u16,
    transaction_config_mask: u32,
    transaction_config_values_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstructionLayout {
    LegacyAndV0,
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizedInstructionView<'a> {
    pub program_id_index: u8,
    pub accounts: &'a [u8],
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizedAddressTableLookup<'a> {
    pub account_key: &'a [u8; PUBKEY_BYTES],
    pub writable_indexes: &'a [u8],
    pub readonly_indexes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizedTransactionConfigView<'a> {
    bytes: &'a [u8],
    mask: u32,
    values_offset: usize,
}

#[derive(Clone)]
pub struct SanitizedInstructionIterator<'a> {
    bytes: &'a [u8],
    header_offset: usize,
    payload_offset: usize,
    remaining: u16,
    layout: InstructionLayout,
}

#[derive(Clone)]
pub struct SanitizedAddressTableLookupIterator<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: u8,
}

impl<'a> SanitizedTransactionView<'a> {
    #[allow(clippy::too_many_lines)]
    pub fn try_new(bytes: &'a [u8]) -> Result<Self, TransactionViewError> {
        let Some(first_byte) = bytes.first().copied() else {
            return Err(TransactionViewError::Parse);
        };
        if first_byte == V1_PREFIX {
            return Self::try_new_v1(bytes);
        }
        if first_byte & MESSAGE_VERSION_PREFIX != 0 {
            return Err(TransactionViewError::UnsupportedVersion);
        }
        if bytes.len() > MAX_LEGACY_V0_TRANSACTION_BYTES {
            return Err(TransactionViewError::Sanitize);
        }

        let mut cursor = Cursor::new(bytes);
        let num_signatures = cursor.read_byte()?;
        if num_signatures == 0 || num_signatures > MAX_SIGNATURES_PER_PACKET {
            return Err(TransactionViewError::Parse);
        }
        let signatures_offset = cursor.offset();
        cursor.skip(usize::from(num_signatures) * SIGNATURE_BYTES)?;

        let message_prefix = cursor.read_byte()?;
        let (message_version, num_required_signatures) =
            if message_prefix & MESSAGE_VERSION_PREFIX == 0 {
                (MessageVersion::Legacy, message_prefix)
            } else if message_prefix == MESSAGE_VERSION_PREFIX {
                (MessageVersion::V0, cursor.read_byte()?)
            } else {
                return Err(TransactionViewError::Parse);
            };
        let num_readonly_signed_static_accounts = cursor.read_byte()?;
        let num_readonly_unsigned_static_accounts = cursor.read_byte()?;

        let num_static_account_keys = cursor.read_byte()?;
        if num_static_account_keys == 0 || num_static_account_keys > MAX_STATIC_ACCOUNTS_PER_PACKET
        {
            return Err(TransactionViewError::Parse);
        }
        let static_account_keys_offset = cursor.offset();
        cursor.skip(usize::from(num_static_account_keys) * PUBKEY_BYTES)?;
        let recent_blockhash_offset = cursor.offset();
        cursor.skip(BLOCKHASH_BYTES)?;

        let num_instructions = cursor.read_compact_u16()?;
        let instructions_offset = cursor.offset();
        let minimum_instruction_bytes = usize::from(num_instructions)
            .checked_mul(3)
            .ok_or(TransactionViewError::Parse)?;
        cursor.require_remaining(minimum_instruction_bytes)?;

        let mut instruction_sanitize_error = num_instructions > MAX_INSTRUCTIONS;
        let mut maximum_instruction_account_index = None::<u8>;
        for _ in 0..num_instructions {
            let program_id_index = cursor.read_byte()?;
            if program_id_index == 0 || program_id_index >= num_static_account_keys {
                instruction_sanitize_error = true;
            }

            let num_accounts = cursor.read_compact_u16()?;
            if num_accounts > MAX_ACCOUNTS_PER_INSTRUCTION {
                instruction_sanitize_error = true;
            }
            for account_index in cursor.read_bytes(usize::from(num_accounts))? {
                maximum_instruction_account_index = Some(
                    maximum_instruction_account_index
                        .map_or(*account_index, |current| current.max(*account_index)),
                );
            }

            let data_len = cursor.read_compact_u16()?;
            cursor.skip(usize::from(data_len))?;
        }

        let (num_address_table_lookups, address_table_lookups_offset) =
            if message_version == MessageVersion::V0 {
                let count = cursor.read_byte()?;
                if count > MAX_ADDRESS_TABLE_LOOKUPS_PER_PACKET {
                    return Err(TransactionViewError::Parse);
                }
                let offset = cursor.offset();
                let minimum_lookup_bytes = usize::from(count)
                    .checked_mul(35)
                    .ok_or(TransactionViewError::Parse)?;
                cursor.require_remaining(minimum_lookup_bytes)?;
                (count, offset)
            } else {
                (0, 0)
            };

        let mut total_writable_lookup_accounts = 0_u16;
        let mut total_readonly_lookup_accounts = 0_u16;
        let mut lookup_sanitize_error = false;
        for _ in 0..num_address_table_lookups {
            cursor.skip(PUBKEY_BYTES)?;
            let writable = cursor.read_compact_u16()?;
            total_writable_lookup_accounts = total_writable_lookup_accounts
                .checked_add(writable)
                .ok_or(TransactionViewError::Sanitize)?;
            cursor.skip(usize::from(writable))?;

            let readonly = cursor.read_compact_u16()?;
            total_readonly_lookup_accounts = total_readonly_lookup_accounts
                .checked_add(readonly)
                .ok_or(TransactionViewError::Sanitize)?;
            cursor.skip(usize::from(readonly))?;
            if writable == 0 && readonly == 0 {
                lookup_sanitize_error = true;
            }
        }
        if cursor.offset() != bytes.len() {
            return Err(TransactionViewError::Parse);
        }

        let header_is_invalid = num_required_signatures == 0
            || num_readonly_signed_static_accounts >= num_required_signatures
            || num_readonly_unsigned_static_accounts
                > num_static_account_keys.wrapping_sub(num_required_signatures);
        let signatures_are_invalid =
            num_signatures != num_required_signatures || num_static_account_keys < num_signatures;
        let total_accounts = u16::from(num_static_account_keys)
            .saturating_add(total_writable_lookup_accounts)
            .saturating_add(total_readonly_lookup_accounts);
        let account_access_is_invalid = total_accounts > 256
            || maximum_instruction_account_index
                .is_some_and(|index| u16::from(index) >= total_accounts);
        if header_is_invalid
            || signatures_are_invalid
            || account_access_is_invalid
            || instruction_sanitize_error
            || lookup_sanitize_error
        {
            return Err(TransactionViewError::Sanitize);
        }

        Ok(Self {
            bytes,
            message_version,
            num_signatures,
            signatures_offset,
            num_required_signatures,
            num_readonly_signed_static_accounts,
            num_readonly_unsigned_static_accounts,
            num_static_account_keys,
            static_account_keys_offset,
            recent_blockhash_offset,
            num_instructions,
            instructions_offset,
            instruction_payloads_offset: 0,
            instruction_layout: InstructionLayout::LegacyAndV0,
            num_address_table_lookups,
            address_table_lookups_offset,
            total_writable_lookup_accounts,
            total_readonly_lookup_accounts,
            transaction_config_mask: 0,
            transaction_config_values_offset: 0,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn try_new_v1(bytes: &'a [u8]) -> Result<Self, TransactionViewError> {
        if bytes.len() > MAX_V1_TRANSACTION_BYTES {
            return Err(TransactionViewError::Sanitize);
        }

        let mut cursor = Cursor::new(bytes);
        if cursor.read_byte()? != V1_PREFIX {
            return Err(TransactionViewError::UnsupportedVersion);
        }
        let num_required_signatures = cursor.read_byte()?;
        let num_readonly_signed_static_accounts = cursor.read_byte()?;
        let num_readonly_unsigned_static_accounts = cursor.read_byte()?;
        let transaction_config_mask = cursor.read_u32_le()?;
        if transaction_config_mask & !V1_CONFIG_KNOWN_BITS != 0
            || matches!(transaction_config_mask & V1_CONFIG_PRIORITY_FEE, 1 | 2)
        {
            return Err(TransactionViewError::Parse);
        }

        let recent_blockhash_offset = cursor.offset();
        cursor.skip(BLOCKHASH_BYTES)?;
        let num_instructions = u16::from(cursor.read_byte()?);
        let num_static_account_keys = cursor.read_byte()?;
        let static_account_keys_offset = cursor.offset();
        cursor.skip(usize::from(num_static_account_keys) * PUBKEY_BYTES)?;

        let transaction_config_values_offset = cursor.offset();
        if transaction_config_mask & V1_CONFIG_PRIORITY_FEE == V1_CONFIG_PRIORITY_FEE {
            cursor.skip(size_of::<u64>())?;
        }
        if transaction_config_mask & V1_CONFIG_COMPUTE_UNIT_LIMIT != 0 {
            cursor.skip(size_of::<u32>())?;
        }
        if transaction_config_mask & V1_CONFIG_LOADED_ACCOUNTS_DATA_SIZE != 0 {
            cursor.skip(size_of::<u32>())?;
        }
        let heap_size = if transaction_config_mask & V1_CONFIG_HEAP_SIZE != 0 {
            Some(cursor.read_u32_le()?)
        } else {
            None
        };

        let instructions_offset = cursor.offset();
        let instruction_headers_len = usize::from(num_instructions)
            .checked_mul(V1_INSTRUCTION_HEADER_BYTES)
            .ok_or(TransactionViewError::Parse)?;
        cursor.skip(instruction_headers_len)?;
        let instruction_payloads_offset = cursor.offset();

        let mut header_offset = instructions_offset;
        let mut payload_offset = instruction_payloads_offset;
        let mut instruction_sanitize_error = num_instructions > MAX_INSTRUCTIONS;
        for _ in 0..num_instructions {
            let program_id_index =
                read_byte_at(bytes, &mut header_offset).ok_or(TransactionViewError::Parse)?;
            let num_accounts =
                read_byte_at(bytes, &mut header_offset).ok_or(TransactionViewError::Parse)?;
            let data_len =
                read_u16_le_at(bytes, &mut header_offset).ok_or(TransactionViewError::Parse)?;

            if program_id_index == 0 || program_id_index >= num_static_account_keys {
                instruction_sanitize_error = true;
            }
            for account_index in
                read_bytes_at(bytes, &mut payload_offset, usize::from(num_accounts))
                    .ok_or(TransactionViewError::Parse)?
            {
                if *account_index >= num_static_account_keys {
                    instruction_sanitize_error = true;
                }
            }
            read_bytes_at(bytes, &mut payload_offset, usize::from(data_len))
                .ok_or(TransactionViewError::Parse)?;
        }
        cursor.offset = payload_offset;

        let signatures_offset = cursor.offset();
        cursor.skip(usize::from(num_required_signatures) * SIGNATURE_BYTES)?;
        if cursor.offset() != bytes.len() {
            return Err(TransactionViewError::Parse);
        }

        let header_is_invalid = num_required_signatures == 0
            || num_readonly_signed_static_accounts >= num_required_signatures
            || num_readonly_unsigned_static_accounts
                > num_static_account_keys.wrapping_sub(num_required_signatures);
        let signatures_are_invalid = num_required_signatures > MAX_SIGNATURES_PER_PACKET
            || num_static_account_keys < num_required_signatures;
        let addresses_are_invalid =
            num_static_account_keys == 0 || num_static_account_keys > MAX_V1_STATIC_ACCOUNTS;
        let heap_size_is_invalid = heap_size.is_some_and(|heap_size| {
            !(MIN_V1_HEAP_SIZE..=MAX_V1_HEAP_SIZE).contains(&heap_size)
                || !heap_size.is_multiple_of(1024)
        });
        if header_is_invalid
            || signatures_are_invalid
            || addresses_are_invalid
            || heap_size_is_invalid
            || instruction_sanitize_error
        {
            return Err(TransactionViewError::Sanitize);
        }

        Ok(Self {
            bytes,
            message_version: MessageVersion::V1,
            num_signatures: num_required_signatures,
            signatures_offset,
            num_required_signatures,
            num_readonly_signed_static_accounts,
            num_readonly_unsigned_static_accounts,
            num_static_account_keys,
            static_account_keys_offset,
            recent_blockhash_offset,
            num_instructions,
            instructions_offset,
            instruction_payloads_offset,
            instruction_layout: InstructionLayout::V1,
            num_address_table_lookups: 0,
            address_table_lookups_offset: 0,
            total_writable_lookup_accounts: 0,
            total_readonly_lookup_accounts: 0,
            transaction_config_mask,
            transaction_config_values_offset,
        })
    }

    pub const fn data(&self) -> &'a [u8] {
        self.bytes
    }

    pub const fn message_version(&self) -> MessageVersion {
        self.message_version
    }

    pub const fn num_signatures(&self) -> u8 {
        self.num_signatures
    }

    pub fn signatures(&self) -> &'a [[u8; SIGNATURE_BYTES]] {
        array_slice(
            self.bytes,
            self.signatures_offset,
            usize::from(self.num_signatures),
        )
    }

    pub const fn num_required_signatures(&self) -> u8 {
        self.num_required_signatures
    }

    pub const fn num_readonly_signed_static_accounts(&self) -> u8 {
        self.num_readonly_signed_static_accounts
    }

    pub const fn num_readonly_unsigned_static_accounts(&self) -> u8 {
        self.num_readonly_unsigned_static_accounts
    }

    pub const fn num_static_account_keys(&self) -> u8 {
        self.num_static_account_keys
    }

    pub fn static_account_keys(&self) -> &'a [[u8; PUBKEY_BYTES]] {
        array_slice(
            self.bytes,
            self.static_account_keys_offset,
            usize::from(self.num_static_account_keys),
        )
    }

    pub fn recent_blockhash(&self) -> &'a [u8; BLOCKHASH_BYTES] {
        self.bytes[self.recent_blockhash_offset..self.recent_blockhash_offset + BLOCKHASH_BYTES]
            .try_into()
            .expect("validated recent blockhash remains in bounds")
    }

    pub const fn num_instructions(&self) -> u16 {
        self.num_instructions
    }

    pub const fn num_address_table_lookups(&self) -> u8 {
        self.num_address_table_lookups
    }

    pub const fn total_writable_lookup_accounts(&self) -> u16 {
        self.total_writable_lookup_accounts
    }

    pub const fn total_readonly_lookup_accounts(&self) -> u16 {
        self.total_readonly_lookup_accounts
    }

    pub const fn instructions_iter(&self) -> SanitizedInstructionIterator<'a> {
        SanitizedInstructionIterator {
            bytes: self.bytes,
            header_offset: self.instructions_offset,
            payload_offset: self.instruction_payloads_offset,
            remaining: self.num_instructions,
            layout: self.instruction_layout,
        }
    }

    pub const fn transaction_config(&self) -> Option<SanitizedTransactionConfigView<'a>> {
        if matches!(self.message_version, MessageVersion::V1) {
            Some(SanitizedTransactionConfigView {
                bytes: self.bytes,
                mask: self.transaction_config_mask,
                values_offset: self.transaction_config_values_offset,
            })
        } else {
            None
        }
    }

    pub const fn address_table_lookup_iter(&self) -> SanitizedAddressTableLookupIterator<'a> {
        SanitizedAddressTableLookupIterator {
            bytes: self.bytes,
            offset: self.address_table_lookups_offset,
            remaining: self.num_address_table_lookups,
        }
    }
}

impl fmt::Debug for SanitizedTransactionView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedTransactionView")
            .field("message_version", &self.message_version)
            .field("num_signatures", &self.num_signatures)
            .field("num_required_signatures", &self.num_required_signatures)
            .field("num_static_account_keys", &self.num_static_account_keys)
            .field("num_instructions", &self.num_instructions)
            .field("num_address_table_lookups", &self.num_address_table_lookups)
            .field(
                "total_writable_lookup_accounts",
                &self.total_writable_lookup_accounts,
            )
            .field(
                "total_readonly_lookup_accounts",
                &self.total_readonly_lookup_accounts,
            )
            .finish()
    }
}

impl SanitizedTransactionConfigView<'_> {
    pub const fn mask(&self) -> u32 {
        self.mask
    }

    pub fn priority_fee_lamports(&self) -> Option<u64> {
        (self.mask & V1_CONFIG_PRIORITY_FEE == V1_CONFIG_PRIORITY_FEE)
            .then(|| read_u64_le(self.bytes, self.values_offset))
    }

    pub fn compute_unit_limit(&self) -> Option<u32> {
        (self.mask & V1_CONFIG_COMPUTE_UNIT_LIMIT != 0)
            .then(|| read_u32_le(self.bytes, self.offset_after_priority_fee()))
    }

    pub fn loaded_accounts_data_size_limit(&self) -> Option<u32> {
        (self.mask & V1_CONFIG_LOADED_ACCOUNTS_DATA_SIZE != 0)
            .then(|| read_u32_le(self.bytes, self.offset_after_compute_unit_limit()))
    }

    pub fn requested_heap_size(&self) -> Option<u32> {
        (self.mask & V1_CONFIG_HEAP_SIZE != 0)
            .then(|| read_u32_le(self.bytes, self.offset_after_loaded_accounts_data_size()))
    }

    fn offset_after_priority_fee(&self) -> usize {
        self.values_offset
            + usize::from(self.mask & V1_CONFIG_PRIORITY_FEE == V1_CONFIG_PRIORITY_FEE)
                * size_of::<u64>()
    }

    fn offset_after_compute_unit_limit(&self) -> usize {
        self.offset_after_priority_fee()
            + usize::from(self.mask & V1_CONFIG_COMPUTE_UNIT_LIMIT != 0) * size_of::<u32>()
    }

    fn offset_after_loaded_accounts_data_size(&self) -> usize {
        self.offset_after_compute_unit_limit()
            + usize::from(self.mask & V1_CONFIG_LOADED_ACCOUNTS_DATA_SIZE != 0) * size_of::<u32>()
    }
}

impl<'a> Iterator for SanitizedInstructionIterator<'a> {
    type Item = SanitizedInstructionView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (program_id_index, accounts, data) = match self.layout {
            InstructionLayout::LegacyAndV0 => {
                let program_id_index = read_byte_at(self.bytes, &mut self.header_offset)?;
                let num_accounts = read_compact_u16_at(self.bytes, &mut self.header_offset)?;
                let accounts = read_bytes_at(
                    self.bytes,
                    &mut self.header_offset,
                    usize::from(num_accounts),
                )?;
                let data_len = read_compact_u16_at(self.bytes, &mut self.header_offset)?;
                let data =
                    read_bytes_at(self.bytes, &mut self.header_offset, usize::from(data_len))?;
                (program_id_index, accounts, data)
            }
            InstructionLayout::V1 => {
                let program_id_index = read_byte_at(self.bytes, &mut self.header_offset)?;
                let num_accounts = read_byte_at(self.bytes, &mut self.header_offset)?;
                let data_len = read_u16_le_at(self.bytes, &mut self.header_offset)?;
                let accounts = read_bytes_at(
                    self.bytes,
                    &mut self.payload_offset,
                    usize::from(num_accounts),
                )?;
                let data =
                    read_bytes_at(self.bytes, &mut self.payload_offset, usize::from(data_len))?;
                (program_id_index, accounts, data)
            }
        };
        self.remaining -= 1;
        Some(SanitizedInstructionView {
            program_id_index,
            accounts,
            data,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for SanitizedInstructionIterator<'_> {
    fn len(&self) -> usize {
        usize::from(self.remaining)
    }
}

impl fmt::Debug for SanitizedInstructionIterator<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.clone()).finish()
    }
}

impl<'a> Iterator for SanitizedAddressTableLookupIterator<'a> {
    type Item = SanitizedAddressTableLookup<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let account_key: &[u8; PUBKEY_BYTES] =
            read_bytes_at(self.bytes, &mut self.offset, PUBKEY_BYTES)?
                .try_into()
                .ok()?;
        let num_writable = read_compact_u16_at(self.bytes, &mut self.offset)?;
        let writable_indexes =
            read_bytes_at(self.bytes, &mut self.offset, usize::from(num_writable))?;
        let num_readonly = read_compact_u16_at(self.bytes, &mut self.offset)?;
        let readonly_indexes =
            read_bytes_at(self.bytes, &mut self.offset, usize::from(num_readonly))?;
        self.remaining -= 1;
        Some(SanitizedAddressTableLookup {
            account_key,
            writable_indexes,
            readonly_indexes,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for SanitizedAddressTableLookupIterator<'_> {
    fn len(&self) -> usize {
        usize::from(self.remaining)
    }
}

impl fmt::Debug for SanitizedAddressTableLookupIterator<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.clone()).finish()
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn read_byte(&mut self) -> Result<u8, TransactionViewError> {
        read_byte_at(self.bytes, &mut self.offset).ok_or(TransactionViewError::Parse)
    }

    fn read_compact_u16(&mut self) -> Result<u16, TransactionViewError> {
        read_compact_u16_at(self.bytes, &mut self.offset).ok_or(TransactionViewError::Parse)
    }

    fn read_u32_le(&mut self) -> Result<u32, TransactionViewError> {
        let bytes: [u8; 4] = self
            .read_bytes(size_of::<u32>())?
            .try_into()
            .map_err(|_| TransactionViewError::Parse)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], TransactionViewError> {
        read_bytes_at(self.bytes, &mut self.offset, len).ok_or(TransactionViewError::Parse)
    }

    fn skip(&mut self, len: usize) -> Result<(), TransactionViewError> {
        self.read_bytes(len).map(|_| ())
    }

    fn require_remaining(&self, len: usize) -> Result<(), TransactionViewError> {
        if len <= self.bytes.len().saturating_sub(self.offset) {
            Ok(())
        } else {
            Err(TransactionViewError::Parse)
        }
    }
}

fn read_byte_at(bytes: &[u8], offset: &mut usize) -> Option<u8> {
    let value = bytes.get(*offset).copied()?;
    *offset = offset.checked_add(1)?;
    Some(value)
}

fn read_compact_u16_at(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let first = *bytes.get(*offset)?;
    if first & 0x80 == 0 {
        *offset = offset.checked_add(1)?;
        return Some(u16::from(first));
    }
    let second = *bytes.get(offset.checked_add(1)?)?;
    if second == 0 || second & 0x80 != 0 {
        return None;
    }
    *offset = offset.checked_add(2)?;
    Some(u16::from(first & 0x7f) | (u16::from(second & 0x7f) << 7))
}

fn read_u16_le_at(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let value = u16::from_le_bytes(
        read_bytes_at(bytes, offset, size_of::<u16>())?
            .try_into()
            .ok()?,
    );
    Some(value)
}

fn read_bytes_at<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    let value = bytes.get(*offset..end)?;
    *offset = end;
    Some(value)
}

fn array_slice<const N: usize>(bytes: &[u8], offset: usize, count: usize) -> &[[u8; N]] {
    let byte_len = count
        .checked_mul(N)
        .expect("validated transaction array length cannot overflow");
    let region = bytes
        .get(offset..offset + byte_len)
        .expect("validated transaction array remains in bounds");
    // SAFETY: `[u8; N]` has alignment one, every bit pattern is valid, the
    // constructor bounds-checked this exact region, and the returned lifetime
    // is tied to the immutable input bytes.
    unsafe { std::slice::from_raw_parts(region.as_ptr().cast::<[u8; N]>(), count) }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + size_of::<u32>()]
            .try_into()
            .expect("validated V1 config value remains in bounds"),
    )
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + size_of::<u64>()]
            .try_into()
            .expect("validated V1 config value remains in bounds"),
    )
}
