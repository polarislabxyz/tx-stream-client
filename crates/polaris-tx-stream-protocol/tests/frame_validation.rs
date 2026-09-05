use {
    polaris_tx_stream_protocol::{
        frame::{
            checked_frame_body_length, FrameEncoder, FrameFlags, FrameHeaderV1, FrameMetadataV1,
            FrameParts, FrameValidationError, MessageVersion, ValidatedFrame, FRAME_MAGIC_V1,
            FRAME_SCHEMA_VERSION_V1,
        },
        layout::{FRAME_BODY_CAPACITY, FRAME_HEADER_BYTES, LAYOUT_VERSION_V1, SLOT_STRIDE_BYTES},
    },
    proptest::prelude::*,
};

const V1_DEFAULT: &[u8] = include_bytes!("../../../fixtures/transactions/v1_default.bin");
const V1_ALL_CONFIG: &[u8] = include_bytes!("../../../fixtures/transactions/v1_all_config.bin");
const V1_1233: &[u8] = include_bytes!("../../../fixtures/transactions/v1_1233.bin");
const V1_4096: &[u8] = include_bytes!("../../../fixtures/transactions/v1_4096.bin");
const V1_4097: &[u8] = include_bytes!("../../../fixtures/transactions/v1_4097.bin");
const V1_TRUNCATED: &[u8] = include_bytes!("../../../fixtures/transactions/v1_truncated.bin");

#[test]
fn frame_header_v1_golden_bytes() {
    let header = FrameHeaderV1 {
        message_version: MessageVersion::V0,
        earliest_source: 3,
        flags: FrameFlags::NATURAL_READY
            | FrameFlags::LEADER_SIGNATURE_VERIFIED
            | FrameFlags::MERKLE_PROOF_VERIFIED
            | FrameFlags::TRANSACTION_SANITIZED
            | FrameFlags::LUT_RESOLVED
            | FrameFlags::DATA_SET_START_VALID
            | FrameFlags::DATA_SET_END_VALID,
        body_length: 349,
        atomic_word_count: 76,
        producer_epoch: 0x0102_0304_0506_0708,
        canonical_sequence: 0x1112_1314_1516_1718,
        slot: 424_200,
        prefix_generation: 9,
        contributing_source_mask: 0b101,
        first_data_shred_index: 40,
        last_data_shred_index: 42,
        data_set_starting_shred_index: 32,
        completed_data_set_ending_shred_index_exclusive: 64,
        entry_ordinal: 7,
        transaction_ordinal: 11,
        transaction_offset: 0,
        transaction_length: 253,
        loaded_writable_offset: 253,
        loaded_writable_length: 64,
        loaded_readonly_offset: 317,
        loaded_readonly_length: 32,
        loaded_writable_count: 2,
        loaded_readonly_count: 1,
        final_padding_bytes: 3,
        first_shred_receive_ns: 10_000,
        transaction_complete_ns: 10_100,
        lut_resolution_complete_ns: 10_150,
        publication_start_ns: 10_200,
    };
    let actual = header.encode();
    let mut expected = [0_u8; FRAME_HEADER_BYTES];
    expected[64..72].copy_from_slice(&FRAME_MAGIC_V1);
    put_u16(&mut expected, 72, FRAME_SCHEMA_VERSION_V1);
    put_u16(&mut expected, 74, LAYOUT_VERSION_V1);
    put_u16(&mut expected, 76, FRAME_HEADER_BYTES as u16);
    expected[78] = 1;
    expected[79] = 3;
    put_u32(&mut expected, 80, header.flags.bits());
    put_u32(&mut expected, 84, 349);
    put_u32(&mut expected, 88, 76);
    put_u64(&mut expected, 96, header.producer_epoch);
    put_u64(&mut expected, 104, header.canonical_sequence);
    put_u64(&mut expected, 112, header.slot);
    put_u64(&mut expected, 120, header.prefix_generation);
    put_u64(&mut expected, 128, header.contributing_source_mask);
    put_u32(&mut expected, 136, 40);
    put_u32(&mut expected, 140, 42);
    put_u32(&mut expected, 144, 32);
    put_u32(&mut expected, 148, 64);
    put_u32(&mut expected, 152, 7);
    put_u32(&mut expected, 156, 11);
    put_u32(&mut expected, 160, 0);
    put_u32(&mut expected, 164, 253);
    put_u32(&mut expected, 168, 253);
    put_u32(&mut expected, 172, 64);
    put_u32(&mut expected, 176, 317);
    put_u32(&mut expected, 180, 32);
    put_u16(&mut expected, 184, 2);
    put_u16(&mut expected, 186, 1);
    expected[188] = 3;
    put_u64(&mut expected, 192, 10_000);
    put_u64(&mut expected, 200, 10_100);
    put_u64(&mut expected, 208, 10_150);
    put_u64(&mut expected, 216, 10_200);

    assert_eq!(actual, expected);
    assert!(actual[..64].iter().all(|byte| *byte == 0));
    assert!(actual[224..].iter().all(|byte| *byte == 0));
    assert_eq!(FrameHeaderV1::decode(&actual).unwrap(), header);
}

#[test]
fn invalid_body_regions_fail_closed() {
    let (canonical, frame_bytes) = encoded_multi_lut_frame();
    let canonical_header = FrameHeaderV1::decode(&canonical).unwrap();
    let mut cases = Vec::new();

    cases.push(corrupt(
        "overlapping_regions",
        &canonical,
        frame_bytes,
        |bytes| put_u32(bytes, 168, canonical_header.transaction_length - 1),
        FrameValidationError::InvalidBodyRegions,
    ));
    cases.push(corrupt(
        "offset_overflow",
        &canonical,
        frame_bytes,
        |bytes| put_u32(bytes, 164, u32::MAX),
        FrameValidationError::InvalidBodyRegions,
    ));
    cases.push(corrupt(
        "body_overrun",
        &canonical,
        frame_bytes,
        |bytes| put_u32(bytes, 84, FRAME_BODY_CAPACITY as u32 + 1),
        FrameValidationError::FrameTooLarge,
    ));
    cases.push(corrupt(
        "key_length_count_mismatch",
        &canonical,
        frame_bytes,
        |bytes| put_u16(bytes, 184, 2),
        FrameValidationError::InvalidLoadedKeyLength,
    ));
    cases.push(corrupt(
        "loaded_keys_on_legacy",
        &canonical,
        frame_bytes,
        |bytes| bytes[78] = MessageVersion::Legacy as u8,
        FrameValidationError::InvalidLoadedKeysForVersion,
    ));
    cases.push(corrupt(
        "unknown_flags",
        &canonical,
        frame_bytes,
        |bytes| {
            let flags = u32::from_le_bytes(bytes[80..84].try_into().unwrap());
            put_u32(bytes, 80, flags | (1 << 31));
        },
        FrameValidationError::UnknownFlags(canonical_header.flags.bits() | (1 << 31)),
    ));
    cases.push(corrupt(
        "excess_atomic_word_count",
        &canonical,
        frame_bytes,
        |bytes| put_u32(bytes, 88, canonical_header.atomic_word_count + 1),
        FrameValidationError::InvalidAtomicWordCount,
    ));
    cases.push(corrupt(
        "nonzero_final_padding",
        &canonical,
        frame_bytes,
        |bytes| {
            let padding_start = FRAME_HEADER_BYTES + canonical_header.body_length as usize;
            bytes[padding_start] = 1;
        },
        FrameValidationError::NonzeroFinalPadding,
    ));

    for (name, bytes, expected) in cases {
        assert_eq!(ValidatedFrame::parse(&bytes), Err(expected), "{name}");
    }

    let transaction = include_bytes!("../../../fixtures/transactions/v0_multi_lut.bin");
    let writable = [[0x20; 32], [0x22; 32]];
    let readonly = [[0x21; 32], [0x2d; 32], [0x2e; 32]];
    let mut output = [0_u8; SLOT_STRIDE_BYTES];
    assert_eq!(
        FrameEncoder::encode_into(
            &metadata(MessageVersion::V0),
            FrameParts {
                transaction,
                loaded_writable: &writable,
                loaded_readonly: &readonly,
            },
            &mut output,
        ),
        Err(FrameValidationError::LoadedAddressCountMismatch)
    );
}

#[test]
fn compact_body_round_trips_original_bytes_and_loaded_groups() {
    let (encoded, frame_bytes) = encoded_multi_lut_frame();
    let frame = ValidatedFrame::parse(&encoded[..frame_bytes]).unwrap();
    let transaction = include_bytes!("../../../fixtures/transactions/v0_multi_lut.bin");
    assert_eq!(frame.transaction_bytes(), transaction);
    assert_eq!(
        frame.loaded_writable_bytes(),
        [[0x20; 32], [0x22; 32], [0x29; 32]].concat()
    );
    assert_eq!(
        frame.loaded_readonly_bytes(),
        [[0x21; 32], [0x2d; 32], [0x2e; 32]].concat()
    );
    let body_end = FRAME_HEADER_BYTES + frame.header().body_length as usize;
    assert!(encoded[body_end..frame_bytes].iter().all(|byte| *byte == 0));
}

#[test]
fn v1_canonical_frames_preserve_exact_wire_and_trailing_signature() {
    for transaction in [V1_DEFAULT, V1_ALL_CONFIG, V1_1233, V1_4096] {
        let mut encoded = [0_u8; SLOT_STRIDE_BYTES];
        let frame_bytes = FrameEncoder::encode_into(
            &metadata(MessageVersion::V1),
            FrameParts {
                transaction,
                loaded_writable: &[],
                loaded_readonly: &[],
            },
            &mut encoded,
        )
        .unwrap();
        let frame = ValidatedFrame::parse(&encoded[..frame_bytes]).unwrap();

        assert_eq!(frame.header().message_version, MessageVersion::V1);
        assert_eq!(
            frame.header().transaction_length as usize,
            transaction.len()
        );
        assert_eq!(frame.header().loaded_writable_count, 0);
        assert_eq!(frame.header().loaded_readonly_count, 0);
        assert_eq!(frame.transaction_bytes(), transaction);
        assert_eq!(frame.transaction_view().signatures().len(), 1);
        assert_eq!(
            frame.transaction_view().signatures()[0].as_slice(),
            &transaction[transaction.len() - 64..]
        );
        assert!(frame.loaded_writable_bytes().is_empty());
        assert!(frame.loaded_readonly_bytes().is_empty());
        assert!(frame_bytes <= SLOT_STRIDE_BYTES);
    }
}

#[test]
fn v1_canonical_frames_reject_inconsistent_metadata_and_invalid_wires() {
    let mut output = [0_u8; SLOT_STRIDE_BYTES];
    assert_eq!(
        FrameEncoder::encode_into(
            &metadata(MessageVersion::V0),
            FrameParts {
                transaction: V1_DEFAULT,
                loaded_writable: &[],
                loaded_readonly: &[],
            },
            &mut output,
        ),
        Err(FrameValidationError::MessageVersionMismatch)
    );
    assert_eq!(
        FrameEncoder::encode_into(
            &metadata(MessageVersion::V1),
            FrameParts {
                transaction: V1_DEFAULT,
                loaded_writable: &[[0x20; 32]],
                loaded_readonly: &[],
            },
            &mut output,
        ),
        Err(FrameValidationError::LoadedAddressCountMismatch)
    );
    for transaction in [V1_4097, V1_TRUNCATED] {
        assert_eq!(
            FrameEncoder::encode_into(
                &metadata(MessageVersion::V1),
                FrameParts {
                    transaction,
                    loaded_writable: &[],
                    loaded_readonly: &[],
                },
                &mut output,
            ),
            Err(FrameValidationError::TransactionParse)
        );
    }

    let frame_bytes = FrameEncoder::encode_into(
        &metadata(MessageVersion::V1),
        FrameParts {
            transaction: V1_DEFAULT,
            loaded_writable: &[],
            loaded_readonly: &[],
        },
        &mut output,
    )
    .unwrap();
    let mut inconsistent = output[..frame_bytes].to_vec();
    put_u16(&mut inconsistent, 184, 1);
    assert_eq!(
        ValidatedFrame::parse(&inconsistent),
        Err(FrameValidationError::InvalidLoadedKeyLength)
    );
}

#[test]
fn maximum_protocol_envelope_fits_v1_slot() {
    assert_eq!(checked_frame_body_length(1_232, 255, 0), Ok(9_392));
    assert_eq!(checked_frame_body_length(4_096, 0, 0), Ok(4_096));
    assert_eq!(
        checked_frame_body_length(FRAME_BODY_CAPACITY + 1, 0, 0),
        Err(FrameValidationError::FrameTooLarge)
    );
    assert_eq!(
        checked_frame_body_length(FRAME_BODY_CAPACITY, 0, 0),
        Ok(FRAME_BODY_CAPACITY)
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_corruption_never_escapes_bounds(
        mutation_kind in 0_u8..18,
        selector in any::<u16>(),
        value in any::<u64>(),
    ) {
        let (canonical, frame_bytes) = encoded_multi_lut_frame();
        let mut bytes = canonical[..frame_bytes].to_vec();
        match mutation_kind {
            0 => put_u32(&mut bytes, 80, value as u32),
            1 => put_u32(&mut bytes, 84, value as u32),
            2 => put_u32(&mut bytes, 88, value as u32),
            3 => put_u16(&mut bytes, 72, value as u16),
            4 => put_u16(&mut bytes, 74, value as u16),
            5 => put_u16(&mut bytes, 76, value as u16),
            6 => bytes[78] = value as u8,
            7 => {
                let offsets = [160, 164, 168, 172, 176, 180];
                put_u32(&mut bytes, offsets[usize::from(selector) % offsets.len()], value as u32);
            }
            8 => {
                let offsets = [184, 186];
                put_u16(&mut bytes, offsets[usize::from(selector) % offsets.len()], value as u16);
            }
            9 => bytes[188] = value as u8,
            10 => {
                let offsets = [192, 200, 208, 216];
                put_u64(&mut bytes, offsets[usize::from(selector) % offsets.len()], value);
            }
            11 => {
                let reserved = [8, 63, 92, 95, 189, 191, 224, 255];
                bytes[reserved[usize::from(selector) % reserved.len()]] = value as u8;
            }
            12 => put_u64(&mut bytes, 0, value),
            13 => {
                let body_offset = FRAME_HEADER_BYTES
                    + usize::from(selector) % (frame_bytes - FRAME_HEADER_BYTES);
                bytes[body_offset] = value as u8;
            }
            14 => {
                let truncated = usize::from(selector) % (frame_bytes + 1);
                bytes.truncate(truncated);
            }
            15 => {
                let extra = usize::from(selector) % (SLOT_STRIDE_BYTES - frame_bytes + 1);
                bytes.resize(frame_bytes + extra, value as u8);
            }
            16 => {
                let offset = usize::from(selector) % bytes.len();
                bytes[offset] ^= value as u8;
            }
            _ => {
                let offsets = [96, 104, 112, 120, 128, 136, 140, 144, 148, 152, 156];
                let offset = offsets[usize::from(selector) % offsets.len()];
                if offset >= 136 {
                    put_u32(&mut bytes, offset, value as u32);
                } else {
                    put_u64(&mut bytes, offset, value);
                }
            }
        }

        let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ValidatedFrame::parse(&bytes).map(|frame| {
                (
                    frame.header().atomic_word_count,
                    frame.transaction_bytes().len(),
                    frame.loaded_writable_bytes().len(),
                    frame.loaded_readonly_bytes().len(),
                )
            })
        }));
        prop_assert!(parsed.is_ok(), "parser panicked for mutation kind {mutation_kind}");
        if let Ok(Ok((words, transaction, writable, readonly))) = parsed {
            prop_assert!(usize::try_from(words).unwrap() <= SLOT_STRIDE_BYTES / 8);
            prop_assert!(transaction > 0);
            prop_assert!(writable + readonly <= FRAME_BODY_CAPACITY);
        }
    }
}

fn encoded_multi_lut_frame() -> ([u8; SLOT_STRIDE_BYTES], usize) {
    let transaction = include_bytes!("../../../fixtures/transactions/v0_multi_lut.bin");
    let writable = [[0x20; 32], [0x22; 32], [0x29; 32]];
    let readonly = [[0x21; 32], [0x2d; 32], [0x2e; 32]];
    let mut output = [0_u8; SLOT_STRIDE_BYTES];
    let frame_bytes = FrameEncoder::encode_into(
        &metadata(MessageVersion::V0),
        FrameParts {
            transaction,
            loaded_writable: &writable,
            loaded_readonly: &readonly,
        },
        &mut output,
    )
    .unwrap();
    (output, frame_bytes)
}

fn metadata(message_version: MessageVersion) -> FrameMetadataV1 {
    FrameMetadataV1 {
        message_version,
        earliest_source: 1,
        flags: FrameFlags::NATURAL_READY
            | FrameFlags::LEADER_SIGNATURE_VERIFIED
            | FrameFlags::MERKLE_PROOF_VERIFIED
            | FrameFlags::TRANSACTION_SANITIZED
            | FrameFlags::LUT_RESOLVED
            | FrameFlags::DATA_SET_START_VALID
            | FrameFlags::DATA_SET_END_VALID,
        producer_epoch: 7,
        canonical_sequence: 11,
        slot: 424_200,
        prefix_generation: 3,
        contributing_source_mask: 1,
        first_data_shred_index: 0,
        last_data_shred_index: 31,
        data_set_starting_shred_index: 0,
        completed_data_set_ending_shred_index_exclusive: 32,
        entry_ordinal: 2,
        transaction_ordinal: 5,
        first_shred_receive_ns: 1_000,
        transaction_complete_ns: 1_100,
        lut_resolution_complete_ns: 1_150,
        publication_start_ns: 1_200,
    }
}

fn corrupt(
    name: &'static str,
    canonical: &[u8; SLOT_STRIDE_BYTES],
    frame_bytes: usize,
    mutation: impl FnOnce(&mut [u8]),
    expected: FrameValidationError,
) -> (&'static str, Vec<u8>, FrameValidationError) {
    let mut bytes = canonical[..frame_bytes].to_vec();
    mutation(&mut bytes);
    (name, bytes, expected)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
