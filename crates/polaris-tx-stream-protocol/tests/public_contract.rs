use polaris_tx_stream_protocol::{
    frame::*, layout::SLOT_STRIDE_BYTES, StreamMode, StreamValidator,
};

#[test]
fn independent_goldens_match_producer_encoder() {
    for (bytes, version, tx, count) in [
        (
            &include_bytes!("../../../fixtures/canonical-v1-legacy.bin")[..],
            MessageVersion::Legacy,
            &include_bytes!("../../../fixtures/transactions/legacy.bin")[..],
            0,
        ),
        (
            &include_bytes!("../../../fixtures/canonical-v1-v0-lut.bin")[..],
            MessageVersion::V0,
            &include_bytes!("../../../fixtures/transactions/v0_multi_lut.bin")[..],
            3,
        ),
        (
            &include_bytes!("../../../fixtures/canonical-v1-v1.bin")[..],
            MessageVersion::V1,
            &include_bytes!("../../../fixtures/transactions/v1_default.bin")[..],
            0,
        ),
    ] {
        let frame = ValidatedFrame::parse(bytes).unwrap();
        assert_eq!(frame.transaction_bytes(), tx);
        assert_eq!(frame.header().message_version, version);
        let metadata = FrameMetadataV1 {
            message_version: version,
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
            slot: 424200,
            prefix_generation: 3,
            contributing_source_mask: 1,
            first_data_shred_index: 0,
            last_data_shred_index: 31,
            data_set_starting_shred_index: 0,
            completed_data_set_ending_shred_index_exclusive: 32,
            entry_ordinal: 2,
            transaction_ordinal: 5,
            first_shred_receive_ns: 1000,
            transaction_complete_ns: 1100,
            lut_resolution_complete_ns: 1150,
            publication_start_ns: 1200,
        };
        let writable = vec![[1; 32]; count];
        let readonly = vec![[2; 32]; count];
        let mut output = [0; SLOT_STRIDE_BYTES];
        let len = FrameEncoder::encode_into(
            &metadata,
            FrameParts {
                transaction: tx,
                loaded_writable: &writable,
                loaded_readonly: &readonly,
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(&output[..len], bytes);
        assert_eq!(frame.loaded_writable_bytes(), vec![1; count * 32]);
        assert_eq!(frame.loaded_readonly_bytes(), vec![2; count * 32]);
    }
}

#[test]
fn stream_rejects_gaps_epoch_changes_trailing_and_corruption() {
    let original = include_bytes!("../../../fixtures/canonical-v1-legacy.bin");
    for (offset, value) in [(104, 13u64), (96, 8)] {
        let mut validator = StreamValidator::new(StreamMode::MatchAll);
        validator.validate_resolved(original).unwrap();
        let mut bytes = original.to_vec();
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(validator.validate_resolved(&bytes).is_err());
    }
    let mut filtered = StreamValidator::new(StreamMode::Filtered);
    filtered.validate_resolved(original).unwrap();
    let mut bytes = original.to_vec();
    bytes[104..112].copy_from_slice(&13u64.to_le_bytes());
    filtered.validate_resolved(&bytes).unwrap();
    assert!(filtered.validate_resolved(&bytes).is_err());
    for len in 0..original.len() {
        assert!(ValidatedFrame::parse(&original[..len]).is_err());
    }
    bytes.push(0);
    assert!(StreamValidator::new(StreamMode::MatchAll)
        .validate_resolved(&bytes)
        .is_err());
}
