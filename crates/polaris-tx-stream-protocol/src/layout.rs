//! Public frame sizes; no shared-memory mapping API.
pub const FRAME_HEADER_BYTES: usize = 256;
pub const SLOT_STRIDE_BYTES: usize = 12_288;
pub const FRAME_BODY_CAPACITY: usize = SLOT_STRIDE_BYTES - FRAME_HEADER_BYTES;
pub const LAYOUT_VERSION_V1: u16 = 1;
