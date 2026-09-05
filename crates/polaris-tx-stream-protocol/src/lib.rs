//! Public canonical transaction contract, exported from the producer revision.
//! No network, shared-memory, control-socket or validator dependency.
pub mod frame;
pub mod layout;
pub mod stream;
pub mod transaction;
pub mod wire;

pub use frame::ValidatedFrame as CanonicalFrameRef;
pub use stream::{CanonicalStreamMode as StreamMode, CanonicalStreamValidator as StreamValidator};
