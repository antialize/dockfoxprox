//! An aligned atomic u64, on a cache line boundary to avoid false sharing
//! with other atomics in the `State`. `align(64)` alone is enough: the
//! compiler inserts tail padding so the struct is a full cache line.
use std::{ops::Deref, sync::atomic::AtomicU64};

#[derive(Default, Debug)]
#[repr(C, align(64))]
pub struct AlignedAtomicU64(AtomicU64);

impl AlignedAtomicU64 {
    /// Create a new `AlignedAtomicU64` with the given initial value.
    pub fn new(val: u64) -> Self {
        Self(AtomicU64::new(val))
    }
}

// Guard against future fields silently doubling the size by overflowing the
// 64-byte cache line.
const _: () = assert!(std::mem::size_of::<AlignedAtomicU64>() == 64);

impl Deref for AlignedAtomicU64 {
    type Target = AtomicU64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
