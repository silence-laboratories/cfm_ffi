// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

/// Domain labels
pub mod constants;

/// Soft spoken Oblivious Transfer
pub mod soft_spoken;

/// Endemic 1 out of 2 Oblivious Transfer
pub mod endemic_ot;

/// Random Vector OLE
pub mod rvole;

/// Utility functions
pub mod utils {
    use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
    use std::ops::Index;

    use crate::sl_oblivious::params::consts::KAPPA_BYTES;
    use crypto_bigint::{Encoding, U128};

    /// Simple trait to extract a bit from a byte array.
    pub trait ExtractBit: Index<usize, Output = u8> {
        /// Extract a bit at given index (in little endian order) from a byte array.
        fn extract_bit(&self, idx: usize) -> bool {
            let byte_idx = idx >> 3;
            let bit_idx = idx & 0x7;
            let byte = self[byte_idx];
            let mask = 1 << bit_idx;
            (byte & mask) != 0
        }
    }

    impl ExtractBit for Vec<u8> {}
    impl<const T: usize> ExtractBit for [u8; T] {}

    pub fn bit_to_bit_mask(bit: u8) -> u8 {
        // constant time
        // outputs 0x00 if `bit == 0` and 0xFF if `bit == 1`
        -(bit as i8) as u8
    }

    pub fn scalar_from_bytes(params: DynResidueParams<2>, bytes: [u8; KAPPA_BYTES]) -> U128 {
        DynResidue::new(&U128::from_be_bytes(bytes), params).retrieve()
    }
}

pub mod params;

pub mod label;
