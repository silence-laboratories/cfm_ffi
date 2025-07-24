use crate::constants::{LAMBDA_BYTES, MASK_BYTES};
use bytemuck::{AnyBitPattern, NoUninit};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

/// External H2 output representation
pub type Hash2Bytes = [u8; LAMBDA_BYTES * 2];

/// External H3 output representation
pub type Hash3Bytes = [u8; MASK_BYTES * 2];

/// POINT_BYTES_SIZE for RistrettoPoint representation
pub const POINT_BYTES_SIZE: usize = 32;

/// External RistrettoPoint representation
pub type PointBytes = [u8; POINT_BYTES_SIZE];

/// External Scalar representation
pub type ScalarBytes = [u8; 32];

/// Encode RistrettoPoint
pub fn encode_point(p: &RistrettoPoint) -> PointBytes {
    p.compress().to_bytes()
}

/// Decode RistrettoPoint
pub fn decode_point(bytes: &PointBytes) -> Option<RistrettoPoint> {
    let Ok(compressed_point) = CompressedRistretto::from_slice(bytes) else {
        return None;
    };
    compressed_point.decompress()
}

/// Encode a Scalar
pub fn encode_scalar(s: &Scalar) -> ScalarBytes {
    s.to_bytes()
}

/// Decode a Scalar
pub fn decode_scalar(bytes: &ScalarBytes) -> Option<Scalar> {
    let s = Scalar::from_canonical_bytes(*bytes);
    if s.is_some().unwrap_u8() == 1 {
        Some(s.unwrap())
    } else {
        None
    }
}

/// XOR two arbitrary arrays
pub fn xor_array<T, const N: usize>(a: [T; N], b: [T; N]) -> [T; N]
where
    T: std::ops::BitXor<Output = T> + Copy,
{
    std::array::from_fn(|i| a[i] ^ b[i])
}

#[derive(Debug, Zeroize, PartialEq)]
pub struct ZS<T: AnyBitPattern + NoUninit> {
    buffer: Vec<u8>,
    marker: PhantomData<T>,
}

impl<T> From<Box<T>> for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn from(b: Box<T>) -> Self {
        assert!(mem::align_of::<T>() == 1);

        let s = mem::size_of::<T>();
        let r = Box::into_raw(b);
        let v = unsafe { Vec::<u8>::from_raw_parts(r as *mut u8, s, s) };

        Self {
            buffer: v,
            marker: PhantomData,
        }
    }
}

impl<T> Default for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn default() -> Self {
        Self {
            buffer: vec![0u8; mem::size_of::<T>()],
            marker: PhantomData,
        }
    }
}

impl<T> Deref for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        bytemuck::from_bytes(&self.buffer)
    }
}

impl<T> DerefMut for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        bytemuck::from_bytes_mut(&mut self.buffer)
    }
}

impl<T> Clone for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            marker: PhantomData,
        }
    }
}

impl<T> serde::Serialize for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.buffer.serialize(serializer)
    }
}

impl<'de, T> serde::Deserialize<'de> for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let buffer = <Vec<u8>>::deserialize(deserializer)?;

        if buffer.len() != mem::size_of::<T>() {
            return Err(serde::de::Error::invalid_length(buffer.len(), &"bytes"));
        }

        Ok(Self {
            buffer,
            marker: PhantomData,
        })
    }
}
