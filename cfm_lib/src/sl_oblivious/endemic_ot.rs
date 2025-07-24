// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::array;
use std::hint::black_box;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;
use rand::prelude::*;

use crate::sl_oblivious::{constants::ENDEMIC_OT_LABEL, params::consts::*, utils::ExtractBit};

use crate::proto::{decode_point, encode_point, PointBytes, POINT_BYTES_SIZE};
use serde::{Deserialize, Serialize};
use std::ops::Neg;

/// EndemicOT Message 1
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit, Debug, PartialEq)]
#[repr(C)]
pub struct EndemicOTMsg1 {
    // values r_0 and r_1 from OTReceiver to OTSender
    r_list: [[PointBytes; 2]; LAMBDA_C],
}

impl Default for EndemicOTMsg1 {
    fn default() -> Self {
        Self {
            r_list: [[[0u8; POINT_BYTES_SIZE]; 2]; LAMBDA_C],
        }
    }
}

/// EndemicOT Message 2
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit, Debug, PartialEq)]
#[repr(C)]
pub struct EndemicOTMsg2 {
    // values m_b_0 and m_b_1 from OTSender to OTReceiver
    m_b_list: [[PointBytes; 2]; LAMBDA_C],
}

impl Default for EndemicOTMsg2 {
    fn default() -> Self {
        Self {
            m_b_list: [[[0u8; POINT_BYTES_SIZE]; 2]; LAMBDA_C],
        }
    }
}

/// The one time pad encryption keys for a single choice.
#[derive(Debug)]
pub(crate) struct OneTimePadEncryptionKeys {
    pub(crate) rho_0: [u8; LAMBDA_C_BYTES],
    pub(crate) rho_1: [u8; LAMBDA_C_BYTES],
}

/// The output of the OT sender.
pub struct SenderOutput {
    pub(crate) otp_enc_keys: [OneTimePadEncryptionKeys; LAMBDA_C],
}

/// The output of the OT receiver.
pub struct ReceiverOutput {
    pub(crate) choice_bits: [u8; LAMBDA_C_BYTES], // LAMBDA_C bits
    pub(crate) otp_dec_keys: [[u8; LAMBDA_C_BYTES]; LAMBDA_C],
}

/// RO for EndemicOT
fn h_function(
    ro_index: usize,
    batch_index: usize,
    session_id: &[u8],
    pk: &RistrettoPoint,
) -> RistrettoPoint {
    let mut t = Transcript::new(&ENDEMIC_OT_LABEL);

    t.append_message(b"session-id", session_id);
    t.append_message(b"ro-index", &(ro_index as u16).to_be_bytes());
    t.append_message(b"batch-index", &(batch_index as u16).to_be_bytes());
    t.append_message(b"pk", pk.compress().as_bytes());

    let mut output = [0u8; 64];
    t.challenge_bytes(b"ro-bytes", &mut output);

    RistrettoPoint::from_uniform_bytes(&output)
}

/// create LAMBDA_C_BYTES ot seed
fn h_function_2(batch_index: usize, pk: &RistrettoPoint) -> [u8; LAMBDA_C_BYTES] {
    let mut t = Transcript::new(&ENDEMIC_OT_LABEL);

    t.append_message(b"batch_index", &(batch_index as u16).to_be_bytes());
    t.append_message(b"pk", pk.compress().as_bytes());

    let mut output = [0u8; LAMBDA_C_BYTES];
    t.challenge_bytes(b"ot-seed", &mut output);

    output
}

/// Sender of the Endemic OT protocol.
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
pub struct EndemicOTSender;

impl EndemicOTSender {
    /// Process EndemicOTMsg1 from OTReceiver
    pub fn process<R: RngCore + CryptoRng>(
        session_id: &[u8],
        msg1: &EndemicOTMsg1,
        msg2: &mut EndemicOTMsg2,
        rng: &mut R,
    ) -> Result<SenderOutput, &'static str> {
        let mut error = false;
        let otp_enc_keys = array::from_fn(|idx| {
            let [r_0, r_1] = &msg1.r_list[idx];

            let r_0_point = match decode_point(r_0) {
                None => {
                    error = true;
                    // return dummy Ristretto Point
                    RistrettoPoint::from_uniform_bytes(&[0u8; 64])
                }
                Some(v) => v,
            };
            let r_1_point = match decode_point(r_1) {
                None => {
                    error = true;
                    // return dummy Ristretto Point
                    RistrettoPoint::from_uniform_bytes(&[0u8; 64])
                }
                Some(v) => v,
            };

            let m_a_0 = r_0_point + h_function(0, idx, session_id, &r_1_point);
            let m_a_1 = r_1_point + h_function(1, idx, session_id, &r_0_point);

            let t_b_0 = Scalar::random(&mut *rng);
            let t_b_1 = Scalar::random(&mut *rng);

            let m_b_0 = RistrettoPoint::mul_base(&t_b_0);
            let m_b_1 = RistrettoPoint::mul_base(&t_b_1);

            msg2.m_b_list[idx] = [encode_point(&m_b_0), encode_point(&m_b_1)];

            let rho_0 = h_function_2(idx, &(m_a_0 * t_b_0));
            let rho_1 = h_function_2(idx, &(m_a_1 * t_b_1));

            OneTimePadEncryptionKeys { rho_0, rho_1 }
        });

        if error {
            return Err("Decode error");
        }

        Ok(SenderOutput { otp_enc_keys })
    }
}

/// EndemicOTReceiver
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
#[derive(Serialize, Deserialize)]
pub struct EndemicOTReceiver {
    packed_choice_bits: [u8; LAMBDA_C_BYTES],
    #[serde(with = "serde_arrays")]
    t_a_list: [Scalar; LAMBDA_C],
}

impl EndemicOTReceiver {
    /// Create a new instance of the EndemicOT receiver.
    pub fn new<R: RngCore + CryptoRng>(
        session_id: &[u8],
        msg1: &mut EndemicOTMsg1,
        rng: &mut R,
    ) -> Self {
        let next_state = Self {
            packed_choice_bits: rng.gen(),
            t_a_list: array::from_fn(|_| Scalar::random(&mut *rng)),
        };

        msg1.r_list
            .iter_mut()
            .enumerate()
            .for_each(|(idx, r_values)| {
                let random_choice_bit = next_state.packed_choice_bits.extract_bit(idx) as usize;

                let t_a = &next_state.t_a_list[idx];

                let r_other = RistrettoPoint::random(&mut *rng);
                let h_choice = h_function(random_choice_bit, idx, session_id, &r_other);

                let r_choice = RistrettoPoint::mul_base(t_a) + h_choice.neg();

                // dummy calculation for constant time
                black_box(h_function(
                    random_choice_bit ^ 1,
                    idx,
                    session_id,
                    &r_choice,
                ));

                r_values[random_choice_bit] = encode_point(&r_choice);
                r_values[random_choice_bit ^ 1] = encode_point(&r_other);
            });

        next_state
    }

    pub fn process(self, msg2: &EndemicOTMsg2) -> Result<ReceiverOutput, &'static str> {
        let mut error = false;
        let rho_w_vec: [[u8; LAMBDA_C_BYTES]; LAMBDA_C] = array::from_fn(|idx| {
            let m_b_values = &msg2.m_b_list[idx];
            let random_choice_bit = self.packed_choice_bits.extract_bit(idx);

            let m_b_value = m_b_values[random_choice_bit as usize];
            let m_b_value = match decode_point(&m_b_value) {
                None => {
                    error = true;
                    // return dummy Ristretto Point
                    RistrettoPoint::from_uniform_bytes(&[0u8; 64])
                }
                Some(v) => v,
            };
            let res = m_b_value * self.t_a_list[idx];
            h_function_2(idx, &res)
        });

        if error {
            return Err("Decode error");
        }

        Ok(ReceiverOutput {
            choice_bits: self.packed_choice_bits,
            otp_dec_keys: rho_w_vec,
        })
    }
}

// FIXME: required only for testing
impl ReceiverOutput {
    /// Create a new `ReceiverOutput`.
    pub fn new(
        choice_bits: [u8; LAMBDA_C_BYTES],
        otp_dec_keys: [[u8; LAMBDA_C_BYTES]; LAMBDA_C],
    ) -> Self {
        Self {
            choice_bits,
            otp_dec_keys,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_endemic_ot() {
        let mut rng = rand::thread_rng();
        let session_id: [u8; 32] = rng.gen();

        let mut msg1 = EndemicOTMsg1::default();

        let receiver = EndemicOTReceiver::new(&session_id, &mut msg1, &mut rng);

        let mut msg2 = EndemicOTMsg2::default();
        let sender_output =
            EndemicOTSender::process(&session_id, &msg1, &mut msg2, &mut rng).unwrap();

        let receiver_output = receiver.process(&msg2).unwrap();

        for i in 0..LAMBDA_C {
            let sender_pad = &sender_output.otp_enc_keys[i];

            let rec_pad = &receiver_output.otp_dec_keys[i];

            let bit = receiver_output.choice_bits.extract_bit(i);

            if bit {
                assert_eq!(&sender_pad.rho_1, rec_pad);
            } else {
                assert_eq!(&sender_pad.rho_0, rec_pad);
            }
        }
    }
}
