// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Implementation of the protocol 5.2 OT-Based Random Vector OLE
//! https://eprint.iacr.org/2023/765.pdf
//!
//! xi = kappa + 2 * lambda_s
//! kappa = |p| = 128
//! lambda_c = 128
//! lambda_s = 128
//! rho = ceil(lambda_c/kappa) = 1

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use std::ops::Mul;

use merlin::Transcript;

use crate::P;
use crypto_bigint::{Encoding, U128};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::sl_oblivious::utils::scalar_from_bytes;
use crate::sl_oblivious::{
    constants::{RANDOM_VOLE_GADGET_VECTOR_LABEL, RANDOM_VOLE_MU_LABEL, RANDOM_VOLE_THETA_LABEL},
    params::consts::*,
    soft_spoken::{
        ReceiverExtendedOutput, ReceiverOTSeed, Round1Output, SenderOTSeed, SoftSpokenOTError,
        SoftSpokenOTReceiver, SoftSpokenOTSender,
    },
    utils::ExtractBit,
};

const XI: usize = L; // by definition

fn generate_gadget_vec(session_id: &[u8]) -> Vec<U128> {
    let mut t = Transcript::new(&RANDOM_VOLE_GADGET_VECTOR_LABEL);
    t.append_message(b"session-id", session_id);

    let params = DynResidueParams::new(&P);

    let output: Vec<U128> = (0..XI)
        .map(move |i| {
            t.append_u64(b"index", i as u64);

            let mut repr = [0u8; KAPPA_BYTES];
            t.challenge_bytes(b"next value", &mut repr);

            scalar_from_bytes(params, repr)
        })
        .collect();

    output
}

/// RVOLEOutputATilde
#[derive(Clone, Serialize, Deserialize)]
pub struct RVOLEOutputATilde {
    #[serde(with = "serde_arrays")]
    pub inner: [[u8; KAPPA_BYTES]; XI],
}

impl Default for RVOLEOutputATilde {
    fn default() -> Self {
        Self {
            inner: [[0u8; KAPPA_BYTES]; XI],
        }
    }
}

/// Message output in RVOLE protocol
#[derive(Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct RVOLEOutput {
    a_tilde: Vec<RVOLEOutputATilde>, // [[[u8; KAPPA_BYTES]; L_BATCH_PLUS_RHO]; XI]
    eta: [[u8; KAPPA_BYTES]; RHO],
    mu_hash: [u8; 2 * LAMBDA_C_BYTES],
}

impl RVOLEOutput {
    fn get_a_tilde(&self, params: DynResidueParams<2>, i: usize, j: usize) -> U128 {
        scalar_from_bytes(params, self.a_tilde[i].inner[j])
    }
}

impl RVOLEOutput {
    pub fn new(l_batch: usize) -> Self {
        RVOLEOutput {
            a_tilde: vec![RVOLEOutputATilde::default(); l_batch + RHO],
            eta: [[0u8; KAPPA_BYTES]; RHO],
            mu_hash: [0u8; 2 * LAMBDA_C_BYTES],
        }
    }
}

/// RVOLEReceiver
#[derive(Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct RVOLEReceiver {
    session_id: [u8; 32],
    #[serde(with = "serde_arrays")]
    beta: [u8; L_BYTES],
    receiver_extended_output: ReceiverExtendedOutput,
}

impl RVOLEReceiver {
    /// Create a new RVOLE receiver
    pub fn new<R: CryptoRng + RngCore>(
        session_id: [u8; 32],
        seed_ot_results: &SenderOTSeed,
        round1_output: &mut Round1Output,
        l_batch: usize,
        rng: &mut R,
    ) -> (Box<RVOLEReceiver>, U128) {
        let params = DynResidueParams::new(&P);

        let mut beta = [0u8; L_BYTES];
        rng.fill_bytes(&mut beta);

        // b = <g, /beta>
        let b = generate_gadget_vec(&session_id).iter().enumerate().fold(
            U128::ZERO,
            |option_0, (i, gv)| {
                let i_bit = beta.extract_bit(i);
                let option_0_dyn_res = DynResidue::new(&option_0, params);
                let gv_dyn_res = DynResidue::new(gv, params);
                let option_1 = option_0_dyn_res.add(&gv_dyn_res).retrieve();

                U128::conditional_select(&option_0, &option_1, Choice::from(i_bit as u8))
            },
        );

        let mut next = Box::new(RVOLEReceiver {
            session_id,
            beta,
            receiver_extended_output: *ReceiverExtendedOutput::new(&beta, l_batch),
        });

        SoftSpokenOTReceiver::process(
            &session_id,
            seed_ot_results,
            round1_output,
            &mut next.receiver_extended_output,
            rng,
        );

        (next, b)
    }
}

impl RVOLEReceiver {
    /// process rvole_output from RVOLESender
    pub fn process(
        &self,
        rvole_output: &RVOLEOutput,
        l_batch: usize,
    ) -> Result<Vec<U128>, &'static str> {
        let params = DynResidueParams::new(&P);

        let mut t = Transcript::new(&RANDOM_VOLE_THETA_LABEL);
        t.append_message(b"session-id", &self.session_id);

        for i in 0..(l_batch + RHO) {
            t.append_u64(b"ot-index", i as u64);
            for j in 0..XI {
                t.append_u64(b"row of a tilde", j as u64);
                t.append_message(b"", &rvole_output.a_tilde[i].inner[j]);
            }
        }

        let mut theta = [vec![U128::ZERO; l_batch]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..l_batch {
                t.append_u64(b"theta k", k as u64);
                t.append_u64(b"theta i", i as u64);

                let mut digest = [0u8; KAPPA_BYTES];
                t.challenge_bytes(b"theta", digest.as_mut());
                theta[k][i] = scalar_from_bytes(params, digest);
            }
        }

        let mut d_dot = vec![[U128::ZERO; XI]; l_batch];
        let mut d_hat = [[U128::ZERO; RHO]; XI];

        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            let j_bit = self.beta.extract_bit(j);
            #[allow(clippy::needless_range_loop)]
            for i in 0..l_batch {
                let option_0 =
                    scalar_from_bytes(params, self.receiver_extended_output.v_x[i].inner[j]);
                let option_0_dyn_res = DynResidue::new(&option_0, params);
                let a_tilde_dyn_res =
                    DynResidue::new(&rvole_output.get_a_tilde(params, i, j), params);
                let option_1 = option_0_dyn_res.add(&a_tilde_dyn_res).retrieve();
                let chosen =
                    U128::conditional_select(&option_0, &option_1, Choice::from(j_bit as u8));
                d_dot[i][j] = chosen
            }
            for k in 0..RHO {
                let option_0 = scalar_from_bytes(
                    params,
                    self.receiver_extended_output.v_x[l_batch + k].inner[j],
                );
                let option_0_dyn_res = DynResidue::new(&option_0, params);
                let a_tilde_dyn_res =
                    DynResidue::new(&rvole_output.get_a_tilde(params, l_batch + k, j), params);
                let option_1 = option_0_dyn_res.add(&a_tilde_dyn_res).retrieve();
                let chosen =
                    U128::conditional_select(&option_0, &option_1, Choice::from(j_bit as u8));
                d_hat[j][k] = chosen
            }
        }

        // mu_prime hash
        let mut t = Transcript::new(&RANDOM_VOLE_MU_LABEL);
        t.append_message(b"session-id", &self.session_id);

        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            let j_bit = self.beta.extract_bit(j);

            for k in 0..RHO {
                let mut v_dyn_res = DynResidue::new(&d_hat[j][k], params);
                for i in 0..l_batch {
                    let theta_dyn_res = DynResidue::new(&theta[k][i], params);
                    let d_dot_dyn_res = DynResidue::new(&d_dot[i][j], params);
                    v_dyn_res = v_dyn_res.add(&theta_dyn_res.mul(&d_dot_dyn_res));
                }

                let option_0 = v_dyn_res.retrieve();
                let option_0_dyn_res = DynResidue::new(&option_0, params);
                let eta = scalar_from_bytes(params, rvole_output.eta[k]);
                let eta_dyn_res = DynResidue::new(&eta, params);
                let option_1 = option_0_dyn_res.sub(&eta_dyn_res).retrieve();
                let chosen =
                    U128::conditional_select(&option_0, &option_1, Choice::from(j_bit as u8));
                t.append_message(b"chosen", &chosen.to_be_bytes());
            }
        }

        let mut mu_prime_hash = [0u8; 2 * LAMBDA_C_BYTES];
        t.challenge_bytes(b"mu-hash", &mut mu_prime_hash);

        if rvole_output.mu_hash.ct_ne(&mu_prime_hash).into() {
            return Err("Consistency check failed");
        }

        let mut d = vec![U128::ZERO; l_batch];
        let gadget_vector = generate_gadget_vec(&self.session_id);
        #[allow(clippy::needless_range_loop)]
        for i in 0..l_batch {
            let mut d_dyn_res = DynResidue::new(&d[i], params);
            for (j, gv) in gadget_vector.iter().enumerate() {
                // d[i] += gv * d_dot[j][i];
                let gv_dyn_res = DynResidue::new(gv, params);
                let d_dot_dyn_res = DynResidue::new(&d_dot[i][j], params);
                d_dyn_res = d_dyn_res.add(&gv_dyn_res.mul(&d_dot_dyn_res));
            }
            d[i] = d_dyn_res.retrieve();
        }

        Ok(d)
    }
}

/// RVOLESender
pub struct RVOLESender;

impl RVOLESender {
    /// process Round1Output from RVOLEReceiver
    pub fn process<R: CryptoRng + RngCore>(
        session_id: &[u8],
        seed_ot_results: &ReceiverOTSeed,
        a: &[U128],
        round1_output: &Round1Output,
        output: &mut RVOLEOutput,
        l_batch: usize,
        rng: &mut R,
    ) -> Result<Vec<U128>, SoftSpokenOTError> {
        let params = DynResidueParams::new(&P);

        let sender_extended_output =
            SoftSpokenOTSender::process(session_id, seed_ot_results, round1_output, l_batch)?;

        let alpha_0 =
            |i: usize, j: usize| scalar_from_bytes(params, sender_extended_output.v_0[i][j]);

        let alpha_1 =
            |i: usize, j: usize| scalar_from_bytes(params, sender_extended_output.v_1[i][j]);

        let mut c = vec![U128::ZERO; l_batch];
        let gadget_vector = generate_gadget_vec(session_id);
        #[allow(clippy::needless_range_loop)]
        for i in 0..l_batch {
            let mut el_dyn_res = DynResidue::new(&U128::ZERO, params);
            for (j, gv) in gadget_vector.iter().enumerate() {
                let gv_dyn_res = DynResidue::new(gv, params);
                let alpha_dyn_res = DynResidue::new(&alpha_0(i, j), params);
                el_dyn_res = el_dyn_res.add(&gv_dyn_res.mul(&alpha_dyn_res))
            }
            el_dyn_res = el_dyn_res.neg();
            c[i] = el_dyn_res.retrieve();
        }

        output.eta.iter_mut().for_each(|eta| {
            // Scalar::generate_biased(rng).to_bytes().into();
            *eta = scalar_from_bytes(params, rng.gen()).to_be_bytes();
        });

        let mut t = Transcript::new(&RANDOM_VOLE_THETA_LABEL);
        t.append_message(b"session-id", session_id);

        #[allow(clippy::needless_range_loop)]
        for i in 0..l_batch {
            t.append_u64(b"ot-index", i as u64);
            for j in 0..XI {
                t.append_u64(b"row of a tilde", j as u64);
                //let v = alpha_0(j, i) - alpha_1(j, i) + a[i];
                let alpha_0_dyn_res = DynResidue::new(&alpha_0(i, j), params);
                let alpha_1_dyn_res = DynResidue::new(&alpha_1(i, j), params);
                let a_dyn_res = DynResidue::new(&a[i], params);

                let v = alpha_0_dyn_res
                    .sub(&alpha_1_dyn_res)
                    .add(&a_dyn_res)
                    .retrieve();
                output.a_tilde[i].inner[j] = v.to_be_bytes();

                t.append_message(b"", &output.a_tilde[i].inner[j]);
            }
        }
        for i in 0..RHO {
            t.append_u64(b"ot-index", (l_batch + i) as u64);
            for j in 0..XI {
                t.append_u64(b"row of a tilde", j as u64);
                // let v = alpha_0(j, L_BATCH + k) - alpha_1(j, L_BATCH + k)
                //     + Scalar::reduce(U256::from_be_bytes(*eta));
                let alpha_0_dyn_res = DynResidue::new(&alpha_0(l_batch + i, j), params);
                let alpha_1_dyn_res = DynResidue::new(&alpha_1(l_batch + i, j), params);
                let eta_dyn_res =
                    DynResidue::new(&scalar_from_bytes(params, output.eta[i]), params);

                let v = alpha_0_dyn_res
                    .sub(&alpha_1_dyn_res)
                    .add(&eta_dyn_res)
                    .retrieve();
                output.a_tilde[l_batch + i].inner[j] = v.to_be_bytes();

                t.append_message(b"", &output.a_tilde[l_batch + i].inner[j]);
            }
        }

        let mut theta = [vec![U128::ZERO; l_batch]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..l_batch {
                t.append_u64(b"theta k", k as u64);
                t.append_u64(b"theta i", i as u64);

                let mut digest = [0u8; KAPPA_BYTES];
                t.challenge_bytes(b"theta", &mut digest);

                theta[k][i] = scalar_from_bytes(params, digest);
            }
        }

        for (k, eta) in output.eta.iter_mut().enumerate() {
            let s = scalar_from_bytes(params, *eta);
            let mut s_dyn_res = DynResidue::new(&s, params);
            // s += theta[k]
            //     .iter()
            //     .zip(a)
            //     .map(|(t_k_i, a_i)| t_k_i * a_i)
            //     .sum::<Scalar>();
            #[allow(clippy::needless_range_loop)]
            for i in 0..l_batch {
                let theta_k_i_dyn_res = DynResidue::new(&theta[k][i], params);
                let a_i_dyn_res = DynResidue::new(&a[i], params);
                s_dyn_res = s_dyn_res.add(&theta_k_i_dyn_res.mul(&a_i_dyn_res));
            }

            *eta = s_dyn_res.retrieve().to_be_bytes();
        }

        let mut t = Transcript::new(&RANDOM_VOLE_MU_LABEL);
        t.append_message(b"session-id", session_id);

        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            for k in 0..RHO {
                // let mut v = alpha_0(j, L_BATCH + k);
                let mut v_dyn_res = DynResidue::new(&alpha_0(l_batch + k, j), params);
                for i in 0..l_batch {
                    // v += theta[k][i] * alpha_0(j, i)
                    let theta_k_i_dyn_res = DynResidue::new(&theta[k][i], params);
                    let alpha_dyn_res = DynResidue::new(&alpha_0(i, j), params);
                    v_dyn_res = v_dyn_res.add(&theta_k_i_dyn_res.mul(&alpha_dyn_res));
                }
                t.append_message(b"chosen", &v_dyn_res.retrieve().to_be_bytes());
            }
        }

        t.challenge_bytes(b"mu-hash", &mut output.mu_hash);

        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sl_oblivious::soft_spoken::generate_all_but_one_seed_ot;

    #[test]
    fn pairwise() {
        let mut rng = rand::thread_rng();
        let l_batch = 7usize;
        let params = DynResidueParams::new(&P);

        let (sender_ot_seed, receiver_ot_seed) = generate_all_but_one_seed_ot(&mut rng);

        let session_id: [u8; 32] = rng.gen();

        let mut round1_output = Round1Output::default();
        let (receiver, beta) = RVOLEReceiver::new(
            session_id,
            &sender_ot_seed,
            &mut round1_output,
            l_batch,
            &mut rng,
        );

        let mut alpha = vec![];
        for _i in 0..l_batch {
            alpha.push(scalar_from_bytes(params, rng.gen()))
        }

        let mut round2_output = RVOLEOutput::new(l_batch);

        let sender_shares = RVOLESender::process(
            &session_id,
            &receiver_ot_seed,
            &alpha,
            &round1_output,
            &mut round2_output,
            l_batch,
            &mut rng,
        )
        .unwrap();

        let receiver_shares = receiver.process(&round2_output, l_batch).unwrap();

        for i in 0..l_batch {
            let sum_0 = DynResidue::new(&receiver_shares[i], params)
                .add(&DynResidue::new(&sender_shares[i], params))
                .retrieve();

            let mul_0 = DynResidue::new(&alpha[i], params)
                .mul(&DynResidue::new(&beta, params))
                .retrieve();

            assert_eq!(sum_0, mul_0);
        }
    }
}
