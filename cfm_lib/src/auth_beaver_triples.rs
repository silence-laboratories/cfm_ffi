//! Authenticated Beaver Triples protocol 4.9 implementation

use crate::cfm_init_protocol::{CFMInitOTSeedsCB, CFMInitOTSeedsOB};
use crate::errors::{ABTCBError, ABTOBError};
use crate::proto::ZS;
use crate::sl_oblivious::constants::{AUTH_BEAVER_TRIPLES_LABEL, COMMIT_RHO_LABEL, RO_RHO_LABEL};
use crate::sl_oblivious::params::consts::KAPPA_BYTES;
use crate::sl_oblivious::rvole::{RVOLEOutput, RVOLEReceiver, RVOLESender};
use crate::sl_oblivious::soft_spoken::Round1Output;
use crate::sl_oblivious::utils::scalar_from_bytes;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::U128;
use merlin::Transcript;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::ops::Mul;

/// ABTMsg1
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTMsg1 {
    /// session id
    pub session_id: [u8; 32],

    /// First messages for F_VOLE(p, 1), (sid|0|i, gen-vole, 0), i /in [4*eta_m]
    pub vole_0_msg1: Vec<ZS<Round1Output>>, // 4 * eta_m elements

    /// First message for F_VOLE(p, 6*eta), (sid|1, gen-vole, 0)
    pub vole_1_msg1: ZS<Round1Output>,

    /// commit for value rho1
    pub commitment: [u8; 32],
}

/// ABTMsg2
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTMsg2 {
    /// session id
    pub session_id: [u8; 32],

    /// Second messages for F_VOLE(p, 1), (sid|0|i, gen-vole, 0), i /in [4*eta_m]
    pub vole_0_msg2: Vec<RVOLEOutput>, // 4 * eta_m elements

    /// Second message for F_VOLE(p, 6*eta), (sid|1, gen-vole, 0)
    pub vole_1_msg2: RVOLEOutput,

    /// First message for F_VOLE(p, 6*eta), (sid|2, gen-vole, 1)
    pub vole_2_msg1: ZS<Round1Output>,

    /// gamma_ob_i, i /in [6*eta]
    pub gamma_ob: Vec<U128>, // 6 * eta_m + eta_i elements

    /// rho2 value
    pub rho2: [u8; 32],
}

/// ABTMsg3
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTMsg3 {
    /// session id
    pub session_id: [u8; 32],

    /// Second message for F_VOLE(p, 6*eta), (sid|2, gen-vole, 1)
    pub vole_2_msg2: RVOLEOutput,

    /// gamma_cb_i, i /in [6*eta]
    pub gamma_cb: Vec<U128>, // 6 * eta elements

    /// blind factor for rho1 commitment
    pub blind_factor: [u8; 32],

    /// rho1 value
    pub rho1: [u8; 32],

    /// Open(d), (d^CB, M^{d,CB}) and Open(e), (e^CB, M^{e,CB})
    pub mul_shares_open: Vec<MulSharesOpen>, // eta elements
}

/// ABTMsg4
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTMsg4 {
    /// session id
    pub session_id: [u8; 32],

    /// Open(d), (d^CB, M^{d,CB}) and Open(e), (e^CB, M^{e,CB})
    pub mul_shares_open: Vec<MulSharesOpen>, // eta elements

    /// Open(z_i - hat(z_i))
    pub open_z: Vec<(U128, U128)>, // eta elements
}

/// ABTMsg5
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTMsg5 {
    /// session id
    pub session_id: [u8; 32],

    /// Open(z_i - hat(z_i))
    pub open_z: Vec<(U128, U128)>, // eta elements
}

/// Authenticated Beaver Triples State for CB round1
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTStateCBR1 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// eta_i
    pub eta_i: usize,

    /// eta_m
    pub eta_m: usize,

    /// vole_0_receivers states
    pub vole_0_receivers: Vec<(Box<RVOLEReceiver>, U128)>,

    /// vole_1_receiver state
    pub vole_1_receiver: (Box<RVOLEReceiver>, U128),

    /// blind factor for rho1 commitment
    pub blind_factor: [u8; 32],

    /// rho1 value
    pub rho1: [u8; 32],
}

/// Authenticated Beaver Triples State for CB round2
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTStateCBR2 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// eta_m
    pub eta_m: usize,

    /// mul_shares_open
    pub mul_shares_state: Vec<MulSharesState>, // eta elements
}

/// Authenticated Beaver Triples State for OB round 1
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTStateOBR1 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// eta_i
    pub eta_i: usize,

    /// eta_m
    pub eta_m: usize,

    /// vole_2_receiver state
    pub vole_2_receiver: (Box<RVOLEReceiver>, U128),

    /// commit for value rho1
    pub commitment: [u8; 32],

    /// rho2 values
    pub rho2: [u8; 32],
}

/// Authenticated Beaver Triples State for OB round 2
#[derive(Clone, Serialize, Deserialize)]
pub struct ABTStateOBR2 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// eta_m
    pub eta_m: usize,

    /// z_diff
    pub z_diff: Vec<Share>, // eta elements
}

/// Share
#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub struct Share {
    /// value
    pub value: U128,
    /// M^value
    pub big_m: U128,
    /// Delta
    pub big_delta: U128,
    /// delta^value
    pub delta: U128,
}

impl Share {
    /// add share
    pub fn add_share(&self, rhs: &Share, params: DynResidueParams<2>) -> Share {
        let value = DynResidue::new(&self.value, params).add(&DynResidue::new(&rhs.value, params));
        let big_m = DynResidue::new(&self.big_m, params).add(&DynResidue::new(&rhs.big_m, params));
        assert_eq!(self.big_delta, rhs.big_delta);
        let delta = DynResidue::new(&self.delta, params).add(&DynResidue::new(&rhs.delta, params));
        Share {
            value: value.retrieve(),
            big_m: big_m.retrieve(),
            big_delta: self.big_delta,
            delta: delta.retrieve(),
        }
    }

    /// sub share
    pub fn sub_share(&self, rhs: &Share, params: DynResidueParams<2>) -> Share {
        let value = DynResidue::new(&self.value, params).sub(&DynResidue::new(&rhs.value, params));
        let big_m = DynResidue::new(&self.big_m, params).sub(&DynResidue::new(&rhs.big_m, params));
        assert_eq!(self.big_delta, rhs.big_delta);
        let delta = DynResidue::new(&self.delta, params).sub(&DynResidue::new(&rhs.delta, params));
        Share {
            value: value.retrieve(),
            big_m: big_m.retrieve(),
            big_delta: self.big_delta,
            delta: delta.retrieve(),
        }
    }

    /// add const ob
    pub fn add_const_ob(&self, c: &U128, params: DynResidueParams<2>) -> Share {
        let value = DynResidue::new(&self.value, params).add(&DynResidue::new(c, params));
        Share {
            value: value.retrieve(),
            big_m: self.big_m,
            big_delta: self.big_delta,
            delta: self.delta,
        }
    }

    /// add const cb
    pub fn add_const_cb(&self, c: &U128, params: DynResidueParams<2>) -> Share {
        let delta = DynResidue::new(&self.delta, params)
            .add(&DynResidue::new(c, params).mul(&DynResidue::new(&self.big_delta, params)));
        Share {
            value: self.value,
            big_m: self.big_m,
            big_delta: self.big_delta,
            delta: delta.retrieve(),
        }
    }

    /// mul const
    pub fn mul_const(&self, c: &U128, params: DynResidueParams<2>) -> Share {
        let c_dyn_res = DynResidue::new(c, params);
        let value = DynResidue::new(&self.value, params).mul(&c_dyn_res);
        let big_m = DynResidue::new(&self.big_m, params).mul(&c_dyn_res);
        let delta = DynResidue::new(&self.delta, params).mul(&c_dyn_res);
        Share {
            value: value.retrieve(),
            big_m: big_m.retrieve(),
            big_delta: self.big_delta,
            delta: delta.retrieve(),
        }
    }

    /// Opens (value, mac)
    pub fn open(&self) -> (U128, U128) {
        (self.value, self.big_m)
    }

    /// Validates M^{x,A} = x^A * Delta^{B} - delta^{x,B}
    /// Outputs x^A + x^B
    pub fn validate_open(
        &self,
        open_value: &U128,
        open_mac: &U128,
        params: DynResidueParams<2>,
    ) -> Result<U128, &'static str> {
        let big_delta_dyn_res = DynResidue::new(&self.big_delta, params);
        let delta = &self.delta;
        let left = DynResidue::new(open_mac, params)
            .add(&DynResidue::new(delta, params))
            .retrieve();
        let right = DynResidue::new(open_value, params)
            .mul(&big_delta_dyn_res)
            .retrieve();
        if left != right {
            return Err("Invalid Open");
        }
        Ok(DynResidue::new(&self.value, params)
            .add(&DynResidue::new(open_value, params))
            .retrieve())
    }

    /// CB-Input([x], y)
    /// Outputs (share_y, d)
    pub fn cb_input(
        &self,
        open_x: &(U128, U128),
        y: &U128,
        params: DynResidueParams<2>,
    ) -> Result<(Share, U128), &'static str> {
        let (value, mac) = open_x;
        let x = match self.validate_open(value, mac, params) {
            Ok(v) => v,
            Err(_) => return Err("Invalid Open"),
        };
        let d = DynResidue::new(y, params)
            .sub(&DynResidue::new(&x, params))
            .retrieve();
        let beta_share = self.add_const_cb(&d, params);
        Ok((beta_share, d))
    }

    /// OB-Input([x], y)
    /// Outputs (share_y, d)
    pub fn ob_input(
        &self,
        open_x: &(U128, U128),
        y: &U128,
        params: DynResidueParams<2>,
    ) -> Result<(Share, U128), &'static str> {
        let (value, mac) = open_x;
        let x = match self.validate_open(value, mac, params) {
            Ok(v) => v,
            Err(_) => return Err("Invalid Open"),
        };
        let d = DynResidue::new(y, params)
            .sub(&DynResidue::new(&x, params))
            .retrieve();
        let beta_share = self.add_const_ob(&d, params);
        Ok((beta_share, d))
    }
}

impl Default for Share {
    fn default() -> Self {
        Self {
            value: U128::ZERO,
            big_m: U128::ZERO,
            big_delta: U128::ZERO,
            delta: U128::ZERO,
        }
    }
}

/// MulSharesState
#[derive(Default, Copy, Clone, Serialize, Deserialize)]
pub struct MulSharesState {
    /// x share
    pub x: Share,

    /// y share
    pub y: Share,

    /// z_hat share
    pub z_hat: Share,

    /// d share
    pub d: Share,

    /// e share
    pub e: Share,
}

/// MulSharesOpen
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct MulSharesOpen {
    /// d value
    pub d: U128,

    /// M^d value
    pub m_d: U128,

    /// e value
    pub e: U128,

    /// M^e value
    pub m_e: U128,
}

impl Default for MulSharesOpen {
    fn default() -> Self {
        Self {
            d: U128::ZERO,
            m_d: U128::ZERO,
            e: U128::ZERO,
            m_e: U128::ZERO,
        }
    }
}

/// Multiply([x], [y], [ˆx], [ˆy], [ˆz]), Shorthand [x] · [y].
pub fn multiply_shares_open(
    x: &Share,
    y: &Share,
    x_hat: &Share,
    y_hat: &Share,
    z_hat: &Share,
    params: DynResidueParams<2>,
) -> (MulSharesState, MulSharesOpen) {
    let d = x.sub_share(x_hat, params);
    let e = y.sub_share(y_hat, params);

    let state = MulSharesState {
        x: *x,
        y: *y,
        z_hat: *z_hat,
        d,
        e,
    };

    let mul_shares_open = MulSharesOpen {
        d: d.value,
        m_d: d.big_m,
        e: e.value,
        m_e: e.big_m,
    };

    (state, mul_shares_open)
}

/// Multiply([x], [y], [ˆx], [ˆy], [ˆz]), Shorthand [x] · [y].
/// is_cb_side = true if function runs on CB side
/// is_cb_side = false if function runs on OB side
pub fn multiply_shares_output(
    state: &MulSharesState,
    mul_shares_open: &MulSharesOpen,
    is_cb_side: bool,
    params: DynResidueParams<2>,
) -> Result<Share, &'static str> {
    // validate Open(d)
    let d_value = state
        .d
        .validate_open(&mul_shares_open.d, &mul_shares_open.m_d, params)?;

    // validate Open(e)
    let e_value = state
        .e
        .validate_open(&mul_shares_open.e, &mul_shares_open.m_e, params)?;

    let d_mul_e_neg = DynResidue::new(&d_value, params)
        .mul(&DynResidue::new(&e_value, params))
        .neg()
        .retrieve();

    let output = state
        .x
        .mul_const(&e_value, params)
        .add_share(&state.y.mul_const(&d_value, params), params)
        .add_share(&state.z_hat, params);

    if is_cb_side {
        Ok(output.add_const_cb(&d_mul_e_neg, params))
    } else {
        Ok(output.add_const_ob(&d_mul_e_neg, params))
    }
}

/// TestBit([x]) open
/// [b] = 1 - ([x]*(1-[x])) = 1 + ([x]*([x]-1))
/// is_cb_side = true if function runs on CB side
/// is_cb_side = false if function runs on OB side
pub fn test_bit_open(
    x: &Share,
    x_hat: &Share,
    y_hat: &Share,
    z_hat: &Share,
    is_cb_side: bool,
    p: &U128,
    params: DynResidueParams<2>,
) -> (MulSharesState, MulSharesOpen) {
    let minus_one = p.saturating_sub(&U128::ONE);
    let y = if is_cb_side {
        x.add_const_cb(&minus_one, params)
    } else {
        x.add_const_ob(&minus_one, params)
    };
    multiply_shares_open(x, &y, x_hat, y_hat, z_hat, params)
}

/// TestBit([x]) output
/// [b] = 1 - ([x]*(1-[x])) = 1 + ([x]*([x]-1))
/// is_cb_side = true if function runs on CB side
/// is_cb_side = false if function runs on OB side
pub fn test_bit_output(
    state: &MulSharesState,
    mul_shares_open: &MulSharesOpen,
    is_cb_side: bool,
    params: DynResidueParams<2>,
) -> Result<Share, &'static str> {
    let share = multiply_shares_output(state, mul_shares_open, is_cb_side, params)?;

    let result = if is_cb_side {
        share.add_const_cb(&U128::ONE, params)
    } else {
        share.add_const_ob(&U128::ONE, params)
    };

    Ok(result)
}

/// Triple Share
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct TripleShare {
    /// [x]
    pub x: Share,
    /// [y]
    pub y: Share,
    /// [z]
    pub z: Share,
}

fn commit_rho_value(session_id: &[u8], blind_factor: &[u8], rho1: &[u8]) -> [u8; 32] {
    let mut t = Transcript::new(&COMMIT_RHO_LABEL);
    t.append_message(b"session-id", session_id);
    t.append_message(b"blind-factor", blind_factor);
    t.append_message(b"rho1-value", rho1);
    let mut commitment = [0u8; 32];
    t.challenge_bytes(b"commitment-rho1", commitment.as_mut());
    commitment
}
use std::time::Instant;

/// CB creates ABTMsg1 for OB
pub fn abt_create_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    ot_seeds_cb: &CFMInitOTSeedsCB,
    p: U128,
    eta_i: usize,
    eta_m: usize,
    rng: &mut R,
) -> (ABTStateCBR1, ABTMsg1) {
    let mut vole_0_msg1 = vec![ZS::<Round1Output>::default(); 4 * eta_m];
    let mut vole_0_receivers = vec![];

    let mut count_i = 0;

    // println!("Started {:?}", vole_0_msg1.len());

    let mut t = Transcript::new(&AUTH_BEAVER_TRIPLES_LABEL);


    // Measure the loop time
    let loop_start = Instant::now();

    t.append_message(b"session-id", session_id);
    t.append_u64(b"vole-instance", 0u64);
    for (i, vole_0_msg1_i) in vole_0_msg1.iter_mut().enumerate().take(4 * eta_m) {
        t.append_u64(b"vole-index", i as u64);
        let mut vole_sid = [0u8; 32];
        t.challenge_bytes(b"vole-sid", vole_sid.as_mut());

        let (receiver, beta) = RVOLEReceiver::new(
            vole_sid,
            &ot_seeds_cb.sender_ot_seed_0,
            vole_0_msg1_i,
            1,
            &mut *rng,
        );
        vole_0_receivers.push((receiver, beta));
        count_i += 1;
        // println!("pushed {:?}", count_i);
    }

    let loop_duration = loop_start.elapsed();

    // Measure time for code outside the loop
    let outside_loop_start = Instant::now();

    let mut t = Transcript::new(&AUTH_BEAVER_TRIPLES_LABEL);
    t.append_message(b"session-id", session_id);
    t.append_u64(b"vole-instance", 1u64);
    let mut vole_sid = [0u8; 32];
    t.challenge_bytes(b"vole-sid", vole_sid.as_mut());

    let mut vole_1_msg1 = ZS::<Round1Output>::default();
    let vole_1_receiver = RVOLEReceiver::new(
        vole_sid,
        &ot_seeds_cb.sender_ot_seed_0,
        &mut vole_1_msg1,
        6 * eta_m + eta_i,
        &mut *rng,
    );

    let mut blind_factor = [0u8; 32];
    rng.fill_bytes(blind_factor.as_mut());

    let mut rho1 = [0u8; 32];
    rng.fill_bytes(rho1.as_mut());

    let commitment = commit_rho_value(session_id, &blind_factor, &rho1);

    let state = ABTStateCBR1 {
        session_id: *session_id,
        p,
        eta_i,
        eta_m,
        vole_0_receivers,
        vole_1_receiver,
        blind_factor,
        rho1,
    };
    let msg1 = ABTMsg1 {
        session_id: *session_id,
        vole_0_msg1,
        vole_1_msg1,
        commitment,
    };


    let outside_loop_duration = outside_loop_start.elapsed();
    // println!("Loop iterations: {}", count_i);
    // println!("Loop duration: {:?}", loop_duration);
    // println!("Time for code outside the loop: {:?}", outside_loop_duration);

    (state, msg1)
}

/// OB processes ABTMsg1 from CB
pub fn abt_process_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    ot_seeds_ob: &CFMInitOTSeedsOB,
    p: U128,
    eta_i: usize,
    eta_m: usize,
    msg1: &ABTMsg1,
    rng: &mut R,
) -> Result<(ABTStateOBR1, Vec<Share>, Vec<TripleShare>, ABTMsg2), ABTOBError> {
    if *session_id != msg1.session_id {
        return Err(ABTOBError::InvalidSessionID);
    }
    if msg1.vole_0_msg1.len() != 4 * eta_m {
        return Err(ABTOBError::InvalidMessage);
    }

    let params = DynResidueParams::new(&p);

    let mut vole_0_msg2 = vec![RVOLEOutput::new(1); 4 * eta_m];
    let mut vole_0_sender_shares = vec![];
    let vole_0_alpha_values = vec![[scalar_from_bytes(params, rng.gen())]; 4 * eta_m];

    let mut t = Transcript::new(&AUTH_BEAVER_TRIPLES_LABEL);
    t.append_message(b"session-id", session_id);
    t.append_u64(b"vole-instance", 0u64);
    for i in 0..4 * eta_m {
        t.append_u64(b"vole-index", i as u64);
        let mut vole_sid = [0u8; 32];
        t.challenge_bytes(b"vole-sid", vole_sid.as_mut());

        let sender_shares = match RVOLESender::process(
            &vole_sid,
            &ot_seeds_ob.receiver_ot_seed_0,
            &vole_0_alpha_values[i],
            &msg1.vole_0_msg1[i],
            &mut vole_0_msg2[i],
            1,
            &mut *rng,
        ) {
            Ok(v) => v,
            Err(_) => return Err(ABTOBError::AbortProtocolAndBanOtherParty),
        };

        vole_0_sender_shares.push(sender_shares);
    }

    let mut t = Transcript::new(&AUTH_BEAVER_TRIPLES_LABEL);
    t.append_message(b"session-id", session_id);
    t.append_u64(b"vole-instance", 1u64);
    let mut vole_sid = [0u8; 32];
    t.challenge_bytes(b"vole-sid", vole_sid.as_mut());

    let mut vole_1_msg2 = RVOLEOutput::new(6 * eta_m + eta_i);
    let vole_1_alpha_values = vec![scalar_from_bytes(params, rng.gen()); 6 * eta_m + eta_i];
    let vole_1_sender_shares = match RVOLESender::process(
        &vole_sid,
        &ot_seeds_ob.receiver_ot_seed_0,
        &vole_1_alpha_values,
        &msg1.vole_1_msg1,
        &mut vole_1_msg2,
        6 * eta_m + eta_i,
        &mut *rng,
    ) {
        Ok(v) => v,
        Err(_) => return Err(ABTOBError::AbortProtocolAndBanOtherParty),
    };

    let mut t = Transcript::new(&AUTH_BEAVER_TRIPLES_LABEL);
    t.append_message(b"session-id", session_id);
    t.append_u64(b"vole-instance", 2u64);
    let mut vole_sid = [0u8; 32];
    t.challenge_bytes(b"vole-sid", vole_sid.as_mut());

    let mut vole_2_msg1 = ZS::<Round1Output>::default();
    let vole_2_receiver = RVOLEReceiver::new(
        vole_sid,
        &ot_seeds_ob.sender_ot_seed_1,
        &mut vole_2_msg1,
        6 * eta_m + eta_i,
        &mut *rng,
    );

    // pre-create mul_shares_ob with big_delta = 0 and delta = 0
    let mut mul_shares_ob: Vec<TripleShare> = vec![];

    let mut gamma_ob = vec![U128::ZERO; 6 * eta_m + eta_i];
    for i in 0..(2 * eta_m) {
        let x_ob_i = vole_0_alpha_values[2 * eta_m + i][0];
        let y_ob_i = vole_0_alpha_values[i][0];
        let z_ob_i = DynResidue::new(&vole_0_sender_shares[i][0], params);
        let z_ob_i = z_ob_i.add(&DynResidue::new(
            &vole_0_sender_shares[2 * eta_m + i][0],
            params,
        ));
        let z_ob_i =
            z_ob_i.add(&DynResidue::new(&y_ob_i, params).mul(&DynResidue::new(&x_ob_i, params)));

        let p_ob_i = &vole_1_alpha_values[i];
        let p_ob_2i = &vole_1_alpha_values[2 * eta_m + i];
        let p_ob_4i = &vole_1_alpha_values[4 * eta_m + i];

        let x_ob_i_dyn_res = DynResidue::new(&x_ob_i, params);
        let y_ob_i_dyn_res = DynResidue::new(&y_ob_i, params);
        let p_ob_i_dyn_res = DynResidue::new(p_ob_i, params);
        let p_ob_2i_dyn_res = DynResidue::new(p_ob_2i, params);
        let p_ob_4i_dyn_res = DynResidue::new(p_ob_4i, params);

        gamma_ob[i] = x_ob_i_dyn_res.sub(&p_ob_i_dyn_res).retrieve();
        gamma_ob[eta_m * 2 + i] = y_ob_i_dyn_res.sub(&p_ob_2i_dyn_res).retrieve();
        gamma_ob[eta_m * 4 + i] = z_ob_i.sub(&p_ob_4i_dyn_res).retrieve();

        mul_shares_ob.push(TripleShare {
            x: Share {
                value: x_ob_i,
                big_m: vole_1_sender_shares[i],
                big_delta: U128::ZERO,
                delta: U128::ZERO,
            },
            y: Share {
                value: y_ob_i,
                big_m: vole_1_sender_shares[2 * eta_m + i],
                big_delta: U128::ZERO,
                delta: U128::ZERO,
            },
            z: Share {
                value: z_ob_i.retrieve(),
                big_m: vole_1_sender_shares[4 * eta_m + i],
                big_delta: U128::ZERO,
                delta: U128::ZERO,
            },
        });
    }

    // pre-create input_shares_ob with big_delta = 0 and delta = 0
    let mut input_shares_ob: Vec<Share> = vec![];
    for i in 6 * eta_m..6 * eta_m + eta_i {
        let share_ob_i = scalar_from_bytes(params, rng.gen());
        let share_p_ob_i = &vole_1_alpha_values[i];

        let share_ob_i_dyn_res = DynResidue::new(&share_ob_i, params);
        let share_p_ob_i_dyn_res = DynResidue::new(share_p_ob_i, params);

        gamma_ob[i] = share_ob_i_dyn_res.sub(&share_p_ob_i_dyn_res).retrieve();

        input_shares_ob.push(Share {
            value: share_ob_i,
            big_m: vole_1_sender_shares[i],
            big_delta: U128::ZERO,
            delta: U128::ZERO,
        });
    }

    let mut rho2 = [0u8; 32];
    rng.fill_bytes(rho2.as_mut());

    let state = ABTStateOBR1 {
        session_id: *session_id,
        p,
        eta_i,
        eta_m,
        vole_2_receiver,
        commitment: msg1.commitment,
        rho2,
    };

    let msg2 = ABTMsg2 {
        session_id: *session_id,
        vole_0_msg2,
        vole_1_msg2,
        vole_2_msg1,
        gamma_ob,
        rho2,
    };

    Ok((state, input_shares_ob, mul_shares_ob, msg2))
}

/// CB processes ABTMsg2 from OB
pub fn abt_process_msg2<R: CryptoRng + RngCore>(
    state_cb: &ABTStateCBR1,
    ot_seeds_cb: &CFMInitOTSeedsCB,
    msg2: &ABTMsg2,
    rng: &mut R,
) -> Result<(ABTStateCBR2, Vec<Share>, Vec<TripleShare>, ABTMsg3), ABTCBError> {
    let params = DynResidueParams::new(&state_cb.p);
    let eta_m = state_cb.eta_m;
    let eta_i = state_cb.eta_i;

    if state_cb.session_id != msg2.session_id {
        return Err(ABTCBError::InvalidSessionID);
    }
    if state_cb.vole_0_receivers.len() != 4 * eta_m {
        return Err(ABTCBError::InvalidState);
    }
    if msg2.vole_0_msg2.len() != 4 * eta_m {
        return Err(ABTCBError::InvalidMessage);
    }
    if msg2.gamma_ob.len() != 6 * eta_m + eta_i {
        return Err(ABTCBError::InvalidMessage);
    }

    let mut t = Transcript::new(&AUTH_BEAVER_TRIPLES_LABEL);
    t.append_message(b"session-id", &state_cb.session_id);
    t.append_u64(b"vole-instance", 2u64);
    let mut vole_sid = [0u8; 32];
    t.challenge_bytes(b"vole-sid", vole_sid.as_mut());

    let mut vole_0_receiver_shares = vec![];
    let mut vole_0_beta_values = vec![];
    for i in 0..4 * eta_m {
        let (receiver, beta) = &state_cb.vole_0_receivers[i];
        let receiver_shares = match receiver.process(&msg2.vole_0_msg2[i], 1) {
            Ok(v) => v,
            Err(_) => return Err(ABTCBError::AbortProtocolAndBanOtherParty),
        };
        vole_0_receiver_shares.push(receiver_shares);
        vole_0_beta_values.push(*beta);
    }

    let (receiver, beta) = &state_cb.vole_1_receiver;
    let vole_1_receiver_shares = match receiver.process(&msg2.vole_1_msg2, 6 * eta_m + eta_i) {
        Ok(v) => v,
        Err(_) => return Err(ABTCBError::AbortProtocolAndBanOtherParty),
    };
    let vole_1_beta_value = *beta;

    let mut vole_2_msg2 = RVOLEOutput::new(6 * eta_m + eta_i);
    let vole_2_alpha_values = vec![scalar_from_bytes(params, rng.gen()); 6 * eta_m + eta_i];
    let vole_2_sender_shares = match RVOLESender::process(
        &vole_sid,
        &ot_seeds_cb.receiver_ot_seed_1,
        &vole_2_alpha_values,
        &msg2.vole_2_msg1,
        &mut vole_2_msg2,
        6 * eta_m + eta_i,
        &mut *rng,
    ) {
        Ok(v) => v,
        Err(_) => return Err(ABTCBError::AbortProtocolAndBanOtherParty),
    };

    // create mul_shares for CB
    let mut mul_shares_cb: Vec<TripleShare> = vec![];
    let big_delta = vole_1_beta_value;
    let big_delta_dyn_res = DynResidue::new(&big_delta, params);

    let mut gamma_cb = vec![U128::ZERO; 6 * eta_m + eta_i];
    for i in 0..(2 * eta_m) {
        let x_cb_i = vole_0_beta_values[i];
        let y_cb_i = vole_0_beta_values[2 * eta_m + i];
        let z_cb_i = DynResidue::new(&vole_0_receiver_shares[i][0], params);
        let z_cb_i = z_cb_i.add(&DynResidue::new(
            &vole_0_receiver_shares[2 * eta_m + i][0],
            params,
        ));
        let z_cb_i =
            z_cb_i.add(&DynResidue::new(&x_cb_i, params).mul(&DynResidue::new(&y_cb_i, params)));

        let p_cb_i = vole_2_alpha_values[i];
        let p_cb_2i = vole_2_alpha_values[2 * eta_m + i];
        let p_cb_4i = vole_2_alpha_values[4 * eta_m + i];

        let x_cb_i_dyn_res = DynResidue::new(&x_cb_i, params);
        let y_cb_i_dyn_res = DynResidue::new(&y_cb_i, params);
        let p_cb_i_dyn_res = DynResidue::new(&p_cb_i, params);
        let p_cb_2i_dyn_res = DynResidue::new(&p_cb_2i, params);
        let p_cb_4i_dyn_res = DynResidue::new(&p_cb_4i, params);

        gamma_cb[i] = x_cb_i_dyn_res.sub(&p_cb_i_dyn_res).retrieve();
        gamma_cb[eta_m * 2 + i] = y_cb_i_dyn_res.sub(&p_cb_2i_dyn_res).retrieve();
        gamma_cb[eta_m * 4 + i] = z_cb_i.sub(&p_cb_4i_dyn_res).retrieve();

        let delta_x = DynResidue::new(&vole_1_receiver_shares[i], params)
            .add(&big_delta_dyn_res.mul(&DynResidue::new(&msg2.gamma_ob[i], params)));

        let delta_y = DynResidue::new(&vole_1_receiver_shares[eta_m * 2 + i], params)
            .add(&big_delta_dyn_res.mul(&DynResidue::new(&msg2.gamma_ob[eta_m * 2 + i], params)));

        let delta_z = DynResidue::new(&vole_1_receiver_shares[eta_m * 4 + i], params)
            .add(&big_delta_dyn_res.mul(&DynResidue::new(&msg2.gamma_ob[eta_m * 4 + i], params)));

        mul_shares_cb.push(TripleShare {
            x: Share {
                value: x_cb_i,
                big_m: vole_2_sender_shares[i],
                big_delta,
                delta: delta_x.retrieve(),
            },
            y: Share {
                value: y_cb_i,
                big_m: vole_2_sender_shares[eta_m * 2 + i],
                big_delta,
                delta: delta_y.retrieve(),
            },
            z: Share {
                value: z_cb_i.retrieve(),
                big_m: vole_2_sender_shares[eta_m * 4 + i],
                big_delta,
                delta: delta_z.retrieve(),
            },
        });
    }

    // create input_shares for CB
    let mut input_shares_cb: Vec<Share> = vec![];
    for i in 6 * eta_m..6 * eta_m + eta_i {
        let share_cb_i = scalar_from_bytes(params, rng.gen());
        let p_cb_i = vole_2_alpha_values[i];

        let share_cb_i_dyn_res = DynResidue::new(&share_cb_i, params);
        let p_cb_i_dyn_res = DynResidue::new(&p_cb_i, params);

        gamma_cb[i] = share_cb_i_dyn_res.sub(&p_cb_i_dyn_res).retrieve();

        let delta_x = DynResidue::new(&vole_1_receiver_shares[i], params)
            .add(&big_delta_dyn_res.mul(&DynResidue::new(&msg2.gamma_ob[i], params)));

        input_shares_cb.push(Share {
            value: share_cb_i,
            big_m: vole_2_sender_shares[i],
            big_delta,
            delta: delta_x.retrieve(),
        });
    }

    // rho value
    let mut t = Transcript::new(&RO_RHO_LABEL);
    t.append_message(b"session-id", &state_cb.session_id);
    t.append_message(b"rho1", &state_cb.rho1);
    t.append_message(b"rho2", &msg2.rho2);
    let mut rho_bytes = [0u8; KAPPA_BYTES];
    t.challenge_bytes(b"rho-value", rho_bytes.as_mut());
    let rho = scalar_from_bytes(params, rho_bytes);

    // Open(e), Open(d)
    let mut mul_shares_state_cb = vec![MulSharesState::default(); eta_m];
    let mut mul_shares_open = vec![MulSharesOpen::default(); eta_m];
    for i in 0..eta_m {
        let triple_share_i = &mul_shares_cb[i];
        let triple_share_eta_plus_i = &mul_shares_cb[eta_m + i];
        let x_i = &triple_share_i.x;
        let y_i = &triple_share_i.y;
        let x_eta_plus_i_mul_rho = &triple_share_eta_plus_i.x.mul_const(&rho, params);
        let y_eta_plus_i_mul_rho = &triple_share_eta_plus_i.y.mul_const(&rho, params);
        let z_eta_plus_i_mul_rho_square = &triple_share_eta_plus_i
            .z
            .mul_const(&rho, params)
            .mul_const(&rho, params);

        let (mul_state, mul_open) = multiply_shares_open(
            x_i,
            y_i,
            x_eta_plus_i_mul_rho,
            y_eta_plus_i_mul_rho,
            z_eta_plus_i_mul_rho_square,
            params,
        );
        mul_shares_state_cb[i] = mul_state;
        mul_shares_open[i] = mul_open;
    }

    let msg3 = ABTMsg3 {
        session_id: state_cb.session_id,
        vole_2_msg2,
        gamma_cb,
        blind_factor: state_cb.blind_factor,
        rho1: state_cb.rho1,
        mul_shares_open,
    };

    let state = ABTStateCBR2 {
        session_id: state_cb.session_id,
        p: state_cb.p,
        eta_m,
        mul_shares_state: mul_shares_state_cb,
    };

    mul_shares_cb.truncate(eta_m);

    Ok((state, input_shares_cb, mul_shares_cb, msg3))
}

/// OB processes ABTMsg3 from CB
pub fn abt_process_msg3(
    state_ob: &ABTStateOBR1,
    input_shares_ob: &mut [Share],
    mul_shares_ob: &mut Vec<TripleShare>,
    msg3: &ABTMsg3,
) -> Result<(ABTStateOBR2, ABTMsg4), ABTOBError> {
    let params = DynResidueParams::new(&state_ob.p);
    let eta_m = state_ob.eta_m;
    let eta_i = state_ob.eta_i;

    if state_ob.session_id != msg3.session_id {
        return Err(ABTOBError::InvalidSessionID);
    }
    if input_shares_ob.len() != eta_i {
        return Err(ABTOBError::InvalidState);
    }
    if mul_shares_ob.len() != 2 * eta_m {
        return Err(ABTOBError::InvalidState);
    }
    if msg3.gamma_cb.len() != 6 * eta_m + eta_i {
        return Err(ABTOBError::InvalidMessage);
    }
    if msg3.mul_shares_open.len() != eta_m {
        return Err(ABTOBError::InvalidMessage);
    }

    let (receiver, beta) = &state_ob.vole_2_receiver;
    let vole_2_receiver_shares = match receiver.process(&msg3.vole_2_msg2, 6 * eta_m + eta_i) {
        Ok(v) => v,
        Err(_) => return Err(ABTOBError::AbortProtocolAndBanOtherParty),
    };

    let vole_2_beta_value = *beta;

    // create final mul_shares for OB
    let big_delta = vole_2_beta_value;
    let big_delta_dyn_res = DynResidue::new(&big_delta, params);
    for i in 0..(2 * eta_m) {
        let delta_x = DynResidue::new(&vole_2_receiver_shares[i], params)
            .add(&big_delta_dyn_res.mul(&DynResidue::new(&msg3.gamma_cb[i], params)));

        let delta_y = DynResidue::new(&vole_2_receiver_shares[eta_m * 2 + i], params)
            .add(&big_delta_dyn_res.mul(&DynResidue::new(&msg3.gamma_cb[eta_m * 2 + i], params)));

        let delta_z = DynResidue::new(&vole_2_receiver_shares[eta_m * 4 + i], params)
            .add(&big_delta_dyn_res.mul(&DynResidue::new(&msg3.gamma_cb[eta_m * 4 + i], params)));

        mul_shares_ob[i].x.big_delta = big_delta;
        mul_shares_ob[i].x.delta = delta_x.retrieve();
        mul_shares_ob[i].y.big_delta = big_delta;
        mul_shares_ob[i].y.delta = delta_y.retrieve();
        mul_shares_ob[i].z.big_delta = big_delta;
        mul_shares_ob[i].z.delta = delta_z.retrieve();
    }

    // create final input_shares for OB
    for i in 0..eta_i {
        let delta_x = DynResidue::new(&vole_2_receiver_shares[6 * eta_m + i], params)
            .add(&big_delta_dyn_res.mul(&DynResidue::new(&msg3.gamma_cb[6 * eta_m + i], params)));

        input_shares_ob[i].big_delta = big_delta;
        input_shares_ob[i].delta = delta_x.retrieve();
    }

    // check commitment for rho1 value
    let commitment = commit_rho_value(&state_ob.session_id, &msg3.blind_factor, &msg3.rho1);
    if commitment != state_ob.commitment {
        return Err(ABTOBError::InvalidCommitment);
    }

    // rho value
    let mut t = Transcript::new(&RO_RHO_LABEL);
    t.append_message(b"session-id", &state_ob.session_id);
    t.append_message(b"rho1", &msg3.rho1);
    t.append_message(b"rho2", &state_ob.rho2);
    let mut rho_bytes = [0u8; KAPPA_BYTES];
    t.challenge_bytes(b"rho-value", rho_bytes.as_mut());
    let rho = scalar_from_bytes(params, rho_bytes);

    // Open(e), Open(d)
    let mut mul_shares_open = vec![MulSharesOpen::default(); eta_m];
    let mut open_z = vec![(U128::ZERO, U128::ZERO); eta_m];
    let mut z_diff = vec![Share::default(); eta_m];
    for i in 0..eta_m {
        let triple_share_i = &mul_shares_ob[i];
        let triple_share_eta_plus_i = &mul_shares_ob[eta_m + i];
        let x_i = &triple_share_i.x;
        let y_i = &triple_share_i.y;
        let x_eta_plus_i_mul_rho = &triple_share_eta_plus_i.x.mul_const(&rho, params);
        let y_eta_plus_i_mul_rho = &triple_share_eta_plus_i.y.mul_const(&rho, params);
        let z_eta_plus_i_mul_rho_square = &triple_share_eta_plus_i
            .z
            .mul_const(&rho, params)
            .mul_const(&rho, params);

        let (mul_state, mul_open) = multiply_shares_open(
            x_i,
            y_i,
            x_eta_plus_i_mul_rho,
            y_eta_plus_i_mul_rho,
            z_eta_plus_i_mul_rho_square,
            params,
        );
        mul_shares_open[i] = mul_open;

        // validate Open(d) and Open(e) from CB
        let z_i_hat =
            match multiply_shares_output(&mul_state, &msg3.mul_shares_open[i], false, params) {
                Ok(v) => v,
                Err(_) => return Err(ABTOBError::InvalidOpen),
            };

        let z_diff_share = &mul_shares_ob[i].z.sub_share(&z_i_hat, params);
        open_z[i] = (z_diff_share.value, z_diff_share.big_m);
        z_diff[i] = *z_diff_share;
    }

    let msg4 = ABTMsg4 {
        session_id: state_ob.session_id,
        mul_shares_open,
        open_z,
    };

    let state = ABTStateOBR2 {
        session_id: state_ob.session_id,
        p: state_ob.p,
        eta_m,
        z_diff,
    };

    mul_shares_ob.truncate(eta_m);

    Ok((state, msg4))
}

/// CB processes ABTMsg4 from OB
pub fn abt_process_msg4(
    state_cb: &ABTStateCBR2,
    mul_shares_cb: &[TripleShare],
    msg4: &ABTMsg4,
) -> Result<ABTMsg5, ABTCBError> {
    let params = DynResidueParams::new(&state_cb.p);
    let eta_m = state_cb.eta_m;

    if state_cb.session_id != msg4.session_id {
        return Err(ABTCBError::InvalidSessionID);
    }
    if state_cb.mul_shares_state.len() != eta_m {
        return Err(ABTCBError::InvalidState);
    }
    if mul_shares_cb.len() != eta_m {
        return Err(ABTCBError::InvalidState);
    }
    if msg4.mul_shares_open.len() != eta_m {
        return Err(ABTCBError::InvalidMessage);
    }
    if msg4.open_z.len() != eta_m {
        return Err(ABTCBError::InvalidMessage);
    }

    let mut open_z = vec![(U128::ZERO, U128::ZERO); eta_m];
    for i in 0..eta_m {
        // validate Open(d) and Open(e) from CB
        let z_i_hat = match multiply_shares_output(
            &state_cb.mul_shares_state[i],
            &msg4.mul_shares_open[i],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(ABTCBError::InvalidOpen),
        };

        let z_diff_share = &mul_shares_cb[i].z.sub_share(&z_i_hat, params);
        open_z[i] = (z_diff_share.value, z_diff_share.big_m);

        // validate Open(z_diff)
        let z_diff_value =
            match z_diff_share.validate_open(&msg4.open_z[i].0, &msg4.open_z[i].1, params) {
                Ok(v) => v,
                Err(_) => {
                    return Err(ABTCBError::InvalidOpen);
                }
            };

        if z_diff_value != U128::ZERO {
            return Err(ABTCBError::InvalidOpen);
        }
    }

    let msg5 = ABTMsg5 {
        session_id: state_cb.session_id,
        open_z,
    };

    Ok(msg5)
}

/// OB processes ABTMsg5 from CB
pub fn abt_process_msg5(state_ob: &ABTStateOBR2, msg5: &ABTMsg5) -> Result<(), ABTOBError> {
    let eta_m = state_ob.eta_m;
    let params = DynResidueParams::new(&state_ob.p);

    if state_ob.session_id != msg5.session_id {
        return Err(ABTOBError::InvalidSessionID);
    }
    if state_ob.z_diff.len() != eta_m {
        return Err(ABTOBError::InvalidState);
    }
    if msg5.open_z.len() != eta_m {
        return Err(ABTOBError::InvalidMessage);
    }

    for i in 0..eta_m {
        let z_diff_share = &state_ob.z_diff[i];

        // validate Open(z_diff)
        let z_diff_value =
            match z_diff_share.validate_open(&msg5.open_z[i].0, &msg5.open_z[i].1, params) {
                Ok(v) => v,
                Err(_) => {
                    return Err(ABTOBError::InvalidOpen);
                }
            };

        if z_diff_value != U128::ZERO {
            return Err(ABTOBError::InvalidOpen);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfm_init_protocol::generate_cfm_ot_seeds_for_test;
    use crate::P;
    use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
    use rand::Rng;

    #[test]
    fn test_auth_triples() {
        let mut rng = rand::thread_rng();
        let init_session_id: [u8; 32] = rng.gen();

        let (ot_seeds_cb, ot_seeds_ob) = generate_cfm_ot_seeds_for_test(&init_session_id, &mut rng);

        let session_id: [u8; 32] = rng.gen();
        let p_prime = P;
        let params = DynResidueParams::new(&p_prime);
        let eta_i = 5;
        let eta_m = 10;

        let (state_cb_r1, msg1) =
            abt_create_msg1(&session_id, &ot_seeds_cb, p_prime, eta_i, eta_m, &mut rng);
        let (state_ob_r1, mut input_shares_ob, mut triple_shares_ob, msg2) = abt_process_msg1(
            &session_id,
            &ot_seeds_ob,
            p_prime,
            eta_i,
            eta_m,
            &msg1,
            &mut rng,
        )
        .unwrap();
        let (state_cb_r2, input_shares_cb, triple_shares_cb, msg3) =
            abt_process_msg2(&state_cb_r1, &ot_seeds_cb, &msg2, &mut rng).unwrap();
        let (state_ob_r2, msg4) = abt_process_msg3(
            &state_ob_r1,
            &mut input_shares_ob,
            &mut triple_shares_ob,
            &msg3,
        )
        .unwrap();
        let msg5 = abt_process_msg4(&state_cb_r2, &triple_shares_cb, &msg4).unwrap();
        abt_process_msg5(&state_ob_r2, &msg5).unwrap();

        assert_eq!(input_shares_ob.len(), eta_i);
        assert_eq!(input_shares_cb.len(), eta_i);

        assert_eq!(triple_shares_cb.len(), eta_m);
        assert_eq!(triple_shares_ob.len(), eta_m);

        for i in 0..eta_i {
            let x_cb = &input_shares_cb[i];
            let x_ob = &input_shares_ob[i];

            // M^{x,CB} = x^CB * Delta^{OB} - delta^{x,OB}
            let left =
                DynResidue::new(&x_cb.big_m, params).add(&DynResidue::new(&x_ob.delta, params));
            let right =
                DynResidue::new(&x_cb.value, params).mul(&DynResidue::new(&x_ob.big_delta, params));
            assert_eq!(left.retrieve(), right.retrieve());
        }

        for i in 0..eta_m {
            let x_cb = &triple_shares_cb[i].x;
            let y_cb = &triple_shares_cb[i].y;
            let z_cb = &triple_shares_cb[i].z;

            let x_ob = &triple_shares_ob[i].x;
            let y_ob = &triple_shares_ob[i].y;
            let z_ob = &triple_shares_ob[i].z;

            // x * y = z
            let x = DynResidue::new(&x_cb.value, params).add(&DynResidue::new(&x_ob.value, params));
            let y = DynResidue::new(&y_cb.value, params).add(&DynResidue::new(&y_ob.value, params));
            let z = DynResidue::new(&z_cb.value, params).add(&DynResidue::new(&z_ob.value, params));
            assert_eq!(x.mul(&y).retrieve(), z.retrieve());

            // M^{x,CB} = x^CB * Delta^{OB} - delta^{x,OB}
            let left =
                DynResidue::new(&x_cb.big_m, params).add(&DynResidue::new(&x_ob.delta, params));
            let right =
                DynResidue::new(&x_cb.value, params).mul(&DynResidue::new(&x_ob.big_delta, params));
            assert_eq!(left.retrieve(), right.retrieve());

            // M^{y,CB} = y^CB * Delta^{OB} - delta^{y,OB}
            let left =
                DynResidue::new(&y_cb.big_m, params).add(&DynResidue::new(&y_ob.delta, params));
            let right =
                DynResidue::new(&y_cb.value, params).mul(&DynResidue::new(&y_ob.big_delta, params));
            assert_eq!(left.retrieve(), right.retrieve());

            // M^{z,CB} = z^CB * Delta^{OB} - delta^{z,OB}
            let left =
                DynResidue::new(&z_cb.big_m, params).add(&DynResidue::new(&z_ob.delta, params));
            let right =
                DynResidue::new(&z_cb.value, params).mul(&DynResidue::new(&z_ob.big_delta, params));
            assert_eq!(left.retrieve(), right.retrieve());
        }
    }
}
