//! Private Capital Flow Management 4.13 implementation
//! with fixed bit length parameter l = 128, B = 47
//! Protocol gets 4l+B+5 = 4 * 128 + 47 + 5 = 564 shares and
//! 4l+B + 2*375 + 2 = 559 + 2*375 + 3 = 1312 authenticated beaver triples

use crate::auth_beaver_triples::{
    multiply_shares_open, multiply_shares_output, test_bit_open, test_bit_output, MulSharesOpen,
    MulSharesState, Share, TripleShare,
};
use crate::comparison::{
    comp_create_msg1, comp_process_msg1, comp_process_msg2, comp_process_msg3, comp_process_msg4,
    comp_process_msg5, comp_process_msg6, comp_process_msg7, comp_process_msg8, comp_process_msg9,
    CompMsg1, CompMsg2, CompMsg3, CompMsg4, CompMsg5, CompMsg6, CompMsg7, CompMsg8, CompMsg9,
    CompStateP1R0, CompStateP1R2, CompStateP1R4, CompStateP1R6, CompStateP2R1, CompStateP2R3,
    CompStateP2R5, CompStateP2R7,
};
use crate::constants::{B_PARAMETER, CFM_LABEL};

use crate::errors::CFMError;
use crate::psit_protocol::{
    psit_create_msg1, psit_process_msg1, psit_process_msg2, PSITMsg1, PSITMsg2, PSITStateOB,
};
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Random, U128, U64};
use merlin::Transcript;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::Choice;

const L: usize = 128;
pub const NUMBER_OF_SHARES: usize = 4 * L + B_PARAMETER + 5;
const AUTH_TRIPLES_OFFSET: usize = 4 * L + B_PARAMETER;
pub const NUMBER_OF_AUTH_BEAVER_TRIPLES: usize = AUTH_TRIPLES_OFFSET + 2 * 375 + 3;
use std::sync::{Arc, Mutex};


/// CFMMsg1
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg1 {
    /// session id
    pub session_id: [u8; 32],

    /// PSITMsg1
    pub psit_msg1: PSITMsg1,

    /// Open for CB-Input([x_i], Z_i^CB)
    #[serde(with = "serde_arrays")]
    pub open_0: [(U128, U128); L],

    /// Open for CB-Input([x_{l+i}], W_i^CB)
    #[serde(with = "serde_arrays")]
    pub open_1: [(U128, U128); L],

    /// Open for CB-Input([/gamma_0], /alpha)
    pub open_2: (U128, U128),

    /// Open for CB-Input([/gamma_1], /beta)
    pub open_3: (U128, U128),

    /// Open for CB-Input([/gamma_3], r_CB)
    pub open_4: (U128, U128),
}

/// CFMMsg2
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CFMMsg2 {
    /// session id
    pub session_id: [u8; 32],

    /// PSITMsg2
    pub psit_msg2: PSITMsg2,

    /// d from CB-Input([x_i], Z_i^CB)
    #[serde(with = "serde_arrays")]
    pub d_0: [U128; L],

    /// d from CB-Input([x_{l+i}], W_i^CB)
    #[serde(with = "serde_arrays")]
    pub d_1: [U128; L],

    /// d from CB-Input([/gamma_0], /alpha)
    pub d_2: U128,

    /// d from CB-Input([/gamma_1], /beta)
    pub d_3: U128,

    /// d from CB-Input([/gamma_3], r_CB)
    pub d_4: U128,

    /// Open for OB-Input([/gamma_2], M_Y)
    pub open_0: (U128, U128),

    /// Open for OB-Input([x_{2l+i}], Z_{Y,i}^OB)
    #[serde(with = "serde_arrays")]
    pub open_1: [(U128, U128); L],

    /// Open for OB-Input([x_{3l+i}], X_i)
    #[serde(with = "serde_arrays")]
    pub open_2: [(U128, U128); B_PARAMETER],

    /// Open for OB-Input([x_{4l+i}], U_i)
    #[serde(with = "serde_arrays")]
    pub open_3: [(U128, U128); L],

    /// Open for OB-Input([/gamma_4], r_OB)
    pub open_4: (U128, U128),

    /// Open Z_{l-1}^CB
    pub open_z_l_minus_1: (U128, U128),
}

/// CFMMsg3
/// 46kB
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg3 {
    /// session id
    pub session_id: [u8; 32],

    /// d from OB-Input([/gamma_2], /M_Y)
    pub d_0: U128,

    /// d from OB-Input([x_{2l+i}], Z_{Y,i}^OB)
    #[serde(with = "serde_arrays")]
    pub d_1: [U128; L],

    /// d from OB-Input([x_{3l+i}], X_i)
    #[serde(with = "serde_arrays")]
    pub d_2: [U128; B_PARAMETER],

    /// d from OB-Input([x_{4l+i}], U_i)
    #[serde(with = "serde_arrays")]
    pub d_3: [U128; L],

    /// d from OB-Input([/gamma_4], r_OB)
    pub d_4: U128,

    /// mul_open for TestBit([Z_i^CB]), TestBit([W_i]),
    /// TestBit([Z_{Y,i}^OB]), TestBit([X_i]), TestBit([U_i])
    #[serde(with = "serde_arrays")]
    pub mul_open_test_bit: [MulSharesOpen; NUMBER_OF_SHARES - 3],
}

/// CFMMsg4
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg4 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open for TestBit([Z_i^CB]), TestBit([W_i]),
    /// TestBit([Z_{Y,i}^OB]), TestBit([X_i]), TestBit([U_i])
    #[serde(with = "serde_arrays")]
    pub mul_open_test_bit: [MulSharesOpen; NUMBER_OF_SHARES - 3],

    /// Open([t_i]), i /in [0, 5l-1]
    #[serde(with = "serde_arrays")]
    pub open_t_i: [(U128, U128); NUMBER_OF_SHARES - 3],
}

/// CFMMsg5
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg5 {
    /// session id
    pub session_id: [u8; 32],

    /// Open([t_i]), i /in [0, 5l-1]
    #[serde(with = "serde_arrays")]
    pub open_t_i: [(U128, U128); NUMBER_OF_SHARES - 3],

    /// Open([V])
    pub open_v: (U128, U128),

    /// Open([T])
    pub open_t: (U128, U128),
}

/// CFMMsg6
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg6 {
    /// session id
    pub session_id: [u8; 32],

    /// Open([V])
    pub open_v: (U128, U128),

    /// Open([T])
    pub open_t: (U128, U128),

    /// CompMsg1
    pub comp_msg1_c: CompMsg1,

    /// CompMsg1
    pub comp_msg1_b: CompMsg1,
}

/// CFMMsg7
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg7 {
    /// session id
    pub session_id: [u8; 32],

    /// CompMsg2
    pub comp_msg2_c: CompMsg2,

    /// CompMsg2
    pub comp_msg2_b: CompMsg2,
}

/// CFMMsg8
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg8 {
    /// session id
    pub session_id: [u8; 32],

    /// CompMsg3
    pub comp_msg3_c: CompMsg3,

    /// CompMsg3
    pub comp_msg3_b: CompMsg3,
}

/// CFMMsg9
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg9 {
    /// session id
    pub session_id: [u8; 32],

    /// CompMsg4
    pub comp_msg4_c: CompMsg4,

    /// CompMsg4
    pub comp_msg4_b: CompMsg4,
}

/// CFMMsg10
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg10 {
    /// session id
    pub session_id: [u8; 32],

    /// CompMsg5
    pub comp_msg5_c: CompMsg5,

    /// CompMsg5
    pub comp_msg5_b: CompMsg5,
}

/// CFMMsg11
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg11 {
    /// session id
    pub session_id: [u8; 32],

    /// CompMsg6
    pub comp_msg6_c: CompMsg6,

    /// CompMsg6
    pub comp_msg6_b: CompMsg6,
}

/// CFMMsg12
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg12 {
    /// session id
    pub session_id: [u8; 32],

    /// CompMsg7
    pub comp_msg7_c: CompMsg7,

    /// CompMsg7
    pub comp_msg7_b: CompMsg7,
}

/// CFMMsg13
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg13 {
    /// session id
    pub session_id: [u8; 32],

    /// CompMsg8
    pub comp_msg8_c: CompMsg8,

    /// CompMsg8
    pub comp_msg8_b: CompMsg8,

    /// mul_open for [a] = Multiply([/alpha], [Z_Y^OB])
    pub mul_open_a: MulSharesOpen,
}

/// CFMMsg14
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg14 {
    /// session id
    pub session_id: [u8; 32],

    /// CompMsg9
    pub comp_msg9_c: CompMsg9,

    /// CompMsg9
    pub comp_msg9_b: CompMsg9,

    /// mul_open for [a] = Multiply([/alpha], [Z_Y^OB])
    pub mul_open_a: MulSharesOpen,

    /// mul_open for Multiply((1 - [c]), (1 - [z]))
    pub mul_open_f1: MulSharesOpen,
}

/// CFMMsg15
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg15 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open for Multiply((1 - [c]), (1 - [z]))
    pub mul_open_f1: MulSharesOpen,

    /// mul_open for [f] = Multiply(1 − [f1], [r])
    pub mul_open_f: MulSharesOpen,
}

/// CFMMsg16
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg16 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open for [f] = Multiply(1 − [f1], [r])
    pub mul_open_f: MulSharesOpen,

    /// Open([f])
    pub open_f: (U128, U128),
}

/// CFMMsg17
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg17 {
    /// session id
    pub session_id: [u8; 32],

    /// Open([f])
    pub open_f: (U128, U128),

    /// Open([b])
    pub open_b: (U128, U128),
}

/// CFMMsg18
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMMsg18 {
    /// session id
    pub session_id: [u8; 32],

    /// Open([b])
    pub open_b: (U128, U128),
}

/// CFM State for OB round1
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR1 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// L
    pub big_l: U64,

    /// X
    pub big_x: U64,

    /// PSITStateOB
    pub psit_state_ob: PSITStateOB,
}

/// CFM State for CB round1
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateCBR1 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// L
    pub big_l: U64,

    /// z_i_cb shares
    #[serde(with = "serde_arrays")]
    pub z_i_cb_shares: [Share; L],

    /// w_i shares
    #[serde(with = "serde_arrays")]
    pub w_i_shares: [Share; L],

    /// alpha share
    pub alpha_share: Share,

    /// beta share
    pub beta_share: Share,

    /// r_cb share
    pub r_cb_share: Share,
}

/// CFM State for OB round2
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR2 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// L
    pub big_l: U64,

    /// r share
    pub r_share: Share,

    /// alpha share
    pub alpha_share: Share,

    /// beta share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// z_i_cb shares
    #[serde(with = "serde_arrays")]
    pub z_i_cb_shares: [Share; L],

    /// w_i shares
    #[serde(with = "serde_arrays")]
    pub w_i_shares: [Share; L],

    /// z_y_i_ob shares
    #[serde(with = "serde_arrays")]
    pub z_y_i_ob_shares: [Share; L],

    /// x_i shares
    #[serde(with = "serde_arrays")]
    pub x_i_shares: [Share; B_PARAMETER],

    /// u_i shares
    #[serde(with = "serde_arrays")]
    pub u_i_shares: [Share; L],

    /// mul_state_test_bit
    #[serde(with = "serde_arrays")]
    pub mul_state_test_bit: [MulSharesState; NUMBER_OF_SHARES - 3],
}

/// CFM State for CB round2
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateCBR2 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// L
    pub big_l: U64,

    /// r share
    pub r_share: Share,

    /// alpha share
    pub alpha_share: Share,

    /// beta share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// z_i_cb shares
    #[serde(with = "serde_arrays")]
    pub z_i_cb_shares: [Share; L],

    /// w_i shares
    #[serde(with = "serde_arrays")]
    pub w_i_shares: [Share; L],

    /// z_y_i_ob shares
    #[serde(with = "serde_arrays")]
    pub z_y_i_ob_shares: [Share; L],

    /// x_i shares
    #[serde(with = "serde_arrays")]
    pub x_i_shares: [Share; B_PARAMETER],

    /// u_i shares
    #[serde(with = "serde_arrays")]
    pub u_i_shares: [Share; L],

    /// t_i shares
    #[serde(with = "serde_arrays")]
    pub t_i_shares: [Share; NUMBER_OF_SHARES - 3],
}

/// CFM State for OB round3
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR3 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// big_m_y share
    pub alpha_share: Share,

    /// big_m_y share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// big_z_y_ob share
    pub big_z_y_ob_share: Share,

    /// z_i_cb shares
    #[serde(with = "serde_arrays")]
    pub z_i_cb_shares: [Share; L],

    /// w_i shares
    #[serde(with = "serde_arrays")]
    pub w_i_shares: [Share; L],

    /// z_y_i_ob shares
    #[serde(with = "serde_arrays")]
    pub z_y_i_ob_shares: [Share; L],

    /// x_i shares
    #[serde(with = "serde_arrays")]
    pub x_i_shares: [Share; B_PARAMETER],

    /// u_i shares
    #[serde(with = "serde_arrays")]
    pub u_i_shares: [Share; L],

    /// big_v share
    pub big_v: Share,

    /// big_t share
    pub big_t: Share,
}

/// CFM State for CB round3
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateCBR3 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// alpha share
    pub alpha_share: Share,

    /// beta share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// big_z_y_ob_share share
    pub big_z_y_ob_share: Share,

    /// comp_0_state_cb_r0
    pub comp_0_state_cb_r0: CompStateP1R0,

    /// comp_1_state_cb_r0
    pub comp_1_state_cb_r0: CompStateP1R0,

    /// z_i_cb shares
    #[serde(with = "serde_arrays")]
    pub z_i_cb_shares: [Share; L],

    /// w_i shares
    #[serde(with = "serde_arrays")]
    pub w_i_shares: [Share; L],

    /// z_y_i_ob shares
    #[serde(with = "serde_arrays")]
    pub z_y_i_ob_shares: [Share; L],

    /// u_i shares
    #[serde(with = "serde_arrays")]
    pub u_i_shares: [Share; L],
}

/// CFM State for OB round4
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR4 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// big_m_y share
    pub alpha_share: Share,

    /// big_m_y share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// big_z_y_ob share
    pub big_z_y_ob_share: Share,

    /// comp_0_state_ob_r1
    pub comp_0_state_ob_r1: CompStateP2R1,

    /// comp_1_state_ob_r1
    pub comp_1_state_ob_r1: CompStateP2R1,
}

/// CFM State for CB round4
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateCBR4 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// alpha share
    pub alpha_share: Share,

    /// beta share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// big_z_y_ob_share share
    pub big_z_y_ob_share: Share,

    /// comp_0_state_cb_r2
    pub comp_0_state_cb_r2: CompStateP1R2,

    /// comp_1_state_cb_r2
    pub comp_1_state_cb_r2: CompStateP1R2,
}

/// CFM State for OB round5
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR5 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// big_m_y share
    pub alpha_share: Share,

    /// big_m_y share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// big_z_y_ob share
    pub big_z_y_ob_share: Share,

    /// comp_1_state_ob_r3
    pub comp_0_state_ob_r3: CompStateP2R3,

    /// comp_1_state_ob_r3
    pub comp_1_state_ob_r3: CompStateP2R3,
}

/// CFM State for CB round5
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateCBR5 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// alpha share
    pub alpha_share: Share,

    /// beta share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// big_z_y_ob_share share
    pub big_z_y_ob_share: Share,

    /// comp_0_state_cb_r4
    pub comp_0_state_cb_r4: CompStateP1R4,

    /// comp_1_state_cb_r4
    pub comp_1_state_cb_r4: CompStateP1R4,
}

/// CFM State for OB round6
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR6 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// big_m_y share
    pub alpha_share: Share,

    /// big_m_y share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// big_z_y_ob share
    pub big_z_y_ob_share: Share,

    /// comp_0_state_ob_r5
    pub comp_0_state_ob_r5: CompStateP2R5,

    /// comp_0_state_ob_r5
    pub comp_1_state_ob_r5: CompStateP2R5,
}

/// CFM State for CB round6
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateCBR6 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// alpha share
    pub alpha_share: Share,

    /// beta share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// big_z_y_ob_share share
    pub big_z_y_ob_share: Share,

    /// comp_0_state_cb_r4
    pub comp_0_state_cb_r6: CompStateP1R6,

    /// comp_1_state_cb_r4
    pub comp_1_state_cb_r6: CompStateP1R6,
}

/// CFM State for OB round7
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR7 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// big_m_y share
    pub beta_share: Share,

    /// big_m_y share
    pub big_m_y_share: Share,

    /// comp_0_state_ob_r7
    pub comp_0_state_ob_r7: CompStateP2R7,

    /// comp_0_state_ob_r7
    pub comp_1_state_ob_r7: CompStateP2R7,

    /// mul_state_a
    pub mul_state_a: MulSharesState,

    /// auth_triple_2
    pub auth_triple_2: TripleShare,

    /// auth_triple_3
    pub auth_triple_3: TripleShare,
}

/// CFM State for CB round7
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateCBR7 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// r share
    pub r_share: Share,

    /// c_share share
    pub c_share: Share,

    /// b_share share
    pub b_share: Share,

    /// mul_state_f1
    pub mul_state_f1: MulSharesState,

    /// auth_triple_3
    pub auth_triple_3: TripleShare,
}

/// CFM State for OB round8
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR8 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// b_share share
    pub b_share: Share,

    /// mul_state_f
    pub mul_state_f: MulSharesState,
}

/// CFM State for CB round8
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateCBR8 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// b share
    pub b_share: Share,

    /// f share
    pub f_share: Share,
}

/// CFM State for OB round9
#[derive(Clone, Serialize, Deserialize)]
pub struct CFMStateOBR9 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// b_share share
    pub b_share: Share,
}

/// MAC function for CFM protocol
fn mac_function(alpha: &U128, beta: &U128, z_y_ob: &U128, params: DynResidueParams<2>) -> U128 {
    DynResidue::new(alpha, params)
        .mul(&DynResidue::new(z_y_ob, params))
        .add(&DynResidue::new(beta, params))
        .retrieve()
}

/// OB creates CFMMsg1 for CB
pub fn cfm_create_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    p: U128,
    big_l: U64,
    big_x: U64,
    y: &[u8; 32],
    x_shares: &[Share],
    rng: &mut R,
) -> (CFMStateOBR1, Box<CFMMsg1>) {
    assert!(
        p > U128::ONE
            .shl(L - 1)
            .saturating_add(&U128::ONE.shl(B_PARAMETER + 1))
    );
    let two_pow_b = U64::ONE.shl(B_PARAMETER);
    assert!(big_l < two_pow_b);
    assert!(big_x < two_pow_b);
    assert_eq!(x_shares.len(), NUMBER_OF_SHARES);

    let mut t = Transcript::new(CFM_LABEL.as_ref());
    t.append_message(b"session-id", session_id);
    let mut psit_session_id = [0u8; 32];
    t.challenge_bytes(b"psit-session-id", &mut psit_session_id);

    let (psit_state_ob, psit_msg1) = psit_create_msg1(&psit_session_id, y, &mut *rng);

    let mut open_0 = [(U128::ZERO, U128::ZERO); L];
    let mut open_1 = [(U128::ZERO, U128::ZERO); L];
    for i in 0..L {
        let x_share_0 = x_shares[i];
        let x_share_1 = x_shares[i + L];
        open_0[i] = x_share_0.open();
        open_1[i] = x_share_1.open();
    }

    let gamma_0 = x_shares[NUMBER_OF_SHARES - 5];
    let gamma_1 = x_shares[NUMBER_OF_SHARES - 4];
    let gamma_3 = x_shares[NUMBER_OF_SHARES - 2];
    let open_2 = gamma_0.open();
    let open_3 = gamma_1.open();
    let open_4 = gamma_3.open();

    let state = CFMStateOBR1 {
        session_id: *session_id,
        p,
        big_l,
        big_x,
        psit_state_ob,
    };
    let msg1 = Box::new(CFMMsg1 {
        session_id: *session_id,
        psit_msg1,
        open_0,
        open_1,
        open_2,
        open_3,
        open_4,
    });

    (state, msg1)
}

/// CB processes CFMMsg1 from OB
#[allow(clippy::too_many_arguments)]
pub fn cfm_process_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    p: U128,
    big_l: U64,
    big_y: Vec<[u8; 32]>,
    big_z: Vec<U64>,
    x_shares: &[Share],
    msg1: &CFMMsg1,
    rng: &mut R,
) -> Result<(Box<CFMStateCBR1>, Box<CFMMsg2>), CFMError> {
    assert!(
        p > U128::ONE
            .shl(L - 1)
            .saturating_add(&U128::ONE.shl(B_PARAMETER + 1))
    );
    let two_pow_b = U64::ONE.shl(B_PARAMETER);
    assert!(big_l < two_pow_b);
    assert_eq!(x_shares.len(), NUMBER_OF_SHARES);

    if *session_id != msg1.session_id {
        return Err(CFMError::InvalidSessionID);
    }
    let params = DynResidueParams::new(&p);

    //  Z_CB ← Z_{2^{ℓ−1}}
    let mut big_z_cb_bytes: [u8; 16] = rng.gen();
    big_z_cb_bytes[15] &= 0x7f;
    let big_z_cb = U128::from_le_slice(&big_z_cb_bytes);

    let big_z_cb_dyn_res = DynResidue::new(&big_z_cb, params);
    let big_w = big_z_cb_dyn_res
        .add(&DynResidue::new(&big_l.resize(), params))
        .retrieve();

    let big_z_ob = big_z
        .iter()
        .map(|x| {
            big_z_cb_dyn_res
                .add(&DynResidue::new(&x.resize(), params))
                .retrieve()
        })
        .collect::<Vec<U128>>();

    let alpha = DynResidue::new(&U128::random(&mut *rng), params).retrieve();
    let beta = DynResidue::new(&U128::random(&mut *rng), params).retrieve();

    let big_mac = big_z_ob
        .iter()
        .map(|x| mac_function(&alpha, &beta, x, params))
        .collect::<Vec<U128>>();

    let mut t = Transcript::new(CFM_LABEL.as_ref());
    t.append_message(b"session-id", session_id);
    let mut psit_session_id = [0u8; 32];
    t.challenge_bytes(b"psit-session-id", &mut psit_session_id);

    let psit_msg2 = match psit_process_msg1(
        &psit_session_id,
        big_y,
        big_z_ob,
        big_mac,
        &msg1.psit_msg1,
        &mut *rng,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::PSITError),
    };

    let mut d_0 = [U128::ZERO; L];
    let mut d_1 = [U128::ZERO; L];
    let mut z_i_cb_shares = [Share::default(); L];
    let mut w_i_shares = [Share::default(); L];
    for i in 0..L {
        // CB-Input([x_i], Z_i^CB)
        let x_share_0 = x_shares[i];
        let y_0 = U128::from_u8(Choice::from(big_z_cb.bit(i)).unwrap_u8());
        (z_i_cb_shares[i], d_0[i]) = match x_share_0.cb_input(&msg1.open_0[i], &y_0, params) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };

        // CB-Input([x_{l+i}], W_i^CB)
        let x_share_1 = x_shares[i + L];
        let y_1 = U128::from_u8(Choice::from(big_w.bit(i)).unwrap_u8());
        (w_i_shares[i], d_1[i]) = match x_share_1.cb_input(&msg1.open_1[i], &y_1, params) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
    }

    let gamma_0 = x_shares[NUMBER_OF_SHARES - 5];
    let gamma_1 = x_shares[NUMBER_OF_SHARES - 4];
    let gamma_2 = x_shares[NUMBER_OF_SHARES - 3];
    let gamma_3 = x_shares[NUMBER_OF_SHARES - 2];
    let gamma_4 = x_shares[NUMBER_OF_SHARES - 1];

    // CB-Input([/gamma_0], /alpha)
    let (alpha_share, d_2) = match gamma_0.cb_input(&msg1.open_2, &alpha, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    // CB-Input([/gamma_1], /beta)
    let (beta_share, d_3) = match gamma_1.cb_input(&msg1.open_3, &beta, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    // CB-Input([/gamma_3], r_CB)
    let r_cb = DynResidue::new(&U128::random(&mut *rng), params).retrieve();
    let (r_cb_share, d_4) = match gamma_3.cb_input(&msg1.open_4, &r_cb, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    let open_0 = gamma_2.open();
    let open_4 = gamma_4.open();
    let mut open_1 = [(U128::ZERO, U128::ZERO); L];
    let mut open_2 = [(U128::ZERO, U128::ZERO); B_PARAMETER];
    let mut open_3 = [(U128::ZERO, U128::ZERO); L];
    let offset = 2 * L;
    for i in 0..L {
        let x_share_1 = x_shares[offset + i];
        open_1[i] = x_share_1.open();
    }
    let offset = 3 * L;
    for i in 0..B_PARAMETER {
        let x_share_2 = x_shares[offset + i];
        open_2[i] = x_share_2.open();
    }
    let offset = 3 * L + B_PARAMETER;
    for i in 0..L {
        let x_share_3 = x_shares[offset + i];
        open_3[i] = x_share_3.open();
    }

    let state = Box::new(CFMStateCBR1 {
        session_id: *session_id,
        p,
        big_l,
        z_i_cb_shares,
        w_i_shares,
        alpha_share,
        beta_share,
        r_cb_share,
    });

    let msg2 = Box::new(CFMMsg2 {
        session_id: *session_id,
        psit_msg2,
        d_0,
        d_1,
        d_2,
        d_3,
        d_4,
        open_0,
        open_1,
        open_2,
        open_3,
        open_4,
        open_z_l_minus_1: z_i_cb_shares[L - 1].open(),
    });

    Ok((state, msg2))
}

/// OB processes CFMMsg2 from CB
pub fn cfm_process_msg2<R: CryptoRng + RngCore>(
    state: &CFMStateOBR1,
    x_shares: &[Share],
    auth_triples: &[TripleShare],
    msg2: &CFMMsg2,
    rng: &mut R,
) -> Result<(Box<CFMStateOBR2>, Box<CFMMsg3>), CFMError> {
    assert_eq!(x_shares.len(), NUMBER_OF_SHARES);

    if state.session_id != msg2.session_id {
        return Err(CFMError::InvalidSessionID);
    }
    let params = DynResidueParams::new(&state.p);

    let mut z_i_cb_shares = [Share::default(); L];
    let mut w_i_shares = [Share::default(); L];

    // println!("THE STATE PARAM IS {:#?}", state.p);
    // println!("THE PARAMS IS {:#?}", params);
    // println!("THE MSG2 d_0 is {:#?}", msg2.d_0);


    for i in 0..L {
        // println!("THE X share I is {:#?}", x_shares[i]);

        // CB-Input([x_i], Z_i^CB)
        z_i_cb_shares[i] = x_shares[i].add_const_ob(&msg2.d_0[i], params);
        // CB-Input([x_{l+i}], W_i^CB)
        w_i_shares[i] = x_shares[i + L].add_const_ob(&msg2.d_1[i], params);
    }

    // println!("111111111111");

    // println!("z_i_cb_shares is {:#?} \n\n\n", z_i_cb_shares[L-1]);

    // println!("\n\n THE MESSAGE 2 is {:#?}", msg2.open_z_l_minus_1);

    // check that Z_{L-1}^CB = 0
    let z_l_minus_1_value = match z_i_cb_shares[L - 1].validate_open(
        &msg2.open_z_l_minus_1.0,
        &msg2.open_z_l_minus_1.1,
        params,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };
    if z_l_minus_1_value != U128::ZERO {
        return Err(CFMError::AbortProtocol);
    }

    let gamma_0 = x_shares[NUMBER_OF_SHARES - 5];
    let gamma_1 = x_shares[NUMBER_OF_SHARES - 4];
    let gamma_2 = x_shares[NUMBER_OF_SHARES - 3];
    let gamma_3 = x_shares[NUMBER_OF_SHARES - 2];
    let gamma_4 = x_shares[NUMBER_OF_SHARES - 1];

    // CB-Input([/gamma_0], /alpha)
    let alpha_share = gamma_0.add_const_ob(&msg2.d_2, params);

    // CB-Input([/gamma_1], /beta)
    let beta_share = gamma_1.add_const_ob(&msg2.d_3, params);

    // CB-Input([/gamma_3], r_CB)
    let r_cb_share = gamma_3.add_const_ob(&msg2.d_4, params);

    let (z_y_ob, big_m_y) = match psit_process_msg2(&state.psit_state_ob, &msg2.psit_msg2) {
        Ok(v) => v,
        Err(_) => (
            U128::ZERO,
            DynResidue::new(&U128::random(&mut *rng), params).retrieve(),
        ),
    };

    let big_u = DynResidue::new(&state.big_x.resize(), params)
        .add(&DynResidue::new(&z_y_ob, params))
        .retrieve();

    // println!("22222222222222");


    // OB-Input([/gamma_2], /M_Y)
    let (big_m_y_share, d_0) = match gamma_2.ob_input(&msg2.open_0, &big_m_y, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    // println!("33333333333333");


    // OB-Input([/gamma_4], r_OB)
    let r_ob = DynResidue::new(&U128::random(&mut *rng), params).retrieve();
    let (r_ob_share, d_4) = match gamma_4.ob_input(&msg2.open_4, &r_ob, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    let r_share = r_cb_share.add_share(&r_ob_share, params);

    let mut d_1 = [U128::ZERO; L];
    let mut d_2 = [U128::ZERO; B_PARAMETER];
    let mut d_3 = [U128::ZERO; L];
    let mut z_y_i_ob_shares = [Share::default(); L];
    let mut x_i_shares = [Share::default(); B_PARAMETER];
    let mut u_i_shares = [Share::default(); L];
    let offset = 2 * L;
    for i in 0..L {
        // OB-Input([x_{2l+i}], Z_{Y,i}^OB)
        let x_share = x_shares[offset + i];
        let y = U128::from_u8(Choice::from(z_y_ob.bit(i)).unwrap_u8());
        // println!("444444444444444 {:?}", i);

        (z_y_i_ob_shares[i], d_1[i]) = match x_share.ob_input(&msg2.open_1[i], &y, params) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
    }
    let offset = 3 * L;
    for i in 0..B_PARAMETER {
        // OB-Input([x_{3l+i}], X_i)
        let x_share = x_shares[offset + i];
        let y = U128::from_u8(Choice::from(state.big_x.bit(i)).unwrap_u8());
        // println!("55555555555555 {:?}", i);

        (x_i_shares[i], d_2[i]) = match x_share.ob_input(&msg2.open_2[i], &y, params) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
    }
    let offset = 3 * L + B_PARAMETER;
    for i in 0..L {
        // OB-Input([x_{4l+i}], U_i)
        let x_share = x_shares[offset + i];
        let y = U128::from_u8(Choice::from(big_u.bit(i)).unwrap_u8());
        // println!("666666666666666 {:?}", i);

        (u_i_shares[i], d_3[i]) = match x_share.ob_input(&msg2.open_3[i], &y, params) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
    }

    let mut mul_state_test_bit = [MulSharesState::default(); NUMBER_OF_SHARES - 3];
    let mut mul_open_test_bit = [MulSharesOpen::default(); NUMBER_OF_SHARES - 3];
    for i in 0..L {
        let auth_triple = &auth_triples[i];
        (mul_state_test_bit[i], mul_open_test_bit[i]) = test_bit_open(
            &z_i_cb_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            false,
            &state.p,
            params,
        );

        let auth_triple = &auth_triples[L + i];
        (mul_state_test_bit[L + i], mul_open_test_bit[L + i]) = test_bit_open(
            &w_i_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            false,
            &state.p,
            params,
        );

        let auth_triple = &auth_triples[2 * L + i];
        (mul_state_test_bit[2 * L + i], mul_open_test_bit[2 * L + i]) = test_bit_open(
            &z_y_i_ob_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            false,
            &state.p,
            params,
        );
    }
    let offset = 3 * L;
    for i in 0..B_PARAMETER {
        let auth_triple = &auth_triples[offset + i];
        (
            mul_state_test_bit[offset + i],
            mul_open_test_bit[offset + i],
        ) = test_bit_open(
            &x_i_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            false,
            &state.p,
            params,
        );
    }
    let offset = 3 * L + B_PARAMETER;
    for i in 0..L {
        let auth_triple = &auth_triples[offset + i];
        (
            mul_state_test_bit[offset + i],
            mul_open_test_bit[offset + i],
        ) = test_bit_open(
            &u_i_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            false,
            &state.p,
            params,
        );
    }

    let state = Box::new(CFMStateOBR2 {
        session_id: state.session_id,
        p: state.p,
        big_l: state.big_l,
        r_share,
        alpha_share,
        beta_share,
        big_m_y_share,
        z_i_cb_shares,
        w_i_shares,
        z_y_i_ob_shares,
        x_i_shares,
        u_i_shares,
        mul_state_test_bit,
    });

    let msg3 = Box::new(CFMMsg3 {
        session_id: state.session_id,
        d_0,
        d_1,
        d_2,
        d_3,
        d_4,
        mul_open_test_bit,
    });

    Ok((state, msg3))
}

/// CB processes CFMMsg3 from OB
pub fn cfm_process_msg3(
    state: Box<CFMStateCBR1>,
    x_shares: &[Share],
    auth_triples: &[TripleShare],
    msg3: &CFMMsg3,
) -> Result<(Box<CFMStateCBR2>, Box<CFMMsg4>), CFMError> {
    assert_eq!(x_shares.len(), NUMBER_OF_SHARES);
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg3.session_id {
        return Err(CFMError::InvalidSessionID);
    }
    let params = DynResidueParams::new(&state.p);

    let gamma_2 = x_shares[NUMBER_OF_SHARES - 3];
    let gamma_4 = x_shares[NUMBER_OF_SHARES - 1];

    // OB-Input([/gamma_2], /M_Y)
    let big_m_y_share = gamma_2.add_const_cb(&msg3.d_0, params);

    // OB-Input([/gamma_4], r_OB)
    let r_ob_share = gamma_4.add_const_cb(&msg3.d_4, params);

    let r_share = state.r_cb_share.add_share(&r_ob_share, params);

    let mut z_y_i_ob_shares = [Share::default(); L];
    let mut x_i_shares = [Share::default(); B_PARAMETER];
    let mut u_i_shares = [Share::default(); L];
    let offset = 2 * L;
    for i in 0..L {
        // OB-Input([x_{2l+i}], Z_{Y,i}^OB)
        z_y_i_ob_shares[i] = x_shares[offset + i].add_const_cb(&msg3.d_1[i], params);
    }
    let offset = 3 * L;
    for i in 0..B_PARAMETER {
        // OB-Input([x_{3l+i}], X_i)
        x_i_shares[i] = x_shares[offset + i].add_const_cb(&msg3.d_2[i], params);
    }
    let offset = 3 * L + B_PARAMETER;
    for i in 0..L {
        // OB-Input([x_{3l+i}], X_i)
        u_i_shares[i] = x_shares[offset + i].add_const_cb(&msg3.d_3[i], params);
    }

    let mut t_i_shares = [Share::default(); NUMBER_OF_SHARES - 3];
    let mut open_t_i = [(U128::ZERO, U128::ZERO); NUMBER_OF_SHARES - 3];
    let mut mul_open_test_bit = [MulSharesOpen::default(); NUMBER_OF_SHARES - 3];
    for i in 0..L {
        let auth_triple = &auth_triples[i];
        let (mul_state, mul_open) = test_bit_open(
            &state.z_i_cb_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            true,
            &state.p,
            params,
        );
        mul_open_test_bit[i] = mul_open;
        t_i_shares[i] = match test_bit_output(&mul_state, &msg3.mul_open_test_bit[i], true, params)
        {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
        open_t_i[i] = t_i_shares[i].open();
    }
    let offset = L;
    for i in 0..L {
        let auth_triple = &auth_triples[offset + i];
        let (mul_state, mul_open) = test_bit_open(
            &state.w_i_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            true,
            &state.p,
            params,
        );
        mul_open_test_bit[offset + i] = mul_open;
        t_i_shares[offset + i] = match test_bit_output(
            &mul_state,
            &msg3.mul_open_test_bit[offset + i],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
        open_t_i[offset + i] = t_i_shares[offset + i].open();
    }
    let offset = 2 * L;
    for i in 0..L {
        let auth_triple = &auth_triples[offset + i];
        let (mul_state, mul_open) = test_bit_open(
            &z_y_i_ob_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            true,
            &state.p,
            params,
        );
        mul_open_test_bit[offset + i] = mul_open;
        t_i_shares[offset + i] = match test_bit_output(
            &mul_state,
            &msg3.mul_open_test_bit[offset + i],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
        open_t_i[offset + i] = t_i_shares[offset + i].open();
    }
    let offset = 3 * L;
    for i in 0..B_PARAMETER {
        let auth_triple = &auth_triples[offset + i];
        let (mul_state, mul_open) = test_bit_open(
            &x_i_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            true,
            &state.p,
            params,
        );
        mul_open_test_bit[offset + i] = mul_open;
        t_i_shares[offset + i] = match test_bit_output(
            &mul_state,
            &msg3.mul_open_test_bit[offset + i],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
        open_t_i[offset + i] = t_i_shares[offset + i].open();
    }
    let offset = 3 * L + B_PARAMETER;
    for i in 0..L {
        let auth_triple = &auth_triples[offset + i];
        let (mul_state, mul_open) = test_bit_open(
            &u_i_shares[i],
            &auth_triple.x,
            &auth_triple.y,
            &auth_triple.z,
            true,
            &state.p,
            params,
        );
        mul_open_test_bit[offset + i] = mul_open;
        t_i_shares[offset + i] = match test_bit_output(
            &mul_state,
            &msg3.mul_open_test_bit[offset + i],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
        open_t_i[offset + i] = t_i_shares[offset + i].open();
    }

    let state = Box::new(CFMStateCBR2 {
        session_id: state.session_id,
        p: state.p,
        big_l: state.big_l,
        r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share,
        z_i_cb_shares: state.z_i_cb_shares,
        w_i_shares: state.w_i_shares,
        z_y_i_ob_shares,
        x_i_shares,
        u_i_shares,
        t_i_shares,
    });

    let msg4 = Box::new(CFMMsg4 {
        session_id: state.session_id,
        mul_open_test_bit,
        open_t_i,
    });

    Ok((state, msg4))
}

/// OB processes CFMMsg4 from CB
pub fn cfm_process_msg4(
    state: Box<CFMStateOBR2>,
    msg4: &CFMMsg4,
) -> Result<(Box<CFMStateOBR3>, Box<CFMMsg5>), CFMError> {
    if state.session_id != msg4.session_id {
        return Err(CFMError::InvalidSessionID);
    }
    let params = DynResidueParams::new(&state.p);

    let mut open_t_i = [(U128::ZERO, U128::ZERO); NUMBER_OF_SHARES - 3];
    #[allow(clippy::needless_range_loop)]
    for i in 0..(NUMBER_OF_SHARES - 3) {
        let t_i_share = match test_bit_output(
            &state.mul_state_test_bit[i],
            &msg4.mul_open_test_bit[i],
            false,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
        open_t_i[i] = t_i_share.open();
        let t_i_value =
            match t_i_share.validate_open(&msg4.open_t_i[i].0, &msg4.open_t_i[i].1, params) {
                Ok(v) => v,
                Err(_) => return Err(CFMError::InvalidOpen),
            };
        if t_i_value != U128::ONE {
            return Err(CFMError::AbortProtocol);
        }
    }

    let mut big_z_cb_share = state.z_i_cb_shares[0];
    let mut big_w_share = state.w_i_shares[0];
    let mut big_z_y_ob_share = state.z_y_i_ob_shares[0];
    let mut big_x_share = state.x_i_shares[0];
    let mut big_u_share = state.u_i_shares[0];
    for i in 1..L {
        let power_of_two = U128::ONE.shl(i);
        big_z_cb_share = big_z_cb_share.add_share(
            &state.z_i_cb_shares[i].mul_const(&power_of_two, params),
            params,
        );
        big_w_share = big_w_share.add_share(
            &state.w_i_shares[i].mul_const(&power_of_two, params),
            params,
        );
        big_z_y_ob_share = big_z_y_ob_share.add_share(
            &state.z_y_i_ob_shares[i].mul_const(&power_of_two, params),
            params,
        );
        big_u_share = big_u_share.add_share(
            &state.u_i_shares[i].mul_const(&power_of_two, params),
            params,
        );
    }
    for i in 1..B_PARAMETER {
        let power_of_two = U128::ONE.shl(i);
        big_x_share = big_x_share.add_share(
            &state.x_i_shares[i].mul_const(&power_of_two, params),
            params,
        );
    }

    let big_v = big_u_share
        .sub_share(&big_x_share, params)
        .sub_share(&big_z_y_ob_share, params);

    let share_w = big_z_cb_share.add_const_ob(&state.big_l.resize(), params);
    let big_t = big_w_share.sub_share(&share_w, params);

    let open_v = big_v.open();
    let open_t = big_t.open();

    let state = Box::new(CFMStateOBR3 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        big_z_y_ob_share,
        z_i_cb_shares: state.z_i_cb_shares,
        w_i_shares: state.w_i_shares,
        z_y_i_ob_shares: state.z_y_i_ob_shares,
        x_i_shares: state.x_i_shares,
        u_i_shares: state.u_i_shares,
        big_v,
        big_t,
    });

    let msg5 = Box::new(CFMMsg5 {
        session_id: state.session_id,
        open_t_i,
        open_v,
        open_t,
    });

    Ok((state, msg5))
}

/// CB processes CFMMsg5 from OB
pub fn cfm_process_msg5(
    state: Box<CFMStateCBR2>,
    auth_triples: &[TripleShare],
    msg5: &CFMMsg5,
) -> Result<(CFMStateCBR3, Box<CFMMsg6>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg5.session_id {
        return Err(CFMError::InvalidSessionID);
    }
    let params = DynResidueParams::new(&state.p);

    for i in 0..(NUMBER_OF_SHARES - 3) {
        let t_i_value = match state.t_i_shares[i].validate_open(
            &msg5.open_t_i[i].0,
            &msg5.open_t_i[i].1,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };
        if t_i_value != U128::ONE {
            return Err(CFMError::AbortProtocol);
        }
    }

    let mut big_z_cb_share = state.z_i_cb_shares[0];
    let mut big_w_share = state.w_i_shares[0];
    let mut big_z_y_ob_share = state.z_y_i_ob_shares[0];
    let mut big_x_share = state.x_i_shares[0];
    let mut big_u_share = state.u_i_shares[0];
    for i in 1..L {
        let power_of_two = U128::ONE.shl(i);
        big_z_cb_share = big_z_cb_share.add_share(
            &state.z_i_cb_shares[i].mul_const(&power_of_two, params),
            params,
        );
        big_w_share = big_w_share.add_share(
            &state.w_i_shares[i].mul_const(&power_of_two, params),
            params,
        );
        big_z_y_ob_share = big_z_y_ob_share.add_share(
            &state.z_y_i_ob_shares[i].mul_const(&power_of_two, params),
            params,
        );
        big_u_share = big_u_share.add_share(
            &state.u_i_shares[i].mul_const(&power_of_two, params),
            params,
        );
    }
    for i in 1..B_PARAMETER {
        let power_of_two = U128::ONE.shl(i);
        big_x_share = big_x_share.add_share(
            &state.x_i_shares[i].mul_const(&power_of_two, params),
            params,
        );
    }

    let big_v = big_u_share
        .sub_share(&big_x_share, params)
        .sub_share(&big_z_y_ob_share, params);

    let share_w = big_z_cb_share.add_const_cb(&state.big_l.resize(), params);
    let big_t = big_w_share.sub_share(&share_w, params);

    let open_v = big_v.open();
    let open_t = big_t.open();
    let big_v_value = match big_v.validate_open(&msg5.open_v.0, &msg5.open_v.1, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };
    let big_t_value = match big_t.validate_open(&msg5.open_t.0, &msg5.open_t.1, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    if big_v_value != U128::ZERO {
        return Err(CFMError::AbortProtocol);
    }
    if big_t_value != U128::ZERO {
        return Err(CFMError::AbortProtocol);
    }

    let mut t = Transcript::new(CFM_LABEL.as_ref());
    t.append_message(b"session-id", &state.session_id);
    let mut comparison_session_id_0 = [0u8; 32];
    let mut comparison_session_id_1 = [0u8; 32];
    t.challenge_bytes(b"comparison-session-id-0", &mut comparison_session_id_0);
    t.challenge_bytes(b"comparison-session-id-1", &mut comparison_session_id_1);

    let (comp_0_state_cb_r0, comp_0_msg1) = comp_create_msg1(
        &comparison_session_id_0,
        &state.z_i_cb_shares,
        &state.z_y_i_ob_shares,
        &auth_triples[AUTH_TRIPLES_OFFSET..AUTH_TRIPLES_OFFSET + 128],
        state.p,
    );
    let (comp_1_state_cb_r0, comp_1_msg1) = comp_create_msg1(
        &comparison_session_id_1,
        &state.w_i_shares,
        &state.u_i_shares,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375..AUTH_TRIPLES_OFFSET + 375 + 128],
        state.p,
    );

    let state = CFMStateCBR3 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        big_z_y_ob_share,
        comp_0_state_cb_r0,
        comp_1_state_cb_r0,
        z_i_cb_shares: state.z_i_cb_shares,
        w_i_shares: state.w_i_shares,
        z_y_i_ob_shares: state.z_y_i_ob_shares,
        u_i_shares: state.u_i_shares,
    };

    let msg6 = Box::new(CFMMsg6 {
        session_id: state.session_id,
        open_v,
        open_t,
        comp_msg1_c: comp_0_msg1,
        comp_msg1_b: comp_1_msg1,
    });

    Ok((state, msg6))
}

/// OB processes CFMMsg6 from CB
pub fn cfm_process_msg6(
    state: Box<CFMStateOBR3>,
    auth_triples: &[TripleShare],
    msg6: &CFMMsg6,
) -> Result<(CFMStateOBR4, Box<CFMMsg7>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg6.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);
    let big_v_value = match state
        .big_v
        .validate_open(&msg6.open_v.0, &msg6.open_v.1, params)
    {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };
    let big_t_value = match state
        .big_t
        .validate_open(&msg6.open_t.0, &msg6.open_t.1, params)
    {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };
    if big_v_value != U128::ZERO {
        return Err(CFMError::AbortProtocol);
    }
    if big_t_value != U128::ZERO {
        return Err(CFMError::AbortProtocol);
    }

    let mut t = Transcript::new(CFM_LABEL.as_ref());
    t.append_message(b"session-id", &state.session_id);
    let mut comparison_session_id_0 = [0u8; 32];
    let mut comparison_session_id_1 = [0u8; 32];
    t.challenge_bytes(b"comparison-session-id-0", &mut comparison_session_id_0);
    t.challenge_bytes(b"comparison-session-id-1", &mut comparison_session_id_1);

    let (comp_0_state_ob_r1, comp_0_msg2) = match comp_process_msg1(
        &comparison_session_id_0,
        &state.z_i_cb_shares,
        &state.z_y_i_ob_shares,
        &auth_triples[AUTH_TRIPLES_OFFSET..AUTH_TRIPLES_OFFSET + 255],
        state.p,
        &msg6.comp_msg1_c,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let (comp_1_state_ob_r1, comp_1_msg2) = match comp_process_msg1(
        &comparison_session_id_1,
        &state.w_i_shares,
        &state.u_i_shares,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375..AUTH_TRIPLES_OFFSET + 375 + 255],
        state.p,
        &msg6.comp_msg1_b,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let state = CFMStateOBR4 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        big_z_y_ob_share: state.big_z_y_ob_share,
        comp_0_state_ob_r1,
        comp_1_state_ob_r1,
    };

    let msg7 = Box::new(CFMMsg7 {
        session_id: state.session_id,
        comp_msg2_c: comp_0_msg2,
        comp_msg2_b: comp_1_msg2,
    });

    Ok((state, msg7))
}

/// CB processes CFMMsg7 from OB
pub fn cfm_process_msg7(
    state: CFMStateCBR3,
    auth_triples: &[TripleShare],
    msg7: &CFMMsg7,
) -> Result<(CFMStateCBR4, Box<CFMMsg8>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg7.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let (comp_0_state_cb_r2, comp_0_msg3) = match comp_process_msg2(
        &state.comp_0_state_cb_r0,
        &state.z_i_cb_shares,
        &state.z_y_i_ob_shares,
        &auth_triples[AUTH_TRIPLES_OFFSET + 128..AUTH_TRIPLES_OFFSET + 318],
        &msg7.comp_msg2_c,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let (comp_1_state_cb_r2, comp_1_msg3) = match comp_process_msg2(
        &state.comp_1_state_cb_r0,
        &state.w_i_shares,
        &state.u_i_shares,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375 + 128..AUTH_TRIPLES_OFFSET + 375 + 318],
        &msg7.comp_msg2_b,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let state = CFMStateCBR4 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        big_z_y_ob_share: state.big_z_y_ob_share,
        comp_0_state_cb_r2,
        comp_1_state_cb_r2,
    };

    let msg8 = Box::new(CFMMsg8 {
        session_id: state.session_id,
        comp_msg3_c: comp_0_msg3,
        comp_msg3_b: comp_1_msg3,
    });

    Ok((state, msg8))
}

/// OB processes CFMMsg8 from CB
pub fn cfm_process_msg8(
    state: CFMStateOBR4,
    auth_triples: &[TripleShare],
    msg8: &CFMMsg8,
) -> Result<(CFMStateOBR5, Box<CFMMsg9>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg8.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let (comp_0_state_ob_r3, comp_0_msg4) = match comp_process_msg3(
        &state.comp_0_state_ob_r1,
        &auth_triples[AUTH_TRIPLES_OFFSET + 255..AUTH_TRIPLES_OFFSET + 349],
        &msg8.comp_msg3_c,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let (comp_1_state_ob_r3, comp_1_msg4) = match comp_process_msg3(
        &state.comp_1_state_ob_r1,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375 + 255..AUTH_TRIPLES_OFFSET + 375 + 349],
        &msg8.comp_msg3_b,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let state = CFMStateOBR5 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        big_z_y_ob_share: state.big_z_y_ob_share,
        comp_0_state_ob_r3,
        comp_1_state_ob_r3,
    };

    let msg9 = Box::new(CFMMsg9 {
        session_id: state.session_id,
        comp_msg4_c: comp_0_msg4,
        comp_msg4_b: comp_1_msg4,
    });

    Ok((state, msg9))
}

/// CB processes CFMMsg9 from OB
pub fn cfm_process_msg9(
    state: CFMStateCBR4,
    auth_triples: &[TripleShare],
    msg9: &CFMMsg9,
) -> Result<(CFMStateCBR5, Box<CFMMsg10>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg9.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let (comp_0_state_cb_r4, comp_0_msg5) = match comp_process_msg4(
        &state.comp_0_state_cb_r2,
        &auth_triples[AUTH_TRIPLES_OFFSET + 318..AUTH_TRIPLES_OFFSET + 364],
        &msg9.comp_msg4_c,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let (comp_1_state_cb_r4, comp_1_msg5) = match comp_process_msg4(
        &state.comp_1_state_cb_r2,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375 + 318..AUTH_TRIPLES_OFFSET + 375 + 364],
        &msg9.comp_msg4_b,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let state = CFMStateCBR5 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        big_z_y_ob_share: state.big_z_y_ob_share,
        comp_0_state_cb_r4,
        comp_1_state_cb_r4,
    };

    let msg10 = Box::new(CFMMsg10 {
        session_id: state.session_id,
        comp_msg5_c: comp_0_msg5,
        comp_msg5_b: comp_1_msg5,
    });

    Ok((state, msg10))
}

/// OB processes CFMMsg10 from CB
pub fn cfm_process_msg10(
    state: CFMStateOBR5,
    auth_triples: &[TripleShare],
    msg10: &CFMMsg10,
) -> Result<(CFMStateOBR6, Box<CFMMsg11>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg10.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let (comp_0_state_ob_r5, comp_0_msg6) = match comp_process_msg5(
        &state.comp_0_state_ob_r3,
        &auth_triples[AUTH_TRIPLES_OFFSET + 349..AUTH_TRIPLES_OFFSET + 371],
        &msg10.comp_msg5_c,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let (comp_1_state_ob_r5, comp_1_msg6) = match comp_process_msg5(
        &state.comp_1_state_ob_r3,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375 + 349..AUTH_TRIPLES_OFFSET + 375 + 371],
        &msg10.comp_msg5_b,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let state = CFMStateOBR6 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        big_z_y_ob_share: state.big_z_y_ob_share,
        comp_0_state_ob_r5,
        comp_1_state_ob_r5,
    };

    let msg11 = Box::new(CFMMsg11 {
        session_id: state.session_id,
        comp_msg6_c: comp_0_msg6,
        comp_msg6_b: comp_1_msg6,
    });

    Ok((state, msg11))
}

/// CB processes CFMMsg11 from OB
pub fn cfm_process_msg11(
    state: CFMStateCBR5,
    auth_triples: &[TripleShare],
    msg11: &CFMMsg11,
) -> Result<(CFMStateCBR6, Box<CFMMsg12>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg11.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let (comp_0_state_cb_r6, comp_0_msg7) = match comp_process_msg6(
        &state.comp_0_state_cb_r4,
        &auth_triples[AUTH_TRIPLES_OFFSET + 364..AUTH_TRIPLES_OFFSET + 374],
        &msg11.comp_msg6_c,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let (comp_1_state_cb_r6, comp_1_msg7) = match comp_process_msg6(
        &state.comp_1_state_cb_r4,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375 + 364..AUTH_TRIPLES_OFFSET + 375 + 374],
        &msg11.comp_msg6_b,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let state = CFMStateCBR6 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        alpha_share: state.alpha_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        big_z_y_ob_share: state.big_z_y_ob_share,
        comp_0_state_cb_r6,
        comp_1_state_cb_r6,
    };

    let msg12 = Box::new(CFMMsg12 {
        session_id: state.session_id,
        comp_msg7_c: comp_0_msg7,
        comp_msg7_b: comp_1_msg7,
    });

    Ok((state, msg12))
}

/// OB processes CFMMsg12 from CB
pub fn cfm_process_msg12(
    state: CFMStateOBR6,
    auth_triples: &[TripleShare],
    msg12: &CFMMsg12,
) -> Result<(CFMStateOBR7, Box<CFMMsg13>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg12.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let (comp_0_state_ob_r7, comp_0_msg8) = match comp_process_msg7(
        &state.comp_0_state_ob_r5,
        &auth_triples[AUTH_TRIPLES_OFFSET + 371..AUTH_TRIPLES_OFFSET + 375],
        &msg12.comp_msg7_c,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let (comp_1_state_ob_r7, comp_1_msg8) = match comp_process_msg7(
        &state.comp_1_state_ob_r5,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375 + 371..AUTH_TRIPLES_OFFSET + 375 + 375],
        &msg12.comp_msg7_b,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let params = DynResidueParams::new(&state.p);
    let auth_triple_1 = &auth_triples[AUTH_TRIPLES_OFFSET + 2 * 375];
    let (mul_state_a, mul_open_a) = multiply_shares_open(
        &state.alpha_share,
        &state.big_z_y_ob_share,
        &auth_triple_1.x,
        &auth_triple_1.y,
        &auth_triple_1.z,
        params,
    );

    let auth_triple_2 = auth_triples[AUTH_TRIPLES_OFFSET + 2 * 375 + 1];
    let auth_triple_3 = auth_triples[AUTH_TRIPLES_OFFSET + 2 * 375 + 2];

    let state = CFMStateOBR7 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        beta_share: state.beta_share,
        big_m_y_share: state.big_m_y_share,
        comp_0_state_ob_r7,
        comp_1_state_ob_r7,
        mul_state_a,
        auth_triple_2,
        auth_triple_3,
    };

    let msg13 = Box::new(CFMMsg13 {
        session_id: state.session_id,
        comp_msg8_c: comp_0_msg8,
        comp_msg8_b: comp_1_msg8,
        mul_open_a,
    });

    Ok((state, msg13))
}

/// CB processes CFMMsg13 from OB
pub fn cfm_process_msg13(
    state: CFMStateCBR6,
    auth_triples: &[TripleShare], // &[TripleShare; 2*375]
    msg13: &CFMMsg13,
) -> Result<(CFMStateCBR7, Box<CFMMsg14>), CFMError> {
    assert_eq!(auth_triples.len(), NUMBER_OF_AUTH_BEAVER_TRIPLES);

    if state.session_id != msg13.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let (c_share, comp_0_msg9) = match comp_process_msg8(
        &state.comp_0_state_cb_r6,
        &auth_triples[AUTH_TRIPLES_OFFSET + 374..AUTH_TRIPLES_OFFSET + 375],
        &msg13.comp_msg8_c,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let (b_share, comp_1_msg9) = match comp_process_msg8(
        &state.comp_1_state_cb_r6,
        &auth_triples[AUTH_TRIPLES_OFFSET + 375 + 374..AUTH_TRIPLES_OFFSET + 375 + 375],
        &msg13.comp_msg8_b,
    ) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let params = DynResidueParams::new(&state.p);
    let auth_triple_1 = &auth_triples[AUTH_TRIPLES_OFFSET + 2 * 375];
    let (mul_state_a, mul_open_a) = multiply_shares_open(
        &state.alpha_share,
        &state.big_z_y_ob_share,
        &auth_triple_1.x,
        &auth_triple_1.y,
        &auth_triple_1.z,
        params,
    );

    let a_share = match multiply_shares_output(&mul_state_a, &msg13.mul_open_a, true, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    let z_share = a_share
        .add_share(&state.beta_share, params)
        .sub_share(&state.big_m_y_share, params);

    // [f1] = (1 − [c]) · (1 − [z]) = ([c] - 1) · ([z] - 1)
    // [f] = (1 - [f1]) · [r]
    let minus_one = DynResidue::new(&U128::ONE, params).neg().retrieve();
    let auth_triple_2 = &auth_triples[AUTH_TRIPLES_OFFSET + 2 * 375 + 1];
    let (mul_state_f1, mul_open_f1) = multiply_shares_open(
        &c_share.add_const_cb(&minus_one, params),
        &z_share.add_const_cb(&minus_one, params),
        &auth_triple_2.x,
        &auth_triple_2.y,
        &auth_triple_2.z,
        params,
    );

    let auth_triple_3 = auth_triples[AUTH_TRIPLES_OFFSET + 2 * 375 + 2];

    let state = CFMStateCBR7 {
        session_id: state.session_id,
        p: state.p,
        r_share: state.r_share,
        c_share,
        b_share,
        mul_state_f1,
        auth_triple_3,
    };

    let msg14 = Box::new(CFMMsg14 {
        session_id: state.session_id,
        comp_msg9_c: comp_0_msg9,
        comp_msg9_b: comp_1_msg9,
        mul_open_a,
        mul_open_f1,
    });

    Ok((state, msg14))
}

/// OB processes CFMMsg14 from CB
pub fn cfm_process_msg14(
    state: CFMStateOBR7,
    msg14: &CFMMsg14,
) -> Result<(CFMStateOBR8, CFMMsg15), CFMError> {
    if state.session_id != msg14.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let c_share = match comp_process_msg9(&state.comp_0_state_ob_r7, &msg14.comp_msg9_c) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let b_share = match comp_process_msg9(&state.comp_1_state_ob_r7, &msg14.comp_msg9_b) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::Comparison),
    };

    let params = DynResidueParams::new(&state.p);
    let a_share = match multiply_shares_output(&state.mul_state_a, &msg14.mul_open_a, false, params)
    {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    let z_share = a_share
        .add_share(&state.beta_share, params)
        .sub_share(&state.big_m_y_share, params);

    // [f1] = (1 − [c]) · (1 − [z]) = ([c] - 1) · ([z] - 1)
    let minus_one = DynResidue::new(&U128::ONE, params).neg().retrieve();
    let (mul_state_f1, mul_open_f1) = multiply_shares_open(
        &c_share.add_const_ob(&minus_one, params),
        &z_share.add_const_ob(&minus_one, params),
        &state.auth_triple_2.x,
        &state.auth_triple_2.y,
        &state.auth_triple_2.z,
        params,
    );
    let f1_share = match multiply_shares_output(&mul_state_f1, &msg14.mul_open_f1, false, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    // [f2] = (1 - [f1])
    // [f] = [f2] · [r]
    let f2_share = f1_share
        .mul_const(&minus_one, params)
        .add_const_ob(&U128::ONE, params);
    let (mul_state_f, mul_open_f) = multiply_shares_open(
        &f2_share,
        &state.r_share,
        &state.auth_triple_3.x,
        &state.auth_triple_3.y,
        &state.auth_triple_3.z,
        params,
    );

    let state = CFMStateOBR8 {
        session_id: state.session_id,
        p: state.p,
        b_share,
        mul_state_f,
    };

    let msg15 = CFMMsg15 {
        session_id: state.session_id,
        mul_open_f1,
        mul_open_f,
    };

    Ok((state, msg15))
}

/// CB processes CFMMsg15 from OB
pub fn cfm_process_msg15(
    state: CFMStateCBR7,
    msg15: &CFMMsg15,
) -> Result<(CFMStateCBR8, CFMMsg16), CFMError> {
    if state.session_id != msg15.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // [f1] = (1 − [c]) · (1 − [z]) = ([c] - 1) · ([z] - 1)
    let f1_share =
        match multiply_shares_output(&state.mul_state_f1, &msg15.mul_open_f1, true, params) {
            Ok(v) => v,
            Err(_) => return Err(CFMError::InvalidOpen),
        };

    // [f2] = (1 - [f1])
    // [f] = [f2] · [r]
    let minus_one = DynResidue::new(&U128::ONE, params).neg().retrieve();
    let f2_share = f1_share
        .mul_const(&minus_one, params)
        .add_const_cb(&U128::ONE, params);
    let (mul_state_f, mul_open_f) = multiply_shares_open(
        &f2_share,
        &state.r_share,
        &state.auth_triple_3.x,
        &state.auth_triple_3.y,
        &state.auth_triple_3.z,
        params,
    );

    let f_share = match multiply_shares_output(&mul_state_f, &msg15.mul_open_f, true, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    let open_f = f_share.open();

    let state = CFMStateCBR8 {
        session_id: state.session_id,
        p: state.p,
        b_share: state.b_share,
        f_share,
    };

    let msg16 = CFMMsg16 {
        session_id: state.session_id,
        mul_open_f,
        open_f,
    };

    Ok((state, msg16))
}

/// OB processes CFMMsg16 from CB
pub fn cfm_process_msg16(
    state: CFMStateOBR8,
    msg16: &CFMMsg16,
) -> Result<(CFMStateOBR9, CFMMsg17), CFMError> {
    if state.session_id != msg16.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    let f_share = match multiply_shares_output(&state.mul_state_f, &msg16.mul_open_f, false, params)
    {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    let open_f = f_share.open();
    let f_value = match f_share.validate_open(&msg16.open_f.0, &msg16.open_f.1, params) {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    if f_value != U128::ZERO {
        return Err(CFMError::AbortProtocol);
    }

    let open_b = state.b_share.open();

    let state = CFMStateOBR9 {
        session_id: state.session_id,
        p: state.p,
        b_share: state.b_share,
    };

    let msg17 = CFMMsg17 {
        session_id: state.session_id,
        open_f,
        open_b,
    };

    Ok((state, msg17))
}

/// CB processes CFMMsg17 from OB
pub fn cfm_process_msg17(
    state: CFMStateCBR8,
    msg17: &CFMMsg17,
) -> Result<(bool, CFMMsg18), CFMError> {
    if state.session_id != msg17.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    let f_value = match state
        .f_share
        .validate_open(&msg17.open_f.0, &msg17.open_f.1, params)
    {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    if f_value != U128::ZERO {
        return Err(CFMError::AbortProtocol);
    }

    let open_b = state.b_share.open();
    let b_value = match state
        .b_share
        .validate_open(&msg17.open_b.0, &msg17.open_b.1, params)
    {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    let b = b_value == U128::ONE;

    let msg18 = CFMMsg18 {
        session_id: state.session_id,
        open_b,
    };

    Ok((b, msg18))
}

/// OB processes CFMMsg18 from CB
pub fn cfm_process_msg18(state: CFMStateOBR9, msg18: &CFMMsg18) -> Result<bool, CFMError> {
    if state.session_id != msg18.session_id {
        return Err(CFMError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    let b_value = match state
        .b_share
        .validate_open(&msg18.open_b.0, &msg18.open_b.1, params)
    {
        Ok(v) => v,
        Err(_) => return Err(CFMError::InvalidOpen),
    };

    Ok(b_value == U128::ONE)
}

#[cfg(test)]
mod tests {
    use crate::auth_beaver_triples::{
        abt_create_msg1, abt_process_msg1, abt_process_msg2, abt_process_msg3, abt_process_msg4,
        abt_process_msg5,
    };
    use crate::cfm_init_protocol::generate_cfm_ot_seeds_for_test;
    use crate::cfm_protocol::{
        cfm_create_msg1, cfm_process_msg1, cfm_process_msg10, cfm_process_msg11, cfm_process_msg12,
        cfm_process_msg13, cfm_process_msg14, cfm_process_msg15, cfm_process_msg16,
        cfm_process_msg17, cfm_process_msg18, cfm_process_msg2, cfm_process_msg3, cfm_process_msg4,
        cfm_process_msg5, cfm_process_msg6, cfm_process_msg7, cfm_process_msg8, cfm_process_msg9,
        NUMBER_OF_AUTH_BEAVER_TRIPLES, NUMBER_OF_SHARES,
    };
    use crate::utils::Customer;
    use crate::P;
    use crypto_bigint::U64;
    use rand::Rng;
    use std::vec;
    use std::sync::{Arc, Mutex};
    use rand::rngs::OsRng;


    #[test]
    fn test_cfm() {
        // let mut rng = rand::thread_rng();
        let mut rng = OsRng;

        // create OT seeds
        let init_session_id: [u8; 32] = rng.gen();
        let (ot_seeds_cb, ot_seeds_ob) = generate_cfm_ot_seeds_for_test(&init_session_id, &mut rng);

        // create auth beaver triples
        let session_id: [u8; 32] = rng.gen();
        let p = P;
        let eta_i = NUMBER_OF_SHARES;
        let eta_m = NUMBER_OF_AUTH_BEAVER_TRIPLES;
        let (state_cb_r1, msg1) =
            abt_create_msg1(&session_id, &ot_seeds_cb, p, eta_i, eta_m, &mut rng);
        let (state_ob_r1, mut shares_ob, mut auth_triples_ob, msg2) =
            abt_process_msg1(&session_id, &ot_seeds_ob, p, eta_i, eta_m, &msg1, &mut rng).unwrap();
        let (state_cb_r2, shares_cb, auth_triples_cb, msg3) =
            abt_process_msg2(&state_cb_r1, &ot_seeds_cb, &msg2, &mut rng).unwrap();
        let (state_ob_r2, msg4) =
            abt_process_msg3(&state_ob_r1, &mut shares_ob, &mut auth_triples_ob, &msg3).unwrap();
        let msg5 = abt_process_msg4(&state_cb_r2, &auth_triples_cb, &msg4).unwrap();
        abt_process_msg5(&state_ob_r2, &msg5).unwrap();

        // run cfm

        // public value L
        let big_l = U64::from_u32(104);

        // The private input for CB
        // a list of companies(customers) Y
        let big_y = vec![
            Customer::new("Customer1", "P1234567", "123 Main St"),
            Customer::new("Customer2", "P2345678", "456 Church St"),
            Customer::new("Customer3", "P3456789", "789 Maple St"),
            Customer::new("Customer4", "P4567890", "101 Oak St"),
            Customer::new("Customer5", "P5678901", "111 Pine St"),
            Customer::new("Customer6", "P6789012", "121 Cedar St"),
            Customer::new("Customer7", "P7890123", "314 Birch St"),
            Customer::new("Customer8", "P8901234", "151 Walnut St"),
            Customer::new("Customer9", "P9012345", "617 Chestnut St"),
            Customer::new("Customer10", "P0123456", "181 Spruce St"),
        ];
        let big_y_bytes: Vec<[u8; 32]> = big_y.iter().map(|row| row.to_hash_bytes()).collect();
        // The private input for CB
        // existing capital flows
        let big_z = vec![
            U64::from_u8(1),
            U64::from_u8(2),
            U64::from_u8(3),
            U64::from_u8(4),
            U64::from_u8(5),
            U64::from_u8(6),
            U64::from_u8(7),
            U64::from_u8(8),
            U64::from_u8(9),
            U64::from_u8(10),
        ];

        // The private input for OB
        // company(customer) Y
        let customer_y = Customer::new("Customer3", "P3456789", "789 Maple St");
        let customer_y_bytes = customer_y.to_hash_bytes();
        // proposed transaction amount
        let big_x = U64::from_u32(100);

        // OB starts cfm protocol
        let (cfm_state_ob_r1, msg1) = cfm_create_msg1(
            &session_id,
            p,
            big_l,
            big_x,
            &customer_y_bytes,
            &shares_ob,
            &mut rng,
        );

        // CB processes msg1
        let (cfm_state_cb_r1, msg2) = cfm_process_msg1(
            &session_id,
            p,
            big_l,
            big_y_bytes,
            big_z,
            &shares_cb,
            &msg1,
            &mut rng,
        )
        .unwrap();

        // OB processes msg2
        let (cfm_state_ob_r2, msg3) = cfm_process_msg2(
            &cfm_state_ob_r1,
            &shares_ob,
            &auth_triples_ob,
            &msg2,
            &mut rng,
        )
        .unwrap();

        // CB processes msg3
        let (cfm_state_cb_r2, msg4) =
            cfm_process_msg3(cfm_state_cb_r1, &shares_cb, &auth_triples_cb, &msg3).unwrap();

        // OB processes msg4
        let (cfm_state_ob_r3, msg5) = cfm_process_msg4(cfm_state_ob_r2, &msg4).unwrap();

        // CB processes msg5
        let (cfm_state_cb_r3, msg6) =
            cfm_process_msg5(cfm_state_cb_r2, &auth_triples_cb, &msg5).unwrap();

        // OB processes msg6
        let (cfm_state_ob_r4, msg7) =
            cfm_process_msg6(cfm_state_ob_r3, &auth_triples_ob, &msg6).unwrap();

        // CB processes msg7
        let (cfm_state_cb_r4, msg8) =
            cfm_process_msg7(cfm_state_cb_r3, &auth_triples_cb, &msg7).unwrap();

        // OB processes msg8
        let (cfm_state_ob_r5, msg9) =
            cfm_process_msg8(cfm_state_ob_r4, &auth_triples_ob, &msg8).unwrap();

        // CB processes msg9
        let (cfm_state_cb_r5, msg10) =
            cfm_process_msg9(cfm_state_cb_r4, &auth_triples_cb, &msg9).unwrap();

        // OB processes msg10
        let (cfm_state_ob_r6, msg11) =
            cfm_process_msg10(cfm_state_ob_r5, &auth_triples_ob, &msg10).unwrap();

        // CB processes msg11
        let (cfm_state_cb_r6, msg12) =
            cfm_process_msg11(cfm_state_cb_r5, &auth_triples_cb, &msg11).unwrap();

        // OB processes msg12
        let (cfm_state_ob_r7, msg13) =
            cfm_process_msg12(cfm_state_ob_r6, &auth_triples_ob, &msg12).unwrap();

        // CB processes msg13
        let (cfm_state_cb_r7, msg14) =
            cfm_process_msg13(cfm_state_cb_r6, &auth_triples_cb, &msg13).unwrap();

        // OB processes msg14
        let (cfm_state_ob_r8, msg15) = cfm_process_msg14(cfm_state_ob_r7, &msg14).unwrap();

        // CB processes msg15
        let (cfm_state_cb_r8, msg16) = cfm_process_msg15(cfm_state_cb_r7, &msg15).unwrap();

        // OB processes msg16
        let (cfm_state_ob_r9, msg17) = cfm_process_msg16(cfm_state_ob_r8, &msg16).unwrap();

        // CB processes msg17
        let (b_cb_value, msg18) = cfm_process_msg17(cfm_state_cb_r8, &msg17).unwrap();

        // OB processes msg18
        let b_ob_value = cfm_process_msg18(cfm_state_ob_r9, &msg18).unwrap();

        println!("{:#?} --- {:#?}", b_cb_value, b_ob_value);

        assert_eq!(b_cb_value, b_ob_value);

        // X = 100, Z_Y = 3, L = 104
        // (X + Z_Y) < L
        assert_eq!(b_cb_value, true);
    }
}
