//! Comparison protocol 4.12 implementation
//! with fixed bit length parameter l = 128
//! Protocol gets 375 authenticated beaver triples
//! P1 = CB, P2 = OB
//! outputs share [c], where c = 1 if X > Y , and is 0 otherwise.

use crate::auth_beaver_triples::{
    multiply_shares_open, multiply_shares_output, MulSharesOpen, MulSharesState, Share, TripleShare,
};
use crate::errors::CompError;
use crypto_bigint::modular::runtime_mod::DynResidueParams;
use crypto_bigint::U128;
use serde::{Deserialize, Serialize};

/// CompMsg1
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg1 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open
    #[serde(with = "serde_arrays")]
    pub mul_open: [MulSharesOpen; 128],
}

/// CompMsg2
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg2 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open
    #[serde(with = "serde_arrays")]
    pub mul_open: [MulSharesOpen; 128],

    /// mul_open_t_r1
    #[serde(with = "serde_arrays")]
    pub mul_open_t_r1: [MulSharesOpen; 64],

    /// mul_open_z_r1
    #[serde(with = "serde_arrays")]
    pub mul_open_z_r1: [MulSharesOpen; 63],
}

/// CompMsg3
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg3 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open_t_r1
    #[serde(with = "serde_arrays")]
    pub mul_open_t_r1: [MulSharesOpen; 64],

    /// mul_open_z_r1
    #[serde(with = "serde_arrays")]
    pub mul_open_z_r1: [MulSharesOpen; 63],

    /// mul_open_t_r2
    pub mul_open_t_r2: [MulSharesOpen; 32],

    /// mul_open_z_r2
    pub mul_open_z_r2: [MulSharesOpen; 31],
}

/// CompMsg4
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg4 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open_t_r2
    pub mul_open_t_r2: [MulSharesOpen; 32],

    /// mul_open_z_r2
    pub mul_open_z_r2: [MulSharesOpen; 31],

    /// mul_open_t_r3
    pub mul_open_t_r3: [MulSharesOpen; 16],

    /// mul_open_z_r3
    pub mul_open_z_r3: [MulSharesOpen; 15],
}

/// CompMsg5
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg5 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open_t_r3
    pub mul_open_t_r3: [MulSharesOpen; 16],

    /// mul_open_z_r3
    pub mul_open_z_r3: [MulSharesOpen; 15],

    /// mul_open_t_r4
    pub mul_open_t_r4: [MulSharesOpen; 8],

    /// mul_open_z_r4
    pub mul_open_z_r4: [MulSharesOpen; 7],
}

/// CompMsg6
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg6 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open_t_r4
    pub mul_open_t_r4: [MulSharesOpen; 8],

    /// mul_open_z_r4
    pub mul_open_z_r4: [MulSharesOpen; 7],

    /// mul_open_t_r5
    pub mul_open_t_r5: [MulSharesOpen; 4],

    /// mul_open_z_r5
    pub mul_open_z_r5: [MulSharesOpen; 3],
}

/// CompMsg7
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg7 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open_t_r5
    pub mul_open_t_r5: [MulSharesOpen; 4],

    /// mul_open_z_r5
    pub mul_open_z_r5: [MulSharesOpen; 3],

    /// mul_open_t_r6
    pub mul_open_t_r6: [MulSharesOpen; 2],

    /// mul_open_z_r6
    pub mul_open_z_r6: [MulSharesOpen; 1],
}

/// CompMsg8
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg8 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open_t_r6
    pub mul_open_t_r6: [MulSharesOpen; 2],

    /// mul_open_z_r6
    pub mul_open_z_r6: [MulSharesOpen; 1],

    /// mul_open_t_r7
    pub mul_open_t_r7: [MulSharesOpen; 1],
}

/// CompMsg9
#[derive(Clone, Serialize, Deserialize)]
pub struct CompMsg9 {
    /// session id
    pub session_id: [u8; 32],

    /// mul_open_t_r7
    pub mul_open_t_r7: [MulSharesOpen; 1],
}

/// Comparison State for P1 round 0
#[derive(Clone, Serialize, Deserialize)]
pub struct CompStateP1R0 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// mul_state
    #[serde(with = "serde_arrays")]
    pub mul_state: [MulSharesState; 128],
}

/// Comparison State for P2 round 1
#[derive(Clone, Serialize, Deserialize)]
pub struct CompStateP2R1 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// mul_state_t_r1
    #[serde(with = "serde_arrays")]
    pub mul_state_t_r1: [MulSharesState; 64],

    /// mul_state_z_r1
    #[serde(with = "serde_arrays")]
    pub mul_state_z_r1: [MulSharesState; 63],

    /// t_shares
    #[serde(with = "serde_arrays")]
    pub t_shares: [Share; 128],
}

/// Comparison State for P1 round 2
#[derive(Clone, Serialize, Deserialize)]
pub struct CompStateP1R2 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// mul_state_t_r2
    pub mul_state_t_r2: [MulSharesState; 32],

    /// mul_state_z_r2
    pub mul_state_z_r2: [MulSharesState; 31],

    /// t_shares
    #[serde(with = "serde_arrays")]
    pub t_shares: [Share; 64],
}

/// Comparison State for P2 round 3
#[derive(Clone, Serialize, Deserialize)]
pub struct CompStateP2R3 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// mul_state_t_r3
    pub mul_state_t_r3: [MulSharesState; 16],

    /// mul_state_z_r3
    pub mul_state_z_r3: [MulSharesState; 15],

    /// t_shares
    pub t_shares: [Share; 32],
}

/// Comparison State for P1 round 4
#[derive(Clone, Serialize, Deserialize)]
pub struct CompStateP1R4 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// mul_state_t_r4
    pub mul_state_t_r4: [MulSharesState; 8],

    /// mul_state_z_r4
    pub mul_state_z_r4: [MulSharesState; 7],

    /// t_shares
    pub t_shares: [Share; 16],
}

/// Comparison State for P2 round 5
#[derive(Clone, Serialize, Deserialize)]
pub struct CompStateP2R5 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// mul_state_t_r5
    pub mul_state_t_r5: [MulSharesState; 4],

    /// mul_state_z_r5
    pub mul_state_z_r5: [MulSharesState; 3],

    /// t_shares
    pub t_shares: [Share; 8],
}

/// Comparison State for P1 round 6
#[derive(Clone, Serialize, Deserialize)]
pub struct CompStateP1R6 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// mul_state_t_r6
    pub mul_state_t_r6: [MulSharesState; 2],

    /// mul_state_z_r6
    pub mul_state_z_r6: [MulSharesState; 1],

    /// t_shares
    pub t_shares: [Share; 4],
}

/// Comparison State for P2 round 7
#[derive(Clone, Serialize, Deserialize)]
pub struct CompStateP2R7 {
    /// session id
    pub session_id: [u8; 32],

    /// p
    pub p: U128,

    /// mul_state_t_r7
    pub mul_state_t_r7: [MulSharesState; 1],

    /// t_shares
    pub t_shares: [Share; 2],
}

/// P1 creates CompMsg1 for P2
pub fn comp_create_msg1(
    session_id: &[u8; 32],
    x: &[Share; 128],
    y: &[Share; 128],
    auth_triples: &[TripleShare], // &[TripleShare; 128]
    p: U128,
) -> (CompStateP1R0, CompMsg1) {
    let params = DynResidueParams::new(&p);

    // start [X_i]*[Y_i]
    let mut mul_shares_state = [MulSharesState::default(); 128];
    let mut mul_shares_open = [MulSharesOpen::default(); 128];
    for i in 0..128 {
        let (mul_state, mul_open) = multiply_shares_open(
            &x[i],
            &y[i],
            &auth_triples[i].x,
            &auth_triples[i].y,
            &auth_triples[i].z,
            params,
        );
        mul_shares_state[i] = mul_state;
        mul_shares_open[i] = mul_open;
    }

    let state = CompStateP1R0 {
        session_id: *session_id,
        p,
        mul_state: mul_shares_state,
    };

    let msg1 = CompMsg1 {
        session_id: *session_id,
        mul_open: mul_shares_open,
    };

    (state, msg1)
}

/// P2 process CompMsg1 from P1
pub fn comp_process_msg1(
    session_id: &[u8; 32],
    x: &[Share; 128],
    y: &[Share; 128],
    auth_triples: &[TripleShare], // &[TripleShare; 255]
    p: U128,
    msg1: &CompMsg1,
) -> Result<(CompStateP2R1, CompMsg2), CompError> {
    if *session_id != msg1.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&p);

    // process [X_i]*[Y_i]
    let mut t_shares = [Share::default(); 128];
    let mut z_shares = [Share::default(); 128];
    let mut mul_shares_open_0 = [MulSharesOpen::default(); 128];
    for i in 0..128 {
        let (mul_state, mul_open_0) = multiply_shares_open(
            &x[i],
            &y[i],
            &auth_triples[i].x,
            &auth_triples[i].y,
            &auth_triples[i].z,
            params,
        );
        mul_shares_open_0[i] = mul_open_0;
        let x_i_mul_y_i = match multiply_shares_output(&mul_state, &msg1.mul_open[i], false, params)
        {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        // [t_{i,1}] = [X_i] - [X_i*Y_i]
        t_shares[i] = x[i].sub_share(&x_i_mul_y_i, params);
        if i > 0 {
            // [z_{i,1}] = 1 - [X_i] - [Y_i] + 2*[X_i*Y_i]
            z_shares[i] = x_i_mul_y_i
                .mul_const(&U128::from_u8(2), params)
                .add_const_ob(&U128::ONE, params)
                .sub_share(&x[i], params)
                .sub_share(&y[i], params);
        }
    }

    // start round j = 1
    let mut mul_state_t_r1 = [MulSharesState::default(); 64];
    let mut mul_state_z_r1 = [MulSharesState::default(); 63];
    let mut mul_open_t_r1 = [MulSharesOpen::default(); 64];
    let mut mul_open_z_r1 = [MulSharesOpen::default(); 63];
    let offset = 128;
    for i in 1..64 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &z_shares[i * 2],
            &auth_triples[offset + i - 1].x,
            &auth_triples[offset + i - 1].y,
            &auth_triples[offset + i - 1].z,
            params,
        );
        mul_state_z_r1[i - 1] = mul_state;
        mul_open_z_r1[i - 1] = mul_open;
    }
    let offset = 128 + 63;
    for i in 0..64 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &t_shares[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_state_t_r1[i] = mul_state;
        mul_open_t_r1[i] = mul_open;
    }

    let state = CompStateP2R1 {
        session_id: *session_id,
        p,
        mul_state_t_r1,
        mul_state_z_r1,
        t_shares,
    };

    let msg2 = CompMsg2 {
        session_id: *session_id,
        mul_open: mul_shares_open_0,
        mul_open_t_r1,
        mul_open_z_r1,
    };

    Ok((state, msg2))
}

/// P1 process CompMsg2 from P2
pub fn comp_process_msg2(
    state: &CompStateP1R0,
    x: &[Share; 128],
    y: &[Share; 128],
    auth_triples: &[TripleShare], // &[TripleShare; 190]
    msg2: &CompMsg2,
) -> Result<(CompStateP1R2, CompMsg3), CompError> {
    if state.session_id != msg2.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // end [X_i]*[Y_i]
    let mut t_shares = [Share::default(); 128];
    let mut z_shares = [Share::default(); 128];
    for i in 0..128 {
        let x_i_mul_y_i =
            match multiply_shares_output(&state.mul_state[i], &msg2.mul_open[i], true, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        // [t_{i,1}] = [X_i] - [X_i*Y_i]
        t_shares[i] = x[i].sub_share(&x_i_mul_y_i, params);
        if i > 0 {
            // [z_{i,1}] = 1 - [X_i] - [Y_i] + 2*[X_i*Y_i]
            z_shares[i] = x_i_mul_y_i
                .mul_const(&U128::from_u8(2), params)
                .add_const_cb(&U128::ONE, params)
                .sub_share(&x[i], params)
                .sub_share(&y[i], params);
        }
    }

    // process round j = 1
    let mut t_shares_next = [Share::default(); 64];
    let mut z_shares_next = [Share::default(); 64];
    let mut mul_open_t_r1 = [MulSharesOpen::default(); 64];
    let mut mul_open_z_r1 = [MulSharesOpen::default(); 63];
    for i in 1..64 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &z_shares[i * 2],
            &auth_triples[i - 1].x,
            &auth_triples[i - 1].y,
            &auth_triples[i - 1].z,
            params,
        );
        mul_open_z_r1[i - 1] = mul_open;

        let z_share =
            match multiply_shares_output(&mul_state, &msg2.mul_open_z_r1[i - 1], true, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        z_shares_next[i] = z_share;
    }
    let offset = 63;
    for i in 0..64 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &t_shares[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_open_t_r1[i] = mul_open;

        let t_mul_share =
            match multiply_shares_output(&mul_state, &msg2.mul_open_t_r1[i], true, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        t_shares_next[i] = t_mul_share.add_share(&t_shares[i * 2 + 1], params);
    }

    // start round j = 2
    let mut mul_state_t_r2 = [MulSharesState::default(); 32];
    let mut mul_state_z_r2 = [MulSharesState::default(); 31];
    let mut mul_open_t_r2 = [MulSharesOpen::default(); 32];
    let mut mul_open_z_r2 = [MulSharesOpen::default(); 31];
    let offset = 63 + 64;
    for i in 1..32 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &z_shares_next[i * 2],
            &auth_triples[offset + i - 1].x,
            &auth_triples[offset + i - 1].y,
            &auth_triples[offset + i - 1].z,
            params,
        );
        mul_state_z_r2[i - 1] = mul_state;
        mul_open_z_r2[i - 1] = mul_open;
    }
    let offset = 63 + 64 + 31;
    for i in 0..32 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &t_shares_next[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_state_t_r2[i] = mul_state;
        mul_open_t_r2[i] = mul_open;
    }

    let next_state = CompStateP1R2 {
        session_id: state.session_id,
        p: state.p,
        mul_state_t_r2,
        mul_state_z_r2,
        t_shares: t_shares_next,
    };

    let msg3 = CompMsg3 {
        session_id: state.session_id,
        mul_open_t_r1,
        mul_open_z_r1,
        mul_open_t_r2,
        mul_open_z_r2,
    };

    Ok((next_state, msg3))
}

/// P2 process CompMsg3 from P1
pub fn comp_process_msg3(
    state: &CompStateP2R1,
    auth_triples: &[TripleShare], // &[TripleShare; 94]
    msg3: &CompMsg3,
) -> Result<(CompStateP2R3, CompMsg4), CompError> {
    if state.session_id != msg3.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // end round j = 1
    let mut t_shares = [Share::default(); 64];
    let mut z_shares = [Share::default(); 64];
    #[allow(clippy::needless_range_loop)]
    for i in 1..64 {
        // [z_{i,j-1}]
        let z_share = match multiply_shares_output(
            &state.mul_state_z_r1[i - 1],
            &msg3.mul_open_z_r1[i - 1],
            false,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        z_shares[i] = z_share;
    }
    #[allow(clippy::needless_range_loop)]
    for i in 0..64 {
        // [t_{i,j-1}]
        let t_share = match multiply_shares_output(
            &state.mul_state_t_r1[i],
            &msg3.mul_open_t_r1[i],
            false,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        t_shares[i] = t_share.add_share(&state.t_shares[i * 2 + 1], params);
    }

    // process round j = 2
    let mut t_shares_next = [Share::default(); 32];
    let mut z_shares_next = [Share::default(); 32];
    let mut mul_open_t_r2 = [MulSharesOpen::default(); 32];
    let mut mul_open_z_r2 = [MulSharesOpen::default(); 31];
    for i in 1..32 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &z_shares[i * 2],
            &auth_triples[i - 1].x,
            &auth_triples[i - 1].y,
            &auth_triples[i - 1].z,
            params,
        );
        mul_open_z_r2[i - 1] = mul_open;

        let z_share =
            match multiply_shares_output(&mul_state, &msg3.mul_open_z_r2[i - 1], false, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        z_shares_next[i] = z_share;
    }
    let offset = 31;
    for i in 0..32 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &t_shares[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_open_t_r2[i] = mul_open;

        let t_mul_share =
            match multiply_shares_output(&mul_state, &msg3.mul_open_t_r2[i], false, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        t_shares_next[i] = t_mul_share.add_share(&t_shares[i * 2 + 1], params);
    }

    // start round j = 3
    let mut mul_state_t_r3 = [MulSharesState::default(); 16];
    let mut mul_state_z_r3 = [MulSharesState::default(); 15];
    let mut mul_open_t_r3 = [MulSharesOpen::default(); 16];
    let mut mul_open_z_r3 = [MulSharesOpen::default(); 15];
    let offset = 31 + 32;
    for i in 1..16 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &z_shares_next[i * 2],
            &auth_triples[offset + i - 1].x,
            &auth_triples[offset + i - 1].y,
            &auth_triples[offset + i - 1].z,
            params,
        );
        mul_state_z_r3[i - 1] = mul_state;
        mul_open_z_r3[i - 1] = mul_open;
    }
    let offset = 31 + 32 + 15;
    for i in 0..16 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &t_shares_next[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_state_t_r3[i] = mul_state;
        mul_open_t_r3[i] = mul_open;
    }

    let next_state = CompStateP2R3 {
        session_id: state.session_id,
        p: state.p,
        mul_state_t_r3,
        mul_state_z_r3,
        t_shares: t_shares_next,
    };

    let msg4 = CompMsg4 {
        session_id: state.session_id,
        mul_open_t_r2,
        mul_open_z_r2,
        mul_open_t_r3,
        mul_open_z_r3,
    };

    Ok((next_state, msg4))
}

/// P1 process CompMsg4 from P2
pub fn comp_process_msg4(
    state: &CompStateP1R2,
    auth_triples: &[TripleShare], // &[TripleShare; 46]
    msg4: &CompMsg4,
) -> Result<(CompStateP1R4, CompMsg5), CompError> {
    if state.session_id != msg4.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // end round j = 2
    let mut t_shares = [Share::default(); 32];
    let mut z_shares = [Share::default(); 32];
    #[allow(clippy::needless_range_loop)]
    for i in 1..32 {
        // [z_{i,j-1}]
        let z_share = match multiply_shares_output(
            &state.mul_state_z_r2[i - 1],
            &msg4.mul_open_z_r2[i - 1],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        z_shares[i] = z_share;
    }
    #[allow(clippy::needless_range_loop)]
    for i in 0..32 {
        // [t_{i,j-1}]
        let t_share = match multiply_shares_output(
            &state.mul_state_t_r2[i],
            &msg4.mul_open_t_r2[i],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        t_shares[i] = t_share.add_share(&state.t_shares[i * 2 + 1], params);
    }

    // process round j = 3
    let mut t_shares_next = [Share::default(); 16];
    let mut z_shares_next = [Share::default(); 16];
    let mut mul_open_t_r3 = [MulSharesOpen::default(); 16];
    let mut mul_open_z_r3 = [MulSharesOpen::default(); 15];
    for i in 1..16 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &z_shares[i * 2],
            &auth_triples[i - 1].x,
            &auth_triples[i - 1].y,
            &auth_triples[i - 1].z,
            params,
        );
        mul_open_z_r3[i - 1] = mul_open;

        let z_share =
            match multiply_shares_output(&mul_state, &msg4.mul_open_z_r3[i - 1], true, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        z_shares_next[i] = z_share;
    }
    let offset = 15;
    for i in 0..16 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &t_shares[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_open_t_r3[i] = mul_open;

        let t_mul_share =
            match multiply_shares_output(&mul_state, &msg4.mul_open_t_r3[i], true, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        t_shares_next[i] = t_mul_share.add_share(&t_shares[i * 2 + 1], params);
    }

    // start round j = 4
    let mut mul_state_t_r4 = [MulSharesState::default(); 8];
    let mut mul_state_z_r4 = [MulSharesState::default(); 7];
    let mut mul_open_t_r4 = [MulSharesOpen::default(); 8];
    let mut mul_open_z_r4 = [MulSharesOpen::default(); 7];
    let offset = 15 + 16;
    for i in 1..8 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &z_shares_next[i * 2],
            &auth_triples[offset + i - 1].x,
            &auth_triples[offset + i - 1].y,
            &auth_triples[offset + i - 1].z,
            params,
        );
        mul_state_z_r4[i - 1] = mul_state;
        mul_open_z_r4[i - 1] = mul_open;
    }
    let offset = 15 + 16 + 7;
    for i in 0..8 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &t_shares_next[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_state_t_r4[i] = mul_state;
        mul_open_t_r4[i] = mul_open;
    }

    let next_state = CompStateP1R4 {
        session_id: state.session_id,
        p: state.p,
        mul_state_t_r4,
        t_shares: t_shares_next,
        mul_state_z_r4,
    };

    let msg5 = CompMsg5 {
        session_id: state.session_id,
        mul_open_t_r3,
        mul_open_z_r3,
        mul_open_t_r4,
        mul_open_z_r4,
    };

    Ok((next_state, msg5))
}

/// P2 process CompMsg5 from P1
pub fn comp_process_msg5(
    state: &CompStateP2R3,
    auth_triples: &[TripleShare], // &[TripleShare; 22]
    msg5: &CompMsg5,
) -> Result<(CompStateP2R5, CompMsg6), CompError> {
    if state.session_id != msg5.session_id {
        return Err(CompError::InvalidSessionID);
    }
    if state.session_id != msg5.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // end round j = 3
    let mut t_shares = [Share::default(); 16];
    let mut z_shares = [Share::default(); 16];
    #[allow(clippy::needless_range_loop)]
    for i in 1..16 {
        // [z_{i,j-1}]
        let z_share = match multiply_shares_output(
            &state.mul_state_z_r3[i - 1],
            &msg5.mul_open_z_r3[i - 1],
            false,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        z_shares[i] = z_share;
    }
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 {
        // [t_{i,j-1}]
        let t_share = match multiply_shares_output(
            &state.mul_state_t_r3[i],
            &msg5.mul_open_t_r3[i],
            false,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        t_shares[i] = t_share.add_share(&state.t_shares[i * 2 + 1], params);
    }

    // process round j = 4
    let mut t_shares_next = [Share::default(); 8];
    let mut z_shares_next = [Share::default(); 8];
    let mut mul_open_t_r4 = [MulSharesOpen::default(); 8];
    let mut mul_open_z_r4 = [MulSharesOpen::default(); 7];
    for i in 1..8 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &z_shares[i * 2],
            &auth_triples[i - 1].x,
            &auth_triples[i - 1].y,
            &auth_triples[i - 1].z,
            params,
        );
        mul_open_z_r4[i - 1] = mul_open;

        let z_share =
            match multiply_shares_output(&mul_state, &msg5.mul_open_z_r4[i - 1], false, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        z_shares_next[i] = z_share;
    }
    let offset = 7;
    for i in 0..8 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &t_shares[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_open_t_r4[i] = mul_open;

        let t_mul_share =
            match multiply_shares_output(&mul_state, &msg5.mul_open_t_r4[i], false, params) {
                Ok(v) => v,
                Err(_) => {
                    println!("err4");
                    return Err(CompError::InvalidOpen);
                }
            };
        t_shares_next[i] = t_mul_share.add_share(&t_shares[i * 2 + 1], params);
    }

    // start round j = 5
    let mut mul_state_t_r5 = [MulSharesState::default(); 4];
    let mut mul_state_z_r5 = [MulSharesState::default(); 3];
    let mut mul_open_t_r5 = [MulSharesOpen::default(); 4];
    let mut mul_open_z_r5 = [MulSharesOpen::default(); 3];
    let offset = 7 + 8;
    for i in 1..4 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &z_shares_next[i * 2],
            &auth_triples[offset + i - 1].x,
            &auth_triples[offset + i - 1].y,
            &auth_triples[offset + i - 1].z,
            params,
        );
        mul_state_z_r5[i - 1] = mul_state;
        mul_open_z_r5[i - 1] = mul_open;
    }
    let offset = 7 + 8 + 3;
    for i in 0..4 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &t_shares_next[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_state_t_r5[i] = mul_state;
        mul_open_t_r5[i] = mul_open;
    }

    let next_state = CompStateP2R5 {
        session_id: state.session_id,
        p: state.p,
        mul_state_t_r5,
        t_shares: t_shares_next,
        mul_state_z_r5,
    };

    let msg6 = CompMsg6 {
        session_id: state.session_id,
        mul_open_t_r4,
        mul_open_z_r4,
        mul_open_t_r5,
        mul_open_z_r5,
    };

    Ok((next_state, msg6))
}

/// P1 process CompMsg6 from P2
pub fn comp_process_msg6(
    state: &CompStateP1R4,
    auth_triples: &[TripleShare], // &[TripleShare; 10]
    msg6: &CompMsg6,
) -> Result<(CompStateP1R6, CompMsg7), CompError> {
    if state.session_id != msg6.session_id {
        return Err(CompError::InvalidSessionID);
    }
    if state.session_id != msg6.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // end round j = 4
    let mut t_shares = [Share::default(); 8];
    let mut z_shares = [Share::default(); 8];
    #[allow(clippy::needless_range_loop)]
    for i in 1..8 {
        // [z_{i,j-1}]
        let z_share = match multiply_shares_output(
            &state.mul_state_z_r4[i - 1],
            &msg6.mul_open_z_r4[i - 1],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        z_shares[i] = z_share;
    }
    #[allow(clippy::needless_range_loop)]
    for i in 0..8 {
        // [t_{i,j-1}]
        let t_share = match multiply_shares_output(
            &state.mul_state_t_r4[i],
            &msg6.mul_open_t_r4[i],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        t_shares[i] = t_share.add_share(&state.t_shares[i * 2 + 1], params);
    }

    // process round j = 5
    let mut t_shares_next = [Share::default(); 4];
    let mut z_shares_next = [Share::default(); 4];
    let mut mul_open_t_r5 = [MulSharesOpen::default(); 4];
    let mut mul_open_z_r5 = [MulSharesOpen::default(); 3];
    for i in 1..4 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &z_shares[i * 2],
            &auth_triples[i - 1].x,
            &auth_triples[i - 1].y,
            &auth_triples[i - 1].z,
            params,
        );
        mul_open_z_r5[i - 1] = mul_open;

        let z_share =
            match multiply_shares_output(&mul_state, &msg6.mul_open_z_r5[i - 1], true, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        z_shares_next[i] = z_share;
    }
    let offset = 3;
    for i in 0..4 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &t_shares[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_open_t_r5[i] = mul_open;

        let t_mul_share =
            match multiply_shares_output(&mul_state, &msg6.mul_open_t_r5[i], true, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        t_shares_next[i] = t_mul_share.add_share(&t_shares[i * 2 + 1], params);
    }

    // start round j = 6
    let mut mul_state_t_r6 = [MulSharesState::default(); 2];
    let mut mul_state_z_r6 = [MulSharesState::default(); 1];
    let mut mul_open_t_r6 = [MulSharesOpen::default(); 2];
    let mut mul_open_z_r6 = [MulSharesOpen::default(); 1];
    let offset = 3 + 4;
    for i in 1..2 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &z_shares_next[i * 2],
            &auth_triples[offset + i - 1].x,
            &auth_triples[offset + i - 1].y,
            &auth_triples[offset + i - 1].z,
            params,
        );
        mul_state_z_r6[i - 1] = mul_state;
        mul_open_z_r6[i - 1] = mul_open;
    }
    let offset = 3 + 4 + 1;
    for i in 0..2 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &t_shares_next[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_state_t_r6[i] = mul_state;
        mul_open_t_r6[i] = mul_open;
    }

    let next_state = CompStateP1R6 {
        session_id: state.session_id,
        p: state.p,
        t_shares: t_shares_next,
        mul_state_z_r6,
        mul_state_t_r6,
    };

    let msg7 = CompMsg7 {
        session_id: state.session_id,
        mul_open_t_r5,
        mul_open_z_r5,
        mul_open_t_r6,
        mul_open_z_r6,
    };

    Ok((next_state, msg7))
}

/// P2 process CompMsg7 from P1
pub fn comp_process_msg7(
    state: &CompStateP2R5,
    auth_triples: &[TripleShare], // &[TripleShare; 4]
    msg7: &CompMsg7,
) -> Result<(CompStateP2R7, CompMsg8), CompError> {
    if state.session_id != msg7.session_id {
        return Err(CompError::InvalidSessionID);
    }
    if state.session_id != msg7.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // end round j = 5
    let mut t_shares = [Share::default(); 4];
    let mut z_shares = [Share::default(); 4];
    #[allow(clippy::needless_range_loop)]
    for i in 1..4 {
        // [z_{i,j-1}]
        let z_share = match multiply_shares_output(
            &state.mul_state_z_r5[i - 1],
            &msg7.mul_open_z_r5[i - 1],
            false,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        z_shares[i] = z_share;
    }
    #[allow(clippy::needless_range_loop)]
    for i in 0..4 {
        // [t_{i,j-1}]
        let t_share = match multiply_shares_output(
            &state.mul_state_t_r5[i],
            &msg7.mul_open_t_r5[i],
            false,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        t_shares[i] = t_share.add_share(&state.t_shares[i * 2 + 1], params);
    }

    // process round j = 6
    let mut t_shares_next = [Share::default(); 2];
    let mut z_shares_next = [Share::default(); 2];
    let mut mul_open_t_r6 = [MulSharesOpen::default(); 2];
    let mut mul_open_z_r6 = [MulSharesOpen::default(); 1];
    for i in 1..2 {
        // [z_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &z_shares[i * 2],
            &auth_triples[i - 1].x,
            &auth_triples[i - 1].y,
            &auth_triples[i - 1].z,
            params,
        );
        mul_open_z_r6[i - 1] = mul_open;

        let z_share =
            match multiply_shares_output(&mul_state, &msg7.mul_open_z_r6[i - 1], false, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        z_shares_next[i] = z_share;
    }
    let offset = 1;
    for i in 0..2 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &t_shares[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_open_t_r6[i] = mul_open;

        let t_mul_share =
            match multiply_shares_output(&mul_state, &msg7.mul_open_t_r6[i], false, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        t_shares_next[i] = t_mul_share.add_share(&t_shares[i * 2 + 1], params);
    }

    // start round j = 7
    let mut mul_state_t_r7 = [MulSharesState::default(); 1];
    let mut mul_open_t_r7 = [MulSharesOpen::default(); 1];
    let offset = 1 + 2;
    for i in 0..1 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares_next[i * 2 + 1],
            &t_shares_next[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_state_t_r7[i] = mul_state;
        mul_open_t_r7[i] = mul_open;
    }

    let next_state = CompStateP2R7 {
        session_id: state.session_id,
        p: state.p,
        mul_state_t_r7,
        t_shares: t_shares_next,
    };

    let msg8 = CompMsg8 {
        session_id: state.session_id,
        mul_open_t_r6,
        mul_open_z_r6,
        mul_open_t_r7,
    };

    Ok((next_state, msg8))
}

/// P1 process CompMsg8 from P2
pub fn comp_process_msg8(
    state: &CompStateP1R6,
    auth_triples: &[TripleShare], // &[TripleShare; 1]
    msg8: &CompMsg8,
) -> Result<(Share, CompMsg9), CompError> {
    if state.session_id != msg8.session_id {
        return Err(CompError::InvalidSessionID);
    }
    if state.session_id != msg8.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // end round j = 6
    let mut t_shares = [Share::default(); 2];
    let mut z_shares = [Share::default(); 2];
    #[allow(clippy::needless_range_loop)]
    for i in 1..2 {
        // [z_{i,j-1}]
        let z_share = match multiply_shares_output(
            &state.mul_state_z_r6[i - 1],
            &msg8.mul_open_z_r6[i - 1],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        z_shares[i] = z_share;
    }
    #[allow(clippy::needless_range_loop)]
    for i in 0..2 {
        // [t_{i,j-1}]
        let t_share = match multiply_shares_output(
            &state.mul_state_t_r6[i],
            &msg8.mul_open_t_r6[i],
            true,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        t_shares[i] = t_share.add_share(&state.t_shares[i * 2 + 1], params);
    }

    // process round j = 7
    let mut t_shares_next = [Share::default(); 1];
    let mut mul_open_t_r7 = [MulSharesOpen::default(); 1];
    let offset = 0;
    for i in 0..1 {
        // [t_{i,j-1}]
        let (mul_state, mul_open) = multiply_shares_open(
            &z_shares[i * 2 + 1],
            &t_shares[i * 2],
            &auth_triples[offset + i].x,
            &auth_triples[offset + i].y,
            &auth_triples[offset + i].z,
            params,
        );
        mul_open_t_r7[i] = mul_open;

        let t_mul_share =
            match multiply_shares_output(&mul_state, &msg8.mul_open_t_r7[i], true, params) {
                Ok(v) => v,
                Err(_) => return Err(CompError::InvalidOpen),
            };
        t_shares_next[i] = t_mul_share.add_share(&t_shares[i * 2 + 1], params);
    }

    let share = t_shares_next[0];

    let msg9 = CompMsg9 {
        session_id: state.session_id,
        mul_open_t_r7,
    };

    Ok((share, msg9))
}

/// P2 process CompMsg9 from P1
pub fn comp_process_msg9(state: &CompStateP2R7, msg9: &CompMsg9) -> Result<Share, CompError> {
    if state.session_id != msg9.session_id {
        return Err(CompError::InvalidSessionID);
    }
    if state.session_id != msg9.session_id {
        return Err(CompError::InvalidSessionID);
    }

    let params = DynResidueParams::new(&state.p);

    // end round j = 7
    let mut t_shares = [Share::default(); 1];
    #[allow(clippy::needless_range_loop)]
    for i in 0..1 {
        // [t_{i,j-1}]
        let t_share = match multiply_shares_output(
            &state.mul_state_t_r7[i],
            &msg9.mul_open_t_r7[i],
            false,
            params,
        ) {
            Ok(v) => v,
            Err(_) => return Err(CompError::InvalidOpen),
        };
        t_shares[i] = t_share.add_share(&state.t_shares[i * 2 + 1], params);
    }

    let share = t_shares[0];

    Ok(share)
}

#[cfg(test)]
mod tests {
    use crate::auth_beaver_triples::{
        abt_create_msg1, abt_process_msg1, abt_process_msg2, abt_process_msg3, abt_process_msg4,
        abt_process_msg5, Share, TripleShare,
    };
    use crate::cfm_init_protocol::generate_cfm_ot_seeds_for_test;
    use crate::comparison::{
        comp_create_msg1, comp_process_msg1, comp_process_msg2, comp_process_msg3,
        comp_process_msg4, comp_process_msg5, comp_process_msg6, comp_process_msg7,
        comp_process_msg8, comp_process_msg9,
    };
    use crate::P;
    use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
    use crypto_bigint::{Random, U128};
    use rand::Rng;
    use subtle::Choice;
    use rand::rngs::OsRng;

    fn create_auth_triples_for_test(
        p_prime: U128,
        eta_m: usize,
    ) -> (Vec<TripleShare>, Vec<TripleShare>) {
        // let mut rng = rand::thread_rng();
        let mut rng = OsRng;


        let init_session_id: [u8; 32] = rng.gen();
        let (ot_seeds_cb, ot_seeds_ob) = generate_cfm_ot_seeds_for_test(&init_session_id, &mut rng);

        let session_id: [u8; 32] = rng.gen();

        let eta_i = 0;
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
        let (state_cb_r2, _input_shares_cb, triple_shares_cb, msg3) =
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

        (triple_shares_cb, triple_shares_ob)
    }

    #[test]
    fn test_comparison_1() {
        let mut rng = rand::thread_rng();
        let session_id: [u8; 32] = rng.gen();
        let params = DynResidueParams::new(&P);

        let eta = 128 + 375;
        let (triple_shares_cb, triple_shares_ob) = create_auth_triples_for_test(P, eta);

        let mut x_cb = [Share::default(); 128];
        let mut y_cb = [Share::default(); 128];
        let mut x_ob = [Share::default(); 128];
        let mut y_ob = [Share::default(); 128];
        for i in 0..128 {
            x_cb[i] = triple_shares_cb[i].x.clone();
            y_cb[i] = triple_shares_cb[i].y.clone();
            x_ob[i] = triple_shares_ob[i].x.clone();
            y_ob[i] = triple_shares_ob[i].y.clone();
        }

        // X > Y
        let big_x = U128::random(&mut rng);
        let big_y = big_x.saturating_sub(&U128::from_u8(10));

        // apply inputs for [x]_i and [y]_i
        for i in 0..128 {
            let x_i = DynResidue::new(&x_cb[i].value, params)
                .add(&DynResidue::new(&x_ob[i].value, params))
                .retrieve();
            let x_i_bit = U128::from_u8(Choice::from(big_x.bit(i)).unwrap_u8());
            let d_x_i = DynResidue::new(&x_i_bit, params)
                .sub(&DynResidue::new(&x_i, params))
                .retrieve();
            x_cb[i] = x_cb[i].add_const_cb(&d_x_i, params);
            x_ob[i] = x_ob[i].add_const_ob(&d_x_i, params);

            let y_i = DynResidue::new(&y_cb[i].value, params)
                .add(&DynResidue::new(&y_ob[i].value, params))
                .retrieve();
            let y_i_bit = U128::from_u8(Choice::from(big_y.bit(i)).unwrap_u8());
            let d_y_i = DynResidue::new(&y_i_bit, params)
                .sub(&DynResidue::new(&y_i, params))
                .retrieve();
            y_cb[i] = y_cb[i].add_const_cb(&d_y_i, params);
            y_ob[i] = y_ob[i].add_const_ob(&d_y_i, params);
        }

        let (state_cb_r0, msg1) =
            comp_create_msg1(&session_id, &x_cb, &y_cb, &triple_shares_cb[128..256], P);
        let (state_ob_r1, msg2) = comp_process_msg1(
            &session_id,
            &x_ob,
            &y_ob,
            &triple_shares_ob[128..383],
            P,
            &msg1,
        )
        .unwrap();
        let (state_cb_r2, msg3) = comp_process_msg2(
            &state_cb_r0,
            &x_cb,
            &y_cb,
            &triple_shares_cb[256..256 + 190],
            &msg2,
        )
        .unwrap();
        let (state_ob_r3, msg4) =
            comp_process_msg3(&state_ob_r1, &triple_shares_ob[383..383 + 94], &msg3).unwrap();
        let (state_cb_r4, msg5) =
            comp_process_msg4(&state_cb_r2, &triple_shares_cb[446..446 + 46], &msg4).unwrap();
        let (state_ob_r5, msg6) =
            comp_process_msg5(&state_ob_r3, &triple_shares_ob[477..477 + 22], &msg5).unwrap();
        let (state_cb_r6, msg7) =
            comp_process_msg6(&state_cb_r4, &triple_shares_cb[492..492 + 10], &msg6).unwrap();
        let (state_ob_r7, msg8) =
            comp_process_msg7(&state_ob_r5, &triple_shares_ob[499..499 + 4], &msg7).unwrap();
        let (share_cb, msg9) =
            comp_process_msg8(&state_cb_r6, &triple_shares_cb[502..502 + 1], &msg8).unwrap();
        let share_ob = comp_process_msg9(&state_ob_r7, &msg9).unwrap();

        let value_c = DynResidue::new(&share_cb.value, params)
            .add(&DynResidue::new(&share_ob.value, params))
            .retrieve();

        assert_eq!(value_c, U128::ONE);
    }

    #[test]
    fn test_comparison_2() {
        let mut rng = rand::thread_rng();
        let session_id: [u8; 32] = rng.gen();
        let params = DynResidueParams::new(&P);

        let eta = 128 + 375;
        let (triple_shares_cb, triple_shares_ob) = create_auth_triples_for_test(P, eta);

        let mut x_cb = [Share::default(); 128];
        let mut y_cb = [Share::default(); 128];
        let mut x_ob = [Share::default(); 128];
        let mut y_ob = [Share::default(); 128];
        for i in 0..128 {
            x_cb[i] = triple_shares_cb[i].x.clone();
            y_cb[i] = triple_shares_cb[i].y.clone();
            x_ob[i] = triple_shares_ob[i].x.clone();
            y_ob[i] = triple_shares_ob[i].y.clone();
        }

        // X < Y
        let big_x = U128::random(&mut rng);
        let big_y = big_x.saturating_add(&U128::from_u8(10));

        // apply inputs for [x]_i and [y]_i
        for i in 0..128 {
            let x_i = DynResidue::new(&x_cb[i].value, params)
                .add(&DynResidue::new(&x_ob[i].value, params))
                .retrieve();
            let x_i_bit = U128::from_u8(Choice::from(big_x.bit(i)).unwrap_u8());
            let d_x_i = DynResidue::new(&x_i_bit, params)
                .sub(&DynResidue::new(&x_i, params))
                .retrieve();
            x_cb[i] = x_cb[i].add_const_cb(&d_x_i, params);
            x_ob[i] = x_ob[i].add_const_ob(&d_x_i, params);

            let y_i = DynResidue::new(&y_cb[i].value, params)
                .add(&DynResidue::new(&y_ob[i].value, params))
                .retrieve();
            let y_i_bit = U128::from_u8(Choice::from(big_y.bit(i)).unwrap_u8());
            let d_y_i = DynResidue::new(&y_i_bit, params)
                .sub(&DynResidue::new(&y_i, params))
                .retrieve();
            y_cb[i] = y_cb[i].add_const_cb(&d_y_i, params);
            y_ob[i] = y_ob[i].add_const_ob(&d_y_i, params);
        }

        let (state_cb_r0, msg1) =
            comp_create_msg1(&session_id, &x_cb, &y_cb, &triple_shares_cb[128..256], P);
        let (state_ob_r1, msg2) = comp_process_msg1(
            &session_id,
            &x_ob,
            &y_ob,
            &triple_shares_ob[128..383],
            P,
            &msg1,
        )
        .unwrap();
        let (state_cb_r2, msg3) = comp_process_msg2(
            &state_cb_r0,
            &x_cb,
            &y_cb,
            &triple_shares_cb[256..256 + 190],
            &msg2,
        )
        .unwrap();
        let (state_ob_r3, msg4) =
            comp_process_msg3(&state_ob_r1, &triple_shares_ob[383..383 + 94], &msg3).unwrap();
        let (state_cb_r4, msg5) =
            comp_process_msg4(&state_cb_r2, &triple_shares_cb[446..446 + 46], &msg4).unwrap();
        let (state_ob_r5, msg6) =
            comp_process_msg5(&state_ob_r3, &triple_shares_ob[477..477 + 22], &msg5).unwrap();
        let (state_cb_r6, msg7) =
            comp_process_msg6(&state_cb_r4, &triple_shares_cb[492..492 + 10], &msg6).unwrap();
        let (state_ob_r7, msg8) =
            comp_process_msg7(&state_ob_r5, &triple_shares_ob[499..499 + 4], &msg7).unwrap();
        let (share_cb, msg9) =
            comp_process_msg8(&state_cb_r6, &triple_shares_cb[502..502 + 1], &msg8).unwrap();
        let share_ob = comp_process_msg9(&state_ob_r7, &msg9).unwrap();

        let value_c = DynResidue::new(&share_cb.value, params)
            .add(&DynResidue::new(&share_ob.value, params))
            .retrieve();

        assert_eq!(value_c, U128::ZERO);
    }
}
