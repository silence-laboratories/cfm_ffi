//! Private Sanction List Check protocol 3.3 implementation

use crate::dlog_proof::DLogProof;
use crate::errors::{PSCBBError, PSCOBError};
use crate::proto::{decode_point, encode_point, Hash2Bytes, PointBytes};
use crate::utils::{h1_function, h2_function};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::prelude::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// PSCMsg1
#[derive(Clone, Serialize, Deserialize)]
pub struct PSCMsg1 {
    /// session id
    pub session_id: [u8; 32],

    /// point A
    pub big_a: PointBytes,
}

/// PSCMsg2
#[derive(Clone, Serialize, Deserialize)]
pub struct PSCMsg2 {
    /// session id
    pub session_id: [u8; 32],

    /// hat(Y)
    pub hat_big_y: Vec<Hash2Bytes>,

    /// point B
    pub big_b: PointBytes,

    /// DLog proof
    pub dlog_proof: DLogProof,
}

/// PSC State for OB
#[derive(Clone, Serialize, Deserialize)]
pub struct PSCStateOB {
    /// session id
    pub session_id: [u8; 32],

    /// h1(x)
    pub h1_x: RistrettoPoint,

    /// Scalar r
    pub r: Scalar,

    /// Point A
    pub big_a: RistrettoPoint,
}

/// OB creates PSCMsg1 for BB
pub fn psc_create_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    x: &[u8; 32],
    rng: &mut R,
) -> (PSCStateOB, PSCMsg1) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let r = Scalar::from_bytes_mod_order(bytes);
    let big_a = h1_function(session_id, x) * r;

    let state = PSCStateOB {
        session_id: *session_id,
        h1_x: h1_function(session_id, x),
        r,
        big_a,
    };

    let msg1 = PSCMsg1 {
        session_id: *session_id,
        big_a: encode_point(&big_a),
    };

    (state, msg1)
}

/// BB processes PSCMsg1 from OB
pub fn psc_process_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    big_y: Vec<[u8; 32]>,
    msg1: &PSCMsg1,
    rng: &mut R,
) -> Result<PSCMsg2, PSCBBError> {
    if *session_id != msg1.session_id {
        return Err(PSCBBError::InvalidSessionID);
    }

    let big_a = match decode_point(&msg1.big_a) {
        None => {
            return Err(PSCBBError::InvalidMessage);
        }
        Some(v) => v,
    };

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let k = Scalar::from_bytes_mod_order(bytes);
    let big_b = big_a * k;

    let dlog_proof = DLogProof::prove(&k, &big_a, session_id, &mut *rng);

    let mut hat_big_y = big_y.clone();
    hat_big_y.shuffle(&mut *rng);
    let hat_big_y: Vec<Hash2Bytes> = hat_big_y
        .iter()
        .map(|v| {
            let h1 = h1_function(session_id, v);
            h2_function(session_id, &h1, &(h1 * k))
        })
        .collect();

    Ok(PSCMsg2 {
        session_id: *session_id,
        hat_big_y,
        big_b: encode_point(&big_b),
        dlog_proof,
    })
}

/// OB processes PSCMsg2 from BB
pub fn psc_process_msg2(state: &PSCStateOB, msg2: &PSCMsg2) -> Result<bool, PSCOBError> {
    if state.session_id != msg2.session_id {
        return Err(PSCOBError::InvalidSessionID);
    }

    let big_b = match decode_point(&msg2.big_b) {
        None => {
            return Err(PSCOBError::InvalidMessage);
        }
        Some(v) => v,
    };

    let proof_valid = msg2
        .dlog_proof
        .verify(&big_b, &state.big_a, &state.session_id);
    if proof_valid.unwrap_u8() != 1 {
        return Err(PSCOBError::InvalidDLogProof);
    }

    let r_inv = state.r.invert();
    let x_hat = h2_function(&state.session_id, &state.h1_x, &(big_b * r_inv));

    Ok(msg2.hat_big_y.contains(&x_hat))
}

#[cfg(test)]
mod tests {
    use crate::psc_protocol::{psc_create_msg1, psc_process_msg1, psc_process_msg2};
    use crate::utils::Customer;
    use rand::Rng;

    #[test]
    pub fn psc_x_in_list() {
        use rand::thread_rng;

        let mut rng = thread_rng();

        let session_id: [u8; 32] = rng.gen();

        // A list of customers for testing
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

        // x customer instance
        let customer_x = Customer::new("Customer8", "P8901234", "151 Walnut St");
        let customer_x_bytes = customer_x.to_hash_bytes();

        let big_y_bytes: Vec<[u8; 32]> = big_y.iter().map(|row| row.to_hash_bytes()).collect();

        let (state, msg1) = psc_create_msg1(&session_id, &customer_x_bytes, &mut rng);
        let msg2 = psc_process_msg1(&session_id, big_y_bytes, &msg1, &mut rng).unwrap();
        let result = psc_process_msg2(&state, &msg2).unwrap();

        assert!(result);
    }

    #[test]
    pub fn psc_x_not_in_list() {
        use rand::thread_rng;

        let mut rng = thread_rng();

        let session_id: [u8; 32] = rng.gen();

        // A list of customers for testing
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

        // x customer instance
        let customer_x = Customer::new("Customer0", "P0000001", "None");
        let customer_x_bytes = customer_x.to_hash_bytes();

        let big_y_bytes: Vec<[u8; 32]> = big_y.iter().map(|row| row.to_hash_bytes()).collect();

        let (state, msg1) = psc_create_msg1(&session_id, &customer_x_bytes, &mut rng);
        let msg2 = psc_process_msg1(&session_id, big_y_bytes, &msg1, &mut rng).unwrap();
        let result = psc_process_msg2(&state, &msg2).unwrap();

        assert!(!result);
    }
}
