//! Private Set Intersection and Transfer protocol 4.2 implementation

use crate::constants::MASK_BYTES;
use crate::dlog_proof::DLogProof;
use crate::errors::{PSITCBError, PSITOBError};
use crate::proto::{decode_point, encode_point, xor_array, Hash2Bytes, Hash3Bytes, PointBytes};
use crate::utils::{h1_function, h2_function, h3_function};
use crypto_bigint::{Encoding, U128};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::prelude::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// PSITMsg1
#[derive(Clone, Serialize, Deserialize)]
pub struct PSITMsg1 {
    /// session id
    pub session_id: [u8; 32],

    /// point A
    pub big_a: PointBytes,
}

/// PSITMsg2
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PSITMsg2 {
    /// session id
    pub session_id: [u8; 32],

    /// hat(Y)
    pub hat_big_y: Vec<Hash2Bytes>,

    /// hat(Z)
    pub hat_big_z: Vec<Hash3Bytes>,

    /// point B
    pub big_b: PointBytes,

    /// DLog proof
    pub dlog_proof: DLogProof,
}

/// PSIT State for OB
#[derive(Clone, Serialize, Deserialize)]
pub struct PSITStateOB {
    /// session id
    pub session_id: [u8; 32],

    /// H1(Y)
    pub h1_y: RistrettoPoint,

    /// Scalar r
    pub r: Scalar,

    /// Point A
    pub big_a: RistrettoPoint,
}

/// OB creates PSITMsg1 for CB
pub fn psit_create_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    y: &[u8; 32],
    rng: &mut R,
) -> (PSITStateOB, PSITMsg1) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let r = Scalar::from_bytes_mod_order(bytes);
    let big_a = h1_function(session_id, y) * r;

    let state = PSITStateOB {
        session_id: *session_id,
        h1_y: h1_function(session_id, y),
        r,
        big_a,
    };

    let msg1 = PSITMsg1 {
        session_id: *session_id,
        big_a: encode_point(&big_a),
    };

    (state, msg1)
}

/// CB processes PSCMsg1 from OB
pub fn psit_process_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    big_y: Vec<[u8; 32]>,
    big_z: Vec<U128>,
    big_m: Vec<U128>,
    msg1: &PSITMsg1,
    rng: &mut R,
) -> Result<PSITMsg2, PSITCBError> {
    if *session_id != msg1.session_id {
        return Err(PSITCBError::InvalidSessionID);
    }

    let big_a = match decode_point(&msg1.big_a) {
        None => {
            return Err(PSITCBError::InvalidMessage);
        }
        Some(v) => v,
    };

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let k = Scalar::from_bytes_mod_order(bytes);
    let big_b = big_a * k;

    let dlog_proof = DLogProof::prove(&k, &big_a, session_id, &mut *rng);

    let mut indices: Vec<usize> = (0..big_y.len()).collect();
    indices.shuffle(&mut *rng);

    let mut hat_big_y = big_y.clone();
    (0..hat_big_y.len()).for_each(|i| hat_big_y.swap(i, indices[i]));

    let hat_big_y: Vec<Hash2Bytes> = hat_big_y
        .iter()
        .map(|v| {
            let h1 = h1_function(session_id, v);
            h2_function(session_id, &h1, &(h1 * k))
        })
        .collect();

    let mut shuffled_big_z = big_z.clone();
    (0..shuffled_big_z.len()).for_each(|i| shuffled_big_z.swap(i, indices[i]));

    let mut shuffled_big_m = big_m.clone();
    (0..shuffled_big_m.len()).for_each(|i| shuffled_big_m.swap(i, indices[i]));

    let mut shuffled_big_y = big_y.clone();
    (0..shuffled_big_y.len()).for_each(|i| shuffled_big_y.swap(i, indices[i]));

    let mut hat_big_z: Vec<Hash3Bytes> = Vec::new();
    for i in 0..shuffled_big_y.len() {
        let v = shuffled_big_y[i];
        let h1 = h1_function(session_id, &v);
        let h3 = h3_function(session_id, &h1, &(h1 * k));
        let z: Hash3Bytes = {
            let mut result = [0u8; 2 * MASK_BYTES];
            result[..MASK_BYTES].copy_from_slice(&shuffled_big_z[i].to_be_bytes());
            result[MASK_BYTES..].copy_from_slice(&shuffled_big_m[i].to_be_bytes());
            result
        };
        hat_big_z.push(xor_array(h3, z));
    }

    Ok(PSITMsg2 {
        session_id: *session_id,
        hat_big_y,
        hat_big_z,
        big_b: encode_point(&big_b),
        dlog_proof,
    })
}

/// OB processes PSITMsg2 from CB
pub fn psit_process_msg2(
    state: &PSITStateOB,
    msg2: &PSITMsg2,
) -> Result<(U128, U128), PSITOBError> {
    if state.session_id != msg2.session_id {
        return Err(PSITOBError::InvalidSessionID);
    }

    let big_b = match decode_point(&msg2.big_b) {
        None => {
            return Err(PSITOBError::InvalidMessage);
        }
        Some(v) => v,
    };

    let proof_valid = msg2
        .dlog_proof
        .verify(&big_b, &state.big_a, &state.session_id);
    if proof_valid.unwrap_u8() != 1 {
        return Err(PSITOBError::InvalidDLogProof);
    }

    let r_inv = state.r.invert();
    let x_hat = h2_function(&state.session_id, &state.h1_y, &(big_b * r_inv));

    let mut z_y: [u8; MASK_BYTES] = [0u8; MASK_BYTES];
    let mut m_y: [u8; MASK_BYTES] = [0u8; MASK_BYTES];

    if let Some(index) = msg2.hat_big_y.iter().position(|&x| x == x_hat) {
        let z = xor_array(
            msg2.hat_big_z[index],
            h3_function(&state.session_id, &state.h1_y, &(big_b * r_inv)),
        );
        z_y.copy_from_slice(&z[..MASK_BYTES]);
        m_y.copy_from_slice(&z[MASK_BYTES..]);
    } else {
        return Err(PSITOBError::NotInList);
    }
    Ok((U128::from_be_slice(&z_y), U128::from_be_slice(&m_y)))
}

#[cfg(test)]
mod tests {
    use crate::psit_protocol::{psit_create_msg1, psit_process_msg1, psit_process_msg2};
    use crate::utils::Customer;
    use crypto_bigint::U128;
    use rand::Rng;

    #[test]
    pub fn psit_x_in_list() {
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
        let customer_x = Customer::new("Customer3", "P3456789", "789 Maple St");
        let customer_x_bytes = customer_x.to_hash_bytes();

        let big_y_bytes: Vec<[u8; 32]> = big_y.iter().map(|row| row.to_hash_bytes()).collect();

        let big_z = vec![
            U128::from_u8(1),
            U128::from_u8(2),
            U128::from_u8(3),
            U128::from_u8(4),
            U128::from_u8(5),
            U128::from_u8(6),
            U128::from_u8(7),
            U128::from_u8(8),
            U128::from_u8(9),
            U128::from_u8(10),
        ];

        let big_m = vec![
            U128::from_u8(11),
            U128::from_u8(12),
            U128::from_u8(13),
            U128::from_u8(14),
            U128::from_u8(15),
            U128::from_u8(16),
            U128::from_u8(17),
            U128::from_u8(18),
            U128::from_u8(19),
            U128::from_u8(20),
        ];

        let (state, msg1) = psit_create_msg1(&session_id, &customer_x_bytes, &mut rng);
        let msg2 =
            psit_process_msg1(&session_id, big_y_bytes, big_z, big_m, &msg1, &mut rng).unwrap();
        let (_z, _m) = psit_process_msg2(&state, &msg2).unwrap();
    }

    #[test]
    pub fn psit_x_not_in_list() {
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
        let customer_x = Customer::new("Customer11", "P3456789", "789 Maple St");
        let customer_x_bytes = customer_x.to_hash_bytes();

        let big_y_bytes: Vec<[u8; 32]> = big_y.iter().map(|row| row.to_hash_bytes()).collect();

        let big_z = vec![
            U128::from_u8(1),
            U128::from_u8(2),
            U128::from_u8(3),
            U128::from_u8(4),
            U128::from_u8(5),
            U128::from_u8(6),
            U128::from_u8(7),
            U128::from_u8(8),
            U128::from_u8(9),
            U128::from_u8(10),
        ];

        let big_m = vec![
            U128::from_u8(11),
            U128::from_u8(12),
            U128::from_u8(13),
            U128::from_u8(14),
            U128::from_u8(15),
            U128::from_u8(16),
            U128::from_u8(17),
            U128::from_u8(18),
            U128::from_u8(19),
            U128::from_u8(20),
        ];

        let (state, msg1) = psit_create_msg1(&session_id, &customer_x_bytes, &mut rng);
        let msg2 =
            psit_process_msg1(&session_id, big_y_bytes, big_z, big_m, &msg1, &mut rng).unwrap();
        let result = psit_process_msg2(&state, &msg2);
        assert!(result.is_err());
    }
}
