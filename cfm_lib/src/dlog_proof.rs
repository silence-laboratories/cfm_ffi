use crate::constants::DLOG_LABEL;
use crate::proto::{
    decode_point, decode_scalar, encode_point, encode_scalar, PointBytes, ScalarBytes,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

/// Non-interactive Proof of knowledge of discrete logarithm with Fiat-Shamir transform.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DLogProof {
    /// Public point `t`.
    pub t: PointBytes,

    /// Challenge response
    pub s: ScalarBytes,
}

impl DLogProof {
    /// Prove knowledge of discrete logarithm.
    /// y = base_point * x
    pub fn prove<R: CryptoRng + RngCore>(
        x: &Scalar,
        base_point: &RistrettoPoint,
        session_id: &[u8],
        rng: &mut R,
    ) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let r = Scalar::from_bytes_mod_order(bytes);
        let t = base_point * r;
        let y = base_point * x;
        let c = Self::fiat_shamir(&y, &t, base_point, session_id);

        let s = r + c * x;

        Self {
            t: encode_point(&t),
            s: encode_scalar(&s),
        }
    }

    /// Verify knowledge of discrete logarithm.
    pub fn verify(
        &self,
        y: &RistrettoPoint,
        base_point: &RistrettoPoint,
        session_id: &[u8],
    ) -> Choice {
        let t = match decode_point(&self.t) {
            None => {
                return Choice::from(0);
            }
            Some(v) => v,
        };
        let s = match decode_scalar(&self.s) {
            None => {
                return Choice::from(0);
            }
            Some(v) => v,
        };
        let c = Self::fiat_shamir(y, &t, base_point, session_id);
        let lhs = base_point * s;
        let rhs = t + y * c;

        lhs.ct_eq(&rhs)
    }

    /// Get fiat-shamir challenge for Discrete log proof.
    fn fiat_shamir(
        y: &RistrettoPoint,
        t: &RistrettoPoint,
        base_point: &RistrettoPoint,
        session_id: &[u8],
    ) -> Scalar {
        let mut transcript = Transcript::new(DLOG_LABEL.as_ref());

        transcript.append_message(b"session-id", session_id);
        transcript.append_message(b"y", y.compress().as_bytes());
        transcript.append_message(b"t", t.compress().as_bytes());
        transcript.append_message(b"base-point", base_point.compress().as_bytes());

        let mut bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge-bytes", &mut bytes);

        Scalar::from_bytes_mod_order_wide(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::{thread_rng, Rng};
    use rand_core::RngCore;

    use super::DLogProof;

    #[test]
    pub fn dlog_proof() {
        use rand::thread_rng;

        let mut rng = thread_rng();

        let session_id: [u8; 32] = rng.gen();

        let mut x_bytes = [0u8; 32];
        rng.fill_bytes(&mut x_bytes);
        let x = Scalar::from_bytes_mod_order(x_bytes);

        let mut base_point_bytes = [0u8; 64];
        rng.fill_bytes(&mut base_point_bytes);
        let base_point = RistrettoPoint::from_uniform_bytes(&base_point_bytes);

        let y = base_point * x;

        let proof = DLogProof::prove(&x, &base_point, &session_id, &mut rng);

        assert_eq!(proof.verify(&y, &base_point, &session_id).unwrap_u8(), 1);
    }

    #[test]
    pub fn wrong_dlog_proof() {
        let mut rng = thread_rng();

        let session_id: [u8; 32] = rng.gen();

        let mut x_bytes = [0u8; 32];
        rng.fill_bytes(&mut x_bytes);
        let x = Scalar::from_bytes_mod_order(x_bytes);

        let mut wrong_x_bytes = [0u8; 32];
        rng.fill_bytes(&mut wrong_x_bytes);
        let wrong_x = Scalar::from_bytes_mod_order(wrong_x_bytes);

        let mut base_point_bytes = [0u8; 64];
        rng.fill_bytes(&mut base_point_bytes);
        let base_point = RistrettoPoint::from_uniform_bytes(&base_point_bytes);

        let y = base_point * x;

        let proof = DLogProof::prove(&wrong_x, &base_point, &session_id, &mut rng);

        assert_eq!(proof.verify(&y, &base_point, &session_id).unwrap_u8(), 0);
    }

    #[test]
    pub fn dlog_proof_fiat_shamir() {
        use rand::thread_rng;

        let mut rng = thread_rng();

        let session_id: [u8; 32] = rng.gen();
        let wrong_session_id: [u8; 32] = rng.gen();

        let mut x_bytes = [0u8; 32];
        rng.fill_bytes(&mut x_bytes);
        let x = Scalar::from_bytes_mod_order(x_bytes);

        let mut base_point_bytes = [0u8; 64];
        rng.fill_bytes(&mut base_point_bytes);
        let base_point = RistrettoPoint::from_uniform_bytes(&base_point_bytes);

        let y = base_point * x;

        let proof = DLogProof::prove(&x, &base_point, &session_id, &mut rng);

        assert_eq!(
            proof.verify(&y, &base_point, &wrong_session_id).unwrap_u8(),
            0,
            "Proof should fail with wrong session id"
        );
    }
}
