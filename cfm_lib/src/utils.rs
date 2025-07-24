use crate::constants::{H1_RO_LABEL, H2_RO_LABEL, LAMBDA_BYTES, MASK_BYTES};
use crate::proto::{Hash2Bytes, Hash3Bytes};
use curve25519_dalek::ristretto::RistrettoPoint;
use merlin::Transcript;
use serde::{Serialize, Deserialize};

/// H1 function
pub(crate) fn h1_function(session_id: &[u8], x: &[u8]) -> RistrettoPoint {
    let mut t = Transcript::new(H1_RO_LABEL.as_ref());

    t.append_message(b"session-id", session_id);
    t.append_message(b"x", x);

    let mut output = [0u8; 64];
    t.challenge_bytes(b"h1-ro-bytes", &mut output);

    RistrettoPoint::from_uniform_bytes(&output)
}

/// H2 function
pub(crate) fn h2_function(
    session_id: &[u8],
    point1: &RistrettoPoint,
    point2: &RistrettoPoint,
) -> Hash2Bytes {
    let mut t = Transcript::new(H2_RO_LABEL.as_ref());

    t.append_message(b"session-id", session_id);
    t.append_message(b"point1", point1.compress().as_bytes());
    t.append_message(b"point2", point2.compress().as_bytes());

    let mut output: Hash2Bytes = [0u8; LAMBDA_BYTES * 2];
    t.challenge_bytes(b"h2-ro-bytes", &mut output);

    output
}

/// H3 function
pub(crate) fn h3_function(
    session_id: &[u8],
    point1: &RistrettoPoint,
    point2: &RistrettoPoint,
) -> Hash3Bytes {
    let mut t = Transcript::new(H2_RO_LABEL.as_ref());

    t.append_message(b"session-id", session_id);
    t.append_message(b"point1", point1.compress().as_bytes());
    t.append_message(b"point2", point2.compress().as_bytes());

    let mut output: Hash3Bytes = [0u8; MASK_BYTES * 2];
    t.challenge_bytes(b"h2-ro-bytes", &mut output);

    output
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Customer {
    name: String,
    passport_number: String,
    address: String,
}

impl Customer {
    pub fn new(name: &str, passport_number: &str, address: &str) -> Self {
        Customer {
            name: name.to_string(),
            passport_number: passport_number.to_string(),
            address: address.to_string(),
        }
    }

    pub fn to_hash_bytes(&self) -> [u8; 32] {
        let mut transcript = Transcript::new(b"Customer hash bytes");

        transcript.append_message(b"name", self.name.as_bytes());
        transcript.append_message(b"passport_number", self.passport_number.as_bytes());
        transcript.append_message(b"address", self.address.as_bytes());

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge-bytes", &mut bytes);

        bytes
    }
}
