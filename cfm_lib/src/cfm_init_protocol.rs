use crate::proto::ZS;
use crate::sl_oblivious::endemic_ot::{
    EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender,
};
use crate::sl_oblivious::soft_spoken::{
    build_pprf, eval_pprf, PPRFOutput, ReceiverOTSeed, SenderOTSeed,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// CFMInitMsg1
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Debug, PartialEq)]
pub struct CFMInitMsg1 {
    /// session id
    pub session_id: [u8; 32],

    /// EndemicOTMsg1
    pub msg1_a: ZS<EndemicOTMsg1>,
}

/// CFMInitMsg2
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Debug, PartialEq)]
pub struct CFMInitMsg2 {
    /// session id
    pub session_id: [u8; 32],

    /// EndemicOTMsg2
    pub msg2_a: ZS<EndemicOTMsg2>,

    /// pprf_output_a
    pub pprf_output_a: ZS<PPRFOutput>,

    /// EndemicOTMsg1
    pub msg1_b: ZS<EndemicOTMsg1>,
}

/// CFMInitMsg3
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Debug, PartialEq)]
pub struct CFMInitMsg3 {
    /// session id
    pub session_id: [u8; 32],

    /// EndemicOTMsg2
    pub msg2_b: ZS<EndemicOTMsg2>,

    /// pprf_output_b
    pub pprf_output_b: ZS<PPRFOutput>,
}

/// CFMInitStateCB
#[derive(Serialize, Deserialize)]
pub struct CFMInitStateCB {
    /// session id
    pub session_id: [u8; 32],

    /// EndemicOTReceiver
    pub receiver: EndemicOTReceiver,

    /// sender_ot_seed_0
    pub sender_ot_seed_0: ZS<SenderOTSeed>,
}

/// CFMInitStateOB
#[derive(Serialize, Deserialize)]
pub struct CFMInitStateOB {
    /// session id
    pub session_id: [u8; 32],

    /// EndemicOTReceiver
    pub receiver: EndemicOTReceiver,
}

/// CFMInitOTSeedsOB
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CFMInitOTSeedsOB {
    /// receiver_ot_seed_0
    pub receiver_ot_seed_0: ZS<ReceiverOTSeed>,

    /// sender_ot_seed_1
    pub sender_ot_seed_1: ZS<SenderOTSeed>,
}

/// CFMInitOTSeedsCB
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CFMInitOTSeedsCB {
    /// sender_ot_seed_0
    pub sender_ot_seed_0: ZS<SenderOTSeed>,

    /// receiver_ot_seed_1
    pub receiver_ot_seed_1: ZS<ReceiverOTSeed>,
}

/// OB creates CFMInitMsg1 for CB
pub fn cfm_init_create_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    msg1: &mut CFMInitMsg1,
    rng: &mut R,
) -> CFMInitStateOB {
    msg1.session_id = *session_id;
    let receiver = EndemicOTReceiver::new(session_id, &mut msg1.msg1_a, rng);
    CFMInitStateOB {
        session_id: *session_id,
        receiver,
    }
}

/// CB processes CFMInitMsg1 from OB
pub fn cfm_init_process_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    msg1: &CFMInitMsg1,
    msg2: &mut CFMInitMsg2,
    rng: &mut R,
) -> Result<CFMInitStateCB, &'static str> {
    msg2.session_id = *session_id;
    let sender_output_0 =
        EndemicOTSender::process(session_id, &msg1.msg1_a, &mut msg2.msg2_a, rng)?;
    let receiver = EndemicOTReceiver::new(session_id, &mut msg2.msg1_b, rng);

    let mut sender_ot_seed_0 = ZS::<SenderOTSeed>::default();
    build_pprf(
        session_id,
        &sender_output_0,
        &mut sender_ot_seed_0,
        &mut msg2.pprf_output_a,
    );

    Ok(CFMInitStateCB {
        session_id: *session_id,
        receiver,
        sender_ot_seed_0,
    })
}

/// OB processes CFMInitMsg2 from CB
pub fn cfm_init_process_msg2<R: CryptoRng + RngCore>(
    state: CFMInitStateOB,
    msg2: &CFMInitMsg2,
    msg3: &mut CFMInitMsg3,
    rng: &mut R,
) -> Result<CFMInitOTSeedsOB, &'static str> {
    msg3.session_id = state.session_id;
    let receiver_output = state.receiver.process(&msg2.msg2_a).unwrap();
    let mut receiver_ot_seed_0 = ZS::<ReceiverOTSeed>::default();
    eval_pprf(
        &state.session_id,
        &receiver_output,
        &msg2.pprf_output_a,
        &mut receiver_ot_seed_0,
    )?;

    let sender_output_1 =
        EndemicOTSender::process(&state.session_id, &msg2.msg1_b, &mut msg3.msg2_b, rng)?;
    let mut sender_ot_seed_1 = ZS::<SenderOTSeed>::default();
    build_pprf(
        &state.session_id,
        &sender_output_1,
        &mut sender_ot_seed_1,
        &mut msg3.pprf_output_b,
    );

    Ok(CFMInitOTSeedsOB {
        receiver_ot_seed_0,
        sender_ot_seed_1,
    })
}

/// CB processes CFMInitMsg3 from OB
pub fn cfm_init_process_msg3(
    state: CFMInitStateCB,
    msg3: &CFMInitMsg3,
) -> Result<CFMInitOTSeedsCB, &'static str> {
    let receiver_output_1 = state.receiver.process(&msg3.msg2_b)?;

    let mut receiver_ot_seed_1 = ZS::<ReceiverOTSeed>::default();
    eval_pprf(
        &state.session_id,
        &receiver_output_1,
        &msg3.pprf_output_b,
        &mut receiver_ot_seed_1,
    )?;

    Ok(CFMInitOTSeedsCB {
        sender_ot_seed_0: state.sender_ot_seed_0,
        receiver_ot_seed_1,
    })
}

pub fn generate_cfm_ot_seeds_for_test<R: RngCore + CryptoRng>(
    session_id: &[u8; 32],
    rng: &mut R,
) -> (CFMInitOTSeedsCB, CFMInitOTSeedsOB) {
    let mut msg1 = CFMInitMsg1::default();
    let state_ob = cfm_init_create_msg1(session_id, &mut msg1, rng);

    let mut msg2 = CFMInitMsg2::default();
    let state_cb = cfm_init_process_msg1(session_id, &msg1, &mut msg2, rng).unwrap();

    let mut msg3 = CFMInitMsg3::default();
    let ot_seeds_ob = cfm_init_process_msg2(state_ob, &msg2, &mut msg3, rng).unwrap();
    let ot_seeds_cb = cfm_init_process_msg3(state_cb, &msg3).unwrap();

    (ot_seeds_cb, ot_seeds_ob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_cfm_init() {
        let mut rng = rand::thread_rng();
        let session_id: [u8; 32] = rng.gen();
        let (_ot_seeds_cb, _ot_seeds_ob) = generate_cfm_ot_seeds_for_test(&session_id, &mut rng);
    }
}
