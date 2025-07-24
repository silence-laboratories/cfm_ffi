use crypto_bigint::U64;
use cfm_lib::auth_beaver_triples::{
    abt_create_msg1, abt_process_msg1, abt_process_msg2, abt_process_msg3, abt_process_msg4,
    abt_process_msg5, Share,
};
use cfm_lib::cfm_init_protocol::{
    cfm_init_create_msg1, cfm_init_process_msg1, cfm_init_process_msg2, cfm_init_process_msg3,
    CFMInitMsg1, CFMInitMsg2, CFMInitMsg3,
};
use cfm_lib::cfm_protocol::{
    cfm_create_msg1, cfm_process_msg1, cfm_process_msg10, cfm_process_msg11, cfm_process_msg12,
    cfm_process_msg13, cfm_process_msg14, cfm_process_msg15, cfm_process_msg16, cfm_process_msg17,
    cfm_process_msg18, cfm_process_msg2, cfm_process_msg3, cfm_process_msg4, cfm_process_msg5,
    cfm_process_msg6, cfm_process_msg7, cfm_process_msg8, cfm_process_msg9,
    NUMBER_OF_AUTH_BEAVER_TRIPLES, NUMBER_OF_SHARES,
};
use cfm_lib::utils::Customer;
use cfm_lib::P;
use rand::Rng;
use std::time::{Duration, Instant};
use serde::Serialize; // Ensure your types implement Serialize

// A simple structure for logging each step.
#[derive(Debug)]
struct BenchmarkLog {
    step: String,
    duration: Duration,
    size: usize,
}

// A helper function to record and print a log entry given a serializable output.
fn log_step<T: Serialize>(
    log: &mut Vec<BenchmarkLog>,
    step: &str,
    duration: Duration,
    message: &T,
) {
    let size = bincode::serialize(message).unwrap().len();
    println!("{:<30} | Time: {:?} | Size: {} bytes", step, duration, size);
    log.push(BenchmarkLog {
        step: step.to_string(),
        duration,
        size,
    });
}

/// Runs the entire protocol for a given sanction list size.
/// Returns a vector of BenchmarkLog entries summarizing each step.
fn benchmark_cfm_with_sanction_list(size: usize) -> Vec<BenchmarkLog> {
    let mut log: Vec<BenchmarkLog> = Vec::new();
    let mut rng = rand::thread_rng();
    println!("\n=== Benchmark with sanction list size: {} ===", size);

    // ----------------------------
    // 1. OT Seeds Setup Phase
    // ----------------------------
    let start_ot = Instant::now();
    let init_session_id: [u8; 32] = rng.gen();

    let mut init_msg1 = CFMInitMsg1::default();
    let start = Instant::now();
    let state_ob = cfm_init_create_msg1(&init_session_id, &mut init_msg1, &mut rng);
    log_step(&mut log, "cfm_init_create_msg1", start.elapsed(), &init_msg1);

    let mut init_msg2 = CFMInitMsg2::default();
    let start = Instant::now();
    let state_cb = cfm_init_process_msg1(&init_session_id, &init_msg1, &mut init_msg2, &mut rng)
        .expect("cfm_init_process_msg1 failed");
    log_step(&mut log, "cfm_init_process_msg1", start.elapsed(), &init_msg2);

    let mut init_msg3 = CFMInitMsg3::default();
    let start = Instant::now();
    let ot_seeds_ob = cfm_init_process_msg2(state_ob, &init_msg2, &mut init_msg3, &mut rng)
        .expect("cfm_init_process_msg2 failed");
    log_step(&mut log, "cfm_init_process_msg2", start.elapsed(), &init_msg3);

    let start = Instant::now();
    let ot_seeds_cb = cfm_init_process_msg3(state_cb, &init_msg3)
        .expect("cfm_init_process_msg3 failed");
    log_step(&mut log, "cfm_init_process_msg3", start.elapsed(), &ot_seeds_cb);

    let ot_time = start_ot.elapsed();
    println!("OT seeds creation total time: {:?}", ot_time);

    // ----------------------------
    // 2. Auth Beaver Triples Setup
    // ----------------------------
    let start_abt = Instant::now();
    let session_id: [u8; 32] = rng.gen();
    let p = P;
    let eta_i = NUMBER_OF_SHARES;
    let eta_m = NUMBER_OF_AUTH_BEAVER_TRIPLES;

    let start = Instant::now();
    let (state_cb_r1, abt_msg1) =
        abt_create_msg1(&session_id, &ot_seeds_cb, p, eta_i, eta_m, &mut rng);
    log_step(&mut log, "abt_create_msg1", start.elapsed(), &abt_msg1);

    let start = Instant::now();
    let (state_ob_r1, mut shares_ob, mut auth_triples_ob, abt_msg2) =
        abt_process_msg1(&session_id, &ot_seeds_ob, p, eta_i, eta_m, &abt_msg1, &mut rng)
            .expect("abt_process_msg1 failed");
    log_step(&mut log, "abt_process_msg1", start.elapsed(), &abt_msg2);

    let start = Instant::now();
    let (state_cb_r2, shares_cb, auth_triples_cb, abt_msg3) =
        abt_process_msg2(&state_cb_r1, &ot_seeds_cb, &abt_msg2, &mut rng)
            .expect("abt_process_msg2 failed");
    log_step(&mut log, "abt_process_msg2", start.elapsed(), &abt_msg3);

    let start = Instant::now();
    let (state_ob_r2, abt_msg4) =
        abt_process_msg3(&state_ob_r1, &mut shares_ob, &mut auth_triples_ob, &abt_msg3)
            .expect("abt_process_msg3 failed");
    log_step(&mut log, "abt_process_msg3", start.elapsed(), &abt_msg4);

    let start = Instant::now();
    let abt_msg5 = abt_process_msg4(&state_cb_r2, &auth_triples_cb, &abt_msg4)
        .expect("abt_process_msg4 failed");
    log_step(&mut log, "abt_process_msg4", start.elapsed(), &abt_msg5);

    let start = Instant::now();
    abt_process_msg5(&state_ob_r2, &abt_msg5)
        .expect("abt_process_msg5 failed");
    log_step(&mut log, "abt_process_msg5", start.elapsed(), &"N/A".to_string());
    let abt_time = start_abt.elapsed();
    println!("Auth Beaver Triples total time: {:?}", abt_time);

    // ----------------------------
    // 3. Generate Sanction List (big_y and big_z)
    // ----------------------------
    let start_list = Instant::now();
    let mut big_y: Vec<Customer> = Vec::with_capacity(size);
    let mut big_z: Vec<U64> = Vec::with_capacity(size);
    for i in 0..size {
        if i == 2 {
            let fixed_customer = Customer::new("Customer3", "P3456789", "789 Maple St");
            big_y.push(fixed_customer);
            // Set its capital flow to 30 (so that 100 + 30 = 130 < 140).
            big_z.push(U64::from_u32(30));
        } else {
            let cust = Customer::new(&format!("Customer{}", i + 1), &format!("P{:07}", i + 1), "XYZ");
            big_y.push(cust);
            big_z.push(U64::from_u32(rng.gen_range(40..=60)));
        }
    }
    let big_y_bytes: Vec<[u8; 32]> = big_y.iter().map(|c| c.to_hash_bytes()).collect();
    let start = Instant::now();
    // Log the total sanction list bytes (each hash is 32 bytes).
    let list_bytes = big_y_bytes.len() * 32;
    println!("{:<30} | Time: {:?} | Size: {} bytes", "Sanction list (big_y)", start.elapsed(), list_bytes);
    log.push(BenchmarkLog {
        step: "Sanction list (big_y)".to_string(),
        duration: start.elapsed(),
        size: list_bytes,
    });
    let list_time = start_list.elapsed();
    println!("Sanction list generation total time: {:?}", list_time);

    // ----------------------------
    // 4. CFM Protocol Phase
    // ----------------------------
    // Set parameters: public threshold L = 140 and transaction amount big_x = 100.
    let big_l = U64::from_u32(140);
    let big_x = U64::from_u32(100);
    let customer_y = Customer::new("Customer3", "P3456789", "789 Maple St");
    let customer_y_bytes = customer_y.to_hash_bytes();

    let start_cfm = Instant::now();
    let start = Instant::now();
    let (cfm_state_ob_r1, cfm_msg1) =
        cfm_create_msg1(&session_id, p, big_l, big_x, &customer_y_bytes, &shares_ob, &mut rng);
    log_step(&mut log, "cfm_create_msg1", start.elapsed(), &cfm_msg1);

    let start = Instant::now();
    let (cfm_state_cb_r1, cfm_msg2) = cfm_process_msg1(
        &session_id,
        p,
        big_l,
        big_y_bytes,
        big_z,
        &shares_cb,
        &cfm_msg1,
        &mut rng,
    )
    .expect("cfm_process_msg1 failed");
    log_step(&mut log, "cfm_process_msg1", start.elapsed(), &cfm_msg2);

    let start = Instant::now();
    let (cfm_state_ob_r2, cfm_msg3) = cfm_process_msg2(
        &cfm_state_ob_r1,
        &shares_ob,
        &auth_triples_ob,
        &cfm_msg2,
        &mut rng,
    )
    .expect("cfm_process_msg2 failed");
    log_step(&mut log, "cfm_process_msg2", start.elapsed(), &cfm_msg3);

    let start = Instant::now();
    let (cfm_state_cb_r2, cfm_msg4) = cfm_process_msg3(
        cfm_state_cb_r1,
        &shares_cb,
        &auth_triples_cb,
        &cfm_msg3,
    )
    .expect("cfm_process_msg3 failed");
    log_step(&mut log, "cfm_process_msg3", start.elapsed(), &cfm_msg4);

    let start = Instant::now();
    let (cfm_state_ob_r3, cfm_msg5) =
        cfm_process_msg4(cfm_state_ob_r2, &cfm_msg4).expect("cfm_process_msg4 failed");
    log_step(&mut log, "cfm_process_msg4", start.elapsed(), &cfm_msg5);

    let start = Instant::now();
    let state_cb_r2_for_chain = cfm_state_cb_r2.clone();
    let (cfm_state_cb_r3, cfm_msg6) = cfm_process_msg5(
        state_cb_r2_for_chain,
        &auth_triples_cb,
        &cfm_msg5,
    )
    .expect("cfm_process_msg5 failed");
    log_step(&mut log, "cfm_process_msg5", start.elapsed(), &cfm_msg6);

    let start = Instant::now();
    let (cfm_state_ob_r4, cfm_msg7) =
        cfm_process_msg6(cfm_state_ob_r3, &auth_triples_ob, &cfm_msg6)
            .expect("cfm_process_msg6 failed");
    log_step(&mut log, "cfm_process_msg6", start.elapsed(), &cfm_msg7);

    let start = Instant::now();
    let (cfm_state_cb_r4, cfm_msg8) = cfm_process_msg7(
        cfm_state_cb_r3,
        &auth_triples_cb,
        &cfm_msg7,
    )
    .expect("cfm_process_msg7 failed");
    log_step(&mut log, "cfm_process_msg7", start.elapsed(), &cfm_msg8);

    let start = Instant::now();
    let (cfm_state_ob_r5, cfm_msg9) =
        cfm_process_msg8(cfm_state_ob_r4, &auth_triples_ob, &cfm_msg8)
            .expect("cfm_process_msg8 failed");
    log_step(&mut log, "cfm_process_msg8", start.elapsed(), &cfm_msg9);

    let start = Instant::now();
    let (cfm_state_cb_r5, cfm_msg10) = cfm_process_msg9(
        cfm_state_cb_r4,
        &auth_triples_cb,
        &cfm_msg9,
    )
    .expect("cfm_process_msg9 failed");
    log_step(&mut log, "cfm_process_msg9", start.elapsed(), &cfm_msg10);

    let start = Instant::now();
    let (cfm_state_ob_r6, cfm_msg11) = cfm_process_msg10(
        cfm_state_ob_r5,
        &auth_triples_ob,
        &cfm_msg10,
    )
    .expect("cfm_process_msg10 failed");
    log_step(&mut log, "cfm_process_msg10", start.elapsed(), &cfm_msg11);

    let start = Instant::now();
    let (cfm_state_cb_r6, cfm_msg12) = cfm_process_msg11(
        cfm_state_cb_r5,
        &auth_triples_cb,
        &cfm_msg11,
    )
    .expect("cfm_process_msg11 failed");
    log_step(&mut log, "cfm_process_msg11", start.elapsed(), &cfm_msg12);

    let start = Instant::now();
    let (cfm_state_ob_r7, cfm_msg13) = cfm_process_msg12(
        cfm_state_ob_r6,
        &auth_triples_ob,
        &cfm_msg12,
    )
    .expect("cfm_process_msg12 failed");
    log_step(&mut log, "cfm_process_msg12", start.elapsed(), &cfm_msg13);

    let start = Instant::now();
    let (cfm_state_cb_r7, cfm_msg14) = cfm_process_msg13(
        cfm_state_cb_r6,
        &auth_triples_cb,
        &cfm_msg13,
    )
    .expect("cfm_process_msg13 failed");
    log_step(&mut log, "cfm_process_msg13", start.elapsed(), &cfm_msg14);

    let start = Instant::now();
    let (cfm_state_ob_r8, cfm_msg15) = cfm_process_msg14(
        cfm_state_ob_r7,
        &cfm_msg14,
    )
    .expect("cfm_process_msg14 failed");
    log_step(&mut log, "cfm_process_msg14", start.elapsed(), &cfm_msg15);

    let start = Instant::now();
    let (cfm_state_cb_r8, cfm_msg16) = cfm_process_msg15(
        cfm_state_cb_r7,
        &cfm_msg15,
    )
    .expect("cfm_process_msg15 failed");
    log_step(&mut log, "cfm_process_msg15", start.elapsed(), &cfm_msg16);

    let start = Instant::now();
    let (cfm_state_ob_r9, cfm_msg17) = cfm_process_msg16(
        cfm_state_ob_r8,
        &cfm_msg16,
    )
    .expect("cfm_process_msg16 failed");
    log_step(&mut log, "cfm_process_msg16", start.elapsed(), &cfm_msg17);

    let start = Instant::now();
    let (b_cb_value, cfm_msg18) = cfm_process_msg17(
        cfm_state_cb_r8,
        &cfm_msg17,
    )
    .expect("cfm_process_msg17 failed");
    log_step(&mut log, "cfm_process_msg17", start.elapsed(), &cfm_msg18);

    let start = Instant::now();
    let b_ob_value = cfm_process_msg18(
        cfm_state_ob_r9,
        &cfm_msg18,
    )
    .expect("cfm_process_msg18 failed");
    log_step(&mut log, "cfm_process_msg18", start.elapsed(), &b_ob_value);

    assert_eq!(b_cb_value, b_ob_value);
    let cfm_time = start_cfm.elapsed();
    println!("CFM protocol total time: {:?}", cfm_time);
    println!("Benchmark for size {} completed. Final result: {:?}", size, b_cb_value);

    log
}

fn main() {
    // Run benchmarks for sanction list sizes: 1,000; 10,000; 100,000; 1,000,000.
    let sizes = [1000, 10_000, 100_000, 1_000_000];
    for &size in sizes.iter() {
        let log_entries = benchmark_cfm_with_sanction_list(size);
        println!("\n--- Detailed Log for size {} ---", size);
        for entry in log_entries {
            println!("{:<30} | Time: {:?} | Size: {} bytes", entry.step, entry.duration, entry.size);
        }
    }
}
