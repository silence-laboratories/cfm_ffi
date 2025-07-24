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

fn main() {
    let mut rng = rand::thread_rng();

    // Start measuring time
    let start_ot_seeds = std::time::Instant::now();

    // Generate session ID
    let init_session_id: [u8; 32] = rng.gen();

    // Serialize session ID
    // let serialized_session_id = bincode::serialize(&init_session_id).unwrap();
    // println!("Serialized session ID size: {} bytes", serialized_session_id.len());

    // Create and serialize msg1
    let mut msg1 = CFMInitMsg1::default();
    // println!("THE MSG1 is {:#?}", msg1);
    // let serialized_msg1 = bincode::serialize(&msg1).unwrap();
    // println!("Serialized msg1 size: {} bytes", serialized_msg1.len());

    let msg1_clone = msg1.clone();

    // Call cfm_init_create_msg1
    let state_ob = cfm_init_create_msg1(&init_session_id, &mut msg1, &mut rng);

    // println!("CHECK IF MSG1 was actually modified");
    // assert_eq!(msg1_clone, msg1);

    // Serialize state_ob
    // let serialized_state_ob = match bincode::serialize(&state_ob) {
    //     Ok(data) => {
    //         println!("Serialized state_ob size: {} bytes", data.len());
    //         data
    //     },
    //     Err(e) => {
    //         println!("Error serializing state_ob: {:?}", e);
    //         return;
    //     }
    // };

    // Create and serialize msg2
    let mut msg2 = CFMInitMsg2::default();
    // let serialized_msg2 = bincode::serialize(&msg2).unwrap();
    // println!("Serialized msg2 size: {} bytes", serialized_msg2.len());

    // Call cfm_init_process_msg1
    let state_cb = match cfm_init_process_msg1(&init_session_id, &msg1, &mut msg2, &mut rng) {
        Ok(state) => state,
        Err(e) => {
            println!("Error in cfm_init_process_msg1: {:?}", e);
            return;
        }
    };

    // Serialize state_cb
    // let serialized_state_cb = bincode::serialize(&state_cb).unwrap();
    // println!("Serialized state_cb size: {} bytes", serialized_state_cb.len());

    // Create and serialize msg3
    let mut msg3 = CFMInitMsg3::default();
    // let serialized_msg3 = bincode::serialize(&msg3).unwrap();
    // println!("Serialized msg3 size: {} bytes", serialized_msg3.len());

    // Call cfm_init_process_msg2
    let ot_seeds_ob = match cfm_init_process_msg2(state_ob, &msg2, &mut msg3, &mut rng) {
        Ok(seeds) => seeds,
        Err(e) => {
            println!("Error in cfm_init_process_msg2: {:?}", e);
            return;
        }
    };

    // Serialize ot_seeds_ob
    // let serialized_ot_seeds_ob = bincode::serialize(&ot_seeds_ob).unwrap();
    // println!("Serialized ot_seeds_ob size: {} bytes", serialized_ot_seeds_ob.len());

    // Call cfm_init_process_msg3
    let ot_seeds_cb = match cfm_init_process_msg3(state_cb, &msg3) {
        Ok(seeds) => seeds,
        Err(e) => {
            println!("Error in cfm_init_process_msg3: {:?}", e);
            return;
        }
    };

    // Serialize ot_seeds_cb
    // let serialized_ot_seeds_cb = bincode::serialize(&ot_seeds_cb).unwrap();
    // println!("Serialized ot_seeds_cb size: {} bytes", serialized_ot_seeds_cb.len());

    // Print total execution time
    println!("Create OT seeds time: {:?}", start_ot_seeds.elapsed());


    // create auth beaver triples
    let start_auth_triples = std::time::Instant::now();
    let session_id: [u8; 32] = rng.gen();
    let p = P;
    let eta_i = NUMBER_OF_SHARES;
    let eta_m = NUMBER_OF_AUTH_BEAVER_TRIPLES;

    println!("p is {:#?}", P);
    // println!("eta_i is {:#?}", eta_i);
    // println!("eta_m is {:#?}", eta_m);

    let start_abt_create_msg1 = std::time::Instant::now();
    let (state_cb_r1, msg1) =
        abt_create_msg1(&session_id, &ot_seeds_cb, p, eta_i, eta_m, &mut rng); // cb DONE

    // let serialized_state_cb_r1 = bincode::serialize(&state_cb_r1).unwrap();
    // let serialized_msg1 = bincode::serialize(&msg1).unwrap();
    // println!("Serialized state_cb_r1 size: {} bytes", serialized_state_cb_r1.len());
    // println!("Serialized msg1 size: {} bytes", serialized_msg1.len());


    let end_abt_create_msg1 = start_abt_create_msg1.elapsed();
    println!("abt_create_msg1 time is: {:?}", end_abt_create_msg1);

    let start_abt_process_msg1 = std::time::Instant::now();
    let (state_ob_r1, mut shares_ob, mut auth_triples_ob, msg2) =
        abt_process_msg1(&session_id, &ot_seeds_ob, p, eta_i, eta_m, &msg1, &mut rng).unwrap(); // ob


    // println!("THE SHARES OB IS LLLLLLLLLLLL{:#?}", shares_ob);

    // let serialized_state_ob_r1 = bincode::serialize(&state_ob_r1).unwrap();
    // let serialized_shares_ob = bincode::serialize(&shares_ob).unwrap();
    // let serialized_auth_triples_ob = bincode::serialize(&auth_triples_ob).unwrap();
    // let serialized_msg2 = bincode::serialize(&msg2).unwrap();


    // println!("\n\nSerialized state_ob_r1 size: {} bytes", serialized_state_ob_r1.len());
    // println!("Serialized shares_ob size: {} bytes", serialized_shares_ob.len());
    // println!("Serialized auth_triples_ob size: {} bytes", serialized_auth_triples_ob.len());
    // println!("Serialized msg2 size: {} bytes", serialized_msg2.len());

    let end_abt_process_msg1 = start_abt_create_msg1.elapsed() - end_abt_create_msg1;
    println!("abt_process_msg1 time is: {:?}", end_abt_process_msg1);

    let start_abt_process_msg2 = std::time::Instant::now();
    let (state_cb_r2, shares_cb, auth_triples_cb, msg3) =
        abt_process_msg2(&state_cb_r1, &ot_seeds_cb, &msg2, &mut rng).unwrap(); // cb

    // let serialized_state_cb_r2 = bincode::serialize(&state_cb_r2).unwrap();
    // let serialized_shares_cb = bincode::serialize(&shares_cb).unwrap();
    // let serialized_auth_triples_cb = bincode::serialize(&auth_triples_cb).unwrap();
    // let serialized_msg3 = bincode::serialize(&msg3).unwrap();


    // println!("\n\nSerialized state_cb_r2 size: {} bytes", serialized_state_cb_r2.len());
    // println!("Serialized shares_cb size: {} bytes", serialized_shares_cb.len());
    // println!("Serialized auth_triples_cb size: {} bytes", serialized_auth_triples_cb.len());
    // println!("Serialized msg3 size: {} bytes", serialized_msg3.len());


    let end_abt_process_msg2 = start_abt_create_msg1.elapsed() - end_abt_process_msg1 - end_abt_create_msg1;
    println!("abt_process_msg2 time is: {:?}", end_abt_process_msg2);


    let start_abt_process_msg3 = std::time::Instant::now();
    let (state_ob_r2, msg4) =
        abt_process_msg3(&state_ob_r1, &mut shares_ob, &mut auth_triples_ob, &msg3).unwrap();

    // let serialized_state_ob_r2 = bincode::serialize(&state_ob_r2).unwrap();
    // let serialized_msg4 = bincode::serialize(&msg4).unwrap();
    // let serialized_shares_ob = bincode::serialize(&shares_ob).unwrap();
    // let serialized_auth_triples_ob = bincode::serialize(&auth_triples_ob).unwrap();



    // println!("\n\nSerialized state_ob_r2 size: {} bytes", serialized_state_ob_r2.len());
    // println!("Serialized msg4 size: {} bytes", serialized_msg4.len());
    // println!("Updated Shared Ob size: {} bytes", serialized_shares_ob.len());
    // println!("Updated Auth Triples Ob size : {} bytes", serialized_auth_triples_ob.len());


    let end_abt_process_msg3 = start_abt_create_msg1.elapsed() - end_abt_process_msg2 - end_abt_process_msg1 - end_abt_create_msg1;
    println!("abt_process_msg3 time is: {:?}", end_abt_process_msg3);


    let start_abt_process_msg4 = std::time::Instant::now();
    let msg5 = abt_process_msg4(&state_cb_r2, &auth_triples_cb, &msg4).unwrap();

    // let serialized_msg5 = bincode::serialize(&msg5).unwrap();

    // println!("Serialized msg5 size: {} bytes", serialized_msg5.len());


    let end_abt_process_msg4 = start_abt_create_msg1.elapsed() - end_abt_process_msg3 - end_abt_process_msg2 - end_abt_process_msg1 - end_abt_create_msg1;
    println!("abt_process_msg4 time is: {:?}", end_abt_process_msg4);

    let start_abt_process_msg5 = std::time::Instant::now();
    abt_process_msg5(&state_ob_r2, &msg5).unwrap();
    let end_abt_process_msg5 = start_abt_create_msg1.elapsed() - end_abt_process_msg4 - end_abt_process_msg3 - end_abt_process_msg2 - end_abt_process_msg1 - end_abt_create_msg1;
    println!("abt_process_msg5 time is: {:?}", end_abt_process_msg5);


    println!(
        "Create Auth Beaver Triples time: {:?}",
        start_auth_triples.elapsed()
    );


    let start_cfm = std::time::Instant::now();

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
    let concatenated_hex = big_y_bytes
    .iter()
    .flat_map(|hash| hash.iter().map(|b| format!("{:02x}", b)))
    .collect::<String>();
    // println!("CUSTOMER LIST HASH IS {:#?}", concatenated_hex);
    // println!("Time to hash List of companies is {:?}", start_cfm.elapsed());
    // println!("THE CUSTOMER HASH BYTES SZIE IS {:#?}", big_y_bytes.len());

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
    let hex_string = customer_y_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    // println!("CUSTOMER  HASH IS {:#?}",hex_string);

    // proposed transaction amount
    let big_x = U64::from_u32(100);

    let start_cfm_step = std::time::Instant::now();
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

    // let serialized_cfm_state_ob_r1 = bincode::serialize(&cfm_state_ob_r1).unwrap();
    // let serialized_msg1 = bincode::serialize(&msg1).unwrap();

    // println!("CFM STATE OB R1 size {:#?}", serialized_cfm_state_ob_r1.len());
    // println!("SERIALIZED MSG1 CFM {:#?}", serialized_msg1.len());


    // println!("CFM Step 1 time: {:?}", start_cfm_step.elapsed());


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

    // let serialized_cfm_state_cb_r1 = bincode::serialize(&cfm_state_cb_r1).unwrap();
    // let serialized_msg2 = bincode::serialize(&msg2).unwrap();

    // println!("CFM STATE CB R1 size {:#?}", serialized_cfm_state_cb_r1.len());
    // println!("SERIALIZED MSG2 CFM {:#?}", serialized_msg2.len());

    // println!("CFM Step 2 time: {:?}", start_cfm_step.elapsed());



    // OB processes msg2
    let (cfm_state_ob_r2, msg3) = cfm_process_msg2(
        &cfm_state_ob_r1,
        &shares_ob,
        &auth_triples_ob,
        &msg2,
        &mut rng,
    )
    .unwrap();

    // let serialized_cfm_state_ob_r2 = bincode::serialize(&cfm_state_ob_r2).unwrap();
    // let serialized_msg3 = bincode::serialize(&msg3).unwrap();

    // println!("CFM STATE OB R2 size {:#?}", serialized_cfm_state_ob_r2.len());
    // println!("SERIALIZED MSG3 CFM {:#?}", serialized_msg3.len());

    // println!("CFM Step 3 time: {:?}", start_cfm_step.elapsed());


    // CB processes msg3
    let (cfm_state_cb_r2, msg4) =
        cfm_process_msg3(cfm_state_cb_r1, &shares_cb, &auth_triples_cb, &msg3).unwrap();


    // let serialized_cfm_state_cb_r2 = bincode::serialize(&cfm_state_cb_r2).unwrap();
    // let serialized_msg4 = bincode::serialize(&msg4).unwrap();

    // println!("CFM STATE CB R2 size {:#?}", serialized_cfm_state_cb_r2.len());
    // println!("SERIALIZED MSG4 CFM {:#?}", serialized_msg4.len());
    

    println!("CFM Step 4 time: {:?}", start_cfm_step.elapsed());


    // OB processes msg4
    let (cfm_state_ob_r3, msg5) = cfm_process_msg4(cfm_state_ob_r2, &msg4).unwrap();
    
    // let serialized_cfm_state_ob_r3 = bincode::serialize(&cfm_state_ob_r3).unwrap();
    // let serialized_msg5 = bincode::serialize(&msg5).unwrap();

    // println!("CFM STATE OB R3 size {:#?}", serialized_cfm_state_ob_r3.len());
    // println!("SERIALIZED MSG5 CFM {:#?}", serialized_msg5.len());
    
    println!("CFM Step 5 time: {:?}", start_cfm_step.elapsed());

    // CB processes msg5
    let (cfm_state_cb_r3, msg6) =
        cfm_process_msg5(cfm_state_cb_r2, &auth_triples_cb, &msg5).unwrap();


    // let serialized_cfm_state_cb_r3 = bincode::serialize(&cfm_state_cb_r3).unwrap();
    // let serialized_msg6 = bincode::serialize(&msg6).unwrap();

    // println!("CFM STATE CB R3 size {:#?}", serialized_cfm_state_cb_r3.len());
    // println!("SERIALIZED MSG6 CFM {:#?}", serialized_msg6.len());

    println!("CFM Step 6 time: {:?}", start_cfm_step.elapsed());

    // OB processes msg6
    let (cfm_state_ob_r4, msg7) =
        cfm_process_msg6(cfm_state_ob_r3, &auth_triples_ob, &msg6).unwrap();

    // let serialized_cfm_state_ob_r4 = bincode::serialize(&cfm_state_ob_r4).unwrap();
    // let serialized_msg7 = bincode::serialize(&msg7).unwrap();

    // println!("CFM STATE OB R4 size {:#?}", serialized_cfm_state_ob_r4.len());
    // println!("SERIALIZED MSG7 CFM {:#?}", serialized_msg7.len());

    println!("CFM Step 7 time: {:?}", start_cfm_step.elapsed());

    // CB processes msg7
    let (cfm_state_cb_r4, msg8) =
        cfm_process_msg7(cfm_state_cb_r3, &auth_triples_cb, &msg7).unwrap();

    // let serialized_cfm_state_cb_r4 = bincode::serialize(&cfm_state_cb_r4).unwrap();
    // let serialized_msg8 = bincode::serialize(&msg8).unwrap();

    // println!("CFM STATE CB R4 size {:#?}", serialized_cfm_state_cb_r4.len());
    // println!("SERIALIZED MSG8 CFM {:#?}", serialized_msg8.len());


    println!("CFM Step 8 time: {:?}", start_cfm_step.elapsed());

    // OB processes msg8
    let (cfm_state_ob_r5, msg9) =
        cfm_process_msg8(cfm_state_ob_r4, &auth_triples_ob, &msg8).unwrap();

    // let serialized_cfm_state_ob_r5 = bincode::serialize(&cfm_state_ob_r5).unwrap();
    // let serialized_msg9 = bincode::serialize(&msg9).unwrap();

    // println!("CFM STATE OB R5 size {:#?}", serialized_cfm_state_ob_r5.len());
    // println!("SERIALIZED MSG9 CFM {:#?}", serialized_msg9.len());

    println!("CFM Step 9 time: {:?}", start_cfm_step.elapsed());

    // CB processes msg9
    let (cfm_state_cb_r5, msg10) =
        cfm_process_msg9(cfm_state_cb_r4, &auth_triples_cb, &msg9).unwrap();

    // let serialized_cfm_state_cb_r5 = bincode::serialize(&cfm_state_cb_r5).unwrap();
    // let serialized_msg10 = bincode::serialize(&msg10).unwrap();

    // println!("CFM STATE CB R5 size {:#?}", serialized_cfm_state_cb_r5.len());
    // println!("SERIALIZED MSG10 CFM {:#?}", serialized_msg10.len());



    println!("CFM Step 10 time: {:?}", start_cfm_step.elapsed());

    // OB processes msg10
    let (cfm_state_ob_r6, msg11) =
        cfm_process_msg10(cfm_state_ob_r5, &auth_triples_ob, &msg10).unwrap();

    // let serialized_cfm_state_ob_r6 = bincode::serialize(&cfm_state_ob_r6).unwrap();
    // let serialized_msg11 = bincode::serialize(&msg11).unwrap();

    // println!("CFM STATE OB R6 size {:#?}", serialized_cfm_state_ob_r6.len());
    // println!("SERIALIZED MSG11 CFM {:#?}", serialized_msg11.len());


    println!("CFM Step 11 time: {:?}", start_cfm_step.elapsed());

    // CB processes msg11
    let (cfm_state_cb_r6, msg12) =
        cfm_process_msg11(cfm_state_cb_r5, &auth_triples_cb, &msg11).unwrap();

    // let serialized_cfm_state_cb_r6 = bincode::serialize(&cfm_state_cb_r6).unwrap();
    // let serialized_msg12 = bincode::serialize(&msg12).unwrap();

    // println!("CFM STATE CB R6 size {:#?}", serialized_cfm_state_cb_r6.len());
    // println!("SERIALIZED MSG12 CFM {:#?}", serialized_msg12.len());

    println!("CFM Step 12 time: {:?}", start_cfm_step.elapsed());

    // OB processes msg12
    let (cfm_state_ob_r7, msg13) =
        cfm_process_msg12(cfm_state_ob_r6, &auth_triples_ob, &msg12).unwrap();

    // let serialized_cfm_state_ob_r7 = bincode::serialize(&cfm_state_ob_r7).unwrap();
    // let serialized_msg13 = bincode::serialize(&msg13).unwrap();

    // println!("CFM STATE OB R7 size {:#?}", serialized_cfm_state_ob_r7.len());
    // println!("SERIALIZED MSG13 CFM {:#?}", serialized_msg13.len());

    println!("CFM Step 13 time: {:?}", start_cfm_step.elapsed());

    // CB processes msg13
    let (cfm_state_cb_r7, msg14) =
        cfm_process_msg13(cfm_state_cb_r6, &auth_triples_cb, &msg13).unwrap();

    // let serialized_cfm_state_cb_r7 = bincode::serialize(&cfm_state_cb_r7).unwrap();
    // let serialized_msg14 = bincode::serialize(&msg14).unwrap();

    // println!("CFM STATE CB R7 size {:#?}", serialized_cfm_state_cb_r7.len());
    // println!("SERIALIZED MSG14 CFM {:#?}", serialized_msg14.len());


    println!("CFM Step 14 time: {:?}", start_cfm_step.elapsed());

    // OB processes msg14
    let (cfm_state_ob_r8, msg15) = cfm_process_msg14(cfm_state_ob_r7, &msg14).unwrap();

    // let serialized_cfm_state_ob_r8 = bincode::serialize(&cfm_state_ob_r8).unwrap();
    // let serialized_msg15 = bincode::serialize(&msg15).unwrap();

    // println!("CFM STATE OB R8 size {:#?}", serialized_cfm_state_ob_r8.len());
    // println!("SERIALIZED MSG15 CFM {:#?}", serialized_msg15.len());

    println!("CFM Step 15 time: {:?}", start_cfm_step.elapsed());

    // CB processes msg15
    let (cfm_state_cb_r8, msg16) = cfm_process_msg15(cfm_state_cb_r7, &msg15).unwrap();

    // let serialized_cfm_state_cb_r8 = bincode::serialize(&cfm_state_cb_r8).unwrap();
    // let serialized_msg16 = bincode::serialize(&msg16).unwrap();

    // println!("CFM STATE CB R8 size {:#?}", serialized_cfm_state_cb_r8.len());
    // println!("SERIALIZED MSG16 CFM {:#?}", serialized_msg16.len());

    println!("CFM Step 16 time: {:?}", start_cfm_step.elapsed());

    // OB processes msg16
    let (cfm_state_ob_r9, msg17) = cfm_process_msg16(cfm_state_ob_r8, &msg16).unwrap();

    // let serialized_cfm_state_ob_r9 = bincode::serialize(&cfm_state_ob_r9).unwrap();
    // let serialized_msg17 = bincode::serialize(&msg17).unwrap();

    // println!("CFM STATE OB R9 size {:#?}", serialized_cfm_state_ob_r9.len());
    // println!("SERIALIZED MSG17 CFM {:#?}", serialized_msg17.len());

    println!("CFM Step 17 time: {:?}", start_cfm_step.elapsed());

    // CB processes msg17
    let (b_cb_value, msg18) = cfm_process_msg17(cfm_state_cb_r8, &msg17).unwrap();

    // let serialized_b_cb_value = bincode::serialize(&b_cb_value).unwrap();
    // let serialized_msg18 = bincode::serialize(&msg18).unwrap();

    // println!("Serialized B CB Value size {:#?}", serialized_b_cb_value.len());
    // println!("SERIALIZED MSG18 CFM {:#?}", serialized_msg18.len());


    println!("CFM Step 18 time: {:?}", start_cfm_step.elapsed());

    // OB processes msg18
    let b_ob_value = cfm_process_msg18(cfm_state_ob_r9, &msg18).unwrap();

    // let serialized_b_ob_value = bincode::serialize(&b_ob_value).unwrap();

    // println!("Serialized B CB Value size {:#?}", serialized_b_ob_value.len());

    println!("CFM Step 19 time: {:?}", start_cfm_step.elapsed());

    assert_eq!(b_cb_value, b_ob_value);

    // X = 100, Z_Y = 3, L = 104
    // (X + Z_Y) < L

    println!("THE RESULT IS {:#?}", b_cb_value);

    assert_eq!(b_cb_value, true);
}

// fn main(){}