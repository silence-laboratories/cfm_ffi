from cfm_ffi import *
import time
import zlib

### **Test the Flow**
if __name__ == "__main__":
    start_time = time.time()
    print("Start Time is", start_time)
    rng = create_rng()
    # print("RNG IS", rng)

    session_id = generate_init_session_id(rng)
    # print(f"Session ID (serialized) size: {len(session_id)}")

    msg1_serialized = create_msg("msg1")
    print(f"Msg1 (serialized) size: {len(msg1_serialized)}", " ---------- ", len(zlib.compress(msg1_serialized)))

    state_ob_serialized, updated_msg1_serialized = ffi_cfm_init_create_msg1(session_id, msg1_serialized, rng)
    print(f"State Object (serialized) size: {len(state_ob_serialized)}",  " ---------- ", len(zlib.compress(state_ob_serialized)))

    msg2_serialized = create_msg("msg2")
    print(f"Msg2 (serialized) size: {len(msg2_serialized)}",  " ---------- ", len(zlib.compress(msg2_serialized)))

    state_cb_serialized, updated_msg2_serialized = ffi_cfm_init_process_msg1(session_id, updated_msg1_serialized, msg2_serialized, rng)
    print(f"State CB  (serialized) size: {len(state_cb_serialized)}",  " ---------- ", len(zlib.compress(state_cb_serialized)))


    msg3_serialized = create_msg("msg3")
    print(f"Msg3 (serialized) size: {len(msg3_serialized)}",  " ---------- ", len(zlib.compress(msg3_serialized)))

    ot_seeds_ob_serialized, updated_msg3_serialized = ffi_cfm_init_process_msg2(state_ob_serialized, updated_msg2_serialized, msg3_serialized, rng)
    print(f"OT Seeds OB  (serialized) size: {len(ot_seeds_ob_serialized)}",  " ---------- ", len(zlib.compress(ot_seeds_ob_serialized)))

    ot_seeds_cb_serialized = ffi_cfm_init_process_msg3(state_cb_serialized, updated_msg3_serialized)
    print(f"OT SEEDS CB (serialized) size: {len(ot_seeds_cb_serialized)}",  " ---------- ", len(zlib.compress(ot_seeds_cb_serialized)))

    session_id_new = generate_init_session_id(rng)
    state_cb_r1_serialized, abt_msg1_serialized = ffi_abt_create_msg1(session_id_new, ot_seeds_cb_serialized, rng)
    print(f"STATE CB R1 (serialized) size: {len(state_cb_r1_serialized)}",  " ---------- ", len(zlib.compress(state_cb_r1_serialized)))
    print(f"ABT MSG1 (serialized) size: {len(abt_msg1_serialized)}",  " ---------- ", len(zlib.compress(abt_msg1_serialized)))


    state_ob_r1_serialized, shares_ob_serialized, auth_triples_ob_serialized, abt_msg2_serialized = ffi_abt_process_msg1(
    session_id_new, ot_seeds_ob_serialized, abt_msg1_serialized, rng
        )
    
    print(f"State OB R1 size: {len(state_ob_r1_serialized)} bytes",  " ---------- ", len(zlib.compress(state_ob_r1_serialized)))
    print(f"Shares OB size: {len(shares_ob_serialized)} bytes",  " ---------- ", len(zlib.compress(shares_ob_serialized)))
    print(f"Auth Triples OB size: {len(auth_triples_ob_serialized)} bytes",  " ---------- ", len(zlib.compress(auth_triples_ob_serialized)))
    print(f"ABT MSG2 size: {len(abt_msg2_serialized)} bytes",  " ---------- ", len(zlib.compress(abt_msg2_serialized)))


    state_cb_r2, shares_cb, auth_triples_cb, abt_msg3_serialized = ffi_abt_process_msg2(
        state_cb_r1_serialized, ot_seeds_cb_serialized, abt_msg2_serialized, rng
    )

    print(f"State CB R2 size: {len(state_cb_r2)} bytes",  " ---------- ", len(zlib.compress(state_cb_r2)))
    print(f"Shares CB size: {len(shares_cb)} bytes",  " ---------- ", len(zlib.compress(shares_cb)))
    print(f"Auth Triples CB size: {len(auth_triples_cb)} bytes",  " ---------- ", len(zlib.compress(auth_triples_cb)))
    print(f"ABT MSG3 size: {len(abt_msg3_serialized)} bytes",  " ---------- ", len(zlib.compress(abt_msg3_serialized)))


    state_ob_r2_serialized, abt_msg4_serialized, updated_shares_ob_serialized, updated_auth_triples_ob_serialized = ffi_abt_process_msg3(
        state_ob_r1_serialized, shares_ob_serialized, auth_triples_ob_serialized, abt_msg3_serialized)
    

    print(f"State OB R2 size: {len(state_ob_r2_serialized)} bytes",  " ---------- ", len(zlib.compress(state_ob_r2_serialized)))
    print(f"ABT MSG4 size: {len(abt_msg4_serialized)} bytes",  " ---------- ", len(zlib.compress(abt_msg4_serialized)))


    abt_msg5_serialized = ffi_abt_process_msg4(state_cb_r2, auth_triples_cb, abt_msg4_serialized)

    print(f"ABT MSG5 size: {len(abt_msg5_serialized)} bytes",  " ---------- ", len(zlib.compress(abt_msg5_serialized)))

    ffi_abt_process_msg5(state_ob_r2_serialized, abt_msg5_serialized)

    print(len(shares_ob_serialized),  " ---------- ", len(zlib.compress(shares_ob_serialized)))
    print(len(updated_shares_ob_serialized),  " ---------- ", len(zlib.compress(updated_shares_ob_serialized)))

    # print(len(auth_triples_ob_serialized))
    # print(len(updated_auth_triples_ob_serialized))

    # print(len(shares_ob_serialized), " ---", len(updated_shares_ob_serialized))
    # print(len(auth_triples_ob_serialized), "----", len(updated_auth_triples_ob_serialized))
    # print( shares_ob_serialized == updated_shares_ob_serialized)
    # print( auth_triples_ob_serialized == updated_auth_triples_ob_serialized)

    # print(f"Shares CB size: {len(shares_cb)} bytes")
    # print(f"Auth Triples CB size: {len(auth_triples_cb)} bytes")

    print("lllllllllll----",time.time())

#    1️⃣ Hashing a Single Customer
    customer = {
        "name": "Customer3",
        "passport_number": "P3456789",
        "address": "789 Maple St"
    }

    hash_single = hash_customers(customer, False)
    # print(f"Single Customer Hash (Binary): {hash_single.hex()}")


    # 2️⃣ Hashing a List of Customers
    customers = [
        {"name": "Customer1", "passport_number": "P1234567", "address": "123 Main St"},
        {"name": "Customer2", "passport_number": "P2345678", "address": "456 Church St"},
        {"name": "Customer3", "passport_number": "P3456789", "address": "789 Maple St"},
        {"name": "Customer4", "passport_number": "P4567890", "address": "101 Oak St"},
        {"name": "Customer5", "passport_number": "P5678901", "address": "111 Pine St"},
        {"name": "Customer6", "passport_number": "P6789012", "address": "121 Cedar St"},
        {"name": "Customer7", "passport_number": "P7890123", "address": "314 Birch St"},
        {"name": "Customer8", "passport_number": "P8901234", "address": "151 Walnut St"},
        {"name": "Customer9", "passport_number": "P9012345", "address": "617 Chestnut St"},
        {"name": "Customer10", "passport_number": "P0123456", "address": "181 Spruce St"}
    ]

    hash_list = hash_customers(customers, True)
    # print(f"List of Customers Hash (Binary): {hash_list[8:].hex()}")
    # print("CUSTOMER HASH LIST SIZE IS", len(hash_list[8:]))

    big_l = 199
    big_x = 100

    cfm_state_ob_r1_serialized, cfm_msg1_serialized = ffi_cfm_create_msg1(
        session_id_new, big_l, big_x, 
        hash_single,
        shares_ob_serialized,
        rng
    )

    print(f"CMF STATE OB R1 size: {len(cfm_state_ob_r1_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r1_serialized)))
    print(f"CFM MSG1 size: {len(cfm_msg1_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg1_serialized)))

    big_z = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    cfm_state_cb_r1_serialized, cfm_msg2_serialized = ffi_cfm_process_msg1(
        session_id_new, big_l, hash_list,
        big_z, shares_cb, cfm_msg1_serialized, rng
    )

    print(f"CMF STATE CB R1 size: {len(cfm_state_cb_r1_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_cb_r1_serialized)))
    print(f"CFM MSG2 size: {len(cfm_msg2_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg2_serialized)))


    cfm_state_ob_r2_serialized, cfm_msg3_serialized = ffi_cfm_process_msg2(
        cfm_state_ob_r1_serialized, updated_shares_ob_serialized,
        updated_auth_triples_ob_serialized, cfm_msg2_serialized,
        rng
    )

    print(f"CFM STATE OB R2 size: {len(cfm_state_ob_r2_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r2_serialized)))
    print(f"CFM MSG3 size: {len(cfm_msg3_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg3_serialized)))


    cfm_state_cb_r2_serialized, cfm_msg4_serialized = ffi_cfm_process_msg3(
        cfm_state_cb_r1_serialized, shares_cb, auth_triples_cb, cfm_msg3_serialized
    )

    print(f"CFM STATE CB R2 size: {len(cfm_state_cb_r2_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_cb_r2_serialized)))
    print(f"CFM MSG4 size: {len(cfm_msg4_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg4_serialized)))


    cfm_state_ob_r3_serialized, cfm_msg5_serialized = ffi_cfm_process_msg4(
        cfm_state_ob_r2_serialized, cfm_msg4_serialized
    )

    print(f"CFM STATE OB R3 size: {len(cfm_state_ob_r3_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r3_serialized)))
    print(f"CFM MSG5 size: {len(cfm_msg5_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg5_serialized)))


    cfm_state_cb_r3_serialized, cfm_msg6_serialized = ffi_cfm_process_msg5(
        cfm_state_cb_r2_serialized, auth_triples_cb, cfm_msg5_serialized
    )

    print(f"CFM STATE CB R3 size: {len(cfm_state_cb_r3_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_cb_r3_serialized)))
    print(f"CFM MSG6 size: {len(cfm_msg6_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg6_serialized)))


    cfm_state_ob_r4_serialized, cfm_msg7_serialized = ffi_cfm_process_msg6(
        cfm_state_ob_r3_serialized, updated_auth_triples_ob_serialized,
        cfm_msg6_serialized
    )

    print(f"CFM STATE OB R4 size: {len(cfm_state_ob_r4_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r4_serialized)))
    print(f"CFM MSG7 size: {len(cfm_msg7_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg7_serialized)))

    cfm_state_cb_r4_serialized, cfm_msg8_serialized = ffi_cfm_process_msg7(
        cfm_state_cb_r3_serialized, auth_triples_cb, cfm_msg7_serialized
    )

    print(f"CFM STATE CB R4 size: {len(cfm_state_cb_r4_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_cb_r4_serialized)))
    print(f"CFM MSG8 size: {len(cfm_msg8_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg8_serialized))) 


    cfm_state_ob_r5_serialized, cfm_msg9_serialized = ffi_cfm_process_msg8(
        cfm_state_ob_r4_serialized, updated_auth_triples_ob_serialized, 
        cfm_msg8_serialized
    )

    print(f"CFM STATE OB R5 size: {len(cfm_state_ob_r5_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r5_serialized)))
    print(f"CFM MSG9 size: {len(cfm_msg9_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg9_serialized))) 

    cfm_state_cb_r5_serialized, cfm_msg10_serialized = ffi_cfm_process_msg9(
        cfm_state_cb_r4_serialized, auth_triples_cb, cfm_msg9_serialized
    )

    print(f"CFM STATE CB R5 size: {len(cfm_state_cb_r5_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_cb_r5_serialized)))
    print(f"CFM MSG10 size: {len(cfm_msg10_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg10_serialized))) 


    cfm_state_ob_r6_serialized, cfm_msg11_serialized = ffi_cfm_process_msg10(
        cfm_state_ob_r5_serialized, updated_auth_triples_ob_serialized,
        cfm_msg10_serialized
    )

    print(f"CFM STATE OB R6 size: {len(cfm_state_ob_r6_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r6_serialized)))
    print(f"CFM MSG11 size: {len(cfm_msg11_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg11_serialized))) 


    cfm_state_cb_r6_serialized, cfm_msg12_serialized = ffi_cfm_process_msg11(
        cfm_state_cb_r5_serialized, auth_triples_cb, cfm_msg11_serialized
    )

    print(f"CFM STATE CB R6 size: {len(cfm_state_cb_r6_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_cb_r6_serialized)))
    print(f"CFM MSG12 size: {len(cfm_msg12_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg12_serialized))) 


    cfm_state_ob_r7_serialized, cfm_msg13_serialized = ffi_cfm_process_msg12(
        cfm_state_ob_r6_serialized, updated_auth_triples_ob_serialized, cfm_msg12_serialized
    )

    print(f"CFM STATE OB R7 size: {len(cfm_state_ob_r7_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r7_serialized)))
    print(f"CFM MSG13 size: {len(cfm_msg13_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg13_serialized))) 


    cfm_state_cb_r7_serialized, cfm_msg14_serialized = ffi_cfm_process_msg13(
        cfm_state_cb_r6_serialized, auth_triples_cb, cfm_msg13_serialized
    )

    print(f"CFM STATE CB R7 size: {len(cfm_state_cb_r7_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_cb_r7_serialized)))
    print(f"CFM MSG14 size: {len(cfm_msg14_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg14_serialized))) 

    cfm_state_ob_r8_serialized, cfm_msg15_serialized = ffi_cfm_process_msg14(
        cfm_state_ob_r7_serialized, cfm_msg14_serialized
    )

    print(f"CFM STATE OB R8 size: {len(cfm_state_ob_r8_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r8_serialized)))
    print(f"CFM MSG15 size: {len(cfm_msg15_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg15_serialized))) 


    cfm_state_cb_r8_serialized, cfm_msg16_serialized = ffi_cfm_process_msg15(
        cfm_state_cb_r7_serialized, cfm_msg15_serialized
    )

    print(f"CFM STATE CB R8 size: {len(cfm_state_cb_r8_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_cb_r8_serialized)))
    print(f"CFM MSG16 size: {len(cfm_msg16_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg16_serialized))) 

    cfm_state_ob_r9_serialized, cfm_msg17_serialized = ffi_cfm_process_msg16(
        cfm_state_ob_r8_serialized, cfm_msg16_serialized
    )

    print(f"CFM STATE OB R9 size: {len(cfm_state_ob_r9_serialized)}",  " ---------- ", len(zlib.compress(cfm_state_ob_r9_serialized)))
    print(f"CFM MSG17 size: {len(cfm_msg17_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg17_serialized))) 

    b_cb_value_serialized, cfm_msg18_serialized = ffi_cfm_process_msg17(
        cfm_state_cb_r8_serialized, cfm_msg17_serialized
    )

    print(f"B _CB VALUE SERIALIZED size: {len(b_cb_value_serialized)}", b_cb_value_serialized,  " ---------- ", len(zlib.compress(b_cb_value_serialized)))
    print(f"CFM MSG18 size: {len(cfm_msg18_serialized)}",  " ---------- ", len(zlib.compress(cfm_msg18_serialized))) 


    b_ob_value_serialized = ffi_cfm_process_msg18(
        cfm_state_ob_r9_serialized, cfm_msg18_serialized
    )

    # print(f"B _OB VALUE SERIALIZED size: {len(b_ob_value_serialized)}", b_ob_value_serialized)


    print("Process completed successfully!")
    end_time = time.time()
    print("End Time is", end_time)




# from cfm_ffi import *
# import time
# import zlib

# if __name__ == "__main__":
#     start_time = time.time()
#     print("Start Time is", start_time)

#     # Create a secure RNG | OB
#     rng = create_rng()

#     # Generate a shared session ID | OB
#     session_id = generate_init_session_id(rng)

#     # Create Msg1 | OB
#     msg1_serialized = create_msg("msg1")

#     # OB creates and sends CFMInitMsg1 → CB
#     state_ob_serialized, updated_msg1_serialized = ffi_cfm_init_create_msg1(session_id, msg1_serialized, rng)

#     # Create Msg2 | CB
#     msg2_serialized = create_msg("msg2")
#     rng2 = create_rng()

#     # CB processes CFMInitMsg1 from OB → sends back Msg2
#     state_cb_serialized, updated_msg2_serialized = ffi_cfm_init_process_msg1(session_id, updated_msg1_serialized, msg2_serialized, rng2)

#     # Create Msg3 | OB
#     msg3_serialized = create_msg("msg3")

#     # OB processes CFMInitMsg2 from CB → sends Msg3
#     ot_seeds_ob_serialized, updated_msg3_serialized = ffi_cfm_init_process_msg2(state_ob_serialized, updated_msg2_serialized, msg3_serialized, rng)

#     # CB processes CFMInitMsg3 from OB
#     ot_seeds_cb_serialized = ffi_cfm_init_process_msg3(state_cb_serialized, updated_msg3_serialized)

#     # Generate new session ID for authenticated triples | CB
#     session_id_new = generate_init_session_id(rng2)

#     # CB creates and sends ABTMsg1 → OB
#     state_cb_r1_serialized, abt_msg1_serialized = ffi_abt_create_msg1(session_id_new, ot_seeds_cb_serialized, rng2)

#     # OB processes ABTMsg1 from CB → sends ABTMsg2
#     state_ob_r1_serialized, shares_ob_serialized, auth_triples_ob_serialized, abt_msg2_serialized = ffi_abt_process_msg1(session_id_new, ot_seeds_ob_serialized, abt_msg1_serialized, rng)

#     # CB processes ABTMsg2 from OB → sends ABTMsg3
#     state_cb_r2, shares_cb, auth_triples_cb, abt_msg3_serialized = ffi_abt_process_msg2(state_cb_r1_serialized, ot_seeds_cb_serialized, abt_msg2_serialized, rng2)

#     # OB processes ABTMsg3 → sends ABTMsg4
#     state_ob_r2_serialized, abt_msg4_serialized, updated_shares_ob_serialized, updated_auth_triples_ob_serialized = ffi_abt_process_msg3(state_ob_r1_serialized, shares_ob_serialized, auth_triples_ob_serialized, abt_msg3_serialized)

#     # CB processes ABTMsg4 → sends ABTMsg5
#     abt_msg5_serialized = ffi_abt_process_msg4(state_cb_r2, auth_triples_cb, abt_msg4_serialized)

#     # OB processes ABTMsg5 → finalizes triple setup
#     ffi_abt_process_msg5(state_ob_r2_serialized, abt_msg5_serialized)

#     # Hash one customer (lookup query) | OB
#     customer = {
#         "name": "Customer3",
#         "passport_number": "P3456789",
#         "address": "789 Maple St"
#     }
#     hash_single = hash_customers(customer, False)

#     # Hash list of customers (sanctioned database) | CB
#     customers = [
#         {"name": "Customer1", "passport_number": "P1234567", "address": "123 Main St"},
#         {"name": "Customer2", "passport_number": "P2345678", "address": "456 Church St"},
#         {"name": "Customer3", "passport_number": "P3456789", "address": "789 Maple St"},
#         {"name": "Customer4", "passport_number": "P4567890", "address": "101 Oak St"},
#         {"name": "Customer5", "passport_number": "P5678901", "address": "111 Pine St"},
#         {"name": "Customer6", "passport_number": "P6789012", "address": "121 Cedar St"},
#         {"name": "Customer7", "passport_number": "P7890123", "address": "314 Birch St"},
#         {"name": "Customer8", "passport_number": "P8901234", "address": "151 Walnut St"},
#         {"name": "Customer9", "passport_number": "P9012345", "address": "617 Chestnut St"},
#         {"name": "Customer10", "passport_number": "P0123456", "address": "181 Spruce St"}
#     ]
#     hash_list = hash_customers(customers, True)

#     # Public parameter: CB-imposed limit | OB
#     big_l = 199
#     big_x = 100  # OB's proposed transfer

#     # OB creates and sends CFMMsg1 → CB
#     cfm_state_ob_r1_serialized, cfm_msg1_serialized = ffi_cfm_create_msg1(session_id_new, big_l, big_x, hash_single, shares_ob_serialized, rng)

#     # Private capital flow history | CB
#     big_z = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

#     # CB processes CFMMsg1 → sends CFMMsg2
#     cfm_state_cb_r1_serialized, cfm_msg2_serialized = ffi_cfm_process_msg1(session_id_new, big_l, hash_list, big_z, shares_cb, cfm_msg1_serialized, rng2)

#     # OB processes CFMMsg2 → sends CFMMsg3
#     cfm_state_ob_r2_serialized, cfm_msg3_serialized = ffi_cfm_process_msg2(cfm_state_ob_r1_serialized, updated_shares_ob_serialized, updated_auth_triples_ob_serialized, cfm_msg2_serialized, rng)

#     # CB processes CFMMsg3 → sends CFMMsg4
#     cfm_state_cb_r2_serialized, cfm_msg4_serialized = ffi_cfm_process_msg3(cfm_state_cb_r1_serialized, shares_cb, auth_triples_cb, cfm_msg3_serialized)

#     # OB → CB → OB → CB ... Continue secure circuit round trip
#     cfm_state_ob_r3_serialized, cfm_msg5_serialized = ffi_cfm_process_msg4(cfm_state_ob_r2_serialized, cfm_msg4_serialized)
#     cfm_state_cb_r3_serialized, cfm_msg6_serialized = ffi_cfm_process_msg5(cfm_state_cb_r2_serialized, auth_triples_cb, cfm_msg5_serialized)
#     cfm_state_ob_r4_serialized, cfm_msg7_serialized = ffi_cfm_process_msg6(cfm_state_ob_r3_serialized, updated_auth_triples_ob_serialized, cfm_msg6_serialized)
#     cfm_state_cb_r4_serialized, cfm_msg8_serialized = ffi_cfm_process_msg7(cfm_state_cb_r3_serialized, auth_triples_cb, cfm_msg7_serialized)
#     cfm_state_ob_r5_serialized, cfm_msg9_serialized = ffi_cfm_process_msg8(cfm_state_ob_r4_serialized, updated_auth_triples_ob_serialized, cfm_msg8_serialized)
#     cfm_state_cb_r5_serialized, cfm_msg10_serialized = ffi_cfm_process_msg9(cfm_state_cb_r4_serialized, auth_triples_cb, cfm_msg9_serialized)
#     cfm_state_ob_r6_serialized, cfm_msg11_serialized = ffi_cfm_process_msg10(cfm_state_ob_r5_serialized, updated_auth_triples_ob_serialized, cfm_msg10_serialized)
#     cfm_state_cb_r6_serialized, cfm_msg12_serialized = ffi_cfm_process_msg11(cfm_state_cb_r5_serialized, auth_triples_cb, cfm_msg11_serialized)
#     cfm_state_ob_r7_serialized, cfm_msg13_serialized = ffi_cfm_process_msg12(cfm_state_ob_r6_serialized, updated_auth_triples_ob_serialized, cfm_msg12_serialized)
#     cfm_state_cb_r7_serialized, cfm_msg14_serialized = ffi_cfm_process_msg13(cfm_state_cb_r6_serialized, auth_triples_cb, cfm_msg13_serialized)
#     cfm_state_ob_r8_serialized, cfm_msg15_serialized = ffi_cfm_process_msg14(cfm_state_ob_r7_serialized, cfm_msg14_serialized)
#     cfm_state_cb_r8_serialized, cfm_msg16_serialized = ffi_cfm_process_msg15(cfm_state_cb_r7_serialized, cfm_msg15_serialized)
#     cfm_state_ob_r9_serialized, cfm_msg17_serialized = ffi_cfm_process_msg16(cfm_state_ob_r8_serialized, cfm_msg16_serialized)

#     # CB evaluates result share → sends final Msg18
#     b_cb_value_serialized, cfm_msg18_serialized = ffi_cfm_process_msg17(cfm_state_cb_r8_serialized, cfm_msg17_serialized)

#     # OB completes circuit → obtains result
#     b_ob_value_serialized = ffi_cfm_process_msg18(cfm_state_ob_r9_serialized, cfm_msg18_serialized)

#     # Final evaluation — both parties compare their bits (mocked here via CB output)
#     if b_cb_value_serialized == b'\x01':
#         print("✅ Transaction is within the capital flow limit.")
#     else:
#         print("❌ Transaction exceeds the capital flow limit.")

#     print("End Time is", time.time())



# -------------------------------------------------

# from cfm_ffi import *
# import time
# import zlib


# def size_info(label, blob):
#     original = len(blob)
#     compressed = len(zlib.compress(blob))
#     print(f"{label:<40} | Raw: {original:>6} bytes | Compressed: {compressed:>6} bytes")
#     return original, compressed


# if __name__ == "__main__":
#     print("Starting Capital Flow Management (CFM) Protocol...")
#     rng_ob = create_rng()
#     rng_cb = create_rng()

#     # OB: Generate Session ID
#     session_id = generate_init_session_id(rng_ob)
#     size_info("Session ID", session_id)

#     # OB: Create initial msg1
#     msg1 = create_msg("msg1")
#     size_info("Msg1 (OB to CB)", msg1)

#     state_ob, updated_msg1 = ffi_cfm_init_create_msg1(session_id, msg1, rng_ob)
#     size_info("State OB (local) after Msg1", state_ob)
#     size_info("Updated Msg1 (sent)", updated_msg1)

#     # CB: Create msg2 and process msg1
#     msg2 = create_msg("msg2")
#     size_info("Msg2 (CB local)", msg2)

#     state_cb, updated_msg2 = ffi_cfm_init_process_msg1(session_id, updated_msg1, msg2, rng_cb)
#     size_info("State CB (local) after Msg2", state_cb)
#     size_info("Updated Msg2 (sent)", updated_msg2)

#     # OB: Create msg3 and process msg2
#     msg3 = create_msg("msg3")
#     size_info("Msg3 (OB local)", msg3)

#     ot_seeds_ob, updated_msg3 = ffi_cfm_init_process_msg2(state_ob, updated_msg2, msg3, rng_ob)
#     size_info("OT Seeds OB (shared)", ot_seeds_ob)
#     size_info("Updated Msg3 (sent)", updated_msg3)

#     # CB: process msg3 to generate OT seeds
#     ot_seeds_cb = ffi_cfm_init_process_msg3(state_cb, updated_msg3)
#     size_info("OT Seeds CB (shared)", ot_seeds_cb)

#     # CB: Begin ABT
#     session_id2 = generate_init_session_id(rng_cb)
#     state_cb_r1, abt_msg1 = ffi_abt_create_msg1(session_id2, ot_seeds_cb, rng_cb)
#     size_info("ABT Msg1 (CB to OB)", abt_msg1)

#     state_ob_r1, shares_ob, triples_ob, abt_msg2 = ffi_abt_process_msg1(session_id2, ot_seeds_ob, abt_msg1, rng_ob)
#     size_info("ABT Msg2 (OB to CB)", abt_msg2)
#     size_info("Shares OB", shares_ob)
#     size_info("Auth Triples OB", triples_ob)

#     state_cb_r2, shares_cb, triples_cb, abt_msg3 = ffi_abt_process_msg2(state_cb_r1, ot_seeds_cb, abt_msg2, rng_cb)
#     size_info("ABT Msg3 (CB to OB)", abt_msg3)
#     size_info("Shares CB", shares_cb)
#     size_info("Auth Triples CB", triples_cb)

#     state_ob_r2, abt_msg4, shares_ob_upd, triples_ob_upd = ffi_abt_process_msg3(state_ob_r1, shares_ob, triples_ob, abt_msg3)
#     size_info("ABT Msg4 (OB to CB)", abt_msg4)

#     abt_msg5 = ffi_abt_process_msg4(state_cb_r2, triples_cb, abt_msg4)
#     size_info("ABT Msg5 (CB to OB)", abt_msg5)

#     ffi_abt_process_msg5(state_ob_r2, abt_msg5)

#     print("\n✅ Initial ABT exchange complete.")

#     # Hash single customer | OB
#     customer = {"name": "CustomerX", "passport_number": "PX123456", "address": "Street 123"}
#     hash_y = hash_customers(customer, False)
#     size_info("Customer Y Hash (OB)", hash_y)

#     # Hash sanction list | CB
#     customer_list = [customer for _ in range(10)]  # list of 10 repeated customers
#     hash_list = hash_customers(customer_list, True)
#     size_info("Customer List Hash (CB)", hash_list)

#     big_l, big_x = 104, 100

#     cfm_state_ob_r1, cfm_msg1 = ffi_cfm_create_msg1(session_id2, big_l, big_x, hash_y, shares_ob, rng_ob)
#     size_info("CFM Msg1 (OB to CB)", cfm_msg1)

#     big_z = list(range(1, 11))
#     cfm_state_cb_r1, cfm_msg2 = ffi_cfm_process_msg1(session_id2, big_l, hash_list, big_z, shares_cb, cfm_msg1, rng_cb)
#     size_info("CFM Msg2 (CB to OB)", cfm_msg2)

#     cfm_state_ob_r2, cfm_msg3 = ffi_cfm_process_msg2(cfm_state_ob_r1, shares_ob_upd, triples_ob_upd, cfm_msg2, rng_ob)
#     size_info("CFM Msg3 (OB to CB)", cfm_msg3)

#     cfm_state_cb_r2, cfm_msg4 = ffi_cfm_process_msg3(cfm_state_cb_r1, shares_cb, triples_cb, cfm_msg3)
#     size_info("CFM Msg4 (CB to OB)", cfm_msg4)

#     cfm_state_ob_r3, cfm_msg5 = ffi_cfm_process_msg4(cfm_state_ob_r2, cfm_msg4)
#     size_info("CFM Msg5 (OB to CB)", cfm_msg5)

#     cfm_state_cb_r3, cfm_msg6 = ffi_cfm_process_msg5(cfm_state_cb_r2, triples_cb, cfm_msg5)
#     size_info("CFM Msg6 (CB to OB)", cfm_msg6)

#     cfm_state_ob_r4, cfm_msg7 = ffi_cfm_process_msg6(cfm_state_ob_r3, triples_ob_upd, cfm_msg6)
#     size_info("CFM Msg7 (OB to CB)", cfm_msg7)

#     cfm_state_cb_r4, cfm_msg8 = ffi_cfm_process_msg7(cfm_state_cb_r3, triples_cb, cfm_msg7)
#     size_info("CFM Msg8 (CB to OB)", cfm_msg8)

#     cfm_state_ob_r5, cfm_msg9 = ffi_cfm_process_msg8(cfm_state_ob_r4, triples_ob_upd, cfm_msg8)
#     size_info("CFM Msg9 (OB to CB)", cfm_msg9)

#     cfm_state_cb_r5, cfm_msg10 = ffi_cfm_process_msg9(cfm_state_cb_r4, triples_cb, cfm_msg9)
#     size_info("CFM Msg10 (CB to OB)", cfm_msg10)

#     cfm_state_ob_r6, cfm_msg11 = ffi_cfm_process_msg10(cfm_state_ob_r5, triples_ob_upd, cfm_msg10)
#     size_info("CFM Msg11 (OB to CB)", cfm_msg11)

#     cfm_state_cb_r6, cfm_msg12 = ffi_cfm_process_msg11(cfm_state_cb_r5, triples_cb, cfm_msg11)
#     size_info("CFM Msg12 (CB to OB)", cfm_msg12)

#     cfm_state_ob_r7, cfm_msg13 = ffi_cfm_process_msg12(cfm_state_ob_r6, triples_ob_upd, cfm_msg12)
#     size_info("CFM Msg13 (OB to CB)", cfm_msg13)

#     cfm_state_cb_r7, cfm_msg14 = ffi_cfm_process_msg13(cfm_state_cb_r6, triples_cb, cfm_msg13)
#     size_info("CFM Msg14 (CB to OB)", cfm_msg14)

#     cfm_state_ob_r8, cfm_msg15 = ffi_cfm_process_msg14(cfm_state_ob_r7, cfm_msg14)
#     size_info("CFM Msg15 (OB to CB)", cfm_msg15)

#     cfm_state_cb_r8, cfm_msg16 = ffi_cfm_process_msg15(cfm_state_cb_r7, cfm_msg15)
#     size_info("CFM Msg16 (CB to OB)", cfm_msg16)

#     cfm_state_ob_r9, cfm_msg17 = ffi_cfm_process_msg16(cfm_state_ob_r8, cfm_msg16)
#     size_info("CFM Msg17 (OB to CB)", cfm_msg17)

#     b_cb, cfm_msg18 = ffi_cfm_process_msg17(cfm_state_cb_r8, cfm_msg17)
#     size_info("CFM Msg18 (CB to OB)", cfm_msg18)

#     b_ob = ffi_cfm_process_msg18(cfm_state_ob_r9, cfm_msg18)
#     size_info("Final Verdict (OB output)", b_ob)

#     print("\n✅ CFM Protocol complete.")
