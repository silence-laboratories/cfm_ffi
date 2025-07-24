import ctypes
from ctypes import c_void_p, c_char_p
import os

lib_path = os.path.join(os.getcwd(), "cfm_lib/target/release/libcfm_lib.so")
# Load the compiled Rust shared library
rust_lib = ctypes.CDLL(lib_path)  # Adjust path if needed

# Define function return and argument types
rust_lib.create_rng.restype = c_void_p
rust_lib.generate_init_session_id.argtypes = [c_void_p]
rust_lib.generate_init_session_id.restype = c_void_p
rust_lib.create_msg.argtypes = [c_char_p]
rust_lib.create_msg.restype = c_void_p
rust_lib.get_state_ob.argtypes = [c_void_p, c_void_p, c_void_p]
rust_lib.get_state_ob.restype = c_void_p
rust_lib.get_state_cb.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
rust_lib.get_state_cb.restype = c_void_p
rust_lib.get_ot_seed_ob.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
rust_lib.get_ot_seed_ob.restype = c_void_p
rust_lib.get_ot_seed_cb.argtypes = [c_void_p, c_void_p]
rust_lib.get_ot_seed_cb.restype = c_void_p

# Define a struct to hold two void* pointers
class AbtMsg1Result(ctypes.Structure):
    _fields_ = [
        ("state_cb_r1", ctypes.c_void_p), 
        ("msg1", ctypes.c_void_p)
        ]

rust_lib.ffi_abt_create_msg1.argtypes = [c_void_p, c_void_p, c_void_p]
rust_lib.ffi_abt_create_msg1.restype = AbtMsg1Result

class AbtProcessMsg1Result(ctypes.Structure):
    _fields_ = [
        ("state_ob_r1", ctypes.c_void_p),
        ("shares_ob", ctypes.c_void_p),
        ("auth_triples_ob", ctypes.c_void_p),
        ("msg2", ctypes.c_void_p)
    ]
rust_lib.ffi_abt_process_msg1.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
rust_lib.ffi_abt_process_msg1.restype = AbtProcessMsg1Result


class AbtProcessMsg2Result(ctypes.Structure):
    _fields_ = [
        ("state_cb_r2", ctypes.c_void_p),
        ("shares_cb", ctypes.c_void_p),
        ("auth_triples_cb", ctypes.c_void_p),
        ("msg3", ctypes.c_void_p)
    ]
rust_lib.ffi_abt_process_msg2.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
rust_lib.ffi_abt_process_msg2.restype = AbtProcessMsg2Result


class AbtProcessMsg3Result(ctypes.Structure):
    _fields_ = [
        ("state_ob_r2", ctypes.c_void_p),
        ("msg4", ctypes.c_void_p)
    ]
rust_lib.ffi_abt_process_msg3.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
rust_lib.ffi_abt_process_msg3.restype = AbtProcessMsg3Result

# Step 1: Create RNG
rng = rust_lib.create_rng()

# Step 2: Generate init_session_id
init_session_id = rust_lib.generate_init_session_id(rng)
print(f"Init Session ID Pointer: {init_session_id}")

# Step 3: Create msg1
msg1 = rust_lib.create_msg(ctypes.c_char_p(b"msg1"))
print(f"Message 1 Pointer: {msg1}")

# Step 4: Create state_ob
state_ob = rust_lib.get_state_ob(init_session_id, msg1, rng)
print(f"State OB Pointer: {state_ob}")

# Step 5: Create msg2
msg2 = rust_lib.create_msg(ctypes.c_char_p(b"msg2"))
print(f"Message 2 Pointer: {msg2}")

# Step 6: Create state_cb
state_cb = rust_lib.get_state_cb(init_session_id, msg1, msg2, rng)
print(f"State CB Pointer: {state_cb}")

# Step 7: Create msg3
msg3 = rust_lib.create_msg(ctypes.c_char_p(b"msg3"))
print(f"Message 3 Pointer: {msg3}")

# Step 8: Create ot_seeds_ob
ot_seeds_ob = rust_lib.get_ot_seed_ob(state_ob, msg2, msg3, rng)
print(f"OT Seeds OB Pointer: {ot_seeds_ob}")

# Step 9: Create ot_seeds_cb
ot_seeds_cb = rust_lib.get_ot_seed_cb(state_cb, msg3)
print(f"OT Seeds CB Pointer: {ot_seeds_cb}")

# Ensure proper memory management (if required, implement Rust-side free functions)

new_session_id = rust_lib.generate_init_session_id(rng)

print(new_session_id)


# Call Rust function
abt_create_msg1_result = rust_lib.ffi_abt_create_msg1(
    new_session_id,  
    ot_seeds_cb,  # Previously obtained ot_seeds_cb pointer
    rng
)

# Print pointers to confirm successful allocation
print(f"State CB R1 Pointer: {abt_create_msg1_result.state_cb_r1}")
print(f"Message 1 Pointer: {abt_create_msg1_result.msg1}")

msg1 = abt_create_msg1_result.msg1

abt_process_msg1_result = rust_lib.ffi_abt_process_msg1(
    new_session_id, 
    ot_seeds_ob,
    msg1,
    rng
)

# Print pointers to confirm successful allocation
print(f"State OB R1 Pointer: {abt_process_msg1_result.state_ob_r1}")
print(f"Shares_ob Pointer: {abt_process_msg1_result.shares_ob}")
print(f"Auth Triples OB Pointer: {abt_process_msg1_result.auth_triples_ob}")
print(f"Message 2 Pointer: {abt_process_msg1_result.msg2}")

abt_process_msg2_result = rust_lib.ffi_abt_process_msg2(
    abt_create_msg1_result.state_cb_r1,
    ot_seeds_cb,
    abt_process_msg1_result.msg2,
    rng
)

# Print pointers to confirm successful allocation
print(f"State CB R2 Pointer: {abt_process_msg2_result.state_cb_r2}")
print(f"Shares_CB Pointer: {abt_process_msg2_result.shares_cb}")
print(f"Auth Triples CB Pointer: {abt_process_msg2_result.auth_triples_cb}")
print(f"Message 3 Pointer: {abt_process_msg2_result.msg3}")


abt_process_msg3_result = rust_lib.ffi_abt_process_msg3(
    abt_process_msg1_result.state_ob_r1,
    abt_process_msg1_result.shares_ob,
    abt_process_msg1_result.auth_triples_ob,
    abt_process_msg2_result.msg3
)

print(f"State OB R2 Pointer: {abt_process_msg2_result.state_ob_r2}")
print(f"Message 4 Pointer: {abt_process_msg2_result.msg4}")



'''
    # 1️⃣ Hashing a Single Customer
    customer = {
        "name": "Customer3",
        "passport_number": "P3456789",
        "address": "789 Maple St"
    }

    hash_single = hash_customers(customer, False)
    print(f"Single Customer Hash (Binary): {hash_single.hex()}")

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
    print(f"List of Customers Hash (Binary): {hash_list[8:].hex()}")



'''