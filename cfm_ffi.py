import ctypes
import os
import json
import gc

# Load the Rust shared library
lib_path = os.path.join(os.getcwd(), "cfm_lib/target/release/libcfm_lib.so")
rust_lib = ctypes.CDLL(lib_path)

# Define function signatures for Rust FFI calls
rust_lib.create_rng.argtypes = []
rust_lib.create_rng.restype = ctypes.c_void_p  # Returns an opaque pointer to RngHolder

rust_lib.free_rng.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
rust_lib.free_rng.restype = None

rust_lib.generate_init_session_id.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
rust_lib.generate_init_session_id.restype = ctypes.POINTER(ctypes.c_ubyte)

rust_lib.create_msg.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
rust_lib.create_msg.restype = ctypes.POINTER(ctypes.c_ubyte)

rust_lib.ffi_cfm_init_create_msg1.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # Session ID (serialized)
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # Msg1 (serialized)
    ctypes.c_void_p,  # RNG pointer
    ctypes.POINTER(ctypes.c_size_t)  # Output state size
]
rust_lib.ffi_cfm_init_create_msg1.restype = ctypes.POINTER(ctypes.c_ubyte)

rust_lib.ffi_cfm_init_process_msg1.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # Session ID (serialized)
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # Msg1 (serialized)
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # Msg2 (serialized)
    ctypes.c_void_p,  # RNG pointer
    ctypes.POINTER(ctypes.c_size_t)  # Output state size
]
rust_lib.ffi_cfm_init_process_msg1.restype = ctypes.POINTER(ctypes.c_ubyte)


rust_lib.ffi_cfm_init_process_msg2.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # state_ob (serialized)
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg2 (serialized)
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg3 (mutable, serialized)
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)  # RNG pointer, output size
]

# Define return type for ffi_cfm_init_process_msg2
rust_lib.ffi_cfm_init_process_msg2.restype = ctypes.POINTER(ctypes.c_ubyte)


# Define argument types for ffi_cfm_init_process_msg3
rust_lib.ffi_cfm_init_process_msg3.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # state_cb (serialized)
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg3 (serialized)
    ctypes.POINTER(ctypes.c_size_t)                   # Output ot_seeds_cb size
]

# Define return type for ffi_cfm_init_process_msg3
rust_lib.ffi_cfm_init_process_msg3.restype = ctypes.POINTER(ctypes.c_ubyte)


class FFI_AbtCreateMsg1Result(ctypes.Structure):
    _fields_ = [
        ("state_cb_r1_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("state_cb_r1_size", ctypes.c_size_t),
        ("msg1_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg1_size", ctypes.c_size_t),
    ]

rust_lib.ffi_abt_create_msg1.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # session_id
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # ot_seeds_cb
    ctypes.c_void_p,  # rng_ptr
]
rust_lib.ffi_abt_create_msg1.restype = FFI_AbtCreateMsg1Result


class FFI_AbtProcessMsg1Result(ctypes.Structure):
    _fields_ = [
        ("state_ob_r1_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("state_ob_r1_size", ctypes.c_size_t),
        ("shares_ob_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("shares_ob_size", ctypes.c_size_t),
        ("auth_triples_ob_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("auth_triples_ob_size", ctypes.c_size_t),
        ("msg2_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg2_size", ctypes.c_size_t),
    ]

rust_lib.ffi_abt_process_msg1.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # session_id
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # ot_seeds_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg1
    ctypes.c_void_p,  # rng_ptr
]
rust_lib.ffi_abt_process_msg1.restype = FFI_AbtProcessMsg1Result


# Define the FFI result structure
class FFI_AbtProcessMsg2Result(ctypes.Structure):
    _fields_ = [
        ("state_cb_r2_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("state_cb_r2_size", ctypes.c_size_t),
        ("shares_cb_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("shares_cb_size", ctypes.c_size_t),
        ("auth_triples_cb_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("auth_triples_cb_size", ctypes.c_size_t),
        ("msg3_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg3_size", ctypes.c_size_t),
    ]

# Define function signatures for Rust FFI
rust_lib.ffi_abt_process_msg2.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # state_cb_r1
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # ot_seeds_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg2
    ctypes.c_void_p  # RNG pointer
]
rust_lib.ffi_abt_process_msg2.restype = FFI_AbtProcessMsg2Result


class FFI_AbtProcessMsg3Result(ctypes.Structure):
    _fields_ = [
        ("state_ob_r2_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("state_ob_r2_size", ctypes.c_size_t),
        ("shares_ob_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("shares_ob_size", ctypes.c_size_t),
        ("auth_triples_ob_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("auth_triples_ob_size", ctypes.c_size_t),
        ("msg4_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg4_size", ctypes.c_size_t),
    ]

rust_lib.ffi_abt_process_msg3.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # state_ob_r1
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # shares_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg3
]
rust_lib.ffi_abt_process_msg3.restype = FFI_AbtProcessMsg3Result


class FFI_AbtProcessMsg4Result(ctypes.Structure):
    _fields_ = [
        ("msg5_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg5_size", ctypes.c_size_t),
    ]

# Define Rust function signature
rust_lib.ffi_abt_process_msg4.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # state_cb_r2
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg4
]
rust_lib.ffi_abt_process_msg4.restype = FFI_AbtProcessMsg4Result


# Define Rust function signature
rust_lib.ffi_abt_process_msg5.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # state_ob_r2
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg5
]
rust_lib.ffi_abt_process_msg5.restype = None  # No return value


# Define function signatures
rust_lib.ffi_hash_customers.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.POINTER(ctypes.c_size_t)]
rust_lib.ffi_hash_customers.restype = ctypes.POINTER(ctypes.c_ubyte)


class FFI_CfmCreateMsg1Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r1_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r1_size", ctypes.c_size_t),
        ("msg1_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg1_size", ctypes.c_size_t),
    ]

# Define function argument types for the Rust function
rust_lib.ffi_cfm_create_msg1.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # session_id
    ctypes.c_uint64, ctypes.c_uint64,  # big_l, big_x
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # customer_y_bytes
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # shares_ob (mutable)
    ctypes.c_void_p,  # rng_ptr
]

# Define return type for ffi_cfm_create_msg1
rust_lib.ffi_cfm_create_msg1.restype = FFI_CfmCreateMsg1Result


class FFI_CfmProcessMsg1Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_cb_r1_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_cb_r1_size", ctypes.c_size_t),
        ("msg2_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg2_size", ctypes.c_size_t),
    ]

rust_lib.ffi_cfm_process_msg1.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # session_id
    ctypes.c_uint64,  # big_l
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # big_y_bytes
    ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,  # big_z
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # shares_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg1
    ctypes.c_void_p,  # rng_ptr
]
rust_lib.ffi_cfm_process_msg1.restype = FFI_CfmProcessMsg1Result


class FFI_CfmProcessMsg2Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r2_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r2_size", ctypes.c_size_t),
        ("msg3_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg3_size", ctypes.c_size_t),
    ]

# Define function signature for `ffi_cfm_process_msg2`
rust_lib.ffi_cfm_process_msg2.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r1
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # shares_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg2
    ctypes.c_void_p  # RNG pointer
]
rust_lib.ffi_cfm_process_msg2.restype = FFI_CfmProcessMsg2Result  # Struct return type


class FFI_CfmProcessMsg3Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_cb_r2_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_cb_r2_size", ctypes.c_size_t),
        ("msg4_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg4_size", ctypes.c_size_t),
    ]

rust_lib.ffi_cfm_process_msg3.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_cb_r1
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # shares_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg3
]

rust_lib.ffi_cfm_process_msg3.restype = FFI_CfmProcessMsg3Result


class FFI_CfmProcessMsg4Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r3_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r3_size", ctypes.c_size_t),
        ("msg5_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg5_size", ctypes.c_size_t),
    ]

rust_lib.ffi_cfm_process_msg4.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r2
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg4
]

rust_lib.ffi_cfm_process_msg4.restype = FFI_CfmProcessMsg4Result


class FFI_CfmProcessMsg5Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_cb_r3_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_cb_r3_size", ctypes.c_size_t),
        ("msg6_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg6_size", ctypes.c_size_t),
    ]

rust_lib.ffi_cfm_process_msg5.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_cb_r2
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg5
]

rust_lib.ffi_cfm_process_msg5.restype = FFI_CfmProcessMsg5Result


class FFI_CfmProcessMsg6Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r4_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r4_size", ctypes.c_size_t),
        ("msg7_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg7_size", ctypes.c_size_t),
    ]

# Define Rust function signature
rust_lib.ffi_cfm_process_msg6.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r3
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg6
]
rust_lib.ffi_cfm_process_msg6.restype = FFI_CfmProcessMsg6Result


class FFI_CfmProcessMsg7Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_cb_r4_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_cb_r4_size", ctypes.c_size_t),
        ("msg8_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg8_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg7
rust_lib.ffi_cfm_process_msg7.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_cb_r3
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg7
]
rust_lib.ffi_cfm_process_msg7.restype = FFI_CfmProcessMsg7Result


class FFI_CfmProcessMsg8Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r5_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r5_size", ctypes.c_size_t),
        ("msg9_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg9_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg8
rust_lib.ffi_cfm_process_msg8.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r4
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg8
]
rust_lib.ffi_cfm_process_msg8.restype = FFI_CfmProcessMsg8Result


class FFI_CfmProcessMsg9Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_cb_r5_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_cb_r5_size", ctypes.c_size_t),
        ("msg10_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg10_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg9
rust_lib.ffi_cfm_process_msg9.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_cb_r4
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg9
]
rust_lib.ffi_cfm_process_msg9.restype = FFI_CfmProcessMsg9Result


class FFI_CfmProcessMsg10Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r6_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r6_size", ctypes.c_size_t),
        ("msg11_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg11_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg10
rust_lib.ffi_cfm_process_msg10.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r5
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg10
]
rust_lib.ffi_cfm_process_msg10.restype = FFI_CfmProcessMsg10Result


class FFI_CfmProcessMsg11Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_cb_r6_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_cb_r6_size", ctypes.c_size_t),
        ("msg12_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg12_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg11
rust_lib.ffi_cfm_process_msg11.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_cb_r5
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg11
]
rust_lib.ffi_cfm_process_msg11.restype = FFI_CfmProcessMsg11Result

class FFI_CfmProcessMsg12Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r7_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r7_size", ctypes.c_size_t),
        ("msg13_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg13_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg12
rust_lib.ffi_cfm_process_msg12.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r6
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_ob
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg12
]
rust_lib.ffi_cfm_process_msg12.restype = FFI_CfmProcessMsg12Result


class FFI_CfmProcessMsg13Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_cb_r7_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_cb_r7_size", ctypes.c_size_t),
        ("msg14_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg14_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg13
rust_lib.ffi_cfm_process_msg13.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_cb_r6
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # auth_triples_cb
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg13
]
rust_lib.ffi_cfm_process_msg13.restype = FFI_CfmProcessMsg13Result


class FFI_CfmProcessMsg14Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r8_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r8_size", ctypes.c_size_t),
        ("msg15_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg15_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg14
rust_lib.ffi_cfm_process_msg14.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r7
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg14
]
rust_lib.ffi_cfm_process_msg14.restype = FFI_CfmProcessMsg14Result


class FFI_CfmProcessMsg15Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_cb_r8_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_cb_r8_size", ctypes.c_size_t),
        ("msg16_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg16_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg15
rust_lib.ffi_cfm_process_msg15.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_cb_r7
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg15
]
rust_lib.ffi_cfm_process_msg15.restype = FFI_CfmProcessMsg15Result

class FFI_CfmProcessMsg16Result(ctypes.Structure):
    _fields_ = [
        ("cfm_state_ob_r9_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("cfm_state_ob_r9_size", ctypes.c_size_t),
        ("msg17_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg17_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg16
rust_lib.ffi_cfm_process_msg16.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r8
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg16
]
rust_lib.ffi_cfm_process_msg16.restype = FFI_CfmProcessMsg16Result


class FFI_CfmProcessMsg17Result(ctypes.Structure):
    _fields_ = [
        ("b_cb_value_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("b_cb_value_size", ctypes.c_size_t),
        ("msg18_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("msg18_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg17
rust_lib.ffi_cfm_process_msg17.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_cb_r8
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg17
]
rust_lib.ffi_cfm_process_msg17.restype = FFI_CfmProcessMsg17Result


class FFI_CfmProcessMsg18Result(ctypes.Structure):
    _fields_ = [
        ("b_ob_value_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("b_ob_value_size", ctypes.c_size_t),
    ]

# Define the function signature for ffi_cfm_process_msg18
rust_lib.ffi_cfm_process_msg18.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # cfm_state_ob_r9
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,  # msg18
]
rust_lib.ffi_cfm_process_msg18.restype = FFI_CfmProcessMsg18Result


rust_lib.free_buffer.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
rust_lib.free_buffer.restype = None


### **Step 1: Create RNG**
def create_rng():
    """Creates an RNG instance in Rust."""
    rng_ptr = rust_lib.create_rng()
    print(rng_ptr)
    if not rng_ptr:
        raise ValueError("Failed to create RNG in Rust.")
    return rng_ptr

def free_rng(rng_ptr):
    if rng_ptr:
        rust_lib.free_rng(rng_ptr)

### **Step 2: Generate a Session ID**
def generate_init_session_id(rng_ptr):
    """Generates a serialized session ID using Rust."""
    size_var = ctypes.c_size_t()

    session_id_ptr = rust_lib.generate_init_session_id(rng_ptr, ctypes.byref(size_var))

    if not session_id_ptr:
        raise ValueError("Failed to generate session ID in Rust.")

    size = size_var.value
    serialized_session_id = ctypes.string_at(session_id_ptr, size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(session_id_ptr, size)

    return serialized_session_id


### **Step 3: Create Msg1**
def create_msg(msg_type: str):
    print("Enter ", msg_type)
    """Creates a serialized Msg1 using Rust."""
    msg_type = msg_type.encode("utf-8")
    size_var = ctypes.c_size_t()
    msg1_ptr = rust_lib.create_msg(ctypes.c_char_p(msg_type), ctypes.byref(size_var))

    if not msg1_ptr:
        raise ValueError("Failed to create Msg1 in Rust.")

    size = size_var.value
    serialized_msg1 = ctypes.string_at(msg1_ptr, size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(msg1_ptr, size)

    return serialized_msg1


### **Step 4: Call `ffi_cfm_init_create_msg1`**
def ffi_cfm_init_create_msg1(session_id, msg1_serialized, rng_ptr):
    """Calls the Rust function to process session_id and msg1, and returns serialized state_ob and updated msg1."""
    if not session_id or not msg1_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_cfm_init_create_msg1.")

    # Convert Python bytes to ctypes-compatible format
    session_id_array = (ctypes.c_ubyte * len(session_id))(*session_id)

    # Allocate msg1 buffer as mutable memory
    msg1_buffer = (ctypes.c_ubyte * len(msg1_serialized))(*msg1_serialized)

    # Get pointers to the arrays
    session_id_ptr = ctypes.cast(session_id_array, ctypes.POINTER(ctypes.c_ubyte))
    msg1_ptr = ctypes.cast(msg1_buffer, ctypes.POINTER(ctypes.c_ubyte))  # Mutable buffer

    state_size = ctypes.c_size_t()

    # Call Rust FFI function
    state_ptr = rust_lib.ffi_cfm_init_create_msg1(
        session_id_ptr, len(session_id),
        msg1_ptr, len(msg1_serialized),  # Mutable msg1
        rng_ptr, ctypes.byref(state_size)
    )

    if not state_ptr:
        raise ValueError("Failed to generate state_ob in Rust.")

    # Read serialized state_ob
    state_ob_serialized = ctypes.string_at(state_ptr, state_size.value)

    # Read updated msg1 from the same memory buffer
    updated_msg1_serialized = bytes(msg1_buffer)

    # Free allocated memory in Rust
    rust_lib.free_buffer(state_ptr, state_size.value)

    return state_ob_serialized, updated_msg1_serialized  # ✅ Returning both state_ob and updated msg1


def ffi_cfm_init_process_msg1(session_id, msg1_serialized, msg2_serialized, rng_ptr):
    """Calls the Rust function to process session_id, msg1, msg2, and RNG, and returns serialized state_cb."""
    if not session_id or not msg1_serialized or not msg2_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_cfm_init_process_msg1.")

    # Convert Python bytes to ctypes-compatible format
    session_id_array = (ctypes.c_ubyte * len(session_id))(*session_id)
    msg1_array = (ctypes.c_ubyte * len(msg1_serialized))(*msg1_serialized)
    msg2_array = (ctypes.c_ubyte * len(msg2_serialized))(*msg2_serialized)

    # Get pointers to the arrays
    session_id_ptr = ctypes.cast(session_id_array, ctypes.POINTER(ctypes.c_ubyte))
    msg1_ptr = ctypes.cast(msg1_array, ctypes.POINTER(ctypes.c_ubyte))
    msg2_ptr = ctypes.cast(msg2_array, ctypes.POINTER(ctypes.c_ubyte))

    state_size = ctypes.c_size_t()

    # Call Rust function
    state_ptr = rust_lib.ffi_cfm_init_process_msg1(
        session_id_ptr, len(session_id),
        msg1_ptr, len(msg1_serialized),
        msg2_ptr, len(msg2_serialized),
        rng_ptr, ctypes.byref(state_size)
    )

    if not state_ptr:
        raise ValueError("Failed to generate state_cb in Rust.")

    # Read serialized state_cb
    state_cb_serialized = ctypes.string_at(state_ptr, state_size.value)

    # Read back the updated msg2 from memory
    updated_msg2_serialized = bytes(msg2_array)

    # Free allocated memory in Rust
    rust_lib.free_buffer(state_ptr, state_size.value)

    return state_cb_serialized, updated_msg2_serialized


def ffi_cfm_init_process_msg2(state_ob, msg2_serialized, msg3_serialized, rng_ptr):
    """Calls the Rust function to process state_ob, msg2, msg3, and RNG, and returns serialized ot_seeds_ob."""
    if not state_ob or not msg2_serialized or not msg3_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_cfm_init_process_msg2.")

    # Convert Python bytes to ctypes-compatible format
    state_ob_array = (ctypes.c_ubyte * len(state_ob))(*state_ob)
    msg2_array = (ctypes.c_ubyte * len(msg2_serialized))(*msg2_serialized)
    msg3_array = (ctypes.c_ubyte * len(msg3_serialized))(*msg3_serialized)

    # Get pointers to the arrays
    state_ob_ptr = ctypes.cast(state_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    msg2_ptr = ctypes.cast(msg2_array, ctypes.POINTER(ctypes.c_ubyte))
    msg3_ptr = ctypes.cast(msg3_array, ctypes.POINTER(ctypes.c_ubyte))

    ot_seeds_size = ctypes.c_size_t()

    # Call Rust function
    ot_seeds_ptr = rust_lib.ffi_cfm_init_process_msg2(
        state_ob_ptr, len(state_ob),
        msg2_ptr, len(msg2_serialized),
        msg3_ptr, len(msg3_serialized),
        rng_ptr, ctypes.byref(ot_seeds_size)
    )

    if not ot_seeds_ptr:
        raise ValueError("Failed to generate ot_seeds_ob in Rust.")

    # Read serialized ot_seeds_ob
    ot_seeds_ob_serialized = ctypes.string_at(ot_seeds_ptr, ot_seeds_size.value)

    # Read back the updated msg3 from memory
    updated_msg3_serialized = bytes(msg3_array)

    # Free allocated memory in Rust
    rust_lib.free_buffer(ot_seeds_ptr, ot_seeds_size.value)

    return ot_seeds_ob_serialized, updated_msg3_serialized


def ffi_cfm_init_process_msg3(state_cb, msg3_serialized):
    """Calls the Rust function to process state_cb and msg3, and returns serialized ot_seeds_cb."""
    if not state_cb or not msg3_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_init_process_msg3.")

    # Convert Python bytes to ctypes-compatible format
    state_cb_array = (ctypes.c_ubyte * len(state_cb))(*state_cb)
    msg3_array = (ctypes.c_ubyte * len(msg3_serialized))(*msg3_serialized)

    # Get pointers to the arrays
    state_cb_ptr = ctypes.cast(state_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg3_ptr = ctypes.cast(msg3_array, ctypes.POINTER(ctypes.c_ubyte))

    ot_seeds_size = ctypes.c_size_t()

    ot_seeds_ptr = rust_lib.ffi_cfm_init_process_msg3(
        state_cb_ptr, len(state_cb),
        msg3_ptr, len(msg3_serialized),
        ctypes.byref(ot_seeds_size)
    )

    if not ot_seeds_ptr:
        raise ValueError("Failed to generate ot_seeds_cb in Rust.")

    # Read serialized ot_seeds_cb
    ot_seeds_cb_serialized = ctypes.string_at(ot_seeds_ptr, ot_seeds_size.value)

    # Free allocated memory in Rust
    rust_lib.free_buffer(ot_seeds_ptr, ot_seeds_size.value)

    return ot_seeds_cb_serialized

def ffi_abt_create_msg1(session_id, ot_seeds_cb_serialized, rng_ptr):
    """Calls Rust function and returns serialized state_cb_r1 and msg1."""
    if not session_id or not ot_seeds_cb_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_abt_create_msg1.")

    session_id_array = (ctypes.c_ubyte * len(session_id))(*session_id)
    ot_seeds_cb_array = (ctypes.c_ubyte * len(ot_seeds_cb_serialized))(*ot_seeds_cb_serialized)

    result = rust_lib.ffi_abt_create_msg1(
        session_id_array, len(session_id),
        ot_seeds_cb_array, len(ot_seeds_cb_serialized),
        rng_ptr
    )

    state_cb_r1_serialized = ctypes.string_at(result.state_cb_r1_ptr, result.state_cb_r1_size)
    msg1_serialized = ctypes.string_at(result.msg1_ptr, result.msg1_size)

    rust_lib.free_buffer(result.state_cb_r1_ptr, result.state_cb_r1_size)
    rust_lib.free_buffer(result.msg1_ptr, result.msg1_size)

    return state_cb_r1_serialized, msg1_serialized


def ffi_abt_process_msg1(session_id, ot_seeds_ob, msg1_serialized, rng_ptr):
    """Calls the Rust function to process session_id, ot_seeds_ob, msg1, and RNG, returning multiple outputs."""
    
    if not session_id or not ot_seeds_ob or not msg1_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_abt_process_msg1.")

    # Convert Python bytes to ctypes-compatible format
    session_id_array = (ctypes.c_ubyte * len(session_id))(*session_id)
    ot_seeds_ob_array = (ctypes.c_ubyte * len(ot_seeds_ob))(*ot_seeds_ob)
    msg1_array = (ctypes.c_ubyte * len(msg1_serialized))(*msg1_serialized)

    # Get pointers to the arrays
    session_id_ptr = ctypes.cast(session_id_array, ctypes.POINTER(ctypes.c_ubyte))
    ot_seeds_ob_ptr = ctypes.cast(ot_seeds_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    msg1_ptr = ctypes.cast(msg1_array, ctypes.POINTER(ctypes.c_ubyte))

    # Set the return type for the Rust function
    rust_lib.ffi_abt_process_msg1.restype = FFI_AbtProcessMsg1Result

    # Call the Rust function
    result = rust_lib.ffi_abt_process_msg1(
        session_id_ptr, len(session_id),
        ot_seeds_ob_ptr, len(ot_seeds_ob),
        msg1_ptr, len(msg1_serialized),
        rng_ptr
    )

    if not result.state_ob_r1_ptr or result.state_ob_r1_size == 0:
        raise ValueError("Failed to generate state_ob_r1.")

    # Extract and read serialized data from Rust
    state_ob_r1_serialized = ctypes.string_at(result.state_ob_r1_ptr, result.state_ob_r1_size)
    shares_ob_serialized = ctypes.string_at(result.shares_ob_ptr, result.shares_ob_size)
    auth_triples_ob_serialized = ctypes.string_at(result.auth_triples_ob_ptr, result.auth_triples_ob_size)
    msg2_serialized = ctypes.string_at(result.msg2_ptr, result.msg2_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.state_ob_r1_ptr, result.state_ob_r1_size)
    rust_lib.free_buffer(result.shares_ob_ptr, result.shares_ob_size)
    rust_lib.free_buffer(result.auth_triples_ob_ptr, result.auth_triples_ob_size)
    rust_lib.free_buffer(result.msg2_ptr, result.msg2_size)

    return state_ob_r1_serialized, shares_ob_serialized, auth_triples_ob_serialized, msg2_serialized


def ffi_abt_process_msg2(state_cb_r1, ot_seeds_cb, msg2_serialized, rng_ptr):
    """Calls Rust function and extracts the multiple returned values."""
    
    if not state_cb_r1 or not ot_seeds_cb or not msg2_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_abt_process_msg2.")

    # Convert Python bytes to ctypes-compatible format
    state_cb_r1_array = (ctypes.c_ubyte * len(state_cb_r1))(*state_cb_r1)
    ot_seeds_cb_array = (ctypes.c_ubyte * len(ot_seeds_cb))(*ot_seeds_cb)
    msg2_array = (ctypes.c_ubyte * len(msg2_serialized))(*msg2_serialized)

    # Get pointers
    state_cb_r1_ptr = ctypes.cast(state_cb_r1_array, ctypes.POINTER(ctypes.c_ubyte))
    ot_seeds_cb_ptr = ctypes.cast(ot_seeds_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg2_ptr = ctypes.cast(msg2_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_abt_process_msg2(
        state_cb_r1_ptr, len(state_cb_r1),
        ot_seeds_cb_ptr, len(ot_seeds_cb),
        msg2_ptr, len(msg2_serialized),
        rng_ptr
    )

    if not result.state_cb_r2_ptr:
        raise ValueError("Failed to generate state_cb_r2.")

    # Read serialized results
    state_cb_r2_serialized = ctypes.string_at(result.state_cb_r2_ptr, result.state_cb_r2_size)
    shares_cb_serialized = ctypes.string_at(result.shares_cb_ptr, result.shares_cb_size)
    auth_triples_cb_serialized = ctypes.string_at(result.auth_triples_cb_ptr, result.auth_triples_cb_size)
    msg3_serialized = ctypes.string_at(result.msg3_ptr, result.msg3_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.state_cb_r2_ptr, result.state_cb_r2_size)
    rust_lib.free_buffer(result.shares_cb_ptr, result.shares_cb_size)
    rust_lib.free_buffer(result.auth_triples_cb_ptr, result.auth_triples_cb_size)
    rust_lib.free_buffer(result.msg3_ptr, result.msg3_size)

    return state_cb_r2_serialized, shares_cb_serialized, auth_triples_cb_serialized, msg3_serialized


def ffi_abt_process_msg3(state_ob_r1, shares_ob, auth_triples_ob, msg3_serialized):
    """Calls Rust function and extracts multiple returned values."""
    
    if not state_ob_r1 or not shares_ob or not auth_triples_ob or not msg3_serialized:
        raise ValueError("Invalid inputs to ffi_abt_process_msg3.")

    # Convert Python bytes to ctypes-compatible format
    state_ob_r1_array = (ctypes.c_ubyte * len(state_ob_r1))(*state_ob_r1)
    shares_ob_array = (ctypes.c_ubyte * len(shares_ob))(*shares_ob)
    auth_triples_ob_array = (ctypes.c_ubyte * len(auth_triples_ob))(*auth_triples_ob)
    msg3_array = (ctypes.c_ubyte * len(msg3_serialized))(*msg3_serialized)

    # Get pointers
    state_ob_r1_ptr = ctypes.cast(state_ob_r1_array, ctypes.POINTER(ctypes.c_ubyte))
    shares_ob_ptr = ctypes.cast(shares_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_ob_ptr = ctypes.cast(auth_triples_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    msg3_ptr = ctypes.cast(msg3_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_abt_process_msg3(
        state_ob_r1_ptr, len(state_ob_r1),
        shares_ob_ptr, len(shares_ob),
        auth_triples_ob_ptr, len(auth_triples_ob),
        msg3_ptr, len(msg3_serialized)
    )

    if not result.state_ob_r2_ptr:
        raise ValueError("Failed to process abt_process_msg3 in Rust.")

    # Read serialized outputs
    state_ob_r2_serialized = ctypes.string_at(result.state_ob_r2_ptr, result.state_ob_r2_size)
    msg4_serialized = ctypes.string_at(result.msg4_ptr, result.msg4_size)
    updated_shares_ob_serialized = ctypes.string_at(result.shares_ob_ptr, result.shares_ob_size)
    updated_auth_triples_ob_serialized = ctypes.string_at(result.auth_triples_ob_ptr, result.auth_triples_ob_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.state_ob_r2_ptr, result.state_ob_r2_size)
    rust_lib.free_buffer(result.msg4_ptr, result.msg4_size)
    rust_lib.free_buffer(result.shares_ob_ptr, result.shares_ob_size)
    rust_lib.free_buffer(result.auth_triples_ob_ptr, result.auth_triples_ob_size)

    return state_ob_r2_serialized, msg4_serialized, updated_shares_ob_serialized, updated_auth_triples_ob_serialized

def ffi_abt_process_msg4(state_cb_r2, auth_triples_cb, msg4_serialized):
    """Calls Rust function to process state_cb_r2, auth_triples_cb, and msg4, returning msg5."""
    
    if not state_cb_r2 or not auth_triples_cb or not msg4_serialized:
        raise ValueError("Invalid inputs to ffi_abt_process_msg4.")

    # Convert Python bytes to ctypes-compatible format
    state_cb_r2_array = (ctypes.c_ubyte * len(state_cb_r2))(*state_cb_r2)
    auth_triples_cb_array = (ctypes.c_ubyte * len(auth_triples_cb))(*auth_triples_cb)
    msg4_array = (ctypes.c_ubyte * len(msg4_serialized))(*msg4_serialized)

    # Get pointers
    state_cb_r2_ptr = ctypes.cast(state_cb_r2_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_cb_ptr = ctypes.cast(auth_triples_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg4_ptr = ctypes.cast(msg4_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_abt_process_msg4(
        state_cb_r2_ptr, len(state_cb_r2),
        auth_triples_cb_ptr, len(auth_triples_cb),
        msg4_ptr, len(msg4_serialized)
    )

    if not result.msg5_ptr:
        raise ValueError("Failed to process abt_process_msg4 in Rust.")

    # Read serialized msg5
    msg5_serialized = ctypes.string_at(result.msg5_ptr, result.msg5_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.msg5_ptr, result.msg5_size)

    return msg5_serialized

def ffi_abt_process_msg5(state_ob_r2, msg5_serialized):
    """Calls Rust function to process state_ob_r2 and msg5."""
    
    if not state_ob_r2 or not msg5_serialized:
        raise ValueError("Invalid inputs to ffi_abt_process_msg5.")

    # Convert Python bytes to ctypes-compatible format
    state_ob_r2_array = (ctypes.c_ubyte * len(state_ob_r2))(*state_ob_r2)
    msg5_array = (ctypes.c_ubyte * len(msg5_serialized))(*msg5_serialized)

    # Get pointers
    state_ob_r2_ptr = ctypes.cast(state_ob_r2_array, ctypes.POINTER(ctypes.c_ubyte))
    msg5_ptr = ctypes.cast(msg5_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function (no return value)
    rust_lib.ffi_abt_process_msg5(state_ob_r2_ptr, len(state_ob_r2), msg5_ptr, len(msg5_serialized))


def hash_customers(customers, is_list):
    """Hashes a list of customers or a single customer and returns the binary hash output."""
    
    # Convert input data to JSON string
    customers_json = json.dumps(customers).encode('utf-8')

    # Allocate memory for output size
    out_size = ctypes.c_size_t()

    # Call Rust function
    hash_ptr = rust_lib.ffi_hash_customers(ctypes.c_char_p(customers_json), is_list, ctypes.byref(out_size))

    if not hash_ptr:
        raise ValueError("Failed to hash customer(s) in Rust.")

    # Read the binary hash output
    hashed_data = ctypes.string_at(hash_ptr, out_size.value)

    # Free the allocated memory in Rust
    rust_lib.free_buffer(hash_ptr, out_size.value)

    return hashed_data


def ffi_cfm_create_msg1(session_id, big_l, big_x, customer_y_bytes, shares_ob_serialized, rng_ptr):
    """Calls Rust function to process inputs and returns state_ob_r1 and msg1."""

    if not session_id or not customer_y_bytes or not shares_ob_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_cfm_create_msg1.")

    # Convert Python bytes to ctypes-compatible format
    session_id_array = (ctypes.c_ubyte * len(session_id))(*session_id)
    customer_y_bytes_array = (ctypes.c_ubyte * len(customer_y_bytes))(*customer_y_bytes)
    
    # Allocate shares_ob as a mutable buffer
    shares_ob_array = (ctypes.c_ubyte * len(shares_ob_serialized))(*shares_ob_serialized)

    # Get pointers to the arrays
    session_id_ptr = ctypes.cast(session_id_array, ctypes.POINTER(ctypes.c_ubyte))
    customer_y_bytes_ptr = ctypes.cast(customer_y_bytes_array, ctypes.POINTER(ctypes.c_ubyte))
    shares_ob_ptr = ctypes.cast(shares_ob_array, ctypes.POINTER(ctypes.c_ubyte))  # Mutable buffer

    # Call Rust function
    result = rust_lib.ffi_cfm_create_msg1(
        session_id_ptr, len(session_id),
        big_l, big_x,
        customer_y_bytes_ptr, len(customer_y_bytes),
        shares_ob_ptr, len(shares_ob_serialized),
        rng_ptr
    )

    # Check if we received valid pointers
    if not result.cfm_state_ob_r1_ptr or not result.msg1_ptr:
        raise ValueError("Failed to process ffi_cfm_create_msg1 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r1_serialized = ctypes.string_at(result.cfm_state_ob_r1_ptr, result.cfm_state_ob_r1_size)
    msg1_serialized = ctypes.string_at(result.msg1_ptr, result.msg1_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r1_ptr, result.cfm_state_ob_r1_size)
    rust_lib.free_buffer(result.msg1_ptr, result.msg1_size)

    return cfm_state_ob_r1_serialized, msg1_serialized


def ffi_cfm_process_msg1(session_id, big_l, big_y_bytes, big_z, shares_cb, msg1_serialized, rng_ptr):
    if not session_id or not big_y_bytes or not big_z or not shares_cb or not msg1_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg1.")

    session_id_array = (ctypes.c_ubyte * len(session_id))(*session_id)
    big_y_bytes_array = (ctypes.c_ubyte * len(big_y_bytes))(*big_y_bytes)
    big_z_array = (ctypes.c_uint64 * len(big_z))(*big_z)  # Convert Python list to C uint64 array
    shares_cb_array = (ctypes.c_ubyte * len(shares_cb))(*shares_cb)
    msg1_array = (ctypes.c_ubyte * len(msg1_serialized))(*msg1_serialized)

    result = rust_lib.ffi_cfm_process_msg1(
        session_id_array, len(session_id),
        big_l,
        big_y_bytes_array, len(big_y_bytes),
        big_z_array, len(big_z),
        shares_cb_array, len(shares_cb),
        msg1_array, len(msg1_serialized),
        rng_ptr
    )

    state_cb_r1 = ctypes.string_at(result.cfm_state_cb_r1_ptr, result.cfm_state_cb_r1_size)
    msg2 = ctypes.string_at(result.msg2_ptr, result.msg2_size)

    rust_lib.free_buffer(result.cfm_state_cb_r1_ptr, result.cfm_state_cb_r1_size)
    rust_lib.free_buffer(result.msg2_ptr, result.msg2_size)

    return state_cb_r1, msg2


def ffi_cfm_process_msg2(cfm_state_ob_r1, shares_ob, auth_triples_ob, msg2_serialized, rng_ptr):
    """Calls Rust FFI function `ffi_cfm_process_msg2` and extracts results."""
    
    if not cfm_state_ob_r1 or not shares_ob or not auth_triples_ob or not msg2_serialized or not rng_ptr:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg2.")

    # Convert Python byte arrays to ctypes-compatible format
    cfm_state_ob_r1_array = (ctypes.c_ubyte * len(cfm_state_ob_r1))(*cfm_state_ob_r1)
    shares_ob_array = (ctypes.c_ubyte * len(shares_ob))(*shares_ob)
    auth_triples_ob_array = (ctypes.c_ubyte * len(auth_triples_ob))(*auth_triples_ob)
    msg2_array = (ctypes.c_ubyte * len(msg2_serialized))(*msg2_serialized)

    # Get pointers
    cfm_state_ob_r1_ptr = ctypes.cast(cfm_state_ob_r1_array, ctypes.POINTER(ctypes.c_ubyte))
    shares_ob_ptr = ctypes.cast(shares_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_ob_ptr = ctypes.cast(auth_triples_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    msg2_ptr = ctypes.cast(msg2_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg2(
        cfm_state_ob_r1_ptr, len(cfm_state_ob_r1),
        shares_ob_ptr, len(shares_ob),
        auth_triples_ob_ptr, len(auth_triples_ob),
        msg2_ptr, len(msg2_serialized),
        rng_ptr
    )

    if not result.cfm_state_ob_r2_ptr or not result.msg3_ptr:
        raise ValueError("Failed to process ffi_cfm_process_msg2 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r2_serialized = ctypes.string_at(result.cfm_state_ob_r2_ptr, result.cfm_state_ob_r2_size)
    msg3_serialized = ctypes.string_at(result.msg3_ptr, result.msg3_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r2_ptr, result.cfm_state_ob_r2_size)
    rust_lib.free_buffer(result.msg3_ptr, result.msg3_size)

    return cfm_state_ob_r2_serialized, msg3_serialized


def ffi_cfm_process_msg3(cfm_state_cb_r1, shares_cb, auth_triples_cb, msg3_serialized):
    """Calls Rust function to process cfm_state_cb_r1, shares_cb, auth_triples_cb, and msg3, returning cfm_state_cb_r2 and msg4."""
    
    if not cfm_state_cb_r1 or not shares_cb or not auth_triples_cb or not msg3_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg3.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_cb_r1_array = (ctypes.c_ubyte * len(cfm_state_cb_r1))(*cfm_state_cb_r1)
    shares_cb_array = (ctypes.c_ubyte * len(shares_cb))(*shares_cb)
    auth_triples_cb_array = (ctypes.c_ubyte * len(auth_triples_cb))(*auth_triples_cb)
    msg3_array = (ctypes.c_ubyte * len(msg3_serialized))(*msg3_serialized)

    # Get pointers
    cfm_state_cb_r1_ptr = ctypes.cast(cfm_state_cb_r1_array, ctypes.POINTER(ctypes.c_ubyte))
    shares_cb_ptr = ctypes.cast(shares_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_cb_ptr = ctypes.cast(auth_triples_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg3_ptr = ctypes.cast(msg3_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg3(
        cfm_state_cb_r1_ptr, len(cfm_state_cb_r1),
        shares_cb_ptr, len(shares_cb),
        auth_triples_cb_ptr, len(auth_triples_cb),
        msg3_ptr, len(msg3_serialized)
    )

    if not result.cfm_state_cb_r2_ptr or result.cfm_state_cb_r2_size == 0:
        raise ValueError("Failed to process cfm_process_msg3 in Rust.")

    # Read serialized outputs
    cfm_state_cb_r2_serialized = ctypes.string_at(result.cfm_state_cb_r2_ptr, result.cfm_state_cb_r2_size)
    msg4_serialized = ctypes.string_at(result.msg4_ptr, result.msg4_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_cb_r2_ptr, result.cfm_state_cb_r2_size)
    rust_lib.free_buffer(result.msg4_ptr, result.msg4_size)

    return cfm_state_cb_r2_serialized, msg4_serialized


def ffi_cfm_process_msg4(cfm_state_ob_r2, msg4_serialized):
    """Calls Rust function to process cfm_state_ob_r2 and msg4, returning cfm_state_ob_r3 and msg5."""
    
    if not cfm_state_ob_r2 or not msg4_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg4.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_ob_r2_array = (ctypes.c_ubyte * len(cfm_state_ob_r2))(*cfm_state_ob_r2)
    msg4_array = (ctypes.c_ubyte * len(msg4_serialized))(*msg4_serialized)

    # Get pointers
    cfm_state_ob_r2_ptr = ctypes.cast(cfm_state_ob_r2_array, ctypes.POINTER(ctypes.c_ubyte))
    msg4_ptr = ctypes.cast(msg4_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg4(
        cfm_state_ob_r2_ptr, len(cfm_state_ob_r2),
        msg4_ptr, len(msg4_serialized)
    )

    if not result.cfm_state_ob_r3_ptr or result.cfm_state_ob_r3_size == 0:
        raise ValueError("Failed to process cfm_process_msg4 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r3_serialized = ctypes.string_at(result.cfm_state_ob_r3_ptr, result.cfm_state_ob_r3_size)
    msg5_serialized = ctypes.string_at(result.msg5_ptr, result.msg5_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r3_ptr, result.cfm_state_ob_r3_size)
    rust_lib.free_buffer(result.msg5_ptr, result.msg5_size)

    return cfm_state_ob_r3_serialized, msg5_serialized

def ffi_cfm_process_msg5(cfm_state_cb_r2, auth_triples_cb, msg5_serialized):
    """Calls Rust function to process cfm_state_cb_r2, auth_triples_cb, and msg5, returning cfm_state_cb_r3 and msg6."""
    
    if not cfm_state_cb_r2 or not auth_triples_cb or not msg5_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg5.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_cb_r2_array = (ctypes.c_ubyte * len(cfm_state_cb_r2))(*cfm_state_cb_r2)
    auth_triples_cb_array = (ctypes.c_ubyte * len(auth_triples_cb))(*auth_triples_cb)
    msg5_array = (ctypes.c_ubyte * len(msg5_serialized))(*msg5_serialized)

    # Get pointers
    cfm_state_cb_r2_ptr = ctypes.cast(cfm_state_cb_r2_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_cb_ptr = ctypes.cast(auth_triples_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg5_ptr = ctypes.cast(msg5_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg5(
        cfm_state_cb_r2_ptr, len(cfm_state_cb_r2),
        auth_triples_cb_ptr, len(auth_triples_cb),
        msg5_ptr, len(msg5_serialized)
    )

    if not result.cfm_state_cb_r3_ptr or not result.msg6_ptr:
        raise ValueError("Failed to process cfm_process_msg5 in Rust.")

    # Extract serialized outputs
    cfm_state_cb_r3_serialized = ctypes.string_at(result.cfm_state_cb_r3_ptr, result.cfm_state_cb_r3_size)
    msg6_serialized = ctypes.string_at(result.msg6_ptr, result.msg6_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_cb_r3_ptr, result.cfm_state_cb_r3_size)
    rust_lib.free_buffer(result.msg6_ptr, result.msg6_size)

    return cfm_state_cb_r3_serialized, msg6_serialized


def ffi_cfm_process_msg6(cfm_state_ob_r3, auth_triples_ob, msg6_serialized):
    """Calls Rust function to process cfm_state_ob_r3, auth_triples_ob, and msg6, returning cfm_state_ob_r4 and msg7."""
    
    if not cfm_state_ob_r3 or not auth_triples_ob or not msg6_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg6.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_ob_r3_array = (ctypes.c_ubyte * len(cfm_state_ob_r3))(*cfm_state_ob_r3)
    auth_triples_ob_array = (ctypes.c_ubyte * len(auth_triples_ob))(*auth_triples_ob)
    msg6_array = (ctypes.c_ubyte * len(msg6_serialized))(*msg6_serialized)

    # Get pointers
    cfm_state_ob_r3_ptr = ctypes.cast(cfm_state_ob_r3_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_ob_ptr = ctypes.cast(auth_triples_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    msg6_ptr = ctypes.cast(msg6_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg6(
        cfm_state_ob_r3_ptr, len(cfm_state_ob_r3),
        auth_triples_ob_ptr, len(auth_triples_ob),
        msg6_ptr, len(msg6_serialized)
    )

    if not result.cfm_state_ob_r4_ptr:
        raise ValueError("Failed to process cfm_process_msg6 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r4_serialized = ctypes.string_at(result.cfm_state_ob_r4_ptr, result.cfm_state_ob_r4_size)
    msg7_serialized = ctypes.string_at(result.msg7_ptr, result.msg7_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r4_ptr, result.cfm_state_ob_r4_size)
    rust_lib.free_buffer(result.msg7_ptr, result.msg7_size)

    return cfm_state_ob_r4_serialized, msg7_serialized


def ffi_cfm_process_msg7(cfm_state_cb_r3, auth_triples_cb, msg7_serialized):
    """Calls Rust function to process cfm_state_cb_r3, auth_triples_cb, and msg7, returning cfm_state_cb_r4 and msg8."""
    
    if not cfm_state_cb_r3 or not auth_triples_cb or not msg7_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg7.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_cb_r3_array = (ctypes.c_ubyte * len(cfm_state_cb_r3))(*cfm_state_cb_r3)
    auth_triples_cb_array = (ctypes.c_ubyte * len(auth_triples_cb))(*auth_triples_cb)
    msg7_array = (ctypes.c_ubyte * len(msg7_serialized))(*msg7_serialized)

    # Get pointers
    cfm_state_cb_r3_ptr = ctypes.cast(cfm_state_cb_r3_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_cb_ptr = ctypes.cast(auth_triples_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg7_ptr = ctypes.cast(msg7_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg7(
        cfm_state_cb_r3_ptr, len(cfm_state_cb_r3),
        auth_triples_cb_ptr, len(auth_triples_cb),
        msg7_ptr, len(msg7_serialized)
    )

    if not result.cfm_state_cb_r4_ptr:
        raise ValueError("Failed to process cfm_process_msg7 in Rust.")

    # Read serialized outputs
    cfm_state_cb_r4_serialized = ctypes.string_at(result.cfm_state_cb_r4_ptr, result.cfm_state_cb_r4_size)
    msg8_serialized = ctypes.string_at(result.msg8_ptr, result.msg8_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_cb_r4_ptr, result.cfm_state_cb_r4_size)
    rust_lib.free_buffer(result.msg8_ptr, result.msg8_size)

    return cfm_state_cb_r4_serialized, msg8_serialized


def ffi_cfm_process_msg8(cfm_state_ob_r4, auth_triples_ob, msg8_serialized):
    """Calls Rust function to process cfm_state_ob_r4, auth_triples_ob, and msg8, returning cfm_state_ob_r5 and msg9."""
    
    if not cfm_state_ob_r4 or not auth_triples_ob or not msg8_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg8.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_ob_r4_array = (ctypes.c_ubyte * len(cfm_state_ob_r4))(*cfm_state_ob_r4)
    auth_triples_ob_array = (ctypes.c_ubyte * len(auth_triples_ob))(*auth_triples_ob)
    msg8_array = (ctypes.c_ubyte * len(msg8_serialized))(*msg8_serialized)

    # Get pointers
    cfm_state_ob_r4_ptr = ctypes.cast(cfm_state_ob_r4_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_ob_ptr = ctypes.cast(auth_triples_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    msg8_ptr = ctypes.cast(msg8_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg8(
        cfm_state_ob_r4_ptr, len(cfm_state_ob_r4),
        auth_triples_ob_ptr, len(auth_triples_ob),
        msg8_ptr, len(msg8_serialized)
    )

    if not result.cfm_state_ob_r5_ptr:
        raise ValueError("Failed to process cfm_process_msg8 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r5_serialized = ctypes.string_at(result.cfm_state_ob_r5_ptr, result.cfm_state_ob_r5_size)
    msg9_serialized = ctypes.string_at(result.msg9_ptr, result.msg9_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r5_ptr, result.cfm_state_ob_r5_size)
    rust_lib.free_buffer(result.msg9_ptr, result.msg9_size)

    return cfm_state_ob_r5_serialized, msg9_serialized


def ffi_cfm_process_msg9(cfm_state_cb_r4, auth_triples_cb, msg9_serialized):
    """Calls Rust function to process cfm_state_cb_r4, auth_triples_cb, and msg9, returning cfm_state_cb_r5 and msg10."""
    
    if not cfm_state_cb_r4 or not auth_triples_cb or not msg9_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg9.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_cb_r4_array = (ctypes.c_ubyte * len(cfm_state_cb_r4))(*cfm_state_cb_r4)
    auth_triples_cb_array = (ctypes.c_ubyte * len(auth_triples_cb))(*auth_triples_cb)
    msg9_array = (ctypes.c_ubyte * len(msg9_serialized))(*msg9_serialized)

    # Get pointers
    cfm_state_cb_r4_ptr = ctypes.cast(cfm_state_cb_r4_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_cb_ptr = ctypes.cast(auth_triples_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg9_ptr = ctypes.cast(msg9_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg9(
        cfm_state_cb_r4_ptr, len(cfm_state_cb_r4),
        auth_triples_cb_ptr, len(auth_triples_cb),
        msg9_ptr, len(msg9_serialized)
    )

    if not result.cfm_state_cb_r5_ptr:
        raise ValueError("Failed to process cfm_process_msg9 in Rust.")

    # Read serialized outputs
    cfm_state_cb_r5_serialized = ctypes.string_at(result.cfm_state_cb_r5_ptr, result.cfm_state_cb_r5_size)
    msg10_serialized = ctypes.string_at(result.msg10_ptr, result.msg10_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_cb_r5_ptr, result.cfm_state_cb_r5_size)
    rust_lib.free_buffer(result.msg10_ptr, result.msg10_size)

    return cfm_state_cb_r5_serialized, msg10_serialized

def ffi_cfm_process_msg10(cfm_state_ob_r5, auth_triples_ob, msg10_serialized):
    """Calls Rust function to process cfm_state_ob_r5, auth_triples_ob, and msg10, returning cfm_state_ob_r6 and msg11."""
    
    if not cfm_state_ob_r5 or not auth_triples_ob or not msg10_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg10.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_ob_r5_array = (ctypes.c_ubyte * len(cfm_state_ob_r5))(*cfm_state_ob_r5)
    auth_triples_ob_array = (ctypes.c_ubyte * len(auth_triples_ob))(*auth_triples_ob)
    msg10_array = (ctypes.c_ubyte * len(msg10_serialized))(*msg10_serialized)

    # Get pointers
    cfm_state_ob_r5_ptr = ctypes.cast(cfm_state_ob_r5_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_ob_ptr = ctypes.cast(auth_triples_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    msg10_ptr = ctypes.cast(msg10_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg10(
        cfm_state_ob_r5_ptr, len(cfm_state_ob_r5),
        auth_triples_ob_ptr, len(auth_triples_ob),
        msg10_ptr, len(msg10_serialized)
    )

    if not result.cfm_state_ob_r6_ptr:
        raise ValueError("Failed to process cfm_process_msg10 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r6_serialized = ctypes.string_at(result.cfm_state_ob_r6_ptr, result.cfm_state_ob_r6_size)
    msg11_serialized = ctypes.string_at(result.msg11_ptr, result.msg11_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r6_ptr, result.cfm_state_ob_r6_size)
    rust_lib.free_buffer(result.msg11_ptr, result.msg11_size)

    return cfm_state_ob_r6_serialized, msg11_serialized


def ffi_cfm_process_msg11(cfm_state_cb_r5, auth_triples_cb, msg11_serialized):
    """Calls Rust function to process cfm_state_cb_r5, auth_triples_cb, and msg11, returning cfm_state_cb_r6 and msg12."""
    
    if not cfm_state_cb_r5 or not auth_triples_cb or not msg11_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg11.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_cb_r5_array = (ctypes.c_ubyte * len(cfm_state_cb_r5))(*cfm_state_cb_r5)
    auth_triples_cb_array = (ctypes.c_ubyte * len(auth_triples_cb))(*auth_triples_cb)
    msg11_array = (ctypes.c_ubyte * len(msg11_serialized))(*msg11_serialized)

    # Get pointers
    cfm_state_cb_r5_ptr = ctypes.cast(cfm_state_cb_r5_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_cb_ptr = ctypes.cast(auth_triples_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg11_ptr = ctypes.cast(msg11_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg11(
        cfm_state_cb_r5_ptr, len(cfm_state_cb_r5),
        auth_triples_cb_ptr, len(auth_triples_cb),
        msg11_ptr, len(msg11_serialized)
    )

    if not result.cfm_state_cb_r6_ptr:
        raise ValueError("Failed to process cfm_process_msg11 in Rust.")

    # Read serialized outputs
    cfm_state_cb_r6_serialized = ctypes.string_at(result.cfm_state_cb_r6_ptr, result.cfm_state_cb_r6_size)
    msg12_serialized = ctypes.string_at(result.msg12_ptr, result.msg12_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_cb_r6_ptr, result.cfm_state_cb_r6_size)
    rust_lib.free_buffer(result.msg12_ptr, result.msg12_size)

    return cfm_state_cb_r6_serialized, msg12_serialized


def ffi_cfm_process_msg12(cfm_state_ob_r6, auth_triples_ob, msg12_serialized):
    """Calls Rust function to process cfm_state_ob_r6, auth_triples_ob, and msg12, returning cfm_state_ob_r7 and msg13."""
    
    if not cfm_state_ob_r6 or not auth_triples_ob or not msg12_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg12.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_ob_r6_array = (ctypes.c_ubyte * len(cfm_state_ob_r6))(*cfm_state_ob_r6)
    auth_triples_ob_array = (ctypes.c_ubyte * len(auth_triples_ob))(*auth_triples_ob)
    msg12_array = (ctypes.c_ubyte * len(msg12_serialized))(*msg12_serialized)

    # Get pointers
    cfm_state_ob_r6_ptr = ctypes.cast(cfm_state_ob_r6_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_ob_ptr = ctypes.cast(auth_triples_ob_array, ctypes.POINTER(ctypes.c_ubyte))
    msg12_ptr = ctypes.cast(msg12_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg12(
        cfm_state_ob_r6_ptr, len(cfm_state_ob_r6),
        auth_triples_ob_ptr, len(auth_triples_ob),
        msg12_ptr, len(msg12_serialized)
    )

    if not result.cfm_state_ob_r7_ptr:
        raise ValueError("Failed to process cfm_process_msg12 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r7_serialized = ctypes.string_at(result.cfm_state_ob_r7_ptr, result.cfm_state_ob_r7_size)
    msg13_serialized = ctypes.string_at(result.msg13_ptr, result.msg13_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r7_ptr, result.cfm_state_ob_r7_size)
    rust_lib.free_buffer(result.msg13_ptr, result.msg13_size)

    return cfm_state_ob_r7_serialized, msg13_serialized


def ffi_cfm_process_msg13(cfm_state_cb_r6, auth_triples_cb, msg13_serialized):
    """Calls Rust function to process cfm_state_cb_r6, auth_triples_cb, and msg13, returning cfm_state_cb_r7 and msg14."""
    
    if not cfm_state_cb_r6 or not auth_triples_cb or not msg13_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg13.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_cb_r6_array = (ctypes.c_ubyte * len(cfm_state_cb_r6))(*cfm_state_cb_r6)
    auth_triples_cb_array = (ctypes.c_ubyte * len(auth_triples_cb))(*auth_triples_cb)
    msg13_array = (ctypes.c_ubyte * len(msg13_serialized))(*msg13_serialized)

    # Get pointers
    cfm_state_cb_r6_ptr = ctypes.cast(cfm_state_cb_r6_array, ctypes.POINTER(ctypes.c_ubyte))
    auth_triples_cb_ptr = ctypes.cast(auth_triples_cb_array, ctypes.POINTER(ctypes.c_ubyte))
    msg13_ptr = ctypes.cast(msg13_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg13(
        cfm_state_cb_r6_ptr, len(cfm_state_cb_r6),
        auth_triples_cb_ptr, len(auth_triples_cb),
        msg13_ptr, len(msg13_serialized)
    )

    if not result.cfm_state_cb_r7_ptr:
        raise ValueError("Failed to process cfm_process_msg13 in Rust.")

    # Read serialized outputs
    cfm_state_cb_r7_serialized = ctypes.string_at(result.cfm_state_cb_r7_ptr, result.cfm_state_cb_r7_size)
    msg14_serialized = ctypes.string_at(result.msg14_ptr, result.msg14_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_cb_r7_ptr, result.cfm_state_cb_r7_size)
    rust_lib.free_buffer(result.msg14_ptr, result.msg14_size)

    return cfm_state_cb_r7_serialized, msg14_serialized


def ffi_cfm_process_msg14(cfm_state_ob_r7, msg14_serialized):
    """Calls Rust function to process cfm_state_ob_r7 and msg14, returning cfm_state_ob_r8 and msg15."""
    
    if not cfm_state_ob_r7 or not msg14_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg14.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_ob_r7_array = (ctypes.c_ubyte * len(cfm_state_ob_r7))(*cfm_state_ob_r7)
    msg14_array = (ctypes.c_ubyte * len(msg14_serialized))(*msg14_serialized)

    # Get pointers
    cfm_state_ob_r7_ptr = ctypes.cast(cfm_state_ob_r7_array, ctypes.POINTER(ctypes.c_ubyte))
    msg14_ptr = ctypes.cast(msg14_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg14(
        cfm_state_ob_r7_ptr, len(cfm_state_ob_r7),
        msg14_ptr, len(msg14_serialized)
    )

    if not result.cfm_state_ob_r8_ptr:
        raise ValueError("Failed to process cfm_process_msg14 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r8_serialized = ctypes.string_at(result.cfm_state_ob_r8_ptr, result.cfm_state_ob_r8_size)
    msg15_serialized = ctypes.string_at(result.msg15_ptr, result.msg15_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r8_ptr, result.cfm_state_ob_r8_size)
    rust_lib.free_buffer(result.msg15_ptr, result.msg15_size)

    return cfm_state_ob_r8_serialized, msg15_serialized


def ffi_cfm_process_msg15(cfm_state_cb_r7, msg15_serialized):
    """Calls Rust function to process cfm_state_cb_r7 and msg15, returning cfm_state_cb_r8 and msg16."""
    
    if not cfm_state_cb_r7 or not msg15_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg15.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_cb_r7_array = (ctypes.c_ubyte * len(cfm_state_cb_r7))(*cfm_state_cb_r7)
    msg15_array = (ctypes.c_ubyte * len(msg15_serialized))(*msg15_serialized)

    # Get pointers
    cfm_state_cb_r7_ptr = ctypes.cast(cfm_state_cb_r7_array, ctypes.POINTER(ctypes.c_ubyte))
    msg15_ptr = ctypes.cast(msg15_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg15(
        cfm_state_cb_r7_ptr, len(cfm_state_cb_r7),
        msg15_ptr, len(msg15_serialized)
    )

    if not result.cfm_state_cb_r8_ptr:
        raise ValueError("Failed to process cfm_process_msg15 in Rust.")

    # Read serialized outputs
    cfm_state_cb_r8_serialized = ctypes.string_at(result.cfm_state_cb_r8_ptr, result.cfm_state_cb_r8_size)
    msg16_serialized = ctypes.string_at(result.msg16_ptr, result.msg16_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_cb_r8_ptr, result.cfm_state_cb_r8_size)
    rust_lib.free_buffer(result.msg16_ptr, result.msg16_size)

    return cfm_state_cb_r8_serialized, msg16_serialized


def ffi_cfm_process_msg16(cfm_state_ob_r8, msg16_serialized):
    """Calls Rust function to process cfm_state_ob_r8 and msg16, returning cfm_state_ob_r9 and msg17."""
    
    if not cfm_state_ob_r8 or not msg16_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg16.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_ob_r8_array = (ctypes.c_ubyte * len(cfm_state_ob_r8))(*cfm_state_ob_r8)
    msg16_array = (ctypes.c_ubyte * len(msg16_serialized))(*msg16_serialized)

    # Get pointers
    cfm_state_ob_r8_ptr = ctypes.cast(cfm_state_ob_r8_array, ctypes.POINTER(ctypes.c_ubyte))
    msg16_ptr = ctypes.cast(msg16_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg16(
        cfm_state_ob_r8_ptr, len(cfm_state_ob_r8),
        msg16_ptr, len(msg16_serialized)
    )

    if not result.cfm_state_ob_r9_ptr:
        raise ValueError("Failed to process cfm_process_msg16 in Rust.")

    # Read serialized outputs
    cfm_state_ob_r9_serialized = ctypes.string_at(result.cfm_state_ob_r9_ptr, result.cfm_state_ob_r9_size)
    msg17_serialized = ctypes.string_at(result.msg17_ptr, result.msg17_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.cfm_state_ob_r9_ptr, result.cfm_state_ob_r9_size)
    rust_lib.free_buffer(result.msg17_ptr, result.msg17_size)

    return cfm_state_ob_r9_serialized, msg17_serialized

def ffi_cfm_process_msg17(cfm_state_cb_r8, msg17_serialized):
    """Calls Rust function to process cfm_state_cb_r8 and msg17, returning b_cb_value and msg18."""
    
    if not cfm_state_cb_r8 or not msg17_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg17.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_cb_r8_array = (ctypes.c_ubyte * len(cfm_state_cb_r8))(*cfm_state_cb_r8)
    msg17_array = (ctypes.c_ubyte * len(msg17_serialized))(*msg17_serialized)

    # Get pointers
    cfm_state_cb_r8_ptr = ctypes.cast(cfm_state_cb_r8_array, ctypes.POINTER(ctypes.c_ubyte))
    msg17_ptr = ctypes.cast(msg17_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg17(
        cfm_state_cb_r8_ptr, len(cfm_state_cb_r8),
        msg17_ptr, len(msg17_serialized)
    )

    if not result.b_cb_value_ptr:
        raise ValueError("Failed to process cfm_process_msg17 in Rust.")

    # Read serialized outputs
    b_cb_value_serialized = ctypes.string_at(result.b_cb_value_ptr, result.b_cb_value_size)
    msg18_serialized = ctypes.string_at(result.msg18_ptr, result.msg18_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.b_cb_value_ptr, result.b_cb_value_size)
    rust_lib.free_buffer(result.msg18_ptr, result.msg18_size)

    return b_cb_value_serialized, msg18_serialized


def ffi_cfm_process_msg18(cfm_state_ob_r9, msg18_serialized):
    """Calls Rust function to process cfm_state_ob_r9 and msg18, returning b_ob_value."""
    
    if not cfm_state_ob_r9 or not msg18_serialized:
        raise ValueError("Invalid inputs to ffi_cfm_process_msg18.")

    # Convert Python bytes to ctypes-compatible format
    cfm_state_ob_r9_array = (ctypes.c_ubyte * len(cfm_state_ob_r9))(*cfm_state_ob_r9)
    msg18_array = (ctypes.c_ubyte * len(msg18_serialized))(*msg18_serialized)

    # Get pointers
    cfm_state_ob_r9_ptr = ctypes.cast(cfm_state_ob_r9_array, ctypes.POINTER(ctypes.c_ubyte))
    msg18_ptr = ctypes.cast(msg18_array, ctypes.POINTER(ctypes.c_ubyte))

    # Call Rust function
    result = rust_lib.ffi_cfm_process_msg18(
        cfm_state_ob_r9_ptr, len(cfm_state_ob_r9),
        msg18_ptr, len(msg18_serialized)
    )

    if not result.b_ob_value_ptr:
        raise ValueError("Failed to process cfm_process_msg18 in Rust.")

    # Read serialized outputs
    b_ob_value_serialized = ctypes.string_at(result.b_ob_value_ptr, result.b_ob_value_size)

    # Free allocated memory in Rust
    rust_lib.free_buffer(result.b_ob_value_ptr, result.b_ob_value_size)

    return b_ob_value_serialized
