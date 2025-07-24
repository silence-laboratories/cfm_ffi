use crypto_bigint::U128;

/// Misc protocol helper functions
pub mod proto;

/// Constants
pub mod constants;

/// DLog proof
pub mod dlog_proof;

/// Private Sanction List Check protocol
pub mod psc_protocol;

/// Private Set Intersection and Transfer protocol
pub mod psit_protocol;

/// errors
pub mod errors;

/// utils
pub mod utils;

/// auth_beaver_triples
pub mod auth_beaver_triples;

/// comparison protocol
pub mod comparison;

/// sl_oblivious
pub mod sl_oblivious;

/// cfm protocol
pub mod cfm_protocol;

/// Creation ot_seeds for cfm protocol
pub mod cfm_init_protocol;

use utils::Customer;



const P_HEX: &str = "ccc87af2fe0b80db9924beecec1bc803";
/// Prime integer p
pub const P: U128 = U128::from_be_hex(P_HEX);


use rand::{thread_rng, Rng, RngCore};
use rand::rngs::{StdRng, ThreadRng};
use std::os::raw::{c_char, c_void, c_uchar};
use std::ffi::CStr;
use rand::SeedableRng;

use std::ffi::{CString};
use serde::{Serialize, Deserialize};
use bincode;
use crypto_bigint::U64;

use cfm_init_protocol::{
    cfm_init_create_msg1, cfm_init_process_msg1, cfm_init_process_msg2, cfm_init_process_msg3,
    CFMInitMsg1, CFMInitMsg2, CFMInitMsg3
};

use auth_beaver_triples::{
    abt_create_msg1, abt_process_msg1, abt_process_msg2, abt_process_msg3, abt_process_msg4, abt_process_msg5, ABTMsg1, ABTMsg2, ABTStateCBR1, ABTStateCBR2, ABTStateOBR1, Share, TripleShare,
    ABTMsg3, ABTMsg4, ABTMsg5, ABTStateOBR2
};

use cfm_protocol::{
    cfm_create_msg1, cfm_process_msg1, cfm_process_msg10, cfm_process_msg11, cfm_process_msg12,
    cfm_process_msg13, cfm_process_msg14, cfm_process_msg15, cfm_process_msg16, cfm_process_msg17,
    cfm_process_msg18, cfm_process_msg2, cfm_process_msg3, cfm_process_msg4, cfm_process_msg5,
    cfm_process_msg6, cfm_process_msg7, cfm_process_msg8, cfm_process_msg9,
    NUMBER_OF_AUTH_BEAVER_TRIPLES, NUMBER_OF_SHARES, CFMMsg1, CFMStateOBR1,CFMMsg2, CFMStateCBR1, CFMMsg3,
    CFMStateOBR2, CFMMsg4, CFMStateCBR2, CFMMsg5, CFMStateOBR3, CFMMsg6, CFMStateCBR3, CFMMsg7,
    CFMStateOBR4, CFMMsg8, CFMStateCBR4, CFMMsg9, CFMStateOBR5, CFMMsg10, CFMStateCBR5, CFMMsg11,
    CFMStateOBR6, CFMMsg12, CFMStateCBR6, CFMMsg13,CFMStateOBR7, CFMMsg14, CFMStateCBR7, CFMMsg15,
    CFMStateOBR8, CFMMsg16, CFMStateCBR8, CFMMsg17, CFMStateOBR9, CFMMsg18
};

use crate::cfm_init_protocol::{CFMInitOTSeedsCB, CFMInitOTSeedsOB, CFMInitStateOB, CFMInitStateCB};
use std::alloc::{alloc, dealloc, Layout};
use std::ptr;
use std::slice;
use std::mem;


/// Enum mapping type names to Rust types
enum TypeRegistry {
    CFMInitMessage,
    CFMInitMsg1,
    CFMInitMsg2,
}

impl TypeRegistry {
    fn from_str(type_name: &str) -> Option<Self> {
        match type_name {
            "CFMInitMessage" => Some(TypeRegistry::CFMInitMessage),
            "CFMInitMsg1" => Some(TypeRegistry::CFMInitMsg1),
            "CFMInitMsg2" => Some(TypeRegistry::CFMInitMsg2),
            _ => None,
        }
    }
}

/// Generic deserialization function that converts binary (Bincode) to JSON
fn deserialize_generic<T: for<'de> Deserialize<'de> + Serialize>(serialized: &[u8]) -> *mut c_char {
    match bincode::deserialize::<T>(serialized) {
        Ok(msg) => match serde_json::to_string(&msg) {
            Ok(json) => match CString::new(json) {
                Ok(c_string) => c_string.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}


/// **FFI Wrapper function that accepts type name and deserializes accordingly**
#[no_mangle]
pub extern "C" fn deserialize_msg(
    serialized_ptr: *const c_uchar,
    size: usize,
    type_name_ptr: *const c_char
) -> *mut c_char {
    if serialized_ptr.is_null() || size == 0 || type_name_ptr.is_null() {
        return ptr::null_mut();
    }

    let serialized = unsafe { slice::from_raw_parts(serialized_ptr, size) };

    // Convert C string to Rust &str
    let type_name = unsafe {
        match CStr::from_ptr(type_name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    // Match type name and call appropriate deserialization
    match TypeRegistry::from_str(type_name) {
        Some(TypeRegistry::CFMInitMessage) => deserialize_generic::<CFMInitMessage>(serialized),
        Some(TypeRegistry::CFMInitMsg1) => deserialize_generic::<CFMInitMsg1>(serialized),
        Some(TypeRegistry::CFMInitMsg2) => deserialize_generic::<CFMInitMsg2>(serialized),
        None => ptr::null_mut(), // Unknown type
    }
}



// Function to free the allocated memory in Rust
#[no_mangle]
pub extern "C" fn free_buffer(ptr: *mut u8, size: usize) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        let layout = Layout::array::<u8>(size).unwrap();
        dealloc(ptr, layout);
    }
}

/// Free allocated memory for C strings
#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(ptr)); // Automatically deallocates memory
    }
}


// A holder for our RNG so that the pointer we return is a thin pointer.
#[repr(C)]
pub struct RngHolder {
    // This field is a Box<dyn RngCore> (a fat pointer) but the struct itself
    // is allocated on the heap and we return a pointer to the struct.
    pub rng: Box<dyn RngCore>,
}

#[no_mangle]
pub extern "C" fn free_rng(rng_ptr: *mut ThreadRng) {
    if rng_ptr.is_null() {
        return;
    }

    // SAFELY reclaim the Box and drop it
    unsafe {
        drop(Box::from_raw(rng_ptr));
    }
}

/// Creates an RNG.  
/// If `seed_req` is null, uses `thread_rng()`.  
/// Otherwise, uses `StdRng::seed_from_u64(seed)` with the provided seed.
/// Returns a pointer to a RngHolder as an opaque pointer.
#[no_mangle]
pub extern "C" fn create_rng() -> *mut ThreadRng {
    // Create a non-deterministic RNG using thread_rng.
    let rng = Box::new(thread_rng()); // Now directly using `ThreadRng`
    
    // Convert the Box into a raw pointer (caller must free it later)
    Box::into_raw(rng)
}



#[no_mangle]
pub extern "C" fn generate_init_session_id(rng_ptr: *mut c_void, out_size: *mut usize) -> *mut u8 {
    if rng_ptr.is_null() || out_size.is_null() {
        eprintln!("Invalid RNG pointer or output size.");
        return ptr::null_mut();
    }

    // SAFELY Extract RngHolder and access the RNG
    // let rng_holder = unsafe { &mut *(rng_ptr as *mut Rng) };
    // let rng = &mut rng_holder.rng; // Now correctly using the RNG
    
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Generate a random 32-byte session ID
    let session_id: [u8; 32] = rng.gen();


    // Serialize the session ID using Bincode
    let serialized = match bincode::serialize(&session_id) {
        Ok(data) => data,
        Err(_) => return ptr::null_mut(),
    };

    // Allocate heap memory for the serialized data
    let size = serialized.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("Memory allocation failed!");
        return ptr::null_mut();
    }

    // Copy serialized data to allocated memory
    unsafe {
        ptr.copy_from_nonoverlapping(serialized.as_ptr(), size);
        *out_size = size;
    }

    // println!("Returning pointer: {:#?}", ptr);

    ptr
}


/// Enum to represent different message types
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum CFMInitMessage {
    Msg1(CFMInitMsg1),
    Msg2(CFMInitMsg2),
    Msg3(CFMInitMsg3),
}

#[no_mangle]
pub extern "C" fn create_msg(msg_type: *const c_char, out_size: *mut usize) -> *mut u8 {
    // Ensure input pointers are valid
    if msg_type.is_null() || out_size.is_null() {
        eprintln!("Invalid input to create_msg");
        return ptr::null_mut();
    }

    // Convert the C string to a Rust &str
    let c_str = unsafe { CStr::from_ptr(msg_type) };

    let serialized = match c_str.to_str() {
        Ok("msg1") => {
            let msg = CFMInitMsg1::default();
            bincode::serialize(&msg)
        }
        Ok("msg2") => {
            let msg = CFMInitMsg2::default();
            bincode::serialize(&msg)
        }
        Ok("msg3") => {
            let msg = CFMInitMsg3::default();
            bincode::serialize(&msg)
        }
        _ => {
            eprintln!("Unexpected message type: {:?}", c_str);
            return ptr::null_mut();
        }
    };

    // Handle serialization failure
    let serialized = match serialized {
        Ok(data) => {
            // println!("Serialization successful, size: {}", data.len());
            data
        }
        Err(e) => {
            eprintln!("Serialization failed: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Allocate memory for serialized data
    let size = serialized.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("Memory allocation failed!");
        return ptr::null_mut();
    }

    // Copy serialized data to allocated memory
    unsafe {
        ptr.copy_from_nonoverlapping(serialized.as_ptr(), size);
        *out_size = size;
    }

    ptr
}

fn round_trip_check<T>(data: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let serialized = bincode::serialize(data).unwrap();
    let deserialized: T = bincode::deserialize(&serialized).unwrap();

    assert_eq!(*data, deserialized, "Data mismatch! Serialization is lossy.");
    // println!("Serialization is **lossless** ✅");
}

#[no_mangle]
pub extern "C" fn ffi_cfm_init_create_msg1(
    session_id_bytes_ptr: *const u8,
    session_id_size: usize,
    msg1_bytes_ptr: *mut u8,  // Changed to `*mut u8` to allow modification
    msg1_size: usize,
    rng_ptr: *mut c_void,
    out_state_size: *mut usize,
) -> *mut u8 {
    if session_id_bytes_ptr.is_null() || session_id_size == 0 || 
       msg1_bytes_ptr.is_null() || msg1_size == 0 || 
       rng_ptr.is_null() || out_state_size.is_null() {
        eprintln!("Invalid input pointers in ffi_cfm_init_create_msg1");
        return ptr::null_mut();
    }

    // eprintln!(
    //     "Received session_id_size: {}, msg1_size: {}",
    //     session_id_size, msg1_size
    // );
    
    // Deserialize session_id (we receive serialized bytes from Python)
    let session_id_bytes = unsafe { slice::from_raw_parts(session_id_bytes_ptr, session_id_size) };
    let session_id: [u8; 32] = match bincode::deserialize(session_id_bytes) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to deserialize session_id: {:?}", e);
            return ptr::null_mut();
        }
    };

    // eprintln!("Session ID successfully deserialized.");

    // Deserialize msg1 (Mutable)
    let msg1_bytes = unsafe { slice::from_raw_parts_mut(msg1_bytes_ptr, msg1_size) };
    let mut msg1: CFMInitMsg1 = match bincode::deserialize(msg1_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg1: {:?}", e);
            return ptr::null_mut();
        }
    };

    // eprintln!("Message 1 successfully deserialized.");

    // Get the RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Call the actual function
    let state_ob: CFMInitStateOB = cfm_init_create_msg1(&session_id, &mut msg1, rng);

    // Serialize the updated `msg1`
    let updated_msg1_serialized = match bincode::serialize(&msg1) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize updated msg1: {:?}", e);
            return ptr::null_mut();
        }
    };

    // ✅ Copy updated msg1 back to original pointer
    if updated_msg1_serialized.len() != msg1_size {
        // eprintln!(
        //     "Updated msg1 size mismatch: expected {}, got {}",
        //     msg1_size, updated_msg1_serialized.len()
        // );
        return ptr::null_mut();
    }

    unsafe {
        msg1_bytes_ptr.copy_from_nonoverlapping(updated_msg1_serialized.as_ptr(), msg1_size);
    }

    // ✅ Serialize state_ob
    let serialized_state = match bincode::serialize(&state_ob) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize state_ob: {:?}", e);
            return ptr::null_mut();
        }
    };

    // ✅ Allocate memory for state_ob
    let size = serialized_state.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("Memory allocation failed for state_ob, size: {}", size);
        return ptr::null_mut();
    }

    // ✅ Copy serialized state_ob to allocated memory
    unsafe {
        ptr.copy_from_nonoverlapping(serialized_state.as_ptr(), size);
        *out_state_size = size;
    }

    ptr
}


#[no_mangle]
pub extern "C" fn ffi_cfm_init_process_msg1(
    session_id_bytes_ptr: *const u8,
    session_id_size: usize,
    msg1_bytes_ptr: *const u8,
    msg1_size: usize,
    msg2_bytes_ptr: *mut u8,
    msg2_size: usize,
    rng_ptr: *mut c_void,
    out_state_size: *mut usize,
) -> *mut u8 {
    if session_id_bytes_ptr.is_null() || session_id_size == 0 || 
       msg1_bytes_ptr.is_null() || msg1_size == 0 || 
       msg2_bytes_ptr.is_null() || msg2_size == 0 ||
       rng_ptr.is_null() || out_state_size.is_null() {
        eprintln!("Invalid input pointers in ffi_cfm_init_process_msg1");
        return ptr::null_mut();
    }

    // eprintln!(
    //     "Received session_id_size: {}, msg1_size: {}, msg2_size: {}",
    //     session_id_size, msg1_size, msg2_size
    // );

    // Deserialize session_id
    let session_id_bytes = unsafe { slice::from_raw_parts(session_id_bytes_ptr, session_id_size) };
    let session_id: [u8; 32] = match bincode::deserialize(session_id_bytes) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to deserialize session_id: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Deserialize msg1
    let msg1_bytes = unsafe { slice::from_raw_parts(msg1_bytes_ptr, msg1_size) };
    let msg1: CFMInitMsg1 = match bincode::deserialize(msg1_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg1: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Deserialize msg2 (Mutable)
    let msg2_bytes = unsafe { slice::from_raw_parts_mut(msg2_bytes_ptr, msg2_size) };
    let mut msg2: CFMInitMsg2 = match bincode::deserialize(msg2_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg2: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Get RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Call the actual function
    let state_cb: CFMInitStateCB = match cfm_init_process_msg1(&session_id, &msg1, &mut msg2, rng) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("cfm_init_process_msg1 failed: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Serialize state_cb
    let serialized_state_cb = match bincode::serialize(&state_cb) {
        Ok(data) => {
            // println!("Serialized state_cb size: {} bytes", data.len());
            data
        },
        Err(e) => {
            eprintln!("Failed to serialize state_cb: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Serialize updated msg2 (since it is mutated inside `cfm_init_process_msg1`)
    let serialized_msg2 = match bincode::serialize(&msg2) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize updated msg2: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Ensure the buffer size is correct before copying updated msg2 back
    if serialized_msg2.len() != msg2_size {
        eprintln!(
            "Error: Updated msg2 size mismatch! Expected {}, but got {}",
            msg2_size, serialized_msg2.len()
        );
        return ptr::null_mut();
    }

    // Copy updated msg2 back into the provided buffer
    unsafe {
        msg2_bytes_ptr.copy_from_nonoverlapping(serialized_msg2.as_ptr(), msg2_size);
    }

    // Allocate memory for the serialized state_cb
    let size = serialized_state_cb.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("Memory allocation failed for state_cb, size: {}", size);
        return ptr::null_mut();
    }

    // Copy serialized state_cb to allocated memory
    unsafe {
        ptr.copy_from_nonoverlapping(serialized_state_cb.as_ptr(), size);
        *out_state_size = size;
    }

    ptr
}

#[no_mangle]
pub extern "C" fn ffi_cfm_init_process_msg2(
    state_ob_ptr: *const u8,
    state_ob_size: usize,
    msg2_ptr: *const u8,
    msg2_size: usize,
    msg3_ptr: *mut u8,
    msg3_size: usize,
    rng_ptr: *mut c_void,
    out_ot_seeds_size: *mut usize,
) -> *mut u8 {
    if state_ob_ptr.is_null() || state_ob_size == 0 ||
       msg2_ptr.is_null() || msg2_size == 0 ||
       msg3_ptr.is_null() || msg3_size == 0 ||
       rng_ptr.is_null() || out_ot_seeds_size.is_null() {
        eprintln!("Invalid input pointers in ffi_cfm_init_process_msg2");
        return ptr::null_mut();
    }

    // eprintln!(
    //     "Received state_ob_size: {}, msg2_size: {}, msg3_size: {}",
    //     state_ob_size, msg2_size, msg3_size
    // );

    // Deserialize state_ob
    let state_ob_bytes = unsafe { slice::from_raw_parts(state_ob_ptr, state_ob_size) };
    let state_ob: CFMInitStateOB = match bincode::deserialize(state_ob_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize state_ob: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Deserialize msg2
    let msg2_bytes = unsafe { slice::from_raw_parts(msg2_ptr, msg2_size) };
    let msg2: CFMInitMsg2 = match bincode::deserialize(msg2_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg2: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Deserialize msg3 (Mutable)
    let msg3_bytes = unsafe { slice::from_raw_parts_mut(msg3_ptr, msg3_size) };
    let mut msg3: CFMInitMsg3 = match bincode::deserialize(msg3_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg3: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Get the RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Call the actual function
    let ot_seeds_ob: CFMInitOTSeedsOB = match cfm_init_process_msg2(state_ob, &msg2, &mut msg3, rng) {
        Ok(seeds) => seeds,
        Err(e) => {
            eprintln!("cfm_init_process_msg2 failed: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Serialize ot_seeds_ob
    let serialized_ot_seeds = match bincode::serialize(&ot_seeds_ob) {
        Ok(data) => {
            // println!("Serialized ot_seeds_ob size: {} bytes", data.len());
            data
        },
        Err(e) => {
            eprintln!("Failed to serialize ot_seeds_ob: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Serialize updated msg3
    let updated_msg3_serialized = match bincode::serialize(&msg3) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize updated msg3: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Ensure updated msg3 is correctly sized before copying back
    if updated_msg3_serialized.len() != msg3_size {
        eprintln!(
            "Updated msg3 size mismatch: expected {}, got {}",
            msg3_size, updated_msg3_serialized.len()
        );
        return ptr::null_mut();
    }

    // Copy updated msg3 back into provided buffer
    unsafe {
        msg3_ptr.copy_from_nonoverlapping(updated_msg3_serialized.as_ptr(), msg3_size);
    }

    // Allocate memory for serialized ot_seeds_ob
    let size = serialized_ot_seeds.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("Memory allocation failed for ot_seeds_ob, size: {}", size);
        return ptr::null_mut();
    }

    // Copy serialized ot_seeds_ob and return
    unsafe {
        ptr.copy_from_nonoverlapping(serialized_ot_seeds.as_ptr(), size);
        *out_ot_seeds_size = size;
    }

    ptr
}



#[no_mangle]
pub extern "C" fn ffi_cfm_init_process_msg3(
    state_cb_ptr: *const u8,
    state_cb_size: usize,
    msg3_ptr: *const u8,
    msg3_size: usize,
    out_ot_seeds_size: *mut usize,
) -> *mut u8 {
    if state_cb_ptr.is_null() || state_cb_size == 0 ||
       msg3_ptr.is_null() || msg3_size == 0 ||
       out_ot_seeds_size.is_null() {
        eprintln!("Invalid input pointers in ffi_cfm_init_process_msg3");
        return ptr::null_mut();
    }

    // eprintln!(
    //     "Received state_cb_size: {}, msg3_size: {}",
    //     state_cb_size, msg3_size
    // );

    // Deserialize state_cb
    let state_cb_bytes = unsafe { slice::from_raw_parts(state_cb_ptr, state_cb_size) };
    let state_cb: CFMInitStateCB = match bincode::deserialize(state_cb_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize state_cb: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Deserialize msg3
    let msg3_bytes = unsafe { slice::from_raw_parts(msg3_ptr, msg3_size) };
    let msg3: CFMInitMsg3 = match bincode::deserialize(msg3_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg3: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Call the actual function
    let ot_seeds_cb: CFMInitOTSeedsCB = match cfm_init_process_msg3(state_cb, &msg3) {
        Ok(seeds) => seeds,
        Err(e) => {
            eprintln!("cfm_init_process_msg3 failed: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Serialize ot_seeds_cb
    let serialized_ot_seeds = match bincode::serialize(&ot_seeds_cb) {
        Ok(data) => {
            // println!("Serialized ot_seeds_cb size: {} bytes", data.len());
            data
        },
        Err(e) => {
            eprintln!("Failed to serialize ot_seeds_cb: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Allocate memory for serialized ot_seeds_cb
    let size = serialized_ot_seeds.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("Memory allocation failed for ot_seeds_cb, size: {}", size);
        return ptr::null_mut();
    }

    // Copy serialized ot_seeds_cb and return
    unsafe {
        ptr.copy_from_nonoverlapping(serialized_ot_seeds.as_ptr(), size);
        *out_ot_seeds_size = size;
    }

    ptr
}


#[repr(C)]
pub struct FFI_AbtCreateMsg1Result {
    state_cb_r1_ptr: *mut u8,
    state_cb_r1_size: usize,
    msg1_ptr: *mut u8,
    msg1_size: usize,
}
use rand::rngs::OsRng;

#[no_mangle]
pub extern "C" fn ffi_abt_create_msg1(
    session_id_ptr: *const u8,
    session_id_size: usize,
    ot_seeds_cb_ptr: *const u8,
    ot_seeds_cb_size: usize,
    rng_ptr: *mut c_void,
) -> FFI_AbtCreateMsg1Result {
    if session_id_ptr.is_null() || session_id_size == 0 ||
       ot_seeds_cb_ptr.is_null() || ot_seeds_cb_size == 0 ||
       rng_ptr.is_null() {
        eprintln!("Invalid input pointers in ffi_abt_create_msg1");
        return FFI_AbtCreateMsg1Result {
            state_cb_r1_ptr: ptr::null_mut(),
            state_cb_r1_size: 0,
            msg1_ptr: ptr::null_mut(),
            msg1_size: 0,
        };
    }

    // eprintln!(
    //     "Received session_id_size: {}, ot_seeds_cb_size: {}",
    //     session_id_size, ot_seeds_cb_size
    // );

    // Deserialize session_id
    let session_id_bytes = unsafe { slice::from_raw_parts(session_id_ptr, session_id_size) };
    let session_id: [u8; 32] = match bincode::deserialize(session_id_bytes) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to deserialize session_id: {:?}", e);
            return FFI_AbtCreateMsg1Result {
                state_cb_r1_ptr: ptr::null_mut(),
                state_cb_r1_size: 0,
                msg1_ptr: ptr::null_mut(),
                msg1_size: 0,
            };
        }
    };

    // Deserialize ot_seeds_cb
    let ot_seeds_cb_bytes = unsafe { slice::from_raw_parts(ot_seeds_cb_ptr, ot_seeds_cb_size) };
    let ot_seeds_cb: CFMInitOTSeedsCB = match bincode::deserialize(ot_seeds_cb_bytes) {
        Ok(seeds) => seeds,
        Err(e) => {
            eprintln!("Failed to deserialize ot_seeds_cb: {:?}", e);
            return FFI_AbtCreateMsg1Result {
                state_cb_r1_ptr: ptr::null_mut(),
                state_cb_r1_size: 0,
                msg1_ptr: ptr::null_mut(),
                msg1_size: 0,
            };
        }
    };

    // Get RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut OsRng) };

    // Call `abt_create_msg1` function (with P, eta_i, eta_m inside)
    let p = P;
    let eta_i = NUMBER_OF_SHARES;
    let eta_m = NUMBER_OF_AUTH_BEAVER_TRIPLES;
    let (state_cb_r1, msg1) = abt_create_msg1(&session_id, &ot_seeds_cb, p, eta_i, eta_m, rng);

    // Serialize state_cb_r1
    let serialized_state_cb_r1 = match bincode::serialize(&state_cb_r1) {
        Ok(data) => {
            // println!("Serialized state_cb_r1 size: {} bytes", data.len());
            data
        },
        Err(e) => {
            eprintln!("Failed to serialize state_cb_r1: {:?}", e);
            return FFI_AbtCreateMsg1Result {
                state_cb_r1_ptr: ptr::null_mut(),
                state_cb_r1_size: 0,
                msg1_ptr: ptr::null_mut(),
                msg1_size: 0,
            };
        }
    };

    // Serialize msg1
    let serialized_msg1 = match bincode::serialize(&msg1) {
        Ok(data) => {
            // println!("Serialized msg1 size: {} bytes", data.len());
            data
        },
        Err(e) => {
            eprintln!("Failed to serialize msg1: {:?}", e);
            return FFI_AbtCreateMsg1Result {
                state_cb_r1_ptr: ptr::null_mut(),
                state_cb_r1_size: 0,
                msg1_ptr: ptr::null_mut(),
                msg1_size: 0,
            };
        }
    };

    // Allocate memory for state_cb_r1
    let state_cb_r1_size = serialized_state_cb_r1.len();
    let state_cb_r1_layout = Layout::array::<u8>(state_cb_r1_size).unwrap();
    let state_cb_r1_ptr = unsafe { alloc(state_cb_r1_layout) };
    if state_cb_r1_ptr.is_null() {
        eprintln!("Memory allocation failed for state_cb_r1, size: {}", state_cb_r1_size);
        return FFI_AbtCreateMsg1Result {
            state_cb_r1_ptr: ptr::null_mut(),
            state_cb_r1_size: 0,
            msg1_ptr: ptr::null_mut(),
            msg1_size: 0,
        };
    }
    unsafe {
        state_cb_r1_ptr.copy_from_nonoverlapping(serialized_state_cb_r1.as_ptr(), state_cb_r1_size);
    }

    // Allocate memory for msg1
    let msg1_size = serialized_msg1.len();
    let msg1_layout = Layout::array::<u8>(msg1_size).unwrap();
    let msg1_ptr = unsafe { alloc(msg1_layout) };
    if msg1_ptr.is_null() {
        eprintln!("Memory allocation failed for msg1, size: {}", msg1_size);
        return FFI_AbtCreateMsg1Result {
            state_cb_r1_ptr: ptr::null_mut(),
            state_cb_r1_size: 0,
            msg1_ptr: ptr::null_mut(),
            msg1_size: 0,
        };
    }
    unsafe {
        msg1_ptr.copy_from_nonoverlapping(serialized_msg1.as_ptr(), msg1_size);
    }

    // Return result struct with pointers and sizes
    FFI_AbtCreateMsg1Result {
        state_cb_r1_ptr,
        state_cb_r1_size,
        msg1_ptr,
        msg1_size,
    }
}


#[repr(C)]
pub struct FFI_AbtProcessMsg1Result {
    state_ob_r1_ptr: *mut u8,
    state_ob_r1_size: usize,
    shares_ob_ptr: *mut u8,
    shares_ob_size: usize,
    auth_triples_ob_ptr: *mut u8,
    auth_triples_ob_size: usize,
    msg2_ptr: *mut u8,
    msg2_size: usize,
}

impl Default for FFI_AbtProcessMsg1Result {
    fn default() -> Self {
        FFI_AbtProcessMsg1Result {
            state_ob_r1_ptr: ptr::null_mut(),
            state_ob_r1_size: 0,
            shares_ob_ptr: ptr::null_mut(),
            shares_ob_size: 0,
            auth_triples_ob_ptr: ptr::null_mut(),
            auth_triples_ob_size: 0,
            msg2_ptr: ptr::null_mut(),
            msg2_size: 0,
        }
    }
}


#[no_mangle]
pub extern "C" fn ffi_abt_process_msg1(
    session_id_ptr: *const u8,
    session_id_size: usize,
    ot_seeds_ob_ptr: *const u8,
    ot_seeds_ob_size: usize,
    msg1_ptr: *const u8,
    msg1_size: usize,
    rng_ptr: *mut c_void,
) -> FFI_AbtProcessMsg1Result {
    if session_id_ptr.is_null() || session_id_size == 0 ||
       ot_seeds_ob_ptr.is_null() || ot_seeds_ob_size == 0 ||
       msg1_ptr.is_null() || msg1_size == 0 ||
       rng_ptr.is_null() {
        eprintln!("Invalid input pointers in ffi_abt_process_msg1");
        return FFI_AbtProcessMsg1Result::default();

    }

    // eprintln!(
    //     "Received session_id_size: {}, ot_seeds_ob_size: {}, msg1_size: {}",
    //     session_id_size, ot_seeds_ob_size, msg1_size
    // );

    // Deserialize session_id
    let session_id_bytes = unsafe { slice::from_raw_parts(session_id_ptr, session_id_size) };
    let session_id: [u8; 32] = match bincode::deserialize(session_id_bytes) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to deserialize session_id: {:?}", e);
            return FFI_AbtProcessMsg1Result::default();
        }
    };

    // Deserialize ot_seeds_ob
    let ot_seeds_ob_bytes = unsafe { slice::from_raw_parts(ot_seeds_ob_ptr, ot_seeds_ob_size) };
    let ot_seeds_ob: CFMInitOTSeedsOB = match bincode::deserialize(ot_seeds_ob_bytes) {
        Ok(seeds) => seeds,
        Err(e) => {
            eprintln!("Failed to deserialize ot_seeds_ob: {:?}", e);
            return FFI_AbtProcessMsg1Result::default();
        }
    };

    // Deserialize msg1
    let msg1_bytes = unsafe { slice::from_raw_parts(msg1_ptr, msg1_size) };
    let msg1: ABTMsg1 = match bincode::deserialize(msg1_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg1: {:?}", e);
            return FFI_AbtProcessMsg1Result::default();
        }
    };

    // Get RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Call `abt_process_msg1` function (with P, eta_i, eta_m inside)
    let p = P;
    let eta_i = NUMBER_OF_SHARES;
    let eta_m = NUMBER_OF_AUTH_BEAVER_TRIPLES;
    let (state_ob_r1, mut shares_ob, mut auth_triples_ob, msg2) =
        match abt_process_msg1(&session_id, &ot_seeds_ob, p, eta_i, eta_m, &msg1, rng) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Error in abt_process_msg1: {:?}", e);
                return FFI_AbtProcessMsg1Result::default();
            }
        };

    // Serialize outputs
    let serialized_state_ob_r1 = match bincode::serialize(&state_ob_r1) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize state_ob_r1: {:?}", e);
            return FFI_AbtProcessMsg1Result::default();
        }
    };

    let serialized_shares_ob = match bincode::serialize(&shares_ob) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize shares_ob: {:?}", e);
            return FFI_AbtProcessMsg1Result::default();
        }
    };

    let serialized_auth_triples_ob = match bincode::serialize(&auth_triples_ob) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize auth_triples_ob: {:?}", e);
            return FFI_AbtProcessMsg1Result::default();
        }
    };

    let serialized_msg2 = match bincode::serialize(&msg2) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg2: {:?}", e);
            return FFI_AbtProcessMsg1Result::default();
        }
    };

    // Allocate memory for outputs
    let state_ob_r1_ptr = unsafe { alloc(Layout::array::<u8>(serialized_state_ob_r1.len()).unwrap()) };
    let shares_ob_ptr = unsafe { alloc(Layout::array::<u8>(serialized_shares_ob.len()).unwrap()) };
    let auth_triples_ob_ptr = unsafe { alloc(Layout::array::<u8>(serialized_auth_triples_ob.len()).unwrap()) };
    let msg2_ptr = unsafe { alloc(Layout::array::<u8>(serialized_msg2.len()).unwrap()) };

    if state_ob_r1_ptr.is_null() || shares_ob_ptr.is_null() || auth_triples_ob_ptr.is_null() || msg2_ptr.is_null() {
        eprintln!("Memory allocation failed!");
        return FFI_AbtProcessMsg1Result::default();
    }

    unsafe {
        state_ob_r1_ptr.copy_from_nonoverlapping(serialized_state_ob_r1.as_ptr(), serialized_state_ob_r1.len());
        shares_ob_ptr.copy_from_nonoverlapping(serialized_shares_ob.as_ptr(), serialized_shares_ob.len());
        auth_triples_ob_ptr.copy_from_nonoverlapping(serialized_auth_triples_ob.as_ptr(), serialized_auth_triples_ob.len());
        msg2_ptr.copy_from_nonoverlapping(serialized_msg2.as_ptr(), serialized_msg2.len());
    }

    FFI_AbtProcessMsg1Result {
        state_ob_r1_ptr,
        state_ob_r1_size: serialized_state_ob_r1.len(),
        shares_ob_ptr,
        shares_ob_size: serialized_shares_ob.len(),
        auth_triples_ob_ptr,
        auth_triples_ob_size: serialized_auth_triples_ob.len(),
        msg2_ptr,
        msg2_size: serialized_msg2.len(),
    }
}


#[repr(C)]
pub struct FFI_AbtProcessMsg2Result {
    state_cb_r2_ptr: *mut u8,
    state_cb_r2_size: usize,
    shares_cb_ptr: *mut u8,
    shares_cb_size: usize,
    auth_triples_cb_ptr: *mut u8,
    auth_triples_cb_size: usize,
    msg3_ptr: *mut u8,
    msg3_size: usize,
}

impl Default for FFI_AbtProcessMsg2Result {
    fn default() -> Self {
        FFI_AbtProcessMsg2Result {
            state_cb_r2_ptr: ptr::null_mut(),
            state_cb_r2_size: 0,
            shares_cb_ptr: ptr::null_mut(),
            shares_cb_size: 0,
            auth_triples_cb_ptr: ptr::null_mut(),
            auth_triples_cb_size: 0,
            msg3_ptr: ptr::null_mut(),
            msg3_size: 0,
        }
    }
}


#[no_mangle]
pub extern "C" fn ffi_abt_process_msg2(
    state_cb_r1_ptr: *const u8,
    state_cb_r1_size: usize,
    ot_seeds_cb_ptr: *const u8,
    ot_seeds_cb_size: usize,
    msg2_ptr: *const u8,
    msg2_size: usize,
    rng_ptr: *mut c_void,
) -> FFI_AbtProcessMsg2Result {
    if state_cb_r1_ptr.is_null() || state_cb_r1_size == 0 ||
       ot_seeds_cb_ptr.is_null() || ot_seeds_cb_size == 0 ||
       msg2_ptr.is_null() || msg2_size == 0 ||
       rng_ptr.is_null() {
        eprintln!("Invalid input pointers in ffi_abt_process_msg2");
        return FFI_AbtProcessMsg2Result::default()
    }

    // Deserialize inputs
    let state_cb_r1_bytes = unsafe { slice::from_raw_parts(state_cb_r1_ptr, state_cb_r1_size) };
    let state_cb_r1: ABTStateCBR1 = match bincode::deserialize(state_cb_r1_bytes) {
        Ok(data) => data,
        Err(_) => return FFI_AbtProcessMsg2Result::default(),
    };

    let ot_seeds_cb_bytes = unsafe { slice::from_raw_parts(ot_seeds_cb_ptr, ot_seeds_cb_size) };
    let ot_seeds_cb: CFMInitOTSeedsCB = match bincode::deserialize(ot_seeds_cb_bytes) {
        Ok(data) => data,
        Err(_) => return FFI_AbtProcessMsg2Result::default(),
    };

    let msg2_bytes = unsafe { slice::from_raw_parts(msg2_ptr, msg2_size) };
    let msg2: ABTMsg2 = match bincode::deserialize(msg2_bytes) {
        Ok(data) => data,
        Err(_) => return FFI_AbtProcessMsg2Result::default(),
    };

    // Get RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Call Rust function
    let (state_cb_r2, shares_cb, auth_triples_cb, msg3) = match abt_process_msg2(&state_cb_r1, &ot_seeds_cb, &msg2, rng) {
        Ok(result) => result,
        Err(_) => return FFI_AbtProcessMsg2Result::default(),
    };

    // Serialize output
    let state_cb_r2_serialized = bincode::serialize(&state_cb_r2).unwrap_or_default();
    let shares_cb_serialized = bincode::serialize(&shares_cb).unwrap_or_default();
    let auth_triples_cb_serialized = bincode::serialize(&auth_triples_cb).unwrap_or_default();
    let msg3_serialized = bincode::serialize(&msg3).unwrap_or_default();

    // Allocate memory for output
    let state_cb_r2_ptr = allocate_memory(&state_cb_r2_serialized);
    let shares_cb_ptr = allocate_memory(&shares_cb_serialized);
    let auth_triples_cb_ptr = allocate_memory(&auth_triples_cb_serialized);
    let msg3_ptr = allocate_memory(&msg3_serialized);

    FFI_AbtProcessMsg2Result {
        state_cb_r2_ptr,
        state_cb_r2_size: state_cb_r2_serialized.len(),
        shares_cb_ptr,
        shares_cb_size: shares_cb_serialized.len(),
        auth_triples_cb_ptr,
        auth_triples_cb_size: auth_triples_cb_serialized.len(),
        msg3_ptr,
        msg3_size: msg3_serialized.len(),
    }
}

// Helper function to allocate memory for output
fn allocate_memory(data: &[u8]) -> *mut u8 {
    let size = data.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { ptr.copy_from_nonoverlapping(data.as_ptr(), size) };
    ptr
}


#[repr(C)]
pub struct FFI_AbtProcessMsg3Result {
    state_ob_r2_ptr: *mut u8,
    state_ob_r2_size: usize,
    shares_ob_ptr: *mut u8,
    shares_ob_size: usize,
    auth_triples_ob_ptr: *mut u8,
    auth_triples_ob_size: usize,
    msg4_ptr: *mut u8,
    msg4_size: usize,
}

impl Default for FFI_AbtProcessMsg3Result {
    fn default() -> Self {
        FFI_AbtProcessMsg3Result {
            state_ob_r2_ptr: std::ptr::null_mut(),
            state_ob_r2_size: 0,
            shares_ob_ptr: std::ptr::null_mut(),
            shares_ob_size: 0,
            auth_triples_ob_ptr: std::ptr::null_mut(),
            auth_triples_ob_size: 0,
            msg4_ptr: std::ptr::null_mut(),
            msg4_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_abt_process_msg3(
    state_ob_r1_ptr: *const u8,
    state_ob_r1_size: usize,
    shares_ob_ptr: *mut u8,
    shares_ob_size: usize,
    auth_triples_ob_ptr: *mut u8,
    auth_triples_ob_size: usize,
    msg3_ptr: *const u8,
    msg3_size: usize,
) -> FFI_AbtProcessMsg3Result {
    if state_ob_r1_ptr.is_null() || state_ob_r1_size == 0 ||
       shares_ob_ptr.is_null() || shares_ob_size == 0 ||
       auth_triples_ob_ptr.is_null() || auth_triples_ob_size == 0 ||
       msg3_ptr.is_null() || msg3_size == 0 {
        eprintln!("Invalid input pointers in ffi_abt_process_msg3");
        return FFI_AbtProcessMsg3Result::default()
    }

    // Deserialize state_ob_r1
    let state_ob_r1_bytes = unsafe { slice::from_raw_parts(state_ob_r1_ptr, state_ob_r1_size) };
    let state_ob_r1: ABTStateOBR1 = match bincode::deserialize(state_ob_r1_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize state_ob_r1: {:?}", e);
            return FFI_AbtProcessMsg3Result::default()
        }
    };

    // Deserialize shares_ob (Mutable)
    let shares_ob_bytes = unsafe { slice::from_raw_parts_mut(shares_ob_ptr, shares_ob_size) };
    let mut shares_ob: Vec<Share>  = match bincode::deserialize(shares_ob_bytes) {
        Ok(shares) => shares,
        Err(e) => {
            eprintln!("Failed to deserialize shares_ob: {:?}", e);
            return FFI_AbtProcessMsg3Result::default();
        }
    };

    // Deserialize auth_triples_ob (Mutable)
    let auth_triples_ob_bytes = unsafe { slice::from_raw_parts_mut(auth_triples_ob_ptr, auth_triples_ob_size) };
    let mut auth_triples_ob: Vec<TripleShare> = match bincode::deserialize(auth_triples_ob_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_ob: {:?}", e);
            return FFI_AbtProcessMsg3Result::default();
        }
    };

    // Deserialize msg3
    let msg3_bytes = unsafe { slice::from_raw_parts(msg3_ptr, msg3_size) };
    let msg3: ABTMsg3 = match bincode::deserialize(msg3_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg3: {:?}", e);
            return FFI_AbtProcessMsg3Result::default()
        }
    };

    // Call the actual function
    let (state_ob_r2, msg4) = match abt_process_msg3(&state_ob_r1, &mut shares_ob, &mut auth_triples_ob, &msg3) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in abt_process_msg3: {:?}", e);
            return FFI_AbtProcessMsg3Result::default()
        }
    };

    // Serialize outputs
    let serialized_state_ob_r2 = match bincode::serialize(&state_ob_r2) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize state_ob_r2: {:?}", e);
            return FFI_AbtProcessMsg3Result::default()
        }
    };

    let serialized_shares_ob = match bincode::serialize(&shares_ob) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize updated shares_ob: {:?}", e);
            return FFI_AbtProcessMsg3Result::default()
        }
    };

    let serialized_auth_triples_ob = match bincode::serialize(&auth_triples_ob) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize updated auth_triples_ob: {:?}", e);
            return FFI_AbtProcessMsg3Result::default()
        }
    };

    let serialized_msg4 = match bincode::serialize(&msg4) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg4: {:?}", e);
            return FFI_AbtProcessMsg3Result::default()
        }
    };

    // Allocate heap memory for the serialized outputs
    let state_ob_r2_ptr = unsafe { alloc(Layout::array::<u8>(serialized_state_ob_r2.len()).unwrap()) };
    let shares_ob_ptr = unsafe { alloc(Layout::array::<u8>(serialized_shares_ob.len()).unwrap()) };
    let auth_triples_ob_ptr = unsafe { alloc(Layout::array::<u8>(serialized_auth_triples_ob.len()).unwrap()) };
    let msg4_ptr = unsafe { alloc(Layout::array::<u8>(serialized_msg4.len()).unwrap()) };

    if state_ob_r2_ptr.is_null() || shares_ob_ptr.is_null() || auth_triples_ob_ptr.is_null() || msg4_ptr.is_null() {
        eprintln!("Memory allocation failed for one or more return values.");
        return FFI_AbtProcessMsg3Result::default()
    }

    // Copy serialized data
    unsafe {
        state_ob_r2_ptr.copy_from_nonoverlapping(serialized_state_ob_r2.as_ptr(), serialized_state_ob_r2.len());
        shares_ob_ptr.copy_from_nonoverlapping(serialized_shares_ob.as_ptr(), serialized_shares_ob.len());
        auth_triples_ob_ptr.copy_from_nonoverlapping(serialized_auth_triples_ob.as_ptr(), serialized_auth_triples_ob.len());
        msg4_ptr.copy_from_nonoverlapping(serialized_msg4.as_ptr(), serialized_msg4.len());
    }

    // Return struct with allocated memory
    FFI_AbtProcessMsg3Result {
        state_ob_r2_ptr,
        state_ob_r2_size: serialized_state_ob_r2.len(),
        shares_ob_ptr,
        shares_ob_size: serialized_shares_ob.len(),
        auth_triples_ob_ptr,
        auth_triples_ob_size: serialized_auth_triples_ob.len(),
        msg4_ptr,
        msg4_size: serialized_msg4.len(),
    }
}


#[repr(C)]
pub struct FFI_AbtProcessMsg4Result {
    msg5_ptr: *mut u8,
    msg5_size: usize,
}

impl Default for FFI_AbtProcessMsg4Result {
    fn default() -> Self {
        FFI_AbtProcessMsg4Result {
            msg5_ptr: std::ptr::null_mut(),
            msg5_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_abt_process_msg4(
    state_cb_r2_ptr: *const u8,
    state_cb_r2_size: usize,
    auth_triples_cb_ptr: *const u8,
    auth_triples_cb_size: usize,
    msg4_ptr: *const u8,
    msg4_size: usize,
) -> FFI_AbtProcessMsg4Result {
    if state_cb_r2_ptr.is_null() || state_cb_r2_size == 0 ||
       auth_triples_cb_ptr.is_null() || auth_triples_cb_size == 0 ||
       msg4_ptr.is_null() || msg4_size == 0 {
        eprintln!("Invalid input pointers in ffi_abt_process_msg4");
        return FFI_AbtProcessMsg4Result::default();
    }

    // Deserialize state_cb_r2
    let state_cb_r2_bytes = unsafe { slice::from_raw_parts(state_cb_r2_ptr, state_cb_r2_size) };
    let state_cb_r2: ABTStateCBR2 = match bincode::deserialize(state_cb_r2_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize state_cb_r2: {:?}", e);
            return FFI_AbtProcessMsg4Result::default();
        }
    };

    // Deserialize auth_triples_cb
    let auth_triples_cb_bytes = unsafe { slice::from_raw_parts(auth_triples_cb_ptr, auth_triples_cb_size) };
    let auth_triples_cb: Vec<TripleShare> = match bincode::deserialize(auth_triples_cb_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_cb: {:?}", e);
            return FFI_AbtProcessMsg4Result::default();
        }
    };

    // Deserialize msg4
    let msg4_bytes = unsafe { slice::from_raw_parts(msg4_ptr, msg4_size) };
    let msg4: ABTMsg4 = match bincode::deserialize(msg4_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg4: {:?}", e);
            return FFI_AbtProcessMsg4Result::default();
        }
    };

    // Call the actual function
    let msg5 = match abt_process_msg4(&state_cb_r2, &auth_triples_cb, &msg4) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Error in abt_process_msg4: {:?}", e);
            return FFI_AbtProcessMsg4Result::default();
        }
    };

    // Serialize msg5
    let serialized_msg5 = match bincode::serialize(&msg5) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg5: {:?}", e);
            return FFI_AbtProcessMsg4Result::default();
        }
    };

    // Allocate memory for msg5
    let size = serialized_msg5.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("Memory allocation failed for msg5, size: {}", size);
        return FFI_AbtProcessMsg4Result::default();
    }

    // Copy serialized msg5 data
    unsafe {
        ptr.copy_from_nonoverlapping(serialized_msg5.as_ptr(), size);
    }

    FFI_AbtProcessMsg4Result {
        msg5_ptr: ptr,
        msg5_size: size,
    }
}


#[no_mangle]
pub extern "C" fn ffi_abt_process_msg5(
    state_ob_r2_ptr: *const u8,
    state_ob_r2_size: usize,
    msg5_ptr: *const u8,
    msg5_size: usize,
) {
    if state_ob_r2_ptr.is_null() || state_ob_r2_size == 0 ||
       msg5_ptr.is_null() || msg5_size == 0 {
        eprintln!("Invalid input pointers in ffi_abt_process_msg5");
        return;
    }

    // Deserialize state_ob_r2
    let state_ob_r2_bytes = unsafe { slice::from_raw_parts(state_ob_r2_ptr, state_ob_r2_size) };
    let state_ob_r2: ABTStateOBR2 = match bincode::deserialize(state_ob_r2_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize state_ob_r2: {:?}", e);
            return;
        }
    };

    // Deserialize msg5
    let msg5_bytes = unsafe { slice::from_raw_parts(msg5_ptr, msg5_size) };
    let msg5: ABTMsg5 = match bincode::deserialize(msg5_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg5: {:?}", e);
            return;
        }
    };

    // Call the actual function
    if let Err(e) = abt_process_msg5(&state_ob_r2, &msg5) {
        eprintln!("Error in abt_process_msg5: {:?}", e);
    }
}


#[no_mangle]
pub extern "C" fn ffi_hash_customers(
    customers_json_ptr: *const c_char,
    is_list: bool,
    out_size: *mut usize,
) -> *mut u8 {
    if customers_json_ptr.is_null() || out_size.is_null() {
        eprintln!("Invalid input to ffi_hash_customers.");
        return std::ptr::null_mut();
    }

    // Convert C string to Rust String
    let c_str = unsafe { CStr::from_ptr(customers_json_ptr) };
    let customers_json = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Failed to convert C string.");
            return std::ptr::null_mut();
        }
    };

    let serialized_data = if is_list {
        // Deserialize JSON into a Vec<Customer>
        let customers: Vec<Customer> = match serde_json::from_str(customers_json) {
            Ok(list) => list,
            Err(e) => {
                eprintln!("Failed to deserialize list of customers: {:?}", e);
                return std::ptr::null_mut();
            }
        };

        let hashes: Vec<[u8; 32]> = customers.iter().map(|c| c.to_hash_bytes()).collect();
        match bincode::serialize(&hashes) {
            Ok(data) => data,
            Err(_) => return std::ptr::null_mut(),
        }
    } else {
        // Deserialize JSON into a single Customer
        let customer: Customer = match serde_json::from_str(customers_json) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to deserialize single customer: {:?}", e);
                return std::ptr::null_mut();
            }
        };

        let hash_bytes = customer.to_hash_bytes();
        match bincode::serialize(&hash_bytes) {
            Ok(data) => data,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    // Allocate memory using `alloc()` instead of `malloc()`
    let size = serialized_data.len();
    let layout = Layout::array::<u8>(size).unwrap();
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("Memory allocation failed.");
        return std::ptr::null_mut();
    }

    // Copy serialized data into allocated memory
    unsafe {
        ptr.copy_from_nonoverlapping(serialized_data.as_ptr(), size);
        *out_size = size;
    }

    ptr
}


#[repr(C)]
pub struct FFI_CfmCreateMsg1Result {
    cfm_state_ob_r1_ptr: *mut u8,
    cfm_state_ob_r1_size: usize,
    msg1_ptr: *mut u8,
    msg1_size: usize,
}

impl Default for FFI_CfmCreateMsg1Result {
    fn default() -> Self {
        FFI_CfmCreateMsg1Result {
            cfm_state_ob_r1_ptr: std::ptr::null_mut(),
            cfm_state_ob_r1_size: 0,
            msg1_ptr: std::ptr::null_mut(),
            msg1_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_create_msg1(
    session_id_ptr: *const u8,
    session_id_size: usize,
    big_l: u64,
    big_x: u64,
    customer_y_bytes_ptr: *const u8,
    customer_y_bytes_size: usize,
    shares_ob_ptr: *const u8,
    shares_ob_size: usize,
    rng_ptr: *mut c_void,
) -> FFI_CfmCreateMsg1Result {
    if session_id_ptr.is_null() || session_id_size == 0 ||
       customer_y_bytes_ptr.is_null() || customer_y_bytes_size == 0 ||
       shares_ob_ptr.is_null() || shares_ob_size == 0 ||
       rng_ptr.is_null() {
        eprintln!("Invalid input pointers in ffi_cfm_create_msg1");
        return FFI_CfmCreateMsg1Result::default()
    }

    // Deserialize session_id
    let session_id_bytes = unsafe { slice::from_raw_parts(session_id_ptr, session_id_size) };
    let session_id: [u8; 32] = match bincode::deserialize(session_id_bytes) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to deserialize session_id: {:?}", e);
            return FFI_CfmCreateMsg1Result::default()
        }
    };

    // Convert big_l and big_x into U64
    let big_l = U64::from(big_l);
    let big_x = U64::from(big_x);

    // Deserialize customer_y_bytes
    let customer_y_bytes_bytes = unsafe { slice::from_raw_parts(customer_y_bytes_ptr, customer_y_bytes_size) };
    let customer_y_bytes: [u8; 32] = match bincode::deserialize(customer_y_bytes_bytes) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to deserialize customer_y_bytes: {:?}", e);
            return FFI_CfmCreateMsg1Result::default()
        }
    };

    // Deserialize shares_ob (Mutable)
    let shares_ob_bytes = unsafe { slice::from_raw_parts(shares_ob_ptr, shares_ob_size) };
    let shares_ob: Vec<Share> = match bincode::deserialize(shares_ob_bytes) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to deserialize shares_ob: {:?}", e);
            return FFI_CfmCreateMsg1Result::default()
        }
    };

    // Get RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Call the actual function
    let (cfm_state_ob_r1, msg1) = cfm_create_msg1(
        &session_id,
        P,
        big_l,
        big_x,
        &customer_y_bytes,
        &shares_ob,
        rng,
    );

    // Serialize cfm_state_ob_r1
    let serialized_cfm_state_ob_r1 = match bincode::serialize(&cfm_state_ob_r1) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r1: {:?}", e);
            return FFI_CfmCreateMsg1Result::default()
        }
    };

    // Serialize msg1
    let serialized_msg1 = match bincode::serialize(&msg1) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg1: {:?}", e);
            return FFI_CfmCreateMsg1Result::default()
        }
    };

    // Allocate memory for serialized cfm_state_ob_r1
    let cfm_state_ob_r1_size = serialized_cfm_state_ob_r1.len();
    let cfm_state_ob_r1_layout = Layout::array::<u8>(cfm_state_ob_r1_size).unwrap();
    let cfm_state_ob_r1_ptr = unsafe { alloc(cfm_state_ob_r1_layout) };
    unsafe {
        cfm_state_ob_r1_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r1.as_ptr(), cfm_state_ob_r1_size);
    }

    // Allocate memory for serialized msg1
    let msg1_size = serialized_msg1.len();
    let msg1_layout = Layout::array::<u8>(msg1_size).unwrap();
    let msg1_ptr = unsafe { alloc(msg1_layout) };
    unsafe {
        msg1_ptr.copy_from_nonoverlapping(serialized_msg1.as_ptr(), msg1_size);
    }

    // Return the struct containing pointers and sizes
    FFI_CfmCreateMsg1Result {
        cfm_state_ob_r1_ptr,
        cfm_state_ob_r1_size,
        msg1_ptr,
        msg1_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg1Result {
    cfm_state_cb_r1_ptr: *mut u8,
    cfm_state_cb_r1_size: usize,
    msg2_ptr: *mut u8,
    msg2_size: usize,
}

impl Default for FFI_CfmProcessMsg1Result {
    fn default() -> Self {
        FFI_CfmProcessMsg1Result {
            cfm_state_cb_r1_ptr: ptr::null_mut(),
            cfm_state_cb_r1_size: 0,
            msg2_ptr: ptr::null_mut(),
            msg2_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg1(
    session_id_ptr: *const u8,
    session_id_size: usize,
    big_l: u64,
    big_y_bytes_ptr: *const u8,
    big_y_bytes_size: usize,
    big_z_ptr: *const u64, // Now receiving a pointer to u64 integers (array)
    big_z_size: usize,     // Number of elements in big_z
    shares_cb_ptr: *const u8,
    shares_cb_size: usize,
    msg1_ptr: *const u8,
    msg1_size: usize,
    rng_ptr: *mut c_void,
) -> FFI_CfmProcessMsg1Result {
    if session_id_ptr.is_null() || session_id_size == 0 ||
       big_y_bytes_ptr.is_null() || big_y_bytes_size == 0 ||
       big_z_ptr.is_null() || big_z_size == 0 ||
       shares_cb_ptr.is_null() || shares_cb_size == 0 ||
       msg1_ptr.is_null() || msg1_size == 0 ||
       rng_ptr.is_null() {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg1");
        return FFI_CfmProcessMsg1Result::default();
    }

    // Deserialize session_id
    let session_id_bytes = unsafe { slice::from_raw_parts(session_id_ptr, session_id_size) };
    let session_id: [u8; 32] = match bincode::deserialize(session_id_bytes) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to deserialize session_id: {:?}", e);
            return FFI_CfmProcessMsg1Result::default();
        }
    };

    // Convert big_l into U64
    let big_l = U64::from(big_l);

    // Deserialize big_y_bytes (Vec<[u8; 32]>)
    let big_y_bytes_data = unsafe { slice::from_raw_parts(big_y_bytes_ptr, big_y_bytes_size) };
    let big_y_bytes: Vec<[u8; 32]> = match bincode::deserialize(big_y_bytes_data) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to deserialize big_y_bytes: {:?}", e);
            return FFI_CfmProcessMsg1Result::default();
        }
    };


    let concatenated_hex = big_y_bytes
    .iter()
    .flat_map(|hash| hash.iter().map(|b| format!("{:02x}", b)))
    .collect::<String>();
    // println!("CUSTOMER LIST HASH IS {:#?}", concatenated_hex);

    // ✅ **Fix: Deserialize big_y_bytes as Vec<[u8; 32]>**
    // let big_y_bytes_data = unsafe { slice::from_raw_parts(big_y_bytes_ptr, big_y_bytes_size) };

    // // Ensure the size is valid (320 bytes should be exactly 10 elements of [u8; 32])
    // if big_y_bytes_data.len() % 32 != 0 {
    //     eprintln!("big_y_bytes size mismatch! Expected multiple of 32, got {}", big_y_bytes_data.len());
    //     return FFI_CfmProcessMsg1Result::default();
    // }

    // let big_y_bytes: Vec<[u8; 32]> = big_y_bytes_data
    //     .chunks_exact(32)
    //     .map(|chunk| {
    //         let mut array = [0u8; 32];
    //         array.copy_from_slice(chunk);
    //         array
    //     })
    //     .collect();

    // println!("Successfully deserialized big_y_bytes as Vec<[u8; 32]>: {} elements", big_y_bytes.len());
    

    // Convert big_z (Vec<U64>) from an array of u64 values
    let big_z_values = unsafe { slice::from_raw_parts(big_z_ptr, big_z_size) };
    let big_z: Vec<U64> = big_z_values.iter().map(|&val| U64::from(val)).collect();

    // Deserialize shares_cb
    let shares_cb_data = unsafe { slice::from_raw_parts(shares_cb_ptr, shares_cb_size) };
    let shares_cb: Vec<Share> = match bincode::deserialize(shares_cb_data) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to deserialize shares_cb: {:?}", e);
            return FFI_CfmProcessMsg1Result::default();
        }
    };

    // Deserialize msg1
    let msg1_data = unsafe { slice::from_raw_parts(msg1_ptr, msg1_size) };
    let msg1:  Box<CFMMsg1> = match bincode::deserialize(msg1_data) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg1: {:?}", e);
            return FFI_CfmProcessMsg1Result::default();
        }
    };

    // Get RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Call the actual function
    let (cfm_state_cb_r1, msg2) = match cfm_process_msg1(
        &session_id,
        P,
        big_l,
        big_y_bytes,
        big_z,
        &shares_cb,
        &msg1,
        rng,
    ) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("cfm_process_msg1 failed: {:?}", e);
            return FFI_CfmProcessMsg1Result::default();
        }
    };

    // Serialize cfm_state_cb_r1
    let serialized_cfm_state_cb_r1 = match bincode::serialize(&cfm_state_cb_r1) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_cb_r1: {:?}", e);
            return FFI_CfmProcessMsg1Result::default();
        }
    };

    // Serialize msg2
    let serialized_msg2 = match bincode::serialize(&msg2) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg2: {:?}", e);
            return FFI_CfmProcessMsg1Result::default();
        }
    };

    // Allocate memory for serialized cfm_state_cb_r1
    let cfm_state_cb_r1_size = serialized_cfm_state_cb_r1.len();
    let cfm_state_cb_r1_layout = Layout::array::<u8>(cfm_state_cb_r1_size).unwrap();
    let cfm_state_cb_r1_ptr = unsafe { alloc(cfm_state_cb_r1_layout) };
    unsafe {
        cfm_state_cb_r1_ptr.copy_from_nonoverlapping(serialized_cfm_state_cb_r1.as_ptr(), cfm_state_cb_r1_size);
    }

    // Allocate memory for serialized msg2
    let msg2_size = serialized_msg2.len();
    let msg2_layout = Layout::array::<u8>(msg2_size).unwrap();
    let msg2_ptr = unsafe { alloc(msg2_layout) };
    unsafe {
        msg2_ptr.copy_from_nonoverlapping(serialized_msg2.as_ptr(), msg2_size);
    }

    // Return the struct containing pointers and sizes
    FFI_CfmProcessMsg1Result {
        cfm_state_cb_r1_ptr,
        cfm_state_cb_r1_size,
        msg2_ptr,
        msg2_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg2Result {
    pub cfm_state_ob_r2_ptr: *mut u8,
    pub cfm_state_ob_r2_size: usize,
    pub msg3_ptr: *mut u8,
    pub msg3_size: usize,
}

impl Default for FFI_CfmProcessMsg2Result {
    fn default() -> Self {
        FFI_CfmProcessMsg2Result {
            cfm_state_ob_r2_ptr: ptr::null_mut(),
            cfm_state_ob_r2_size: 0,
            msg3_ptr: ptr::null_mut(),
            msg3_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg2(
    cfm_state_ob_r1_ptr: *const u8,
    cfm_state_ob_r1_size: usize,
    shares_ob_ptr: *const u8,
    shares_ob_size: usize,
    auth_triples_ob_ptr: *const u8,
    auth_triples_ob_size: usize,
    msg2_ptr: *const u8,
    msg2_size: usize,
    rng_ptr: *mut c_void,
) -> FFI_CfmProcessMsg2Result {
    if cfm_state_ob_r1_ptr.is_null() || cfm_state_ob_r1_size == 0 ||
       shares_ob_ptr.is_null() || shares_ob_size == 0 ||
       auth_triples_ob_ptr.is_null() || auth_triples_ob_size == 0 ||
       msg2_ptr.is_null() || msg2_size == 0 ||
       rng_ptr.is_null() {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg2");
        return FFI_CfmProcessMsg2Result::default();
    }

    // ✅ Deserialize cfm_state_ob_r1
    let cfm_state_ob_r1_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r1_ptr, cfm_state_ob_r1_size) };
    let cfm_state_ob_r1: CFMStateOBR1 = match bincode::deserialize(cfm_state_ob_r1_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r1: {:?}", e);
            return FFI_CfmProcessMsg2Result::default();
        }
    };

    // ✅ Deserialize shares_ob
    let shares_ob_bytes = unsafe { slice::from_raw_parts(shares_ob_ptr, shares_ob_size) };
    let shares_ob: Vec<Share> = match bincode::deserialize(shares_ob_bytes) {
        Ok(shares) => shares,
        Err(e) => {
            eprintln!("Failed to deserialize shares_ob: {:?}", e);
            return FFI_CfmProcessMsg2Result::default();
        }
    };

    // ✅ Deserialize auth_triples_ob
    let auth_triples_ob_bytes = unsafe { slice::from_raw_parts(auth_triples_ob_ptr, auth_triples_ob_size) };
    let auth_triples_ob: Vec<TripleShare> = match bincode::deserialize(auth_triples_ob_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_ob: {:?}", e);
            return FFI_CfmProcessMsg2Result::default();
        }
    };

    // ✅ Deserialize msg2
    let msg2_bytes = unsafe { slice::from_raw_parts(msg2_ptr, msg2_size) };
    let msg2: Box<CFMMsg2> = match bincode::deserialize(msg2_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg2: {:?}", e);
            return FFI_CfmProcessMsg2Result::default();
        }
    };

    // ✅ Get RNG reference
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // ✅ Call the actual function
    let (cfm_state_ob_r2, msg3) = match cfm_process_msg2(
        &cfm_state_ob_r1,
        &shares_ob,
        &auth_triples_ob,
        &msg2,
        rng,
    ) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("cfm_process_msg2 failed: {:?}", e);
            return FFI_CfmProcessMsg2Result::default();
        }
    };

    // ✅ Serialize cfm_state_ob_r2
    let serialized_cfm_state_ob_r2 = match bincode::serialize(&cfm_state_ob_r2) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r2: {:?}", e);
            return FFI_CfmProcessMsg2Result::default();
        }
    };

    // ✅ Serialize msg3
    let serialized_msg3 = match bincode::serialize(&msg3) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg3: {:?}", e);
            return FFI_CfmProcessMsg2Result::default();
        }
    };

    // ✅ Allocate memory for serialized cfm_state_ob_r2
    let cfm_state_ob_r2_size = serialized_cfm_state_ob_r2.len();
    let cfm_state_ob_r2_ptr = unsafe { alloc(Layout::array::<u8>(cfm_state_ob_r2_size).unwrap()) };
    unsafe {
        cfm_state_ob_r2_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r2.as_ptr(), cfm_state_ob_r2_size);
    }

    // ✅ Allocate memory for serialized msg3
    let msg3_size = serialized_msg3.len();
    let msg3_ptr = unsafe { alloc(Layout::array::<u8>(msg3_size).unwrap()) };
    unsafe {
        msg3_ptr.copy_from_nonoverlapping(serialized_msg3.as_ptr(), msg3_size);
    }

    // ✅ Return the struct containing pointers and sizes
    FFI_CfmProcessMsg2Result {
        cfm_state_ob_r2_ptr,
        cfm_state_ob_r2_size,
        msg3_ptr,
        msg3_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg3Result {
    pub cfm_state_cb_r2_ptr: *mut u8,
    pub cfm_state_cb_r2_size: usize,
    pub msg4_ptr: *mut u8,
    pub msg4_size: usize,
}

impl Default for FFI_CfmProcessMsg3Result {
    fn default() -> Self {
        FFI_CfmProcessMsg3Result {
            cfm_state_cb_r2_ptr: std::ptr::null_mut(),
            cfm_state_cb_r2_size: 0,
            msg4_ptr: std::ptr::null_mut(),
            msg4_size: 0,
        }
    }
}


#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg3(
    cfm_state_cb_r1_ptr: *const u8,
    cfm_state_cb_r1_size: usize,
    shares_cb_ptr: *const u8,
    shares_cb_size: usize,
    auth_triples_cb_ptr: *const u8,
    auth_triples_cb_size: usize,
    msg3_ptr: *const u8,
    msg3_size: usize,
) -> FFI_CfmProcessMsg3Result {
    if cfm_state_cb_r1_ptr.is_null() || cfm_state_cb_r1_size == 0 ||
       shares_cb_ptr.is_null() || shares_cb_size == 0 ||
       auth_triples_cb_ptr.is_null() || auth_triples_cb_size == 0 ||
       msg3_ptr.is_null() || msg3_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg3");
        return FFI_CfmProcessMsg3Result::default();
    }

    // Deserialize `cfm_state_cb_r1`
    let cfm_state_cb_r1_bytes = unsafe { slice::from_raw_parts(cfm_state_cb_r1_ptr, cfm_state_cb_r1_size) };
    let cfm_state_cb_r1: Box<CFMStateCBR1> = match bincode::deserialize(cfm_state_cb_r1_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_cb_r1: {:?}", e);
            return FFI_CfmProcessMsg3Result::default();
        }
    };

    // Deserialize `shares_cb`
    let shares_cb_bytes = unsafe { slice::from_raw_parts(shares_cb_ptr, shares_cb_size) };
    let shares_cb: Vec<Share> = match bincode::deserialize(shares_cb_bytes) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to deserialize shares_cb: {:?}", e);
            return FFI_CfmProcessMsg3Result::default();
        }
    };

    // Deserialize `auth_triples_cb`
    let auth_triples_cb_bytes = unsafe { slice::from_raw_parts(auth_triples_cb_ptr, auth_triples_cb_size) };
    let auth_triples_cb: Vec<TripleShare> = match bincode::deserialize(auth_triples_cb_bytes) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_cb: {:?}", e);
            return FFI_CfmProcessMsg3Result::default();
        }
    };

    // Deserialize `msg3`
    let msg3_bytes = unsafe { slice::from_raw_parts(msg3_ptr, msg3_size) };
    let msg3: Box<CFMMsg3> = match bincode::deserialize(msg3_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg3: {:?}", e);
            return FFI_CfmProcessMsg3Result::default();
        }
    };

    // Call `cfm_process_msg3`
    let (cfm_state_cb_r2, msg4) = match cfm_process_msg3(cfm_state_cb_r1, &shares_cb, &auth_triples_cb, &msg3) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("cfm_process_msg3 failed: {:?}", e);
            return FFI_CfmProcessMsg3Result::default();
        }
    };

    // Serialize `cfm_state_cb_r2`
    let serialized_cfm_state_cb_r2 = match bincode::serialize(&cfm_state_cb_r2) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_cb_r2: {:?}", e);
            return FFI_CfmProcessMsg3Result::default();
        }
    };

    // Serialize `msg4`
    let serialized_msg4 = match bincode::serialize(&msg4) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg4: {:?}", e);
            return FFI_CfmProcessMsg3Result::default();
        }
    };

    // Allocate memory for `cfm_state_cb_r2`
    let cfm_state_cb_r2_size = serialized_cfm_state_cb_r2.len();
    let cfm_state_cb_r2_layout = Layout::array::<u8>(cfm_state_cb_r2_size).unwrap();
    let cfm_state_cb_r2_ptr = unsafe { alloc(cfm_state_cb_r2_layout) };
    unsafe {
        cfm_state_cb_r2_ptr.copy_from_nonoverlapping(serialized_cfm_state_cb_r2.as_ptr(), cfm_state_cb_r2_size);
    }

    // Allocate memory for `msg4`
    let msg4_size = serialized_msg4.len();
    let msg4_layout = Layout::array::<u8>(msg4_size).unwrap();
    let msg4_ptr = unsafe { alloc(msg4_layout) };
    unsafe {
        msg4_ptr.copy_from_nonoverlapping(serialized_msg4.as_ptr(), msg4_size);
    }

    // Return FFI struct containing pointers and sizes
    FFI_CfmProcessMsg3Result {
        cfm_state_cb_r2_ptr,
        cfm_state_cb_r2_size,
        msg4_ptr,
        msg4_size,
    }
}


pub struct FFI_CfmProcessMsg4Result {
    cfm_state_ob_r3_ptr: *mut u8,
    cfm_state_ob_r3_size: usize,
    msg5_ptr: *mut u8,
    msg5_size: usize,
}

impl Default for FFI_CfmProcessMsg4Result {
    fn default() -> Self {
        FFI_CfmProcessMsg4Result {
            cfm_state_ob_r3_ptr: ptr::null_mut(),
            cfm_state_ob_r3_size: 0,
            msg5_ptr: ptr::null_mut(),
            msg5_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg4(
    cfm_state_ob_r2_ptr: *const u8,
    cfm_state_ob_r2_size: usize,
    msg4_ptr: *const u8,
    msg4_size: usize,
) -> FFI_CfmProcessMsg4Result {
    if cfm_state_ob_r2_ptr.is_null() || cfm_state_ob_r2_size == 0 || 
       msg4_ptr.is_null() || msg4_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg4");
        return FFI_CfmProcessMsg4Result::default();
    }

    // Deserialize cfm_state_ob_r2
    let cfm_state_ob_r2_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r2_ptr, cfm_state_ob_r2_size) };
    let cfm_state_ob_r2: Box<CFMStateOBR2> = match bincode::deserialize(cfm_state_ob_r2_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r2: {:?}", e);
            return FFI_CfmProcessMsg4Result::default();
        }
    };

    // Deserialize msg4
    let msg4_bytes = unsafe { slice::from_raw_parts(msg4_ptr, msg4_size) };
    let msg4: Box<CFMMsg4> = match bincode::deserialize(msg4_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg4: {:?}", e);
            return FFI_CfmProcessMsg4Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_ob_r3, msg5) = match cfm_process_msg4(cfm_state_ob_r2, &msg4) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg4: {:?}", e);
            return FFI_CfmProcessMsg4Result::default();
        }
    };

    // Serialize cfm_state_ob_r3
    let serialized_cfm_state_ob_r3 = match bincode::serialize(&cfm_state_ob_r3) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r3: {:?}", e);
            return FFI_CfmProcessMsg4Result::default();
        }
    };

    // Serialize msg5
    let serialized_msg5 = match bincode::serialize(&msg5) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg5: {:?}", e);
            return FFI_CfmProcessMsg4Result::default();
        }
    };

    // Allocate memory for cfm_state_ob_r3
    let cfm_state_ob_r3_size = serialized_cfm_state_ob_r3.len();
    let cfm_state_ob_r3_layout = Layout::array::<u8>(cfm_state_ob_r3_size).unwrap();
    let cfm_state_ob_r3_ptr = unsafe { alloc(cfm_state_ob_r3_layout) };
    unsafe {
        cfm_state_ob_r3_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r3.as_ptr(), cfm_state_ob_r3_size);
    }

    // Allocate memory for msg5
    let msg5_size = serialized_msg5.len();
    let msg5_layout = Layout::array::<u8>(msg5_size).unwrap();
    let msg5_ptr = unsafe { alloc(msg5_layout) };
    unsafe {
        msg5_ptr.copy_from_nonoverlapping(serialized_msg5.as_ptr(), msg5_size);
    }

    // Return the struct containing pointers and sizes
    FFI_CfmProcessMsg4Result {
        cfm_state_ob_r3_ptr,
        cfm_state_ob_r3_size,
        msg5_ptr,
        msg5_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg5Result {
    cfm_state_cb_r3_ptr: *mut u8,
    cfm_state_cb_r3_size: usize,
    msg6_ptr: *mut u8,
    msg6_size: usize,
}

impl Default for FFI_CfmProcessMsg5Result {
    fn default() -> Self {
        FFI_CfmProcessMsg5Result {
            cfm_state_cb_r3_ptr: ptr::null_mut(),
            cfm_state_cb_r3_size: 0,
            msg6_ptr: ptr::null_mut(),
            msg6_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg5(
    cfm_state_cb_r2_ptr: *const u8,
    cfm_state_cb_r2_size: usize,
    auth_triples_cb_ptr: *const u8,
    auth_triples_cb_size: usize,
    msg5_ptr: *const u8,
    msg5_size: usize,
) -> FFI_CfmProcessMsg5Result {
    if cfm_state_cb_r2_ptr.is_null() || cfm_state_cb_r2_size == 0 ||
       auth_triples_cb_ptr.is_null() || auth_triples_cb_size == 0 ||
       msg5_ptr.is_null() || msg5_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg5");
        return FFI_CfmProcessMsg5Result::default();
    }

    // Deserialize cfm_state_cb_r2
    let cfm_state_cb_r2_bytes = unsafe { slice::from_raw_parts(cfm_state_cb_r2_ptr, cfm_state_cb_r2_size) };
    let cfm_state_cb_r2: Box<CFMStateCBR2> = match bincode::deserialize(cfm_state_cb_r2_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_cb_r2: {:?}", e);
            return FFI_CfmProcessMsg5Result::default();
        }
    };

    // Deserialize auth_triples_cb
    let auth_triples_cb_bytes = unsafe { slice::from_raw_parts(auth_triples_cb_ptr, auth_triples_cb_size) };
    let auth_triples_cb: Vec<TripleShare> = match bincode::deserialize(auth_triples_cb_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_cb: {:?}", e);
            return FFI_CfmProcessMsg5Result::default();
        }
    };

    // Deserialize msg5
    let msg5_bytes = unsafe { slice::from_raw_parts(msg5_ptr, msg5_size) };
    let msg5: Box<CFMMsg5> = match bincode::deserialize(msg5_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg5: {:?}", e);
            return FFI_CfmProcessMsg5Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_cb_r3, msg6) = match cfm_process_msg5(cfm_state_cb_r2, &auth_triples_cb, &msg5) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg5: {:?}", e);
            return FFI_CfmProcessMsg5Result::default();
        }
    };

    // Serialize cfm_state_cb_r3
    let serialized_cfm_state_cb_r3 = match bincode::serialize(&cfm_state_cb_r3) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_cb_r3: {:?}", e);
            return FFI_CfmProcessMsg5Result::default();
        }
    };

    // Serialize msg6
    let serialized_msg6 = match bincode::serialize(&msg6) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg6: {:?}", e);
            return FFI_CfmProcessMsg5Result::default();
        }
    };

    // Allocate memory for cfm_state_cb_r3
    let cfm_state_cb_r3_size = serialized_cfm_state_cb_r3.len();
    let cfm_state_cb_r3_layout = Layout::array::<u8>(cfm_state_cb_r3_size).unwrap();
    let cfm_state_cb_r3_ptr = unsafe { alloc(cfm_state_cb_r3_layout) };
    unsafe {
        cfm_state_cb_r3_ptr.copy_from_nonoverlapping(serialized_cfm_state_cb_r3.as_ptr(), cfm_state_cb_r3_size);
    }

    // Allocate memory for msg6
    let msg6_size = serialized_msg6.len();
    let msg6_layout = Layout::array::<u8>(msg6_size).unwrap();
    let msg6_ptr = unsafe { alloc(msg6_layout) };
    unsafe {
        msg6_ptr.copy_from_nonoverlapping(serialized_msg6.as_ptr(), msg6_size);
    }

    // Return the struct containing pointers and sizes
    FFI_CfmProcessMsg5Result {
        cfm_state_cb_r3_ptr,
        cfm_state_cb_r3_size,
        msg6_ptr,
        msg6_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg6Result {
    cfm_state_ob_r4_ptr: *mut u8,
    cfm_state_ob_r4_size: usize,
    msg7_ptr: *mut u8,
    msg7_size: usize,
}

impl Default for FFI_CfmProcessMsg6Result {
    fn default() -> Self {
        FFI_CfmProcessMsg6Result {
            cfm_state_ob_r4_ptr: ptr::null_mut(),
            cfm_state_ob_r4_size: 0,
            msg7_ptr: ptr::null_mut(),
            msg7_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg6(
    cfm_state_ob_r3_ptr: *const u8,
    cfm_state_ob_r3_size: usize,
    auth_triples_ob_ptr: *const u8,
    auth_triples_ob_size: usize,
    msg6_ptr: *const u8,
    msg6_size: usize,
) -> FFI_CfmProcessMsg6Result {
    if cfm_state_ob_r3_ptr.is_null() || cfm_state_ob_r3_size == 0 ||
       auth_triples_ob_ptr.is_null() || auth_triples_ob_size == 0 ||
       msg6_ptr.is_null() || msg6_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg6");
        return FFI_CfmProcessMsg6Result::default();
    }

    // Deserialize cfm_state_ob_r3
    let cfm_state_ob_r3_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r3_ptr, cfm_state_ob_r3_size) };
    let cfm_state_ob_r3: Box<CFMStateOBR3> = match bincode::deserialize(cfm_state_ob_r3_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r3: {:?}", e);
            return FFI_CfmProcessMsg6Result::default();
        }
    };

    // Deserialize auth_triples_ob
    let auth_triples_ob_bytes = unsafe { slice::from_raw_parts(auth_triples_ob_ptr, auth_triples_ob_size) };
    let auth_triples_ob: Vec<TripleShare> = match bincode::deserialize(auth_triples_ob_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_ob: {:?}", e);
            return FFI_CfmProcessMsg6Result::default();
        }
    };

    // Deserialize msg6
    let msg6_bytes = unsafe { slice::from_raw_parts(msg6_ptr, msg6_size) };
    let msg6: Box<CFMMsg6> = match bincode::deserialize(msg6_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg6: {:?}", e);
            return FFI_CfmProcessMsg6Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_ob_r4, msg7) = match cfm_process_msg6(cfm_state_ob_r3, &auth_triples_ob, &msg6) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error in cfm_process_msg6: {:?}", e);
            return FFI_CfmProcessMsg6Result::default();
        }
    };

    // Serialize cfm_state_ob_r4
    let serialized_cfm_state_ob_r4 = match bincode::serialize(&cfm_state_ob_r4) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r4: {:?}", e);
            return FFI_CfmProcessMsg6Result::default();
        }
    };

    // Serialize msg7
    let serialized_msg7 = match bincode::serialize(&msg7) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg7: {:?}", e);
            return FFI_CfmProcessMsg6Result::default();
        }
    };

    // Allocate memory for cfm_state_ob_r4
    let cfm_state_ob_r4_size = serialized_cfm_state_ob_r4.len();
    let cfm_state_ob_r4_layout = Layout::array::<u8>(cfm_state_ob_r4_size).unwrap();
    let cfm_state_ob_r4_ptr = unsafe { alloc(cfm_state_ob_r4_layout) };
    unsafe {
        cfm_state_ob_r4_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r4.as_ptr(), cfm_state_ob_r4_size);
    }

    // Allocate memory for msg7
    let msg7_size = serialized_msg7.len();
    let msg7_layout = Layout::array::<u8>(msg7_size).unwrap();
    let msg7_ptr = unsafe { alloc(msg7_layout) };
    unsafe {
        msg7_ptr.copy_from_nonoverlapping(serialized_msg7.as_ptr(), msg7_size);
    }

    FFI_CfmProcessMsg6Result {
        cfm_state_ob_r4_ptr,
        cfm_state_ob_r4_size,
        msg7_ptr,
        msg7_size,
    }
}



#[repr(C)]
pub struct FFI_CfmProcessMsg7Result {
    cfm_state_cb_r4_ptr: *mut u8,
    cfm_state_cb_r4_size: usize,
    msg8_ptr: *mut u8,
    msg8_size: usize,
}

impl Default for FFI_CfmProcessMsg7Result {
    fn default() -> Self {
        FFI_CfmProcessMsg7Result {
            cfm_state_cb_r4_ptr: std::ptr::null_mut(),
            cfm_state_cb_r4_size: 0,
            msg8_ptr: std::ptr::null_mut(),
            msg8_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg7(
    cfm_state_cb_r3_ptr: *const u8,
    cfm_state_cb_r3_size: usize,
    auth_triples_cb_ptr: *const u8,
    auth_triples_cb_size: usize,
    msg7_ptr: *const u8,
    msg7_size: usize,
) -> FFI_CfmProcessMsg7Result {
    if cfm_state_cb_r3_ptr.is_null() || cfm_state_cb_r3_size == 0 ||
       auth_triples_cb_ptr.is_null() || auth_triples_cb_size == 0 ||
       msg7_ptr.is_null() || msg7_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg7");
        return FFI_CfmProcessMsg7Result::default();
    }

    // Deserialize cfm_state_cb_r3
    let cfm_state_cb_r3_bytes = unsafe { slice::from_raw_parts(cfm_state_cb_r3_ptr, cfm_state_cb_r3_size) };
    let cfm_state_cb_r3: CFMStateCBR3 = match bincode::deserialize(cfm_state_cb_r3_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_cb_r3: {:?}", e);
            return FFI_CfmProcessMsg7Result::default();
        }
    };

    // Deserialize auth_triples_cb
    let auth_triples_cb_bytes = unsafe { slice::from_raw_parts(auth_triples_cb_ptr, auth_triples_cb_size) };
    let auth_triples_cb: Vec<TripleShare> = match bincode::deserialize(auth_triples_cb_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_cb: {:?}", e);
            return FFI_CfmProcessMsg7Result::default();
        }
    };

    // Deserialize msg7
    let msg7_bytes = unsafe { slice::from_raw_parts(msg7_ptr, msg7_size) };
    let msg7: Box<CFMMsg7> = match bincode::deserialize(msg7_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg7: {:?}", e);
            return FFI_CfmProcessMsg7Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_cb_r4, msg8) = match cfm_process_msg7(cfm_state_cb_r3, &auth_triples_cb, &msg7) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg7: {:?}", e);
            return FFI_CfmProcessMsg7Result::default();
        }
    };

    // Serialize cfm_state_cb_r4
    let serialized_cfm_state_cb_r4 = match bincode::serialize(&cfm_state_cb_r4) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_cb_r4: {:?}", e);
            return FFI_CfmProcessMsg7Result::default();
        }
    };

    // Serialize msg8
    let serialized_msg8 = match bincode::serialize(&msg8) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg8: {:?}", e);
            return FFI_CfmProcessMsg7Result::default();
        }
    };

    // Allocate memory for cfm_state_cb_r4
    let cfm_state_cb_r4_size = serialized_cfm_state_cb_r4.len();
    let cfm_state_cb_r4_layout = Layout::array::<u8>(cfm_state_cb_r4_size).unwrap();
    let cfm_state_cb_r4_ptr = unsafe { alloc(cfm_state_cb_r4_layout) };
    unsafe {
        cfm_state_cb_r4_ptr.copy_from_nonoverlapping(serialized_cfm_state_cb_r4.as_ptr(), cfm_state_cb_r4_size);
    }

    // Allocate memory for msg8
    let msg8_size = serialized_msg8.len();
    let msg8_layout = Layout::array::<u8>(msg8_size).unwrap();
    let msg8_ptr = unsafe { alloc(msg8_layout) };
    unsafe {
        msg8_ptr.copy_from_nonoverlapping(serialized_msg8.as_ptr(), msg8_size);
    }

    // Return result
    FFI_CfmProcessMsg7Result {
        cfm_state_cb_r4_ptr,
        cfm_state_cb_r4_size,
        msg8_ptr,
        msg8_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg8Result {
    cfm_state_ob_r5_ptr: *mut u8,
    cfm_state_ob_r5_size: usize,
    msg9_ptr: *mut u8,
    msg9_size: usize,
}

impl Default for FFI_CfmProcessMsg8Result {
    fn default() -> Self {
        FFI_CfmProcessMsg8Result {
            cfm_state_ob_r5_ptr: std::ptr::null_mut(),
            cfm_state_ob_r5_size: 0,
            msg9_ptr: std::ptr::null_mut(),
            msg9_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg8(
    cfm_state_ob_r4_ptr: *const u8,
    cfm_state_ob_r4_size: usize,
    auth_triples_ob_ptr: *const u8,
    auth_triples_ob_size: usize,
    msg8_ptr: *const u8,
    msg8_size: usize,
) -> FFI_CfmProcessMsg8Result {
    if cfm_state_ob_r4_ptr.is_null() || cfm_state_ob_r4_size == 0 ||
       auth_triples_ob_ptr.is_null() || auth_triples_ob_size == 0 ||
       msg8_ptr.is_null() || msg8_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg8");
        return FFI_CfmProcessMsg8Result::default();
    }

    // Deserialize cfm_state_ob_r4
    let cfm_state_ob_r4_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r4_ptr, cfm_state_ob_r4_size) };
    let cfm_state_ob_r4: CFMStateOBR4 = match bincode::deserialize(cfm_state_ob_r4_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r4: {:?}", e);
            return FFI_CfmProcessMsg8Result::default();
        }
    };

    // Deserialize auth_triples_ob
    let auth_triples_ob_bytes = unsafe { slice::from_raw_parts(auth_triples_ob_ptr, auth_triples_ob_size) };
    let auth_triples_ob: Vec<TripleShare> = match bincode::deserialize(auth_triples_ob_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_ob: {:?}", e);
            return FFI_CfmProcessMsg8Result::default();
        }
    };

    // Deserialize msg8
    let msg8_bytes = unsafe { slice::from_raw_parts(msg8_ptr, msg8_size) };
    let msg8:  Box<CFMMsg8> = match bincode::deserialize(msg8_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg8: {:?}", e);
            return FFI_CfmProcessMsg8Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_ob_r5, msg9) = match cfm_process_msg8(cfm_state_ob_r4, &auth_triples_ob, &msg8) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg8: {:?}", e);
            return FFI_CfmProcessMsg8Result::default();
        }
    };

    // Serialize cfm_state_ob_r5
    let serialized_cfm_state_ob_r5 = match bincode::serialize(&cfm_state_ob_r5) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r5: {:?}", e);
            return FFI_CfmProcessMsg8Result::default();
        }
    };

    // Serialize msg9
    let serialized_msg9 = match bincode::serialize(&msg9) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg9: {:?}", e);
            return FFI_CfmProcessMsg8Result::default();
        }
    };

    // Allocate memory for cfm_state_ob_r5
    let cfm_state_ob_r5_size = serialized_cfm_state_ob_r5.len();
    let cfm_state_ob_r5_layout = Layout::array::<u8>(cfm_state_ob_r5_size).unwrap();
    let cfm_state_ob_r5_ptr = unsafe { alloc(cfm_state_ob_r5_layout) };
    unsafe {
        cfm_state_ob_r5_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r5.as_ptr(), cfm_state_ob_r5_size);
    }

    // Allocate memory for msg9
    let msg9_size = serialized_msg9.len();
    let msg9_layout = Layout::array::<u8>(msg9_size).unwrap();
    let msg9_ptr = unsafe { alloc(msg9_layout) };
    unsafe {
        msg9_ptr.copy_from_nonoverlapping(serialized_msg9.as_ptr(), msg9_size);
    }

    // Return result
    FFI_CfmProcessMsg8Result {
        cfm_state_ob_r5_ptr,
        cfm_state_ob_r5_size,
        msg9_ptr,
        msg9_size,
    }
}



#[repr(C)]
pub struct FFI_CfmProcessMsg9Result {
    cfm_state_cb_r5_ptr: *mut u8,
    cfm_state_cb_r5_size: usize,
    msg10_ptr: *mut u8,
    msg10_size: usize,
}

impl Default for FFI_CfmProcessMsg9Result {
    fn default() -> Self {
        FFI_CfmProcessMsg9Result {
            cfm_state_cb_r5_ptr: std::ptr::null_mut(),
            cfm_state_cb_r5_size: 0,
            msg10_ptr: std::ptr::null_mut(),
            msg10_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg9(
    cfm_state_cb_r4_ptr: *const u8,
    cfm_state_cb_r4_size: usize,
    auth_triples_cb_ptr: *const u8,
    auth_triples_cb_size: usize,
    msg9_ptr: *const u8,
    msg9_size: usize,
) -> FFI_CfmProcessMsg9Result {
    if cfm_state_cb_r4_ptr.is_null() || cfm_state_cb_r4_size == 0 ||
       auth_triples_cb_ptr.is_null() || auth_triples_cb_size == 0 ||
       msg9_ptr.is_null() || msg9_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg9");
        return FFI_CfmProcessMsg9Result::default();
    }

    // Deserialize cfm_state_cb_r4
    let cfm_state_cb_r4_bytes = unsafe { slice::from_raw_parts(cfm_state_cb_r4_ptr, cfm_state_cb_r4_size) };
    let cfm_state_cb_r4: CFMStateCBR4 = match bincode::deserialize(cfm_state_cb_r4_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_cb_r4: {:?}", e);
            return FFI_CfmProcessMsg9Result::default();
        }
    };

    // Deserialize auth_triples_cb
    let auth_triples_cb_bytes = unsafe { slice::from_raw_parts(auth_triples_cb_ptr, auth_triples_cb_size) };
    let auth_triples_cb: Vec<TripleShare> = match bincode::deserialize(auth_triples_cb_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_cb: {:?}", e);
            return FFI_CfmProcessMsg9Result::default();
        }
    };

    // Deserialize msg9
    let msg9_bytes = unsafe { slice::from_raw_parts(msg9_ptr, msg9_size) };
    let msg9: Box<CFMMsg9> = match bincode::deserialize(msg9_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg9: {:?}", e);
            return FFI_CfmProcessMsg9Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_cb_r5, msg10) = match cfm_process_msg9(cfm_state_cb_r4, &auth_triples_cb, &msg9) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg9: {:?}", e);
            return FFI_CfmProcessMsg9Result::default();
        }
    };

    // Serialize cfm_state_cb_r5
    let serialized_cfm_state_cb_r5 = match bincode::serialize(&cfm_state_cb_r5) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_cb_r5: {:?}", e);
            return FFI_CfmProcessMsg9Result::default();
        }
    };

    // Serialize msg10
    let serialized_msg10 = match bincode::serialize(&msg10) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg10: {:?}", e);
            return FFI_CfmProcessMsg9Result::default();
        }
    };

    // Allocate memory for cfm_state_cb_r5
    let cfm_state_cb_r5_size = serialized_cfm_state_cb_r5.len();
    let cfm_state_cb_r5_layout = Layout::array::<u8>(cfm_state_cb_r5_size).unwrap();
    let cfm_state_cb_r5_ptr = unsafe { alloc(cfm_state_cb_r5_layout) };
    unsafe {
        cfm_state_cb_r5_ptr.copy_from_nonoverlapping(serialized_cfm_state_cb_r5.as_ptr(), cfm_state_cb_r5_size);
    }

    // Allocate memory for msg10
    let msg10_size = serialized_msg10.len();
    let msg10_layout = Layout::array::<u8>(msg10_size).unwrap();
    let msg10_ptr = unsafe { alloc(msg10_layout) };
    unsafe {
        msg10_ptr.copy_from_nonoverlapping(serialized_msg10.as_ptr(), msg10_size);
    }

    // Return result
    FFI_CfmProcessMsg9Result {
        cfm_state_cb_r5_ptr,
        cfm_state_cb_r5_size,
        msg10_ptr,
        msg10_size,
    }
}



#[repr(C)]
pub struct FFI_CfmProcessMsg10Result {
    cfm_state_ob_r6_ptr: *mut u8,
    cfm_state_ob_r6_size: usize,
    msg11_ptr: *mut u8,
    msg11_size: usize,
}

impl Default for FFI_CfmProcessMsg10Result {
    fn default() -> Self {
        FFI_CfmProcessMsg10Result {
            cfm_state_ob_r6_ptr: std::ptr::null_mut(),
            cfm_state_ob_r6_size: 0,
            msg11_ptr: std::ptr::null_mut(),
            msg11_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg10(
    cfm_state_ob_r5_ptr: *const u8,
    cfm_state_ob_r5_size: usize,
    auth_triples_ob_ptr: *const u8,
    auth_triples_ob_size: usize,
    msg10_ptr: *const u8,
    msg10_size: usize,
) -> FFI_CfmProcessMsg10Result {
    if cfm_state_ob_r5_ptr.is_null() || cfm_state_ob_r5_size == 0 ||
       auth_triples_ob_ptr.is_null() || auth_triples_ob_size == 0 ||
       msg10_ptr.is_null() || msg10_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg10");
        return FFI_CfmProcessMsg10Result::default();
    }

    // Deserialize cfm_state_ob_r5
    let cfm_state_ob_r5_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r5_ptr, cfm_state_ob_r5_size) };
    let cfm_state_ob_r5: CFMStateOBR5 = match bincode::deserialize(cfm_state_ob_r5_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r5: {:?}", e);
            return FFI_CfmProcessMsg10Result::default();
        }
    };

    // Deserialize auth_triples_ob
    let auth_triples_ob_bytes = unsafe { slice::from_raw_parts(auth_triples_ob_ptr, auth_triples_ob_size) };
    let auth_triples_ob: Vec<TripleShare> = match bincode::deserialize(auth_triples_ob_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_ob: {:?}", e);
            return FFI_CfmProcessMsg10Result::default();
        }
    };

    // Deserialize msg10
    let msg10_bytes = unsafe { slice::from_raw_parts(msg10_ptr, msg10_size) };
    let msg10: Box<CFMMsg10> = match bincode::deserialize(msg10_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg10: {:?}", e);
            return FFI_CfmProcessMsg10Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_ob_r6, msg11) = match cfm_process_msg10(cfm_state_ob_r5, &auth_triples_ob, &msg10) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg10: {:?}", e);
            return FFI_CfmProcessMsg10Result::default();
        }
    };

    // Serialize cfm_state_ob_r6
    let serialized_cfm_state_ob_r6 = match bincode::serialize(&cfm_state_ob_r6) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r6: {:?}", e);
            return FFI_CfmProcessMsg10Result::default();
        }
    };

    // Serialize msg11
    let serialized_msg11 = match bincode::serialize(&msg11) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg11: {:?}", e);
            return FFI_CfmProcessMsg10Result::default();
        }
    };

    // Allocate memory for cfm_state_ob_r6
    let cfm_state_ob_r6_size = serialized_cfm_state_ob_r6.len();
    let cfm_state_ob_r6_layout = Layout::array::<u8>(cfm_state_ob_r6_size).unwrap();
    let cfm_state_ob_r6_ptr = unsafe { alloc(cfm_state_ob_r6_layout) };
    unsafe {
        cfm_state_ob_r6_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r6.as_ptr(), cfm_state_ob_r6_size);
    }

    // Allocate memory for msg11
    let msg11_size = serialized_msg11.len();
    let msg11_layout = Layout::array::<u8>(msg11_size).unwrap();
    let msg11_ptr = unsafe { alloc(msg11_layout) };
    unsafe {
        msg11_ptr.copy_from_nonoverlapping(serialized_msg11.as_ptr(), msg11_size);
    }

    // Return result
    FFI_CfmProcessMsg10Result {
        cfm_state_ob_r6_ptr,
        cfm_state_ob_r6_size,
        msg11_ptr,
        msg11_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg11Result {
    cfm_state_cb_r6_ptr: *mut u8,
    cfm_state_cb_r6_size: usize,
    msg12_ptr: *mut u8,
    msg12_size: usize,
}

impl Default for FFI_CfmProcessMsg11Result {
    fn default() -> Self {
        FFI_CfmProcessMsg11Result {
            cfm_state_cb_r6_ptr: std::ptr::null_mut(),
            cfm_state_cb_r6_size: 0,
            msg12_ptr: std::ptr::null_mut(),
            msg12_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg11(
    cfm_state_cb_r5_ptr: *const u8,
    cfm_state_cb_r5_size: usize,
    auth_triples_cb_ptr: *const u8,
    auth_triples_cb_size: usize,
    msg11_ptr: *const u8,
    msg11_size: usize,
) -> FFI_CfmProcessMsg11Result {
    if cfm_state_cb_r5_ptr.is_null() || cfm_state_cb_r5_size == 0 ||
       auth_triples_cb_ptr.is_null() || auth_triples_cb_size == 0 ||
       msg11_ptr.is_null() || msg11_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg11");
        return FFI_CfmProcessMsg11Result::default();
    }

    // Deserialize cfm_state_cb_r5
    let cfm_state_cb_r5_bytes = unsafe { slice::from_raw_parts(cfm_state_cb_r5_ptr, cfm_state_cb_r5_size) };
    let cfm_state_cb_r5: CFMStateCBR5 = match bincode::deserialize(cfm_state_cb_r5_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_cb_r5: {:?}", e);
            return FFI_CfmProcessMsg11Result::default();
        }
    };

    // Deserialize auth_triples_cb
    let auth_triples_cb_bytes = unsafe { slice::from_raw_parts(auth_triples_cb_ptr, auth_triples_cb_size) };
    let auth_triples_cb: Vec<TripleShare> = match bincode::deserialize(auth_triples_cb_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_cb: {:?}", e);
            return FFI_CfmProcessMsg11Result::default();
        }
    };

    // Deserialize msg11
    let msg11_bytes = unsafe { slice::from_raw_parts(msg11_ptr, msg11_size) };
    let msg11: Box<CFMMsg11> = match bincode::deserialize(msg11_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg11: {:?}", e);
            return FFI_CfmProcessMsg11Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_cb_r6, msg12) = match cfm_process_msg11(cfm_state_cb_r5, &auth_triples_cb, &msg11) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg11: {:?}", e);
            return FFI_CfmProcessMsg11Result::default();
        }
    };

    // Serialize cfm_state_cb_r6
    let serialized_cfm_state_cb_r6 = match bincode::serialize(&cfm_state_cb_r6) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_cb_r6: {:?}", e);
            return FFI_CfmProcessMsg11Result::default();
        }
    };

    // Serialize msg12
    let serialized_msg12 = match bincode::serialize(&msg12) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg12: {:?}", e);
            return FFI_CfmProcessMsg11Result::default();
        }
    };

    // Allocate memory for cfm_state_cb_r6
    let cfm_state_cb_r6_size = serialized_cfm_state_cb_r6.len();
    let cfm_state_cb_r6_layout = Layout::array::<u8>(cfm_state_cb_r6_size).unwrap();
    let cfm_state_cb_r6_ptr = unsafe { alloc(cfm_state_cb_r6_layout) };
    unsafe {
        cfm_state_cb_r6_ptr.copy_from_nonoverlapping(serialized_cfm_state_cb_r6.as_ptr(), cfm_state_cb_r6_size);
    }

    // Allocate memory for msg12
    let msg12_size = serialized_msg12.len();
    let msg12_layout = Layout::array::<u8>(msg12_size).unwrap();
    let msg12_ptr = unsafe { alloc(msg12_layout) };
    unsafe {
        msg12_ptr.copy_from_nonoverlapping(serialized_msg12.as_ptr(), msg12_size);
    }

    // Return result
    FFI_CfmProcessMsg11Result {
        cfm_state_cb_r6_ptr,
        cfm_state_cb_r6_size,
        msg12_ptr,
        msg12_size,
    }
}



#[repr(C)]
pub struct FFI_CfmProcessMsg12Result {
    cfm_state_ob_r7_ptr: *mut u8,
    cfm_state_ob_r7_size: usize,
    msg13_ptr: *mut u8,
    msg13_size: usize,
}

impl Default for FFI_CfmProcessMsg12Result {
    fn default() -> Self {
        FFI_CfmProcessMsg12Result {
            cfm_state_ob_r7_ptr: std::ptr::null_mut(),
            cfm_state_ob_r7_size: 0,
            msg13_ptr: std::ptr::null_mut(),
            msg13_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg12(
    cfm_state_ob_r6_ptr: *const u8,
    cfm_state_ob_r6_size: usize,
    auth_triples_ob_ptr: *const u8,
    auth_triples_ob_size: usize,
    msg12_ptr: *const u8,
    msg12_size: usize,
) -> FFI_CfmProcessMsg12Result {
    if cfm_state_ob_r6_ptr.is_null() || cfm_state_ob_r6_size == 0 ||
       auth_triples_ob_ptr.is_null() || auth_triples_ob_size == 0 ||
       msg12_ptr.is_null() || msg12_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg12");
        return FFI_CfmProcessMsg12Result::default();
    }

    // Deserialize cfm_state_ob_r6
    let cfm_state_ob_r6_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r6_ptr, cfm_state_ob_r6_size) };
    let cfm_state_ob_r6: CFMStateOBR6 = match bincode::deserialize(cfm_state_ob_r6_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r6: {:?}", e);
            return FFI_CfmProcessMsg12Result::default();
        }
    };

    // Deserialize auth_triples_ob
    let auth_triples_ob_bytes = unsafe { slice::from_raw_parts(auth_triples_ob_ptr, auth_triples_ob_size) };
    let auth_triples_ob: Vec<TripleShare> = match bincode::deserialize(auth_triples_ob_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_ob: {:?}", e);
            return FFI_CfmProcessMsg12Result::default();
        }
    };

    // Deserialize msg12
    let msg12_bytes = unsafe { slice::from_raw_parts(msg12_ptr, msg12_size) };
    let msg12: Box<CFMMsg12> = match bincode::deserialize(msg12_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg12: {:?}", e);
            return FFI_CfmProcessMsg12Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_ob_r7, msg13) = match cfm_process_msg12(cfm_state_ob_r6, &auth_triples_ob, &msg12) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg12: {:?}", e);
            return FFI_CfmProcessMsg12Result::default();
        }
    };

    // Serialize cfm_state_ob_r7
    let serialized_cfm_state_ob_r7 = match bincode::serialize(&cfm_state_ob_r7) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r7: {:?}", e);
            return FFI_CfmProcessMsg12Result::default();
        }
    };

    // Serialize msg13
    let serialized_msg13 = match bincode::serialize(&msg13) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg13: {:?}", e);
            return FFI_CfmProcessMsg12Result::default();
        }
    };

    // Allocate memory for cfm_state_ob_r7
    let cfm_state_ob_r7_size = serialized_cfm_state_ob_r7.len();
    let cfm_state_ob_r7_layout = Layout::array::<u8>(cfm_state_ob_r7_size).unwrap();
    let cfm_state_ob_r7_ptr = unsafe { alloc(cfm_state_ob_r7_layout) };
    unsafe {
        cfm_state_ob_r7_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r7.as_ptr(), cfm_state_ob_r7_size);
    }

    // Allocate memory for msg13
    let msg13_size = serialized_msg13.len();
    let msg13_layout = Layout::array::<u8>(msg13_size).unwrap();
    let msg13_ptr = unsafe { alloc(msg13_layout) };
    unsafe {
        msg13_ptr.copy_from_nonoverlapping(serialized_msg13.as_ptr(), msg13_size);
    }

    // Return result
    FFI_CfmProcessMsg12Result {
        cfm_state_ob_r7_ptr,
        cfm_state_ob_r7_size,
        msg13_ptr,
        msg13_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg13Result {
    cfm_state_cb_r7_ptr: *mut u8,
    cfm_state_cb_r7_size: usize,
    msg14_ptr: *mut u8,
    msg14_size: usize,
}

impl Default for FFI_CfmProcessMsg13Result {
    fn default() -> Self {
        FFI_CfmProcessMsg13Result {
            cfm_state_cb_r7_ptr: std::ptr::null_mut(),
            cfm_state_cb_r7_size: 0,
            msg14_ptr: std::ptr::null_mut(),
            msg14_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg13(
    cfm_state_cb_r6_ptr: *const u8,
    cfm_state_cb_r6_size: usize,
    auth_triples_cb_ptr: *const u8,
    auth_triples_cb_size: usize,
    msg13_ptr: *const u8,
    msg13_size: usize,
) -> FFI_CfmProcessMsg13Result {
    if cfm_state_cb_r6_ptr.is_null() || cfm_state_cb_r6_size == 0 ||
       auth_triples_cb_ptr.is_null() || auth_triples_cb_size == 0 ||
       msg13_ptr.is_null() || msg13_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg13");
        return FFI_CfmProcessMsg13Result::default();
    }

    // Deserialize cfm_state_cb_r6
    let cfm_state_cb_r6_bytes = unsafe { slice::from_raw_parts(cfm_state_cb_r6_ptr, cfm_state_cb_r6_size) };
    let cfm_state_cb_r6: CFMStateCBR6 = match bincode::deserialize(cfm_state_cb_r6_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_cb_r6: {:?}", e);
            return FFI_CfmProcessMsg13Result::default();
        }
    };

    // Deserialize auth_triples_cb
    let auth_triples_cb_bytes = unsafe { slice::from_raw_parts(auth_triples_cb_ptr, auth_triples_cb_size) };
    let auth_triples_cb: Vec<TripleShare> = match bincode::deserialize(auth_triples_cb_bytes) {
        Ok(triples) => triples,
        Err(e) => {
            eprintln!("Failed to deserialize auth_triples_cb: {:?}", e);
            return FFI_CfmProcessMsg13Result::default();
        }
    };

    // Deserialize msg13
    let msg13_bytes = unsafe { slice::from_raw_parts(msg13_ptr, msg13_size) };
    let msg13: Box<CFMMsg13> = match bincode::deserialize(msg13_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg13: {:?}", e);
            return FFI_CfmProcessMsg13Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_cb_r7, msg14) = match cfm_process_msg13(cfm_state_cb_r6, &auth_triples_cb, &msg13) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg13: {:?}", e);
            return FFI_CfmProcessMsg13Result::default();
        }
    };

    // Serialize cfm_state_cb_r7
    let serialized_cfm_state_cb_r7 = match bincode::serialize(&cfm_state_cb_r7) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_cb_r7: {:?}", e);
            return FFI_CfmProcessMsg13Result::default();
        }
    };

    // Serialize msg14
    let serialized_msg14 = match bincode::serialize(&msg14) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg14: {:?}", e);
            return FFI_CfmProcessMsg13Result::default();
        }
    };

    // Allocate memory for cfm_state_cb_r7
    let cfm_state_cb_r7_size = serialized_cfm_state_cb_r7.len();
    let cfm_state_cb_r7_layout = Layout::array::<u8>(cfm_state_cb_r7_size).unwrap();
    let cfm_state_cb_r7_ptr = unsafe { alloc(cfm_state_cb_r7_layout) };
    unsafe {
        cfm_state_cb_r7_ptr.copy_from_nonoverlapping(serialized_cfm_state_cb_r7.as_ptr(), cfm_state_cb_r7_size);
    }

    // Allocate memory for msg14
    let msg14_size = serialized_msg14.len();
    let msg14_layout = Layout::array::<u8>(msg14_size).unwrap();
    let msg14_ptr = unsafe { alloc(msg14_layout) };
    unsafe {
        msg14_ptr.copy_from_nonoverlapping(serialized_msg14.as_ptr(), msg14_size);
    }

    // Return result
    FFI_CfmProcessMsg13Result {
        cfm_state_cb_r7_ptr,
        cfm_state_cb_r7_size,
        msg14_ptr,
        msg14_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg14Result {
    cfm_state_ob_r8_ptr: *mut u8,
    cfm_state_ob_r8_size: usize,
    msg15_ptr: *mut u8,
    msg15_size: usize,
}

impl Default for FFI_CfmProcessMsg14Result {
    fn default() -> Self {
        FFI_CfmProcessMsg14Result {
            cfm_state_ob_r8_ptr: std::ptr::null_mut(),
            cfm_state_ob_r8_size: 0,
            msg15_ptr: std::ptr::null_mut(),
            msg15_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg14(
    cfm_state_ob_r7_ptr: *const u8,
    cfm_state_ob_r7_size: usize,
    msg14_ptr: *const u8,
    msg14_size: usize,
) -> FFI_CfmProcessMsg14Result {
    if cfm_state_ob_r7_ptr.is_null() || cfm_state_ob_r7_size == 0 ||
       msg14_ptr.is_null() || msg14_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg14");
        return FFI_CfmProcessMsg14Result::default();
    }

    // Deserialize cfm_state_ob_r7
    let cfm_state_ob_r7_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r7_ptr, cfm_state_ob_r7_size) };
    let cfm_state_ob_r7: CFMStateOBR7 = match bincode::deserialize(cfm_state_ob_r7_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r7: {:?}", e);
            return FFI_CfmProcessMsg14Result::default();
        }
    };

    // Deserialize msg14
    let msg14_bytes = unsafe { slice::from_raw_parts(msg14_ptr, msg14_size) };
    let msg14: Box<CFMMsg14> = match bincode::deserialize(msg14_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg14: {:?}", e);
            return FFI_CfmProcessMsg14Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_ob_r8, msg15) = match cfm_process_msg14(cfm_state_ob_r7, &msg14) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg14: {:?}", e);
            return FFI_CfmProcessMsg14Result::default();
        }
    };

    // Serialize cfm_state_ob_r8
    let serialized_cfm_state_ob_r8 = match bincode::serialize(&cfm_state_ob_r8) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r8: {:?}", e);
            return FFI_CfmProcessMsg14Result::default();
        }
    };

    // Serialize msg15
    let serialized_msg15 = match bincode::serialize(&msg15) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg15: {:?}", e);
            return FFI_CfmProcessMsg14Result::default();
        }
    };

    // Allocate memory for cfm_state_ob_r8
    let cfm_state_ob_r8_size = serialized_cfm_state_ob_r8.len();
    let cfm_state_ob_r8_layout = Layout::array::<u8>(cfm_state_ob_r8_size).unwrap();
    let cfm_state_ob_r8_ptr = unsafe { alloc(cfm_state_ob_r8_layout) };
    unsafe {
        cfm_state_ob_r8_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r8.as_ptr(), cfm_state_ob_r8_size);
    }

    // Allocate memory for msg15
    let msg15_size = serialized_msg15.len();
    let msg15_layout = Layout::array::<u8>(msg15_size).unwrap();
    let msg15_ptr = unsafe { alloc(msg15_layout) };
    unsafe {
        msg15_ptr.copy_from_nonoverlapping(serialized_msg15.as_ptr(), msg15_size);
    }

    // Return result
    FFI_CfmProcessMsg14Result {
        cfm_state_ob_r8_ptr,
        cfm_state_ob_r8_size,
        msg15_ptr,
        msg15_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg15Result {
    cfm_state_cb_r8_ptr: *mut u8,
    cfm_state_cb_r8_size: usize,
    msg16_ptr: *mut u8,
    msg16_size: usize,
}

impl Default for FFI_CfmProcessMsg15Result {
    fn default() -> Self {
        FFI_CfmProcessMsg15Result {
            cfm_state_cb_r8_ptr: std::ptr::null_mut(),
            cfm_state_cb_r8_size: 0,
            msg16_ptr: std::ptr::null_mut(),
            msg16_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg15(
    cfm_state_cb_r7_ptr: *const u8,
    cfm_state_cb_r7_size: usize,
    msg15_ptr: *const u8,
    msg15_size: usize,
) -> FFI_CfmProcessMsg15Result {
    if cfm_state_cb_r7_ptr.is_null() || cfm_state_cb_r7_size == 0 ||
       msg15_ptr.is_null() || msg15_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg15");
        return FFI_CfmProcessMsg15Result::default();
    }

    // Deserialize cfm_state_cb_r7
    let cfm_state_cb_r7_bytes = unsafe { slice::from_raw_parts(cfm_state_cb_r7_ptr, cfm_state_cb_r7_size) };
    let cfm_state_cb_r7: CFMStateCBR7 = match bincode::deserialize(cfm_state_cb_r7_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_cb_r7: {:?}", e);
            return FFI_CfmProcessMsg15Result::default();
        }
    };

    // Deserialize msg15
    let msg15_bytes = unsafe { slice::from_raw_parts(msg15_ptr, msg15_size) };
    let msg15: CFMMsg15 = match bincode::deserialize(msg15_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg15: {:?}", e);
            return FFI_CfmProcessMsg15Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_cb_r8, msg16) = match cfm_process_msg15(cfm_state_cb_r7, &msg15) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg15: {:?}", e);
            return FFI_CfmProcessMsg15Result::default();
        }
    };

    // Serialize cfm_state_cb_r8
    let serialized_cfm_state_cb_r8 = match bincode::serialize(&cfm_state_cb_r8) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_cb_r8: {:?}", e);
            return FFI_CfmProcessMsg15Result::default();
        }
    };

    // Serialize msg16
    let serialized_msg16 = match bincode::serialize(&msg16) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg16: {:?}", e);
            return FFI_CfmProcessMsg15Result::default();
        }
    };

    // Allocate memory for cfm_state_cb_r8
    let cfm_state_cb_r8_size = serialized_cfm_state_cb_r8.len();
    let cfm_state_cb_r8_layout = Layout::array::<u8>(cfm_state_cb_r8_size).unwrap();
    let cfm_state_cb_r8_ptr = unsafe { alloc(cfm_state_cb_r8_layout) };
    unsafe {
        cfm_state_cb_r8_ptr.copy_from_nonoverlapping(serialized_cfm_state_cb_r8.as_ptr(), cfm_state_cb_r8_size);
    }

    // Allocate memory for msg16
    let msg16_size = serialized_msg16.len();
    let msg16_layout = Layout::array::<u8>(msg16_size).unwrap();
    let msg16_ptr = unsafe { alloc(msg16_layout) };
    unsafe {
        msg16_ptr.copy_from_nonoverlapping(serialized_msg16.as_ptr(), msg16_size);
    }

    // Return result
    FFI_CfmProcessMsg15Result {
        cfm_state_cb_r8_ptr,
        cfm_state_cb_r8_size,
        msg16_ptr,
        msg16_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg16Result {
    cfm_state_ob_r9_ptr: *mut u8,
    cfm_state_ob_r9_size: usize,
    msg17_ptr: *mut u8,
    msg17_size: usize,
}

impl Default for FFI_CfmProcessMsg16Result {
    fn default() -> Self {
        FFI_CfmProcessMsg16Result {
            cfm_state_ob_r9_ptr: std::ptr::null_mut(),
            cfm_state_ob_r9_size: 0,
            msg17_ptr: std::ptr::null_mut(),
            msg17_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg16(
    cfm_state_ob_r8_ptr: *const u8,
    cfm_state_ob_r8_size: usize,
    msg16_ptr: *const u8,
    msg16_size: usize,
) -> FFI_CfmProcessMsg16Result {
    if cfm_state_ob_r8_ptr.is_null() || cfm_state_ob_r8_size == 0 ||
       msg16_ptr.is_null() || msg16_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg16");
        return FFI_CfmProcessMsg16Result::default();
    }

    // Deserialize cfm_state_ob_r8
    let cfm_state_ob_r8_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r8_ptr, cfm_state_ob_r8_size) };
    let cfm_state_ob_r8: CFMStateOBR8 = match bincode::deserialize(cfm_state_ob_r8_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r8: {:?}", e);
            return FFI_CfmProcessMsg16Result::default();
        }
    };

    // Deserialize msg16
    let msg16_bytes = unsafe { slice::from_raw_parts(msg16_ptr, msg16_size) };
    let msg16: CFMMsg16 = match bincode::deserialize(msg16_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg16: {:?}", e);
            return FFI_CfmProcessMsg16Result::default();
        }
    };

    // Call the actual function
    let (cfm_state_ob_r9, msg17) = match cfm_process_msg16(cfm_state_ob_r8, &msg16) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg16: {:?}", e);
            return FFI_CfmProcessMsg16Result::default();
        }
    };

    // Serialize cfm_state_ob_r9
    let serialized_cfm_state_ob_r9 = match bincode::serialize(&cfm_state_ob_r9) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize cfm_state_ob_r9: {:?}", e);
            return FFI_CfmProcessMsg16Result::default();
        }
    };

    // Serialize msg17
    let serialized_msg17 = match bincode::serialize(&msg17) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg17: {:?}", e);
            return FFI_CfmProcessMsg16Result::default();
        }
    };

    // Allocate memory for cfm_state_ob_r9
    let cfm_state_ob_r9_size = serialized_cfm_state_ob_r9.len();
    let cfm_state_ob_r9_layout = Layout::array::<u8>(cfm_state_ob_r9_size).unwrap();
    let cfm_state_ob_r9_ptr = unsafe { alloc(cfm_state_ob_r9_layout) };
    unsafe {
        cfm_state_ob_r9_ptr.copy_from_nonoverlapping(serialized_cfm_state_ob_r9.as_ptr(), cfm_state_ob_r9_size);
    }

    // Allocate memory for msg17
    let msg17_size = serialized_msg17.len();
    let msg17_layout = Layout::array::<u8>(msg17_size).unwrap();
    let msg17_ptr = unsafe { alloc(msg17_layout) };
    unsafe {
        msg17_ptr.copy_from_nonoverlapping(serialized_msg17.as_ptr(), msg17_size);
    }

    // Return result
    FFI_CfmProcessMsg16Result {
        cfm_state_ob_r9_ptr,
        cfm_state_ob_r9_size,
        msg17_ptr,
        msg17_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg17Result {
    b_cb_value_ptr: *mut u8,
    b_cb_value_size: usize,
    msg18_ptr: *mut u8,
    msg18_size: usize,
}

impl Default for FFI_CfmProcessMsg17Result {
    fn default() -> Self {
        FFI_CfmProcessMsg17Result {
            b_cb_value_ptr: std::ptr::null_mut(),
            b_cb_value_size: 0,
            msg18_ptr: std::ptr::null_mut(),
            msg18_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg17(
    cfm_state_cb_r8_ptr: *const u8,
    cfm_state_cb_r8_size: usize,
    msg17_ptr: *const u8,
    msg17_size: usize,
) -> FFI_CfmProcessMsg17Result {
    if cfm_state_cb_r8_ptr.is_null() || cfm_state_cb_r8_size == 0 ||
       msg17_ptr.is_null() || msg17_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg17");
        return FFI_CfmProcessMsg17Result::default();
    }

    // Deserialize cfm_state_cb_r8
    let cfm_state_cb_r8_bytes = unsafe { slice::from_raw_parts(cfm_state_cb_r8_ptr, cfm_state_cb_r8_size) };
    let cfm_state_cb_r8: CFMStateCBR8 = match bincode::deserialize(cfm_state_cb_r8_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_cb_r8: {:?}", e);
            return FFI_CfmProcessMsg17Result::default();
        }
    };

    // Deserialize msg17
    let msg17_bytes = unsafe { slice::from_raw_parts(msg17_ptr, msg17_size) };
    let msg17: CFMMsg17 = match bincode::deserialize(msg17_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg17: {:?}", e);
            return FFI_CfmProcessMsg17Result::default();
        }
    };

    // Call the actual function
    let (b_cb_value, msg18) = match cfm_process_msg17(cfm_state_cb_r8, &msg17) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg17: {:?}", e);
            return FFI_CfmProcessMsg17Result::default();
        }
    };

    // Serialize b_cb_value
    let serialized_b_cb_value = match bincode::serialize(&b_cb_value) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize b_cb_value: {:?}", e);
            return FFI_CfmProcessMsg17Result::default();
        }
    };

    // Serialize msg18
    let serialized_msg18 = match bincode::serialize(&msg18) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize msg18: {:?}", e);
            return FFI_CfmProcessMsg17Result::default();
        }
    };

    // Allocate memory for b_cb_value
    let b_cb_value_size = serialized_b_cb_value.len();
    let b_cb_value_layout = Layout::array::<u8>(b_cb_value_size).unwrap();
    let b_cb_value_ptr = unsafe { alloc(b_cb_value_layout) };
    unsafe {
        b_cb_value_ptr.copy_from_nonoverlapping(serialized_b_cb_value.as_ptr(), b_cb_value_size);
    }

    // Allocate memory for msg18
    let msg18_size = serialized_msg18.len();
    let msg18_layout = Layout::array::<u8>(msg18_size).unwrap();
    let msg18_ptr = unsafe { alloc(msg18_layout) };
    unsafe {
        msg18_ptr.copy_from_nonoverlapping(serialized_msg18.as_ptr(), msg18_size);
    }

    // Return result
    FFI_CfmProcessMsg17Result {
        b_cb_value_ptr,
        b_cb_value_size,
        msg18_ptr,
        msg18_size,
    }
}


#[repr(C)]
pub struct FFI_CfmProcessMsg18Result {
    b_ob_value_ptr: *mut u8,
    b_ob_value_size: usize,
}

impl Default for FFI_CfmProcessMsg18Result {
    fn default() -> Self {
        FFI_CfmProcessMsg18Result {
            b_ob_value_ptr: std::ptr::null_mut(),
            b_ob_value_size: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_cfm_process_msg18(
    cfm_state_ob_r9_ptr: *const u8,
    cfm_state_ob_r9_size: usize,
    msg18_ptr: *const u8,
    msg18_size: usize,
) -> FFI_CfmProcessMsg18Result {
    if cfm_state_ob_r9_ptr.is_null() || cfm_state_ob_r9_size == 0 ||
       msg18_ptr.is_null() || msg18_size == 0 {
        eprintln!("Invalid input pointers in ffi_cfm_process_msg18");
        return FFI_CfmProcessMsg18Result::default();
    }

    // Deserialize cfm_state_ob_r9
    let cfm_state_ob_r9_bytes = unsafe { slice::from_raw_parts(cfm_state_ob_r9_ptr, cfm_state_ob_r9_size) };
    let cfm_state_ob_r9: CFMStateOBR9 = match bincode::deserialize(cfm_state_ob_r9_bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to deserialize cfm_state_ob_r9: {:?}", e);
            return FFI_CfmProcessMsg18Result::default();
        }
    };

    // Deserialize msg18
    let msg18_bytes = unsafe { slice::from_raw_parts(msg18_ptr, msg18_size) };
    let msg18: CFMMsg18 = match bincode::deserialize(msg18_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Failed to deserialize msg18: {:?}", e);
            return FFI_CfmProcessMsg18Result::default();
        }
    };

    // Call the actual function
    let b_ob_value = match cfm_process_msg18(cfm_state_ob_r9, &msg18) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error in cfm_process_msg18: {:?}", e);
            return FFI_CfmProcessMsg18Result::default();
        }
    };

    // Serialize b_ob_value
    let serialized_b_ob_value = match bincode::serialize(&b_ob_value) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to serialize b_ob_value: {:?}", e);
            return FFI_CfmProcessMsg18Result::default();
        }
    };

    // Allocate memory for b_ob_value
    let b_ob_value_size = serialized_b_ob_value.len();
    let b_ob_value_layout = Layout::array::<u8>(b_ob_value_size).unwrap();
    let b_ob_value_ptr = unsafe { alloc(b_ob_value_layout) };
    unsafe {
        b_ob_value_ptr.copy_from_nonoverlapping(serialized_b_ob_value.as_ptr(), b_ob_value_size);
    }

    // Return result
    FFI_CfmProcessMsg18Result {
        b_ob_value_ptr,
        b_ob_value_size,
    }
}
