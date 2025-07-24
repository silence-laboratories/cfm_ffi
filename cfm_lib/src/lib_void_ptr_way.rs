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

const P_HEX: &str = "ccc87af2fe0b80db9924beecec1bc803";
/// Prime integer p
pub const P: U128 = U128::from_be_hex(P_HEX);


use rand::{thread_rng, Rng, RngCore};
use rand::rngs::{StdRng, ThreadRng};
use std::os::raw::{c_char, c_void};
use std::ffi::CStr;
use rand::SeedableRng;


use cfm_init_protocol::{
    cfm_init_create_msg1, cfm_init_process_msg1, cfm_init_process_msg2, cfm_init_process_msg3,
    CFMInitMsg1, CFMInitMsg2, CFMInitMsg3
};

use auth_beaver_triples::{
    abt_create_msg1, abt_process_msg1, abt_process_msg2, abt_process_msg3, abt_process_msg4, abt_process_msg5, ABTMsg1, ABTMsg2, ABTStateCBR1, ABTStateCBR2, ABTStateOBR1, Share, TripleShare,
    ABTMsg3
};

use cfm_protocol::{
    cfm_create_msg1, cfm_process_msg1, cfm_process_msg10, cfm_process_msg11, cfm_process_msg12,
    cfm_process_msg13, cfm_process_msg14, cfm_process_msg15, cfm_process_msg16, cfm_process_msg17,
    cfm_process_msg18, cfm_process_msg2, cfm_process_msg3, cfm_process_msg4, cfm_process_msg5,
    cfm_process_msg6, cfm_process_msg7, cfm_process_msg8, cfm_process_msg9,
    NUMBER_OF_AUTH_BEAVER_TRIPLES, NUMBER_OF_SHARES,
};

use crate::cfm_init_protocol::{CFMInitOTSeedsCB, CFMInitOTSeedsOB};

// A holder for our RNG so that the pointer we return is a thin pointer.
#[repr(C)]
pub struct RngHolder {
    // This field is a Box<dyn RngCore> (a fat pointer) but the struct itself
    // is allocated on the heap and we return a pointer to the struct.
    pub rng: Box<dyn RngCore>,
}

/// Creates an RNG.  
/// If `seed_req` is null, uses `thread_rng()`.  
/// Otherwise, uses `StdRng::seed_from_u64(seed)` with the provided seed.
/// Returns a pointer to a RngHolder as an opaque pointer.
#[no_mangle]
pub extern "C" fn create_rng() -> *mut c_void {
    // Create a non-deterministic RNG using thread_rng.
    let rng: Box<dyn RngCore> = Box::new(thread_rng());
    let holder = Box::new(RngHolder { rng });
    Box::into_raw(holder) as *mut c_void
}



#[no_mangle]
pub extern "C" fn generate_init_session_id(rng_ptr: *mut c_void) -> *mut c_void {
    // Safety: we assume rng_ptr is a valid pointer to a Box<ThreadRng>
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };
    let session_id: [u8; 32] = rng.gen();
    Box::into_raw(Box::new(session_id)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn create_msg(msg_type: *const c_char) -> *mut c_void {
    // Ensure the pointer is not null.
    if msg_type.is_null() {
        return std::ptr::null_mut();
    }
    
    // Convert the C string to a Rust &str.
    let c_str = unsafe { CStr::from_ptr(msg_type) };
    match c_str.to_str() {
        Ok("msg1") => {
            let msg1 = CFMInitMsg1::default();
            Box::into_raw(Box::new(msg1)) as *mut c_void
        }
        Ok("msg2") => {
            let msg2 = CFMInitMsg2::default();
            Box::into_raw(Box::new(msg2)) as *mut c_void
        }
        Ok("msg3") => {
            let msg2 = CFMInitMsg3::default();
            Box::into_raw(Box::new(msg2)) as *mut c_void
        }
        _ => std::ptr::null_mut(),
    }
}


#[no_mangle]
pub extern "C" fn get_state_ob(
    session_id_ptr: *const c_void,
    msg1_ptr: *mut c_void,
    rng_ptr: *mut c_void,
) -> *mut c_void {
    // Reconstruct the session ID from the opaque pointer.
    let session_id = unsafe { *(session_id_ptr as *const [u8; 32]) };
    // Reconstruct msg1 from the opaque pointer.
    let msg1 = unsafe { &mut *(msg1_ptr as *mut CFMInitMsg1) };
    // Reconstruct the RNG from the opaque pointer.
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    // Call the underlying function.
    let state_ob = cfm_init_create_msg1(&session_id, msg1, rng);
    // Box the state_ob and return an opaque pointer.
    Box::into_raw(Box::new(state_ob)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn get_state_cb(
    session_id_ptr: *const c_void,
    msg1_ptr: *const c_void,
    msg2_ptr: *mut c_void,
    rng_ptr: *mut c_void,
) -> *mut c_void {
    // Safety: we assume session_id_ptr points to a [u8; 32]
    let session_id = unsafe { *(session_id_ptr as *const [u8; 32]) };
    // Safety: we assume msg1_ptr points to a CFMInitMsg1
    let msg1 = unsafe { &*(msg1_ptr as *const CFMInitMsg1) };
    // Safety: we assume msg2_ptr points to a CFMInitMsg2
    let msg2 = unsafe { &mut *(msg2_ptr as *mut CFMInitMsg2) };
    // Safety: we assume rng_ptr points to a ThreadRng
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    let state_cb = cfm_init_process_msg1(&session_id, msg1, msg2, rng)
        .expect("cfm_init_process_msg1 failed");

    Box::into_raw(Box::new(state_cb)) as *mut c_void
}


#[no_mangle]
pub extern "C" fn get_ot_seed_ob(
    state_ob_ptr: *mut c_void,
    msg2_ptr: *const c_void,
    msg3_ptr: *mut c_void,
    rng_ptr: *mut c_void,
) -> *mut c_void {
    // Consume state_ob by converting the raw pointer back into a Box.
    let state_ob = unsafe { Box::from_raw(state_ob_ptr as *mut _) };
    // Reconstruct msg2 (borrowed).
    let msg2 = unsafe { &*(msg2_ptr as *const CFMInitMsg2) };
    // Reconstruct msg3 as mutable.
    let msg3 = unsafe { &mut *(msg3_ptr as *mut CFMInitMsg3) };
    // Reconstruct the RNG.
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    let ot_seeds_ob = cfm_init_process_msg2(*state_ob, msg2, msg3, rng)
        .expect("cfm_init_process_msg2 failed");
    Box::into_raw(Box::new(ot_seeds_ob)) as *mut c_void
}


#[no_mangle]
pub extern "C" fn get_ot_seed_cb(
    state_cb_ptr: *mut c_void,
    msg3_ptr: *const c_void,
) -> *mut c_void {
    // Consume state_cb.
    let state_cb = unsafe { Box::from_raw(state_cb_ptr as *mut _) };
    // Reconstruct msg3 (borrowed).
    let msg3 = unsafe { &*(msg3_ptr as *const CFMInitMsg3) };

    let ot_seeds_cb = cfm_init_process_msg3(*state_cb, msg3)
        .expect("cfm_init_process_msg3 failed");
    Box::into_raw(Box::new(ot_seeds_cb)) as *mut c_void
}


#[repr(C)]
pub struct AbtMsg1Result {
    state_cb_r1: *mut c_void,
    msg1: *mut c_void,
}

#[no_mangle]
pub extern "C" fn ffi_abt_create_msg1(
    session_id_ptr: *const c_void,
    ot_seeds_cb_ptr: *const c_void,
    rng_ptr: *mut c_void,
) -> AbtMsg1Result {
    // Reconstruct session_id
    let session_id = unsafe { *(session_id_ptr as *const [u8; 32]) };

    // Reconstruct ot_seeds_cb
    let ot_seeds_cb = unsafe { &*(ot_seeds_cb_ptr as *const CFMInitOTSeedsCB) };

    // Reconstruct RNG
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    let eta_i = NUMBER_OF_SHARES;
    let eta_m = NUMBER_OF_AUTH_BEAVER_TRIPLES;

    // Call the actual function
    let (state_cb_r1, msg1) = abt_create_msg1(&session_id, ot_seeds_cb, P, eta_i, eta_m, rng);

    // Return a struct containing two pointers
    AbtMsg1Result {
        state_cb_r1: Box::into_raw(Box::new(state_cb_r1)) as *mut c_void,
        msg1: Box::into_raw(Box::new(msg1)) as *mut c_void,
    }
}


#[repr(C)]
pub struct AbtProcessMsg1Result {
    state_ob_r1: *mut c_void,
    shares_ob: *mut c_void,
    auth_triples_ob: *mut c_void,
    msg2: *mut c_void,
}

#[no_mangle]
pub extern "C" fn ffi_abt_process_msg1(
    session_id_ptr: *const c_void,
    ot_seeds_ob_ptr: *const c_void,
    msg1_ptr: *const c_void,
    rng_ptr: *mut c_void,
) -> AbtProcessMsg1Result {
    // Reconstruct session_id
    let session_id = unsafe { *(session_id_ptr as *const [u8; 32]) };

    // Reconstruct ot_seeds_ob
    let ot_seeds_ob = unsafe { &*(ot_seeds_ob_ptr as *const CFMInitOTSeedsOB) };

    // Reconstructs msg_1
    let msg1 = unsafe { &*(msg1_ptr as *const ABTMsg1)};

    // Reconstruct RNG
    let rng = unsafe { &mut *(rng_ptr as *mut ThreadRng) };

    let eta_i = NUMBER_OF_SHARES;
    let eta_m = NUMBER_OF_AUTH_BEAVER_TRIPLES;
    let p = P;

    // Call the actual function
    let (state_ob_r1, shares_ob, auth_triples_ob, msg2) =
        abt_process_msg1(&session_id, ot_seeds_ob, p, eta_i, eta_m, msg1, rng).unwrap();

    // Convert to raw pointers
    let state_ob_r1_ptr = Box::into_raw(Box::new(state_ob_r1)) as *mut c_void;
    let shares_ob_ptr = Box::into_raw(Box::new(shares_ob)) as *mut c_void;
    let auth_triples_ob_ptr = Box::into_raw(Box::new(auth_triples_ob)) as *mut c_void;
    let msg2_ptr = Box::into_raw(Box::new(msg2)) as *mut c_void;

    AbtProcessMsg1Result {
        state_ob_r1: state_ob_r1_ptr,
        shares_ob: shares_ob_ptr,
        auth_triples_ob: auth_triples_ob_ptr,
        msg2: msg2_ptr,
    }
}


#[repr(C)]
pub struct AbtProcessMsg2Result {
    state_cb_r2: *mut c_void,
    shares_cb: *mut c_void,
    auth_triples_cb: *mut c_void,
    msg3: *mut c_void,
}

#[no_mangle]
pub extern "C" fn ffi_abt_process_msg2(
    state_cb_r1_ptr: *const c_void,
    ot_seeds_cb_ptr: *const c_void,
    msg2_prt: *const c_void,
    rng_ptr: *const c_void
) -> AbtProcessMsg2Result {
    let state_cb_r1 = unsafe {
        & *(state_cb_r1_ptr as *const ABTStateCBR1)
    };

    let ot_seeds_cb = unsafe {
        & *(ot_seeds_cb_ptr as *const CFMInitOTSeedsCB)
    };

    let msg2 = unsafe {
        & *(msg2_prt as *const ABTMsg2)
    };

    let rng = unsafe {
        &mut *(rng_ptr as *mut ThreadRng)
    };

    let (state_cb_r2, shares_cb, auth_triples_cb, msg3) =
            abt_process_msg2(state_cb_r1, ot_seeds_cb, msg2, rng).unwrap();

            
    // Convert to raw pointers
    let state_cb_r2_ptr = Box::into_raw(Box::new(state_cb_r2)) as *mut c_void;
    let shares_cb_ptr = Box::into_raw(Box::new(shares_cb)) as *mut c_void;
    let auth_triples_cb_ptr = Box::into_raw(Box::new(auth_triples_cb)) as *mut c_void;
    let msg3_ptr = Box::into_raw(Box::new(msg3)) as *mut c_void;
    
    AbtProcessMsg2Result{
        state_cb_r2: state_cb_r2_ptr,
        shares_cb: shares_cb_ptr,
        auth_triples_cb: auth_triples_cb_ptr,
        msg3: msg3_ptr
    }
}

#[repr(C)]
pub struct AbtProcessMsg3Result {
    state_ob_r2: *mut c_void,
    msg4: *mut c_void
}

//The #[no_mangle] attribute prevents Rust from renaming the function during compilation so that it can be called from external programs (like Python, C, or other languages via FFI).

#[no_mangle]
pub extern "C" fn ffi_abt_process_msg3(
    state_ob_r1_ptr: *const c_void,
    shares_ob_ptr: *mut c_void,  // Ensure mutable for Vec<Share>
    auth_triples_ob_ptr: *mut c_void,  // Ensure mutable for Vec<TripleShare>
    msg3_ptr: *const c_void,
) -> AbtProcessMsg3Result {
    // Ensure pointers are not null before dereferencing
    if state_ob_r1_ptr.is_null() || shares_ob_ptr.is_null() || auth_triples_ob_ptr.is_null() || msg3_ptr.is_null() {
        println!("ffi_abt_process_msg3: Received null pointer!");
        return AbtProcessMsg3Result {
            state_ob_r2: std::ptr::null_mut(),
            msg4: std::ptr::null_mut(),
        };
    }

    // Safely reconstruct references from raw pointers
    let state_ob_r1 = unsafe { &*(state_ob_r1_ptr as *const ABTStateOBR1) };
    let shares_ob = unsafe { &mut *(shares_ob_ptr as *mut Vec<Share>) };
    let auth_triples_ob = unsafe { &mut *(auth_triples_ob_ptr as *mut Vec<TripleShare>) };
    let msg3 = unsafe { &*(msg3_ptr as *const ABTMsg3) };

    // Call the actual function and handle errors gracefully
    match abt_process_msg3(state_ob_r1, shares_ob, auth_triples_ob, msg3) {
        Ok((state_ob_r2, msg4)) => {
            let state_ob_r2_ptr = Box::into_raw(Box::new(state_ob_r2)) as *mut c_void;
            let msg4_ptr = Box::into_raw(Box::new(msg4)) as *mut c_void;

            println!("ffi_abt_process_msg3 -> state_ob_r2_ptr: {:?}", state_ob_r2_ptr);
            println!("ffi_abt_process_msg3 -> msg4_ptr: {:?}", msg4_ptr);

            AbtProcessMsg3Result {
                state_ob_r2: state_ob_r2_ptr,
                msg4: msg4_ptr,
            }
        }
        Err(e) => {
            println!("ffi_abt_process_msg3: Error occurred - {:?}", e);
            AbtProcessMsg3Result {
                state_ob_r2: std::ptr::null_mut(),
                msg4: std::ptr::null_mut(),
            }
        }
    }
}
