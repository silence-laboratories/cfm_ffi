/// Computation security parameter
pub const LAMBDA: usize = 128;

/// Statistical security parameter
pub const LAMBDA_S: usize = 80;

/// Computation security parameter in bytes
pub const LAMBDA_BYTES: usize = LAMBDA / 8;

/// B parameter
pub const B_PARAMETER: usize = 47;

/// Masking parameter
pub const MASK: usize = LAMBDA_S + B_PARAMETER + 1;

/// Masking parameter in bytes
pub const MASK_BYTES: usize = MASK / 8;

/// LABEL for H1 random oracle function
pub const H1_RO_LABEL: &str = "SL-PSC-H1-function";

/// LABEL for H2 random oracle function
pub const H2_RO_LABEL: &str = "SL-PSC-H2-function";

/// LABEL for DLog proof
pub const DLOG_LABEL: &str = "SL-PSC-DLog-proof";

/// LABEL for CFM protocol
pub const CFM_LABEL: &str = "SL-CFM-protocol";
