// SPDX-License-Identifier: MIT
//! Low-level FFI bindings for seeded Falcon-512 keypair generation

use libc::{c_int, size_t, uint8_t, uint32_t};

/// Status codes from liboqs
pub type OQS_STATUS = c_int;

pub const OQS_SUCCESS: OQS_STATUS = 0;
pub const OQS_ERROR: OQS_STATUS = -1;

/// Falcon-512 key sizes
pub const OQS_SIG_FALCON_512_LENGTH_PUBLIC_KEY: usize = 897;
pub const OQS_SIG_FALCON_512_LENGTH_SECRET_KEY: usize = 1281;

/// Minimum seed length (48 bytes)
pub const OQS_SIG_FALCON_MIN_SEED_LEN: usize = 48;

extern "C" {
    /// Generate Falcon-512 keypair from deterministic seed
    pub fn OQS_SIG_falcon_512_keypair_from_seed(
        public_key: *mut uint8_t,
        secret_key: *mut uint8_t,
        seed: *const uint8_t,
        seed_len: size_t,
    ) -> OQS_STATUS;

    /// Derive seed from passphrase
    pub fn OQS_SIG_falcon_512_seed_from_passphrase(
        passphrase: *const uint8_t,
        passphrase_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
        iterations: uint32_t,
        out_seed: *mut uint8_t,
    ) -> OQS_STATUS;
}
