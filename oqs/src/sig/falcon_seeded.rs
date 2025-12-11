// SPDX-License-Identifier: MIT
//! Safe Rust wrapper for seeded Falcon-512 keypair generation

use crate::*;
use crate::ffi::{self, rand::OQS_randombytes, sig_falcon_seeded};

/// Minimum seed length for Falcon-512 (48 bytes)
pub const MIN_SEED_LENGTH: usize = 48;

/// Public key size
pub const PUBLIC_KEY_LENGTH: usize = 897;

/// Secret key size  
pub const SECRET_KEY_LENGTH: usize = 1281;

/// Errors for seeded Falcon operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeededFalconError {
    SeedTooShort,
    EmptyPassphrase,
    SaltTooShort,
    IterationCountTooLow,
    KeyGenerationFailed,
}

impl std::fmt::Display for SeededFalconError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeedTooShort => write!(f, "Seed must be at least {} bytes", MIN_SEED_LENGTH),
            Self::EmptyPassphrase => write!(f, "Passphrase cannot be empty"),
            Self::SaltTooShort => write!(f, "Salt must be at least 8 bytes"),
            Self::IterationCountTooLow => write!(f, "Iterations must be > 0"),
            Self::KeyGenerationFailed => write!(f, "Key generation failed"),
        }
    }
}

impl std::error::Error for SeededFalconError {}

pub type Result<T> = std::result::Result<T, SeededFalconError>;

/// Seeded Falcon-512 implementation
pub struct SeededFalcon512;

impl SeededFalcon512 {
    /// Generate a cryptographically secure seed
    pub fn generate_seed() -> Vec<u8> {
        let mut seed = vec![0u8; MIN_SEED_LENGTH];
        unsafe {
            OQS_randombytes(seed.as_mut_ptr(), MIN_SEED_LENGTH);
        }
        seed
    }

    /// Generate keypair from deterministic seed
    pub fn keypair_from_seed(seed: &[u8]) -> Result<(sig::PublicKey, sig::SecretKey)> {
        if seed.len() < MIN_SEED_LENGTH {
            return Err(SeededFalconError::SeedTooShort);
        }

        let mut public_key = vec![0u8; PUBLIC_KEY_LENGTH];
        let mut secret_key = vec![0u8; SECRET_KEY_LENGTH];

        let status = unsafe {
            sig_falcon_seeded::OQS_SIG_falcon_512_keypair_from_seed(
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
                seed.as_ptr(),
                seed.len(),
            )
        };

        if status != sig_falcon_seeded::OQS_SUCCESS {
            return Err(SeededFalconError::KeyGenerationFailed);
        }

        Ok((
            sig::PublicKey { bytes: public_key },
            sig::SecretKey { bytes: secret_key },
        ))
    }

    /// Derive seed from passphrase
    pub fn seed_from_passphrase(
        passphrase: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Vec<u8>> {
        if passphrase.is_empty() {
            return Err(SeededFalconError::EmptyPassphrase);
        }
        if salt.len() < 8 {
            return Err(SeededFalconError::SaltTooShort);
        }
        if iterations == 0 {
            return Err(SeededFalconError::IterationCountTooLow);
        }

        let mut seed = vec![0u8; MIN_SEED_LENGTH];

        let status = unsafe {
            sig_falcon_seeded::OQS_SIG_falcon_512_seed_from_passphrase(
                passphrase.as_ptr(),
                passphrase.len(),
                salt.as_ptr(),
                salt.len(),
                iterations,
                seed.as_mut_ptr(),
            )
        };

        if status != sig_falcon_seeded::OQS_SUCCESS {
            return Err(SeededFalconError::KeyGenerationFailed);
        }

        Ok(seed)
    }

    /// Generate keypair from passphrase (convenience method)
    pub fn keypair_from_passphrase(
        passphrase: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<(sig::PublicKey, sig::SecretKey)> {
        let seed = Self::seed_from_passphrase(passphrase, salt, iterations)?;
        Self::keypair_from_seed(&seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_generation() {
        let seed = SeededFalcon512::generate_seed();
        let (pk1, sk1) = SeededFalcon512::keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = SeededFalcon512::keypair_from_seed(&seed).unwrap();

        assert_eq!(pk1.as_ref(), pk2.as_ref());
        assert_eq!(sk1.as_ref(), sk2.as_ref());
    }

    #[test]
    fn test_different_seeds() {
        let seed1 = SeededFalcon512::generate_seed();
        let seed2 = SeededFalcon512::generate_seed();
        
        let (pk1, _) = SeededFalcon512::keypair_from_seed(&seed1).unwrap();
        let (pk2, _) = SeededFalcon512::keypair_from_seed(&seed2).unwrap();

        assert_ne!(pk1.as_ref(), pk2.as_ref());
    }

    #[test]
    fn test_seed_too_short() {
        let short_seed = vec![0u8; 32];
        assert!(matches!(
            SeededFalcon512::keypair_from_seed(&short_seed),
            Err(SeededFalconError::SeedTooShort)
        ));
    }

    #[test]
    fn test_passphrase_derivation() {
        let passphrase = b"correct horse battery staple";
        let salt = SeededFalcon512::generate_seed();
        
        let (pk1, _) = SeededFalcon512::keypair_from_passphrase(passphrase, &salt, 10000).unwrap();
        let (pk2, _) = SeededFalcon512::keypair_from_passphrase(passphrase, &salt, 10000).unwrap();

        assert_eq!(pk1.as_ref(), pk2.as_ref());
    }
}
