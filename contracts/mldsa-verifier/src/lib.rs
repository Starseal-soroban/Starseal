//! Starseal ML-DSA verifier.
//!
//! A stateless Soroban contract that an OpenZeppelin smart account names as the
//! verifier of an external signer, `Signer::External(verifier, key_data)`. It
//! checks ML-DSA signatures (FIPS 204) at all three security levels with the
//! host functions added in Protocol 30 (CAP-87), so the lattice arithmetic runs
//! in Stellar Core rather than in contract code.
//!
//! # Wire format
//!
//! The format matches the Perch and nido verifiers, so a key and a signature
//! made for one of them also work here:
//!
//! - `key_data` is `sha256(public_key)`, 32 bytes. OpenZeppelin limits external
//!   key data to 256 bytes and ML-DSA public keys are 1,312 to 2,592 bytes, so
//!   the account stores a commitment and each signature carries the key.
//! - `sig_data` is the XDR of [`MlDsaSigData`], a map of `public_key` and
//!   `signature`.
//! - The signature is pure `ML-DSA.Sign` (not HashML-DSA) over the 32-byte
//!   digest the account passes as `hash`, with the context string [`CONTEXT`].
//!
//! The security level is read from the public key's length, and the signature
//! must have the matching length.
//!
//! # Results
//!
//! - Malformed input traps with an [`Error`].
//! - A public key that doesn't match `key_data` returns `false`.
//! - A well-formed signature that fails verification traps in the host, because
//!   the ML-DSA host functions have no boolean form. The account's
//!   authorization fails in both cases.
//! - Otherwise `verify` returns `true`.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, xdr::FromXdr, Bytes,
    BytesN, Env, Vec,
};

/// FIPS 204 context string bound into every signature. Shared with the Perch
/// and nido verifiers.
pub const CONTEXT: &[u8] = b"nido-mldsa-v1";

/// Length of the digest an OpenZeppelin account asks its verifiers to check.
pub const DIGEST_LEN: u32 = 32;

/// What a signer submits as `sig_data`, XDR-encoded.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlDsaSigData {
    /// The FIPS 204 encoded public key. Its SHA-256 is the signer's `key_data`.
    pub public_key: Bytes,
    /// The FIPS 204 encoded signature over the 32-byte digest.
    pub signature: Bytes,
}

/// Reasons `verify` rejects its input as malformed.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// `hash` is not 32 bytes.
    DigestLength = 1,
    /// `sig_data` is not the XDR of `MlDsaSigData`.
    SigDataEncoding = 2,
    /// The public key length matches no ML-DSA parameter set.
    PublicKeyLength = 3,
    /// The signature length doesn't match the public key's parameter set.
    SignatureLength = 4,
}

/// An ML-DSA parameter set.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Level {
    /// NIST security category 2.
    MlDsa44,
    /// NIST security category 3.
    MlDsa65,
    /// NIST security category 5.
    MlDsa87,
}

impl Level {
    /// The parameter set whose public keys have `len` bytes.
    pub const fn from_public_key_len(len: u32) -> Option<Self> {
        match len {
            1312 => Some(Self::MlDsa44),
            1952 => Some(Self::MlDsa65),
            2592 => Some(Self::MlDsa87),
            _ => None,
        }
    }

    /// Encoded public key length in bytes.
    pub const fn public_key_len(self) -> u32 {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Encoded signature length in bytes.
    pub const fn signature_len(self) -> u32 {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

/// The `key_data` an account stores for an encoded ML-DSA public key.
pub fn key_commitment(e: &Env, public_key: &Bytes) -> BytesN<32> {
    e.crypto().sha256(public_key).to_bytes()
}

#[contract]
pub struct MlDsaVerifier;

#[contractimpl]
impl MlDsaVerifier {
    /// Checks that `sig_data` proves the key named by `key_data` signed `hash`.
    ///
    /// `hash` is the account's 32-byte auth digest. `key_data` is the SHA-256 of
    /// an encoded ML-DSA public key. `sig_data` is the XDR of the map
    /// `{ public_key: Bytes, signature: Bytes }`; the level (44, 65 or 87) is
    /// taken from the public key's length. The signature must be pure ML-DSA
    /// with context `nido-mldsa-v1`.
    ///
    /// Returns `false` when the public key doesn't match `key_data`. Traps on
    /// malformed input and on a signature that fails verification.
    pub fn verify(e: Env, hash: Bytes, key_data: BytesN<32>, sig_data: Bytes) -> bool {
        if hash.len() != DIGEST_LEN {
            panic_with_error!(&e, Error::DigestLength);
        }
        let sig = MlDsaSigData::from_xdr(&e, &sig_data)
            .unwrap_or_else(|_| panic_with_error!(&e, Error::SigDataEncoding));
        let level = Level::from_public_key_len(sig.public_key.len())
            .unwrap_or_else(|| panic_with_error!(&e, Error::PublicKeyLength));
        if sig.signature.len() != level.signature_len() {
            panic_with_error!(&e, Error::SignatureLength);
        }
        if key_commitment(&e, &sig.public_key) != key_data {
            return false;
        }

        let context = Bytes::from_slice(&e, CONTEXT);
        let crypto = e.crypto();
        match level {
            Level::MlDsa44 => crypto.ml_dsa_44_verify(
                &fixed(&e, &sig.public_key),
                &hash,
                &fixed(&e, &sig.signature),
                &context,
            ),
            Level::MlDsa65 => crypto.ml_dsa_65_verify(
                &fixed(&e, &sig.public_key),
                &hash,
                &fixed(&e, &sig.signature),
                &context,
            ),
            Level::MlDsa87 => crypto.ml_dsa_87_verify(
                &fixed(&e, &sig.public_key),
                &hash,
                &fixed(&e, &sig.signature),
                &context,
            ),
        }
        true
    }

    /// The canonical form of a signer's key: the 32-byte commitment itself.
    ///
    /// Each public key has exactly one encoding, so one commitment. The account
    /// compares these values to reject duplicate signers.
    pub fn canonicalize_key(_e: Env, key_data: BytesN<32>) -> Bytes {
        key_data.into()
    }

    /// [`Self::canonicalize_key`] for each key, in input order.
    pub fn batch_canonicalize_key(e: Env, key_data: Vec<BytesN<32>>) -> Vec<Bytes> {
        Vec::from_iter(&e, key_data.iter().map(Bytes::from))
    }
}

/// Converts bytes whose length was already checked into a fixed-size array.
fn fixed<const N: usize>(e: &Env, bytes: &Bytes) -> BytesN<N> {
    BytesN::try_from(bytes).unwrap_or_else(|_| panic_with_error!(e, Error::SigDataEncoding))
}

#[cfg(test)]
mod test;
