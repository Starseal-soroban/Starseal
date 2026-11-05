extern crate std;

use fips204::traits::{KeyGen, SerDes, Signer};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use soroban_sdk::{xdr::ToXdr, Bytes, BytesN, Env, Error as SdkError, Vec};
use std::vec::Vec as StdVec;

use crate::{
    key_commitment, Error, Level, MlDsaSigData, MlDsaVerifier, MlDsaVerifierClient, CONTEXT,
};

const KEY_SEED: [u8; 32] = [7u8; 32];
const SIGN_SEED: [u8; 32] = [9u8; 32];
const DIGEST: [u8; 32] = [0xab; 32];

/// A key pair and a signature over `message` with `context`, made with the
/// `fips204` crate rather than the host's implementation.
fn sign(level: Level, message: &[u8], context: &[u8]) -> (StdVec<u8>, StdVec<u8>) {
    match level {
        Level::MlDsa44 => {
            let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&KEY_SEED);
            let sig = sk.try_sign_with_seed(&SIGN_SEED, message, context).unwrap();
            (pk.into_bytes().to_vec(), sig.to_vec())
        }
        Level::MlDsa65 => {
            let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&KEY_SEED);
            let sig = sk.try_sign_with_seed(&SIGN_SEED, message, context).unwrap();
            (pk.into_bytes().to_vec(), sig.to_vec())
        }
        Level::MlDsa87 => {
            let (pk, sk) = ml_dsa_87::KG::keygen_from_seed(&KEY_SEED);
            let sig = sk.try_sign_with_seed(&SIGN_SEED, message, context).unwrap();
            (pk.into_bytes().to_vec(), sig.to_vec())
        }
    }
}

fn sig_data(e: &Env, public_key: &[u8], signature: &[u8]) -> Bytes {
    MlDsaSigData {
        public_key: Bytes::from_slice(e, public_key),
        signature: Bytes::from_slice(e, signature),
    }
    .to_xdr(e)
}

struct Setup {
    env: Env,
    client: MlDsaVerifierClient<'static>,
}

fn setup() -> Setup {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let id = env.register(MlDsaVerifier, ());
    let client = MlDsaVerifierClient::new(&env, &id);
    Setup { env, client }
}

fn digest(e: &Env) -> Bytes {
    Bytes::from_array(e, &DIGEST)
}

fn commitment(e: &Env, public_key: &[u8]) -> BytesN<32> {
    key_commitment(e, &Bytes::from_slice(e, public_key))
}

#[test]
fn accepts_a_valid_signature_at_each_level() {
    let s = setup();
    for level in [Level::MlDsa44, Level::MlDsa65, Level::MlDsa87] {
        let (pk, sig) = sign(level, &DIGEST, CONTEXT);
        assert_eq!(pk.len() as u32, level.public_key_len());
        assert_eq!(sig.len() as u32, level.signature_len());
        assert!(s.client.verify(
            &digest(&s.env),
            &commitment(&s.env, &pk),
            &sig_data(&s.env, &pk, &sig)
        ));
    }
}

#[test]
fn returns_false_when_the_key_does_not_match_key_data() {
    let s = setup();
    let (pk, sig) = sign(Level::MlDsa65, &DIGEST, CONTEXT);
    let other_key = BytesN::from_array(&s.env, &[1u8; 32]);
    assert!(!s
        .client
        .verify(&digest(&s.env), &other_key, &sig_data(&s.env, &pk, &sig)));
}

#[test]
fn traps_on_a_tampered_signature() {
    let s = setup();
    let (pk, mut sig) = sign(Level::MlDsa65, &DIGEST, CONTEXT);
    sig[10] ^= 0x01;
    let result = s.client.try_verify(
        &digest(&s.env),
        &commitment(&s.env, &pk),
        &sig_data(&s.env, &pk, &sig),
    );
    assert!(result.is_err());
}

#[test]
fn traps_when_the_digest_differs_from_what_was_signed() {
    let s = setup();
    let (pk, sig) = sign(Level::MlDsa44, &DIGEST, CONTEXT);
    let other_digest = Bytes::from_array(&s.env, &[0xcd; 32]);
    let result = s.client.try_verify(
        &other_digest,
        &commitment(&s.env, &pk),
        &sig_data(&s.env, &pk, &sig),
    );
    assert!(result.is_err());
}

#[test]
fn traps_on_a_signature_made_with_another_context() {
    let s = setup();
    let (pk, sig) = sign(Level::MlDsa87, &DIGEST, b"");
    let result = s.client.try_verify(
        &digest(&s.env),
        &commitment(&s.env, &pk),
        &sig_data(&s.env, &pk, &sig),
    );
    assert!(result.is_err());
}

#[test]
fn rejects_a_digest_that_is_not_32_bytes() {
    let s = setup();
    let (pk, sig) = sign(Level::MlDsa65, &DIGEST, CONTEXT);
    let short = Bytes::from_array(&s.env, &[0xab; 31]);
    let result = s.client.try_verify(
        &short,
        &commitment(&s.env, &pk),
        &sig_data(&s.env, &pk, &sig),
    );
    assert_eq!(result, Err(Ok(SdkError::from(Error::DigestLength))));
}

#[test]
fn rejects_a_public_key_of_unknown_length() {
    let s = setup();
    let (mut pk, sig) = sign(Level::MlDsa65, &DIGEST, CONTEXT);
    pk.push(0);
    let result = s.client.try_verify(
        &digest(&s.env),
        &commitment(&s.env, &pk),
        &sig_data(&s.env, &pk, &sig),
    );
    assert_eq!(result, Err(Ok(SdkError::from(Error::PublicKeyLength))));
}

#[test]
fn rejects_a_signature_from_another_level() {
    let s = setup();
    let (pk, _) = sign(Level::MlDsa65, &DIGEST, CONTEXT);
    let (_, sig44) = sign(Level::MlDsa44, &DIGEST, CONTEXT);
    let result = s.client.try_verify(
        &digest(&s.env),
        &commitment(&s.env, &pk),
        &sig_data(&s.env, &pk, &sig44),
    );
    assert_eq!(result, Err(Ok(SdkError::from(Error::SignatureLength))));
}

#[test]
fn rejects_sig_data_that_is_not_the_expected_xdr() {
    let s = setup();
    let (pk, _) = sign(Level::MlDsa65, &DIGEST, CONTEXT);
    let garbage = Bytes::from_array(&s.env, &[0u8; 64]);
    let result = s
        .client
        .try_verify(&digest(&s.env), &commitment(&s.env, &pk), &garbage);
    assert!(result.is_err());
}

#[test]
fn canonical_key_is_the_commitment() {
    let s = setup();
    let key = BytesN::from_array(&s.env, &[3u8; 32]);
    assert_eq!(s.client.canonicalize_key(&key), Bytes::from(key.clone()));
}

#[test]
fn batch_canonicalization_keeps_input_order() {
    let s = setup();
    let a = BytesN::from_array(&s.env, &[1u8; 32]);
    let b = BytesN::from_array(&s.env, &[2u8; 32]);
    let keys = Vec::from_array(&s.env, [a.clone(), b.clone()]);
    let out = s.client.batch_canonicalize_key(&keys);
    assert_eq!(
        out,
        Vec::from_array(&s.env, [Bytes::from(a), Bytes::from(b)])
    );
}
