//! Checks the verifier against signatures made with @noble/post-quantum, the
//! library the TypeScript SDK signs with. Regenerate the vectors with
//! `node test-vectors/generate.mjs`.

use serde_json::Value;
use soroban_sdk::{xdr::ToXdr, Bytes, BytesN, Env};
use starseal_mldsa_verifier::{MlDsaSigData, MlDsaVerifier, MlDsaVerifierClient};

const VECTORS: &str = include_str!("../../../test-vectors/ml-dsa.json");

fn bytes(e: &Env, v: &Value, field: &str) -> Bytes {
    let raw = hex::decode(v[field].as_str().unwrap()).unwrap();
    Bytes::from_slice(e, &raw)
}

#[test]
fn noble_signatures_verify_on_the_host() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(doc["context"], "nido-mldsa-v1");
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 9);

    for v in vectors {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let client = MlDsaVerifierClient::new(&env, &env.register(MlDsaVerifier, ()));

        let key_data: BytesN<32> = bytes(&env, v, "key_data").try_into().unwrap();
        let sig_data = MlDsaSigData {
            public_key: bytes(&env, v, "public_key"),
            signature: bytes(&env, v, "signature"),
        }
        .to_xdr(&env);
        let digest = bytes(&env, v, "digest");

        let result = client.try_verify(&digest, &key_data, &sig_data);
        let name = v["name"].as_str().unwrap();
        if v["valid"].as_bool().unwrap() {
            assert_eq!(result, Ok(Ok(true)), "{name} should verify");
        } else {
            assert!(result.is_err(), "{name} should be rejected");
        }
    }
}
