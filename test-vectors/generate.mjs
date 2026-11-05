// Generates test-vectors/ml-dsa.json: ML-DSA signatures made with
// @noble/post-quantum, the library @starseal/sdk signs with. The Rust tests
// check that the Soroban host verifies them, so the two sides stay compatible.
//
// Run: node test-vectors/generate.mjs
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

const CONTEXT = utf8ToBytes("nido-mldsa-v1");
const LEVELS = [
  ["ml-dsa-44", ml_dsa44],
  ["ml-dsa-65", ml_dsa65],
  ["ml-dsa-87", ml_dsa87],
];

const vectors = [];
for (const [level, scheme] of LEVELS) {
  const seed = sha256(utf8ToBytes(`starseal key seed ${level}`));
  const { publicKey, secretKey } = scheme.keygen(seed);
  const digest = sha256(utf8ToBytes(`starseal auth digest ${level}`));
  const base = {
    level,
    public_key: bytesToHex(publicKey),
    key_data: bytesToHex(sha256(publicKey)),
    digest: bytesToHex(digest),
  };

  vectors.push({
    ...base,
    name: `${level} deterministic`,
    signature: bytesToHex(
      scheme.sign(digest, secretKey, { context: CONTEXT, extraEntropy: false }),
    ),
    valid: true,
  });

  const entropy = sha256(utf8ToBytes(`starseal signing entropy ${level}`));
  vectors.push({
    ...base,
    name: `${level} hedged`,
    signature: bytesToHex(
      scheme.sign(digest, secretKey, { context: CONTEXT, extraEntropy: entropy }),
    ),
    valid: true,
  });

  vectors.push({
    ...base,
    name: `${level} signed without the context string`,
    signature: bytesToHex(scheme.sign(digest, secretKey, { extraEntropy: false })),
    valid: false,
  });
}

const out = {
  generator: "@noble/post-quantum 0.7.1",
  context: "nido-mldsa-v1",
  vectors,
};
const path = join(dirname(fileURLToPath(import.meta.url)), "ml-dsa.json");
writeFileSync(path, `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${vectors.length} vectors to ${path}`);
