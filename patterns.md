# Pattern Catalog

This catalog is for passive static scanning. Matches are hypotheses, not final
findings. The verifier must confirm context before a maintainer-facing claim is
made.

## File types to include

- Source: `.js`, `.ts`, `.tsx`, `.py`, `.go`, `.rs`, `.java`, `.kt`, `.cs`,
  `.rb`, `.php`, `.c`, `.cc`, `.cpp`, `.h`, `.hpp`, `.swift`
- Config: `.json`, `.yaml`, `.yml`, `.toml`, `.ini`, `.conf`, `.cnf`, `.env.example`
- Build/dependency: `package.json`, `package-lock.json`, `pyproject.toml`,
  `requirements.txt`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `pom.xml`,
  `build.gradle`, `composer.json`, `Gemfile.lock`
- Infra: `Dockerfile`, `docker-compose.yml`, `.github/workflows/*.yml`,
  `nginx.conf`, `traefik.yml`, `caddyfile`
- Docs: `README.md`, `SECURITY.md`, `docs/**/*.md`

Exclude or down-rank:

- `node_modules/`
- `vendor/`
- `dist/`
- `build/`
- generated protobuf code
- minified bundles
- fixture-only directories
- lockfile-only mentions without a runtime parent

## Primitive patterns

RSA:

- `RSA`
- `RS256`, `RS384`, `RS512`
- `rsa-sha256`
- `createPrivateKey`
- `createPublicKey`
- `crypto.privateDecrypt`
- `crypto.publicEncrypt`
- `PKCS1`
- `PKCS#1`
- `OAEP`
- `rsaEncryption`
- `-----BEGIN RSA PRIVATE KEY-----`
- `-----BEGIN PUBLIC KEY-----`

ECDSA/ECDH:

- `ECDSA`
- `ECDH`
- `ES256`, `ES384`, `ES512`
- `prime256v1`
- `secp256r1`
- `P-256`
- `P-384`
- `P-521`
- `elliptic`
- `ecparam`

secp256k1:

- `secp256k1`
- `k256`
- `bitcoinjs-lib`
- `ethers`
- `web3`
- `@noble/secp256k1`
- `elliptic.ec('secp256k1')`
- `EC('secp256k1')`
- `ECPair`
- `wallet`
- `privateKeyToAccount`

Ed25519:

- `Ed25519`
- `ed25519`
- `EdDSA`
- `tweetnacl`
- `libsodium`
- `sodium-native`
- `@noble/ed25519`

PQC readiness:

- `post-quantum`
- `post quantum`
- `PQC`
- `hybrid`
- `Kyber`
- `ML-KEM`
- `Dilithium`
- `ML-DSA`
- `Falcon`
- `SPHINCS`
- `liboqs`
- `oqs`
- `Open Quantum Safe`
- `X25519MLKEM768`
- `SecP256r1MLKEM768`

JWT:

- `jsonwebtoken`
- `jwt`
- `jose`
- `JWKS`
- `JWK`
- `alg`
- `algorithm`
- `none`
- `HS256`
- `RS256`
- `ES256`
- `decode(` near `jwt`
- `verify(` near `jwt`

TLS:

- `TLSv1`
- `TLSv1.0`
- `TLSv1.1`
- `TLSv1.2`
- `TLSv1.3`
- `ssl_protocols`
- `ciphers`
- `minVersion`
- `maxVersion`
- `rejectUnauthorized`
- `NODE_TLS_REJECT_UNAUTHORIZED`
- `InsecureSkipVerify`
- `verify_mode`
- `CERT_NONE`

## Dependency library hints

JavaScript/TypeScript:

- `crypto`
- `node-forge`
- `jsonwebtoken`
- `jose`
- `elliptic`
- `@noble/secp256k1`
- `@noble/ed25519`
- `ethers`
- `web3`
- `bitcoinjs-lib`
- `tls`
- `https`

Python:

- `cryptography`
- `pycryptodome`
- `rsa`
- `ecdsa`
- `jwcrypto`
- `pyjwt`
- `python-jose`
- `ssl`
- `OpenSSL`

Go:

- `crypto/rsa`
- `crypto/ecdsa`
- `crypto/elliptic`
- `crypto/tls`
- `github.com/golang-jwt/jwt`
- `github.com/lestrrat-go/jwx`

Rust:

- `rsa`
- `p256`
- `p384`
- `k256`
- `ed25519-dalek`
- `jsonwebtoken`
- `rustls`
- `openssl`

Java/Kotlin:

- `java.security.Signature`
- `KeyPairGenerator`
- `RSA`
- `EC`
- `Nimbus JOSE JWT`
- `jjwt`
- `BouncyCastle`

## Risk boosts

Boost confidence/risk when evidence appears near:

- `sign`
- `verify`
- `token`
- `auth`
- `session`
- `wallet`
- `address`
- `certificate`
- `x509`
- `csr`
- `keystore`
- `privateKey`
- `publicKey`
- `issuer`
- `jwks`
- `firmware`
- `package signing`
- `release signing`

## Risk reducers

Reduce confidence/risk when evidence appears in:

- tests only
- examples only
- comments only
- docs comparing algorithms only
- migration notes that already discuss PQC/hybrid migration
- dependency lockfiles without source/config usage

