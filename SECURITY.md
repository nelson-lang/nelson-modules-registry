# Security Model

The `registry.json` file is signed using Ed25519. Each package entry contains the SHA-256 checksum of its `.nmz` archive. By signing `registry.json`, all package checksums are therefore authenticated transitively: there is no separate signature for each package.

* The private signing key is stored only in a GitHub Actions secret and in an offline backup. It is never stored in the repository.
* The public key is published in `pubkey.ed25519` and embedded in Nelson.
* A Nelson client rejects a remote registry if its signature is missing or invalid, unless `NELSON_NMM_REGISTRY_ALLOW_UNSIGNED=1` is set.

Key rotation: to change the signing key, first publish the new public key in a Nelson release, sign `registry.json` with both the old and new keys for at least one release, then retire the old key.

To report a security issue, open a private issue or contact the maintainer.
