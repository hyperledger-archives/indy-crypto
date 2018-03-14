# Shamir Secret Sharing
Exposes the low level API for generating and reconstructing secrets. Depends on [rusty-secrets](https://github.com/SpinResearch/RustySecrets).

1. `shard_secret(secret: Vec<u8>, m: u8, n: u8, sign_shares: Option<bool>) -> Result<Vec<Share>, IndyCryptoError>`.  
Splits the bytes of the secret `secret` in `n` different shares and `m-of-n` shares are required to reconstitute the secret. `sign_shares` if provided, all shards are signed.  
1. `recover_secret(shards: Vec<Share>, verify_signatures: Option<bool>) -> Result<Vec<u8>, IndyCryptoError>`.  
Recover the secret from the given `shards`. `verify_signatures` if given verifies the signatures.
