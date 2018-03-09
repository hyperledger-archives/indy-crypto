extern crate rusty_secrets;

use errors::IndyCryptoError;
use utils::json::{JsonEncodable, JsonDecodable};

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Share {
    value: String
}

impl JsonEncodable for Share {}

impl<'a> JsonDecodable<'a> for Share {}

pub fn shard_secret(m: u8, n: u8, secret: &str, sign_shares: bool) -> Result<Vec<Share>, IndyCryptoError> {
    match rusty_secrets::sss::split_secret(m, n, &secret.as_bytes(), sign_shares) {
        Ok(shares) => Ok(shares.into_iter().map(|share| Share { value: share }).collect()),
        Err(msg) => Err(IndyCryptoError::InvalidStructure(format!("Unable to create shares: {:?}", msg)))
    }
}

pub fn recover_secret(shares: Vec<Share>, verify_signature: bool) -> Result<Vec<u8>, IndyCryptoError> {
    let string_shares: Vec<String> = shares.into_iter().map(|share| share.value).collect();
    match rusty_secrets::sss::recover_secret(&string_shares, verify_signature) {
        Ok(secret) => Ok(secret.to_vec()),
        Err(msg) => Err(IndyCryptoError::InvalidStructure(format!("Unable to recreate secret: {:?}", msg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_shares() {
        let secret = "this is a really big test string";
        let shares = shard_secret(3, 5, secret, false).unwrap();
        println!("shares={:?}", shares);
        assert_eq!(shares.len(), 5);
    }
}
