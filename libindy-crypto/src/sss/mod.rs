extern crate rusty_secrets;

use errors::IndyCryptoError;
use utils::json::{JsonEncodable, JsonDecodable};

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct Share {
    value: String
}

impl JsonEncodable for Share {}

impl<'a> JsonDecodable<'a> for Share {}

pub fn shard_secret(m: usize, n: usize, secret: &Vec<u8>, sign_shares: bool) -> Result<Vec<Share>, IndyCryptoError> {
    match rusty_secrets::sss::split_secret(m as u8, n as u8, &secret.as_slice(), sign_shares) {
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
    use std::str;

    fn check_secret(secret: &str, mut shares: Vec<Share>, p: usize){
        let recovered_secret = recover_secret(shares.split_at_mut(p).0.to_vec(), false).unwrap();
        let recovered_secret_as_str = str::from_utf8(&recovered_secret).unwrap();
        println!("recovered secret={:?}; from {} shares", &recovered_secret_as_str, p);
        assert_eq!(secret, recovered_secret_as_str);
    }

    #[test]
    fn test_create_shares() {
        let secret = "this is a really big test string";
        let shares = shard_secret(3, 5, &secret.as_bytes().to_vec(), false).unwrap();
        println!("shares={:?}", shares);
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_recover_secret() {
        let secret = "this is a really big test string";
        let mut shares = shard_secret(3, 5, &secret.as_bytes().to_vec(), false).unwrap();

        // Recover with threshold number of shares
        check_secret(&secret, shares.clone(), 3);

        // Recover with more than threshold number of shares
        check_secret(&secret, shares.clone(), 4);

        // Recover with less than threshold number of shares
        assert!(recover_secret(shares.split_at_mut(2).0.to_vec(), false).is_err());
    }
}
