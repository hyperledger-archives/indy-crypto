#[macro_use]
pub mod ctypes;
pub mod json;
pub mod commitment;
pub mod rsa;

use bn::BigNumber;
use errors::IndyCryptoError;

pub fn get_hash_as_int(nums: &Vec<Vec<u8>>) -> Result<BigNumber, IndyCryptoError> {
    trace!("Helpers::get_hash_as_int: >>> nums: {:?}", nums);

    let hash = BigNumber::from_bytes(&BigNumber::hash_array(&nums)?);

    trace!("Helpers::get_hash_as_int: <<< hash: {:?}", hash);

    hash
}

pub fn clone_option_bignum(b: Option<BigNumber>) -> Result<Option<BigNumber>, IndyCryptoError> {
    match b {
        Some(ref bn) => Ok(Some(bn.clone()?)),
        None => Ok(None)
    }
}

macro_rules! hashset {
    ( $( $x:expr ),* ) => {
        {
            let mut set = ::std::collections::HashSet::new();
            $(
                set.insert($x);
            )*
            set
        }
    }
}

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {
        {
            let mut map = ::std::collections::HashMap::new();
            $(
                map.insert($key, $val);
            )*
            map
        }
    }
}

macro_rules! btreeset {
    ( $( $x:expr ),* ) => {
        {
            let mut set = ::std::collections::BTreeSet::new();
            $(
                set.insert($x);
            )*
            set
        }
    }
}

macro_rules! btreemap {
    ($( $key: expr => $val: expr ),*) => {
        {
            let mut map = ::std::collections::BTreeMap::new();
            $(
                map.insert($key, $val);
            )*
            map
        }
    }
}
