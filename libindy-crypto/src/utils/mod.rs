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

macro_rules! hashset {
    ( $( $x:expr ),* ) => {
        {
            let mut temp_set = ::std::collections::HashSet::new();
            $(
                temp_set.insert($x);
            )*
            temp_set
        }
    };
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
