use bn::BigNumber;

use ffi::ErrorCode;
use errors::ToErrorCode;
use std::os::raw::c_void;
use std::slice;

#[no_mangle]
pub extern fn indy_crypto_primality_check(number: u64,
                                          is_prime: *mut bool) -> ErrorCode {
    trace!("indy_crypto_primality_check: >>> number: {:?}, is_prime: {:?}", number, is_prime);

    check_useful_c_positive_number!(number, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(is_prime, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_primality_check: number: {:?}, is_prime: {:?}", number, is_prime);

    let res = match BigNumber::from_dec(&number.to_string()) {
        Ok(big_number) => {
            match big_number.is_prime(None) {
                Ok(valid) => {
                    trace!("indy_crypto_primality_check: big_number: {:?}", valid);
                    unsafe { *is_prime = valid; }
                    ErrorCode::Success
                }
                Err(err) => err.to_error_code()
            }

        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_primality_check: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn indy_crypto_primality_check_works() {
        let number1 = 29;
        let mut valid = false;
        let err_code = indy_crypto_primality_check(number1,&mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number2 = 39;
        let err_code = indy_crypto_primality_check(number2, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!valid);

        let number3 = 47055833459;
        let err_code = indy_crypto_primality_check(number3,&mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number4 = 47055833460;
        let err_code = indy_crypto_primality_check(number4,&mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!valid);

//        let number5 = -21;
//        let err_code = indy_crypto_primality_check(number5,&mut valid);
//        assert_ne!(err_code, ErrorCode::Success);

//        let number6 = 23.5;
//        let err_code = indy_crypto_primality_check(number6,&mut valid);
//        assert_ne!(err_code, ErrorCode::Success);
    }
}