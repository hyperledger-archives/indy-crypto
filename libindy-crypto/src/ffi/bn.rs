use bn::BigNumber;

use ffi::ErrorCode;
use errors::ToErrorCode;
use std::slice;

#[no_mangle]
pub extern fn indy_crypto_primality_check(big_endian_number: *const u8,
                                          size_in_bytes: usize,
                                          is_prime: *mut bool) -> ErrorCode {
    trace!("indy_crypto_primality_check: >>> big_endian_number: {:?}, size_in_bytes: {:?}, is_prime: {:?}", big_endian_number, size_in_bytes, is_prime);

    check_useful_c_byte_array!(big_endian_number, size_in_bytes, ErrorCode::CommonInvalidParam1, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(is_prime, ErrorCode::CommonInvalidParam3);

    trace!("indy_crypto_primality_check: big_endian_number: {:?}, size_in_bytes: {:?}, is_prime: {:?}", big_endian_number, size_in_bytes, is_prime);

    let res = match BigNumber::from_bytes(&big_endian_number) {
        Ok(big_number) => {
            match big_number.is_prime(None) {
                Ok(valid) => {
                    trace!("indy_crypto_primality_check: big_endian_number: {:?}", big_number);
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

    #[test]
    fn c() {
        let number1 = vec![29].as_ptr() as *const u8;
        let mut valid = false;
        let err_code = indy_crypto_primality_check(number1,1, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number2 = vec![1, 153, 25].as_ptr() as *const u8; // number 104729
        let err_code = indy_crypto_primality_check(number2, 3,&mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number3 = vec![9, 252, 51, 8, 129].as_ptr() as *const u8;   // number 42885908609
        let err_code = indy_crypto_primality_check(number3,5, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number4 = [116, 9, 191, 244, 10].as_ptr() as *const u8;   // number 47055833460
        let err_code = indy_crypto_primality_check(number4,5, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!valid);
    }
}