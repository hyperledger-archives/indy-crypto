use bn::BigNumber;

use ffi::ErrorCode;
use errors::ToErrorCode;
use std::slice;

#[no_mangle]
pub extern fn indy_crypto_primality_check(big_endian_number: *const u8,
                                          size_in_bytes: usize,
                                          is_prime: *mut bool) -> ErrorCode {
    trace!("indy_crypto_primality_check: >>> big_endian_number: {:?}, size_in_bytes: {:?}, is_prime: {:?}", big_endian_number, size_in_bytes, is_prime);
    println!("before {:?}", big_endian_number);
    check_useful_c_byte_array!(big_endian_number, size_in_bytes, ErrorCode::CommonInvalidParam1, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(is_prime, ErrorCode::CommonInvalidParam3);

    trace!("indy_crypto_primality_check: big_endian_number: {:?}, size_in_bytes: {:?}, is_prime: {:?}", big_endian_number, size_in_bytes, is_prime);

    println!("after {:?}", big_endian_number);
    let res = match BigNumber::from_bytes(&big_endian_number) {
        Ok(big_number) => {
            match big_number.is_prime(None) {
                Ok(valid) => {
                    println!("{:?}", big_number);
                    println!("to bytes {:?}", big_number.to_bytes());
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
    fn indy_crypto_primality_check_works() {
        let number1 = vec![29].as_ptr();
        let mut valid = false;
        let err_code = indy_crypto_primality_check(number1,1, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number2 = vec![1, 153, 25].as_ptr(); // number 104729
        let err_code = indy_crypto_primality_check(number2, 3,&mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number3 = vec![9, 252, 51, 8, 129].as_ptr();   // number 42885908609
        let err_code = indy_crypto_primality_check(number3,5, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number4 = [116, 9, 191, 244, 10].as_ptr();   // number 47055833460
        let err_code = indy_crypto_primality_check(number4,5, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!valid);

        let number6 = [204, 248, 234, 50, 24, 50, 123, 244, 109, 76, 16, 66, 12, 245, 54, 77].as_ptr();   // number 272454950813783527414999934504692692557
        let err_code = indy_crypto_primality_check(number6,16, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

//        let number5 = vec![175, 151, 131, 108, 102, 141, 162, 107, 99, 34, 90, 210, 161, 21, 95, 135, 74, 195, 151, 217, 185, 90, 220, 50, 204, 96, 223, 214, 10, 240, 182, 15].as_ptr();   // number 79422449460098942399106282402512198969536520971550757303162642879618420356623
        let number5 = vec![175, 151, 131, 108, 102, 141, 162, 107, 99, 34, 90, 210, 161, 21, 95, 135, 74, 195, 151, 217, 185, 90, 220, 50, 204, 96, 223, 214, 10, 240, 182, 15].as_ptr();   // number 79422449460098942399106282402512198969536520971550757303162642879618420356623
        let err_code = indy_crypto_primality_check(number5,32, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);
    }
}