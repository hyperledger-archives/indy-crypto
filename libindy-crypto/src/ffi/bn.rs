use bn::BigNumber;

use ffi::ErrorCode;
use errors::ToErrorCode;
use utils::ctypes::CTypesUtils;

use std::slice;
use std::os::raw::{c_void, c_char};

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

#[no_mangle]
pub extern fn indy_crypto_modular_exponentiation(base: *const u8,
                                                 base_size_in_bytes: usize,
                                                 exponent: *const u8,
                                                 exponent_size_in_bytes: usize,
                                                 modulus: *const u8,
                                                 modulus_size_in_bytes: usize,
                                                 result: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_modular_exponentiation: >>> base: {:?}, base_size_in_bytes: {:?}, exponent: {:?}, exponent_size_in_bytes: {:?}, \
    modulus: {:?}, modulus_size_in_bytes: {:?}, result: {:?}", base, base_size_in_bytes, exponent, exponent_size_in_bytes, modulus,
           modulus_size_in_bytes, result);
    check_useful_c_byte_array!(base, base_size_in_bytes, ErrorCode::CommonInvalidParam1, ErrorCode::CommonInvalidParam2);
    check_useful_c_byte_array!(exponent, exponent_size_in_bytes, ErrorCode::CommonInvalidParam3, ErrorCode::CommonInvalidParam4);
    check_useful_c_byte_array!(modulus, modulus_size_in_bytes, ErrorCode::CommonInvalidParam5, ErrorCode::CommonInvalidParam6);
    check_useful_c_ptr!(result, ErrorCode::CommonInvalidParam7);

    trace!("indy_crypto_modular_exponentiation: >>> base: {:?}, base_size_in_bytes: {:?}, exponent: {:?}, exponent_size_in_bytes: {:?}, \
    modulus: {:?}, modulus_size_in_bytes: {:?}, result: {:?}", base, base_size_in_bytes, exponent, exponent_size_in_bytes, modulus,
           modulus_size_in_bytes, result);

    let base_num = match BigNumber::from_bytes(&base) {
        Ok(big_number) => big_number,
        Err(err) => {
            error!("indy_crypto_modular_exponentiation: >>> Cannot convert {:?} to BigNumber", &base);
            return err.to_error_code()
        }
    };

    let exponent_num = match BigNumber::from_bytes(&exponent) {
        Ok(big_number) => big_number,
        Err(err) => {
            error!("indy_crypto_modular_exponentiation: >>> Cannot convert {:?} to BigNumber", &exponent);
            return err.to_error_code()
        }
    };

    let modulus_num = match BigNumber::from_bytes(&modulus) {
        Ok(big_number) => big_number,
        Err(err) => {
            error!("indy_crypto_modular_exponentiation: >>> Cannot convert {:?} to BigNumber", &modulus);
            return err.to_error_code()
        }
    };

    let res = match base_num.mod_exp(&exponent_num, &modulus_num, None) {
        Ok(big_number) => {
            trace!("indy_crypto_modular_exponentiation: result: {:?}", big_number);
            unsafe { *result = Box::into_raw(Box::new(big_number)) as *const c_void; }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_modular_exponentiation: <<< res: {:?}", res);
    res
}

#[no_mangle]
pub extern fn indy_crypto_big_number_as_bytes(big_number: *const c_void,
                                              bytes_p: *mut *const u8, bytes_len_p: *mut usize) -> ErrorCode {
    trace!("indy_crypto_big_number_as_bytes: >>> big_number: {:?}, bytes_p: {:?}, bytes_len_p: {:?}", big_number, bytes_p, bytes_len_p);

    check_useful_c_reference!(big_number, BigNumber, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(bytes_p, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(bytes_len_p, ErrorCode::CommonInvalidParam3);

    trace!("indy_crypto_big_number_as_bytes: big_number: {:?}", big_number);

    unsafe {
        let big_num_vec = big_number.to_bytes().unwrap();
        let big_num_bytes = big_num_vec.as_slice();
        println!("big_num_bytes={:?}", &big_num_bytes);
        *bytes_p = big_num_bytes.as_ptr();
        *bytes_len_p = big_num_bytes.len();
        println!("bytes_p={:?}", bytes_p);
        println!("*bytes_p={:?}", *bytes_p);
        println!("big_num_bytes.as_ptr={:?}", big_num_bytes.as_ptr());
        /*println!("bytes={:?}", *bytes_p as u8);
        println!("bytes_len_p={:?}", *bytes_len_p);*/
    };

    let res = ErrorCode::Success;

    trace!("indy_crypto_big_number_as_bytes: <<< res: {:?}", res);
    res
}

// TODO: Remove me; This is temporary code
#[no_mangle]
pub extern fn indy_crypto_big_number_as_decimal_str(big_number: *const c_void,
                                                    decimal: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_big_number_as_bytes: >>> big_number: {:?}, decimal: {:?}", big_number, decimal);

    check_useful_c_reference!(big_number, BigNumber, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(decimal, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_big_number_as_decimal_str: big_number: {:?}", big_number);

    unsafe {
        let big_num_str = big_number.to_dec().unwrap();
        let big_num_c_str = CTypesUtils::string_to_cstring(big_num_str);
        *decimal = big_num_c_str.into_raw();
    };

    let res = ErrorCode::Success;

    trace!("indy_crypto_big_number_as_bytes: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn indy_crypto_primality_check_works() {
        let number1 = vec![29];
        let mut valid = false;
        let err_code = indy_crypto_primality_check(number1.as_ptr(),1, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number2 = vec![1, 153, 25]; // number 104729
        let err_code = indy_crypto_primality_check(number2.as_ptr(), 3,&mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number3 = vec![9, 252, 51, 8, 129];   // number 42885908609
        let err_code = indy_crypto_primality_check(number3.as_ptr(),5, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let number4 = [116, 9, 191, 244, 10];   // number 47055833460
        let err_code = indy_crypto_primality_check(number4.as_ptr(),5, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!valid);

        let number6 = [204, 248, 234, 50, 24, 50, 123, 244, 109, 76, 16, 66, 12, 245, 54, 77];   // number 272454950813783527414999934504692692557
        let err_code = indy_crypto_primality_check(number6.as_ptr(),16, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

//        let number5 = vec![175, 151, 131, 108, 102, 141, 162, 107, 99, 34, 90, 210, 161, 21, 95, 135, 74, 195, 151, 217, 185, 90, 220, 50, 204, 96, 223, 214, 10, 240, 182, 15].as_ptr();   // number 79422449460098942399106282402512198969536520971550757303162642879618420356623
        let number5 = vec![175, 151, 131, 108, 102, 141, 162, 107, 99, 34, 90, 210, 161, 21, 95, 135, 74, 195, 151, 217, 185, 90, 220, 50, 204, 96, 223, 214, 10, 240, 182, 15];   // number 79422449460098942399106282402512198969536520971550757303162642879618420356623
        let err_code = indy_crypto_primality_check(number5.as_ptr(),32, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);
    }

    #[test]
    fn indy_crypto_modular_exponentiation_works() {
        let base = vec![29];
        let exp = vec![5];
        let modulus = vec![101];
        let mut result: *const c_void = ptr::null();
        let err_code = indy_crypto_modular_exponentiation(base.as_ptr(), 1, exp.as_ptr(), 1, modulus.as_ptr(), 1, &mut result);
        assert_eq!(err_code, ErrorCode::Success);
        println!("result={:?}", &result);
        assert!(!result.is_null());

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = indy_crypto_big_number_as_bytes(result, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        println!("bytes reference={:?}", &bytes);
        println!("bytes={:?}", bytes);
        println!("bytes_len={:?}", &bytes_len);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);
        unsafe {
            assert_eq!(*bytes, 69 as u8);
        }

        // TODO: Complete this test or remove `indy_crypto_big_number_as_decimal_str`
        let mut string: *const c_char = ptr::null();
        let err_code = indy_crypto_big_number_as_decimal_str(result, &mut string);
        assert_eq!(err_code, ErrorCode::Success);
        println!("string={:?}", &string);
        unsafe {
            println!("*string={:?}", *string);
        }
        assert!(!string.is_null());
    }
}