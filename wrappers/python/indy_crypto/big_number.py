import logging
import math
import ctypes
from ctypes import c_bool, byref, c_int8, c_void_p, POINTER, c_ubyte, c_size_t, c_ulonglong, c_wchar_p

from .lib import do_call


logger = logging.getLogger(__name__)


class BigNumber:
    @staticmethod
    def check_valid_number(number):
        if not isinstance(number, int) or number < 1:
            raise ValueError('Need a positive integer, not {}', number)

    @staticmethod
    def number_to_big_endian_array(number):
        int_array = list(
            number.to_bytes(math.ceil(number.bit_length() / 8),
                            'big') or b'\0')
        logger.debug("BigNumber::number_to_big_endian_array: <<< "
                     "number is: %r, array is: %r", number, int_array)
        array_size = len(int_array)
        pointer = (c_int8 * array_size)(*int_array)
        return pointer, array_size

    @staticmethod
    def is_prime(number) -> bool:
        logger.debug(
            "BigNumber::is_prime: >>> number: %r", number)

        BigNumber.check_valid_number(number)

        pointer, array_size = BigNumber.number_to_big_endian_array(number)
        valid = c_bool()
        do_call('indy_crypto_primality_check',
                pointer,
                array_size,
                byref(valid))

        res = valid
        logger.debug("BigNumber::is_prime: <<< res: %r", res)
        return res

    @staticmethod
    def modular_exponentiation(base, exponent, modulus):
        logger.debug("BigNumber::modular_exponentiation: >>> base: %r, "
                     "exponent: %r, modulus: %r", base, exponent, modulus)

        BigNumber.check_valid_number(base)
        BigNumber.check_valid_number(exponent)
        BigNumber.check_valid_number(modulus)

        base_pointer, base_array_size = BigNumber.number_to_big_endian_array(base)
        exponent_pointer, exponent_array_size = BigNumber.number_to_big_endian_array(exponent)
        modulus_pointer, modulus_array_size = BigNumber.number_to_big_endian_array(modulus)
        result_instance = c_void_p()
        do_call('indy_crypto_modular_exponentiation',
                base_pointer, base_array_size,
                exponent_pointer, exponent_array_size,
                modulus_pointer, modulus_array_size,
                byref(result_instance))

        # return BigNumber.from_bytes(result_instance)
        return BigNumber.from_string(result_instance)

    @staticmethod
    def from_bytes(c_instance):
        xbytes = POINTER(c_ubyte)()
        xbytes_len = c_size_t()

        do_call('indy_crypto_big_number_as_bytes', c_instance, byref(xbytes), byref(xbytes_len))

        logger.debug("BigNumber::modular_exponentiation: <<< xbytes: %r, xbytes_len: %r", xbytes, xbytes_len.value)
        logger.debug("BigNumber::modular_exponentiation: <<< byref(xbytes): %r, xbytes_len: %r", byref(xbytes), xbytes_len.value)

        res = bytes(xbytes[:xbytes_len.value])

        logger.debug("BigNumber::modular_exponentiation: <<< res: %r", res)

        return res

    @staticmethod
    def from_string(c_instance):
        xstr = POINTER(c_wchar_p)()
        do_call('indy_crypto_big_number_as_decimal_str', c_instance,
                byref(xstr))
        logger.debug("BigNumber::modular_exponentiation: <<< xstr: %r", xstr)
        return int(ctypes.string_at(xstr))