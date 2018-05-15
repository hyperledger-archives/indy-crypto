import logging
import math
from ctypes import c_bool, byref, c_int8

from .lib import do_call


class BigNumber:
    @staticmethod
    def is_prime(number) -> bool:
        logger = logging.getLogger(__name__)
        logger.debug(
            "BigNumber::is_prime: >>> number: %r", number)

        if not isinstance(number, int) or number < 1:
            raise ValueError('Need a positive integer, not {}', number)

        int_array = list(
            number.to_bytes(math.ceil(number.bit_length() / 8),
                            'big') or b'\0')
        logger.debug("BigNumber::is_prime: <<< array is: %r", int_array)
        array_size = len(int_array)
        pointer = (c_int8 * array_size)(*int_array)
        valid = c_bool()
        do_call('indy_crypto_primality_check',
                pointer,
                array_size,
                byref(valid))

        res = valid
        logger.debug("BigNumber::is_prime: <<< res: %r", res)
        return res
