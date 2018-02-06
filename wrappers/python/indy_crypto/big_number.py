import logging
from ctypes import c_bool, byref

from .lib import do_call


class BigNumber:
    @staticmethod
    def is_prime(number) -> bool:
        logger = logging.getLogger(__name__)
        logger.debug(
            "BigNumber::is_prime: >>> number: %r", number)

        valid = c_bool()
        do_call('indy_crypto_primality_check',
                number,
                byref(valid))

        res = valid
        logger.debug("BigNumber::is_prime: <<< res: %r", res)
        return res
