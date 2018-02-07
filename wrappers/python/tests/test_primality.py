import pytest

from indy_crypto.big_number import BigNumber


def test_bad_input():
    for n in [-90, 0, 2.2, 91.0]:
        with pytest.raises(ValueError):
            assert BigNumber.is_prime(n)


def test_check_primes():
    for number in [2, 23, 31, 263, 104729, 42885908609, 24473809133, 47055833459]:
        assert BigNumber.is_prime(number), number


def test_check_non_primes():
    for number in [24, 42885908610, 24473809134, 47055833460]:
        assert not BigNumber.is_prime(number), number


def test_big_primes():
    big_primes_256bit = [
        79422449460098942399106282402512198969536520971550757303162642879618420356623,
        111239814848601840476117025037343156956140807592049293111743976116251852031961,
        110807377343103593013767585056169865297439509005813309754958294117148328724967
    ]
    for number in big_primes_256bit:
        assert BigNumber.is_prime(number), number

    for number in big_primes_256bit:
        # Since each prime is odd, prime+1 will not be prime
        assert not BigNumber.is_prime(number+1), number
