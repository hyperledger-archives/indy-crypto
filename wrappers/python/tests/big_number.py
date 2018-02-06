from indy_crypto.big_number import BigNumber


def test_primality_testing():
    for number in [2, 23, 31, 42885908609, 24473809133, 47055833459]:
        assert BigNumber.is_prime(number), number

    for number in [24, 42885908610, 24473809134, 47055833460]:
        assert not BigNumber.is_prime(number), number
