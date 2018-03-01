use bn::{BigNumber, BigNumberContext};
use errors::IndyCryptoError;


pub fn generate_RSA_modulus(size_in_bits: usize,
                            ctx: &mut BigNumberContext) -> Result<(BigNumber, BigNumber, BigNumber), IndyCryptoError> {
    if size_in_bits % 2 != 0 {
        return Err(IndyCryptoError::InvalidParam1(
            format!("Need an even number of bits, found {}", size_in_bits))
        );
    }

    let factor_size = size_in_bits / 2;
    let p = BigNumber::generate_safe_prime(factor_size)?;
    let q = BigNumber::generate_safe_prime(factor_size)?;
    let n = p.mul(&q, Some(ctx))?;
    Ok((n, p, q))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_RSA_modulus_basic() {
        // check modulus is the product of 2 primes
        let mut ctx = BigNumber::new_context().unwrap();
        let (n, p, q) = generate_RSA_modulus(2048, &mut ctx).unwrap();
        assert!(BigNumber::is_prime(&p,Some(&mut ctx)).unwrap());
        assert!(BigNumber::is_prime(&q,Some(&mut ctx)).unwrap());
        assert_eq!(n, p.mul(&q, Some(&mut ctx)).unwrap());
    }
}