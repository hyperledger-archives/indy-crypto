use bn::{BigNumber, BigNumberContext};
use utils::commitment::get_pedersen_commitment;
use utils::rsa::generate_RSA_modulus;
use errors::IndyCryptoError;
use super::constants::*;


pub fn generate_policy_address(ctx: &mut BigNumberContext) -> Result<BigNumber, IndyCryptoError> {
    let n1 = BigNumber::from_dec(ACCUM1_MODULUS_BY_4)?;
    let n2 = BigNumber::from_dec(ACCUM2_MODULUS_BY_4)?;
    let mut i;
    loop {
        i = BigNumber::rand(ACCUM_MODULUS_SIZE-2)?;
        // Since n1 and n2 are calculated only once, the next line can be reduced to only one comparison by comparing with just the smaller of n1 and n2
        if i < n1 && i < n2 { break; }
    }
    Ok(i)
}

/// Generate a double commitment, i.e pedersen commitment to pedersen commitment over a secret
///
/// # Arguments
/// * `g_1` - first generator of the first commitment
/// * `h_1` - second generator of the first commitment
/// * `g_2` - first generator of the second commitment
/// * `h_2` - second generator of the second commitment
/// * `secret` - the secret to which the first commitment is made
/// * `policy_address` - the random value to be used in the second commitment
/// * `mod1` - modulus for the first commitment
/// * `mod2` - modulus for the second commitment
/// * `ctx` - big number context
///
/// # Result
/// Return the double commitment, `C_2` and the random value `r_0` of the first commitment,
/// i.e `C_2 = (g_2^C_1)*(h_2^policy_address) where C_1 = (g_1^secret)*(h_1^r_0)`
pub fn gen_double_commitment_to_secret(g_1: &BigNumber, h_1: &BigNumber, secret: &BigNumber,
                                       g_2: &BigNumber, h_2: &BigNumber,
                                       policy_address: &BigNumber, mod1: &BigNumber,
                                       mod2: &BigNumber, ctx: &mut BigNumberContext) -> Result<(BigNumber, BigNumber), IndyCryptoError> {
    trace!("helpers::gen_double_commitment_to_secret: >>> g_1: {:?}, h_1: {:?}, secret: {:?}, \
    g_2: {:?}, h_2: {:?}, policy_address: {:?}", g_1, h_1, secret, g_2, h_2, policy_address);

    let mut double_commitment;
    let mut r_0;

    loop {
        // TODO: Revisit `R_0_SIZE`, the paper constraints it to < N/4 which should matter R_0_SIZE << ACCUM1_MODULUS
        r_0 = BigNumber::rand(R_0_SIZE)?;
        let first_commitment = get_pedersen_commitment(g_1, secret, h_1, &r_0, mod1, ctx)?;
        double_commitment = get_pedersen_commitment(g_2, &first_commitment, h_2, policy_address, mod2, ctx)?;
        if double_commitment.is_prime(Some(ctx))? { break; }
    }
    trace!("Helpers::gen_double_commitment_to_secret: <<< double_commitment: {:?}", double_commitment);

    Ok((double_commitment, r_0))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_commitment() {
        let mut ctx = BigNumber::new_context().unwrap();

        let g_1 = BigNumber::from_dec(G_1).unwrap();
        let g_2 = BigNumber::from_dec(G_2).unwrap();
        let h_1 = BigNumber::from_dec(H_1).unwrap();
        let h_2 = BigNumber::from_dec(H_2).unwrap();
        let mod_1 = BigNumber::from_dec(P_1).unwrap();
        let mod_2 = BigNumber::from_dec(P_2).unwrap();

        let secret = BigNumber::rand(SECRET_SIZE).unwrap();;
        let policy_address = BigNumber::rand(POLICY_ADDRESS_SIZE).unwrap();

        let (comm, _) = gen_double_commitment_to_secret(&g_1, &h_1, &secret, &g_2, &h_2,
                                                        &policy_address, &mod_1,
                                                        &mod_2, &mut ctx).unwrap();
        assert!(comm.is_prime(Some(&mut ctx)).unwrap());
    }

    #[test]
    #[ignore] //TODO Expensive test, only run to generate public params
    fn test_generate_public_ps() {
        // Generating p_1, p_2, p_3, such that all 3 are safe primes satisfying
        // p_1 = 2p_0 + 1; p_2 = 2p_1 + 1; p_3 = 2p_2 + 1
        let mut ctx = BigNumber::new_context().unwrap();
        let mut p_1;
        let mut p_2;
        let mut p_3;
        loop {
            p_1 = BigNumber::generate_safe_prime(P_SIZE).unwrap();
            println!("p_1 is {:?}", p_1);
            p_2 = p_1.mul(&BigNumber::from_u32(2).unwrap(), Some(&mut ctx)).unwrap().add(&BigNumber::from_u32(1).unwrap()).unwrap();
            println!("p_2 is {:?}", p_2);
            if p_2.is_prime(Some(&mut ctx)).unwrap() {
                p_3 = p_2.mul(&BigNumber::from_u32(2).unwrap(), Some(&mut ctx)).unwrap().add(&BigNumber::from_u32(1).unwrap()).unwrap();
                println!("p_3 is {:?}", p_3);
                if p_3.is_prime(Some(&mut ctx)).unwrap() { break; }
            }
        }
    }

    #[test]
    fn test_check_public_ps() {
        let mut ctx = BigNumber::new_context().unwrap();
        let p_1 = BigNumber::from_dec(P_1).unwrap();
        let p_2 = BigNumber::from_dec(P_2).unwrap();
        let p_3 = BigNumber::from_dec(P_3).unwrap();
        assert!(p_1.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_2.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_3.is_prime(Some(&mut ctx)).unwrap());
    }

    #[test]
    #[ignore] //TODO Expensive test, only run to generate public params
    fn test_generate_generators() {
        // Generating g_1, g_2, g_3, h_1, h_2, h_3
        let mut g_1;
        let mut g_2;
        let mut g_3;
        let mut h_1;
        let mut h_2;
        let mut h_3;
        let p1 = BigNumber::from_dec(P_1).unwrap();
        let p2 = BigNumber::from_dec(P_2).unwrap();
        let p3 = BigNumber::from_dec(P_3).unwrap();
        let number1 = BigNumber::from_u32(1).unwrap();
        loop {
            g_1 = BigNumber::random_QR(&p1).unwrap();
            if number1 != g_1 { break; }
        }
        println!("g_1 is {:?}", g_1);
        loop {
            h_1 = BigNumber::random_QR(&p1).unwrap();
            if number1 != h_1 { break; }
        }
        println!("h_1 is {:?}", h_1);
        loop {
            g_2 = BigNumber::random_QR(&p2).unwrap();
            if number1 != g_2 { break; }
        }
        println!("g_2 is {:?}", g_2);
        loop {
            h_2 = BigNumber::random_QR(&p2).unwrap();
            if number1 != h_2 { break; }
        }
        println!("h_2 is {:?}", h_2);
        loop {
            g_3 = BigNumber::random_QR(&p3).unwrap();
            if number1 != g_3 { break; }
        }
        println!("g_3 is {:?}", g_3);
        loop {
            h_3 = BigNumber::random_QR(&p3).unwrap();
            if number1 != h_3 { break; }
        }
        println!("h_3 is {:?}", h_3);
    }

    #[test]
    #[ignore] //TODO Expensive test, only run to generate public params
    fn test_generate_accumulator_moduli() {
        let mut ctx = BigNumber::new_context().unwrap();
        let n1 = generate_RSA_modulus(ACCUM_MODULUS_SIZE, &mut ctx).unwrap();
        let n2 = generate_RSA_modulus(ACCUM_MODULUS_SIZE, &mut ctx).unwrap();
        println!("n1 is {:?}", n1.0);
        println!("n2 is {:?}", n2.0);
        let number4 = BigNumber::from_u32(4).unwrap();
        let n1_by4 = n1.0.div(&number4, Some(&mut ctx)).unwrap();
        let n2_by4 = n2.0.div(&number4, Some(&mut ctx)).unwrap();
        println!("n1_by4 is {:?}", n1_by4);
        println!("n2_by4 is {:?}", n2_by4);
    }

    #[test]
    fn test_generate_policy_address() {
        let mut ctx = BigNumber::new_context().unwrap();
        let i = generate_policy_address(&mut ctx).unwrap();
        assert!(i < BigNumber::from_dec(ACCUM1_MODULUS_BY_4).unwrap());
        assert!(i < BigNumber::from_dec(ACCUM2_MODULUS_BY_4).unwrap());
    }
}