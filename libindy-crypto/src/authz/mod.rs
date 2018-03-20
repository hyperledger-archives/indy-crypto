pub mod constants;
#[macro_use]
pub mod helpers;

use utils::commitment::{get_pedersen_commitment,get_generalized_pedersen_commitment};
use utils::json::{JsonEncodable, JsonDecodable};
use utils::get_hash_as_int;
use errors::IndyCryptoError;
use self::helpers::{generate_nonce, get_map_value};

use bn::BigNumber;

use std::vec::Vec;
use std::collections::{BTreeMap, HashMap};
use cl::{CredentialValues,
         Nonce,
         PrimaryCredentialSignature};

struct SecretEqualityProof {}

impl SecretEqualityProof {
    pub fn commit(gen: &AuthzProofGenerators,
                  t_values: &mut Vec<u8>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;

        let r_1 = generate_nonce(constants::P_0_SIZE, None, &gen.p_2)?;
        let r_2 = generate_nonce(constants::P_5_SIZE - 1, None, &gen.p_4)?;
        let r_3 = generate_nonce(constants::P_5_SIZE - 1, None, &gen.p_4)?;

        let t_1 = get_pedersen_commitment(&gen.g_3, &r_2, &gen.h_3, &r_1, &gen.p_3, &mut ctx)?;
        let t_2 = get_pedersen_commitment(&gen.g_4, &r_2, &gen.h_4, &r_3, &gen.p_5, &mut ctx)?;
        t_values.extend_from_slice(&t_1.to_bytes()?);
        t_values.extend_from_slice(&t_2.to_bytes()?);
        Ok(hashmap![
            "r_1".to_string() => r_1,
            "r_2".to_string() => r_2,
            "r_3".to_string() => r_3
        ])
    }

    pub fn challenge(challenge_hash: &BigNumber,
                     x: &BigNumber,
                     y: &BigNumber,
                     z: &BigNumber,
                     r_values: &HashMap<String, BigNumber>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;

        Ok(hashmap![
            "s_1".to_string() => r_values["r_1"].sub(&challenge_hash.mul(y, Some(&mut ctx))?)?,
            "s_2".to_string() => r_values["r_2"].sub(&challenge_hash.mul(x, Some(&mut ctx))?)?,
            "s_3".to_string() => r_values["r_3"].sub(&challenge_hash.mul(z, Some(&mut ctx))?)?
        ])
    }

    pub fn verify(gen: &AuthzProofGenerators,
                  challenge_hash: &BigNumber,
                  c_3: &BigNumber,
                  c_4: &BigNumber,
                  p_se: &HashMap<String, BigNumber>,
                  t_values: &mut Vec<u8>) -> Result<(), IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let get_value = |key: &str| get_map_value(&p_se, key, format!("Value by key '{}' not found in SecretEqualityProof.verify", key));

        let s_1 = get_value("s_1")?;
        let s_2 = get_value("s_2")?;
        let s_3 = get_value("s_3")?;

        let t_1_hat = get_generalized_pedersen_commitment(vec![(c_3, challenge_hash), (&gen.g_3, s_2), (&gen.h_3, s_1)],
                                                          &gen.p_3, &mut ctx)?;
        let t_2_hat = get_generalized_pedersen_commitment(vec![(c_4, challenge_hash), (&gen.g_4, s_2), (&gen.h_4, s_3)],
                                                          &gen.p_5, &mut ctx)?;
        t_values.extend_from_slice(&t_1_hat.to_bytes()?);
        t_values.extend_from_slice(&t_2_hat.to_bytes()?);
        Ok(())
    }
}

struct DoubleCommitmentProof2 {}

impl DoubleCommitmentProof2 {
    pub fn commit(c_1: &BigNumber,
                  num_attrs: usize,
                  gen: &AuthzProofGenerators,
                  t_values: &mut Vec<u8>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let mut u_values = HashMap::new();

        let p_0_size = gen.p_0.num_bits()? as usize;
        let p_1_size = gen.p_1.num_bits()? as usize;

        for i in 0..num_attrs {
            let e_i = generate_nonce(p_0_size, None, &gen.p_0)?;
            let f_i = generate_nonce(p_1_size, None, &gen.p_1)?;
            let p_i = generate_nonce(p_1_size, None, &gen.p_1)?;

            let x = c_1.mul(&gen.h_1.mod_exp(&e_i, &gen.p_1, Some(&mut ctx))?, Some(&mut ctx))?;

            let t_i = get_generalized_pedersen_commitment(vec![(&gen.g_2, &x),
                                                               (&gen.h_2, &f_i),
                                                               (&gen.k_2, &p_i)],
                                                          &gen.p_2,
                                                          &mut ctx)?;

            t_values.extend_from_slice(&t_i.to_bytes()?);

            u_values.insert(format!("e_{}", i + 1), e_i);
            u_values.insert(format!("f_{}", i + 1), f_i);
            u_values.insert(format!("p_{}", i + 1), p_i);
        }

        let a = generate_nonce(p_0_size, None, &gen.p_0)?;
        let b = generate_nonce(p_0_size, None, &gen.p_0)?;

        let v = get_pedersen_commitment(&gen.g_1, &a,
                                        &gen.h_1, &b,
                                        &gen.p_1, &mut ctx)?;

        t_values.extend_from_slice(&v.to_bytes()?);

        u_values.insert("a".to_string(), a);
        u_values.insert("b".to_string(), b);

        Ok(u_values)
    }

    pub fn challenge(gen: &AuthzProofGenerators,
                     a: &BigNumber,
                     b: &BigNumber,
                     e: &BigNumber,
                     f: &BigNumber,
                     p: &BigNumber,
                     challenge_hash: &BigNumber,
                     u_dc2: &HashMap<String, BigNumber>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let mut ctx1 = BigNumber::new_context()?;
        let mut hide_value = |first: &BigNumber, second: &BigNumber| first.sub(&challenge_hash.mul(second, Some(&mut ctx))?);
        let hide_iter = |first: &BigNumber, second: &BigNumber, index: usize| if challenge_hash.is_bit_set(index as i32)? {first.sub(second)} else {first.clone()};

        let p_values: HashMap<String, BigNumber> = HashMap::new();

        let a_prime = &u_dc2["a"];
        let b_prime = &u_dc2["b"];

        let a_hat = hide_value(&a_prime, a)?.modulus(&gen.p_0, Some(&mut ctx1))?;
        let b_hat = hide_value(&b_prime, b)?.modulus(&gen.p_0, Some(&mut ctx1))?;

        let mut p_values = HashMap::new();

        p_values.insert("a".to_string(), a_hat);
        p_values.insert("b".to_string(), b_hat);

        let num_attrs = (u_dc2.len() - 2) / 3;

        for i in 0..num_attrs {
            let e_key = format!("e_{}", i+1);
            let f_key = format!("f_{}", i+1);
            let p_key = format!("p_{}", i+1);

            let e_prime = &u_dc2[&e_key];
            let f_prime = &u_dc2[&f_key];
            let p_prime = &u_dc2[&p_key];

            let e_hat = hide_iter(&e_prime, e, i)?.modulus(&gen.p_0, Some(&mut ctx1))?;

            let f_tilde = f.mul(&gen.h_1.mod_exp(&e_hat, &gen.p_1, Some(&mut ctx1))?, Some(&mut ctx1))?;

            let f_hat = hide_iter(&f_prime, &f_tilde, i)?.modulus(&gen.p_1, Some(&mut ctx1))?;

            let p_tilde = p.mul(&gen.h_1.mod_exp(&e_hat, &gen.p_1, Some(&mut ctx1))?, Some(&mut ctx1))?;

            let p_hat = hide_iter(&p_prime, &p_tilde, i)?.modulus(&gen.p_1, Some(&mut ctx1))?;

            p_values.insert(e_key, e_hat);
            p_values.insert(f_key, f_hat);
            p_values.insert(p_key, p_hat);
        }

        Ok(p_values)
    }

    pub fn verify(challenge_hash: &BigNumber,
                  gen: &AuthzProofGenerators,
                  c_1: &BigNumber,
                  c_2: &BigNumber,
                  p_dc2: &HashMap<String, BigNumber>,
                  t_values: &mut Vec<u8>) -> Result<(), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;

        let get_value = |key: &str| get_map_value(&p_dc2, key, format!("Value by key '{}' not found in DoubleCommitmentProof2.verify", key));

        let num_attrs = (p_dc2.len() - 2) / 3;

        for i in 0..num_attrs {
            let e_hat = get_value(&format!("e_{}", i + 1))?;
            let f_hat = get_value(&format!("f_{}", i + 1))?;
            let p_hat = get_value(&format!("p_{}", i + 1))?;

            let x = get_pedersen_commitment(&gen.h_2, f_hat,
                                            &gen.k_2, p_hat,
                                            &gen.p_2, &mut ctx)?;

            let y = gen.h_1.mod_exp(e_hat, &gen.p_1, Some(&mut ctx))?;

            let t_hat =
                if challenge_hash.is_bit_set(i as i32)? {
                    x.mod_mul(&c_2.mod_exp(&y, &gen.p_2, Some(&mut ctx))?,
                              &gen.p_2, Some(&mut ctx))?
                } else {
                    let z = c_1.mul(&y, Some(&mut ctx))?;

                    x.mod_mul(&gen.g_2.mod_exp(&z, &gen.p_2, Some(&mut ctx))?,
                              &gen.p_2, Some(&mut ctx))?
                };

            t_values.extend_from_slice(&t_hat.to_bytes()?);
        }

        let a_hat = get_value("a")?;
        let b_hat = get_value("b")?;

        let v_hat = get_generalized_pedersen_commitment(vec![(c_1, challenge_hash),
                                                             (&gen.g_1, a_hat),
                                                             (&gen.h_1, b_hat)],
                                                        &gen.p_1, &mut ctx)?;
        t_values.extend_from_slice(&v_hat.to_bytes()?);
        Ok(())

    }
}

struct DoubleCommitmentProof1 {}

impl DoubleCommitmentProof1 {
    pub fn commit(c_1: &BigNumber,
                  num_attrs: usize,
                  gen: &AuthzProofGenerators,
                  t_values: &mut Vec<u8>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let mut u_values = HashMap::new();

        let p_1_size = gen.p_1.num_bits()? as usize;
        let p_2_size = gen.p_2.num_bits()? as usize;

        for i in 0..num_attrs {
            let e_i = generate_nonce(p_1_size, None, &gen.p_1)?;
            let f_i = generate_nonce(p_2_size, None, &gen.p_2)?;

            let tmp = c_1.mul(&gen.k_2.mod_exp(&e_i, &gen.p_2, Some(&mut ctx))?, Some(&mut ctx))?;

            let t_i = get_pedersen_commitment(&gen.g_3, &tmp,
                                              &gen.h_3, &f_i,
                                              &gen.p_3, &mut ctx)?;

            t_values.extend_from_slice(&t_i.to_bytes()?);
            u_values.insert(format!("e_{}", i+1), e_i);
            u_values.insert(format!("f_{}", i+1), f_i);
        }

        //a_prime
        let a = generate_nonce(p_1_size, None, &gen.p_1)?;
        //b_prime
        let b = generate_nonce(p_1_size, None, &gen.p_1)?;
        //d_prime
        let d = generate_nonce(p_1_size, None, &gen.p_1)?;

        let v = get_generalized_pedersen_commitment(vec![(&gen.g_2, &a),
                                                         (&gen.h_2, &b),
                                                         (&gen.k_2, &d)],
                                                    &gen.p_2,
                                                    &mut ctx)?;
        t_values.extend_from_slice(&v.to_bytes()?);

        u_values.insert("a".to_string(), a);
        u_values.insert("b".to_string(), b);
        u_values.insert("d".to_string(), d);
        Ok(u_values)
    }

    pub fn challenge(gen: &AuthzProofGenerators,
                     a: &BigNumber,
                     b: &BigNumber,
                     d: &BigNumber,
                     e: &BigNumber,
                     f: &BigNumber,
                     challenge_hash: &BigNumber,
                     u_dc1: &HashMap<String, BigNumber>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let mut ctx1 = BigNumber::new_context()?;
        let mut hide_value = |first: &BigNumber, second: &BigNumber| first.sub(&challenge_hash.mul(second, Some(&mut ctx))?);
        let hide_iter = |first: &BigNumber, second: &BigNumber, index: usize| if challenge_hash.is_bit_set(index as i32)? {first.sub(second)} else {first.clone()};

        let a_prime = &u_dc1["a"];
        let b_prime = &u_dc1["b"];
        let d_prime = &u_dc1["d"];

        let a_hat = hide_value(&a_prime, a)?.modulus(&gen.p_1, Some(&mut ctx1))?;
        let b_hat = hide_value(&b_prime, b)?.modulus(&gen.p_1, Some(&mut ctx1))?;
        let d_hat = hide_value(&d_prime, d)?.modulus(&gen.p_1, Some(&mut ctx1))?;

        let mut p_values = HashMap::new();

        p_values.insert("a".to_string(), a_hat);
        p_values.insert("b".to_string(), b_hat);
        p_values.insert("d".to_string(), d_hat);

        let num_attrs = (u_dc1.len() - 3) / 2;

        for i in 0..num_attrs {
            let e_key = format!("e_{}", i+1);
            let f_key = format!("f_{}", i+1);

            let e_prime = &u_dc1[&e_key];
            let f_prime = &u_dc1[&f_key];

            let e_hat = hide_iter(&e_prime, e, i)?.modulus(&gen.p_1, Some(&mut ctx1))?;

            let f_tilde = f.mul(&gen.k_2.mod_exp(&e_hat, &gen.p_2, Some(&mut ctx1))?,
                                Some(&mut ctx1))?;

            let f_hat = hide_iter(&f_prime, &f_tilde, i)?.modulus(&gen.p_2, Some(&mut ctx1))?;

            p_values.insert(e_key, e_hat);
            p_values.insert(f_key, f_hat);
        }

        Ok(p_values)
    }

    pub fn verify(challenge_hash: &BigNumber,
                  gen: &AuthzProofGenerators,
                  c_1: &BigNumber,
                  c_2: &BigNumber,
                  p_dc1: &HashMap<String, BigNumber>,
                  t_values: &mut Vec<u8>) -> Result<(), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;

        let get_value = |key: &str| get_map_value(&p_dc1, key, format!("Value by key '{}' not found in DoubleCommitmentProof1.verify", key));

        let num_attrs = (p_dc1.len() - 3) / 2;

        for i in 0..num_attrs {
            let e_hat = get_value(&format!("e_{}", i + 1))?;
            let f_hat = get_value(&format!("f_{}", i + 1))?;

            let x = gen.k_2.mod_exp(e_hat, &gen.p_2, Some(&mut ctx))?;

            let t_hat =
                if challenge_hash.is_bit_set(i as i32)? {
                    get_pedersen_commitment(c_2, &x,
                                            &gen.h_3, f_hat,
                                            &gen.p_3, &mut ctx)?
                } else {
                    get_pedersen_commitment(&gen.g_3, &c_1.mul(&x, Some(&mut ctx))?,
                                            &gen.h_3, f_hat,
                                            &gen.p_3, &mut ctx)?
                };
            t_values.extend_from_slice(&t_hat.to_bytes()?);
        }

        let a_hat = get_value("a")?;
        let b_hat = get_value("b")?;
        let d_hat = get_value("d")?;

        let v_hat = get_generalized_pedersen_commitment(vec![(c_1, challenge_hash),
                                                             (&gen.g_2, a_hat),
                                                             (&gen.h_2, b_hat),
                                                             (&gen.k_2, d_hat)],
                                                        &gen.p_2, &mut ctx)?;
        t_values.extend_from_slice(&v_hat.to_bytes()?);
        Ok(())
    }
}

struct CommitmentAccumulatorProof {}

impl CommitmentAccumulatorProof {
    pub fn commit(g_4: &BigNumber,
                  h_4: &BigNumber,
                  p_5: &BigNumber,
                  g_n: &BigNumber,
                  h_n: &BigNumber,
                  n: &BigNumber,
                  b: &BigNumber,
                  u: &BigNumber,
                  c_b: &BigNumber,
                  t_values: &mut Vec<u8>) -> Result<(HashMap<String, BigNumber>,
                                                     HashMap<String, BigNumber>), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let n_div_4 = n.rshift(2)?;
        let b_hat = BigNumber::from_dec(constants::B_HAT)?;
        let security_level = BigNumber::from_dec(constants::SECURITY_LEVEL)?;

        let r_1 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_2 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_3 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_4 = generate_nonce((b_hat.num_bits()? - 2) as usize, None, &b_hat.rshift(2)?)?;
        let r_5 = generate_nonce(constants::P_5_SIZE - 1, None, &p_5)?;
        let r_6 = generate_nonce(constants::P_5_SIZE - 1, None, &p_5)?;
        let r_7 = generate_nonce(constants::P_5_SIZE - 1, None, &p_5)?;
        let r_8 = generate_nonce(constants::P_5_SIZE - 1, None, &p_5)?;
        let r_9 = generate_nonce(constants::P_5_SIZE - 1, None, &p_5)?;

        let r_10_upper = n.mul(&b_hat, Some(&mut ctx))?
                          .div(&security_level, Some(&mut ctx))?;

        let r_10 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_10_upper)?;
        let r_11 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_10_upper)?;
        let r_12 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_10_upper)?;

        let r_13_upper = r_10_upper.mul(&p_5, Some(&mut ctx))?;

        let r_13 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_13_upper)?;
        let r_14 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_13_upper)?;

        let c_prime_b = get_pedersen_commitment(&g_n, &b,
                                                &h_n, &r_1,
                                                &n,
                                                &mut ctx)?;

        let c_u = u.mod_mul(&h_n.mod_exp(&r_2, &n, Some(&mut ctx))?, &n, Some(&mut ctx))?;

        let c_r = get_pedersen_commitment(&g_n, &r_2,
                                          &h_n, &r_3,
                                          &n, &mut ctx)?;

        let t_1 = get_pedersen_commitment(&g_4, &r_4,
                                          &h_4, &r_6,
                                          &p_5, &mut ctx)?;
        let t_2 = get_pedersen_commitment(&c_b.mod_div(&g_4, &p_5, Some(&mut ctx))?, &r_5,
                                          &h_4, &r_7,
                                          &p_5, &mut ctx)?;

        let t_3 = get_pedersen_commitment(&c_b.mod_mul(&g_4, &p_5, Some(&mut ctx))?, &r_8,
                                          &h_4, &r_9,
                                          &p_5, &mut ctx)?;

        let t_4 = get_pedersen_commitment(&g_n, &r_12,
                                          &h_n, &r_10,
                                          &n, &mut ctx)?;

        let t_5 = get_pedersen_commitment(&g_n, &r_4,
                                          &h_n, &r_11,
                                          &n, &mut ctx)?;

        let h_n_inverse = &h_n.inverse(&n, Some(&mut ctx))?;

        let t_6 = get_pedersen_commitment(&c_u, &r_4,
                                          &h_n_inverse, &r_13,
                                          &n, &mut ctx)?;

        let t_7 = get_generalized_pedersen_commitment(vec![(&c_r, &r_4),
                                                           (&h_n_inverse, &r_14),
                                                           (&g_n.inverse(&n, Some(&mut ctx))?, &r_13)],
                                                      &n, &mut ctx)?;

        t_values.extend_from_slice(&t_1.to_bytes()?);
        t_values.extend_from_slice(&t_2.to_bytes()?);
        t_values.extend_from_slice(&t_3.to_bytes()?);
        t_values.extend_from_slice(&t_4.to_bytes()?);
        t_values.extend_from_slice(&t_5.to_bytes()?);
        t_values.extend_from_slice(&t_6.to_bytes()?);
        t_values.extend_from_slice(&t_7.to_bytes()?);

        Ok((hashmap![
            "c_prime_b".to_string() => c_prime_b,
            "c_u".to_string() => c_u,
            "c_r".to_string() => c_r
         ],
            hashmap![
            "r_1".to_string() => r_1,
            "r_2".to_string() => r_2,
            "r_3".to_string() => r_3,
            "r_4".to_string() => r_4,
            "r_5".to_string() => r_5,
            "r_6".to_string() => r_6,
            "r_7".to_string() => r_7,
            "r_8".to_string() => r_8,
            "r_9".to_string() => r_9,
            "r_10".to_string() => r_10,
            "r_11".to_string() => r_11,
            "r_12".to_string() => r_12,
            "r_13".to_string() => r_13,
            "r_14".to_string() => r_14
         ])
        )
    }

    pub fn challenge(challenge_hash: &BigNumber,
                     b: &BigNumber,
                     r: &BigNumber,
                     p_4: &BigNumber,
                     r_ca: &HashMap<String, BigNumber>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let mut ctx2 = BigNumber::new_context()?;

        let mut sub_value = |first: &BigNumber, second: &BigNumber| first.sub(&challenge_hash.mul(second, Some(&mut ctx))?);
        let mut add_value = |first: &BigNumber, second: &BigNumber| first.add(&challenge_hash.mul(second, Some(&mut ctx2))?);

        let mut ctx1 = BigNumber::new_context()?;
        let b_m1_inverse = b.decrement()?.inverse(p_4, Some(&mut ctx1))?;
        let b_p1_inverse = b.increment()?.inverse(p_4, Some(&mut ctx1))?;

        let s_1 = sub_value(&r_ca["r_4"], &b)?;
        let s_2 = sub_value(&r_ca["r_11"], &r_ca["r_1"])?;
        let s_3 = sub_value(&r_ca["r_6"], &r)?;
        let s_4 = sub_value(&r_ca["r_13"], &b.mul(&r_ca["r_2"], Some(&mut ctx1))?)?;
        let s_5 = sub_value(&r_ca["r_10"], &r_ca["r_3"])?;

        let s_6 = sub_value(&r_ca["r_5"], &b_m1_inverse)?;
        let s_7 = sub_value(&r_ca["r_12"], &r_ca["r_2"])?;
        let s_8 = sub_value(&r_ca["r_14"], &b.mul(&r_ca["r_3"], Some(&mut ctx1))?)?;

        let s_9 = add_value(&r_ca["r_7"], &r.mul(&b_m1_inverse, Some(&mut ctx1))?)?;
        let s_10 = sub_value(&r_ca["r_8"], &b_p1_inverse)?;
        let s_11 = add_value(&r_ca["r_9"], &r.mul(&b_p1_inverse, Some(&mut ctx1))?)?;

        Ok(hashmap![
            "s_1".to_string() => s_1, "s_2".to_string() => s_2,
            "s_3".to_string() => s_3, "s_4".to_string() => s_4,
            "s_5".to_string() => s_5, "s_6".to_string() => s_6,
            "s_7".to_string() => s_7, "s_8".to_string() => s_8,
            "s_9".to_string() => s_9, "s_10".to_string() => s_10,
            "s_11".to_string() => s_11
        ])
    }

    pub fn verify(g_4: &BigNumber,
                  h_4: &BigNumber,
                  p_5: &BigNumber,
                  g_n: &BigNumber,
                  h_n: &BigNumber,
                  n: &BigNumber,
                  challenge_hash: &BigNumber,
                  c_b: &BigNumber,
                  u_ca: &HashMap<String, BigNumber>,
                  p_ca: &HashMap<String, BigNumber>,
                  accumulator: &BigNumber,
                  t_values: &mut Vec<u8>) -> Result<(), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let b_hat = BigNumber::from_dec(constants::B_HAT)?;
        let max = b_hat.rshift1()?;
        let min = max.set_negative(true)?;

        let pget_value = |key: &str| get_map_value(&p_ca, key, format!("Value by key '{}' not found in CommitmentAccumulatorProof.verify", key));
        let uget_value = |key: &str| get_map_value(&u_ca, key, format!("Value by key '{}' not found in CommitmentAccumulatorProof.verify", key));

        let s_1 = pget_value("s_1")?;

        if *s_1 < min || *s_1 > max {
            return Err(IndyCryptoError::InvalidStructure("s_1 not found in range - CommitmentAccumulatorProof.verify".to_string()));
        }

        let s_2 = pget_value("s_2")?;
        let s_3 = pget_value("s_3")?;
        let s_4 = pget_value("s_4")?;
        let s_5 = pget_value("s_5")?;
        let s_6 = pget_value("s_6")?;
        let s_7 = pget_value("s_7")?;
        let s_8 = pget_value("s_8")?;
        let s_9 = pget_value("s_9")?;
        let s_10 = pget_value("s_10")?;
        let s_11 = pget_value("s_11")?;

        let c_prime_b = uget_value("c_prime_b")?;
        let c_u = uget_value("c_u")?;
        let c_r = uget_value("c_r")?;

        let h_n_inverse = h_n.inverse(&n, Some(&mut ctx))?;


        let t_1_hat = get_generalized_pedersen_commitment(vec![(&c_b, &challenge_hash),
                                                               (&g_4, &s_1),
                                                               (&h_4, &s_3)],
                                                          &p_5,
                                                          &mut ctx)?;

        let t_2_hat = get_generalized_pedersen_commitment(vec![(&g_4, &challenge_hash),
                                                               (&c_b.mod_div(&g_4, &p_5, Some(&mut ctx))?, &s_6),
                                                               (&h_4, &s_9)],
                                                          &p_5,
                                                          &mut ctx)?;

        let t_3_hat = get_generalized_pedersen_commitment(vec![(&g_4, &challenge_hash),
                                                               (&c_b.mul(&g_4, Some(&mut ctx))?, &s_10),
                                                               (&h_4, &s_11)],
                                                          &p_5,
                                                          &mut ctx)?;
        let t_4_hat = get_generalized_pedersen_commitment(vec![(&c_r, &challenge_hash),
                                                               (&g_n, &s_7),
                                                               (&h_n, &s_5)],
                                                          &n,
                                                          &mut ctx)?;
        let t_5_hat = get_generalized_pedersen_commitment(vec![(&c_prime_b, &challenge_hash),
                                                               (&g_n, &s_1),
                                                               (&h_n, &s_2)],
                                                          &n,
                                                          &mut ctx)?;
        let t_6_hat = get_generalized_pedersen_commitment(vec![(&accumulator, &challenge_hash),
                                                               (&c_u, &s_1),
                                                               (&h_n_inverse, &s_4)],
                                                          &n,
                                                          &mut ctx)?;
        let t_7_hat = get_generalized_pedersen_commitment(vec![(&c_r, &s_1),
                                                               (&g_n.inverse(&n, Some(&mut ctx))?, &s_4),
                                                               (&h_n_inverse, &s_8)],
                                                          &n,
                                                          &mut ctx)?;

        t_values.extend_from_slice(&t_1_hat.to_bytes()?);
        t_values.extend_from_slice(&t_2_hat.to_bytes()?);
        t_values.extend_from_slice(&t_3_hat.to_bytes()?);
        t_values.extend_from_slice(&t_4_hat.to_bytes()?);
        t_values.extend_from_slice(&t_5_hat.to_bytes()?);
        t_values.extend_from_slice(&t_6_hat.to_bytes()?);
        t_values.extend_from_slice(&t_7_hat.to_bytes()?);
        Ok(())
    }
}

struct SelectiveDisclosureCLProof {}

impl SelectiveDisclosureCLProof {
    pub fn commit(policy_address_m_tilde: &BigNumber) -> Result<(BigNumber, BigNumber, BigNumber), IndyCryptoError> {

        let gen = AuthzProofGenerators::new()?;

        let mut ctx = BigNumber::new_context()?;

        let a_tilde = generate_nonce(constants::P_0_SIZE, None, &gen.p_2)?;
        let b_tilde = generate_nonce(constants::P_0_SIZE, None, &gen.p_2)?;

        let t_3 = get_generalized_pedersen_commitment(vec![(&gen.g_2, &a_tilde),
                                                           (&gen.h_2, policy_address_m_tilde),
                                                           (&gen.k_2, &b_tilde)],
                                                      &gen.p_2, &mut ctx)?;

        Ok((a_tilde, b_tilde, t_3))
    }

    pub fn challenge(challenge_hash: &BigNumber,
                     a_tilde: &BigNumber,
                     b_tilde: &BigNumber,
                     a: &BigNumber,
                     b: &BigNumber) -> Result<(BigNumber, BigNumber), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let a_hat = a_tilde.sub(&challenge_hash.mul(a, Some(&mut ctx))?)?;
        let b_hat = b_tilde.sub(&challenge_hash.mul(b, Some(&mut ctx))?)?;

        return Ok((a_hat, b_hat))
    }
    pub fn verify(challenge_hash: &BigNumber,
                  c_2: &BigNumber,
                  a_hat: &BigNumber,
                  b_hat: &BigNumber,
                  policy_address_m_hat: &BigNumber) -> Result<BigNumber, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let gen = AuthzProofGenerators::new()?;
        let t_3_hat = get_generalized_pedersen_commitment(vec![(c_2, challenge_hash),
                                                               (&gen.g_2, a_hat),
                                                               (&gen.h_2, policy_address_m_hat),
                                                               (&gen.k_2, b_hat)],
                                                          &gen.p_2, &mut ctx)?;
        Ok(t_3_hat)
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct AuthzProofCommitments {
    c_1: BigNumber,
    c_2: BigNumber,
    c_3: BigNumber,
    c_4: BigNumber
}

impl AuthzProofCommitments {
    pub fn new(authz_proof_factors: &AuthzProofFactors,
               authz_proof_blinding_factors: &AuthzProofBlindingFactors,
               authz_proof_generators: &AuthzProofGenerators) -> Result<AuthzProofCommitments, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;

        let c_1 = get_pedersen_commitment(&authz_proof_generators.g_1, &authz_proof_factors.agent_secret,
                                          &authz_proof_generators.h_1, &authz_proof_blinding_factors.r_1,
                                          &authz_proof_generators.p_1, &mut ctx)?;

        let c_2 = get_generalized_pedersen_commitment(vec![(&authz_proof_generators.g_2, &authz_proof_factors.K),
                                                           (&authz_proof_generators.h_2, &authz_proof_factors.policy_address),
                                                           (&authz_proof_generators.k_2, &authz_proof_blinding_factors.r_2)],
                                                      &authz_proof_generators.p_2, &mut ctx)?;

        let c_3 = get_pedersen_commitment(&authz_proof_generators.g_3, &authz_proof_factors.P,
                                          &authz_proof_generators.h_3, &authz_proof_blinding_factors.r_3,
                                          &authz_proof_generators.p_3, &mut ctx)?;

        let c_4 = get_pedersen_commitment(&authz_proof_generators.g_4, &authz_proof_factors.P,
                                          &authz_proof_generators.h_4, &authz_proof_blinding_factors.r_4,
                                          &authz_proof_generators.p_5, &mut ctx)?;

        Ok(AuthzProofCommitments { c_1, c_2, c_3, c_4 })
    }
}

impl JsonEncodable for AuthzProofCommitments {}

impl<'a> JsonDecodable<'a> for AuthzProofCommitments {}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct AuthzProofFactors {
    agent_secret: BigNumber,
    policy_address: BigNumber,
    r: BigNumber,
    r_prime: BigNumber,
    K: BigNumber,               //Commitment_p1(g1^agent_secret, h1^r)
    P: BigNumber                //Commitment_p2(g2^K, h2^policy_address, k2^r_prime)
}

impl AuthzProofFactors {
    pub fn new(gen: &AuthzProofGenerators, agent_secret: &BigNumber, policy_address: &BigNumber) -> Result<AuthzProofFactors, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let r = generate_nonce(constants::R_0_SIZE, None, &gen.p_0)?;

        let K = get_pedersen_commitment(&gen.g_1, &agent_secret,
                                        &gen.h_1, &r,
                                        &gen.p_1, &mut ctx)?;
        let mut r_prime;
        let mut P;

        loop {
            r_prime = generate_nonce(constants::R_0_SIZE, None, &gen.p_0)?;
            P = get_generalized_pedersen_commitment(vec![(&gen.g_2, &K),
                                                         (&gen.h_2, &policy_address),
                                                         (&gen.k_2, &r_prime)],
                                                    &gen.p_2, &mut ctx)?;
            if P.is_prime(Some(&mut ctx))? { break; }
        }

        Ok(AuthzProofFactors { agent_secret: agent_secret.clone()?, policy_address: policy_address.clone()?, r, r_prime, K, P })
    }
}

impl JsonEncodable for AuthzProofFactors {}

impl<'a> JsonDecodable<'a> for AuthzProofFactors {}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthzProofBlindingFactors {
    r_1: BigNumber,
    r_2: BigNumber,
    r_3: BigNumber,
    r_4: BigNumber,
}

impl AuthzProofBlindingFactors {
    pub fn new(gen: &AuthzProofGenerators) -> Result<AuthzProofBlindingFactors, IndyCryptoError> {
        let r_1 = generate_nonce(constants::R_0_SIZE, None, &gen.p_0)?;
        let r_2 = generate_nonce(constants::R_0_SIZE, None, &gen.p_0)?;
        let r_3 = generate_nonce(constants::R_0_SIZE, None, &gen.p_0)?;
        let r_4 = generate_nonce(constants::P_5_SIZE - 1, None, &gen.p_4)?;

        Ok(AuthzProofBlindingFactors { r_1, r_2, r_3, r_4 })
    }
}

#[derive(Debug)]
pub struct AuthzProofGenerators {
    g_1: BigNumber,
    h_1: BigNumber,

    g_2: BigNumber,
    h_2: BigNumber,
    k_2: BigNumber,

    g_3: BigNumber,
    h_3: BigNumber,

    g_4: BigNumber,
    h_4: BigNumber,

    p_0: BigNumber,
    p_1: BigNumber,
    p_2: BigNumber,
    p_3: BigNumber,
    p_4: BigNumber,
    p_5: BigNumber,

    g_n_1: BigNumber,
    h_n_1: BigNumber,
    n_1: BigNumber,

    g_n_2: BigNumber,
    h_n_2: BigNumber,
    n_2: BigNumber
}

impl AuthzProofGenerators {
    pub fn new() -> Result<AuthzProofGenerators, IndyCryptoError> {
        let g_1 = BigNumber::from_dec(constants::G_1)?;
        let h_1 = BigNumber::from_dec(constants::H_1)?;

        let g_2 = BigNumber::from_dec(constants::G_2)?;
        let h_2 = BigNumber::from_dec(constants::H_2)?;
        let k_2 = BigNumber::from_dec(constants::K_2)?;

        let g_3 = BigNumber::from_dec(constants::G_3)?;
        let h_3 = BigNumber::from_dec(constants::G_3)?;

        let g_4 = BigNumber::from_dec(constants::G_4)?;
        let h_4 = BigNumber::from_dec(constants::H_4)?;

        let p_5 = BigNumber::from_dec(constants::P_5)?;
        let p_4 = p_5.rshift1()?;
        let p_3 = BigNumber::from_dec(constants::P_3)?;
        let p_2 = p_3.rshift1()?;
        let p_1 = p_2.rshift1()?;
        let p_0 = p_1.rshift1()?;

        let g_n_1 = BigNumber::from_dec(constants::G_N_1)?;
        let h_n_1 = BigNumber::from_dec(constants::H_N_1)?;
        let g_n_2 = BigNumber::from_dec(constants::G_N_2)?;
        let h_n_2 = BigNumber::from_dec(constants::H_N_2)?;

        let n_1 = BigNumber::from_dec(constants::ACCUM1_MODULUS)?;
        let n_2 = BigNumber::from_dec(constants::ACCUM2_MODULUS)?;

//        let p_0 = BigNumber::from_dec(constants::P_0)?;
//        let p_1 = BigNumber::from_dec(constants::P_1)?;
//        let p_2 = BigNumber::from_dec(constants::P_2)?;
//        let p_3 = BigNumber::from_dec(constants::P_3)?;

        Ok(AuthzProofGenerators { g_1, h_1, g_2, h_2, k_2, g_3, h_3, g_4, h_4, p_0, p_1, p_2, p_3, p_4, p_5, g_n_1, h_n_1, g_n_2, h_n_2, n_1, n_2 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use self::helpers::{MockHelper, bn_rand, gen_double_commitment_to_secret};
    use cl::prover::mocks as prover_mocks;

    #[test]
    fn secret_equality_proof() {
        let factors = mocks::authz_proof_factors();
        let generators = AuthzProofGenerators::new().unwrap();
        let blinding_factors = mocks::authz_proof_blinding_factors();
        let commitments = AuthzProofCommitments::new(&factors, &blinding_factors, &generators).unwrap();
        let verifier_nonce = bn_rand(128).unwrap();

        let mut ctx = BigNumber::new_context().unwrap();
        let mut t_values = Vec::new();

        let u_se = SecretEqualityProof::commit(&generators, &mut t_values).unwrap();

        t_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());
        let challenge_hash = get_hash_as_int(&vec![t_values]).unwrap();

        let p_se = SecretEqualityProof::challenge(&challenge_hash, &factors.P, &blinding_factors.r_3, &blinding_factors.r_4, &u_se).unwrap();

        let mut t_hat_values = Vec::new();

        SecretEqualityProof::verify(&generators,
                                    &challenge_hash,
                                    &commitments.c_3,
                                    &commitments.c_4,
                                    &p_se,
                                    &mut t_hat_values).unwrap();

        t_hat_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let verify_hash = get_hash_as_int(&vec![t_hat_values]).unwrap();

        assert_eq!(verify_hash, challenge_hash);
    }

    #[test]
    fn double_comm_proof_2_works() {
        let factors = mocks::authz_proof_factors();
        let generators = AuthzProofGenerators::new().unwrap();
        let blinding_factors = mocks::authz_proof_blinding_factors();
        let commitments = AuthzProofCommitments::new(&factors, &blinding_factors, &generators).unwrap();
        let num_attrs = mocks::dummy_num_attrs();

        let mut ctx = BigNumber::new_context().unwrap();

        let verifier_nonce = bn_rand(128).unwrap();
        let mut t_values = Vec::new();

        let u_dc2 = DoubleCommitmentProof2::commit(&commitments.c_1,
                                                   num_attrs,
                                                   &generators,
                                                   &mut t_values).unwrap();

        t_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let challenge_hash = get_hash_as_int(&vec![t_values]).unwrap();
        let p_dc2 = DoubleCommitmentProof2::challenge(&generators,
                                                      &factors.agent_secret,
                                                      &blinding_factors.r_1,
                                                      &factors.r.sub(&blinding_factors.r_1).unwrap(),
                                                      &factors.policy_address,
                                                      &blinding_factors.r_2,
                                                      &challenge_hash,
                                                      &u_dc2).unwrap();
        let mut t_hat_values = Vec::new();

        DoubleCommitmentProof2::verify(&challenge_hash,
                                       &generators,
                                       &commitments.c_1,
                                       &commitments.c_2,
                                       &p_dc2,
                                       &mut t_hat_values).unwrap();

        t_hat_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let verify_hash = get_hash_as_int(&vec![t_hat_values]).unwrap();

        assert_eq!(verify_hash, challenge_hash);
    }

    #[test]
    fn double_comm_proof_1_works() {
        let factors = mocks::authz_proof_factors();
        let generators = AuthzProofGenerators::new().unwrap();
        let blinding_factors = mocks::authz_proof_blinding_factors();
        let commitments = AuthzProofCommitments::new(&factors, &blinding_factors, &generators).unwrap();
        let num_attrs = mocks::dummy_num_attrs();

        let mut ctx = BigNumber::new_context().unwrap();

        let verifier_nonce = bn_rand(128).unwrap();
        let mut t_values = Vec::new();
        let u_dc1 = DoubleCommitmentProof1::commit(&commitments.c_2,
                                                   num_attrs,
                                                   &generators,
                                                   &mut t_values).unwrap();

        t_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let challenge_hash = get_hash_as_int(&vec![t_values]).unwrap();

        let p_dc1 = DoubleCommitmentProof1::challenge(&generators,
                                                      &factors.K,
                                                      &factors.policy_address,
                                                      &blinding_factors.r_2,
                                                      &factors.r_prime.sub(&blinding_factors.r_2).unwrap(),
                                                      &blinding_factors.r_3,
                                                      &challenge_hash,
                                                      &u_dc1).unwrap();
        let mut t_hat_values = Vec::new();

        DoubleCommitmentProof1::verify(&challenge_hash,
                                       &generators,
                                       &commitments.c_2,
                                       &commitments.c_3,
                                       &p_dc1,
                                       &mut t_hat_values).unwrap();

        t_hat_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let verify_hash = get_hash_as_int(&vec![t_hat_values]).unwrap();

        assert_eq!(verify_hash, challenge_hash);
    }

    #[test]
    fn commitment_accum_proof_works() {
        let factors = mocks::authz_proof_factors();
        let blinding_factors = mocks::authz_proof_blinding_factors();
        let generators = AuthzProofGenerators::new().unwrap();
        let commitments = AuthzProofCommitments::new(&factors, &blinding_factors, &generators).unwrap();

        let verifier_nonce = bn_rand(128).unwrap();
        let mut ctx = BigNumber::new_context().unwrap();

        let witness =  generators.g_n_1.clone().unwrap();
        let accumulator = generators.g_n_1.mod_exp(&factors.P, &generators.n_1, Some(&mut ctx)).unwrap();

        let mut t_values = Vec::new();

        let (u_ca, r_ca) = CommitmentAccumulatorProof::commit(&generators.g_4,
                                                              &generators.h_4,
                                                              &generators.p_5,
                                                              &generators.g_n_1,
                                                              &generators.h_n_1,
                                                              &generators.n_1,
                                                              &factors.P,
                                                              &witness,
                                                              &commitments.c_4,
                                                              &mut t_values).unwrap();

        t_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let challenge_hash = get_hash_as_int(&vec![t_values]).unwrap();

        let p_ca = CommitmentAccumulatorProof::challenge(&challenge_hash,
                                                         &factors.P,
                                                         &blinding_factors.r_4,
                                                         &generators.p_4,
                                                         &r_ca).unwrap();

        let mut t_hat_values = Vec::new();

        CommitmentAccumulatorProof::verify(&generators.g_4,
                                           &generators.h_4,
                                           &generators.p_5,
                                           &generators.g_n_1,
                                           &generators.h_n_1,
                                           &generators.n_1,
                                           &challenge_hash,
                                           &commitments.c_4,
                                           &u_ca,
                                           &p_ca,
                                           &accumulator,
                                           &mut t_hat_values).unwrap();

        t_hat_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let verify_hash = get_hash_as_int(&vec![t_hat_values]).unwrap();

        assert_eq!(verify_hash, challenge_hash);
    }

    #[test]
    fn selective_disclosure_cl_proof_works() {
        let factors = mocks::authz_proof_factors();
        let gen = AuthzProofGenerators::new().unwrap();
        let blinding_factors = mocks::authz_proof_blinding_factors();
        let commitments = AuthzProofCommitments::new(&factors, &blinding_factors, &gen).unwrap();

        let primary_eq_proof = prover_mocks::eq_proof();
        let m_tildes = mocks::m_tildes();
        let m_tilde = m_tildes.get("policy_address").unwrap();

        let (a_tilde, b_tilde, t_3) = SelectiveDisclosureCLProof::commit(&m_tilde).unwrap();

        let challenge_hash = get_hash_as_int(&vec![t_3.to_bytes().unwrap()]).unwrap();

        let (a_hat, b_hat) = SelectiveDisclosureCLProof::challenge(&challenge_hash,
                                                                   &a_tilde, &b_tilde,
                                                                   &factors.K,
                                                                   &blinding_factors.r_2).unwrap();

        let m_hat = m_tilde.sub(&challenge_hash.mul(&factors.policy_address, None).unwrap()).unwrap();

        let t_3_hat = SelectiveDisclosureCLProof::verify(&challenge_hash,
                                                         &commitments.c_2,
                                                         &a_hat, &b_hat, &m_hat).unwrap();

        let verify_hash = get_hash_as_int(&vec![t_3_hat.to_bytes().unwrap()]).unwrap();

        assert_eq!(challenge_hash, verify_hash);
    }

    #[test]
    fn authz_proof_works() {
        MockHelper::inject();

//        let cred_values = prover_mocks::credential_values();
//        let cred_signature = prover_mocks::primary_credential();
//        let authz_proof_factors = mocks::authz_proof_factors();
//        let authz_proof_generators = mocks::authz_proof_generators();
//        let authz_proof_commitments = mocks::authz_proof_commitments();
//
//        let verifier_nonce = bn_rand(128).unwrap();
//        let mut ctx = BigNumber::new_context().unwrap();
//
//        let n = BigNumber::from_dec(constants::ACCUM1_MODULUS).unwrap();
//
//        let witness = BigNumber::from_u32(1).unwrap();
//        let accumulator = authz_proof_generators.g_n.mod_exp(&authz_proof_commitments.c_1, &n, Some(&mut ctx)).unwrap();
//
//        let authzproof = AuthzProof::new(&cred_values,
//                                         &cred_signature,
//                                         &mocks::revealed_attrs(),
//                                         "policy_address",
//                                         &mocks::m_tildes(),
//                                         &authz_proof_factors,
//                                         &witness,
//                                         &verifier_nonce).unwrap();

//        assert!(authzproof.verify(&accumulator, &verifier_nonce).unwrap());
    }

    #[test]
    #[ignore] //TODO Expensive test
    fn test_authz_mocks() {
//        let mut ctx = BigNumber::new_context().unwrap();
//        let gen = AuthzProofGenerators::new().unwrap();
//
//        let factors = AuthzProofFactors::new(&gen, &BigNumber::from_dec("89035060045652462381130209244352620421002985094628950327696113598322429853594").unwrap(), &BigNumber::from_dec("82482513509927463198200988655461469819592280137503867166383914706498311851913").unwrap()).unwrap();
//
//        println!("factors = {:?}", factors);
//
//        let blinding_factors = AuthzProofBlindingFactors::new(&gen).unwrap();
//
//        println!("blinding_factors = {:?}", blinding_factors);

//        let factors = mocks::authz_proof_factors(); //AuthzProofFactors::new(&gen, &BigNumber::from_dec("89035060045652462381130209244352620421002985094628950327696113598322429853594").unwrap(), &BigNumber::from_dec("82482513509927463198200988655461469819592280137503867166383914706498311851913").unwrap()).unwrap();
//        let blinding_factors = mocks::authz_proof_blinding_factors();

//        let commitments = AuthzProofCommitments::new(&factors, &blinding_factors, &gen).unwrap();
//
//        println!("commitments = {:?}", commitments);

        println!("bn_rand(771) = {:?}", bn_rand(771));

//        let authz_proof_factors = mocks::authz_proof_factors();
//        let (c_1, r_0) = gen_double_commitment_to_secret(&authz_proof_generators.g_1, &authz_proof_generators.h_1, &authz_proof_factors.agent_secret,
//                                                         &authz_proof_generators.g_2, &authz_proof_generators.h_2, &prover_mocks::policy_address(),
//                                                         &authz_proof_generators.p_1, &authz_proof_generators.p_2, &mut ctx).unwrap();
    }
}

#[cfg(test)]
mod mocks {
    use super::*;
    use cl::prover::mocks as prover_mocks;

    pub fn dummy_proof_factors() -> AuthzProofFactors {
        AuthzProofFactors {
            agent_secret: BigNumber::from_u32(79).unwrap(),
            policy_address: BigNumber::from_u32(24).unwrap(),
            r: BigNumber::from_u32(2).unwrap(),
            r_prime: BigNumber::from_u32(5).unwrap(),
            K: BigNumber::from_u32(172).unwrap(),
            P: BigNumber::from_u32(193).unwrap()
        }
    }

    pub fn dummy_blinding_factors() -> AuthzProofBlindingFactors {
        AuthzProofBlindingFactors {
            r_1: BigNumber::from_u32(33).unwrap(),
            r_2: BigNumber::from_u32(18).unwrap(),
            r_3: BigNumber::from_u32(54).unwrap(),
            r_4: BigNumber::from_u32(293).unwrap(),
        }
    }

    pub fn dummy_generators() -> AuthzProofGenerators {
        AuthzProofGenerators {
            p_0: BigNumber::from_u32(89).unwrap(),
            p_1: BigNumber::from_u32(179).unwrap(),
            p_2: BigNumber::from_u32(359).unwrap(),
            p_3: BigNumber::from_u32(719).unwrap(),
            p_4: BigNumber::from_u32(1451).unwrap(),
            p_5: BigNumber::from_u32(2903).unwrap(),
            n_1: BigNumber::from_u32(9428737).unwrap(),
            n_2: BigNumber::from_u32(9428737).unwrap(),
            g_1: BigNumber::from_u32(19).unwrap(),
            h_1: BigNumber::from_u32(39).unwrap(),
            g_2: BigNumber::from_u32(15).unwrap(),
            h_2: BigNumber::from_u32(79).unwrap(),
            k_2: BigNumber::from_u32(317).unwrap(),
            g_3: BigNumber::from_u32(354).unwrap(),
            h_3: BigNumber::from_u32(10).unwrap(),
            g_4: BigNumber::from_u32(891).unwrap(),
            h_4: BigNumber::from_u32(331).unwrap(),
            g_n_1: BigNumber::from_u32(8917538).unwrap(),
            h_n_1: BigNumber::from_u32(3720276).unwrap(),
            g_n_2: BigNumber::from_u32(8917538).unwrap(),
            h_n_2: BigNumber::from_u32(3720276).unwrap()
        }
    }

    pub fn dummy_commitments() -> AuthzProofCommitments {
        AuthzProofCommitments {
            c_1: BigNumber::from_u32(155).unwrap(),
            c_2: BigNumber::from_u32(51).unwrap(),
            c_3: BigNumber::from_u32(111).unwrap(),
            c_4: BigNumber::from_u32(1737).unwrap(),
        }
    }

    pub fn dummy_num_attrs() -> usize {
        5
    }

    pub fn authz_proof_factors() -> AuthzProofFactors {
        AuthzProofFactors {
            agent_secret: BigNumber::from_dec("89035060045652462381130209244352620421002985094628950327696113598322429853594").unwrap(),
            policy_address: BigNumber::from_dec("82482513509927463198200988655461469819592280137503867166383914706498311851913").unwrap(),
            r: BigNumber::from_dec("373444499435622973298120774765644881530061950099441311686212507378365323396832957807277718321730882745388197842273738442078548394397370359563018795728458638144442479896198137150388200112065672398518558284220177381071088569286401838").unwrap(),
            r_prime: BigNumber::from_dec("907587248344987532621760705590319645589225452345736905831961251252706433531501632567778084937083295085731780227145189350928250532127936426120838942949748192065894619150630831984039393134488948797558783391080380475775385474968663537").unwrap(),
            K: BigNumber::from_dec("1567730211124226934595886878953317251990337439723327855719339400121568240657401972636562612767421619497944853573124317651438443951049003075097489617220862842193521919486318064069497834525392511901493827566389924927370527412378291840").unwrap(),
            P: BigNumber::from_dec("1854766729919658859329031426948455698710224539700418666233056341411942283682652953555950690726373814627113748721241326318927206421862799458962389249514456142398382186866591365421111152297685303084514560652643576538426116604250179827").unwrap()
        }
    }

    pub fn authz_proof_blinding_factors() -> AuthzProofBlindingFactors {
        AuthzProofBlindingFactors {
            r_1: BigNumber::from_dec("65129174411411124782539338181400365516471533729661936065376957040661914580046314262021878796927852292237013939215505452912667385567979705875158002540276882222212988171380231314913897491671099498687901463482090854657207378873347336").unwrap(),
            r_2: BigNumber::from_dec("639503229105111299807869079995664932890489507380868310741351495542799365098174695609275542909071663962914875070400874829958718225853261516353498155164198998884433004492299895885906383407728704200432838139658059812905321207445502249").unwrap(),
            r_3: BigNumber::from_dec("467675726582599103468821744708279833270639571741215534369582603727399795116052068207530052428672705906300156428100418790524554887735418374801353777605910545082278228080772555134707728121391255671608704313385651959445968627474162042").unwrap(),
            r_4: BigNumber::from_dec("721881323724960162445358150750224976525126143031612484471138181520802603516414620173940463456681570613003319613348247287090832029150837625474188679889855920700143012697024041201697924565364150259707847638851632947539367964290245128075300619298145975528723932452013392480701859096955065770026392558729304515498714331815516222105411248903786520708464626544347412582282329441513000932773092433827725604763495730136631338044673850192890030578553213295009627715001409").unwrap()
        }
    }

    pub fn authz_proof_commitments() -> AuthzProofCommitments {
        AuthzProofCommitments {
            c_1: BigNumber::from_dec("1302965041477986568837097080730219950930425563812104708300196382826548983478219403773130881943254282197659891903533312288382453858888407161432946992850126793011979117999320705930661139807328129539723811101714259305116922365513478151").unwrap(),
            c_2: BigNumber::from_dec("3633710581229959010173629794835933967003424651356029895506030137354190078557221129160855403879534195091373926176560513029413251517672734056564495071463932862778561397043668412068430893598580832422967153362257052195811063548753703428").unwrap(),
            c_3: BigNumber::from_dec("5247580181400880015489246887155088447104882484140483747572941799081450646357693220308757837591373601700150061754734228089996841896637997893495020560477480003008582233729074032680048869571759633693615375673419405511207631477262341641").unwrap(),
            c_4: BigNumber::from_dec("3249183533908630114267097883310529979840035631571024018841933947336242323760498253700251806050923350698547533674468221833272674206753236371458116349404333600692856723754492926682408034487693019398748794127946693792829298590861749761354313458374886175625656674595087229069206093453014693731574954408635807971226368194112265828540613080627541404820601549354533901376968368888280390654838377396096002342422762802610553991429292070851012115401122504414251949554391227").unwrap(),
        }
    }

    pub fn revealed_attrs() -> BTreeMap<String, BigNumber> {
        btreemap![
            "name".to_string() => BigNumber::from_dec("71359565546479723151967460283929432570283558415909434050407244812473401631735").unwrap()
        ]
    }

    pub fn m_tildes() -> BTreeMap<String, BigNumber> {
        btreemap![
            "age".to_string() => BigNumber::from_dec("6836093372281486729646184617597916991214841800681868769509121358446601587666656078277382831520780194784633779972340766019270181226687531873137224042876323371837541729936681716283").unwrap(),
            "gender".to_string() => BigNumber::from_dec("4542318061882004307306710524823292909367354014982094469360419388235416361659421872055188917411511348723801433939000162068648359710064864074328818068135002769743420312965221028822").unwrap(),
            "height".to_string() => BigNumber::from_dec("14026972358434558653527907928880138680231339872942176589090005931999052178490653973804126077690180779183645816908705545840786777387513981683922240925968963101602220371688597019438").unwrap(),
            "link_secret".to_string() => BigNumber::from_dec("4892729562200808264076540862404013238001307499748689320429858988078324558904367508942728432460660990926041590483751331803827498498722952826056044123024082476338911626588928674717").unwrap(),
            "policy_address".to_string() => BigNumber::from_dec("11664269910239554114811575093790927659772178198758113538135247369261107627305346049376434641904817122430281258357521645529616304587802924324741078725146425973306841956896342639608").unwrap()
        ]
    }
}
