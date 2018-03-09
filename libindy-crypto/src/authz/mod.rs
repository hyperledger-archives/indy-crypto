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

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthzProof {
    u_ca: HashMap<String, BigNumber>,
    p_ca: HashMap<String, BigNumber>,
    challenge_hash: BigNumber,
    c_2: BigNumber,
    c_3: BigNumber,
    c_4: BigNumber,
}

impl AuthzProof {

    pub fn new(cred_values: &CredentialValues,
               cred_signature: &PrimaryCredentialSignature,
               revealed_attrs: &BTreeMap<String, BigNumber>,
               attribute_name: &str,
               m_tilde: &BTreeMap<String, BigNumber>,
               authz_proof_factors: &AuthzProofFactors,
               witness: &BigNumber,
               verifier_nonce: &Nonce) -> Result<AuthzProof, IndyCryptoError> {

        let authz_proof_generators = AuthzProofGenerators::new()?;
        let authz_proof_blinding_factors = AuthzProofBlindingFactors::new(&authz_proof_generators.p_0)?;
        let authz_proof_commitments = AuthzProofCommitments::new(&authz_proof_factors,
                                                                 &authz_proof_blinding_factors,
                                                                 &authz_proof_generators)?;
        let mut t_values = Vec::new();

        let (u_ca, r_ca) = CommitmentAccumulatorProof::commit(&authz_proof_commitments.c_1,
                                                              &authz_proof_blinding_factors.r_3,
                                                              witness,
                                                              &authz_proof_commitments.c_4,
                                                              &authz_proof_generators,
                                                              &mut t_values)?;

        t_values.extend_from_slice(&verifier_nonce.to_bytes()?);

        let challenge_hash = get_hash_as_int(&vec![t_values])?;

        let p_ca = CommitmentAccumulatorProof::challenge(&authz_proof_commitments.c_1,
                                                          &authz_proof_blinding_factors.r_3,
                                                          &challenge_hash,
                                                          &authz_proof_generators,
                                                          &r_ca)?;

        let c_2 = authz_proof_commitments.c_2.clone()?;
        let c_3 = authz_proof_commitments.c_3.clone()?;
        let c_4 = authz_proof_commitments.c_4.clone()?;

        Ok(AuthzProof{ u_ca, p_ca, challenge_hash, c_2, c_3, c_4 })
    }

    pub fn verify(&self,
                  accumulator_value: &BigNumber,
                  verifier_nonce: &BigNumber) -> Result<bool, IndyCryptoError> {
        let authz_proof_generators = AuthzProofGenerators::new()?;

        let mut t_hat_values = Vec::new();

        CommitmentAccumulatorProof::verify(&authz_proof_generators,
                                           &self.challenge_hash,
                                           &self.c_4,
                                           &self.u_ca,
                                           &self.p_ca,
                                           accumulator_value,
                                           &mut t_hat_values)?;

        t_hat_values.extend_from_slice(&verifier_nonce.to_bytes()?);

        let verify_hash = get_hash_as_int(&vec![t_hat_values])?;

        if verify_hash == self.challenge_hash {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl JsonEncodable for AuthzProof {}

impl<'a> JsonDecodable<'a> for AuthzProof {}

struct DoubleCommitmentProof2Group {}

impl DoubleCommitmentProof2Group {
    pub fn commit(c_1: &BigNumber,
                  num_attrs: usize,
                  authz_proof_generators: &AuthzProofGenerators,
                  t_values: &mut Vec<u8>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let mut u_values = HashMap::new();

        for i in 0..num_attrs {
            let e_i = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;
            let f_i = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;
            let p_i = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;

            let x = c_1.mod_mul(&authz_proof_generators.g_2_1.mod_exp(&e_i, &authz_proof_generators.p_1, Some(&mut ctx))?,
                                &authz_proof_generators.p_1, Some(&mut ctx))?;

            let t_i = get_generalized_pedersen_commitment(vec![(&authz_proof_generators.g_2_1, &x),
                                                               (&authz_proof_generators.g_2_2, &f_i),
                                                               (&authz_proof_generators.g_2_3, &p_i)],
                                                          &authz_proof_generators.p_2,
                                                          &mut ctx)?;
            t_values.extend_from_slice(&t_i.to_bytes()?);

            u_values.insert(format!("e_{}", i + 1), e_i);
            u_values.insert(format!("f_{}", i + 1), f_i);
            u_values.insert(format!("p_{}", i + 1), p_i);
        }

        let a = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;
        let b = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;

        let v = get_pedersen_commitment(&authz_proof_generators.g_1_1, &a,
                                        &authz_proof_generators.g_1_2, &b,
                                        &authz_proof_generators.p_1, &mut ctx)?;

        t_values.extend_from_slice(&v.to_bytes()?);

        u_values.insert("a".to_string(), a);
        u_values.insert("b".to_string(), b);

        Ok(u_values)
    }

    pub fn challenge(authz_proof_generators: &AuthzProofGenerators,
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
        let mut hide_iter = |first: &BigNumber, second: &BigNumber, index: usize| if challenge_hash.is_bit_set(index as i32)? {first.sub(second)} else {first.clone()};
        let get_value = |key: &str| get_map_value(&u_dc2, key, format!("Value by key '{}' not found in DoubleCommitmentProof2Group.challenge", key));

        let mut p_values: HashMap<String, BigNumber> = HashMap::new();

        let a_prime = get_value("a")?;
        let b_prime = get_value("b")?;

        let a_hat = hide_value(a_prime, a)?;
        let b_hat = hide_value(b_prime, b)?;

        let mut p_values = HashMap::new();

        p_values.insert("a".to_string(), a_hat);
        p_values.insert("b".to_string(), b_hat);

        let num_attrs = (u_dc2.len() - 2) / 3;

        for i in (0..num_attrs) {
            let e_key = format!("e_{}", i+1);
            let f_key = format!("f_{}", i+1);
            let p_key = format!("p_{}", i+1);

            let e_prime = get_value(&e_key)?;
            let f_prime = get_value(&f_key)?;
            let p_prime = get_value(&p_key)?;

            let e_hat = hide_iter(e_prime, e, i)?;

            let f_tilde = f.mod_mul(&authz_proof_generators.g_1_2.mod_exp(&e_hat, &authz_proof_generators.p_1, Some(&mut ctx1))?,
                                    &authz_proof_generators.p_1, Some(&mut ctx1))?;

            let f_hat = hide_iter(f_prime, &f_tilde, i)?;

            let p_tilde = p.mod_mul(&authz_proof_generators.g_1_2.mod_exp(&e_hat, &authz_proof_generators.p_1, Some(&mut ctx1))?,
                                     &authz_proof_generators.p_1, Some(&mut ctx1))?;

            let p_hat = hide_iter(p_prime, &p_tilde, i)?;

            p_values.insert(e_key, e_hat);
            p_values.insert(f_key, f_hat);
            p_values.insert(p_key, p_hat);
        }

        Ok(p_values)
    }

    pub fn verify(challenge_hash: &BigNumber,
                  authz_proof_generators: &AuthzProofGenerators,
                  c_1: &BigNumber,
                  c_2: &BigNumber,
                  p_dc2: &HashMap<String, BigNumber>,
                  t_values: &mut Vec<u8>) -> Result<(), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;

        let get_value = |key: &str| get_map_value(&p_dc2, key, format!("Value by key '{}' not found in DoubleCommitmentProof2Group.verify", key));

        let num_attrs = (p_dc2.len() - 2) / 3;

        for i in (0..num_attrs) {
            let e_hat = get_value(&format!("e_{}", i + 1))?;
            let f_hat = get_value(&format!("f_{}", i + 1))?;
            let p_hat = get_value(&format!("p_{}", i + 1))?;

            let x = get_pedersen_commitment(&authz_proof_generators.g_2_2, f_hat,
                                            &authz_proof_generators.g_2_3, p_hat,
                                            &authz_proof_generators.p_2, &mut ctx)?;

            let y = authz_proof_generators.g_1_2.mod_exp(e_hat, &authz_proof_generators.p_1, Some(&mut ctx))?;

            let t_hat =
                if challenge_hash.is_bit_set(i as i32)? {
                    x.mod_mul(&c_2.mod_exp(&y, &authz_proof_generators.p_2, Some(&mut ctx))?,
                              &authz_proof_generators.p_2, Some(&mut ctx))?
                } else {
                    let z = c_1.mod_mul(&y, &authz_proof_generators.p_2, Some(&mut ctx))?;

                    x.mod_mul(&authz_proof_generators.g_2_1.mod_exp(&z, &authz_proof_generators.p_2, Some(&mut ctx))?,
                              &authz_proof_generators.p_2, Some(&mut ctx))?
                };

            t_values.extend_from_slice(&t_hat.to_bytes()?);
        }

        let a_hat = get_value("a")?;
        let b_hat = get_value("b")?;

        let v_hat = get_generalized_pedersen_commitment(vec![(c_1, challenge_hash),
                                                             (&authz_proof_generators.g_1_1, a_hat),
                                                             (&authz_proof_generators.g_1_2, b_hat)],
                                                        &authz_proof_generators.p_1, &mut ctx)?;
        t_values.extend_from_slice(&v_hat.to_bytes()?);
        Ok(())

    }
}

struct DoubleCommitmentProof3Group {}

impl DoubleCommitmentProof3Group {
    pub fn commit(c_1: &BigNumber,
                  num_attrs: usize,
                  authz_proof_generators: &AuthzProofGenerators,
                  t_values: &mut Vec<u8>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let mut u_values = HashMap::new();

        for i in 0..num_attrs {
            let e_i = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_0)?;
            let f_i = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_0)?;

            let tmp = c_1.mod_mul(
                        &authz_proof_generators.g_2_3.mod_exp(&e_i, &authz_proof_generators.p_2, Some(&mut ctx))?,
                        &authz_proof_generators.p_2,
                        Some(&mut ctx))?;

            let t_i = get_pedersen_commitment(&authz_proof_generators.g_3_1, &tmp,
                                              &authz_proof_generators.g_3_2, &f_i,
                                              &authz_proof_generators.p_3, &mut ctx)?;

            t_values.extend_from_slice(&t_i.to_bytes()?);
            u_values.insert(format!("e_{}", i+1), e_i);
            u_values.insert(format!("f_{}", i+1), f_i);
        }

        //a_prime
        let a = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_0)?;
        //b_prime
        let b = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_0)?;
        //d_prime
        let d = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_0)?;

        let v = get_generalized_pedersen_commitment(vec![(&authz_proof_generators.g_2_1, &a),
                                                         (&authz_proof_generators.g_2_2, &b),
                                                         (&authz_proof_generators.g_2_3, &d)],
                                                    &authz_proof_generators.p_2,
                                                    &mut ctx)?;
        t_values.extend_from_slice(&v.to_bytes()?);

        u_values.insert("a".to_string(), a);
        u_values.insert("b".to_string(), b);
        u_values.insert("d".to_string(), d);
        Ok(u_values)
    }

    pub fn challenge(authz_proof_generators: &AuthzProofGenerators,
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
        let mut hide_iter = |first: &BigNumber, second: &BigNumber, index: usize| if challenge_hash.is_bit_set(index as i32)? {first.sub(second)} else {first.clone()};
        let get_value = |key: &str| get_map_value(&u_dc1, key, format!("Value by key '{}' not found in DoubleCommitmentProof3Group.challenge", key));

        let a_prime = get_value("a")?;
        let b_prime = get_value("b")?;
        let d_prime = get_value("d")?;

        let a_hat = hide_value(a_prime, a)?;
        let b_hat = hide_value(b_prime, b)?;
        let d_hat = hide_value(d_prime, d)?;

        let mut p_values = HashMap::new();

        p_values.insert("a".to_string(), a_hat);
        p_values.insert("b".to_string(), b_hat);
        p_values.insert("d".to_string(), d_hat);

        let num_attrs = (u_dc1.len() - 3) / 2;

        for i in (0..num_attrs) {
            let e_key = format!("e_{}", i+1);
            let f_key = format!("f_{}", i+1);

            let e_prime = get_value(&e_key)?;
            let f_prime = get_value(&f_key)?;

            let e_hat = hide_iter(e_prime, e, i)?;

            let f_tilde = f.mod_mul(&authz_proof_generators.g_2_3.mod_exp(&e_hat, &authz_proof_generators.p_2, Some(&mut ctx1))?,
                                    &authz_proof_generators.p_2, Some(&mut ctx1))?;

            let f_hat = hide_iter(f_prime, &f_tilde, i)?;

            p_values.insert(e_key, e_hat);
            p_values.insert(f_key, f_hat);
        }

        Ok(p_values)
    }

    pub fn verify(challenge_hash: &BigNumber,
                  authz_proof_generators: &AuthzProofGenerators,
                  c_1: &BigNumber,
                  c_2: &BigNumber,
                  p_dc1: &HashMap<String, BigNumber>,
                  t_values: &mut Vec<u8>) -> Result<(), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;

        let get_value = |key: &str| get_map_value(&p_dc1, key, format!("Value by key '{}' not found in DoubleCommitmentProof3Group.verify", key));

        let num_attrs = (p_dc1.len() - 3) / 2;

        for i in (0..num_attrs) {
            let e_hat = get_value(&format!("e_{}", i + 1))?;
            let f_hat = get_value(&format!("f_{}", i + 1))?;

            let x = authz_proof_generators.g_2_3.mod_exp(e_hat, &authz_proof_generators.p_2, Some(&mut ctx))?;

            let t_hat =
                if challenge_hash.is_bit_set(i as i32)? {
                    get_pedersen_commitment(c_2, &x,
                                            &authz_proof_generators.g_3_2, f_hat,
                                            &authz_proof_generators.p_3, &mut ctx)?
                } else {
                    let x1 = c_1.mod_mul(&x, &authz_proof_generators.p_2, Some(&mut ctx))?;

                    get_pedersen_commitment(&authz_proof_generators.g_3_1, &x1,
                                            &authz_proof_generators.g_3_2, f_hat,
                                            &authz_proof_generators.p_3, &mut ctx)?
                };

            t_values.extend_from_slice(&t_hat.to_bytes()?);
        }

        let a_hat = get_value("a")?;
        let b_hat = get_value("b")?;
        let d_hat = get_value("d")?;

        let v_hat = get_generalized_pedersen_commitment(vec![(c_1, challenge_hash),
                                                             (&authz_proof_generators.g_2_1, a_hat),
                                                             (&authz_proof_generators.g_2_2, b_hat),
                                                             (&authz_proof_generators.g_2_3, d_hat)],
                                                        &authz_proof_generators.p_2, &mut ctx)?;
        t_values.extend_from_slice(&v_hat.to_bytes()?);
        Ok(())
    }
}

struct CommitmentAccumulatorProof {}

impl CommitmentAccumulatorProof {
    pub fn commit(b: &BigNumber,
                  r: &BigNumber,
                  u: &BigNumber,
                  c_b: &BigNumber,
                  authz_proof_generators: &AuthzProofGenerators,
                  t_values: &mut Vec<u8>) -> Result<(HashMap<String, BigNumber>,
                                                     HashMap<String, BigNumber>), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let n_div_4 = BigNumber::from_dec(constants::ACCUM1_MODULUS_BY_4)?;
        let n = BigNumber::from_dec(constants::ACCUM1_MODULUS)?;
        let b_hat = BigNumber::from_dec(constants::B_HAT)?;
        let security_level = BigNumber::from_dec(constants::SECURITY_LEVEL)?;

        let r_1 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_2 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_3 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_4 = generate_nonce(constants::ACCUM_A_SIZE*2-2, None, &b_hat.rshift(2)?)?;
        let r_5 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;
        let r_6 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;
        let r_7 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;
        let r_8 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;
        let r_9 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_generators.p_1)?;

        let r_10_upper = n.mul(&b_hat, Some(&mut ctx))?
                          .div(&security_level, Some(&mut ctx))?;

        let r_10 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_10_upper)?;
        let r_11 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_10_upper)?;
        let r_12 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_10_upper)?;

        let r_13_upper = r_10_upper.mul(&authz_proof_generators.p_1, Some(&mut ctx))?;

        let r_13 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_13_upper)?;
        let r_14 = generate_nonce(constants::ACCUM_MODULUS_SIZE, None, &r_13_upper)?;

        let c_prime_b = get_pedersen_commitment(&authz_proof_generators.g_n, &b,
                                                &authz_proof_generators.h_n, &r_1,
                                                &n,
                                                &mut ctx)?;

        let c_u = u.mod_mul(&authz_proof_generators.h_n.mod_exp(&r_2, &n, Some(&mut ctx))?, &n, Some(&mut ctx))?;

        let c_r = get_pedersen_commitment(&authz_proof_generators.g_n, &r_2,
                                          &authz_proof_generators.h_n, &r_3,
                                          &n, &mut ctx)?;

        let t_1 = get_pedersen_commitment(&authz_proof_generators.g_3_1, &r_4,
                                          &authz_proof_generators.g_3_2, &r_6,
                                          &authz_proof_generators.p_3, &mut ctx)?;

        let t_2 = get_pedersen_commitment(&c_b.mod_div(&authz_proof_generators.g_3_1, &authz_proof_generators.p_3, Some(&mut ctx))?, &r_5,
                                          &authz_proof_generators.g_3_2, &r_7,
                                          &authz_proof_generators.p_3, &mut ctx)?;

        let t_3 = get_pedersen_commitment(&c_b.mod_mul(&authz_proof_generators.g_3_1, &authz_proof_generators.p_3, Some(&mut ctx))?, &r_8,
                                          &authz_proof_generators.g_3_2, &r_9,
                                          &authz_proof_generators.p_3, &mut ctx)?;

        let t_4 = get_pedersen_commitment(&authz_proof_generators.g_n, &r_12,
                                          &authz_proof_generators.h_n, &r_10,
                                          &n, &mut ctx)?;

        let t_5 = get_pedersen_commitment(&authz_proof_generators.g_n, &r_4,
                                          &authz_proof_generators.h_n, &r_11,
                                          &n, &mut ctx)?;

        let h_n_inverse = &authz_proof_generators.h_n.inverse(&n, Some(&mut ctx))?;

        let t_6 = get_pedersen_commitment(&c_u, &r_4,
                                          &h_n_inverse, &r_13,
                                          &n, &mut ctx)?;

        let t_7 = get_generalized_pedersen_commitment(vec![(&c_r, &r_4),
                                                           (&h_n_inverse, &r_14),
                                                           (&authz_proof_generators.g_n.inverse(&n, Some(&mut ctx))?, &r_13)],
                                                      &n, &mut ctx)?;

        t_values.extend_from_slice(&t_1.to_bytes()?);
        println!("t_2 = {:?}", t_2);
//        t_values.extend_from_slice(&t_2.to_bytes()?);
//        t_values.extend_from_slice(&t_3.to_bytes()?);
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

    pub fn challenge(b: &BigNumber,
                      r: &BigNumber,
                      challenge_hash: &BigNumber,
                      authz_proof_generators: &AuthzProofGenerators,
                      r_ca: &HashMap<String, BigNumber>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let mut ctx2 = BigNumber::new_context()?;

        let mut sub_value = |first: &BigNumber, second: &BigNumber| first.sub(&challenge_hash.mul(second, Some(&mut ctx))?);
        let mut add_value = |first: &BigNumber, second: &BigNumber| first.add(&challenge_hash.mul(second, Some(&mut ctx2))?);
        let get_value = |key: &str| get_map_value(&r_ca, key, format!("Value by key '{}' not found in CommitmentAccumulatorProof.challenges", key));

        let mut ctx1 = BigNumber::new_context()?;
        let r_1 = get_value("r_1")?;
        let r_2 = get_value("r_2")?;
        let r_3 = get_value("r_3")?;
        let r_4 = get_value("r_4")?;
        let r_5 = get_value("r_5")?;
        let r_6 = get_value("r_6")?;
        let r_7 = get_value("r_7")?;
        let r_8 = get_value("r_8")?;
        let r_9 = get_value("r_9")?;
        let r_10 = get_value("r_10")?;
        let r_11 = get_value("r_11")?;
        let r_12 = get_value("r_12")?;
        let r_13 = get_value("r_13")?;
        let r_14 = get_value("r_14")?;

        let b_m1_inverse = b.decrement()?.inverse(&authz_proof_generators.p_3, Some(&mut ctx1))?;
        let b_p1_inverse = b.increment()?.inverse(&authz_proof_generators.p_3, Some(&mut ctx1))?;

        let s_1 = sub_value(r_4, &b)?;
        let s_2 = sub_value(r_11, r_1)?;
        let s_3 = sub_value(r_6, &r)?;
        let s_4 = sub_value(r_13, &b.mul(r_2, Some(&mut ctx1))?)?;
        let s_5 = sub_value(r_10, r_3)?;

        let s_6 = sub_value(r_5, &b_m1_inverse)?;

        let s_7 = sub_value(r_12, r_2)?;
        let s_8 = sub_value(r_14, &b.mul(r_3, Some(&mut ctx1))?)?;

        let s_9 = add_value(r_7, &r.mul(&b_m1_inverse, Some(&mut ctx1))?)?;

        let s_10 = sub_value(r_8, &b_p1_inverse)?;
        let s_11 = add_value(r_9, &r.mul(&b_p1_inverse, Some(&mut ctx1))?)?;

        Ok(hashmap![
            "s_1".to_string() => s_1, "s_2".to_string() => s_2,
            "s_3".to_string() => s_3, "s_4".to_string() => s_4,
            "s_5".to_string() => s_5, "s_6".to_string() => s_6,
            "s_7".to_string() => s_7, "s_8".to_string() => s_8,
            "s_9".to_string() => s_9, "s_10".to_string() => s_10,
            "s_11".to_string() => s_11
        ])
    }

    pub fn verify(authz_proof_generators: &AuthzProofGenerators,
                  challenge_hash: &BigNumber,
                  c_b: &BigNumber,
                  u_ca: &HashMap<String, BigNumber>,
                  p_ca: &HashMap<String, BigNumber>,
                  accumulator: &BigNumber,
                  t_values: &mut Vec<u8>) -> Result<(), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let n = BigNumber::from_dec(constants::ACCUM1_MODULUS)?;
        let b_hat = BigNumber::from_dec(constants::B_HAT)?;
        let max = b_hat.rshift1()?;
        let min = max.set_negative(true)?;
        let msg = "Value by key '{}' not found in CommitmentAccumulatorProof.verify";

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

        let h_n_inverse = authz_proof_generators.h_n.inverse(&n, Some(&mut ctx))?;


        let t_1_hat = get_generalized_pedersen_commitment(vec![(&c_b, &challenge_hash),
                                                               (&authz_proof_generators.g_3_1, &s_1),
                                                               ( &authz_proof_generators.g_3_2, &s_3)],
                                                          &authz_proof_generators.p_3,
                                                          &mut ctx)?;
        let t_2_hat = get_generalized_pedersen_commitment(vec![(&authz_proof_generators.g_3_1, &challenge_hash),
                                                               (&c_b.mod_div(&authz_proof_generators.g_3_1, &authz_proof_generators.p_3,Some(&mut ctx))?, &s_6),
                                                               (&authz_proof_generators.g_3_2, &s_9) ],
                                                          &authz_proof_generators.p_3,
                                                          &mut ctx)?;
        let t_3_hat = get_generalized_pedersen_commitment(vec![(&authz_proof_generators.g_1_1, &challenge_hash),
                                                               (&c_b.mul(&authz_proof_generators.g_1_1, Some(&mut ctx))?, &s_10),
                                                               (&authz_proof_generators.g_1_2, &s_11)],
                                                          &authz_proof_generators.p_1,
                                                          &mut ctx)?;
        let t_4_hat = get_generalized_pedersen_commitment(vec![(&c_r, &challenge_hash),
                                                               (&authz_proof_generators.g_n, &s_7),
                                                               (&authz_proof_generators.h_n, &s_5)],
                                                          &n,
                                                          &mut ctx)?;
        let t_5_hat = get_generalized_pedersen_commitment(vec![(&c_prime_b, &challenge_hash),
                                                               (&authz_proof_generators.g_n, &s_1),
                                                               (&authz_proof_generators.h_n, &s_2)],
                                                          &n,
                                                          &mut ctx)?;
        let t_6_hat = get_generalized_pedersen_commitment(vec![(&accumulator, &challenge_hash),
                                                               (&c_u, &s_1),
                                                               (&h_n_inverse, &s_4)],
                                                          &n,
                                                          &mut ctx)?;
        let t_7_hat = get_generalized_pedersen_commitment(vec![(&c_r, &s_1),
                                                               (&authz_proof_generators.g_n.inverse(&n, Some(&mut ctx))?, &s_4),
                                                               (&h_n_inverse, &s_8)],
                                                          &n,
                                                          &mut ctx)?;

        t_values.extend_from_slice(&t_1_hat.to_bytes()?);
        println!("t_2 = {:?}", t_2_hat);

//        t_values.extend_from_slice(&t_2_hat.to_bytes()?);
//        t_values.extend_from_slice(&t_3_hat.to_bytes()?);
        t_values.extend_from_slice(&t_4_hat.to_bytes()?);
        t_values.extend_from_slice(&t_5_hat.to_bytes()?);
        t_values.extend_from_slice(&t_6_hat.to_bytes()?);
        t_values.extend_from_slice(&t_7_hat.to_bytes()?);
        Ok(())
    }
}

struct SelectiveDisclosureCLProof {}

impl SelectiveDisclosureCLProof {
    pub fn commit(revealed_attrs: &BTreeMap<String, BigNumber>) -> Result<HashMap<String, BigNumber>, IndyCryptoError>{

        Ok(hashmap![])
    }


//    fn _create_selective_disclosure_commitment(cred_signature: &PrimaryCredentialSignature,
//                                               revealed_attrs: &BTreeMap<String, BigNumber>,
//                                               m_tilde: &BTreeMap<String, BigNumber>,
//                                               attribute_name: &str,
//                                               authz_proof_commitments: &AuthzProofCommitments,
//                                               authz_proof_blinding_factors: &AuthzProofBlindingFactors,
//                                               r_values: &mut Vec<u8>,
//                                               t_values: &mut Vec<u8>) -> Result<Vec<BigNumber>, IndyCryptoError> {
//
//        let a = &authz_proof_commitments.k;
//
//
//        let u_values = Vec::new();
//        Ok(u_values)
//    }
    pub fn challenge() {

    }
    pub fn verify() {

    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct AuthzProofCommitments {
    k: BigNumber,
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

        let k = get_pedersen_commitment(&authz_proof_generators.g_1_1, &authz_proof_factors.agent_secret,
                                        &authz_proof_generators.g_1_2, &authz_proof_factors.r_0,
                                        &authz_proof_generators.p_1, &mut ctx)?;

        let c_1 = get_pedersen_commitment(&authz_proof_generators.g_2_1, &k,
                                          &authz_proof_generators.g_2_2, &authz_proof_factors.policy_address,
                                          &authz_proof_generators.p_2, &mut ctx)?;

        let c_2 = get_pedersen_commitment(&authz_proof_generators.g_1_1, &authz_proof_factors.agent_secret,
                                          &authz_proof_generators.g_1_2, &authz_proof_blinding_factors.r_1,
                                          &authz_proof_generators.p_1, &mut ctx)?;

        let c_3 = get_generalized_pedersen_commitment(vec![(&authz_proof_generators.g_2_1, &k),
                                                           (&authz_proof_generators.g_2_2, &authz_proof_factors.policy_address),
                                                           (&authz_proof_generators.g_2_3, &authz_proof_blinding_factors.r_2)],
                                                      &authz_proof_generators.p_2, &mut ctx)?;

        let c_4 = get_pedersen_commitment(&authz_proof_generators.g_3_1, &c_1,
                                          &authz_proof_generators.g_3_2,&authz_proof_blinding_factors.r_3,
                                          &authz_proof_generators.p_3, &mut ctx)?;

        Ok(AuthzProofCommitments { k, c_1, c_2, c_3, c_4 })
    }
}

impl JsonEncodable for AuthzProofCommitments {}

impl<'a> JsonDecodable<'a> for AuthzProofCommitments {}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct AuthzProofFactors {
    agent_secret: BigNumber,
    r_0: BigNumber,
    policy_address: BigNumber,
}

impl JsonEncodable for AuthzProofFactors {}

impl<'a> JsonDecodable<'a> for AuthzProofFactors {}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthzProofBlindingFactors {
    r_1: BigNumber,
    r_2: BigNumber,
    r_3: BigNumber,
}

impl AuthzProofBlindingFactors {
    pub fn new(p_0: &BigNumber) -> Result<AuthzProofBlindingFactors, IndyCryptoError> {
        let r_1 = generate_nonce(constants::R_0_SIZE, None, &p_0)?;
        let r_2 = generate_nonce(constants::R_0_SIZE, None, &p_0)?;
        let r_3 = generate_nonce(constants::R_0_SIZE, None, &p_0)?;

        Ok(AuthzProofBlindingFactors { r_1, r_2, r_3 })
    }
}

#[derive(Debug)]
pub struct AuthzProofGenerators {
    g_1_1: BigNumber,
    g_1_2: BigNumber,
    g_1_3: BigNumber,

    g_2_1: BigNumber,
    g_2_2: BigNumber,
    g_2_3: BigNumber,

    g_3_1: BigNumber,
    g_3_2: BigNumber,

    p_0: BigNumber,
    p_1: BigNumber,
    p_2: BigNumber,
    p_3: BigNumber,

    g_n: BigNumber,
    h_n: BigNumber
}

impl AuthzProofGenerators {
    pub fn new() -> Result<AuthzProofGenerators, IndyCryptoError> {
        let g_1_1 = BigNumber::from_dec(constants::G_1_1)?;
        let g_1_2 = BigNumber::from_dec(constants::G_1_2)?;
        let g_1_3 = BigNumber::from_dec(constants::G_1_3)?;


        let g_2_1 = BigNumber::from_dec(constants::G_2_1)?;
        let g_2_2 = BigNumber::from_dec(constants::G_2_2)?;
        let g_2_3 = BigNumber::from_dec(constants::G_2_3)?;

        let g_3_1 = BigNumber::from_dec(constants::G_3_1)?;
        let g_3_2 = BigNumber::from_dec(constants::G_3_2)?;

        let g_n = BigNumber::from_dec(constants::G_N)?;
        let h_n = BigNumber::from_dec(constants::H_N)?;

        let p_0 = BigNumber::from_dec(constants::P_0)?;
        let p_1 = BigNumber::from_dec(constants::P_1)?;
        let p_2 = BigNumber::from_dec(constants::P_2)?;
        let p_3 = BigNumber::from_dec(constants::P_3)?;

        Ok(AuthzProofGenerators { g_1_1, g_1_2, g_1_3, g_2_1, g_2_2, g_2_3, g_3_1, g_3_2, p_0, p_1, p_2, p_3, g_n, h_n })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use self::helpers::{MockHelper, bn_rand};
    use cl::prover::mocks as prover_mocks;

    #[test]
    fn double_comm_2_group_proof_works() {
        MockHelper::inject();

        let authz_proof_factors = mocks::authz_proof_factors();
        let authz_proof_generators = mocks::authz_proof_generators();
        let authz_proof_blinding_factors = mocks::authz_proof_blinding_factors();
        let authz_proof_commitments = AuthzProofCommitments::new(&mocks::authz_proof_factors(),
                                                                 &mocks::authz_proof_blinding_factors(),
                                                                 &mocks::authz_proof_generators()).unwrap();

        let verifier_nonce = bn_rand(128).unwrap();
        let mut t_values = Vec::new();
        let num_attrs = 5;

        let u_dc2 = DoubleCommitmentProof2Group::commit(&authz_proof_commitments.c_2,
                                                        num_attrs,
                                                        &authz_proof_generators,
                                                        &mut t_values).unwrap();

        t_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let challenge_hash = get_hash_as_int(&vec![t_values]).unwrap();

        let p_dc2 = DoubleCommitmentProof2Group::challenge(&authz_proof_generators,
                                                           &authz_proof_factors.agent_secret,
                                                           &authz_proof_blinding_factors.r_1,
                                                           &authz_proof_factors.r_0,
                                                           &authz_proof_blinding_factors.r_1.set_negative(true).unwrap(),
                                                           &authz_proof_factors.policy_address,
                                                           &challenge_hash,
                                                           &u_dc2).unwrap();
        let mut t_hat_values = Vec::new();

        DoubleCommitmentProof2Group::verify(&challenge_hash,
                                            &authz_proof_generators,
                                            &authz_proof_commitments.c_2,
                                            &authz_proof_commitments.c_3,
                                            &p_dc2,
                                            &mut t_hat_values).unwrap();

        t_hat_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let verify_hash = get_hash_as_int(&vec![t_hat_values]).unwrap();

        assert_eq!(verify_hash, challenge_hash);
    }

    #[test]
    fn double_comm_3_group_proof_works() {
        MockHelper::inject();

        let authz_proof_factors = mocks::authz_proof_factors();
        let authz_proof_generators = mocks::authz_proof_generators();
        let authz_proof_blinding_factors = mocks::authz_proof_blinding_factors();
        let authz_proof_commitments = AuthzProofCommitments::new(&mocks::authz_proof_factors(),
                                                                 &mocks::authz_proof_blinding_factors(),
                                                                 &mocks::authz_proof_generators()).unwrap();

        let mut ctx = BigNumber::new_context().unwrap();
        let x = authz_proof_generators.g_2_3.mod_exp(&authz_proof_blinding_factors.r_2.set_negative(true).unwrap(),
                                                     &authz_proof_generators.p_2, Some(&mut ctx)).unwrap();
        let y = authz_proof_commitments.c_3.mod_mul(&x, &authz_proof_generators.p_2, Some(&mut ctx)).unwrap();
        let c_4 = get_pedersen_commitment(&authz_proof_generators.g_3_1, &y,
                                          &authz_proof_generators.g_3_2, &authz_proof_blinding_factors.r_3,
                                          &authz_proof_generators.p_3, &mut ctx).unwrap();

        assert_eq!(authz_proof_commitments.c_4, c_4);

        let verifier_nonce = bn_rand(128).unwrap();
        let mut t_values = Vec::new();
        let num_attrs = 5;

        let u_dc1 = DoubleCommitmentProof3Group::commit(&authz_proof_commitments.c_3,
                                                        num_attrs,
                                                        &authz_proof_generators,
                                                        &mut t_values).unwrap();

        t_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let challenge_hash = get_hash_as_int(&vec![t_values]).unwrap();

        let p_dc1 = DoubleCommitmentProof3Group::challenge(&authz_proof_generators,
                                                           &authz_proof_commitments.k,
                                                           &authz_proof_factors.policy_address,
                                                           &authz_proof_blinding_factors.r_2,
                                                           &authz_proof_blinding_factors.r_2.set_negative(true).unwrap(),
                                                           &authz_proof_blinding_factors.r_3,
                                                           &challenge_hash,
                                                           &u_dc1).unwrap();
        let mut t_hat_values = Vec::new();

        DoubleCommitmentProof3Group::verify(&challenge_hash,
                                           &authz_proof_generators,
                                           &authz_proof_commitments.c_3,
                                           &authz_proof_commitments.c_4,
                                           &p_dc1,
                                           &mut t_hat_values).unwrap();

        t_hat_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let verify_hash = get_hash_as_int(&vec![t_hat_values]).unwrap();

        assert_eq!(verify_hash, challenge_hash);
    }

    #[test]
    fn commitment_accum_proof_works() {
        MockHelper::inject();

        let authz_proof_factors = mocks::authz_proof_factors();
        let authz_proof_generators = mocks::authz_proof_generators();
        let authz_proof_blinding_factors = mocks::authz_proof_blinding_factors();

        let authz_proof_commitments = AuthzProofCommitments::new(&mocks::authz_proof_factors(),
                                                                 &mocks::authz_proof_blinding_factors(),
                                                                 &mocks::authz_proof_generators()).unwrap();

        let verifier_nonce = bn_rand(128).unwrap();
        let n = BigNumber::from_dec(constants::ACCUM1_MODULUS).unwrap();
        let mut ctx = BigNumber::new_context().unwrap();

        let witness =  authz_proof_generators.g_n.mod_exp(&BigNumber::from_u32(1).unwrap(), &n, Some(&mut ctx)).unwrap();
        let accumulator = authz_proof_generators.g_n.mod_exp(&authz_proof_commitments.c_1, &n, Some(&mut ctx)).unwrap();

        let mut t_values = Vec::new();

        let (u_ca, r_ca) = CommitmentAccumulatorProof::commit(&authz_proof_commitments.c_1,
                                                              &authz_proof_blinding_factors.r_3,
                                                              &witness,
                                                              &authz_proof_commitments.c_4,
                                                              &authz_proof_generators,
                                                              &mut t_values).unwrap();

        t_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let challenge_hash = get_hash_as_int(&vec![t_values]).unwrap();

        let p_ca = CommitmentAccumulatorProof::challenge(&authz_proof_commitments.c_1,
                                                         &authz_proof_blinding_factors.r_3,
                                                         &challenge_hash,
                                                         &authz_proof_generators,
                                                         &r_ca).unwrap();

        let mut t_hat_values = Vec::new();

        CommitmentAccumulatorProof::verify(&authz_proof_generators,
                                           &challenge_hash,
                                           &authz_proof_commitments.c_4,
                                           &u_ca,
                                           &p_ca,
                                           &accumulator,
                                           &mut t_hat_values).unwrap();

        t_hat_values.extend_from_slice(&verifier_nonce.to_bytes().unwrap());

        let verify_hash = get_hash_as_int(&vec![t_hat_values]).unwrap();

        assert_eq!(verify_hash, challenge_hash);
    }

    #[test]
    fn comm_acc_proof_math_works() {

        println!("{:?}", bn_rand(constants::P_3_SIZE).unwrap());
        let p0: i64 = 11;
        let p1: i64 = 23;
        let p2: i64 = 47;
        let p3: i64 = 107;
        let n: i64 = 179 * 227;

        let g1: i64 = 4;
        let h1: i64 = 9;
        let g2: i64 = 16;
        let h2: i64 = 25;
        let k2: i64 = 36;
        let g3: i64 = 49;
        let h3: i64 = 64;
        let gn: i64 = 81;
        let hn: i64 = 100;

        let s: i64 = 3;
        let policy_address: i64 = 12;
        let r0: i64 = 16;
        let K: i64 = 6;
        let C1: i64 = 37;

        let r3: i64 = 67;
        let C4: i64 = 97;

        let r4: i64 = 5;
        let r6: i64 = 7;
        let c: i64 = 87;
        let s1: i64 = r4 - (c * C1);
        let s3: i64 = r6 - (c * r3);

//        let t1: i64 = ((g3.pow(r4 as u32) % p3) * (h3.pow(r6 as u32) % p3)) % p3;
//        println!("t1={}", t1);
//        let t3_1: i64 = C4.pow(c as u32) % p3;
//        let t3_2: i64 = g3.pow(s1 as u32) % p3;
//        let t3_3: i64 = h3.pow(s3 as u32) % p3;
        //let t1_hat: i64 = (t3_1 * t3_2 * t3_3) % p3;
        //println!("t1_hat={}", t1_hat);
    }



    #[test]
    fn authz_proof_works() {
//        println!("{:?}", bn_rand(4096).unwrap());
//        assert!(false);
        MockHelper::inject();

        let cred_values = prover_mocks::credential_values();
        let cred_signature = prover_mocks::primary_credential();
        let authz_proof_factors = mocks::authz_proof_factors();
        let authz_proof_generators = mocks::authz_proof_generators();
        let authz_proof_commitments = mocks::authz_proof_commitments();

        let verifier_nonce = bn_rand(128).unwrap();
        let mut ctx = BigNumber::new_context().unwrap();

        let n = BigNumber::from_dec(constants::ACCUM1_MODULUS).unwrap();

        let witness = BigNumber::from_u32(1).unwrap();
        let accumulator = authz_proof_generators.g_n.mod_exp(&authz_proof_commitments.c_1, &n, Some(&mut ctx)).unwrap();

        let authzproof = AuthzProof::new(&cred_values,
                                         &cred_signature,
                                         &mocks::revealed_attrs(),
                                         "policy_address",
                                         &mocks::m_tildes(),
                                         &authz_proof_factors,
                                         &witness,
                                         &verifier_nonce).unwrap();

        assert!(authzproof.verify(&accumulator, &verifier_nonce).unwrap());
    }
}

#[cfg(test)]
mod mocks {
    use super::*;
    use cl::prover::mocks as prover_mocks;

    pub fn authz_proof_factors() -> AuthzProofFactors {
        AuthzProofFactors {
            agent_secret: BigNumber::from_dec("89035060045652462381130209244352620421002985094628950327696113598322429853594").unwrap(),
            r_0: BigNumber::from_dec("29725375518143676472497118402814248170934510546363505461475082817019922191783244582330235228330025889172470252840976585553324632262649056007024189423886399201806006228087529099455044738776684918313074191200956161692248149307624096938416544786574760117875013644543290937513606567526487502629191714368998789806").unwrap(),
            policy_address: prover_mocks::policy_address()
        }
    }

    pub fn authz_proof_blinding_factors() -> AuthzProofBlindingFactors {
        AuthzProofBlindingFactors {
            r_1: BigNumber::from_dec("71588807687259531469323534193930354158985511062889656599217955369709123716753735680945396508653008863246585030943388662749859835034063975143348180090832511435888702029247366886224038966742887508037386913238688124357430456891728557252301897575385174980962989227680005573977551037967305036613404034644046966308").unwrap(),
            r_2: BigNumber::from_dec("178398259962269860213055513912245878024921516450065957656498178841103122342839240505874425215882188553520880788161385837080911962236278230337978845213493141187529155099680578904930347110671710882303871356966602563995421887796650356978472844462005663303876223144475072112959794461702460526141343944337319245673").unwrap(),
            r_3: BigNumber::from_dec("159427017826742260383931350922695026433930943086629892370906302847930234312541984240833502393642099362330296815748885505329393395510320212216553791958995789709048733672457131320473850370228029207943302681078152722504453150506062578226284268336580048892564963063091221249035066150963457391556887800939372608126").unwrap(),
        }
    }

    pub fn authz_proof_generators() -> AuthzProofGenerators {
        AuthzProofGenerators {
            g_1_1: BigNumber::from_dec(constants::G_1_1).unwrap(),
            g_1_2: BigNumber::from_dec(constants::G_1_2).unwrap(),
            g_1_3: BigNumber::from_dec(constants::G_1_3).unwrap(),
            g_2_1: BigNumber::from_dec(constants::G_2_1).unwrap(),
            g_2_2: BigNumber::from_dec(constants::G_2_2).unwrap(),
            g_2_3: BigNumber::from_dec(constants::G_2_3).unwrap(),
            g_3_1: BigNumber::from_dec(constants::G_3_1).unwrap(),
            g_3_2: BigNumber::from_dec(constants::G_3_2).unwrap(),
            g_n: BigNumber::from_dec(constants::G_N).unwrap(),
            h_n: BigNumber::from_dec(constants::H_N).unwrap(),
            p_0: BigNumber::from_dec(constants::P_0).unwrap(),
            p_1: BigNumber::from_dec(constants::P_1).unwrap(),
            p_2: BigNumber::from_dec(constants::P_2).unwrap(),
            p_3: BigNumber::from_dec(constants::P_3).unwrap()
        }
    }

    pub fn authz_proof_commitments() -> AuthzProofCommitments {
        AuthzProofCommitments {
            k: BigNumber::from_dec("271447533829039025200297072042676626600527844938592421627544370089245193773721260633464672903393291404438685584573600628734912879143019121437885403570241619036817567685648650157093526238659092266050215116304067384686023653527370265879456498711934387184896543633577662527315105686230622215106400026662141042563").unwrap(),
            c_1: BigNumber::from_dec("501963907841135302359152573063071931671684105553568177576757985066166760873202459039436134440400029830217356858492265921808089228336421168824501496128431477195091380998017589164152785657241796132221122371224748360962727309683266667608510508299115591826159629269907845577178527054995879391806410437126584058086").unwrap(),
            c_2: BigNumber::from_dec("367763954732381053863467060705022438949559485080046039115425879357653897909591462049218199180139702047335603505704097301468303038576869870181877187793296448154512585161980850782456433960095193084633120393572862508402261023595354889938185570478522993388289048302557891167738873369819120824744719887957386737497").unwrap(),
            c_3: BigNumber::from_dec("1159720079513948348509020506619662995264838488891317524145057625146536180119316289754424201870035609882397700106813232076605292055301186920095284550440498951883637113899560746932485434424488738097717278332855021258505107954996063310094579808948558797219615837616091712736576212523488327118817495556843850448577").unwrap(),
            c_4: BigNumber::from_dec("2800350907981024842149935397661007650038556645935389938029996214445841367440969287450741486608243628921433981487420747404658989509291582987069328464220833675810051789971330157791930703059659912462770546755851988432223929484056319138975721384487989022580020646673623252415940176448765066809499468911250709015994466285456350325984698895040171179453458433438652749576321020409518185072774786500012546545233421549779995176338868839751209151586890154679312709411009171").unwrap(),
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
