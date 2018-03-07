mod constants;
#[macro_use]
mod helpers;

use utils::commitment::{get_pedersen_commitment,get_generalised_pedersen_commitment};
use utils::json::{JsonEncodable, JsonDecodable};
use errors::IndyCryptoError;
use self::helpers::generate_nonce;

use bn::BigNumber;

use std::vec::Vec;
use std::collections::{BTreeMap, HashMap};
use cl::{CredentialValues,
         Nonce,
         PrimaryCredentialSignature};

#[derive(Debug)]
pub struct AuthzProof {

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

        let authz_proof_blinding_factors = AuthzProofBlindingFactors::new()?;
        let authz_proof_commitments = AuthzProofCommitments::new(&authz_proof_factors, &authz_proof_blinding_factors)?;

//        let mut r_values = Vec::new();
        let mut t_values = Vec::new();

        let (u_ca, r_ca) = CommitmentAccumulatorProof::commit(&authz_proof_commitments,
                                                              &authz_proof_blinding_factors,
                                                              witness,
                                                              &mut t_values)?;



        Ok(AuthzProof{})
    }

    fn _create_selective_disclosure_commitment(cred_signature: &PrimaryCredentialSignature,
                                               revealed_attrs: &BTreeMap<String, BigNumber>,
                                               m_tilde: &BTreeMap<String, BigNumber>,
                                               attribute_name: &str,
                                               authz_proof_commitments: &AuthzProofCommitments,
                                               authz_proof_blinding_factors: &AuthzProofBlindingFactors,
                                               r_values: &mut Vec<u8>,
                                               t_values: &mut Vec<u8>) -> Result<Vec<BigNumber>, IndyCryptoError> {

        let a = &authz_proof_commitments.k;


        let u_values = Vec::new();
        Ok(u_values)
    }

    fn _create_double_commitment_proof_commitment(double_commitment: &BigNumber,
                                                  num_attrs: usize,
                                                  authz_proof_blinding_factors: &AuthzProofBlindingFactors,
                                                  t_values: &mut Vec<u8>) -> Result<Vec<BigNumber>, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;
        let mut u_values = Vec::new();

        //a_prime
        u_values.push(generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?);
        //b_prime
        u_values.push(generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?);
        //d_prime
        u_values.push(generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?);

        for i in 0..num_attrs {
            let e_i = generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?;
            let f_i = generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?;

            let tmp = double_commitment.mod_mul(
                        &authz_proof_blinding_factors.g_1_3.mod_exp(&e_i,
                                                                   &authz_proof_blinding_factors.p_1,
                                                                   Some(&mut ctx))?,
                        &authz_proof_blinding_factors.p_1,
                        Some(&mut ctx))?;

            let t_i = get_pedersen_commitment(&authz_proof_blinding_factors.g_2_1,
                                              &tmp,
                                              &authz_proof_blinding_factors.g_2_2,
                                              &f_i,
                                              &authz_proof_blinding_factors.p_2,
                                              &mut ctx)?;

            t_values.extend_from_slice(&t_i.to_bytes()?);
            u_values.push(e_i);
            u_values.push(f_i);
        }

        let v = get_generalised_pedersen_commitment(vec![(&u_values[0], &authz_proof_blinding_factors.g_1_1),
                                                         (&u_values[1], &authz_proof_blinding_factors.g_1_2)],
                                                    &authz_proof_blinding_factors.g_1_3,
                                                    &u_values[2],
                                                    &authz_proof_blinding_factors.p_1,
                                                    &mut ctx)?;
        t_values.extend_from_slice(&v.to_bytes()?);
        Ok(u_values)
    }
}

pub struct CommitmentAccumulatorProof {}

impl CommitmentAccumulatorProof {
    pub fn commit(authz_proof_commitments: &AuthzProofCommitments,
                  authz_proof_blinding_factors: &AuthzProofBlindingFactors,
                  u: &BigNumber,
                  t_values: &mut Vec<u8>) -> Result<(HashMap<String, BigNumber>,
                                                     HashMap<String, BigNumber>), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let b = &authz_proof_commitments.c_1;
        let r = &authz_proof_blinding_factors.r_3;
        let c_b = &authz_proof_commitments.c_4;

        let n_div_4 = BigNumber::from_dec(constants::ACCUM1_MODULUS_BY_4)?;
        let n = BigNumber::from_dec(constants::ACCUM1_MODULUS)?;
        let b_hat = BigNumber::from_dec(constants::B_HAT)?;
        let security_level = BigNumber::from_dec(constants::SECURITY_LEVEL)?;

        let r_1 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_2 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_3 = generate_nonce(constants::ACCUM_MODULUS_SIZE-2, None, &n_div_4)?;
        let r_4_upper = b_hat.div(&BigNumber::from_u32(4)?, Some(&mut ctx))?;

        let r_4 = generate_nonce(constants::ACCUM_A_SIZE*2-2,
                                 Some(&r_4_upper.set_negative(true)?),
                                 &r_4_upper)?;

        let r_5 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?;
        let r_6 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?;
        let r_7 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?;
        let r_8 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?;
        let r_9 = generate_nonce(constants::R_0_SIZE, None, &authz_proof_blinding_factors.p_0)?;

        let r_10_upper = n.mul(&b_hat, Some(&mut ctx))?
                          .div(&security_level, Some(&mut ctx))?;
        let r_10_lower = r_10_upper.set_negative(true)?;

        let r_10 = generate_nonce(constants::ACCUM_MODULUS_SIZE, Some(&r_10_lower), &r_10_upper)?;
        let r_11 = generate_nonce(constants::ACCUM_MODULUS_SIZE, Some(&r_10_lower), &r_10_upper)?;
        let r_12 = generate_nonce(constants::ACCUM_MODULUS_SIZE, Some(&r_10_lower), &r_10_upper)?;

        let r_13_upper = r_10_upper.mul(&authz_proof_blinding_factors.p_0, Some(&mut ctx))?;
        let r_13_lower = r_10_lower.mul(&authz_proof_blinding_factors.p_0, Some(&mut ctx))?;

        let r_13 = generate_nonce(constants::ACCUM_MODULUS_SIZE, Some(&r_13_lower), &r_13_upper)?;
        let r_14 = generate_nonce(constants::ACCUM_MODULUS_SIZE, Some(&r_13_lower), &r_13_upper)?;

        let c_prime_b = get_pedersen_commitment(&authz_proof_blinding_factors.g_n,
                                                &b,
                                                &authz_proof_blinding_factors.h_n,
                                                &r_1,
                                                &n,
                                                &mut ctx)?;

        let c_u = u.mod_mul(&authz_proof_blinding_factors.h_n.mod_exp(&r_2, &n, Some(&mut ctx))?, &n, Some(&mut ctx))?;
        let c_r = get_pedersen_commitment(&authz_proof_blinding_factors.g_n,
                                          &r,
                                          &authz_proof_blinding_factors.h_n,
                                          &r_3,
                                          &n,
                                          &mut ctx)?;

        let t_1 = get_pedersen_commitment(&authz_proof_blinding_factors.g_1_1,
                                          &r_4,
                                          &authz_proof_blinding_factors.g_1_2,
                                          &r_6,
                                          &authz_proof_blinding_factors.p_1,
                                          &mut ctx)?;
        let t_2 = get_pedersen_commitment(&c_b.div(&authz_proof_blinding_factors.g_1_1, Some(&mut ctx))?,
                                          &r_5,
                                          &authz_proof_blinding_factors.g_1_2,
                                          &r_7,
                                          &authz_proof_blinding_factors.p_1,
                                          &mut ctx)?;
        let t_3 = get_pedersen_commitment(&c_b.mul(&authz_proof_blinding_factors.g_1_1, Some(&mut ctx))?,
                                          &r_8,
                                          &authz_proof_blinding_factors.g_1_2,
                                          &r_9,
                                          &authz_proof_blinding_factors.p_1,
                                          &mut ctx)?;
        let t_4 = get_pedersen_commitment(&authz_proof_blinding_factors.g_n,
                                          &r_12,
                                          &authz_proof_blinding_factors.h_n,
                                          &r_10,
                                          &n,
                                          &mut ctx)?;
        let t_5 = get_pedersen_commitment(&authz_proof_blinding_factors.g_n,
                                          &r_11,
                                          &authz_proof_blinding_factors.h_n,
                                          &r_4,
                                          &n,
                                          &mut ctx)?;

        let h_2_inverse = &authz_proof_blinding_factors.h_n.inverse(&n, Some(&mut ctx))?;

        let t_6 = get_pedersen_commitment(&c_u,
                                          &r_4,
                                          &h_2_inverse,
                                          &r_13,
                                          &n,
                                          &mut ctx)?;

        let t_7 = get_generalised_pedersen_commitment(vec![(&c_r, &r_4),
                                                           (&h_2_inverse, &r_14)],
                                                      &authz_proof_blinding_factors.g_n.inverse(&n, Some(&mut ctx))?,
                                                      &r_13,
                                                      &n,
                                                      &mut ctx)?;

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

    pub fn open(challenge_hash: &BigNumber,
                authz_proof_commitments: &AuthzProofCommitments,
                authz_proof_blinding_factors: &AuthzProofBlindingFactors,
                u_ca: &HashMap<String, BigNumber>) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let msg = "Value by key '{}' not found in CommitmentAccumulatorProof.open";
        let b = &authz_proof_commitments.c_1;
        let r = &authz_proof_blinding_factors.r_3;

        let mut hide_value = |first: &BigNumber, second: &BigNumber| first.sub(&challenge_hash.mul(second, Some(&mut ctx))?);
        let get_value = |key: &str| u_ca.get(key).ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in CommitmentAccumulatorProof.open", key)));

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

        let s_1 = hide_value(r_4, &b)?;
        let s_2 = hide_value(r_11, r_1)?;
        let s_3 = hide_value(r_6, &r)?;

        let s_4 = hide_value(r_13, &b.mul(r_2, Some(&mut ctx1))?)?;
        let s_5 = hide_value(r_10, r_2)?;

        let b_m1_inverse = b.decrement()?.inverse(&authz_proof_blinding_factors.p_1, Some(&mut ctx1))?;
        let b_p1_inverse = b.increment()?.inverse(&authz_proof_blinding_factors.p_1, Some(&mut ctx1))?;

        let s_6 = hide_value(r_5, &b_m1_inverse)?;
        let s_7 = hide_value(r_12, r_3)?;
        let s_8 = hide_value(r_14, &b.mul(r_3, Some(&mut ctx1))?)?;
        let s_9 = hide_value(r_7, &r.mul(&b_m1_inverse, Some(&mut ctx1))?)?;
        let s_10 = hide_value(r_8, &b_p1_inverse)?;
        let s_11 = hide_value(r_9, &r.mul(&b_p1_inverse, Some(&mut ctx1))?)?;

        Ok(hashmap![
            "s_1".to_string() => s_1, "s_2".to_string() => s_2,
            "s_3".to_string() => s_3, "s_4".to_string() => s_4,
            "s_5".to_string() => s_5, "s_6".to_string() => s_6,
            "s_7".to_string() => s_7, "s_8".to_string() => s_8,
            "s_9".to_string() => s_9, "s_10".to_string() => s_10,
            "s_11".to_string() => s_11
        ])
    }

    pub fn verify(authz_proof_blinding_factors: &AuthzProofBlindingFactors,
                  challenge_hash: &BigNumber,
                  c_b: &BigNumber,
                  r_ca: &HashMap<String, BigNumber>,
                  p_ca: &HashMap<String, BigNumber>,
                  accumulator: &BigNumber,
                  t_values: &mut Vec<u8>) -> Result<(), IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;
        let n = BigNumber::from_dec(constants::ACCUM1_MODULUS)?;
        let b_hat = BigNumber::from_dec(constants::B_HAT)?;
        let max = b_hat.rshift1()?;
        let min = max.set_negative(true)?;
        let msg = "Value by key '{}' not found in CommitmentAccumulatorProof.verify";

        let pget_value = |key: &str| p_ca.get(key).ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in CommitmentAccumulatorProof.verify", key)));
        let rget_value = |key: &str| r_ca.get(key).ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in CommitmentAccumulatorProof.verify", key)));

        let s_1 = pget_value("s_1")?;
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






        let c_prime_b = rget_value("c_prime_b")?;
        let c_u = rget_value("c_u")?;
        let c_r = rget_value("c_r")?;

        let h_n_inverse = authz_proof_blinding_factors.h_n.inverse(&n, Some(&mut ctx))?;

        let t_1_hat = get_generalised_pedersen_commitment(vec![(&c_b, &challenge_hash), (&authz_proof_blinding_factors.g_1_1, &s_1)],
                                                          &authz_proof_blinding_factors.g_1_2,
                                                          &s_3,
                                                          &authz_proof_blinding_factors.p_1,
                                                          &mut ctx)?;
        let t_2_hat = get_generalised_pedersen_commitment(vec![(&authz_proof_blinding_factors.g_1_1, &challenge_hash), (&c_b.div(&authz_proof_blinding_factors.g_1_1, Some(&mut ctx))?, &s_6)],
                                                          &authz_proof_blinding_factors.g_1_2,
                                                          &s_9,
                                                          &authz_proof_blinding_factors.p_1,
                                                          &mut ctx)?;
        let t_3_hat = get_generalised_pedersen_commitment(vec![(&authz_proof_blinding_factors.g_1_1, &challenge_hash), (&c_b.mul(&authz_proof_blinding_factors.g_1_1, Some(&mut ctx))?, &s_10)],
                                                          &authz_proof_blinding_factors.g_1_2,
                                                          &s_11,
                                                          &authz_proof_blinding_factors.p_1,
                                                          &mut ctx)?;
        let t_4_hat = get_generalised_pedersen_commitment(vec![(&c_r, &challenge_hash), (&authz_proof_blinding_factors.g_n, &s_7)],
                                                          &authz_proof_blinding_factors.h_n,
                                                          &s_5,
                                                          &n,
                                                          &mut ctx)?;
        let t_5_hat = get_generalised_pedersen_commitment(vec![(&c_prime_b, &challenge_hash), (&authz_proof_blinding_factors.h_n, &s_1)],
                                                          &authz_proof_blinding_factors.g_n,
                                                          &s_2,
                                                          &n,
                                                          &mut ctx)?;
        let t_6_hat = get_generalised_pedersen_commitment(vec![(&accumulator, &challenge_hash), (&c_u, &s_1)],
                                                          &h_n_inverse,
                                                          &s_4,
                                                          &n,
                                                          &mut ctx)?;
        let t_7_hat = get_generalised_pedersen_commitment(vec![(&c_r, &s_1), (&authz_proof_blinding_factors.g_n.inverse(&n, Some(&mut ctx))?, &s_4)],
                                                          &h_n_inverse,
                                                          &s_8,
                                                          &n,
                                                          &mut ctx)?;

        Ok(())
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
               authz_proof_blinding_factors: &AuthzProofBlindingFactors) -> Result<AuthzProofCommitments, IndyCryptoError> {

        let mut ctx = BigNumber::new_context()?;

        let k = get_pedersen_commitment(&authz_proof_blinding_factors.g_1_1,
                                        &authz_proof_factors.agent_secret,
                                        &authz_proof_blinding_factors.g_1_2,
                                        &authz_proof_factors.r_0,
                                        &authz_proof_blinding_factors.p_1,
                                        &mut ctx)?;

        let c_1 = get_pedersen_commitment(&authz_proof_blinding_factors.g_2_1,
                                         &k,
                                         &authz_proof_blinding_factors.g_2_2,
                                         &authz_proof_factors.policy_address,
                                         &authz_proof_blinding_factors.p_2,
                                         &mut ctx)?;
        let c_2 = get_pedersen_commitment(&authz_proof_blinding_factors.g_1_1,
                                          &authz_proof_factors.agent_secret,
                                          &authz_proof_blinding_factors.g_1_2,
                                          &authz_proof_blinding_factors.r_1,
                                          &authz_proof_blinding_factors.p_1,
                                          &mut ctx)?;
        let c_3 = get_generalised_pedersen_commitment(vec![(&authz_proof_blinding_factors.g_2_1, &k),
                                                           (&authz_proof_blinding_factors.g_2_2, &authz_proof_factors.policy_address)],
                                                      &authz_proof_blinding_factors.g_2_3,
                                                      &authz_proof_blinding_factors.r_2,
                                                      &authz_proof_blinding_factors.p_2,
                                                      &mut ctx)?;
        let c_4 = get_pedersen_commitment(&authz_proof_blinding_factors.g_3_1,
                                          &c_1,
                                          &authz_proof_blinding_factors.g_3_2,
                                          &authz_proof_blinding_factors.r_3,
                                          &authz_proof_blinding_factors.p_3,
                                          &mut ctx)?;
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

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct AuthzProofBlindingFactors {
    r_1: BigNumber,
    r_2: BigNumber,
    r_3: BigNumber,

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
    h_n: BigNumber,
}

impl AuthzProofBlindingFactors {
    pub fn new() -> Result<AuthzProofBlindingFactors, IndyCryptoError> {
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

        let r_1 = generate_nonce(constants::R_0_SIZE, None, &p_0)?;
        let r_2 = generate_nonce(constants::R_0_SIZE, None, &p_0)?;
        let r_3 = generate_nonce(constants::R_0_SIZE, None, &p_0)?;

        Ok(AuthzProofBlindingFactors { r_1, r_2, r_3, g_1_1, g_1_2, g_1_3, g_2_1, g_2_2, g_2_3, g_3_1, g_3_2, p_0, p_1, p_2, p_3, g_n, h_n })
    }
}

impl JsonEncodable for AuthzProofBlindingFactors {}

impl<'a> JsonDecodable<'a> for AuthzProofBlindingFactors {}

#[cfg(test)]
mod tests {
    use super::*;
    use self::helpers::MockHelper;

    #[test]
    fn authz_blinding_factors_new_works() {
        MockHelper::inject();

        assert_eq!(mocks::authz_proof_blinding_factors(), AuthzProofBlindingFactors::new().unwrap());
    }

    #[test]
    fn authz_proof_commitments_new_works() {
        MockHelper::inject();

        let authz_proof_commitments = AuthzProofCommitments::new(&mocks::authz_proof_factors(),
                                                                 &mocks::authz_proof_blinding_factors()).unwrap();
        assert_eq!(mocks::authz_proof_commitments(), authz_proof_commitments);
    }
}

#[cfg(test)]
mod mocks {
    use super::*;

    pub fn authz_proof_factors() -> AuthzProofFactors {
        AuthzProofFactors {
            agent_secret: BigNumber::from_dec("89035060045652462381130209244352620421002985094628950327696113598322429853594").unwrap(),
            r_0: BigNumber::from_dec("29725375518143676472497118402814248170934510546363505461475082817019922191783244582330235228330025889172470252840976585553324632262649056007024189423886399201806006228087529099455044738776684918313074191200956161692248149307624096938416544786574760117875013644543290937513606567526487502629191714368998789806").unwrap(),
            policy_address: BigNumber::from_dec("10979965024420741692162843547224767380599967419244397339536483088110145809187").unwrap()
        }
    }

    pub fn authz_proof_blinding_factors() -> AuthzProofBlindingFactors {
        AuthzProofBlindingFactors {
            r_1: BigNumber::from_dec("48494631233207955414853387579459463667625284089442525091171986044059375848170630925424510748349918677840484459795910981760195632663159075063144770240917652713621089799017299698306302266805293701042461417057168331260940672146774932257056859706038053676216817045826698701820174406548527622912293747330765189484").unwrap(),
            r_2: BigNumber::from_dec("48494631233207955414853387579459463667625284089442525091171986044059375848170630925424510748349918677840484459795910981760195632663159075063144770240917652713621089799017299698306302266805293701042461417057168331260940672146774932257056859706038053676216817045826698701820174406548527622912293747330765189484").unwrap(),
            r_3: BigNumber::from_dec("48494631233207955414853387579459463667625284089442525091171986044059375848170630925424510748349918677840484459795910981760195632663159075063144770240917652713621089799017299698306302266805293701042461417057168331260940672146774932257056859706038053676216817045826698701820174406548527622912293747330765189484").unwrap(),
            p_0: BigNumber::from_dec(constants::P_0).unwrap(),
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
            p_1: BigNumber::from_dec(constants::P_1).unwrap(),
            p_2: BigNumber::from_dec(constants::P_2).unwrap(),
            p_3: BigNumber::from_dec(constants::P_3).unwrap()
        }
    }

    pub fn authz_proof_commitments() -> AuthzProofCommitments {
        AuthzProofCommitments {
            k: BigNumber::from_dec("271447533829039025200297072042676626600527844938592421627544370089245193773721260633464672903393291404438685584573600628734912879143019121437885403570241619036817567685648650157093526238659092266050215116304067384686023653527370265879456498711934387184896543633577662527315105686230622215106400026662141042563").unwrap(),
            c_1: BigNumber::from_dec("266105828820876557808635912214843074241417069447192420262236039300579677967750427734453051218847123046159124129792848869873752467144733394079638940816739722359668332886711732705408586175087900208737675061277555293262732936468345673274291365502056872834409707270526694823765559922682197036609699667135793840483").unwrap(),
            c_2: BigNumber::from_dec("367763954732381053863467060705022438949559485080046039115425879357653897909591462049218199180139702047335603505704097301468303038576869870181877187793296448154512585161980850782456433960095193084633120393572862508402261023595354889938185570478522993388289048302557891167738873369819120824744719887957386737497").unwrap(),
            c_3: BigNumber::from_dec("155896332368123762801956153344504549060335301015742894722031334021229143246720614755197061265767850227376787531687360132616585125014719826058461529282435109252698337084024676160230328299934525591515183015313961657211459844974849050487555886724159894297825235113404376594691586350564507841314085073530734052797").unwrap(),
            c_4: BigNumber::from_dec("2439031523083526907541492954511171565410125169973527439050424290906898494737209448528169122171303905371979705754605821910384249425992360049374967224702493098288191876210948281676853058526073868115546874318254554784442981141057786492167387408889341180534855001389661650686286691627606215954509745859389435892604099136284119776713615424953304490015008789656225423855534914421557640901683766186749680702604084644878525001991670703896810916880059825567713025584523436").unwrap(),
        }
    }
}
