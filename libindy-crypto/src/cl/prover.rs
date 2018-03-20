use bn::BigNumber;
use cl::*;
use cl::constants::*;
use errors::IndyCryptoError;
use pair::*;
use super::helpers::*;
use utils::commitment::{get_pedersen_commitment, get_exponentiated_generators};
use utils::get_hash_as_int;
//use authz::{SelectiveDisclosureCLProof, AuthzProofGenerators};

use std::collections::{BTreeMap, HashSet};
use std::iter::FromIterator;

/// Credentials owner that can proof and partially disclose the credentials to verifier.
pub struct Prover {}

impl Prover {
    /// Creates a master secret.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let _master_secret = Prover::new_master_secret().unwrap();
    /// ```
    pub fn new_master_secret() -> Result<MasterSecret, IndyCryptoError> {
        Ok(MasterSecret {
            ms: bn_rand(LARGE_MASTER_SECRET)?
        })
    }

    /// Creates blinded master secret for given issuer key and master secret.
    ///
    /// # Arguments
    /// * `credential_pub_key` - Credential public keys.
    /// * `credential_key_correctness_proof` - Credential key correctness proof.
    /// * `master_secret` - Master secret.
    /// * `master_secret_blinding_nonce` - Nonce used for creation of blinded_master_secret_correctness_proof.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::new_nonce;
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    /// 
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (credential_pub_key, _credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    /// let (_blinded_master_secret, _master_secret_blinding_data, _blinded_master_secret_correctness_proof) =
    ///     Prover::blind_credential_secrets(&credential_pub_key,
    ///                                 &cred_key_correctness_proof,
    ///                                 &master_secret,
    ///                                 &master_secret_blinding_nonce).unwrap();
    /// ```
    pub fn blind_credential_secrets(credential_pub_key: &CredentialPublicKey,
                                    credential_key_correctness_proof: Option<&CredentialKeyCorrectnessProof>,
                                    credential_values: &CredentialValues,
                                    credential_nonce: Option<&Nonce>) -> Result<(BlindedCredentialSecrets,
                                                                         CredentialSecretsBlindingFactors,
                                                                                 Option<BlindedCredentialSecretsCorrectnessProof>), IndyCryptoError> {
        trace!("Prover::blind_credential_secrets: >>> credential_pub_key: {:?}, \
                                                      credential_key_correctness_proof: {:?}, \
                                                      credential_values: {:?}, \
                                                      credential_nonce: {:?}",
                                                      credential_pub_key,
                                                      credential_key_correctness_proof,
                                                      credential_values,
                                                      credential_nonce);

        if credential_key_correctness_proof.is_some() {
            Prover::_check_credential_key_correctness_proof(&credential_pub_key.p_key, credential_key_correctness_proof.unwrap())?;
        }

        let primary_blinded_credential_secrets =
            Prover::_generate_primary_blinded_credential_secrets(&credential_pub_key.p_key, &credential_values)?;

        let blinded_revocation_master_secret = match credential_pub_key.r_key {
            Some(ref r_pk) => Some(Prover::_generate_revocation_blinded_credential_secrets(r_pk)?),
            _ => None
        };

        let blinded_credential_secrets_correctness_proof = match credential_nonce {
            Some(nonce) => Some(Prover::_new_blinded_credential_secrets_correctness_proof(&credential_pub_key.p_key,
                                                                                          &primary_blinded_credential_secrets,
                                                                                          &nonce,
                                                                                          &credential_values)?),
            None => None
        };

        let blinded_credential_secrets = BlindedCredentialSecrets {
            u: primary_blinded_credential_secrets.u,
            ur: blinded_revocation_master_secret.as_ref().map(|d| d.ur),
            hidden_attributes: primary_blinded_credential_secrets.hidden_attributes,
            committed_attributes: primary_blinded_credential_secrets.committed_attributes
        };

        let credential_secrets_blinding_factors = CredentialSecretsBlindingFactors {
            v_prime: primary_blinded_credential_secrets.v_prime,
            vr_prime: blinded_revocation_master_secret.map(|d| d.vr_prime)
        };

        trace!("Prover::blind_credential_secrets: <<< blinded_credential_secrets: {:?}, \
                                                      credential_secrets_blinding_factors: {:?}, \
                                                      blinded_credential_secrets_correctness_proof: {:?},",
                                                      blinded_credential_secrets,
                                                      credential_secrets_blinding_factors,
                                                      blinded_credential_secrets_correctness_proof);

        Ok((blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof))
    }

    /// Updates the credential signature by a master secret blinding data.
    ///
    /// # Arguments
    /// * `credential_signature` - Credential signature generated by Issuer.
    /// * `credential_values` - Credential values.
    /// * `signature_correctness_proof` - Credential signature correctness proof.
    /// * `master_secret_blinding_data` - Master secret blinding data.
    /// * `master_secret` - Master secret.
    /// * `credential_pub_key` - Credential public key.
    /// * `nonce` -  Nonce was used by Issuer for the creation of signature_correctness_proof.
    /// * `rev_key_pub` - (Optional) Revocation registry public key.
    /// * `rev_reg` - (Optional) Revocation registry.
    /// * `witness` - (Optional) Witness.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::new_nonce;
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (credential_pub_key, credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    /// let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
    ///     Prover::blind_master_secret(&credential_pub_key, &cred_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (mut credential_signature, signature_correctness_proof) =
    ///     Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                             &blinded_master_secret,
    ///                             &blinded_master_secret_correctness_proof,
    ///                             &master_secret_blinding_nonce,
    ///                             &credential_issuance_nonce,
    ///                             &credential_values,
    ///                             &credential_pub_key,
    ///                             &credential_priv_key).unwrap();
    ///
    /// Prover::process_credential_signature(&mut credential_signature,
    ///                                      &credential_values,
    ///                                      &signature_correctness_proof,
    ///                                      &master_secret_blinding_data,
    ///                                      &master_secret,
    ///                                      &credential_pub_key,
    ///                                      &credential_issuance_nonce,
    ///                                      None, None, None).unwrap();
    /// ```
    pub fn process_credential_signature(credential_signature: &mut CredentialSignature,
                                        credential_values: &CredentialValues,
                                        signature_correctness_proof: Option<&SignatureCorrectnessProof>,
                                        credential_secrets_blinding_factors: &CredentialSecretsBlindingFactors,
                                        credential_pub_key: &CredentialPublicKey,
                                        nonce: Option<&Nonce>,
                                        rev_key_pub: Option<&RevocationKeyPublic>,
                                        rev_reg: Option<&RevocationRegistry>,
                                        witness: Option<&Witness>) -> Result<(), IndyCryptoError> {
        trace!("Prover::process_credential_signature: >>> credential_signature: {:?}, \
                                                          credential_values: {:?}, \
                                                          signature_correctness_proof: {:?}, \
                                                          credential_secrets_blinding_factors: {:?}, \
                                                          credential_pub_key: {:?}, \
                                                          nonce: {:?}, \
                                                          rev_key_pub: {:?}, \
                                                          rev_reg: {:?}, \
                                                          witness: {:?}",
                                                        credential_signature,
                                                        credential_values,
                                                        signature_correctness_proof,
                                                        credential_secrets_blinding_factors,
                                                        credential_pub_key,
                                                        nonce,
                                                        rev_key_pub,
                                                        rev_reg,
                                                        witness);

        Prover::_process_primary_credential(&mut credential_signature.p_credential, &credential_secrets_blinding_factors.v_prime)?;

        match (signature_correctness_proof, nonce) {
            (Some(prf), Some(cred_nonce)) => Prover::_check_signature_correctness_proof(&credential_signature.p_credential,
                                                                                        credential_values,
                                                                                        prf,
                                                                                        &credential_pub_key.p_key,
                                                                                        cred_nonce)?,
            _ => ()
        }

        if let (&mut Some(ref mut non_revocation_cred), Some(ref vr_prime), &Some(ref r_key),
            Some(ref r_key_pub), Some(ref r_reg), Some(ref witness)) = (&mut credential_signature.r_credential,
                                                                        credential_secrets_blinding_factors.vr_prime,
                                                                        &credential_pub_key.r_key,
                                                                        rev_key_pub,
                                                                        rev_reg,
                                                                        witness) {
            Prover::_process_non_revocation_credential(non_revocation_cred,
                                                       vr_prime,
                                                       &r_key,
                                                       r_key_pub,
                                                       r_reg,
                                                       witness)?;
        }

        trace!("Prover::process_credential_signature: <<<");

        Ok(())
    }

    /// Creates and returns proof builder.
    ///
    /// The purpose of proof builder is building of proof entity according to the given request .
    /// # Example
    /// ```
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let _proof_builder = Prover::new_proof_builder();
    pub fn new_proof_builder() -> Result<ProofBuilder, IndyCryptoError> {
        Ok(ProofBuilder {
            init_proofs: BTreeMap::new(),
            c_list: Vec::new(),
            tau_list: Vec::new()
        })
    }

    fn _check_credential_key_correctness_proof(pr_pub_key: &CredentialPrimaryPublicKey,
                                               key_correctness_proof: &CredentialKeyCorrectnessProof) -> Result<(), IndyCryptoError> {
        trace!("Prover::_check_credential_key_correctness_proof: >>> pr_pub_key: {:?}, key_correctness_proof: {:?}",
               pr_pub_key, key_correctness_proof);

        let mut ctx = BigNumber::new_context()?;

        let z_inverse = pr_pub_key.z.inverse(&pr_pub_key.n, Some(&mut ctx))?;
        let z_cap = get_pedersen_commitment(&z_inverse, &key_correctness_proof.c,
                                            &pr_pub_key.s, &key_correctness_proof.xz_cap, &pr_pub_key.n, &mut ctx)?;

        let mut r_cap: BTreeMap<String, BigNumber> = BTreeMap::new();
        for (key, r_value) in pr_pub_key.r.iter() {
            let xr_cap_value = key_correctness_proof.xr_cap
                .get(key)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in key_correctness_proof.xr_cap", key)))?;

            let r_inverse = r_value.inverse(&pr_pub_key.n, Some(&mut ctx))?;
            let val = get_pedersen_commitment(&r_inverse, &key_correctness_proof.c,
                                              &pr_pub_key.s, &xr_cap_value, &pr_pub_key.n, &mut ctx)?;

            r_cap.insert(key.to_owned(), val);
        }

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&pr_pub_key.z.to_bytes()?);
        for val in pr_pub_key.r.values() {
            values.extend_from_slice(&val.to_bytes()?);
        }
        values.extend_from_slice(&z_cap.to_bytes()?);
        for val in r_cap.values() {
            values.extend_from_slice(&val.to_bytes()?);
        }

        let c = get_hash_as_int(&mut vec![values])?;

        let valid = key_correctness_proof.c.eq(&c);

        if !valid {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid Credential key correctness proof")));
        }

        trace!("Prover::_check_credential_key_correctness_proof: <<<");

        Ok(())
    }

    // TODO: Fixme; This should be private, making it public temporarily
    pub fn _generate_primary_blinded_credential_secrets(p_pub_key: &CredentialPrimaryPublicKey,
                                                    credential_values: &CredentialValues) -> Result<PrimaryBlindedCredentialSecretsFactors, IndyCryptoError> {
        trace!("Prover::_generate_blinded_primary_master_secret: >>> p_pub_key: {:?}, credential_values: {:?}", p_pub_key, credential_values);

        let mut ctx = BigNumber::new_context()?;
        let v_prime = bn_rand(LARGE_VPRIME)?;

        //Hidden attributes are combined in this value
        let hidden_attributes = credential_values.attrs_values
                                                 .iter()
                                                 .filter(|&(_, v)| v.is_hidden())
                                                 .map(|(attr, _)| attr.clone()).collect::<BTreeSet<String>>();
        let u = hidden_attributes.iter()
                                 .fold(p_pub_key.s.mod_exp(&v_prime, &p_pub_key.n, Some(&mut ctx)),
                                       |acc, attr| {
                                           let pk_r = p_pub_key.r
                                                            .get(&attr.clone())
                                                            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", attr)))?;
                                           let cred_value = &credential_values.attrs_values[attr];
                                           acc?.mod_mul(&pk_r.mod_exp(cred_value.value(), &p_pub_key.n, Some(&mut ctx))?,
                                                        &p_pub_key.n, Some(&mut ctx))
                                       })?;


        let mut committed_attributes = BTreeMap::new();

        for (attr, cv) in credential_values.attrs_values.iter().filter(|&(_, v)| v.is_commitment()) {
            if let &CredentialValue::Commitment{ref value, ref blinding_factor} = cv {
                committed_attributes.insert(attr.clone(), get_pedersen_commitment(&p_pub_key.s, blinding_factor,
                                                                                  &p_pub_key.z, value,
                                                                                  &p_pub_key.n, &mut ctx)?);
            }
        }

        let primary_blinded_cred_secrets = PrimaryBlindedCredentialSecretsFactors { u, v_prime, hidden_attributes, committed_attributes };

        trace!("Prover::_generate_blinded_primary_master_secret: <<< primary_blinded_cred_secrets: {:?}", primary_blinded_cred_secrets);

        Ok(primary_blinded_cred_secrets)
    }

    fn _generate_revocation_blinded_credential_secrets(r_pub_key: &CredentialRevocationPublicKey) -> Result<RevocationBlindedCredentialSecretsFactors, IndyCryptoError> {
        trace!("Prover::_generate_revocation_blinded_credential_secrets: >>> r_pub_key: {:?}", r_pub_key);

        let vr_prime = GroupOrderElement::new()?;
        let ur = r_pub_key.h2.mul(&vr_prime)?;

        let revocation_blinded_cred_secrets = RevocationBlindedCredentialSecretsFactors { ur, vr_prime };

        trace!("Prover::_generate_revocation_blinded_credential_secrets: <<< revocation_blinded_cred_secrets: {:?}", revocation_blinded_cred_secrets);

        Ok(revocation_blinded_cred_secrets)
    }

    fn _new_blinded_credential_secrets_correctness_proof(p_pub_key: &CredentialPrimaryPublicKey,
                                                         primary_blinded_cred_secrets: &PrimaryBlindedCredentialSecretsFactors,
                                                         nonce: &BigNumber,
                                                         cred_values: &CredentialValues) -> Result<BlindedCredentialSecretsCorrectnessProof, IndyCryptoError> {
        trace!("Prover::_new_blinded_credential_secrets_correctness_proof: >>> p_pub_key: {:?}, primary_blinded_cred_secrets: {:?}, nonce: {:?}, cred_values: {:?}",
               primary_blinded_cred_secrets, nonce, p_pub_key, cred_values);

        let mut ctx = BigNumber::new_context()?;

        let v_dash_tilde = bn_rand(LARGE_VPRIME_TILDE)?;

        let mut m_tildes = BTreeMap::new();
        let mut r_tildes = BTreeMap::new();

        let mut values: Vec<u8> = Vec::new();
        let mut u_tilde = p_pub_key.s.mod_exp(&v_dash_tilde, &p_pub_key.n, Some(&mut ctx))?;

        for (attr, cred_value) in cred_values.attrs_values.iter().filter(|&(_, v)| v.is_hidden() || v.is_commitment()) {
            let m_tilde = bn_rand(LARGE_MTILDE)?;
            let pk_r = p_pub_key.r
                .get(attr)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", attr)))?;

            match *cred_value {
                CredentialValue::Hidden { .. } => {
                    u_tilde = u_tilde.mod_mul(&pk_r.mod_exp(&m_tilde, &p_pub_key.n, Some(&mut ctx))?,
                                              &p_pub_key.n, Some(&mut ctx))?;
                    ()
                },
                CredentialValue::Commitment { .. } => {
                    let r_tilde = bn_rand(LARGE_MTILDE)?;
                    let commitment_tilde = get_pedersen_commitment(&p_pub_key.z,
                                                                   &m_tilde,
                                                                   &p_pub_key.s,
                                                                   &r_tilde,
                                                                   &p_pub_key.n,
                                                                   &mut ctx)?;
                    r_tildes.insert(attr.clone(), r_tilde);

                    values.extend_from_slice(&commitment_tilde.to_bytes()?);
                    let ca_value = primary_blinded_cred_secrets.committed_attributes
                                                               .get(attr)
                                                               .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in primary_blinded_cred_secrets.committed_attributes", attr)))?;
                    values.extend_from_slice(&ca_value.to_bytes()?);
                    ()
                }
                _ => ()
            }
            m_tildes.insert(attr.clone(), m_tilde);
        }

        values.extend_from_slice(&primary_blinded_cred_secrets.u.to_bytes()?);
        values.extend_from_slice(&u_tilde.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&vec![values])?;

        let v_dash_cap = c.mul(&primary_blinded_cred_secrets.v_prime, Some(&mut ctx))?
                          .add(&v_dash_tilde)?;

        let mut m_caps = BTreeMap::new();
        let mut r_caps = BTreeMap::new();

        for (attr, m_tilde) in &m_tildes {
            let ca = cred_values.attrs_values
                      .get(attr)
                      .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in cred_values.committed_attributes", attr)))?;

            match ca {
                &CredentialValue::Hidden{ref value} => {
                    let m_cap = m_tilde.add(&c.mul(value, Some(&mut ctx))?)?;
                    m_caps.insert(attr.clone(), m_cap);
                    ()
                },
                &CredentialValue::Commitment{ref value, ref blinding_factor} => {
                    let m_cap = m_tilde.add(&c.mul(value, Some(&mut ctx))?)?;
                    let r_cap = r_tildes[attr].add(&c.mul(blinding_factor, Some(&mut ctx))?)?;

                    m_caps.insert(attr.clone(), m_cap);
                    r_caps.insert(attr.clone(), r_cap);
                    ()
                },
                _ => ()
            }
        }

        let blinded_credential_secrets_correctness_proof = BlindedCredentialSecretsCorrectnessProof { c, v_dash_cap, m_caps, r_caps };

        trace!("Prover::_new_blinded_credential_secrets_correctness_proof: <<< blinded_primary_master_secret_correctness_proof: {:?}",
               blinded_credential_secrets_correctness_proof);

        Ok(blinded_credential_secrets_correctness_proof)
    }

    fn _process_primary_credential(p_cred: &mut PrimaryCredentialSignature,
                                   v_prime: &BigNumber) -> Result<(), IndyCryptoError> {
        trace!("Prover::_process_primary_credential: >>> p_cred: {:?}, v_prime: {:?}", p_cred, v_prime);

        p_cred.v = v_prime.add(&p_cred.v)?;

        trace!("Prover::_process_primary_credential: <<<");

        Ok(())
    }

    fn _process_non_revocation_credential(r_cred: &mut NonRevocationCredentialSignature,
                                          vr_prime: &GroupOrderElement,
                                          cred_rev_pub_key: &CredentialRevocationPublicKey,
                                          rev_key_pub: &RevocationKeyPublic,
                                          rev_reg: &RevocationRegistry,
                                          witness: &Witness) -> Result<(), IndyCryptoError> {
        trace!("Prover::_process_non_revocation_credential: >>> r_cred: {:?}, vr_prime: {:?}, cred_rev_pub_key: {:?}, rev_reg: {:?}, rev_key_pub: {:?}",
               r_cred, vr_prime, cred_rev_pub_key, rev_reg, rev_key_pub);

        let r_cnxt_m2 = BigNumber::from_bytes(&r_cred.m2.to_bytes()?)?;
        r_cred.vr_prime_prime = vr_prime.add_mod(&r_cred.vr_prime_prime)?;
        Prover::_test_witness_signature(&r_cred, cred_rev_pub_key, rev_key_pub, rev_reg, witness, &r_cnxt_m2)?;

        trace!("Prover::_process_non_revocation_credential: <<<");

        Ok(())
    }

    fn _check_signature_correctness_proof(p_cred_sig: &PrimaryCredentialSignature,
                                          cred_values: &CredentialValues,
                                          signature_correctness_proof: &SignatureCorrectnessProof,
                                          p_pub_key: &CredentialPrimaryPublicKey,
                                          nonce: &Nonce) -> Result<(), IndyCryptoError> {
        trace!("Prover::_check_signature_correctness_proof: >>> p_cred_sig: {:?}, \
                                                                cred_values: {:?}, \
                                                                signature_correctness_proof: {:?}, \
                                                                p_pub_key: {:?}, \
                                                                nonce: {:?}",
                                                                p_cred_sig,
                                                                cred_values,
                                                                signature_correctness_proof,
                                                                p_pub_key,
                                                                nonce);

        let mut ctx = BigNumber::new_context()?;

        if !p_cred_sig.e.is_prime(Some(&mut ctx))? {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid Signature correctness proof")));
        }

        let rx = cred_values.attrs_values
            .iter()
            .filter(|&(ref attr, ref value)| (value.is_known() || value.is_hidden()) && p_pub_key.r.contains_key(attr.clone()))
            .fold(get_pedersen_commitment(&p_pub_key.s, &p_cred_sig.v, &p_pub_key.rctxt, &p_cred_sig.m_2, &p_pub_key.n, &mut ctx),
                  |acc, (attr, value)| {
                      acc?.mod_mul(&p_pub_key.r[&attr.clone()].mod_exp(value.value(), &p_pub_key.n, Some(&mut ctx))?, &p_pub_key.n, Some(&mut ctx))
                  })?;

//        let mut generators_and_exponents = cred_values.attrs_values
//                                                      .iter()
//                                                      .filter(|&(ref key, ref value)| (value.is_known() || value.is_hidden()) && p_pub_key.r.contains_key(key.clone()))
//                                                      .map(|(key, value)| (p_pub_key.r.get(&key.clone()).unwrap(), value.value())).collect::<Vec<(&BigNumber, &BigNumber)>>();
//        generators_and_exponents.push((&p_pub_key.s, &p_cred_sig.v));
//        generators_and_exponents.push((&p_pub_key.rctxt, &p_cred_sig.m_2));
//
//        for (key, attr) in cred_values.attrs_values.iter() {
//            let pk_r = p_pub_key.r
//                .get(key)
//                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", key)))?;
//            let value = attr.value()?;
//
//            match attr {
//                &CredentialValue::Known{..} => {
//                    generators_and_exponents.push((&pk_r, value));
//                    ()
//                },
//                &CredentialValue::Hidden{..} => {
//                    generators_and_exponents.push((&pk_r, value));
//                    ()
//                },
//                _ => ()
//            };
//        }
//
//        let rx = get_exponentiated_generators(generators_and_exponents, &p_pub_key.n, &mut ctx)?;

        let q = p_pub_key.z.mod_div(&rx, &p_pub_key.n, Some(&mut ctx))?;

        let expected_q = p_cred_sig.a.mod_exp(&p_cred_sig.e, &p_pub_key.n, Some(&mut ctx))?;

        if !q.eq(&expected_q) {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid Signature correctness proof")));
        }

        let degree = signature_correctness_proof.c.add(
            &signature_correctness_proof.se.mul(&p_cred_sig.e, Some(&mut ctx))?
        )?;

        let a_cap = p_cred_sig.a.mod_exp(&degree, &p_pub_key.n, Some(&mut ctx))?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&q.to_bytes()?);
        values.extend_from_slice(&p_cred_sig.a.to_bytes()?);
        values.extend_from_slice(&a_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&vec![values])?;

        let valid = signature_correctness_proof.c.eq(&c);

        if !valid {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid Signature correctness proof")));
        }

        trace!("Prover::_check_signature_correctness_proof: <<<");

        Ok(())
    }

    fn _test_witness_signature(r_cred: &NonRevocationCredentialSignature,
                               cred_rev_pub_key: &CredentialRevocationPublicKey,
                               rev_key_pub: &RevocationKeyPublic,
                               rev_reg: &RevocationRegistry,
                               witness: &Witness,
                               r_cnxt_m2: &BigNumber) -> Result<(), IndyCryptoError> {
        trace!("Prover::_test_witness_signature: >>> r_cred: {:?}, cred_rev_pub_key: {:?}, rev_key_pub: {:?}, rev_reg: {:?}, r_cnxt_m2: {:?}",
               r_cred, cred_rev_pub_key, rev_key_pub, rev_reg, r_cnxt_m2);

        let z_calc = Pair::pair(&r_cred.witness_signature.g_i, &rev_reg.accum)?
            .mul(&Pair::pair(&cred_rev_pub_key.g, &witness.omega)?.inverse()?)?;

        if z_calc != rev_key_pub.z {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }
        let pair_gg_calc = Pair::pair(&cred_rev_pub_key.pk.add(&r_cred.g_i)?, &r_cred.witness_signature.sigma_i)?;
        let pair_gg = Pair::pair(&cred_rev_pub_key.g, &cred_rev_pub_key.g_dash)?;

        if pair_gg_calc != pair_gg {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        let m2 = GroupOrderElement::from_bytes(&r_cnxt_m2.to_bytes()?)?;

        let pair_h1 = Pair::pair(&r_cred.sigma, &cred_rev_pub_key.y.add(&cred_rev_pub_key.h_cap.mul(&r_cred.c)?)?)?;
        let pair_h2 = Pair::pair(
            &cred_rev_pub_key.h0
                .add(&cred_rev_pub_key.h1.mul(&m2)?)?
                .add(&cred_rev_pub_key.h2.mul(&r_cred.vr_prime_prime)?)?
                .add(&r_cred.g_i)?,
            &cred_rev_pub_key.h_cap
        )?;

        if pair_h1 != pair_h2 {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        trace!("Prover::_test_witness_signature: <<<");

        Ok(())
    }
}

#[derive(Debug)]
pub struct ProofBuilder {
    pub init_proofs: BTreeMap<String, InitProof>,
    pub c_list: Vec<Vec<u8>>,
    pub tau_list: Vec<Vec<u8>>,
}

impl ProofBuilder {
    /// Adds sub proof request to proof builder which will be used fo building of proof.
    /// Part of proof request related to a particular schema-key.
    ///
    /// # Arguments
    /// * `proof_builder` - Proof builder.
    /// * `key_id` - Unique credential identifier.
    /// * `sub_proof_request` -Requested attributes and predicates.
    /// * `credential_schema` - Credential schema.
    /// * `credential_signature` - Credential signature.
    /// * `credential_values` - Credential values.
    /// * `credential_pub_key` - Credential public key.
    /// * `rev_reg_pub` - (Optional) Revocation registry public.
    ///
    /// #Example
    /// ```
    /// use indy_crypto::cl::new_nonce;
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    /// use indy_crypto::cl::verifier::Verifier;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (credential_pub_key, credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    /// let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
    ///     Prover::blind_master_secret(&credential_pub_key, &cred_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (mut credential_signature, signature_correctness_proof) =
    ///     Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                             &blinded_master_secret,
    ///                             &blinded_master_secret_correctness_proof,
    ///                             &master_secret_blinding_nonce,
    ///                             &credential_issuance_nonce,
    ///                             &credential_values,
    ///                             &credential_pub_key,
    ///                             &credential_priv_key).unwrap();
    ///
    /// Prover::process_credential_signature(&mut credential_signature,
    ///                                      &credential_values,
    ///                                      &signature_correctness_proof,
    ///                                      &master_secret_blinding_data,
    ///                                      &master_secret,
    ///                                      &credential_pub_key,
    ///                                      &credential_issuance_nonce,
    ///                                      None, None, None).unwrap();
    ///
    /// let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
    /// sub_proof_request_builder.add_revealed_attr("sex").unwrap();
    /// let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
    ///
    /// let mut proof_builder = Prover::new_proof_builder().unwrap();
    /// proof_builder.add_sub_proof_request("issuer_key_id_1",
    ///                                     &sub_proof_request,
    ///                                     &credential_schema,
    ///                                     &credential_signature,
    ///                                     &credential_values,
    ///                                     &credential_pub_key,
    ///                                     None,
    ///                                     None).unwrap();
    /// ```
    pub fn add_sub_proof_request(&mut self,
                                 key_id: &str,
                                 sub_proof_request: &SubProofRequest,
                                 credential_schema: &CredentialSchema,
                                 non_credential_schema_elements: &NonCredentialSchemaElements,
                                 credential_signature: &CredentialSignature,
                                 credential_values: &CredentialValues,
                                 credential_pub_key: &CredentialPublicKey,
                                 rev_reg: Option<&RevocationRegistry>,
                                 witness: Option<&Witness>) -> Result<(), IndyCryptoError> {
        trace!("ProofBuilder::add_sub_proof_request: >>> key_id: {:?}, credential_signature: {:?}, credential_values: {:?}, credential_pub_key: {:?}, \
        rev_reg: {:?}, sub_proof_request: {:?}, credential_schema: {:?}",
               key_id, credential_signature, credential_values, credential_pub_key, rev_reg, sub_proof_request, credential_schema);

        ProofBuilder::_check_add_sub_proof_request_params_consistency(credential_values, sub_proof_request, credential_schema, non_credential_schema_elements)?;

        let mut non_revoc_init_proof = None;
        let mut m2_tilde: Option<BigNumber> = None;

        if let (&Some(ref r_cred), &Some(ref r_reg), &Some(ref r_pub_key), &Some(ref witness)) = (&credential_signature.r_credential,
                                                                                                  &rev_reg,
                                                                                                  &credential_pub_key.r_key,
                                                                                                  &witness) {
            let (m, p) = self.add_sub_proof_request_revocation(&r_cred,
                                                                 &r_reg,
                                                                 &r_pub_key,
                                                                 &witness)?;
            m2_tilde = Some(m);
            non_revoc_init_proof = Some(p);  
        }

        let primary_init_proof = self.add_sub_proof_request_primary(&credential_pub_key.p_key,
                                                                   &credential_signature.p_credential,
                                                                   credential_values,
                                                                   credential_schema,
                                                                   non_credential_schema_elements,
                                                                   sub_proof_request,
                                                                   m2_tilde)?;
        let init_proof = InitProof {
            primary_init_proof,
            non_revoc_init_proof,
            credential_values: credential_values.clone()?,
            sub_proof_request: sub_proof_request.clone(),
            credential_schema: credential_schema.clone(),
            non_credential_schema_elements: non_credential_schema_elements.clone()
        };
        self.init_proofs.insert(key_id.to_owned(), init_proof);

        trace!("ProofBuilder::add_sub_proof_request: <<<");

        Ok(())
    }

    /// Finalize proof.
    ///
    /// # Arguments
    /// * `proof_builder` - Proof builder.
    /// * `nonce` - Nonce.
    /// * `master_secret` - Master secret.
    ///
    /// #Example
    /// ```
    /// use indy_crypto::cl::new_nonce;
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    /// use indy_crypto::cl::verifier::Verifier;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (credential_pub_key, credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    /// let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
    ///     Prover::blind_master_secret(&credential_pub_key, &cred_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (mut credential_signature, signature_correctness_proof) =
    ///     Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                             &blinded_master_secret,
    ///                             &blinded_master_secret_correctness_proof,
    ///                             &master_secret_blinding_nonce,
    ///                             &credential_issuance_nonce,
    ///                             &credential_values,
    ///                             &credential_pub_key,
    ///                             &credential_priv_key).unwrap();
    ///
    /// Prover::process_credential_signature(&mut credential_signature,
    ///                                      &credential_values,
    ///                                      &signature_correctness_proof,
    ///                                      &master_secret_blinding_data,
    ///                                      &master_secret,
    ///                                      &credential_pub_key,
    ///                                      &credential_issuance_nonce,
    ///                                      None, None, None).unwrap();
    ///
    /// let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
    /// sub_proof_request_builder.add_revealed_attr("sex").unwrap();
    /// let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
    ///
    /// let mut proof_builder = Prover::new_proof_builder().unwrap();
    /// proof_builder.add_sub_proof_request("issuer_key_id_1",
    ///                                     &sub_proof_request,
    ///                                     &credential_schema,
    ///                                     &credential_signature,
    ///                                     &credential_values,
    ///                                     &credential_pub_key,
    ///                                     None,
    ///                                     None).unwrap();
    ///
    /// let proof_request_nonce = new_nonce().unwrap();
    /// let _proof = proof_builder.finalize(&proof_request_nonce, &master_secret).unwrap();
    /// ```
    pub fn finalize(&self, nonce: &Nonce) -> Result<Proof, IndyCryptoError> {
        trace!("ProofBuilder::finalize: >>> nonce: {:?}", nonce);

        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&self.tau_list);
        values.extend_from_slice(&self.c_list);
        values.push(nonce.to_bytes()?);

        // In the anoncreds whitepaper, `challenge` is denoted by `c_h`
        let challenge = get_hash_as_int(&mut values)?;

        let mut proofs: BTreeMap<String, SubProof> = BTreeMap::new();

        for (proof_cred_uuid, init_proof) in self.init_proofs.iter() {
            let mut non_revoc_proof: Option<NonRevocProof> = None;
            if let Some(ref non_revoc_init_proof) = init_proof.non_revoc_init_proof {
                non_revoc_proof = Some(ProofBuilder::_finalize_non_revocation_proof(&non_revoc_init_proof, &challenge)?);
            }

            let primary_proof = ProofBuilder::_finalize_primary_proof(&init_proof.primary_init_proof,
                                                                      &challenge,
                                                                      &init_proof.credential_schema,
                                                                      &init_proof.non_credential_schema_elements,
                                                                      &init_proof.credential_values,
                                                                      &init_proof.sub_proof_request)?;

            let proof = SubProof { primary_proof, non_revoc_proof };
            proofs.insert(proof_cred_uuid.to_owned(), proof);
        }

        let aggregated_proof = AggregatedProof { c_hash: challenge, c_list: self.c_list.clone() };

        let proof = Proof { proofs, aggregated_proof };

        trace!("ProofBuilder::finalize: <<< proof: {:?}", proof);

        Ok(proof)
    }

    // TODO: Fixme; This method should be private
    pub fn add_sub_proof_request_primary(&mut self, primary_public_key: &CredentialPrimaryPublicKey, 
        primary_credential: &PrimaryCredentialSignature, credential_values: &CredentialValues, 
        credential_schema: &CredentialSchema, non_credential_schema_elements: &NonCredentialSchemaElements,
        sub_proof_request: &SubProofRequest, m2_tilde: Option<BigNumber>) -> Result<PrimaryInitProof, IndyCryptoError> {
        let primary_init_proof = ProofBuilder::_init_primary_proof(&primary_public_key,
                                                                   &primary_credential,
                                                                   credential_values,
                                                                   credential_schema,
                                                                   non_credential_schema_elements,
                                                                   sub_proof_request,
                                                                   m2_tilde)?;
        self.c_list.extend_from_slice(&primary_init_proof.as_c_list()?);
        self.tau_list.extend_from_slice(&primary_init_proof.as_tau_list()?);
        Ok(primary_init_proof)
    }

    // TODO: Fixme; This method should be private
    pub fn add_sub_proof_request_revocation(&mut self, revocation_credential: &NonRevocationCredentialSignature, 
                                rev_reg: &RevocationRegistry,
                                cred_rev_pub_key: &CredentialRevocationPublicKey,
                                witness: &Witness) -> Result<(BigNumber, NonRevocInitProof), IndyCryptoError> {
        let proof = ProofBuilder::_init_non_revocation_proof(&revocation_credential,
                                                                 &rev_reg,
                                                                 &cred_rev_pub_key,
                                                                 &witness)?;

        self.c_list.extend_from_slice(&proof.as_c_list()?);
        self.tau_list.extend_from_slice(&proof.as_tau_list()?);
        let m2_tilde = group_element_to_bignum(&proof.tau_list_params.m2)?;
        let non_revoc_init_proof = proof;
        Ok((m2_tilde, non_revoc_init_proof))
    }

    fn _check_add_sub_proof_request_params_consistency(cred_values: &CredentialValues,
                                                       sub_proof_request: &SubProofRequest,
                                                       cred_schema: &CredentialSchema,
                                                       non_credential_schema_elements: &NonCredentialSchemaElements) -> Result<(), IndyCryptoError> {
        trace!("ProofBuilder::_check_add_sub_proof_request_params_consistency: >>> cred_values: {:?}, sub_proof_request: {:?}, cred_schema: {:?}",
               cred_values, sub_proof_request, cred_schema);

        let schema_attrs = non_credential_schema_elements.attrs.union(
                           &cred_schema.attrs).cloned().collect::<BTreeSet<String>>();

        let cred_attrs = BTreeSet::from_iter(cred_values.attrs_values.keys().cloned());

        if schema_attrs != cred_attrs {
            return Err(IndyCryptoError::InvalidStructure(format!("Credential doesn't correspond to credential schema")));
        }

        if sub_proof_request.revealed_attrs.difference(&cred_attrs).count() != 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("Credential doesn't contain requested attribute")));
        }

        let predicates_attrs =
            sub_proof_request.predicates.iter()
                .map(|predicate| predicate.attr_name.clone())
                .collect::<BTreeSet<String>>();

        if predicates_attrs.difference(&cred_attrs).count() != 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("Credential doesn't contain attribute requested in predicate")));
        }

        trace!("ProofBuilder::_check_add_sub_proof_request_params_consistency: <<<");

        Ok(())
    }

    fn _init_primary_proof(issuer_pub_key: &CredentialPrimaryPublicKey,
                           c1: &PrimaryCredentialSignature,
                           cred_values: &CredentialValues,
                           cred_schema: &CredentialSchema,
                           non_cred_schema_elems: &NonCredentialSchemaElements,
                           sub_proof_request: &SubProofRequest,
                           m2_t: Option<BigNumber>) -> Result<PrimaryInitProof, IndyCryptoError> {
        trace!("ProofBuilder::_init_primary_proof: >>> issuer_pub_key: {:?}, c1: {:?}, cred_values: {:?}, cred_schema: {:?}, sub_proof_request: {:?}, m2_t: {:?}",
               issuer_pub_key, c1, cred_values, cred_schema, sub_proof_request, m2_t);

        let eq_proof = ProofBuilder::_init_eq_proof(&issuer_pub_key, c1, cred_schema, non_cred_schema_elems, sub_proof_request, m2_t)?;

        let mut ge_proofs: Vec<PrimaryPredicateGEInitProof> = Vec::new();
        for predicate in sub_proof_request.predicates.iter() {
            let ge_proof = ProofBuilder::_init_ge_proof(&issuer_pub_key, &eq_proof.m_tilde, cred_values, predicate)?;
            ge_proofs.push(ge_proof);
        }

        let primary_init_proof = PrimaryInitProof { eq_proof, ge_proofs };

        trace!("ProofBuilder::_init_primary_proof: <<< primary_init_proof: {:?}", primary_init_proof);

        Ok(primary_init_proof)
    }

    fn _init_non_revocation_proof(r_cred: &NonRevocationCredentialSignature,
                                  rev_reg: &RevocationRegistry,
                                  cred_rev_pub_key: &CredentialRevocationPublicKey,
                                  witness: &Witness) -> Result<NonRevocInitProof, IndyCryptoError> {
        trace!("ProofBuilder::_init_non_revocation_proof: >>> r_cred: {:?}, rev_reg: {:?}, cred_rev_pub_key: {:?}, witness: {:?}",
               r_cred, rev_reg, cred_rev_pub_key, witness);

        let c_list_params = ProofBuilder::_gen_c_list_params(&r_cred)?;
        let c_list = ProofBuilder::_create_c_list_values(&r_cred, &c_list_params, &cred_rev_pub_key, witness)?;

        let tau_list_params = ProofBuilder::_gen_tau_list_params()?;
        let tau_list = create_tau_list_values(&cred_rev_pub_key,
                                              &rev_reg,
                                              &tau_list_params,
                                              &c_list)?;

        let r_init_proof = NonRevocInitProof {
            c_list_params,
            tau_list_params,
            c_list,
            tau_list
        };

        trace!("ProofBuilder::_init_non_revocation_proof: <<< r_init_proof: {:?}", r_init_proof);

        Ok(r_init_proof)
    }

    fn _init_eq_proof(credr_pub_key: &CredentialPrimaryPublicKey,
                      c1: &PrimaryCredentialSignature,
                      cred_schema: &CredentialSchema,
                      non_cred_schema_elems: &NonCredentialSchemaElements,
                      sub_proof_request: &SubProofRequest,
                      m2_t: Option<BigNumber>) -> Result<PrimaryEqualInitProof, IndyCryptoError> {
        trace!("ProofBuilder::_init_eq_proof: >>> credr_pub_key: {:?}, c1: {:?}, cred_schema: {:?}, sub_proof_request: {:?}, m2_t: {:?}",
               credr_pub_key, c1, cred_schema, sub_proof_request, m2_t);

        let mut ctx = BigNumber::new_context()?;

        let m2_tilde = m2_t.unwrap_or(bn_rand(LARGE_MVECT)?);

        let r = bn_rand(LARGE_VPRIME)?;
        let e_tilde = bn_rand(LARGE_ETILDE)?;
        let v_tilde = bn_rand(LARGE_VTILDE)?;

        let unrevealed_attrs = non_cred_schema_elems.attrs.union(&cred_schema.attrs)
                                                    .cloned()
                                                    .collect::<BTreeSet<String>>()
                                                    .difference(&sub_proof_request.revealed_attrs)
                                                    .cloned()
                                                    .collect::<BTreeSet<String>>();

        let m_tilde = get_mtilde(&unrevealed_attrs)?;

        let a_prime = credr_pub_key.s
            .mod_exp(&r, &credr_pub_key.n, Some(&mut ctx))?
            .mod_mul(&c1.a, &credr_pub_key.n, Some(&mut ctx))?;

        let v_prime = c1.v.sub(
            &c1.e.mul(&r, Some(&mut ctx))?
        )?;

        let e_prime = c1.e.sub(
            &BigNumber::from_u32(2)?.exp(&BigNumber::from_dec(&LARGE_E_START.to_string())?, Some(&mut ctx))?
        )?;

        let t = calc_teq(&credr_pub_key, &a_prime, &e_tilde, &v_tilde, &m_tilde, &m2_tilde, &unrevealed_attrs)?;


//        let (authz_a_tilde, authz_b_tilde, authz_t3) = SelectiveDisclosureCLProof::commit()?;

        //TODO: Add authz selective disclosure step here

        let primary_equal_init_proof = PrimaryEqualInitProof {
            a_prime,
            t,
            e_tilde,
            e_prime,
            v_tilde,
            v_prime,
            m_tilde,
            m2_tilde: m2_tilde.clone()?,
            m2: c1.m_2.clone()?
        };

        trace!("ProofBuilder::_init_eq_proof: <<< primary_equal_init_proof: {:?}", primary_equal_init_proof);

        Ok(primary_equal_init_proof)
    }

    fn _init_ge_proof(p_pub_key: &CredentialPrimaryPublicKey,
                      m_tilde: &BTreeMap<String, BigNumber>,
                      cred_values: &CredentialValues,
                      predicate: &Predicate) -> Result<PrimaryPredicateGEInitProof, IndyCryptoError> {
        trace!("ProofBuilder::_init_ge_proof: >>> p_pub_key: {:?}, m_tilde: {:?}, cred_values: {:?}, predicate: {:?}",
               p_pub_key, m_tilde, cred_values, predicate);

        let mut ctx = BigNumber::new_context()?;
        let (k, value) = (&predicate.attr_name, predicate.value);

        let attr_value = cred_values.attrs_values.get(k.as_str())
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in cred_values", k)))?
            .value()
            .to_dec()?
            .parse::<i32>()
            .map_err(|_| IndyCryptoError::InvalidStructure(format!("Value by key '{}' has invalid format", k)))?;

        let delta: i32 = attr_value - value;

        if delta < 0 {
            return Err(IndyCryptoError::InvalidStructure("Predicate is not satisfied".to_string()));
        }

        let u = four_squares(delta)?;

        let mut r: BTreeMap<String, BigNumber> = BTreeMap::new();
        let mut t: BTreeMap<String, BigNumber> = BTreeMap::new();
        let mut c_list: Vec<BigNumber> = Vec::new();

        for i in 0..ITERATION {
            let cur_u = u.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in u1", i)))?;

            let cur_r = bn_rand(LARGE_VPRIME)?;
            let cut_t = get_pedersen_commitment(&p_pub_key.z, &cur_u, &p_pub_key.s,
                                                &cur_r, &p_pub_key.n, &mut ctx)?;

            r.insert(i.to_string(), cur_r);
            t.insert(i.to_string(), cut_t.clone()?);
            c_list.push(cut_t)
        }

        let r_delta = bn_rand(LARGE_VPRIME)?;

        let t_delta = get_pedersen_commitment(&p_pub_key.z, &BigNumber::from_dec(&delta.to_string())?,
                                              &p_pub_key.s, &r_delta, &p_pub_key.n, &mut ctx)?;

        r.insert("DELTA".to_string(), r_delta);
        t.insert("DELTA".to_string(), t_delta.clone()?);
        c_list.push(t_delta);

        let mut u_tilde: BTreeMap<String, BigNumber> = BTreeMap::new();
        let mut r_tilde: BTreeMap<String, BigNumber> = BTreeMap::new();

        for i in 0..ITERATION {
            u_tilde.insert(i.to_string(), bn_rand(LARGE_UTILDE)?);
            r_tilde.insert(i.to_string(), bn_rand(LARGE_RTILDE)?);
        }

        r_tilde.insert("DELTA".to_string(), bn_rand(LARGE_RTILDE)?);
        let alpha_tilde = bn_rand(LARGE_ALPHATILDE)?;

        let mj = m_tilde.get(k.as_str())
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in eq_proof.mtilde", k)))?;

        let tau_list = calc_tge(&p_pub_key, &u_tilde, &r_tilde, &mj, &alpha_tilde, &t)?;

        let primary_predicate_ge_init_proof = PrimaryPredicateGEInitProof {
            c_list,
            tau_list,
            u,
            u_tilde,
            r,
            r_tilde,
            alpha_tilde,
            predicate: predicate.clone(),
            t
        };

        trace!("ProofBuilder::_init_ge_proof: <<< primary_predicate_ge_init_proof: {:?}", primary_predicate_ge_init_proof);

        Ok(primary_predicate_ge_init_proof)
    }

    fn _finalize_eq_proof(init_proof: &PrimaryEqualInitProof,
                          challenge: &BigNumber,
                          cred_schema: &CredentialSchema,
                          non_cred_schema_elems: &NonCredentialSchemaElements,
                          cred_values: &CredentialValues,
                          sub_proof_request: &SubProofRequest) -> Result<PrimaryEqualProof, IndyCryptoError> {
        trace!("ProofBuilder::_finalize_eq_proof: >>> init_proof: {:?}, challenge: {:?}, cred_schema: {:?}, \
        cred_values: {:?}, sub_proof_request: {:?}", init_proof, challenge, cred_schema, cred_values, sub_proof_request);

        let mut ctx = BigNumber::new_context()?;

        let e = challenge
            .mul(&init_proof.e_prime, Some(&mut ctx))?
            .add(&init_proof.e_tilde)?;

        let v = challenge
            .mul(&init_proof.v_prime, Some(&mut ctx))?
            .add(&init_proof.v_tilde)?;

        let mut m: BTreeMap<String, BigNumber> = BTreeMap::new();

        let unrevealed_attrs = non_cred_schema_elems.attrs.union(&cred_schema.attrs)
                                                          .cloned()
                                                          .collect::<BTreeSet<String>>()
                                                          .difference(&sub_proof_request.revealed_attrs)
                                                          .cloned()
                                                          .collect::<BTreeSet<String>>();

        for k in unrevealed_attrs.iter() {
            let cur_mtilde = init_proof.m_tilde.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.mtilde", k)))?;

            let cur_val = cred_values.attrs_values.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in attributes_values", k)))?;

            let val = challenge
                .mul(&cur_val.value(), Some(&mut ctx))?
                .add(&cur_mtilde)?;

            m.insert(k.clone(), val);
        }

        let m2 = challenge
            .mul(&init_proof.m2, Some(&mut ctx))?
            .add(&init_proof.m2_tilde)?;

        let mut revealed_attrs_with_values: BTreeMap<String, BigNumber> = BTreeMap::new();

        for attr in sub_proof_request.revealed_attrs.iter() {
            revealed_attrs_with_values.insert(
                attr.clone(),
                cred_values.attrs_values
                    .get(attr)
                    .ok_or(IndyCryptoError::InvalidStructure(format!("Encoded value not found")))?
                    .value()
                    .clone()?,
            );
        }

        let primary_equal_proof = PrimaryEqualProof {
            revealed_attrs: revealed_attrs_with_values,
            a_prime: init_proof.a_prime.clone()?,
            e,
            v,
            m,
            m2
        };

        trace!("ProofBuilder::_finalize_eq_proof: <<< primary_equal_proof: {:?}", primary_equal_proof);

        Ok(primary_equal_proof)
    }

    fn _finalize_ge_proof(c_h: &BigNumber,
                          init_proof: &PrimaryPredicateGEInitProof,
                          eq_proof: &PrimaryEqualProof) -> Result<PrimaryPredicateGEProof, IndyCryptoError> {
        trace!("ProofBuilder::_finalize_ge_proof: >>> c_h: {:?}, init_proof: {:?}, eq_proof: {:?}", c_h, init_proof, eq_proof);

        let mut ctx = BigNumber::new_context()?;
        let mut u: BTreeMap<String, BigNumber> = BTreeMap::new();
        let mut r: BTreeMap<String, BigNumber> = BTreeMap::new();
        let mut urproduct = BigNumber::new()?;

        for i in 0..ITERATION {
            let cur_utilde = &init_proof.u_tilde[&i.to_string()];
            let cur_u = &init_proof.u[&i.to_string()];
            let cur_rtilde = &init_proof.r_tilde[&i.to_string()];
            let cur_r = &init_proof.r[&i.to_string()];

            let new_u: BigNumber = c_h
                .mul(&cur_u, Some(&mut ctx))?
                .add(&cur_utilde)?;
            let new_r: BigNumber = c_h
                .mul(&cur_r, Some(&mut ctx))?
                .add(&cur_rtilde)?;

            u.insert(i.to_string(), new_u);
            r.insert(i.to_string(), new_r);

            urproduct = cur_u
                .mul(&cur_r, Some(&mut ctx))?
                .add(&urproduct)?;

            let cur_rtilde_delta = &init_proof.r_tilde["DELTA"];

            let new_delta = c_h
                .mul(&init_proof.r["DELTA"], Some(&mut ctx))?
                .add(&cur_rtilde_delta)?;

            r.insert("DELTA".to_string(), new_delta);
        }

        let alpha = init_proof.r["DELTA"]
            .sub(&urproduct)?
            .mul(&c_h, Some(&mut ctx))?
            .add(&init_proof.alpha_tilde)?;

        let primary_predicate_ge_proof = PrimaryPredicateGEProof {
            u,
            r,
            mj: eq_proof.m[&init_proof.predicate.attr_name].clone()?,
            alpha,
            t: clone_bignum_map(&init_proof.t)?,
            predicate: init_proof.predicate.clone()
        };

        trace!("ProofBuilder::_finalize_ge_proof: <<< primary_predicate_ge_proof: {:?}", primary_predicate_ge_proof);

        Ok(primary_predicate_ge_proof)
    }

    fn _finalize_primary_proof(init_proof: &PrimaryInitProof,
                               challenge: &BigNumber,
                               cred_schema: &CredentialSchema,
                               non_cred_schema_elems: &NonCredentialSchemaElements,
                               cred_values: &CredentialValues,
                               sub_proof_request: &SubProofRequest) -> Result<PrimaryProof, IndyCryptoError> {
        trace!("ProofBuilder::_finalize_primary_proof: >>> init_proof: {:?}, challenge: {:?}, cred_schema: {:?}, \
        cred_values: {:?}, sub_proof_request: {:?}", init_proof, challenge, cred_schema, cred_values, sub_proof_request);

        let eq_proof = ProofBuilder::_finalize_eq_proof(&init_proof.eq_proof, challenge, cred_schema, non_cred_schema_elems, cred_values, sub_proof_request)?;
        let mut ge_proofs: Vec<PrimaryPredicateGEProof> = Vec::new();

        for init_ge_proof in init_proof.ge_proofs.iter() {
            let ge_proof = ProofBuilder::_finalize_ge_proof(challenge, init_ge_proof, &eq_proof)?;
            ge_proofs.push(ge_proof);
        }

        let primary_proof = PrimaryProof { eq_proof, ge_proofs };

        trace!("ProofBuilder::_finalize_primary_proof: <<< primary_proof: {:?}", primary_proof);

        Ok(primary_proof)
    }

    fn _gen_c_list_params(r_cred: &NonRevocationCredentialSignature) -> Result<NonRevocProofXList, IndyCryptoError> {
        trace!("ProofBuilder::_gen_c_list_params: >>> r_cred: {:?}", r_cred);

        let rho = GroupOrderElement::new()?;
        let r = GroupOrderElement::new()?;
        let r_prime = GroupOrderElement::new()?;
        let r_prime_prime = GroupOrderElement::new()?;
        let r_prime_prime_prime = GroupOrderElement::new()?;
        let o = GroupOrderElement::new()?;
        let o_prime = GroupOrderElement::new()?;
        let m = rho.mul_mod(&r_cred.c)?;
        let m_prime = r.mul_mod(&r_prime_prime)?;
        let t = o.mul_mod(&r_cred.c)?;
        let t_prime = o_prime.mul_mod(&r_prime_prime)?;
        let m2 = GroupOrderElement::from_bytes(&r_cred.m2.to_bytes()?)?;

        let non_revoc_proof_x_list = NonRevocProofXList {
            rho,
            r,
            r_prime,
            r_prime_prime,
            r_prime_prime_prime,
            o,
            o_prime,
            m,
            m_prime,
            t,
            t_prime,
            m2,
            s: r_cred.vr_prime_prime,
            c: r_cred.c
        };

        trace!("ProofBuilder::_gen_c_list_params: <<< non_revoc_proof_x_list: {:?}", non_revoc_proof_x_list);

        Ok(non_revoc_proof_x_list)
    }

    fn _create_c_list_values(r_cred: &NonRevocationCredentialSignature,
                             params: &NonRevocProofXList,
                             r_pub_key: &CredentialRevocationPublicKey,
                             witness: &Witness) -> Result<NonRevocProofCList, IndyCryptoError> {
        trace!("ProofBuilder::_create_c_list_values: >>> r_cred: {:?}, r_pub_key: {:?}", r_cred, r_pub_key);

        let e = r_pub_key.h
            .mul(&params.rho)?
            .add(
                &r_pub_key.htilde.mul(&params.o)?
            )?;

        let d = r_pub_key.g
            .mul(&params.r)?
            .add(
                &r_pub_key.htilde.mul(&params.o_prime)?
            )?;

        let a = r_cred.sigma
            .add(
                &r_pub_key.htilde.mul(&params.rho)?
            )?;

        let g = r_cred.g_i
            .add(
                &r_pub_key.htilde.mul(&params.r)?
            )?;

        let w = witness.omega
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime)?
            )?;

        let s = r_cred.witness_signature.sigma_i
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime_prime)?
            )?;

        let u = r_cred.witness_signature.u_i
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime_prime_prime)?
            )?;

        let non_revoc_proof_c_list = NonRevocProofCList {
            e,
            d,
            a,
            g,
            w,
            s,
            u
        };

        trace!("ProofBuilder::_create_c_list_values: <<< non_revoc_proof_c_list: {:?}", non_revoc_proof_c_list);

        Ok(non_revoc_proof_c_list)
    }

    fn _gen_tau_list_params() -> Result<NonRevocProofXList, IndyCryptoError> {
        trace!("ProofBuilder::_gen_tau_list_params: >>>");

        let non_revoc_proof_x_list = NonRevocProofXList {
            rho: GroupOrderElement::new()?,
            r: GroupOrderElement::new()?,
            r_prime: GroupOrderElement::new()?,
            r_prime_prime: GroupOrderElement::new()?,
            r_prime_prime_prime: GroupOrderElement::new()?,
            o: GroupOrderElement::new()?,
            o_prime: GroupOrderElement::new()?,
            m: GroupOrderElement::new()?,
            m_prime: GroupOrderElement::new()?,
            t: GroupOrderElement::new()?,
            t_prime: GroupOrderElement::new()?,
            m2: GroupOrderElement::new()?,
            s: GroupOrderElement::new()?,
            c: GroupOrderElement::new()?
        };

        trace!("ProofBuilder::_gen_tau_list_params: <<< Nnon_revoc_proof_x_list: {:?}", non_revoc_proof_x_list);

        Ok(non_revoc_proof_x_list)
    }

    fn _finalize_non_revocation_proof(init_proof: &NonRevocInitProof, c_h: &BigNumber) -> Result<NonRevocProof, IndyCryptoError> {
        trace!("ProofBuilder::_finalize_non_revocation_proof: >>> init_proof: {:?}, c_h: {:?}", init_proof, c_h);

        let ch_num_z = bignum_to_group_element(&c_h)?;
        let mut x_list: Vec<GroupOrderElement> = Vec::new();

        for (x, y) in init_proof.tau_list_params.as_list()?.iter().zip(init_proof.c_list_params.as_list()?.iter()) {
            x_list.push(x.add_mod(
                &ch_num_z.mul_mod(&y)?.mod_neg()?
            )?);
        }

        let non_revoc_proof = NonRevocProof {
            x_list: NonRevocProofXList::from_list(x_list),
            c_list: init_proof.c_list.clone()
        };

        trace!("ProofBuilder::_finalize_non_revocation_proof: <<< non_revoc_proof: {:?}", non_revoc_proof);

        Ok(non_revoc_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::issuer;
    use pair::PairMocksHelper;

    #[ignore]
    #[test]
    fn generate_master_secret_works() {
        MockHelper::inject();

        let ms = Prover::new_master_secret().unwrap();
        assert_eq!(ms.ms.to_dec().unwrap(), mocks::master_secret().ms.to_dec().unwrap());
    }

    #[test]
    fn generate_primary_blinded_credential_secrets_works() {
        MockHelper::inject();

        let primary_blinded_credential_secrets =
            Prover::_generate_primary_blinded_credential_secrets(&issuer::mocks::credential_primary_public_key(),
                                                                 &mocks::credential_values()).unwrap();
        assert_eq!(primary_blinded_credential_secrets, mocks::primary_blinded_credential_secrets_factors());
    }

    #[test]
    fn generate_revocation_blinded_credential_secrets_works() {
        MockHelper::inject();

        let r_pk = issuer::mocks::credential_revocation_public_key();
        Prover::_generate_revocation_blinded_credential_secrets(&r_pk).unwrap();
    }

    #[test]
    fn generate_blinded_credential_secrets_works() {
        MockHelper::inject();
        PairMocksHelper::inject();

        let (blinded_credential_secrets,
             credential_secrets_blinding_factors,
             blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(&issuer::mocks::credential_public_key(),
                                                 Some(&issuer::mocks::credential_key_correctness_proof()),
                                                 &mocks::credential_values(),
                                                 Some(&mocks::credential_nonce())).unwrap();

        assert_eq!(blinded_credential_secrets.u, mocks::primary_blinded_credential_secrets_factors().u);
        assert_eq!(credential_secrets_blinding_factors.v_prime, mocks::primary_blinded_credential_secrets_factors().v_prime);
        assert_eq!(blinded_credential_secrets.committed_attributes, mocks::primary_blinded_credential_secrets_factors().committed_attributes);
        assert!(blinded_credential_secrets.ur.is_some());
        assert!(credential_secrets_blinding_factors.vr_prime.is_some());
        assert_eq!(blinded_credential_secrets_correctness_proof, Some(mocks::blinded_credential_secrets_correctness_proof()))
    }

    #[test]
    fn process_primary_credential_works() {
        MockHelper::inject();

        let mut credential = issuer::mocks::primary_credential();
        let v_prime = mocks::primary_blinded_credential_secrets_factors().v_prime;

        Prover::_process_primary_credential(&mut credential, &v_prime).unwrap();

        assert_eq!(mocks::primary_credential(), credential);
    }

    #[ignore]
    #[test]
    fn process_credential_signature_works() {
        MockHelper::inject();

        let mut credential_signature = issuer::mocks::credential();

        Prover::process_credential_signature(&mut credential_signature,
                                             &mocks::credential_values(),
                                             Some(issuer::mocks::signature_correctness_proof()).as_ref(),
                                             &mocks::credential_secrets_blinding_factors(),
                                             &issuer::mocks::credential_public_key(),
                                             Some(issuer::mocks::credential_issuance_nonce()).as_ref(),
                                             None,
                                             None,
                                             None).unwrap();

        assert_eq!(mocks::primary_credential(), credential_signature.p_credential);
    }

//    #[test]
//    fn init_eq_proof_works() {
//        MockHelper::inject();
//
//        let pk = issuer::mocks::credential_primary_public_key();
//        let credential_schema = issuer::mocks::credential_schema();
//        let credential = mocks::primary_credential();
//        let sub_proof_request = mocks::sub_proof_request();
//        let m1_t = mocks::m1_t();
//
//        let init_eq_proof = ProofBuilder::_init_eq_proof(&pk,
//                                                         &credential,
//                                                         &credential_schema,
//                                                         &sub_proof_request,
//                                                         &m1_t,
//                                                         None).unwrap();
//
//        assert_eq!(mocks::primary_equal_init_proof(), init_eq_proof);
//    }
//
//    #[test]
//    fn init_ge_proof_works() {
//        MockHelper::inject();
//
//        let pk = issuer::mocks::credential_primary_public_key();
//        let init_eq_proof = mocks::primary_equal_init_proof();
//        let predicate = mocks::predicate();
//        let credential_schema = issuer::mocks::credential_values();
//
//        let init_ge_proof = ProofBuilder::_init_ge_proof(&pk,
//                                                         &init_eq_proof.m_tilde,
//                                                         &credential_schema,
//                                                         &predicate).unwrap();
//
//        assert_eq!(mocks::primary_ge_init_proof(), init_ge_proof);
//    }
//
//    #[test]
//    fn init_primary_proof_works() {
//        MockHelper::inject();
//
//        let pk = issuer::mocks::credential_primary_public_key();
//        let credential_schema = issuer::mocks::credential_schema();
//        let credential = mocks::credential();
//        let m1_t = mocks::m1_t();
//        let credential_values = issuer::mocks::credential_values();
//        let sub_proof_request = mocks::sub_proof_request();
//
//        let init_proof = ProofBuilder::_init_primary_proof(&pk,
//                                                           &credential.p_credential,
//                                                           &credential_values,
//                                                           &credential_schema,
//                                                           &sub_proof_request,
//                                                           &m1_t,
//                                                           None).unwrap();
//        assert_eq!(mocks::primary_init_proof(), init_proof);
//    }
//
//    #[test]
//    fn finalize_eq_proof_works() {
//        MockHelper::inject();
//
//        let ms = mocks::master_secret();
//        let c_h = mocks::aggregated_proof().c_hash;
//        let init_proof = mocks::primary_equal_init_proof();
//        let credential_values = issuer::mocks::credential_values();
//        let credential_schema = issuer::mocks::credential_schema();
//        let sub_proof_request = mocks::sub_proof_request();
//
//        let eq_proof = ProofBuilder::_finalize_eq_proof(&ms.ms,
//                                                        &init_proof,
//                                                        &c_h,
//                                                        &credential_schema,
//                                                        &credential_values,
//                                                        &sub_proof_request).unwrap();
//
//        assert_eq!(mocks::eq_proof(), eq_proof);
//    }
//
//    #[test]
//    fn finalize_ge_proof_works() {
//        MockHelper::inject();
//
//        let c_h = mocks::aggregated_proof().c_hash;
//        let ge_proof = mocks::primary_ge_init_proof();
//        let eq_proof = mocks::eq_proof();
//
//        let ge_proof = ProofBuilder::_finalize_ge_proof(&c_h,
//                                                        &ge_proof,
//                                                        &eq_proof).unwrap();
//        assert_eq!(mocks::ge_proof(), ge_proof);
//    }
//
//    #[test]
//    fn finalize_primary_proof_works() {
//        MockHelper::inject();
//
//        let proof = mocks::primary_init_proof();
//        let ms = mocks::master_secret();
//        let c_h = mocks::aggregated_proof().c_hash;
//        let credential_schema = issuer::mocks::credential_schema();
//        let credential_values = issuer::mocks::credential_values();
//        let sub_proof_request = mocks::sub_proof_request();
//
//        let proof = ProofBuilder::_finalize_primary_proof(&ms.ms,
//                                                          &proof,
//                                                          &c_h,
//                                                          &credential_schema,
//                                                          &credential_values,
//                                                          &sub_proof_request).unwrap();
//
//        assert_eq!(mocks::primary_proof(), proof);
//    }
//
//    #[test]
//    fn test_witness_credential_works() {
//        let mut r_credential = issuer::mocks::revocation_credential();
//        let r_key = issuer::mocks::credential_revocation_public_key();
//        let rev_key_pub = issuer::mocks::revocation_key_public();
//        let rev_reg = issuer::mocks::revocation_registry();
//        let witness = issuer::mocks::witness();
//        let r_cnxt_m2 = issuer::mocks::r_cnxt_m2();
//
//        Prover::_test_witness_signature(&mut r_credential, &r_key, &rev_key_pub, &rev_reg, &witness, &r_cnxt_m2).unwrap();
//    }
//
//    #[test]
//    fn test_c_and_tau_list() {
//        let r_credential = issuer::mocks::revocation_credential();
//        let r_key = issuer::mocks::credential_revocation_public_key();
//        let rev_pub_key = issuer::mocks::revocation_key_public();
//        let rev_reg = issuer::mocks::revocation_registry();
//        let witness = issuer::mocks::witness();
//
//        let c_list_params = ProofBuilder::_gen_c_list_params(&r_credential).unwrap();
//
//        let proof_c_list = ProofBuilder::_create_c_list_values(&r_credential, &c_list_params, &r_key, &witness).unwrap();
//
//        let proof_tau_list = create_tau_list_values(&r_key, &rev_reg,
//                                                    &c_list_params, &proof_c_list).unwrap();
//
//        let proof_tau_list_calc = create_tau_list_expected_values(&r_key,
//                                                                  &rev_reg,
//                                                                  &rev_pub_key,
//                                                                  &proof_c_list).unwrap();
//
//        assert_eq!(proof_tau_list.as_slice().unwrap(), proof_tau_list_calc.as_slice().unwrap());
//    }
//
//    extern crate time;
//
//    /*
//    Results:
//
//    N = 100
//    Create RevocationRegistry Time: Duration { secs: 0, nanos: 153759082 }
//    Update NonRevocation Credential Time: Duration { secs: 0, nanos: 490382 }
//    Total Time for 100 credentials: Duration { secs: 5, nanos: 45915383 }
//
//    N = 1000
//    Create RevocationRegistry Time: Duration { secs: 1, nanos: 636113212 }
//    Update NonRevocation Credential Time: Duration { secs: 0, nanos: 5386575 }
//    Total Time for 1000 credentials: Duration { secs: 6, nanos: 685771457 }
//
//    N = 10000
//    Create RevocationRegistry Time: Duration { secs: 16, nanos: 844061103 }
//    Update NonRevocation Credential Time: Duration { secs: 0, nanos: 52396763 }
//    Total Time for 10000 credentials: Duration { secs: 29, nanos: 628240611 }
//
//    N = 100000
//    Create RevocationRegistry Time: Duration { secs: 175, nanos: 666428558 }
//    Update NonRevocation Credential Time: Duration { secs: 0, nanos: 667879620 }
//    Total Time for 100000 credentials: Duration { secs: 185, nanos: 810126906 }
//
//    N = 1000000
//    Create RevocationRegistry Time: Duration { secs: 1776, nanos: 485208599 }
//    Update NonRevocation Credential Time: Duration { secs: 6, nanos: 35027554 }
//    Total Time for 1000000 credentials: Duration { secs: 1798, nanos: 420564334 }
//    */
//    #[test]
//    fn test_update_proof() {
//        println!("Update Proof test -> start");
//        let n = 100;
//
//        let total_start_time = time::get_time();
//
//        let cred_schema = issuer::mocks::credential_schema();
//        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = issuer::Issuer::new_credential_def(&cred_schema, true).unwrap();
//
//        let start_time = time::get_time();
//
//        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = issuer::Issuer::new_revocation_registry_def(&cred_pub_key, n, false).unwrap();
//
//        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
//
//        let end_time = time::get_time();
//
//        println!("Create RevocationRegistry Time: {:?}", end_time - start_time);
//
//        let cred_values = issuer::mocks::credential_values();
//
//        // Issue first correct Claim
//        let master_secret = Prover::new_master_secret().unwrap();
//        let master_secret_blinding_nonce = new_nonce().unwrap();
//
//        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
//            Prover::blind_credential_secrets(&cred_pub_key,
//                                             &cred_key_correctness_proof,
//                                             &master_secret,
//                                             &master_secret_blinding_nonce).unwrap();
//
//        let cred_issuance_nonce = new_nonce().unwrap();
//
//        let rev_idx = 1;
//        let (mut cred_signature, signature_correctness_proof, rev_reg_delta) =
//            issuer::Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
//                                                       &blinded_master_secret,
//                                                       &blinded_master_secret_correctness_proof,
//                                                       &master_secret_blinding_nonce,
//                                                       &cred_issuance_nonce,
//                                                       &cred_values,
//                                                       &cred_pub_key,
//                                                       &cred_priv_key,
//                                                       rev_idx,
//                                                       n,
//                                                       false,
//                                                       &mut rev_reg,
//                                                       &rev_key_priv,
//                                                       &simple_tail_accessor).unwrap();
//        let mut rev_reg_delta = rev_reg_delta.unwrap();
//
//        let mut witness = Witness::new(rev_idx, n, &rev_reg_delta, &simple_tail_accessor).unwrap();
//
//        Prover::process_credential_signature(&mut cred_signature,
//                                             &cred_values,
//                                             &signature_correctness_proof,
//                                             &master_secret_blinding_data,
//                                             &master_secret,
//                                             &cred_pub_key,
//                                             &cred_issuance_nonce,
//                                             Some(&rev_key_pub),
//                                             Some(&rev_reg),
//                                             Some(&witness)).unwrap();
//
//        // Populate accumulator
//        for i in 2..n {
//            let index = n + 1 - i;
//
//            simple_tail_accessor.access_tail(index, &mut |tail| {
//                rev_reg_delta.accum = rev_reg_delta.accum.sub(tail).unwrap();
//            }).unwrap();
//
//            rev_reg_delta.issued.insert(i);
//        }
//
//        // Update NonRevoc Credential
//
//        let start_time = time::get_time();
//
//        witness.update(rev_idx, n, &rev_reg_delta, &simple_tail_accessor).unwrap();
//
//        let end_time = time::get_time();
//
//        println!("Update NonRevocation Credential Time: {:?}", end_time - start_time);
//
//        let total_end_time = time::get_time();
//        println!("Total Time for {} credentials: {:?}", n, total_end_time - total_start_time);
//
//        println!("Update Proof test -> end");
//    }
}

#[cfg(test)]
pub mod mocks {
    use std::iter::FromIterator;
    use super::*;

    pub const PROVER_DID: &'static str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

    pub fn master_secret() -> MasterSecret {
        MasterSecret {
            ms: link_secret()
        }
    }

    pub fn link_secret() -> BigNumber {
        BigNumber::from_dec("34940487469005237202297983870352092482682591325620866393958633274031736589516").unwrap()
    }

    pub fn link_secret_blinding_factor() -> BigNumber {
        BigNumber::from_dec("12403977281408319830341147313026597120312785716035135330072781873547187561426").unwrap()
    }

    pub fn policy_address() -> BigNumber {
        BigNumber::from_dec("82482513509927463198200988655461469819592280137503867166383914706498311851913").unwrap()
    }

    pub fn policy_address_blinding_factor() -> BigNumber {
        BigNumber::from_dec("101896356200142281702846875799022863451783539174051329030463640228462536469916").unwrap()
    }

    pub fn credential_nonce() -> Nonce {
        BigNumber::from_dec("526193306511429638192053").unwrap()
    }

    pub fn non_credential_schema_elements() -> NonCredentialSchemaElements {
        NonCredentialSchemaElements {
            attrs: btreeset![String::from("link_secret"), String::from("policy_address")]
        }
    }

    pub fn credential_schema() -> CredentialSchema {
        CredentialSchema {
            attrs: btreeset![
                String::from("name"),
                String::from("gender"),
                String::from("age"),
                String::from("height")
            ]
        }
    }

    pub fn credential_values() -> CredentialValues {
        CredentialValues {
            attrs_values: btreemap![
                String::from("link_secret") => CredentialValue::Hidden { value: link_secret() },
                String::from("policy_address") => CredentialValue::Hidden { value: policy_address() },
                String::from("name") => CredentialValue::Known { value: BigNumber::from_dec("71359565546479723151967460283929432570283558415909434050407244812473401631735").unwrap() },
                String::from("gender") => CredentialValue::Known { value: BigNumber::from_dec("1796449712852417654363673724889734415544693752249017564928908250031932273569").unwrap() },
                String::from("age") => CredentialValue::Known { value: BigNumber::from_dec("35").unwrap() },
                String::from("height") => CredentialValue::Known { value: BigNumber::from_dec("175").unwrap() }
            ]
        }
    }

    pub fn blinded_credential_secrets() -> BlindedCredentialSecrets {
        BlindedCredentialSecrets {
            u: primary_blinded_credential_secrets_factors().u,
            ur: Some(revocation_blinded_credential_secrets_factors().ur),
            hidden_attributes: primary_blinded_credential_secrets_factors().hidden_attributes,
            committed_attributes: primary_blinded_credential_secrets_factors().committed_attributes
        }
    }

    pub fn credential_secrets_blinding_factors() -> CredentialSecretsBlindingFactors {
        CredentialSecretsBlindingFactors {
            v_prime: primary_blinded_credential_secrets_factors().v_prime,
            vr_prime: Some(revocation_blinded_credential_secrets_factors().vr_prime)
        }
    }

    pub fn primary_blinded_credential_secrets_factors() -> PrimaryBlindedCredentialSecretsFactors {
        PrimaryBlindedCredentialSecretsFactors {
            u: BigNumber::from_dec("47723789467324780675596875081347747479320627810048281093901400047762979563059906556791220135858818030513899970550825333284342841510800678843474627885555246105908411614394363087122961850889010634506499101410088942045336606938075323428990497144271795963654705507552770440603826268000601604722427749968097516106288723402025571295850992636738524478503550849567356041275809736561947892778594556789352642394950858071131551896302034046337284082758795918249422986376466412526903587523169139938125179844417875931185766113421874861290614367429698444482776956343469971398441588630248177425682784201204788643072267753274494264901").unwrap(),
            v_prime: BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436").unwrap(),
            hidden_attributes: btreeset!["link_secret".to_string(), "policy_address".to_string()],
            committed_attributes: BTreeMap::new()
        }
    }

    pub fn revocation_blinded_credential_secrets_factors() -> RevocationBlindedCredentialSecretsFactors {
        RevocationBlindedCredentialSecretsFactors {
            ur: PointG1::from_string("false CFFE6ECFE88B20 D07CD714AF7D2D 2A5B4CBEA3C20 9F01A39E9CAC4 D65FB18 853E49F76DED9D 8FD8E08920FA65 D60F7F43C2ED2 A5800960965DF0 EB86FB4 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            vr_prime: GroupOrderElement::from_string("B7D7DC1499EA50 6F16C9B5FE2C00 466542B923D8C9 FB01F2122DE924 22EB5716").unwrap()
        }
    }

    pub fn blinded_credential_secrets_correctness_proof() -> BlindedCredentialSecretsCorrectnessProof {
        BlindedCredentialSecretsCorrectnessProof {
            c: BigNumber::from_dec("41363708552899491482967123354025727783041394957801862794507299492642851871869").unwrap(),
            v_dash_cap: BigNumber::from_dec("79477230445124340412355135331512631332722746549591064544407872397590479611126581579324962195667429483997509492680814561137770781126131148727698769664077589502001894178840666346000194557447457274020154921952336844315124915547239553865426321263250055048331091059913482273602917153430056605520865331593204471731828029863938592478567282943017148677878205165013268924621430967883622879738809927355429095301964044999346168842861746968508978875649044406157345408356119559714870915481102452138933140386757170565744838081204616344798909609569734854156255770552701665904364822629486188028037395295585051594090933096744390540765487864225403679410800306257324133891363581133307141377493126320794077474704040109460337273678709629").unwrap(),
            m_caps: btreemap![
                "link_secret".to_string() => BigNumber::from_dec("10838856720335086997514321362930394283556101400008112071495587755466979684093030882847444561579356480922326595489746025886532480780967365202826164327243513358033057767953215523419").unwrap(),
                "policy_address".to_string() => BigNumber::from_dec("10838856720335086997514323329444903454621130300428677453490176453637285955242357752437452659131210150427095344992567154204158417597801625460210583594876055970065477299634513333412").unwrap()
            ],
            r_caps: BTreeMap::new()
        }
    }

    pub fn credential() -> CredentialSignature {
        CredentialSignature {
            p_credential: primary_credential(),
            r_credential: Some(issuer::mocks::revocation_credential())
        }
    }

//    pub fn m1_t() -> BigNumber {
//        BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509").unwrap()
//    }
//
    pub fn primary_credential() -> PrimaryCredentialSignature {
        PrimaryCredentialSignature {
            m_2: BigNumber::from_dec("69277050336954731912953999596899794023422356864020449587821228635678593076726").unwrap(),
            a: BigNumber::from_dec("59576650729757014001266415495048651014371875592452607038291814388111315911848291102110497520252073850059895120162321101149178450199060886721905586280704576277966012808672880874635221160361161880289965721881196877768108586929304787520934823952926459697296988463659936307341225404107666757142995151042428995859916215979973310048071060845782364280443800907503315348117229725994495933944492229338552866398085646193855519664376641572721062419860464686594200135802645323748450574040748736978128316478992822369888152234869857797942929992424339164545866301175765533370751998934550269667261831972378348502681712036651084791677").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881").unwrap(),
            v: BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644127544973467090784833169581477025096651956458587024481106269073426545688878633368395090950721246745797130514914475184220252785922714892764536041334549342283500382915967329086709002330282037812607548379718641877595592743676836398647524633348205332354808351273389207425490367080293557186321576642355686995967422099839906367044852871358174711678743078106239862383119503287568833606375474359241383490799700740580296717320354647238288294827855343155547056851646090370313395520915221874011198982966904484363631910557996205942678772502957389321620232931357572315089162587705606682143499451357592399858038685832965830759409094928957246320485487746463").unwrap()
        }
    }

//    pub fn primary_init_proof() -> PrimaryInitProof {
//        PrimaryInitProof {
//            eq_proof: primary_equal_init_proof(),
//            ge_proofs: vec![primary_ge_init_proof()]
//        }
//    }
//
//    pub fn primary_equal_init_proof() -> PrimaryEqualInitProof {
//        let a_prime = BigNumber::from_dec("71198415862588101794999647637020594298636904952221229203758282286975648719760139091058820193148109269247332893072500009542535008873854752148253162724944592022459474653064164142982594342926411034455992098661321743462319688749656666526142178124484745737199241840970729963874025117751516490879240004090076615289806927701165887254974076649588902577976777511906325622743656262704616698456422853985442045734201762141883277985205745253481177231940188177322557579410753761153630309562334285168209207788901648739373257862961666829476892899815574748297248950737715666360295849203006237827045519446375662564835999315073290305487").unwrap();
//        let t = BigNumber::from_dec("37079530399722470518553835765280909308924406195904537678706963737490514431969110883727762237489123135983690261368793099989547448050747260585120834115084482614671513768476918647769960328169587408048655264846527352389174831143008287892168564249124614290079578751533814072028575120651597983808151398302966613224948742301708922129750198808877460802873030542484563816871765427025336010548850910648439965691024868634556032480548923062720951911497199235783825753860665261995069217380645765606332915666031431712257374872377210061771504712087791540252026824755757495835057557581532161492715832664496193177508138480821897473809").unwrap();
//        let e_tilde = BigNumber::from_dec("162083298053730499878539835193560156486733663622707027216327685550780519347628838870322946818623352681120371349972731968874009673965057322").unwrap();
//        let e_prime = BigNumber::from_dec("524456141360955985047633523128638545").unwrap();
//        let v_tilde = BigNumber::from_dec("241132863422049783305938184561371219250127488499746090592218003869595412171810997360214885239402274273939963489505434726467041932541499422544431299362364797699330176612923593931231233163363211565697860685967381420219969754969010598350387336530924879073366177641099382257720898488467175132844984811431059686249020737675861448309521855120928434488546976081485578773933300425198911646071284164884533755653094354378714645351464093907890440922615599556866061098147921890790915215227463991346847803620736586839786386846961213073783437136210912924729098636427160258710930323242639624389905049896225019051952864864612421360643655700799102439682797806477476049234033513929028472955119936073490401848509891547105031112859155855833089675654686301183778056755431562224990888545742379494795601542482680006851305864539769704029428620446639445284011289708313620219638324467338840766574612783533920114892847440641473989502440960354573501").unwrap();
//        let v_prime = BigNumber::from_dec("6122626610060688577826028713229499074477199356382901788064599481139201841946675307459429492073681684106974266732473283582251199684473394004038677069391278799297504466809439456560373351261561843732294201399342642485048861806520699838955215375938183164246905713902888830173868746004110336429406019431751890876414837974585857037931936009631605481447289893116786856562441832216311257042439806063785598342878372454731622929805073343996197573787090352073902245810345895873431467898909436762044613966967021911486188119609549831292025135993050932365492572744590585266402690739158346280929929978500499339008113747791946209747828024836255098012541106593813811665807502701513851726770557955311255012143102074491761548144980609065262303926782928259410970230923851333959833714917949253189276799418924788811164548907247060119625232347").unwrap();
//        let m_tilde = mocks::mtilde();
//
//        let m2_tilde = BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap();
//        let m2 = BigNumber::from_dec("79198861930494722247098854124679815411215565468368019592091735771996515839812").unwrap();
//
//        PrimaryEqualInitProof {
//            a_prime,
//            t,
//            e_tilde,
//            e_prime,
//            v_tilde,
//            v_prime,
//            m_tilde,
//            m2_tilde,
//            m2
//        }
//    }
//
//    pub fn primary_ge_init_proof() -> PrimaryPredicateGEInitProof {
//        let c_list: Vec<BigNumber> = c_list();
//        let tau_list: Vec<BigNumber> = tau_list();
//
//        let mut u: HashMap<String, BigNumber> = HashMap::new();
//        u.insert("0".to_string(), BigNumber::from_dec("3").unwrap());
//        u.insert("1".to_string(), BigNumber::from_dec("1").unwrap());
//        u.insert("2".to_string(), BigNumber::from_dec("0").unwrap());
//        u.insert("3".to_string(), BigNumber::from_dec("0").unwrap());
//
//        let mut u_tilde = HashMap::new();
//        u_tilde.insert("3".to_string(), BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap());
//        u_tilde.insert("1".to_string(), BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap());
//        u_tilde.insert("2".to_string(), BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap());
//        u_tilde.insert("0".to_string(), BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap());
//
//        let mut r = HashMap::new();
//        r.insert("3".to_string(), BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436").unwrap());
//        r.insert("1".to_string(), BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436").unwrap());
//        r.insert("2".to_string(), BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436").unwrap());
//        r.insert("0".to_string(), BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436").unwrap());
//        r.insert("DELTA".to_string(), BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436").unwrap());
//
//        let mut r_tilde = HashMap::new();
//        r_tilde.insert("3".to_string(), BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap());
//        r_tilde.insert("1".to_string(), BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap());
//        r_tilde.insert("2".to_string(), BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap());
//        r_tilde.insert("0".to_string(), BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap());
//        r_tilde.insert("DELTA".to_string(), BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap());
//
//        let alpha_tilde = BigNumber::from_dec("15019832071918025992746443764672619814038193111378331515587108416842661492145380306078894142589602719572721868876278167686578705125701790763532708415180504799241968357487349133908918935916667492626745934151420791943681376124817051308074507483664691464171654649868050938558535412658082031636255658721308264295197092495486870266555635348911182100181878388728256154149188718706253259396012667950509304959158288841789791483411208523521415447630365867367726300467842829858413745535144815825801952910447948288047749122728907853947789264574578039991615261320141035427325207080621563365816477359968627596441227854436137047681372373555472236147836722255880181214889123172703767379416198854131024048095499109158532300492176958443747616386425935907770015072924926418668194296922541290395990933578000312885508514814484100785527174742772860178035596639").unwrap();
//        let predicate = predicate();
//
//        let mut t = HashMap::new();
//        t.insert("3".to_string(), BigNumber::from_dec("46369083086117629643055653975857627769028160828983987182078946658047913327657659075673217449651724551898727205835194812073207899212452294564444639346668484070129687160427147938076018605551830861026465851076491021338935906152700477977234743314769181602525430955162020248817746661022702546242365043781931307417744503802184994273068810023321000162105949048577491174537385619391992689890177380388187493777623608221690561227863928538947292434940859766215223694325554781311625439704847971277102325299579636232682943235572924328291095040633959587110788517670425708774447736335155403676598370782714048226320498065574125026899").unwrap());
//        t.insert("1".to_string(), BigNumber::from_dec("42633794716405561166353758783443542082448925291459053109072523255543918476162700915813468558725428930654732720550388668689693688311928225615248227542838894861904877843723074396340940707779041622733024047596548590206852224857490474241304499513238502020545990648514598111266718428654653729661393150510227786297395151012680735494729670444556589448695350091598078767475426612902588875098609575406745197186551303270002056095805065181028711913238674710248448811408868490444106100385953490031500705851784934426334273103423243390196341490285527664863980694992161784435576660236953710046735477189662522764706620430688287285864").unwrap());
//        t.insert("2".to_string(), BigNumber::from_dec("46369083086117629643055653975857627769028160828983987182078946658047913327657659075673217449651724551898727205835194812073207899212452294564444639346668484070129687160427147938076018605551830861026465851076491021338935906152700477977234743314769181602525430955162020248817746661022702546242365043781931307417744503802184994273068810023321000162105949048577491174537385619391992689890177380388187493777623608221690561227863928538947292434940859766215223694325554781311625439704847971277102325299579636232682943235572924328291095040633959587110788517670425708774447736335155403676598370782714048226320498065574125026899").unwrap());
//        t.insert("0".to_string(), BigNumber::from_dec("78330570979325941798365644373115445702503890126796448033540676436952642712474355493362616083006349657268453144498828167557958002187631433688600374998507190955348534609331062289505584464470965930026066960445862271919137219085035331183489708020179104768806542397317724245476749638435898286962686099614654775075210180478240806960936772266501650713946075532415486293498432032415822169972407762416677793858709680700551196367079406811614109643837625095590323201355832120222436221544300974405069957610226245036804939616341080518318062198049430554737724174625842765640174768911551668897074696860939233144184997614684980589924").unwrap());
//        t.insert("DELTA".to_string(), BigNumber::from_dec("55689486371095551191153293221620120399985911078762073609790094310886646953389020785947364735709221760939349576244277298015773664794725470336037959586509430339581241350326035321187900311380031369930812685369312069872023094452466688619635133201050270873513970497547720395196520621008569032923514500216567833262585947550373732948093781160931218148684610639834393439060745307992621402105096757255088629786888737281709324281552413987274960223110927132818654699339106642690418211294536451370321243108928564278387404368783012923356880461335644797776340191719071088431730682007888636922131293039620517120570619351490238276806").unwrap());
//
//        PrimaryPredicateGEInitProof {
//            c_list,
//            tau_list,
//            u,
//            u_tilde,
//            r,
//            r_tilde,
//            alpha_tilde,
//            predicate,
//            t
//        }
//    }
//
//    pub fn c_list() -> Vec<BigNumber> {
//        let mut c_list: Vec<BigNumber> = Vec::new();
//        c_list.push(BigNumber::from_dec("78330570979325941798365644373115445702503890126796448033540676436952642712474355493362616083006349657268453144498828167557958002187631433688600374998507190955348534609331062289505584464470965930026066960445862271919137219085035331183489708020179104768806542397317724245476749638435898286962686099614654775075210180478240806960936772266501650713946075532415486293498432032415822169972407762416677793858709680700551196367079406811614109643837625095590323201355832120222436221544300974405069957610226245036804939616341080518318062198049430554737724174625842765640174768911551668897074696860939233144184997614684980589924").unwrap());
//        c_list.push(BigNumber::from_dec("42633794716405561166353758783443542082448925291459053109072523255543918476162700915813468558725428930654732720550388668689693688311928225615248227542838894861904877843723074396340940707779041622733024047596548590206852224857490474241304499513238502020545990648514598111266718428654653729661393150510227786297395151012680735494729670444556589448695350091598078767475426612902588875098609575406745197186551303270002056095805065181028711913238674710248448811408868490444106100385953490031500705851784934426334273103423243390196341490285527664863980694992161784435576660236953710046735477189662522764706620430688287285864").unwrap());
//        c_list.push(BigNumber::from_dec("46369083086117629643055653975857627769028160828983987182078946658047913327657659075673217449651724551898727205835194812073207899212452294564444639346668484070129687160427147938076018605551830861026465851076491021338935906152700477977234743314769181602525430955162020248817746661022702546242365043781931307417744503802184994273068810023321000162105949048577491174537385619391992689890177380388187493777623608221690561227863928538947292434940859766215223694325554781311625439704847971277102325299579636232682943235572924328291095040633959587110788517670425708774447736335155403676598370782714048226320498065574125026899").unwrap());
//        c_list.push(BigNumber::from_dec("46369083086117629643055653975857627769028160828983987182078946658047913327657659075673217449651724551898727205835194812073207899212452294564444639346668484070129687160427147938076018605551830861026465851076491021338935906152700477977234743314769181602525430955162020248817746661022702546242365043781931307417744503802184994273068810023321000162105949048577491174537385619391992689890177380388187493777623608221690561227863928538947292434940859766215223694325554781311625439704847971277102325299579636232682943235572924328291095040633959587110788517670425708774447736335155403676598370782714048226320498065574125026899").unwrap());
//        c_list.push(BigNumber::from_dec("55689486371095551191153293221620120399985911078762073609790094310886646953389020785947364735709221760939349576244277298015773664794725470336037959586509430339581241350326035321187900311380031369930812685369312069872023094452466688619635133201050270873513970497547720395196520621008569032923514500216567833262585947550373732948093781160931218148684610639834393439060745307992621402105096757255088629786888737281709324281552413987274960223110927132818654699339106642690418211294536451370321243108928564278387404368783012923356880461335644797776340191719071088431730682007888636922131293039620517120570619351490238276806").unwrap());
//        c_list
//    }
//
//    pub fn tau_list() -> Vec<BigNumber> {
//        let mut tau_list: Vec<BigNumber> = Vec::new();
//        tau_list.push(BigNumber::from_dec("37691036678500088864090706889277344529085698202855318342609662324455534725777810174779988243614834740383002484042961779535438729512700925723800184769772855117653609397311580937440131814111009890073972276784593662470810723687676167680062717239972656425563430838236749325671702463390044920572001860955651242331741037260836613506653323682056706226370698422365916655999046380426509541586034749242827978969972239524676039139025602263974101808887008331192929679659076910995855665477952930199692854778469439162325030246066895851569630345729938981633504514117558420480144828304421708923356898912192737390539479512879411139535").unwrap());
//        tau_list.push(BigNumber::from_dec("37691036678500088864090706889277344529085698202855318342609662324455534725777810174779988243614834740383002484042961779535438729512700925723800184769772855117653609397311580937440131814111009890073972276784593662470810723687676167680062717239972656425563430838236749325671702463390044920572001860955651242331741037260836613506653323682056706226370698422365916655999046380426509541586034749242827978969972239524676039139025602263974101808887008331192929679659076910995855665477952930199692854778469439162325030246066895851569630345729938981633504514117558420480144828304421708923356898912192737390539479512879411139535").unwrap());
//        tau_list.push(BigNumber::from_dec("37691036678500088864090706889277344529085698202855318342609662324455534725777810174779988243614834740383002484042961779535438729512700925723800184769772855117653609397311580937440131814111009890073972276784593662470810723687676167680062717239972656425563430838236749325671702463390044920572001860955651242331741037260836613506653323682056706226370698422365916655999046380426509541586034749242827978969972239524676039139025602263974101808887008331192929679659076910995855665477952930199692854778469439162325030246066895851569630345729938981633504514117558420480144828304421708923356898912192737390539479512879411139535").unwrap());
//        tau_list.push(BigNumber::from_dec("37691036678500088864090706889277344529085698202855318342609662324455534725777810174779988243614834740383002484042961779535438729512700925723800184769772855117653609397311580937440131814111009890073972276784593662470810723687676167680062717239972656425563430838236749325671702463390044920572001860955651242331741037260836613506653323682056706226370698422365916655999046380426509541586034749242827978969972239524676039139025602263974101808887008331192929679659076910995855665477952930199692854778469439162325030246066895851569630345729938981633504514117558420480144828304421708923356898912192737390539479512879411139535").unwrap());
//        tau_list.push(BigNumber::from_dec("37691036678500088864090706889277344529085698202855318342609662324455534725777810174779988243614834740383002484042961779535438729512700925723800184769772855117653609397311580937440131814111009890073972276784593662470810723687676167680062717239972656425563430838236749325671702463390044920572001860955651242331741037260836613506653323682056706226370698422365916655999046380426509541586034749242827978969972239524676039139025602263974101808887008331192929679659076910995855665477952930199692854778469439162325030246066895851569630345729938981633504514117558420480144828304421708923356898912192737390539479512879411139535").unwrap());
//        tau_list.push(BigNumber::from_dec("47065304866607958075946961264533928435933122536016679690080278659386698316132559908768761685743414728586341914305025339970537873714845915164843100776821561200343390749927996265246866447155790487554483555192805709960222015718787293872197230832464704800887153568636866026153126587657548580608446574507279965440247754859129693686186427399103313737110632413255017522482016458190003045641077338674019608347139399755470654452373975228190041980152120799403855480909173865431397307988238759767251890853580982844825639097363091181044515877489450972963624109587697097258041963985607958610791800500711857115582406526050626576194").unwrap());
//        tau_list
//    }
//
//    pub fn mtilde() -> HashMap<String, BigNumber> {
//        let mut mtilde = HashMap::new();
//        mtilde.insert("height".to_string(), BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap());
//        mtilde.insert("age".to_string(), BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap());
//        mtilde.insert("sex".to_string(), BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap());
//        mtilde
//    }
//
    pub fn eq_proof() -> PrimaryEqualProof {
        PrimaryEqualProof {
            revealed_attrs: btreemap![
                "name".to_string() => BigNumber::from_dec("71359565546479723151967460283929432570283558415909434050407244812473401631735").unwrap()
            ],
            a_prime: BigNumber::from_dec("34058645662221524755637265027124666664569675269841853714291263309000191762242457313357319189759805622622555110559335562630442751701977830074539510617988729259474984245839448768501926395759154147058491381782965822753416693135027718073273700692539210090241752790568483347321105624190572699082858062963032637791336986711696500868198190746494345341752356311829390919178046339967872378744518707393167107254866842777034591597977690004824824291406258023727344993772735885636669568776208773287594726609417985075314362252902352298223843392136155771931435876167580547778596584869770935045957077785470104135337651581041899100976").unwrap(),
            e: BigNumber::from_dec("176783915116812778548195027164475325740715572943725251032520360490844704920448088205853672364046756471055381794183109170599036224538455018").unwrap(),
            v: BigNumber::from_dec("606818910236588115814884961268211499584834655495151223185909421388922312907531515810303599987667849882769205906156632002060585624848411894392738136431651035870428552960232711860107034277299635153813743404410469671095129479204881044732257687155905886732339461947470152456413922660240534279581143291752951827985346806704152780877156994245506625612958201305295668526249202222090554510736798397449850889113249125233680689444816628824151471617826386579546879239447731539075234631878119015681611882908662704946666871852317719253297539772293752537970219133557383832674331405050166730833579653237829273538201814179023736007716851651321249558334363895801050993579301103047303647557013720523906494893017644314502434371527587096112190644600803377187333337414588946639470900798150111236461939020460963296845302894997782013405306604658877487546881879060611292941501546715850226442310698492699838808541030676106946042680727157531376528").unwrap(),
            m: btreemap![
                "age".to_string() => BigNumber::from_dec("6836093372281486729646184617597916991214841800681868769509121358446601587666656078277382831520780194784633779972340766019270181226687531873137224042876323371837541729936681716283").unwrap(),
                "gender".to_string() => BigNumber::from_dec("4542318061882004307306710524823292909367354014982094469360419388235416361659421872055188917411511348723801433939000162068648359710064864074328818068135002769743420312965221028822").unwrap(),
                "height".to_string() => BigNumber::from_dec("14026972358434558653527907928880138680231339872942176589090005931999052178490653973804126077690180779183645816908705545840786777387513981683922240925968963101602220371688597019438").unwrap(),
                "link_secret".to_string() => BigNumber::from_dec("4892729562200808264076540862404013238001307499748689320429858988078324558904367508942728432460660990926041590483751331803827498498722952826056044123024082476338911626588928674717").unwrap(),
                "policy_address".to_string() => BigNumber::from_dec("11664269910239554114811575093790927659772178198758113538135247369261107627305346049376434641904817122430281258357521645529616304587802924324741078725146425973306841956896342639608").unwrap()
            ],
            m2: BigNumber::from_dec("15424669485993499527208006742378227382874512395170441470177478000443772356450352181536326766687098033073903437962279333173356714502304355714518902132000163569339702119532494575893").unwrap(),
        }
    }

    pub fn aggregated_proof() -> AggregatedProof {
        AggregatedProof {
            c_list: vec![
                vec![1, 13, 203, 227, 177, 215, 104, 246, 100, 86, 29, 181, 216, 220, 107, 99, 81, 95, 238, 135, 177, 25, 157, 255, 226, 4, 192, 15, 121, 167, 94, 19, 199, 115, 145, 94, 142, 115, 168, 229, 120, 173, 87, 71, 137, 72, 39, 115, 90, 243, 6, 108, 170, 135, 230, 51, 12, 192, 124, 187, 97, 208, 168, 233, 123, 124, 136, 94, 139, 199, 152, 73, 225, 212, 166, 174, 226, 66, 119, 247, 78, 0, 144, 130, 98, 44, 84, 14, 171, 154, 189, 111, 92, 47, 2, 152, 46, 170, 181, 160, 32, 133, 153, 145, 87, 120, 25, 211, 40, 92, 186, 132, 107, 75, 47, 190, 183, 195, 105, 137, 3, 159, 117, 218, 212, 230, 97, 192, 123, 104, 207, 72, 242, 73, 179, 208, 242, 83, 141, 239, 21, 210, 52, 98, 205, 244, 109, 17, 97, 134, 185, 199, 46, 252, 138, 34, 89, 165, 247, 250, 113, 189, 1, 40, 104, 177, 112, 38, 160, 43, 68, 42, 208, 143, 213, 137, 190, 197, 198, 3, 145, 6, 115, 184, 2, 175, 32, 35, 24, 234, 34, 91, 95, 106, 133, 247, 110, 68, 127, 134, 114, 78, 214, 173, 27, 246, 128, 34, 181, 223, 179, 97, 152, 43, 147, 114, 115, 107, 84, 185, 179, 161, 186, 29, 187, 226, 95, 229, 80, 160, 3, 249, 91, 92, 134, 191, 225, 134, 169, 74, 9, 135, 246, 73, 91, 63, 226, 252, 164, 246, 22, 116, 84, 185, 202, 91, 48],
                vec![3, 44, 241, 155, 203, 162, 23, 95, 243, 77, 3, 209, 14, 47, 224, 46, 36, 230, 198, 114, 18, 112, 43, 199, 8, 97, 20, 110, 156, 139, 185, 3, 222, 97, 9, 252, 170, 173, 87, 203, 73, 104, 175, 160, 21, 33, 169, 124, 243, 106, 93, 52, 138, 204, 247, 217, 53, 10, 8, 140, 183, 124, 220, 85, 99, 16, 235, 175, 117, 44, 163, 115, 24, 52, 17, 60, 145, 190, 40, 113, 13, 45, 185, 87, 169, 236, 82, 56, 61, 41, 170, 222, 132, 27, 241, 255, 102, 21, 74, 170, 189, 132, 126, 39, 208, 151, 114, 194, 47, 164, 179, 72, 237, 7, 215, 196, 119, 250, 73, 249, 67, 25, 135, 223, 191, 90, 218, 94, 21, 35, 137, 76, 115, 233, 69, 59, 22, 226, 4, 244, 49, 4, 3, 100, 30, 244, 8, 95, 207, 243, 10, 97, 204, 81, 99, 189, 140, 218, 44, 169, 41, 40, 212, 140, 131, 248, 204, 247, 3, 157, 79, 75, 242, 186, 75, 240, 216, 227, 143, 242, 89, 189, 22, 241, 89, 46, 123, 245, 170, 61, 1, 28, 167, 190, 2, 74, 2, 99, 62, 236, 101, 15, 195, 168, 179, 69, 223, 133, 35, 110, 43, 13, 148, 164, 64, 104, 186, 219, 188, 24, 228, 103, 106, 45, 194, 44, 101, 81, 46, 66, 48, 250, 251, 102, 166, 29, 144, 9, 45, 218, 215, 22, 141, 158, 183, 11, 93, 162, 242, 227, 186, 72, 186, 115, 67, 21, 18],
                vec![1, 205, 82, 105, 255, 196, 166, 105, 25, 186, 69, 101, 95, 68, 83, 194, 124, 169, 79, 14, 59, 62, 18, 221, 201, 133, 38, 103, 220, 90, 32, 250, 161, 11, 17, 144, 46, 227, 127, 108, 94, 127, 83, 242, 241, 61, 173, 52, 130, 63, 123, 246, 33, 221, 94, 204, 180, 0, 26, 230, 107, 170, 236, 97, 184, 118, 161, 64, 93, 100, 77, 27, 158, 105, 183, 78, 218, 196, 157, 7, 69, 26, 130, 3, 129, 250, 175, 212, 62, 181, 75, 239, 102, 56, 155, 69, 217, 158, 233, 195, 124, 16, 178, 27, 72, 58, 225, 98, 156, 196, 60, 94, 194, 255, 174, 219, 24, 202, 116, 92, 23, 177, 248, 18, 205, 87, 185, 77, 251, 215, 49, 202, 4, 164, 39, 202, 246, 159, 199, 209, 108, 132, 86, 3, 40, 86, 30, 226, 240, 25, 17, 178, 154, 164, 40, 19, 164, 75, 194, 156, 68, 170, 159, 148, 167, 168, 60, 170, 67, 41, 231, 178, 55, 19, 154, 243, 177, 97, 14, 238, 7, 223, 203, 238, 255, 26, 244, 61, 11, 26, 128, 10, 242, 17, 96, 75, 60, 218, 174, 145, 153, 254, 180, 144, 231, 222, 158, 161, 43, 69, 63, 29, 210, 16, 132, 83, 82, 125, 22, 165, 23, 14, 249, 193, 4, 191, 214, 174, 165, 77, 250, 62, 171, 167, 182, 38, 66, 179, 253, 51, 8, 169, 177, 148, 186, 198, 194, 249, 210, 93, 163, 143, 16, 229, 102, 74, 175],
                vec![207, 245, 229, 171, 239, 2, 174, 43, 134, 235, 51, 240, 97, 101, 34, 156, 72, 12, 180, 81, 106, 151, 216, 18, 111, 62, 70, 44, 251, 108, 39, 65, 226, 19, 121, 76, 147, 121, 116, 13, 211, 236, 81, 44, 183, 16, 96, 212, 218, 175, 88, 171, 205, 40, 8, 50, 20, 242, 198, 197, 226, 248, 56, 122, 163, 101, 174, 193, 61, 201, 177, 76, 34, 41, 186, 182, 20, 203, 71, 81, 56, 242, 192, 12, 161, 163, 67, 24, 152, 142, 199, 171, 76, 83, 57, 12, 217, 170, 82, 143, 66, 250, 227, 85, 140, 97, 12, 73, 229, 143, 249, 62, 44, 211, 108, 226, 169, 167, 8, 228, 101, 59, 222, 9, 254, 148, 160, 33, 100, 166, 254, 192, 64, 198, 255, 88, 216, 233, 61, 189, 230, 206, 138, 2, 103, 200, 185, 71, 135, 223, 97, 245, 227, 13, 124, 235, 66, 3, 104, 15, 20, 162, 165, 131, 119, 54, 45, 173, 29, 76, 216, 121, 11, 176, 56, 32, 200, 61, 131, 80, 240, 195, 230, 21, 112, 203, 142, 124, 76, 46, 192, 169, 220, 254, 24, 162, 109, 3, 69, 3, 48, 248, 201, 19, 182, 144, 3, 85, 86, 90, 21, 229, 121, 108, 183, 207, 251, 32, 26, 103, 95, 189, 80, 91, 46, 36, 205, 36, 194, 138, 239, 180, 209, 203, 80, 15, 36, 241, 22, 236, 238, 204, 150, 73, 76, 50, 15, 89, 139, 207, 207, 112, 229, 19, 250, 245],
                vec![1, 59, 146, 208, 108, 97, 245, 104, 95, 237, 34, 17, 34, 249, 122, 131, 25, 188, 4, 205, 205, 157, 189, 178, 235, 198, 238, 1, 117, 176, 183, 120, 222, 229, 205, 169, 206, 86, 54, 82, 40, 145, 174, 237, 246, 71, 83, 158, 214, 228, 94, 16, 152, 220, 117, 57, 106, 182, 149, 131, 233, 21, 105, 206, 69, 245, 185, 193, 250, 124, 151, 143, 2, 49, 109, 71, 91, 54, 168, 128, 95, 8, 187, 55, 249, 154, 131, 36, 25, 239, 24, 74, 51, 70, 55, 132, 122, 184, 0, 232, 70, 135, 168, 116, 229, 91, 147, 160, 241, 40, 115, 78, 137, 32, 80, 228, 30, 238, 141, 249, 132, 107, 49, 74, 34, 214, 246, 135, 250, 174, 53, 179, 198, 153, 35, 63, 146, 41, 201, 180, 192, 211, 201, 85, 184, 68, 250, 72, 199, 241, 195, 188, 172, 25, 91, 108, 168, 120, 237, 253, 196, 117, 72, 70, 79, 183, 158, 205, 37, 37, 177, 95, 99, 86, 194, 154, 22, 241, 155, 37, 209, 40, 42, 207, 135, 70, 35, 136, 196, 84, 183, 221, 163, 7, 47, 93, 102, 110, 98, 22, 109, 55, 131, 39, 115, 22, 120, 132, 8, 134, 189, 78, 248, 152, 55, 151, 197, 229, 197, 89, 182, 172, 70, 239, 164, 25, 250, 202, 203, 44, 251, 211, 229, 62, 227, 248, 94, 184, 60, 226, 29, 40, 4, 11, 68, 185, 210, 148, 153, 216, 98, 69, 85, 217, 33, 157, 57],
                vec![2, 243, 244, 62, 30, 12, 124, 216, 3, 52, 120, 227, 46, 98, 135, 133, 150, 102, 217, 75, 112, 69, 198, 246, 118, 102, 179, 233, 40, 145, 113, 208, 191, 141, 120, 111, 129, 12, 233, 2, 195, 41, 13, 208, 253, 152, 12, 231, 246, 126, 35, 19, 30, 118, 55, 248, 174, 215, 145, 139, 206, 35, 249, 108, 134, 29, 196, 42, 87, 165, 255, 55, 173, 85, 247, 211, 223, 157, 49, 137, 114, 45, 25, 59, 3, 18, 25, 226, 49, 206, 71, 252, 232, 248, 77, 17, 214, 197, 5, 139, 9, 108, 19, 251, 183, 88, 118, 201, 141, 53, 155, 176, 242, 97, 252, 91, 31, 229, 41, 175, 253, 105, 225, 225, 77, 233, 188, 138, 232, 97, 95, 223, 130, 192, 224, 71, 248, 95, 127, 138, 202, 37, 244, 21, 35, 98, 116, 174, 69, 8, 255, 241, 244, 174, 222, 251, 216, 23, 72, 132, 19, 41, 163, 49, 96, 222, 28, 133, 131, 194, 26, 108, 76, 219, 194, 157, 250, 100, 57, 32, 31, 66, 40, 95, 26, 122, 176, 54, 81, 105, 180, 134, 11, 14, 157, 23, 227, 63, 52, 60, 98, 69, 53, 106, 31, 240, 206, 63, 170, 45, 122, 246, 75, 194, 72, 89, 204, 62, 85, 212, 181, 251, 254, 168, 129, 117, 189, 24, 71, 98, 31, 42, 60, 52, 29, 120, 80, 148, 143, 209, 217, 55, 97, 233, 202, 12, 71, 161, 140, 58, 226, 241, 4, 222, 16, 67, 214]
		    ],
            c_hash: BigNumber::from_dec("76637087247475488633433930797979906803296136643399661099027589810045779012272").unwrap()
        }
    }

    pub fn ge_proof() -> PrimaryPredicateGEProof {
        let m = btreemap![
            "age".to_string() => BigNumber::from_dec("6836093372281486729646184617597916991214841800681868769509121358446601587666656078277382831520780194784633779972340766019270181226687531873137224042876323371837541729936681716283").unwrap(),
            "gender".to_string() => BigNumber::from_dec("4542318061882004307306710524823292909367354014982094469360419388235416361659421872055188917411511348723801433939000162068648359710064864074328818068135002769743420312965221028822").unwrap(),
            "height".to_string() => BigNumber::from_dec("14026972358434558653527907928880138680231339872942176589090005931999052178490653973804126077690180779183645816908705545840786777387513981683922240925968963101602220371688597019438").unwrap(),
            "link_secret".to_string() => BigNumber::from_dec("4892729562200808264076540862404013238001307499748689320429858988078324558904367508942728432460660990926041590483751331803827498498722952826056044123024082476338911626588928674717").unwrap(),
            "policy_address".to_string() => BigNumber::from_dec("11664269910239554114811575093790927659772178198758113538135247369261107627305346049376434641904817122430281258357521645529616304587802924324741078725146425973306841956896342639608").unwrap()
        ];

        let u = btreemap![
            "0".to_string() => BigNumber::from_dec("9093502544616887363402366946597929497250045918843017784884340750933755148570016155333019797972345695653100583198499397771911603170413241746179502436028455084672113277853645621023").unwrap(),
            "1".to_string() => BigNumber::from_dec("11313042062749845768515492850053028037881397074959770898723373276064566909711448454948700615519235623391182011945901634164990996625979461011432215533640387575421581865505588102133").unwrap(),
            "2".to_string() => BigNumber::from_dec("1318828420130396546966093416095900074823130396091563409483284721171790570703964948675721339223101467415337043662970709061397208361142641707101015189323151207348182340790995413192").unwrap(),
            "3".to_string() => BigNumber::from_dec("8686333835923163897336248045363777169320457247092673089221424105338460371200331815142663748707816974161336223760024826810663041415196777868669754428720604965912216725998781090136").unwrap()
        ];

        let r = btreemap![
            "0".to_string() => BigNumber::from_dec("669651578516028397422135234615972315033981887403123341256378577372796445539125914093229655757887438925809259526373519390718312195013821992928774558828443271411716202577073302277467299906981683229125678705029745875173823257527616398603389381952383832328948060259427115531154516105397613245084284506389518947074902220424012969755956089268739624670166468975965603885345039094495124645789841807572710361659420706266014588207136819843996073511459207026058914240580847021996979060055303541592335880349950692344180895766947129317958672551227306726079587974052408764945347226082695267779781773304169696701686574790162530130697587788535536903729367112048465018811160961115437822326461347659604214103527525910056892655604548144").unwrap(),
            "1".to_string() => BigNumber::from_dec("726289655403183966584344089441860995629840211722581085822609452764410987916702638631890042306526244924050465790056814064587837604906989091299592690973776546176181753614779914447733927920784478986397868998711387967785641723877469214529446218946898810818156338405880353759646063168192798267823385233869884083399050198408794418006865731868095303537461468986431647457078191785738204792311102637991250474143797921895160562457182247135879245880941697717679537232521966972805169973438186754257382385167350741171278357871052106402886872821016051398197146707429919167288133324346435946395270762553102269221739719877421695926812960729885433601514516416108110755229516153776343277175853981693257064609937171299464664481127613479").unwrap(),
            "2".to_string() => BigNumber::from_dec("2983828369508339707212174366010892636806749562648593094718747343257387574167597439239248117066792476657126786479978760877151945170431164592689237928641509473514721904010325582103949363743587838999898434495654175536665669191274945210762043186068644342601352747064058276937778689431363561069201027297939568003104144360208178482686573450578234180879171220802782040136106813263836264533763707770025786869522967116321420582794514537082182840433773192011915934875075604677078149477674452580669309731756777711611814856114171456263175418983440447733145393898236778473269975205380094677998143931578871284372401702078386208388419467566923004904570323349401804693474000229422819589555116082403671689723279299732653413665002117375").unwrap(),
            "3".to_string() => BigNumber::from_dec("2723593514334273560571467004517122100110068114876338029934292154018026772413234515412036905897854651106086952963403551656090466794584164597093665802531036021125573022353887660498434096369745371648282936470132553289479891991732131092480884851725368323261114696006169571933670258734084815087656303201834442516024420112659542649233300965997384172909393751705566687537158535736594946304780977445065415264095461194150599426714776468957884494166360076688245253069879519299777097673900431172641051292910941853473749109550135752272810512862525219191870184328491531726829617417377462958980214185578376221061115744189907193561668553631230056001734258335039555854472054220988255154306390287852665587631895108329886950227157560741").unwrap(),
            "DELTA".to_string() => BigNumber::from_dec("1911006565712802010135042141425146382930602758036633927033877679068899633815884730245592183864761302229498618832439939520307706158855397609698378930275413649799548090813734018492195129305487020401452320416029721081422518502476984444473865852866923330381206699637090514872077442834549337457497918749465707203130632585189932292994657772653747541386783802938933646176952000683224360925944467084137748507454843857106300181352134525860261230268798130383930493130309313138241154199720229171542168282344401298106355156663130284199513249844205962148212912920958568975930314114965997379535605533145810705028842567995665429500487495955332294190872729327146112067090858761362847163765763912879758127625201116212024084706247659036").unwrap()
        ];

        let t = btreemap![
            "0".to_string() => BigNumber::from_dec("102624645261707697261422232573329755991227979193836995249007836216063261279835070612141568628976713711790287924384083398737387581626447564773600238262745725182002485648196172344176614720428263880924147224881787333522165313453225993678514679052360487464385481590506092429854657519306729280109691178772445629442752497404463369432223955459674343934935500885921948707387532759200852226802247540794976205952280593940279457543039859003520574365836540057130006250408329732126128433988765944378606702848840328845588055741345299435410174374035849334911984929401384314090702707542557661459568738034681424816028140447037808383250").unwrap(),
            "1".to_string() => BigNumber::from_dec("58236498476496753847438951866738148059084225561758931140709080161696374188940229427291812215389361591373327785918240944969104436840032495797068857022729041757520448109673001188099025860327627398458023289576138352189352399862697514178743803878060022384271227648027813319588789393282724182963897922612418915036779380610773961340539247743589664926094400984085445802674480962757994076022381975685527986469960600918423879941992552962841293404152576198551919092499023180156218473261362248976954607036557981903871043501444904365151634258927833782442946988332476126799574936009698612898694931466823977488962747958099400084143").unwrap(),
            "2".to_string() => BigNumber::from_dec("26252585534269050565068741484515530568890436775390971042622158130194908037514090769388919331457623120129628710859907261040794300296398006747466559323820734893992121127866503381567023140095412300143207546662686797949466733600223538022568194663559048138880631369365084142460061270460698570310944732352080884199454852653168846890717220773039884165784044267955531574931072615941525849986488199635454075729160160923971700865699657096712109643413643398537178662065674815925226028975232185220642206230286400896924670956402861592377054470639220989236303997275725108496040441811536986434381177998673046648572487459044242750197").unwrap(),
            "3".to_string() => BigNumber::from_dec("39837462821805436133322837257422138261511709423649304612532848394401808799393548951388327498726346693662561483609225729409228188579356674118659545662090610932209137061003248491244384015465163086101072890147290883270462919019031984822805279075477975704138004275002981623269068827409791668013207504764391562531919716089460156850098892567055982223796089951135516427188750383818187577636870604578181978841897067408228260667658109780376819110965225230164124908061391819332560062875872632439107270865196615874214940197437001573356779860630338048436274661919049214930314927964320495299286920997596596265902571019133549387065").unwrap(),
            "DELTA".to_string() => BigNumber::from_dec("95430360787001112870191130945308950372267635654623017169087749142602153683788673550140324911072684150773923005636190640743945782248768283368811820745286342034953878369319245360856254208651411694979366062683145875731095886877732818295745945047935008108812788144080276970522265702079518922078840622441394393662964332822351534799169816030396341053486889122224545295693031443292252643437737357820865277687330434161502568486056306667220447722669033440914479536065517724956711792991160521080160391746701719077438975311143796860814304749383081922822379545919729584642550310461363945817460194652787694752449446403712192889814").unwrap()
        ];

        PrimaryPredicateGEProof {
            u,
            r,
            mj: BigNumber::from_dec("6836093372281486729646184617597916991214841800681868769509121358446601587666656078277382831520780194784633779972340766019270181226687531873137224042876323371837541729936681716283").unwrap(),
            alpha: BigNumber::from_dec("21341332128947884794422343977482411373204136713790236919507762661605075720168323728157011654764306229732212355396647823252595905497488230330270756162713040460273065661764571542988115316204573074902566955879110157355708791790526204418589581052789545641467339995827952773456975183583821998736814136885950023950723109110482678697106537681549106736790397357697921673986149622452955800201250788870407128968822002030540015121132880433924272151167454795975627295926734217424073227326420300075207313663780631529283674319291595603074939973729154495139873365667390661237674607916037131337506961471733312428607123721207386446410188935686532659581860988810311714607227227464020421135909142851484319553158070216090794685944936659088147285078134836727162691683833214102242518504100186127048470535686544981674021286014565836226340987678329540770020500204").unwrap(),
            t,
            predicate: predicate()
        }
    }
//
//    pub fn primary_proof() -> PrimaryProof {
//        PrimaryProof {
//            eq_proof: eq_proof(),
//            ge_proofs: vec![ge_proof()]
//        }
//    }
//
//    pub fn sub_proof_request() -> SubProofRequest {
//        let mut sub_proof_request_builder = SubProofRequestBuilder::new().unwrap();
//        sub_proof_request_builder.add_revealed_attr("name").unwrap();
//        sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
//        sub_proof_request_builder.finalize().unwrap()
//    }
//
//    pub fn revealed_attrs() -> HashSet<String> {
//        HashSet::from_iter(vec!["name".to_owned()].into_iter())
//    }
//
//    pub fn unrevealed_attrs() -> HashSet<String> {
//        HashSet::from_iter(vec!["height".to_owned(), "age".to_owned(), "sex".to_owned()])
//    }
//
//    pub fn credential_revealed_attributes_values() -> CredentialValues {
//        let mut credential_values_builder = CredentialValuesBuilder::new().unwrap();
//        credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
//        credential_values_builder.finalize().unwrap()
//    }
//
    pub fn predicate() -> Predicate {
        Predicate {
            attr_name: "age".to_owned(),
            p_type: PredicateType::GE,
            value: 18
        }
    }
}
