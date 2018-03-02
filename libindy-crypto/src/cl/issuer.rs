use bn::BigNumber;
use cl::*;
use errors::IndyCryptoError;
use pair::*;
use cl::constants::*;
use cl::helpers::*;
use utils::commitment::*;

use std::collections::{BTreeMap, HashSet};

/// Trust source that provides credentials to prover.
pub struct Issuer {}

impl Issuer {
    /// Creates and returns credential schema entity builder.
    ///
    /// The purpose of credential schema builder is building of credential schema entity that
    /// represents credential schema attributes set.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let _credential_schema = credential_schema_builder.finalize().unwrap();
    /// ```
    pub fn new_credential_schema_builder() -> Result<CredentialSchemaBuilder, IndyCryptoError> {
        let res = CredentialSchemaBuilder::new()?;
        Ok(res)
    }

    /// Creates and returns credential definition (public and private keys, correctness proof) entities.
    ///
    /// # Arguments
    /// * `credential_schema` - Credential schema entity.
    /// * `support_revocation` - If true non revocation part of keys will be generated.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (_cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();
    /// ```
    pub fn new_credential_def(credential_schema: &CredentialSchema,
                              support_revocation: bool) -> Result<(CredentialPublicKey,
                                                                   CredentialPrivateKey,
                                                                   CredentialKeyCorrectnessProof), IndyCryptoError> {
        trace!("Issuer::new_credential_def: >>> credential_schema: {:?}, support_revocation: {:?}", credential_schema, support_revocation);

        let (p_pub_key, p_priv_key, p_key_meta) =
            Issuer::_new_credential_primary_keys(credential_schema)?;

        let (r_pub_key, r_priv_key) = if support_revocation {
            Issuer::_new_credential_revocation_keys()
                .map(|(r_pub_key, r_priv_key)| (Some(r_pub_key), Some(r_priv_key)))?
        } else {
            (None, None)
        };

        let cred_pub_key = CredentialPublicKey { p_key: p_pub_key, r_key: r_pub_key };
        let cred_priv_key = CredentialPrivateKey { p_key: p_priv_key, r_key: r_priv_key };
        let cred_key_correctness_proof =
            Issuer::_new_credential_key_correctness_proof(&cred_pub_key.p_key,
                                                          &cred_priv_key.p_key,
                                                          &p_key_meta)?;

        trace!("Issuer::new_credential_def: <<< cred_pub_key: {:?}, cred_priv_key: {:?}, cred_key_correctness_proof: {:?}",
               cred_pub_key, cred_priv_key, cred_key_correctness_proof);

        Ok((cred_pub_key, cred_priv_key, cred_key_correctness_proof))
    }

    /// Creates and returns revocation registry definition (public and private keys, accumulator and tails generator) entities.
    ///
    /// # Arguments
    /// * `credential_pub_key` - Credential public key entity.
    /// * `max_cred_num` - Max credential number in generated registry.
    /// * `issuance_by_default` - Type of issuance.
    ///   If true all indices are assumed to be issued and initial accumulator is calculated over all indices
    ///   If false nothing is issued initially accumulator is 1
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();
    ///
    /// let (_rev_key_pub, _rev_key_priv, _rev_reg, _rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, 5, false).unwrap();
    /// ```
    pub fn new_revocation_registry_def(credential_pub_key: &CredentialPublicKey,
                                       max_cred_num: u32,
                                       issuance_by_default: bool) -> Result<(RevocationKeyPublic,
                                                                             RevocationKeyPrivate,
                                                                             RevocationRegistry,
                                                                             RevocationTailsGenerator), IndyCryptoError> {
        trace!("Issuer::new_revocation_registry_def: >>> credential_pub_key: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}",
               credential_pub_key, max_cred_num, issuance_by_default);

        let cred_rev_pub_key: &CredentialRevocationPublicKey = credential_pub_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("There are not revocation keys in the credential public key.")))?;

        let (rev_key_pub, rev_key_priv) = Issuer::_new_revocation_registry_keys(cred_rev_pub_key, max_cred_num)?;

        let rev_reg = Issuer::_new_revocation_registry(cred_rev_pub_key,
                                                       &rev_key_priv,
                                                       max_cred_num,
                                                       issuance_by_default)?;

        let rev_tails_generator = RevocationTailsGenerator::new(
            max_cred_num,
            rev_key_priv.gamma.clone(),
            cred_rev_pub_key.g_dash.clone());

        trace!("Issuer::new_revocation_registry_def: <<< rev_key_pub: {:?}, rev_key_priv: {:?}, rev_reg: {:?}, rev_tails_generator: {:?}",
               rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);

        Ok((rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator))
    }

    /// Creates and returns credential values entity builder.
    ///
    /// The purpose of credential values builder is building of credential values entity that
    /// represents credential attributes values map.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_dec_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// credential_values_builder.add_dec_value("name", "1139481716457488690172217916278103335").unwrap();
    /// let _credential_values = credential_values_builder.finalize().unwrap();
    /// ```
    pub fn new_credential_values_builder() -> Result<CredentialValuesBuilder, IndyCryptoError> {
        let res = CredentialValuesBuilder::new()?;
        Ok(res)
    }

    /// Signs credential values with primary keys only.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_master_secret` - Blinded master secret generated by Prover.
    /// * `blinded_master_secret_correctness_proof` - Blinded master secret correctness proof.
    /// * `master_secret_blinding_nonce` - Nonce used for verification of blinded_master_secret_correctness_proof.
    /// * `credential_issuance_nonce` - Nonce used for creation of signature_correctness_proof.
    /// * `credential_values` - Claim values to be signed.
    /// * `credential_pub_key` - Credential public key.
    /// * `credential_priv_key` - Credential private key.
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
    /// let (blinded_master_secret, _, blinded_master_secret_correctness_proof) =
    ///      Prover::blind_master_secret(&credential_pub_key, &cred_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_dec_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (_credential_signature, _signature_correctness_proof) =
    ///     Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                             &blinded_master_secret,
    ///                             &blinded_master_secret_correctness_proof,
    ///                             &master_secret_blinding_nonce,
    ///                             &credential_issuance_nonce,
    ///                             &credential_values,
    ///                             &credential_pub_key,
    ///                             &credential_priv_key).unwrap();
    /// ```
    pub fn sign_credential(prover_id: &str,
                           blinded_credential_secrets: &BlindedCredentialSecrets,
                           blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
                           credential_nonce: &Nonce,
                           credential_issuance_nonce: &Nonce,
                           credential_values: &CredentialValues,
                           credential_pub_key: &CredentialPublicKey,
                           credential_priv_key: &CredentialPrivateKey) -> Result<(CredentialSignature, SignatureCorrectnessProof), IndyCryptoError> {
        trace!("Issuer::sign_credential: >>> prover_id: {:?}, \
                                             blinded_credential_secrets: {:?}, \
                                             blinded_credential_secrets_correctness_proof: {:?}, \
                                             credential_nonce: {:?}, \
                                             credential_issuance_nonce: {:?}, \
                                             credential_values: {:?}, \
                                             credential_pub_key: {:?}, \
                                             credential_priv_key: {:?}",
                                            prover_id,
                                            blinded_credential_secrets,
                                            blinded_credential_secrets_correctness_proof,
                                            credential_nonce,
                                            credential_values,
                                            credential_issuance_nonce,
                                            credential_pub_key,
                                            credential_priv_key);

        Issuer::_check_blinded_credential_secrets_correctness_proof(blinded_credential_secrets,
                                                                    blinded_credential_secrets_correctness_proof,
                                                                    credential_nonce,
                                                                    &credential_pub_key.p_key)?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, None)?;

        let (p_cred, q) = Issuer::_new_primary_credential(&cred_context,
                                                          credential_pub_key,
                                                          credential_priv_key,
                                                          blinded_credential_secrets,
                                                          credential_values)?;

        let cred_signature = CredentialSignature { p_credential: p_cred, r_credential: None };

        let signature_correctness_proof = Issuer::_new_signature_correctness_proof(&credential_pub_key.p_key,
                                                                                   &credential_priv_key.p_key,
                                                                                   &cred_signature.p_credential,
                                                                                   &q,
                                                                                   credential_issuance_nonce)?;


        trace!("Issuer::sign_credential: <<< cred_signature: {:?}, signature_correctness_proof: {:?}",
               cred_signature, signature_correctness_proof);

        Ok((cred_signature, signature_correctness_proof))
    }

    /// Signs credential values with both primary and revocation keys.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_master_secret` - Blinded master secret generated by Prover.
    /// * `blinded_master_secret_correctness_proof` - Blinded master secret correctness proof.
    /// * `master_secret_blinding_nonce` - Nonce used for verification of blinded_master_secret_correctness_proof.
    /// * `credential_issuance_nonce` - Nonce used for creation of signature_correctness_proof.
    /// * `credential_values` - Claim values to be signed.
    /// * `credential_pub_key` - Credential public key.
    /// * `credential_priv_key` - Credential private key.
    /// * `rev_idx` - User index in revocation accumulator. Required for non-revocation credential_signature part generation.
    /// * `max_cred_num` - Max credential number in generated registry.
    /// * `rev_reg` - Revocation registry.
    /// * `rev_key_priv` - Revocation registry private key.
    /// * `rev_tails_accessor` - Revocation registry tails accessor.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::{new_nonce, SimpleTailsAccessor};
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_master_secret, _master_secret_blinding_data, blinded_master_secret_correctness_proof) =
    ///     Prover::blind_master_secret(&cred_pub_key, &cred_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_master_secret,
    ///                                        &blinded_master_secret_correctness_proof,
    ///                                        &master_secret_blinding_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        1,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                        &simple_tail_accessor).unwrap();
    /// ```
    pub fn sign_credential_with_revoc<RTA>(prover_id: &str,
                                           blinded_credential_secrets: &BlindedCredentialSecrets,
                                           blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
                                           credential_nonce: &Nonce,
                                           credential_issuance_nonce: &Nonce,
                                           credential_values: &CredentialValues,
                                           credential_pub_key: &CredentialPublicKey,
                                           credential_priv_key: &CredentialPrivateKey,
                                           rev_idx: u32,
                                           max_cred_num: u32,
                                           issuance_by_default: bool,
                                           rev_reg: &mut RevocationRegistry,
                                           rev_key_priv: &RevocationKeyPrivate,
                                           rev_tails_accessor: &RTA)
                                           -> Result<(CredentialSignature, SignatureCorrectnessProof, Option<RevocationRegistryDelta>),
                                               IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Issuer::sign_credential: >>> prover_id: {:?}, blinded_master_secret: {:?}, blinded_master_secret_correctness_proof: {:?},\
        master_secret_blinding_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        rev_idx: {:?}, max_cred_num: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
               prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof, credential_nonce, credential_values, credential_issuance_nonce,
               credential_pub_key, credential_priv_key, rev_idx, max_cred_num, rev_reg, rev_key_priv);

        Issuer::_check_blinded_credential_secrets_correctness_proof(blinded_credential_secrets,
                                                                    blinded_credential_secrets_correctness_proof,
                                                                    credential_nonce,
                                                                    &credential_pub_key.p_key)?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, Some(rev_idx))?;

        let (p_cred, q) = Issuer::_new_primary_credential(&cred_context,
                                                          credential_pub_key,
                                                          credential_priv_key,
                                                          blinded_credential_secrets,
                                                          credential_values)?;

        let (r_cred, rev_reg_delta) = Issuer::_new_non_revocation_credential(rev_idx,
                                                                             &cred_context,
                                                                             blinded_credential_secrets,
                                                                             credential_pub_key,
                                                                             credential_priv_key,
                                                                             max_cred_num,
                                                                             issuance_by_default,
                                                                             rev_reg,
                                                                             rev_key_priv,
                                                                             rev_tails_accessor)?;

        let cred_signature = CredentialSignature { p_credential: p_cred, r_credential: Some(r_cred) };

        let signature_correctness_proof = Issuer::_new_signature_correctness_proof(&credential_pub_key.p_key,
                                                                                   &credential_priv_key.p_key,
                                                                                   &cred_signature.p_credential,
                                                                                   &q,
                                                                                   credential_issuance_nonce)?;


        trace!("Issuer::sign_credential: <<< cred_signature: {:?}, signature_correctness_proof: {:?}, rev_reg_delta: {:?}",
               cred_signature, signature_correctness_proof, rev_reg_delta);

        Ok((cred_signature, signature_correctness_proof, rev_reg_delta))
    }

    /// Revokes a credential by a rev_idx in a given revocation registry.
    ///
    /// # Arguments
    /// * `rev_reg` - Revocation registry.
    /// * `max_cred_num` - Max credential number in revocation registry.
    ///  * rev_idx` - Index of the user in the revocation registry.
    /// * `rev_tails_accessor` - Revocation registry tails accessor.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::{new_nonce, SimpleTailsAccessor};
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_master_secret, _master_secret_blinding_data, blinded_master_secret_correctness_proof) =
    ///     Prover::blind_master_secret(&cred_pub_key, &cred_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let rev_idx = 1;
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_master_secret,
    ///                                        &blinded_master_secret_correctness_proof,
    ///                                        &master_secret_blinding_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        rev_idx,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                         &simple_tail_accessor).unwrap();
    /// Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor).unwrap();
    /// ```
    pub fn revoke_credential<RTA>(rev_reg: &mut RevocationRegistry,
                                  max_cred_num: u32,
                                  rev_idx: u32,
                                  rev_tails_accessor: &RTA) -> Result<RevocationRegistryDelta, IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Issuer::revoke_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}", rev_reg, max_cred_num, rev_idx);

        let prev_accum = rev_reg.accum.clone();

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        rev_tails_accessor.access_tail(index, &mut |tail| {
            rev_reg.accum = rev_reg.accum.sub(tail).unwrap();
        })?;

        let rev_reg_delta = RevocationRegistryDelta {
            prev_accum: Some(prev_accum),
            accum: rev_reg.accum.clone(),
            issued: HashSet::new(),
            revoked: hashset![rev_idx]
        };

        trace!("Issuer::revoke_credential: <<< rev_reg_delta: {:?}", rev_reg_delta);

        Ok(rev_reg_delta)
    }

    /// Recovery a credential by a rev_idx in a given revocation registry
    ///
    /// # Arguments
    /// * `rev_reg` - Revocation registry.
    /// * `max_cred_num` - Max credential number in revocation registry.
    ///  * rev_idx` - Index of the user in the revocation registry.
    /// * `rev_tails_accessor` - Revocation registry tails accessor.
    ///
    pub fn recovery_credential<RTA>(rev_reg: &mut RevocationRegistry,
                                    max_cred_num: u32,
                                    rev_idx: u32,
                                    rev_tails_accessor: &RTA) -> Result<RevocationRegistryDelta, IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Issuer::recovery_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}", rev_reg, max_cred_num, rev_idx);

        let prev_accum = rev_reg.accum.clone();

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        rev_tails_accessor.access_tail(index, &mut |tail| {
            rev_reg.accum = rev_reg.accum.add(tail).unwrap();
        })?;

        let rev_reg_delta = RevocationRegistryDelta {
            prev_accum: Some(prev_accum),
            accum: rev_reg.accum.clone(),
            issued: hashset![rev_idx],
            revoked: HashSet::new()
        };

        trace!("Issuer::recovery_credential: <<< rev_reg_delta: {:?}", rev_reg_delta);

        Ok(rev_reg_delta)
    }

    fn _new_credential_primary_keys(credential_schema: &CredentialSchema) -> Result<(CredentialPrimaryPublicKey,
                                                                                     CredentialPrimaryPrivateKey,
                                                                                     CredentialPrimaryPublicKeyMetadata), IndyCryptoError> {
        trace!("Issuer::_new_credential_primary_keys: >>> credential_schema: {:?}", credential_schema);

        let mut ctx = BigNumber::new_context()?;

        if credential_schema.attrs.len() == 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("List of attributes is empty")));
        }

        let p_safe = generate_safe_prime(LARGE_PRIME)?;
        let q_safe = generate_safe_prime(LARGE_PRIME)?;

        let mut p = p_safe.sub(&BigNumber::from_u32(1)?)?;
        p.div_word(2)?;

        let mut q = q_safe.sub(&BigNumber::from_u32(1)?)?;
        q.div_word(2)?;

        let n = p_safe.mul(&q_safe, Some(&mut ctx))?;
        let s = random_qr(&n)?;
        let xz = gen_x(&p, &q)?;

        let mut xr = BTreeMap::new();
        for attribute in &credential_schema.attrs {
            xr.insert(attribute.to_string(), gen_x(&p, &q)?);
        }

        let mut r = BTreeMap::new();
        for (key, xr_value) in xr.iter() {
            r.insert(key.to_string(), s.mod_exp(&xr_value, &n, Some(&mut ctx))?);
        }

        let z = s.mod_exp(&xz, &n, Some(&mut ctx))?;

        let rctxt = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;

        let cred_pr_pub_key = CredentialPrimaryPublicKey { n, s, rctxt, r, z };
        let cred_pr_priv_key = CredentialPrimaryPrivateKey { p, q };
        let cred_pr_pub_key_metadata = CredentialPrimaryPublicKeyMetadata { xz, xr };

        trace!("Issuer::_new_credential_primary_keys: <<< cred_pr_pub_key: {:?}, cred_pr_priv_key: {:?}, cred_pr_pub_key_metadata: {:?}",
               cred_pr_pub_key, cred_pr_priv_key, cred_pr_pub_key_metadata);

        Ok((cred_pr_pub_key, cred_pr_priv_key, cred_pr_pub_key_metadata))
    }

    fn _new_credential_revocation_keys() -> Result<(CredentialRevocationPublicKey,
                                                    CredentialRevocationPrivateKey), IndyCryptoError> {
        trace!("Issuer::_new_credential_revocation_keys: >>>");

        let h = PointG1::new()?;
        let h0 = PointG1::new()?;
        let h1 = PointG1::new()?;
        let h2 = PointG1::new()?;
        let htilde = PointG1::new()?;
        let g = PointG1::new()?;

        let u = PointG2::new()?;
        let h_cap = PointG2::new()?;

        let x = GroupOrderElement::new()?;
        let sk = GroupOrderElement::new()?;
        let g_dash = PointG2::new()?;

        let pk = g.mul(&sk)?;
        let y = h_cap.mul(&x)?;

        let cred_rev_pub_key = CredentialRevocationPublicKey { g, g_dash, h, h0, h1, h2, htilde, h_cap, u, pk, y };
        let cred_rev_priv_key = CredentialRevocationPrivateKey { x, sk };

        trace!("Issuer::_new_credential_revocation_keys: <<< cred_rev_pub_key: {:?}, cred_rev_priv_key: {:?}", cred_rev_pub_key, cred_rev_priv_key);

        Ok((cred_rev_pub_key, cred_rev_priv_key))
    }

    fn _new_credential_key_correctness_proof(cred_pr_pub_key: &CredentialPrimaryPublicKey,
                                             cred_pr_priv_key: &CredentialPrimaryPrivateKey,
                                             cred_pr_pub_key_meta: &CredentialPrimaryPublicKeyMetadata) -> Result<CredentialKeyCorrectnessProof, IndyCryptoError> {
        trace!("Issuer::_new_credential_key_correctness_proof: >>> cred_pr_pub_key: {:?}, cred_pr_priv_key: {:?}, cred_pr_pub_key_meta: {:?}",
               cred_pr_pub_key, cred_pr_priv_key, cred_pr_pub_key_meta);

        let mut ctx = BigNumber::new_context()?;

        let xz_tilda = gen_x(&cred_pr_priv_key.p, &cred_pr_priv_key.q)?;

        let mut xr_tilda = BTreeMap::new();
        for key in cred_pr_pub_key.r.keys() {
            xr_tilda.insert(key.to_string(), gen_x(&cred_pr_priv_key.p, &cred_pr_priv_key.q)?);
        }

        let z_tilda = cred_pr_pub_key.s.mod_exp(&xz_tilda, &cred_pr_pub_key.n, Some(&mut ctx))?;

        let mut r_tilda = BTreeMap::new();
        for (key, xr_tilda_value) in xr_tilda.iter() {
            r_tilda.insert(key.to_string(), cred_pr_pub_key.s.mod_exp(&xr_tilda_value, &cred_pr_pub_key.n, Some(&mut ctx))?);
        }

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&cred_pr_pub_key.z.to_bytes()?);
        for val in cred_pr_pub_key.r.values() {
            values.extend_from_slice(&val.to_bytes()?);
        }
        values.extend_from_slice(&z_tilda.to_bytes()?);
        for val in r_tilda.values() {
            values.extend_from_slice(&val.to_bytes()?);
        }

        let c = get_hash_as_int(&mut vec![values])?;

        let xz_cap =
            c.mul(&cred_pr_pub_key_meta.xz, Some(&mut ctx))?
                .add(&xz_tilda)?;

        let mut xr_cap: BTreeMap<String, BigNumber> = BTreeMap::new();
        for (key, xr_tilda_value) in xr_tilda {
            let val =
                c.mul(&cred_pr_pub_key_meta.xr[&key], Some(&mut ctx))?
                    .add(&xr_tilda_value)?;
            xr_cap.insert(key.to_string(), val);
        }

        let key_correctness_proof = CredentialKeyCorrectnessProof { c, xz_cap, xr_cap };

        trace!("Issuer::_new_credential_key_correctness_proof: <<< key_correctness_proof: {:?}", key_correctness_proof);

        Ok(key_correctness_proof)
    }

    fn _new_revocation_registry(cred_rev_pub_key: &CredentialRevocationPublicKey,
                                rev_key_priv: &RevocationKeyPrivate,
                                max_cred_num: u32,
                                issuance_by_default: bool) -> Result<RevocationRegistry, IndyCryptoError> {
        trace!("Issuer::_new_revocation_registry: >>> cred_rev_pub_key: {:?}, rev_key_priv: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}",
               cred_rev_pub_key, rev_key_priv, max_cred_num, issuance_by_default);

        let mut accum = Accumulator::new_inf()?;

        if issuance_by_default {
            for i in 1..max_cred_num + 1 {
                let index = Issuer::_get_index(max_cred_num, i);
                accum = accum.add(&Tail::new_tail(index, &cred_rev_pub_key.g_dash, &rev_key_priv.gamma)?)?;
            }
        };

        let rev_reg = RevocationRegistry {
            accum
        };

        trace!("Issuer::_new_revocation_registry: <<< rev_reg: {:?}", rev_reg);

        Ok(rev_reg)
    }

    fn _new_revocation_registry_keys(cred_rev_pub_key: &CredentialRevocationPublicKey,
                                     max_cred_num: u32) -> Result<(RevocationKeyPublic, RevocationKeyPrivate), IndyCryptoError> {
        trace!("Issuer::_new_revocation_registry_keys: >>> cred_rev_pub_key: {:?}, max_cred_num: {:?}",
               cred_rev_pub_key, max_cred_num);

        let gamma = GroupOrderElement::new()?;

        let mut z = Pair::pair(&cred_rev_pub_key.g, &cred_rev_pub_key.g_dash)?;
        let mut pow = GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(max_cred_num + 1))?;
        pow = gamma.pow_mod(&pow)?;
        z = z.pow(&pow)?;

        let rev_key_pub = RevocationKeyPublic { z };
        let rev_key_priv = RevocationKeyPrivate { gamma };

        trace!("Issuer::_new_revocation_registry_keys: <<< rev_key_pub: {:?}, rev_key_priv: {:?}", rev_key_pub, rev_key_priv);

        Ok((rev_key_pub, rev_key_priv))
    }

    fn _check_blinded_credential_secrets_correctness_proof(blinded_cred_secrets: &BlindedCredentialSecrets,
                                                           blinded_cred_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
                                                           nonce: &Nonce,
                                                           cred_pr_pub_key: &CredentialPrimaryPublicKey) -> Result<(), IndyCryptoError> {
        trace!("Issuer::_check_blinded_credential_secrets_correctness_proof: >>> blinded_cred_secrets: {:?}, blinded_cred_secrets_correctness_proof: {:?},\
         nonce: {:?}, cred_pr_pub_key: {:?}", blinded_cred_secrets, blinded_cred_secrets_correctness_proof, nonce, cred_pr_pub_key);

        let mut values: Vec<u8> = Vec::new();
        let mut ctx = BigNumber::new_context()?;

        let mut u_cap =
            blinded_cred_secrets.u
                .inverse(&cred_pr_pub_key.n, Some(&mut ctx))?
                .mod_exp(&blinded_cred_secrets_correctness_proof.c, &cred_pr_pub_key.n, Some(&mut ctx))?
                .mod_mul(
                    &cred_pr_pub_key.s.mod_exp(&blinded_cred_secrets_correctness_proof.v_dash_cap, &cred_pr_pub_key.n, Some(&mut ctx))?,
                    &cred_pr_pub_key.n,
                    Some(&mut ctx)
                )?;

        for (key, value) in &blinded_cred_secrets.committed_attributes {
            let pk_r = cred_pr_pub_key.r
                .get(key)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", key)))?;

            let m_cap = &blinded_cred_secrets_correctness_proof.m_caps[key];

            u_cap = u_cap.mod_mul(&pk_r.mod_exp(&m_cap, &cred_pr_pub_key.n, Some(&mut ctx))?,
                                  &cred_pr_pub_key.n, Some(&mut ctx))?;

            let comm_att_cap = value.inverse(&cred_pr_pub_key.n, Some(&mut ctx))?
                                    .mod_exp(&blinded_cred_secrets_correctness_proof.c, &cred_pr_pub_key.n, Some(&mut ctx))?
                                    .mod_mul(&get_pedersen_commitment(&cred_pr_pub_key.z, &m_cap,
                                                                      &cred_pr_pub_key.s, &blinded_cred_secrets_correctness_proof.r_caps[key],
                                                                      &cred_pr_pub_key.n, &mut ctx)?,
                                             &cred_pr_pub_key.n, Some(&mut ctx))?;

            values.extend_from_slice(&comm_att_cap.to_bytes()?);
            values.extend_from_slice(&value.to_bytes()?);
        }


        values.extend_from_slice(&blinded_cred_secrets.u.to_bytes()?);
        values.extend_from_slice(&u_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&vec![values])?;

        let valid = blinded_cred_secrets_correctness_proof.c.eq(&c);

        if !valid {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid BlindedCredentialSecrets correctness proof")));
        }

        trace!("Issuer::_check_blinded_credential_secrets_correctness_proof: <<<");

        Ok(())
    }

    // In the anoncreds whitepaper, `credential context` is denoted by `m2`
    fn _gen_credential_context(prover_id: &str, rev_idx: Option<u32>) -> Result<BigNumber, IndyCryptoError> {
        trace!("Issuer::_calc_m2: >>> prover_id: {:?}, rev_idx: {:?}", prover_id, rev_idx);

        let rev_idx = rev_idx.map(|i| i as i32).unwrap_or(-1);

        let prover_id_bn = encode_attribute(prover_id, ByteOrder::Little)?;
        let rev_idx_bn = encode_attribute(&rev_idx.to_string(), ByteOrder::Little)?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&prover_id_bn.to_bytes()?);
        values.extend_from_slice(&rev_idx_bn.to_bytes()?);

        let credential_context = get_hash_as_int(&mut vec![values])?;

        trace!("Issuer::_gen_credential_context: <<< credential_context: {:?}", credential_context);

        Ok(credential_context)
    }

    fn _new_primary_credential(credential_context: &BigNumber,
                               cred_pub_key: &CredentialPublicKey,
                               cred_priv_key: &CredentialPrivateKey,
                               blinded_credential_secrets: &BlindedCredentialSecrets,
                               cred_values: &CredentialValues) -> Result<(PrimaryCredentialSignature, BigNumber), IndyCryptoError> {
        trace!("Issuer::_new_primary_credential: >>> credential_context: {:?}, cred_pub_key: {:?}, cred_priv_key: {:?}, blinded_ms: {:?},\
         cred_values: {:?}", credential_context, cred_pub_key, cred_priv_key, blinded_credential_secrets, cred_values);

        let v = generate_v_prime_prime()?;

        let e_start = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_E_START)?, None)?;
        let e_end = BigNumber::from_u32(2)?
            .exp(&BigNumber::from_u32(LARGE_E_END_RANGE)?, None)?
            .add(&e_start)?;

        let e = generate_prime_in_range(&e_start, &e_end)?;
        let (a, q) = Issuer::_sign_primary_credential(cred_pub_key, cred_priv_key, &credential_context, &cred_values, &v, blinded_credential_secrets, &e)?;

        let pr_cred_sig = PrimaryCredentialSignature { m_2: credential_context.clone()?, a, e, v };

        trace!("Issuer::_new_primary_credential: <<< pr_cred_sig: {:?}, q: {:?}", pr_cred_sig, q);

        Ok((pr_cred_sig, q))
    }

    fn _sign_primary_credential(cred_pub_key: &CredentialPublicKey,
                                cred_priv_key: &CredentialPrivateKey,
                                cred_context: &BigNumber,
                                cred_values: &CredentialValues,
                                v: &BigNumber,
                                blinded_cred_secrets: &BlindedCredentialSecrets,
                                e: &BigNumber) -> Result<(BigNumber, BigNumber), IndyCryptoError> {
        trace!("Issuer::_sign_primary_credential: >>> cred_pub_key: {:?}, cred_priv_key: {:?}, cred_context: {:?}, cred_values: {:?}, v: {:?},\
         blnd_ms: {:?}, e: {:?}", cred_pub_key, cred_priv_key, cred_context, cred_values, v, blinded_cred_secrets, e);

        let p_pub_key = &cred_pub_key.p_key;
        let p_priv_key = &cred_priv_key.p_key;

        let mut context = BigNumber::new_context()?;

        let mut rx = p_pub_key.s
            .mod_exp(&v, &p_pub_key.n, Some(&mut context))?;

        if blinded_cred_secrets.u != BigNumber::from_u32(0)? {
            rx = blinded_cred_secrets.u.modulus(&p_pub_key.n, Some(&mut context))?
                .mul(&rx, Some(&mut context))?;
        }

        rx = p_pub_key.rctxt.mod_exp(&cred_context, &p_pub_key.n, Some(&mut context))?
            .mul(&rx, Some(&mut context))?;

        for (key, attr) in cred_values.attrs_values.iter().filter(|&(_, v)| v.blinding_factor.is_none()) {
            let pk_r = p_pub_key.r
                .get(key)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", key)))?;

            rx = pk_r.mod_exp(&attr.value, &p_pub_key.n, Some(&mut context))?
                .mod_mul(&rx, &p_pub_key.n, Some(&mut context))?;
        }

        let q = p_pub_key.z.mod_div(&rx, &p_pub_key.n)?;

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut context))?;
        let e_inverse = e.inverse(&n, Some(&mut context))?;

        let a = q.mod_exp(&e_inverse, &p_pub_key.n, Some(&mut context))?;

        trace!("Issuer::_sign_primary_credential: <<< a: {:?}, q: {:?}", a, q);

        Ok((a, q))
    }

    fn _new_signature_correctness_proof(p_pub_key: &CredentialPrimaryPublicKey,
                                        p_priv_key: &CredentialPrimaryPrivateKey,
                                        p_cred_signature: &PrimaryCredentialSignature,
                                        q: &BigNumber,
                                        nonce: &BigNumber) -> Result<SignatureCorrectnessProof, IndyCryptoError> {
        trace!("Issuer::_new_signature_correctness_proof: >>> p_pub_key: {:?}, p_priv_key: {:?}, p_cred_signature: {:?}, q: {:?}, nonce: {:?}",
               p_pub_key, p_priv_key, p_cred_signature, q, nonce);

        let mut ctx = BigNumber::new_context()?;

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut ctx))?;
        let r = bn_rand_range(&n)?;

        let a_cap = q.mod_exp(&r, &p_pub_key.n, Some(&mut ctx))?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&q.to_bytes()?);
        values.extend_from_slice(&p_cred_signature.a.to_bytes()?);
        values.extend_from_slice(&a_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&mut vec![values])?;

        let se = r.mod_sub(
            &c.mod_mul(&p_cred_signature.e.inverse(&n, Some(&mut ctx))?, &n, Some(&mut ctx))?,
            &n,
            Some(&mut ctx)
        )?;

        let signature_correctness_proof = SignatureCorrectnessProof { c, se };

        trace!("Issuer::_new_signature_correctness_proof: <<< signature_correctness_proof: {:?}", signature_correctness_proof);

        Ok(signature_correctness_proof)
    }

    fn _get_index(max_cred_num: u32, rev_idx: u32) -> u32 {
        max_cred_num + 1 - rev_idx
    }

    fn _new_non_revocation_credential(rev_idx: u32,
                                      cred_context: &BigNumber,
                                      blinded_credential_secrets: &BlindedCredentialSecrets,
                                      cred_pub_key: &CredentialPublicKey,
                                      cred_priv_key: &CredentialPrivateKey,
                                      max_cred_num: u32,
                                      issuance_by_default: bool,
                                      rev_reg: &mut RevocationRegistry,
                                      rev_key_priv: &RevocationKeyPrivate,
                                      rev_tails_accessor: &RevocationTailsAccessor)
                                      -> Result<(NonRevocationCredentialSignature, Option<RevocationRegistryDelta>), IndyCryptoError> {
        trace!("Issuer::_new_non_revocation_credential: >>> rev_idx: {:?}, cred_context: {:?}, blinded_ms: {:?}, cred_pub_key: {:?}, cred_priv_key: {:?}, \
        max_cred_num: {:?}, issuance_by_default: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
               rev_idx, cred_context, blinded_credential_secrets, cred_pub_key, cred_priv_key, max_cred_num, issuance_by_default, rev_reg, rev_key_priv);

        let ur = blinded_credential_secrets.ur
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in blinded master secret.")))?;

        let r_pub_key: &CredentialRevocationPublicKey = cred_pub_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in credential revocation public key.")))?;

        let r_priv_key: &CredentialRevocationPrivateKey = cred_priv_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in credential revocation private key.")))?;

        let vr_prime_prime = GroupOrderElement::new()?;
        let c = GroupOrderElement::new()?;
        let m2 = GroupOrderElement::from_bytes(&cred_context.to_bytes()?)?;

        let g_i = {
            let i_bytes = transform_u32_to_array_of_u8(rev_idx);
            let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
            pow = rev_key_priv.gamma.pow_mod(&pow)?;
            r_pub_key.g.mul(&pow)?
        };

        let sigma =
            r_pub_key.h0.add(&r_pub_key.h1.mul(&m2)?)?
                .add(&ur)?
                .add(&g_i)?
                .add(&r_pub_key.h2.mul(&vr_prime_prime)?)?
                .mul(&r_priv_key.x.add_mod(&c)?.inverse()?)?;


        let sigma_i = r_pub_key.g_dash
            .mul(&r_priv_key.sk
                .add_mod(&rev_key_priv.gamma
                    .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(rev_idx))?)?)?
                .inverse()?)?;
        let u_i = r_pub_key.u
            .mul(&rev_key_priv.gamma
                .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(rev_idx))?)?)?;

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        let rev_reg_delta = if issuance_by_default {
            None
        } else {
            let prev_acc = rev_reg.accum.clone();

            rev_tails_accessor.access_tail(index, &mut |tail| {
                rev_reg.accum = rev_reg.accum.add(tail).unwrap();
            })?;

            Some(RevocationRegistryDelta {
                prev_accum: Some(prev_acc),
                accum: rev_reg.accum.clone(),
                issued: hashset![rev_idx],
                revoked: HashSet::new()
            })
        };

        let witness_signature = WitnessSignature {
            sigma_i,
            u_i,
            g_i: g_i.clone(),
        };

        let non_revocation_cred_sig = NonRevocationCredentialSignature {
            sigma,
            c,
            vr_prime_prime,
            witness_signature,
            g_i: g_i.clone(),
            i: rev_idx,
            m2
        };

        trace!("Issuer::_new_non_revocation_credential: <<< non_revocation_cred_sig: {:?}, rev_reg_delta: {:?}",
               non_revocation_cred_sig, rev_reg_delta);

        Ok((non_revocation_cred_sig, rev_reg_delta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::prover::*;
    use cl::prover::mocks::*;
    use cl::issuer::{Issuer, mocks};
    use cl::helpers::MockHelper;

    #[test]
    fn generate_context_attribute_works() {
        let rev_idx = 110;
        let user_id = "111";
        //let answer = BigNumber::from_dec("31894574610223295263712513093148707509913459424901632064286025736442349335521").unwrap();
        let result = Issuer::_gen_credential_context(user_id, Some(rev_idx)).unwrap();
        assert_eq!(result, mocks::context_attribute());
    }

    #[test]
    fn credential_schema_builder_works() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        assert!(credential_schema.attrs.contains("sex"));
        assert!(credential_schema.attrs.contains("name"));
        assert!(credential_schema.attrs.contains("age"));
        assert!(!credential_schema.attrs.contains("height"));
    }

    #[test]
    fn credential_values_builder_works() {
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_dec_value("sex", "89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        credential_values_builder.add_dec_value("name", "58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let credential_values = credential_values_builder.finalize().unwrap();

        assert!(credential_values.attrs_values.get("sex").unwrap().value.eq(&BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap()));
        assert!(credential_values.attrs_values.get("name").unwrap().value.eq(&BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap()));
        assert!(credential_values.attrs_values.get("age").is_none());
    }

    #[test]
    fn issuer_new_credential_def_works() {
        MockHelper::inject();

        let (pub_key, priv_key, key_correctness_proof) = Issuer::new_credential_def(&prover::mocks::credential_schema(), true).unwrap();
        assert_eq!(pub_key.p_key, mocks::credential_primary_public_key());
        assert_eq!(priv_key.p_key, mocks::credential_primary_private_key());
        assert_eq!(key_correctness_proof, mocks::credential_key_correctness_proof());
        assert!(pub_key.r_key.is_some());
        assert!(priv_key.r_key.is_some());
    }

    #[test]
    fn issuer_new_credential_def_works_without_revocation_part() {
        MockHelper::inject();

        let (pub_key, priv_key, key_correctness_proof) = Issuer::new_credential_def(&prover::mocks::credential_schema(), false).unwrap();
        assert_eq!(pub_key.p_key, mocks::credential_primary_public_key());
        assert_eq!(priv_key.p_key, mocks::credential_primary_private_key());
        assert_eq!(key_correctness_proof, mocks::credential_key_correctness_proof());
        assert!(pub_key.r_key.is_none());
        assert!(priv_key.r_key.is_none());
    }

    #[test]
    fn issuer_new_credential_works_for_empty_attributes() {
        let cred_attrs = CredentialSchema { attrs: HashSet::new() };
        let res = Issuer::new_credential_def(&cred_attrs, false);
        assert!(res.is_err())
    }

    #[test]
    fn issuer_new_revocation_registry_def_works() {
        MockHelper::inject();

        let (pub_key, _, _) = Issuer::new_credential_def(&prover::mocks::credential_schema(), true).unwrap();
        Issuer::new_revocation_registry_def(&pub_key, 100, false).unwrap();
    }

    #[test]
    fn sign_primary_credential_works() {
        MockHelper::inject();

        let (pub_key, secret_key) = (mocks::credential_public_key(), mocks::credential_private_key());

        let v = BigNumber::from_dec("5237513942984418438429595379849430501110274945835879531523435677101657022026899212054747703201026332785243221088006425007944260107143086435227014329174143861116260506019310628220538205630726081406862023584806749693647480787838708606386447727482772997839699379017499630402117304253212246286800412454159444495341428975660445641214047184934669036997173182682771745932646179140449435510447104436243207291913322964918630514148730337977117021619857409406144166574010735577540583316493841348453073326447018376163876048624924380855323953529434806898415857681702157369526801730845990252958130662749564283838280707026676243727830151176995470125042111348846500489265328810592848939081739036589553697928683006514398844827534478669492201064874941684905413964973517155382540340695991536826170371552446768460042588981089470261358687308").unwrap();

        let u = BigNumber::from_dec("72637991796589957272144423539998982864769854130438387485781642285237707120228376409769221961371420625002149758076600738245408098270501483395353213773728601101770725294535792756351646443825391806535296461087756781710547778467803194521965309091287301376623972321639262276779134586366620773325502044026364814032821517244814909708610356590687571152567177116075706850536899272749781370266769562695357044719529245223811232258752001942940813585440938291877640445002571323841625932424781535818087233087621479695522263178206089952437764196471098717335358765920438275944490561172307673744212256272352897964947435086824617146019").unwrap();
        let e = BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930214202955935602153431795703076242907").unwrap();

        let expected_signature = BigNumber::from_dec("51756877575661148119436429527229232604266086511502575413412002534598934802004159904626151244214143371787509047155192345964327778969905246151551428601982401245522489230370314496872571578700213125523785664883126408955420645953005298828726807444268872401346082286518152302793210246882726731654840910733196012340887910970351041188100147914556098014360907911127670736409504899168470236932678670431665564917039680753109891635515871262504254940428913003076259073402198278806650239709758730044004765156116522738338492773204490799479627784334290416983709204164043893918903877361220225484590579312505417126696646719987559025339").unwrap();
        let expected_q = BigNumber::from_dec("16139740091002525376476960748446138506164394309014165623190613620281377599818592081324765874784138849517889721361960958517284509280078706212100445514589711416397573656059295333273664393098035956170804601100114047461165900802596404452552133379339701657829499968771458503092237095880773885848638486488094864010596691291013460125552172352885198107160911327813308005823130470173369690828583682567455987292427266665791977359788243875135194042918385739183491267761055668664761800711502396184655897636007586520719134683428079978647529342180101721740937797422915134751176194262289677437189457839080022551742241490221575806035").unwrap();


        let (credential_signature, q) = Issuer::_sign_primary_credential(&pub_key,
                                                                         &secret_key,
                                                                         &mocks::context_attribute(),
                                                                         &prover::mocks::credential_values(),
                                                                         &v,
                                                                         &BlindedCredentialSecrets { u: u, ur: None, committed_attributes: BTreeMap::new() },
                                                                         &e).unwrap();
        assert_eq!(expected_signature, credential_signature);
        assert_eq!(expected_q, q);
    }

    #[test]
    fn sign_credential_signature_works() {
        MockHelper::inject();

        let (credential_signature_signature, signature_correctness_proof) = Issuer::sign_credential(&prover::mocks::PROVER_DID,
                                                                                                    &prover::mocks::blinded_credential_secrets(),
                                                                                                    &prover::mocks::blinded_credential_secrets_correctness_proof(),
                                                                                                    &prover::mocks::credential_nonce(),
                                                                                                    &mocks::credential_issuance_nonce(),
                                                                                                    &prover::mocks::credential_values(),
                                                                                                    &mocks::credential_public_key(),
                                                                                                    &mocks::credential_private_key()).unwrap();

        assert_eq!(mocks::primary_credential(), credential_signature_signature.p_credential);
        assert_eq!(mocks::signature_correctness_proof(), signature_correctness_proof);
    }
}

pub mod mocks {
    use super::*;
    use amcl::big::BIG;
    use cl::prover::mocks::*;

    pub fn context_attribute() -> BigNumber {
        BigNumber::from_dec("31894574610223295263712513093148707509913459424901632064286025736442349335521").unwrap()
    }

    pub fn credential_public_key() -> CredentialPublicKey {
        CredentialPublicKey {
            p_key: credential_primary_public_key(),
            r_key: Some(credential_revocation_public_key())
        }
    }

    pub fn credential_private_key() -> CredentialPrivateKey {
        CredentialPrivateKey {
            p_key: credential_primary_private_key(),
            r_key: Some(credential_revocation_private_key())
        }
    }

    pub fn credential_key_correctness_proof() -> CredentialKeyCorrectnessProof {
        CredentialKeyCorrectnessProof {
            c: BigNumber::from_dec("100106049974222168831996448086485741777991664124878758088584364203057899227900").unwrap(),
            xz_cap: BigNumber::from_dec("2177951602992237658370774270771544151326309421506803803347011698290069700739758331803454440686877762632306322517341667534699457677900159466927541605774666242106256241441561385139361113671097719444141941202229322436843690416655142638933496415525461448253192188503734703992168081943755289922530213540393375805611734439623129883511785278088605406827034155837883459256816520437946850409974727474744596063766785013734142024207309632886919442178649184579704290849897847640182586565090235350277878660904401656055938299842568444764871277431314404904719687380000097728978284082372724810000897936055872222738379038687142164851728982797063147471058300489840107375548275875433933947975617476030383356402138").unwrap(),
            xr_cap: btreemap![
                String::from("age") => BigNumber::from_dec("2177951602992237658370774270771544151326309421506803803347011698290069700739758331803454440686877762632306322517341667534699457677900159466927541605774666242106256241441561385139361113671097719444141941202229322436843690416655142638933496415525461448253192188503734703992168081943755289922530213540393375805611734439623129883511785278088605406827034155837883459256816520437946850409974727474744596063766785013734142024207309632886919442178649184579704290849897847640182586565090235350277878660904401656055938299842568444764871277431314404904719687380000097728978284082372724810000897936055872222738379038687142164851728982797063147471058300489840107375548275875433933947975617476030383356402138").unwrap(),
                String::from("gender") => BigNumber::from_dec("2177951602992237658370774270771544151326309421506803803347011698290069700739758331803454440686877762632306322517341667534699457677900159466927541605774666242106256241441561385139361113671097719444141941202229322436843690416655142638933496415525461448253192188503734703992168081943755289922530213540393375805611734439623129883511785278088605406827034155837883459256816520437946850409974727474744596063766785013734142024207309632886919442178649184579704290849897847640182586565090235350277878660904401656055938299842568444764871277431314404904719687380000097728978284082372724810000897936055872222738379038687142164851728982797063147471058300489840107375548275875433933947975617476030383356402138").unwrap(),
                String::from("height") => BigNumber::from_dec("2177951602992237658370774270771544151326309421506803803347011698290069700739758331803454440686877762632306322517341667534699457677900159466927541605774666242106256241441561385139361113671097719444141941202229322436843690416655142638933496415525461448253192188503734703992168081943755289922530213540393375805611734439623129883511785278088605406827034155837883459256816520437946850409974727474744596063766785013734142024207309632886919442178649184579704290849897847640182586565090235350277878660904401656055938299842568444764871277431314404904719687380000097728978284082372724810000897936055872222738379038687142164851728982797063147471058300489840107375548275875433933947975617476030383356402138").unwrap(),
                String::from("link_secret") => BigNumber::from_dec("2177951602992237658370774270771544151326309421506803803347011698290069700739758331803454440686877762632306322517341667534699457677900159466927541605774666242106256241441561385139361113671097719444141941202229322436843690416655142638933496415525461448253192188503734703992168081943755289922530213540393375805611734439623129883511785278088605406827034155837883459256816520437946850409974727474744596063766785013734142024207309632886919442178649184579704290849897847640182586565090235350277878660904401656055938299842568444764871277431314404904719687380000097728978284082372724810000897936055872222738379038687142164851728982797063147471058300489840107375548275875433933947975617476030383356402138").unwrap(),
                String::from("name") => BigNumber::from_dec("2177951602992237658370774270771544151326309421506803803347011698290069700739758331803454440686877762632306322517341667534699457677900159466927541605774666242106256241441561385139361113671097719444141941202229322436843690416655142638933496415525461448253192188503734703992168081943755289922530213540393375805611734439623129883511785278088605406827034155837883459256816520437946850409974727474744596063766785013734142024207309632886919442178649184579704290849897847640182586565090235350277878660904401656055938299842568444764871277431314404904719687380000097728978284082372724810000897936055872222738379038687142164851728982797063147471058300489840107375548275875433933947975617476030383356402138").unwrap(),
                String::from("policy_address") => BigNumber::from_dec("2177951602992237658370774270771544151326309421506803803347011698290069700739758331803454440686877762632306322517341667534699457677900159466927541605774666242106256241441561385139361113671097719444141941202229322436843690416655142638933496415525461448253192188503734703992168081943755289922530213540393375805611734439623129883511785278088605406827034155837883459256816520437946850409974727474744596063766785013734142024207309632886919442178649184579704290849897847640182586565090235350277878660904401656055938299842568444764871277431314404904719687380000097728978284082372724810000897936055872222738379038687142164851728982797063147471058300489840107375548275875433933947975617476030383356402138").unwrap()
            ]
        }
    }

    pub fn credential_primary_public_key() -> CredentialPrimaryPublicKey {
        CredentialPrimaryPublicKey {
	        n: BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap(),
	        s: BigNumber::from_dec("64684820421150545443421261645532741305438158267230326415141505826951816460650437611148133267480407958360035501128469885271549378871140475869904030424615175830170939416512594291641188403335834762737251794282186335118831803135149622404791467775422384378569231649224208728902565541796896860352464500717052768431523703881746487372385032277847026560711719065512366600220045978358915680277126661923892187090579302197390903902744925313826817940566429968987709582805451008234648959429651259809188953915675063700676546393568304468609062443048457324721450190021552656280473128156273976008799243162970386898307404395608179975243").unwrap(),
	        rctxt: BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap(),
	        z: BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap(),
	        r: btreemap![
                String::from("age") => BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap(),
                String::from("gender") => BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap(),
                String::from("height") => BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap(),
                String::from("link_secret") => BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap(),
                String::from("name") => BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap(),
                String::from("policy_address") => BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap()
            ]
        }
    }

    pub fn credential_primary_private_key() -> CredentialPrimaryPrivateKey {
        CredentialPrimaryPrivateKey {
            p: BigNumber::from_dec("149212738775716179659508649034140914067267873385650452563221860367878267143635191771233591587868730221903476199105022913859057555905442876114559838735355652672950963033972314646471235775711934244481758977047119803475879470383993713606231800156950590334088086141997103196482505556481059579729337361392854778311").unwrap(),
            q: BigNumber::from_dec("149212738775716179659508649034140914067267873385650452563221860367878267143635191771233591587868730221903476199105022913859057555905442876114559838735355652672950963033972314646471235775711934244481758977047119803475879470383993713606231800156950590334088086141997103196482505556481059579729337361392854778311").unwrap()
        }
    }

    pub fn credential() -> CredentialSignature {
        CredentialSignature {
            p_credential: primary_credential(),
            r_credential: Some(revocation_credential())
        }
    }

    pub fn credential_issuance_nonce() -> Nonce {
        BigNumber::from_dec("526193306511429638192053").unwrap()
    }

    pub fn primary_credential() -> PrimaryCredentialSignature {
        PrimaryCredentialSignature {
            m_2: BigNumber::from_dec("69277050336954731912953999596899794023422356864020449587821228635678593076726").unwrap(),
            a: BigNumber::from_dec("59576650729757014001266415495048651014371875592452607038291814388111315911848291102110497520252073850059895120162321101149178450199060886721905586280704576277966012808672880874635221160361161880289965721881196877768108586929304787520934823952926459697296988463659936307341225404107666757142995151042428995859916215979973310048071060845782364280443800907503315348117229725994495933944492229338552866398085646193855519664376641572721062419860464686594200135802645323748450574040748736978128316478992822369888152234869857797942929992424339164545866301175765533370751998934550269667261831972378348502681712036651084791677").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881").unwrap(),
            v: BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap(),
        }
    }

    pub fn signature_correctness_proof() -> SignatureCorrectnessProof {
        SignatureCorrectnessProof {
            se: BigNumber::from_dec("4359806026932570972005002115004855513137801468153085802103125699099444860429826876484720166943916292559705748243400038454199487701813056947328036252178846097182035089819748042108217580199840484192195237322364433335758552474189258678435709084101988569300000464092058396808235335766899155809860536554918318090107768660077903412447736854772189705952999215896097404770942536882338427022595773835184141181082311239554205460415598620866872509184547352850910248307574375129986682991907191337174610021802932720767462265749763393310672481596173511707065560430341217133432761604508275607240643678210464766905882622884364580783").unwrap(),
            c: BigNumber::from_dec("113042807352802523503228902412909354917179109592309864414288979689439382029834").unwrap()
        }
    }

    pub fn revocation_credential() -> NonRevocationCredentialSignature {
        NonRevocationCredentialSignature {
            sigma: PointG1::from_string("false C8C7213101C60F F625A22E65736C 695A1F398B4787 D087ABB966C5BC 1EA63E37 7895832C96B02C 60C7E086DFA7AF 1518CD71A957F3 C1BED176429FB9 11DD23B3 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            c: GroupOrderElement::from_string("4CF57E7A173E6 27720818863F49 D72801BCE5CBE9 7C8C588E2A8B3B 3642B08").unwrap(),
            vr_prime_prime: GroupOrderElement::from_string("2BC52B6D8B5F4B 26E57208D0DB35 D0411E4BE49639 18A8BC10BF946E 1F8689A5").unwrap(),
            witness_signature: witness_signature(),
            g_i: PointG1::from_string("false 1A5D92950F9D1C 82DB5D4BF49AB8 FBFF5E631AD221 9B89F534C2AC04 165F1606 2E5EE0ECDBB554 F4C238315ACC2 57CAA2D6085FA6 CCE1970A4628E9 119D86E1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            i: 1,
            m2: GroupOrderElement::from_string("7219C82BC1A5C5 2E958256CDE0D B6FBB94E62AC37 4DAA41B3F577 74DDF3F3").unwrap()
        }
    }

    fn witness_signature() -> WitnessSignature {
        WitnessSignature {
            sigma_i: PointG2::from_string("false D75D129A90AC7C E980CE49738692 E81F6656B7EC8B 5CB508713E5514 1C8D263D 277F296ED2870 DD07D7557B996C 3E3A4CBE72B433 CE6A5B3F49DCF0 12760A8D 794C7329844D36 5F061EF8268D0B 6931F242E445A2 941EE07805B105 112CCA EA8F2154379FFC E347F4C23152D6 81B0FD797DECC 99649EAE531C52 306F627 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            u_i: PointG2::from_string("false 5BDC53BAF81A3F 161769B604A474 B7D29413291CFF 339D755F2188BC 33CD0CE D67B914F2755B3 9753565047A4C7 A431380FD96DC BDC9CF432D6969 167143C2 E8C107037A2973 9D6DC89136F5CD 24A92213C2C956 5B52182802ADB 23673530 237EC2A2AE67B4 B2680968AA2A 52E5202656A6A6 CB2696283382AE 251DD0E6 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            g_i: PointG1::from_string("false 1A5D92950F9D1C 82DB5D4BF49AB8 FBFF5E631AD221 9B89F534C2AC04 165F1606 2E5EE0ECDBB554 F4C238315ACC2 57CAA2D6085FA6 CCE1970A4628E9 119D86E1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
        }
    }

    pub fn witness() -> Witness {
        Witness {
            omega: PointG2::from_string("true 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").unwrap()
        }
    }

    pub fn credential_revocation_public_key() -> CredentialRevocationPublicKey {
        CredentialRevocationPublicKey {
            g: PointG1::from_string("false F60F69A1E13425 F73E546433CFD0 637C41C79B9A20 A7C1C61FF3C8DC CE301AF A5B963E8F819BA A1BEDEBBC6969D 5D8AE7E9520A03 61B5E1B0F66956 66BA1F5 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            g_dash: PointG2::from_string("false A8C2313283814C 4158ED9E0C3D39 91BACB977CFDE6 52E34A79A2214E 133BB6A5 1CCC0C0DFC68F1 E01261CACF6FEE 79059429DD1685 133B200E3C3981 20332F20 FBCEB270DA3CAC 2B48592768214A AAC1E363238BB2 1FCD181EFECFD 2467DC72 A9DE4A1D6F2BBE 35644E82B1D167 693B0BBF673C0 4C7728DBFFAC6B 1588E22F FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            h: PointG1::from_string("false FD2B5AD0538033 D015DF671528A6 F529C6D3C1E86 3619CB74900509 88FD6A1 206BE198E9FD2E 3A2AF838B850DD BFD3676C34A56A 7E9396B580460B 18CE0C9E FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h0: PointG1::from_string("false BC70A9E3B966DA 5C20B7CF04326C 1995F7EDE0FA55 8647224A1B94FD 215E7D7 B70990359F1ECC C253AECA1AF037 CD5C39F0F5FEB6 DE29EC1B333A0E 1A416931 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h1: PointG1::from_string("false 3F208F32C3A1EA F9C17CD8CBC476 FF6FE3AD3E638C F60F09CC9354FC 24B6A0D9 E66FDC8EA9A500 C9F6DD1A422220 552AA0E2555006 6C4FEC4A4DD5E4 5A80875 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h2: PointG1::from_string("false 12B39984A618C2 8301484A361459 3178A1EF7A475D 560744F8926BF1 F0CC09B 566C31CA56F841 BA448A640130E7 5C094012CB08EA 14BF1613BFD884 18F83F38 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            htilde: PointG1::from_string("false 1B9C6C124255F0 DCDD43865C2C5B 71C506B6DAED7D C9B07D3475B680 F64FDD9 6788BC29CC436C DFB69513E3443F 80F349D6B3AEDD 249185A03F1894 B5A30D6 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h_cap: PointG2::from_string("false 40D72C85B11CE9 BF72E0BFF2EF7D A0BF05E6B65730 D3196DA7F1E2AE 21DECE46 B6A71B2793E03F 365980B4BBC513 EEF7E36A2C4EF2 97A24735BB35D3 24CD0EC8 B61E9C0CAADBA1 D188893578CDE9 189941E2A97F86 D3FDA76C77446E 11C00332 B8EBFEFA4806ED 2B24292A60E93D 58A6B808268819 7332DB02354F60 22F5DCAB FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            u: PointG2::from_string("false 949870C263DD9D F4AF6AA66AF766 51BFF0CB997107 9B088B00E9010F 1B83B3E2 A1C934F44D4EBE ED5B25CEA92EB6 5A9EC1AE6DA6A 78BC99E18F65C1 54B7102 FCACE93A8DB060 4B53C12B6811CC C4127B919DE7D0 A7E41A24369A90 C309A89 CB0142A1B8D145 8BBE86201B83F5 96BB41F2907C00 842592B2DBECF8 15FF67F7 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            pk: PointG1::from_string("false AE93B6098E05F C7CFECF37CCB8E E2E93AAC0E460F 4D2C7DFF61504B C498846 CB979E2650AB30 9F892BE1DCCFBF 2F6C9070B5A281 B578E8C6428FB2 12CF0F26 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            y: PointG2::from_string("false BDAD2F22EF14CF AE5D9A51E77EE0 E89DDD10883E27 5C37117977D66B 211AE2CC DA45AF79987D7A 2A19F08C9A2FCC 6795935F9ED1E6 DECB5E087C411B 1DDF53D2 54E6378BB99D77 2C90E57308CACF 9D66330D2FA668 DD7C8C8ABB6AE8 251B8CD4 1E00DEB599A5A5 5F80E6AA5FAE14 DB48A68FEA6131 B9F2CDF5DDEEA2 167298BC FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap()
        }
    }

    pub fn credential_revocation_private_key() -> CredentialRevocationPrivateKey {
        CredentialRevocationPrivateKey {
            x: GroupOrderElement::from_string("15828423A33686 D8963528DB5407 A879E05D368FE6 7905F61394DA42 12EFD625").unwrap(),
            sk: GroupOrderElement::from_string("FB1C5F110B9C9 BDA290C1C4AD27 F5F95DCDF3B1A0 FA9EF0550BD3DE 2522B69E").unwrap()
        }
    }

    pub fn revocation_key_public() -> RevocationKeyPublic {
        RevocationKeyPublic {
            z: Pair::from_string("B0C52EBB799E8 6FC6F7D6883390 BC4244EDBC1787 FDEA974C84C1F1 234FA3A6 F411BCC525581F B238C8B10BBACB 8536CC797D203D DEFEAA1B1DBC5B 736EAC 529F008C0398B9 CD0B30B71A1F14 2D332E37CEBF1B A3D9B3319DCDAD CA1AAD2 E5B506C98D6F95 575329E5789B3B CA3A9AB8CED863 BB16612D7EDFC9 241D0C39 810C5FA05825E3 C8A863BA7721CD DCCCB939E4BC22 1817F872AA9906 E423204 C38DCA6D9C80D6 5DE52EA7CFE23E FB41FA284C112E E438D18C192C1D 88A018F EF8569C86B3916 119FE81D359A09 6D5A0088955ED3 6904F412A28BD4 11F6C539 29AD474B03EE99 D0353A66812CA7 C9763FC9EEB4A3 217160B2B8982E 10983B69 7F67C0FCFD4244 45C9665E75EC5B 4A23D9F0D1182F 3A8C685A922F6 20A176A9 883FF71EB14569 5030243F2B2B79 95A67EF0922D07 A6D74310BFE00A F8BBB21 476E55B2836798 16B49B2120D6EB 68EABD968A44DE E8DF358500A99A 15A3F96B 28749CC7A07F60 F82B17A0CA933F EE4166241C77F2 9BE2BB4B802250 19F0D85E").unwrap(),
        }
    }

    fn accumulator() -> Accumulator {
        PointG2::from_string("false 1348A2A978E0DB 34007FF6AF40CE 6D0587A6FB0664 5C7BE100A9A5F0 195FD169 A8C3298C4E3638 F93A75199C097D F3659F1FB6AE4A A03EC27AEB629 2435D86 4DA6C9C1917365 866CCF7C293373 216DF40B2F9E81 19F44DEEC2C748 170C3B8A DDEA4569FCEEC7 1685AB7B80F94F 5BB29412B2822D 3FE85A96139673 109B08B8 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap()
    }

    pub fn revocation_registry() -> RevocationRegistry {
        RevocationRegistry {
            accum: accumulator()
        }
    }

    pub fn max_cred_num() -> u32 {
        5
    }

    pub fn revocation_registry_delta() -> RevocationRegistryDelta {
        RevocationRegistryDelta {
            prev_accum: None,
            accum: accumulator(),
            issued: hashset![1],
            revoked: HashSet::new()
        }
    }
}
