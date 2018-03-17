extern crate serde_json;

mod constants;
#[macro_use]
mod helpers;
pub mod issuer;
pub mod prover;
pub mod verifier;

use bn::BigNumber;
use errors::IndyCryptoError;
use pair::*;
use utils::json::{JsonEncodable, JsonDecodable};

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Creates random nonce
///
/// # Example
/// ```
/// use indy_crypto::cl::new_nonce;
///
/// let _nonce = new_nonce().unwrap();
/// ```
pub fn new_nonce() -> Result<Nonce, IndyCryptoError> {
    Ok(helpers::bn_rand(constants::LARGE_NONCE)?)
}

/// A list of attributes a Claim is based on.
#[derive(Debug, Clone)]
pub struct CredentialSchema {
    pub attrs: BTreeSet<String> /* attr names */
}

/// A Builder of `Claim Schema`.
#[derive(Debug)]
pub struct CredentialSchemaBuilder {
    attrs: BTreeSet<String> /* attr names */
}

impl CredentialSchemaBuilder {
    pub fn new() -> Result<CredentialSchemaBuilder, IndyCryptoError> {
        Ok(CredentialSchemaBuilder {
            attrs: BTreeSet::new()
        })
    }

    pub fn add_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self) -> Result<CredentialSchema, IndyCryptoError> {
        Ok(CredentialSchema {
            attrs: self.attrs
        })
    }
}

#[derive(Debug, Clone)]
pub struct NonCredentialSchemaElements {
    pub attrs: BTreeSet<String>
}

#[derive(Debug)]
pub struct NonCredentialSchemaElementsBuilder {
    attrs: BTreeSet<String>
}

impl NonCredentialSchemaElementsBuilder {
    pub fn new() -> Result<NonCredentialSchemaElementsBuilder, IndyCryptoError> {
        Ok(NonCredentialSchemaElementsBuilder {
            attrs: BTreeSet::new()
        })
    }

    pub fn add_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self) -> Result<NonCredentialSchemaElements, IndyCryptoError> {
        Ok(NonCredentialSchemaElements {
            attrs: self.attrs
        })
    }
}

/// The m value for attributes,
/// commitments also store a blinding factor
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum CredentialValue {
    Known { value: BigNumber },  //Issuer and Prover know these
    Hidden { value: BigNumber }, //Only known to Prover who binds these into the U factor
    Commitment { value: BigNumber, blinding_factor: BigNumber } //Only known to Prover, not included in the credential, used for proving knowledge during issuance
}

impl CredentialValue {
    pub fn clone(&self) -> Result<CredentialValue, IndyCryptoError> {
        Ok(match *self {
            CredentialValue::Known{ref value} => CredentialValue::Known{ value: value.clone()? },
            CredentialValue::Hidden{ref value} => CredentialValue::Hidden{ value: value.clone()? },
            CredentialValue::Commitment{ref value, ref blinding_factor} =>
                CredentialValue::Commitment { value: value.clone()?, blinding_factor: blinding_factor.clone()? }
        })
    }

    pub fn is_known(&self) -> bool {
        match *self {
            CredentialValue::Known { .. } => true,
            _ => false
        }
    }

    pub fn is_hidden(&self) -> bool {
        match *self {
            CredentialValue::Hidden { .. } => true,
            _ => false
        }
    }

    pub fn is_commitment(&self) -> bool {
        match *self {
            CredentialValue::Commitment { .. } => true,
            _ => false
        }
    }

    pub fn value(&self) -> &BigNumber {
        match *self {
            CredentialValue::Known{ref value} => value,
            CredentialValue::Hidden{ref value} => value,
            CredentialValue::Commitment{ref value, ..} => value
        }
    }
}

impl JsonEncodable for CredentialValue {}

impl<'a> JsonDecodable<'a> for CredentialValue {}

/// Values of attributes from `Claim Schema` (must be integers).
#[derive(Debug)]
pub struct CredentialValues {
    attrs_values: BTreeMap<String, CredentialValue>
}

impl CredentialValues {
    pub fn clone(&self) -> Result<CredentialValues, IndyCryptoError> {
        Ok(CredentialValues {
            attrs_values: clone_credentialvalue_map(&self.attrs_values)?
        })
    }

    pub fn len(&self) -> usize {
        self.attrs_values.len()
    }
}

/// A Builder of `Claim Values`.
#[derive(Debug)]
pub struct CredentialValuesBuilder {
    attrs_values: BTreeMap<String, CredentialValue> /* attr_name -> int representation of value */
}

impl CredentialValuesBuilder {
    pub fn new() -> Result<CredentialValuesBuilder, IndyCryptoError> {
        Ok(CredentialValuesBuilder {
            attrs_values: BTreeMap::new()
        })
    }

    pub fn add_dec_known(&mut self, attr: &str, value: &str) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), CredentialValue::Known { value: BigNumber::from_dec(value)? });
        Ok(())
    }

    pub fn add_dec_hidden(&mut self, attr: &str, value: &str) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), CredentialValue::Hidden { value: BigNumber::from_dec(value)? });
        Ok(())
    }

    pub fn add_dec_commitment(&mut self, attr: &str, value: &str, blinding_factor: &str) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), CredentialValue::Commitment { value: BigNumber::from_dec(value)?, blinding_factor: BigNumber::from_dec(blinding_factor)? });
        Ok(())
    }

    pub fn add_value_known(&mut self, attr: &str, value: &BigNumber) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), CredentialValue::Known {value: value.clone()?});
        Ok(())
    }

    pub fn add_value_hidden(&mut self, attr: &str, value: &BigNumber) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), CredentialValue::Hidden {value: value.clone()?});
        Ok(())
    }

    pub fn add_value_commitment(&mut self, attr: &str, value: &BigNumber, blinding_factor: &BigNumber) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), CredentialValue::Commitment {value: value.clone()?, blinding_factor: blinding_factor.clone()?});
        Ok(())
    }

    pub fn finalize(self) -> Result<CredentialValues, IndyCryptoError> {
        Ok(CredentialValues {
            attrs_values: self.attrs_values
        })
    }
}

/// `Issuer Public Key` contains 2 internal parts.
/// One for signing primary credentials and second for signing non-revocation credentials.
/// These keys are used to proof that credential was issued and doesn’t revoked by this issuer.
/// Issuer keys have global identifier that must be known to all parties.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct CredentialPublicKey {
    p_key: CredentialPrimaryPublicKey,
    r_key: Option<CredentialRevocationPublicKey>,
}

impl CredentialPublicKey {
    pub fn clone(&self) -> Result<CredentialPublicKey, IndyCryptoError> {
        Ok(CredentialPublicKey {
            p_key: self.p_key.clone()?,
            r_key: self.r_key.clone()
        })
    }

    pub fn get_primary_key(&self) -> Result<CredentialPrimaryPublicKey, IndyCryptoError> {
        Ok(self.p_key.clone()?)
    }

    pub fn get_revocation_key(&self) -> Result<Option<CredentialRevocationPublicKey>, IndyCryptoError> {
        Ok(self.r_key.clone())
    }

    pub fn build_from_parts(p_key: &CredentialPrimaryPublicKey, r_key: Option<&CredentialRevocationPublicKey>) -> Result<CredentialPublicKey, IndyCryptoError> {
        Ok(CredentialPublicKey {
            p_key: p_key.clone()?,
            r_key: r_key.map(|key| key.clone())
        })
    }
}

impl JsonEncodable for CredentialPublicKey {}

impl<'a> JsonDecodable<'a> for CredentialPublicKey {}

/// `Issuer Private Key`: contains 2 internal parts.
/// One for signing primary credentials and second for signing non-revocation credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialPrivateKey {
    p_key: CredentialPrimaryPrivateKey,
    r_key: Option<CredentialRevocationPrivateKey>,
}

impl CredentialPrivateKey {
    pub fn get_primary_key(&self) -> Result<CredentialPrimaryPrivateKey, IndyCryptoError> {
        Ok(self.p_key.clone()?)
    }

    pub fn get_revocation_key(&self) -> Result<Option<CredentialRevocationPrivateKey>, IndyCryptoError> {
        Ok(self.r_key.clone())
    }
}

impl JsonEncodable for CredentialPrivateKey {}

impl<'a> JsonDecodable<'a> for CredentialPrivateKey {}

/// Issuer's "Public Key" is used to verify the Issuer's signature over the Claim's attributes' values (primary credential).
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialPrimaryPublicKey {
    pub n: BigNumber,
    pub s: BigNumber,
    pub r: BTreeMap<String /* attr_name */, BigNumber>,
    pub rctxt: BigNumber,
    pub z: BigNumber
}

impl CredentialPrimaryPublicKey {
    pub fn clone(&self) -> Result<CredentialPrimaryPublicKey, IndyCryptoError> {
        Ok(CredentialPrimaryPublicKey {
            n: self.n.clone()?,
            s: self.s.clone()?,
            r: clone_btree_bignum_map(&self.r)?,
            rctxt: self.rctxt.clone()?,
            z: self.z.clone()?
        })
    }
}

/// Issuer's "Private Key" used for signing Claim's attributes' values (primary credential)
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialPrimaryPrivateKey {
    pub p: BigNumber,
    pub q: BigNumber
}

impl CredentialPrimaryPrivateKey {
    pub fn clone(&self) -> Result<CredentialPrimaryPrivateKey, IndyCryptoError> {
        Ok(CredentialPrimaryPrivateKey {
            p: self.p.clone()?,
            q: self.q.clone()?
        })
    }
}

/// `Primary Public Key Metadata` required for building of Proof Correctness of `Issuer Public Key`
#[derive(Debug)]
pub struct CredentialPrimaryPublicKeyMetadata {
    xz: BigNumber,
    xr: BTreeMap<String, BigNumber>
}

/// Proof of `Issuer Public Key` correctness
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialKeyCorrectnessProof {
    c: BigNumber,
    xz_cap: BigNumber,
    xr_cap: BTreeMap<String, BigNumber>
}

impl JsonEncodable for CredentialKeyCorrectnessProof {}

impl<'a> JsonDecodable<'a> for CredentialKeyCorrectnessProof {}

/// `Revocation Public Key` is used to verify that credential was'nt revoked by Issuer.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CredentialRevocationPublicKey {
    pub g: PointG1,
    pub g_dash: PointG2,
    pub h: PointG1,
    pub h0: PointG1,
    pub h1: PointG1,
    pub h2: PointG1,
    pub htilde: PointG1,
    pub h_cap: PointG2,
    pub u: PointG2,
    pub pk: PointG1,
    pub y: PointG2,
}

/// `Revocation Private Key` is used for signing Claim.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialRevocationPrivateKey {
    pub x: GroupOrderElement,
    pub sk: GroupOrderElement
}

pub type Accumulator = PointG2;

/// `Revocation Registry` contains accumulator.
/// Must be published by Issuer on a tamper-evident and highly available storage
/// Used by prover to prove that a claim hasn't revoked by the issuer
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationRegistry {
    accum: Accumulator
}

impl From<RevocationRegistryDelta> for RevocationRegistry {
    fn from(rev_reg_delta: RevocationRegistryDelta) -> RevocationRegistry {
        RevocationRegistry {
            accum: rev_reg_delta.accum
        }
    }
}

impl JsonEncodable for RevocationRegistry {}

impl<'a> JsonDecodable<'a> for RevocationRegistry {}

/// `Revocation Registry Delta` contains Accumulator changes.
/// Must be applied to `Revocation Registry`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationRegistryDelta {
    prev_accum: Option<Accumulator>,
    accum: Accumulator,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    issued: HashSet<u32>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    revoked: HashSet<u32>
}

impl JsonEncodable for RevocationRegistryDelta {}

impl<'a> JsonDecodable<'a> for RevocationRegistryDelta {}

impl RevocationRegistryDelta {
    pub fn merge(&mut self, other_delta: &RevocationRegistryDelta) -> Result<(), IndyCryptoError> {
        if other_delta.prev_accum.is_none() || self.accum != other_delta.prev_accum.unwrap() {
            return Err(IndyCryptoError::InvalidStructure(format!("Deltas can not be merged.")));
        }

        self.prev_accum = Some(self.accum);
        self.accum = other_delta.accum;

        self.issued.extend(
            other_delta.issued.difference(&self.revoked));

        self.revoked.extend(
            other_delta.revoked.difference(&self.issued));

        for index in other_delta.revoked.iter() {
            self.issued.remove(index);
        }

        for index in other_delta.issued.iter() {
            self.revoked.remove(index);
        }

        Ok(())
    }
}

/// `Revocation Key Public` Accumulator public key.
/// Must be published together with Accumulator
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationKeyPublic {
    z: Pair
}

impl JsonEncodable for RevocationKeyPublic {}

impl<'a> JsonDecodable<'a> for RevocationKeyPublic {}

/// `Revocation Key Private` Accumulator primate key.
#[derive(Debug, Deserialize, Serialize)]
pub struct RevocationKeyPrivate {
    gamma: GroupOrderElement
}

impl JsonEncodable for RevocationKeyPrivate {}

impl<'a> JsonDecodable<'a> for RevocationKeyPrivate {}

/// `Tail` point of curve used to update accumulator.
pub type Tail = PointG2;

impl Tail {
    fn new_tail(index: u32, g_dash: &PointG2, gamma: &GroupOrderElement) -> Result<Tail, IndyCryptoError> {
        let i_bytes = helpers::transform_u32_to_array_of_u8(index);
        let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
        pow = gamma.pow_mod(&pow)?;
        Ok(g_dash.mul(&pow)?)
    }
}

/// Generator of `Tail's`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationTailsGenerator {
    size: u32,
    current_index: u32,
    g_dash: PointG2,
    gamma: GroupOrderElement
}

impl RevocationTailsGenerator {
    fn new(max_cred_num: u32, gamma: GroupOrderElement, g_dash: PointG2) -> Self {
        RevocationTailsGenerator {
            size: 2 * max_cred_num + 1, /* Unused 0th + valuable 1..L + unused (L+1)th + valuable (L+2)..(2L) */
            current_index: 0,
            gamma,
            g_dash,
        }
    }

    pub fn count(&self) -> u32 {
        self.size - self.current_index
    }

    pub fn next(&mut self) -> Result<Option<Tail>, IndyCryptoError> {
        if self.current_index >= self.size {
            return Ok(None);
        }

        let tail = Tail::new_tail(self.current_index, &self.g_dash, &self.gamma)?;

        self.current_index += 1;

        Ok(Some(tail))
    }
}

impl JsonEncodable for RevocationTailsGenerator {}

impl<'a> JsonDecodable<'a> for RevocationTailsGenerator {}

pub trait RevocationTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut FnMut(&Tail)) -> Result<(), IndyCryptoError>;
}

/// Simple implementation of `RevocationTailsAccessor` that stores all tails as BTreeMap.
#[derive(Debug, Clone)]
pub struct SimpleTailsAccessor {
    tails: Vec<Tail>
}

impl RevocationTailsAccessor for SimpleTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut FnMut(&Tail)) -> Result<(), IndyCryptoError> {
        Ok(accessor(&self.tails[tail_id as usize]))
    }
}

impl SimpleTailsAccessor {
    pub fn new(rev_tails_generator: &mut RevocationTailsGenerator) -> Result<SimpleTailsAccessor, IndyCryptoError> {
        let mut tails: Vec<Tail> = Vec::new();
        while let Some(tail) = rev_tails_generator.next()? {
            tails.push(tail);
        }
        Ok(SimpleTailsAccessor {
            tails
        })
    }
}


/// Issuer's signature over Claim attribute values.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialSignature {
    p_credential: PrimaryCredentialSignature,
    r_credential: Option<NonRevocationCredentialSignature> /* will be used to proof is credential revoked preparation */,
}

impl CredentialSignature {
    pub fn extract_index(&self) -> Option<u32> {
        self.r_credential
            .as_ref()
            .map(|r_credential| r_credential.i)
    }
}

impl JsonEncodable for CredentialSignature {}

impl<'a> JsonDecodable<'a> for CredentialSignature {}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryCredentialSignature {
    m_2: BigNumber,
    a: BigNumber,
    e: BigNumber,
    v: BigNumber
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocationCredentialSignature {
    sigma: PointG1,
    c: GroupOrderElement,
    vr_prime_prime: GroupOrderElement,
    witness_signature: WitnessSignature,
    g_i: PointG1,
    i: u32,
    m2: GroupOrderElement
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SignatureCorrectnessProof {
    se: BigNumber,
    c: BigNumber
}

impl JsonEncodable for SignatureCorrectnessProof {}

impl<'a> JsonDecodable<'a> for SignatureCorrectnessProof {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Witness {
    omega: PointG2
}

impl JsonEncodable for Witness {}

impl<'a> JsonDecodable<'a> for Witness {}

impl Witness {
    pub fn new<RTA>(rev_idx: u32,
                    max_cred_num: u32,
                    rev_reg_delta: &RevocationRegistryDelta,
                    rev_tails_accessor: &RTA) -> Result<Witness, IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Witness::new: >>> rev_idx: {:?}, max_cred_num: {:?}, rev_reg_delta: {:?}",
               rev_idx, max_cred_num, rev_reg_delta);

        let mut omega = PointG2::new_inf()?;

        let mut issued = rev_reg_delta.issued.clone();
        issued.remove(&rev_idx);

        for j in issued.iter() {
            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega = omega.add(tail).unwrap();
            })?;
        }

        let witness = Witness {
            omega
        };

        trace!("Witness::new: <<< witness: {:?}", witness);

        Ok(witness)
    }

    pub fn update<RTA>(&mut self,
                       rev_idx: u32,
                       max_cred_num: u32,
                       rev_reg_delta: &RevocationRegistryDelta,
                       rev_tails_accessor: &RTA) -> Result<(), IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Witness::update: >>> rev_idx: {:?}, max_cred_num: {:?}, rev_reg_delta: {:?}",
               rev_idx, max_cred_num, rev_reg_delta);

        let mut omega_denom = PointG2::new_inf()?;
        for j in rev_reg_delta.revoked.iter() {
            if rev_idx.eq(j) { continue; }

            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega_denom = omega_denom.add(tail).unwrap();
            })?;
        }

        let mut omega_num = PointG2::new_inf()?;
        for j in rev_reg_delta.issued.iter() {
            if rev_idx.eq(j) { continue; }

            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega_num = omega_num.add(tail).unwrap();
            })?;
        }

        let new_omega: PointG2 = self.omega.add(
            &omega_num.sub(&omega_denom)?)?;

        self.omega = new_omega;

        trace!("Witness::update: <<<");

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessSignature {
    sigma_i: PointG2,
    u_i: PointG2,
    g_i: PointG1
}

/// Secret key encoded in a credential that is used to prove that prover owns the credential; can be used to
/// prove linkage across credentials.
/// Prover blinds master secret, generating `BlindedCredentialSecrets` and `CredentialSecretsBlindingFactors` (blinding factors)
/// and sends the `BlindedCredentialSecrets` to Issuer who then encodes it credential creation.
/// The blinding factors are used by Prover for post processing of issued credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct MasterSecret {
    ms: BigNumber,
}

impl MasterSecret {
    pub fn clone(&self) -> Result<MasterSecret, IndyCryptoError> {
        Ok(MasterSecret { ms: self.ms.clone()? })
    }
}

impl JsonEncodable for MasterSecret {}

impl<'a> JsonDecodable<'a> for MasterSecret {}

/// Blinded Master Secret uses by Issuer in credential creation.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlindedCredentialSecrets {
    u: BigNumber,
    ur: Option<PointG1>,
    hidden_attributes: BTreeSet<String>,
    committed_attributes: BTreeMap<String, BigNumber>
}

impl JsonEncodable for BlindedCredentialSecrets {}

impl<'a> JsonDecodable<'a> for BlindedCredentialSecrets {}

/// `CredentialSecretsBlindingFactors` used by Prover for post processing of credentials received from Issuer.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialSecretsBlindingFactors {
    v_prime: BigNumber,
    vr_prime: Option<GroupOrderElement>
}

impl JsonEncodable for CredentialSecretsBlindingFactors {}

impl<'a> JsonDecodable<'a> for CredentialSecretsBlindingFactors {}

#[derive(Eq, PartialEq, Debug)]
pub struct PrimaryBlindedCredentialSecretsFactors {
    u: BigNumber,
    v_prime: BigNumber,
    hidden_attributes: BTreeSet<String>,
    committed_attributes: BTreeMap<String, BigNumber>
}

#[derive(Debug)]
pub struct RevocationBlindedCredentialSecretsFactors {
    ur: PointG1,
    vr_prime: GroupOrderElement,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BlindedCredentialSecretsCorrectnessProof {
    c: BigNumber,                       // Fiat-Shamir challenge hash
    v_dash_cap: BigNumber,              // Value to prove knowledge of `u` construction in `BlindedCredentialSecrets`
    m_caps: BTreeMap<String, BigNumber>, // Values for proving knowledge of committed values
    r_caps: BTreeMap<String, BigNumber>  // Blinding values for m_caps
}

impl JsonEncodable for BlindedCredentialSecretsCorrectnessProof {}

impl<'a> JsonDecodable<'a> for BlindedCredentialSecretsCorrectnessProof {}

/// “Sub Proof Request” - input to create a Proof for a credential;
/// Contains attributes to be revealed and predicates.
#[derive(Debug, Clone)]
pub struct SubProofRequest {
    revealed_attrs: BTreeSet<String>,
    predicates: BTreeSet<Predicate>,
}

/// Builder of “Sub Proof Request”.
#[derive(Debug)]
pub struct SubProofRequestBuilder {
    value: SubProofRequest
}

impl SubProofRequestBuilder {
    pub fn new() -> Result<SubProofRequestBuilder, IndyCryptoError> {
        Ok(SubProofRequestBuilder {
            value: SubProofRequest {
                revealed_attrs: BTreeSet::new(),
                predicates: BTreeSet::new()
            }
        })
    }

    pub fn add_revealed_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.value.revealed_attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn add_predicate(&mut self, attr_name: &str, p_type: &str, value: i32) -> Result<(), IndyCryptoError> {
        let p_type = match p_type {
            "GE" => PredicateType::GE,
            p_type => return Err(IndyCryptoError::InvalidStructure(format!("Invalid predicate type: {:?}", p_type)))
        };

        let predicate = Predicate {
            attr_name: attr_name.to_owned(),
            p_type,
            value
        };

        self.value.predicates.insert(predicate);
        Ok(())
    }

    pub fn finalize(self) -> Result<SubProofRequest, IndyCryptoError> {
        Ok(self.value)
    }
}

/// Some condition that must be satisfied.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Predicate {
    attr_name: String,
    p_type: PredicateType,
    value: i32,
}

/// Condition type (Currently GE only).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum PredicateType {
    GE
}

impl Ord for Predicate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.attr_name.cmp(&other.attr_name)
    }
}

impl PartialOrd for Predicate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Proof is complex crypto structure created by prover over multiple credentials that allows to prove that prover:
/// 1) Knows signature over credentials issued with specific issuer keys (identified by key id)
/// 2) Claim contains attributes with specific values that prover wants to disclose
/// 3) Claim contains attributes with valid predicates that verifier wants the prover to satisfy.
#[derive(Debug, Deserialize, Serialize)]
pub struct Proof {
    proofs: BTreeMap<String /* issuer pub key id */, SubProof>,
    aggregated_proof: AggregatedProof,
}

impl JsonEncodable for Proof {}

impl<'a> JsonDecodable<'a> for Proof {}

#[derive(Debug, Deserialize, Serialize)]
pub struct SubProof {
    primary_proof: PrimaryProof,
    non_revoc_proof: Option<NonRevocProof>
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AggregatedProof {
    c_hash: BigNumber,
    c_list: Vec<Vec<u8>>
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryProof {
    eq_proof: PrimaryEqualProof,
    ge_proofs: Vec<PrimaryPredicateGEProof>
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryEqualProof {
    revealed_attrs: BTreeMap<String /* attr_name of revealed */, BigNumber>,
    a_prime: BigNumber,
    e: BigNumber,
    v: BigNumber,
    m: BTreeMap<String /* attr_name of all except revealed */, BigNumber>,
    m2: BigNumber
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryPredicateGEProof {
    u: BTreeMap<String, BigNumber>,
    r: BTreeMap<String, BigNumber>,
    mj: BigNumber,
    alpha: BigNumber,
    t: BTreeMap<String, BigNumber>,
    predicate: Predicate
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NonRevocProof {
    x_list: NonRevocProofXList,
    c_list: NonRevocProofCList
}

#[derive(Debug)]
pub struct InitProof {
    primary_init_proof: PrimaryInitProof,
    non_revoc_init_proof: Option<NonRevocInitProof>,
    credential_values: CredentialValues,
    sub_proof_request: SubProofRequest,
    credential_schema: CredentialSchema,
    non_credential_schema_elements: NonCredentialSchemaElements
}


#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryInitProof {
    eq_proof: PrimaryEqualInitProof,
    ge_proofs: Vec<PrimaryPredicateGEInitProof>
}

impl PrimaryInitProof {
    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let mut c_list: Vec<Vec<u8>> = self.eq_proof.as_list()?;
        for ge_proof in self.ge_proofs.iter() {
            c_list.append_vec(ge_proof.as_list()?)?;
        }
        Ok(c_list)
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let mut tau_list: Vec<Vec<u8>> = self.eq_proof.as_tau_list()?;
        for ge_proof in self.ge_proofs.iter() {
            tau_list.append_vec(ge_proof.as_tau_list()?)?;
        }
        Ok(tau_list)
    }
}

#[derive(Debug)]
pub struct NonRevocInitProof {
    c_list_params: NonRevocProofXList,
    tau_list_params: NonRevocProofXList,
    c_list: NonRevocProofCList,
    tau_list: NonRevocProofTauList
}

impl NonRevocInitProof {
    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.c_list.as_list()?;
        Ok(vec)
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.tau_list.as_slice()?;
        Ok(vec)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryEqualInitProof {
    a_prime: BigNumber,
    t: BigNumber,
    e_tilde: BigNumber,
    e_prime: BigNumber,
    v_tilde: BigNumber,
    v_prime: BigNumber,
    m_tilde: BTreeMap<String, BigNumber>,
    m2_tilde: BigNumber,
    m2: BigNumber,
//TODO: Add authz proof
//    authz_a_tilde: BigNumber,
//    authz_b_tilde: BigNumber,
//    authz_t_3: BigNumber
}

impl PrimaryEqualInitProof {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.a_prime.to_bytes()?])
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.t.to_bytes()?])
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryPredicateGEInitProof {
    c_list: Vec<BigNumber>,
    tau_list: Vec<BigNumber>,
    u: BTreeMap<String, BigNumber>,
    u_tilde: BTreeMap<String, BigNumber>,
    r: BTreeMap<String, BigNumber>,
    r_tilde: BTreeMap<String, BigNumber>,
    alpha_tilde: BigNumber,
    predicate: Predicate,
    t: BTreeMap<String, BigNumber>
}

impl PrimaryPredicateGEInitProof {
    pub fn as_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
        Ok(&self.c_list)
    }

    pub fn as_tau_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
        Ok(&self.tau_list)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocProofXList {
    rho: GroupOrderElement,
    r: GroupOrderElement,
    r_prime: GroupOrderElement,
    r_prime_prime: GroupOrderElement,
    r_prime_prime_prime: GroupOrderElement,
    o: GroupOrderElement,
    o_prime: GroupOrderElement,
    m: GroupOrderElement,
    m_prime: GroupOrderElement,
    t: GroupOrderElement,
    t_prime: GroupOrderElement,
    m2: GroupOrderElement,
    s: GroupOrderElement,
    c: GroupOrderElement
}

impl NonRevocProofXList {
    pub fn as_list(&self) -> Result<Vec<GroupOrderElement>, IndyCryptoError> {
        Ok(vec![self.rho, self.o, self.c, self.o_prime, self.m, self.m_prime, self.t, self.t_prime,
                self.m2, self.s, self.r, self.r_prime, self.r_prime_prime, self.r_prime_prime_prime])
    }

    pub fn from_list(seq: Vec<GroupOrderElement>) -> NonRevocProofXList {
        NonRevocProofXList {
            rho: seq[0],
            r: seq[10],
            r_prime: seq[11],
            r_prime_prime: seq[12],
            r_prime_prime_prime: seq[13],
            o: seq[1],
            o_prime: seq[3],
            m: seq[4],
            m_prime: seq[5],
            t: seq[6],
            t_prime: seq[7],
            m2: seq[8],
            s: seq[9],
            c: seq[2]
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocProofCList {
    e: PointG1,
    d: PointG1,
    a: PointG1,
    g: PointG1,
    w: PointG2,
    s: PointG2,
    u: PointG2
}

impl NonRevocProofCList {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.e.to_bytes()?, self.d.to_bytes()?, self.a.to_bytes()?, self.g.to_bytes()?,
                self.w.to_bytes()?, self.s.to_bytes()?, self.u.to_bytes()?])
    }
}

#[derive(Clone, Debug)]
pub struct NonRevocProofTauList {
    t1: PointG1,
    t2: PointG1,
    t3: Pair,
    t4: Pair,
    t5: PointG1,
    t6: PointG1,
    t7: Pair,
    t8: Pair
}

impl NonRevocProofTauList {
    pub fn as_slice(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.t1.to_bytes()?, self.t2.to_bytes()?, self.t3.to_bytes()?, self.t4.to_bytes()?,
                self.t5.to_bytes()?, self.t6.to_bytes()?, self.t7.to_bytes()?, self.t8.to_bytes()?])
    }
}

/// Random BigNumber that uses `Prover` for proof generation and `Verifier` for proof verification.
pub type Nonce = BigNumber;

impl JsonEncodable for Nonce {}

impl<'a> JsonDecodable<'a> for Nonce {}

#[derive(Debug)]
pub struct VerifiableCredential {
    pub_key: CredentialPublicKey,
    sub_proof_request: SubProofRequest,
    credential_schema: CredentialSchema,
    non_credential_schema_elements: NonCredentialSchemaElements,
    rev_key_pub: Option<RevocationKeyPublic>,
    rev_reg: Option<RevocationRegistry>
}

trait BytesView {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError>;
}

impl BytesView for BigNumber {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for PointG1 {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for GroupOrderElement {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for Pair {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

trait AppendByteArray {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError>;
}

impl AppendByteArray for Vec<Vec<u8>> {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError> {
        for el in other.iter() {
            self.push(el.to_bytes()?);
        }
        Ok(())
    }
}

fn clone_bignum_map<K: Clone + Eq + Ord>(other: &BTreeMap<K, BigNumber>)
                                          -> Result<BTreeMap<K, BigNumber>, IndyCryptoError> {
    let mut res: BTreeMap<K, BigNumber> = BTreeMap::new();
    for (k, v) in other {
        res.insert(k.clone(), v.clone()?);
    }
    Ok(res)
}

fn clone_btree_bignum_map<K: Clone + Eq + Ord>(other: &BTreeMap<K, BigNumber>)
                                                      -> Result<BTreeMap<K, BigNumber>, IndyCryptoError> {
    let mut res: BTreeMap<K, BigNumber> = BTreeMap::new();
    for (k, v) in other {
        res.insert(k.clone(), v.clone()?);
    }
    Ok(res)
}

fn clone_credentialvalue_map<K: Clone + Eq + Ord>(other: &BTreeMap<K, CredentialValue>)
                                                    -> Result<BTreeMap<K, CredentialValue>, IndyCryptoError> {
    let mut res: BTreeMap<K, CredentialValue> = BTreeMap::new();
    for (k, v) in other {
        res.insert(k.clone(), v.clone()?);
    }
    Ok(res)
}

#[cfg(test)]
mod test {
    use super::*;
    use self::issuer::Issuer;
    use self::prover::Prover;
    use self::verifier::Verifier;
    use cl::helpers::MockHelper;

    #[test]
    fn demo() {
        let (credential_schema,
             non_credential_schema_elements,
             credential_values,
             credential_nonce,
             credential_pub_key,
             credential_priv_key,
             credential_key_correctness_proof,
             blinded_credential_secrets,
             credential_secrets_blinding_factors,
             blinded_credential_secrets_correctness_proof,
             credential_issuance_nonce) = setup_test();

        let (mut credential_signature, signature_correctness_proof) =
                    Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                                            &blinded_credential_secrets,
                                            blinded_credential_secrets_correctness_proof.as_ref(),
                                            credential_nonce.as_ref(),
                                            credential_issuance_nonce.as_ref(),
                                            &credential_values,
                                            &credential_pub_key,
                                            &credential_priv_key).unwrap();

        compute_proof(credential_schema,
                    non_credential_schema_elements,
                    credential_values,
                    &mut credential_signature,
                    signature_correctness_proof,
                    credential_secrets_blinding_factors,
                    credential_pub_key,
                    credential_issuance_nonce,
        None, None, None)
    }

    #[test]
    fn demo_revocation() {
        let (credential_schema,
             non_credential_schema_elements,
             credential_values,
             credential_nonce,
             credential_pub_key,
             credential_priv_key,
             credential_key_correctness_proof,
             blinded_credential_secrets,
             credential_secrets_blinding_factors,
             blinded_credential_secrets_correctness_proof,
             credential_issuance_nonce) = setup_test();

        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, issuer::mocks::max_cred_num(), issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        let rev_idx = 1;
        let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                                               &blinded_credential_secrets,
                                               blinded_credential_secrets_correctness_proof.as_ref(),
                                               credential_nonce.as_ref(),
                                               credential_issuance_nonce.as_ref(),
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx,
                                               issuer::mocks::max_cred_num(),
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();

        let witness = Witness::new(rev_idx, issuer::mocks::max_cred_num(), &rev_reg_delta.unwrap(), &simple_tail_accessor).unwrap();

        compute_proof(credential_schema,
                    non_credential_schema_elements,
                    credential_values,
                    &mut credential_signature,
                    signature_correctness_proof,
                    credential_secrets_blinding_factors,
                    credential_pub_key,
                    credential_issuance_nonce,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                    Some(&witness));
    }

    fn setup_test() -> (CredentialSchema,
                        NonCredentialSchemaElements,
                        CredentialValues,
                        Option<Nonce>,
                        CredentialPublicKey,
                        CredentialPrivateKey,
                        CredentialKeyCorrectnessProof,
                        BlindedCredentialSecrets,
                        CredentialSecretsBlindingFactors,
                        Option<BlindedCredentialSecretsCorrectnessProof>,
                        Option<Nonce>) {

        let credential_schema = prover::mocks::credential_schema();
        let non_credential_schema_elements = prover::mocks::non_credential_schema_elements();
        let credential_values = prover::mocks::credential_values();
        let credential_nonce = new_nonce().unwrap();
        let (credential_pub_key,
             credential_priv_key,
             credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema_elements, true).unwrap();

        let (blinded_credential_secrets,
             credential_secrets_blinding_factors,
             blinded_credential_secrets_correctness_proof) =
                                Prover::blind_credential_secrets(&credential_pub_key,
                                                                 &credential_key_correctness_proof,
                                                                 &credential_values,
                                                                 &credential_nonce).unwrap();
        (
            credential_schema,
            non_credential_schema_elements,
            credential_values,
            Some(credential_nonce),
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            Some(blinded_credential_secrets_correctness_proof),
            Some(new_nonce().unwrap())
        )
    }

    fn compute_proof(credential_schema: CredentialSchema,
                     non_credential_schema_elements: NonCredentialSchemaElements,
                     credential_values: CredentialValues,
                     credential_signature: &mut CredentialSignature,
                     signature_correctness_proof: Option<SignatureCorrectnessProof>,
                     credential_secrets_blinding_factors: CredentialSecretsBlindingFactors,
                     credential_pub_key: CredentialPublicKey,
                     credential_issuance_nonce: Option<Nonce>,
                     rev_key_pub: Option<&RevocationKeyPublic>,
                     rev_reg: Option<&RevocationRegistry>,
                     witness: Option<&Witness>) {
        Prover::process_credential_signature(credential_signature,
                                             &credential_values,
                                             signature_correctness_proof.as_ref(),
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             credential_issuance_nonce.as_ref(),
                                             rev_key_pub,
                                             rev_reg,
                                             witness).unwrap();

//        println!("credential_signature = {:?}", credential_signature);

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        proof_builder.add_sub_proof_request("issuer_key_id_1",
                                            &sub_proof_request,
                                            &credential_schema,
                                            &non_credential_schema_elements,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            rev_reg,
                                            witness).unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

//        println!("proof={:?}", proof);

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request("issuer_key_id_1",
                                             &sub_proof_request,
                                             &credential_schema,
                                             &non_credential_schema_elements,
                                             &credential_pub_key,
                                             rev_key_pub,
                                             rev_reg).unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }
}
