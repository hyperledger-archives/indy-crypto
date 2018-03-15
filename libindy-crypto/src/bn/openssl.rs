use errors::IndyCryptoError;

use int_traits::IntTraits;

use openssl::bn::{BigNum, BigNumRef, BigNumContext, MSB_MAYBE_ZERO};
use openssl::hash::{hash2, MessageDigest, Hasher};
use openssl::error::ErrorStack;

#[cfg(feature = "serialization")]
use serde::ser::{Serialize, Serializer, Error as SError};

#[cfg(feature = "serialization")]
use serde::de::{Deserialize, Deserializer, Visitor, Error as DError};

use std::error::Error;
use std::fmt;
use std::cmp::Ord;
use std::cmp::Ordering;

use std::time::{SystemTime, UNIX_EPOCH};


pub struct BigNumberContext {
    openssl_bn_context: BigNumContext
}

#[derive(Debug)]
pub struct BigNumber {
    openssl_bn: BigNum
}

impl BigNumber {
    pub fn new_context() -> Result<BigNumberContext, IndyCryptoError> {
        let ctx = BigNumContext::new()?;
        Ok(BigNumberContext {
            openssl_bn_context: ctx
        })
    }

    pub fn new() -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::new()?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn generate_prime(size: usize) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, size as i32, false, None, None)?;
        Ok(bn)
    }

    pub fn generate_safe_prime(size: usize) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, (size + 1) as i32, true, None, None)?;
        Ok(bn)
    }

    pub fn generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        let mut prime;
        let mut iteration = 0;
        let mut bn_ctx = BigNumber::new_context()?;
        let sub = end.sub(start)?;

        loop {
            prime = sub.rand_range()?;
            prime = prime.add(start)?;

            if prime.is_prime(Some(&mut bn_ctx))? {
                debug!("Found prime in {} iteration", iteration);
                break;
            }
            iteration += 1;
        }

        Ok(prime)
    }

    pub fn is_prime(&self, ctx: Option<&mut BigNumberContext>) -> Result<bool, IndyCryptoError> {
        let prime_len = self.to_dec()?.len();
        let checks = prime_len.log2() as i32;
        match ctx {
            Some(context) => Ok(self.openssl_bn.is_prime(checks, &mut context.openssl_bn_context)?),
            None => {
                let mut ctx = BigNumber::new_context()?;
                Ok(self.openssl_bn.is_prime(checks, &mut ctx.openssl_bn_context)?)
            }
        }
    }

    pub fn rand(size: usize) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand(&mut bn.openssl_bn, size as i32, MSB_MAYBE_ZERO, false)?;
        Ok(bn)
    }

    pub fn rand_range(&self) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand_range(&self.openssl_bn, &mut bn.openssl_bn)?;
        Ok(bn)
    }

    pub fn num_bits(&self) -> Result<i32, IndyCryptoError> {
        Ok(self.openssl_bn.num_bits())
    }

    pub fn is_bit_set(&self, n: i32) -> Result<bool, IndyCryptoError> {
        Ok(self.openssl_bn.is_bit_set(n))
    }

    pub fn set_bit(&mut self, n: i32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::set_bit(&mut self.openssl_bn, n)?;
        Ok(self)
    }

    pub fn from_u32(n: usize) -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::from_u32(n as u32)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_dec(dec: &str) -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::from_dec_str(dec)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_hex(hex: &str) -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::from_hex_str(hex)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::from_slice(bytes)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn to_dec(&self) -> Result<String, IndyCryptoError> {
        let result = self.openssl_bn.to_dec_str()?;
        Ok(result.to_string())
    }

    pub fn to_hex(&self) -> Result<String, IndyCryptoError> {
        let result = self.openssl_bn.to_hex_str()?;
        Ok(result.to_string())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.openssl_bn.to_vec())
    }

    pub fn hash(data: &[u8]) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(hash2(MessageDigest::sha256(), data)?.to_vec())
    }

    pub fn add(&self, a: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_add(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    pub fn sub(&self, a: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    pub fn sqr(&self, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::sqr(&mut bn.openssl_bn, &self.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::sqr(&mut bn.openssl_bn, &self.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn mul(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::checked_mul(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::checked_mul(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn mod_mul(&self, a: &BigNumber, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_mul(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &n.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_mul(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &n.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn mod_sub(&self, a: &BigNumber, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &n.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &n.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn div(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::checked_div(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::checked_div(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn add_word(&mut self, w: u32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::add_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn sub_word(&mut self, w: u32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::sub_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mul_word(&mut self, w: u32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::mul_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn div_word(&mut self, w: u32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::div_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mod_exp(&self, a: &BigNumber, b: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &b.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &b.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn modulus(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::nnmod(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::nnmod(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn exp(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn inverse(&self, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_inverse(&mut bn.openssl_bn, &self.openssl_bn, &n.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_inverse(&mut bn.openssl_bn, &self.openssl_bn, &n.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn mod_div(&self, b: &BigNumber, p: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        //(a*  (1/b mod p) mod p)

        let mut context = BigNumber::new_context()?;

        let res = b
            .inverse(p, Some(&mut context))?
            .mul(&self, Some(&mut context))?
            .modulus(&p, Some(&mut context))?;
        Ok(res)
    }

    pub fn clone(&self) -> Result<BigNumber, IndyCryptoError> {
        Ok(BigNumber {
            openssl_bn: BigNum::from_slice(&self.openssl_bn.to_vec()[..])?
        })
    }

    pub fn hash_array(nums: &Vec<Vec<u8>>) -> Result<Vec<u8>, IndyCryptoError> {
        let mut sha256 = Hasher::new(MessageDigest::sha256())?;

        for num in nums.iter() {
            sha256.update(&num)?;
        }

        Ok(sha256.finish2()?.to_vec())
    }
}

impl Ord for BigNumber {
    fn cmp(&self, other: &BigNumber) -> Ordering {
        self.openssl_bn.ucmp(&other.openssl_bn)
    }
}

impl Eq for BigNumber {}

impl PartialOrd for BigNumber {
    fn partial_cmp(&self, other: &BigNumber) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BigNumber {
    fn eq(&self, other: &BigNumber) -> bool {
        self.openssl_bn == other.openssl_bn
    }
}

#[cfg(feature = "serialization")]
impl Serialize for BigNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_newtype_struct("BigNumber", &self.to_dec().map_err(SError::custom)?)
    }
}

#[cfg(feature = "serialization")]
impl<'a> Deserialize<'a> for BigNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'a> {
        struct BigNumberVisitor;

        impl<'a> Visitor<'a> for BigNumberVisitor {
            type Value = BigNumber;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected BigNumber")
            }

            fn visit_str<E>(self, value: &str) -> Result<BigNumber, E>
                where E: DError
            {
                Ok(BigNumber::from_dec(value).map_err(DError::custom)?)
            }
        }

        deserializer.deserialize_str(BigNumberVisitor)
    }
}

impl From<ErrorStack> for IndyCryptoError {
    fn from(err: ErrorStack) -> IndyCryptoError {
        // TODO: FIXME: Analyze ErrorStack and split invalid structure errors from other errors
        IndyCryptoError::InvalidStructure(err.description().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json;

    const RANGE_LEFT: usize = 592;
    const RANGE_RIGHT: usize = 592;

    #[test]
    #[ignore] //TODO check
    fn generate_prime_in_range_works() {
        let start = BigNumber::rand(RANGE_LEFT).unwrap();
        let end = BigNumber::rand(RANGE_RIGHT).unwrap();
        let random_prime = BigNumber::generate_prime_in_range(&start, &end).unwrap();
        assert!(start < random_prime);
        assert!(end > random_prime);
    }

    #[test]
    fn is_prime_works() {
        let primes:Vec<u64> = vec![2, 23, 31, 42885908609, 24473809133, 47055833459];
        for pr in primes {
            let num = BigNumber::from_dec(&pr.to_string()).unwrap();
            assert!(num.is_prime(None).unwrap());
        }
        let num = BigNumber::from_dec("36").unwrap();
        assert!(!num.is_prime(None).unwrap());

        let mut n128 = BigNumber::new().unwrap();
        BigNumRef::generate_prime(&mut n128.openssl_bn, 128, false, None, None).unwrap();
        assert!(n128.is_prime(None).unwrap());
        let mut n256 = BigNumber::new().unwrap();
        BigNumRef::generate_prime(&mut n256.openssl_bn, 256, false, None, None).unwrap();
        assert!(n256.is_prime(None).unwrap());

        let vec1 = vec![9, 252, 51, 8, 129]; // big endian representation of 42885908609
        let v1 = BigNumber::from_bytes(&vec1).unwrap();
        assert!(v1.is_prime(None).unwrap());
        let vec2 = vec![129, 8, 51, 252, 9]; // little endian representation of 42885908609
        let v2 = BigNumber::from_bytes(&vec2).unwrap();
        assert!(!v2.is_prime(None).unwrap());
        let vec3 = vec![1, 153, 25]; // big endian representation of 104729
        let v3 = BigNumber::from_bytes(&vec3).unwrap();
        assert!(v3.is_prime(None).unwrap());
    }

    #[test]
    fn modular_inverse() {
        let p_safe = BigNumber::generate_safe_prime(1024).unwrap();
        let q_safe = BigNumber::generate_safe_prime(1024).unwrap();
        let n = p_safe.mul(&q_safe, None).unwrap();
        let number_1 = BigNumber::from_dec("1").unwrap();

        let start_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        for _i in 1..10001 {
            let mut prime1 = BigNumber::generate_prime(256).unwrap();
            let mut prime1_inv = prime1.inverse(&n, None).unwrap();
            let mut product = prime1.mod_mul(&prime1_inv, &n, None).unwrap();
//            println!("{:?} {:?}", prime1, prime1_inv);
            assert_eq!(product, number_1)
        }
        println!("{:?}", start_since_the_epoch);
        let end_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        println!("{:?}", end_since_the_epoch);
        println!("{:?}", end_since_the_epoch.as_secs()-start_since_the_epoch.as_secs());
        println!("{:?}", end_since_the_epoch.subsec_nanos()-start_since_the_epoch.subsec_nanos());
    }

    #[test]
    fn accumulation() {
        let element_size: usize = 256;
        let generator_size: usize = 1024;
        let factor_size: usize = 1024;
        let p_safe = BigNumber::generate_safe_prime(factor_size).unwrap();
        let q_safe = BigNumber::generate_safe_prime(factor_size).unwrap();
        let p_prime = p_safe.sub(&BigNumber::from_u32(1).unwrap()).unwrap();
        let q_prime = q_safe.sub(&BigNumber::from_u32(1).unwrap()).unwrap();
        let n = p_safe.mul(&q_safe, None).unwrap();
        let m = p_prime.mul(&q_prime, None).unwrap();
        let g = BigNumber::generate_safe_prime(generator_size).unwrap();;
        let mut accumulator = g.clone().unwrap();
        let mut product_modn = BigNumber::from_dec("1").unwrap();
        let mut product_modm = BigNumber::from_dec("1").unwrap();
        println!("Before: Accumulator {:?} g {:?}", accumulator, g);
        for _i in 1..31 {
            let mut prime = BigNumber::generate_prime(element_size).unwrap();
            println!("Prime {:?}", prime);
            product_modn = product_modn.mod_mul(&prime, &n, None).unwrap();
            product_modm = product_modm.mod_mul(&prime, &m, None).unwrap();
            accumulator = accumulator.mod_exp(&prime, &n, None).unwrap();
        }
        let g_pr_mod_m = g.mod_exp(&product_modm, &n, None).unwrap();
        let g_pr_mod_n = g.mod_exp(&product_modn, &n, None).unwrap();
        println!("After: Accumulator {:?} g {:?}", accumulator, g);
        println!("Product mod n {:?}", product_modn);
        println!("Product mod m {:?}", product_modm);
        println!("g to the power mod m {:?}", product_modm);
        println!("g to the power mod n {:?}", product_modn);
        assert_eq!(accumulator, g_pr_mod_m);
        assert_ne!(accumulator, g_pr_mod_n);
    }

    #[test]
    fn exponentiation_time() {
        let generator = BigNumber::from_dec("1915182769368569486963976668657418846122016471585262452138689064979880063217142171230525667406114297912997697884669760718181148903891406258652154564474937314809392827351229074850339882653085906709452763512017926382658040877860425398565313118206001571983057266861433787870120516963262872556160137632986790799637800187327525373894833699998137974425675888510468704041321563743266953919273330110447213516904474856325884904918747921700098338253140217925656078220294833113261362981479227102302139442862538529417112227112104830922667359007109709204936925922862592053626140248383988977967399826184116697852122995719423774656923017777301713520425580745782097460248899329835740441429284020663186635354571333690692107185946297929772630086928323118606594588790915139339431940489511850279806818826143040378319619062305629273497273725721368157955512179352674013822087432127910233025333571203452180390613181846035364105352384024395662959142236311712295552933323767329374261596612060957502167831080774021620823718240397211269873903737841346862215246685242302847894894907938934985950908016181737929997451061016202494801606490097096889822976223609532834237496884730642312786447889763148272139117981855545441295507862786712405210727374768044118436617961").unwrap();
        let modulus = BigNumber::from_dec("3204629348400311894981147889064213475911502950610822910497794640539580108252311103815602649702091072442089016826192705629222534383850640976103541074965825911439481511841669818218556523699545667979238433531950872370285535430396347665030321087803912182039011247460768098263564546879241877558066260767468387251243972651463237193324761892342299558684399419909028079667195672054655387173203038107042778744649155842364672936664532754000715885900524415403622527226575507346822066350920781137340258848229685505555558665781467456342659911415599377043489979596237979941386501264463874766166877146485965674900595259972161874714381016252770855749700706860768647580178487242906896883599546187195495868346449603306725234279605044720570340541521141682943069084999263530360914420274990375408153529679146137934097158741957518183323298580558730909779698051995609396227449697670716584357361212378371486020465912177797480071144296559699016912326564059836301570632836543118917475972178423287627710340103368809606657431184660768586693677060010145686280797896075497757615632909442703186036300871183851569319692562563918216157762976445282183184528709786306196550055260857987968870798605413506633826598403862811608523439523945519737279157633473140586034211201").unwrap();
        let element_size: usize = 1500;
        let mut accumulator = generator.clone().unwrap();
        let start_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let total = 100;
        for _ in 0..total {
            println!("Accumulator is {:?}", accumulator);
            let start_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            let mut prime = BigNumber::generate_prime(element_size).unwrap();
            println!("prime is {:?}", prime);
            let end_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
//            println!("Time to generate prime {:?}", end_since_the_epoch.subsec_nanos()-start_since_the_epoch.subsec_nanos());

            let start_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            accumulator = accumulator.mod_exp(&prime, &modulus, None).unwrap();
            let end_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
//            println!("Time to exponentiate {:?}", end_since_the_epoch.subsec_nanos()-start_since_the_epoch.subsec_nanos());
        }
        let end_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        println!("Time to generate and exponentiate {} primes is {:?}", total, end_since_the_epoch.as_secs()-start_since_the_epoch.as_secs());
    }

    #[cfg(feature = "serialization")]
    #[derive(Serialize, Deserialize)]
    struct Test {
        field: BigNumber
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn serialize_works() {
        let s = Test { field: BigNumber::from_dec("1").unwrap() };
        let serialized = serde_json::to_string(&s);

        assert!(serialized.is_ok());
        assert_eq!("{\"field\":\"1\"}", serialized.unwrap());
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn deserialize_works() {
        let s = "{\"field\":\"1\"}";
        let bn: Result<Test, _> = serde_json::from_str(&s);

        assert!(bn.is_ok());
        assert_eq!("1", bn.unwrap().field.to_dec().unwrap());
    }
}
