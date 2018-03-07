use bn::{BigNumber, BigNumberContext};
use utils::commitment::get_pedersen_commitment;
use utils::rsa::generate_RSA_modulus;
use errors::IndyCryptoError;
use super::constants::*;

#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::mem;

#[cfg(test)]
thread_local! {
  pub static USE_MOCKS: RefCell<bool> = RefCell::new(false);
}

#[cfg(test)]
pub struct MockHelper {}

#[cfg(test)]
impl MockHelper {
    pub fn inject() {
        USE_MOCKS.with(|use_mocks| {
            *use_mocks.borrow_mut() = true;
        });
    }

    pub fn is_injected() -> bool {
        USE_MOCKS.with(|use_mocks| {
            return *use_mocks.borrow();
        })
    }
}

#[cfg(test)]
pub fn bn_rand(size: usize) -> Result<BigNumber, IndyCryptoError> {
    if MockHelper::is_injected() {
        return match size {
            R_0_SIZE => Ok(BigNumber::from_dec("48494631233207955414853387579459463667625284089442525091171986044059375848170630925424510748349918677840484459795910981760195632663159075063144770240917652713621089799017299698306302266805293701042461417057168331260940672146774932257056859706038053676216817045826698701820174406548527622912293747330765189484")?),
            P_0_SIZE => Ok(BigNumber::from_dec("20592452604296582555839505745748811131448526227355210412654253024947815250162847742042686438330316346994288352532060872899276918010600129738735237120867676836478877942523578375351493929471873540630420516112649777881879039142807612228922648860771278153908040065768051990454574764941823655051005790263974831023")?),
            POLICY_ADDRESS_SIZE => Ok(BigNumber::from_dec("5335497231318891902548990386467574848779258208603411211906580985229414017413")?),
            SECRET_SIZE => Ok(BigNumber::from_dec("17446008246355142382618942024717783446146867812515892348776265188820655174637")?),
            _ => {
                panic!("Uncovered case: {}", size);
            }
        };
    }
    _bn_rand(size)
}

#[cfg(not(test))]
pub fn bn_rand(size: usize) -> Result<BigNumber, IndyCryptoError> {
    _bn_rand(size)
}

pub fn _bn_rand(size: usize) -> Result<BigNumber, IndyCryptoError> {
    trace!("Helpers::bn_rand: >>> size:: {:?}", size);

    let res = BigNumber::rand(size)?;

    trace!("Helpers::bn_rand: <<< res: {:?}", res);

    Ok(res)
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

    let p_0 = BigNumber::from_dec(P_0)?;

    let mut double_commitment;
    let mut r_0;

    loop {
        r_0 = BigNumber::rand(R_0_SIZE)?;
        if r_0 >= p_0 { continue; }
        let first_commitment = get_pedersen_commitment(g_1, secret, h_1, &r_0, mod1, ctx)?;
        double_commitment = get_pedersen_commitment(g_2, &first_commitment, h_2, policy_address, mod2, ctx)?;
        if double_commitment.is_prime(Some(ctx))? { break; }
    }
    trace!("Helpers::gen_double_commitment_to_secret: <<< double_commitment: {:?}", double_commitment);

    Ok((double_commitment, r_0))
}

pub fn generate_policy_address() -> Result<BigNumber, IndyCryptoError> {
    generate_nonce(POLICY_ADDRESS_SIZE, None, &BigNumber::from_dec(P_0)?)
}

pub fn generate_nonce(size: usize, lower: Option<&BigNumber>, upper: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
    if let Some(l) = lower {
        loop {
            let r = bn_rand(size)?;
            if *l < r && r < *upper {
                return Ok(r);
            }
        }
    }
    loop {
        let r = bn_rand(size)?;
        if r < *upper {
            return Ok(r);
        }
    }
}

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {
        {
            let mut map = ::std::collections::HashMap::new();
            $(
                map.insert($key, $val);
            )*
            map
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_commitment() {
        let mut ctx = BigNumber::new_context().unwrap();

        let g_1_1 = BigNumber::from_dec(G_1_1).unwrap();
        let g_1_2 = BigNumber::from_dec(G_1_2).unwrap();
        let g_2_1 = BigNumber::from_dec(G_2_1).unwrap();
        let g_2_2 = BigNumber::from_dec(G_2_2).unwrap();
        let mod_1 = BigNumber::from_dec(P_1).unwrap();
        let mod_2 = BigNumber::from_dec(P_2).unwrap();

        let secret = BigNumber::rand(SECRET_SIZE).unwrap();;
        let policy_address = BigNumber::rand(POLICY_ADDRESS_SIZE).unwrap();

        let (comm, r_0) = gen_double_commitment_to_secret(&g_1, &h_1, &secret, &g_2, &h_2,
                                                        &policy_address, &mod_1,
                                                        &mod_2, &mut ctx).unwrap();
        assert!(comm.is_prime(Some(&mut ctx)).unwrap());
        assert!(r_0 < BigNumber::from_dec(P_0).unwrap());
    }

    #[test]
    #[ignore] //TODO Expensive test, only run to generate public params
    fn test_generate_public_ps() {
        // Generating primes p_0, p_1, p_2, p_3, such that p_1, p_2, p_3 are safe primes satisfying
        // p_1 = 2p_0 + 1; p_2 = 2p_1 + 1; p_3 = 2p_2 + 1

        let mut ctx = BigNumber::new_context().unwrap();

        let mut p_0;
        let mut p_1;
        let mut p_2;
        let mut attempt = 1;

        println!("Generating p values");

        loop {
            println!("Attempt {:?}", attempt);
            p_0 = BigNumber::generate_safe_prime(P_0_SIZE+1).unwrap();

            p_1 = p_0.lshift1().unwrap()
                     .increment().unwrap();

            if p_1.is_prime(Some(&mut ctx)).unwrap() {
                println!("p_1 is prime");

                p_2 = p_1.lshift1().unwrap()
                         .increment().unwrap();

                if p_2.is_prime(Some(&mut ctx)).unwrap() {
                    break;
                } else {
                    p_2 = p_0.decrement().unwrap()
                             .rshift1().unwrap();

                    if p_2.is_prime(Some(&mut ctx)).unwrap() {
                        mem::swap(&mut p_0, &mut p_1);
                        mem::swap(&mut p_0, &mut p_2);
                        break;
                    }

                    println!("p_2 is not prime");
                }
            } else {
                println!("Bigger didn't work");
                p_1 = p_0.decrement().unwrap()
                         .rshift1().unwrap();

                //Should always work
                if p_1.is_prime(Some(&mut ctx)).unwrap() {

                    p_2 = p_1.decrement().unwrap()
                             .rshift1().unwrap();

                    if p_2.is_prime(Some(&mut ctx)).unwrap() {
                        mem::swap(&mut p_0, &mut p_2);
                        break;
                    }
                }
                println!("Smaller didn't work");
            }
            attempt = attempt + 1;
        }


        let p_3 = BigNumber::generate_safe_prime(P_3_SIZE).unwrap();

        println!("p_0={:?}", p_0);
        println!("p_1={:?}", p_1);
        println!("p_2={:?}", p_2);
        println!("p_3={:?}", p_3);
    }

    #[test]
    fn test_check_public_ps() {
        let mut ctx = BigNumber::new_context().unwrap();
        let p_0 = BigNumber::from_dec(P_0).unwrap();
        let p_1 = BigNumber::from_dec(P_1).unwrap();
        let p_2 = BigNumber::from_dec(P_2).unwrap();
        let p_3 = BigNumber::from_dec(P_3).unwrap();

//        let p_0=BigNumber::from_dec("342746746630198769587188362941633361135560124689646425521680977506225322276387227741067034544479094411714004599311120760485035571655778439484768711370405653282832105442822212127931391170907193584210573852292058253615408787319187355584026249235847398250452645512426120385580225504856590490940029951599115616979").unwrap();
//        let p_1=BigNumber::from_dec("685493493260397539174376725883266722271120249379292851043361955012450644552774455482134069088958188823428009198622241520970071143311556878969537422740811306565664210885644424255862782341814387168421147704584116507230817574638374711168052498471694796500905291024852240771160451009713180981880059903198231233959").unwrap();
//        let p_2=BigNumber::from_dec("1370986986520795078348753451766533444542240498758585702086723910024901289105548910964268138177916377646856018397244483041940142286623113757939074845481622613131328421771288848511725564683628774336842295409168233014461635149276749422336104996943389593001810582049704481542320902019426361963760119806396462467919").unwrap();
//        let p_3=BigNumber::from_dec("4806876214089177439121678559764069543282270755154137981051366776821330958611719328037311759924923156830623290278296826263863902327008664143707117531049168010908663795201825132050017581985031718536424081509084930569115857201636971728388275433540277562846153879803474020036767852693656753257597801227199822164846876100177774044259379232968071371318658371230787073384750022830829873718254139779006439569882904712552834431199870749249168775012460891012776977366721903").unwrap();

//        let p_0=BigNumber::from_dec("289352949328666070181364406941444326077805992703685859224772908020973916188437002420751727343325395550850303903236198426526817174941170776689008429400553159234173888652221843570821954806415125040209822644349357507254662834115945752708227363578502312436305700782449237685072095101766134407093709707459682861671").unwrap();
//        let p_1=BigNumber::from_dec("578705898657332140362728813882888652155611985407371718449545816041947832376874004841503454686650791101700607806472396853053634349882341553378016858801106318468347777304443687141643909612830250080419645288698715014509325668231891505416454727157004624872611401564898475370144190203532268814187419414919365723343").unwrap();
//        let p_2=BigNumber::from_dec("1157411797314664280725457627765777304311223970814743436899091632083895664753748009683006909373301582203401215612944793706107268699764683106756033717602212636936695554608887374283287819225660500160839290577397430029018651336463783010832909454314009249745222803129796950740288380407064537628374838829838731446687").unwrap();
//        let p_3=BigNumber::from_dec("4303003089309485416067779399500861157780149200948830189664310600314501227382012382931816303525694083788926002322351937472669074517440770474831548110572744987388897088672114771213443347055641147722678883307125580160826920512299252392587374142318532458114296352387146288982866670587610946047363953576129649528926237923019615335751537902557336236271388620922460001266023362141969094439631579953069613108767749209987590972590210839233341977491965114151948097649110107").unwrap();

        assert!(p_0.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_1.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_2.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_3.is_prime(Some(&mut ctx)).unwrap());

        //TODO: use is_safe_prime
        assert_eq!(p_0, p_1.decrement().unwrap().rshift1().unwrap());
        assert_eq!(p_1, p_2.decrement().unwrap().rshift1().unwrap());
        assert_eq!(p_0.num_bits().unwrap() as usize, P_0_SIZE+1);
        assert_eq!(p_1.num_bits().unwrap() as usize, P_0_SIZE+2);
        assert_eq!(p_2.num_bits().unwrap() as usize, P_0_SIZE+3);
        assert_eq!(p_3.num_bits().unwrap() as usize, P_3_SIZE+1);

        let number1 = BigNumber::from_u32(1).unwrap();
        let number2 = BigNumber::from_u32(2).unwrap();
        assert!(p_0.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_1.is_safe_prime(Some(&mut ctx)).unwrap());
        assert!(p_2.is_safe_prime(Some(&mut ctx)).unwrap());
        assert!(p_3.is_safe_prime(Some(&mut ctx)).unwrap());
        assert_eq!(p_1, p_0.mul(&number2, Some(&mut ctx)).unwrap().add(&number1).unwrap());
        assert_eq!(p_2, p_1.mul(&number2, Some(&mut ctx)).unwrap().add(&number1).unwrap());
        assert_eq!(p_3, p_2.mul(&number2, Some(&mut ctx)).unwrap().add(&number1).unwrap());
    }

    #[test]
    #[ignore] //TODO Expensive test, only run to generate public params
    fn test_generate_generators() {
        // Generating g_1, g_2, g_3, h_1, h_2, h_3, g_n, h_n

        let p1 = BigNumber::from_dec(P_1).unwrap();
        let p2 = BigNumber::from_dec(P_2).unwrap();
        let p3 = BigNumber::from_dec(P_3).unwrap();
        let n = BigNumber::from_dec(ACCUM1_MODULUS).unwrap();
        let number1 = BigNumber::from_u32(1).unwrap();

        println!("g_1_1={:?}", _create_generator(&number1, &p1));
        println!("g_1_2={:?}", _create_generator(&number1, &p1));
        println!("g_1_3={:?}", _create_generator(&number1, &p1));
        println!("g_2_1={:?}", _create_generator(&number1, &p2));
        println!("g_2_2={:?}", _create_generator(&number1, &p2));
        println!("g_2_3={:?}", _create_generator(&number1, &p2));
        println!("g_3_1={:?}", _create_generator(&number1, &p3));
        println!("g_3_2={:?}", _create_generator(&number1, &p3));
        println!("g_N={:?}", _create_generator(&number1, &n));
        println!("h_N={:?}", _create_generator(&number1, &n));
    }

    fn _create_generator(number1: &BigNumber,
                         group: &BigNumber) -> BigNumber {
        let mut g;
        loop {
            g = BigNumber::random_QR(group).unwrap();
            if *number1 != g { break; }
        }
        g
    }

    #[test]  //Expensive test, only run to generate public params
    #[ignore]
    fn generate_a_and_b_values() {
        let A1 = BigNumber::generate_prime(ACCUM_A_SIZE).unwrap();
        let B1 = BigNumber::generate_prime(ACCUM_B_SIZE).unwrap();

        println!("A1={:?}", A1);
        println!("B1={:?}", B1);

        let mut A2;
        let mut B2;
        loop {
            A2 = BigNumber::generate_prime(ACCUM_A_SIZE).unwrap();
            if A1 != A2 {
                B2 = BigNumber::generate_prime(ACCUM_B_SIZE).unwrap();

                if B1 != B2 { break; }
            }
        }

        println!("A2={:?}", A2);
        println!("B2={:?}", B2);
    }

    #[test]
    #[ignore] //TODO Expensive test, only run to generate public params
    fn test_generate_public_accumulator_moduli() {
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
        let i = generate_policy_address().unwrap();
        assert!(i < BigNumber::from_dec(P_0).unwrap());
    }
}
