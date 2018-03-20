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
            128 => Ok(BigNumber::from_dec("92463499845682298368924329373611179898")?),
            4094 => Ok(BigNumber::from_dec("73142877520184868952461107514686880537289086380843331448330173363821948941982598634589912899771846698119500329723018322099503041728084640576284992855391485650728024053452574938132663699456826365534257436132033651960338034015948371755787564189736131422642045458260490469887620578455257036315501922717007496568914062315340987915563343887693705667053423347952541122926742345523725616515404559078379887393781879936351291201206345075290671281649427310428155466345304256281783365380790922519081494135130680455533314974445264438905973811879024975034967391010206045025264331923234225673901188903955073094921791324116408038546384010223390207183426812091267364773256554328363214442035569536972695776849024022212858077977775894020993660322782815860964850518222346048838180235085597448904526156064854151767146299729359615695517319406134117645068497200826737638845238797661709479428120537593079754675083005238992238711542003730857248585016391913645303532581995227949274856902708803810531122747517135250258787766925878149832295563193179891805348198752851569982306223536576367777713794956609593281637508810788356868432042154282618548492266706078426627489068214136719929773268073719237157880580625274511328351827907915501375712330619309115953747456")?),
            1282 => Ok(BigNumber::from_dec("4119948197077937115187023948168934828432628772115050077821356213850205658741099562225271983511944816020476858741999333013643717268111832121837462999300401243707912910424284762280491485344724600005853196704733469273147682388283341513129080971599743588316299143965114557405768762659424988518941760494075567121618422506032419986944700959516608021545908292031816402335192180620196923686509")?),
            P_3_SIZE => Ok(BigNumber::from_dec("2204759580196030475539717384874585053268957408497622063609119331773734529872587439894192421106178234254378771919275377769510946068267394284020679039520399265067199182415970117265634837003052518830579192434346189738394159943691758281393331616487196741296404446979837744800766667982893845063764660986439632005384563600376889051773459124263871117485999846494531840940894278099556994214305610002011733466496332514538145085555215960568136654660319701613573062104412576")?),
            ACCUM_MODULUS_SIZE => Ok(BigNumber::from_dec("22931080656637753399271113513979248503498661735703213416118457548733696923590859979542159312519852182766800607280378267860300950674257329948172840737823515551383174155166456272513426217762327004984604160584036946819582744279681727326471147834381317444715145395265561289064895673601017811358474829030759105573252239244521288510898209858079173680740752017892466429264936491407579856776149077256541574774671981465200234805260053028689101568922327726281204310862210723961990466609376194838392649798390716061090762979574672610578450837474650206888414243311215591717853867547557701024178505785697437106734157399503231098408150412881135700329380567350732605358377042359475733151168170257976185987394412987899051780137074331249279902341902179115891201928857492531596567076885150159997021146395635674250636588017411292050812681031459722608898462326470972297051434510446325918319597266302472912470578110251158716612456405947433774141832932340220412385280296215773896859077018572593613991611381002068943498129510115553425733307825726056867767722073984981158138992285741104219013739224273238170500316650329505894844514920206354078612638072470558565134693176536867097300715694934446544084548912381204091961209567746793588567030054356143545715249")?),
            2128 => Ok(BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436")?),
            3060 => Ok(BigNumber::from_dec("241132863422049783305938184561371219250127488499746090592218003869595412171810997360214885239402274273939963489505434726467041932541499422544431299362364797699330176612923593931231233163363211565697860685967381420219969754969010598350387336530924879073366177641099382257720898488467175132844984811431059686249020737675861448309521855120928434488546976081485578773933300425198911646071284164884533755653094354378714645351464093907890440922615599556866061098147921890790915215227463991346847803620736586839786386846961213073783437136210912924729098636427160258710930323242639624389905049896225019051952864864612421360643655700799102439682797806477476049234033513929028472955119936073490401848509891547105031112859155855833089675654686301183778056755431562224990888545742379494795601542482680006851305864539769704029428620446639445284011289708313620219638324467338840766574612783533920114892847440641473989502440960354573501")?),
            456 => Ok(BigNumber::from_dec("162083298053730499878539835193560156486733663622707027216327685550780519347628838870322946818623352681120371349972731968874009673965057322")?),
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

pub fn get_map_value<'a>(map: &'a ::std::collections::HashMap<String, BigNumber>, key: &str, msg: String) -> Result<&'a BigNumber, IndyCryptoError> {
    map.get(key).ok_or(IndyCryptoError::InvalidStructure(msg))
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    #[ignore]
    fn test_accumulator_compute() {
        let n = BigNumber::from_dec(ACCUM1_MODULUS).unwrap();
        let g_n = BigNumber::from_dec(G_N).unwrap();
        let total = 2000;

        println!("Generating {} primes", total);
        print!("Generating 1");
        let mut stdout = ::std::io::stdout();
        stdout.flush().unwrap();

        let mut primes = Vec::new();
        for i in 0..total {
            primes.push(BigNumber::generate_prime(R_0_SIZE).unwrap());
            for _ in 0..i.to_string().len() {
                print!("\x08");
            }
            print!("{}", i + 1);
            stdout.flush().unwrap();
        }
        println!();

        println!("Starting timing test to accumulate {} commitments", total);

        let mut ctx = BigNumber::new_context().unwrap();
        let mut acc = g_n;
        let now = ::std::time::Instant::now();
        for prime in primes {
            acc = acc.mod_exp(&prime, &n, Some(&mut ctx)).unwrap();
        }
        println!("Total time {}", now.elapsed().as_secs());
    }

    #[test]
    fn test_double_commitment() {
        let mut ctx = BigNumber::new_context().unwrap();

        let g_1 = BigNumber::from_dec(G_1).unwrap();
        let h_1 = BigNumber::from_dec(H_1).unwrap();
        let g_2 = BigNumber::from_dec(G_2).unwrap();
        let h_2 = BigNumber::from_dec(H_2).unwrap();
        let mod_1 = BigNumber::from_dec(P_1).unwrap();
        let mod_2 = BigNumber::from_dec(P_2).unwrap();

        let secret = BigNumber::rand(SECRET_SIZE).unwrap();;
        let policy_address = BigNumber::rand(POLICY_ADDRESS_SIZE).unwrap();

        let (comm, r_0) = gen_double_commitment_to_secret(&g_1, &h_1, &secret, &g_2, &h_2,
                                                        &policy_address, &mod_1,
                                                        &mod_2, &mut ctx).unwrap();
        assert!(comm.is_prime(Some(&mut ctx)).unwrap());
        assert!(r_0 < BigNumber::from_dec(P_0).unwrap());
        println!("Comm {:?} {:?}", BigNumber::to_dec(&comm), BigNumber::to_dec(&policy_address));
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

        assert!(p_0.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_1.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_2.is_prime(Some(&mut ctx)).unwrap());
        assert!(p_3.is_prime(Some(&mut ctx)).unwrap());

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
        let subgroup1 = |g: &BigNumber, p: &BigNumber| {
            g.sqr(None).unwrap().modulus(p, None).unwrap() != number1 &&
            g.mod_exp(&p.decrement().unwrap().rshift1().unwrap(), p, None).unwrap() != number1
        };

        let subgroup2 = |g: &BigNumber, p: &BigNumber| {
            g.sqr(None).unwrap().modulus(p, None).unwrap() != number1 &&
            g.mod_exp(&p.decrement().unwrap().rshift1().unwrap(), p, None).unwrap() == number1
        };
        let subgroup3 = |g: &BigNumber, p: &BigNumber| {
            g.sqr(None).unwrap().modulus(p, None).unwrap() != number1
        };

        println!("g_1={:?}", _create_generator(&p1, &subgroup1));
        println!("h_1={:?}", _create_generator(&p1, &subgroup1));
        println!("k_1={:?}", _create_generator(&p1, &subgroup1));
        println!("g_2={:?}", _create_generator(&p2, &subgroup1));
        println!("h_2={:?}", _create_generator(&p2, &subgroup1));
        println!("k_2={:?}", _create_generator(&p2, &subgroup1));
        println!("g_3={:?}", _create_generator(&p3, &subgroup2));
        println!("h_3={:?}", _create_generator(&p3, &subgroup2));
        println!("g_N={:?}", _create_generator(&n, &subgroup3));
        println!("h_N={:?}", _create_generator(&n, &subgroup3));
    }

    fn _create_generator(group: &BigNumber,
                         predicate: &Fn(&BigNumber, &BigNumber) -> bool) -> BigNumber {
        let mut g;
        loop {
            g = BigNumber::rand_range(group).unwrap();
            if predicate(&g, group) {
                break;
            }
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
