extern crate rand;

use secp256k1;

pub mod client {
    use crate::{server, primitives::{Engine, Secret}};
    use aes_gcm::Aes256Gcm;
    use aead::{Aead, NewAead, generic_array::GenericArray};
    use hex;
    use gmp;

    const DIGEST_SIZE: usize = 32;
    const CURVE_SIZE: usize = 33;

    pub struct Client {
        pub(crate) username: String,
        pub(crate) password: String,
        pub(crate) engine: Engine,
    }

    pub struct Session {
        r: Secret,
        xu: Secret,
    }

    impl Client {
        pub fn new(username: &str, password: &str) -> Self {
            let engine = Engine::new();
            Self{username: username.to_string(), password: password.to_string(), engine}
        }

        pub fn login(&self) -> (Session, server::LoginRequest) {
            let r = Engine::gen_key();
            let xu = Engine::gen_key();
            let alpha = self.engine.to_curve(self.password.as_bytes(), r.0.as_ref());
            let Xu = self.engine.exp(&xu);
            (Session{ r, xu }, server::LoginRequest{alpha, Xu})
        }

        pub fn complete(&self, session: Session, mut login: server::LoginResponse, As: Option<secp256k1::PublicKey>) -> [u8; DIGEST_SIZE] {
            // Check that beta is not the generator
            let mut buf = [0u8; DIGEST_SIZE];
            let modulus = gmp::mpz::Mpz::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).expect("modulus");
            let val = gmp::mpz::Mpz::from_str_radix(&hex::encode(session.r.0.as_ref()), 16).expect("val");
            let inv = val.invert(&modulus).expect("inv");
            let mut buf = [0u8; DIGEST_SIZE];
            let mut inv_string = inv.to_str_radix(16);
            if inv_string.len() % 2 != 0 {
                inv_string = "0".to_string() + &inv_string;
            }
            let inv_buf = hex::decode(&inv_string).expect("inv to str");
            buf[DIGEST_SIZE-inv_buf.len()..].copy_from_slice(&inv_buf);
            let inv_secret = Secret(buf);
            self.engine.custom_exp(&mut login.beta, &inv_secret);
            let rw = Engine::hash(self.password.as_bytes(), &login.beta);

            let enc_key = GenericArray::clone_from_slice(rw.as_ref());
            let aead = Aes256Gcm::new(enc_key);
            let nonce = GenericArray::from_slice(b"unique_nonce");
            let decryption = aead.encrypt(nonce, login.ciphertext.as_ref()).expect("Encryption Failure");

            let mut pu_buf = [0u8; DIGEST_SIZE];
            pu_buf.copy_from_slice(&decryption[..DIGEST_SIZE]);
            let pu = Secret(pu_buf);

            let Pu = secp256k1::PublicKey::from_slice(&decryption[DIGEST_SIZE..DIGEST_SIZE+CURVE_SIZE]).expect("Pu from slice");
            let Ps = secp256k1::PublicKey::from_slice(&decryption[DIGEST_SIZE+CURVE_SIZE..DIGEST_SIZE+2*CURVE_SIZE]).expect("Ps from slice");

            let Xu = self.engine.exp(&session.xu);

            let eu = Secret(Engine::hash("Server".as_bytes(), &Xu));
            let es = Secret(Engine::hash(self.username.as_bytes(), &login.Xs));

            let mut temp = secp256k1::PublicKey::from_slice(Ps.serialize().as_ref()).expect("temp");
            self.engine.custom_exp(&mut temp, &es);
            let mut lhs = temp.combine(&login.Xs).expect("lhs");

            let mut rhs = secp256k1::PublicKey::from_slice(lhs.serialize().as_ref()).expect("rhs");
            self.engine.custom_exp(&mut lhs, &session.xu);
            self.engine.custom_exp(&mut rhs, &eu);
            self.engine.custom_exp(&mut rhs, &pu);

            let out = lhs.combine(&rhs).expect("out");

            Engine::hash("".as_bytes(), &out)
        }
    }
}

pub mod server {
    use crate::{client , primitives::{Engine, Secret}};
    use std::collections::HashMap;
    use aes_gcm::Aes256Gcm;
    use aead::{Aead, NewAead, generic_array::GenericArray};
    use std::convert::TryFrom;

    const DIGEST_SIZE: usize = 32;
    const CURVE_SIZE: usize = 33;

    #[derive(Hash, Debug)]
    pub struct File {
        pub(crate) ks: Secret,
        pub(crate) ps: Secret,
        pub(crate) Ps: secp256k1::PublicKey,
        pub(crate) Pu: secp256k1::PublicKey,
        pub(crate) c: Vec<u8>,
    }

    impl Clone for File {
        fn clone(&self) -> Self {
            let mut buf_ks = [0u8; DIGEST_SIZE];
            buf_ks.copy_from_slice(self.ks.0.as_ref());
            let ks = Secret(buf_ks);
            let mut buf_ps = [0u8; DIGEST_SIZE];
            let ps = Secret(buf_ps);
            buf_ps.copy_from_slice(self.ps.0.as_ref());
            let Ps = secp256k1::PublicKey::from_slice(self.Ps.serialize().as_ref()).unwrap();
            let Pu = secp256k1::PublicKey::from_slice(self.Pu.serialize().as_ref()).unwrap();
            let c = self.c.clone();
            Self{ks, ps, Ps, Pu, c}
        }
    }

    pub struct Session {
        xs: Secret,
    }

    pub struct Server {
        pub(crate) backend: HashMap<String, File>,
        engine: Engine,
    }

    pub struct LoginRequest {
        pub(crate) alpha: secp256k1::PublicKey,
        pub(crate) Xu: secp256k1::PublicKey,
    }

    impl From<LoginRequest> for Vec<u8> {
        fn from(login: LoginRequest) -> Self {
            let mut buf = Vec::new();
            buf.append(&mut login.alpha.serialize().to_vec());
            buf.append(&mut login.Xu.serialize().to_vec());
            buf
        }
    }

    impl TryFrom<&Vec<u8>> for LoginRequest {
        type Error = &'static str;

        fn try_from(buf: &Vec<u8>) -> Result<Self, Self::Error> {
            let buf_len = buf.len();
            if buf_len >= 66 {
                if let Ok(alpha) = secp256k1::PublicKey::from_slice(&buf[..33]) {
                    if let Ok(Xu) = secp256k1::PublicKey::from_slice(&buf[33..66]) {
                        return Ok(LoginRequest{ alpha, Xu });
                    }
                    return Err("Xu is not a valid public key");
                }
                return Err("Alpha is not a valid public key");
            }
            Err("LoginRequest must be exactly 66 bytes")
        }
    }

    pub struct LoginResponse {
        pub(crate) beta: secp256k1::PublicKey, 
        pub(crate) Xs: secp256k1::PublicKey,
        pub(crate) ciphertext: Vec<u8>,
    }

    impl From<LoginResponse> for Vec<u8> {
        fn from(mut login: LoginResponse) -> Self {
            let mut buf = Vec::new();
            buf.append(&mut login.beta.serialize().to_vec());
            buf.append(&mut login.Xs.serialize().to_vec());
            buf.append(&mut login.ciphertext);
            buf
        }
    }

    impl TryFrom<&Vec<u8>> for LoginResponse {
        type Error = &'static str;

        fn try_from(buf: &Vec<u8>) -> Result<Self, Self::Error> {
            if buf.len() >= 67 {
                if let Ok(beta) = secp256k1::PublicKey::from_slice(&buf[..33]) {
                    if let Ok(Xs) = secp256k1::PublicKey::from_slice(&buf[33..66]) {
                        let ciphertext = buf[66..].to_vec();
                        return Ok(LoginResponse{beta, Xs, ciphertext});
                    }
                }
            }
            Err("LoginResponse must be at least 67 bytes")
        }
    }

    impl Clone for Server {
        fn clone(&self) -> Self {
            let backend = self.backend.clone();
            let engine = Engine::new();
            Self{backend, engine}
        }
    }

    impl Server {
        pub fn new() -> Self {
            let backend = HashMap::new();
            let engine = Engine::new();
            Self{backend, engine}
        }

        pub fn setup(&mut self, username: &str, password: &str) -> bool {
            let username_str = username.to_string();
            if self.backend.contains_key(&username_str) {
                return false;
            }
            let ks = Engine::gen_key();
            let rw = self.engine.oprf(password.as_bytes(), &ks);
            let ps = Engine::gen_key();
            let Ps = self.engine.exp(&ps);
            let pu = Engine::gen_key();
            let Pu = self.engine.exp(&pu);
            let enc_key = GenericArray::clone_from_slice(rw.as_ref());
            let aead = Aes256Gcm::new(enc_key);
            let nonce = GenericArray::from_slice(b"unique_nonce");
            let mut buf = [0u8; DIGEST_SIZE + 2*CURVE_SIZE];
            buf[..DIGEST_SIZE].copy_from_slice(&pu.0);
            buf[DIGEST_SIZE..DIGEST_SIZE+CURVE_SIZE].copy_from_slice(Pu.serialize().as_ref());
            buf[DIGEST_SIZE+CURVE_SIZE..DIGEST_SIZE+2*CURVE_SIZE].copy_from_slice(Ps.serialize().as_ref());
            let c = aead.encrypt(nonce, buf.as_ref()).expect("Encryption Failure");
            self.backend.insert(username_str, File{ks, ps, Ps, Pu, c});
            true
        }

        pub fn process(&self, username: &str, login: &LoginRequest) -> Option<([u8; DIGEST_SIZE], Session, LoginResponse)> {
            // Check that alpha is not generator
            let username_str = username.to_string();
            if let Some(file) = self.backend.get(&username_str) {
                let mut beta = secp256k1::PublicKey::from_slice(login.alpha.serialize().as_ref()).expect("beta");
                let xs = Engine::gen_key();
                let session = Session{ xs };
                self.engine.custom_exp(&mut beta, &file.ks);
                let Xs = self.engine.exp(&session.xs);

                let es = Secret(Engine::hash(username.as_bytes(), &Xs));
                let eu = Secret(Engine::hash("Server".as_bytes(), &login.Xu));

                let mut temp = secp256k1::PublicKey::from_slice(file.Pu.serialize().as_ref()).expect("temp");
                self.engine.custom_exp(&mut temp, &eu);
                let mut lhs = temp.combine(&login.Xu).expect("lhs");

                let mut rhs = secp256k1::PublicKey::from_slice(lhs.serialize().as_ref()).expect("rhs");
                self.engine.custom_exp(&mut lhs, &session.xs);
                self.engine.custom_exp(&mut rhs, &es);
                self.engine.custom_exp(&mut rhs, &file.ps);

                let out = lhs.combine(&rhs).expect("out");

                let key = Engine::hash("".as_bytes(), &out);

                let Ps = self.engine.exp(&file.ps);

                return Some((key, session, LoginResponse{ beta, Xs, ciphertext: file.c.clone()}));
            }
            None
        }
    }
}

pub mod primitives {
    use sha2::{Sha256, Digest};
    use rand::{self, RngCore, SeedableRng};
    use rand_chacha::{ChaChaRng};

    const DIGEST_SIZE: usize = 32;
    const CURVE_SIZE: usize = 33;

    #[derive(Hash, Debug)]
    pub struct Secret(pub(crate) [u8; 32]);

    pub struct Engine {
        curve: secp256k1::Secp256k1<secp256k1::All>
    }

    impl Engine {
        pub fn new() -> Self {
            let mut curve = secp256k1::Secp256k1::new();
            Self { curve }
        }

        pub fn hash(lhs: &[u8], rhs: &secp256k1::PublicKey) -> [u8; DIGEST_SIZE] {
            let mut engine = Sha256::new();
            engine.input(lhs);
            engine.input(rhs.serialize().as_ref());
            let mut result = [0u8; DIGEST_SIZE];
            result.copy_from_slice(engine.result().as_ref());
            result
        }

        fn sha256_chacha20(input: &[u8]) -> [u8; CURVE_SIZE] {
            let mut seed_buf = [0u8; DIGEST_SIZE];
            seed_buf.copy_from_slice(Sha256::digest(input).as_ref());
            let mut rng = ChaChaRng::from_seed(seed_buf);
            let mut buf = [0u8; CURVE_SIZE];
            rng.fill_bytes(&mut buf);
            buf
        }

        pub fn to_curve(&self, input: &[u8], exp: &[u8]) -> secp256k1::PublicKey {
            let mut bytes = [0u8; CURVE_SIZE];
            let mut curve_point = Self::sha256_chacha20(input);
            loop {
                if let Ok(mut point) = secp256k1::PublicKey::from_slice(curve_point.as_ref()) {
                    point.mul_assign(&self.curve, exp).expect("point");
                    return point;
                }
                curve_point = Self::sha256_chacha20(curve_point.as_ref());
            }
        }

        pub fn gen_key() -> Secret {
            let mut bytes = [0u8; DIGEST_SIZE];
            loop {
                rand::thread_rng().fill_bytes(&mut bytes);
                if secp256k1::SecretKey::from_slice(bytes.as_ref()).is_ok() {
                    return Secret(bytes);
                }
            }
        }

        pub fn exp(&self, input:  &Secret) -> secp256k1::PublicKey {
           let secret = secp256k1::SecretKey::from_slice(input.0.as_ref()).expect("secret");
           secp256k1::PublicKey::from_secret_key(&self.curve, &secret)
        }

        pub fn custom_exp(&self, base: &mut secp256k1::PublicKey, input: &Secret) {
           base.mul_assign(&self.curve, input.0.as_ref()).expect("custom_exp");
        }

        pub fn oprf(&self, input: &[u8], key: &Secret) -> [u8; DIGEST_SIZE] { 
            let point = self.to_curve(input, &key.0);
            Self::hash(input, &point)
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Sha256, Digest};
    use secp256k1;
    use rand::{self, RngCore};
    use crate::{client, server, primitives};

    const DIGEST_SIZE: usize = 32;
    const CURVE_SIZE: usize = 33;

    #[test]
    fn it_works() {
        let mut server = server::Server::new();
        let mut bytes = [0u8; DIGEST_SIZE];
        rand::thread_rng().fill_bytes(&mut bytes);
        for i in 0..100 {
            let mut engine = Sha256::new();
            engine.input(bytes.as_ref());
            engine.input([i as u8].as_ref());
            assert!(server.setup(&format!("{}", i), &format!("password{:?}", engine.result())));
        }
        for i in 0..100 {
            let mut hash_engine = Sha256::new();
            hash_engine.input(bytes.as_ref());
            hash_engine.input([ i as u8 ].as_ref());
            let engine = primitives::Engine::new();
            let client = client::Client{ username: format!("{}", i), password: format!("password{:?}", hash_engine.result()), engine};
            let (client_session, login_request) = client.login();
            if let Some((server_secret, server_session, login_response)) = server.process(&client.username, &login_request) {
                let client_secret = client.complete(client_session, login_response, None);
                assert_eq!(hex::encode(server_secret.as_ref()), hex::encode(client_secret.as_ref()));
            } else {
                println!("Shit's not working");
            }
        }
    }
}
