extern crate rand;

use secp256k1;

mod client {
    use crate::primitives::{Hasher, Secret};
    use aes_gcm::Aes256Gcm;
    use aead::{Aead, NewAead, generic_array::GenericArray};
    use hex;
    use gmp;

    const DIGEST_SIZE: usize = 32;
    const CURVE_SIZE: usize = 33;

    pub struct Client {
        pub(crate) username: String,
        pub(crate) password: String,
    }

    pub struct Session {
        r: Secret,
        xu: Secret,
    }

    impl Client {
        pub fn login(&self) -> (Session, secp256k1::PublicKey, secp256k1::PublicKey) {
            let r = Hasher::gen_key();
            let xu = Hasher::gen_key();
            let hasher = Hasher::new();
            let alpha = hasher.to_curve(self.password.as_bytes(), r.0.as_ref());
            let Xu = hasher.exp(&xu)
            (Session{ r, xu }, alpha, Xu)
        }

        pub fn complete(&self, session: Session, mut beta: secp256k1::PublicKey, Xs: secp256k1::PublicKey, c: Vec<u8>, As: Option<secp256k1::PublicKey>) {
            // Check that beta is not the generator
            let hasher = Hasher::new();
            let mut buf = [0u8; DIGEST_SIZE];
            let modulus = gmp::mpz::Mpz::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
            let val = gmp::mpz::Mpz::from_str_radix(&hex::encode(session.r.0.as_ref()), 16).unwrap();
            let inv = val.invert(&modulus).unwrap();
            let mut buf = [0u8; DIGEST_SIZE];
            buf.copy_from_slice(&hex::decode(inv.to_str_radix(16)).unwrap());
            let invSecret = Secret(buf);
            hasher.custom_exp(&mut beta, &invSecret);
            let rw = Hasher::hash(self.password.as_bytes(), &beta);

            let enc_key = GenericArray::clone_from_slice(rw.as_ref());
            let aead = Aes256Gcm::new(enc_key);
            let nonce = GenericArray::from_slice(b"unique_nonce");
            let decryption = aead.encrypt(nonce, c.as_ref()).expect("Encryption Failure");
            let pu = decryption[..DIGEST_SIZE].to_vec();
            let Pu = decryption[DIGEST_SIZE..DIGEST_SIZE+CURVE_SIZE].to_vec();
            let Ps = decryption[DIGEST_SIZE+CURVE_SIZE..DIGEST_SIZE+2*CURVE_SIZE].to_vec();

            let Xu = hasher.exp(&xu);
            let eu = Hasher::hash("Server".as_bytes(), &Xu)
        }


    }
}

mod server {
    use crate::{client , primitives::{Hasher, Secret}};
    use std::collections::HashMap;
    use aes_gcm::Aes256Gcm;
    use aead::{Aead, NewAead, generic_array::GenericArray};

    const DIGEST_SIZE: usize = 32;
    const CURVE_SIZE: usize = 33;

    #[derive(Hash, Debug)]
    pub struct File {
        ks: Secret,
        ps: Secret,
        Ps: secp256k1::PublicKey,
        Pu: secp256k1::PublicKey,
        c: Vec<u8>,
    }

    pub struct Session {
        xs: Secret,
    }

    pub struct Server {
        pub(crate) backend: HashMap<String, File>,
        hasher: Hasher,
    }

    impl Server {
        pub fn new() -> Self {
            let backend = HashMap::new();
            let hasher = Hasher::new();
            Self{ backend, hasher }
        }

        pub fn setup(&mut self, username: &str, password: &str) -> bool {
            let username_str = username.to_string();
            if self.backend.contains_key(&username_str) {
                return false;
            }
            println!("\n\nUsername: {}", username);
            let ks = Hasher::gen_key();
            let rw = self.hasher.oprf(password.as_bytes(), &ks);
            let ps = Hasher::gen_key();
            let Ps = self.hasher.exp(&ps);
            let pu = Hasher::gen_key();
            println!("pu\t{:?}", pu.0.to_vec());
            println!("Ps\t{:?}", Ps.serialize().to_vec());
            let Pu = self.hasher.exp(&pu);
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

        pub fn process(&self, username: &str, mut alpha: secp256k1::PublicKey) -> Option<(Session, secp256k1::PublicKey, secp256k1::PublicKey, Vec<u8>)> {
            // Check that alpha is not generator
            let hasher = Hasher::new();
            let username_str = username.to_string();
            if let Some(file) = self.backend.get(&username_str) {
                let xs = Hasher::gen_key();
                let session = Session{ xs };
                hasher.custom_exp(&mut alpha, &file.ks);
                let Xs = hasher.exp(&session.xs);
                return Some((session, alpha, Xs, file.c.clone()));
            }
            None
        }
    }
}

mod primitives {
    use sha2::{Sha256, Digest};
    use rand::{self, RngCore, SeedableRng};
    use rand_chacha::{ChaChaRng};

    const DIGEST_SIZE: usize = 32;
    const CURVE_SIZE: usize = 33;

    #[derive(Hash, Debug)]
    pub struct Secret(pub(crate) [u8; 32]);

    pub struct Hasher {
        curve: secp256k1::Secp256k1<secp256k1::All>
    }

    impl Hasher {
        pub fn new() -> Self {
            let mut curve = secp256k1::Secp256k1::new();
            Self { curve }
        }

        pub fn hash(lhs: &[u8], rhs: &secp256k1::PublicKey) -> [u8; DIGEST_SIZE] {
            let mut hasher = Sha256::new();
            hasher.input(lhs);
            hasher.input(rhs.serialize().as_ref());
            let mut result = [0u8; DIGEST_SIZE];
            result.copy_from_slice(hasher.result().as_ref());
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
                    point.mul_assign(&self.curve, exp).unwrap();
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
           let secret = secp256k1::SecretKey::from_slice(input.0.as_ref()).unwrap();
           secp256k1::PublicKey::from_secret_key(&self.curve, &secret)
        }

        pub fn custom_exp(&self, base: &mut secp256k1::PublicKey, input: &Secret) {
           base.mul_assign(&self.curve, input.0.as_ref()).unwrap();
        }

        pub fn oprf(&self, input: &[u8], key: &Secret) -> [u8; DIGEST_SIZE] { 
            let point = self.to_curve(input, &key.0);
            Self::hash(input, &point)
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1;
    use rand::{self, RngCore};
    use crate::{client, server, primitives};

    const DIGEST_SIZE: usize = 32;
    const CURVE_SIZE: usize = 33;

    #[test]
    fn it_works() {
        let mut server = server::Server::new();
        for i in 0..10 {
            assert!(server.setup(&format!("{}", i), &format!("password{}", i)));
        }
        let mut client = client::Client{ username: "5".to_string(), password: "password5".to_string() };
        let (client_session, alpha) = client.login();
        if let Some((server_session, mut beta, Xs, c)) = server.process(&client.username, alpha) {
            client.complete(client_session, beta, Xs, c, None);
        }
    }
}
