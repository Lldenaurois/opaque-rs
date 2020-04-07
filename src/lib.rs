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
            let Xu = hasher.exp(&xu);
            (Session{ r, xu }, alpha, Xu)
        }

        pub fn complete(&self, session: Session, mut beta: secp256k1::PublicKey, Xs: secp256k1::PublicKey, c: Vec<u8>, As: Option<secp256k1::PublicKey>) -> Secret {
            // Check that beta is not the generator
            let hasher = Hasher::new();
            let mut buf = [0u8; DIGEST_SIZE];
            let modulus = gmp::mpz::Mpz::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).expect("modulus");
            let val = gmp::mpz::Mpz::from_str_radix(&hex::encode(session.r.0.as_ref()), 16).expect("val");
            let inv = val.invert(&modulus).expect("inv");
            let mut buf = [0u8; DIGEST_SIZE];
            let mut inv_string = inv.to_str_radix(16);
            if inv_string.len() % 2 != 0 {
                inv_string = "0".to_string() + &inv_string;
            }
            buf.copy_from_slice(&hex::decode(&inv_string).expect("inv to str"));
            let invSecret = Secret(buf);
            hasher.custom_exp(&mut beta, &invSecret);
            let rw = Hasher::hash(self.password.as_bytes(), &beta);

            let enc_key = GenericArray::clone_from_slice(rw.as_ref());
            let aead = Aes256Gcm::new(enc_key);
            let nonce = GenericArray::from_slice(b"unique_nonce");
            let decryption = aead.encrypt(nonce, c.as_ref()).expect("Encryption Failure");

            let mut pu_buf = [0u8; DIGEST_SIZE];
            pu_buf.copy_from_slice(&decryption[..DIGEST_SIZE]);
            let pu = Secret(pu_buf);

            let Pu = secp256k1::PublicKey::from_slice(&decryption[DIGEST_SIZE..DIGEST_SIZE+CURVE_SIZE]).expect("Pu from slice");
            let Ps = secp256k1::PublicKey::from_slice(&decryption[DIGEST_SIZE+CURVE_SIZE..DIGEST_SIZE+2*CURVE_SIZE]).expect("Ps from slice");

            let Xu = hasher.exp(&session.xu);

            let eu = Secret(Hasher::hash("Server".as_bytes(), &Xu));
            let es = Secret(Hasher::hash(self.username.as_bytes(), &Xs));

            let mut temp = secp256k1::PublicKey::from_slice(Ps.serialize().as_ref()).expect("temp");
            hasher.custom_exp(&mut temp, &es);
            let mut lhs = temp.combine(&Xs).expect("lhs");

            let mut rhs = secp256k1::PublicKey::from_slice(lhs.serialize().as_ref()).expect("rhs");
            hasher.custom_exp(&mut lhs, &session.xu);
            hasher.custom_exp(&mut rhs, &eu);
            hasher.custom_exp(&mut rhs, &pu);

            let out = lhs.combine(&rhs).expect("out");

            Secret(Hasher::hash("".as_bytes(), &out))
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
            let ks = Hasher::gen_key();
            let rw = self.hasher.oprf(password.as_bytes(), &ks);
            let ps = Hasher::gen_key();
            let Ps = self.hasher.exp(&ps);
            let pu = Hasher::gen_key();
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

        pub fn process(&self, username: &str, mut alpha: secp256k1::PublicKey, Xu: secp256k1::PublicKey) -> Option<(Secret, Session, secp256k1::PublicKey, secp256k1::PublicKey, Vec<u8>)> {
            // Check that alpha is not generator
            let hasher = Hasher::new();
            let username_str = username.to_string();
            if let Some(file) = self.backend.get(&username_str) {
                let xs = Hasher::gen_key();
                let session = Session{ xs };
                hasher.custom_exp(&mut alpha, &file.ks);
                let Xs = hasher.exp(&session.xs);

                let es = Secret(Hasher::hash(username.as_bytes(), &Xs));
                let eu = Secret(Hasher::hash("Server".as_bytes(), &Xu));

                let mut temp = secp256k1::PublicKey::from_slice(file.Pu.serialize().as_ref()).expect("temp");
                hasher.custom_exp(&mut temp, &eu);
                let mut lhs = temp.combine(&Xu).expect("lhs");

                let mut rhs = secp256k1::PublicKey::from_slice(lhs.serialize().as_ref()).expect("rhs");
                hasher.custom_exp(&mut lhs, &session.xs);
                hasher.custom_exp(&mut rhs, &es);
                hasher.custom_exp(&mut rhs, &file.ps);

                let out = lhs.combine(&rhs).expect("out");

                let key = Secret(Hasher::hash("".as_bytes(), &out));

                let Ps = hasher.exp(&file.ps);

                return Some((key, session, alpha, Xs, file.c.clone()));
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
            let mut hasher = Sha256::new();
            hasher.input(bytes.as_ref());
            hasher.input([i as u8].as_ref());
            assert!(server.setup(&format!("{}", i), &format!("password{:?}", hasher.result())));
        }
        for i in 0..100 {
            let mut hasher = Sha256::new();
            hasher.input(bytes.as_ref());
            hasher.input([ i as u8 ].as_ref());
            let mut client = client::Client{ username: format!("{}", i), password: format!("password{:?}", hasher.result()) };
            let (client_session, alpha, Xu) = client.login();
            if let Some((server_secret, server_session, mut beta, Xs, c)) = server.process(&client.username, alpha, Xu) {
                let client_secret = client.complete(client_session, beta, Xs, c, None);
                assert!(server_secret.0.to_vec() == client_secret.0.to_vec());
            }
        }
    }
}
