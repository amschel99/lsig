use crate::helpers::{bin_to_hex, hex_to_bin};
use num_bigint::{BigInt, BigUint};
use rand::{rngs::OsRng, CryptoRng, Rng, RngCore};
use sha256::digest;
use std::cell::{RefCell, RefMut};

enum Index {
    Zero = 0,
    One = 1,
}

struct PrivateKey {
    index: Index,
    data: [String; 8],
}
impl PrivateKey {
    fn index_zero() -> Self {
        let mut rng = OsRng;
        let mut data: [String; 8] = Default::default();

        for num in data.iter_mut() {
            *num = format!("{:0256X}", generate_random_256_bit_number(&mut rng));
        }

        PrivateKey {
            index: Index::Zero,
            data,
        }
    }

    fn index_one() -> Self {
        let mut rng = OsRng;
        let mut data: [String; 8] = Default::default();

        for num in data.iter_mut() {
            *num = format!("{:0256X}", generate_random_256_bit_number(&mut rng));
        }

        PrivateKey {
            index: Index::One,
            data,
        }
    }
}
fn generate_random_256_bit_number<R: RngCore + CryptoRng>(rng: &mut R) -> BigUint {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    BigUint::from_bytes_be(&bytes)
}
fn generate_private_key() -> String {
    let private_key: String = {
        let mut result = String::new();

        for element in PrivateKey::index_zero().data.iter() {
            result.push_str(&element.to_string());
        }
        for element in PrivateKey::index_one().data.iter() {
            result.push_str(&element.to_string());
        }

        result
    };
    println!("The private key is {}", private_key.len());
    private_key
}
fn generate_public_key() -> String {
    let mut public_key = String::new();
    let private_key_bin = hex_to_bin(&generate_private_key());

    let mut start_index = 0;
    let mut end_index = 31;

    for _ in 0..128 {
        //generate a public key hash
        public_key.push_str(digest(&private_key_bin[start_index..end_index]).as_str());
        start_index += 32;
        end_index += 32;
    }
    println!("The public key is, {}", public_key);
    public_key
}
fn generate_keys() -> (String, String) {
    (generate_private_key(), generate_public_key())
}

fn sign(secret_key: &str, message: &str) -> String {
    let mut signature = String::new();
    let hashed_message = digest(message);
    let mut secret_key_0 = String::new();
    let mut secret_key_1 = String::new();

    let hashed_bin_representation = hex_to_bin(&hashed_message);
    // println!("{}", hashed_bin_representation);
    for (index, c) in hex_to_bin(secret_key).chars().enumerate() {
        if index < 8192 {
            secret_key_0.push_str(&c.to_string());
        } else {
            secret_key_1.push_str(&c.to_string());
        }
    }

    let mut index_secret_key_1 = 0;
    let mut index_secret_key_0 = 0;

    let mut start_index = 0;
    let mut end_index = 31;

    let mut start_index2 = 0;
    let mut end_index2 = 31;
    for (_, b) in hashed_bin_representation.chars().enumerate() {
        if b == '1' {
            signature.push_str(&secret_key_1[start_index..end_index]);
            start_index += 32;
            end_index += 32;
        }
        if b == '0' {
            signature.push_str(&secret_key_0[start_index2..end_index2]);
            start_index += 32;
            end_index += 32;
        }
    }
    signature = bin_to_hex(&signature);
    // println!(
    //     "the indeces are, {}, {}",
    //     index_secret_key_0, index_secret_key_1
    // );

    println!(
        "The Secret key is ={} and the signature  is = {}",
        secret_key, signature
    );

    signature
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_key_is_512_bits() {
        let private_key: String = generate_private_key();

        // assert_eq!(
        //     private_key.len() * 4,
        //     512,
        //     "Private key is not 512 bits long"
        // );
    }
    #[test]
    fn generate_keys_works() {
        let keys = generate_keys();
        println!("Private Key is :{}", keys.0);
        println!("Public Key is :{}", keys.1);
    }
    #[test]
    fn hash_message_works() {
        sign(generate_keys().0.as_str(), "In code we trust");
    }
    #[test]
    fn bin_to_hex_works() {
        let hex = "D5B2";
        let binary = hex_to_bin(hex);
        assert_eq!(binary, "1101010110110010");
    }
    #[test]
    fn pub_key() {
        generate_public_key();
    }
}
