use crate::helpers::{bin_to_hex, hex_to_bin};
use rand::{rngs::OsRng, Rng};
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
        let data: [u32; 8] = rng.gen();
        let mut hex_data: [String; 8] = Default::default();

        for (i, &num) in data.iter().enumerate() {
            hex_data[i] = format!("{:08X}", num);
        }

        PrivateKey {
            index: Index::Zero,
            data: hex_data,
        }
    }
    fn index_one() -> Self {
        let mut rng = OsRng;
        let data: [u32; 8] = rng.gen();
        let mut hex_data: [String; 8] = Default::default();

        for (i, &num) in data.iter().enumerate() {
            hex_data[i] = format!("{:08X}", num);
        }

        PrivateKey {
            index: Index::One,
            data: hex_data,
        }
    }
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
    private_key
}
fn generate_public_key() -> String {
    digest(generate_private_key())
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
    println!("{}", hashed_bin_representation);
    for (index, c) in secret_key.chars().enumerate() {
        if index < 64 {
            secret_key_0.push_str(&c.to_string());
        } else {
            secret_key_1.push_str(&c.to_string());
        }
    }

    let mut index_secret_key_1 = 0;
    let mut index_secret_key_0 = 0;

    //convert secret_keys into binary
    secret_key_0 = hex_to_bin(&secret_key_0);
    secret_key_1 = hex_to_bin(&secret_key_1);

    for (_, b) in hashed_bin_representation.chars().enumerate() {
        if b == '1' {
            signature.push_str(
                &secret_key_1
                    .chars()
                    .nth(index_secret_key_0)
                    .unwrap_or_else(|| {
                        eprintln!("Error: Index out of bounds in secret_key_0");
                        panic!("Index out of bounds in secret_key_0");
                    })
                    .to_string(),
            );
            index_secret_key_0 += 1;
        }
        if b == '0' {
            signature.push_str(
                &secret_key_0
                    .chars()
                    .nth(index_secret_key_1)
                    .unwrap_or_else(|| {
                        eprintln!("Error: Index out of bounds in secret_key_0");
                        panic!("Index out of bounds in secret_key_0");
                    })
                    .to_string(),
            );
            index_secret_key_1 += 1;
        }
    }
    signature = bin_to_hex(&signature);
    println!(
        "the indeces are, {}, {}",
        index_secret_key_0, index_secret_key_1
    );

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

        assert_eq!(
            private_key.len() * 4,
            512,
            "Private key is not 512 bits long"
        );
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
}
