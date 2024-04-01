use crate::helpers::{bin_to_hex, hex_to_bin, string_to_binary};
use num_bigint::{BigInt, BigUint};
use rand::{rngs::OsRng, CryptoRng, Rng, RngCore};
use sha256::digest;
use std::{
    cell::{RefCell, RefMut},
    collections::HashMap,
};

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
    //error below
    let hashed_bin_representation = hex_to_bin(&hashed_message); //this is not in hex
    println!(
        "The size of the hashed message in bin {}",
        hashed_bin_representation.len()
    ); // println!("{}", hashed_bin_representation);
    for (index, c) in hex_to_bin(secret_key).chars().enumerate() {
        if index < 8192 {
            secret_key_0.push_str(&c.to_string());
        } else {
            secret_key_1.push_str(&c.to_string());
        }
    }
    println!(
        "The sizes of the blocks are , {}, {}",
        secret_key_0.len(),
        secret_key_1.len()
    );
    let mut bits = 0;
    let mut start_index = 0;
    let mut end_index = 31;

    let mut start_index2 = 0;
    let mut end_index2 = 31;
    let mut counter = 0;
    for (_, b) in hashed_bin_representation.chars().enumerate() {
        if b == '1' {
            bits += 32;
            signature.push_str(&secret_key_1[start_index..end_index + 1]);
            start_index += 32;
            end_index += 32;
        } else if b == '0' {
            bits += 32;
            signature.push_str(&secret_key_0[start_index2..end_index2 + 1]);
            start_index2 += 32;
            end_index2 += 32;
        }
        println!("After that bullshit its, {}", signature.len());
    }
    println!(
        "The signature length afterwards is, {} and bits are {}",
        signature.len(),
        bits
    );
    signature = bin_to_hex(&signature);
    // println!(
    //     "the indeces are, {}, {}",
    //     index_secret_key_0, index_secret_key_1
    // );

    signature
}

fn verify(signature: &str, message: &str, public_key: &str) -> bool {
    let mut equal: bool = true;
    let mut sig_block = String::new();
    let mut pub_block = String::new();
    // Hash the message to get the digest
    let hashed_message = digest(message);

    // Convert the hashed message to binary representation
    let hashed_message_bin = hex_to_bin(&hashed_message);

    // Convert the signature to binary representation
    let signature_bin = string_to_binary(signature);

    let mut block1 = String::new();
    let mut block2 = String::new();

    let mut start_index = 0;
    let mut end_index = 31;
    let mut start_index2: usize = 0;
    let mut end_index2 = 31;
    println!("The signature key size is , {}", signature.len() * 4);

    for (index, bit) in hashed_message_bin.chars().enumerate() {
        if bit == '1' {
            //push 32 bits to the upper section and then hash them and find if they look like public key
            let sig_hash = digest(&signature_bin[start_index..end_index]);
            let pub_hash = public_key[start_index..end_index].to_string();
            sig_block.push_str(&sig_hash);
            pub_block.push_str(&pub_hash);

            start_index += 32;
            end_index += 32;
        } else if bit == '0' {
            //push 32 bits to the upper section and then hash them and find if they look like public key
            let sig_hash = digest(&signature_bin[start_index..end_index]);
            let pub_hash = public_key[start_index2..end_index2].to_string();
            sig_block.push_str(&sig_hash);
            pub_block.push_str(&pub_hash);

            start_index2 += 32;
            end_index2 += 32;
        }
    }
    println!("Signature block is {}", sig_block.len());
    println!("pub key  block is {}", pub_block.len());
    chars_match(&sig_block, &pub_block)
}
fn chars_match(s1: &str, s2: &str) -> bool {
    if s1.len() != s2.len() {
        return false;
    }

    let mut char_count1 = HashMap::new();
    let mut char_count2 = HashMap::new();

    // Count occurrences of each character in string 1
    for c in s1.chars() {
        *char_count1.entry(c).or_insert(0) += 1;
    }

    // Count occurrences of each character in string 2
    for c in s2.chars() {
        *char_count2.entry(c).or_insert(0) += 1;
    }
    println!("char counts are {:?}, {:?}", char_count1, char_count2);

    // Check if the character counts are equal for both strings
    char_count1 == char_count2
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
        let bin = string_to_binary(hex);
        assert_eq!(bin, "1101010110110010");
    }
    #[test]
    fn pub_key() {
        generate_public_key();
    }
    #[test]
    fn verify_signature() {
        // Generate keys
        let (private_key, public_key) = generate_keys();

        // Message and sign it
        let message = "In code we trust";
        let signature = sign(&private_key, message);

        // Verify signature
        let result = verify(&signature, message, &public_key);

        // Assert the result
        assert!(result, "Signature verification failed");
    }
}
