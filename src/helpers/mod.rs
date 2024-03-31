pub fn bin_to_hex(binary: &str) -> String {
    let mut hex = String::new();
    let mut chunk = String::new();

    for (i, bit) in binary.chars().enumerate() {
        chunk.push(bit);

        // If we've accumulated 4 bits, convert them to hexadecimal
        if (i + 1) % 4 == 0 {
            let hex_digit = match u8::from_str_radix(&chunk, 2) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Error: Invalid binary string.");
                    return String::from("Error: Invalid binary string.");
                }
            };

            // Convert the decimal value to a hexadecimal character
            let hex_char = match hex_digit {
                0..=9 => (hex_digit + b'0') as char,
                10..=15 => (hex_digit - 10 + b'A') as char,
                _ => panic!("Invalid hexadecimal digit"),
            };

            hex.push(hex_char);

            // Clear the chunk for the next set of bits
            chunk.clear();
        }
    }

    // If there are remaining bits, pad the last chunk and convert it to hexadecimal
    if !chunk.is_empty() {
        while chunk.len() < 4 {
            chunk.push('0');
        }

        let hex_digit = u8::from_str_radix(&chunk, 2).unwrap();

        let hex_char = match hex_digit {
            0..=9 => (hex_digit + b'0') as char,
            10..=15 => (hex_digit - 10 + b'A') as char,
            _ => panic!("Invalid hexadecimal digit"),
        };

        hex.push(hex_char);
    }

    hex
}
pub fn hex_to_bin(hex_string: &str) -> String {
    let mut result = String::new();
    for c in hex_string.chars() {
        let hex_digit = c.to_digit(16).expect("Invalid hexadecimal digit");
        let bin_str = format!("{:04b}", hex_digit);
        result.push_str(&bin_str);
    }
    result
}
// fn verify(signature: &str, message: &str, public_key: &str) {
//     // Hash the message to get the digest
//     let hashed_message = digest(message);

//     // Convert the hashed message to binary representation
//     let hashed_message_bin = hex_to_bin(&hashed_message);

//     // Convert the signature to binary representation
//     let signature_bin = hex_to_bin(signature);

//     let mut block1 = String::new();
//     let mut block2 = String::new();
//     let mut index_secret_key_1 = 0;
//     let mut index_secret_key_0 = 0;
//     println!("message ----{}", hashed_message_bin);
//     println!("signature ----{}", signature_bin);

//     for (index, bit) in hashed_message_bin.chars().enumerate() {
//         if bit == '1' {
//             block1.push_str(
//                 signature_bin
//                     .chars()
//                     .nth(index_secret_key_0)
//                     .unwrap_or_else(|| {
//                         eprintln!("Error: Index out of bounds in secret_key_0");
//                         panic!("Index out of bounds in secret_key_0");
//                     })
//                     .to_string()
//                     .as_str(),
//             );
//             index_secret_key_0 += 1;
//             // println!("{}---- {}", bit, block1);
//         } else if bit == '0' {
//             block2.push_str(
//                 signature_bin
//                     .chars()
//                     .nth(index_secret_key_1)
//                     .unwrap_or_else(|| {
//                         eprintln!("Error: Index out of bounds in secret_key_0");
//                         panic!("Index out of bounds in secret_key_0");
//                     })
//                     .to_string()
//                     .as_str(),
//             );
//             index_secret_key_1 += 1;
//         }
//     }

//     block1 = bin_to_hex(&block1);
//     block2 = bin_to_hex(&block2);
//     println!(
//         "the blocks are : {} and {}",
//         index_secret_key_0, index_secret_key_1
//     );
// }
