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
