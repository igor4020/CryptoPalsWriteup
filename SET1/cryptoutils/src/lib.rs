const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


// Table for scoring english text, took from wikipedia.
pub fn score_english(text: &[u8]) -> f32 {
    text.iter()
        .map(|&c| match c {
            b'a' | b'A' => 8.2,
            b'e' | b'E' => 13.0,
            b't' | b'T' => 9.1,
            b'o' | b'O' => 7.5,
            b'i' | b'I' => 7.0,
            b'n' | b'N' => 6.7,
            b' ' => 13.0,
            b'r' | b'R' => 6.0,
            b's' | b'S' => 6.3,
            b'd' | b'D' => 4.3,
            b'l' | b'L' => 4.0,
            b'h' | b'H' => 6.1,
            32..=126 => 1.0, // printable ASCII
            _ => -5.0,        // non-printable
        })
        .sum()
}

// I think this is not necessary anymore with because of the function below
pub fn single_byte_xor(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

pub fn xor_with_key(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

pub fn hex_char_to_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn hex_2_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("Odd hex string length, maybe you're missing some of the string?".to_string());
    }

    let mut result = Vec::new();

    for i in (0..bytes.len()).step_by(2) {
        let high_b = hex_char_to_val(bytes[i]).ok_or("Invalid Hex Character")?;
        let low_b = hex_char_to_val(bytes[i+1]).ok_or("Invalid Hex Character")?;
                result.push((high_b << 4) | low_b);
    }
    Ok(result)
}

pub fn bytes_2_hex(bytes: &[u8]) -> String {
    let mut hex_string = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    hex_string
}


fn bytes_to_base64(bytes: &[u8]) -> String {
    let mut result = String::new();

    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + i < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };

        let triple = ((b0 as u32) << 16) | ((b1 as u32)) << 8 | (b2 as u32);

        let c0 = ((triple >> 18 ) & 0x3F) as usize;
        let c1 = ((triple >> 12) & 0x3F) as usize;
        let c2 = ((triple >> 6) & 0x3F) as usize;
        let c3 = (triple & 0x3F) as usize;

        result.push(BASE64_TABLE[c0] as char);
        result.push(BASE64_TABLE[c1] as char);
        result.push(if i + 1 < bytes.len() { BASE64_TABLE[c2] as char } else { '=' });
        result.push(if i + 2 < bytes.len() { BASE64_TABLE[c3] as char } else { '=' });

        i += 3;
    }

    result

}

pub fn hex_2_b64(hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = hex_2_bytes(hex).expect("Invalid Hex String, maybe you're missing a part?");
    Ok(bytes_to_base64(&bytes))
}

pub fn buffers_xor(buf1: &[u8], buf2: &[u8]) -> Result<Vec<u8>, String> {
    if buf1.len() != buf2.len() {
        return Err("Buffers are not the same length".to_string());
    }
    let result: Vec<u8> = buf1.iter()
        .zip(buf2.iter())
        .map(|(b1,b2)| b1 ^ b2)
        .collect();

    Ok(result)
}

pub fn xor_hexes_strings(hex1: &str, hex2: &str) -> Result<String, Box<dyn std::error::Error>> {
    let b1 = hex_2_bytes(hex1).expect("Invalid First Hex String");
    let b2 = hex_2_bytes(hex2).expect("Invalid Second Hex String");
    let xored = buffers_xor(&b1, &b2).expect("Error when xoring buffers");
    Ok(bytes_2_hex(&xored))

}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    assert_eq!(a.len(), b.len(), "Inputs must be the same length");
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x ^ y).count_ones())
        .sum()
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex2b64_test() {
        let b64string = hex_2_b64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").expect("Error converting hex string to base64 string");
        assert_eq!(b64string ,"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaQBlIAAgcABpcwBubwBzIAB1cwBybwBt".to_string());
    }

    #[test]
    fn xor_strings_test() {
        let result = xor_hexes_strings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").expect("Failed to xor hex strings");
        assert_eq!(result, "746865206b696420646f6e277420706c6179");
    }
    #[test]
    fn key_xor_test() {
        let plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = b"ICE";

        let encryptedb = xor_with_key(plaintext, key);

        let encrypted = bytes_2_hex(&encryptedb);

        assert_eq!(encrypted, 
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }

    #[test]
    fn hamming_distance_test() {
        let s1 = b"this is a test";
        let s2 = b"wokka wokka!!!";

        let distance = hamming_distance(s1, s2);
        assert_eq!(distance, 37);
    }
}
