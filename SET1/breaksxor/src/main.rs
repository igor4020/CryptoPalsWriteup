use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;


use cryptoutils::{single_byte_xor, hex_2_bytes, score_english};
use clap::Parser;


#[derive(Parser)]
#[command(name = "XOR breaker")]
#[command(version = "0.1")]
#[command(about = "Breaks single and multi bytes key xor encryption on hex strings and files", long_about = None)]
struct Cli {
    #[arg(long)]
    hex: Option<String>,
    #[arg(long)]
    file_path: Option<String>,
    #[arg(long)]
    single_byte_key: Option<bool>,
    #[arg(long)]
    multi_byte_key: Option<bool>
}

fn breaksxor(ciphertext: &[u8]) -> (f32, u8, String) {
    let mut best_score = f32::MIN;
    let mut best_key = 0;
    let mut best_plaintext = String::new();

    for key in 0u8..=255 {
        let plaintext_bytes = single_byte_xor(ciphertext, key);
        if let Ok(plaintext) = String::from_utf8(plaintext_bytes.clone()) {
            let score = score_english(plaintext.as_bytes());
            if score > best_score {
                best_score = score;
                best_key = key;
                best_plaintext = plaintext;
            }
        }
    }

    (best_score, best_key, best_plaintext)
}


fn main() {
    let cli = Cli::parse();

    let hex_string: &str = match &(cli.hex) {
        Some(s) => s.as_str(),
        None => "",
    };

    let file_path: &str = match &(cli.file_path) {
        Some(s) => s.as_str(),
        None => "",
    };

    if !hex_string.is_empty(){
        println!("Hex String: {}", hex_string);

        let bytes = hex_2_bytes(hex_string).expect("Invalid Hex string");
        let (best_score, best_key, best_plaintext) = breaksxor(&bytes);
        println!("Score: {}, Key: {}, Plaintext: {}", best_score, best_key, best_plaintext);
 
    }

    if !file_path.is_empty() {
        let path = Path::new(&file_path);
        let file = File::open(&path).expect("File not found or invalid path");
        let reader = io::BufReader::new(file);

        let mut best_score_final: f32 = 0.0;
        let mut best_key_final: u8 = 0;
        let mut best_plaintext_final: String = "".to_string();
        for line in reader.lines() {
            let line = line.expect("Invalid line");
            let bytes = hex_2_bytes(&line).expect("Invalid Hex");
            let (best_score, best_key, best_plaintext) = breaksxor(&bytes);
            if best_score > best_score_final {
                best_score_final = best_score;
                best_key_final = best_key;
                best_plaintext_final = best_plaintext;
            }

        }
        println!("Score: {}, Key: {}, Plaintext: {}", best_score_final, best_key_final, best_plaintext_final);
    }
}

