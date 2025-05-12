use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use cryptoutils::{
    single_byte_xor, hex_2_bytes, xor_with_key, score_english, hamming_distance,
    base64_to_bytes,
};
use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    file_path: Option<String>,
    #[arg(long)]
    multi_byte_key: Option<bool>,
}

const MIN_KEYSIZE: usize = 2;
const MAX_KEYSIZE: usize = 40;
const TOP_KEYSIZES: usize = 3;  // try the 3 best keysizes

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

/// Returns the top N keysizes (2..=40) ranked by lowest normalized Hamming distance.
fn find_key_sizes(ciphertext: &[u8]) -> Vec<usize> {
    let mut distances = Vec::new();

    for keysize in MIN_KEYSIZE..=MAX_KEYSIZE {
        if ciphertext.len() < keysize * 4 { continue; }
        // take first 4 blocks of length `keysize`
        let chunks: Vec<&[u8]> = (0..4)
            .map(|i| &ciphertext[i*keysize .. (i+1)*keysize])
            .collect();
        // compute three pairwise distances and normalize
        let mut dists = Vec::new();
        for pair in &[(0,1), (1,2), (2,3)] {
            let (a, b) = (chunks[pair.0], chunks[pair.1]);
            let dist = hamming_distance(a, b) as f32 / keysize as f32;
            dists.push(dist);
        }
        let avg = dists.iter().sum::<f32>() / dists.len() as f32;
        distances.push((avg, keysize));
    }

    distances.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    distances.into_iter()
             .take(TOP_KEYSIZES)
             .map(|(_, ks)| ks)
             .collect()
}

/// Given a ciphertext and a single keysize, finds the best key (via single-byte XOR)
/// and returns (key_bytes, decrypted_plaintext, score).
fn break_for_keysize(ciphertext: &[u8], keysize: usize) -> (Vec<u8>, String, f32) {
    // transpose into `keysize` blocks
    let mut blocks = vec![Vec::new(); keysize];
    for (i, &b) in ciphertext.iter().enumerate() {
        blocks[i % keysize].push(b);
    }

    // recover each key‐byte
    let mut key = Vec::with_capacity(keysize);
    for block in blocks {
        let (_score, k, _pt) = breaksxor(&block);
        key.push(k);
    }

    // decrypt full message
    let decrypted = xor_with_key(ciphertext, &key);
    let plaintext = String::from_utf8_lossy(&decrypted).to_string();
    let score = score_english(plaintext.as_bytes());

    (key, plaintext, score)
}

/// Tries the top N keysizes and picks the **one** producing the highest-scoring plaintext.
fn break_repeating_key_xor(ciphertext: &[u8]) -> (Vec<u8>, String) {
    let mut best = (Vec::new(), String::new(), f32::MIN);

    for keysize in find_key_sizes(ciphertext) {
        let (key, pt, score) = break_for_keysize(ciphertext, keysize);
        if score > best.2 {
            best = (key, pt, score);
        }
    }

    // best is (key, plaintext, score)
    (best.0, best.1)
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    if cli.multi_byte_key.unwrap_or(false) {
        let path = cli.file_path.expect("Please provide --file_path");
        let mut b64 = String::new();
        File::open(&path)?.read_to_string(&mut b64)?;

        let ciphertext =
            base64_to_bytes(&b64).expect("Base64 decoding failed");
        let (key, plaintext) = break_repeating_key_xor(&ciphertext);

        println!("Guessed key: {}", String::from_utf8_lossy(&key));
        println!("Decrypted text:\n{}", plaintext);
    }

    Ok(())
}

