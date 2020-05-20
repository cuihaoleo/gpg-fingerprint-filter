extern crate clap;
extern crate hex;
extern crate num_cpus;
extern crate openssl;
extern crate regex;

use std::fs;
use std::io::Write;

use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::RegexBuilder;

use openssl::pkey;
use openssl::rsa::Rsa;
use openssl::sha::Sha1;

fn calc_fingerprint(timestamp: u32, rsa_key: &Rsa<pkey::Private>) -> String {
    let mut hasher = Sha1::new();

    let n = rsa_key.n();
    let e = rsa_key.e();

    // See: RFC 4880
    hasher.update(b"\x99");

    // length of latter parts
    let length = (10 + n.num_bytes() + e.num_bytes()) as u16;
    hasher.update(&length.to_be_bytes());
    // version = 0x04
    hasher.update(b"\x04");
    // timestamp
    hasher.update(&timestamp.to_be_bytes());
    // algorithm = 0x01 (RSA)
    hasher.update(b"\x01");

    // algorithm-specific parts
    hasher.update(&(n.num_bits() as u16).to_be_bytes());
    hasher.update(&n.to_vec());
    hasher.update(&(e.num_bits() as u16).to_be_bytes());
    hasher.update(&e.to_vec());

    let hash = hasher.finish();
    hex::encode(hash)
}

fn main() -> std::io::Result<()> {
    let yml = clap::load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yml)
        .name(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!())
        .get_matches();

    let pattern = matches.value_of("pattern").unwrap();
    let pattern = RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .unwrap();

    let output_path = matches.value_of("output").unwrap();

    let key_size = matches.value_of("key-size").unwrap();
    let key_size = key_size.parse().unwrap();

    let time_offset = matches.value_of("time-offset").unwrap();
    let time_offset = time_offset.parse().unwrap();

    let print_interval = matches.value_of("print-interval").unwrap();
    let print_interval = print_interval.parse().unwrap();
    let print_interval = Duration::from_secs(print_interval);

    let jobs = matches.value_of("jobs").unwrap();
    let jobs = jobs.parse().unwrap_or(num_cpus::get());

    let (tx, rx) = mpsc::channel();
    let should_exit = Arc::new(AtomicBool::new(false));
    let hash_count = Arc::new(AtomicU64::new(0));
    let mut handles = vec![];

    for _ in 0..jobs {
        let should_exit = Arc::clone(&should_exit);
        let hash_count = Arc::clone(&hash_count);
        let tx = tx.clone();
        let pattern = pattern.clone();

        let handle = thread::spawn(move || 'mainloop: loop {
            let t1 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            let t0 = t1.checked_sub(time_offset).unwrap();

            let rsa = Rsa::generate(key_size).unwrap();
            let mut result_timestamp = None;

            for t in t0..t1 {
                if should_exit.load(Ordering::Relaxed) {
                    break 'mainloop;
                }

                let fingerprint = calc_fingerprint(t, &rsa);
                hash_count.fetch_add(1, Ordering::Relaxed);
                if pattern.is_match(&fingerprint) {
                    result_timestamp = Some(t);
                    break;
                }
            }

            match result_timestamp {
                Some(t) => {
                    tx.send((rsa, t)).unwrap_or_else(|e| {
                        if !should_exit.load(Ordering::Relaxed) {
                            std::panic!(e);
                        };
                    });
                    break;
                }
                None => continue,
            }
        });

        handles.push(handle);
    }

    let timer = Instant::now();

    loop {
        match rx.recv_timeout(print_interval) {
            Ok((rsa, t)) => {
                let fingerprint = calc_fingerprint(t, &rsa);
                let pem = rsa.private_key_to_pem()?;

                let mut fout = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .mode(0o600)
                    .open(output_path)?;
                fout.write_all(&pem)?;

                println!("TIMESTAMP = {}", t);
                println!("FINGERPRINT = {}", fingerprint);
                println!("KEY written to {}", output_path);

                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(e) => panic!(e),
        }

        let elapsed = timer.elapsed().as_millis() as f64;
        let hash_count = hash_count.load(Ordering::Relaxed);
        let speed = hash_count as f64 / elapsed * 1000.0;
        println!("{:.4} hashes / sec", speed);
    }

    should_exit.store(true, Ordering::Relaxed);
    drop(rx);

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}
