#![allow(deprecated)]

pub mod ae;
pub mod analyze;
pub mod ec;
pub mod host;
pub mod psbt;
pub mod script;
pub mod sighash;
pub mod signer;
pub mod store;
pub mod tx;
pub mod util;

use util::hex_decode;


pub fn host_main(args: &[String]) -> i32 {
    let mut devices: Vec<[u8; 33]> = Vec::new();
    let mut store = None;
    let mut max_retries: Option<u32> = None;
    let mut psbt = None;
    let mut rhos = Vec::new();
    let mut ack = false;
    let mut i = 0;
    macro_rules! val {
        () => {{
            i += 1;
            match args.get(i) {
                Some(v) => v.clone(),
                None => {
                    eprintln!("missing value for {}", args[i - 1]);
                    return 2;
                }
            }
        }};
    }
    while i < args.len() {
        match args[i].as_str() {
            "--device-key" => {
                let v = val!();
                match hex_decode(&v).and_then(|b| <[u8; 33]>::try_from(b.as_slice()).ok()) {
                    Some(k) if ec::parse33(&k).is_some() => devices.push(k),
                    _ => {
                        eprintln!("bad --device-key");
                        return 2;
                    }
                }
            }
            "--store" => store = Some(val!()),
            "--max-retries" => match val!().parse::<u32>() {
                Ok(n) => max_retries = Some(n),
                Err(_) => {
                    eprintln!("bad --max-retries");
                    return 2;
                }
            },
            "--psbt" => {
                let v = val!();
                match hex_decode(&v) {
                    Some(b) => psbt = Some(b),
                    None => {
                        eprintln!("bad --psbt");
                        return 2;
                    }
                }
            }
            "--rho" => {
                let v = val!();
                let parts: Vec<&str> = v.split(':').collect();
                let parsed = if parts.len() == 3 {
                    let idx = parts[0].parse::<usize>().ok();
                    let id = hex_decode(parts[1]);
                    let rho = hex_decode(parts[2]).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                    match (idx, id, rho) {
                        (Some(a), Some(b), Some(c)) => Some(((a, b), c)),
                        _ => None,
                    }
                } else {
                    None
                };
                match parsed {
                    Some(p) => rhos.push(p),
                    None => {
                        eprintln!("bad --rho");
                        return 2;
                    }
                }
            }
            "--ack-warning" => ack = true,
            a => {
                eprintln!("unknown argument {a}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(store), Some(psbt)) = (store, psbt) else {
        eprintln!("--store and --psbt are required");
        return 2;
    };
    if devices.is_empty() {
        eprintln!("at least one --device-key is required");
        return 2;
    }
    host::run_host(host::HostOpts { devices, store, max_retries: max_retries.unwrap_or(0), psbt, rhos, ack })
}

/// Extra, not part of the contract: `reset --store <path> --device-key <hex33>... --confirm-clear-failure-count`.
pub fn reset_main(args: &[String]) -> i32 {
    let mut devices: Vec<[u8; 33]> = Vec::new();
    let mut store = None;
    let mut confirm = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--device-key" => {
                i += 1;
                match args.get(i).and_then(|v| hex_decode(v)).and_then(|b| <[u8; 33]>::try_from(b.as_slice()).ok()) {
                    Some(k) => devices.push(k),
                    None => return 2,
                }
            }
            "--store" => {
                i += 1;
                store = args.get(i).cloned();
            }
            "--confirm-clear-failure-count" => confirm = true,
            _ => return 2,
        }
        i += 1;
    }
    match (store, confirm, devices.is_empty()) {
        (Some(s), true, false) => host::run_reset(devices, &s),
        _ => {
            eprintln!("reset needs --store, --device-key and --confirm-clear-failure-count");
            2
        }
    }
}

