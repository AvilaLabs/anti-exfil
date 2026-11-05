use aexf::{host_main, reset_main, signer};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("signer") => signer::run_signer(&args[1..]),
        Some("host") => host_main(&args[1..]),
        Some("reset") => reset_main(&args[1..]),
        _ => {
            eprintln!("usage: aexf signer|host ...");
            2
        }
    };
    std::process::exit(code);
}
