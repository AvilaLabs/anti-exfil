//! The signer role.

use std::collections::BTreeMap;

use crate::ae::*;
use crate::analyze::*;
use crate::ec::*;
use crate::psbt::*;
use crate::util::*;

#[derive(Default, Clone, Debug)]
pub struct Fields {
    pub hc: Option<[u8; 32]>,
    pub nc: Option<[u8; 33]>,
    pub rho: Option<[u8; 32]>,
}

pub fn is_ae_key(k: &[u8]) -> bool {
    !k.is_empty() && (I_AE_HOST_COMMITMENT..=I_AE_HOST_RANDOMNESS).contains(&k[0])
}

/// Collects the anti-exfil fields of every input map, keyed by (input, key identifier).
pub fn collect_fields(psbt: &Psbt) -> Result<BTreeMap<(usize, Vec<u8>), Fields>, String> {
    let mut out: BTreeMap<(usize, Vec<u8>), Fields> = BTreeMap::new();
    for (i, map) in psbt.inputs.iter().enumerate() {
        for (k, v) in map {
            if !is_ae_key(k) {
                continue;
            }
            let id = k[1..].to_vec();
            if !matches!(id.len(), 32 | 33 | 64) {
                return Err(format!("input {i}: anti-exfil key identifier of {} bytes", id.len()));
            }
            let f = out.entry((i, id)).or_default();
            match k[0] {
                I_AE_HOST_COMMITMENT => {
                    f.hc = Some(<[u8; 32]>::try_from(v.as_slice()).map_err(|_| "host commitment must be 32 bytes")?)
                }
                I_AE_NONCE_COMMITMENT => {
                    f.nc = Some(<[u8; 33]>::try_from(v.as_slice()).map_err(|_| "nonce commitment must be 33 bytes")?)
                }
                _ => {
                    f.rho = Some(<[u8; 32]>::try_from(v.as_slice()).map_err(|_| "host randomness must be 32 bytes")?)
                }
            }
        }
    }
    Ok(out)
}

pub struct SignerOpts {
    pub secrets: Vec<[u8; 32]>,
    pub decline: bool,
}

pub fn sig_field_value(p: &PairCtx, sig: &[u8; 64]) -> Vec<u8> {
    match p.kind {
        Kind::Ecdsa => {
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&sig[..32]);
            s.copy_from_slice(&sig[32..]);
            der_encode(&r, &s, p.sighash_type as u8)
        }
        _ => {
            let mut v = sig.to_vec();
            if p.sighash_type != 0 {
                v.push(p.sighash_type as u8);
            }
            v
        }
    }
}

pub fn handle_request(raw: &[u8], opts: &SignerOpts) -> Result<Vec<u8>, String> {
    let mut psbt = Psbt::parse(raw)?;
    let fields = collect_fields(&psbt)?;
    if fields.is_empty() {
        return Err("not a request under this protocol".into());
    }
    // Phases: a pair with randomness is second pass; with only a host commitment, first pass.
    let mut first = 0;
    let mut second = 0;
    for f in fields.values() {
        if f.rho.is_some() {
            second += 1;
        } else if f.hc.is_some() {
            first += 1;
        } else {
            return Err("pair with only a nonce commitment".into());
        }
    }
    if first > 0 && second > 0 {
        return Err("mixed phases".into());
    }
    let second_pass = second > 0;

    let mut devs = Devices { check_purpose: true, ..Devices::default() };
    let mut sks: Vec<(Sc, [u8; 33])> = Vec::new();
    for s in &opts.secrets {
        let sc = scalar_checked(s).filter(|x| !sc_is_zero(x)).ok_or("invalid secret key")?;
        let pk = ser33(&mul_g(&sc)).ok_or("invalid secret key")?;
        devs.keys.push(pk);
        sks.push((sc, pk));
    }

    let pair_inputs: Vec<usize> = fields.keys().map(|(i, _)| *i).collect();
    let ctx = build_ctx(&psbt, &pair_inputs)?;
    let mut pairs: Vec<PairCtx> = Vec::new();
    let mut eff_sk: Vec<[u8; 32]> = Vec::new();
    for (i, id) in fields.keys() {
        let p = analyze_pair(&ctx, &devs, *i, id)?;
        // key ownership
        let found = match p.kind {
            Kind::Ecdsa => sks.iter().find(|(_, pk)| pk[..] == p.key_id[..]),
            Kind::TapKey => sks.iter().find(|(_, pk)| pk[1..] == p.key_id[..]),
            Kind::TapScript => sks.iter().find(|(_, pk)| pk[1..] == p.key_id[..32]),
        };
        let (sc, _) = found.ok_or_else(|| format!("input {i}: the signer does not hold the key"))?;
        let e = match p.tweak {
            Some(t) => {
                let v = tweak_secret(sc, &t);
                if sc_is_zero(&v) {
                    return Err("tweaked secret is zero".into());
                }
                v
            }
            None => *sc,
        };
        eff_sk.push(sc_bytes(&e));
        pairs.push(p);
    }
    for (a, pa) in pairs.iter().enumerate() {
        for pb in pairs.iter().skip(a + 1) {
            if pa.input == pb.input
                && ((pa.kind == Kind::TapKey && pb.kind == Kind::TapScript)
                    || (pa.kind == Kind::TapScript && pb.kind == Kind::TapKey))
            {
                return Err("one input has both a key path and a script path pair".into());
            }
        }
    }
    let has_tap_non_acp = pairs.iter().any(|p| p.kind != Kind::Ecdsa && !p.acp);
    let fee = fee_info(&ctx, has_tap_non_acp)?;
    drop(ctx);

    // Step 2 values, needed in both passes (and used to check what the host sent).
    let mut r0s: Vec<[u8; 33]> = Vec::new();
    for (idx, p) in pairs.iter().enumerate() {
        let f = &fields[&(p.input, p.key_id.clone())];
        let hc = if second_pass {
            let rho = f.rho.as_ref().unwrap();
            let hc = host_commitment(p.scheme(), rho);
            if let Some(h) = f.hc {
                if h != hc {
                    return Err("host commitment differs from the computed value".into());
                }
            }
            hc
        } else {
            f.hc.unwrap()
        };
        let r0 = step2(p.scheme(), &eff_sk[idx], &p.m, &hc)?;
        if let Some(nc) = f.nc {
            if nc != r0 {
                return Err("nonce commitment differs from the computed value".into());
            }
        }
        r0s.push(r0);
    }

    if !second_pass {
        for (idx, p) in pairs.iter().enumerate() {
            map_set(&mut psbt.inputs[p.input], key_of(I_AE_NONCE_COMMITMENT, &p.key_id), r0s[idx].to_vec());
        }
        return Ok(psbt.serialize());
    }

    // Second pass: one approval for the whole PSBT.
    eprintln!("signer: approval requested");
    eprintln!(
        "  fee: {}",
        match (&fee.amount, fee.verified) {
            (Some(a), true) => format!("{a} sat (verified)"),
            (Some(a), false) => format!("{a} sat (UNVERIFIED: not every input amount is checked)"),
            (None, _) => "unknown (UNVERIFIED)".to_string(),
        }
    );
    for o in &psbt.core_tx()?.outputs {
        eprintln!("  output: {} sat to {}", o.amount, hex_encode(&o.script));
    }
    for p in &pairs {
        eprintln!(
            "  sign input {} key {} sighash {:#x} {:?}",
            p.input,
            hex_encode(&p.key_id),
            p.sighash_type,
            p.kind
        );
    }
    if opts.decline {
        return Err("the user declined".into());
    }
    let mut sigs = Vec::new();
    for (idx, p) in pairs.iter().enumerate() {
        let f = &fields[&(p.input, p.key_id.clone())];
        sigs.push(step4(p.scheme(), &eff_sk[idx], &p.m, f.rho.as_ref().unwrap())?);
    }
    for (p, sig) in pairs.iter().zip(sigs.iter()) {
        map_set(&mut psbt.inputs[p.input], p.sig_key.clone(), sig_field_value(p, sig));
        psbt.apply_modifiable_update(p.sighash_type)?;
    }
    for m in &mut psbt.inputs {
        m.retain(|(k, _)| !is_ae_key(k));
    }
    Ok(psbt.serialize())
}

pub fn run_signer(args: &[String]) -> i32 {
    let mut opts = SignerOpts { secrets: Vec::new(), decline: false };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secret-key" => {
                i += 1;
                let b = args.get(i).and_then(|h| hex_decode(h));
                match b.and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
                    Some(k) => opts.secrets.push(k),
                    None => {
                        eprintln!("bad --secret-key");
                        return 2;
                    }
                }
            }
            "--decline" => opts.decline = true,
            a => {
                eprintln!("unknown argument {a}");
                return 2;
            }
        }
        i += 1;
    }
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        eprintln!("cannot read request");
        return 3;
    }
    let raw = match hex_decode(line.trim()) {
        Some(r) => r,
        None => {
            eprintln!("request is not hex");
            return 3;
        }
    };
    match handle_request(&raw, &opts) {
        Ok(out) => {
            println!("{}", hex_encode(&out));
            0
        }
        Err(e) => {
            eprintln!("signer failure: {e}");
            3
        }
    }
}
