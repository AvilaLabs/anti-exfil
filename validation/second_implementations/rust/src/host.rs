//! The host role.

use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::sync::mpsc;
use std::time::Duration;

use crate::ae::*;
use crate::analyze::*;
use crate::ec::*;
use crate::psbt::*;
use crate::script::*;
use crate::signer::{is_ae_key, sig_field_value};
use crate::store::*;
use crate::util::*;

pub struct HostOpts {
    pub devices: Vec<[u8; 33]>,
    pub store: String,
    pub max_retries: u32,
    pub psbt: Vec<u8>,
    pub rhos: Vec<((usize, Vec<u8>), [u8; 32])>,
    pub ack: bool,
}

fn emit(s: &str) {
    let mut o = std::io::stdout();
    let _ = writeln!(o, "{s}");
    let _ = o.flush();
}

fn finish(count: u64, word: &str, code: i32) -> i32 {
    emit(&format!("COUNT {count}"));
    emit(word);
    code
}

fn is_sig_key(k: &[u8]) -> bool {
    !k.is_empty() && matches!(k[0], I_PARTIAL_SIG | I_TAP_KEY_SIG | I_TAP_SCRIPT_SIG)
}

fn has_final(map: &Map) -> bool {
    map_get(map, &[I_FINAL_SCRIPTSIG]).is_some() || map_get(map, &[I_FINAL_SCRIPTWITNESS]).is_some()
}

/// Chooses (input, key identifier) pairs from the host's own PSBT. Returns notices for the user.
pub fn select_pairs(psbt: &Psbt, devs: &Devices) -> Result<(Vec<(usize, Vec<u8>)>, Vec<String>), String> {
    let mut pairs: BTreeSet<(usize, Vec<u8>)> = BTreeSet::new();
    let mut notes = Vec::new();
    for (i, map) in psbt.inputs.iter().enumerate() {
        for (kd, _) in entries_of_type(map, I_BIP32_DERIVATION) {
            if kd.len() == 33 && devs.keys.iter().any(|k| k[..] == *kd) {
                if map_get(map, &key_of(I_PARTIAL_SIG, kd)).is_some() {
                    notes.push(format!("input {i}: signature already present for device key {}, skipped", hex_encode(kd)));
                } else {
                    pairs.insert((i, kd.to_vec()));
                }
            }
        }
        let internal = map_get(map, &[I_TAP_INTERNAL_KEY]);
        let holds_internal = internal.map(|v| v.len() == 32 && devs.has_x(v)).unwrap_or(false);
        if holds_internal {
            if map_get(map, &[I_TAP_KEY_SIG]).is_some() {
                notes.push(format!("input {i}: key path signature already present, skipped"));
            } else {
                pairs.insert((i, internal.unwrap().clone()));
            }
            continue;
        }
        for (xk, val) in entries_of_type(map, I_TAP_BIP32_DERIVATION) {
            if xk.len() != 32 || !devs.has_x(xk) {
                continue;
            }
            let mut r = Reader::new(val);
            let n = r.compact()?;
            if n > (r.remaining() / 32) as u64 {
                return Err("malformed Taproot derivation record".into());
            }
            let mut leaves = Vec::new();
            for _ in 0..n {
                let mut l = [0u8; 32];
                l.copy_from_slice(r.take(32)?);
                leaves.push(l);
            }
            for l in leaves {
                let have = entries_of_type(map, I_TAP_LEAF_SCRIPT)
                    .iter()
                    .any(|(_, v)| !v.is_empty() && tap_leaf_hash(v[v.len() - 1], &v[..v.len() - 1]) == l);
                if !have {
                    notes.push(format!("input {i}: leaf {} is listed with no script, no pair formed", hex_encode(&l)));
                    continue;
                }
                let mut id = xk.to_vec();
                id.extend_from_slice(&l);
                if map_get(map, &key_of(I_TAP_SCRIPT_SIG, &id)).is_some() {
                    notes.push(format!("input {i}: script path signature already present, skipped"));
                } else {
                    pairs.insert((i, id));
                }
            }
        }
    }
    // device keys found only in a script with no derivation record
    for (i, map) in psbt.inputs.iter().enumerate() {
        for t in [I_REDEEM_SCRIPT, I_WITNESS_SCRIPT] {
            if let Some(s) = map_get(map, &[t]) {
                if let Ok(ops) = parse_script(s) {
                    for op in ops {
                        if op.direct && op.data.as_ref().map(|d| d.len()) == Some(33) {
                            let d = op.data.unwrap();
                            if devs.keys.iter().any(|k| k[..] == d[..]) && !pairs.contains(&(i, d.clone())) {
                                notes.push(format!(
                                    "input {i}: device key {} found in a script with no pair for it",
                                    hex_encode(&d)
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok((pairs.into_iter().collect(), notes))
}

enum Fail {
    Retry(String),
    Fatal(String),
}

struct Attempt<'a> {
    psbt: &'a Psbt,
    pairs: &'a [PairCtx],
    hcs: Vec<[u8; 32]>,
    rhos: Vec<[u8; 32]>,
    req_core: Vec<u8>,
    seen_r0: Vec<Option<Vec<u8>>>,
    r0_changed: bool,
    nc: Vec<[u8; 33]>,
    sigs: Vec<Vec<u8>>,
}

impl<'a> Attempt<'a> {
    fn build_request(&self, second: bool) -> Vec<u8> {
        let mut p = self.psbt.clone();
        for (idx, pr) in self.pairs.iter().enumerate() {
            if second {
                map_set(&mut p.inputs[pr.input], key_of(I_AE_HOST_RANDOMNESS, &pr.key_id), self.rhos[idx].to_vec());
            } else {
                map_set(&mut p.inputs[pr.input], key_of(I_AE_HOST_COMMITMENT, &pr.key_id), self.hcs[idx].to_vec());
            }
        }
        p.serialize()
    }

    /// Records every nonce commitment value found in a response, in whatever form.
    fn scan_r0(&mut self, resp: &Psbt) {
        for (idx, pr) in self.pairs.iter().enumerate() {
            if pr.input >= resp.inputs.len() {
                continue;
            }
            if let Some(v) = map_get(&resp.inputs[pr.input], &key_of(I_AE_NONCE_COMMITMENT, &pr.key_id)) {
                match &self.seen_r0[idx] {
                    Some(old) if old != v => self.r0_changed = true,
                    Some(_) => {}
                    None => self.seen_r0[idx] = Some(v.clone()),
                }
            }
        }
    }

    fn check_response(&mut self, line: &str, second: bool) -> Result<(), Fail> {
        let raw = hex_decode(line).ok_or_else(|| Fail::Retry("response is not hex".into()))?;
        let resp = Psbt::parse(&raw).map_err(|e| Fail::Retry(format!("malformed response: {e}")))?;
        self.scan_r0(&resp);
        if self.r0_changed {
            return Err(Fail::Fatal("R0_bytes changed".into()));
        }
        let req = self.psbt;
        if resp.inputs.len() != req.inputs.len() {
            return Err(Fail::Fatal("input count differs".into()));
        }
        match resp.core_tx() {
            Ok(t) if t.core_bytes() == self.req_core => {}
            _ => return Err(Fail::Fatal("core transaction differs from the request".into())),
        }
        for (i, map) in resp.inputs.iter().enumerate() {
            for (k, v) in map {
                if !is_ae_key(k) {
                    continue;
                }
                if second {
                    return Err(Fail::Fatal("second pass response holds an anti-exfil field".into()));
                }
                let idx = self
                    .pairs
                    .iter()
                    .position(|p| p.input == i && p.key_id[..] == k[1..])
                    .ok_or_else(|| Fail::Fatal("anti-exfil field for a pair that was not requested".into()))?;
                match k[0] {
                    I_AE_HOST_RANDOMNESS => return Err(Fail::Fatal("first pass response holds randomness".into())),
                    I_AE_HOST_COMMITMENT => {
                        if v[..] != self.hcs[idx] {
                            return Err(Fail::Fatal("host commitment differs".into()));
                        }
                    }
                    _ => {}
                }
            }
        }
        for (i, rmap) in resp.inputs.iter().enumerate() {
            let qmap = &req.inputs[i];
            for (k, v) in rmap.iter().filter(|(k, _)| is_sig_key(k)) {
                match map_get(qmap, k) {
                    Some(old) => {
                        if old != v {
                            return Err(Fail::Fatal("signature field changed".into()));
                        }
                    }
                    None => {
                        let requested = second && self.pairs.iter().any(|p| p.input == i && p.sig_key == *k);
                        if !requested {
                            return Err(Fail::Fatal("signature field added".into()));
                        }
                    }
                }
            }
            if !has_final(qmap) {
                for (k, _) in qmap.iter().filter(|(k, _)| is_sig_key(k)) {
                    if map_get(rmap, k).is_none() {
                        return Err(Fail::Fatal("signature field removed".into()));
                    }
                }
            }
        }
        if !second {
            let mut nc = Vec::new();
            for (idx, p) in self.pairs.iter().enumerate() {
                let v = map_get(&resp.inputs[p.input], &key_of(I_AE_NONCE_COMMITMENT, &p.key_id))
                    .ok_or_else(|| Fail::Retry("nonce commitment missing".into()))?;
                let _ = idx;
                if v.len() != 33 || parse33(v).is_none() {
                    return Err(Fail::Retry("nonce commitment does not parse".into()));
                }
                let mut a = [0u8; 33];
                a.copy_from_slice(v);
                nc.push(a);
            }
            self.nc = nc;
            return Ok(());
        }
        let mut fields = Vec::new();
        for p in self.pairs {
            match map_get(&resp.inputs[p.input], &p.sig_key) {
                Some(v) => fields.push(v.clone()),
                None => return Err(Fail::Retry("signature missing".into())),
            }
        }
        let mut sigs = Vec::new();
        for (idx, p) in self.pairs.iter().enumerate() {
            let v = &fields[idx];
            let rho = &self.rhos[idx];
            let ok_sig: [u8; 64];
            if p.kind == Kind::Ecdsa {
                let (r, s, ht) = der_parse_strict(v).ok_or_else(|| Fail::Fatal("signature is not strict DER".into()))?;
                if ht as u32 != p.sighash_type {
                    return Err(Fail::Fatal("unexpected sighash type in the signature".into()));
                }
                if !step5_ecdsa(&p.pk, &p.m, rho, &self.nc[idx], &r, &s) {
                    return Err(Fail::Fatal("signature failed the step 5 checks".into()));
                }
                let mut a = [0u8; 64];
                a[..32].copy_from_slice(&r);
                a[32..].copy_from_slice(&s);
                ok_sig = a;
            } else {
                let want = if p.sighash_type == 0 { 64 } else { 65 };
                if v.len() != want || (want == 65 && v[64] as u32 != p.sighash_type) {
                    return Err(Fail::Fatal("signature length or sighash byte is wrong".into()));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&p.pk);
                if !step5_schnorr(&pk, &p.m, rho, &self.nc[idx], &v[..64]) {
                    return Err(Fail::Fatal("signature failed the step 5 checks".into()));
                }
                let mut a = [0u8; 64];
                a.copy_from_slice(&v[..64]);
                ok_sig = a;
            }
            // rebuilt from the verified values only
            sigs.push(sig_field_value(p, &ok_sig));
        }
        self.sigs = sigs;
        Ok(())
    }
}

enum Resp {
    Line(String),
    Eof,
    Timeout,
}

fn read_resp(rx: &mpsc::Receiver<Option<String>>, timeout: Duration) -> Resp {
    match rx.recv_timeout(timeout) {
        Ok(Some(l)) => Resp::Line(l),
        Ok(None) => Resp::Eof,
        Err(mpsc::RecvTimeoutError::Timeout) => Resp::Timeout,
        Err(mpsc::RecvTimeoutError::Disconnected) => Resp::Eof,
    }
}

pub fn run_host(o: HostOpts) -> i32 {
    let devs = Devices { keys: o.devices.clone(), check_purpose: false };
    let dev_id = device_id(&o.devices);
    let mut store = Store::load(&o.store);
    let ri = store.rec_index(&dev_id);

    // A restart ends an open attempt as failed.
    match store.recs[ri].state {
        State::Open => {
            store.recs[ri].count += 1;
            store.recs[ri].state = State::None;
            let _ = store.save().map_err(|e| eprintln!("host: {e}"));
        }
        State::OpenCounted => {
            store.recs[ri].state = State::None;
            let _ = store.save().map_err(|e| eprintln!("host: {e}"));
        }
        State::None => {}
    }
    macro_rules! count {
        () => {
            store.recs[ri].count
        };
    }

    // Request validation, all before any record is made.
    let psbt = match Psbt::parse(&o.psbt) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("host: refused: {e}");
            return finish(count!(), "REFUSED", 4);
        }
    };
    if psbt.inputs.iter().any(|m| m.iter().any(|(k, _)| is_ae_key(k))) {
        eprintln!("host: refused: the PSBT already holds anti-exfil fields");
        return finish(count!(), "REFUSED", 4);
    }
    let (sel, notes) = match select_pairs(&psbt, &devs) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("host: refused: {e}");
            return finish(count!(), "REFUSED", 4);
        }
    };
    for n in &notes {
        eprintln!("host: note: {n}");
    }
    if sel.is_empty() {
        eprintln!("host: refused: no pairs remain");
        return finish(count!(), "REFUSED", 4);
    }
    let pair_inputs: Vec<usize> = sel.iter().map(|(i, _)| *i).collect();
    let ctx = match build_ctx(&psbt, &pair_inputs) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("host: refused: {e}");
            return finish(count!(), "REFUSED", 4);
        }
    };
    let mut pairs = Vec::new();
    for (i, id) in &sel {
        match analyze_pair(&ctx, &devs, *i, id) {
            Ok(p) => pairs.push(p),
            Err(e) => {
                eprintln!("host: refused: {e}");
                return finish(count!(), "REFUSED", 4);
            }
        }
    }
    let has_tap_non_acp = pairs.iter().any(|p| p.kind != Kind::Ecdsa && !p.acp);
    let fee = match fee_info(&ctx, has_tap_non_acp) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("host: refused: {e}");
            return finish(count!(), "REFUSED", 4);
        }
    };
    let req_core = ctx.tx.core_bytes();
    drop(ctx);

    // Randomness supplied by the caller.
    let mut rhos = Vec::new();
    for p in &pairs {
        match o.rhos.iter().find(|((i, id), _)| *i == p.input && *id == p.key_id) {
            Some((_, r)) => rhos.push(*r),
            None => {
                return finish(count!(), "MISSING_RHO", 9);
            }
        }
    }
    let hcs: Vec<[u8; 32]> = pairs.iter().zip(rhos.iter()).map(|(p, r)| host_commitment(p.scheme(), r)).collect();
    // A new rho for every pair and every attempt: no host commitment may repeat.
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    for h in &hcs {
        if !seen.insert(*h) || store.recs[ri].used.contains(&hex_encode(h)) {
            eprintln!("host: refused: a rho value was already used");
            return finish(count!(), "REFUSED", 4);
        }
    }

    // Warning owed?
    if store.recs[ri].count > store.recs[ri].acked && !o.ack {
        eprintln!(
            "host: WARNING: {} earlier attempt(s) with this device failed. Repeated failures can mean a malicious device. Acknowledge to continue.",
            store.recs[ri].count
        );
        return finish(count!(), "NOT_ACKNOWLEDGED", 5);
    }

    // Tell the user what is requested.
    eprintln!("host: requesting anti-exfil signing for {} pair(s)", pairs.len());
    match (&fee.amount, fee.verified) {
        (Some(a), true) => eprintln!("host: fee {a} sat (verified)"),
        (Some(a), false) => eprintln!("host: fee {a} sat (UNVERIFIED: not every input amount is checked)"),
        (None, _) => eprintln!("host: fee unknown (UNVERIFIED)"),
    }

    // Durable record of the open attempt, with the acknowledgement used up in the same write.
    let backup = store.recs[ri].clone();
    {
        let r = &mut store.recs[ri];
        if o.ack {
            r.acked = r.count;
        }
        r.state = State::Open;
        r.used.extend(hcs.iter().map(|h| hex_encode(h)));
    }
    if let Err(e) = store.save() {
        eprintln!("host: refused: {e}");
        store.recs[ri] = backup;
        return finish(count!(), "REFUSED", 4);
    }
    let mut counted = false;

    macro_rules! failure_event {
        () => {
            if !counted {
                counted = true;
                store.recs[ri].count += 1;
                store.recs[ri].state = State::OpenCounted;
                if let Err(e) = store.save() {
                    eprintln!("host: {e}");
                }
            }
        };
    }
    macro_rules! end_attempt {
        () => {
            store.recs[ri].state = State::None;
            if let Err(e) = store.save() {
                eprintln!("host: {e}");
            }
        };
    }

    let timeout = Duration::from_secs(
        std::env::var("AEXF_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(120),
    );
    let (tx, rx) = mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut l = stdin.lock();
        loop {
            let mut s = String::new();
            match l.read_line(&mut s) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
                Ok(_) => {
                    if tx.send(Some(s.trim().to_string())).is_err() {
                        return;
                    }
                }
            }
        }
    });

    let mut at = Attempt {
        psbt: &psbt,
        pairs: &pairs,
        hcs,
        rhos,
        req_core,
        seen_r0: vec![None; pairs.len()],
        r0_changed: false,
        nc: Vec::new(),
        sigs: Vec::new(),
    };

    // Runs one pass with retries. Ok(()) when accepted, Err(()) when the attempt failed.
    for second in [false, true] {
        let req_hex = hex_encode(&at.build_request(second));
        let mut tries = 0u32;
        loop {
            emit(&format!("REQUEST {req_hex}"));
            let outcome: Result<(), Fail> = match read_resp(&rx, timeout) {
                Resp::Line(l) if l == "ERROR" => Err(Fail::Retry("device reported an error".into())),
                Resp::Line(l) => at.check_response(&l, second),
                Resp::Eof => Err(Fail::Retry("no response".into())),
                Resp::Timeout => Err(Fail::Retry("timeout".into())),
            };
            match outcome {
                Ok(()) => break,
                Err(f) => {
                    failure_event!();
                    let (retry, msg) = match f {
                        Fail::Retry(m) => (true, m),
                        Fail::Fatal(m) => (false, m),
                    };
                    eprintln!("host: failure event: {msg}");
                    if !retry || at.r0_changed || tries >= o.max_retries {
                        end_attempt!();
                        return finish(count!(), "FAILED", 3);
                    }
                    tries += 1;
                }
            }
        }
    }

    // Result: only fields built from the verified values.
    let mut res = psbt.clone();
    for (idx, p) in pairs.iter().enumerate() {
        map_set(&mut res.inputs[p.input], p.sig_key.clone(), at.sigs[idx].clone());
        if let Err(e) = res.apply_modifiable_update(p.sighash_type) {
            eprintln!("host: {e}");
            end_attempt!();
            return finish(count!(), "FAILED", 3);
        }
    }
    for r in at.rhos.iter_mut() {
        *r = [0u8; 32];
    }
    end_attempt!();
    let c = count!();
    emit(&format!("COUNT {c}"));
    emit(&format!("RESULT {}", hex_encode(&res.serialize())));
    0
}

/// Explicit user action: clears the failure count, the pending warning and any open attempt.
pub fn run_reset(devices: Vec<[u8; 33]>, store_path: &str) -> i32 {
    let id = device_id(&devices);
    let mut store = Store::load(store_path);
    let i = store.rec_index(&id);
    let cleared = store.recs[i].count;
    eprintln!("reset: clearing the failure count ({cleared}) and the pending warning for this device");
    store.recs[i].count = 0;
    store.recs[i].acked = 0;
    store.recs[i].state = State::None;
    if let Err(e) = store.save() {
        eprintln!("reset: {e}");
        return 4;
    }
    emit("COUNT 0");
    emit("RESET");
    0
}

