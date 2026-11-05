//! Classification and validation of one (input, key identifier) pair, shared by host and signer.

use crate::ae::*;
use crate::ec::*;
use crate::psbt::*;
use crate::script::*;
use crate::sighash::*;
use crate::tx::Tx;
use crate::util::*;

/// Device keys known to a party, as exact 33-byte compressed public keys.
#[derive(Clone, Debug, Default)]
pub struct Devices {
    pub keys: Vec<[u8; 33]>,
    /// Signer only: fail on a derivation path purpose that belongs to the other scheme.
    pub check_purpose: bool,
}

impl Devices {
    pub fn uncompressed(&self) -> Vec<[u8; 65]> {
        self.keys.iter().filter_map(|k| parse33(k).and_then(|p| uncompressed(&p))).collect()
    }
    pub fn has_x(&self, x: &[u8]) -> bool {
        self.keys.iter().any(|k| &k[1..] == x)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Ecdsa,
    TapKey,
    TapScript,
}

#[derive(Clone, Debug)]
pub struct PairCtx {
    pub input: usize,
    pub key_id: Vec<u8>,
    pub kind: Kind,
    /// Effective sighash type (0 is SIGHASH_DEFAULT).
    pub sighash_type: u32,
    /// Protocol pk: 33 bytes (ECDSA) or 32 bytes (BIP340).
    pub pk: Vec<u8>,
    pub m: [u8; 32],
    /// Full PSBT key of the signature field.
    pub sig_key: Vec<u8>,
    /// Key path only: the tweak applied to the (normalized) internal secret.
    pub tweak: Option<Sc>,
    /// Whether the sighash type has ANYONECANPAY.
    pub acp: bool,
}

impl PairCtx {
    pub fn scheme(&self) -> Scheme {
        if self.kind == Kind::Ecdsa {
            Scheme::Ecdsa
        } else {
            Scheme::Schnorr
        }
    }
}

#[derive(Clone, Debug)]
pub struct Prev {
    pub out: Prevout,
    /// Taken from a PSBT_IN_NON_WITNESS_UTXO that hashes to the input's txid.
    pub verified: bool,
}

pub struct Ctx<'a> {
    pub psbt: &'a Psbt,
    pub tx: Tx,
    pub prev: Vec<Option<Prev>>,
}

impl<'a> Ctx<'a> {
    pub fn prevouts(&self) -> Vec<Option<Prevout>> {
        self.prev.iter().map(|p| p.as_ref().map(|p| p.out.clone())).collect()
    }
}

fn parse_witness_utxo(v: &[u8]) -> Result<Prevout, String> {
    let mut r = Reader::new(v);
    let amount = r.u64le()?;
    let spk = r.var_bytes()?.to_vec();
    if r.remaining() != 0 {
        return Err("trailing bytes in witness UTXO".into());
    }
    Ok(Prevout { amount, spk })
}

/// Resolves previous outputs. For inputs in `pair_inputs` bad data is an error; for the rest
/// it is treated as absent.
pub fn build_ctx<'a>(psbt: &'a Psbt, pair_inputs: &[usize]) -> Result<Ctx<'a>, String> {
    let tx = psbt.core_tx()?;
    let mut prev = Vec::new();
    for (i, map) in psbt.inputs.iter().enumerate() {
        let strict = pair_inputs.contains(&i);
        let mut nw: Option<Prevout> = None;
        let mut w: Option<Prevout> = None;
        let mut bad = false;
        if let Some(raw) = map_get(map, &[I_NON_WITNESS_UTXO]) {
            match Tx::parse(raw) {
                Ok(t) if t.txid() == tx.inputs[i].txid && (tx.inputs[i].vout as usize) < t.outputs.len() => {
                    let o = &t.outputs[tx.inputs[i].vout as usize];
                    nw = Some(Prevout { amount: o.amount, spk: o.script.clone() });
                }
                Ok(_) => {
                    if strict {
                        return Err(format!("input {i}: non-witness UTXO does not match the previous output"));
                    }
                    bad = true;
                }
                Err(e) => {
                    if strict {
                        return Err(format!("input {i}: bad non-witness UTXO: {e}"));
                    }
                    bad = true;
                }
            }
        }
        if let Some(raw) = map_get(map, &[I_WITNESS_UTXO]) {
            match parse_witness_utxo(raw) {
                Ok(p) => w = Some(p),
                Err(e) => {
                    if strict {
                        return Err(format!("input {i}: bad witness UTXO: {e}"));
                    }
                    bad = true;
                }
            }
        }
        let p = match (nw, w) {
            (Some(a), Some(b)) => {
                if a != b {
                    if strict {
                        return Err(format!("input {i}: the two UTXO fields disagree"));
                    }
                    None
                } else {
                    Some(Prev { out: a, verified: true })
                }
            }
            (Some(a), None) => Some(Prev { out: a, verified: true }),
            (None, Some(b)) => Some(Prev { out: b, verified: false }),
            (None, None) => None,
        };
        let _ = bad;
        prev.push(p);
    }
    Ok(Ctx { psbt, tx, prev })
}

#[derive(Clone, Debug)]
pub struct Fee {
    /// None if some input amount is unknown.
    pub amount: Option<u128>,
    pub verified: bool,
}

/// Fee computation; fails if outputs exceed inputs when every input amount is known.
pub fn fee_info(ctx: &Ctx, has_tap_non_acp: bool) -> Result<Fee, String> {
    if ctx.prev.iter().any(|p| p.is_none()) {
        return Ok(Fee { amount: None, verified: false });
    }
    let ins: u128 = ctx.prev.iter().map(|p| p.as_ref().unwrap().out.amount as u128).sum();
    let outs: u128 = ctx.tx.outputs.iter().map(|o| o.amount as u128).sum();
    if outs > ins {
        return Err("outputs exceed inputs".into());
    }
    let all_nwu = ctx.prev.iter().all(|p| p.as_ref().unwrap().verified);
    Ok(Fee { amount: Some(ins - outs), verified: all_nwu || has_tap_non_acp })
}

pub fn parse_sighash_type(map: &Map, ecdsa: bool) -> Result<u32, String> {
    match map_get(map, &[I_SIGHASH_TYPE]) {
        None => Ok(if ecdsa { 1 } else { 0 }),
        Some(v) => {
            if v.len() != 4 {
                return Err("sighash type must be 4 bytes".into());
            }
            let t = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            match t {
                1 | 2 | 3 | 0x81 | 0x82 | 0x83 => Ok(t),
                0 if !ecdsa => Ok(0),
                _ => Err(format!("unsupported sighash type {t:#x}")),
            }
        }
    }
}

fn is_p2pkh(s: &[u8]) -> bool {
    s.len() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac
}
fn is_p2wpkh(s: &[u8]) -> bool {
    s.len() == 22 && s[0] == 0x00 && s[1] == 0x14
}
fn is_p2sh(s: &[u8]) -> bool {
    s.len() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87
}
fn is_p2wsh(s: &[u8]) -> bool {
    s.len() == 34 && s[0] == 0x00 && s[1] == 0x20
}
fn is_p2tr(s: &[u8]) -> bool {
    s.len() == 34 && s[0] == 0x51 && s[1] == 0x20
}
fn p2pkh_code(h: &[u8]) -> Vec<u8> {
    let mut v = vec![0x76, 0xa9, 0x14];
    v.extend_from_slice(h);
    v.extend_from_slice(&[0x88, 0xac]);
    v
}

/// A script containing the device key in a supported form (ECDSA).
fn check_ecdsa_script(script: &[u8], key: &[u8]) -> Result<(), String> {
    let ops = parse_script(script)?;
    if has_codeseparator(&ops) {
        return Err("script contains OP_CODESEPARATOR".into());
    }
    if let Some(k) = match_single_key(script) {
        if k[..] == *key {
            return Ok(());
        }
        return Err("key not in script".into());
    }
    if let Some(keys) = match_multisig(script) {
        let n = keys.iter().filter(|k| k[..] == *key).count();
        return match n {
            1 => Ok(()),
            0 => Err("key not in script".into()),
            _ => Err("device key listed twice".into()),
        };
    }
    // Optional form: the key as a direct push immediately before a signature opcode.
    match count_key_before_sigop(&ops, key, &[OP_CHECKSIG, OP_CHECKSIGVERIFY]) {
        1 => Ok(()),
        0 => Err("key not in script in a supported form".into()),
        _ => Err("key appears before several signature opcodes".into()),
    }
}

fn musig_and_uncompressed_checks(map: &Map, devs: &Devices, taproot: bool, internal: Option<&[u8]>) -> Result<(), String> {
    let unc = devs.uncompressed();
    for (kd, _) in entries_of_type(map, I_BIP32_DERIVATION) {
        if kd.len() == 65 && unc.iter().any(|u| u[..] == *kd) {
            return Err("derivation record with the uncompressed form of a device key".into());
        }
    }
    if taproot {
        for (agg, val) in entries_of_type(map, I_MUSIG2_PARTICIPANT_PUBKEYS) {
            if val.len() % 33 != 0 {
                return Err("malformed MuSig2 participant field".into());
            }
            for c in val.chunks(33) {
                if devs.has_x(&c[1..]) {
                    return Err("MuSig2 participant list holds a device key".into());
                }
            }
            if agg.len() == 33 {
                if let Some(ik) = internal {
                    if ik == &agg[1..] {
                        return Err("internal key is a MuSig2 aggregate key".into());
                    }
                }
                if let Some(v) = map_get(map, &[I_TAP_INTERNAL_KEY]) {
                    if v[..] == agg[1..] {
                        return Err("internal key is a MuSig2 aggregate key".into());
                    }
                }
            }
        }
    }
    Ok(())
}

/// First element of the derivation path if it is hardened, as a purpose number.
fn derivation_purpose(value: &[u8]) -> Option<u32> {
    if value.len() < 8 || (value.len() - 4) % 4 != 0 {
        return None;
    }
    let e = u32::from_le_bytes([value[4], value[5], value[6], value[7]]);
    if e & 0x8000_0000 != 0 {
        Some(e & 0x7fff_ffff)
    } else {
        None
    }
}

/// Where the purpose can be told, it must belong to the pair's scheme: 44', 49' and 84' are ECDSA, 86' is BIP340.
fn check_purpose(map: &Map, kind: Kind, key_id: &[u8]) -> Result<(), String> {
    let value: Option<&[u8]> = match kind {
        Kind::Ecdsa => map_get(map, &key_of(I_BIP32_DERIVATION, key_id)).map(|v| v.as_slice()),
        Kind::TapKey | Kind::TapScript => {
            let x = &key_id[..32];
            match map_get(map, &key_of(I_TAP_BIP32_DERIVATION, x)) {
                Some(v) => {
                    let mut r = Reader::new(v);
                    match r.compact() {
                        Ok(n) if n <= (r.remaining() / 32) as u64 => {
                            r.pos += 32 * n as usize;
                            Some(&v[r.pos..])
                        }
                        _ => return Err("malformed Taproot derivation record".into()),
                    }
                }
                None => None,
            }
        }
    };
    if let Some(p) = value.and_then(derivation_purpose) {
        let tap = kind != Kind::Ecdsa;
        if (tap && matches!(p, 44 | 49 | 84)) || (!tap && p == 86) {
            return Err(format!("derivation purpose {p}' belongs to the other signature scheme"));
        }
    }
    Ok(())
}

/// Validate one pair and compute its message. Used by the host (with its device keys) and the signer.
pub fn analyze_pair(ctx: &Ctx, devs: &Devices, input: usize, key_id: &[u8]) -> Result<PairCtx, String> {
    let map = &ctx.psbt.inputs[input];
    if map_get(map, &[I_FINAL_SCRIPTSIG]).is_some() || map_get(map, &[I_FINAL_SCRIPTWITNESS]).is_some() {
        return Err(format!("input {input}: already finalized"));
    }
    let kind = match key_id.len() {
        33 => Kind::Ecdsa,
        32 => Kind::TapKey,
        64 => Kind::TapScript,
        n => return Err(format!("input {input}: key identifier of {n} bytes")),
    };
    let ecdsa = kind == Kind::Ecdsa;
    if devs.check_purpose {
        check_purpose(map, kind, key_id)?;
    }
    let ht = parse_sighash_type(map, ecdsa)?;
    let acp = ht & 0x80 != 0;
    let prev = ctx.prev[input].as_ref().ok_or_else(|| format!("input {input}: no UTXO data"))?;
    let spk = &prev.out.spk;
    let nwu = map_get(map, &[I_NON_WITNESS_UTXO]).is_some();
    let prevouts = ctx.prevouts();

    if ecdsa {
        if parse33(key_id).is_none() {
            return Err(format!("input {input}: invalid public key"));
        }
        musig_and_uncompressed_checks(map, devs, false, None)?;
        let sig_key = key_of(I_PARTIAL_SIG, key_id);
        if map_get(map, &sig_key).is_some() {
            return Err(format!("input {input}: signature already present for the key"));
        }
        let h160 = hash160(key_id);
        let m = if is_p2pkh(spk) {
            if !nwu {
                return Err("legacy spend needs a non-witness UTXO".into());
            }
            if spk[3..23] != h160 {
                return Err("key does not match P2PKH script".into());
            }
            sighash_legacy(&ctx.tx, input, spk, ht)?
        } else if is_p2wpkh(spk) {
            if spk[2..22] != h160 {
                return Err("key does not match P2WPKH script".into());
            }
            sighash_bip143(&ctx.tx, input, &p2pkh_code(&h160), prev.out.amount, ht)?
        } else if is_p2wsh(spk) {
            let ws = map_get(map, &[I_WITNESS_SCRIPT]).ok_or("missing witness script")?;
            if sha256(ws)[..] != spk[2..34] {
                return Err("witness script does not match the output".into());
            }
            check_ecdsa_script(ws, key_id)?;
            sighash_bip143(&ctx.tx, input, ws, prev.out.amount, ht)?
        } else if is_p2sh(spk) {
            let rs = map_get(map, &[I_REDEEM_SCRIPT]).ok_or("missing redeem script")?;
            if hash160(rs)[..] != spk[2..22] {
                return Err("redeem script does not match the output".into());
            }
            if is_p2wpkh(rs) {
                if rs[2..22] != h160 {
                    return Err("key does not match P2SH-P2WPKH script".into());
                }
                sighash_bip143(&ctx.tx, input, &p2pkh_code(&h160), prev.out.amount, ht)?
            } else if is_p2wsh(rs) {
                let ws = map_get(map, &[I_WITNESS_SCRIPT]).ok_or("missing witness script")?;
                if sha256(ws)[..] != rs[2..34] {
                    return Err("witness script does not match the redeem script".into());
                }
                check_ecdsa_script(ws, key_id)?;
                sighash_bip143(&ctx.tx, input, ws, prev.out.amount, ht)?
            } else {
                if !nwu {
                    return Err("legacy spend needs a non-witness UTXO".into());
                }
                check_ecdsa_script(rs, key_id)?;
                sighash_legacy(&ctx.tx, input, rs, ht)?
            }
        } else {
            return Err(format!("input {input}: unsupported output script"));
        };
        return Ok(PairCtx {
            input,
            key_id: key_id.to_vec(),
            kind,
            sighash_type: ht,
            pk: key_id.to_vec(),
            m,
            sig_key,
            tweak: None,
            acp,
        });
    }

    // Taproot
    if !is_p2tr(spk) {
        return Err(format!("input {input}: Taproot key identifier on a non-Taproot output"));
    }
    if !acp && prevouts.iter().any(|p| p.is_none()) {
        return Err("a Taproot signature hash needs every previous output".into());
    }
    if kind == Kind::TapKey {
        let internal = key_id;
        if let Some(v) = map_get(map, &[I_TAP_INTERNAL_KEY]) {
            if v[..] != *internal {
                return Err("key identifier differs from the internal key".into());
            }
        }
        musig_and_uncompressed_checks(map, devs, true, Some(internal))?;
        let sig_key = vec![I_TAP_KEY_SIG];
        if map_get(map, &sig_key).is_some() {
            return Err(format!("input {input}: key path signature already present"));
        }
        let root = match map_get(map, &[I_TAP_MERKLE_ROOT]) {
            Some(r) if r.len() == 32 => Some(r.as_slice()),
            Some(_) => return Err("merkle root must be 32 bytes".into()),
            None => None,
        };
        let (q, t) = tap_tweak(internal, root).ok_or("cannot tweak the internal key")?;
        let qx = x_bytes(&q);
        if qx[..] != spk[2..34] {
            return Err("output key does not match the internal key and merkle root".into());
        }
        let m = sighash_taproot(&ctx.tx, input, &prevouts, ht, None)?;
        return Ok(PairCtx {
            input,
            key_id: key_id.to_vec(),
            kind,
            sighash_type: ht,
            pk: qx.to_vec(),
            m,
            sig_key,
            tweak: Some(t),
            acp,
        });
    }

    // Script path
    let xkey = &key_id[..32];
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&key_id[32..]);
    let sig_key = key_of(I_TAP_SCRIPT_SIG, key_id);
    if map_get(map, &sig_key).is_some() {
        return Err(format!("input {input}: script path signature already present"));
    }
    let mut matches = Vec::new();
    for (control, val) in entries_of_type(map, I_TAP_LEAF_SCRIPT) {
        if val.is_empty() {
            return Err("empty leaf script entry".into());
        }
        let ver = val[val.len() - 1];
        let script = &val[..val.len() - 1];
        if tap_leaf_hash(ver, script) == leaf {
            matches.push((control, ver, script));
        }
    }
    if matches.len() != 1 {
        return Err(format!("{} leaf script entries match the leaf hash", matches.len()));
    }
    let (control, ver, script) = matches[0];
    if ver != 0xc0 {
        return Err("leaf version is not 0xc0".into());
    }
    if control.is_empty() || control[0] & 0xfe != 0xc0 {
        return Err("control block leaf version mismatch".into());
    }
    let (ox, parity, ik) = control_block_output(control, &leaf).ok_or("bad control block")?;
    if ox[..] != spk[2..34] || parity != (control[0] & 1 == 1) {
        return Err("control block does not compute the spent output key".into());
    }
    musig_and_uncompressed_checks(map, devs, true, Some(&ik))?;
    let ops = parse_script(script)?;
    if has_codeseparator(&ops) {
        return Err("leaf contains OP_CODESEPARATOR".into());
    }
    if has_op_success(&ops) {
        return Err("leaf contains an OP_SUCCESS opcode".into());
    }
    match count_key_before_sigop(&ops, xkey, &[OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD]) {
        1 => {}
        0 => return Err("key not in leaf before a signature opcode".into()),
        _ => return Err("key appears before several signature opcodes".into()),
    }
    let m = sighash_taproot(&ctx.tx, input, &prevouts, ht, Some(&leaf))?;
    Ok(PairCtx {
        input,
        key_id: key_id.to_vec(),
        kind,
        sighash_type: ht,
        pk: xkey.to_vec(),
        m,
        sig_key,
        tweak: None,
        acp,
    })
}
