//! Test helpers. Everything except hex, ripemd160 and PSBT container parsing is written
//! independently of the crate's own protocol, sighash and verification code.
#![allow(dead_code)]

use aexf::util::{hex_decode, hex_encode, ripemd160};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

pub type Map = Vec<(Vec<u8>, Vec<u8>)>;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
pub fn sha256d(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b))
}
pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
pub fn hash160(b: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(b))
}
pub fn compact(n: u64) -> Vec<u8> {
    let mut o = Vec::new();
    aexf::util::put_compact(&mut o, n);
    o
}
pub fn push(d: &[u8]) -> Vec<u8> {
    assert!(d.len() < 76);
    let mut v = vec![d.len() as u8];
    v.extend_from_slice(d);
    v
}

pub fn reduce(b: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(b))
}
pub fn sc_from(b: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr(*FieldBytes::from_slice(b)))
}
pub fn g_mul(s: &Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * *s
}
pub fn enc(p: &ProjectivePoint, compressed: bool) -> Vec<u8> {
    p.to_affine().to_encoded_point(compressed).as_bytes().to_vec()
}
pub fn xonly(p: &ProjectivePoint) -> [u8; 32] {
    let e = enc(p, true);
    let mut x = [0u8; 32];
    x.copy_from_slice(&e[1..]);
    x
}
pub fn is_odd(p: &ProjectivePoint) -> bool {
    enc(p, true)[0] == 3
}
pub fn lift(x: &[u8]) -> ProjectivePoint {
    let mut b = vec![2u8];
    b.extend_from_slice(x);
    point(&b)
}
pub fn point(b: &[u8]) -> ProjectivePoint {
    let ep = k256::EncodedPoint::from_bytes(b).unwrap();
    ProjectivePoint::from(k256::AffinePoint::try_from(ep).unwrap())
}

#[derive(Clone)]
pub struct Key {
    pub sk: [u8; 32],
    pub sc: Scalar,
    pub p: ProjectivePoint,
    pub pk: [u8; 33],
    pub x: [u8; 32],
}

pub fn key(n: u32) -> Key {
    let mut h = sha256(format!("aexf test key {n}").as_bytes());
    loop {
        if let Some(sc) = sc_from(&h) {
            let p = g_mul(&sc);
            let e = enc(&p, true);
            let mut pk = [0u8; 33];
            pk.copy_from_slice(&e);
            return Key { sk: h, sc, p, pk, x: xonly(&p) };
        }
        h = sha256(&h);
    }
}

/// A key whose compressed public key has the given parity (odd = true).
pub fn key_with_parity(odd: bool, start: u32) -> Key {
    let mut n = start;
    loop {
        let k = key(n);
        if is_odd(&k.p) == odd {
            return k;
        }
        n += 1;
    }
}

// ---- transactions ----
#[derive(Clone, Debug)]
pub struct TIn {
    pub txid: [u8; 32],
    pub vout: u32,
    pub seq: u32,
}
#[derive(Clone, Debug)]
pub struct TOut {
    pub amount: u64,
    pub spk: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct T {
    pub ver: u32,
    pub lock: u32,
    pub ins: Vec<TIn>,
    pub outs: Vec<TOut>,
}

pub fn ser_out(o: &TOut) -> Vec<u8> {
    let mut v = o.amount.to_le_bytes().to_vec();
    v.extend(compact(o.spk.len() as u64));
    v.extend(&o.spk);
    v
}
pub fn ser_outpoint(i: &TIn) -> Vec<u8> {
    let mut v = i.txid.to_vec();
    v.extend(i.vout.to_le_bytes());
    v
}
pub fn ser_tx(t: &T) -> Vec<u8> {
    let mut v = t.ver.to_le_bytes().to_vec();
    v.extend(compact(t.ins.len() as u64));
    for i in &t.ins {
        v.extend(ser_outpoint(i));
        v.push(0);
        v.extend(i.seq.to_le_bytes());
    }
    v.extend(compact(t.outs.len() as u64));
    for o in &t.outs {
        v.extend(ser_out(o));
    }
    v.extend(t.lock.to_le_bytes());
    v
}

pub fn sh_legacy(t: &T, idx: usize, code: &[u8], ht: u32) -> [u8; 32] {
    let base = ht & 3;
    let acp = ht & 0x80 != 0;
    let mut v = t.ver.to_le_bytes().to_vec();
    let ins: Vec<usize> = if acp { vec![idx] } else { (0..t.ins.len()).collect() };
    v.extend(compact(ins.len() as u64));
    for &j in &ins {
        v.extend(ser_outpoint(&t.ins[j]));
        if j == idx {
            v.extend(compact(code.len() as u64));
            v.extend(code);
        } else {
            v.push(0);
        }
        let s = if j != idx && base != 1 { 0 } else { t.ins[j].seq };
        v.extend(s.to_le_bytes());
    }
    match base {
        2 => v.extend(compact(0)),
        3 => {
            v.extend(compact(idx as u64 + 1));
            for j in 0..=idx {
                if j == idx {
                    v.extend(ser_out(&t.outs[j]));
                } else {
                    v.extend(u64::MAX.to_le_bytes());
                    v.push(0);
                }
            }
        }
        _ => {
            v.extend(compact(t.outs.len() as u64));
            for o in &t.outs {
                v.extend(ser_out(o));
            }
        }
    }
    v.extend(t.lock.to_le_bytes());
    v.extend(ht.to_le_bytes());
    sha256d(&v)
}

pub fn sh_bip143(t: &T, idx: usize, code: &[u8], amount: u64, ht: u32) -> [u8; 32] {
    let base = ht & 3;
    let acp = ht & 0x80 != 0;
    let hp = if acp {
        [0u8; 32]
    } else {
        sha256d(&t.ins.iter().flat_map(ser_outpoint).collect::<Vec<u8>>())
    };
    let hs = if acp || base == 2 || base == 3 {
        [0u8; 32]
    } else {
        sha256d(&t.ins.iter().flat_map(|i| i.seq.to_le_bytes()).collect::<Vec<u8>>())
    };
    let ho = match base {
        2 => [0u8; 32],
        3 => sha256d(&ser_out(&t.outs[idx])),
        _ => sha256d(&t.outs.iter().flat_map(ser_out).collect::<Vec<u8>>()),
    };
    let mut v = t.ver.to_le_bytes().to_vec();
    v.extend(hp);
    v.extend(hs);
    v.extend(ser_outpoint(&t.ins[idx]));
    v.extend(compact(code.len() as u64));
    v.extend(code);
    v.extend(amount.to_le_bytes());
    v.extend(t.ins[idx].seq.to_le_bytes());
    v.extend(ho);
    v.extend(t.lock.to_le_bytes());
    v.extend(ht.to_le_bytes());
    sha256d(&v)
}

pub fn sh_taproot(t: &T, idx: usize, prevs: &[(u64, Vec<u8>)], ht: u32, leaf: Option<[u8; 32]>) -> [u8; 32] {
    let out_t = if ht == 0 { 1 } else { ht & 3 };
    let acp = ht & 0x80 != 0;
    let mut m = vec![0u8, ht as u8];
    m.extend(t.ver.to_le_bytes());
    m.extend(t.lock.to_le_bytes());
    if !acp {
        m.extend(sha256(&t.ins.iter().flat_map(ser_outpoint).collect::<Vec<u8>>()));
        m.extend(sha256(&prevs.iter().flat_map(|p| p.0.to_le_bytes()).collect::<Vec<u8>>()));
        m.extend(sha256(
            &prevs.iter().flat_map(|p| { let mut s = compact(p.1.len() as u64); s.extend(&p.1); s }).collect::<Vec<u8>>(),
        ));
        m.extend(sha256(&t.ins.iter().flat_map(|i| i.seq.to_le_bytes()).collect::<Vec<u8>>()));
    }
    if out_t == 1 {
        m.extend(sha256(&t.outs.iter().flat_map(ser_out).collect::<Vec<u8>>()));
    }
    m.push(if leaf.is_some() { 2 } else { 0 });
    if acp {
        m.extend(ser_outpoint(&t.ins[idx]));
        m.extend(prevs[idx].0.to_le_bytes());
        m.extend(compact(prevs[idx].1.len() as u64));
        m.extend(&prevs[idx].1);
        m.extend(t.ins[idx].seq.to_le_bytes());
    } else {
        m.extend((idx as u32).to_le_bytes());
    }
    if out_t == 3 {
        m.extend(sha256(&ser_out(&t.outs[idx])));
    }
    if let Some(l) = leaf {
        m.extend(l);
        m.push(0);
        m.extend(0xffff_ffffu32.to_le_bytes());
    }
    tagged("TapSighash", &[&m])
}

// ---- independent signature verification ----
pub fn ecdsa_verify(pk: &[u8], z: &[u8; 32], r: &Scalar, s: &Scalar) -> bool {
    use k256::elliptic_curve::Field;
    let zs = reduce(z);
    let si: Scalar = Option::from(s.invert()).unwrap();
    let v = g_mul(&(zs * si)) + point(pk) * (*r * si);
    if v == ProjectivePoint::IDENTITY {
        return false;
    }
    reduce(&xonly(&v)) == *r
}

pub fn schnorr_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    let p = lift(pk);
    let r_bytes = &sig[..32];
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&sig[32..]);
    let s = match sc_from(&sb) {
        Some(s) => s,
        None => return false,
    };
    let mut ee = [0u8; 32];
    ee.copy_from_slice(&tagged("BIP0340/challenge", &[r_bytes, pk, m]));
    let e = reduce(&ee);
    let r = g_mul(&s) + (-(p * e));
    r != ProjectivePoint::IDENTITY && !is_odd(&r) && xonly(&r) == r_bytes
}

// ---- scripts ----
pub fn p2pkh(h: &[u8]) -> Vec<u8> {
    let mut v = vec![0x76, 0xa9, 0x14];
    v.extend(h);
    v.extend([0x88, 0xac]);
    v
}
pub fn p2wpkh(h: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 0x14];
    v.extend(h);
    v
}
pub fn p2sh(h: &[u8]) -> Vec<u8> {
    let mut v = vec![0xa9, 0x14];
    v.extend(h);
    v.push(0x87);
    v
}
pub fn p2wsh(h: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 0x20];
    v.extend(h);
    v
}
pub fn p2tr(x: &[u8]) -> Vec<u8> {
    let mut v = vec![0x51, 0x20];
    v.extend(x);
    v
}
pub fn multisig(keys: &[[u8; 33]], m: u8) -> Vec<u8> {
    let mut v = vec![0x50 + m];
    for k in keys {
        v.extend(push(k));
    }
    v.push(0x50 + keys.len() as u8);
    v.push(0xae);
    v
}
pub fn checksig_script(pk: &[u8]) -> Vec<u8> {
    let mut v = push(pk);
    v.push(0xac);
    v
}

pub fn tap_leaf(ver: u8, script: &[u8]) -> [u8; 32] {
    let mut l = vec![ver];
    l.extend(compact(script.len() as u64));
    l.extend(script);
    tagged("TapLeaf", &[&l])
}
pub fn tap_branch(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a < b { tagged("TapBranch", &[a, b]) } else { tagged("TapBranch", &[b, a]) }
}
/// Output key (point) and tweak scalar.
pub fn tap_output(internal_x: &[u8; 32], root: Option<&[u8; 32]>) -> (ProjectivePoint, Scalar) {
    let h = match root {
        Some(r) => tagged("TapTweak", &[internal_x, r]),
        None => tagged("TapTweak", &[internal_x]),
    };
    let t = sc_from(&h).unwrap();
    (lift(internal_x) + g_mul(&t), t)
}

// ---- PSBT assembly ----
pub fn ser_map(m: &Map) -> Vec<u8> {
    let mut v = Vec::new();
    for (k, val) in m {
        v.extend(compact(k.len() as u64));
        v.extend(k);
        v.extend(compact(val.len() as u64));
        v.extend(val);
    }
    v.push(0);
    v
}
pub fn kv(t: u8, data: &[u8], val: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut k = vec![t];
    k.extend(data);
    (k, val.to_vec())
}

#[derive(Clone, Debug)]
pub struct Spec {
    pub version: u32,
    pub t: T,
    pub glob: Map,
    pub ins: Vec<Map>,
    pub outs: Vec<Map>,
}

impl Spec {
    pub fn psbt(&self) -> Vec<u8> {
        let mut v = b"psbt\xff".to_vec();
        let mut g = self.glob.clone();
        if self.version == 0 {
            g.insert(0, kv(0x00, &[], &ser_tx(&self.t)));
        } else {
            g.push(kv(0xfb, &[], &2u32.to_le_bytes()));
            g.push(kv(0x02, &[], &self.t.ver.to_le_bytes()));
            g.push(kv(0x04, &[], &compact(self.t.ins.len() as u64)));
            g.push(kv(0x05, &[], &compact(self.t.outs.len() as u64)));
            if self.t.lock != 0 {
                g.push(kv(0x03, &[], &self.t.lock.to_le_bytes()));
            }
        }
        v.extend(ser_map(&g));
        for (i, m) in self.ins.iter().enumerate() {
            let mut m = m.clone();
            if self.version == 2 {
                m.push(kv(0x0e, &[], &self.t.ins[i].txid));
                m.push(kv(0x0f, &[], &self.t.ins[i].vout.to_le_bytes()));
                m.push(kv(0x10, &[], &self.t.ins[i].seq.to_le_bytes()));
            }
            v.extend(ser_map(&m));
        }
        for (i, m) in self.outs.iter().enumerate() {
            let mut m = m.clone();
            if self.version == 2 {
                m.push(kv(0x03, &[], &self.t.outs[i].amount.to_le_bytes()));
                m.push(kv(0x04, &[], &self.t.outs[i].spk));
            }
            v.extend(ser_map(&m));
        }
        v
    }
    pub fn hex(&self) -> String {
        hex_encode(&self.psbt())
    }
    pub fn set(&mut self, input: usize, key: Vec<u8>, val: Vec<u8>) {
        if let Some(e) = self.ins[input].iter_mut().find(|(k, _)| *k == key) {
            e.1 = val;
        } else {
            self.ins[input].push((key, val));
        }
    }
    pub fn remove(&mut self, input: usize, key: &[u8]) {
        self.ins[input].retain(|(k, _)| k != key);
    }
    pub fn get(&self, input: usize, key: &[u8]) -> Option<Vec<u8>> {
        self.ins[input].iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spend {
    P2pkh,
    P2wpkh,
    P2shP2wpkh,
    P2wsh1,
    P2wshMulti,
    P2shP2wsh,
    P2shLegacy,
    TapKey,
    TapScript,
}

pub const ALL_SPENDS: [Spend; 9] = [
    Spend::P2pkh,
    Spend::P2wpkh,
    Spend::P2shP2wpkh,
    Spend::P2wsh1,
    Spend::P2wshMulti,
    Spend::P2shP2wsh,
    Spend::P2shLegacy,
    Spend::TapKey,
    Spend::TapScript,
];

pub struct Built {
    pub spec: Spec,
    pub dev: Key,
    pub spend: Spend,
    /// Key identifier of the pair on input 0.
    pub id: Vec<u8>,
    /// Effective sighash type (0 = default).
    pub ht: u32,
    pub prevs: Vec<(u64, Vec<u8>)>,
    pub leaf: Option<[u8; 32]>,
    pub internal: Option<Key>,
    pub merkle: Option<[u8; 32]>,
    pub code: Vec<u8>,
}

pub const AMT0: u64 = 100_000;
pub const AMT1: u64 = 50_000;

pub fn fund_tx(spk: &[u8], amount: u64, salt: u8) -> (Vec<u8>, [u8; 32]) {
    let t = T {
        ver: 2,
        lock: 0,
        ins: vec![TIn { txid: [salt; 32], vout: 0, seq: 0xffff_ffff }],
        outs: vec![TOut { amount, spk: spk.to_vec() }],
    };
    let raw = ser_tx(&t);
    let id = sha256d(&raw);
    (raw, id)
}

pub fn wu(amount: u64, spk: &[u8]) -> Vec<u8> {
    let mut v = amount.to_le_bytes().to_vec();
    v.extend(compact(spk.len() as u64));
    v.extend(spk);
    v
}

/// Builds a two input, two output transaction whose input 0 is spent by the device key (key 1).
/// `ht`: None leaves PSBT_IN_SIGHASH_TYPE out.
pub fn build(spend: Spend, version: u32, ht: Option<u32>) -> Built {
    let dev = key(1);
    let k2 = key(2);
    let k3 = key(3);
    let other_in = key(4);
    let ecdsa = !matches!(spend, Spend::TapKey | Spend::TapScript);
    let mut m0: Map = Vec::new();
    let mut spk0;
    let mut id = dev.pk.to_vec();
    let mut code = Vec::new();
    let mut leaf = None;
    let mut internal = None;
    let mut merkle = None;
    let deriv = |pk: &[u8]| kv(0x06, pk, &[1, 2, 3, 4, 0x80, 0, 0, 0]);
    let mut nwu: Option<Vec<u8>> = None;
    let mut wu_used = true;
    match spend {
        Spend::P2pkh => {
            spk0 = p2pkh(&hash160(&dev.pk));
            code = spk0.clone();
            m0.push(deriv(&dev.pk));
            wu_used = false;
        }
        Spend::P2wpkh => {
            spk0 = p2wpkh(&hash160(&dev.pk));
            code = p2pkh(&hash160(&dev.pk));
            m0.push(deriv(&dev.pk));
        }
        Spend::P2shP2wpkh => {
            let redeem = p2wpkh(&hash160(&dev.pk));
            spk0 = p2sh(&hash160(&redeem));
            code = p2pkh(&hash160(&dev.pk));
            m0.push(kv(0x04, &[], &redeem));
            m0.push(deriv(&dev.pk));
        }
        Spend::P2wsh1 => {
            let ws = checksig_script(&dev.pk);
            spk0 = p2wsh(&sha256(&ws));
            m0.push(kv(0x05, &[], &ws));
            m0.push(deriv(&dev.pk));
            code = ws;
        }
        Spend::P2wshMulti => {
            let ws = multisig(&[k2.pk, dev.pk, k3.pk], 2);
            spk0 = p2wsh(&sha256(&ws));
            m0.push(kv(0x05, &[], &ws));
            m0.push(deriv(&dev.pk));
            code = ws;
        }
        Spend::P2shP2wsh => {
            let ws = multisig(&[dev.pk, k2.pk], 1);
            let redeem = p2wsh(&sha256(&ws));
            spk0 = p2sh(&hash160(&redeem));
            m0.push(kv(0x04, &[], &redeem));
            m0.push(kv(0x05, &[], &ws));
            m0.push(deriv(&dev.pk));
            code = ws;
        }
        Spend::P2shLegacy => {
            let rs = checksig_script(&dev.pk);
            spk0 = p2sh(&hash160(&rs));
            m0.push(kv(0x04, &[], &rs));
            m0.push(deriv(&dev.pk));
            code = rs;
            wu_used = false;
        }
        Spend::TapKey => {
            let (q, _) = tap_output(&dev.x, None);
            spk0 = p2tr(&xonly(&q));
            id = dev.x.to_vec();
            m0.push(kv(0x17, &[], &dev.x));
            let mut v = compact(0);
            v.extend([1, 2, 3, 4, 0x80, 0, 0, 0]);
            m0.push(kv(0x16, &dev.x, &v));
        }
        Spend::TapScript => {
            let ik = key(5);
            let script = checksig_script_x(&dev.x);
            let sib_script = checksig_script_x(&k2.x);
            let l = tap_leaf(0xc0, &script);
            let sib = tap_leaf(0xc0, &sib_script);
            let root = tap_branch(&l, &sib);
            let (q, _) = tap_output(&ik.x, Some(&root));
            spk0 = p2tr(&xonly(&q));
            let mut control = vec![0xc0 | is_odd(&q) as u8];
            control.extend(ik.x);
            control.extend(sib);
            let mut val = script.clone();
            val.push(0xc0);
            m0.push(kv(0x15, &control, &val));
            m0.push(kv(0x17, &[], &ik.x));
            let mut v = compact(1);
            v.extend(l);
            v.extend([1, 2, 3, 4, 0x80, 0, 0, 0]);
            m0.push(kv(0x16, &dev.x, &v));
            id = dev.x.to_vec();
            id.extend(l);
            leaf = Some(l);
            internal = Some(ik);
            merkle = Some(root);
            code = script;
        }
    }
    let (fraw, fid) = fund_tx(&spk0, AMT0, 0x11);
    if wu_used {
        m0.push(kv(0x01, &[], &wu(AMT0, &spk0)));
    } else {
        nwu = Some(fraw.clone());
    }
    if let Some(n) = &nwu {
        m0.push(kv(0x00, &[], n));
    }
    if let Some(h) = ht {
        m0.push(kv(0x03, &[], &h.to_le_bytes()));
    }
    let spk1 = p2wpkh(&hash160(&other_in.pk));
    let (_, fid1) = fund_tx(&spk1, AMT1, 0x22);
    let m1: Map = vec![kv(0x01, &[], &wu(AMT1, &spk1)), kv(0x06, &other_in.pk, &[9, 9, 9, 9, 0x80, 0, 0, 0])];
    let t = T {
        ver: 2,
        lock: 0,
        ins: vec![
            TIn { txid: fid, vout: 0, seq: 0xffff_fffd },
            TIn { txid: fid1, vout: 0, seq: 0xffff_fffe },
        ],
        outs: vec![
            TOut { amount: 60_000, spk: p2wpkh(&hash160(&key(7).pk)) },
            TOut { amount: 70_000, spk: p2wpkh(&hash160(&key(8).pk)) },
        ],
    };
    let eff = match ht {
        Some(h) => h,
        None => {
            if ecdsa { 1 } else { 0 }
        }
    };
    let _ = ecdsa;
    Built {
        spec: Spec { version, t, glob: vec![], ins: vec![m0, m1], outs: vec![vec![], vec![]] },
        dev,
        spend,
        id,
        ht: eff,
        prevs: vec![(AMT0, spk0), (AMT1, spk1)],
        leaf,
        internal,
        merkle,
        code,
    }
}

pub fn checksig_script_x(x: &[u8]) -> Vec<u8> {
    let mut v = push(x);
    v.push(0xac);
    v
}

impl Built {
    /// The protocol message for the device pair, computed independently.
    pub fn msg(&self) -> [u8; 32] {
        let t = &self.spec.t;
        match self.spend {
            Spend::P2pkh | Spend::P2shLegacy => sh_legacy(t, 0, &self.code, self.ht),
            Spend::P2wpkh | Spend::P2shP2wpkh | Spend::P2wsh1 | Spend::P2wshMulti | Spend::P2shP2wsh => {
                sh_bip143(t, 0, &self.code, AMT0, self.ht)
            }
            Spend::TapKey => sh_taproot(t, 0, &self.prevs, self.ht, None),
            Spend::TapScript => sh_taproot(t, 0, &self.prevs, self.ht, self.leaf),
        }
    }
    pub fn is_ecdsa(&self) -> bool {
        !matches!(self.spend, Spend::TapKey | Spend::TapScript)
    }
    /// Protocol pk.
    pub fn pk(&self) -> Vec<u8> {
        match self.spend {
            Spend::TapKey => xonly(&tap_output(&self.dev.x, None).0).to_vec(),
            Spend::TapScript => self.dev.x.to_vec(),
            _ => self.dev.pk.to_vec(),
        }
    }
    pub fn sig_key(&self) -> Vec<u8> {
        match self.spend {
            Spend::TapKey => vec![0x13],
            Spend::TapScript => {
                let mut k = vec![0x14];
                k.extend(&self.id);
                k
            }
            _ => {
                let mut k = vec![0x02];
                k.extend(&self.dev.pk);
                k
            }
        }
    }
}

// ---- driving the protocol ----
pub fn with_field(spec: &Spec, input: usize, ty: u8, id: &[u8], val: &[u8]) -> Spec {
    let mut s = spec.clone();
    s.set(input, { let mut k = vec![ty]; k.extend(id); k }, val.to_vec());
    s
}

pub fn hc_of(ecdsa: bool, rho: &[u8; 32]) -> [u8; 32] {
    tagged(if ecdsa { "s2c/ecdsa/data" } else { "s2c/schnorr/data" }, &[rho])
}

pub fn rho_n(n: u8) -> [u8; 32] {
    sha256(&[b'r', b'h', b'o', n])
}

pub fn signer_opts(keys: &[&Key], decline: bool) -> aexf::signer::SignerOpts {
    aexf::signer::SignerOpts { secrets: keys.iter().map(|k| k.sk).collect(), decline }
}

pub fn req1(b: &Built, rho: &[u8; 32]) -> Spec {
    with_field(&b.spec, 0, 0x21, &b.id, &hc_of(b.is_ecdsa(), rho))
}
pub fn req2(b: &Built, rho: &[u8; 32]) -> Spec {
    with_field(&b.spec, 0, 0x23, &b.id, rho)
}

pub fn parse(raw: &[u8]) -> aexf::psbt::Psbt {
    aexf::psbt::Psbt::parse(raw).unwrap()
}

/// Full exchange against the in-process signer. Returns (R0, response 2 PSBT).
pub fn exchange(b: &Built, rho: &[u8; 32], opts: &aexf::signer::SignerOpts) -> Result<([u8; 33], aexf::psbt::Psbt), String> {
    let r1 = aexf::signer::handle_request(&req1(b, rho).psbt(), opts)?;
    let p1 = parse(&r1);
    let mut key22 = vec![0x22];
    key22.extend(&b.id);
    let r0v = aexf::psbt::map_get(&p1.inputs[0], &key22).ok_or("no nonce commitment")?.clone();
    let mut r0 = [0u8; 33];
    r0.copy_from_slice(&r0v);
    let r2 = aexf::signer::handle_request(&req2(b, rho).psbt(), opts)?;
    Ok((r0, parse(&r2)))
}

/// Independent check of a completed exchange: the signature is valid for the independently
/// computed message and carries the sign-to-contract relation to R0.
pub fn check_signature(b: &Built, rho: &[u8; 32], r0: &[u8; 33], resp: &aexf::psbt::Psbt) {
    let v = aexf::psbt::map_get(&resp.inputs[0], &b.sig_key()).expect("signature field present").clone();
    let m = b.msg();
    let tag = if b.is_ecdsa() { "s2c/ecdsa/point" } else { "s2c/schnorr/point" };
    let t = sc_from(&tagged(tag, &[r0, rho])).unwrap();
    let w = point(r0) + g_mul(&t);
    if b.is_ecdsa() {
        // minimal DER walk
        assert_eq!(v[0], 0x30);
        assert_eq!(v[1] as usize, v.len() - 3);
        assert_eq!(*v.last().unwrap() as u32, b.ht);
        let lr = v[3] as usize;
        let rb = &v[4..4 + lr];
        let ls = v[5 + lr] as usize;
        let sb = &v[6 + lr..6 + lr + ls];
        let strip = |x: &[u8]| -> [u8; 32] {
            let x = if x[0] == 0 { &x[1..] } else { x };
            let mut o = [0u8; 32];
            o[32 - x.len()..].copy_from_slice(x);
            o
        };
        let (rbytes, sbytes) = (strip(rb), strip(sb));
        let r = sc_from(&rbytes).unwrap();
        let s = sc_from(&sbytes).unwrap();
        assert!(ecdsa_verify(&b.dev.pk, &m, &r, &s), "ecdsa verify");
        // low s
        assert!(!(s + s == Scalar::ZERO) && sbytes <= HALF_N);
        assert_eq!(reduce(&xonly(&w)), r, "x(W) mod n == r");
        assert!(point(&b.dev.pk) == b.dev.p);
    } else {
        let want = if b.ht == 0 { 64 } else { 65 };
        assert_eq!(v.len(), want);
        if want == 65 {
            assert_eq!(v[64] as u32, b.ht);
        }
        assert!(schnorr_verify(&b.pk(), &m, &v[..64]), "schnorr verify");
        assert_eq!(&v[..32], &xonly(&w)[..], "r == x(W)");
    }
}

pub const HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E,
    0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

// ---- host process driver ----
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

pub struct HostOut {
    pub lines: Vec<String>,
    pub code: i32,
    pub requests: Vec<String>,
}

impl HostOut {
    pub fn last(&self) -> &str {
        self.lines.last().map(|s| s.as_str()).unwrap_or("")
    }
    pub fn count(&self) -> u64 {
        self.lines
            .iter()
            .find_map(|l| l.strip_prefix("COUNT ").map(|n| n.parse().unwrap()))
            .expect("COUNT line")
    }
}

pub struct HostArgs {
    pub psbt: String,
    pub devs: Vec<String>,
    pub store: String,
    pub retries: u32,
    pub rhos: Vec<(usize, Vec<u8>, [u8; 32])>,
    pub ack: bool,
}

pub fn store_path(name: &str) -> String {
    let d = format!("{}/tmp", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(&d).unwrap();
    let p = format!("{d}/{name}");
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}.tmp"));
    p
}

pub fn host_args(b: &Built, store: &str, rho: &[u8; 32]) -> HostArgs {
    HostArgs {
        psbt: b.spec.hex(),
        devs: vec![hex_encode(&b.dev.pk)],
        store: store.to_string(),
        retries: 0,
        rhos: vec![(0, b.id.clone(), *rho)],
        ack: false,
    }
}

/// Runs the host binary. `device(n, request_hex)` returns the line to send back, or None for end of input.
pub fn run_host(a: &HostArgs, device: &mut dyn FnMut(usize, &str) -> Option<String>) -> HostOut {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aexf"));
    cmd.arg("host");
    for d in &a.devs {
        cmd.arg("--device-key").arg(d);
    }
    cmd.arg("--store").arg(&a.store).arg("--max-retries").arg(a.retries.to_string()).arg("--psbt").arg(&a.psbt);
    for (i, id, r) in &a.rhos {
        cmd.arg("--rho").arg(format!("{}:{}:{}", i, hex_encode(id), hex_encode(r)));
    }
    if a.ack {
        cmd.arg("--ack-warning");
    }
    cmd.env("AEXF_TIMEOUT_SECS", "20");
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take();
    let out = BufReader::new(child.stdout.take().unwrap());
    let mut lines = Vec::new();
    let mut requests = Vec::new();
    for l in out.lines() {
        let l = l.unwrap();
        if let Some(h) = l.strip_prefix("REQUEST ") {
            let n = requests.len();
            requests.push(h.to_string());
            match device(n, h) {
                Some(resp) => {
                    if let Some(s) = stdin.as_mut() {
                        let _ = writeln!(s, "{resp}");
                        let _ = s.flush();
                    }
                }
                None => {
                    stdin = None;
                }
            }
        }
        lines.push(l);
    }
    let st = child.wait().unwrap();
    HostOut { lines, code: st.code().unwrap_or(-1), requests }
}

/// An honest device backed by the in-process signer.
pub fn honest(keys: Vec<Key>) -> impl FnMut(usize, &str) -> Option<String> {
    move |_, req| {
        let refs: Vec<&Key> = keys.iter().collect();
        let opts = signer_opts(&refs, false);
        match aexf::signer::handle_request(&hex_decode(req).unwrap(), &opts) {
            Ok(r) => Some(hex_encode(&r)),
            Err(_) => Some("ERROR".to_string()),
        }
    }
}
