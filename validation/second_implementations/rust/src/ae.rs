//! The anti-exfil protocol arithmetic (steps 1, 2, 4 and 5) for BIP340 and ECDSA,
//! plus DER and Taproot helpers.

use crate::ec::*;
use crate::util::{put_compact, sha256, tagged_hash};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    Schnorr,
    Ecdsa,
}

/// Step 1: hc = tagged_hash(".../data", rho).
pub fn host_commitment(s: Scheme, rho: &[u8; 32]) -> [u8; 32] {
    match s {
        Scheme::Schnorr => tagged_hash("s2c/schnorr/data", &[rho]),
        Scheme::Ecdsa => tagged_hash("s2c/ecdsa/data", &[rho]),
    }
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = a[i] ^ b[i];
    }
    o
}

struct Base {
    d: Sc,
    k0: Sc,
    r0_bytes: [u8; 33],
    pk: Vec<u8>,
}

/// Step 2 values: d, pk, k0, R0_bytes. `sk` is the (already tweaked, if applicable) secret.
fn base(s: Scheme, sk: &[u8; 32], m: &[u8], hc: &[u8; 32]) -> Result<Base, String> {
    let d_prime = scalar_checked(sk).ok_or("secret key out of range")?;
    if sc_is_zero(&d_prime) {
        return Err("secret key is zero".into());
    }
    match s {
        Scheme::Schnorr => {
            let p = mul_g(&d_prime);
            let d = if y_is_odd(&p) { -d_prime } else { d_prime };
            let pk = x_bytes(&p);
            let t0 = xor32(&sc_bytes(&d), &tagged_hash("BIP0340/aux", &[hc]));
            let k0 = scalar_reduce(&tagged_hash("s2c/schnorr/nonce", &[&t0, &pk, m, hc]));
            if sc_is_zero(&k0) {
                return Err("k0 is zero".into());
            }
            let r0_bytes = ser33(&mul_g(&k0)).ok_or("R0 at infinity")?;
            Ok(Base { d, k0, r0_bytes, pk: pk.to_vec() })
        }
        Scheme::Ecdsa => {
            if m.len() != 32 {
                return Err("ECDSA message must be 32 bytes".into());
            }
            let pk = ser33(&mul_g(&d_prime)).ok_or("public key at infinity")?;
            let d_mask = xor32(&sc_bytes(&d_prime), &tagged_hash("s2c/ecdsa/aux", &[hc]));
            let h = tagged_hash("s2c/ecdsa/nonce", &[&d_mask, &pk, m, hc]);
            let k0 = scalar_checked(&h).ok_or("k0 out of range")?;
            if sc_is_zero(&k0) {
                return Err("k0 is zero".into());
            }
            let r0_bytes = ser33(&mul_g(&k0)).ok_or("R0 at infinity")?;
            Ok(Base { d: d_prime, k0, r0_bytes, pk: pk.to_vec() })
        }
    }
}

/// Step 2: the device's nonce commitment for (sk, m, hc).
pub fn step2(s: Scheme, sk: &[u8; 32], m: &[u8], hc: &[u8; 32]) -> Result<[u8; 33], String> {
    Ok(base(s, sk, m, hc)?.r0_bytes)
}

/// Step 4: the device's signature for (sk, m, rho). hc is recomputed from rho.
/// The result is (sig64). Includes the SHOULD self-check of step 5.
pub fn step4(s: Scheme, sk: &[u8; 32], m: &[u8], rho: &[u8; 32]) -> Result<[u8; 64], String> {
    let hc = host_commitment(s, rho);
    let b = base(s, sk, m, &hc)?;
    let tag = match s {
        Scheme::Schnorr => "s2c/schnorr/point",
        Scheme::Ecdsa => "s2c/ecdsa/point",
    };
    let t = scalar_checked(&tagged_hash(tag, &[&b.r0_bytes, rho])).ok_or("t >= n")?;
    let kp = b.k0 + t;
    if sc_is_zero(&kp) {
        return Err("k' is zero".into());
    }
    let w = mul_g(&kp);
    let mut sig = [0u8; 64];
    match s {
        Scheme::Schnorr => {
            let k = if y_is_odd(&w) { -kp } else { kp };
            let r = x_bytes(&w);
            let e = scalar_reduce(&tagged_hash("BIP0340/challenge", &[&r, &b.pk, m]));
            let sv = k + e * b.d;
            sig[..32].copy_from_slice(&r);
            sig[32..].copy_from_slice(&sc_bytes(&sv));
            let mut pk32 = [0u8; 32];
            pk32.copy_from_slice(&b.pk);
            if !step5_schnorr(&pk32, m, rho, &b.r0_bytes, &sig) {
                return Err("self-check failed".into());
            }
        }
        Scheme::Ecdsa => {
            let z = scalar_reduce(m.try_into().map_err(|_| "message length")?);
            let r = scalar_reduce(&x_bytes(&w));
            if sc_is_zero(&r) {
                return Err("r is zero".into());
            }
            let kinv = sc_inv(&kp).ok_or("k' not invertible")?;
            let mut sv = kinv * (z + r * b.d);
            if sc_is_zero(&sv) {
                return Err("s is zero".into());
            }
            if sc_bytes(&sv) > HALF_N_BYTES {
                sv = -sv;
            }
            sig[..32].copy_from_slice(&sc_bytes(&r));
            sig[32..].copy_from_slice(&sc_bytes(&sv));
            let mut r32 = [0u8; 32];
            let mut s32 = [0u8; 32];
            r32.copy_from_slice(&sig[..32]);
            s32.copy_from_slice(&sig[32..]);
            if !step5_ecdsa(&b.pk, m, rho, &b.r0_bytes, &r32, &s32) {
                return Err("self-check failed".into());
            }
        }
    }
    Ok(sig)
}

/// Step 5 for BIP340 with the host's own pk (32 bytes), m, rho and the stored R0_bytes.
pub fn step5_schnorr(pk: &[u8; 32], m: &[u8], rho: &[u8; 32], r0_bytes: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let r0 = match parse33(r0_bytes) {
        Some(p) => p,
        None => return false,
    };
    let t = match scalar_checked(&tagged_hash("s2c/schnorr/point", &[r0_bytes, rho])) {
        Some(t) => t,
        None => return false,
    };
    let w = r0 + mul_g(&t);
    if is_inf(&w) || x_bytes(&w)[..] != sig[..32] {
        return false;
    }
    bip340_verify(pk, m, sig)
}

/// BIP340 verification.
pub fn bip340_verify(pk: &[u8; 32], m: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let p = match lift_x(pk) {
        Some(p) => p,
        None => return false,
    };
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&sig[32..]);
    let s = match scalar_checked(&sb) {
        Some(s) => s,
        None => return false,
    };
    let e = scalar_reduce(&tagged_hash("BIP0340/challenge", &[&sig[..32], pk, m]));
    let r = mul_g(&s) - p * e;
    if is_inf(&r) || y_is_odd(&r) {
        return false;
    }
    x_bytes(&r)[..] == sig[..32]
}

/// Step 5 for ECDSA. `pk` is the 33-byte key, `m` is 32 bytes, r and s are the halves of sig.
pub fn step5_ecdsa(pk: &[u8], m: &[u8], rho: &[u8; 32], r0_bytes: &[u8], r: &[u8; 32], s: &[u8; 32]) -> bool {
    let r0 = match parse33(r0_bytes) {
        Some(p) => p,
        None => return false,
    };
    let t = match scalar_checked(&tagged_hash("s2c/ecdsa/point", &[r0_bytes, rho])) {
        Some(t) => t,
        None => return false,
    };
    let w = r0 + mul_g(&t);
    if is_inf(&w) {
        return false;
    }
    let rs = match scalar_checked(r) {
        Some(x) if !sc_is_zero(&x) => x,
        _ => return false,
    };
    let ss = match scalar_checked(s) {
        Some(x) if !sc_is_zero(&x) => x,
        _ => return false,
    };
    if *s > HALF_N_BYTES {
        return false;
    }
    if scalar_reduce(&x_bytes(&w)) != rs {
        return false;
    }
    let p = match parse33(pk) {
        Some(p) => p,
        None => return false,
    };
    let m32: [u8; 32] = match m.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let z = scalar_reduce(&m32);
    let sinv = match sc_inv(&ss) {
        Some(x) => x,
        None => return false,
    };
    let v = mul_g(&(z * sinv)) + p * (rs * sinv);
    if is_inf(&v) || scalar_reduce(&x_bytes(&v)) != rs {
        return false;
    }
    v == w || v == -w
}

/// Minimal strict-DER (BIP 66) encoding of (r, s) followed by the sighash byte.
pub fn der_encode(r: &[u8; 32], s: &[u8; 32], sighash: u8) -> Vec<u8> {
    fn int(v: &[u8; 32]) -> Vec<u8> {
        let mut i = 0;
        while i < 31 && v[i] == 0 {
            i += 1;
        }
        let mut o = Vec::new();
        if v[i] & 0x80 != 0 {
            o.push(0);
        }
        o.extend_from_slice(&v[i..]);
        o
    }
    let (ri, si) = (int(r), int(s));
    let mut o = vec![0x30, (4 + ri.len() + si.len()) as u8, 0x02, ri.len() as u8];
    o.extend_from_slice(&ri);
    o.push(0x02);
    o.push(si.len() as u8);
    o.extend_from_slice(&si);
    o.push(sighash);
    o
}

/// BIP 66 strict DER parse of `DER || sighash byte`. Returns (r, s, sighash byte).
pub fn der_parse_strict(sig: &[u8]) -> Option<([u8; 32], [u8; 32], u8)> {
    if sig.len() < 9 || sig.len() > 73 {
        return None;
    }
    let ht = sig[sig.len() - 1];
    let d = &sig[..sig.len() - 1];
    if d[0] != 0x30 || d[1] as usize != d.len() - 2 || d[2] != 0x02 {
        return None;
    }
    let lr = d[3] as usize;
    if lr == 0 || 5 + lr >= d.len() || d[4 + lr] != 0x02 {
        return None;
    }
    let ls = d[5 + lr] as usize;
    if ls == 0 || 6 + lr + ls != d.len() {
        return None;
    }
    let rb = &d[4..4 + lr];
    let sb = &d[6 + lr..];
    fn conv(b: &[u8]) -> Option<[u8; 32]> {
        if b[0] & 0x80 != 0 {
            return None;
        }
        if b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
            return None;
        }
        let b = if b[0] == 0 && b.len() > 1 { &b[1..] } else { b };
        if b.len() > 32 {
            return None;
        }
        let mut o = [0u8; 32];
        o[32 - b.len()..].copy_from_slice(b);
        Some(o)
    }
    Some((conv(rb)?, conv(sb)?, ht))
}

// ---- Taproot helpers ----

pub fn tap_leaf_hash(version: u8, script: &[u8]) -> [u8; 32] {
    let mut l = vec![version];
    put_compact(&mut l, script.len() as u64);
    l.extend_from_slice(script);
    tagged_hash("TapLeaf", &[&l])
}

pub fn tap_branch(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a <= b {
        tagged_hash("TapBranch", &[a, b])
    } else {
        tagged_hash("TapBranch", &[b, a])
    }
}

/// Output key Q = lift_x(internal) + t*G with t = TapTweak(internal || root).
/// Returns (Q, t). None if the internal key is invalid, t >= n or Q is at infinity.
pub fn tap_tweak(internal_x: &[u8], root: Option<&[u8]>) -> Option<(Pt, Sc)> {
    let p = lift_x(internal_x)?;
    let h = match root {
        Some(r) => tagged_hash("TapTweak", &[internal_x, r]),
        None => tagged_hash("TapTweak", &[internal_x]),
    };
    let t = scalar_checked(&h)?;
    let q = p + mul_g(&t);
    if is_inf(&q) {
        return None;
    }
    Some((q, t))
}

/// Secret key for the output key: BIP 341 normalization then tweak.
pub fn tweak_secret(sk: &Sc, t: &Sc) -> Sc {
    let p = mul_g(sk);
    let d = if y_is_odd(&p) { -*sk } else { *sk };
    d + *t
}

/// Walks a control block from `leaf` and returns (output key x, parity bit as in the block).
/// None if the control block is malformed or has more than 128 path elements.
pub fn control_block_output(control: &[u8], leaf: &[u8; 32]) -> Option<([u8; 32], bool, [u8; 32])> {
    if control.len() < 33 || (control.len() - 33) % 32 != 0 || (control.len() - 33) / 32 > 128 {
        return None;
    }
    let mut node = *leaf;
    for chunk in control[33..].chunks(32) {
        let mut c = [0u8; 32];
        c.copy_from_slice(chunk);
        node = tap_branch(&node, &c);
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(&control[1..33]);
    let (q, _) = tap_tweak(&ik, Some(&node))?;
    Some((x_bytes(&q), y_is_odd(&q), ik))
}

#[allow(dead_code)]
pub fn sha256_of(b: &[u8]) -> [u8; 32] {
    sha256(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    #[test]
    fn bip340_vector_zero() {
        // BIP340 official test vector 0.
        let pk = hex_decode("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9").unwrap();
        let m = [0u8; 32];
        let sig = hex_decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0").unwrap();
        let mut p = [0u8; 32];
        p.copy_from_slice(&pk);
        assert!(bip340_verify(&p, &m, &sig));
        let mut bad = sig.clone();
        bad[63] ^= 1;
        assert!(!bip340_verify(&p, &m, &bad));
    }

    fn rho(n: u8) -> [u8; 32] {
        crate::util::sha256(&[n])
    }

    #[test]
    fn protocol_roundtrip_and_tampering() {
        let sk = crate::util::sha256(b"unit key");
        for s in [Scheme::Schnorr, Scheme::Ecdsa] {
            let m = crate::util::sha256(b"message");
            for n in 0..12u8 {
                let r = rho(n);
                let hc = host_commitment(s, &r);
                let r0 = step2(s, &sk, &m, &hc).unwrap();
                let sig = step4(s, &sk, &m, &r).unwrap();
                let sc = scalar_checked(&sk).unwrap();
                let p = mul_g(&sc);
                let ok = match s {
                    Scheme::Schnorr => {
                        let pk = x_bytes(&p);
                        let good = step5_schnorr(&pk, &m, &r, &r0, &sig);
                        // tampering
                        let mut bad_sig = sig;
                        bad_sig[40] ^= 1;
                        let mut bad_r0 = r0;
                        bad_r0[3] ^= 1;
                        let mut other_m = m;
                        other_m[0] ^= 1;
                        good && !step5_schnorr(&pk, &m, &r, &r0, &bad_sig)
                            && !step5_schnorr(&pk, &m, &r, &bad_r0, &sig)
                            && !step5_schnorr(&pk, &other_m, &r, &r0, &sig)
                            && !step5_schnorr(&pk, &m, &rho(n + 100), &r0, &sig)
                            && !step5_schnorr(&pk, &m, &r, &r0, &sig[..63])
                    }
                    Scheme::Ecdsa => {
                        let pk = ser33(&p).unwrap();
                        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
                        a.copy_from_slice(&sig[..32]);
                        b.copy_from_slice(&sig[32..]);
                        let good = step5_ecdsa(&pk, &m, &r, &r0, &a, &b);
                        let mut b2 = b;
                        b2[31] ^= 1;
                        let mut a2 = a;
                        a2[31] ^= 1;
                        // high-s form of the same signature is rejected
                        let hsb = sc_bytes(&-scalar_checked(&b).unwrap());
                        let mut other_m = m;
                        other_m[0] ^= 1;
                        good && !step5_ecdsa(&pk, &m, &r, &r0, &a, &b2)
                            && !step5_ecdsa(&pk, &m, &r, &r0, &a2, &b)
                            && !step5_ecdsa(&pk, &m, &r, &r0, &a, &hsb)
                            && !step5_ecdsa(&pk, &other_m, &r, &r0, &a, &b)
                            && !step5_ecdsa(&pk, &m, &rho(n + 100), &r0, &a, &b)
                            && !step5_ecdsa(&pk, &m, &r, &r0, &[0u8; 32], &b)
                            && !step5_ecdsa(&pk, &m, &r, &r0, &a, &[0u8; 32])
                    }
                };
                assert!(ok, "{s:?} {n}");
                // the signer is deterministic
                assert_eq!(sig, step4(s, &sk, &m, &r).unwrap());
            }
        }
    }

    #[test]
    fn bip340_long_and_empty_messages() {
        let sk = crate::util::sha256(b"unit key 2");
        for m in [vec![], vec![7u8; 1], vec![9u8; 1000]] {
            let r = rho(5);
            let hc = host_commitment(Scheme::Schnorr, &r);
            let r0 = step2(Scheme::Schnorr, &sk, &m, &hc).unwrap();
            let sig = step4(Scheme::Schnorr, &sk, &m, &r).unwrap();
            let pk = x_bytes(&mul_g(&scalar_checked(&sk).unwrap()));
            assert!(step5_schnorr(&pk, &m, &r, &r0, &sig));
        }
        // ECDSA requires a 32-byte message
        assert!(step2(Scheme::Ecdsa, &sk, &[1u8; 31], &[0u8; 32]).is_err());
        assert!(step2(Scheme::Ecdsa, &[0u8; 32], &[1u8; 32], &[0u8; 32]).is_err());
        assert!(step2(Scheme::Schnorr, &N_BYTES, &[1u8; 32], &[0u8; 32]).is_err());
    }

    #[test]
    fn der_roundtrip_and_strictness() {
        let mut r = [0u8; 32];
        r[31] = 5;
        let mut s = [0xffu8; 32];
        s[0] = 0x7f;
        let d = der_encode(&r, &s, 1);
        let (r2, s2, h) = der_parse_strict(&d).unwrap();
        assert_eq!((r2, s2, h), (r, s, 1));
        // high bit r needs a leading zero
        let mut rh = [0u8; 32];
        rh[0] = 0x80;
        let d = der_encode(&rh, &s, 1);
        assert_eq!(d[4], 0x00);
        assert!(der_parse_strict(&d).is_some());
        // non-minimal: extra leading zero
        let bad = [0x30, 0x08, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x07, 0x01];
        assert!(der_parse_strict(&bad).is_none());
        // negative r
        let bad = [0x30, 0x07, 0x02, 0x01, 0x85, 0x02, 0x01, 0x07, 0x01];
        assert!(der_parse_strict(&bad).is_none());
        // trailing garbage
        let mut ok = der_encode(&r, &s, 1);
        ok.insert(ok.len() - 1, 0);
        assert!(der_parse_strict(&ok).is_none());
    }
}
