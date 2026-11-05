//! Thin helpers over k256 for the byte conventions used in the documents.

use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

pub use k256::elliptic_curve::group::GroupEncoding;

pub type Pt = ProjectivePoint;
pub type Sc = Scalar;

/// Group order n, big endian.
pub const N_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC,
    0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// (n - 1) / 2, big endian.
pub const HALF_N_BYTES: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E,
    0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

pub fn be_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a >= b
}

/// int(b) < n required; None otherwise.
pub fn scalar_checked(b: &[u8; 32]) -> Option<Sc> {
    let fb = *FieldBytes::from_slice(b);
    Option::from(Sc::from_repr(fb))
}

/// int(b) mod n (b is 256 bits, so at most one subtraction is needed).
pub fn scalar_reduce(b: &[u8; 32]) -> Sc {
    let mut v = *b;
    if be_ge(&v, &N_BYTES) {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = v[i] as i16 - N_BYTES[i] as i16 - borrow;
            if d < 0 {
                d += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            v[i] = d as u8;
        }
    }
    scalar_checked(&v).expect("reduced value is below n")
}

pub fn sc_bytes(s: &Sc) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&s.to_repr());
    o
}

pub fn sc_is_zero(s: &Sc) -> bool {
    bool::from(s.is_zero())
}

pub fn sc_inv(s: &Sc) -> Option<Sc> {
    Option::from(s.invert())
}

pub fn mul_g(s: &Sc) -> Pt {
    ProjectivePoint::GENERATOR * *s
}

pub fn is_inf(p: &Pt) -> bool {
    bool::from(p.is_identity())
}

pub fn x_bytes(p: &Pt) -> [u8; 32] {
    let a: AffinePoint = p.to_affine();
    let mut o = [0u8; 32];
    o.copy_from_slice(&a.x());
    o
}

pub fn y_is_odd(p: &Pt) -> bool {
    bool::from(p.to_affine().y_is_odd())
}

/// ser33; None for the point at infinity.
pub fn ser33(p: &Pt) -> Option<[u8; 33]> {
    if is_inf(p) {
        return None;
    }
    let mut o = [0u8; 33];
    o[0] = if y_is_odd(p) { 3 } else { 2 };
    o[1..].copy_from_slice(&x_bytes(p));
    Some(o)
}

/// parse33 as defined in the protocol document.
pub fn parse33(b: &[u8]) -> Option<Pt> {
    if b.len() != 33 || (b[0] != 2 && b[0] != 3) {
        return None;
    }
    let arr = *k256::CompressedPoint::from_slice(b);
    let p: Option<Pt> = Option::from(<Pt as GroupEncoding>::from_bytes(&arr));
    let p = p?;
    if is_inf(&p) {
        return None;
    }
    Some(p)
}

/// Point with even y for the given x coordinate (BIP340 lift_x).
pub fn lift_x(x: &[u8]) -> Option<Pt> {
    if x.len() != 32 {
        return None;
    }
    let mut b = [0u8; 33];
    b[0] = 2;
    b[1..].copy_from_slice(x);
    parse33(&b)
}

pub fn uncompressed(p: &Pt) -> Option<[u8; 65]> {
    if is_inf(p) {
        return None;
    }
    let e = p.to_affine().to_encoded_point(false);
    let mut o = [0u8; 65];
    if e.as_bytes().len() != 65 {
        return None;
    }
    o.copy_from_slice(e.as_bytes());
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    #[test]
    fn constants_consistent() {
        // n - 1 is the largest valid scalar, n is not.
        let mut nm1 = N_BYTES;
        nm1[31] -= 1;
        assert!(scalar_checked(&nm1).is_some());
        assert!(scalar_checked(&N_BYTES).is_none());
        // half n: 2*half + 1 == n
        let h = scalar_checked(&HALF_N_BYTES).unwrap();
        assert_eq!(sc_bytes(&(h + h + Sc::ONE)), [0u8; 32]);
    }

    #[test]
    fn reduce_wraps() {
        let all = [0xffu8; 32];
        let r = scalar_reduce(&all);
        // 2^256 - 1 - n = 0x14551231950B75FC4402DA1732FC9BEBE
        let mut want = [0u8; 32];
        let t = hex_decode("014551231950b75fc4402da1732fc9bebe").unwrap();
        want[32 - t.len()..].copy_from_slice(&t);
        assert_eq!(sc_bytes(&r), want);
        assert_eq!(sc_bytes(&scalar_reduce(&N_BYTES)), [0u8; 32]);
    }

    #[test]
    fn parse33_rules() {
        let g = hex_decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let p = parse33(&g).unwrap();
        assert_eq!(ser33(&p).unwrap().to_vec(), g);
        let mut bad = g.clone();
        bad[0] = 4;
        assert!(parse33(&bad).is_none());
        bad[0] = 0;
        assert!(parse33(&bad).is_none());
        assert!(parse33(&g[..32]).is_none());
        // x = p (not below p)
        let mut xp = vec![2u8];
        xp.extend_from_slice(&hex_decode("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f").unwrap());
        assert!(parse33(&xp).is_none());
        // x = 5 is not on the curve (5^3+7=132 is a non-residue mod p)? try x=0.. find some off-curve
        let mut found_off = false;
        for x in 1u8..20 {
            let mut b = vec![2u8];
            b.extend_from_slice(&[0u8; 31]);
            b.push(x);
            if parse33(&b).is_none() {
                found_off = true;
            }
        }
        assert!(found_off);
    }
}
