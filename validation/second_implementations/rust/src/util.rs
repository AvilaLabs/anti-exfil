//! Hex, hashes, compact size.

use sha2::{Digest, Sha256};

pub fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    for c in b.chunks(2) {
        out.push((nib(c[0])? << 4) | nib(c[1])?);
    }
    Some(out)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let th = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(th);
    h.update(th);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn rol(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    const R: [[usize; 16]; 5] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
        [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
        [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
        [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
    ];
    const RP: [[usize; 16]; 5] = [
        [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
        [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
        [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
        [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
        [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
    ];
    const S: [[u32; 16]; 5] = [
        [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
        [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
        [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
        [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
        [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
    ];
    const SP: [[u32; 16]; 5] = [
        [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
        [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
        [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
        [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
        [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
    ];
    const K: [u32; 5] = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
    const KP: [u32; 5] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0];
    fn f(round: usize, x: u32, y: u32, z: u32) -> u32 {
        match round {
            0 => x ^ y ^ z,
            1 => (x & y) | (!x & z),
            2 => (x | !y) ^ z,
            3 => (x & z) | (y & !z),
            _ => x ^ (y | !z),
        }
    }
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_le_bytes());
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for block in msg.chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        let (mut ap, mut bp, mut cp, mut dp, mut ep) = (h[0], h[1], h[2], h[3], h[4]);
        for rd in 0..5 {
            for j in 0..16 {
                let t = rol(
                    a.wrapping_add(f(rd, b, c, d)).wrapping_add(x[R[rd][j]]).wrapping_add(K[rd]),
                    S[rd][j],
                )
                .wrapping_add(e);
                a = e;
                e = d;
                d = rol(c, 10);
                c = b;
                b = t;
                let tp = rol(
                    ap.wrapping_add(f(4 - rd, bp, cp, dp)).wrapping_add(x[RP[rd][j]]).wrapping_add(KP[rd]),
                    SP[rd][j],
                )
                .wrapping_add(ep);
                ap = ep;
                ep = dp;
                dp = rol(cp, 10);
                cp = bp;
                bp = tp;
            }
        }
        let t = h[1].wrapping_add(c).wrapping_add(dp);
        h[1] = h[2].wrapping_add(d).wrapping_add(ep);
        h[2] = h[3].wrapping_add(e).wrapping_add(ap);
        h[3] = h[4].wrapping_add(a).wrapping_add(bp);
        h[4] = h[0].wrapping_add(b).wrapping_add(cp);
        h[0] = t;
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

pub fn put_compact(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Cursor over a byte slice.
pub struct Reader<'a> {
    pub b: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.remaining() < n {
            return Err("truncated data".into());
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    pub fn u32le(&mut self) -> Result<u32, String> {
        let t = self.take(4)?;
        Ok(u32::from_le_bytes([t[0], t[1], t[2], t[3]]))
    }
    pub fn u64le(&mut self) -> Result<u64, String> {
        let t = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(t);
        Ok(u64::from_le_bytes(a))
    }
    /// Compact size; non-canonical encodings fail.
    pub fn compact(&mut self) -> Result<u64, String> {
        let f = self.u8()?;
        let v = match f {
            0xfd => {
                let t = self.take(2)?;
                let v = u16::from_le_bytes([t[0], t[1]]) as u64;
                if v < 0xfd {
                    return Err("non-canonical compact size".into());
                }
                v
            }
            0xfe => {
                let v = self.u32le()? as u64;
                if v <= 0xffff {
                    return Err("non-canonical compact size".into());
                }
                v
            }
            0xff => {
                let v = self.u64le()?;
                if v <= 0xffff_ffff {
                    return Err("non-canonical compact size".into());
                }
                v
            }
            n => n as u64,
        };
        Ok(v)
    }
    /// Compact size length followed by that many bytes.
    pub fn var_bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.compact()?;
        if n > self.remaining() as u64 {
            return Err("truncated data".into());
        }
        self.take(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ripemd_vectors() {
        assert_eq!(hex_encode(&ripemd160(b"")), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        assert_eq!(hex_encode(&ripemd160(b"abc")), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        assert_eq!(
            hex_encode(&ripemd160(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
        );
    }

    #[test]
    fn hash160_of_known_key() {
        // hash160 of the generator point compressed key (well known: 751e76e8199196d454941c45d1b3a323f1433bd6)
        let g = hex_decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        assert_eq!(hex_encode(&hash160(&g)), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }

    #[test]
    fn hex_roundtrip_and_errors() {
        assert_eq!(hex_decode("00ffAb").unwrap(), vec![0, 255, 171]);
        assert!(hex_decode("0").is_none());
        assert!(hex_decode("zz").is_none());
        assert_eq!(hex_encode(&[1, 2, 255]), "0102ff");
    }

    #[test]
    fn compact_roundtrip() {
        for n in [0u64, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffff_ffff, 0x1_0000_0000] {
            let mut v = Vec::new();
            put_compact(&mut v, n);
            let mut r = Reader::new(&v);
            assert_eq!(r.compact().unwrap(), n);
            assert_eq!(r.remaining(), 0);
        }
        // non canonical
        let mut r = Reader::new(&[0xfd, 0x01, 0x00]);
        assert!(r.compact().is_err());
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            hex_encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
