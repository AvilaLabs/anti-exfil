//! Script parsing and the pattern checks the documents need.

use crate::ec::parse33;

#[derive(Clone, Debug)]
pub struct Op {
    pub code: u8,
    /// Pushed data for push opcodes.
    pub data: Option<Vec<u8>>,
    /// True for the single-byte-length push opcodes 0x01..=0x4b.
    pub direct: bool,
}

pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKSIGADD: u8 = 0xba;
pub const OP_CODESEPARATOR: u8 = 0xab;

pub fn parse_script(s: &[u8]) -> Result<Vec<Op>, String> {
    let mut ops = Vec::new();
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        i += 1;
        let (len, direct) = match c {
            0x01..=0x4b => (Some(c as usize), true),
            0x4c => {
                if i + 1 > s.len() {
                    return Err("truncated OP_PUSHDATA1".into());
                }
                let l = s[i] as usize;
                i += 1;
                (Some(l), false)
            }
            0x4d => {
                if i + 2 > s.len() {
                    return Err("truncated OP_PUSHDATA2".into());
                }
                let l = u16::from_le_bytes([s[i], s[i + 1]]) as usize;
                i += 2;
                (Some(l), false)
            }
            0x4e => {
                if i + 4 > s.len() {
                    return Err("truncated OP_PUSHDATA4".into());
                }
                let l = u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]) as usize;
                i += 4;
                (Some(l), false)
            }
            _ => (None, false),
        };
        match len {
            Some(l) => {
                if l > s.len() - i {
                    return Err("truncated push".into());
                }
                ops.push(Op { code: c, data: Some(s[i..i + l].to_vec()), direct });
                i += l;
            }
            None => ops.push(Op { code: c, data: None, direct: false }),
        }
    }
    Ok(ops)
}

pub fn has_codeseparator(ops: &[Op]) -> bool {
    ops.iter().any(|o| o.code == OP_CODESEPARATOR)
}

/// BIP 342 OP_SUCCESSx opcodes.
pub fn is_op_success(c: u8) -> bool {
    matches!(c, 80 | 98 | 126..=129 | 131..=134 | 137..=138 | 141..=142 | 149..=153 | 187..=254)
}

pub fn has_op_success(ops: &[Op]) -> bool {
    ops.iter().any(|o| is_op_success(o.code))
}

/// Number of signature opcodes (from `sigops`) immediately preceded by a direct push of `key`.
pub fn count_key_before_sigop(ops: &[Op], key: &[u8], sigops: &[u8]) -> usize {
    let mut n = 0;
    for i in 1..ops.len() {
        if sigops.contains(&ops[i].code) {
            let p = &ops[i - 1];
            if p.direct && p.data.as_deref() == Some(key) {
                n += 1;
            }
        }
    }
    n
}

/// `<key> OP_CHECKSIG` exactly, with a valid 33-byte key.
pub fn match_single_key(script: &[u8]) -> Option<[u8; 33]> {
    if script.len() == 35 && script[0] == 0x21 && script[34] == OP_CHECKSIG && parse33(&script[1..34]).is_some() {
        let mut k = [0u8; 33];
        k.copy_from_slice(&script[1..34]);
        Some(k)
    } else {
        None
    }
}

/// `OP_m <key>... OP_n OP_CHECKMULTISIG` exactly. Returns the keys in script order.
pub fn match_multisig(script: &[u8]) -> Option<Vec<[u8; 33]>> {
    if script.len() < 4 {
        return None;
    }
    let is_small = |c: u8| (0x51..=0x60).contains(&c);
    let m = script[0];
    let n = script[script.len() - 2];
    if !is_small(m) || !is_small(n) || script[script.len() - 1] != OP_CHECKMULTISIG {
        return None;
    }
    let m = (m - 0x50) as usize;
    let n = (n - 0x50) as usize;
    if m < 1 || m > n || n > 16 {
        return None;
    }
    let body = &script[1..script.len() - 2];
    if body.len() != 34 * n {
        return None;
    }
    let mut keys = Vec::new();
    for i in 0..n {
        let e = &body[34 * i..34 * (i + 1)];
        if e[0] != 0x21 || parse33(&e[1..]).is_none() {
            return None;
        }
        let mut k = [0u8; 33];
        k.copy_from_slice(&e[1..]);
        keys.push(k);
    }
    Some(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let ops = parse_script(&[0x51, 0x02, 0xab, 0xab, 0xab]).unwrap();
        assert_eq!(ops.len(), 3);
        // the 0xab bytes inside the push are not opcodes; the trailing one is
        assert!(has_codeseparator(&ops));
        let ops = parse_script(&[0x02, 0xab, 0xab]).unwrap();
        assert!(!has_codeseparator(&ops));
        assert!(parse_script(&[0x05, 1, 2]).is_err());
        assert!(parse_script(&[0x4c]).is_err());
        assert!(parse_script(&[0x4c, 0x01, 0xff]).is_ok());
    }

    #[test]
    fn op_success_set() {
        for c in [80u8, 98, 126, 129, 131, 134, 137, 138, 141, 142, 149, 153, 187, 254] {
            assert!(is_op_success(c), "{c}");
        }
        for c in [0u8, 81, 97, 99, 130, 135, 136, 139, 140, 143, 148, 154, 186, 255, 0xac, 0xba] {
            assert!(!is_op_success(c), "{c}");
        }
    }
}
