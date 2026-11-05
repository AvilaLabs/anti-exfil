//! PSBT (BIP 174 / 370) container: ordered key-value maps.

use crate::tx::{Tx, TxIn, TxOut};
use crate::util::{put_compact, Reader};

pub const MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

// global
pub const G_UNSIGNED_TX: u8 = 0x00;
pub const G_TX_VERSION: u8 = 0x02;
pub const G_FALLBACK_LOCKTIME: u8 = 0x03;
pub const G_INPUT_COUNT: u8 = 0x04;
pub const G_OUTPUT_COUNT: u8 = 0x05;
pub const G_TX_MODIFIABLE: u8 = 0x06;
pub const G_VERSION: u8 = 0xfb;
// input
pub const I_NON_WITNESS_UTXO: u8 = 0x00;
pub const I_WITNESS_UTXO: u8 = 0x01;
pub const I_PARTIAL_SIG: u8 = 0x02;
pub const I_SIGHASH_TYPE: u8 = 0x03;
pub const I_REDEEM_SCRIPT: u8 = 0x04;
pub const I_WITNESS_SCRIPT: u8 = 0x05;
pub const I_BIP32_DERIVATION: u8 = 0x06;
pub const I_FINAL_SCRIPTSIG: u8 = 0x07;
pub const I_FINAL_SCRIPTWITNESS: u8 = 0x08;
pub const I_PREVIOUS_TXID: u8 = 0x0e;
pub const I_OUTPUT_INDEX: u8 = 0x0f;
pub const I_SEQUENCE: u8 = 0x10;
pub const I_REQ_TIME_LOCKTIME: u8 = 0x11;
pub const I_REQ_HEIGHT_LOCKTIME: u8 = 0x12;
pub const I_TAP_KEY_SIG: u8 = 0x13;
pub const I_TAP_SCRIPT_SIG: u8 = 0x14;
pub const I_TAP_LEAF_SCRIPT: u8 = 0x15;
pub const I_TAP_BIP32_DERIVATION: u8 = 0x16;
pub const I_TAP_INTERNAL_KEY: u8 = 0x17;
pub const I_TAP_MERKLE_ROOT: u8 = 0x18;
pub const I_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x1a;
// anti-exfil input fields
pub const I_AE_HOST_COMMITMENT: u8 = 0x21;
pub const I_AE_NONCE_COMMITMENT: u8 = 0x22;
pub const I_AE_HOST_RANDOMNESS: u8 = 0x23;
// output
pub const O_AMOUNT: u8 = 0x03;
pub const O_SCRIPT: u8 = 0x04;

pub type Map = Vec<(Vec<u8>, Vec<u8>)>;

pub fn map_get<'a>(m: &'a Map, key: &[u8]) -> Option<&'a Vec<u8>> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub fn map_set(m: &mut Map, key: Vec<u8>, val: Vec<u8>) {
    if let Some(e) = m.iter_mut().find(|(k, _)| *k == key) {
        e.1 = val;
    } else {
        m.push((key, val));
    }
}

pub fn map_remove(m: &mut Map, key: &[u8]) {
    m.retain(|(k, _)| k != key);
}

/// Entries whose key type is the single byte `t` (keydata returned without the type byte).
pub fn entries_of_type(m: &Map, t: u8) -> Vec<(&[u8], &[u8])> {
    m.iter()
        .filter(|(k, _)| !k.is_empty() && k[0] == t)
        .map(|(k, v)| (&k[1..], v.as_slice()))
        .collect()
}

pub fn key_of(t: u8, data: &[u8]) -> Vec<u8> {
    let mut k = vec![t];
    k.extend_from_slice(data);
    k
}

#[derive(Clone, Debug)]
pub struct Psbt {
    pub version: u32,
    pub global: Map,
    pub inputs: Vec<Map>,
    pub outputs: Vec<Map>,
}

fn read_map(r: &mut Reader) -> Result<Map, String> {
    let mut m: Map = Vec::new();
    loop {
        let klen = r.compact()?;
        if klen == 0 {
            return Ok(m);
        }
        if klen > r.remaining() as u64 {
            return Err("truncated key".into());
        }
        let key = r.take(klen as usize)?.to_vec();
        let val = r.var_bytes()?.to_vec();
        if m.iter().any(|(k, _)| *k == key) {
            return Err("duplicate key in map".into());
        }
        m.push((key, val));
    }
}

fn write_map(out: &mut Vec<u8>, m: &Map) {
    for (k, v) in m {
        put_compact(out, k.len() as u64);
        out.extend_from_slice(k);
        put_compact(out, v.len() as u64);
        out.extend_from_slice(v);
    }
    out.push(0);
}

fn u32_field(v: &[u8], what: &str) -> Result<u32, String> {
    if v.len() != 4 {
        return Err(format!("{what} must be 4 bytes"));
    }
    Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

impl Psbt {
    pub fn parse(b: &[u8]) -> Result<Psbt, String> {
        if b.len() < 5 || b[..5] != MAGIC {
            return Err("bad PSBT magic".into());
        }
        let mut r = Reader::new(&b[5..]);
        let global = read_map(&mut r)?;
        let version = match map_get(&global, &[G_VERSION]) {
            Some(v) => u32_field(v, "PSBT_GLOBAL_VERSION")?,
            None => 0,
        };
        let (nin, nout) = match version {
            0 => {
                let raw = map_get(&global, &[G_UNSIGNED_TX]).ok_or("version 0 PSBT without unsigned transaction")?;
                let tx = Tx::parse(raw)?;
                (tx.inputs.len() as u64, tx.outputs.len() as u64)
            }
            2 => {
                let ci = map_get(&global, &[G_INPUT_COUNT]).ok_or("version 2 PSBT without input count")?;
                let co = map_get(&global, &[G_OUTPUT_COUNT]).ok_or("version 2 PSBT without output count")?;
                let mut a = Reader::new(ci);
                let nin = a.compact()?;
                if a.remaining() != 0 {
                    return Err("bad input count".into());
                }
                let mut c = Reader::new(co);
                let nout = c.compact()?;
                if c.remaining() != 0 {
                    return Err("bad output count".into());
                }
                (nin, nout)
            }
            v => return Err(format!("unsupported PSBT version {v}")),
        };
        if nin > r.remaining() as u64 || nout > r.remaining() as u64 {
            return Err("map counts exceed data".into());
        }
        let mut inputs = Vec::new();
        for _ in 0..nin {
            inputs.push(read_map(&mut r)?);
        }
        let mut outputs = Vec::new();
        for _ in 0..nout {
            outputs.push(read_map(&mut r)?);
        }
        if r.remaining() != 0 {
            return Err("trailing bytes after PSBT".into());
        }
        Ok(Psbt { version, global, inputs, outputs })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = MAGIC.to_vec();
        write_map(&mut o, &self.global);
        for m in &self.inputs {
            write_map(&mut o, m);
        }
        for m in &self.outputs {
            write_map(&mut o, m);
        }
        o
    }

    /// The core transaction: version, inputs (prevout and sequence), outputs, locktime.
    /// Script signatures of a version 0 unsigned transaction are cleared.
    pub fn core_tx(&self) -> Result<Tx, String> {
        match self.version {
            0 => {
                let raw = map_get(&self.global, &[G_UNSIGNED_TX]).ok_or("no unsigned transaction")?;
                let mut tx = Tx::parse(raw)?;
                if tx.inputs.len() != self.inputs.len() || tx.outputs.len() != self.outputs.len() {
                    return Err("map counts differ from the unsigned transaction".into());
                }
                for i in &mut tx.inputs {
                    i.script_sig.clear();
                }
                Ok(tx)
            }
            2 => {
                let version = u32_field(
                    map_get(&self.global, &[G_TX_VERSION]).ok_or("no PSBT_GLOBAL_TX_VERSION")?,
                    "PSBT_GLOBAL_TX_VERSION",
                )?;
                let fallback = match map_get(&self.global, &[G_FALLBACK_LOCKTIME]) {
                    Some(v) => Some(u32_field(v, "PSBT_GLOBAL_FALLBACK_LOCKTIME")?),
                    None => None,
                };
                let mut inputs = Vec::new();
                let mut times: Vec<Option<u32>> = Vec::new();
                let mut heights: Vec<Option<u32>> = Vec::new();
                for m in &self.inputs {
                    let t = map_get(m, &[I_PREVIOUS_TXID]).ok_or("input without previous txid")?;
                    if t.len() != 32 {
                        return Err("previous txid must be 32 bytes".into());
                    }
                    let mut txid = [0u8; 32];
                    txid.copy_from_slice(t);
                    let vout = u32_field(map_get(m, &[I_OUTPUT_INDEX]).ok_or("input without output index")?, "output index")?;
                    let sequence = match map_get(m, &[I_SEQUENCE]) {
                        Some(v) => u32_field(v, "sequence")?,
                        None => 0xffff_ffff,
                    };
                    times.push(match map_get(m, &[I_REQ_TIME_LOCKTIME]) {
                        Some(v) => Some(u32_field(v, "required time locktime")?),
                        None => None,
                    });
                    heights.push(match map_get(m, &[I_REQ_HEIGHT_LOCKTIME]) {
                        Some(v) => Some(u32_field(v, "required height locktime")?),
                        None => None,
                    });
                    inputs.push(TxIn { txid, vout, script_sig: Vec::new(), sequence });
                }
                if times.iter().flatten().any(|&t| t < 500_000_000) || heights.iter().flatten().any(|&h| h >= 500_000_000) {
                    return Err("required locktime out of range".into());
                }
                let constrained: Vec<usize> =
                    (0..inputs.len()).filter(|&i| times[i].is_some() || heights[i].is_some()).collect();
                let locktime = if constrained.is_empty() {
                    fallback.unwrap_or(0)
                } else if constrained.iter().all(|&i| heights[i].is_some()) {
                    constrained.iter().filter_map(|&i| heights[i]).max().unwrap()
                } else if constrained.iter().all(|&i| times[i].is_some()) {
                    constrained.iter().filter_map(|&i| times[i]).max().unwrap()
                } else {
                    return Err("inputs require conflicting locktime types".into());
                };
                let mut outputs = Vec::new();
                for m in &self.outputs {
                    let a = map_get(m, &[O_AMOUNT]).ok_or("output without amount")?;
                    if a.len() != 8 {
                        return Err("output amount must be 8 bytes".into());
                    }
                    let mut ab = [0u8; 8];
                    ab.copy_from_slice(a);
                    let script = map_get(m, &[O_SCRIPT]).ok_or("output without script")?.clone();
                    outputs.push(TxOut { amount: u64::from_le_bytes(ab), script });
                }
                Ok(Tx { version, inputs, outputs, locktime })
            }
            v => Err(format!("unsupported PSBT version {v}")),
        }
    }

    /// BIP 370 flag updates for one added signature with the given sighash type
    /// (SIGHASH_DEFAULT counts as SIGHASH_ALL). No effect on version 0.
    pub fn apply_modifiable_update(&mut self, sighash: u32) -> Result<(), String> {
        if self.version != 2 {
            return Ok(());
        }
        let mut flags = match map_get(&self.global, &[G_TX_MODIFIABLE]) {
            Some(v) if v.len() == 1 => v[0],
            Some(_) => return Err("PSBT_GLOBAL_TX_MODIFIABLE must be 1 byte".into()),
            None => 0,
        };
        let eff = if sighash == 0 { 1 } else { sighash };
        let base = eff & 0x03;
        if eff & 0x80 == 0 {
            flags &= !0x01; // inputs modifiable
        }
        if base != 2 {
            flags &= !0x02; // outputs modifiable
        }
        if base == 3 {
            flags |= 0x04; // has SIGHASH_SINGLE
        }
        let present = map_get(&self.global, &[G_TX_MODIFIABLE]).is_some();
        if present || flags != 0 {
            map_set(&mut self.global, vec![G_TX_MODIFIABLE], vec![flags]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_psbt() -> Psbt {
        let mut global: Map = vec![
            (vec![G_VERSION], 2u32.to_le_bytes().to_vec()),
            (vec![G_TX_VERSION], 2u32.to_le_bytes().to_vec()),
            (vec![G_INPUT_COUNT], vec![1]),
            (vec![G_OUTPUT_COUNT], vec![1]),
        ];
        global.push((vec![0xf0, 1], vec![5]));
        Psbt {
            version: 2,
            global,
            inputs: vec![vec![
                (vec![I_PREVIOUS_TXID], vec![7; 32]),
                (vec![I_OUTPUT_INDEX], 1u32.to_le_bytes().to_vec()),
            ]],
            outputs: vec![vec![(vec![O_AMOUNT], 5u64.to_le_bytes().to_vec()), (vec![O_SCRIPT], vec![0x6a])]],
        }
    }

    #[test]
    fn roundtrip_v2_and_core_tx() {
        let p = v2_psbt();
        let raw = p.serialize();
        let q = Psbt::parse(&raw).unwrap();
        assert_eq!(q.serialize(), raw);
        let t = q.core_tx().unwrap();
        assert_eq!(t.inputs[0].sequence, 0xffff_ffff);
        assert_eq!(t.inputs[0].vout, 1);
        assert_eq!(t.locktime, 0);
        assert_eq!(t.outputs[0].amount, 5);
    }

    #[test]
    fn malformed_containers_fail() {
        let raw = v2_psbt().serialize();
        assert!(Psbt::parse(&raw[..raw.len() - 1]).is_err());
        let mut extra = raw.clone();
        extra.push(0);
        assert!(Psbt::parse(&extra).is_err());
        assert!(Psbt::parse(b"psbt").is_err());
        assert!(Psbt::parse(b"pset\xff\x00").is_err());
        // duplicate key
        let mut p = v2_psbt();
        p.global.push((vec![G_TX_VERSION], vec![1, 0, 0, 0]));
        assert!(Psbt::parse(&p.serialize()).is_err());
        // unsupported version
        let mut p = v2_psbt();
        p.global[0].1 = 7u32.to_le_bytes().to_vec();
        assert!(Psbt::parse(&p.serialize()).is_err());
        // v2 missing counts
        let mut p = v2_psbt();
        p.global.retain(|(k, _)| k[0] != G_INPUT_COUNT);
        assert!(Psbt::parse(&p.serialize()).is_err());
    }

    #[test]
    fn modifiable_flag_updates() {
        let mut p = v2_psbt();
        p.apply_modifiable_update(1).unwrap();
        assert!(map_get(&p.global, &[G_TX_MODIFIABLE]).is_none());
        p.apply_modifiable_update(3).unwrap();
        assert_eq!(map_get(&p.global, &[G_TX_MODIFIABLE]).unwrap(), &vec![4]);
        p.apply_modifiable_update(0x82).unwrap();
        assert_eq!(map_get(&p.global, &[G_TX_MODIFIABLE]).unwrap(), &vec![4]);
        let mut p = v2_psbt();
        map_set(&mut p.global, vec![G_TX_MODIFIABLE], vec![0xff]);
        p.apply_modifiable_update(0x82).unwrap();
        assert_eq!(map_get(&p.global, &[G_TX_MODIFIABLE]).unwrap(), &vec![0xff]);
        p.apply_modifiable_update(0x81).unwrap();
        assert_eq!(map_get(&p.global, &[G_TX_MODIFIABLE]).unwrap(), &vec![0xfd]);
        p.apply_modifiable_update(0).unwrap();
        assert_eq!(map_get(&p.global, &[G_TX_MODIFIABLE]).unwrap(), &vec![0xfc]);
        let mut p = v2_psbt();
        map_set(&mut p.global, vec![G_TX_MODIFIABLE], vec![1, 2]);
        assert!(p.apply_modifiable_update(1).is_err());
    }
}
