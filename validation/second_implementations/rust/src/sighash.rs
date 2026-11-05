//! Signature hashes: legacy, BIP 143, BIP 341/342.

use crate::tx::{Tx, TxOut};
use crate::util::{put_compact, sha256, sha256d, tagged_hash};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prevout {
    pub amount: u64,
    pub spk: Vec<u8>,
}

fn outpoint(tx: &Tx, i: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&tx.inputs[i].txid);
    out.extend_from_slice(&tx.inputs[i].vout.to_le_bytes());
}

pub fn sighash_legacy(tx: &Tx, idx: usize, script_code: &[u8], ht: u32) -> Result<[u8; 32], String> {
    if idx >= tx.inputs.len() {
        return Err("input index out of range".into());
    }
    let acp = ht & 0x80 != 0;
    let base = ht & 3;
    if base == 3 && idx >= tx.outputs.len() {
        return Err("SIGHASH_SINGLE without a matching output".into());
    }
    let mut o = Vec::new();
    o.extend_from_slice(&tx.version.to_le_bytes());
    let list: Vec<usize> = if acp { vec![idx] } else { (0..tx.inputs.len()).collect() };
    put_compact(&mut o, list.len() as u64);
    for &j in &list {
        outpoint(tx, j, &mut o);
        if j == idx {
            put_compact(&mut o, script_code.len() as u64);
            o.extend_from_slice(script_code);
        } else {
            o.push(0);
        }
        let seq = if j != idx && (base == 2 || base == 3) { 0 } else { tx.inputs[j].sequence };
        o.extend_from_slice(&seq.to_le_bytes());
    }
    match base {
        2 => o.push(0),
        3 => {
            put_compact(&mut o, (idx + 1) as u64);
            for j in 0..=idx {
                if j < idx {
                    o.extend_from_slice(&u64::MAX.to_le_bytes());
                    o.push(0);
                } else {
                    tx.outputs[j].serialize(&mut o);
                }
            }
        }
        _ => {
            put_compact(&mut o, tx.outputs.len() as u64);
            for t in &tx.outputs {
                t.serialize(&mut o);
            }
        }
    }
    o.extend_from_slice(&tx.locktime.to_le_bytes());
    o.extend_from_slice(&ht.to_le_bytes());
    Ok(sha256d(&o))
}

pub fn sighash_bip143(tx: &Tx, idx: usize, script_code: &[u8], amount: u64, ht: u32) -> Result<[u8; 32], String> {
    if idx >= tx.inputs.len() {
        return Err("input index out of range".into());
    }
    let acp = ht & 0x80 != 0;
    let base = ht & 3;
    if base == 3 && idx >= tx.outputs.len() {
        return Err("SIGHASH_SINGLE without a matching output".into());
    }
    let mut o = Vec::new();
    o.extend_from_slice(&tx.version.to_le_bytes());
    if acp {
        o.extend_from_slice(&[0u8; 32]);
    } else {
        let mut b = Vec::new();
        for j in 0..tx.inputs.len() {
            outpoint(tx, j, &mut b);
        }
        o.extend_from_slice(&sha256d(&b));
    }
    if acp || base == 2 || base == 3 {
        o.extend_from_slice(&[0u8; 32]);
    } else {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.sequence.to_le_bytes());
        }
        o.extend_from_slice(&sha256d(&b));
    }
    outpoint(tx, idx, &mut o);
    put_compact(&mut o, script_code.len() as u64);
    o.extend_from_slice(script_code);
    o.extend_from_slice(&amount.to_le_bytes());
    o.extend_from_slice(&tx.inputs[idx].sequence.to_le_bytes());
    match base {
        2 => o.extend_from_slice(&[0u8; 32]),
        3 => {
            let mut b = Vec::new();
            tx.outputs[idx].serialize(&mut b);
            o.extend_from_slice(&sha256d(&b));
        }
        _ => {
            let mut b = Vec::new();
            for t in &tx.outputs {
                t.serialize(&mut b);
            }
            o.extend_from_slice(&sha256d(&b));
        }
    }
    o.extend_from_slice(&tx.locktime.to_le_bytes());
    o.extend_from_slice(&ht.to_le_bytes());
    Ok(sha256d(&o))
}

/// BIP 341 key path (`leaf` None) or BIP 342 script path (`leaf` Some(leaf hash)), no annex.
/// `prevouts[j]` must be Some for every input unless ANYONECANPAY, where only `idx` is needed.
pub fn sighash_taproot(
    tx: &Tx,
    idx: usize,
    prevouts: &[Option<Prevout>],
    ht: u32,
    leaf: Option<&[u8; 32]>,
) -> Result<[u8; 32], String> {
    if idx >= tx.inputs.len() || prevouts.len() != tx.inputs.len() {
        return Err("input index out of range".into());
    }
    let acp = ht & 0x80 != 0;
    let out_type = ht & 3;
    if out_type == 3 && idx >= tx.outputs.len() {
        return Err("SIGHASH_SINGLE without a matching output".into());
    }
    let mut m = vec![0x00u8, ht as u8];
    m.extend_from_slice(&tx.version.to_le_bytes());
    m.extend_from_slice(&tx.locktime.to_le_bytes());
    if !acp {
        let mut pv = Vec::new();
        let mut am = Vec::new();
        let mut sp = Vec::new();
        let mut sq = Vec::new();
        for j in 0..tx.inputs.len() {
            outpoint(tx, j, &mut pv);
            let p = prevouts[j].as_ref().ok_or("missing previous output for a Taproot signature hash")?;
            am.extend_from_slice(&p.amount.to_le_bytes());
            put_compact(&mut sp, p.spk.len() as u64);
            sp.extend_from_slice(&p.spk);
            sq.extend_from_slice(&tx.inputs[j].sequence.to_le_bytes());
        }
        m.extend_from_slice(&sha256(&pv));
        m.extend_from_slice(&sha256(&am));
        m.extend_from_slice(&sha256(&sp));
        m.extend_from_slice(&sha256(&sq));
    }
    if out_type != 2 && out_type != 3 {
        let mut b = Vec::new();
        for t in &tx.outputs {
            t.serialize(&mut b);
        }
        m.extend_from_slice(&sha256(&b));
    }
    let ext_flag: u8 = if leaf.is_some() { 1 } else { 0 };
    m.push(ext_flag * 2);
    if acp {
        outpoint(tx, idx, &mut m);
        let p = prevouts[idx].as_ref().ok_or("missing previous output for a Taproot signature hash")?;
        m.extend_from_slice(&p.amount.to_le_bytes());
        put_compact(&mut m, p.spk.len() as u64);
        m.extend_from_slice(&p.spk);
        m.extend_from_slice(&tx.inputs[idx].sequence.to_le_bytes());
    } else {
        m.extend_from_slice(&(idx as u32).to_le_bytes());
    }
    if out_type == 3 {
        let mut b = Vec::new();
        let t: &TxOut = &tx.outputs[idx];
        t.serialize(&mut b);
        m.extend_from_slice(&sha256(&b));
    }
    if let Some(l) = leaf {
        m.extend_from_slice(l);
        m.push(0x00);
        m.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    }
    Ok(tagged_hash("TapSighash", &[&m]))
}
