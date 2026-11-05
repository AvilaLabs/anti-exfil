//! Bitcoin transaction parsing and serialization.

use crate::util::{put_compact, sha256d, Reader};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub amount: u64,
    pub script: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

pub fn parse_txout(r: &mut Reader) -> Result<TxOut, String> {
    let amount = r.u64le()?;
    let script = r.var_bytes()?.to_vec();
    Ok(TxOut { amount, script })
}

impl TxOut {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.amount.to_le_bytes());
        put_compact(out, self.script.len() as u64);
        out.extend_from_slice(&self.script);
    }
}

impl Tx {
    /// Parses a transaction in network serialization, with or without witness data.
    /// The whole slice must be consumed.
    pub fn parse(b: &[u8]) -> Result<Tx, String> {
        let mut r = Reader::new(b);
        let version = r.u32le()?;
        let mut segwit = false;
        if r.remaining() >= 2 && r.b[r.pos] == 0x00 && r.b[r.pos + 1] != 0x00 {
            if r.b[r.pos + 1] != 0x01 {
                return Err("bad segwit flag".into());
            }
            segwit = true;
            r.pos += 2;
        }
        let nin = r.compact()?;
        if nin > (r.remaining() / 41) as u64 {
            return Err("input count too large".into());
        }
        let mut inputs = Vec::new();
        for _ in 0..nin {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(r.take(32)?);
            let vout = r.u32le()?;
            let script_sig = r.var_bytes()?.to_vec();
            let sequence = r.u32le()?;
            inputs.push(TxIn { txid, vout, script_sig, sequence });
        }
        let nout = r.compact()?;
        if nout > (r.remaining() / 9) as u64 {
            return Err("output count too large".into());
        }
        let mut outputs = Vec::new();
        for _ in 0..nout {
            outputs.push(parse_txout(&mut r)?);
        }
        if segwit {
            let mut any = false;
            for _ in 0..inputs.len() {
                let n = r.compact()?;
                for _ in 0..n {
                    r.var_bytes()?;
                    any = true;
                }
                if n > 0 {
                    any = true;
                }
            }
            if !any {
                return Err("segwit marker with empty witnesses".into());
            }
        }
        let locktime = r.u32le()?;
        if r.remaining() != 0 {
            return Err("trailing bytes after transaction".into());
        }
        Ok(Tx { version, inputs, outputs, locktime })
    }

    /// Non-witness serialization.
    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.version.to_le_bytes());
        put_compact(&mut o, self.inputs.len() as u64);
        for i in &self.inputs {
            o.extend_from_slice(&i.txid);
            o.extend_from_slice(&i.vout.to_le_bytes());
            put_compact(&mut o, i.script_sig.len() as u64);
            o.extend_from_slice(&i.script_sig);
            o.extend_from_slice(&i.sequence.to_le_bytes());
        }
        put_compact(&mut o, self.outputs.len() as u64);
        for t in &self.outputs {
            t.serialize(&mut o);
        }
        o.extend_from_slice(&self.locktime.to_le_bytes());
        o
    }

    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }

    /// The transaction with scriptSigs cleared: version, prevouts, sequences, outputs, locktime.
    pub fn core_bytes(&self) -> Vec<u8> {
        let mut t = self.clone();
        for i in &mut t.inputs {
            i.script_sig.clear();
        }
        t.serialize()
    }
}
