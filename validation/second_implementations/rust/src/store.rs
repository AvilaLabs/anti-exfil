//! The host's durable record: per device failure count, acknowledgement mark, open attempt state
//! and the host commitments already used (never `rho`).

use std::fs;
use std::io::Write;

use crate::util::{hex_decode, hex_encode, sha256};

const HEADER: &str = "AEXF-STORE 1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    None,
    /// An attempt is open and no failure has been counted for it.
    Open,
    /// An attempt is open and its failure has already been counted.
    OpenCounted,
}

#[derive(Clone, Debug)]
pub struct DevRec {
    pub id: String,
    pub count: u64,
    /// Failure count at the time the user last acknowledged a warning.
    pub acked: u64,
    pub state: State,
    /// Host commitments already sent to this device.
    pub used: Vec<String>,
}

pub struct Store {
    pub path: String,
    pub recs: Vec<DevRec>,
    /// The file existed but could not be read or parsed.
    pub unreadable: bool,
}

pub fn device_id(keys: &[[u8; 33]]) -> String {
    let mut ks: Vec<&[u8; 33]> = keys.iter().collect();
    ks.sort();
    ks.dedup();
    let mut b = Vec::new();
    for k in ks {
        b.extend_from_slice(k);
    }
    hex_encode(&sha256(&b))
}

fn parse(text: &str) -> Option<Vec<DevRec>> {
    let mut lines = text.lines();
    if lines.next()? != HEADER {
        return None;
    }
    let mut recs = Vec::new();
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let f: Vec<&str> = l.split(' ').collect();
        if f.len() != 6 || f[0] != "D" {
            return None;
        }
        if hex_decode(f[1]).map(|b| b.len()) != Some(32) {
            return None;
        }
        let state = match f[4] {
            "N" => State::None,
            "U" => State::Open,
            "C" => State::OpenCounted,
            _ => return None,
        };
        let used: Vec<String> = if f[5] == "-" { Vec::new() } else { f[5].split(',').map(|s| s.to_string()).collect() };
        if used.iter().any(|u| hex_decode(u).map(|b| b.len()) != Some(32)) {
            return None;
        }
        recs.push(DevRec { id: f[1].to_string(), count: f[2].parse().ok()?, acked: f[3].parse().ok()?, state, used });
    }
    Some(recs)
}

impl Store {
    pub fn load(path: &str) -> Store {
        match fs::read(path) {
            Ok(b) => match String::from_utf8(b).ok().and_then(|t| parse(&t)) {
                Some(recs) => Store { path: path.to_string(), recs, unreadable: false },
                None => Store { path: path.to_string(), recs: Vec::new(), unreadable: true },
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Store { path: path.to_string(), recs: Vec::new(), unreadable: false }
            }
            Err(_) => Store { path: path.to_string(), recs: Vec::new(), unreadable: true },
        }
    }

    /// The record for a device. If the records could not be read, a fresh record with a count of one.
    pub fn rec_index(&mut self, id: &str) -> usize {
        if let Some(i) = self.recs.iter().position(|r| r.id == id) {
            return i;
        }
        let count = if self.unreadable { 1 } else { 0 };
        self.recs.push(DevRec { id: id.to_string(), count, acked: 0, state: State::None, used: Vec::new() });
        self.recs.len() - 1
    }

    /// Atomic durable write: temporary file in the same directory, fsync, rename.
    pub fn save(&mut self) -> Result<(), String> {
        let mut text = String::from(HEADER);
        text.push('\n');
        for r in &self.recs {
            let st = match r.state {
                State::None => "N",
                State::Open => "U",
                State::OpenCounted => "C",
            };
            let used = if r.used.is_empty() { "-".to_string() } else { r.used.join(",") };
            text.push_str(&format!("D {} {} {} {} {}\n", r.id, r.count, r.acked, st, used));
        }
        let tmp = format!("{}.tmp", self.path);
        let res = (|| -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            if let Some(dir) = std::path::Path::new(&self.path).parent() {
                let d = if dir.as_os_str().is_empty() { std::path::Path::new(".") } else { dir };
                if let Ok(df) = fs::File::open(d) {
                    let _ = df.sync_all();
                }
            }
            Ok(())
        })();
        match res {
            Ok(()) => {
                self.unreadable = false;
                Ok(())
            }
            Err(e) => Err(format!("cannot write store: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let d = format!("{}/tmp", env!("CARGO_MANIFEST_DIR"));
        let _ = fs::create_dir_all(&d);
        let p = format!("{d}/{name}");
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn roundtrip_and_unreadable() {
        let p = tmp("store_rt");
        let mut s = Store::load(&p);
        assert!(!s.unreadable);
        let id = device_id(&[[2u8; 33]]);
        let i = s.rec_index(&id);
        assert_eq!(s.recs[i].count, 0);
        s.recs[i].count = 3;
        s.recs[i].state = State::OpenCounted;
        s.recs[i].used.push(hex_encode(&[7u8; 32]));
        s.save().unwrap();
        let mut s2 = Store::load(&p);
        let j = s2.rec_index(&id);
        assert_eq!(s2.recs[j].count, 3);
        assert_eq!(s2.recs[j].state, State::OpenCounted);
        assert_eq!(s2.recs[j].used.len(), 1);
        // garbage -> unreadable -> count one
        fs::write(&p, b"garbage").unwrap();
        let mut s3 = Store::load(&p);
        assert!(s3.unreadable);
        let k = s3.rec_index(&id);
        assert_eq!(s3.recs[k].count, 1);
    }

    #[test]
    fn device_id_order_independent() {
        assert_eq!(device_id(&[[2u8; 33], [3u8; 33]]), device_id(&[[3u8; 33], [2u8; 33]]));
    }
}
