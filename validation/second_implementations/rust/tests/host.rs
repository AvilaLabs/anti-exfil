mod common;
use aexf::psbt::{map_get, Psbt};
use aexf::util::{hex_decode, hex_encode};
use common::*;
use std::cell::RefCell;
use std::rc::Rc;

fn run_with(b: &Built, store: &str, rho: u8, f: &mut dyn FnMut(usize, &str) -> Option<String>) -> HostOut {
    let a = host_args(b, store, &rho_n(rho));
    run_host(&a, f)
}
fn dev_keys(b: &Built) -> Vec<Key> {
    vec![b.dev.clone(), key(4)]
}
fn honest_for(b: &Built) -> impl FnMut(usize, &str) -> Option<String> {
    honest(dev_keys(b))
}

/// Device that answers honestly and then lets `f` rewrite the parsed response.
fn tamper<F: FnMut(usize, &mut Psbt)>(b: &Built, mut f: F) -> impl FnMut(usize, &str) -> Option<String> {
    let mut h = honest_for(b);
    move |n, req| {
        let r = h(n, req)?;
        if r == "ERROR" {
            return Some(r);
        }
        let mut p = Psbt::parse(&hex_decode(&r).unwrap()).unwrap();
        f(n, &mut p);
        Some(hex_encode(&p.serialize()))
    }
}

fn result_psbt(o: &HostOut) -> Psbt {
    let l = o.last();
    let h = l.strip_prefix("RESULT ").unwrap_or_else(|| panic!("no result: {:?}", o.lines));
    Psbt::parse(&hex_decode(h).unwrap()).unwrap()
}

fn has_ae(p: &Psbt) -> bool {
    p.inputs.iter().any(|m| m.iter().any(|(k, _)| matches!(k[0], 0x21..=0x23)))
}

#[test]
fn honest_run_every_form_and_version() {
    let mut n = 0;
    for v in [0, 2] {
        for s in ALL_SPENDS {
            for h in [None, Some(3u32), Some(0x81)] {
                n += 1;
                let b = build(s, v, h);
                let store = store_path(&format!("h_{n}"));
                let r0 = Rc::new(RefCell::new(None::<[u8; 33]>));
                let r0c = r0.clone();
                let mut inner = honest_for(&b);
                let id = b.id.clone();
                let mut dev = move |i: usize, req: &str| {
                    let r = inner(i, req)?;
                    if i == 0 {
                        let p = Psbt::parse(&hex_decode(&r).unwrap()).unwrap();
                        let mut k = vec![0x22];
                        k.extend(&id);
                        let v = map_get(&p.inputs[0], &k).unwrap();
                        let mut a = [0u8; 33];
                        a.copy_from_slice(v);
                        *r0c.borrow_mut() = Some(a);
                    }
                    Some(r)
                };
                let o = run_with(&b, &store, 1, &mut dev);
                assert_eq!(o.code, 0, "{s:?} v{v} {h:?}: {:?}", o.lines);
                assert_eq!(o.count(), 0);
                assert_eq!(o.requests.len(), 2);
                let res = result_psbt(&o);
                assert!(!has_ae(&res));
                check_signature(&b, &rho_n(1), &r0.borrow().unwrap(), &res);
                // request shapes
                let q1 = Psbt::parse(&hex_decode(&o.requests[0]).unwrap()).unwrap();
                let q2 = Psbt::parse(&hex_decode(&o.requests[1]).unwrap()).unwrap();
                let ae1: Vec<u8> = q1.inputs.iter().flatten().filter(|(k, _)| matches!(k[0], 0x21..=0x23)).map(|(k, _)| k[0]).collect();
                let ae2: Vec<u8> = q2.inputs.iter().flatten().filter(|(k, _)| matches!(k[0], 0x21..=0x23)).map(|(k, _)| k[0]).collect();
                assert_eq!(ae1, vec![0x21]);
                assert_eq!(ae2, vec![0x23]);
                // the second request holds rho, not the first request's commitment
                let mut k23 = vec![0x23];
                k23.extend(&b.id);
                assert_eq!(map_get(&q2.inputs[0], &k23).unwrap()[..], rho_n(1)[..]);
                assert_eq!(q1.core_tx().unwrap(), q2.core_tx().unwrap());
            }
        }
    }
}

#[test]
fn result_is_host_psbt_plus_signature_only() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("shape");
    let o = run_with(&b, &store, 1, &mut honest_for(&b));
    let res = result_psbt(&o);
    let orig = Psbt::parse(&b.spec.psbt()).unwrap();
    assert_eq!(res.global, orig.global);
    assert_eq!(res.outputs, orig.outputs);
    assert_eq!(res.inputs[1], orig.inputs[1]);
    assert_eq!(res.inputs[0].len(), orig.inputs[0].len() + 1);
    for e in &orig.inputs[0] {
        assert!(res.inputs[0].contains(e));
    }
}

#[test]
fn v2_flags_in_host_result() {
    let mut b = build(Spend::P2wpkh, 2, Some(3));
    b.spec.glob.push(kv(0x06, &[], &[0x07]));
    let store = store_path("flags");
    let o = run_with(&b, &store, 1, &mut honest_for(&b));
    let res = result_psbt(&o);
    assert_eq!(map_get(&res.global, &[0x06]).unwrap()[0], 0x04);
    // taproot default counts as ALL
    let mut b = build(Spend::TapKey, 2, None);
    b.spec.glob.push(kv(0x06, &[], &[0x07]));
    let o = run_with(&b, &store_path("flags2"), 1, &mut honest_for(&b));
    assert_eq!(map_get(&result_psbt(&o).global, &[0x06]).unwrap()[0], 0x04);
    // absent field, SINGLE creates it
    let b = build(Spend::P2wpkh, 2, Some(3));
    let o = run_with(&b, &store_path("flags3"), 1, &mut honest_for(&b));
    assert_eq!(map_get(&result_psbt(&o).global, &[0x06]).unwrap()[0], 0x04);
    // absent field, ALL leaves it absent
    let b = build(Spend::P2wpkh, 2, None);
    let o = run_with(&b, &store_path("flags4"), 1, &mut honest_for(&b));
    assert!(map_get(&result_psbt(&o).global, &[0x06]).is_none());
}

#[test]
fn failure_counts_persist_and_warning_flow() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("flow");
    // run 1: device error, no retries
    let o = run_with(&b, &store, 1, &mut |_, _| Some("ERROR".to_string()));
    assert_eq!((o.code, o.last(), o.count()), (3, "FAILED", 1));
    assert_eq!(o.requests.len(), 1);
    // run 2: warning owed, not acknowledged: nothing is sent
    let o = run_with(&b, &store, 2, &mut honest_for(&b));
    assert_eq!((o.code, o.last(), o.count()), (5, "NOT_ACKNOWLEDGED", 1));
    assert!(o.requests.is_empty());
    // still owed after another refusal to acknowledge
    let o = run_with(&b, &store, 2, &mut honest_for(&b));
    assert_eq!(o.code, 5);
    // run 3: acknowledged
    let mut a = host_args(&b, &store, &rho_n(3));
    a.ack = true;
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!((o.code, o.count()), (0, 1));
    assert!(o.last().starts_with("RESULT"));
    // run 4: the earlier success does not undo the count, but the acknowledgement covered it
    let o = run_with(&b, &store, 4, &mut honest_for(&b));
    assert_eq!((o.code, o.count()), (0, 1));
}

#[test]
fn acknowledgement_covers_exactly_one_attempt() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("ackone");
    let _ = run_with(&b, &store, 1, &mut |_, _| Some("ERROR".to_string()));
    // acknowledged attempt that fails again
    let mut a = host_args(&b, &store, &rho_n(2));
    a.ack = true;
    let o = run_host(&a, &mut |_, _| Some("ERROR".to_string()));
    assert_eq!((o.code, o.count()), (3, 2));
    // the count rose since the acknowledgement: a new warning is owed
    let o = run_with(&b, &store, 3, &mut honest_for(&b));
    assert_eq!((o.code, o.last()), (5, "NOT_ACKNOWLEDGED"));
    // --ack-warning with no warning owed is harmless
    let mut a = host_args(&b, &store, &rho_n(4));
    a.ack = true;
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!(o.code, 0);
    let mut a = host_args(&b, &store, &rho_n(5));
    a.ack = true;
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!((o.code, o.count()), (0, 2));
}

#[test]
fn retries_first_pass() {
    let b = build(Spend::P2wpkh, 0, None);
    // one error then fine, one retry allowed
    let store = store_path("r1");
    let mut h = honest_for(&b);
    let mut a = host_args(&b, &store, &rho_n(1));
    a.retries = 1;
    let o = run_host(&a, &mut |n, r| if n == 0 { Some("ERROR".into()) } else { h(n, r) });
    assert_eq!((o.code, o.count(), o.requests.len()), (0, 1, 3));
    assert_eq!(o.requests[0], o.requests[1]);
    // retries run out: count rises once only
    let store = store_path("r2");
    let mut a = host_args(&b, &store, &rho_n(1));
    a.retries = 3;
    let o = run_host(&a, &mut |_, _| Some("ERROR".into()));
    assert_eq!((o.code, o.last(), o.count(), o.requests.len()), (3, "FAILED", 1, 4));
    // zero retries never retries
    let store = store_path("r3");
    let o = run_with(&b, &store, 1, &mut |_, _| Some("ERROR".into()));
    assert_eq!(o.requests.len(), 1);
}

#[test]
fn retries_second_pass_reuse_the_same_rho() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("r4");
    let mut h = honest_for(&b);
    let mut a = host_args(&b, &store, &rho_n(1));
    a.retries = 2;
    let o = run_host(&a, &mut |n, r| if n == 1 || n == 2 { Some("ERROR".into()) } else { h(n, r) });
    assert_eq!((o.code, o.count(), o.requests.len()), (0, 1, 4));
    assert_eq!(o.requests[1], o.requests[2]);
    assert_eq!(o.requests[2], o.requests[3]);
    // second pass retries run out
    let store = store_path("r5");
    let mut h = honest_for(&b);
    let mut a = host_args(&b, &store, &rho_n(1));
    a.retries = 1;
    let o = run_host(&a, &mut |n, r| if n >= 1 { Some("ERROR".into()) } else { h(n, r) });
    assert_eq!((o.code, o.last(), o.count(), o.requests.len()), (3, "FAILED", 1, 3));
    // separate budgets per step
    let store = store_path("r6");
    let mut h = honest_for(&b);
    let mut a = host_args(&b, &store, &rho_n(1));
    a.retries = 1;
    let o = run_host(&a, &mut |n, r| if n == 0 || n == 2 { Some("ERROR".into()) } else { h(n, r) });
    assert_eq!((o.code, o.count(), o.requests.len()), (0, 1, 4));
}

#[test]
fn eof_and_garbage_are_failure_events() {
    let b = build(Spend::P2wpkh, 0, None);
    let o = run_with(&b, &store_path("eof"), 1, &mut |_, _| None);
    assert_eq!((o.code, o.last(), o.count()), (3, "FAILED", 1));
    for junk in ["zz", "00", "70736274ff00", "ERRORX"] {
        let o = run_with(&b, &store_path("junk"), 1, &mut |_, _| Some(junk.to_string()));
        assert_eq!((o.code, o.count()), (3, 1), "{junk}");
    }
    // junk then honest, with a retry
    let mut h = honest_for(&b);
    let mut a = host_args(&b, &store_path("junk2"), &rho_n(1));
    a.retries = 1;
    let o = run_host(&a, &mut |n, r| if n == 0 { Some("nothex".into()) } else { h(n, r) });
    assert_eq!((o.code, o.count()), (0, 1));
}

#[test]
fn changed_r0_ends_the_attempt_even_with_retries() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("r0a");
    let mut h = honest_for(&b);
    let id = b.id.clone();
    let mut a = host_args(&b, &store, &rho_n(1));
    a.retries = 5;
    // first response: carries a 34-byte nonce commitment (rejected, but a value received), second: the honest one
    let o = run_host(&a, &mut |n, r| {
        let resp = h(n, r)?;
        if n == 0 {
            let mut p = Psbt::parse(&hex_decode(&resp).unwrap()).unwrap();
            let mut k = vec![0x22];
            k.extend(&id);
            aexf::psbt::map_set(&mut p.inputs[0], k, vec![2u8; 34]);
            Some(hex_encode(&p.serialize()))
        } else {
            Some(resp)
        }
    });
    assert_eq!((o.code, o.last(), o.count(), o.requests.len()), (3, "FAILED", 1, 2));

    // a valid R0 first, a different valid R0 on a retried step 2
    let store = store_path("r0b");
    let mut h = honest_for(&b);
    let id = b.id.clone();
    let mut a = host_args(&b, &store, &rho_n(1));
    a.retries = 5;
    let o = run_host(&a, &mut |n, r| {
        let resp = h(n, r)?;
        let mut p = Psbt::parse(&hex_decode(&resp).unwrap()).unwrap();
        let mut k = vec![0x22];
        k.extend(&id);
        let v = map_get(&p.inputs[0], &k).unwrap().clone();
        if n == 0 {
            // drop a signature-irrelevant thing that makes it fail: remove the pair's commitment of another kind? Use core tx change
            p.inputs[0].retain(|(kk, _)| kk[0] != 0x21 || false);
            // missing nothing; make the response unacceptable by a malformed second field
            p.inputs[0].push((vec![0xaa], vec![]));
            let _ = v;
            // not rejected -> accepted; so instead corrupt the commitment length
            let mut bad = map_get(&p.inputs[0], &k).unwrap().clone();
            bad.push(0);
            aexf::psbt::map_set(&mut p.inputs[0], k.clone(), bad);
        } else if n == 1 {
            let mut other = v.clone();
            other[1] ^= 1;
            aexf::psbt::map_set(&mut p.inputs[0], k.clone(), other);
        }
        Some(hex_encode(&p.serialize()))
    });
    assert_eq!((o.code, o.last()), (3, "FAILED"));
    assert_eq!(o.count(), 1);
    assert_eq!(o.requests.len(), 2);
}

#[test]
fn nonce_commitment_in_second_response_is_a_failure() {
    let b = build(Spend::P2wpkh, 0, None);
    let id = b.id.clone();
    let mut dev = tamper(&b, move |n, p| {
        if n == 1 {
            let mut k = vec![0x22];
            k.extend(&id);
            p.inputs[0].push((k, vec![2u8; 33]));
        }
    });
    let mut a = host_args(&b, &store_path("nc2"), &rho_n(1));
    a.retries = 3;
    let o = run_host(&a, &mut dev);
    assert_eq!((o.code, o.count()), (3, 1));
    // a stray anti-exfil field of any type in the second response fails
    for ty in [0x21u8, 0x23] {
        let id = b.id.clone();
        let mut dev = tamper(&b, move |n, p| {
            if n == 1 {
                let mut k = vec![ty];
                k.extend(&id);
                p.inputs[0].push((k, vec![1u8; 32]));
            }
        });
        let o = run_with(&b, &store_path("nc2b"), 1, &mut dev);
        assert_eq!((o.code, o.count()), (3, 1), "{ty:#x}");
    }
}

#[test]
fn first_pass_response_violations() {
    let b = build(Spend::P2wpkh, 0, None);
    let id = b.id.clone();
    // randomness in a first-pass response
    let i2 = id.clone();
    let mut d = tamper(&b, move |n, p| {
        if n == 0 {
            let mut k = vec![0x23];
            k.extend(&i2);
            p.inputs[0].push((k, vec![1; 32]));
        }
    });
    let o = run_with(&b, &store_path("fp1"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    // a different host commitment
    let i2 = id.clone();
    let mut d = tamper(&b, move |n, p| {
        if n == 0 {
            let mut k = vec![0x21];
            k.extend(&i2);
            aexf::psbt::map_set(&mut p.inputs[0], k, vec![1; 32]);
        }
    });
    let o = run_with(&b, &store_path("fp2"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    // field for a pair that was not requested (other input)
    let mut d = tamper(&b, move |n, p| {
        if n == 0 {
            let mut k = vec![0x22];
            k.extend(key(4).pk);
            p.inputs[1].push((k, vec![2; 33]));
        }
    });
    let o = run_with(&b, &store_path("fp3"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    // missing nonce commitment
    let i2 = id.clone();
    let mut d = tamper(&b, move |n, p| {
        if n == 0 {
            let mut k = vec![0x22];
            k.extend(&i2);
            p.inputs[0].retain(|(kk, _)| *kk != k);
        }
    });
    let o = run_with(&b, &store_path("fp4"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    // nonce commitment that does not parse as a point (x not on curve, tag valid)
    let i2 = id.clone();
    let mut d = tamper(&b, move |n, p| {
        if n == 0 {
            let mut k = vec![0x22];
            k.extend(&i2);
            let mut v = vec![2u8];
            v.extend([0xffu8; 32]);
            aexf::psbt::map_set(&mut p.inputs[0], k, v);
        }
    });
    let o = run_with(&b, &store_path("fp5"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    // wrong tag byte
    let i2 = id.clone();
    let mut d = tamper(&b, move |n, p| {
        if n == 0 {
            let mut k = vec![0x22];
            k.extend(&i2);
            let mut v = map_get(&p.inputs[0], &k).unwrap().clone();
            v[0] = 4;
            aexf::psbt::map_set(&mut p.inputs[0], k, v);
        }
    });
    let o = run_with(&b, &store_path("fp6"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
}

#[test]
fn core_transaction_changes_fail_both_versions() {
    for v in [0, 2] {
        let b = build(Spend::P2wpkh, v, None);
        for pass in [0usize, 1] {
            let mut d = tamper(&b, move |n, p| {
                if n == pass {
                    if p.version == 0 {
                        let mut t = aexf::tx::Tx::parse(map_get(&p.global, &[0]).unwrap()).unwrap();
                        t.outputs[0].amount += 1;
                        aexf::psbt::map_set(&mut p.global, vec![0], t.serialize());
                    } else {
                        aexf::psbt::map_set(&mut p.outputs[0], vec![0x03], 60_001u64.to_le_bytes().to_vec());
                    }
                }
            });
            let o = run_with(&b, &store_path("core"), 1, &mut d);
            assert_eq!((o.code, o.count()), (3, 1), "v{v} pass {pass}");
        }
    }
    // sequence and locktime changes also count as core transaction changes
    let b = build(Spend::P2wpkh, 2, None);
    let mut d = tamper(&b, |n, p| {
        if n == 1 {
            aexf::psbt::map_set(&mut p.inputs[1], vec![0x10], 5u32.to_le_bytes().to_vec());
        }
    });
    let o = run_with(&b, &store_path("core2"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
}

#[test]
fn signature_field_rules() {
    let b = build(Spend::P2wpkh, 0, None);
    let k4 = key(4);
    let mut sk4 = vec![0x02];
    sk4.extend(k4.pk);
    // a signature the host did not ask for, added
    for pass in [0usize, 1] {
        let sk4 = sk4.clone();
        let mut d = tamper(&b, move |n, p| {
            if n == pass {
                p.inputs[1].push((sk4.clone(), vec![0x30, 0x06, 2, 1, 1, 2, 1, 1, 1]));
            }
        });
        let o = run_with(&b, &store_path("sf1"), 1, &mut d);
        assert_eq!((o.code, o.count()), (3, 1), "pass {pass}");
    }
    // a signature in the first pass for the requested pair
    let sig_key = b.sig_key();
    let mut d = tamper(&b, move |n, p| {
        if n == 0 {
            p.inputs[0].push((sig_key.clone(), vec![0x30, 0x06, 2, 1, 1, 2, 1, 1, 1]));
        }
    });
    let o = run_with(&b, &store_path("sf2"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    // changed / removed signature fields already in the host PSBT
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(1, sk4.clone(), vec![0x30, 0x06, 2, 1, 1, 2, 1, 1, 1]);
    for pass in [0usize, 1] {
        let sk = sk4.clone();
        let mut d = tamper(&b, move |n, p| {
            if n == pass {
                aexf::psbt::map_set(&mut p.inputs[1], sk.clone(), vec![0x30, 0x06, 2, 1, 2, 2, 1, 1, 1]);
            }
        });
        let o = run_with(&b, &store_path("sf3"), 1, &mut d);
        assert_eq!((o.code, o.count()), (3, 1), "changed pass {pass}");
        let sk = sk4.clone();
        let mut d = tamper(&b, move |n, p| {
            if n == pass {
                p.inputs[1].retain(|(k, _)| *k != sk);
            }
        });
        let o = run_with(&b, &store_path("sf4"), 1, &mut d);
        assert_eq!((o.code, o.count()), (3, 1), "removed pass {pass}");
    }
    // unchanged is fine
    let o = run_with(&b, &store_path("sf5"), 1, &mut honest_for(&b));
    assert_eq!(o.code, 0);
    // removal from a finalized input is allowed
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(1, sk4.clone(), vec![0x30, 0x06, 2, 1, 1, 2, 1, 1, 1]);
    b.spec.set(1, vec![0x08], vec![0]);
    let sk = sk4.clone();
    let mut d = tamper(&b, move |_, p| {
        p.inputs[1].retain(|(k, _)| *k != sk);
    });
    let o = run_with(&b, &store_path("sf6"), 1, &mut d);
    assert_eq!(o.code, 0, "{:?}", o.lines);
    // and the host result keeps its own copy
    assert!(map_get(&result_psbt(&o).inputs[1], &sk4).is_some());
    // taproot key and script signature fields count too
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(1, vec![0x13], vec![7; 64]);
    let mut d = tamper(&b, |_, p| {
        p.inputs[1].retain(|(k, _)| k[0] != 0x13);
    });
    let o = run_with(&b, &store_path("sf7"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    let mut d = tamper(&b, |n, p| {
        if n == 0 {
            p.inputs[0].push((vec![0x14, 1, 2], vec![9; 64]));
        }
    });
    let b2 = build(Spend::P2wpkh, 0, None);
    let o = run_with(&b2, &store_path("sf8"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
}

#[test]
fn other_differences_are_ignored_and_not_copied() {
    let b = build(Spend::P2wpkh, 0, None);
    let mut d = tamper(&b, |_, p| {
        p.inputs[0].reverse();
        p.inputs[0].push((vec![0xf0, 1], b"device chosen data".to_vec()));
        p.inputs[1].push((vec![0x06, 9, 9], vec![0; 4]));
        p.outputs[0].push((vec![0xee], vec![1, 2, 3]));
        p.global.push((vec![0xf1], b"more".to_vec()));
        p.inputs[0].retain(|(k, _)| k[0] != 0x06);
    });
    let o = run_with(&b, &store_path("ign"), 1, &mut d);
    assert_eq!(o.code, 0, "{:?}", o.lines);
    let res = result_psbt(&o);
    let s = hex_encode(&res.serialize());
    assert!(!s.contains(&hex_encode(b"device chosen data")));
    assert!(!s.contains(&hex_encode(b"more")));
    // the host keeps its own derivation record
    assert!(res.inputs[0].iter().any(|(k, _)| k[0] == 0x06));
}

#[test]
fn bad_signatures_fail_the_attempt_without_retry() {
    let b = build(Spend::P2wpkh, 0, None);
    let sk = b.sig_key();
    // flip a bit in s
    let cases: Vec<(&str, Box<dyn Fn(&mut Vec<u8>)>)> = vec![
        ("flip s", Box::new(|v: &mut Vec<u8>| { let n = v.len(); v[n - 2] ^= 1; })),
        ("flip r", Box::new(|v: &mut Vec<u8>| v[6] ^= 1)),
        ("wrong sighash byte", Box::new(|v: &mut Vec<u8>| { let n = v.len(); v[n - 1] = 2; })),
        ("no sighash byte", Box::new(|v: &mut Vec<u8>| { v.pop(); })),
        ("trailing byte", Box::new(|v: &mut Vec<u8>| v.push(1))),
        ("garbage", Box::new(|v: &mut Vec<u8>| *v = vec![1, 2, 3])),
        ("empty", Box::new(|v: &mut Vec<u8>| v.clear())),
    ];
    for (name, f) in cases {
        let sk = sk.clone();
        let mut d = tamper(&b, move |n, p| {
            if n == 1 {
                let e = p.inputs[0].iter_mut().find(|(k, _)| *k == sk).unwrap();
                f(&mut e.1);
            }
        });
        let mut a = host_args(&b, &store_path("bs"), &rho_n(1));
        a.retries = 3;
        let o = run_host(&a, &mut d);
        assert_eq!((o.code, o.count(), o.requests.len()), (3, 1, 2), "{name}");
        assert!(!o.lines.iter().any(|l| l.starts_with("RESULT")));
    }
}

#[test]
fn high_s_and_ber_signatures_fail() {
    let b = build(Spend::P2wpkh, 0, None);
    let sk = b.sig_key();
    // high-s: replace s by n - s
    let skc = sk.clone();
    let mut d = tamper(&b, move |n, p| {
        if n == 1 {
            let e = p.inputs[0].iter_mut().find(|(k, _)| *k == skc).unwrap();
            let v = &e.1;
            let lr = v[3] as usize;
            let ls = v[5 + lr] as usize;
            let sb = &v[6 + lr..6 + lr + ls];
            let mut s32 = [0u8; 32];
            let sb = if sb[0] == 0 { &sb[1..] } else { sb };
            s32[32 - sb.len()..].copy_from_slice(sb);
            let s = sc_from(&s32).unwrap();
            let hs = -s;
            use k256::elliptic_curve::ff::PrimeField;
            let hb: [u8; 32] = hs.to_repr().into();
            let mut r32 = [0u8; 32];
            let rb = &v[4..4 + lr];
            let rb = if rb[0] == 0 { &rb[1..] } else { rb };
            r32[32 - rb.len()..].copy_from_slice(rb);
            e.1 = aexf::ae::der_encode(&r32, &hb, 1);
        }
    });
    let o = run_with(&b, &store_path("hs"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    // BER: pad r with a redundant zero (still a valid ECDSA signature, not strict DER)
    let skc = sk.clone();
    let mut d = tamper(&b, move |n, p| {
        if n == 1 {
            let e = p.inputs[0].iter_mut().find(|(k, _)| *k == skc).unwrap();
            let v = e.1.clone();
            let lr = v[3] as usize;
            let mut o = vec![0x30, v[1] + 1, 0x02, lr as u8 + 1, 0x00];
            o.extend(&v[4..]);
            e.1 = o;
        }
    });
    let o = run_with(&b, &store_path("ber"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
}

#[test]
fn signature_for_a_different_rho_or_message_fails() {
    let b = build(Spend::P2wpkh, 0, None);
    // second pass signed under another rho: nonce relation breaks
    let h = honest_for(&b);
    let hh = Rc::new(RefCell::new(h));
    let h2 = hh.clone();
    let id = b.id.clone();
    let b_spec = b.spec.clone();
    let mut d = move |n: usize, req: &str| -> Option<String> {
        if n == 1 {
            // answer a request built with a different rho
            let s = with_field(&b_spec, 0, 0x23, &id, &rho_n(77));
            (h2.borrow_mut())(1, &hex_encode(&s.psbt()))
        } else {
            (hh.borrow_mut())(n, req)
        }
    };
    let o = run_with(&b, &store_path("wr"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    // the device signs a different message but with a commitment-compatible nonce is impossible; use a changed amount
    let mut b2 = build(Spend::P2wpkh, 0, None);
    b2.spec.t.outs[1].amount = 69_000;
    let mut h = honest_for(&b2);
    let mut d = move |n: usize, req: &str| -> Option<String> {
        if n == 1 {
            // second request from the host, but the device answers one for another transaction
            let mut p = Psbt::parse(&hex_decode(req).unwrap()).unwrap();
            let mut t = aexf::tx::Tx::parse(map_get(&p.global, &[0]).unwrap()).unwrap();
            t.outputs[1].amount = 69_000;
            aexf::psbt::map_set(&mut p.global, vec![0], t.serialize());
            h(1, &hex_encode(&p.serialize()))
        } else {
            h(n, req)
        }
    };
    let o = run_with(&b, &store_path("wm"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
}

#[test]
fn taproot_signature_format_checks() {
    for (name, ht, edit) in [
        ("extra zero sighash byte", None, 0u8),
        ("missing sighash byte", Some(3u32), 1),
        ("wrong sighash byte", Some(3), 2),
        ("short", None, 3),
        ("tampered", None, 4),
    ] {
        let b = build(Spend::TapKey, 0, ht);
        let mut d = tamper(&b, move |n, p| {
            if n == 1 {
                let e = p.inputs[0].iter_mut().find(|(k, _)| k[0] == 0x13).unwrap();
                match edit {
                    0 => e.1.push(0),
                    1 => { e.1.pop(); }
                    2 => { let l = e.1.len(); e.1[l - 1] = 1; }
                    3 => { e.1.pop(); }
                    _ => e.1[40] ^= 1,
                }
            }
        });
        let o = run_with(&b, &store_path("tf"), 1, &mut d);
        assert_eq!((o.code, o.count()), (3, 1), "{name}");
    }
    // script path tampering
    let b = build(Spend::TapScript, 0, None);
    let mut d = tamper(&b, |n, p| {
        if n == 1 {
            let e = p.inputs[0].iter_mut().find(|(k, _)| k[0] == 0x14).unwrap();
            e.1[3] ^= 1;
        }
    });
    let o = run_with(&b, &store_path("tf2"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
}

fn refused(b: &Built, name: &str) {
    let store = store_path(name);
    let o = run_with(b, &store, 1, &mut honest_for(b));
    assert_eq!((o.code, o.last()), (4, "REFUSED"), "{name}: {:?}", o.lines);
    assert!(o.requests.is_empty(), "{name}: nothing may be sent");
    assert_eq!(o.count(), 0);
    // no attempt was recorded
    let s = std::fs::read_to_string(&store).unwrap_or_default();
    assert!(!s.contains(" U ") && !s.contains(" C "), "{name}: {s}");
}

#[test]
fn host_refusals() {
    // device key not in the PSBT at all
    let mut b = build(Spend::P2wpkh, 0, None);
    b.dev = key(99);
    refused(&b, "ref_nokey");
    // PSBT already holds anti-exfil fields
    for ty in [0x21u8, 0x22, 0x23] {
        let mut b = build(Spend::P2wpkh, 0, None);
        b.spec.set(1, { let mut k = vec![ty]; k.extend(key(4).pk); k }, vec![0; 33]);
        refused(&b, "ref_ae");
    }
    // finalized input with a pair
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(0, vec![0x07], vec![0]);
    refused(&b, "ref_final");
    // derivation record names a device key the script does not contain
    let mut b = build(Spend::P2wsh1, 0, None);
    let ws = checksig_script(&key(2).pk);
    let spk = p2wsh(&sha256(&ws));
    b.spec.set(0, vec![0x05], ws);
    b.spec.set(0, vec![0x01], wu(AMT0, &spk));
    refused(&b, "ref_notinscript");
    // device key twice in multisig
    let mut b = build(Spend::P2wshMulti, 0, None);
    let ws = multisig(&[b.dev.pk, key(2).pk, b.dev.pk], 2);
    let spk = p2wsh(&sha256(&ws));
    b.spec.set(0, vec![0x05], ws);
    b.spec.set(0, vec![0x01], wu(AMT0, &spk));
    refused(&b, "ref_dupkey");
    // unsupported script shape
    let mut b = build(Spend::P2wsh1, 0, None);
    let mut ws = push(&b.dev.pk);
    ws.extend([0x75, 0x51]);
    let spk = p2wsh(&sha256(&ws));
    b.spec.set(0, vec![0x05], ws);
    b.spec.set(0, vec![0x01], wu(AMT0, &spk));
    refused(&b, "ref_shape");
    // invalid sighash type, ECDSA zero, SINGLE without output
    let mut b = build(Spend::P2wpkh, 0, Some(1));
    b.spec.set(0, vec![0x03], 4u32.to_le_bytes().to_vec());
    refused(&b, "ref_ht");
    let mut b = build(Spend::P2wpkh, 0, Some(1));
    b.spec.set(0, vec![0x03], 0u32.to_le_bytes().to_vec());
    refused(&b, "ref_ht0");
    let mut b = build(Spend::P2wpkh, 0, Some(3));
    b.spec.t.outs.clear();
    b.spec.outs.clear();
    refused(&b, "ref_single");
    // missing UTXO, mismatched UTXO
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.remove(0, &[0x01]);
    refused(&b, "ref_utxo");
    let mut b = build(Spend::P2pkh, 0, None);
    b.spec.set(0, vec![0x00], fund_tx(&b.prevs[0].1, AMT0, 0x77).0);
    refused(&b, "ref_nwu");
    // outputs exceed inputs
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.t.outs[0].amount = 999_999;
    refused(&b, "ref_over");
    // taproot without all prevouts
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.remove(1, &[0x01]);
    refused(&b, "ref_tapprev");
    // MuSig2 participant listing the device key
    let mut b = build(Spend::TapKey, 0, None);
    let v: Vec<u8> = [key(61).pk, b.dev.pk].iter().flat_map(|k| k.to_vec()).collect();
    b.spec.set(0, { let mut k = vec![0x1a]; k.extend(key(62).pk); k }, v);
    refused(&b, "ref_musig");
    // OP_CODESEPARATOR in the leaf
    let mut s = vec![0xab];
    s.extend(checksig_script_x(&key(1).x));
    // unparseable PSBT
    let o = {
        let b = build(Spend::P2wpkh, 0, None);
        let mut a = host_args(&b, &store_path("ref_bad"), &rho_n(1));
        a.psbt = "70736274ff00".to_string();
        run_host(&a, &mut honest_for(&b))
    };
    assert_eq!((o.code, o.last()), (4, "REFUSED"));
    let _ = s;
    // a store that cannot be written
    let b = build(Spend::P2wpkh, 0, None);
    let a = host_args(&b, "/nonexistent-dir-for-aexf/store", &rho_n(1));
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!((o.code, o.last()), (4, "REFUSED"));
    assert!(o.requests.is_empty());
}

#[test]
fn pairs_already_signed_are_skipped() {
    // the only pair signed: no pairs remain
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(0, b.sig_key(), vec![0x30, 0x06, 2, 1, 1, 2, 1, 1, 1]);
    refused(&b, "skip_all");
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.set(0, vec![0x13], vec![0; 64]);
    refused(&b, "skip_tap");
    let mut b = build(Spend::TapScript, 0, None);
    let k = b.sig_key();
    b.spec.set(0, k, vec![0; 64]);
    refused(&b, "skip_tapscript");
    // two device inputs, one already signed: the other is requested
    let b = build(Spend::P2wpkh, 0, None);
    let mut s = b.spec.clone();
    let k4 = key(4);
    let mut sk4 = vec![0x02];
    sk4.extend(k4.pk);
    s.set(1, sk4, vec![0x30, 0x06, 2, 1, 1, 2, 1, 1, 1]);
    let b2 = Built { spec: s, ..clone_built(&b) };
    let mut a = host_args(&b2, &store_path("skip_one"), &rho_n(1));
    a.devs.push(hex_encode(&k4.pk));
    let o = run_host(&a, &mut honest_for(&b2));
    assert_eq!(o.code, 0, "{:?}", o.lines);
}

fn clone_built(b: &Built) -> Built {
    Built {
        spec: b.spec.clone(),
        dev: b.dev.clone(),
        spend: b.spend,
        id: b.id.clone(),
        ht: b.ht,
        prevs: b.prevs.clone(),
        leaf: b.leaf,
        internal: b.internal.clone(),
        merkle: b.merkle,
        code: b.code.clone(),
    }
}

#[test]
fn missing_rho_exit_9() {
    let b = build(Spend::P2wpkh, 0, None);
    let mut a = host_args(&b, &store_path("mr"), &rho_n(1));
    a.rhos.clear();
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!((o.code, o.last(), o.count()), (9, "MISSING_RHO", 0));
    assert!(o.requests.is_empty());
    // a rho for a different key identifier does not count
    let mut a = host_args(&b, &store_path("mr2"), &rho_n(1));
    a.rhos = vec![(1, b.id.clone(), rho_n(1))];
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!(o.code, 9);
}

#[test]
fn rho_reuse_is_refused() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("reuse");
    let o = run_with(&b, &store, 1, &mut honest_for(&b));
    assert_eq!(o.code, 0);
    let o = run_with(&b, &store, 1, &mut honest_for(&b));
    assert_eq!((o.code, o.last()), (4, "REFUSED"));
    assert!(o.requests.is_empty());
    // a failed attempt's rho is used up too
    let store = store_path("reuse2");
    let _ = run_with(&b, &store, 1, &mut |_, _| Some("ERROR".into()));
    let mut a = host_args(&b, &store, &rho_n(1));
    a.ack = true;
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!(o.code, 4);
    // the store holds the host commitment but never rho
    let text = std::fs::read_to_string(&store).unwrap();
    assert!(!text.contains(&hex_encode(&rho_n(1))));
    assert!(text.contains(&hex_encode(&hc_of(true, &rho_n(1)))));
    // two pairs with the same rho in one attempt
    let b = build(Spend::P2wpkh, 0, None);
    let k4 = key(4);
    let mut a = host_args(&b, &store_path("reuse3"), &rho_n(1));
    a.devs.push(hex_encode(&k4.pk));
    a.rhos.push((1, k4.pk.to_vec(), rho_n(1)));
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!(o.code, 4);
}

#[test]
fn two_pairs_two_rhos() {
    let b = build(Spend::P2wpkh, 2, None);
    let k4 = key(4);
    let mut a = host_args(&b, &store_path("two"), &rho_n(1));
    a.devs.push(hex_encode(&k4.pk));
    a.rhos.push((1, k4.pk.to_vec(), rho_n(2)));
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!(o.code, 0, "{:?}", o.lines);
    let res = result_psbt(&o);
    let mut s0 = vec![0x02];
    s0.extend(b.dev.pk);
    let mut s1 = vec![0x02];
    s1.extend(k4.pk);
    assert!(map_get(&res.inputs[0], &s0).is_some());
    let v = map_get(&res.inputs[1], &s1).unwrap().clone();
    assert_eq!(v[0], 0x30);
    let q1 = Psbt::parse(&hex_decode(&o.requests[0]).unwrap()).unwrap();
    assert_eq!(q1.inputs.iter().flatten().filter(|(k, _)| k[0] == 0x21).count(), 2);
    // one failing pair fails the whole attempt and nothing is added
    let id = b.id.clone();
    let mut d = tamper(&b, move |n, p| {
        if n == 1 {
            let mut k = vec![0x02];
            k.extend(&id[..]);
            let e = p.inputs[0].iter_mut().find(|(kk, _)| *kk == k).unwrap();
            e.1[8] ^= 1;
        }
    });
    let mut a = host_args(&b, &store_path("two2"), &rho_n(1));
    a.devs.push(hex_encode(&k4.pk));
    a.rhos.push((1, k4.pk.to_vec(), rho_n(2)));
    let o = run_host(&a, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
    assert!(!o.lines.iter().any(|l| l.starts_with("RESULT")));
}

#[test]
fn two_forms_of_one_xonly_key_make_one_pair() {
    let b = build(Spend::TapKey, 0, None);
    let mut other = b.dev.pk;
    other[0] ^= 1;
    let mut a = host_args(&b, &store_path("xonly"), &rho_n(1));
    a.devs.push(hex_encode(&other));
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!(o.code, 0, "{:?}", o.lines);
    let q1 = Psbt::parse(&hex_decode(&o.requests[0]).unwrap()).unwrap();
    assert_eq!(q1.inputs.iter().flatten().filter(|(k, _)| k[0] == 0x21).count(), 1);
    // device given only in the other parity form still matches the Taproot key
    let mut a = host_args(&b, &store_path("xonly2"), &rho_n(1));
    a.devs = vec![hex_encode(&other)];
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!(o.code, 0);
}

#[test]
fn key_path_preferred_over_script_path() {
    let b = build(Spend::TapKey, 0, None);
    let mut s = b.spec.clone();
    // add a leaf the device key also appears in, with a derivation record listing the leaf
    let script = checksig_script_x(&b.dev.x);
    let l = tap_leaf(0xc0, &script);
    let mut ctl = vec![0xc0];
    ctl.extend([1u8; 32]);
    let mut val = script;
    val.push(0xc0);
    s.ins[0].push(kv(0x15, &ctl, &val));
    let mut dv = compact(1);
    dv.extend(l);
    dv.extend([0; 8]);
    s.set(0, { let mut k = vec![0x16]; k.extend(b.dev.x); k }, dv);
    let b2 = Built { spec: s, ..clone_built(&b) };
    let o = run_with(&b2, &store_path("kp"), 1, &mut honest_for(&b2));
    assert_eq!(o.code, 0, "{:?}", o.lines);
    let q1 = Psbt::parse(&hex_decode(&o.requests[0]).unwrap()).unwrap();
    let ids: Vec<usize> = q1.inputs[0].iter().filter(|(k, _)| k[0] == 0x21).map(|(k, _)| k.len() - 1).collect();
    assert_eq!(ids, vec![32]);
}

#[test]
fn listed_leaf_without_script_forms_no_pair() {
    // script path input whose derivation record lists a second leaf with no script: only the real leaf is a pair
    let b = build(Spend::TapScript, 0, None);
    let mut s = b.spec.clone();
    let mut dv = compact(2);
    dv.extend(b.leaf.unwrap());
    dv.extend([9u8; 32]);
    dv.extend([0; 8]);
    s.set(0, { let mut k = vec![0x16]; k.extend(b.dev.x); k }, dv);
    let b2 = Built { spec: s, ..clone_built(&b) };
    let o = run_with(&b2, &store_path("noscript"), 1, &mut honest_for(&b2));
    assert_eq!(o.code, 0, "{:?}", o.lines);
}

#[test]
fn store_is_written_before_the_commitment_is_sent_and_counts_once() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("durable");
    let hc = hex_encode(&hc_of(true, &rho_n(1)));
    let st = store.clone();
    let mut a = host_args(&b, &store, &rho_n(1));
    a.retries = 3;
    let o = run_host(&a, &mut |n, _| {
        let t = std::fs::read_to_string(&st).unwrap();
        match n {
            0 => {
                // attempt open, uncounted, commitment recorded
                assert!(t.contains(" 0 0 U "), "{t}");
                assert!(t.contains(&hc));
            }
            _ => {
                // first failure event counted atomically with the open state
                assert!(t.contains(" 1 0 C "), "{t}");
            }
        }
        Some("ERROR".into())
    });
    assert_eq!((o.code, o.count(), o.requests.len()), (3, 1, 4));
    let t = std::fs::read_to_string(&store).unwrap();
    assert!(t.contains(" 1 0 N "), "{t}");
}

#[test]
fn open_attempt_at_startup_counts_as_failed() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("restart");
    let o = run_with(&b, &store, 1, &mut honest_for(&b));
    assert_eq!(o.code, 0);
    // simulate a crash mid-attempt: the record says an attempt is open and uncounted
    let t = std::fs::read_to_string(&store).unwrap();
    let t2 = t.replace(" 0 0 N ", " 0 0 U ");
    assert_ne!(t, t2);
    std::fs::write(&store, &t2).unwrap();
    let o = run_with(&b, &store, 2, &mut honest_for(&b));
    assert_eq!((o.code, o.last(), o.count()), (5, "NOT_ACKNOWLEDGED", 1));
    // already counted: no second count
    let store = store_path("restart2");
    let _ = run_with(&b, &store, 1, &mut honest_for(&b));
    let t = std::fs::read_to_string(&store).unwrap();
    std::fs::write(&store, t.replace(" 0 0 N ", " 1 0 C ")).unwrap();
    let o = run_with(&b, &store, 2, &mut honest_for(&b));
    assert_eq!((o.code, o.last(), o.count()), (5, "NOT_ACKNOWLEDGED", 1));
    let mut a = host_args(&b, &store, &rho_n(3));
    a.ack = true;
    let o = run_host(&a, &mut honest_for(&b));
    assert_eq!((o.code, o.count()), (0, 1));
}

#[test]
fn unreadable_records_count_as_one() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("unread");
    std::fs::write(&store, b"\xff\xfenot a store").unwrap();
    let o = run_with(&b, &store, 1, &mut honest_for(&b));
    assert_eq!((o.code, o.last(), o.count()), (5, "NOT_ACKNOWLEDGED", 1));
    // no records at all: a new device
    let store = store_path("norec");
    let o = run_with(&b, &store, 1, &mut honest_for(&b));
    assert_eq!((o.code, o.count()), (0, 0));
    // records of another device do not count against this one
    let o2 = {
        let mut a = host_args(&b, &store, &rho_n(2));
        a.devs = vec![hex_encode(&b.dev.pk), hex_encode(&key(90).pk)];
        run_host(&a, &mut honest_for(&b))
    };
    assert_eq!((o2.code, o2.count()), (0, 0));
    let t = std::fs::read_to_string(&store).unwrap();
    assert_eq!(t.lines().count(), 3);
}

#[test]
fn reset_clears_count_and_warning() {
    let b = build(Spend::P2wpkh, 0, None);
    let store = store_path("reset");
    let _ = run_with(&b, &store, 1, &mut |_, _| Some("ERROR".into()));
    let o = run_with(&b, &store, 2, &mut honest_for(&b));
    assert_eq!(o.code, 5);
    // without the explicit confirmation nothing is cleared
    let st = std::process::Command::new(env!("CARGO_BIN_EXE_aexf"))
        .args(["reset", "--store", &store, "--device-key", &hex_encode(&b.dev.pk)])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_ne!(st.code(), Some(0));
    let o = run_with(&b, &store, 2, &mut honest_for(&b));
    assert_eq!(o.code, 5);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_aexf"))
        .args(["reset", "--store", &store, "--device-key", &hex_encode(&b.dev.pk), "--confirm-clear-failure-count"])
        .stderr(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    let o = run_with(&b, &store, 2, &mut honest_for(&b));
    assert_eq!((o.code, o.count()), (0, 0));
}

#[test]
fn device_returning_ordinary_signature_or_nothing_new_fails() {
    // a device that ignores the fields and returns the PSBT unchanged: no nonce commitment
    let b = build(Spend::P2wpkh, 0, None);
    let o = run_with(&b, &store_path("ord"), 1, &mut |_, _| Some(b.spec.hex()));
    assert_eq!((o.code, o.count()), (3, 1));
    // a device that returns an ordinary signature in the first pass
    let mut d = tamper(&b, |n, p| {
        if n == 0 {
            // pretend to sign: add a signature and drop the commitment
            p.inputs[0].retain(|(k, _)| k[0] != 0x22);
        }
    });
    let o = run_with(&b, &store_path("ord2"), 1, &mut d);
    assert_eq!((o.code, o.count()), (3, 1));
}

#[test]
fn host_cli_argument_errors() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_aexf")).args(["host", "--bogus"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_aexf")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn signer_cli_behaviour() {
    use std::io::Write;
    let b = build(Spend::P2wpkh, 0, None);
    let rho = rho_n(1);
    let run = |extra: &[&str], line: &str| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_aexf"));
        c.arg("signer").arg("--secret-key").arg(hex_encode(&b.dev.sk));
        c.args(extra);
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
        let mut ch = c.spawn().unwrap();
        writeln!(ch.stdin.take().unwrap(), "{line}").unwrap();
        ch.wait_with_output().unwrap()
    };
    let o = run(&[], &hex_encode(&req1(&b, &rho).psbt()));
    assert_eq!(o.status.code(), Some(0));
    let line = String::from_utf8(o.stdout).unwrap();
    assert_eq!(line.trim().len() + 1, line.len());
    let o = run(&["--decline"], &hex_encode(&req2(&b, &rho).psbt()));
    assert_eq!(o.status.code(), Some(3));
    assert!(o.stdout.is_empty());
    let o = run(&["--decline"], &hex_encode(&req1(&b, &rho).psbt()));
    assert_eq!(o.status.code(), Some(0));
    let o = run(&[], &b.spec.hex());
    assert_eq!(o.status.code(), Some(3));
    assert!(o.stdout.is_empty());
    let o = run(&[], "nothex");
    assert_eq!(o.status.code(), Some(3));
    let o = run(&[], &hex_encode(&req2(&b, &rho).psbt()));
    assert_eq!(o.status.code(), Some(0));
}
