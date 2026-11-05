mod common;
use aexf::psbt::{map_get, Psbt};
use aexf::signer::handle_request;
use common::*;

fn keys_for(b: &Built) -> Vec<Key> {
    vec![b.dev.clone(), key(4)]
}
fn opts(b: &Built) -> aexf::signer::SignerOpts {
    let ks = keys_for(b);
    let refs: Vec<&Key> = ks.iter().collect();
    signer_opts(&refs, false)
}
const RHO: u8 = 1;

fn sign_ok(b: &Built) {
    let rho = rho_n(RHO);
    let (r0, resp) = exchange(b, &rho, &opts(b)).unwrap_or_else(|e| panic!("{:?} v{} ht {:#x}: {e}", b.spend, b.spec.version, b.ht));
    check_signature(b, &rho, &r0, &resp);
}

fn first_fails(spec: &Spec, b: &Built) -> bool {
    handle_request(&req1_spec(spec, b).psbt(), &opts(b)).is_err()
}
fn second_fails(spec: &Spec, b: &Built) -> bool {
    handle_request(&req2_spec(spec, b).psbt(), &opts(b)).is_err()
}
fn req1_spec(spec: &Spec, b: &Built) -> Spec {
    with_field(spec, 0, 0x21, &b.id, &hc_of(b.is_ecdsa(), &rho_n(RHO)))
}
fn req2_spec(spec: &Spec, b: &Built) -> Spec {
    with_field(spec, 0, 0x23, &b.id, &rho_n(RHO))
}
/// Both passes must fail.
fn both_fail(b: &Built, spec: &Spec) {
    assert!(first_fails(spec, b), "first pass should fail");
    assert!(second_fails(spec, b), "second pass should fail");
}

#[test]
fn every_spend_form_both_versions() {
    for v in [0, 2] {
        for s in ALL_SPENDS {
            sign_ok(&build(s, v, None));
        }
    }
}

#[test]
fn every_sighash_type() {
    for v in [0, 2] {
        for s in ALL_SPENDS {
            let hts: Vec<u32> = if matches!(s, Spend::TapKey | Spend::TapScript) {
                vec![0, 1, 2, 3, 0x81, 0x82, 0x83]
            } else {
                vec![1, 2, 3, 0x81, 0x82, 0x83]
            };
            for h in hts {
                sign_ok(&build(s, v, Some(h)));
            }
        }
    }
}

#[test]
fn bip143_published_vector() {
    // BIP 143 native P2WPKH example, input 1.
    let raw = aexf::util::hex_decode("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000").unwrap();
    let t = aexf::tx::Tx::parse(&raw).unwrap();
    let code = aexf::util::hex_decode("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac").unwrap();
    let h = aexf::sighash::sighash_bip143(&t, 1, &code, 600_000_000, 1).unwrap();
    assert_eq!(aexf::util::hex_encode(&h), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
}

#[test]
fn crate_sighash_matches_independent_sighash() {
    // The signer's message equals the independently computed one: check via the nonce commitment path
    // by signing and verifying against the independent message (done in check_signature); here compare directly.
    for s in ALL_SPENDS {
        for h in [1u32, 2, 3, 0x81, 0x83] {
            let b = build(s, 0, Some(h));
            let psbt = parse(&b.spec.psbt());
            let tx = psbt.core_tx().unwrap();
            let m = match s {
                Spend::P2pkh | Spend::P2shLegacy => aexf::sighash::sighash_legacy(&tx, 0, &b.code, h).unwrap(),
                Spend::TapKey | Spend::TapScript => {
                    let prevs: Vec<Option<aexf::sighash::Prevout>> = b
                        .prevs
                        .iter()
                        .map(|p| Some(aexf::sighash::Prevout { amount: p.0, spk: p.1.clone() }))
                        .collect();
                    aexf::sighash::sighash_taproot(&tx, 0, &prevs, h, b.leaf.as_ref()).unwrap()
                }
                _ => aexf::sighash::sighash_bip143(&tx, 0, &b.code, AMT0, h).unwrap(),
            };
            assert_eq!(m, b.msg(), "{s:?} {h:#x}");
        }
    }
}

#[test]
fn first_pass_adds_nonce_commitment_only() {
    for s in ALL_SPENDS {
        let b = build(s, 2, None);
        let rho = rho_n(RHO);
        let r1 = handle_request(&req1(&b, &rho).psbt(), &opts(&b)).unwrap();
        let p = parse(&r1);
        let mut k22 = vec![0x22];
        k22.extend(&b.id);
        let mut k21 = vec![0x21];
        k21.extend(&b.id);
        assert_eq!(map_get(&p.inputs[0], &k22).unwrap().len(), 33);
        assert_eq!(map_get(&p.inputs[0], &k21).unwrap()[..], hc_of(b.is_ecdsa(), &rho)[..]);
        assert!(map_get(&p.inputs[0], &b.sig_key()).is_none());
        // stateless and deterministic
        let r1b = handle_request(&req1(&b, &rho).psbt(), &opts(&b)).unwrap();
        assert_eq!(r1, r1b);
        // a present, equal nonce commitment is accepted, a different one is not
        let ok = with_field(&req1(&b, &rho), 0, 0x22, &b.id, map_get(&p.inputs[0], &k22).unwrap());
        assert!(handle_request(&ok.psbt(), &opts(&b)).is_ok());
        let mut bad = map_get(&p.inputs[0], &k22).unwrap().clone();
        bad[5] ^= 1;
        let bad = with_field(&req1(&b, &rho), 0, 0x22, &b.id, &bad);
        assert!(handle_request(&bad.psbt(), &opts(&b)).is_err());
    }
}

#[test]
fn second_pass_removes_fields_and_keeps_rest() {
    for s in ALL_SPENDS {
        let b = build(s, 0, None);
        let rho = rho_n(RHO);
        let (_, resp) = exchange(&b, &rho, &opts(&b)).unwrap();
        for m in &resp.inputs {
            assert!(m.iter().all(|(k, _)| !(0x21..=0x23).contains(&k[0]) || k[0] == 0x23 && false || !matches!(k[0], 0x21..=0x23)));
        }
        // only the one signature was added to input 0 and nothing to input 1
        assert_eq!(resp.inputs[1].len(), b.spec.ins[1].len());
        assert_eq!(resp.inputs[0].len(), parse(&b.spec.psbt()).inputs[0].len() + 1);
    }
}

#[test]
fn second_pass_checks_commitments_when_present() {
    let b = build(Spend::P2wpkh, 0, None);
    let rho = rho_n(RHO);
    let good_hc = hc_of(true, &rho);
    let s = with_field(&req2(&b, &rho), 0, 0x21, &b.id, &good_hc);
    assert!(handle_request(&s.psbt(), &opts(&b)).is_ok());
    let mut bad = good_hc;
    bad[0] ^= 1;
    let s = with_field(&req2(&b, &rho), 0, 0x21, &b.id, &bad);
    assert!(handle_request(&s.psbt(), &opts(&b)).is_err());
    let (r0, _) = exchange(&b, &rho, &opts(&b)).unwrap();
    let s = with_field(&req2(&b, &rho), 0, 0x22, &b.id, &r0);
    assert!(handle_request(&s.psbt(), &opts(&b)).is_ok());
    let mut r0b = r0;
    r0b[10] ^= 4;
    let s = with_field(&req2(&b, &rho), 0, 0x22, &b.id, &r0b);
    assert!(handle_request(&s.psbt(), &opts(&b)).is_err());
}

#[test]
fn nonce_parity_and_w_parity_both_occur() {
    // Over several rho values both parities of R0 and of W show up, and every signature verifies.
    let mut r0_parities = [false; 2];
    let mut w_parities = [false; 2];
    for s in [Spend::P2wpkh, Spend::TapKey] {
        let b = build(s, 2, None);
        for n in 0..24u8 {
            let rho = rho_n(100 + n);
            let (r0, resp) = exchange(&b, &rho, &opts(&b)).unwrap();
            check_signature(&b, &rho, &r0, &resp);
            r0_parities[(r0[0] - 2) as usize] = true;
            let tag = if b.is_ecdsa() { "s2c/ecdsa/point" } else { "s2c/schnorr/point" };
            let t = sc_from(&tagged(tag, &[&r0, &rho])).unwrap();
            let w = point(&r0) + g_mul(&t);
            w_parities[is_odd(&w) as usize] = true;
        }
    }
    assert!(r0_parities == [true, true] && w_parities == [true, true]);
}

#[test]
fn key_parities_for_taproot_and_ecdsa() {
    // device keys with odd and even y, ECDSA and Taproot
    for odd in [false, true] {
        let k = key_with_parity(odd, 40);
        let mut b = build(Spend::P2wpkh, 2, None);
        // rebuild around a different device key by direct construction
        let spk = p2wpkh(&hash160(&k.pk));
        b.spec.set(0, vec![0x01], wu(AMT0, &spk));
        b.spec.ins[0].retain(|(kk, _)| kk[0] != 0x06);
        b.spec.ins[0].push(kv(0x06, &k.pk, &[0; 8]));
        b.prevs[0].1 = spk;
        b.code = p2pkh(&hash160(&k.pk));
        b.dev = k.clone();
        b.id = k.pk.to_vec();
        sign_ok(&b);
    }
}

#[test]
fn declined_second_pass_returns_nothing_first_pass_needs_no_approval() {
    let b = build(Spend::P2wpkh, 0, None);
    let rho = rho_n(RHO);
    let ks = keys_for(&b);
    let refs: Vec<&Key> = ks.iter().collect();
    let dec = signer_opts(&refs, true);
    assert!(handle_request(&req1(&b, &rho).psbt(), &dec).is_ok());
    assert!(handle_request(&req2(&b, &rho).psbt(), &dec).is_err());
}

#[test]
fn not_a_request() {
    let b = build(Spend::P2wpkh, 0, None);
    assert!(handle_request(&b.spec.psbt(), &opts(&b)).is_err());
    assert!(handle_request(b"garbage", &opts(&b)).is_err());
}

#[test]
fn only_nonce_commitment_fails() {
    let b = build(Spend::P2wpkh, 0, None);
    let s = with_field(&b.spec, 0, 0x22, &b.id, &[2u8; 33]);
    assert!(handle_request(&s.psbt(), &opts(&b)).is_err());
}

#[test]
fn wrong_field_lengths_fail() {
    let b = build(Spend::P2wpkh, 0, None);
    let rho = rho_n(RHO);
    for (ty, len) in [(0x21u8, 31usize), (0x21, 33), (0x23, 31), (0x23, 33)] {
        let s = with_field(&b.spec, 0, ty, &b.id, &vec![7u8; len]);
        assert!(handle_request(&s.psbt(), &opts(&b)).is_err(), "{ty:#x} {len}");
    }
    let s = with_field(&req1(&b, &rho), 0, 0x22, &b.id, &[2u8; 32]);
    assert!(handle_request(&s.psbt(), &opts(&b)).is_err());
    // bad key identifier lengths
    for n in [31usize, 34, 65, 0, 63] {
        let id = vec![2u8; n];
        let s = with_field(&b.spec, 0, 0x21, &id, &[0u8; 32]);
        assert!(handle_request(&s.psbt(), &opts(&b)).is_err(), "id len {n}");
    }
    // a 65-byte identifier next to a good pair still fails the whole request
    let s = with_field(&req1(&b, &rho), 0, 0x21, &[4u8; 65], &[0u8; 32]);
    assert!(handle_request(&s.psbt(), &opts(&b)).is_err());
}

#[test]
fn fields_outside_input_maps_are_ordinary_unknown_fields() {
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.glob.push(kv(0x21, &b.id, &[0u8; 32]));
    b.spec.outs[0].push(kv(0x23, &b.id, &[0u8; 32]));
    // no input holds a field: not a request
    assert!(handle_request(&b.spec.psbt(), &opts(&b)).is_err());
    // with a proper request the extra fields are ignored and kept
    let rho = rho_n(RHO);
    let (r0, resp) = exchange(&b, &rho, &opts(&b)).unwrap();
    check_signature(&b, &rho, &r0, &resp);
    assert_eq!(resp.global.iter().filter(|(k, _)| k[0] == 0x21).count(), 1);
    assert_eq!(resp.outputs[0].iter().filter(|(k, _)| k[0] == 0x23).count(), 1);
}

#[test]
fn mixed_phases_fail() {
    let b = build(Spend::P2wpkh, 0, None);
    let rho = rho_n(RHO);
    let k4 = key(4);
    // pair on input 0 in the second phase, pair on input 1 in the first
    let mut s = req2(&b, &rho);
    s.set(1, { let mut k = vec![0x21]; k.extend(k4.pk); k }, hc_of(true, &rho_n(9)).to_vec());
    assert!(handle_request(&s.psbt(), &opts(&b)).is_err());
    // both pairs in the same phase work
    let mut s = req2(&b, &rho);
    s.set(1, { let mut k = vec![0x23]; k.extend(k4.pk); k }, rho_n(9).to_vec());
    let out = handle_request(&s.psbt(), &opts(&b)).unwrap();
    let p = parse(&out);
    assert!(map_get(&p.inputs[0], &b.sig_key()).is_some());
    let mut k = vec![0x02];
    k.extend(k4.pk);
    assert!(map_get(&p.inputs[1], &k).is_some());
}

#[test]
fn two_pairs_each_checked() {
    // device key twice in two inputs (same key), distinct rho
    let b = build(Spend::P2wpkh, 2, None);
    let k4 = key(4);
    let mut s = b.spec.clone();
    let mut r1 = vec![0x23];
    r1.extend(&b.id);
    s.set(0, r1, rho_n(1).to_vec());
    let mut r2 = vec![0x23];
    r2.extend(k4.pk);
    s.set(1, r2, rho_n(2).to_vec());
    let out = handle_request(&s.psbt(), &opts(&b)).unwrap();
    let p = parse(&out);
    // verify the second signature independently: input 1 is P2WPKH of key 4
    let mut sk = vec![0x02];
    sk.extend(k4.pk);
    let v = map_get(&p.inputs[1], &sk).unwrap().clone();
    let t = &s.t;
    let m = sh_bip143(t, 1, &p2pkh(&hash160(&k4.pk)), AMT1, 1);
    let lr = v[3] as usize;
    let strip = |x: &[u8]| -> [u8; 32] {
        let x = if x[0] == 0 { &x[1..] } else { x };
        let mut o = [0u8; 32];
        o[32 - x.len()..].copy_from_slice(x);
        o
    };
    let r = sc_from(&strip(&v[4..4 + lr])).unwrap();
    let ls = v[5 + lr] as usize;
    let sv = sc_from(&strip(&v[6 + lr..6 + lr + ls])).unwrap();
    assert!(ecdsa_verify(&k4.pk, &m, &r, &sv));
}

#[test]
fn finalized_inputs_fail() {
    for s in [Spend::P2wpkh, Spend::TapKey, Spend::P2pkh] {
        for f in [0x07u8, 0x08] {
            let mut b = build(s, 0, None);
            b.spec.set(0, vec![f], vec![1, 2, 3]);
            both_fail(&b, &b.spec);
        }
    }
    // a finalized input without a pair is not constrained
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(1, vec![0x07], vec![0x00]);
    sign_ok(&b);
}

#[test]
fn missing_or_mismatched_utxo_data_fails() {
    for s in ALL_SPENDS {
        let mut b = build(s, 0, None);
        b.spec.remove(0, &[0x00]);
        b.spec.remove(0, &[0x01]);
        both_fail(&b, &b.spec);
    }
    // legacy needs the non-witness UTXO
    for s in [Spend::P2pkh, Spend::P2shLegacy] {
        let mut b = build(s, 0, None);
        let spk = b.prevs[0].1.clone();
        b.spec.remove(0, &[0x00]);
        b.spec.set(0, vec![0x01], wu(AMT0, &spk));
        both_fail(&b, &b.spec);
    }
    // non-witness UTXO that does not hash to the previous txid
    let mut b = build(Spend::P2pkh, 0, None);
    let spk = b.prevs[0].1.clone();
    let (other, _) = fund_tx(&spk, AMT0, 0x99);
    b.spec.set(0, vec![0x00], other);
    both_fail(&b, &b.spec);
    // output index out of range
    let mut b = build(Spend::P2pkh, 0, None);
    b.spec.t.ins[0].vout = 3;
    both_fail(&b, &b.spec);
    // two UTXO fields that disagree
    let mut b = build(Spend::P2wpkh, 0, None);
    let spk = b.prevs[0].1.clone();
    let (raw, id) = fund_tx(&spk, AMT0 + 5, 0x33);
    b.spec.set(0, vec![0x00], raw);
    b.spec.t.ins[0].txid = id;
    both_fail(&b, &b.spec);
    // two UTXO fields that agree are fine
    let mut b = build(Spend::P2wpkh, 0, None);
    let spk = b.prevs[0].1.clone();
    let (raw, id) = fund_tx(&spk, AMT0, 0x33);
    b.spec.set(0, vec![0x00], raw);
    b.spec.t.ins[0].txid = id;
    sign_ok(&b);
    // witness UTXO with trailing garbage
    let mut b = build(Spend::P2wpkh, 0, None);
    let mut w = b.spec.get(0, &[0x01]).unwrap();
    w.push(0);
    b.spec.set(0, vec![0x01], w);
    both_fail(&b, &b.spec);
}

#[test]
fn script_data_mismatch_fails() {
    for (s, ty) in [
        (Spend::P2shP2wpkh, 0x04u8),
        (Spend::P2wsh1, 0x05),
        (Spend::P2wshMulti, 0x05),
        (Spend::P2shP2wsh, 0x04),
        (Spend::P2shP2wsh, 0x05),
        (Spend::P2shLegacy, 0x04),
    ] {
        let mut b = build(s, 0, None);
        let mut v = b.spec.get(0, &[ty]).unwrap();
        let n = v.len();
        v[n - 1] ^= 1;
        b.spec.set(0, vec![ty], v);
        both_fail(&b, &b.spec);
        let mut b = build(s, 0, None);
        b.spec.remove(0, &[ty]);
        both_fail(&b, &b.spec);
    }
    // P2PKH / P2WPKH whose script does not belong to the key
    let mut b = build(Spend::P2wpkh, 0, None);
    let spk = p2wpkh(&hash160(&key(30).pk));
    b.spec.set(0, vec![0x01], wu(AMT0, &spk));
    both_fail(&b, &b.spec);
    // unknown output script
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(0, vec![0x01], wu(AMT0, &[0x6a]));
    both_fail(&b, &b.spec);
}

#[test]
fn signer_without_the_key_fails() {
    let b = build(Spend::P2wpkh, 0, None);
    let other = signer_opts(&[&key(50)], false);
    assert!(handle_request(&req1(&b, &rho_n(1)).psbt(), &other).is_err());
    assert!(handle_request(&req2(&b, &rho_n(1)).psbt(), &other).is_err());
    // the other parity of the same x is a different public key
    let mut b = build(Spend::P2wpkh, 0, None);
    let mut neg = b.dev.pk;
    neg[0] ^= 1;
    b.id = neg.to_vec();
    let spk = p2wpkh(&hash160(&neg));
    b.spec.set(0, vec![0x01], wu(AMT0, &spk));
    both_fail(&b, &b.spec);
}

#[test]
fn key_lookup_does_not_depend_on_order() {
    let b = build(Spend::P2wshMulti, 2, None);
    let ks = [key(9), key(8), b.dev.clone(), key(4), key(7)];
    let refs: Vec<&Key> = ks.iter().collect();
    let o = signer_opts(&refs, false);
    let rho = rho_n(1);
    assert!(handle_request(&req2(&b, &rho).psbt(), &o).is_ok());
    let mut rev = refs.clone();
    rev.reverse();
    let o2 = signer_opts(&rev, false);
    assert_eq!(handle_request(&req2(&b, &rho).psbt(), &o).unwrap(), handle_request(&req2(&b, &rho).psbt(), &o2).unwrap());
}

#[test]
fn invalid_sighash_types_fail() {
    for (s, bad) in [
        (Spend::P2wpkh, vec![4u32, 0x84, 0x100, 0x1_0001, 0, 0x80, 0xff]),
        (Spend::TapKey, vec![4u32, 0x84, 0x100, 0x80, 0xff]),
        (Spend::TapScript, vec![5u32, 0x85]),
        (Spend::P2pkh, vec![0u32]),
    ] {
        for h in bad {
            let mut b = build(s, 0, Some(1));
            b.spec.set(0, vec![0x03], h.to_le_bytes().to_vec());
            both_fail(&b, &b.spec);
        }
    }
    // wrong length
    let mut b = build(Spend::P2wpkh, 0, Some(1));
    b.spec.set(0, vec![0x03], vec![1, 0]);
    both_fail(&b, &b.spec);
    b.spec.set(0, vec![0x03], vec![1, 0, 0, 0, 0]);
    both_fail(&b, &b.spec);
    // present zero is SIGHASH_DEFAULT for BIP340
    sign_ok(&build(Spend::TapKey, 0, Some(0)));
    // an invalid type on an input without a pair is not examined
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(1, vec![0x03], 0x55u32.to_le_bytes().to_vec());
    sign_ok(&b);
}

#[test]
fn sighash_single_without_matching_output_fails() {
    for s in ALL_SPENDS {
        for h in [3u32, 0x83] {
            let mut b = build(s, 0, Some(h));
            b.spec.t.outs.clear();
            b.spec.outs.clear();
            both_fail(&b, &b.spec);
        }
    }
    // SINGLE, matching output exists
    sign_ok(&build(Spend::P2wpkh, 0, Some(3)));
    // ALL with no outputs is fine
    let mut b = build(Spend::P2wpkh, 0, Some(1));
    b.spec.t.outs.clear();
    b.spec.outs.clear();
    sign_ok(&b);
}

#[test]
fn outputs_exceeding_inputs_fail() {
    for s in [Spend::P2wpkh, Spend::P2pkh, Spend::TapKey] {
        let mut b = build(s, 0, None);
        b.spec.t.outs[0].amount = 200_000;
        both_fail(&b, &b.spec);
        // exactly equal is allowed (zero fee)
        let mut b = build(s, 0, None);
        b.spec.t.outs[0].amount = 150_000 - 70_000;
        sign_ok(&b);
    }
    // not every amount known: no check, still signs
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.remove(1, &[0x01]);
    b.spec.t.outs[0].amount = 900_000;
    sign_ok(&b);
}

#[test]
fn taproot_needs_all_prevouts_unless_anyonecanpay() {
    for s in [Spend::TapKey, Spend::TapScript] {
        let mut b = build(s, 0, None);
        b.spec.remove(1, &[0x01]);
        both_fail(&b, &b.spec);
        let mut b = build(s, 0, Some(0x81));
        b.spec.remove(1, &[0x01]);
        sign_ok(&b);
    }
}

#[test]
fn existing_signature_fails() {
    let b0 = build(Spend::P2wpkh, 0, None);
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(0, b0.sig_key(), vec![0x30; 9]);
    both_fail(&b, &b.spec);
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.set(0, vec![0x13], vec![1; 64]);
    both_fail(&b, &b.spec);
    let mut b = build(Spend::TapScript, 0, None);
    let k = b.sig_key();
    b.spec.set(0, k, vec![1; 64]);
    both_fail(&b, &b.spec);
}

#[test]
fn multisig_forms() {
    // device key at each position of a 3-key multisig and of a 16-key multisig
    for pos in 0..3 {
        let dev = key(1);
        let mut ks = vec![key(11).pk, key(12).pk];
        ks.insert(pos, dev.pk);
        let ws = multisig(&ks, 2);
        sign_ok(&rewrap_wsh(ws));
    }
    let dev = key(1);
    let mut ks: Vec<[u8; 33]> = (20..35).map(|i| key(i).pk).collect();
    ks.push(dev.pk);
    sign_ok(&rewrap_wsh(multisig(&ks, 16)));
    sign_ok(&rewrap_wsh(multisig(&ks, 1)));
    // listed twice
    let ws = multisig(&[dev.pk, key(12).pk, dev.pk], 2);
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    // m > n, m = 0, n mismatch, 17 keys, invalid key
    let mut ws = multisig(&[dev.pk, key(12).pk], 1);
    ws[0] = 0x53;
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    let mut ws = multisig(&[dev.pk, key(12).pk], 1);
    ws[0] = 0x00;
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    let mut ws = multisig(&[dev.pk, key(12).pk], 1);
    let n = ws.len();
    ws[n - 2] = 0x53;
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    let mut ks: Vec<[u8; 33]> = (20..36).map(|i| key(i).pk).collect();
    ks.push(dev.pk);
    let mut ws = vec![0x51];
    for k in &ks {
        ws.extend(push(k));
    }
    ws.push(0x60);
    ws.push(0xae);
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    let mut bad = dev.pk;
    bad[0] = 0x05;
    let mut ws = multisig(&[dev.pk, key(12).pk], 1);
    ws[1 + 1] = 0x05;
    let _ = bad;
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
}

/// P2WSH single-input fixture around an arbitrary witness script.
fn rewrap_wsh(ws: Vec<u8>) -> Built {
    let mut b = build(Spend::P2wsh1, 0, None);
    let spk = p2wsh(&sha256(&ws));
    b.spec.set(0, vec![0x05], ws.clone());
    b.spec.set(0, vec![0x01], wu(AMT0, &spk));
    b.prevs[0].1 = spk;
    b.code = ws;
    b
}

#[test]
fn script_shapes() {
    let dev = key(1);
    let k2 = key(2);
    // optional generic form: key before CHECKSIGVERIFY
    let mut ws = push(&dev.pk);
    ws.extend([0xad, 0x51]);
    sign_ok(&rewrap_wsh(ws));
    // key before CHECKSIG inside a larger script
    let mut ws = push(&k2.pk);
    ws.extend([0xad]);
    ws.extend(push(&dev.pk));
    ws.extend([0xac]);
    sign_ok(&rewrap_wsh(ws));
    // key not before a signature opcode
    let mut ws = push(&dev.pk);
    ws.extend([0x75, 0x51]);
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    // key in OP_PUSHDATA1 form does not count
    let mut ws = vec![0x4c, 33];
    ws.extend(dev.pk);
    ws.push(0xac);
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    // two signature opcodes with the device key
    let mut ws = push(&dev.pk);
    ws.push(0xad);
    ws.extend(push(&dev.pk));
    ws.push(0xac);
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    // OP_CODESEPARATOR as an opcode fails, inside data it does not
    let mut ws = vec![0xab];
    ws.extend(push(&dev.pk));
    ws.push(0xac);
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
    let mut ws = push(&[0xab, 0xab]);
    ws.push(0x75);
    ws.extend(push(&dev.pk));
    ws.push(0xac);
    sign_ok(&rewrap_wsh(ws));
    // key not in script at all
    let b = rewrap_wsh(checksig_script(&k2.pk));
    both_fail(&b, &b.spec);
    // truncated push
    let mut ws = push(&dev.pk);
    ws.push(0xac);
    ws.push(0x05);
    let b = rewrap_wsh(ws);
    both_fail(&b, &b.spec);
}

#[test]
fn legacy_p2sh_and_nested_codeseparator() {
    let dev = key(1);
    let mut rs = vec![0xab];
    rs.extend(checksig_script(&dev.pk));
    let mut b = build(Spend::P2shLegacy, 0, None);
    let spk = p2sh(&hash160(&rs));
    let (raw, id) = fund_tx(&spk, AMT0, 0x11);
    b.spec.set(0, vec![0x04], rs.clone());
    b.spec.set(0, vec![0x00], raw);
    b.spec.t.ins[0].txid = id;
    both_fail(&b, &b.spec);
}

#[test]
fn uncompressed_derivation_records() {
    let dev = key(1);
    let unc = enc(&dev.p, false);
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(0, { let mut k = vec![0x06]; k.extend(&unc); k }, vec![0; 8]);
    both_fail(&b, &b.spec);
    // uncompressed form of a key that is not a device key is not examined
    let mut b = build(Spend::P2wpkh, 0, None);
    let other = enc(&key(60).p, false);
    b.spec.set(0, { let mut k = vec![0x06]; k.extend(&other); k }, vec![0; 8]);
    sign_ok(&b);
    // on an input without a pair it is not examined either
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(1, { let mut k = vec![0x06]; k.extend(&unc); k }, vec![0; 8]);
    sign_ok(&b);
    // Taproot input with the uncompressed device key in a (non-Taproot) derivation record
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.set(0, { let mut k = vec![0x06]; k.extend(&unc); k }, vec![0; 8]);
    both_fail(&b, &b.spec);
}

#[test]
fn musig2_participant_fields() {
    let dev = key(1);
    let other = key(61);
    let agg = key(62);
    let mut flip = dev.pk;
    flip[0] ^= 1;
    for (list, should_fail) in [
        (vec![other.pk, dev.pk], true),
        (vec![other.pk, flip], true), // either parity form
        (vec![other.pk, key(63).pk], false),
    ] {
        for s in [Spend::TapKey, Spend::TapScript] {
            let mut b = build(s, 0, None);
            let v: Vec<u8> = list.iter().flat_map(|k| k.to_vec()).collect();
            b.spec.set(0, { let mut k = vec![0x1a]; k.extend(agg.pk); k }, v);
            if should_fail {
                both_fail(&b, &b.spec);
            } else {
                sign_ok(&b);
            }
        }
    }
    // internal key is the aggregate key
    let mut b = build(Spend::TapKey, 0, None);
    let v: Vec<u8> = [other.pk, key(63).pk].iter().flat_map(|k| k.to_vec()).collect();
    let mut aggkey = vec![0x1a, 0x02];
    aggkey.extend(dev.x);
    b.spec.set(0, aggkey, v);
    both_fail(&b, &b.spec);
    // ECDSA input: the field is not examined
    let mut b = build(Spend::P2wpkh, 0, None);
    let v: Vec<u8> = [other.pk, dev.pk].iter().flat_map(|k| k.to_vec()).collect();
    b.spec.set(0, { let mut k = vec![0x1a]; k.extend(agg.pk); k }, v);
    sign_ok(&b);
}

#[test]
fn taproot_key_path_rules() {
    // identifier differs from a present internal key
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.set(0, vec![0x17], key(70).x.to_vec());
    both_fail(&b, &b.spec);
    // missing internal key: identifier used
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.remove(0, &[0x17]);
    sign_ok(&b);
    // output key mismatch (wrong merkle root)
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.set(0, vec![0x18], vec![5u8; 32]);
    both_fail(&b, &b.spec);
    // bad merkle root length
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.set(0, vec![0x18], vec![5u8; 31]);
    both_fail(&b, &b.spec);
    // key path with a merkle root (tweak with root)
    let dev = key(1);
    let root = [0x42u8; 32];
    let (q, _) = tap_output(&dev.x, Some(&root));
    let spk = p2tr(&xonly(&q));
    let mut b = build(Spend::TapKey, 0, None);
    b.spec.set(0, vec![0x18], root.to_vec());
    b.spec.set(0, vec![0x01], wu(AMT0, &spk));
    b.prevs[0].1 = spk;
    // pk for verification uses the tweaked key; build expects no root, so check manually
    let rho = rho_n(3);
    let (r0, resp) = exchange(&b, &rho, &opts(&b)).unwrap();
    let v = map_get(&resp.inputs[0], &[0x13]).unwrap().clone();
    let m = sh_taproot(&b.spec.t, 0, &b.prevs, 0, None);
    assert!(schnorr_verify(&xonly(&q), &m, &v));
    let _ = r0;
    // key-path and script-path pair on one input
    let b = build(Spend::TapKey, 0, None);
    let mut s = b.spec.clone();
    s.set(0, { let mut k = vec![0x21]; k.extend(&b.id); k }, vec![0; 32]);
    let mut lid = b.id.clone();
    lid.extend([7u8; 32]);
    s.set(0, { let mut k = vec![0x21]; k.extend(&lid); k }, vec![0; 32]);
    assert!(handle_request(&s.psbt(), &opts(&b)).is_err());
    // x-only key identifier whose parity is flipped in the PSBT still maps to the same key
    let b = build(Spend::TapKey, 0, None);
    assert!(handle_request(&req2(&b, &rho_n(1)).psbt(), &signer_opts(&[&key_with_parity(true, 200), &b.dev], false)).is_ok());
}

fn tap_script_fixture(script: Vec<u8>, ver: u8, path_len: usize) -> Built {
    let mut b = build(Spend::TapScript, 0, None);
    let ik = key(5);
    let l = tap_leaf(ver, &script);
    let mut node = l;
    let mut control_tail = Vec::new();
    for i in 0..path_len {
        let sib = sha256(&[i as u8, 0xee]);
        node = tap_branch(&node, &sib);
        control_tail.extend(sib);
    }
    let (q, _) = tap_output(&ik.x, Some(&node));
    let spk = p2tr(&xonly(&q));
    let mut control = vec![(ver & 0xfe) | is_odd(&q) as u8];
    control.extend(ik.x);
    control.extend(control_tail);
    b.spec.ins[0].retain(|(k, _)| k[0] != 0x15 && k[0] != 0x16);
    let mut val = script.clone();
    val.push(ver);
    b.spec.ins[0].push(kv(0x15, &control, &val));
    let mut dv = compact(1);
    dv.extend(l);
    dv.extend([0; 8]);
    b.spec.ins[0].push(kv(0x16, &b.dev.x, &dv));
    b.spec.set(0, vec![0x01], wu(AMT0, &spk));
    b.prevs[0].1 = spk;
    let mut id = b.dev.x.to_vec();
    id.extend(l);
    b.id = id;
    b.leaf = Some(l);
    b.code = script;
    b
}

#[test]
fn taproot_script_path_rules() {
    let dev = key(1);
    let k2 = key(2);
    let good = checksig_script_x(&dev.x);
    sign_ok(&tap_script_fixture(good.clone(), 0xc0, 0));
    sign_ok(&tap_script_fixture(good.clone(), 0xc0, 3));
    sign_ok(&tap_script_fixture(good.clone(), 0xc0, 128));
    // 129 path elements
    let b = tap_script_fixture(good.clone(), 0xc0, 129);
    both_fail(&b, &b.spec);
    // leaf version other than 0xc0
    let b = tap_script_fixture(good.clone(), 0xc2, 1);
    both_fail(&b, &b.spec);
    // CHECKSIGVERIFY and CHECKSIGADD forms
    let mut s = push(&dev.x);
    s.push(0xad);
    s.push(0x51);
    sign_ok(&tap_script_fixture(s, 0xc0, 1));
    let mut s = vec![0x00];
    s.extend(push(&dev.x));
    s.push(0xba);
    s.push(0x51);
    s.push(0x87);
    sign_ok(&tap_script_fixture(s, 0xc0, 1));
    // other keys in the leaf do not count
    let mut s = checksig_script_x(&k2.x);
    s.push(0x69);
    s.extend(checksig_script_x(&dev.x));
    sign_ok(&tap_script_fixture(s, 0xc0, 1));
    // key twice before signature opcodes
    let mut s = checksig_script_x(&dev.x);
    s.push(0x69);
    s.extend(checksig_script_x(&dev.x));
    let b = tap_script_fixture(s, 0xc0, 1);
    both_fail(&b, &b.spec);
    // key present but not before a signature opcode
    let mut s = push(&dev.x);
    s.push(0x75);
    s.push(0x51);
    let b = tap_script_fixture(s, 0xc0, 1);
    both_fail(&b, &b.spec);
    // key as OP_PUSHDATA1
    let mut s = vec![0x4c, 32];
    s.extend(dev.x);
    s.push(0xac);
    let b = tap_script_fixture(s, 0xc0, 1);
    both_fail(&b, &b.spec);
    // OP_SUCCESS anywhere
    for op in [80u8, 98, 126, 187, 254] {
        let mut s = checksig_script_x(&dev.x);
        s.push(op);
        let b = tap_script_fixture(s, 0xc0, 1);
        both_fail(&b, &b.spec);
    }
    // OP_CODESEPARATOR
    let mut s = vec![0xab];
    s.extend(checksig_script_x(&dev.x));
    let b = tap_script_fixture(s, 0xc0, 1);
    both_fail(&b, &b.spec);
    // two entries matching the leaf hash (second control block)
    let mut b = tap_script_fixture(good.clone(), 0xc0, 1);
    let (k, v) = b.spec.ins[0].iter().find(|(k, _)| k[0] == 0x15).cloned().unwrap();
    let mut k2c = k.clone();
    k2c[1] ^= 0; // same type; change the parity bit to make a distinct key
    k2c[1] ^= 1;
    b.spec.ins[0].push((k2c, v));
    both_fail(&b, &b.spec);
    // no entry for the leaf
    let mut b = tap_script_fixture(good.clone(), 0xc0, 1);
    b.spec.ins[0].retain(|(k, _)| k[0] != 0x15);
    both_fail(&b, &b.spec);
    // control block that computes the wrong output key (flip a path byte)
    let mut b = tap_script_fixture(good.clone(), 0xc0, 2);
    let (mut k, v) = b.spec.ins[0].iter().find(|(k, _)| k[0] == 0x15).cloned().unwrap();
    b.spec.ins[0].retain(|(k, _)| k[0] != 0x15);
    let n = k.len();
    k[n - 1] ^= 1;
    b.spec.ins[0].push((k, v));
    // the leaf hash still matches but the control block is wrong
    both_fail(&b, &b.spec);
    // wrong parity bit
    let mut b = tap_script_fixture(good.clone(), 0xc0, 1);
    let (mut k, v) = b.spec.ins[0].iter().find(|(k, _)| k[0] == 0x15).cloned().unwrap();
    b.spec.ins[0].retain(|(k, _)| k[0] != 0x15);
    k[1] ^= 1;
    b.spec.ins[0].push((k, v));
    both_fail(&b, &b.spec);
    // truncated control block
    let mut b = tap_script_fixture(good.clone(), 0xc0, 1);
    let (mut k, v) = b.spec.ins[0].iter().find(|(k, _)| k[0] == 0x15).cloned().unwrap();
    b.spec.ins[0].retain(|(k, _)| k[0] != 0x15);
    k.pop();
    b.spec.ins[0].push((k, v));
    both_fail(&b, &b.spec);
    // an unrelated second leaf entry is ignored
    let mut b = tap_script_fixture(good.clone(), 0xc0, 1);
    let mut ctl = vec![0xc0];
    ctl.extend([3u8; 32]);
    let mut val = vec![0x51];
    val.push(0xc0);
    b.spec.ins[0].push(kv(0x15, &ctl, &val));
    sign_ok(&b);
    // script path: key identifier on a key-path output with no such leaf
    let mut b = tap_script_fixture(good, 0xc0, 1);
    b.id[40] ^= 1;
    both_fail(&b, &b.spec);
}

#[test]
fn unknown_psbt_version_fails() {
    let b = build(Spend::P2wpkh, 2, None);
    let mut s = req2(&b, &rho_n(1));
    s.glob.push(kv(0xfb, &[], &1u32.to_le_bytes())); // duplicate of the version key made by psbt(): malformed
    assert!(handle_request(&s.psbt(), &opts(&b)).is_err());
    let raw = req2(&b, &rho_n(1)).psbt();
    let mut p = Psbt::parse(&raw).unwrap();
    for e in p.global.iter_mut() {
        if e.0 == vec![0xfb] {
            e.1 = 3u32.to_le_bytes().to_vec();
        }
    }
    assert!(handle_request(&p.serialize(), &opts(&b)).is_err());
}

#[test]
fn tx_modifiable_updates() {
    let rho = rho_n(1);
    // (initial flags or None, sighash, expected)
    let cases: Vec<(Option<u8>, u32, Option<u8>)> = vec![
        (Some(0x07), 1, Some(0x04)),
        (Some(0x07), 0x81, Some(0x05)),
        (Some(0x07), 2, Some(0x06)),
        (Some(0x07), 0x82, Some(0x07)),
        (Some(0x07), 3, Some(0x04)),
        (Some(0x03), 3, Some(0x04)),
        (Some(0x03), 0x83, Some(0x05)),
        (Some(0x18), 1, Some(0x18)),
        (Some(0x1f), 3, Some(0x1c)),
        (None, 1, None),
        (None, 2, None),
        (None, 3, Some(0x04)),
        (None, 0x83, Some(0x04)),
        (Some(0x00), 1, Some(0x00)),
    ];
    for (init, h, want) in cases {
        let mut b = build(Spend::P2wpkh, 2, Some(h));
        if let Some(f) = init {
            b.spec.glob.push(kv(0x06, &[], &[f]));
        }
        let (_, resp) = exchange(&b, &rho, &opts(&b)).unwrap();
        let got = map_get(&resp.global, &[0x06]).map(|v| v[0]);
        assert_eq!(got, want, "init {init:?} ht {h:#x}");
    }
    // DEFAULT counts as ALL
    let mut b = build(Spend::TapKey, 2, None);
    b.spec.glob.push(kv(0x06, &[], &[0x07]));
    let (_, resp) = exchange(&b, &rho, &opts(&b)).unwrap();
    assert_eq!(map_get(&resp.global, &[0x06]).unwrap()[0], 0x04);
    // version 0 has no such field and gets none
    let b = build(Spend::P2wpkh, 0, Some(3));
    let (_, resp) = exchange(&b, &rho, &opts(&b)).unwrap();
    assert!(map_get(&resp.global, &[0x06]).is_none());
}

#[test]
fn tx_modifiable_cumulative_over_pairs() {
    // two pairs: SIGHASH_ALL|ACP on input 0 (clears outputs flag), SIGHASH_SINGLE on input 1
    let mut b = build(Spend::P2wpkh, 2, Some(0x81));
    b.spec.glob.push(kv(0x06, &[], &[0x07]));
    b.spec.set(1, vec![0x03], 3u32.to_le_bytes().to_vec());
    let k4 = key(4);
    let mut s = b.spec.clone();
    s.set(0, { let mut k = vec![0x23]; k.extend(&b.id); k }, rho_n(1).to_vec());
    s.set(1, { let mut k = vec![0x23]; k.extend(k4.pk); k }, rho_n(2).to_vec());
    let out = parse(&handle_request(&s.psbt(), &opts(&b)).unwrap());
    // 0x07: ALL|ACP keeps inputs flag, clears outputs flag -> 0x05; SINGLE clears inputs, sets bit 2 -> 0x04
    assert_eq!(map_get(&out.global, &[0x06]).unwrap()[0], 0x04);
}

#[test]
fn v2_locktime_rules() {
    let rho = rho_n(1);
    let run = |b: &Built| {
        let (r0, resp) = exchange(b, &rho, &opts(b)).unwrap();
        check_signature(b, &rho, &r0, &resp);
    };
    // required height locktimes: the maximum is used
    let mut b = build(Spend::P2wpkh, 2, None);
    b.spec.t.lock = 700;
    b.spec.set(0, vec![0x12], 500u32.to_le_bytes().to_vec());
    b.spec.set(1, vec![0x12], 700u32.to_le_bytes().to_vec());
    run(&b);
    // required time locktimes
    let mut b = build(Spend::P2wpkh, 2, None);
    b.spec.t.lock = 600_000_000;
    b.spec.set(0, vec![0x11], 550_000_000u32.to_le_bytes().to_vec());
    b.spec.set(1, vec![0x11], 600_000_000u32.to_le_bytes().to_vec());
    run(&b);
    // both kinds on every input: height wins
    let mut b = build(Spend::P2wpkh, 2, None);
    b.spec.t.lock = 20;
    for (i, h) in [(0usize, 10u32), (1, 20)] {
        b.spec.set(i, vec![0x12], h.to_le_bytes().to_vec());
        b.spec.set(i, vec![0x11], 600_000_000u32.to_le_bytes().to_vec());
    }
    run(&b);
    // an input without any requirement does not constrain the type
    let mut b = build(Spend::P2wpkh, 2, None);
    b.spec.t.lock = 33;
    b.spec.set(0, vec![0x12], 33u32.to_le_bytes().to_vec());
    run(&b);
    // conflicting types: one input height only, another time only -> failure
    let mut b = build(Spend::P2wpkh, 2, None);
    b.spec.set(0, vec![0x12], 500u32.to_le_bytes().to_vec());
    b.spec.set(1, vec![0x11], 600_000_000u32.to_le_bytes().to_vec());
    both_fail(&b, &b.spec);
    // out of range values
    let mut b = build(Spend::P2wpkh, 2, None);
    b.spec.set(0, vec![0x12], 600_000_000u32.to_le_bytes().to_vec());
    both_fail(&b, &b.spec);
    // fallback locktime when no input requires one
    let mut b = build(Spend::P2wpkh, 2, None);
    b.spec.t.lock = 1234;
    run(&b);
}

#[test]
fn ordering_of_maps_does_not_matter() {
    let b = build(Spend::P2wsh1, 0, None);
    let rho = rho_n(1);
    let mut s = req2(&b, &rho);
    s.ins[0].reverse();
    s.ins[1].reverse();
    let out = handle_request(&s.psbt(), &opts(&b)).unwrap();
    let p = parse(&out);
    assert!(map_get(&p.inputs[0], &b.sig_key()).is_some());
}

#[test]
fn ecdsa_signature_is_low_s_and_strict_der() {
    for n in 0..40u8 {
        let b = build(Spend::P2wpkh, 0, None);
        let rho = rho_n(n);
        let (r0, resp) = exchange(&b, &rho, &opts(&b)).unwrap();
        check_signature(&b, &rho, &r0, &resp);
        let v = map_get(&resp.inputs[0], &b.sig_key()).unwrap().clone();
        assert!(aexf::ae::der_parse_strict(&v).is_some());
    }
}

#[test]
fn rho_changes_nonce_and_message_changes_nonce() {
    let b = build(Spend::P2wpkh, 0, None);
    let o = opts(&b);
    let a = handle_request(&req1(&b, &rho_n(1)).psbt(), &o).unwrap();
    let c = handle_request(&req1(&b, &rho_n(2)).psbt(), &o).unwrap();
    assert_ne!(a, c);
    let mut b2 = build(Spend::P2wpkh, 0, None);
    b2.spec.t.outs[0].amount = 59_999;
    let d = handle_request(&req1(&b2, &rho_n(1)).psbt(), &o).unwrap();
    assert_ne!(a, d);
}

#[test]
fn changed_data_between_passes_is_not_signed_silently() {
    // The signer is stateless: a different transaction in pass two gives a signature over that
    // transaction, and the nonce commitment from pass one then no longer matches.
    let b = build(Spend::P2wpkh, 0, None);
    let rho = rho_n(1);
    let (r0, _) = exchange(&b, &rho, &opts(&b)).unwrap();
    let mut b2 = build(Spend::P2wpkh, 0, None);
    b2.spec.t.outs[0].amount = 59_000;
    let s = with_field(&req2(&b2, &rho), 0, 0x22, &b2.id, &r0);
    assert!(handle_request(&s.psbt(), &opts(&b2)).is_err());
}

fn purpose_value(p: u32) -> Vec<u8> {
    let mut v = vec![1, 2, 3, 4];
    v.extend((p | 0x8000_0000).to_le_bytes());
    v.extend(1u32.to_le_bytes());
    v
}

#[test]
fn derivation_purpose_must_match_the_scheme() {
    // ECDSA pair with the Taproot purpose
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(0, { let mut k = vec![0x06]; k.extend(b.dev.pk); k }, purpose_value(86));
    both_fail(&b, &b.spec);
    // ECDSA purposes pass, whatever the single-sig script type
    for p in [44u32, 49, 84, 45, 48] {
        let mut b = build(Spend::P2wpkh, 0, None);
        b.spec.set(0, { let mut k = vec![0x06]; k.extend(b.dev.pk); k }, purpose_value(p));
        sign_ok(&b);
    }
    // Taproot key path with an ECDSA purpose
    for p in [44u32, 49, 84] {
        let mut b = build(Spend::TapKey, 0, None);
        let mut v = compact(0);
        v.extend(purpose_value(p));
        b.spec.set(0, { let mut k = vec![0x16]; k.extend(b.dev.x); k }, v);
        both_fail(&b, &b.spec);
    }
    let mut b = build(Spend::TapKey, 0, None);
    let mut v = compact(0);
    v.extend(purpose_value(86));
    b.spec.set(0, { let mut k = vec![0x16]; k.extend(b.dev.x); k }, v);
    sign_ok(&b);
    // Taproot script path with an ECDSA purpose
    let mut b = build(Spend::TapScript, 0, None);
    let mut v = compact(1);
    v.extend(b.leaf.unwrap());
    v.extend(purpose_value(84));
    b.spec.set(0, { let mut k = vec![0x16]; k.extend(b.dev.x); k }, v);
    both_fail(&b, &b.spec);
    // non-hardened first element: nothing to tell
    let mut b = build(Spend::P2wpkh, 0, None);
    b.spec.set(0, { let mut k = vec![0x06]; k.extend(b.dev.pk); k }, vec![1, 2, 3, 4, 86, 0, 0, 0]);
    sign_ok(&b);
}
