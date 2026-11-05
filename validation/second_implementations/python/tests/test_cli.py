import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import indep as I
import tb


class TestSignerCli(unittest.TestCase):
    def test_success_prints_one_line_and_exits_zero(self):
        c = tb.make([{"form": "p2wpkh"}])
        rc, out, err = tb.run_signer(tb.req1(c), c.dev_sks)
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.splitlines()), 1)
        bytes.fromhex(out)
        self.assertEqual(out, out.lower())

    def test_failure_prints_nothing_and_exits_three(self):
        c = tb.make([{"form": "p2wpkh"}])
        for h in (tb.psbt_hex(c), "zz", "", tb.req2(c)[:-4]):
            args = [sys.executable, "-B", tb.MAIN, "signer"] + tb.sks_args(c.dev_sks)
            r = subprocess.run(args, input=h + "\n", capture_output=True, text=True)
            self.assertEqual(r.returncode, 3)
            self.assertEqual(r.stdout, "")

    def test_decline(self):
        c = tb.make([{"form": "p2wpkh"}])
        rc, out, err = tb.run_signer(tb.req2(c), c.dev_sks, decline=True)
        self.assertEqual((rc, out), (3, ""))
        rc, out, err = tb.run_signer(tb.req1(c), c.dev_sks, decline=True)
        self.assertEqual(rc, 0)
        rc, out, err = tb.run_signer(tb.req2(c), c.dev_sks)
        self.assertEqual(rc, 0)
        tb.check_result(c, out)

    def test_several_secret_keys(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "tr-key", "key": 1}, {"form": "tr-script", "key": 2}])
        rc, out, err = tb.run_signer(tb.req2(c), [tb.DEV[0], tb.DEV[1], tb.DEV[2], tb.DEV[3]])
        self.assertEqual(rc, 0)
        tb.check_result(c, out)
        rc, out, err = tb.run_signer(tb.req2(c), [tb.DEV[0], tb.DEV[1]])
        self.assertEqual((rc, out), (3, ""))

    def test_secret_key_given_as_other_parity_still_works(self):
        # sk and n - sk are the same x-only key
        c = tb.make([{"form": "tr-script"}])
        rc, out, err = tb.run_signer(tb.req2(c), [I.n - tb.DEV[0]])
        self.assertEqual(rc, 0)
        tb.check_result(c, out)


class TestHostCli(unittest.TestCase):
    def test_output_shape(self):
        c = tb.make([{"form": "p2wpkh"}])
        store = os.path.join(tb.SCRATCH, "cli_shape.json")
        if os.path.exists(store):
            os.remove(store)
        r = tb.run_host(c, [tb.pub(tb.DEV[0])], store, device=tb.inproc_device(c.dev_sks), rhos=tb.rho_args(c))
        self.assertEqual([l.split()[0] for l in r.lines], ["REQUEST", "REQUEST", "COUNT", "RESULT"])
        self.assertEqual(r.rc, 0)
        self.assertEqual(r.lines[2], "COUNT 0")

    def test_store_path_may_not_exist_and_is_created(self):
        c = tb.make([{"form": "p2wpkh"}])
        d = os.path.join(tb.SCRATCH, "newdir_cli")
        store = os.path.join(d, "s.json")
        if os.path.exists(store):
            os.remove(store)
        r = tb.run_host(c, [tb.pub(tb.DEV[0])], store, device=tb.inproc_device(c.dev_sks), rhos=tb.rho_args(c))
        self.assertEqual(r.rc, 0)
        self.assertTrue(os.path.exists(store))

    def test_run_file(self):
        with open(os.path.join(tb.ROOT, "RUN")) as f:
            self.assertEqual(f.read().strip(), "python3 -B main.py")


if __name__ == "__main__":
    unittest.main()
