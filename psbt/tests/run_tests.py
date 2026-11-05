"""Run the suite: python3 -B -I psbt/tests/run_tests.py [--no-regtest]"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

mods = ["test_math_codec", "test_known_answers", "test_positive", "test_signer", "test_host_response", "test_lifecycle", "test_regressions", "test_bip_psbt_cases", "test_outside_sighash"]
if "--no-regtest" not in sys.argv:
    mods.append("test_regtest")
suite = unittest.defaultTestLoader.loadTestsFromNames(mods)
res = unittest.TextTestRunner(verbosity=1).run(suite)
sys.exit(0 if res.wasSuccessful() else 1)
