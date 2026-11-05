"""Bitcoin Core regtest helper: private datadir under psbt/.work, localhost only."""
import json
import os
import pathlib
import shutil
import socket
import subprocess
import time

# BITCOIN_BIN: the folder with bitcoind and bitcoin-cli of Bitcoin Core 31.1; the regtest tests are skipped without it
BIN = pathlib.Path(os.environ.get("BITCOIN_BIN") or "/nonexistent-bitcoin-bin")
WORK = pathlib.Path(__file__).resolve().parents[1] / ".work"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Node:
    def __init__(self):
        WORK.mkdir(exist_ok=True)
        self.datadir = WORK / ("regtest-%d" % os.getpid())
        if self.datadir.exists():
            shutil.rmtree(self.datadir)
        self.datadir.mkdir()
        self.rpc, self.p2p = free_port(), free_port()
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen(
            [str(BIN / "bitcoind"), "-regtest", "-datadir=%s" % self.datadir, "-rpcport=%d" % self.rpc,
             "-port=%d" % self.p2p, "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
             "-listen=0", "-dnsseed=0", "-discover=0", "-fallbackfee=0.0002", "-server=1", "-txindex=1"],
            stdout=open(str(self.datadir) + ".log", "wb"), stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                self.cli("getblockcount", wallet=False)
                break
            except RuntimeError:
                time.sleep(0.3)
        else:
            raise RuntimeError("bitcoind did not start")
        self.cli("createwallet", "w", wallet=False)
        self.addr = self.cli("getnewaddress")
        self.cli("generatetoaddress", 101, self.addr)

    def cli(self, *args, wallet=True):
        a = [str(BIN / "bitcoin-cli"), "-regtest", "-datadir=%s" % self.datadir, "-rpcport=%d" % self.rpc]
        if wallet:
            a.append("-rpcwallet=w")
        a += [json.dumps(x) if isinstance(x, (dict, list, bool)) else str(x) for x in args]
        r = subprocess.run(a, capture_output=True, text=True, timeout=120)
        if r.returncode:
            raise RuntimeError((r.stdout + r.stderr).strip())
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except ValueError:
            return out

    def stop(self):
        if self.proc is None:
            return
        try:
            self.cli("stop", wallet=False)
        except RuntimeError:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self.proc.wait(timeout=30)
        self.proc = None
        shutil.rmtree(self.datadir, ignore_errors=True)
