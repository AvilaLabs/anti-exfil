#!/usr/bin/env python3
"""Run Jade's firmware image in Espressif's QEMU, on this machine only.

Replaces Jade's own main/qemu/qemu_run.sh, which kills every qemu-system-xtensa by name and listens on all
addresses. This one:
  - forwards one host port, on 127.0.0.1 only, to the firmware's TCP port 30121;
  - blocks the guest's own network access (restrict=on);
  - stops only the process it started, by PID, after checking the PID is still that process.
It never touches a serial device or a real board: the only machine is the emulated esp32.

  qemu_jade.py start FLASH_IMAGE EFUSE_IMAGE [--port 30121] [--state FILE]
  qemu_jade.py stop [--state FILE]
As a library: Qemu(flash, efuse).start() / .stop().
"""
import argparse
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time

# QEMU_ROOT: install folder of Espressif's QEMU (bin/qemu-system-xtensa, lib/x86_64-linux-gnu)
QEMU_ROOT = pathlib.Path(os.environ.get("QEMU_ROOT") or sys.exit("set QEMU_ROOT to the install folder of Espressif's QEMU"))
QEMU = QEMU_ROOT / "bin/qemu-system-xtensa"
GUEST_PORT = 30121


class Qemu:
    def __init__(self, flash, efuse, port=30121, log=None):
        self.flash, self.efuse, self.port = str(flash), str(efuse), port
        self.log = log
        self.proc = None

    def argv(self):
        return [str(QEMU), "-nographic", "-machine", "esp32", "-m", "4M",
                "-drive", "file=%s,if=mtd,format=raw" % self.flash,
                "-nic", "user,model=open_eth,id=lo0,restrict=on,hostfwd=tcp:127.0.0.1:%d-:%d" % (self.port, GUEST_PORT),
                "-drive", "file=%s,if=none,format=raw,id=efuse" % self.efuse,
                "-global", "driver=nvram.esp32.efuse,property=drive,value=efuse",
                "-global", "driver=timer.esp32.timg,property=wdt_disable,value=true",
                "-serial", "null", "-monitor", "none"]

    def start(self, wait=120):
        env = dict(os.environ, LD_LIBRARY_PATH=str(QEMU_ROOT / "lib/x86_64-linux-gnu"))
        out = open(self.log, "wb") if self.log else subprocess.DEVNULL
        self.proc = subprocess.Popen(self.argv(), env=env, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        deadline = time.time() + wait
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("qemu exited with %s" % self.proc.returncode)
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
                return self.proc.pid
            except OSError:
                time.sleep(1)
        self.stop()
        raise RuntimeError("firmware did not accept a connection in %ds" % wait)

    def stop(self):
        stop_pid(self.proc.pid if self.proc else None, self.flash)
        if self.proc:
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=20)


def stop_pid(pid, flash):
    """SIGTERM one PID, only if it is still a qemu started on this flash image."""
    if not pid:
        return
    try:
        cmd = pathlib.Path("/proc/%d/cmdline" % pid).read_bytes().split(b"\0")
    except OSError:
        return
    if not cmd or not cmd[0].endswith(b"qemu-system-xtensa") or ("file=%s,if=mtd,format=raw" % flash).encode() not in cmd:
        raise RuntimeError("pid %d is not our qemu; not stopping it" % pid)
    os.kill(pid, signal.SIGTERM)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["start", "stop"])
    ap.add_argument("flash", nargs="?")
    ap.add_argument("efuse", nargs="?")
    ap.add_argument("--port", type=int, default=30121)
    ap.add_argument("--state", default="qemu_jade.state")
    a = ap.parse_args()
    if a.cmd == "start":
        q = Qemu(a.flash, a.efuse, a.port)
        pid = q.start()
        pathlib.Path(a.state).write_text(json.dumps({"pid": pid, "flash": q.flash}))
        print("qemu pid %d, 127.0.0.1:%d" % (pid, a.port))
    else:
        st = json.loads(pathlib.Path(a.state).read_text())
        stop_pid(st["pid"], st["flash"])
        print("stopped", st["pid"])


if __name__ == "__main__":
    sys.exit(main())
