"""In-process device link and a scripted malicious signer (for tests).

The link is a request/response channel carrying PSBT bytes. It keeps a
transcript so tests can inspect what the device saw. NOT FOR PRODUCTION.
"""
import psbt_codec as C
import signer as SG


class LinkError(Exception):
    """A transport or device failure. The host does not tell the kinds apart."""


class LinkTimeout(LinkError):
    pass


class LinkDisconnected(LinkError):
    pass


class DeviceError(LinkError):
    """The device reported an error or refusal."""


class LinkCancelled(LinkError):
    """Cancelled on either side while a response was outstanding."""


class InProcessLink:
    def __init__(self, signer):
        self.signer = signer
        self.transcript = []        # (request, response or None)
        self._unsolicited = []

    def exchange(self, request):
        try:
            response = self.signer.sign(request)
        except SG.SignerFail as e:
            self.transcript.append((request, None))
            raise DeviceError(str(e))
        self.transcript.append((request, response))
        return response

    def take_unsolicited(self):
        out, self._unsolicited = self._unsolicited, []
        return out


# ---------------------------------------------------------------- malicious
def honest(req, real):
    return real(req)


def timeout(req, real):
    raise LinkTimeout("scripted timeout")


def disconnect(req, real):
    raise LinkDisconnected("scripted disconnect")


def refuse(req, real):
    raise DeviceError("scripted refusal")


def garbage(req, real):
    return b"not a psbt"


def tamper(fn, run_signer=True):
    """Step: run the real signer, parse its response, let fn(psbt) edit it, return the bytes."""
    def step(req, real):
        p = C.parse(real(req))
        out = fn(p)
        return (out if isinstance(out, C.Psbt) else p).serialize()
    return step


def change_r0(pair_index=0, new=None):
    """Replace one nonce commitment in the response with another valid point."""
    def edit(p):
        keys = sorted((i, k) for i, m in enumerate(p.inputs) for k in m if k[:1] == b"\x22")
        i, k = keys[pair_index]
        p.inputs[i][k] = new or bytes([5 - p.inputs[i][k][0]]) + p.inputs[i][k][1:]
    return tamper(edit)


class ScriptedLink(InProcessLink):
    """Plays steps in order, then behaves honestly. A step is a function (request, real) -> bytes
    that may raise a LinkError subclass. The real signer is reachable through `real`."""

    def __init__(self, signer, steps=(), repeat_last=False):
        super().__init__(signer)
        self.steps = list(steps)
        self.repeat_last = repeat_last
        self.calls = 0
        self.on_exchange = None     # optional hook run while a response is outstanding

    def exchange(self, request):
        self.calls += 1
        if self.on_exchange:
            self.on_exchange(self, request)
        if self.steps:
            step = self.steps[0] if self.repeat_last and len(self.steps) == 1 else self.steps.pop(0)
        else:
            step = honest

        def real(r):
            try:
                return self.signer.sign(r)
            except SG.SignerFail as e:
                raise DeviceError(str(e))
        try:
            resp = step(request, real)
        except LinkError:
            self.transcript.append((request, None))
            raise
        self.transcript.append((request, resp))
        return resp

    def push_unsolicited(self, data):
        self._unsolicited.append(data)
