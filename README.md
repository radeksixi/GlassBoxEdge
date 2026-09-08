# GlassBox Edge — the device half

Live synthetic telemetry from pharma edge devices: two bioreactor lines (BR-101 and BR-201) simulated as
**JET-A** and **JET-B**, two NVIDIA Jetson nodes on a GMP bioprocess line. Each exposes an optional real OPC UA
endpoint, forwards HMAC-signed 30-second summaries with sequence numbers, and validates every inbound command
on the device itself before anything on the line can change.

Everything is fictional and synthetic (GlassBox Pharma AG, Basel).

### Scope of this repository

This is the **edge tier only**, and it is self-contained — clone it, run it, and you have two devices emitting
signed telemetry, no cloud account required. It is one chunk of a larger build; the cloud tier that consumes
this telemetry — the governed tool gateway, the agent graph, the eval harness and the trust dashboard — is
developed and published separately.

So the command path is deliberately half-present here. This repo holds the **last** step of it: the device-side
validator that accepts or rejects a signed command. The steps before it — an agent proposing, a person
approving, a broker signing — live on the cloud side and are not in this repository. You can still drive the
validator directly; see **Testing the validator without the cloud side** below.

## Layout

```
edge/edge_node.py       one process, three concerns:
                          LineSimulator     temperature · pH · DO · agitation · pressure, with phases, drift and
                                            alarms; optional asyncua server so an HMI/PLC toolchain sees a real
                                            OT endpoint
                          Forwarder         every 30 s: summary + edge z-score anomaly model, HMAC-signed frame
                                            with a sequence number -> IoT Hub, or a local JSONL sink offline
                          CommandValidator  the only outside path that mutates the line: a command must carry a
                                            valid signature, a fresh nonce, an allowlisted command with in-range
                                            params, and a valid state precondition
edge/config/lines.json  envelope · setpoints · noise · device and batch ids per line · command allowlist
edge/out/               offline sink: <device>-telemetry.jsonl and <device>.nonces (created on demand)
```

## Run

Offline, no cloud and no third-party packages — the standard library is enough.
Tested on Python 3.11 and 3.12:

```bash
git clone https://github.com/radek-sixi/GlassBoxEdge.git
cd GlassBoxEdge

python edge/edge_node.py --line A --device JET-A --seconds 120 --inject temp_c:+0.9:60
python edge/edge_node.py --line B --device JET-B --rogue --seconds 120
```

Frames land in `edge/out/JET-A-telemetry.jsonl`. `--inject tag:delta:seconds` pushes a tag out of the validated
envelope (an alarm is raised after 30 s outside it); `--rogue` is compromised-device mode — the node writes prompt
injection text into the OPC UA alarm string tag — the hostile input the cloud tier is built to survive. From this
repo's point of view it is simply a device that lies.

On the Jetsons, with `pip install -r requirements.txt` and the variables from `.env.example`:

```bash
IOTHUB_DEVICE_CONNSTR=... EDGE_DEVICE_KEY=<per-device key> python edge/edge_node.py --line A --device JET-A --opcua --iothub
IOTHUB_DEVICE_CONNSTR=... EDGE_DEVICE_KEY=<per-device key> python edge/edge_node.py --line B --device JET-B --rogue --iothub
```

`--opcua` serves `opc.tcp://0.0.0.0:4840/glassbox/<line>`. `EDGE_DEVICE_KEY` is per device and must match the key the
signer uses, or every frame verifies false and every command is rejected on `signature invalid`.

| flag | default | notes |
|---|---|---|
| `--line` | required | `A` or `B`; selects device id, batch id and zone from `lines.json` |
| `--device` | required | device identity, e.g. `JET-A` |
| `--seconds` | 3600 | run duration |
| `--frame-seconds` | 30 | forwarding interval |
| `--inject` | — | `tag:delta:seconds`, repeatable |
| `--rogue` | off | inject prompt text into alarm tags |
| `--opcua` / `--iothub` | off | real OPC UA server / IoT Hub device client |

## Testing the validator without the cloud side

The broker that signs commands is not in this repo, but `CommandValidator` is importable and the signing helper
is three lines, so the accept and reject paths are easy to drive directly:

```python
import sys, time; sys.path.insert(0, "edge")
from edge_node import LineSimulator, CommandValidator, sign, CFG

key = b"dev-key-change-me"                      # must match EDGE_DEVICE_KEY
sim = LineSimulator("B", CFG["lines"]["B"]["batch_id"])
v   = CommandValidator("JET-B", key, CFG["command_allowlist"], CFG["command_max_age_s"])

body = dict(command_id="CMD-1", device_id="JET-B", command="set_agitation_setpoint",
            params={"setpoint_rpm": 110}, nonce=f"n-{time.time()}", exp=time.time() + 30)
print(v.validate(dict(body, signature=sign(key, body)), sim))
```

Sign and validate the *same* dict — `exp` and `nonce` are inside the signed body, so rebuilding it between
signing and validating changes the signature.

To see the rejections, each returning `(False, "REJECTED: ...")` with the reason: set `setpoint_rpm` to `500`
(out of the validated range), pass the identical command twice (replay), or overwrite `signature` with
`"hmac-sha256:" + "0" * 64`.

Note the nonce is a timestamp rather than a constant. Seen nonces are appended to `edge/out/JET-B.nonces` and
reloaded on startup — the replay window deliberately survives a process restart — so a hardcoded nonce works
once and is rejected on every run after that. Delete that file to reset.

## Honest scope

A synthetic line and a synthetic plant. Not a GMP-validated system, not a CE-marked product — a public
demonstration of the device-side patterns: a device that carries an identity of its own, telemetry signed at
source, and a validator that is the only path by which anything outside can change the line.

The larger claim this is a piece of — that a model can be grounded in live OT telemetry while never touching the
PLC — is only half-demonstrable from here. This repo shows the half that runs on the device.

## License

MIT — see [LICENSE](LICENSE). `NOTICE` lists the two optional third-party dependencies and their licenses
(`asyncua` is LGPL-3.0; it is imported, never vendored, and only on the `--opcua` path).
