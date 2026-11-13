# Blindstream

Private music streaming for a closed group. The machines that carry the audio hold no map from a hash to a track or an owner, and keep no log of what they served.

**Measured, and rerunnable from this repository: I dropped 115 shares from an encoded 195 s track and rebuilt it byte for byte.**

Reproducible in this repository:

| Run this | Result |
| --- | --- |
| `python examples/repair_a_track.py` | 17/17 windows rebuilt after 115 shares dropped, file identical |
| `cd relay && python -m pytest tests -q` | 162 tests pass |

Reported from the full deployment. These came from the full system, whose deployment scripts are not published:

| Test | Result |
| --- | --- |
| Relay drops 25% of shares in flight | 17/17 windows, 113 of 398 shares lost |
| One relay killed mid-play | 17/17 answered, 6 through failover |
| Published track read after 24 h | 244 blocks, 16/16 windows, 0 stalls |
| Cold storage node, before it settles | 5/17 windows answered |
| Same node after 8 connected peers | 17/17 windows answered |

## What I built

I designed and built the streaming core in this repository. It has the erasure-coded window format, the signed manifest that names every share, and a relay that reads a whole window per request. The relay also cancels the shares it no longer needs and refuses to log what it served.

I ran the measurements above and wrote the code that produced them. A negative result stays where it belongs. The cold-node row exists because my first version lost 12 of 17 windows, and the cause was a storage node reporting itself ready before it had peers.

## How it works

The owner seals a track, splits it into 32 KiB blocks, and groups them into windows. Each window of n shares rebuilds from any k of them. The schedule sets k per window, at 4 of 12 at the head, 8 of 20 next, then 16 of 32. The owner stores every share as one content-addressed object in a peer-to-peer network, then signs a manifest that lists them.

A relay answers one question, and only one. Give it a content hash, and it returns 32 KiB of ciphertext. It holds no map from hash to owner and no map from hash to track, so it has nothing to disclose.

The client holds the keys and does the decryption. In the full system that client is an iPhone app, and it is not in this repository.

## Why not a normal music server

A self-hosted music server answers the same need and fails the privacy goal. Its host sees every listener's address, every request, and every track, so one subpoena or one curious administrator exposes the whole circle. Its uptime is also the product's uptime.

Blindstream moves the storage off the owner and the knowledge off the relays. The owner uploads once and can then go offline, because replay reads from the network. The relay sees a hash and returns bytes, and it never learns which owner published that hash.

## Try it

The encoding runs offline. The example needs Python 3.9 or newer and one dependency. The tests add pytest and cryptography.

```bash
pip install zfec
python examples/repair_a_track.py
```

Expected output, truncated:

```text
synthetic 320 kbps, 195 s: 7,800,000 bytes, 239 blocks, 17 windows, dropping 25% of shares

window    k    n  shares  lost  rebuilt  result     digest
     0    4   12      12     7        4  ok         ce264d56cdc0c906
     1    8   20      20     3        8  ok         d717de1413b3dbe9
     2   16   32      32     8       16  ok         b6d8a2ace177f75d
...
    16    3    7       7     1        3  ok         0f73dd1449f424d1

shares dropped: 115  windows lost: 0  file identical: yes
```

Pass a file and a loss rate to try it on your own data: `python examples/repair_a_track.py song.m4a 0.1`.

Run the test suite with the full dependency set. It covers all 495 k-subsets of the smallest window and 200 random 16-of-32 subsets. It also covers a corrupted recovery share, and it parses the relay module to prove that no logging call exists in it.

```bash
pip install pytest cryptography
cd relay && python -m pytest tests -q
```

## What is in this repository

| Path | Contents |
| --- | --- |
| `relay/blind_fec.py` | Window schedule, encode, decode, signed manifest |
| `relay/blind_window_reader.py` | Reads a window over held connections, keeps the first k, cancels the rest |
| `relay/blind_relay.py` | HTTP relay, onion-only serving, pass metering, fault injection |
| `relay/blind_door.py` | Per-device credential, spend windows, no identity |
| `relay/blind_substrate.py` | Pooled network reads and the no-retry miss classification |
| `relay/blind_library_index.py` | Catalogue index the owner signs and a client opens without the owner online |
| `relay/tests/` | 162 tests, including the no-logging proof |
| `docs/architecture.md` | Parties, flows, and the one design decision behind them |
| `docs/measurements.md` | Each result above with its caveats |

## Limitations

- **No phone result yet.** Every measurement used a local client. Onion latency, mobile radio time, and the player's own buffer are not in these numbers.
- **A cold storage node cannot serve a first play.** Until a node has connected peers, reads mostly time out. The fix is a readiness gate, measured at 5 connected peers, plus a relay pool that warms before traffic arrives.
- **Per-object overhead is high.** A 195 s track becomes several thousand 32 KiB objects. The encoding exists to make that tail cheap, not to hide it.
- **A copyable stream is copyable.** A client allowed to play a track can record what it decrypts. The design protects the owner and the relationship, not the bytes after delivery.
- **No central recovery.** Keys live with the member. A lost device means the member re-enrols with their owner.
- **The relay side is not the whole claim.** An internet provider still sees that a member uses an anonymising transport, and an observer who watches both ends of a connection is out of scope. The design removes the central observer. It does not remove all observation.

## Status

Research project, actively developed. This repository is a curated extract of a larger private codebase, with the deployment scripts, credentials, and infrastructure removed. The iOS client, the owner server, and the publish pipeline are not included here. The relay, codec, and window reader are the parts that make the architecture legible and they run as shown.

The project stays closed and no license is granted. The code is published to be read.
