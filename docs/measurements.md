# Measured results

Reproducible from this repository: the encoding result in `examples/repair_a_track.py` and the 162 tests in `relay/tests/`. Not reproducible from this repository: the relay, cold-node, and 24-hour numbers. Those came from the full deployment, whose scripts and infrastructure are not published. Read them as reported results, not as checks you can rerun.

*Every number below except the first came from a local HTTP client against the full deployment. None is a device measurement, and none is production latency.*

## The problem the encoding solves

Reading 32 KiB objects one at a time from a fresh storage node does not hold a playback schedule. At any concurrency, a few percent of objects arrive later than a player's buffer allows, and one late object in an ordered stream is a stall.

Window encoding converts that tail into arithmetic. A window of n shares needs any k, so the answer arrives when the k-th share lands, not when the last one does.

| Test | Shares | Windows | Windows lost | Rerunnable here |
| --- | --- | --- | --- | --- |
| Encoding round trip, no network | 12 to 32 per window | 17 | 0 | Yes |
| Relay fault injection, 25% dropped at random | 398 asked, 113 dropped | 17 | **0** | No |
| Relay fault injection, no fault | 293 asked | 17 | 0 | No |

The fault arm cost wall time (17.0 s to 31.4 s) and not a single window. That is the trade the design buys: redundancy pays in latency, never in a hole in the stream.

## One relay dying mid-play

Two relays served one track. At window 6 one was killed, and later windows were still drawn from both, so the client kept meeting the dead one.

| Arm | Answered | Served directly | Failed over | Windows lost |
| --- | --- | --- | --- | --- |
| Control, no kill | 17/17 | 17 | 0 | 0 |
| Kill at window 6 | 17/17 | 11 | 6 | **0** |

The dead relay answered in 0 ms and the survivor answered the same window in 200-250 ms. Both are loopback figures.

## What a cold subscriber pays

A publication that a node has never read is the hard case, and the answer depends on which machine you ask from.

On a node on the same rack as the writer, the first pass over the publication lost 4 of 17 windows to share timeouts and took 536 s. The second pass on the same node answered 17/17 in 38 s with zero failed shares. Every loss was a share timeout, never a short body or a bad digest. That node answered 13 of 17.

On a foreign machine, with the publisher stopped and an empty store, the first pass was far worse. It answered 5 of 17 windows in 815 s, and every loss was a share timeout against the deadline.

The cause was not the encoding. A storage node answers "I am ready" before it has a single connected peer, and reads issued in that window walk an empty routing table. Measured on one node: ready at 5 s, first peer at 22 s, eight peers at 243 s. The same window pass started at 243 s answered 17/17.

| Node state | Windows answered |
| --- | --- |
| Foreign node, reading immediately after "ready" | 5/17 |
| Same rack as the writer, before it settles | 13/17 |
| Any of them, after enough connected peers | **17/17** |

So the release rule is a readiness predicate on connected peers, not an uptime timer and not a warm-up sample. A sweep put the floor at 5 connected peers, where a full pass answers 17/17.

## Content after a day

I published a 196 s track (244 blocks, 16 windows), left it alone, and read it cold 24 hours later.

| Check | Result |
| --- | --- |
| Sampled single blocks still retrievable | 50/50, zero errors |
| 90th-percentile block time | 72 s |
| Windows rebuilt | 16/16 |
| Whole track read | 96 s |
| Playback stalls after a 6 s buffer | 0 |

The tail is why the window layer exists. A tenth of the sampled blocks took over 72 s, and the whole track still arrived without a stall, because recovery shares absorb the tail.

## Two relays, whole track

Two settled relays on separate machines each walked all 17 windows of a published track with a real credential: 17/17 windows, every returned share matching its signed digest.

## What these numbers are not

They are not a phone. Every run used a local HTTP client, so they exclude onion latency, mobile radio behaviour, and the client's own deadlines. They are not five tracks, and they are not a fleet. The device test is the gate that decides the project, and it is a separate result.
