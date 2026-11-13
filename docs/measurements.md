# Measured results

Every number below came from this code running against a real storage node, on hardware I control. Where a result is weaker than it looks, the caveat sits in the same table.

## The problem the encoding solves

Reading 32 KiB objects one at a time from a fresh storage node does not hold a playback schedule. At any concurrency, a few percent of objects arrive later than a player's buffer allows, and one late object in an ordered stream is a stall.

Window encoding converts that tail into arithmetic. A window of n shares needs any k, so the answer arrives when the k-th share lands, not when the last one does.

| Test | Shares | Windows | Windows lost |
| --- | --- | --- | --- |
| No injected fault | 293 asked | 17 | 0 |
| 25% of shares dropped at random | 398 asked, 113 dropped | 17 | **0** |

The fault arm cost wall time (17.0 s to 31.4 s) and not a single window. That is the trade the design buys: redundancy pays in latency, never in a hole in the stream.

## One relay dying mid-play

Two relays served one track. At window 6 one was killed, and later windows were still drawn from both, so the client kept meeting the dead one.

| Arm | Answered | Served directly | Failed over | Windows lost |
| --- | --- | --- | --- | --- |
| Control, no kill | 17/17 | 17 | 0 | 0 |
| Kill at window 6 | 17/17 | 11 | 6 | **0** |

The dead relay answered in 0 ms and the survivor answered the same window in 200-250 ms.

## What a cold subscriber pays

A publication that a node has never read is the hard case. The first pass over a fresh node lost 4 of 17 windows to share timeouts and took 536 s. The second pass on the same node answered 17/17 in 38 s with zero failed shares. Every loss was a share timeout, never a short body or a bad digest.

The cause was not the encoding. A storage node answers "I am ready" before it has a single connected peer, and reads issued in that window walk an empty routing table. Measured on one node: ready at 5 s, first peer at 22 s, eight peers at 243 s. The same window pass started at 243 s answered 17/17.

| Node state | Windows answered |
| --- | --- |
| Reading immediately after "ready" | 5/17 |
| After the node has settled | **17/17** |

So the release rule is a readiness predicate on connected peers, not an uptime timer and not a warm-up sample. A sweep put the floor at 5 connected peers, where a full pass answers 17/17.

## Content after a day

I published a track, left it alone, and read it cold 24 hours later.

| Check | Result |
| --- | --- |
| Single blocks still retrievable | 50/50, zero errors |
| Slowest 10% of blocks | 72 s |
| Windows rebuilt | 16/16 |
| Whole 195 s track read | 96 s |
| Playback stalls after a 6 s buffer | 0 |

The tail is why the window layer exists. One block in ten took over 72 s, and the whole track still arrived without a stall, because the tail is absorbed by recovery shares.

## Two relays, whole track

Two settled relays on separate machines each walked all 17 windows of a published track with a real credential: 17/17 windows, every returned share matching its signed digest.

## What these numbers are not

They are not a phone. Every run used a local HTTP client, so they exclude onion latency, mobile radio behaviour, and the client's own deadlines. They are not five tracks, and they are not a fleet. The device test is the gate that decides the project, and it is a separate result.
