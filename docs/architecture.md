# How the network works

Five parts: an owner server, a substrate, blind relays, a client, and a capability.

## The parties

An **owner** is one member of the circle who runs a server. It holds that member's music files, seals them, and inserts the sealed bytes into a peer-to-peer storage network. The owner is the only party that ever touches plaintext, and it does not have to stay online.

A **relay** is a machine that answers one question: given a content hash, here are 32 KiB of ciphertext. It holds no map from hash to owner, no map from hash to track, and no log. It cannot tell which owner a hash belongs to, because that mapping was never sent to it.

The **substrate** is the storage network behind the relays. It is content-addressed: the hash of the bytes is the address, so anyone holding the bytes can prove what they are.

A **client** holds the decryption keys and a signed list of what its owner published. It fetches ciphertext through relays and decrypts locally. In the full system the client is an iPhone app, which is not part of this repository.

## The three flows

**Enrolment.** A member accepts an invitation carrying the owner's onion address and a one-time secret. The phone enrols directly with the owner and receives its own keys. No central server learns which member joined which owner.

**Publish.** The owner seals each track and splits it into 32 KiB blocks, then groups the blocks into windows. Each window gains recovery shares, so any k of its n shares rebuild it. The owner inserts every share into the substrate. Insert time does not matter, so publishing can run for hours in the background.

**Play.** The phone reads the track's signed manifest, which lists the shares of each window. It asks one or more relays for those shares, takes the first k answers, rebuilds the window, verifies the digest that the owner signed, and hands audio to the player. The owner is not in this path and may be offline.

## The one decision that explains the rest

Every object is uniform 32 KiB of ciphertext with a content hash for an address. That single constraint gives the privacy property, the redundancy property, and the cache property at the same time.

Because a relay returns bytes for a hash and nothing else, it cannot know who is playing what, so there is nothing to disclose and nothing to subpoena. Because the address is the hash, a client can check a share against its own digest the moment it arrives, without asking anyone. And because all objects are the same size, object size gives an observer no signal about which track is playing.

The cost is real. Per-object overhead is high, so a 195 s track becomes several thousand 32 KiB objects. Fetching them one at a time is slow enough to miss a playback deadline. That is why the relay reads a whole window at once, and why the encoding carries the latency budget rather than the transport.

## What it does not do

The design removes the central observer. It does not remove all observation.

An internet provider still sees that a member uses an anonymising transport. A global passive observer who watches both ends of a connection is out of scope. A client that is authorised to play a track can copy the audio it receives. And a member who loses their device loses the keys on it, because there is no server holding a copy.

Those limits are stated here rather than hidden, because a privacy argument that overstates itself is worse than no argument.
