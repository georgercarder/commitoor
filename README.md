## Commitoor

A smart contract allowing multiple parties to register a commitment of a signed message that signals an agreement on that message at a certain point in time, and later reveal this message onchain.

To run demo, be sure the have the *latest* version of `forge foundry` [installed](https://book.getfoundry.sh/), as well as nodejs.

To build call `npm install`

To run call `./run.sh`

From a high level, the `run.sh` script calls a `forge` test that interleaves its setup with system calls to a `node` script `js/ethersCaller.js` running through the "happy path" flow of

- signer account setup
- message preparation (eip 712, eip 191)
- message signing
- commitment construction
- commitment registration to contract (by "anyone")
- secret reveal to contract (by one of the signers)
