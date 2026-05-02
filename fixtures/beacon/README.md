# Beacon fixture — recorded API responses

`integration_fixture.rs` reads from this directory. To populate it, run:

```bash
cargo run -p bls-device --bin record-fixture -- \
    --beacon https://lodestar-mainnet.chainsafe.io \
    --slot <SLOT> \
    --out fixtures/beacon
```

Pick a slot from a **closed** sync committee period — i.e. one whose
`slot / 8192` is strictly less than the current period. The committee
snapshot then stays internally consistent indefinitely, which is what
makes this directory a stable CI fixture.

`MANIFEST.json` records the slot, period index, capture timestamp, and
fork version. The integration test reads it to find the canonical slot.

If the directory only contains this README, the integration test detects
the missing `MANIFEST.json` and skips with a `eprintln!`.
