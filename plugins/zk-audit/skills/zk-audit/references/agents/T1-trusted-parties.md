# Lens T1: trusted parties

Ledger class: `trusted-party`. You own every `trusted-party` unit: one per
privileged contract function, declared role and setup site in the inventory
("Privileged functions", "Roles", "Upgrade and code-execution paths",
`FG-DEV-SETUP` hits).

You list every party the system trusts, what each one can do, and what breaks
if it misbehaves or its key leaks. An admin power is not a non-issue: it is a
trust assumption the report must state, with its blast radius. Judging turns
your items into `needs_validation` records with a trust blocker; it never
drops them (`judging.md`, Gate 3).

## Work plan

1. **Parties.** From the inventory's privileged functions, roles, upgrade
   paths and setup sites, and from `system-map.md`, list each party: owner,
   admin and access-control roles, upgrader, deployer (initializers), setup
   ceremony (who ran `groth16.Setup`, where the keys come from), designated
   prover, sequencer, relayer, oracle, indexer or other off-chain service the
   flow depends on.
2. **Powers.** For each privileged function or path, say what the party can
   change and what that breaks:
   - **soundness**: swap the verifier or VK, upgrade the contract, add a
     Merkle root, accept a proof on a path that skips verification, forge
     with toxic waste;
   - **funds**: mint, sweep, move or lock user funds, set fees without a cap;
   - **liveness**: pause, censor (a designated prover, sequencer or relayer
     that refuses), let roots expire, revoke a role nobody can re-grant;
   - **privacy**: see recipients, IPs, notes or witnesses (relayer, indexer,
     delegated prover).
3. **Mitigations in the code.** Look for what the repository itself shows: a
   timelock (delay before a setter takes effect), a multisig or governance
   contract as the owner, a two-step ownership transfer, events on every
   change, immutables instead of setters, a root derived from deposits
   instead of posted by a party. Quote the line. A comment or a README promise
   is not a mitigation.
4. **Amplifiers.** Find any way an unprivileged actor reaches the same power:
   an ungated setter (gate `none` in the inventory), an initializer anyone can
   call first, a role whose admin role is itself, a signature-authorised admin
   action without a nonce or domain, a proxy whose `_authorizeUpgrade` is
   empty, a `delegatecall` to a caller-chosen target. An amplifier makes the
   item a normal finding, not a trust assumption.
5. **Off-chain trust.** Who generates keys and where they are stored; whether
   the committed verifier or VK can be traced to a multi-party ceremony;
   whether the prover service or relayer can choose public inputs the user
   did not intend (V-PV4).

Report every power that breaks soundness, funds, liveness or privacy, even
when `zk-audit.md` says the party is trusted: judging records it as an
accepted risk. Do not report powers that change nothing users rely on.

## Output

Use a FINDING when you have an amplifier (an unprivileged path to the power,
with a call sequence as `proof:`). Otherwise use a LEAD with these extra
fields, one item per power (two setters of the same power on one contract are
one item):

```text
LEAD | layer: integration | scope: Escrow.setChecker | local: checker | bug_class: trusted-verifier-swap | group_key: Escrow | setChecker | trusted-verifier-swap
detected_by: T1
location: contracts/Escrow.sol:31
code: function setChecker(address c) external onlyOwner {
party: owner (Ownable, single key in the deploy script)
power: replaces the proof checker; a checker that accepts everything drains the vault
breaks: soundness, funds
assumption: the owner key is held by a timelocked multisig and never accepts an unaudited checker
mitigation: none in the repository
code_smells: owner-only setter with no delay and no event
unverified: who holds the owner key on the deployed contract
description: The owner swaps the proof checker at any time and can then accept any proof.
```

`bug_class` names the power: `trusted-verifier-swap`, `trusted-vk-change`,
`trusted-root-insert`, `trusted-upgrade`, `trusted-mint`, `trusted-pause`,
`trusted-censor`, `trusted-setup`, `trusted-relayer-metadata`,
`trusted-config`. `breaks` is one or more of soundness, funds, liveness,
privacy.
