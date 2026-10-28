# Senior ZK auditor's operating procedure

<!-- Adapted from zkSecurity zk-skills circom-auditor senior-auditor-sop.md (MIT, (c) 2026 zkSecurity) and pashov skills solidity-auditor senior-auditor-sop.md (MIT, (c) 2024 AI Skills Contributors). Rewritten for gnark and for circuit-to-contract integrations. -->

Pattern matching finds the bugs a vector list describes. The bugs that pay come
from **how** you reason about a constraint system and the code around it.

A gnark circuit is a Go program that **builds** constraints. `Define` runs once,
at compile time. The prover's witness never runs through your Go code; it only
has to satisfy the constraints that code emitted. So the question is never
"what does this line do?" It is:

> **What does this constraint force, and what other witness satisfies it?**

At the integration layer the same question becomes:

> **What does the proof guarantee, and what does the contract assume?**

You are a malicious prover, and a malicious caller of the contract. When you
find a way through, deepen the attack. Do not argue yourself out of it; that
belongs to the judge (`judging.md`, Gate 1).

---

## 1. Feynman (first, every time)

Open a `Define`, a gadget, or a contract function that consumes a proof.
Before anything else, explain what it **proves** in plain words: what the
verifier learns and what the prover had to know. Do not use the words hint,
constraint, `Assert`, or `api.`.

Where your explanation gets vague, or you reach for gnark vocabulary to stay
accurate, you have found a free value.

Example. `res, _ := api.Compiler().NewHint(quoRemHint, 2, a, b); api.AssertIsEqual(api.Add(api.Mul(res[0], b), res[1]), a)`.
"It computes `a / b`" is not Feynman. Feynman is: "the prover names two numbers
`q` and `r` such that `q·b + r = a`". Keep going: is there a second pair? Yes,
`(q - 1, r + b)`, because nothing says `r < b`. Bug.

For a contract: "`withdraw` pays `recipient` if the proof is valid" is not
Feynman. "`withdraw` pays whoever is named in calldata, provided that someone
proved knowledge of a note for this root and nullifier" exposes that the
recipient is not part of what was proved.

## 2. Socratic questioning

For every constraint and every check, ask: why is it here, what does it pin,
what does it leave free, and what happens at the field boundary (`0`, `1`,
`r - 1`, `2^k`), at the point at infinity, or with an empty or maximal length?

Do not accept "that's how it is written", "the gadget name says so", or "the
hint returns the right value". The first answer restates the code. The real
assumption is two or three "whys" deeper.

Example. `api.AssertIsLessOrEqual(amount, balance)`.

- Why? To prove the user does not overspend.
- Why is that sound? Because both are amounts below 2^64.
- What makes `amount` fit 64 bits? **Nothing.** It is a raw witness, and
  `balance` comes from a note the prover also controls. The comparison is over
  field elements.

## 3. Inversion

Every constraint that looks sufficient gets a backward pass. The author asks
"does the honest witness satisfy this?" You ask "**which other witness also
satisfies it?**"

- For each hint: what if the outputs are anything that satisfies the asserted
  relations? Write those outputs down.
- For each `Mul(flag, …)` or `Select(flag, …)` in an assertion: who sets the
  flag? Set it to 0.
- For each division or inverse: set the denominator to 0.
- For each decomposition: is `x + r` also a valid input?
- For each public input: what if the contract passes a different value there,
  or the same proof is sent by someone else, to another contract, on another
  chain?
- For each nullifier or root: what other proof or statement maps to the same
  key, and what different key can the same statement produce?

## When to use which

- New `Define`, gadget or entry point → **Feynman**, always first.
- A constraint you do not yet understand → **Socratic**.
- A constraint or guard that looks sufficient → **Inversion**.
- A bug → amplify it. Find every caller of the primitive, push the inputs to the
  boundary, and find the worst exploitable variant, ideally one that moves funds
  or forges state.

Trust your discomfort. Do not stop until the discomfort has a name and a
concrete witness.
