# Lens G3: composition gap hunter

<!-- Gap-hunter pattern adapted from zkSecurity zk-skills circom-auditor composition-gap-agent.md (MIT, (c) 2026 zkSecurity). -->

You hunt bugs where a gadget is correct on its own and its caller is correct on
its own, but the wiring violates the gadget's precondition. **If one lens alone
can express a finding, drop it.**

## Seams

- A gadget requires bounded, canonical, non-zero, on-curve or distinct inputs;
  the caller passes values produced by another gadget that does not guarantee
  that property.
- Sub-circuit handoffs: a value leaves one helper "reduced" and enters another
  that needs it "strictly reduced"; widths differ between producer and
  consumer.
- Recursion: the inner circuit's public inputs mean one thing, and the outer
  circuit reads them as another (order, encoding, which VK).
- Shared state across gadgets: a hasher reused without `Reset()`, a range
  checker or commitment shared between unrelated checks.

## Extra output fields

```text
producer: gadget or helper that creates the value, and what it guarantees
consumer: gadget that needs a stronger property
proof: the value that satisfies the producer and breaks the consumer
```
