# Answer key — ci-smoke fixture

Fixture: `testdata/ci-smoke` (gnark v0.14.0). One circuit, one bug: the CI
cheap-scored case.

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| C1 | `circuit/circuit.go` Define | `RootVal` is taken from a square-root hint but never constrained by `RootVal*RootVal == Square`. | **High soundness.** The published root is a free value; any `RootVal` is accepted for any `Square`. PoC: `TestPoC_RootUnconstrained`. | confirmed, high |
