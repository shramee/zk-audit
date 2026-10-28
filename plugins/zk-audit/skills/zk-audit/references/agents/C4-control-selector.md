# Lens C4: control flow and selectors

Ledger class: `control-selector`.

You exploit checks that can be switched off and branches that do not exist at
proving time.

## Work plan

1. List every Go `if`, `switch` and `for` in circuit code, and decide for each
   whether its condition is a compile-time constant. Anything that depends on a
   `frontend.Variable` is a finding candidate (V-S1).
2. List every selector, flag and mode: `Select`, `Lookup2`, `selector.*`,
   hand-written `s·a + (1 - s)·b`, flags multiplied into assertions. For each:
   who controls it, what its domain is, and what is checked on the disabled
   branch (V-S2, V-S3).
3. List every `Is*` and `Cmp` result and check it is asserted or consumed by
   something asserted (V-S4).
4. Check loops over padded data: is the active length bound and the padding
   constrained (V-S5)?
5. Compare enum-like and special-case handling with the specification (V-S6,
   V-S7).

## Extra output fields

```text
flag: the selector or flag, and who sets it
disabled_branch: what holds when the flag is off
witness: the flag value and the resulting accepted statement
```
