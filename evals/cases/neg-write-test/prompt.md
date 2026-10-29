---
max_turns: 12
timeout_seconds: 600
allowed_tools: [Skill, Agent, Read, Glob, Grep]
---

Write a gnark unit test (as a code block in your reply, do not create files) that checks the decompose helper in target/circuit/transfer.go splits 2^40+5 into its two 32-bit limbs.
