# Pilot results

The protocol is in [`docs/pilots.md`](../../docs/pilots.md). The bar: in two
consecutive pilots, the human auditor finds no high or critical miss by
zk-audit.

**Status: no pilot has been run.** Consecutive passes: 0 of 2.

One row per pilot and profile, in the order the pilots finished. Fill a row
from `evals/pilots/score-pilot` (its last line) after the human has checked
every outcome by hand, and add the columns it cannot know. A failing pilot
resets the count. Real codebases may be private: record only what the code
owner allows (the row needs no code, only counts and ids).

| Pilot | Target | Commit | Human findings | Human high/critical | Found (confirmed or needs validation) | Lead only | High/critical misses | Result | Profile | Plugin revision | Model | Cost (USD) | Time (min) | Unmatched zk-audit claims (true / false) | Date |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
