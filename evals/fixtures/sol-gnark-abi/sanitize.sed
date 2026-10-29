# Strips the hint comments from the sol-gnark-abi fixture (evals/sanitize).
/^\/\/ zk-audit test fixture with a deliberate integration bug\.$/d
/^\/\/ BUG: /,/^\/\/ .*every redeem reverts\.$/d
