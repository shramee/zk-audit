# Strips the hint comments from the liveness-roots fixture (evals/sanitize).
/^[[:space:]]*\/\/ BUG:/d
/^\/\/ zk-audit test fixture with a deliberate liveness bug\.$/d
