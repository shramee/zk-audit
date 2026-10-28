# Strips the hint comments from the pool fixture so an eval run cannot read
# the planted-bug locations from the source. Applied to every .go and .sol
# file by evals/sanitize.
/^[[:space:]]*\/\/ BUG:/d
/^[[:space:]]*\/\/ OK:/d
s|^// Package circuit is a zk-audit test fixture\. It contains deliberate bugs so$|// Package circuit holds the shielded-pool transfer and signature circuits.|
/^\/\/ that the inventory tool has something to find\. Do not use it as an example\.$/d
s|^// Command setup compiles the circuit and exports a verifier\. Fixture only\.$|// Command setup compiles the circuit and exports a verifier.|
/^\/\/ zk-audit test fixture with deliberate integration bugs\.$/d
s|^// zk-audit test fixture: a stub with the public surface of a gnark Groth16$|// Placeholder with the public surface of the generated gnark Groth16|
s|^// decompose returns hint outputs to its caller without constraining them\.$|// decompose splits v into a low and a high 32-bit limb.|
s|^// testCircuit only exists in tests\.$|// testCircuit is a minimal circuit for tests.|
