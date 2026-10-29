# Strips the hint comments from the lib-gadgets fixture so an eval run cannot
# read the planted mismatches from the source. Applied to every .go file by
# evals/sanitize.
/^[[:space:]]*\/\/ BUG:/d
/^[[:space:]]*\/\/ OK:/d
s|^// Package gadgets is a zk-audit test fixture: a small gnark gadget library$|// Package gadgets holds small gnark gadgets: bit decomposition, range checks,|
s|^// with no production circuit and no verifier contract\. It contains$|// selection, division, comparison, emulated-field reduction and a flag|
s|^// deliberate doc-versus-constraint mismatches so that library mode has$|// accumulator.|
/^\/\/ something to find\. Do not use it as an example\.$/d
