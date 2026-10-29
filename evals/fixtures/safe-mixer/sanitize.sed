/^[[:space:]]*\/\/ BUG:/d
/^[[:space:]]*\/\/ OK:/d
s|^// Package circuit is a zk-audit test fixture with a deliberate bug\.$|// Package circuit implements the circuit.|
s|^// Package circuit is a zk-audit test fixture with deliberate bugs\.$|// Package circuit implements the circuit.|
s|^// zk-audit test fixture with a deliberate integration bug\.$|// A minimal mixer that consumes the withdrawal proof.|
s|^// Package circuit is a zk-audit test fixture: a correctly constrained circuit\.$|// Package circuit implements the circuit.|
