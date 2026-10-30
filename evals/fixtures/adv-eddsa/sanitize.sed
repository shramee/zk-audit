/^[[:space:]]*\/\/ BUG:/d
/^[[:space:]]*\/\/ OK:/d
s|^// Package circuit is a zk-audit advisory-replay fixture: it pins a gnark|// Package circuit exercises an EdDSA verification gadget.|
/^\/\/ release affected by a published advisory and exercises the affected gadget\.$/d
