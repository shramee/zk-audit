# Pilot findings (human auditor)

Pilot: pilot-1
Target: <repository name>
Commit: <full commit sha the human and zk-audit both reviewed>
Auditor: <auditor or firm>
Report: <where the human's report lives; it may be private>

One row per finding of the human report, in scope for the pilot. Severity
is critical, high, medium, low or info (the mapping from the auditor's
scale is in docs/pilots.md). Location is `file:line` or `file:line-end` at
the pilot commit; add more places separated by commas. Match is an optional
regular expression the matching zk-audit record must contain; write `\|`
for a bar inside the table.

| Id | Title | Severity | Location | Match | Class |
|---|---|---|---|---|---|
| H-01 | <title> | <critical> | `<path/to/file.go:10-14>` | <(?i)word\|other> | <soundness> |
