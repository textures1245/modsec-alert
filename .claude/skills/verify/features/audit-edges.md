# Audit truthfulness

## Sub-features
- On the legacy layout before install: NOT COVERED; flags SPOOFABLE onlyofficeds, ProcessPartial-with-200002-off, `[REMOVED] rule 200002`; stock CRS files are not orphans.
- Hand-edited managed file → `[DRIFT]`, exit 1.
- Managed Include removed → `NOT-LOADED` and MISSING, exit 1.
- No CRS on the Include chain → exit 2 (never a false COVERED).
- Inline `modsecurity_rules` in a file nginx loads → UNKNOWN gap; in a file nginx does not load → ignored.
- python3 missing → exit 2.

## How to get to it (user POV)
`./install-modsec-patch.sh --audit` (or `--audit --json` for fleet collection) on any box, any state.

## Driving it with verify.sh
`verify.sh run audit-edges`. Box: `box_up legacy`, audit before install, then install and break/restore one thing per check inside a single `bx` call so the box returns to COVERED (last check proves it).

## Gotchas
- Each edge case restores what it broke in the same `bx` call; a failed restore shows up as the final "back to COVERED" check failing.
