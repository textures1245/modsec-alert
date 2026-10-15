# Install + coverage audit

## Sub-features
- Install on a box with the legacy `/etc/nginx/modsec` layout: writes managed before/after-crs.conf, adds Include lines, retires covered legacy statements, reloads.
- Retire report: grouped by reason; uncovered statements printed as "kept active".
- Change summary vs the previously installed version ("first install" on a new box).
- `--audit` / `--audit --json`: coverage of RULES x FIELDS, ENDPOINTS, GLOBAL_REMOVE; restored rules ACTIVE; baseline settings in effect.

## How to get to it (user POV)
On the proxy, as root: `./install-modsec-patch.sh`, then `./install-modsec-patch.sh --audit`.

## Driving it with verify.sh
`verify.sh run install-coverage`. Box: `box_up legacy`. Install via `bx 'cd /tmp && bash p.sh; echo "EXIT=$?"'`. Proof = exit 0, `RESULT: COVERED`, `200002 ACTIVE ... 200005 ACTIVE`, `baseline settings N:  all in effect`, JSON parses, plus live smoke (XSS 403, Thai path 200).

## Gotchas
- Depends on every part of the script, so it is STALE after any edit — the cheap smoke that always runs.
- "kept active" must list `id:1000010` (business-drive 920640 line from EXTEEM-106) until 920640 is decided.
