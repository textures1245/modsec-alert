# Operator lifecycle

## Sub-features
- Repatch same version: nothing retired, "changes ... none", exit 0.
- `--uninstall`: managed dir gone, legacy files and main.conf byte-identical to pre-install (retired markers stripped).
- Rollback: an install whose `nginx -t` fails after retiring exits 3 and restores every file.
- Upgrade: last committed script (HEAD) installed, then the working tree — prints the diff vs the previous version.
- Fresh box (no legacy files): installs, nothing to retire.

## How to get to it (user POV)
`./install-modsec-patch.sh` (again), `--uninstall`, or a new script version over an old one.

## Driving it with verify.sh
`verify.sh run lifecycle`. Boxes: `box_up legacy` then `box_up fresh`. Byte checks: `cmp /etc/nginx/modsec/<f> /root/orig/<f>`. Failing install: `bad.sh` = script with an extra `ENDPOINTS` entry `ruleRemoveById=bogus;;` that nginx -t rejects.

## Gotchas
- Upgrade step is `info` when the working tree equals HEAD (nothing to upgrade from).
- Real boxes reload via systemctl; boxes fall through to `nginx -s reload` — systemd path unproven here.
