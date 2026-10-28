# Discord run notification

## Sub-features
- Install and `--uninstall` post one Thai card: VM, public IP, old -> new Patch Version, CHANGELOG line, coverage, vhost guard, body-guard, backup path.
- Failure and rollback post a red card with the reason (exit 1/2/3).
- Not sent: `--status`, `--audit`, `--check-body`, `--print`, unknown option, `--no-notify`, `ONEBOX_NO_NOTIFY=1`.
- Webhook: `ONEBOX_NOTIFY_WEBHOOK` (test hook) else `discord_webhook` in `/etc/fail2ban/jail.d/modsec-alert.local`. None = skipped in Thai. A dead webhook is reported and the exit code is unchanged (curl -m 5).

## How to get to it (user POV)
The operator runs `install-modsec-patch.sh` on a VM and the #modsec-alerts channel shows what changed.

## Driving it with verify.sh
`verify.sh run notify`. Box: `box_up legacy`; `fixtures/notify-stub.py` (127.0.0.1:9099) stands in for Discord and appends each POST body to `/tmp/notify.json`.

## Gotchas
- Discord content limit is 2000 chars; the card is cut at 1850.
- Output is copied with `tee` and read in an EXIT trap, so every exit path (including rollback) notifies.
