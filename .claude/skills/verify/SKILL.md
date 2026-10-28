---
name: verify
description: Prove install-modsec-patch.sh (Onebox ModSecurity fleet patch) works by installing it on throwaway docker boxes laid out like the real proxies and driving real HTTP traffic and operator commands through them. Use after ANY change to install-modsec-patch.sh (new exclusion, field, endpoint, baseline setting, audit/install logic), before committing it, and before rolling a PATCH_VERSION to UAT or the fleet.
---

# verify — install-modsec-patch.sh

The product is an operator script, `install-modsec-patch.sh` (repo root of
`fail2ban/`). Its users touch two surfaces: the **CLI** (install / `--audit` /
`--status` / `--uninstall` on a box) and the **WAF behaviour** it produces
(which HTTP requests nginx+ModSecurity block or pass). Both are driven here, on
docker boxes, never on a real proxy.

Everything goes through one helper, run from anywhere:

```bash
.claude/skills/verify/verify.sh run            # journeys whose inputs changed since their last PASS
.claude/skills/verify/verify.sh run --all      # all journeys (~90 s)
.claude/skills/verify/verify.sh run bypasses   # named journey(s)
.claude/skills/verify/verify.sh status         # last result per journey, current/STALE
.claude/skills/verify/verify.sh doctor         # read-only readiness check
.claude/skills/verify/verify.sh cleanup        # remove leftover verify boxes
```

Paths below are relative to the `fail2ban/` repo root.

## Which journeys to run (keep it cheap)

Each journey is fingerprinted from the parts of `install-modsec-patch.sh` it
proves, plus its own journey file, the fixtures, `verify.sh`, `Dockerfile`, and
`stub-backend.py`. The parts are:

| part | lines of install-modsec-patch.sh | journeys that depend on it |
|---|---|---|
| data | `PATCH_VERSION=` .. `content_hash()` (lists, BASELINE, generators) | install-coverage, bypasses, legit-traffic |
| audit | the embedded `python3 - <<'PY_AUDIT'` block (audit + legacy retire) | install-coverage, lifecycle, audit-edges |
| flow | everything else (detection, install, rollback, uninstall) | install-coverage, lifecycle, audit-edges |

- **While iterating:** `verify.sh run`. Unchanged journeys print `skip` and keep
  their recorded PASS (`state/results.json`), so only what you touched re-runs.
- **Before commit, before a UAT/fleet rollout, after a PATCH_VERSION bump:**
  `verify.sh run --all`. A full run is ~90 s and prints ~10 lines, so there is
  no reason to skip it at a release point.
- **New feature in the script = new checks in a journey, in the same change.**
  A new endpoint exclusion gets a `legit-traffic` check (the request that was
  blocked now returns 200) **and** a scoped control (the same body on another
  path is still blocked). A new setting gets an `install-coverage` check. A
  new operator path gets a `lifecycle` check. Editing the journey file makes
  that journey STALE, so the next `run` executes it.

Never weaken a check to get a PASS. If a precondition is missing, the journey
fails and the reason goes in that feature's `Gotchas`.

## Launch

`verify.sh run` does all of this. Read it only to drive something by hand.

1. **Image.** `onebox-verify:latest` is `owasp/modsecurity-crs:nginx`
   (libmodsecurity 3.0.17, CRS 4.29) plus python3 and `stub-backend.py`. It is
   built on first use or when `Dockerfile`/`stub-backend.py` change (~1 min).
   To rebuild by hand: `verify.sh image --rebuild`.
2. **Box.** `box_up legacy|fresh` in `verify.sh` does the following:
   - `docker run` the image with label `onebox.verify.run=<run-id>`
   - wait until nginx answers on `localhost:8080` inside the box
   - start the stub backend on `127.0.0.1:9000`
   - repoint `/etc/nginx/includes/proxy_backend.conf` to it
   - copy the working-tree script to `/tmp/p.sh` in the box
3. **Layout.**
   - **legacy** builds `/etc/nginx/modsec/` exactly like the old copy-over
     deploy: `fixtures/legacy/*.conf`, plus CRS in `modsec/coreruleset`, plus
     the EXTEEM-106 hand-additions from `fixtures/box-additions.conf`. nginx's
     `modsecurity_rules_file` is pointed at `modsec/main.conf`, and the
     originals are saved to `/root/orig/` for byte comparison.
   - **fresh** keeps the image's own `/etc/modsecurity.d/setup.conf` and has no
     legacy files, which matches a new nginx-mod install.
4. **Ready** means `curl localhost:8080/__ready` inside the box returns **200**,
   i.e. the request went through nginx and ModSecurity and reached the stub.

There are no host ports. Every request runs inside the box (`docker exec ...
curl`), so parallel runs and other containers never collide.

## Doctor

`verify.sh doctor` is read-only. It checks:
- docker is reachable
- host python3 is present (needed for the state file)
- the script parses (`bash -n`)
- the image is current
- no verify boxes were left behind

Run it first whenever a run errors with `ERROR ... journey aborted`.

## Drive

Inside a journey (see `journeys/*.sh`), these helpers act on the current box `$BOX`:

- `bx '<shell>'`: run as root in the box and return combined output. Operator
  commands look like `bx 'cd /tmp && bash p.sh; echo "EXIT=$?"'`, `bx 'bash
  /tmp/p.sh --audit'` and `bx 'bash /tmp/p.sh --uninstall'`.
- `http <curl args>`: run curl in the box and return only the HTTP code. Use
  `http://localhost:8080/<path>` as the target. **200 means the request got
  through** to the stub, and 501 means it got through with a method the stub
  doesn't implement. **403/400/413 mean a WAF or nginx decision.**
- `check "<name>" <want> "<got>"`: compare a result. `want` can be an exact
  value, `!value` (anything but), or `~regex`. Only failures are printed.
- `info "<text>"`: report a known, accepted state. It is never a failure.
- `evidence "<label>" "<output>"`: write full command output to the log.

**Threshold gotcha:** the patch sets an inbound anomaly threshold of 7, and a
single critical rule scores 5. So an attack request that should be blocked has
to trip **two** rules, and a scoping control needs a body that trips the
excluded rule plus one more. `1' AND sleep(5)#` trips 942100 + 942160, for
example. Probe candidates on a box first (see `features/legit-traffic.md`).

## Evidence

- **Location:** every run writes `evidence/<run-id>/<journey>.log`, holding each
  check's PASS/FAIL line plus the full install/audit output. The evidence
  directory is gitignored and survives `cleanup`.
- **State:** `state/results.json` (committed) records per journey the
  fingerprint, result, check count, time, HEAD commit and log path. This is how
  a later session knows what is already proven without re-running it.
- **Proof standard:**
  - Use the real operator path: run the script itself, not its functions.
  - Use real HTTP through nginx and ModSecurity, not rule-file inspection.
  - Check side effects as well as output: files byte-identical after uninstall
    or rollback, the managed directory present or absent.
  - A WAF exclusion is only proven when paired with a control showing the
    protection still holds outside its scope.

## Cleanup

`run` removes its own boxes when each journey ends and again on exit (trap),
by label `onebox.verify.run=<run-id>`. `verify.sh cleanup` removes every box
with the `onebox.verify.run` label, so it only touches boxes verify created.
Nothing is killed by name, and evidence is never deleted.

## Stand-in, not the real target

The boxes stand in for the Ubuntu proxies, so these things are **not** proven
here:
- **systemd reload.** Boxes use `nginx -s reload`; the script's
  `systemctl reload nginx` path is untested.
- **CRS version.** Real boxes run CRS **4.31.0-dev** (EXTEEM-106) and their own
  libmodsecurity build. Rule IDs or behaviour may differ.
- **Thai fix.** `install-crs-thai-fix.sh` is not applied in boxes. Real boxes
  have it, which changes which CRS rules fire on Thai text.
- **Box layout.** Real boxes may hold hand-edits the fixtures don't have. Run
  `--audit` read-only on the real box before installing.

So after the boxes pass, do the rollout's first UAT step on
OneBox-Proxy01-UAT: `--audit`, then install, then watch BLOCK alerts.

## Feature map

See `features/README.md`, which has one file per journey and lists the
features that aren't mapped yet. `/maintain-verification-skill` keeps it
honest.
