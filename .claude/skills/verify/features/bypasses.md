# Closed WAF bypasses

## Sub-features
- A: `?z=/onlyofficeds/` in any query string used to disable blocking (legacy `REQUEST_URI @rx /onlyofficeds/` + ctl:ruleRemoveById=949110).
- B/B2/F: payload after padding past the no-files body limit skipped inspection (ProcessPartial + 200002 removed) — JSON and urlencoded.
- C: body invalid from byte 0 produced no ARGS (200002 removed).
- D: `/onlyofficeds/` exclusion must not match `/onlyofficedsX`.

## How to get to it (user POV)
An attacker sends HTTP to any vhost behind the proxy; nothing to click.

## Driving it with verify.sh
`verify.sh run bypasses`. Box: `box_up legacy` + install. Payload files are built in the box (`/tmp/big.json` 140 KB, `/tmp/huge.json` and `/tmp/form.txt` 1.1 MB). Proof = every request is non-200 (403 from anomaly, 400 from 200002).

## Gotchas
- E (`/business-drive/../api/...` with method FOO) is `info`, not a check: the kept legacy line 1000010 is not path-normalized and still sheds 911100. Turns into a check once 920640 moves into ENDPOINTS.
- 400 from 200002 and 403 from 949110 are both "blocked"; the stub never returns them.
