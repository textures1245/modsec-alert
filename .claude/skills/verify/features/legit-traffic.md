# Legit Onebox traffic

## Sub-features
- Large clean JSON (500 KB, under the 1 MiB no-files limit).
- WebDAV methods (PROPFIND) via `tx.allowed_methods`.
- OnlyOffice `parentOrigin` URL (934110), Thai cost-estimate path `json.path_file` (932370), centrifugo `json.data.array_1.file_path_real` (932370).
- check_duplicate_inbox `header_info.Doc_remark1` (942100) — with a control proving the exclusion is scoped.
- business-drive raw PUT 20 MB (rclone/WebDAV), multipart 2 MB; multipart 20 MB is denied by design (> SecRequestBodyLimit 13 MB).

## How to get to it (user POV)
Onebox web/app users uploading, opening documents, saving items — the requests that produced the BLOCK alerts.

## Driving it with verify.sh
`verify.sh run legit-traffic`. Box: `box_up legacy` + install. Each check is one `http ...` call with the real path and body shape; 200 = reached the backend.

## Gotchas
- Threshold is 7 and one critical rule scores 5: an FP request only reproduces a block if it trips two rules. A scoping control needs a body that trips the excluded rule plus one more. Probe on a box: send the body to an unrelated path on the stock image (threshold 5) and read rule ids from `docker logs <box> | grep '^{'` (JSON audit log, `.transaction.messages[].details.ruleId`).
- When adding an endpoint exclusion to the script, add its real request here and its scoped control in the same change.
