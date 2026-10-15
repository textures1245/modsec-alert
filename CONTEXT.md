# Onebox ModSecurity — Domain Glossary

**Patch** — The versioned, fleet-identical set of false-positive exclusions defined in one script. Identified by a **Patch Version** (`PV-YYYY-MM-DD`). The copy of the script being run *is* the latest Patch; there is no remote lookup.

**Global exclusion** — A (rule, field) pair removed from inspection on every endpoint. A Patch's global exclusions are the full cross product of its rule list and field list.

**Endpoint exclusion** — An exclusion scoped to a URL prefix: either a whole rule, or a (rule, target) pair, removed only for requests under that prefix.

**Managed config** — The config files a Patch writes and owns on a box. Never hand-edited.

**Legacy exclusion** — Any exclusion loaded on a box that is not part of the Managed config (hand-written `sec_actions.conf` lines, per-endpoint drafts, whitelist output). Not necessarily wrong; a candidate to retire once the Patch covers it.

**Loaded config** — The config files nginx actually loads, found by following the include chain from ModSecurity's main rules file. Files that exist on disk but are not on the chain are **Orphan files** and grant no coverage.

**Coverage** — Whether each exclusion in the latest Patch is in effect on a box via the Loaded config, from either the Managed config or a Legacy exclusion. A box is **Covered** when every Patch exclusion is in effect.

**Coverage state** — Per Patch exclusion:
- **FULL** — in effect at the same or broader scope (Managed config, or an equivalent global Legacy exclusion)
- **PARTIAL** — in effect only for some endpoints (narrower-scoped Legacy exclusions)
- **INEFFECTIVE** — an exclusion exists but is loaded where it cannot act (a per-request exclusion that only runs after the rule it targets has already been evaluated)
- **UNKNOWN** — scope cannot be determined mechanically (regex/chained/IP conditions, inline nginx rules); needs a human
- **MISSING** — no exclusion at all
- **N/A** — the rule is not loaded on the box, so there is nothing to exclude

Only FULL and N/A pass.

**Drift** — Managed config on a box whose content no longer matches what its recorded Patch Version would generate (someone hand-edited it).

**Risk tag** — Severity attached to an exclusion found in an audit:
- 🔴 engine off or a rule removed entirely
- 🟡 a rule removed for one endpoint
- 🟢 a single field removed from a rule

**Audit** — A read-only report of a box's Loaded config: its Coverage of the latest Patch, every Legacy exclusion with its Risk tag, Orphan files, and Drift.

_Avoid_: "whitelist" for exclusions (it also means the IP/path whitelist script, which is a different thing).
