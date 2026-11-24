# Stage 1 — Open-source research comparison

Inspected 2026-11-23 by shallow-cloning each repository (last 30 commits) and reading its LICENSE,
README and data files. **Star counts, open-issue counts and GitHub security advisories were not
retrieved**: the GitHub REST API was not reachable from the build environment. Fill those columns
from the GitHub UI before relying on this matrix for a buy/build decision.

| Repository | License (verified in repo) | Last commit | Latest tag | Language / size | Activity |
|---|---|---|---|---|---|
| usnistgov/OSCAL | NIST public domain (US Gov work) | 2026-08-06 | v1.2.3 | Metaschema/XML, 307 files | Active |
| oscal-compass/compliance-trestle | Apache-2.0 | 2026-11-23 | v5.2.1 | Python, 1,574 files | Very active |
| mitre/saf (SAF CLI) | Apache-2.0 | 2026-11-21 | v1.2.24 | TypeScript, 639 files | Very active |
| mitre/heimdall2 | Apache-2.0 | 2026-11-21 | v2.15.0 | TypeScript/Vue, 1,177 files | Very active |
| prowler-cloud/prowler | Apache-2.0 | 2026-11-23 | 5.52.0 | Python, 13,404 files | Very active |
| opencontrol/compliance-masonry | US Gov public domain | 2026-02-15 | v1.1.6 | Go, 977 files | Low (no commits in 9 months) |
| nealfennimore/cmmc | **Elastic License 2.0** (≤ 1.0.0 was MIT) | 2026-11-03 | 1.9.1 | TypeScript + Python notebooks | Active |
| jonathancaruso/awesome-cmmc | CC0-1.0 | 2026-03-05 | — | Markdown list | Low |

## Reusable capabilities, limits, integration approach

| Repository | What we can reuse | Engineering limits | Integration decision |
|---|---|---|---|
| OSCAL | Normative models (catalog, profile, SSP, assessment-plan/results, POA&M) | Only SP 800-171 **Rev. 3** catalog is published in `oscal-content`; CMMC needs **Rev. 2** | Use as the export/interchange format (Stage 6). Our Rev. 2 package is our own JSON, mapped to OSCAL on export. |
| compliance-trestle | OSCAL Python models, validation, markdown authoring | Heavy dependency tree; opinionated repo layout | Use `trestle` (Apache-2.0) as a library for OSCAL serialization + schema validation in Stage 6. |
| mitre/saf | HDF converters (Nessus, Prowler, Burp, SonarQube…), threshold checks | Node CLI; run as a sidecar job, not in-process | Stage 5: run SAF CLI in a container to normalize scanner output to HDF, then ingest HDF as technical evidence. |
| heimdall2 | HDF viewer, comparison | Separate app | Link out / embed for drill-down; do not fork. |
| prowler | Cloud checks with **CMMC mappings** (`cmmc_2.0.json`: 149 reqs incl. L1/L2/L3, checks per provider) | Its mapping is check-to-requirement, not proof of an objective | Stage 5 connector: run Prowler (Apache-2.0) with a read-only workload identity; store findings as `configuration`/`technical_test_result` evidence linked by requirement. |
| compliance-masonry | OpenControl YAML component model | Low activity; OpenControl superseded by OSCAL | Do not depend on. Optional one-way import of legacy OpenControl data. |
| nealfennimore/cmmc | Clean extraction of AG v2.13 requirements + 320 objectives | **ELv2 forbids offering it as a hosted service** | Used **only the MIT-licensed 1.0.0 tag**, only for public-domain NIST/DoD text. No code copied. Point values transcribed independently from 32 CFR 170.24 and cross-checked (110/110). See NOTICE.md. |
| awesome-cmmc | Curated pointers | List only | Reference reading. |

## Standards verified against primary sources (eCFR, retrieved 2026-11-23)

- **32 CFR 170.24** — Level 2 max score 110; NOT MET deducts 5/3/1; MFA (3.5.3) and FIPS crypto
  (3.13.11) have 3-point partial credit; N/A counts as MET; missing/stale SSP (3.12.4) means the
  assessment cannot be completed. Our transcription: 42×5, 14×3, 51×1, 2 special, SSP unscored →
  max deduction 313, minimum score −203.
- **32 CFR 170.21** — Conditional POA&M only if score/110 ≥ 0.8, every POA&M item ≤ 1 point except
  3.13.11 at the 3-point partial, and never 3.1.20, 3.1.22, 3.12.4, 3.10.3, 3.10.4, 3.10.5;
  closeout within 180 days; **no POA&M at Level 1**.
- CMMC incorporates **SP 800-171 Rev. 2** / 800-171A (2018). Rev. 3 is *not* substituted — the
  catalog package is pinned to Rev. 2 and says so.
