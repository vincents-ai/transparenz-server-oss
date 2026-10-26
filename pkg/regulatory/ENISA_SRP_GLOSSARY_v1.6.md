# ENISA CRA Single Reporting Platform — Glossary v1.6

**Source:** https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2
**Version:** 1.6 — last update 21 October 2026
**Retained:** 2026-10-26, fetched directly (HTTP 200; ENISA answers a browser
user-agent and refuses some automated clients).

**Provenance, and what the hash covers.** This file is a normalisation of the
published page rather than its raw HTML: prose the publisher spreads across
unlabelled table cells is placed under one column and the three per-stage
columns are given fixed headers. A SHA-256 over this file therefore attests to
*this transcription*, not to ENISA's markup. `ENISA_SRP_GLOSSARY_v1.6.table.tsv`
sits beside it holding the field positions, applicability and the three
requiredness columns verbatim from the published table, and
`TestV16MatrixMatchesThePublishedTable` compares that against the schema on every
test run — so the transcription is checked against the authority's own table
rather than believed.

An earlier operator-supplied copy of the same version produced this file; the
direct fetch agreed with it on every position, applicability and requiredness
value, and is what the retained copy is now based on.

Unlike v1.4, v1.6 publishes an explicit per-stage requiredness column for **every**
field, including the common fields. That is the single most consequential
difference between the two versions: v1.4's transcription recorded one
requirement per common field, so "N/A at 72h" could not be distinguished from
"not stated". See `ENISA_SRP_v1.4-v1.6-diff.md`.

## Columns

`pos` = glossary position · `applies` = AEV / SI / Both · `EW` / `72h` / `FR` =
requiredness at Early Warning (24h), 72-hour notification, Final Report.

The glossary's own vocabulary is `Required`, `Optional`, `Mandatory`, `N/A`.
They are reproduced verbatim below; `Mandatory` is the publisher's word for a
field that must be present, and is not a fifth category.

## Common fields (1–18)

| pos | Field | applies | EW | 72h | FR |
|---|---|---|---|---|---|
| 1 | Notification type (Actively Exploited Vulnerability / Severe Incident) | Both | Required | N/A | N/A |
| 2 | Title | Both | Required | N/A | N/A |
| 3 | Summary | Both | Required | N/A | N/A |
| 4 | Manufacturer name | Both | Required · platform-populated, read-only | N/A | N/A |
| 5 | Member States where product available (CDaC and Concerned CSIRTs) | Both | Required | N/A | N/A |
| 6 | Product Name | Both | Required | N/A | N/A |
| 7 | Product Version | Both | Required | N/A | N/A |
| 7a | Additional Information (about the manufacturer) | Both | Optional | N/A | N/A |
| 8 | Product Type (Default / Important / Critical) | Both | Optional | N/A | N/A |
| 9 | Product class (Class I / Class II) | Both | Optional | N/A | N/A |
| 10 | Product category (CRA Annexes III/IV) | Both | Optional | N/A | N/A |
| 11 | End of the support indicator | Both | Optional | N/A | N/A |
| 12 | Component name | Both | Optional | N/A | N/A |
| 13 | Mitigating measure expected shortly | Both | Optional | N/A | N/A |
| 14 | User Action able to reduce impact | Both | Optional | N/A | N/A |
| 15 | Considered sensitivity of information | Both | Optional | Optional | N/A |
| 16 | Corrective or mitigating measures taken | Both | Optional | Optional | **Required** |
| 17 | Corrective or mitigating measures that users can take | Both | Optional | Optional | **Required** |
| 18 | Attack vector | Both | N/A | Optional | N/A |

Character limits as published: 2 max 255 · 3 max 4000 · 6 max 255 · 7 max 255 ·
7a max 255 · 12 max 255 · 14 max 4000 · 15 max 255 · 16 max 2000 · 17 max 4000 ·
18 max 255.

Format notes: 1 is a select (Vulnerability | Incident) · 4 is system-generated /
read-only · 5 is one or more Member States · 8 is a select (Default | Important |
Critical) · 9 is a configured class · 11 and 13 are Yes/No selects.

## Actively Exploited Vulnerability (v19–v30)

| pos | Field | EW | 72h | FR |
|---|---|---|---|---|
| v19 | CVE ID | Optional | N/A | N/A |
| v20 | EUVD ID | Optional | N/A | N/A |
| v21 | General information | Optional | **Required** | N/A |
| v22 | Date when corrective or mitigating measure has been available | Optional (after completion of v17) | Optional (after completion of v17) | **Required** |
| v23 | Details about the security update / corrective measure available | Optional | Optional | **Required** |
| v24 | Description of the severity of the vulnerability | Optional | Optional | **Required** |
| v25 | Description of the impact of the vulnerability | Optional | Optional | **Required** |
| v26 | Date and time when you become aware of the Actively Exploited Vulnerability | **Mandatory** | N/A | N/A |
| v26a | Date and time when the Actively Exploited Vulnerability occurred (UTC) | Optional | copied from previous step by default | N/A |
| v27 | Malicious actor that has exploited / is exploiting the vulnerability | Optional | Optional | Required if such information is available |
| v28 | Particularly Exceptional Circumstances (PEC) | N/A | Optional | N/A |
| v29 | PEC Delay Reason | N/A | Optional upon PEC activation | N/A |
| v30 | Please provide further information | N/A | Optional under PEC activation | N/A |

Character limits: v19 max 255 · v20 max 255 · v21 max 4000 · v23 max 2000 ·
v24 max 4000 · v25 max 4000 · v27 max 100 · v30 max 800.

Format notes: v22 is date and time · v26 and v26a are date and time (UTC) ·
v28 is a select of the applicable PEC option(s) · v29 is a checkbox select.

**v26 is now live.** In v1.4 this field carried the footnote "will be available
in the next release of the Platform". v1.6 states it as Mandatory at early
warning and the footnote is gone.

**v28/v29/v30 are the Art. 16(2) third-subparagraph mechanism**, and all three
are unavailable outside the 72-hour notification. v22 additionally cannot be
completed before v17: the publisher states the dependency explicitly
("Optional (after completion of v17)").

## Severe Incident (i31–i39)

| pos | Field | EW | 72h | FR |
|---|---|---|---|---|
| i31 | Incident is suspected of unlawful or malicious acts | **Required** | copied from previous step, or updated | N/A |
| i32 | General information about the nature of the incident | Optional | **Required** | N/A |
| i33 | Applied and ongoing mitigation measures | Optional | Optional | **Required** |
| i34 | Detailed description of the Severity of the incident | Optional | Optional | **Required** |
| i35 | Detailed description of the Impact of the incident | Optional | Optional | **Required** |
| i36 | Type of Threat or root cause likely to have triggered the incident | Optional | Optional | **Required** |
| i37 | Date and time when you become aware of the incident (UTC) | **Mandatory** | N/A | N/A |
| i38 | Date and time when the incident occurred (UTC) | Optional | Optional | N/A |
| i39 | Initial assessment of the incident | Optional | **Required** | N/A |

Character limits: i31 max 255 · i32 max 4000 · i33 max 4000 · i34 max 4000 ·
i35 max 4000 · i36 max 255 · i39 max 4000.

Format notes: i31 is published as **free text** — it was a Yes/No/Unknown select
in v1.4's transcription. i36 is a classification plus short explanation.

## Case-management notes (40–41)

| pos | Field | applies | EW | 72h | FR |
|---|---|---|---|---|---|
| 40 | AR Note — assigned representative free-text supplement | Both | Optional | Optional | Optional |
| 41 | CSIRT Note — designated CSIRT free-text note | Both | Optional | Optional | Optional |

Field 40 is authored by the **assigned representative**; field 41 by the
designated CSIRT. Neither is manufacturer-authored content in the ordinary
sense, and field 41 must never be populated by this product.

## Consequences of the per-stage matrix

Most fields are N/A, not merely optional, outside one or two stages. The form is
not "cumulative with everything optional later": at 72 hours the AEV fields that
apply are v21–v25, v26a, v27, v28–v30, while v19, v20 and v26 are N/A. At the
final report the required set is v22–v25 plus the common fields 16 and 17 (and
v27 where attribution exists), while v19–v21, v26, i32 and i39 are N/A.

A validator that models every field as available at every stage, carrying values
forward, disagrees with this table in both directions: it demands fields the
platform marks N/A, and it omits fields the platform demands.
