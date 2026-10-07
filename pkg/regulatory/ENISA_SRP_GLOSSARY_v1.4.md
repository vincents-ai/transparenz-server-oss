# ENISA CRA Single Reporting Platform — Glossary v1.4

**Source:** https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary
**Version:** 1.4 — last update 01 October 2026
**Retrieved:** 2026-10-07 (human copy; ENISA blocks automated fetch — HTTP 403)

This is the authoritative field list for CRA Article 14 reporting through the SRP.
It is recorded here because `pkg/regulatory/corpus.go` needs it to set
`IdentifierPosition` on every field, and because ENISA's own guidance may change.

**Platform:** https://portal.cra-srp.enisa.europa.eu — available from 11 September 2026

## Columns

`pos` = glossary position · `applies` = AEV / SI / Both · `req` = Required status per stage

Stages: **EW** = Early Warning (24h) · **72h** = Notification · **FR** = Final Report

## Common fields (1–18)

| pos | Field | applies | req |
|---|---|---|---|
| 1 | Notification type (Vulnerability/Incident) | Both | Required |
| 2 | Title | Both | Required · max 255 chars |
| 3 | Summary | Both | Required · max 4000 chars |
| 4 | Manufacturer name | Both | Required · platform-populated, read-only |
| 5 | Member States where product available (Concerned CSIRT) | Both | Required |
| 6 | Product Name | Both | Required · max 255 chars |
| 7 | Product Version | Both | Required · max 255 chars · ranges allowed |
| 8 | Product Type (Default / Important / Critical) | Both | Optional |
| 9 | Product class (Class I / Class II) | Both | Optional |
| 10 | Product category (CRA Annexes III/IV) | Both | Optional |
| 11 | End of support indicator | Both | Optional · Yes/No |
| 12 | Component name | Both | Optional · max 255 chars |
| 13 | Mitigating measure expected shortly | Both | Optional · Yes/No |
| 14 | User action able to reduce impact | Both | Optional · max 4000 chars |
| 15 | Considered sensitivity of information | Both | Optional |
| 16 | Corrective or mitigating measures taken | Both | **Required at FR** · max 2000 chars |
| 17 | Corrective or mitigating measures users can take | Both | **Required at FR** · max 4000 chars |
| 18 | Attack vector | Both | Optional (N/A at EW) · max 255 chars |

## Actively Exploited Vulnerability (v19–v30)

| pos | Field | req |
|---|---|---|
| v19 | CVE ID | Optional · max 255 |
| v20 | EUVD ID | Optional · max 255 |
| v21 | General information | **Required at 72h** · max 4000 |
| v22 | Date when corrective/mitigating measure has been available | **Required at FR** |
| v23 | Details about the security update/corrective measure available | **Required at FR** · max 2000 |
| v24 | Full description of the Severity of the vulnerability | **Required at FR** · max 4000 |
| v25 | Full description of the Impact of the vulnerability | **Required at FR** · max 4000 |
| v26 | Date and time when you became aware of the AEV ¹ | **Required at EW** |
| v26a | Date and time when the AEV occurred (UTC) | **Required at 72h** |
| v27 | Malicious actor that has/is exploiting the vulnerability | **Required at FR if available** · max 100 |
| v28 | Particular Exceptional Circumstances (PEC) | Optional · N/A at EW/FR |
| v29 | PEC Delay Reason | Optional · N/A at EW/FR |
| v30 | Please provide further information | Optional · max 800 |

**PEC** (v28/v29) — the three legally specified circumstances in the third subparagraph of
Art. 16(2) CRA: (a) actively exploited but confined to the coordinator CSIRT's Member State;
(b) further dissemination would compromise essential national security or defence interests;
(c) further dissemination poses an imminent high cybersecurity risk that cannot yet be mitigated.

## Severe Incident (i31–i39)

| pos | Field | req |
|---|---|---|
| i31 | Incident suspected of unlawful or malicious acts | **Required at EW** · Yes/No/Unknown |
| i32 | General information about the nature of the incident | **Required at 72h** · max 4000 |
| i33 | Applied and ongoing mitigation measures | **Required at FR** · max 4000 |
| i34 | Detailed description of the Severity of the incident | **Required at FR** · max 4000 |
| i35 | Detailed description of the Impact of the incident | **Required at FR** · max 4000 |
| i36 | Type of Threat or root cause likely to have triggered the incident | **Required at FR** · max 255 |
| i37 | Date and time when you became aware of the incident (UTC) ² | **Required at EW and 72h** |
| i38 | Date and time when the incident occurred (UTC) | **Required at 72h** |
| i39 | Initial assessment of the incident | **Required at 72h** · max 4000 |

## Case-management notes (40–41)

| pos | Field | req |
|---|---|---|
| 40 | AR Note — authorised representative free-text supplement | Optional |
| 41 | CSIRT Note — designated CSIRT free-text note | Optional |

## Footnotes

¹ v26 will be available in the next release of the Platform.
² In the current release i37 is named **"Date and time when the incident was detected (UTC time)"**.

## Not in the glossary

Reporting timestamps, the reporter identity, and the notification-stage selector are not
glossary fields and are not prepared in advance — the stage selector is chosen by the reporter.

## Operational notes

- The clock runs from **awareness**, not from registration. The platform's own counters are
  not the deadline.
- Notifications go to the coordinator CSIRT of the Member State of main establishment, with a
  fallback chain for manufacturers established outside the EU. The receiving CSIRT disseminates
  to other CSIRTs whose territory the manufacturer flagged as affected.
- Platform support: `cra-srp-helpdesk@enisa.europa.eu`.
- Platform security incidents: `cra-srp-security@enisa.europa.eu`.
- Responsible disclosure for the platform itself: `responsible-disclosure@enisa.europa.eu`.
  None of these are routes for CRA notifications about your own products.
- English only at v1.4; other platform languages are deferred to a later project phase.

## Relationship to this codebase

`EarlyWarningWindow = 24h`, `NotificationWindow = 72h` in `internal/nis2/model.go`
are corroborated by this glossary. The final report is required, not optional, at FR for
fields v22–v25, i33–i36 — the corpus should assert that, not merely record the position.