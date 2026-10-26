# ENISA SRP Glossary: v1.4 → v1.6 — what actually changed, and what it breaks here

**Compared:** `ENISA_SRP_GLOSSARY_v1.4.md` (last update 01 Oct 2026, retrieved
2026-10-07) against `ENISA_SRP_GLOSSARY_v1.6.md` (last update 21 Oct 2026,
retained 2026-10-26).

**v1.5 was not obtained and is not compared.** It is an intermediate release
this product never shipped against. A v1.4 → v1.6 diff answers the compliance
question; a v1.4 → v1.5 → v1.6 chain would only add a version this code has no
records under.

## How far this diff can be trusted

The v1.4 file in this directory is a **transcription**, and for the common
fields it recorded a single requirement per field rather than the three
per-stage columns v1.6 publishes. So for those fields a per-stage difference
cannot be separated from a gap in the v1.4 transcription. Claims below are
labelled:

- **CHANGED** — both versions state the fact explicitly and they disagree.
- **UNDERSPECIFIED IN v1.4** — v1.6 states something v1.4's transcription did
  not, and the earlier text is silent rather than contradictory.
- **UNCHANGED** — both agree.

## Changes (evidence-backed)

| # | Field | v1.4 | v1.6 | Kind |
|---|---|---|---|---|
| 1 | **7a Additional Information** (manufacturer) | absent | Optional, EW only, max 255 | **NEW FIELD** |
| 2 | **i37** incident awareness timestamp | "Date and time when the incident was **detected**"; Required at EW **and 72h** | "Date and time when you **become aware** of the incident"; Mandatory at EW; **N/A at 72h** | **CHANGED** — scope narrowed, semantics renamed |
| 3 | **i38** incident occurrence timestamp | Required at 72h | Optional at EW and 72h; N/A at FR | **CHANGED** — no longer required |
| 4 | **i31** suspected unlawful/malicious acts | Required at EW, format Yes/No/Unknown **select** | Required at EW, format **free text** | **CHANGED** — format |
| 5 | **v26** AEV awareness timestamp | Required at EW, with footnote "will be available in the next release of the Platform" | **Mandatory**, footnote removed | **CHANGED** — the field is now live |
| 6 | **18** Attack vector | "Optional (N/A at EW)" | N/A at EW; Optional at 72h; **N/A at FR** | **CHANGED** — N/A extended to FR |
| 7 | **v19 / v20** CVE / EUVD ID | Optional, no stage stated | Optional at EW; **N/A at 72h and FR** | **UNDERSPECIFIED IN v1.4** |
| 8 | **v22** date measure available | Required at FR | Required at FR; Optional at EW/72h **only after completion of v17** | **UNDERSPECIFIED IN v1.4** — cross-field dependency is new information |
| 9 | Common fields 1–14 | one requirement each | Required at EW; **N/A at 72h and FR** | **UNDERSPECIFIED IN v1.4** |
| 10 | 15 sensitivity | "Optional" | Optional/Optional/**N/A** | **UNDERSPECIFIED IN v1.4** |

Unchanged and now confirmed explicitly: 16 and 17 Required at FR; v21 and i32
Required at 72h; i39 Required at 72h; v23, v24, v25, i33–i36 Required at FR;
v27 Required at FR if available; v28/v29/v30 confined to the 72-hour
notification; 40/41 Optional at all three stages; every character limit.

No field was removed. No field other than i37 was renamed.

**The headline change is structural, not a field.** v1.6 publishes a per-stage
requiredness column for every field including the common ones, and the matrix is
sparse: almost every field is `N/A` outside one or two stages. v1.4's
transcription read as though the form were cumulative with everything optional
later. It is not.

## What this breaks in the corpus

`pkg/regulatory/corpus.go` models 15 fields. Three of them — evidence of
exploitation, remediation outcome, reporting closure — have **no glossary
counterpart at all**; "reporting closure" is explicitly not a glossary field.
Of the 43 positions v1.6 publishes, this code models 13 and does not model 30,
including **all 19 common fields**.

Requiredness conflicts, in the direction that matters — `schema.Validate`
reports an error when a value is supplied for a field marked
`RequirementNotApplicable` (`schema.go`, "field does not apply to … but a value
was supplied"):

| Corpus field | Code says | v1.6 says | Consequence |
|---|---|---|---|
| `FieldAttackVector` | Required at EW (both classes), inherited at 72h/FR | 18: **N/A at EW**, Optional at 72h, **N/A at FR** | The AEV and SI early-warning fixtures demand a field the platform rejects at that stage, and carry it into the final report where it is also N/A |
| `FieldCVEID` | Optional EW, **inherited at 72h/FR** | v19: Optional EW, **N/A at 72h/FR** | Validator accepts — and the schema implies — a CVE at the final report |
| `FieldEUVDID` | Optional at **all six** combinations | v20: Optional EW, **N/A later** | same |
| `FieldIncidentNature` | **Required at EW**, inherited | i32: Optional EW, **Required at 72h**, N/A FR | Wrong stage in both directions |
| `FieldRootCause` | Required at 72h, inherited at FR | i36: Optional EW/72h, **Required at FR** | Requiredness attached to the wrong stage |
| `FieldImpact` | **Required at EW** | i35: Optional EW/72h, **Required at FR** | early warning is over-specified |
| `FieldIncidentMitigation` | **Required at 72h** | i33: Optional EW/72h, **Required at FR** | same |
| `FieldMitigation` | Required at **72h**, inherited at FR | v22/v23: Optional EW/72h, **Required at FR** | same |
| `FieldActor` | Optional everywhere | v27: **Required at FR** if available | under-specified |
| `FieldPEC` | N/A at EW/FR, Optional at 72h | v28: N/A at EW/FR, Optional at 72h | requiredness correct; identifier wrong |

Absent fields that v1.6 marks required at some stage, and so cannot be placed in
any package this code builds:

- **Required at EW:** 1 Notification type · 2 Title · 3 Summary · 4 Manufacturer
  name · 5 Member States · 6 Product Name · 7 Product Version · **v26 / i37
  awareness timestamp** · i31
- **Required at 72h:** v21 General information · i39 Initial assessment
- **Required at FR:** 16 · 17 · v22 · v23 (v24, v25 and i33–i36 exist only as
  differently-identified fields)

The awareness timestamps are the serious omission. `cra.DeadlineAt` anchors every
statutory deadline on awareness and refuses to compute without it
(`ErrNoAwareness`), and `models.CRAReport` stores it — but no code path maps it
into an SRP package. After v1.6 the platform marks it Mandatory at early warning
for both event classes, so the one value that starts the clock is also the one
value a package cannot carry.

## Why no schema version can simply be renumbered

`BuildSRPGlossarySchemaV2` differs from V1 only in v19 and v20. Publishing a
"v1.6" schema on that base would attach a version string that implies a
transcription that has not happened. The work is a field inventory and a
requiredness matrix, not a relabel — hence the crosswalk must come first, then
the artifact is registered with a real hash, and only then is a new schema ID
justified.

Two v1.6 details to carry into that work rather than rediscover:

- Field **4** is platform-populated and read-only, and field **5** pre-fills the
  CDaC. A generated package cannot authoritatively set either; it can only
  confirm them.
- Field **41** is authored by the designated CSIRT. Writing to it would be
  fabricating another party's record.
