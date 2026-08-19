# Project 6 — GRC Risk Assessment (NIST CSF)

A full, professional-grade risk assessment and security policy framework for a fictional
mid-size logistics/environmental-services company, written as an actual GRC analyst
deliverable — not a bullet list. This is deliberately the project that leans hardest into
a Management Engineering background: it's a business/risk document with technical
credibility underneath it, which is exactly the hybrid GRC roles described in the roadmap
are short on.

## Files

- **[`Meridian_Risk_Assessment_NIST_CSF.docx`](Meridian_Risk_Assessment_NIST_CSF.docx)** —
  the primary deliverable. ~15 pages: title page, document control, table of contents,
  executive summary, scope & methodology, a 12-asset inventory, risk scoring methodology,
  a 10-risk register (landscape table, inherent vs. residual scoring), a full security
  policy set mapped to all 5 NIST CSF functions, a prioritized remediation roadmap, and a
  conclusion.
- `asset_inventory.csv` / `risk_register.csv` — the same underlying data as flat files, for
  dropping into a spreadsheet or a GRC tool.
- `build/generate.js` — the docx-js script that generates the Word document
  programmatically (see below for why that's the case).

## Why this is a fictional company

This assesses **Meridian Environmental Logistics**, a fictional company built to be
realistic for the logistics / environmental-services sector — not naming any real employer.
It's realistic on purpose: fleet telematics, a customer billing portal, an ERP/finance
system, and — the detail that makes this more than a generic template — environmental
compliance data that gets reported to regulators, which creates a distinct category of risk
(data integrity tied directly to a business's operating license) that a generic "risk
assessment template" wouldn't surface. Two of the ten risks in the register (R-03, R-08)
exist specifically because of that sector context.

## Resume bullet

> Authored a NIST CSF-aligned cybersecurity risk assessment for a simulated mid-size
> organization: a 12-asset inventory, a 10-item risk register scoring both inherent and
> residual risk, and a full security policy framework mapped to all five NIST CSF functions
> (Identify, Protect, Detect, Respond, Recover), each control traced to a specific
> identified risk.

## Methodology notes (worth being able to speak to in an interview)

- **Inherent vs. residual risk, scored separately.** Every risk shows both "how bad would
  this be with no controls" and "how bad is it given what's actually in place today." That
  distinction is what makes a risk register useful for prioritization instead of just being
  a list of bad things that could happen — R-01 (ransomware) inherently scores 20/25
  (Critical) but residual is 10/25 (High) once existing backups/AV are counted, which is
  the actual argument for *why* the roadmap prioritizes dual-approval and tested restores
  over things that are already partially mitigated.
- **Every policy traces to a risk ID.** Section 5 doesn't list generic NIST CSF best
  practices — each bullet cites the specific risk(s) it addresses (e.g., `[R-01, R-02,
  R-09]`), so the framework reads as a direct response to the assessment rather than a
  copy-pasted checklist.
- **The roadmap is sequenced, not just prioritized.** Section 6 splits recommendations into
  near-term (0–3 months, addressing the Critical/High residual risks specifically),
  mid-term (3–6 months), and ongoing — with an owner named for each item.

## How the document was built

Written programmatically with [`docx`](https://www.npmjs.com/package/docx) (`build/generate.js`)
rather than by hand in Word, so the risk register, scoring, and CSV exports all derive from
one shared source of data — the numbers in the Word tables and the CSVs can't drift out of
sync with each other. To regenerate:

```bash
cd build
npm install
node generate.js       # writes build/output.docx
node export_csv.js     # writes ../asset_inventory.csv and ../risk_register.csv
```

Content was verified with `pandoc -t markdown output.docx`, confirming all headings,
tables (including the landscape-oriented risk register, which needs the extra page width
for 10 columns), and body text render correctly in the final `.docx`.
