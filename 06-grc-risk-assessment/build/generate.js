const fs = require('fs');
const {
  Document, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
  WidthType, ShadingType, BorderStyle, AlignmentType, PageBreak, Packer,
  TableOfContents, LevelFormat, convertInchesToTwip, VerticalAlign, PageOrientation,
} = require('docx');

const PAGE_WIDTH = 12240;  // US Letter, DXA
const PAGE_HEIGHT = 15840;
const MARGIN = 1440; // 1 inch
const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN; // 9360

const NAVY = '1F3864';
const LIGHT_BLUE = 'D9E2F3';
const RED = 'C00000';
const ORANGE = 'ED7D31';
const YELLOW = 'FFD966';
const GREEN = '70AD47';

function h1(text) {
  return new Paragraph({ text, heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 } });
}
function h2(text) {
  return new Paragraph({ text, heading: HeadingLevel.HEADING_2, spacing: { before: 300, after: 150 } });
}
function p(text, opts = {}) {
  return new Paragraph({ children: [new TextRun({ text, ...opts })], spacing: { after: 120 } });
}
function bullet(text, opts = {}) {
  return new Paragraph({
    children: [new TextRun({ text, ...opts })],
    numbering: { reference: 'bullet-list', level: 0 },
    spacing: { after: 60 },
  });
}
function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

function cell(text, { width, bold = false, shade = null, color = null, align = AlignmentType.LEFT, size = 18 } = {}) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: shade ? { fill: shade, type: ShadingType.CLEAR, color: 'auto' } : undefined,
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 60, bottom: 60, left: 80, right: 80 },
    children: [new Paragraph({
      alignment: align,
      children: [new TextRun({ text: String(text), bold, color: color || undefined, size })],
    })],
  });
}

function makeTable(columnWidths, headerRow, dataRows, { headerShade = NAVY, headerColor = 'FFFFFF' } = {}) {
  const rows = [];
  rows.push(new TableRow({
    tableHeader: true,
    children: headerRow.map((text, i) => cell(text, { width: columnWidths[i], bold: true, shade: headerShade, color: headerColor, size: 18 })),
  }));
  for (const row of dataRows) {
    rows.push(new TableRow({
      children: row.map((val, i) => {
        const v = typeof val === 'object' ? val : { text: val };
        return cell(v.text, { width: columnWidths[i], shade: v.shade, bold: v.bold, size: 17 });
      }),
    }));
  }
  return new Table({ width: { size: columnWidths.reduce((a, b) => a + b, 0), type: WidthType.DXA }, columnWidths, rows });
}

function riskShade(level) {
  if (level === 'Critical') return 'F8696B';
  if (level === 'High') return 'FFC7A0';
  if (level === 'Medium') return 'FFEB9C';
  if (level === 'Low') return 'C6EFCE';
  return null;
}

// ---------------------------------------------------------------------------
// ASSET INVENTORY DATA
// ---------------------------------------------------------------------------
const assets = [
  ['A-01', 'Fleet Telematics Platform', 'Cloud/IoT', 'GPS + engine diagnostics from ~340 collection vehicles; vendor-hosted, integrates with dispatch', 'Fleet Operations Mgr', 'Confidential', 'Integrity, Availability'],
  ['A-02', 'Dispatch & Route Optimization System', 'Software (SaaS)', 'Daily route planning, real-time dispatch to drivers', 'Operations Director', 'Internal', 'Availability'],
  ['A-03', 'Customer Billing Portal', 'Web Application', 'Customer-facing invoicing, payment, and account management', 'Finance Director', 'Restricted', 'Confidentiality, Integrity'],
  ['A-04', 'Driver Mobile App', 'Mobile Application', 'Route confirmation, e-signatures, photo proof-of-service, cached login', 'Fleet Operations Mgr', 'Internal', 'Confidentiality'],
  ['A-05', 'ERP / Finance System', 'Software (on-prem + cloud)', 'General ledger, AP/AR, payroll integration, wire transfer approval', 'CFO', 'Restricted', 'Confidentiality, Integrity'],
  ['A-06', 'HR / Payroll System', 'SaaS', 'Employee PII, SIN/SSN, banking details, benefits', 'HR Director', 'Restricted', 'Confidentiality'],
  ['A-07', 'Corporate Email & Collaboration (M365)', 'SaaS', 'Email, Teams, SharePoint document storage', 'IT Manager', 'Confidential', 'Confidentiality, Availability'],
  ['A-08', 'Depot Wi-Fi Networks (x6 regional depots)', 'Network Infrastructure', 'Staff and guest wireless at each regional depot', 'IT Manager', 'Internal', 'Availability'],
  ['A-09', 'Environmental Compliance Data Warehouse', 'Cloud Data Platform', 'Waste volume, disposal method, and emissions data submitted to regulators', 'Compliance Officer', 'Restricted', 'Integrity, Availability'],
  ['A-10', 'Third-Party Disposal Facility Data Exchange', 'B2B Integration', 'Automated data exchange (manifests, weights) with partner disposal/recycling facilities', 'Compliance Officer', 'Confidential', 'Integrity'],
  ['A-11', 'On-Prem File Servers (regional depots)', 'Hardware/Storage', 'Local operational documents, maintenance logs, legacy scheduling files', 'IT Manager', 'Internal', 'Availability'],
  ['A-12', 'Depot CCTV & Access Control', 'Physical Security System', 'Badge access and camera systems at depots and processing facility', 'Facilities Manager', 'Internal', 'Availability, Integrity'],
];
const assetColWidths = [700, 1900, 1300, 3200, 1500, 1100, 1360];
// sum must equal CONTENT_WIDTH = 9360 -> adjust below dynamically instead

// ---------------------------------------------------------------------------
// RISK REGISTER DATA
// Likelihood 1-5, Impact 1-5, Score = L x I, Level bands: Low 1-4, Medium 5-9, High 10-16, Critical 17-25
// ---------------------------------------------------------------------------
function scoreLevel(score) {
  if (score >= 17) return 'Critical';
  if (score >= 10) return 'High';
  if (score >= 5) return 'Medium';
  return 'Low';
}
function risk(id, threat, vuln, asset, L, I, controls, resL, resI, treatment, owner, date) {
  const inh = L * I, res = resL * resI;
  return [id, threat, vuln, asset, `${L} x ${I} = ${inh}`, scoreLevel(inh), controls, `${resL} x ${resI} = ${res}`, scoreLevel(res), treatment, owner, date];
}

const risks = [
  risk('R-01', 'Phishing-delivered ransomware encrypts ERP/finance data, halting payroll and billing',
    'Limited phishing-resistant MFA; inconsistent security-awareness training; legacy VPN access to ERP',
    'A-05 ERP/Finance System', 4, 5,
    'Email filtering (basic), nightly backups (untested restore), antivirus on endpoints',
    2, 5, 'Mitigate', 'CFO / IT Manager', 'Q1 2027'),
  risk('R-02', 'Business email compromise (BEC) leads to a fraudulent wire transfer approval',
    'No dual-approval requirement above a set dollar threshold; spoofable sender display names not flagged',
    'A-05 ERP/Finance System, A-07 Email', 3, 5,
    'Manual callback verification for new vendors (inconsistently followed)',
    2, 5, 'Mitigate', 'CFO', 'Q1 2027'),
  risk('R-03', 'Falsified or tampered environmental compliance data submitted to regulators (insider or integration error)',
    'No integrity checksums on waste-volume data exchange; limited audit trail on manual data corrections',
    'A-09 Compliance Data Warehouse, A-10 Disposal Facility Exchange', 2, 5,
    'Monthly manual spot-check reconciliation by Compliance Officer',
    2, 4, 'Mitigate', 'Compliance Officer', 'Q2 2027'),
  risk('R-04', 'Unpatched IoT telematics units exploited as a pivot point into the corporate network',
    'Vendor-managed firmware with no formal patch SLA; telematics VLAN not fully segmented from corporate LAN',
    'A-01 Fleet Telematics Platform', 3, 4,
    'Vendor manages patching (no visibility into cadence); partial network segmentation',
    2, 4, 'Mitigate', 'IT Manager', 'Q2 2027'),
  risk('R-05', 'Customer billing portal compromised via injection or broken access control, exposing customer payment data',
    'Portal has not had an independent security assessment since launch; no WAF in front of the application',
    'A-03 Customer Billing Portal', 3, 5,
    'TLS in transit, PCI-scoped payment processor (tokenized, not stored directly)',
    2, 4, 'Mitigate', 'Finance Director / IT Manager', 'Q1 2027'),
  risk('R-06', 'Lost or stolen driver mobile device exposes cached credentials or customer service-location data',
    'No enforced mobile device management (MDM); devices not required to have remote wipe enabled',
    'A-04 Driver Mobile App', 4, 3,
    'App requires PIN on open; no remote wipe or MDM enrollment enforced',
    2, 3, 'Mitigate', 'Fleet Operations Mgr', 'Q3 2027'),
  risk('R-07', 'Weak depot guest Wi-Fi security allows an attacker on-site to reach internal systems',
    'Guest and staff Wi-Fi share a VLAN at two of six depots (legacy hardware)',
    'A-08 Depot Wi-Fi Networks', 3, 3,
    'WPA2 in use; guest network exists but VLAN separation incomplete at 2 of 6 sites',
    2, 3, 'Mitigate', 'IT Manager', 'Q3 2027'),
  risk('R-08', 'Cloud data warehouse misconfiguration exposes environmental/compliance data externally',
    'No automated cloud security posture monitoring; access reviews are manual and infrequent',
    'A-09 Compliance Data Warehouse', 2, 4,
    'Access restricted to Compliance team by default; no automated misconfiguration scanning',
    2, 3, 'Mitigate', 'IT Manager / Compliance Officer', 'Q2 2027'),
  risk('R-09', 'HR/Payroll SaaS breach exposes employee PII and banking details',
    'Single sign-on not enforced for the HR platform; standing admin accounts not regularly reviewed',
    'A-06 HR/Payroll System', 2, 5,
    'Vendor holds SOC 2 Type II; encrypted at rest per vendor attestation',
    1, 4, 'Mitigate', 'HR Director', 'Q2 2027'),
  risk('R-10', 'DDoS against customer billing portal during month-end billing cycle disrupts payment collection',
    'No CDN/DDoS mitigation service in front of the portal',
    'A-03 Customer Billing Portal', 2, 3,
    'Cloud host provides basic infrastructure-level protection only',
    2, 2, 'Accept (residual risk within appetite; revisit if traffic profile changes)', 'IT Manager', 'Monitor'),
];

// ---------------------------------------------------------------------------
// BUILD DOCUMENT
// ---------------------------------------------------------------------------
const doc = new Document({
  numbering: {
    config: [{
      reference: 'bullet-list',
      levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 480, hanging: 240 } } } }],
    }],
  },
  sections: [{
    properties: {
      page: {
        size: { width: PAGE_WIDTH, height: PAGE_HEIGHT },
        margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
      },
    },
    children: [
      // ---------------- TITLE PAGE ----------------
      new Paragraph({ text: '', spacing: { before: 1600 } }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: 'NIST CSF-Aligned', bold: true, size: 32, color: NAVY })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 400 },
        children: [new TextRun({ text: 'Cybersecurity Risk Assessment & Policy Framework', bold: true, size: 44, color: NAVY })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 800 },
        children: [new TextRun({ text: 'Meridian Environmental Logistics (fictional entity, used for portfolio purposes)', italics: true, size: 22 })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: 'Prepared as a GRC portfolio project', size: 22 })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: 'Author: Marcel Slowly', size: 22 })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: 'Date: August 18, 2026   |   Version 1.0   |   Classification: Internal — Portfolio Sample', size: 22 })],
      }),
      new Paragraph({ text: '', spacing: { before: 1200 } }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({
          text: 'This document uses a fictional company built to be representative of the logistics / environmental services sector. It demonstrates a full risk-assessment and policy-mapping methodology: asset inventory, risk register, and security policies mapped to the NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover).',
          italics: true, size: 18, color: '595959',
        })],
      }),

      pageBreak(),

      // ---------------- DOCUMENT CONTROL ----------------
      h1('Document Control'),
      makeTable(
        [2000, 1600, 2000, 3760],
        ['Version', 'Date', 'Author', 'Summary of Changes'],
        [
          ['1.0', '2026-08-18', 'Marcel Slowly', 'Initial risk assessment and NIST CSF policy mapping'],
        ]
      ),
      new Paragraph({ text: '', spacing: { after: 300 } }),

      // ---------------- TABLE OF CONTENTS ----------------
      h1('Table of Contents'),
      new TableOfContents('Table of Contents', { hyperlink: true, headingStyleRange: '1-2' }),

      pageBreak(),

      // ---------------- EXECUTIVE SUMMARY ----------------
      h1('Executive Summary'),
      p('Meridian Environmental Logistics (Meridian) operates a fleet-based waste collection, transport, and recycling business across six regional depots, supported by cloud-hosted operational systems, a customer-facing billing portal, and IoT-enabled fleet telematics. This assessment identifies and prioritizes Meridian’s key cybersecurity risks, evaluates existing controls, and proposes a security policy framework aligned to the NIST Cybersecurity Framework (CSF).'),
      p('Twelve information assets were inventoried across cloud, on-premises, mobile, network, and physical categories. Ten risk scenarios were assessed using a 5x5 likelihood/impact model. Three risks were rated Critical or High at their inherent (pre-control) level: a phishing-delivered ransomware scenario against the ERP/finance system, business email compromise leading to fraudulent wire transfer, and compromise of the customer billing portal. Two risks are specific to Meridian’s regulatory context as an environmental services provider: falsified or tampered environmental compliance data, and a cloud misconfiguration exposing that same data.'),
      p('Existing controls meaningfully reduce residual risk in most cases, but consistent gaps recur across scenarios: incomplete network segmentation, no enforced mobile device management, inconsistent security-awareness training, and no dual-approval control on high-value financial transactions. Section 6 provides a prioritized, time-bound roadmap addressing these gaps, sequenced by residual risk and estimated implementation effort.'),
      p('This assessment should be treated as a living document, reviewed at minimum annually or after any material change to Meridian’s systems, vendors, or regulatory obligations.'),

      pageBreak(),

      // ---------------- 1. INTRODUCTION & SCOPE ----------------
      h1('1. Introduction & Scope'),
      h2('1.1 Purpose'),
      p('This document establishes a repeatable risk assessment for Meridian’s information systems and maps recommended security controls to the NIST Cybersecurity Framework (CSF) functions: Identify, Protect, Detect, Respond, and Recover. It is intended to support prioritized security investment decisions and to serve as the baseline for Meridian’s security policy set.'),
      h2('1.2 Scope'),
      p('In scope: all information systems, applications, and infrastructure that store, process, or transmit Meridian business data, customer data, employee data, or environmental compliance data, including cloud-hosted (SaaS/IaaS) systems, on-premises infrastructure at regional depots, fleet telematics and mobile applications, and third-party data exchanges directly integrated with Meridian systems.'),
      p('Out of scope: physical vehicle safety systems unrelated to data processing (e.g., mechanical braking systems), and the internal IT systems of third-party vendors themselves (only the data exchange interface with Meridian is assessed).'),
      h2('1.3 Methodology'),
      p('Asset identification and classification follow a standard CIA-triad-based data classification model (Public, Internal, Confidential, Restricted). Risk scenarios were identified through a structured threat-and-vulnerability walkthrough of each in-scope asset, informed by common threat patterns for the logistics/transportation and environmental services sector (ransomware, business email compromise, IoT/OT exposure, and regulatory data-integrity risk). Each risk is scored using a 5x5 likelihood/impact matrix (Section 3), both at its inherent level (before existing controls) and residual level (after existing controls), to make the effect of current controls explicit rather than assumed.'),
      p('Recommended policies are mapped to specific NIST CSF Functions and Categories (Section 5) rather than presented as a generic checklist, so that each policy traces back to a specific identified risk.'),

      pageBreak(),

      // ---------------- 2. ASSET INVENTORY ----------------
      h1('2. Asset Inventory'),
      p('Twelve information assets were identified as in-scope. Data classification follows: Public (no restriction), Internal (employees only), Confidential (restricted business data), Restricted (regulated/highly sensitive: PII, financial, compliance-reportable data).'),
      makeTable(
        [500, 1550, 1150, 2900, 1350, 1000, 910],
        ['ID', 'Asset', 'Category', 'Description', 'Owner', 'Class.', 'CIA Priority'],
        assets
      ),

      pageBreak(),

      // ---------------- 3. RISK METHODOLOGY ----------------
      h1('3. Risk Assessment Methodology'),
      h2('3.1 Likelihood Scale'),
      makeTable(
        [700, 1660, 7000],
        ['Score', 'Rating', 'Description'],
        [
          ['1', 'Rare', 'Would only occur in exceptional circumstances; no known precedent in this sector'],
          ['2', 'Unlikely', 'Could occur at some point; not expected under normal conditions'],
          ['3', 'Possible', 'Might occur; has happened at comparable organizations in this sector'],
          ['4', 'Likely', 'Will probably occur; has happened to Meridian or close peers before'],
          ['5', 'Almost Certain', 'Expected to occur, potentially multiple times per year, absent intervention'],
        ]
      ),
      new Paragraph({ text: '', spacing: { after: 200 } }),
      h2('3.2 Impact Scale'),
      p('Impact considers financial, operational, regulatory/compliance, and reputational dimensions together, since Meridian’s environmental-services licensing makes regulatory impact especially consequential.'),
      makeTable(
        [700, 1660, 7000],
        ['Score', 'Rating', 'Description'],
        [
          ['1', 'Negligible', 'No material financial loss; no operational disruption; no regulatory exposure'],
          ['2', 'Minor', 'Limited financial loss (<$25K); brief single-depot disruption; no regulatory reporting trigger'],
          ['3', 'Moderate', 'Moderate financial loss ($25K–$250K); multi-depot or multi-day disruption; internal compliance review triggered'],
          ['4', 'Major', 'Significant financial loss ($250K–$1M); company-wide operational disruption; mandatory regulatory disclosure'],
          ['5', 'Severe', 'Loss exceeding $1M; extended company-wide outage; license/permit risk; public regulatory action'],
        ]
      ),
      new Paragraph({ text: '', spacing: { after: 200 } }),
      h2('3.3 Risk Scoring'),
      p('Risk Score = Likelihood x Impact (range 1–25). Bands:'),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [2340, 2340, 2340, 2340],
        rows: [new TableRow({
          children: [
            cell('Low (1-4)', { width: 2340, shade: 'C6EFCE', bold: true, align: AlignmentType.CENTER }),
            cell('Medium (5-9)', { width: 2340, shade: 'FFEB9C', bold: true, align: AlignmentType.CENTER }),
            cell('High (10-16)', { width: 2340, shade: 'FFC7A0', bold: true, align: AlignmentType.CENTER }),
            cell('Critical (17-25)', { width: 2340, shade: 'F8696B', bold: true, align: AlignmentType.CENTER }),
          ],
        })],
      }),
      p('Both inherent risk (assuming no controls) and residual risk (accounting for controls currently in place) are scored for each risk in Section 4, so the register shows not just "how bad" a scenario is, but how much existing controls are actually doing.', { italics: true, size: 18 }),
    ],
  }, {
    // Landscape section — the risk register table needs the extra width.
    properties: {
      page: {
        size: { width: PAGE_WIDTH, height: PAGE_HEIGHT, orientation: PageOrientation.LANDSCAPE },
        margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
      },
    },
    children: [
      // ---------------- 4. RISK REGISTER ----------------
      h1('4. Risk Register'),
      p('Sorted by residual risk (highest first). Full detail — including specific vulnerabilities, existing controls, and treatment owners — supports the roadmap in Section 6.'),
      makeTable(
        [400, 2300, 1600, 1300, 700, 700, 1600, 700, 700, 1200, 1060, 700],
        ['ID', 'Threat Scenario', 'Vulnerability', 'Asset(s)', 'Inh.', 'Inh. Lvl', 'Existing Controls', 'Res.', 'Res. Lvl', 'Treatment', 'Owner', 'Target'],
        risks.sort((a, b) => {
          const scoreOf = (r) => parseInt(r[7].split('=')[1].trim());
          return scoreOf(b) - scoreOf(a);
        }).map(r => [
          r[0], r[1], r[2], r[3], r[4].split('=')[1].trim(), { text: r[5], shade: riskShade(r[5]), bold: true }, r[6], r[7].split('=')[1].trim(), { text: r[8], shade: riskShade(r[8]), bold: true }, r[9], r[10], r[11],
        ])
      ),
    ],
  }, {
    // Back to portrait for the remaining sections.
    properties: {
      page: {
        size: { width: PAGE_WIDTH, height: PAGE_HEIGHT },
        margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
      },
    },
    children: [
      // ---------------- 5. NIST CSF POLICY MAPPING ----------------
      h1('5. Security Policy Framework — Mapped to NIST CSF'),
      p('The following policies directly address the gaps identified in Section 4’s risk register. Each is tagged with the specific NIST CSF Category it implements and the risk ID(s) it mitigates.'),

      h2('5.1 IDENTIFY (ID)'),
      bullet('ID.AM (Asset Management): Maintain the asset inventory in Section 2 as a living register, reviewed quarterly and after any new system procurement. [Supports all risks]'),
      bullet('ID.RA (Risk Assessment): Formalize this risk assessment as an annual cycle, with a lightweight interim review after any material vendor, system, or regulatory change. [Supports all risks]'),
      bullet('ID.GV (Governance): Designate the Compliance Officer as the accountable owner for environmental-data-integrity risk (R-03), distinct from general IT risk ownership, given its direct regulatory/licensing consequence. [R-03]'),
      bullet('ID.SC (Supply Chain Risk Management): Require a signed data-handling addendum and periodic security attestation from the third-party disposal facility data exchange partner(s). [R-03]'),

      h2('5.2 PROTECT (PR)'),
      bullet('PR.AC (Access Control): Enforce phishing-resistant MFA on ERP/finance, HR/Payroll, and email; require dual approval for any wire transfer or vendor-banking-detail change above $10,000. [R-01, R-02, R-09]'),
      bullet('PR.AC (Access Control): Enroll all driver mobile devices in a mobile device management (MDM) solution with remote wipe and enforced device PIN/biometric lock. [R-06]'),
      bullet('PR.DS (Data Security): Segment depot guest Wi-Fi onto a physically or logically isolated VLAN with no route to internal systems, at all six depots. [R-07]'),
      bullet('PR.DS (Data Security): Segment the fleet telematics network (IoT) from the corporate LAN; treat all telematics traffic as untrusted at the network boundary. [R-04]'),
      bullet('PR.IP (Information Protection Processes): Require an independent security assessment (e.g., a focused penetration test) of the customer billing portal before its next major release, and annually thereafter. [R-05]'),
      bullet('PR.AT (Awareness and Training): Deliver mandatory, role-specific security-awareness training at hire and annually thereafter, with phishing-simulation exercises quarterly for finance and HR staff specifically. [R-01, R-02, R-09]'),

      h2('5.3 DETECT (DE)'),
      bullet('DE.CM (Security Continuous Monitoring): Deploy automated cloud security posture monitoring on the Environmental Compliance Data Warehouse to detect misconfigurations (e.g., public access grants) in near-real time. [R-08]'),
      bullet('DE.CM (Security Continuous Monitoring): Implement integrity checksums and automated reconciliation on data received through the disposal facility data exchange, flagging discrepancies for review rather than relying solely on manual monthly spot-checks. [R-03]'),
      bullet('DE.DP (Detection Processes): Enable and centrally review sign-in and admin-activity logs for the ERP, HR/Payroll, and email platforms; alert on impossible-travel and privilege-escalation events. [R-01, R-02, R-09]'),

      h2('5.4 RESPOND (RS)'),
      bullet('RS.RP (Response Planning): Maintain and annually test an incident response plan covering, at minimum, ransomware, business email compromise, and a regulatory-data-integrity incident, each with a named response lead. [R-01, R-02, R-03]'),
      bullet('RS.CO (Communications): Pre-define the regulatory notification process and contacts for any incident affecting environmental compliance data, given Meridian’s reporting obligations. [R-03]'),

      h2('5.5 RECOVER (RC)'),
      bullet('RC.RP (Recovery Planning): Test full restoration from ERP/finance backups at least twice yearly (an untested backup is not a control) with a defined Recovery Time Objective (RTO) of 24 hours for finance systems. [R-01]'),
      bullet('RC.IM (Improvements): Conduct a lessons-learned review after any invoked incident response or disaster recovery event, feeding identified gaps back into Section 4 as new or updated risk entries. [Supports all risks]'),

      pageBreak(),

      // ---------------- 6. ROADMAP ----------------
      h1('6. Prioritized Recommendations & Roadmap'),
      h2('6.1 Near-Term (0–3 months) — addresses Critical/High residual risk'),
      bullet('Enforce MFA + dual-approval wire transfer control on ERP/finance (R-01, R-02) — Owner: CFO/IT Manager'),
      bullet('Independent security assessment of the customer billing portal (R-05) — Owner: Finance Director/IT Manager'),
      bullet('Formalize environmental-data integrity reconciliation with automated checksums (R-03) — Owner: Compliance Officer'),
      h2('6.2 Mid-Term (3–6 months)'),
      bullet('Full network segmentation: telematics IoT VLAN and depot guest Wi-Fi at remaining sites (R-04, R-07) — Owner: IT Manager'),
      bullet('Deploy MDM across all driver mobile devices (R-06) — Owner: Fleet Operations Manager'),
      bullet('Cloud security posture monitoring on the compliance data warehouse (R-08) — Owner: IT Manager/Compliance Officer'),
      bullet('Enforce SSO + admin account review cadence on HR/Payroll (R-09) — Owner: HR Director'),
      h2('6.3 Ongoing'),
      bullet('Quarterly phishing simulations for finance/HR; annual security-awareness training for all staff'),
      bullet('Twice-yearly backup restoration test for ERP/finance systems'),
      bullet('Annual review of this risk assessment and the asset inventory'),

      pageBreak(),

      // ---------------- 7. CONCLUSION ----------------
      h1('7. Conclusion'),
      p('Meridian’s highest-consequence risks concentrate in two areas: financial-system compromise (ransomware and business email compromise against ERP/finance) and regulatory data integrity (environmental compliance reporting). Both are addressed by controls that are well-understood, achievable within the near-term window, and proportionate to Meridian’s size — this is not a call for enterprise-scale security spend, but for closing a small number of specific, identified gaps: dual-approval on financial transactions, an independent look at the customer-facing portal, and integrity checks on regulator-facing data. Executing the near-term roadmap in Section 6 would move all three Critical/High residual risks into the Medium band within one quarter.'),

      pageBreak(),

      // ---------------- APPENDIX ----------------
      h1('Appendix A: Glossary'),
      bullet('CIA Triad: Confidentiality, Integrity, Availability — the three properties security controls protect.'),
      bullet('Inherent Risk: The risk level assuming no controls are in place.'),
      bullet('Residual Risk: The risk level remaining after accounting for existing controls.'),
      bullet('NIST CSF: The NIST Cybersecurity Framework, organizing controls into five Functions — Identify, Protect, Detect, Respond, Recover.'),
      bullet('MDM: Mobile Device Management — software that enforces security policy (encryption, remote wipe, PIN) on mobile devices.'),
      bullet('BEC: Business Email Compromise — a social-engineering attack using a compromised or spoofed business email account to trigger fraudulent action, typically a wire transfer.'),
    ],
  }],
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync('output.docx', buf);
  console.log('Wrote output.docx,', buf.length, 'bytes');
});
