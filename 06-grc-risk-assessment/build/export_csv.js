const fs = require('fs');

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

function scoreLevel(score) {
  if (score >= 17) return 'Critical';
  if (score >= 10) return 'High';
  if (score >= 5) return 'Medium';
  return 'Low';
}
function risk(id, threat, vuln, asset, L, I, controls, resL, resI, treatment, owner, date) {
  const inh = L * I, res = resL * resI;
  return [id, threat, vuln, asset, L, I, inh, scoreLevel(inh), controls, resL, resI, res, scoreLevel(res), treatment, owner, date];
}
const risks = [
  risk('R-01', 'Phishing-delivered ransomware encrypts ERP/finance data, halting payroll and billing', 'Limited phishing-resistant MFA; inconsistent security-awareness training; legacy VPN access to ERP', 'A-05 ERP/Finance System', 4, 5, 'Email filtering (basic), nightly backups (untested restore), antivirus on endpoints', 2, 5, 'Mitigate', 'CFO / IT Manager', 'Q1 2027'),
  risk('R-02', 'Business email compromise (BEC) leads to a fraudulent wire transfer approval', 'No dual-approval requirement above a set dollar threshold; spoofable sender display names not flagged', 'A-05 ERP/Finance System, A-07 Email', 3, 5, 'Manual callback verification for new vendors (inconsistently followed)', 2, 5, 'Mitigate', 'CFO', 'Q1 2027'),
  risk('R-03', 'Falsified or tampered environmental compliance data submitted to regulators (insider or integration error)', 'No integrity checksums on waste-volume data exchange; limited audit trail on manual data corrections', 'A-09 Compliance Data Warehouse, A-10 Disposal Facility Exchange', 2, 5, 'Monthly manual spot-check reconciliation by Compliance Officer', 2, 4, 'Mitigate', 'Compliance Officer', 'Q2 2027'),
  risk('R-04', 'Unpatched IoT telematics units exploited as a pivot point into the corporate network', 'Vendor-managed firmware with no formal patch SLA; telematics VLAN not fully segmented from corporate LAN', 'A-01 Fleet Telematics Platform', 3, 4, 'Vendor manages patching (no visibility into cadence); partial network segmentation', 2, 4, 'Mitigate', 'IT Manager', 'Q2 2027'),
  risk('R-05', 'Customer billing portal compromised via injection or broken access control, exposing customer payment data', 'Portal has not had an independent security assessment since launch; no WAF in front of the application', 'A-03 Customer Billing Portal', 3, 5, 'TLS in transit, PCI-scoped payment processor (tokenized, not stored directly)', 2, 4, 'Mitigate', 'Finance Director / IT Manager', 'Q1 2027'),
  risk('R-06', 'Lost or stolen driver mobile device exposes cached credentials or customer service-location data', 'No enforced mobile device management (MDM); devices not required to have remote wipe enabled', 'A-04 Driver Mobile App', 4, 3, 'App requires PIN on open; no remote wipe or MDM enrollment enforced', 2, 3, 'Mitigate', 'Fleet Operations Mgr', 'Q3 2027'),
  risk('R-07', 'Weak depot guest Wi-Fi security allows an attacker on-site to reach internal systems', 'Guest and staff Wi-Fi share a VLAN at two of six depots (legacy hardware)', 'A-08 Depot Wi-Fi Networks', 3, 3, 'WPA2 in use; guest network exists but VLAN separation incomplete at 2 of 6 sites', 2, 3, 'Mitigate', 'IT Manager', 'Q3 2027'),
  risk('R-08', 'Cloud data warehouse misconfiguration exposes environmental/compliance data externally', 'No automated cloud security posture monitoring; access reviews are manual and infrequent', 'A-09 Compliance Data Warehouse', 2, 4, 'Access restricted to Compliance team by default; no automated misconfiguration scanning', 2, 3, 'Mitigate', 'IT Manager / Compliance Officer', 'Q2 2027'),
  risk('R-09', 'HR/Payroll SaaS breach exposes employee PII and banking details', 'Single sign-on not enforced for the HR platform; standing admin accounts not regularly reviewed', 'A-06 HR/Payroll System', 2, 5, 'Vendor holds SOC 2 Type II; encrypted at rest per vendor attestation', 1, 4, 'Mitigate', 'HR Director', 'Q2 2027'),
  risk('R-10', 'DDoS against customer billing portal during month-end billing cycle disrupts payment collection', 'No CDN/DDoS mitigation service in front of the portal', 'A-03 Customer Billing Portal', 2, 3, 'Cloud host provides basic infrastructure-level protection only', 2, 2, 'Accept (residual risk within appetite; revisit if traffic profile changes)', 'IT Manager', 'Monitor'),
];

function toCsv(rows, header) {
  const esc = v => `"${String(v).replace(/"/g, '""')}"`;
  return [header.map(esc).join(','), ...rows.map(r => r.map(esc).join(','))].join('\n');
}

fs.writeFileSync('../asset_inventory.csv', toCsv(assets, ['ID', 'Asset', 'Category', 'Description', 'Owner', 'Data Classification', 'CIA Priority']));
fs.writeFileSync('../risk_register.csv', toCsv(risks, ['ID', 'Threat Scenario', 'Vulnerability', 'Asset(s)', 'Inherent Likelihood', 'Inherent Impact', 'Inherent Score', 'Inherent Level', 'Existing Controls', 'Residual Likelihood', 'Residual Impact', 'Residual Score', 'Residual Level', 'Treatment', 'Owner', 'Target Date']));
console.log('Wrote asset_inventory.csv and risk_register.csv');
