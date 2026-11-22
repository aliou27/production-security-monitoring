# 07: Incident response process and first incident reports

**Date:** 2026-11-22
**Goal:** turn the investigations of phases 05 and 06 into formal incident reports, with one process and one template, so every alert ends with a documented verdict.

**Result:** 4 incidents investigated and closed: 1 true positive from an authorized simulation (critical vulnerability, fixed), 1 true positive with no compromise, and 2 false positives, each tuned with a documented trade-off.

## 1. Why formal reports

An alert is not a result. The value of a SOC is the answer to four questions: what happened, was it malicious, what was affected, and what changes now. A report forces each answer to rest on evidence, and lets someone else check the reasoning later.

## 2. Process

Every significant alert follows the same steps:

| Step | Question |
|---|---|
| 1. Detection | Which rule fired, at which level, on which asset? |
| 2. Triage | True positive, benign positive or false positive? |
| 3. Investigation | Source, target, timeline, affected resources. What check proves each point? |
| 4. Containment | Is an immediate action needed, and is it proportionate? |
| 5. Eradication and recovery | What removes the cause and restores normal operation? |
| 6. Lessons learned | What changes in the systems, the detections or the process? |

Production belongs to the production team. When a response needs a production change, the SOC writes the recommendation and the production team applies it.

### Classification

| Class | Meaning | Example |
|---|---|---|
| True positive | The rule detected the behaviour it was built for | SOC-2026-001, SOC-2026-002 |
| Benign positive | Real behaviour, but expected or authorized | (none yet) |
| False positive | The rule matched something it was not meant to catch | SOC-2026-003, SOC-2026-004 |

A true positive does not mean a compromise. SOC-2026-002 is a real attack attempt that could not succeed.

## 3. Template

[`incidents/templates/incident-report-template.md`](../incidents/templates/incident-report-template.md): executive summary, timeline, indicators, investigation, impact, response, recommendations, detection review, lessons learned.

Two rules apply to every report: no personal data (accounts appear as fingerprints, the analyst's own IPs are redacted), and every claim points to the check that supports it.

## 4. Incident register

| ID | Title | Severity | Classification | Time to verdict | Report |
|---|---|---|---|---|---|
| SOC-2026-001 | Account takeover through reset code guessing | Critical | True positive (simulation) | Immediate (authorized test) | [link](../incidents/reports/SOC-2026-001-reset-code-account-takeover.md) |
| SOC-2026-002 | SSH attempts with invalid users on production | Low | True positive, no compromise | About 5 minutes | [link](../incidents/reports/SOC-2026-002-ssh-invalid-users-production.md) |
| SOC-2026-003 | Flood of web client errors from legitimate listeners | Informational | False positive | About 6 minutes | [link](../incidents/reports/SOC-2026-003-web-error-flood-anonymous-listeners.md) |
| SOC-2026-004 | "Trojaned" system commands on production | High at detection | False positive | About 6 hours (deprioritized) | [link](../incidents/reports/SOC-2026-004-rootcheck-trojaned-binaries.md) |

## 5. What the four incidents show together

- **Detection found more than attacks.** Two of four investigations ended on a product issue: a critical bug (001) and a functional bug (003).
- **False positives were proven, not assumed.** Each one was closed with a stronger check: request headers for 003, package checksums for 004.
- **Prioritization needs work.** SOC-2026-004 had the highest potential impact but was verified last. A "trojan" alert should be triaged before noisy, low-impact ones.
- **Two gaps limit what can be proven.** Production has no application audit log yet, so past exploitation of the reset flaw cannot be ruled out (001); and production web logs only reach back a few days.

## 6. Open actions

| Action | From | Owner |
|---|---|---|
| Retrospective hunt for reset code guessing in production web logs | 001 | Analyst |
| Security audit log in production | 001 | Production team |
| Dedicated deploy user, `PermitRootLogin no` | 002 | Production team |
| Send personal requests only when logged in; 401 instead of 403 | 003 | Production team |
| Review rule 100400 after Wazuh signature updates | 004 | Analyst |

## 7. Next step

SSH detection engineering and automated response: rules for password spraying and for a successful login after failures, then IP blocking tested on staging only.
