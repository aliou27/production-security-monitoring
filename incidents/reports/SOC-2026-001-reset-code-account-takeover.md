# SOC-2026-001: Account takeover through password reset code guessing

| Field | Value |
|---|---|
| Severity | Critical |
| Classification | True positive (authorized purple-team simulation) |
| Status | Closed: vulnerability fixed in staging and production |
| Affected asset | `zikrou-staging`, Zikrou API, password reset flow |
| Detection source | Zikrou API security audit log, rules 100322, 100323, 100325 |
| ATT&CK | T1110.001 Password Guessing, T1098 Account Manipulation |
| Analyst | Aliou Ba |

## 1. Executive summary

During a controlled test on the staging API, the 3-attempt limit on password reset codes was found to have no effect: wrong codes were never counted. The test account was taken over by changing its password with the reset code. The SIEM detected the full sequence, ending with a level 14 alert. The root cause was a database rollback that erased the failed-attempt counter. The fix was retested on staging the same day and deployed to production by the production team at 18:55 UTC.

## 2. Timeline (2026-11-21, UTC)

| Time | Event |
|---|---|
| 12:38:34 | First wrong reset code on the test account (rule 100322, level 5) |
| 12:38:36 | Fifth wrong code; correlation rule 100323 fires (level 12). The API still answers "2 attempts left". |
| 12:41:28 | Password reset with the code succeeds; rule 100325 fires (level 14, possible account takeover) |
| 12:47:42 | Fix deployed on staging; retest starts |
| 12:47:44 | 4th wrong code now locks the code; the real code is refused afterwards |
| 12:52:40 | New rule 100321 (code locked) validated |
| Same day | Findings report sent to the production team |
| 18:55:30 | Fix live in production (PR #16) |

Detection latency: the level 12 and level 14 alerts appeared within seconds of the corresponding events.

## 3. Indicators

| Type | Value | Notes |
|---|---|---|
| Account | `d962abd6135b7260` | SHA-256 fingerprint of the test account email |
| Source IP | Tester's connection (redacted) | Authorized test from outside the infrastructure |
| Endpoints | `POST /api/v1/auth/verify-reset-code`, `POST /api/v1/auth/reset-password` | |
| Pattern | More than 3 `reset_code_failure` with reason `wrong_code` on one account, followed by `password_reset_success` | Signature of a guessed code |

## 4. Investigation

| Question | Check | Result |
|---|---|---|
| Does the limit apply? | 5 wrong codes on one account | Every answer said "2 attempts left" |
| Can the code still be used after that? | Reset with the real code | Password changed, new tokens issued |
| Did the SIEM see it? | `rule.groups:zikrou`, last hour | 4 &times; 100322, 100323 (level 12), 100325 (level 14) |
| Why 4 &times; 100322 for 5 wrong codes? | Wazuh rule logic | Each event gets one rule; the 5th matched the correlation rule 100323 instead |
| Root cause? | Code review of `AuthService` | The counter was incremented, then a `BadRequestException` rolled back the `@Transactional` method, undoing the increment |

Evidence: [report 05](../../docs/05-api-security-logs-and-reset-code-vulnerability.md), sections 4 and 5, with screenshots before and after the fix.

## 5. Impact assessment

- **Staging:** one test account taken over, by the analyst, as planned.
- **Production:** the same code ran in production until 18:55 UTC. Production had no application audit log at the time, so past exploitation cannot be ruled out from the SIEM. A retrospective search of production web logs for repeated `verify-reset-code` requests from one source is the remaining check (see recommendations). Production web logs are only kept from 2026-11-17, so activity before that date cannot be checked.

## 6. Response actions

| Action | Owner | Justification |
|---|---|---|
| Fix (`noRollbackFor`) on the staging branch, retest | Analyst | Prove the fix before production |
| Findings report with the fix | Analyst | Production belongs to the production team |
| Fix deployed alone (cherry-pick), without the staging-only logging | Production team | Smallest possible production change |
| New detection rule 100321, description of 100323 corrected | Analyst | Keep alerts accurate after the fix |

## 7. Recommendations

| Recommendation | Owner | Status |
|---|---|---|
| Retrospective hunt in production web logs for reset code guessing since 2026-11-17 | Analyst | Open |
| Ship the security audit log to production, so a future attempt is detected the same way | Production team | Waiting for the log cleanup (F3) |
| Add a test that sends a 4th wrong code and expects the code to be locked | Production team | Open |
| Keep production web logs longer than a few days | Production team | Open |

## 8. Detection review

- The chain 100322, 100323, 100325 detected every step, with correct levels.
- After the fix, 100323 still fired, because its 15-minute window counted codes from the earlier test. Its description ("attempt limit bypassed") became wrong and was changed to "repeated wrong reset codes".
- Gap found: the lockout itself raised only a level 3 event. Rule 100321 (level 8) now flags it.

## 9. Lessons learned

1. Testing detections found a critical bug in the application itself.
2. A security counter inside a transaction that rolls back is not a security counter.
3. A forgotten dashboard filter (levels 7 to 11) hid the level 12 and 14 alerts at first. Check filters before concluding "no results".
4. Without application logs in production, the SIEM cannot answer "was this exploited before?". Detection must exist before the incident, not after.
