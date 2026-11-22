# SOC-2026-003: Flood of web client errors from legitimate listeners

| Field | Value |
|---|---|
| Severity | Informational (detection quality issue) |
| Classification | False positive: legitimate activity matched an attack-oriented rule |
| Status | Closed: rules tuned, functional bug reported |
| Affected asset | `zikrou-prod`, Caddy access logs of the API |
| Detection source | Rule 100201 (any 4xx response) |
| ATT&CK | None (no malicious activity) |
| Analyst | Aliou Ba |

## 1. Executive summary

Minutes after production web logs reached the SIEM, rule 100201 fired about 100 times per minute, a rate of roughly 150,000 alerts per day. The investigation showed real users, not attackers: listeners without an account whose app sends listening progress the API is designed to refuse. The rules were tuned in two steps, and the underlying functional bug, which wastes users' mobile data and API capacity, was reported to the production team.

## 2. Timeline (2026-11-22, UTC)

| Time | Event |
|---|---|
| 12:39 | Production Caddy logs connected to the SIEM |
| 12:40 | About 100 alerts per minute from rule 100201, all on `PATCH /api/v1/zikr/{id}/progress` |
| 12:44 | Status code distribution measured |
| 12:46 | Absence of `Authorization` header confirmed on the rejected requests |
| 12:48 | First tuning: exception rule 100202 |
| 13:38 | Second pattern (bursts of 401 and 403 at app launch) analyzed |
| 13:40 | Second tuning: rule 100201 set to level 0 |

## 3. Indicators

No malicious indicators. Source IPs were Senegalese mobile and broadband networks, consistent with the app's real audience.

## 4. Investigation

| Question | Check | Result |
|---|---|---|
| What do the alerts have in common? | Dashboard review | One route, many source IPs, steady rhythm (one request every ~70 s per listener) |
| Which status codes? | Status count on `/progress`, last 20,000 Caddy lines | 2,569 &times; 200, 12,491 &times; 403, 53 &times; 401 |
| What does the API require? | `SecurityConfig` review | `/progress` requires an account; `/play` and `/view` are open to guests; without a token, Spring Security answers 403 |
| Are the 403s guests? | Count of the `Authorization` header (Caddy logs its presence, value redacted) | 0 of the 403s carry one; the 200s do |
| What remains after the first tuning? | 4xx by status and route, excluding `/progress` | 401 on public and personal routes (expired token at app launch); 403 on `/playlists`, `/me/notifications`, `/search/history` (guests again) |

## 5. Impact assessment

- **Security:** none. Access control works as intended: a guest cannot write progress or read personal data.
- **Users:** logged-in users' progress is saved (200). Guests' devices send requests that are bound to fail: about 83% of progress traffic.
- **SOC:** before tuning, the volume made the dashboard unusable and filled the indexer with useless alerts.

## 6. Response actions

| Action | Justification |
|---|---|
| Rule 100202 (level 0): `PATCH` + `/zikr/{id}/progress` + `403` only | Narrow exception; a 401, 404 or 500 on the same route still counts. Also stops guests behind shared carrier IPs from adding up to a false "scan" (rule 100220). |
| Rule 100201 set to level 0 | A single 4xx is never an attack on its own. The rule still feeds the correlation rule 100220 (20 errors in 60 s from one IP, level 10). Targeted rules (100210, 100211, 100212) still alert on the first request. |
| Finding F9 reported to the production team | The fix belongs in the app and the API, not in the SIEM |

## 7. Recommendations

| Recommendation | Owner | Status |
|---|---|---|
| Send progress and personal requests only when a user is logged in | Production team (app) | Open (F9) |
| Return 401 instead of 403 for unauthenticated requests | Production team (API) | Open (F9) |
| Refresh the token before it expires, to avoid a burst of 401 at each app launch | Production team (app) | Open |

## 8. Detection review

- The original design alerted on every client error. It worked on staging, where traffic is mostly tests, and failed on production with real users.
- The final design alerts on behaviour (repetition from one source) and on requests that are suspicious on their own.
- Trade-off: a slow scanner sending fewer than 20 errors per minute no longer raises an alert. Its probes of sensitive paths are still caught by 100210.

## 9. Lessons learned

1. Rules tuned on a test environment must be revalidated on real traffic.
2. Understand a false positive before silencing it: this one revealed a product bug.
3. Prefer a narrow exception or a design change over raising a threshold blindly.
4. In Senegal, many mobile users share one public IP through their carrier. Per-IP thresholds must account for it.
