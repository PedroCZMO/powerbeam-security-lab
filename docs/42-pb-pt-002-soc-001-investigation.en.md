# PB-PT-002 — Real SSH failure detection and SOC-001 investigation

**Project:** PowerBeam Security Lab
**Exercise:** Authorised Purple Team (Red Team / Blue Team)
**Event date:** 6 November 2026 (CET, UTC+01:00)
**Rule:** SOC-001 — Possible brute-force behaviour
**Rule severity:** `medium`
**Disposition:** **True positive for the detection rule; authorised lab activity**
**Case status:** **Investigated and acknowledged (`reviewed`); no outstanding primary-queue alert**

[← Project overview](../README.md) · [Versión española](42-pb-pt-002-investigacion-soc-001-2026-11-06.md)

> This exercise used an owned device on a controlled lab network. No password lists, automated brute-force tools, credentials or exploitation were involved. The alert indicates a behavioural pattern, not confirmed hostile intent or device compromise.

## 1. Objective and scope

Validate an end-to-end SOC-001 detection based on **five failed SSH password authentications from the same source within five minutes**, with logs emitted by a physical Ubiquiti PowerBeam and collected by Ubuntu. Compare V1 (batch) and V3 (incremental) results and document the triage and acknowledgement.

| Role | Component | Lab address |
| --- | --- | --- |
| Red Team client | Kali Linux VM, bridged interface | `192.168.1.30` |
| Target | Ubiquiti PowerBeam / Dropbear SSH | `192.168.1.20:22/TCP` |
| Blue Team collector | Ubuntu / rsyslog | `192.168.1.10:5514/UDP` |
| V1 evidence | Batch monitor | `/var/lib/powerbeam-monitor/alerts.jsonl` |
| V3 evidence | Incremental monitor | `/var/lib/powerbeam-monitor/parallel-v3/alerts-v3.jsonl` |

Pipeline: **Kali → Dropbear on PowerBeam → UDP syslog → Ubuntu rsyslog → V1/V3 detection → JSONL alert → primary alert queue**.

## 2. Five observed failures

The table uses the **outer Ubuntu receive timestamp**. The device's embedded syslog time was approximately one hour behind and was **not** used for correlation.

| Attempt | Receive timestamp (CET) | Dropbear PID | Client port | Outcome |
| ---: | --- | --- | ---: | --- |
| 1 | `18:34:26.838954` | 860 | 53042 | Incorrect password |
| 2 | `18:34:31.160524` | 861 | 43882 | Incorrect password |
| 3 | `18:34:35.922592` | 862 | 43894 | Incorrect password |
| 4 | `18:34:40.775578` | 863 | 56028 | Incorrect password |
| 5 | `18:34:45.560412` | 864 | 56040 | Incorrect password |

The five failures occurred within **18.72 seconds**, below the SOC-001 five-minute threshold window. The same client IP (`192.168.1.30`) and target username (`ubnt`) appeared in all five records.

There were **15 Dropbear records**: five `Child connection` entries, five `Bad password attempt` entries and five `Exit before auth` entries. The parser counted **five actual authentication failures**; session-exit messages were not double-counted.

A separate failed authentication at **13:45:31** on the same date was **outside** this exercise's correlation window.

Representative fifth failure, as received by rsyslog:

```text
2026-11-06T18:34:45.560412+01:00 source=192.168.1.20 <84>Nov  6 17:34:45 dropbear[864]: Bad password attempt for 'ubnt' from 192.168.1.30:56040
```

The outer `source=192.168.1.20` identifies the **syslog-emitting device**; the address after `from` is the **client that attempted authentication**. The detector correctly attributed the alert to Kali.

A review of the **18:34–18:40 CET** Dropbear window found five connections, five failed passwords and five pre-authentication exits, with **no successful SSH authentication observed**. That limited window cannot establish the absence of other activity, other protocols or earlier access.

## 3. Automatic detection: V1

At **18:35:01 CET**, `powerbeam-monitor.service` completed and reported:

```text
Lines read: 66
Authentication events recognised: 27
Successful: 17
Incorrect passwords: 9
Nonexistent users: 1
SOC-001 alerts: 1
SOC-002 alerts: 2
[SOC-001] 2026-11-06T18:34:45.560412+01:00 source=192.168.1.30 failures=5 id=SOC-001-36f69895f7b28039
New alerts appended to alerts.jsonl: 1
```

These lines translate the **observed Spanish-language monitor output**; the batch totals include historical events and the **two older SOC-002 alerts**, not only this exercise. A subsequent V1 run, at **18:40:01**, found the same SOC-001 but appended **zero** new JSONL alerts, demonstrating deduplication in this run.

Time from fifth failure to the detection run: approximately **15.44 seconds**. This reflects the timer schedule, **not a benchmark of detection computation speed**.

## 4. Automatic detection: V3

At **18:37:01 CET**, `powerbeam-monitor-v3.service` reported:

```text
New lines: 15
New authentication events: 5
SOC-001 alerts: 1
SOC-002 alerts: 0
New JSONL alerts: 1
```

At **18:42:01 CET**, the subsequent execution reported **zero new lines** and **zero new alerts**, consistent with incremental offset/state handling.

Time from fifth failure to V3 detection run: approximately **135.44 seconds**. Different execution schedules explain part of the disparity. **V1 and V3 use shared detection logic** with different ingestion paths, so this is a comparison of pipelines, not independent detector implementations.

## 5. Stored alert and equivalence

Exactly **one** JSONL record with the target ID was found in each monitor's output. The parsed JSON objects compared as **identical**:

```json
{
  "alert_id": "SOC-001-36f69895f7b28039",
  "description": "Posibles intentos de fuerza bruta",
  "failed_attempts": 5,
  "rule_id": "SOC-001",
  "severity": "medium",
  "source_ip": "192.168.1.30",
  "timestamp": "2026-11-06T18:34:45.560412+01:00",
  "window_minutes": 5
}
```

V1 stores alerts in the **primary queue source**. V3 writes to a **separate validation file**; combining the two as separate incidents would double-count the same underlying activity.

Before acknowledgement the primary queue reported **3 seen, 1 pending, 0 acknowledged**, with this alert pending.

## 6. SOC L1 triage and disposition

| Analyst question | Evidence-based conclusion |
| --- | --- |
| Was the threshold reached? | Yes: 5 password failures from one IP in under 5 minutes. |
| Was the source correctly identified? | Yes: client `192.168.1.30`, distinct from the syslog sender `192.168.1.20`. |
| Was successful SSH login observed in the reviewed window? | No. |
| Was the activity authorised? | Yes: controlled local Purple Team exercise. |
| Is device compromise confirmed? | No evidence of compromise in the reviewed records; **not** a comprehensive security assessment. |
| Detection classification | **True positive for the SOC-001 rule**, **authorised test activity**, **not confirmed malicious brute force**. |
| Case handling | Investigation documented; the primary alert was acknowledged as `reviewed`. |

The acknowledgement was performed as the restricted `powerbeam-monitor` service user by calling `alert_queue.py ack` with the precise `alert_id` and `--reason reviewed`. Response:

```json
{
  "action": "ack",
  "alert_id": "SOC-001-36f69895f7b28039",
  "reason": "reviewed",
  "pending": 0,
  "acknowledged": 1
}
```

Final `status` output confirmed **`seen=3`, `pending=0`, `acknowledged=1`**. The acknowledgement updates the **queue state**; it is **not** a containment action and does not constitute proof of a deleted or modified original alert. The post-ACK JSONL file was not independently re-read in the supplied evidence.

**Close date:** 6 November 2026. The exact wall-clock ACK time was not established by the evidence; it is not inferred.

## 7. Regression tests, limitations and follow-up

The lab added [`tests/test_purple_team_dropbear.py`](../tests/test_purple_team_dropbear.py) with **eight offline tests** covering Dropbear format recognition, IP attribution, timezone-aware reception timestamps, exclusion of handshake errors and exit messages, and SOC-001/SOC-002 synthetic correlation. **482 tests passed locally and in [GitHub Actions](https://github.com/PedroCZMO/powerbeam-security-lab/actions/runs/42268490185)** on 6 November 2026.

The repository and installed V1/V3 copies of `auth_detector.py`, `bruteforce_detector.py` and `security_monitor.py` had matching SHA-256 hashes. No deployed rule update was needed for this exercise.

**Limitations and improvements:**

- Five manual password failures prove a *detection pattern*, **not an automated attack or hostile intent**.
- The log receiver's and device's internal clocks differ; rely on explicitly normalised timestamps until device clock configuration is verified.
- The reported detection delay includes **systemd timer intervals**; it should not be interpreted as algorithm latency.
- The scenario tests only one IP, one account and the observed window; broaden coverage with authorised, controlled tests and confirm lockout/recovery considerations first.
- Preserve original evidence under restricted access; do not publish full raw logs, tokens, passwords or device backups.

**Final disposition:** **SOC-001 true positive for the rule, authorised laboratory activity, reviewed and closed in the primary queue, with no successful SSH authentication observed during the examined window.**
