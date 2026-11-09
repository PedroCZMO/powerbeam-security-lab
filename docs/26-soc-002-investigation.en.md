# SOC-002 — Investigation of successful authentication after failed attempts

**Project:** PowerBeam Security Lab
**Case reference:** `CASE-2026-11-04-SOC-002-01`
**Detection ID:** `SOC-002-2ad9ffcb5b5d0b58`
**Date:** 4 November 2026 (CET, UTC+01:00)
**Severity assigned by the rule:** `medium`
**Disposition:** **Correct detection of an authorised test sequence; not a confirmed intrusion**

[← Project overview](../README.md) · [Versión española](26-investigacion-soc-002-2026-11-04.md)

## 1. Executive summary

An owned Ubiquiti PowerBeam recorded **two failed authentications followed by one successful authentication from the same client IP** within approximately **19.32 seconds**. SOC-002 requires two or more failures followed by success within five minutes. The batch V1 and incremental V3 monitors generated matching alerts with the same ID, source, timestamp and failure count.

This was an **authorised exercise**. The rule detects a sequence that deserves investigation, **not evidence of unauthorised access**.

## 2. Scope and collection

| Field | Observed detail |
| --- | --- |
| Device / syslog sender | Ubiquiti PowerBeam, `192.168.1.20` |
| Authentication client | `192.168.1.10` (Ubuntu host in this exercise) |
| Account | `ubnt` |
| Device component | `httpd` |
| Collector | Ubuntu / `rsyslog` |
| Detection | SOC-002: failed logins followed by a success |
| Correlation window | Five minutes |
| Independent ingestion paths | V1 batch; V3 incremental |

The `source=192.168.1.20` prefix denotes the **device sending syslog**. The address following `from` identifies the **authentication client**. The detector uses the outer Ubuntu receipt timestamp rather than assuming the device's embedded timestamp is authoritative.

## 3. Timeline and raw evidence

| Receive time (CET) | Event |
| --- | --- |
| `11:00:06.205386` | First incorrect password for `ubnt` |
| `11:00:20.921474` | Second incorrect password |
| `11:00:25.523253` | Password authentication succeeded |

Representative original log records supplied during the investigation:

```text
2026-11-04T11:00:06.205386+01:00 source=192.168.1.20 <14>Nov  4 10:00:06 httpd[864]: Bad password attempt for 'ubnt' from 192.168.1.10
2026-11-04T11:00:20.921474+01:00 source=192.168.1.20 <14>Nov  4 10:00:20 httpd[866]: Bad password attempt for 'ubnt' from 192.168.1.10
2026-11-04T11:00:25.523253+01:00 source=192.168.1.20 <14>Nov  4 10:00:25 httpd[868]: Password auth succeeded for 'ubnt' from 192.168.1.10
```

Measured durations: **14.716 seconds** between failures; **4.602 seconds** from the second failure to success; **19.318 seconds** for the full sequence. These are event timestamps, **not detector runtime measurements**.

## 4. Detection and analysis

Both monitoring pipelines produced the same logical SOC-002 alert:

```json
{
  "alert_id": "SOC-002-2ad9ffcb5b5d0b58",
  "description": "Autenticación correcta tras varios fallos",
  "failed_attempts": 2,
  "rule_id": "SOC-002",
  "severity": "medium",
  "source_ip": "192.168.1.10",
  "timestamp": "2026-11-04T11:00:25.523253+01:00",
  "window_minutes": 5
}
```

The alert timestamp matches the **successful login event** at which the sequence becomes alertable. The log evidence does **not** establish an exact independent detection/emission time.

**Triage questions and conclusions:** Were there two earlier failures? **Yes.** Did they originate from the same client? **Yes.** Was there a later successful authentication inside the window? **Yes.** Is the source known and authorised for the exercise? **Yes.** Is an unauthorised compromise established? **No**.

**Disposition:** **True positive for the configured correlation rule**, with **authorised test activity** as the explanation. The measured severity reflects the rule's configuration and does not independently establish operational impact. This is not evidence of a malicious breach or a full compromise assessment.

## 5. Limitations and lessons learned

- The rule detects a narrow authentication pattern and does not establish the user's intent, the success of any exploit, or coverage of all services.
- Only the described event sequence and available logs were assessed; a deeper investigation would require other relevant telemetry and context.
- `rsyslog` reception time and device-local time differ by approximately one hour; normalise before correlating.
- V1 and V3 share detection components but process different log-reading paths. Agreement is a useful ingestion/correlation check, **not independent algorithm validation**.
- Keep raw operational logs, credentials, tokens and device backups outside the public repository.

For the expanded Spanish-language case record, including the original investigation details and limits, see [`docs/26-investigacion-soc-002-2026-11-04.md`](26-investigacion-soc-002-2026-11-04.md).
