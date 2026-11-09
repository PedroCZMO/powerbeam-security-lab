# PowerBeam Security Lab

**[English](README.md) | [Español](README.es.md)**

[![Python Tests](https://github.com/PedroCZMO/powerbeam-security-lab/actions/workflows/python-tests.yml/badge.svg?branch=main)](https://github.com/PedroCZMO/powerbeam-security-lab/actions/workflows/python-tests.yml)

**Hands-on Blue Team / SOC L1 lab** | Python · Linux · Syslog · Detection Engineering · Incident Triage · Automated Testing

> A documented personal cybersecurity lab built around an **owned Ubiquiti PowerBeam device** and a controlled local test network. This is a learning and engineering project, **not a production SOC, a commercial SIEM, or evidence of a real-world compromise**.

## 30-second overview

I built a small SOC-style monitoring pipeline that ingests **real authentication events** from a physical Ubiquiti PowerBeam, detects suspicious sequences in Python, writes deduplicated JSONL alerts, and supports investigation and acknowledgement. An Ubuntu host receives syslog; a Kali Linux VM produces **authorised** test traffic. Two monitoring implementations allow batch-versus-incremental validation.

| Evidence a reviewer can inspect | Verified outcome |
| --- | --- |
| **Real SSH detection (SOC-001)** | **Five failed SSH logins** from Kali within **18.72 seconds** triggered one alert in both V1 and V3; their parsed JSON alert records were identical. [Investigation →](docs/42-pb-pt-002-soc-001-investigation.en.md) |
| **Failed-then-successful login detection (SOC-002)** | Two failures followed by a success were correlated from real device logs in an authorised simulation. [Investigation →](docs/26-soc-002-investigation.en.md) |
| **Automated verification** | **502 Python unit tests passed** in [GitHub Actions (Python 3.12), 9 Nov 2026](https://github.com/PedroCZMO/powerbeam-security-lab/actions/runs/42609738643); the previous **482 tests passed locally** on 6 Nov. |
| **Operational automation** | V1 and V3 monitor runs (roughly every five minutes), infrastructure health checks, and an alert queue driven by `systemd`. |
| **Case handling** | SOC-001 alert was reviewed and acknowledged; after the exercise, the primary queue reported **3 seen / 0 pending / 1 acknowledged**. |

**Start with the [SOC-001 Purple Team case study](docs/42-pb-pt-002-soc-001-investigation.en.md)** if you are assessing investigation skills, or read the [detectors](scripts/) and [tests](tests/) for implementation details.

## Architecture

```text
                         AUTHORISED LOCAL TEST NETWORK
  Kali Linux VM                                    Ubiquiti PowerBeam
  Red Team / SSH client  ── failed logins ───────> Dropbear SSH server
  192.168.1.30                                     192.168.1.20
                                                        │
                                               UDP/5514 syslog
                                                        │
                                                        ▼
                                                  Ubuntu / rsyslog
                                                  192.168.1.10
                                                        │
                                          /var/log/powerbeam/*.log*
                                                        │
                               ┌────────────────────────┴───────────────────┐
                               ▼                                            ▼
                       Monitor V1 (batch)                           Monitor V3 (incremental)
                         SOC-001/002                                  SOC-001/002
                               │                                            │
                        alerts.jsonl                                 alerts-v3.jsonl
                               │
                         Local alert queue
                         review / acknowledge

               systemd timers · health checks · logrotate · reports
```

Private IPs above describe the lab network, **not public Internet exposure**. V1 and V3 share detection logic while using different ingestion paths; matching outputs are **not** evidence of two independently designed detection engines.

## Detection rules and tested cases

| Rule | Condition | Real-world evidence | Interpretation |
| --- | --- | --- | --- |
| **SOC-001** | At least **five failed authentications from one client IP within five minutes** | Five incorrect passwords recorded by Dropbear on **6 Nov 2026**, from Kali `192.168.1.30`. Both monitors emitted `SOC-001-36f69895f7b28039`. | **True positive for the rule**, but the activity was an **authorised test**, not a confirmed malicious brute-force attack. |
| **SOC-002** | At least **two failures followed by a successful authentication from the same IP within five minutes** | Controlled authentication sequence on **4 Nov 2026**; both monitors produced matching alert fields. | Activity requiring triage; an alert alone does not establish compromise. |

**SOC-001 investigation outcome:** five connection events, five `Bad password attempt` events, and five `Exit before auth` events; **no successful SSH authentication observed in the reviewed 18:34–18:40 CET window**. The alert was persisted, reviewed and acknowledged without deleting the detection record. [Full timeline and evidence →](docs/42-pb-pt-002-soc-001-investigation.en.md)

**SOC-002 investigation outcome:** two incorrect passwords followed by a successful authentication in approximately **19.32 seconds**. The exercise was authorised and documented, not an unauthorised breach. [Case report →](docs/26-soc-002-investigation.en.md)

## Engineering work showcased

| Area | Implementation / evidence |
| --- | --- |
| **Log ingestion and parsing** | `rsyslog` collection from a physical device; Python parsers distinguish the device's syslog sender IP from the actual SSH client IP and use the **Ubuntu receive timestamp** for correlation. |
| **Detection and correlation** | `scripts/auth_detector.py`, `scripts/bruteforce_detector.py`, `scripts/security_monitor.py`: five-minute windows, source-IP correlation and non-duplicating alert IDs. |
| **Incremental processing / resilience** | `stateful_monitor_v3.py`, compressed-log readers and regression tests for disappeared log history, write failures, concurrency and log rotation/inode reuse. V3 remains **experimental**. |
| **Alert handling** | `scripts/alert_queue.py`: persistent local queue, restricted permissions, deduplication and explicit `reviewed` acknowledgement. Separate V3 output avoids double-counting in the primary queue. |
| **Health and operations** | `systemd` units/timers, `logrotate`, UDP listener and service health checks, cautious treatment of missing telemetry, and resilience reports. |
| **Local SOC dashboard** | [`scripts/soc_dashboard.py`](scripts/soc_dashboard.py) turns validated aggregate reports into a private, offline, read-only HTML dashboard. [Setup and safety notes →](docs/43-dia14-soc-dashboard-local.md). |
| **Reporting and trends** | Daily SOC metrics and reports, local private snapshots and trend comparisons. These aggregate V1 alert data; they do **not** claim complete network visibility. |
| **Notifications** | Manual Gmail API/OAuth proof of concept and health checks. **Automatic external alert delivery is not enabled.** |
| **Software quality** | `unittest` suite, offline fixtures including real Dropbear log syntax, and GitHub Actions CI on Ubuntu/Python 3.12. |

## For reviewers: where to look first

1. **[Purple Team case: real SSH failures and SOC-001 investigation](docs/42-pb-pt-002-soc-001-investigation.en.md)** — evidence, timelines, attribution, alert equivalence, triage and acknowledgement.
2. **[SOC-002 case: failed attempts followed by a successful login](docs/26-soc-002-investigation.en.md)** — correlation, classification and evidence limitations.
3. **[Dropbear regression tests](tests/test_purple_team_dropbear.py)** — eight tests derived from the actual SSH message format.
4. **[Core detector](scripts/security_monitor.py)** and **[incremental monitor](scripts/stateful_monitor_v3.py)** — implementation details.
5. **[GitHub Actions: 502 tests passed](https://github.com/PedroCZMO/powerbeam-security-lab/actions/runs/42609738643)** — independently visible CI result.

Additional implementation notes in [`docs/`](docs/) remain mainly in **Spanish**. The two investigation reports above are available in English and Spanish. The complete original overview is preserved in [README.es.md](README.es.md).

## Run the offline tests

Clone the repository and, from its root, run:

```bash
python3 -m unittest discover -s tests -q
```

The test suite uses Python's standard library and synthetic/offline fixtures. **502 tests, OK** were verified in GitHub Actions on **9 Nov 2026**; **482 tests, OK** were previously verified locally on 6 Nov. An expected `argparse` error from a negative test checking Gmail's `--confirm-live-send` safeguard may appear on stderr; the final `OK` and successful workflow conclusion are the relevant result.

To run the batch monitor **without writing alerts**, pipe appropriately formatted local sample syslog lines into:

```bash
python3 scripts/security_monitor.py
```

**Cloning does not reproduce the physical device, live rsyslog feed, systemd services, OAuth credentials or historical incidents.** Follow the lab's deployment documentation and use only hardware and networks you own or are authorised to test.

## Security, scope and limitations

- The lab is **authorised and local**; it does not demonstrate an external attack or a compromised device.
- Original backups, passwords, private keys, access tokens and full unsanitised log collections must **not** be committed. See [SECURITY.md](SECURITY.md) (Spanish).
- Syslog over UDP lacks encryption and delivery guarantees; restrict it to a trusted segment.
- The **device's internal log clock differed by one hour** from the timestamp received by Ubuntu. Correlation uses the receiver's timezone-aware timestamp; the device's clock configuration requires separate validation.
- A healthy process, open UDP socket or ICMP response does **not** prove continuous log ingestion. Health reporting deliberately exposes `UNKNOWN` where it cannot establish freshness.
- The implementation is a **learning project**, without production HA, complete threat coverage, a full SIEM, or automated incident containment.

## Project status

**Verified technical milestone: 9 November 2026** · **README refreshed: 9 November 2026**.

Completed: physical-device syslog ingestion, SOC-001/SOC-002 correlation, dual-monitor evidence matching, automated CI tests, alert triage/acknowledgement, basic operational monitoring, and an offline read-only SOC dashboard. Next areas for improvement: richer detection coverage, verifiable ingestion health, and improvements to the **read-only local SOC dashboard**.

**Language:** [English](README.md) · [Español](README.es.md)
