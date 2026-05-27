# AWS VPC Flow Log Threat Hunter & Anomaly Parser

[![Language](https://img.shields.io/badge/Language-Python%203.9%2B-blue.svg)](https://www.python.org/)
[![SDK](https://img.shields.io/badge/SDK-Boto3-orange.svg)](https://aws.amazon.com/pythonsdk/)
[![Security](https://img.shields.io/badge/Analysis-Network%20Threat%20Hunting-red.svg)](https://aws.amazon.com/vpc/)

## Operational Overview

This repository contains an automated network threat-hunting engine written in Python that programmatically parses **AWS VPC Flow Logs** to identify malicious traffic patterns, port scanning anomalies, and brute-force indicators hitting private cloud infrastructure.

Monitoring network metadata is essential for maintaining compliance perimeters. This tool processes flow log aggregates, isolates rejected connection attempts by external IP addresses, flags spikes in traffic on high-risk management ports (such as SSH `22` and RDP `3389`), and outputs a prioritized network security intelligence report.

---

### Core Security Capabilities

* **Malicious Port-Scan Tracking:** Identifies distributed external traffic hitting high-risk infrastructure entry points to flag active reconnaissance phases.
* **Rejection Analytics Ingestion:** Groups and counts connection statuses marked as `REJECT` to isolate targeted probing attempts against security groups.
* **High-Value Target Auditing:** Aggregates telemetry logs around critical internal resource network interfaces (ENIs) experiencing elevated traffic density.

---

## Repository Structural Mapping

```text
aws-vpc-flow-log-threat-hunter/
├── README.md                      # Technical documentation and scope
├── vpc_flow_hunter.py             # Main Python log analysis engine
├── requirements.txt               # Script dependencies
└── network_threat_report.json     # Mock analysis output payload
