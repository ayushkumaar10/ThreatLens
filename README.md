# ThreatLens

**ThreatLens v2.0** is a Python-based network threat detection tool that analyzes PCAP files and identifies suspicious activity using modular packet-based detectors.

It is designed as a practical cybersecurity project for analyzing captured network traffic and demonstrating common network and application-layer attack detection techniques.

## Features

* PCAP file analysis using Scapy
* Modular detector architecture
* HTTP traffic inspection
* TCP traffic analysis
* DNS traffic analysis
* Network statistics and protocol statistics
* Source and destination host statistics
* Threat severity classification
* Human-readable terminal reporting
* Dedicated PCAP test cases for each detector

## Supported Detectors

| Detector              | Severity | Detection                                               |
| --------------------- | -------- | ------------------------------------------------------- |
| Port Scan             | High     | Multiple destination ports contacted by the same source |
| SQL Injection         | High     | SQL injection patterns such as `UNION SELECT`           |
| Cross-Site Scripting  | Medium   | XSS payload patterns such as `<script>`                 |
| Directory Traversal   | High     | Traversal patterns such as `../` and `/etc/passwd`      |
| Command Injection     | Critical | Command execution patterns such as `; whoami`           |
| Suspicious User-Agent | Low      | Suspicious tool/user-agent strings such as `sqlmap`     |
| DNS Tunneling         | High     | Suspiciously long or encoded-looking DNS queries        |

## Architecture

```text
ThreatLens
│
├── threatlens.py
│
├── core/
│   ├── analyzer.py
│   ├── detector_engine.py
│   ├── parser.py
│   ├── reporter.py
│   ├── statistics.py
│   └── utils.py
│
├── detectors/
│   ├── base_detector.py
│   ├── portscan.py
│   ├── sqli.py
│   ├── xss.py
│   ├── traversal.py
│   ├── command_injection.py
│   ├── suspicious_useragent.py
│   └── dns_tunneling.py
│
├── tests/
│   └── pcap/
│
├── samples/
│   └── test.pcap
│
├── assets/
│   └── banner.py
│
├── captures/
│
├── requirements.txt
└── README.md
```

## Detection Pipeline

ThreatLens follows a modular analysis pipeline:

```text
PCAP File
   │
   ▼
Packet Parser
   │
   ▼
Protocol / Network Analysis
   │
   ▼
Detector Engine
   │
   ├── Port Scan
   ├── SQL Injection
   ├── XSS
   ├── Directory Traversal
   ├── Command Injection
   ├── Suspicious User-Agent
   └── DNS Tunneling
   │
   ▼
Threat Findings
   │
   ▼
Terminal Reporter
```

## Installation

Clone the repository:

```bash
git clone https://github.com/ayushkumaar10/ThreatLens.git
cd ThreatLens
```

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Analyze a PCAP file:

```bash
python threatlens.py <pcap-file>
```

Example:

```bash
python threatlens.py tests/pcap/sqli.pcap
```

Example output:

```text
──────────────────────────── ThreatLens v2.0 ────────────────────────────
PCAP File      : sqli.pcap
Packets Loaded : 22
Detectors Run  : 7
──────────────────────────── Threat Summary ─────────────────────────────
Threats Found: 1

Detector: SQL Injection
Severity: High
Source      : 127.0.0.1
Destination : 127.0.0.1
Message     : Possible SQL Injection detected (union select)
```

## Test PCAPs

ThreatLens v2.0 includes dedicated PCAP files for testing the detectors:

```text
tests/pcap/
├── sqli.pcap
├── xss.pcap
├── traversal.pcap
├── command_injection.pcap
├── suspicious_useragent.pcap
├── dns_tunneling.pcap
└── portscan.pcap
```

Run an individual detector test:

```bash
python threatlens.py tests/pcap/dns_tunneling.pcap
```

The v2.0 regression tests confirmed that all seven detectors execute successfully through the detector engine and identify their corresponding test traffic.

## Example Detections

### SQL Injection

```text
Possible SQL Injection detected (union select)
```

### Cross-Site Scripting

```text
Possible XSS detected (<script)
```

### Directory Traversal

```text
Possible Directory Traversal detected (../)
```

### Command Injection

```text
Possible Command Injection detected (whoami)
```

### Suspicious User-Agent

```text
Suspicious User-Agent detected (sqlmap/1.8)
```

### DNS Tunneling

```text
Possible DNS Tunneling detected (long DNS label)
```

### Port Scan

```text
Possible port scan detected (15 ports)
```

## Development

Compile the project:

```bash
python -m compileall -q core detectors threatlens.py
```

Run the detector regression PCAPs:

```bash
python threatlens.py tests/pcap/sqli.pcap
python threatlens.py tests/pcap/xss.pcap
python threatlens.py tests/pcap/traversal.pcap
python threatlens.py tests/pcap/command_injection.pcap
python threatlens.py tests/pcap/suspicious_useragent.pcap
python threatlens.py tests/pcap/dns_tunneling.pcap
python threatlens.py tests/pcap/portscan.pcap
```

## Project Goals

ThreatLens is intended to demonstrate:

* Network traffic analysis
* PCAP processing
* Python-based security tooling
* Modular security detector design
* HTTP attack detection
* DNS traffic analysis
* Network reconnaissance detection
* Security-focused software architecture

## Version

**ThreatLens v2.0**

### v2.0 Highlights

* Expanded the detector engine to seven detectors
* Added Command Injection detection
* Added Suspicious User-Agent detection
* Added DNS Tunneling detection
* Refactored detectors to use the current `BaseDetector` API
* Added dedicated detector PCAP test cases
* Normalized detector severity reporting
* Completed v2.0 regression testing

## Disclaimer

ThreatLens is intended for educational, defensive security research, and authorized network analysis.

Only analyze network traffic that you are authorized to inspect.
