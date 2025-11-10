```markdown
# Router IDS - IoT Intrusion Detection System for Raspberry Pi

A lightweight, extendable intrusion detection library designed to run on a Raspberry Pi used as an IoT router. Detects three attack types from tcpdump pcap captures: **DDoS**, **MITM**, and **C2C** (command-and-control).

## Features

- **Lightweight**: Synchronous, minimal dependencies. Runs on Raspberry Pi.
- **Modular**: Feature extraction, rule-based pre-checks, and pluggable detection models.
- **Efficient**: Single-pass packet parsing and feature extraction per capture interval.
- **Extendable**: Add new detectors by implementing the `FeatureExtractor` interface and registering with `CoreManager`.
- **Safe**: Includes security notes for production deployment.

## Requirements

- Python 3.11+
- Raspberry Pi OS (or any Linux distribution)
- `tcpdump` installed and configured with appropriate permissions
- Dependencies: scapy, pyyaml, scikit-learn, joblib

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/chetan-914/router-ids.git
   cd router-ids
   ```