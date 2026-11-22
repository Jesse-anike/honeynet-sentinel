# HONEYNET SENTINEL — Cowrie Telemetry Analyzer

Analyze Cowrie honeypot JSON/JSONL exports for source-IP activity, login attempts, session counts, and command patterns; includes an optional Streamlit dashboard.

## Scope

This is a defensive, self-directed portfolio project. It analyzes local logs, source files, or exported cloud data. It does not exploit systems, execute attacker-supplied commands, or automatically change cloud/security settings.

## Requirements

- Python 3.10+
- Standard library for the core CLI
- Optional Streamlit dashboard: `pip install -r requirements.txt`

Install optional project dependencies:

```bash
python -m pip install -r requirements.txt
```

## Quick start

```bash
python main.py cowrie.jsonl
```

## Optional dashboard

```bash
python -m pip install -r requirements.txt
streamlit run dashboard.py
```

Upload a Cowrie `cowrie.json` or JSONL export in the dashboard. The analyzer summarizes events and never executes commands found in honeypot logs.

## Tests

```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Ethical and operational use

Use only logs, source code, cloud exports, and infrastructure you own or are explicitly authorized to assess. Treat every alert as a lead for human investigation. Never expose a honeypot or test service without an approved isolation plan, egress restrictions, monitoring, and an owner-approved budget.

## Portfolio context

Built for Anike-Moses Melie Jesse's cybersecurity and cloud-security portfolio. This is an independent learning implementation and must not be represented as a production deployment or certified security product without separate validation.
