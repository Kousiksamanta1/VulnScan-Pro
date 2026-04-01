# Benchmark Lab

This directory contains a controlled local benchmark lab for evaluating
VulnScan Pro against stable, intentionally vulnerable fixtures.

## Included Targets

- `reflected-xss-lab`: returns reflected input in HTML contexts on `http://localhost:8081`
- `sqli-lab`: simulates error-based, boolean-based, and time-based SQLi behavior on `http://localhost:8082`
- `header-cookie-lab`: omits common defensive headers and sets weak cookies on `http://localhost:8083`
- `tcp-banner-lab`: exposes a simple TCP banner service on `localhost:2525`

## Quick Start

Start the local lab:

```bash
python3 benchmark_lab.py up
```

List the configured targets:

```bash
python3 benchmark_lab.py targets
```

Run VulnScan Pro and optional baseline tools:

```bash
python3 benchmark_runner.py --skip-missing-tools
```

Evaluate a completed run again if needed:

```bash
python3 benchmark_metrics.py benchmarks/results/run_YYYYMMDD_HHMMSS
```

Stop the local lab:

```bash
python3 benchmark_lab.py down
```

## Notes

- The fixtures are designed for local, authorized testing only.
- `nmap` and `zap-baseline.py` are optional baselines; the runner can skip them when absent.
- `targets.json` includes canonical expected findings and tool-specific expectations so precision/recall can be measured.
