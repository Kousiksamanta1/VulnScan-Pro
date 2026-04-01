# Dissertation Readiness Checklist

This project now supports both GUI-led demonstrations and CLI-led repeatable scans.
Use this checklist to turn the repository into a dissertation artifact that is easier
to examine, archive, and publish.

## Already Added

- Headless CLI mode for repeatable scans and report generation
- Runtime and dependency metadata embedded in saved scan results
- Structured error capture in the scan output
- Package metadata in `pyproject.toml`
- CI test workflow in `.github/workflows/tests.yml`
- Controlled benchmark lab assets in `benchmarks/`
- Benchmark runner and evaluator scripts for precision, recall, false positives, and duration

## Next Research Tasks

- Run the controlled benchmark lab and capture initial benchmark tables for VulnScan Pro
- Compare findings, runtime, and false positives against baseline tools such as Nmap and OWASP ZAP
- Extend the benchmark set with larger third-party targets such as OWASP Juice Shop, DVWA, WebGoat, or Metasploitable after the controlled lab is stable
- Extend web coverage toward POST forms, JSON bodies, authentication, and crawl depth

## Publication Checklist

- Confirm licensing and distribution expectations with your supervisor before publishing the repository
- Archive a tagged release and dissertation dataset in a long-term repository such as Zenodo or a Newcastle-supported service
- Keep exported HTML and JSON reports as evidence because they contain run provenance and configuration
- Include an ethics and authorized-use statement in the dissertation and any public repository description
- Store only authorized scan data and redact sensitive targets before sharing examples
