# Contributing

Thanks for helping improve VulnScan Pro.

## Authorized Development

Use only systems you own, intentionally vulnerable local fixtures, or targets
you are explicitly authorized to assess. Never include client data, real scan
results, credentials, or private infrastructure details in tests or issues.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

The optional benchmark lab is documented in
[benchmarks/README.md](benchmarks/README.md).

## Pull Requests

- Keep changes focused and preserve safe cancellation and timeout behavior.
- Add tests for scanner, storage, reporting, CLI, or benchmark changes.
- Describe false-positive and false-negative considerations for new checks.
- Update documentation and report schemas when output changes.

By contributing, you agree that your contribution is licensed under the MIT
License.

