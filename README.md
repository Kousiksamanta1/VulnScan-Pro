# VulnScan Pro

Professional desktop vulnerability scanner built with Python, `customtkinter`, and a threaded scanning engine.

VulnScan Pro combines a polished desktop interface with live scan telemetry, DNS and TLS intelligence, lightweight web security checks, scan history, and export-ready reporting.

## Highlights

- Professional dark desktop UI built with `customtkinter`
- Decoupled architecture with separate GUI, engine, storage, and reporting modules
- Responsive scanning using `threading`, `queue.Queue`, and concurrent workers
- Configurable port presets and custom ranges
- DNS intelligence for `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SPF`, `DMARC`, and `SOA`
- Port scanning with service-aware banner probing
- TLS posture analysis with certificate metadata, expiry awareness, and weak protocol detection
- Lightweight web posture checks for reflected XSS indicators, SQL error indicators, security headers, cookie flags, redirects, and forms
- Persistent settings and scan history
- Snapshot comparison between scans
- Export support for `JSON`, `CSV`, `HTML`, and `PDF`
- PyInstaller build helper for desktop packaging

## Project Structure

```text
.
├── build_release.py
├── main.py
├── requirements.txt
├── requirements-dev.txt
├── scanner_app.py
├── scanner_engine.py
├── scanner_reporting.py
├── scanner_storage.py
├── tests/
│   ├── test_scanner_engine.py
│   └── test_scanner_storage.py
└── README.md
```

## Architecture

### `scanner_engine.py`

Handles:

- target validation and normalization
- port parsing and scan presets
- DNS collection
- port scanning and banner probing
- TLS inspection
- lightweight web checks
- streamed result events for the GUI

### `scanner_app.py`

Handles:

- application layout and styling
- live scan controls and cancellation
- safe UI updates from background threads
- dashboard cards and tabbed views
- history loading and comparison
- export actions

### `scanner_storage.py`

Handles:

- settings persistence
- scan history persistence
- scan snapshot summaries
- comparison between stored and current results

### `scanner_reporting.py`

Handles:

- JSON export
- CSV export
- HTML export
- PDF export

## Installation

### 1. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install runtime dependencies

```bash
pip install -r requirements.txt
```

### 3. Install optional build dependencies

```bash
pip install -r requirements-dev.txt
```

## Run the Application

```bash
python3 main.py
```

Using the local virtual environment:

```bash
.venv/bin/python main.py
```

## How to Use

1. Enter a target IP, domain, or URL.
2. Select a port profile such as `common`, `top100`, `web`, `database`, `mail`, or `remote`.
3. Optionally enter custom ports like `1-1024,8080,8443`.
4. Set timeout, worker count, and preferred export format.
5. Click `Start Scan`.
6. Monitor results in the `Overview`, `Ports`, `Web`, `Intel`, `History`, and `Settings` tabs.
7. Click `Stop` to cancel an active scan safely.
8. Export the loaded results when needed.

## Port Input Examples

- `common`
- `top100`
- `web`
- `21,22,80,443`
- `1-1024`
- `1-1024,8080,8443`

## Export Formats

Supported report formats:

- `JSON`
- `CSV`
- `HTML`
- `PDF`

## Testing

Run the test suite with:

```bash
python3 -m unittest discover -s tests -v
```

## Packaging

After installing `requirements-dev.txt`, build a desktop bundle with:

```bash
python3 build_release.py
```

The generated application bundle will be placed in the PyInstaller output directory.

## Notes

- Web checks in this project are lightweight indicators, not a full web application security assessment.
- Some services may not expose useful banners even when ports are open.
- DNS collection is skipped for IP-only targets where hostname records do not apply.
- TLS analysis depends on the target exposing a reachable TLS service.
- User settings and scan history are stored in `~/.vulnscan_pro/`.

## Disclaimer

Use this tool only on systems, applications, and networks you own or are explicitly authorized to assess.
