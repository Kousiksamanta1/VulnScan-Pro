"""Advanced scanning engine for the professional vulnerability scanner."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import tempfile
import time
import warnings
from collections.abc import Iterable as IterableABC
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

try:
    import dns.resolver as dns_resolver
except ModuleNotFoundError:  # pragma: no cover - optional dependency.
    dns_resolver = None

try:
    import requests
    from requests import RequestException
    from urllib3.exceptions import InsecureRequestWarning

    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
except ModuleNotFoundError:  # pragma: no cover - optional dependency.
    requests = None

    class RequestException(Exception):
        """Fallback exception used when requests is unavailable."""


class HTMLFormParser(HTMLParser):
    """Parse simple HTML forms and their named inputs."""

    def __init__(self) -> None:
        """Initialize parser state for HTML form discovery."""
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Capture form and input metadata from each opening tag."""
        attributes = {key.lower(): value or "" for key, value in attrs}
        normalized_tag = tag.lower()

        if normalized_tag == "form":
            self._current_form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "GET").upper(),
                "inputs": [],
            }
            return

        if normalized_tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = attributes.get("name", "").strip()
            if name:
                self._current_form["inputs"].append(
                    {
                        "name": name,
                        "type": attributes.get("type", normalized_tag or "text"),
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        """Persist each form when its closing tag is encountered."""
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class ScannerEngine:
    """Backend engine responsible for validation, scanning, and streamed events."""

    COMMON_PORTS = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTTP",
        81: "HTTP-Alt",
        88: "Kerberos",
        110: "POP3",
        111: "RPC",
        123: "NTP",
        135: "MSRPC",
        137: "NetBIOS-NS",
        138: "NetBIOS-DGM",
        139: "NetBIOS-SSN",
        143: "IMAP",
        161: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        587: "Submission",
        631: "IPP",
        636: "LDAPS",
        873: "Rsync",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        2049: "NFS",
        2375: "Docker",
        3000: "Node",
        3306: "MySQL",
        3389: "RDP",
        5000: "Flask",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8000: "HTTP-Dev",
        8080: "HTTP-Alt",
        8081: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9000: "SonarQube",
        9200: "Elasticsearch",
        9443: "HTTPS-Alt",
        27017: "MongoDB",
    }

    TOP_100_PORTS = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 135, 139, 143, 179, 199, 389, 427, 443, 444, 445, 465, 513,
        514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
        1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
        2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
        5060, 5101, 5190, 5357, 5432, 5666, 5900, 6000, 6001, 6646, 7070, 8000,
        8008, 8080, 8081, 8443, 8888, 9000, 9040, 9090, 9100, 9999, 10000, 32768,
        49152, 49153, 49154, 49155, 49156, 49157,
    ]

    PORT_PRESETS = {
        "common": sorted(COMMON_PORTS),
        "top100": TOP_100_PORTS,
        "web": [80, 81, 443, 444, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9443],
        "database": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
        "mail": [25, 110, 143, 465, 587, 993, 995],
        "remote": [22, 23, 3389, 5900],
    }

    HTTP_PORTS = {80, 81, 443, 444, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9443}
    TLS_PORTS = {443, 444, 465, 636, 8443, 9443}
    SECURITY_HEADERS = (
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    )
    SQLI_ERROR_PATTERNS = [
        re.compile(r"sql syntax", re.IGNORECASE),
        re.compile(r"warning.*mysql", re.IGNORECASE),
        re.compile(r"unclosed quotation mark", re.IGNORECASE),
        re.compile(r"quoted string not properly terminated", re.IGNORECASE),
        re.compile(r"postgresql.*error", re.IGNORECASE),
        re.compile(r"sqlite.*error", re.IGNORECASE),
        re.compile(r"odbc sql server driver", re.IGNORECASE),
        re.compile(r"ora-\d{4,5}", re.IGNORECASE),
    ]
    XSS_PAYLOADS = (
        {
            "name": "script-tag-breakout",
            "payload": '"><script>window.__vulnscan_xss__=1</script>',
            "contexts": {"attribute", "html_tag", "html_text"},
        },
        {
            "name": "svg-onload-breakout",
            "payload": "'><svg/onload=window.__vulnscan_xss__=1>",
            "contexts": {"attribute", "html_tag", "html_text"},
        },
        {
            "name": "image-onerror-injection",
            "payload": "<img src=x onerror=window.__vulnscan_xss__=1>",
            "contexts": {"html_text", "html_tag"},
        },
        {
            "name": "script-block-breakout",
            "payload": "</script><script>window.__vulnscan_xss__=1</script>",
            "contexts": {"script_block", "html_text"},
        },
        {
            "name": "autofocus-onfocus-breakout",
            "payload": '" autofocus onfocus=window.__vulnscan_xss__=1 x="',
            "contexts": {"attribute", "html_tag"},
        },
    )
    SQLI_ERROR_PAYLOADS = (
        {"name": "single-quote", "payload": "'"},
        {"name": "double-quote", "payload": '"'},
        {"name": "quote-burst", "payload": '\'\"`'},
        {"name": "parenthesis-break", "payload": "')"},
    )
    SQLI_BOOLEAN_PAYLOADS = (
        {
            "name": "quoted-boolean",
            "true_payload": "' OR '1'='1' -- ",
            "false_payload": "' AND '1'='2' -- ",
        },
        {
            "name": "numeric-boolean",
            "true_payload": "1 OR 1=1 -- ",
            "false_payload": "1 AND 1=2 -- ",
        },
    )
    SQLI_TIME_PAYLOADS = (
        {
            "name": "mysql-sleep",
            "payload": "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))v) -- ",
            "delay": 5.0,
        },
        {
            "name": "numeric-mysql-sleep",
            "payload": "1 AND SLEEP(5) -- ",
            "delay": 5.0,
        },
        {
            "name": "mssql-waitfor",
            "payload": "1; WAITFOR DELAY '0:0:5' --",
            "delay": 5.0,
        },
    )
    BOOLEAN_SQLI_MATCH_THRESHOLD = 0.92
    BOOLEAN_SQLI_DIFFERENCE_THRESHOLD = 0.78
    BOOLEAN_SQLI_CROSS_DIFF_THRESHOLD = 0.88
    TIME_SQLI_DELAY_THRESHOLD = 3.0
    RISKY_PORTS = {
        21: "medium",
        23: "high",
        25: "medium",
        110: "medium",
        143: "medium",
        445: "high",
        3389: "high",
        5900: "high",
        6379: "high",
        9200: "high",
        27017: "high",
    }

    def __init__(
        self,
        timeout: float = 2.0,
        max_workers: int = 32,
        stop_event: Any | None = None,
    ) -> None:
        """Initialize the scanner engine with network and threading options."""
        self.timeout = timeout
        self.max_workers = max_workers
        self.stop_event = stop_event

    @classmethod
    def parse_ports(cls, port_spec: str | Iterable[int] | None) -> list[int]:
        """Parse a port preset, list, range, or mixed specification into integers."""
        if port_spec is None:
            return sorted(cls.PORT_PRESETS["common"])

        if isinstance(port_spec, IterableABC) and not isinstance(port_spec, str):
            ports = {int(port) for port in port_spec if 0 < int(port) <= 65535}
            if not ports:
                raise ValueError("No valid ports were supplied.")
            return sorted(ports)

        text = str(port_spec).strip().lower()
        if not text:
            return sorted(cls.PORT_PRESETS["common"])

        tokens = [token.strip() for token in text.split(",") if token.strip()]
        ports: set[int] = set()

        for token in tokens:
            if token in cls.PORT_PRESETS:
                ports.update(cls.PORT_PRESETS[token])
                continue

            if "-" in token:
                start_text, end_text = token.split("-", maxsplit=1)
                if not start_text.isdigit() or not end_text.isdigit():
                    raise ValueError(f"Invalid port range '{token}'.")
                start_port = int(start_text)
                end_port = int(end_text)
                if not 0 < start_port <= end_port <= 65535:
                    raise ValueError(f"Invalid port range '{token}'.")
                ports.update(range(start_port, end_port + 1))
                continue

            if token.isdigit():
                port = int(token)
                if not 0 < port <= 65535:
                    raise ValueError(f"Invalid port '{token}'.")
                ports.add(port)
                continue

            raise ValueError(
                f"Unknown port preset or value '{token}'. "
                "Use presets like common/top100/web or explicit ports."
            )

        if not ports:
            raise ValueError("No valid ports were supplied.")

        return sorted(ports)

    @staticmethod
    def prepare_target(target: str) -> dict[str, Any]:
        """Normalize and validate a target string for network and web checks."""
        raw_target = target.strip()
        if not raw_target:
            raise ValueError("Target cannot be empty.")

        candidate = raw_target if "://" in raw_target else f"http://{raw_target}"
        parsed = urlsplit(candidate)
        hostname = parsed.hostname or ""
        if not hostname:
            raise ValueError("Target must include a valid hostname or IP address.")

        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise ValueError("The target contains an invalid network port.") from exc

        if not ScannerEngine._is_ip_address(hostname) and not ScannerEngine._is_valid_hostname(
            hostname
        ):
            raise ValueError("The supplied hostname is not valid.")

        scheme = parsed.scheme or "http"
        path = parsed.path or "/"
        netloc = parsed.netloc or hostname
        normalized_url = urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))

        return {
            "input": raw_target,
            "hostname": hostname,
            "url": normalized_url,
            "scheme": scheme,
            "port": parsed_port,
            "is_ip": ScannerEngine._is_ip_address(hostname),
        }

    def get_dns_info(self, target: str) -> dict[str, Any]:
        """Return A, AAAA, CNAME, MX, NS, TXT, SPF, DMARC, and SOA records."""
        hostname = self._extract_hostname(target)
        result: dict[str, Any] = {
            "target": hostname,
            "status": "completed",
            "records": {
                "A": [],
                "AAAA": [],
                "CNAME": [],
                "MX": [],
                "NS": [],
                "TXT": [],
                "SPF": [],
                "DMARC": [],
                "SOA": [],
            },
            "errors": {},
        }

        if self._cancelled():
            result["status"] = "cancelled"
            return result

        if self._is_ip_address(hostname):
            result["status"] = "skipped"
            result["errors"]["general"] = "DNS enumeration is skipped for IP targets."
            return result

        if dns_resolver is None:
            result["status"] = "error"
            result["errors"]["general"] = "dnspython is not installed."
            return result

        resolver = dns_resolver.Resolver()
        resolver.lifetime = self.timeout + 2.0
        record_types = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")

        for record_type in record_types:
            if self._cancelled():
                result["status"] = "cancelled"
                return result

            try:
                answers = resolver.resolve(hostname, record_type)
                result["records"][record_type] = self._format_dns_answers(record_type, answers)
            except Exception as exc:  # pragma: no cover - network dependent.
                result["errors"][record_type] = str(exc)

        try:
            result["records"]["SPF"] = [
                record
                for record in result["records"]["TXT"]
                if record.lower().startswith("v=spf1")
            ]
        except Exception:  # pragma: no cover - defensive.
            result["records"]["SPF"] = []

        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            result["records"]["DMARC"] = self._format_dns_answers("TXT", dmarc_answers)
        except Exception as exc:  # pragma: no cover - network dependent.
            result["errors"]["DMARC"] = str(exc)

        return result

    def scan_port(self, target: str, port: int) -> dict[str, Any]:
        """Scan a single TCP port and return service, latency, banner, and severity."""
        hostname = self._extract_hostname(target)
        started = time.perf_counter()
        result = {
            "port": port,
            "service": self._guess_service(port),
            "banner": "",
            "status": "closed",
            "latency_ms": 0.0,
            "severity": self._derive_port_severity(port, "closed"),
        }

        if self._cancelled():
            result["status"] = "cancelled"
            result["severity"] = "info"
            return result

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                result["status"] = "open"
                result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
                banner, service = self._probe_service(sock, hostname, port)
                result["banner"] = banner
                if service:
                    result["service"] = service
                result["severity"] = self._derive_port_severity(port, "open")
        except socket.timeout:
            result["status"] = "timeout"
            result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
            result["severity"] = "low"
        except OSError as exc:
            result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
            error_text = str(exc).lower()
            if "refused" not in error_text and "host down" not in error_text:
                result["status"] = "error"
                result["banner"] = str(exc)
                result["severity"] = "medium"

        return result

    def analyze_tls(self, target: str) -> dict[str, Any]:
        """Analyze TLS posture, certificate data, and weak protocol support."""
        context = self.prepare_target(target)
        hostname = context["hostname"]
        candidate_ports = self._candidate_tls_ports(context)
        result: dict[str, Any] = {
            "target": hostname,
            "status": "completed",
            "grade": "Unavailable",
            "endpoints": [],
            "findings": [],
        }

        if self._cancelled():
            result["status"] = "cancelled"
            return result

        for port in candidate_ports:
            if self._cancelled():
                result["status"] = "cancelled"
                return result

            endpoint = {
                "port": port,
                "status": "unreachable",
                "version": "",
                "cipher": "",
                "subject": "",
                "issuer": "",
                "expires_at": "",
                "days_remaining": None,
                "weak_protocols": [],
                "severity": "info",
                "error": "",
            }

            try:
                with socket.create_connection((hostname, port), timeout=self.timeout) as raw_socket:
                    context_ssl = ssl.create_default_context()
                    context_ssl.check_hostname = False
                    context_ssl.verify_mode = ssl.CERT_NONE
                    with context_ssl.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                        endpoint["status"] = "enabled"
                        endpoint["version"] = tls_socket.version() or ""
                        cipher = tls_socket.cipher()
                        endpoint["cipher"] = cipher[0] if cipher else ""

                certificate = self._decode_certificate(hostname, port)
                endpoint.update(certificate)
                endpoint["weak_protocols"] = self._detect_weak_tls_versions(hostname, port)
                endpoint["severity"] = self._derive_tls_severity(endpoint)

                if endpoint["weak_protocols"]:
                    result["findings"].append(
                        {
                            "name": f"Weak TLS protocol support on {port}",
                            "severity": "high",
                            "evidence": ", ".join(endpoint["weak_protocols"]),
                        }
                    )
                if isinstance(endpoint["days_remaining"], int):
                    if endpoint["days_remaining"] < 15:
                        result["findings"].append(
                            {
                                "name": f"Certificate expiring soon on {port}",
                                "severity": "high",
                                "evidence": f"{endpoint['days_remaining']} days remaining",
                            }
                        )
                    elif endpoint["days_remaining"] < 45:
                        result["findings"].append(
                            {
                                "name": f"Certificate renewal approaching on {port}",
                                "severity": "medium",
                                "evidence": f"{endpoint['days_remaining']} days remaining",
                            }
                        )
            except ssl.SSLError as exc:  # pragma: no cover - network dependent.
                endpoint["status"] = "handshake_failed"
                endpoint["error"] = str(exc)
                endpoint["severity"] = "medium"
            except OSError as exc:  # pragma: no cover - network dependent.
                endpoint["error"] = str(exc)

            result["endpoints"].append(endpoint)

        result["grade"] = self._score_tls_result(result["endpoints"])
        if not any(item["status"] == "enabled" for item in result["endpoints"]):
            result["status"] = "unavailable"

        return result

    def web_vuln_check(self, url: str) -> dict[str, Any]:
        """Run passive and lightweight active web security checks on a URL."""
        normalized_url = self._normalize_url(url)
        result: dict[str, Any] = {
            "url": normalized_url,
            "status": "completed",
            "final_url": normalized_url,
            "server": "",
            "redirects": [],
            "headers": {},
            "security_headers": {},
            "cookies": [],
            "forms": [],
            "parameters": [],
            "xss": {
                "vulnerable": False,
                "evidence": "",
                "tested": [],
                "parameter": "",
                "payload": "",
                "context": "",
            },
            "sqli": {
                "vulnerable": False,
                "evidence": "",
                "tested": [],
                "parameter": "",
                "payload": "",
                "technique": "",
            },
            "findings": [],
        }

        if self._cancelled():
            result["status"] = "cancelled"
            return result

        if requests is None:
            result["status"] = "error"
            result["message"] = "requests is not installed."
            return result

        session = requests.Session()
        session.headers.update({"User-Agent": "VulnScan-Pro/2.0"})
        session.verify = False

        try:
            baseline_started = time.perf_counter()
            baseline_response = session.get(
                normalized_url,
                timeout=self.timeout + 4.0,
                allow_redirects=True,
            )
            baseline_elapsed = time.perf_counter() - baseline_started
            baseline_text = baseline_response.text or ""
            result["final_url"] = baseline_response.url
            result["server"] = baseline_response.headers.get("Server", "")
            result["headers"] = dict(baseline_response.headers.items())
            result["redirects"] = [response.url for response in baseline_response.history]
            result["redirects"].append(baseline_response.url)

            parser = HTMLFormParser()
            parser.feed(baseline_text)
            result["forms"] = parser.forms
            result["parameters"] = self._discover_parameters(baseline_response.url, parser.forms)
            result["security_headers"] = self._inspect_security_headers(
                baseline_response.headers,
                baseline_response.url,
            )
            result["cookies"] = self._inspect_cookies(baseline_response)
            result["findings"].extend(
                self._build_passive_web_findings(
                    result["security_headers"],
                    result["cookies"],
                    baseline_response.headers,
                )
            )

            parameter_targets = self._build_parameter_targets(
                baseline_response.url,
                result["parameters"],
            )

            xss_result = self._run_xss_checks(
                session,
                parameter_targets,
                baseline_text,
            )
            result["xss"] = xss_result
            if xss_result["vulnerable"]:
                result["findings"].append(
                    {
                        "name": (
                            f"Potential reflected XSS in "
                            f"'{xss_result.get('parameter', 'unknown')}'"
                        ),
                        "severity": "high",
                        "evidence": xss_result["evidence"],
                    }
                )

            sqli_result = self._run_sqli_checks(
                session,
                parameter_targets,
                baseline_response,
                baseline_text,
                baseline_elapsed,
            )
            result["sqli"] = sqli_result
            if sqli_result["vulnerable"]:
                technique = sqli_result.get("technique", "heuristic").replace("-", " ")
                result["findings"].append(
                    {
                        "name": (
                            f"Potential SQL injection ({technique}) "
                            f"in '{sqli_result.get('parameter', 'unknown')}'"
                        ),
                        "severity": "high",
                        "evidence": sqli_result["evidence"],
                    }
                )

            powered_by = baseline_response.headers.get("X-Powered-By", "")
            if powered_by:
                result["findings"].append(
                    {
                        "name": "Technology disclosure header",
                        "severity": "low",
                        "evidence": powered_by,
                    }
                )
        except RequestException as exc:  # pragma: no cover - network dependent.
            result["status"] = "error"
            result["message"] = str(exc)
        finally:
            session.close()

        return result

    def run_full_scan(self, target: str, ports: Iterable[int]) -> Iterable[dict[str, Any]]:
        """Run DNS, web, TLS, and threaded port checks while yielding live events."""
        prepared = self.prepare_target(target)
        hostname = prepared["hostname"]
        port_list = self.parse_ports(list(ports))
        total_tasks = len(port_list) + 3
        completed_tasks = 0
        open_ports = 0
        executor = ThreadPoolExecutor(max_workers=min(self.max_workers, max(total_tasks, 4)))
        pending: set[Future[Any]] = set()
        future_map: dict[Future[Any], tuple[str, Any]] = {}

        yield {
            "type": "status",
            "message": f"Preparing scan profile for {hostname}.",
            "completed": 0,
            "total": total_tasks,
        }

        try:
            base_futures = {
                executor.submit(self.get_dns_info, hostname): ("dns", None),
                executor.submit(self.web_vuln_check, prepared["url"]): ("web", None),
                executor.submit(self.analyze_tls, target): ("tls", None),
            }
            future_map.update(base_futures)

            for port in port_list:
                future = executor.submit(self.scan_port, hostname, port)
                future_map[future] = ("port", port)

            pending = set(future_map)

            while pending:
                if self._cancelled():
                    for future in pending:
                        future.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    yield {
                        "type": "cancelled",
                        "message": "Scan cancelled by user.",
                        "completed": completed_tasks,
                        "total": total_tasks,
                    }
                    return

                done, pending = wait(
                    pending,
                    timeout=0.2,
                    return_when=FIRST_COMPLETED,
                )
                if not done:
                    continue

                for future in done:
                    task_type, _ = future_map[future]
                    completed_tasks += 1

                    try:
                        payload = future.result()
                    except Exception as exc:  # pragma: no cover - defensive.
                        yield {
                            "type": "error",
                            "message": f"{task_type.upper()} scan failed: {exc}",
                            "completed": completed_tasks,
                            "total": total_tasks,
                        }
                        continue

                    if task_type == "port" and payload.get("status") == "open":
                        open_ports += 1

                    yield {
                        "type": task_type,
                        "result": payload,
                        "completed": completed_tasks,
                        "total": total_tasks,
                    }
        finally:
            executor.shutdown(wait=False, cancel_futures=self._cancelled())

        yield {
            "type": "complete",
            "message": f"Scan finished. Open ports discovered: {open_ports}.",
            "completed": total_tasks,
            "total": total_tasks,
        }

    def _discover_parameters(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Collect query parameters and GET form inputs into a testable parameter list."""
        parameters: list[dict[str, Any]] = []
        parsed = urlsplit(url)
        query_params = parse_qsl(parsed.query, keep_blank_values=True)

        for key, _ in query_params:
            parameters.append({"name": key, "url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.fragment))})

        for form in forms:
            if form.get("method", "GET").upper() != "GET":
                continue

            action = urljoin(url, form.get("action") or url)
            for input_item in form.get("inputs", [])[:3]:
                parameters.append({"name": input_item["name"], "url": action})

        if not parameters:
            parameters.append({"name": "scanner_probe", "url": url})

        unique_parameters: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for parameter in parameters:
            key = (parameter["name"], parameter["url"])
            if key in seen:
                continue
            seen.add(key)
            unique_parameters.append(parameter)

        return unique_parameters[:8]

    def _build_parameter_targets(
        self,
        base_url: str,
        parameters: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        """Build injectable URLs for each discovered parameter candidate."""
        targets: list[dict[str, str]] = []
        for parameter in parameters:
            url = parameter.get("url") or base_url
            name = parameter["name"]
            targets.append({"url": url, "parameter": name})
        return targets

    def _run_xss_checks(
        self,
        session: Any,
        targets: list[dict[str, str]],
        baseline_text: str,
    ) -> dict[str, Any]:
        """Probe parameters with context-aware reflected XSS payloads."""
        tested: list[str] = []
        for target in targets:
            if self._cancelled():
                break

            for payload_def in self.XSS_PAYLOADS:
                if self._cancelled():
                    break

                probe_url = self._inject_payload(
                    target["url"],
                    payload_def["payload"],
                    target["parameter"],
                )
                tested.append(
                    f"{target['parameter']} @ {target['url']} "
                    f"[{payload_def['name']}]"
                )
                response, _, _ = self._issue_probe(session, probe_url)
                if response is None:
                    continue

                reflection = self._analyze_xss_reflection(
                    response.text or "",
                    baseline_text,
                    payload_def,
                )
                if reflection is None:
                    continue

                return {
                    "vulnerable": True,
                    "evidence": (
                        f"Reflected XSS-style payload '{payload_def['name']}' was "
                        f"returned in {reflection['label']} for parameter "
                        f"'{target['parameter']}' at {response.url}. "
                        f"Snippet: {reflection['snippet']}"
                    ),
                    "tested": tested,
                    "parameter": target["parameter"],
                    "payload": payload_def["payload"],
                    "context": reflection["name"],
                }

        return {
            "vulnerable": False,
            "evidence": "",
            "tested": tested,
            "parameter": "",
            "payload": "",
            "context": "",
        }

    def _run_sqli_checks(
        self,
        session: Any,
        targets: list[dict[str, str]],
        baseline_response: Any,
        baseline_text: str,
        baseline_elapsed: float,
    ) -> dict[str, Any]:
        """Probe parameters with error, boolean, and time-based SQLi heuristics."""
        baseline_errors = set(self._extract_sqli_errors(baseline_text))
        baseline_profile = self._build_response_profile(baseline_response, baseline_text)
        tested: list[str] = []

        for target in targets:
            if self._cancelled():
                break

            control_timings = [baseline_elapsed] if baseline_elapsed > 0 else []

            error_result = self._check_error_based_sqli(
                session,
                target,
                baseline_errors,
                tested,
                control_timings,
            )
            if error_result is not None:
                return error_result

            boolean_result = self._check_boolean_based_sqli(
                session,
                target,
                baseline_profile,
                tested,
                control_timings,
            )
            if boolean_result is not None:
                return boolean_result

            time_result = self._check_time_based_sqli(
                session,
                target,
                baseline_profile,
                tested,
                control_timings,
            )
            if time_result is not None:
                return time_result

        return {
            "vulnerable": False,
            "evidence": "",
            "tested": tested,
            "parameter": "",
            "payload": "",
            "technique": "",
        }

    def _check_error_based_sqli(
        self,
        session: Any,
        target: dict[str, str],
        baseline_errors: set[str],
        tested: list[str],
        control_timings: list[float],
    ) -> dict[str, Any] | None:
        """Detect SQLi by provoking database error messages."""
        for payload_def in self.SQLI_ERROR_PAYLOADS:
            probe_url = self._inject_payload(
                target["url"],
                payload_def["payload"],
                target["parameter"],
            )
            tested.append(
                f"{target['parameter']} @ {target['url']} "
                f"[error-based:{payload_def['name']}]"
            )
            response, elapsed, _ = self._issue_probe(session, probe_url)
            if response is None:
                continue

            control_timings.append(elapsed)
            current_errors = set(self._extract_sqli_errors(response.text or ""))
            new_errors = sorted(current_errors - baseline_errors)
            if not new_errors:
                continue

            return {
                "vulnerable": True,
                "evidence": (
                    f"Database-style error patterns appeared after sending "
                    f"'{payload_def['name']}' to '{target['parameter']}': "
                    f"{', '.join(new_errors)}"
                ),
                "tested": tested,
                "parameter": target["parameter"],
                "payload": payload_def["payload"],
                "technique": "error-based",
            }

        return None

    def _check_boolean_based_sqli(
        self,
        session: Any,
        target: dict[str, str],
        baseline_profile: dict[str, Any],
        tested: list[str],
        control_timings: list[float],
    ) -> dict[str, Any] | None:
        """Detect SQLi by comparing true/false conditional responses."""
        for payload_def in self.SQLI_BOOLEAN_PAYLOADS:
            true_url = self._inject_payload(
                target["url"],
                payload_def["true_payload"],
                target["parameter"],
            )
            tested.append(
                f"{target['parameter']} @ {target['url']} "
                f"[boolean-based:{payload_def['name']}:true]"
            )
            true_response, true_elapsed, _ = self._issue_probe(session, true_url)
            if true_response is None:
                continue

            false_url = self._inject_payload(
                target["url"],
                payload_def["false_payload"],
                target["parameter"],
            )
            tested.append(
                f"{target['parameter']} @ {target['url']} "
                f"[boolean-based:{payload_def['name']}:false]"
            )
            false_response, false_elapsed, _ = self._issue_probe(session, false_url)
            if false_response is None:
                continue

            control_timings.extend([true_elapsed, false_elapsed])
            analysis = self._assess_boolean_sqli(
                baseline_profile,
                true_response,
                false_response,
                payload_def["true_payload"],
                payload_def["false_payload"],
            )
            if analysis is None:
                continue

            return {
                "vulnerable": True,
                "evidence": (
                    f"Boolean-based SQLi behavior detected on "
                    f"'{target['parameter']}': the true condition remained "
                    f"baseline-like ({analysis['true_similarity']:.2f}) while "
                    f"the false condition diverged "
                    f"({analysis['false_similarity']:.2f})."
                ),
                "tested": tested,
                "parameter": target["parameter"],
                "payload": payload_def["true_payload"],
                "technique": "boolean-based",
            }

        return None

    def _check_time_based_sqli(
        self,
        session: Any,
        target: dict[str, str],
        baseline_profile: dict[str, Any],
        tested: list[str],
        control_timings: list[float],
    ) -> dict[str, Any] | None:
        """Detect SQLi by looking for controlled response delays."""
        reference_elapsed = min(
            [value for value in control_timings if value > 0],
            default=0.0,
        )
        for payload_def in self.SQLI_TIME_PAYLOADS:
            probe_url = self._inject_payload(
                target["url"],
                payload_def["payload"],
                target["parameter"],
            )
            tested.append(
                f"{target['parameter']} @ {target['url']} "
                f"[time-based:{payload_def['name']}]"
            )
            timeout_window = max(
                self.timeout + payload_def["delay"] + 3.0,
                reference_elapsed + payload_def["delay"] + 2.0,
            )
            response, elapsed, _ = self._issue_probe(
                session,
                probe_url,
                timeout=timeout_window,
            )
            if response is None:
                continue

            delayed_by = elapsed - reference_elapsed
            response_profile = self._build_response_profile(
                response,
                response.text or "",
                (payload_def["payload"],),
            )
            similarity = self._body_similarity(
                baseline_profile["body"],
                response_profile["body"],
            )
            if (
                delayed_by >= max(self.TIME_SQLI_DELAY_THRESHOLD, payload_def["delay"] - 1.0)
                and (
                    response_profile["status_code"] == baseline_profile["status_code"]
                    or similarity >= self.BOOLEAN_SQLI_DIFFERENCE_THRESHOLD
                )
            ):
                return {
                    "vulnerable": True,
                    "evidence": (
                        f"Time-based SQLi behavior detected on "
                        f"'{target['parameter']}': payload "
                        f"'{payload_def['name']}' delayed the response by "
                        f"{delayed_by:.2f}s over the baseline probe."
                    ),
                    "tested": tested,
                    "parameter": target["parameter"],
                    "payload": payload_def["payload"],
                    "technique": "time-based",
                }

            control_timings.append(elapsed)

        return None

    def _issue_probe(
        self,
        session: Any,
        probe_url: str,
        timeout: float | None = None,
    ) -> tuple[Any | None, float, RequestException | None]:
        """Send a single probe request and capture its duration."""
        started = time.perf_counter()
        try:
            response = session.get(
                probe_url,
                timeout=timeout or (self.timeout + 3.0),
                allow_redirects=True,
            )
            return response, time.perf_counter() - started, None
        except RequestException as exc:
            return None, time.perf_counter() - started, exc

    def _analyze_xss_reflection(
        self,
        response_text: str,
        baseline_text: str,
        payload_def: dict[str, Any],
    ) -> dict[str, str] | None:
        """Return context metadata when an injected payload is reflected unsafely."""
        payload = payload_def["payload"]
        if response_text.count(payload) <= baseline_text.count(payload):
            return None

        start = 0
        while True:
            index = response_text.find(payload, start)
            if index == -1:
                return None

            context = self._classify_html_context(response_text, index, len(payload))
            if context["name"] in payload_def["contexts"]:
                return context
            start = index + len(payload)

    def _classify_html_context(
        self,
        response_text: str,
        index: int,
        payload_length: int,
    ) -> dict[str, str]:
        """Classify the HTML context around a reflected payload."""
        lower_text = response_text.lower()
        last_lt = response_text.rfind("<", 0, index)
        last_gt = response_text.rfind(">", 0, index)
        next_gt = response_text.find(">", index)

        if last_lt > last_gt and next_gt != -1:
            tag_snippet = response_text[last_lt : min(len(response_text), next_gt + 1)]
            tag_prefix = response_text[last_lt:index]
            if re.search(r"[\w:-]+\s*=\s*([\"'][^\"']*)?$", tag_prefix):
                return {
                    "name": "attribute",
                    "label": "an HTML attribute",
                    "snippet": self._compact_snippet(tag_snippet),
                }
            return {
                "name": "html_tag",
                "label": "HTML tag markup",
                "snippet": self._compact_snippet(tag_snippet),
            }

        last_script_open = lower_text.rfind("<script", 0, index)
        last_script_close = lower_text.rfind("</script", 0, index)
        if last_script_open > last_script_close:
            next_script_close = lower_text.find("</script", index + payload_length)
            if next_script_close != -1:
                snippet = response_text[
                    last_script_open : min(len(response_text), next_script_close + 9)
                ]
            else:
                snippet = response_text[
                    max(0, index - 80) : min(len(response_text), index + payload_length + 80)
                ]
            return {
                "name": "script_block",
                "label": "a script block",
                "snippet": self._compact_snippet(snippet),
            }

        snippet = response_text[
            max(0, index - 80) : min(len(response_text), index + payload_length + 80)
        ]
        return {
            "name": "html_text",
            "label": "HTML text",
            "snippet": self._compact_snippet(snippet),
        }

    def _assess_boolean_sqli(
        self,
        baseline_profile: dict[str, Any],
        true_response: Any,
        false_response: Any,
        true_payload: str,
        false_payload: str,
    ) -> dict[str, float] | None:
        """Score whether true/false SQLi probes behave like a conditional split."""
        strip_tokens = (true_payload, false_payload)
        true_profile = self._build_response_profile(
            true_response,
            true_response.text or "",
            strip_tokens,
        )
        false_profile = self._build_response_profile(
            false_response,
            false_response.text or "",
            strip_tokens,
        )
        true_similarity = self._body_similarity(
            baseline_profile["body"],
            true_profile["body"],
        )
        false_similarity = self._body_similarity(
            baseline_profile["body"],
            false_profile["body"],
        )
        true_false_similarity = self._body_similarity(
            true_profile["body"],
            false_profile["body"],
        )
        length_tolerance = max(48, int(max(1, baseline_profile["length"]) * 0.10))
        true_matches_baseline = (
            true_profile["status_code"] == baseline_profile["status_code"]
            and (
                true_similarity >= self.BOOLEAN_SQLI_MATCH_THRESHOLD
                or abs(true_profile["length"] - baseline_profile["length"]) <= length_tolerance
            )
        )
        false_diverges = (
            false_profile["status_code"] != baseline_profile["status_code"]
            or false_similarity <= self.BOOLEAN_SQLI_DIFFERENCE_THRESHOLD
            or abs(false_profile["length"] - baseline_profile["length"]) > length_tolerance
        )
        if (
            true_matches_baseline
            and false_diverges
            and true_false_similarity <= self.BOOLEAN_SQLI_CROSS_DIFF_THRESHOLD
        ):
            return {
                "true_similarity": true_similarity,
                "false_similarity": false_similarity,
            }
        return None

    def _build_response_profile(
        self,
        response: Any,
        response_text: str,
        strip_tokens: Iterable[str] = (),
    ) -> dict[str, Any]:
        """Reduce a response to a compact structure suitable for comparison."""
        normalized_body = self._normalize_response_body(response_text, strip_tokens)
        return {
            "status_code": int(getattr(response, "status_code", 0) or 0),
            "body": normalized_body,
            "length": len(normalized_body),
        }

    def _normalize_response_body(
        self,
        response_text: str,
        strip_tokens: Iterable[str] = (),
    ) -> str:
        """Normalize body content before running body similarity checks."""
        normalized = response_text or ""
        for token in strip_tokens:
            if token:
                normalized = normalized.replace(token, " ")
        normalized = re.sub(r"\s+", " ", normalized).strip().lower()
        return normalized[:6000]

    def _body_similarity(self, left: str, right: str) -> float:
        """Return a stable similarity ratio for two normalized response bodies."""
        if not left and not right:
            return 1.0
        if not left or not right:
            return 0.0
        return SequenceMatcher(a=left, b=right).ratio()

    def _compact_snippet(self, text: str, limit: int = 180) -> str:
        """Collapse whitespace and trim long evidence snippets."""
        snippet = re.sub(r"\s+", " ", text).strip()
        if len(snippet) <= limit:
            return snippet
        return f"{snippet[: limit - 3]}..."

    def _inspect_security_headers(
        self,
        headers: Any,
        url: str,
    ) -> dict[str, dict[str, str | bool]]:
        """Return the presence and values of common defensive HTTP headers."""
        scheme = urlsplit(url).scheme.lower()
        analysis: dict[str, dict[str, str | bool]] = {}
        for header in self.SECURITY_HEADERS:
            value = headers.get(header, "")
            analysis[header] = {"present": bool(value), "value": value}

        if scheme != "https":
            analysis["Strict-Transport-Security"]["present"] = False
            analysis["Strict-Transport-Security"]["value"] = ""

        return analysis

    def _inspect_cookies(self, response: Any) -> list[dict[str, Any]]:
        """Inspect cookie flags for Secure, HttpOnly, and SameSite coverage."""
        cookies: list[dict[str, Any]] = []
        for cookie in response.cookies:
            cookies.append(
                {
                    "name": cookie.name,
                    "secure": bool(cookie.secure),
                    "httponly": bool(cookie._rest.get("HttpOnly")),
                    "samesite": cookie._rest.get("SameSite", ""),
                }
            )
        return cookies

    def _build_passive_web_findings(
        self,
        security_headers: dict[str, dict[str, str | bool]],
        cookies: list[dict[str, Any]],
        headers: Any,
    ) -> list[dict[str, str]]:
        """Convert passive header and cookie observations into findings."""
        findings: list[dict[str, str]] = []
        missing_headers = {
            "Content-Security-Policy": "medium",
            "Strict-Transport-Security": "medium",
            "X-Frame-Options": "low",
            "X-Content-Type-Options": "low",
            "Referrer-Policy": "low",
            "Permissions-Policy": "low",
        }

        for header, severity in missing_headers.items():
            if not security_headers.get(header, {}).get("present"):
                findings.append(
                    {
                        "name": f"Missing {header}",
                        "severity": severity,
                        "evidence": "Header not present in the baseline response.",
                    }
                )

        if headers.get("Server"):
            findings.append(
                {
                    "name": "Server header exposed",
                    "severity": "info",
                    "evidence": headers.get("Server"),
                }
            )

        for cookie in cookies:
            if not cookie["secure"]:
                findings.append(
                    {
                        "name": f"Cookie '{cookie['name']}' missing Secure flag",
                        "severity": "medium",
                        "evidence": cookie["name"],
                    }
                )
            if not cookie["httponly"]:
                findings.append(
                    {
                        "name": f"Cookie '{cookie['name']}' missing HttpOnly flag",
                        "severity": "medium",
                        "evidence": cookie["name"],
                    }
                )
            if not cookie["samesite"]:
                findings.append(
                    {
                        "name": f"Cookie '{cookie['name']}' missing SameSite flag",
                        "severity": "low",
                        "evidence": cookie["name"],
                    }
                )

        return findings

    def _candidate_tls_ports(self, context: dict[str, Any]) -> list[int]:
        """Choose the best TLS ports to evaluate for the supplied target."""
        candidates = set(self.TLS_PORTS)
        if context["scheme"] == "https":
            candidates.add(context["port"] or 443)
        return sorted(port for port in candidates if 0 < port <= 65535)

    def _decode_certificate(self, hostname: str, port: int) -> dict[str, Any]:
        """Fetch and decode certificate fields from a TLS endpoint."""
        certificate_data = {
            "subject": "",
            "issuer": "",
            "expires_at": "",
            "days_remaining": None,
        }
        pem_certificate = ssl.get_server_certificate((hostname, port), timeout=self.timeout + 2.0)

        temp_file: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".pem",
                delete=False,
            ) as handle:
                handle.write(pem_certificate)
                temp_file = Path(handle.name)

            decoded = ssl._ssl._test_decode_cert(str(temp_file))
            certificate_data["subject"] = self._flatten_cert_name(decoded.get("subject", ()))
            certificate_data["issuer"] = self._flatten_cert_name(decoded.get("issuer", ()))
            expires_at = decoded.get("notAfter", "")
            certificate_data["expires_at"] = expires_at
            if expires_at:
                expiry = datetime.strptime(expires_at, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                certificate_data["days_remaining"] = days_remaining
        except Exception:  # pragma: no cover - platform/network dependent.
            return certificate_data
        finally:
            if temp_file and temp_file.exists():
                temp_file.unlink(missing_ok=True)

        return certificate_data

    def _detect_weak_tls_versions(self, hostname: str, port: int) -> list[str]:
        """Detect support for legacy TLS versions that should usually be disabled."""
        weak_versions: list[str] = []
        supported_versions = [
            ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
            ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ]

        for label, version in supported_versions:
            if version is None:
                continue

            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
                with socket.create_connection((hostname, port), timeout=self.timeout) as raw_socket:
                    with context.wrap_socket(raw_socket, server_hostname=hostname):
                        weak_versions.append(label)
            except Exception:  # pragma: no cover - depends on remote service.
                continue

        return weak_versions

    def _probe_service(
        self,
        sock: socket.socket,
        hostname: str,
        port: int,
    ) -> tuple[str, str | None]:
        """Run a protocol-aware banner probe for the most common services."""
        if port in {80, 81, 3000, 5000, 8000, 8080, 8081, 8888}:
            return self._probe_http(sock, hostname), "HTTP"
        if port in {443, 444, 8443, 9443}:
            return "TLS-enabled web service detected", "HTTPS"
        if port in {25, 465, 587}:
            return self._probe_smtp(sock), "SMTP"
        if port == 21:
            return self._probe_immediate_banner(sock), "FTP"
        if port == 22:
            return self._probe_immediate_banner(sock), "SSH"
        if port == 110:
            return self._probe_pop3(sock), "POP3"
        if port in {143, 993}:
            return self._probe_imap(sock), "IMAP"
        if port == 6379:
            return self._probe_redis(sock), "Redis"
        if port == 3306:
            return self._probe_immediate_banner(sock), "MySQL"
        return self._probe_immediate_banner(sock), None

    def _probe_http(self, sock: socket.socket, hostname: str) -> str:
        """Send a minimal HEAD request and return the first response line."""
        try:
            request = f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\nUser-Agent: VulnScan-Pro\r\n\r\n"
            sock.sendall(request.encode("ascii", errors="ignore"))
            data = sock.recv(512)
            return self._normalize_banner(data.decode("utf-8", errors="ignore"))
        except OSError:
            return "HTTP service responded without banner details"

    def _probe_smtp(self, sock: socket.socket) -> str:
        """Capture the SMTP banner and attempt a lightweight EHLO exchange."""
        try:
            banner = sock.recv(512).decode("utf-8", errors="ignore")
            sock.sendall(b"EHLO vulnscan.local\r\n")
            reply = sock.recv(512).decode("utf-8", errors="ignore")
            return self._normalize_banner(f"{banner} {reply}")
        except OSError:
            return "SMTP service detected"

    def _probe_pop3(self, sock: socket.socket) -> str:
        """Capture the POP3 banner and capability response when available."""
        try:
            banner = sock.recv(512).decode("utf-8", errors="ignore")
            sock.sendall(b"CAPA\r\n")
            reply = sock.recv(512).decode("utf-8", errors="ignore")
            return self._normalize_banner(f"{banner} {reply}")
        except OSError:
            return "POP3 service detected"

    def _probe_imap(self, sock: socket.socket) -> str:
        """Capture IMAP greeting and capability output when available."""
        try:
            banner = sock.recv(512).decode("utf-8", errors="ignore")
            sock.sendall(b"a1 CAPABILITY\r\n")
            reply = sock.recv(512).decode("utf-8", errors="ignore")
            return self._normalize_banner(f"{banner} {reply}")
        except OSError:
            return "IMAP service detected"

    def _probe_redis(self, sock: socket.socket) -> str:
        """Send a Redis PING probe and return the response text."""
        try:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            reply = sock.recv(256).decode("utf-8", errors="ignore")
            return self._normalize_banner(reply)
        except OSError:
            return "Redis service detected"

    def _probe_immediate_banner(self, sock: socket.socket) -> str:
        """Read any immediate bytes exposed by the remote service."""
        try:
            data = sock.recv(512)
            if not data:
                return "No banner received"
            return self._normalize_banner(data.decode("utf-8", errors="ignore"))
        except OSError:
            return "No banner received"

    def _format_dns_answers(self, record_type: str, answers: Any) -> list[str]:
        """Normalize dnspython answers into simple string values."""
        if record_type == "MX":
            return [
                f"{answer.preference} {str(answer.exchange).rstrip('.')}"
                for answer in answers
            ]
        if record_type == "TXT":
            return [
                "".join(
                    item.decode("utf-8", errors="ignore") if isinstance(item, bytes) else str(item)
                    for item in answer.strings
                )
                for answer in answers
            ]
        if record_type == "SOA":
            return [
                (
                    f"mname={getattr(answer, 'mname', '')} "
                    f"rname={getattr(answer, 'rname', '')} "
                    f"serial={getattr(answer, 'serial', '')}"
                ).strip()
                for answer in answers
            ]
        return [answer.to_text().rstrip(".") for answer in answers]

    def _score_tls_result(self, endpoints: list[dict[str, Any]]) -> str:
        """Convert TLS endpoint posture into a simple letter grade."""
        enabled_endpoints = [endpoint for endpoint in endpoints if endpoint["status"] == "enabled"]
        if not enabled_endpoints:
            return "Unavailable"

        if any(endpoint["weak_protocols"] for endpoint in enabled_endpoints):
            return "C"
        if any(
            isinstance(endpoint["days_remaining"], int) and endpoint["days_remaining"] < 15
            for endpoint in enabled_endpoints
        ):
            return "D"
        if any(endpoint["version"] not in {"TLSv1.2", "TLSv1.3"} for endpoint in enabled_endpoints):
            return "B"
        return "A"

    def _derive_tls_severity(self, endpoint: dict[str, Any]) -> str:
        """Assign a severity level to a TLS endpoint observation."""
        if endpoint["weak_protocols"]:
            return "high"
        if isinstance(endpoint["days_remaining"], int) and endpoint["days_remaining"] < 15:
            return "high"
        if endpoint["status"] == "handshake_failed":
            return "medium"
        return "low"

    def _derive_port_severity(self, port: int, status: str) -> str:
        """Assign a severity level to a port based on exposure and sensitivity."""
        if status != "open":
            return "info" if status == "closed" else "low"
        return self.RISKY_PORTS.get(port, "low")

    def _extract_sqli_errors(self, response_text: str) -> list[str]:
        """Return SQL error indicators that appear inside a response body."""
        matches: list[str] = []
        for pattern in self.SQLI_ERROR_PATTERNS:
            if pattern.search(response_text):
                matches.append(pattern.pattern)
        return matches

    def _inject_payload(self, url: str, payload: str, parameter_name: str | None = None) -> str:
        """Insert a payload into a URL's query string for a named parameter probe."""
        parsed = urlsplit(url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)

        if parameter_name:
            replaced = False
            updated_items = []
            for key, value in query_items:
                if key == parameter_name and not replaced:
                    updated_items.append((key, payload))
                    replaced = True
                else:
                    updated_items.append((key, value))
            if not replaced:
                updated_items.append((parameter_name, payload))
            query_items = updated_items
        elif query_items:
            key, _ = query_items[0]
            query_items[0] = (key, payload)
        else:
            query_items = [("scanner_probe", payload)]

        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path or "/",
                urlencode(query_items, doseq=True),
                parsed.fragment,
            )
        )

    def _normalize_url(self, target: str) -> str:
        """Convert a target into a well-formed URL string."""
        prepared = self.prepare_target(target)
        return prepared["url"]

    def _extract_hostname(self, target: str) -> str:
        """Extract the hostname or IP portion from a target string."""
        return self.prepare_target(target)["hostname"]

    def _guess_service(self, port: int) -> str:
        """Return the best-effort service name associated with a port."""
        if port in self.COMMON_PORTS:
            return self.COMMON_PORTS[port]

        try:
            return socket.getservbyport(port)
        except OSError:
            return "Unknown"

    def _cancelled(self) -> bool:
        """Return True when a stop event has been triggered by the UI."""
        return bool(self.stop_event and self.stop_event.is_set())

    def _normalize_banner(self, banner: str) -> str:
        """Collapse multiline banners into a compact single-line string."""
        compact = " ".join(banner.split())
        return compact[:180] if compact else "No banner received"

    @staticmethod
    def _flatten_cert_name(parts: Iterable[tuple[tuple[str, str], ...]]) -> str:
        """Flatten certificate subject/issuer tuples into readable text."""
        items: list[str] = []
        for part in parts:
            for key, value in part:
                items.append(f"{key}={value}")
        return ", ".join(items)

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Return True when the supplied string is an IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True

    @staticmethod
    def _is_valid_hostname(hostname: str) -> bool:
        """Validate a hostname while allowing localhost-style single labels."""
        if len(hostname) > 253:
            return False
        if hostname.endswith("."):
            hostname = hostname[:-1]
        labels = hostname.split(".")
        label_regex = re.compile(r"^[a-zA-Z0-9-]{1,63}$")
        return all(
            label
            and label_regex.match(label)
            and not label.startswith("-")
            and not label.endswith("-")
            for label in labels
        )
