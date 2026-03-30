"""Professional CustomTkinter GUI for the upgraded vulnerability scanner."""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any
from uuid import uuid4

import customtkinter as ctk

from scanner_engine import ScannerEngine
from scanner_reporting import export_scan_results
from scanner_storage import (
    append_history,
    build_scan_snapshot,
    collect_findings,
    compare_scans,
    default_settings,
    load_history,
    load_settings,
    save_settings,
)


class ResultsTable(ctk.CTkFrame):
    """Scrollable, filterable port results table with a polished card-based layout."""

    SEVERITY_COLORS = {
        "high": "#ef4444",
        "medium": "#f59e0b",
        "low": "#22c55e",
        "info": "#64748b",
    }
    STATUS_COLORS = {
        "open": "#22c55e",
        "closed": "#64748b",
        "timeout": "#f59e0b",
        "error": "#ef4444",
        "cancelled": "#94a3b8",
    }

    def __init__(self, master: Any) -> None:
        """Create the table header, scroll area, and internal view state."""
        super().__init__(master, corner_radius=24, fg_color="#101826")
        self._results: list[dict[str, Any]] = []
        self._filter_mode = "All"
        self._sort_mode = "Port"
        self._show_closed = True
        self._build_widgets()

    def _build_widgets(self) -> None:
        """Render the fixed header row and scrollable card list."""
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=18, pady=(16, 10))

        title_label = ctk.CTkLabel(
            title_frame,
            text="Port Inventory",
            font=ctk.CTkFont(family="Avenir Next", size=18, weight="bold"),
        )
        title_label.pack(side="left")

        header_frame = ctk.CTkFrame(self, fg_color="#132033", corner_radius=16)
        header_frame.pack(fill="x", padx=18, pady=(0, 10))
        headers = ("Port", "Service", "Status", "Severity", "Latency", "Banner")
        widths = (0, 1, 2, 3, 4, 5)
        for column, title in zip(widths, headers):
            header_frame.grid_columnconfigure(column, weight=1 if column else 0)
            label = ctk.CTkLabel(
                header_frame,
                text=title,
                font=ctk.CTkFont(family="Avenir Next", size=12, weight="bold"),
                text_color="#93c5fd",
                anchor="w",
            )
            label.grid(row=0, column=column, sticky="ew", padx=10, pady=10)

        self.rows_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=18,
            height=360,
        )
        self.rows_frame.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        for column in range(6):
            self.rows_frame.grid_columnconfigure(column, weight=1 if column else 0)

    def set_results(self, results: list[dict[str, Any]]) -> None:
        """Replace the table data and re-render the visible rows."""
        self._results = list(results)
        self._render_rows()

    def configure_view(self, filter_mode: str, sort_mode: str, show_closed: bool) -> None:
        """Update filter/sort controls and re-render the table."""
        self._filter_mode = filter_mode
        self._sort_mode = sort_mode
        self._show_closed = bool(show_closed)
        self._render_rows()

    def _render_rows(self) -> None:
        """Render the current filtered and sorted port list."""
        for widget in self.rows_frame.winfo_children():
            widget.destroy()

        visible_results = self._filtered_results()
        if not visible_results:
            empty_label = ctk.CTkLabel(
                self.rows_frame,
                text="No port results match the current filters yet.",
                text_color="#94a3b8",
                font=ctk.CTkFont(family="Avenir Next", size=14),
            )
            empty_label.grid(row=0, column=0, columnspan=6, pady=30)
            return

        for row_index, result in enumerate(visible_results):
            card = ctk.CTkFrame(
                self.rows_frame,
                corner_radius=16,
                fg_color="#0f172a" if row_index % 2 == 0 else "#111c2d",
            )
            card.grid(row=row_index, column=0, columnspan=6, sticky="ew", pady=5)
            for column in range(6):
                card.grid_columnconfigure(column, weight=1 if column else 0)

            status_color = self.STATUS_COLORS.get(result.get("status", "closed"), "#64748b")
            severity = result.get("severity", "info")
            severity_color = self.SEVERITY_COLORS.get(severity, "#64748b")

            values = [
                str(result.get("port", "")),
                result.get("service", ""),
                result.get("status", ""),
                severity,
                f"{result.get('latency_ms', 0)} ms",
                result.get("banner", ""),
            ]

            for column, value in enumerate(values):
                if column == 2:
                    widget = ctk.CTkLabel(
                        card,
                        text=str(value).upper(),
                        fg_color=status_color,
                        corner_radius=12,
                        text_color="#ffffff",
                        font=ctk.CTkFont(family="Avenir Next", size=11, weight="bold"),
                        padx=10,
                        pady=4,
                    )
                elif column == 3:
                    widget = ctk.CTkLabel(
                        card,
                        text=str(value).upper(),
                        fg_color=severity_color,
                        corner_radius=12,
                        text_color="#ffffff",
                        font=ctk.CTkFont(family="Avenir Next", size=11, weight="bold"),
                        padx=10,
                        pady=4,
                    )
                else:
                    widget = ctk.CTkLabel(
                        card,
                        text=str(value),
                        anchor="w",
                        justify="left",
                        wraplength=340 if column == 5 else 180,
                        font=ctk.CTkFont(family="Avenir Next", size=12),
                    )
                widget.grid(row=0, column=column, sticky="ew", padx=10, pady=10)

    def _filtered_results(self) -> list[dict[str, Any]]:
        """Return the port results after filter and sort rules are applied."""
        results = list(self._results)
        if not self._show_closed:
            results = [item for item in results if item.get("status") == "open"]

        if self._filter_mode == "Open":
            results = [item for item in results if item.get("status") == "open"]
        elif self._filter_mode == "Findings":
            results = [
                item for item in results if item.get("severity") in {"high", "medium"}
            ]
        elif self._filter_mode == "High Risk":
            results = [item for item in results if item.get("severity") == "high"]

        severity_rank = {"high": 3, "medium": 2, "low": 1, "info": 0}
        if self._sort_mode == "Service":
            results.sort(key=lambda item: (str(item.get("service", "")), int(item.get("port", 0))))
        elif self._sort_mode == "Severity":
            results.sort(
                key=lambda item: (
                    -severity_rank.get(item.get("severity", "info"), 0),
                    int(item.get("port", 0)),
                )
            )
        elif self._sort_mode == "Latency":
            results.sort(key=lambda item: float(item.get("latency_ms", 0.0)))
        else:
            results.sort(key=lambda item: int(item.get("port", 0)))

        return results


class ScannerApp(ctk.CTk):
    """Professional desktop shell that coordinates the engine, history, and exports."""

    def __init__(self) -> None:
        """Initialize state, load settings/history, and build the interface."""
        super().__init__()
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.title("VulnScan Pro")
        self.geometry("1460x940")
        self.minsize(1220, 820)
        self.configure(fg_color="#09111d")

        self.settings = load_settings()
        self.history_entries = load_history()
        self.message_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.port_results: dict[int, dict[str, Any]] = {}
        self.scan_results = self._blank_scan_results()
        self.selected_history_index: int | None = None
        self.scan_started_monotonic: float | None = None
        self._window_icon: tk.PhotoImage | None = None
        self.nav_buttons: dict[str, ctk.CTkButton] = {}

        self.target_var = tk.StringVar(value=self.settings.get("last_target", ""))
        self.port_profile_var = tk.StringVar(value=self.settings.get("port_profile", "common"))
        self.custom_ports_var = tk.StringVar(value=self.settings.get("custom_ports", ""))
        self.timeout_var = tk.StringVar(value=str(self.settings.get("timeout", 2.0)))
        self.max_workers_var = tk.StringVar(value=str(self.settings.get("max_workers", 32)))
        self.export_format_var = tk.StringVar(value=self.settings.get("export_format", "JSON"))
        self.port_filter_var = tk.StringVar(value=self.settings.get("port_filter", "All"))
        self.sort_ports_by_var = tk.StringVar(value=self.settings.get("sort_ports_by", "Port"))
        self.show_closed_var = tk.BooleanVar(value=self.settings.get("show_closed_ports", True))
        self.history_limit_var = tk.StringVar(value=str(self.settings.get("history_limit", 30)))

        self.scan_status_var = tk.StringVar(value="Idle")
        self.progress_text_var = tk.StringVar(value="Awaiting target input.")
        self.open_ports_var = tk.StringVar(value="0")
        self.findings_var = tk.StringVar(value="0")
        self.risk_var = tk.StringVar(value="INFO")
        self.tls_grade_var = tk.StringVar(value="Unavailable")
        self.duration_var = tk.StringVar(value="0.0s")

        self._apply_window_icon()
        self._build_layout()
        self._reset_results_state(clear_logs=True)
        self._refresh_history_list()
        self.after(120, self._process_message_queue)
        self.after(400, self._refresh_live_duration)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _apply_window_icon(self) -> None:
        """Create a compact custom icon for the app window."""
        try:
            image = tk.PhotoImage(width=64, height=64)
            image.put("#08111d", to=(0, 0, 64, 64))
            image.put("#10203b", to=(5, 5, 59, 59))
            image.put("#2563eb", to=(10, 10, 54, 18))
            image.put("#132033", to=(10, 18, 54, 54))
            image.put("#14b8a6", to=(14, 24, 24, 44))
            image.put("#14b8a6", to=(24, 34, 32, 44))
            image.put("#14b8a6", to=(32, 24, 42, 44))
            image.put("#f8fafc", to=(42, 18, 50, 50))
            self._window_icon = image
            self.iconphoto(False, image)
        except tk.TclError:
            self._window_icon = None

    def _build_layout(self) -> None:
        """Create the sidebar, hero area, control strip, metrics, and tabs."""
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_area()

    def _build_sidebar(self) -> None:
        """Render the branded sidebar and view navigation."""
        sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color="#0b1220")
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(10, weight=1)

        badge = ctk.CTkLabel(
            sidebar,
            text="AUTHORIZED LAB USE",
            fg_color="#132033",
            corner_radius=12,
            text_color="#93c5fd",
            font=ctk.CTkFont(family="Avenir Next", size=11, weight="bold"),
            padx=12,
            pady=6,
        )
        badge.grid(row=0, column=0, padx=20, pady=(28, 12), sticky="w")

        title = ctk.CTkLabel(
            sidebar,
            text="VulnScan Pro",
            font=ctk.CTkFont(family="Avenir Next", size=28, weight="bold"),
        )
        title.grid(row=1, column=0, padx=20, sticky="w")

        subtitle = ctk.CTkLabel(
            sidebar,
            text="Threaded desktop recon, web posture, TLS, history, and polished reporting.",
            justify="left",
            wraplength=210,
            text_color="#94a3b8",
            font=ctk.CTkFont(family="Avenir Next", size=13),
        )
        subtitle.grid(row=2, column=0, padx=20, pady=(8, 20), sticky="w")

        nav_items = [
            ("Dashboard", "Overview"),
            ("Port Scanner", "Ports"),
            ("Web Vulns", "Web"),
            ("Intel", "Intel"),
            ("History", "History"),
            ("Settings", "Settings"),
        ]
        for row_index, (label, tab_name) in enumerate(nav_items, start=3):
            button = ctk.CTkButton(
                sidebar,
                text=label,
                anchor="w",
                corner_radius=16,
                height=42,
                fg_color="#101826",
                hover_color="#132033",
                command=lambda tab=tab_name: self._set_active_tab(tab),
            )
            button.grid(row=row_index, column=0, padx=16, pady=6, sticky="ew")
            self.nav_buttons[tab_name] = button

        footer = ctk.CTkLabel(
            sidebar,
            text="Stop scans safely, filter high-risk ports, compare history, and export professional reports.",
            justify="left",
            wraplength=210,
            text_color="#64748b",
            font=ctk.CTkFont(family="Avenir Next", size=12),
        )
        footer.grid(row=11, column=0, padx=20, pady=24, sticky="sw")

    def _build_main_area(self) -> None:
        """Render the hero panel, controls, summary cards, and all tab content."""
        container = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        container.grid(row=0, column=1, sticky="nsew", padx=22, pady=22)
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(3, weight=1)

        self._build_hero(container)
        self._build_controls(container)
        self._build_metrics(container)
        self._build_tabs(container)

    def _build_hero(self, master: ctk.CTkFrame) -> None:
        """Build the top hero panel with status and action controls."""
        hero = ctk.CTkFrame(master, corner_radius=28, fg_color="#0f172a")
        hero.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        hero.grid_columnconfigure(0, weight=1)

        copy_frame = ctk.CTkFrame(hero, fg_color="transparent")
        copy_frame.grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 10))

        headline = ctk.CTkLabel(
            copy_frame,
            text="Command Deck",
            font=ctk.CTkFont(family="Avenir Next", size=32, weight="bold"),
        )
        headline.pack(anchor="w")

        description = ctk.CTkLabel(
            copy_frame,
            text="Professional scan orchestration with live telemetry, smarter checks, and export-ready results.",
            text_color="#94a3b8",
            font=ctk.CTkFont(family="Avenir Next", size=14),
        )
        description.pack(anchor="w", pady=(4, 0))

        status_frame = ctk.CTkFrame(hero, fg_color="transparent")
        status_frame.grid(row=0, column=1, sticky="e", padx=(0, 22), pady=(20, 10))

        self.scan_status_badge = ctk.CTkLabel(
            status_frame,
            textvariable=self.scan_status_var,
            fg_color="#132033",
            corner_radius=14,
            text_color="#93c5fd",
            font=ctk.CTkFont(family="Avenir Next", size=12, weight="bold"),
            padx=14,
            pady=8,
        )
        self.scan_status_badge.pack(anchor="e")

        progress_frame = ctk.CTkFrame(hero, fg_color="transparent")
        progress_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=22, pady=(0, 20))
        progress_frame.grid_columnconfigure(0, weight=1)

        progress_label = ctk.CTkLabel(
            progress_frame,
            textvariable=self.progress_text_var,
            text_color="#cbd5e1",
            font=ctk.CTkFont(family="Avenir Next", size=13),
            anchor="w",
        )
        progress_label.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.progress_bar = ctk.CTkProgressBar(
            progress_frame,
            height=14,
            fg_color="#132033",
            progress_color="#14b8a6",
        )
        self.progress_bar.grid(row=1, column=0, sticky="ew")
        self.progress_bar.set(0.0)

    def _build_controls(self, master: ctk.CTkFrame) -> None:
        """Build the scan control strip with runtime configuration inputs."""
        controls = ctk.CTkFrame(master, corner_radius=24, fg_color="#101826")
        controls.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        for column in range(9):
            controls.grid_columnconfigure(column, weight=1 if column < 6 else 0)

        labels = [
            "Target",
            "Profile",
            "Custom Ports",
            "Timeout",
            "Workers",
            "Export",
        ]
        for index, label_text in enumerate(labels):
            label = ctk.CTkLabel(
                controls,
                text=label_text,
                text_color="#94a3b8",
                font=ctk.CTkFont(family="Avenir Next", size=11, weight="bold"),
            )
            label.grid(row=0, column=index, padx=12, pady=(16, 6), sticky="w")

        self.target_entry = ctk.CTkEntry(
            controls,
            textvariable=self.target_var,
            placeholder_text="example.com, 192.168.1.10, or https://target.local/app",
            height=42,
        )
        self.target_entry.grid(row=1, column=0, padx=12, pady=(0, 16), sticky="ew")

        self.port_profile_menu = ctk.CTkOptionMenu(
            controls,
            variable=self.port_profile_var,
            values=["common", "top100", "web", "database", "mail", "remote"],
            height=42,
        )
        self.port_profile_menu.grid(row=1, column=1, padx=12, pady=(0, 16), sticky="ew")

        self.custom_ports_entry = ctk.CTkEntry(
            controls,
            textvariable=self.custom_ports_var,
            placeholder_text="optional: 1-1024,8080,8443",
            height=42,
        )
        self.custom_ports_entry.grid(row=1, column=2, padx=12, pady=(0, 16), sticky="ew")

        self.timeout_entry = ctk.CTkEntry(
            controls,
            textvariable=self.timeout_var,
            width=90,
            height=42,
        )
        self.timeout_entry.grid(row=1, column=3, padx=12, pady=(0, 16), sticky="ew")

        self.max_workers_entry = ctk.CTkEntry(
            controls,
            textvariable=self.max_workers_var,
            width=90,
            height=42,
        )
        self.max_workers_entry.grid(row=1, column=4, padx=12, pady=(0, 16), sticky="ew")

        self.export_menu = ctk.CTkOptionMenu(
            controls,
            variable=self.export_format_var,
            values=["JSON", "CSV", "HTML", "PDF"],
            height=42,
        )
        self.export_menu.grid(row=1, column=5, padx=12, pady=(0, 16), sticky="ew")

        self.start_button = ctk.CTkButton(
            controls,
            text="Start Scan",
            width=128,
            height=42,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            command=self.start_scan,
        )
        self.start_button.grid(row=1, column=6, padx=(8, 8), pady=(0, 16))

        self.stop_button = ctk.CTkButton(
            controls,
            text="Stop",
            width=100,
            height=42,
            fg_color="#ef4444",
            hover_color="#dc2626",
            state="disabled",
            command=self.stop_scan,
        )
        self.stop_button.grid(row=1, column=7, padx=(0, 8), pady=(0, 16))

        self.export_button = ctk.CTkButton(
            controls,
            text="Export",
            width=100,
            height=42,
            fg_color="#14b8a6",
            hover_color="#0f766e",
            state="disabled",
            command=self.export_results,
        )
        self.export_button.grid(row=1, column=8, padx=(0, 12), pady=(0, 16))

    def _build_metrics(self, master: ctk.CTkFrame) -> None:
        """Build the summary card row for scan KPIs."""
        metrics = ctk.CTkFrame(master, fg_color="transparent")
        metrics.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        for column in range(5):
            metrics.grid_columnconfigure(column, weight=1)

        self._create_metric_card(metrics, 0, "Open Ports", self.open_ports_var, "#22c55e")
        self._create_metric_card(metrics, 1, "Findings", self.findings_var, "#f59e0b")
        self._create_metric_card(metrics, 2, "Risk", self.risk_var, "#ef4444")
        self._create_metric_card(metrics, 3, "TLS Grade", self.tls_grade_var, "#2563eb")
        self._create_metric_card(metrics, 4, "Duration", self.duration_var, "#14b8a6")

    def _create_metric_card(
        self,
        master: ctk.CTkFrame,
        column: int,
        title: str,
        variable: tk.StringVar,
        accent: str,
    ) -> None:
        """Create a single metric card with a colored accent strip."""
        card = ctk.CTkFrame(master, corner_radius=22, fg_color="#101826")
        card.grid(row=0, column=column, sticky="ew", padx=6)

        accent_bar = ctk.CTkFrame(card, height=6, corner_radius=22, fg_color=accent)
        accent_bar.pack(fill="x", padx=12, pady=(12, 10))

        label = ctk.CTkLabel(
            card,
            text=title,
            text_color="#94a3b8",
            font=ctk.CTkFont(family="Avenir Next", size=11, weight="bold"),
        )
        label.pack(anchor="w", padx=14)

        value = ctk.CTkLabel(
            card,
            textvariable=variable,
            font=ctk.CTkFont(family="Avenir Next", size=26, weight="bold"),
        )
        value.pack(anchor="w", padx=14, pady=(6, 14))

    def _build_tabs(self, master: ctk.CTkFrame) -> None:
        """Build all main workspace tabs and their widgets."""
        self.tabview = ctk.CTkTabview(
            master,
            corner_radius=24,
            fg_color="#101826",
            segmented_button_selected_color="#2563eb",
            segmented_button_selected_hover_color="#1d4ed8",
        )
        self.tabview.grid(row=3, column=0, sticky="nsew")
        for tab_name in ["Overview", "Ports", "Web", "Intel", "History", "Settings"]:
            self.tabview.add(tab_name)

        self._build_overview_tab()
        self._build_ports_tab()
        self._build_web_tab()
        self._build_intel_tab()
        self._build_history_tab()
        self._build_settings_tab()
        self._set_active_tab("Overview")

    def _build_overview_tab(self) -> None:
        """Build the overview tab with live log, summary, and current findings."""
        tab = self.tabview.tab("Overview")
        tab.grid_columnconfigure(0, weight=2)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        log_frame, self.log_box = self._create_textbox_card(tab, "Live Activity")
        log_frame.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 10), pady=16)

        summary_frame, self.summary_box = self._create_textbox_card(tab, "Current Summary")
        summary_frame.grid(row=0, column=1, sticky="nsew", pady=(16, 10))

        findings_frame, self.findings_box = self._create_textbox_card(tab, "Current Findings")
        findings_frame.grid(row=1, column=1, sticky="nsew", pady=(10, 16))

    def _build_ports_tab(self) -> None:
        """Build the ports tab with filters, sort controls, and results table."""
        tab = self.tabview.tab("Ports")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        toolbar = ctk.CTkFrame(tab, corner_radius=20, fg_color="#0f172a")
        toolbar.grid(row=0, column=0, sticky="ew", pady=16)

        filter_label = ctk.CTkLabel(
            toolbar,
            text="Filter",
            text_color="#94a3b8",
            font=ctk.CTkFont(family="Avenir Next", size=11, weight="bold"),
        )
        filter_label.pack(side="left", padx=(16, 8), pady=12)

        self.port_filter_menu = ctk.CTkSegmentedButton(
            toolbar,
            variable=self.port_filter_var,
            values=["All", "Open", "Findings", "High Risk"],
            command=lambda _value: self._refresh_port_table(),
        )
        self.port_filter_menu.pack(side="left", padx=(0, 16), pady=12)

        sort_label = ctk.CTkLabel(
            toolbar,
            text="Sort",
            text_color="#94a3b8",
            font=ctk.CTkFont(family="Avenir Next", size=11, weight="bold"),
        )
        sort_label.pack(side="left", padx=(0, 8))

        self.sort_menu = ctk.CTkOptionMenu(
            toolbar,
            variable=self.sort_ports_by_var,
            values=["Port", "Service", "Severity", "Latency"],
            command=lambda _value: self._refresh_port_table(),
            width=130,
        )
        self.sort_menu.pack(side="left", padx=(0, 16))

        self.show_closed_switch = ctk.CTkSwitch(
            toolbar,
            text="Show closed",
            variable=self.show_closed_var,
            command=self._refresh_port_table,
        )
        self.show_closed_switch.pack(side="right", padx=16)

        self.results_table = ResultsTable(tab)
        self.results_table.grid(row=1, column=0, sticky="nsew", pady=(0, 16))

    def _build_web_tab(self) -> None:
        """Build the web analysis tab with findings, headers, and form details."""
        tab = self.tabview.tab("Web")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        findings_frame, self.web_findings_box = self._create_textbox_card(tab, "Web Findings")
        findings_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(16, 10))

        headers_frame, self.web_headers_box = self._create_textbox_card(tab, "Headers & Cookies")
        headers_frame.grid(row=0, column=1, sticky="nsew", pady=(16, 10))

        forms_frame, self.web_forms_box = self._create_textbox_card(tab, "Forms, Redirects & Parameters")
        forms_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(10, 16))

    def _build_intel_tab(self) -> None:
        """Build the intelligence tab with DNS and TLS detail panes."""
        tab = self.tabview.tab("Intel")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        dns_frame, self.dns_box = self._create_textbox_card(tab, "DNS Intelligence")
        dns_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=16)

        tls_frame, self.tls_box = self._create_textbox_card(tab, "TLS Posture")
        tls_frame.grid(row=0, column=1, sticky="nsew", pady=16)

    def _build_history_tab(self) -> None:
        """Build the history tab with previous scans and comparison output."""
        tab = self.tabview.tab("History")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        history_list_frame = ctk.CTkFrame(tab, corner_radius=24, fg_color="#0f172a")
        history_list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=16)
        history_list_frame.grid_rowconfigure(1, weight=1)
        history_list_frame.grid_columnconfigure(0, weight=1)

        history_title = ctk.CTkLabel(
            history_list_frame,
            text="Recent Scan History",
            font=ctk.CTkFont(family="Avenir Next", size=18, weight="bold"),
        )
        history_title.grid(row=0, column=0, padx=16, pady=(14, 10), sticky="w")

        self.history_scroll = ctk.CTkScrollableFrame(history_list_frame, fg_color="transparent")
        self.history_scroll.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))

        right_panel = ctk.CTkFrame(tab, corner_radius=24, fg_color="#0f172a")
        right_panel.grid(row=0, column=1, sticky="nsew", pady=16)
        right_panel.grid_columnconfigure(0, weight=1)
        right_panel.grid_rowconfigure(2, weight=1)

        action_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        action_frame.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 10))

        load_button = ctk.CTkButton(
            action_frame,
            text="Load Selected Snapshot",
            command=self.load_selected_history,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
        )
        load_button.pack(side="left")

        refresh_button = ctk.CTkButton(
            action_frame,
            text="Refresh History",
            command=self._refresh_history_list,
            fg_color="#132033",
            hover_color="#1d2f4d",
        )
        refresh_button.pack(side="left", padx=10)

        details_frame, self.history_details_box = self._create_textbox_card(
            right_panel,
            "Selected Snapshot",
        )
        details_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 10))

        comparison_frame, self.history_compare_box = self._create_textbox_card(
            right_panel,
            "Comparison Against Current View",
        )
        comparison_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=(10, 16))

    def _build_settings_tab(self) -> None:
        """Build the settings tab for persistence and runtime defaults."""
        tab = self.tabview.tab("Settings")
        tab.grid_columnconfigure(0, weight=1)
        settings_card = ctk.CTkFrame(tab, corner_radius=24, fg_color="#0f172a")
        settings_card.grid(row=0, column=0, sticky="nsew", pady=16)
        for column in range(3):
            settings_card.grid_columnconfigure(column, weight=1)

        rows = [
            ("Default Port Profile", self.port_profile_var),
            ("Custom Ports", self.custom_ports_var),
            ("Timeout Seconds", self.timeout_var),
            ("Worker Threads", self.max_workers_var),
            ("Default Export Format", self.export_format_var),
            ("History Limit", self.history_limit_var),
        ]
        for index, (label_text, variable) in enumerate(rows):
            row = index // 3
            column = index % 3
            label = ctk.CTkLabel(
                settings_card,
                text=label_text,
                text_color="#94a3b8",
                font=ctk.CTkFont(family="Avenir Next", size=11, weight="bold"),
            )
            label.grid(row=row * 2, column=column, padx=16, pady=(18, 6), sticky="w")

            if label_text == "Default Port Profile":
                widget = ctk.CTkOptionMenu(
                    settings_card,
                    variable=self.port_profile_var,
                    values=["common", "top100", "web", "database", "mail", "remote"],
                    height=42,
                )
            elif label_text == "Default Export Format":
                widget = ctk.CTkOptionMenu(
                    settings_card,
                    variable=self.export_format_var,
                    values=["JSON", "CSV", "HTML", "PDF"],
                    height=42,
                )
            else:
                widget = ctk.CTkEntry(
                    settings_card,
                    textvariable=variable,
                    height=42,
                )
            widget.grid(row=row * 2 + 1, column=column, padx=16, pady=(0, 14), sticky="ew")

        save_button = ctk.CTkButton(
            settings_card,
            text="Save Settings",
            fg_color="#14b8a6",
            hover_color="#0f766e",
            command=self.save_current_settings,
        )
        save_button.grid(row=4, column=0, padx=16, pady=(6, 18), sticky="w")

        reset_button = ctk.CTkButton(
            settings_card,
            text="Reset Defaults",
            fg_color="#132033",
            hover_color="#1d2f4d",
            command=self.reset_settings_to_defaults,
        )
        reset_button.grid(row=4, column=1, padx=16, pady=(6, 18), sticky="w")

    def _create_textbox_card(
        self,
        master: ctk.CTkBaseClass,
        title: str,
    ) -> tuple[ctk.CTkFrame, ctk.CTkTextbox]:
        """Create a titled card with a readonly textbox."""
        frame = ctk.CTkFrame(master, corner_radius=24, fg_color="#0f172a")
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            frame,
            text=title,
            font=ctk.CTkFont(family="Avenir Next", size=18, weight="bold"),
        )
        title_label.grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        textbox = ctk.CTkTextbox(
            frame,
            fg_color="#101826",
            corner_radius=18,
            wrap="word",
            border_width=0,
        )
        textbox.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        textbox.configure(state="disabled")
        return frame, textbox

    def _set_active_tab(self, tab_name: str) -> None:
        """Switch to a tab and highlight the matching sidebar button."""
        self.tabview.set(tab_name)
        for mapped_name, button in self.nav_buttons.items():
            if mapped_name == tab_name:
                button.configure(fg_color="#2563eb")
            else:
                button.configure(fg_color="#101826")

    def _blank_scan_results(self) -> dict[str, Any]:
        """Return a fresh scan result payload."""
        return {
            "scan_id": "",
            "target_input": "",
            "target": "",
            "url": "",
            "status": "idle",
            "started_at": "",
            "finished_at": "",
            "duration_seconds": 0.0,
            "ports_requested": [],
            "ports": [],
            "dns": {},
            "web": {},
            "tls": {},
        }

    def _reset_results_state(self, clear_logs: bool = False) -> None:
        """Reset in-memory scan results and refresh the visible UI."""
        self.scan_results = self._blank_scan_results()
        self.port_results = {}
        self.scan_started_monotonic = None
        self.progress_bar.set(0.0)
        self.scan_status_var.set("Idle")
        self.progress_text_var.set("Awaiting target input.")
        self._refresh_all_views()
        if clear_logs:
            self._set_textbox_content(self.log_box, "")

    def _gather_runtime_settings(self) -> dict[str, Any]:
        """Validate and collect runtime settings from the current controls."""
        target = self.target_var.get().strip()
        if not target:
            raise ValueError("Enter a target before starting a scan.")

        timeout = float(self.timeout_var.get().strip() or "2.0")
        if timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")

        max_workers = int(self.max_workers_var.get().strip() or "32")
        if max_workers <= 0:
            raise ValueError("Worker threads must be greater than zero.")

        history_limit = int(self.history_limit_var.get().strip() or "30")
        if history_limit <= 0:
            raise ValueError("History limit must be greater than zero.")

        port_spec = self.custom_ports_var.get().strip() or self.port_profile_var.get().strip()
        ports = ScannerEngine.parse_ports(port_spec)
        prepared = ScannerEngine.prepare_target(target)

        return {
            "target": target,
            "prepared": prepared,
            "ports": ports,
            "timeout": timeout,
            "max_workers": max_workers,
            "history_limit": history_limit,
        }

    def start_scan(self) -> None:
        """Launch a new background scan after validating current settings."""
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan Running", "A scan is already in progress.")
            return

        try:
            runtime = self._gather_runtime_settings()
        except ValueError as exc:
            messagebox.showerror("Invalid Scan Settings", str(exc))
            return

        self.stop_event = threading.Event()
        self.port_results = {}
        self.scan_started_monotonic = time.perf_counter()
        self.scan_results = self._blank_scan_results()
        self.scan_results.update(
            {
                "scan_id": uuid4().hex[:10],
                "target_input": runtime["target"],
                "target": runtime["prepared"]["hostname"],
                "url": runtime["prepared"]["url"],
                "status": "running",
                "started_at": datetime.now().isoformat(timespec="seconds"),
                "ports_requested": runtime["ports"],
            }
        )

        self._set_textbox_content(self.log_box, "")
        self._append_log(
            f"Scan queued for {runtime['prepared']['hostname']} with {len(runtime['ports'])} ports."
        )
        self._append_log(
            f"Profile: {self.port_profile_var.get()} | Timeout: {runtime['timeout']}s | "
            f"Workers: {runtime['max_workers']}"
        )
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.export_button.configure(state="disabled")
        self.scan_status_var.set("Scanning")
        self.progress_text_var.set("Initializing engine tasks...")
        self.progress_bar.set(0.0)
        self._refresh_all_views()

        self.scan_thread = threading.Thread(
            target=self._run_scan_thread,
            args=(runtime["target"], runtime["ports"], runtime["timeout"], runtime["max_workers"]),
            daemon=True,
        )
        self.scan_thread.start()

    def stop_scan(self) -> None:
        """Signal the engine to cancel the active scan."""
        if not self.scan_thread or not self.scan_thread.is_alive():
            return
        self.stop_event.set()
        self.stop_button.configure(state="disabled")
        self.scan_status_var.set("Cancelling")
        self.progress_text_var.set("Stopping active tasks...")
        self._append_log("Cancellation requested by user.")

    def _run_scan_thread(
        self,
        target: str,
        ports: list[int],
        timeout: float,
        max_workers: int,
    ) -> None:
        """Execute the engine in a worker thread and stream events back to the UI."""
        engine = ScannerEngine(
            timeout=timeout,
            max_workers=max_workers,
            stop_event=self.stop_event,
        )
        try:
            for event in engine.run_full_scan(target, ports):
                self.message_queue.put(event)
        except Exception as exc:  # pragma: no cover - defensive.
            self.message_queue.put({"type": "error", "message": f"Unhandled scanner error: {exc}"})
        finally:
            self.message_queue.put({"type": "thread_done"})

    def _process_message_queue(self) -> None:
        """Process queued events from the worker thread on the Tk main loop."""
        while True:
            try:
                event = self.message_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_scan_event(event)
        self.after(120, self._process_message_queue)

    def _handle_scan_event(self, event: dict[str, Any]) -> None:
        """Route a scanner event to the correct UI and state update path."""
        event_type = event.get("type")
        completed = int(event.get("completed", 0))
        total = int(event.get("total", 0))
        if total:
            self.progress_bar.set(completed / total)
            self.progress_text_var.set(f"Progress: {completed}/{total} tasks completed.")

        if event_type == "status":
            self._append_log(event.get("message", "Status update received."))
            return

        if event_type == "port":
            result = event["result"]
            self.port_results[int(result["port"])] = result
            self.scan_results["ports"] = [
                self.port_results[key] for key in sorted(self.port_results)
            ]
            if result.get("status") == "open":
                self._append_log(
                    f"Open port {result['port']} | {result['service']} | {result['banner']}"
                )
            elif result.get("status") in {"error", "timeout"}:
                self._append_log(
                    f"Port {result['port']} returned {result['status']} ({result.get('banner', '')})"
                )
            self._refresh_all_views()
            return

        if event_type == "dns":
            self.scan_results["dns"] = event["result"]
            self._append_log("DNS intelligence updated.")
            self._refresh_all_views()
            return

        if event_type == "web":
            self.scan_results["web"] = event["result"]
            if event["result"].get("status") == "error":
                self._append_log(f"Web checks failed: {event['result'].get('message', 'Unknown error')}")
            else:
                self._append_log("Web posture analysis updated.")
            self._refresh_all_views()
            return

        if event_type == "tls":
            self.scan_results["tls"] = event["result"]
            self._append_log("TLS posture analysis updated.")
            self._refresh_all_views()
            return

        if event_type == "error":
            self._append_log(event.get("message", "An unknown error occurred."))
            return

        if event_type == "cancelled":
            self._finalize_scan("cancelled", event.get("message", "Scan cancelled."))
            return

        if event_type == "complete":
            self._finalize_scan("completed", event.get("message", "Scan complete."))
            return

        if event_type == "thread_done":
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")

    def _finalize_scan(self, status: str, message: str) -> None:
        """Complete the scan lifecycle, save history, and refresh the dashboard."""
        self.scan_results["status"] = status
        self.scan_results["finished_at"] = datetime.now().isoformat(timespec="seconds")
        if self.scan_started_monotonic is not None:
            self.scan_results["duration_seconds"] = round(
                time.perf_counter() - self.scan_started_monotonic,
                2,
            )
        self.scan_status_var.set(status.title())
        self.progress_bar.set(1.0 if status == "completed" else self.progress_bar.get())
        self.progress_text_var.set("Scan complete." if status == "completed" else "Scan cancelled.")
        self.export_button.configure(
            state="normal" if self.scan_results.get("target") else "disabled"
        )
        self._append_log(message)
        self._refresh_all_views()

        history_limit = int(self.history_limit_var.get().strip() or "30")
        self.history_entries = append_history(self.scan_results, limit=history_limit)
        self._refresh_history_list()

    def export_results(self) -> None:
        """Export the currently loaded scan results to the chosen report format."""
        if not self.scan_results.get("target"):
            messagebox.showinfo("No Results", "Run a scan or load a history snapshot first.")
            return

        export_format = self.export_format_var.get().strip().upper()
        extension = {
            "JSON": ".json",
            "CSV": ".csv",
            "HTML": ".html",
            "PDF": ".pdf",
        }[export_format]
        default_name = self._build_export_filename(extension)
        output_path = filedialog.asksaveasfilename(
            title=f"Export {export_format} Report",
            defaultextension=extension,
            initialfile=default_name,
            initialdir=str(Path.home()),
            filetypes=[(f"{export_format} files", f"*{extension}"), ("All files", "*.*")],
        )
        if not output_path:
            return

        try:
            exported = export_scan_results(
                self.scan_results,
                Path(output_path),
                export_format,
            )
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))
            self._append_log(f"Export failed: {exc}")
            return

        self._append_log(f"Exported {export_format} report to {exported}.")
        messagebox.showinfo("Export Complete", f"Saved report to:\n{exported}")

    def save_current_settings(self) -> None:
        """Persist the current control state to the settings file."""
        try:
            settings = self._collect_settings_payload()
        except ValueError as exc:
            messagebox.showerror("Invalid Settings", str(exc))
            return

        save_settings(settings)
        self.settings = settings
        self._append_log("Settings saved.")
        messagebox.showinfo("Settings Saved", "Your scanner preferences were updated.")

    def reset_settings_to_defaults(self) -> None:
        """Reset form controls back to the application's default settings."""
        defaults = default_settings()
        self.port_profile_var.set(defaults["port_profile"])
        self.custom_ports_var.set(defaults["custom_ports"])
        self.timeout_var.set(str(defaults["timeout"]))
        self.max_workers_var.set(str(defaults["max_workers"]))
        self.export_format_var.set(defaults["export_format"])
        self.history_limit_var.set(str(defaults["history_limit"]))
        self.port_filter_var.set(defaults["port_filter"])
        self.sort_ports_by_var.set(defaults["sort_ports_by"])
        self.show_closed_var.set(defaults["show_closed_ports"])
        self._refresh_port_table()
        self._append_log("Settings reset to defaults.")

    def load_selected_history(self) -> None:
        """Load the selected history snapshot into the main dashboard view."""
        if self.selected_history_index is None:
            messagebox.showinfo("No Selection", "Select a history entry first.")
            return

        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan Running", "Stop the active scan before loading history.")
            return

        entry = self.history_entries[self.selected_history_index]
        self.scan_results = deepcopy(entry.get("results", self._blank_scan_results()))
        self.port_results = {
            int(result["port"]): result for result in self.scan_results.get("ports", [])
        }
        self.scan_status_var.set("History Loaded")
        self.progress_text_var.set("Viewing a saved scan snapshot.")
        self.export_button.configure(state="normal")
        self._refresh_all_views()
        self._append_log(f"Loaded history snapshot for {entry.get('target', 'unknown target')}.")

    def _refresh_history_list(self) -> None:
        """Rebuild the scrollable history list from persisted entries."""
        self.history_entries = load_history()
        for widget in self.history_scroll.winfo_children():
            widget.destroy()

        if not self.history_entries:
            label = ctk.CTkLabel(
                self.history_scroll,
                text="No scan history saved yet.",
                text_color="#94a3b8",
            )
            label.pack(anchor="w", pady=20, padx=8)
            self._set_textbox_content(self.history_details_box, "No history entry selected.")
            self._set_textbox_content(self.history_compare_box, "Run a scan to generate history.")
            return

        for index, entry in enumerate(self.history_entries):
            snapshot = entry.get("snapshot", {})
            card = ctk.CTkFrame(self.history_scroll, corner_radius=18, fg_color="#101826")
            card.pack(fill="x", pady=6, padx=4)

            target_label = ctk.CTkLabel(
                card,
                text=entry.get("target", "Unknown target"),
                font=ctk.CTkFont(family="Avenir Next", size=15, weight="bold"),
            )
            target_label.pack(anchor="w", padx=14, pady=(12, 2))

            meta_label = ctk.CTkLabel(
                card,
                text=(
                    f"{entry.get('finished_at', entry.get('started_at', ''))} | "
                    f"{entry.get('status', '').title()} | "
                    f"Open: {snapshot.get('open_ports_count', 0)} | "
                    f"Findings: {snapshot.get('findings_count', 0)}"
                ),
                text_color="#94a3b8",
                font=ctk.CTkFont(family="Avenir Next", size=12),
            )
            meta_label.pack(anchor="w", padx=14, pady=(0, 8))

            select_button = ctk.CTkButton(
                card,
                text="Select",
                height=32,
                fg_color="#132033",
                hover_color="#1d2f4d",
                command=lambda idx=index: self._select_history_entry(idx),
            )
            select_button.pack(anchor="e", padx=12, pady=(0, 12))

        if self.selected_history_index is None:
            self.selected_history_index = 0
        self._select_history_entry(self.selected_history_index)

    def _select_history_entry(self, index: int) -> None:
        """Select a history entry and render its details and comparison panel."""
        self.selected_history_index = index
        entry = self.history_entries[index]
        snapshot = entry.get("snapshot", {})
        results = entry.get("results", {})
        details = [
            f"Target: {entry.get('target', '')}",
            f"Status: {entry.get('status', '').title()}",
            f"Started: {entry.get('started_at', '')}",
            f"Finished: {entry.get('finished_at', '')}",
            "",
            f"Open ports: {snapshot.get('open_ports_count', 0)}",
            f"Port list: {', '.join(map(str, snapshot.get('open_ports', []))) or 'None'}",
            f"Services: {', '.join(snapshot.get('services', [])) or 'None'}",
            f"Findings: {snapshot.get('findings_count', 0)}",
            f"Highest severity: {snapshot.get('highest_severity', 'info').upper()}",
            f"TLS grade: {snapshot.get('tls_grade', 'Unavailable')}",
        ]
        self._set_textbox_content(self.history_details_box, "\n".join(details))

        if self.scan_results.get("target"):
            delta = compare_scans(self.scan_results, results)
            comparison_lines = [
                f"New open ports: {', '.join(map(str, delta['new_open_ports'])) or 'None'}",
                f"Closed since selected scan: {', '.join(map(str, delta['closed_ports'])) or 'None'}",
                f"Persistent ports: {', '.join(map(str, delta['persistent_ports'])) or 'None'}",
                "",
                f"New findings: {', '.join(delta['new_findings']) or 'None'}",
                f"Resolved findings: {', '.join(delta['resolved_findings']) or 'None'}",
            ]
        else:
            comparison_lines = [
                "Load or run a current scan to compare against this snapshot.",
            ]
        self._set_textbox_content(self.history_compare_box, "\n".join(comparison_lines))

    def _refresh_all_views(self) -> None:
        """Refresh cards, text panes, and tables from the current scan result."""
        snapshot = build_scan_snapshot(self.scan_results)
        findings = collect_findings(self.scan_results)

        self.open_ports_var.set(str(snapshot.get("open_ports_count", 0)))
        self.findings_var.set(str(snapshot.get("findings_count", 0)))
        self.risk_var.set(snapshot.get("highest_severity", "info").upper())
        self.tls_grade_var.set(snapshot.get("tls_grade", "Unavailable"))

        duration = self.scan_results.get("duration_seconds", 0.0)
        self.duration_var.set(f"{duration:.1f}s")

        self.results_table.set_results(self.scan_results.get("ports", []))
        self._refresh_port_table()
        self._set_textbox_content(self.summary_box, self._format_summary_text(snapshot))
        self._set_textbox_content(self.findings_box, self._format_findings_text(findings))
        self._set_textbox_content(self.web_findings_box, self._format_web_findings_text())
        self._set_textbox_content(self.web_headers_box, self._format_web_headers_text())
        self._set_textbox_content(self.web_forms_box, self._format_web_forms_text())
        self._set_textbox_content(self.dns_box, self._format_dns_text())
        self._set_textbox_content(self.tls_box, self._format_tls_text())
        if self.selected_history_index is not None and self.history_entries:
            self._select_history_entry(self.selected_history_index)

    def _refresh_port_table(self) -> None:
        """Apply current filter controls to the port results table."""
        self.results_table.configure_view(
            self.port_filter_var.get(),
            self.sort_ports_by_var.get(),
            self.show_closed_var.get(),
        )

    def _refresh_live_duration(self) -> None:
        """Update the duration card while a scan is running."""
        if self.scan_results.get("status") == "running" and self.scan_started_monotonic is not None:
            elapsed = time.perf_counter() - self.scan_started_monotonic
            self.duration_var.set(f"{elapsed:.1f}s")
        self.after(400, self._refresh_live_duration)

    def _format_summary_text(self, snapshot: dict[str, Any]) -> str:
        """Create the overview summary text block."""
        open_ports = ", ".join(map(str, snapshot.get("open_ports", []))) or "None"
        services = ", ".join(snapshot.get("services", [])) or "None"
        return "\n".join(
            [
                f"Target: {self.scan_results.get('target', 'N/A')}",
                f"URL: {self.scan_results.get('url', 'N/A')}",
                f"Status: {self.scan_results.get('status', 'idle').title()}",
                f"Started: {self.scan_results.get('started_at', 'N/A')}",
                f"Finished: {self.scan_results.get('finished_at', 'N/A')}",
                "",
                f"Ports queued: {len(self.scan_results.get('ports_requested', []))}",
                f"Open ports: {snapshot.get('open_ports_count', 0)}",
                f"Open list: {open_ports}",
                f"Services: {services}",
                f"Findings: {snapshot.get('findings_count', 0)}",
                f"TLS grade: {snapshot.get('tls_grade', 'Unavailable')}",
            ]
        )

    def _format_findings_text(self, findings: list[dict[str, str]]) -> str:
        """Create the current findings text block."""
        if not findings:
            return "No notable findings recorded yet."
        lines = []
        for finding in findings:
            lines.append(
                f"[{finding.get('severity', 'info').upper()}] "
                f"{finding.get('name', '')}\n"
                f"Source: {finding.get('source', 'unknown')} | "
                f"Evidence: {finding.get('evidence', '')}\n"
            )
        return "\n".join(lines)

    def _format_web_findings_text(self) -> str:
        """Create the web findings pane content."""
        web = self.scan_results.get("web", {})
        if not web:
            return "No web analysis available yet."
        lines = [
            f"Status: {web.get('status', 'unknown').title()}",
            f"Baseline URL: {web.get('url', '')}",
            f"Final URL: {web.get('final_url', '')}",
            f"Server: {web.get('server', '') or 'Unknown'}",
            "",
            f"Potential XSS: {'Yes' if web.get('xss', {}).get('vulnerable') else 'No'}",
            web.get("xss", {}).get("evidence", "") or "No reflected payload evidence recorded.",
            "",
            f"Potential SQLi: {'Yes' if web.get('sqli', {}).get('vulnerable') else 'No'}",
            web.get("sqli", {}).get("evidence", "") or "No SQL error indicators recorded.",
            "",
            "Findings:",
        ]
        if web.get("findings"):
            for finding in web["findings"]:
                lines.append(
                    f"- [{finding.get('severity', 'info').upper()}] "
                    f"{finding.get('name', '')}: {finding.get('evidence', '')}"
                )
        else:
            lines.append("- No passive findings recorded.")
        return "\n".join(lines)

    def _format_web_headers_text(self) -> str:
        """Create the web headers and cookie pane content."""
        web = self.scan_results.get("web", {})
        if not web:
            return "No header analysis available yet."

        lines = ["Security headers:"]
        for header, payload in web.get("security_headers", {}).items():
            lines.append(
                f"- {header}: {'present' if payload.get('present') else 'missing'}"
                + (f" | {payload.get('value')}" if payload.get("value") else "")
            )

        lines.append("")
        lines.append("Cookies:")
        if web.get("cookies"):
            for cookie in web["cookies"]:
                lines.append(
                    f"- {cookie.get('name')} | Secure={cookie.get('secure')} | "
                    f"HttpOnly={cookie.get('httponly')} | SameSite={cookie.get('samesite') or 'None'}"
                )
        else:
            lines.append("- No cookies observed.")
        return "\n".join(lines)

    def _format_web_forms_text(self) -> str:
        """Create the forms, redirects, and parameter pane content."""
        web = self.scan_results.get("web", {})
        if not web:
            return "No form or redirect analysis available yet."

        lines = ["Redirect chain:"]
        redirects = web.get("redirects", [])
        if redirects:
            for item in redirects:
                lines.append(f"- {item}")
        else:
            lines.append("- No redirects observed.")

        lines.append("")
        lines.append("Parameters:")
        if web.get("parameters"):
            for item in web["parameters"]:
                lines.append(f"- {item.get('name')} @ {item.get('url')}")
        else:
            lines.append("- No parameters discovered.")

        lines.append("")
        lines.append("Forms:")
        if web.get("forms"):
            for form in web["forms"]:
                inputs = ", ".join(input_item["name"] for input_item in form.get("inputs", []))
                lines.append(
                    f"- Method={form.get('method', 'GET')} | Action={form.get('action', '') or 'same-page'} | Inputs={inputs or 'None'}"
                )
        else:
            lines.append("- No forms discovered.")

        return "\n".join(lines)

    def _format_dns_text(self) -> str:
        """Create the DNS pane content."""
        dns_result = self.scan_results.get("dns", {})
        if not dns_result:
            return "No DNS intelligence available yet."

        lines = [
            f"Status: {dns_result.get('status', 'unknown').title()}",
            f"Target: {dns_result.get('target', '')}",
            "",
        ]
        for record_type, values in dns_result.get("records", {}).items():
            pretty_values = ", ".join(values) if values else "None"
            lines.append(f"{record_type}: {pretty_values}")
        if dns_result.get("errors"):
            lines.append("")
            lines.append("Resolver issues:")
            for record_type, error in dns_result["errors"].items():
                lines.append(f"- {record_type}: {error}")
        return "\n".join(lines)

    def _format_tls_text(self) -> str:
        """Create the TLS pane content."""
        tls_result = self.scan_results.get("tls", {})
        if not tls_result:
            return "No TLS analysis available yet."

        lines = [
            f"Status: {tls_result.get('status', 'unknown').title()}",
            f"Grade: {tls_result.get('grade', 'Unavailable')}",
            "",
            "Endpoints:",
        ]
        for endpoint in tls_result.get("endpoints", []):
            lines.append(
                (
                    f"- Port {endpoint.get('port')} | {endpoint.get('status')} | "
                    f"Version={endpoint.get('version') or 'N/A'} | "
                    f"Cipher={endpoint.get('cipher') or 'N/A'} | "
                    f"Days Remaining={endpoint.get('days_remaining')}"
                )
            )
            if endpoint.get("weak_protocols"):
                lines.append(f"  Weak protocols: {', '.join(endpoint['weak_protocols'])}")
            if endpoint.get("subject"):
                lines.append(f"  Subject: {endpoint.get('subject')}")
            if endpoint.get("issuer"):
                lines.append(f"  Issuer: {endpoint.get('issuer')}")
            if endpoint.get("error"):
                lines.append(f"  Error: {endpoint.get('error')}")

        lines.append("")
        lines.append("Findings:")
        if tls_result.get("findings"):
            for finding in tls_result["findings"]:
                lines.append(
                    f"- [{finding.get('severity', 'info').upper()}] "
                    f"{finding.get('name')}: {finding.get('evidence')}"
                )
        else:
            lines.append("- No TLS findings recorded.")
        return "\n".join(lines)

    def _set_textbox_content(self, textbox: ctk.CTkTextbox, content: str) -> None:
        """Replace the full contents of a readonly textbox."""
        textbox.configure(state="normal")
        textbox.delete("1.0", "end")
        textbox.insert("1.0", content)
        textbox.configure(state="disabled")

    def _append_log(self, message: str) -> None:
        """Append a timestamped entry to the live log pane."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{timestamp}] {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _build_export_filename(self, extension: str) -> str:
        """Build a sensible default filename for exported reports."""
        target = self.scan_results.get("target", "scan").replace("/", "_").replace(":", "_")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{target}_{stamp}{extension}"

    def _collect_settings_payload(self) -> dict[str, Any]:
        """Validate and return the current GUI settings payload."""
        timeout = float(self.timeout_var.get().strip() or "2.0")
        max_workers = int(self.max_workers_var.get().strip() or "32")
        history_limit = int(self.history_limit_var.get().strip() or "30")
        if timeout <= 0 or max_workers <= 0 or history_limit <= 0:
            raise ValueError("Timeout, worker count, and history limit must be positive.")

        return {
            "timeout": timeout,
            "max_workers": max_workers,
            "port_profile": self.port_profile_var.get().strip(),
            "custom_ports": self.custom_ports_var.get().strip(),
            "export_format": self.export_format_var.get().strip().upper(),
            "history_limit": history_limit,
            "show_closed_ports": bool(self.show_closed_var.get()),
            "sort_ports_by": self.sort_ports_by_var.get().strip(),
            "port_filter": self.port_filter_var.get().strip(),
            "last_target": self.target_var.get().strip(),
        }

    def _on_close(self) -> None:
        """Persist settings on exit and close the application."""
        try:
            save_settings(self._collect_settings_payload())
        except Exception:
            pass
        self.destroy()
