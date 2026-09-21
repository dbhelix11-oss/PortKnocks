"""Tkinter GUI wrapping the same parameter surface as knockc.cli: a config
file, a target, and a channel, plus preview/send actions. Imports the same
knockc modules cli.py uses directly (derive/config/keyfile/preview/sender/
sshconfig) rather than shelling out, so there's one derivation code path
for the CLI, the GUI, and the tests.

Sending real knocks needs a raw socket (root); previewing does not. Launch
this like the CLI: `sudo .venv/bin/python -m knockc.gui` if you intend to
actually send, or unprivileged if you only want to preview.
"""
import io
import json
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from rich.console import Console

from .config import load_config
from .derive import NUM_CHANNELS, derive_ports, time_counter
from .keyfile import KeyfilePermissionError, load_secret
from .preview import render_preview
from .sender import send_knocks
from .sshconfig import resolve_target

HISTORY_PATH = Path.home() / ".config" / "knockc" / "gui_history.json"
MAX_RECENTS = 10


def load_history(path: Path = HISTORY_PATH) -> dict:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"config": [], "target": []}
    return {"config": list(data.get("config", [])), "target": list(data.get("target", []))}


def save_history(history: dict, path: Path = HISTORY_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history, indent=2))


def remember(history: dict, key: str, value: str) -> None:
    """Move `value` to the front of history[key], deduplicated, capped at MAX_RECENTS."""
    if not value:
        return
    entries = [e for e in history.get(key, []) if e != value]
    entries.insert(0, value)
    history[key] = entries[:MAX_RECENTS]


class KnockGui(tk.Tk):
    def __init__(self, history_path: Path = HISTORY_PATH):
        super().__init__()
        self.title("knockc")
        self.history_path = history_path
        self.history = load_history(history_path)

        self.config_var = tk.StringVar()
        self.target_var = tk.StringVar()
        self.reveal_var = tk.BooleanVar(value=False)

        self._build_widgets()

    def _build_widgets(self):
        pad = {"padx": 6, "pady": 4}

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        frm = ttk.Frame(self, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="Config file:").grid(row=0, column=0, sticky="w", **pad)
        self.config_box = ttk.Combobox(frm, textvariable=self.config_var,
                                        values=self.history["config"])
        self.config_box.grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Browse...", command=self._browse_config).grid(row=0, column=2, **pad)

        ttk.Label(frm, text="Target:").grid(row=1, column=0, sticky="w", **pad)
        self.target_box = ttk.Combobox(frm, textvariable=self.target_var,
                                        values=self.history["target"])
        self.target_box.grid(row=1, column=1, columnspan=2, sticky="ew", **pad)

        ttk.Label(frm, text="Channel:").grid(row=2, column=0, sticky="w", **pad)
        channel_values = ["0 -- open target port(s)"] + [
            f"{n} -- server-configured action" for n in range(1, NUM_CHANNELS)
        ]
        self.channel_box = ttk.Combobox(frm, values=channel_values, state="readonly")
        self.channel_box.current(0)
        self.channel_box.grid(row=2, column=1, columnspan=2, sticky="ew", **pad)

        ttk.Checkbutton(frm, text="Reveal secret in preview", variable=self.reveal_var).grid(
            row=3, column=1, sticky="w", **pad)

        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, columnspan=3, pady=(4, 8))
        ttk.Button(btns, text="Preview", command=self._on_preview).grid(row=0, column=0, padx=4)
        ttk.Button(btns, text="Send Knock", command=self._on_send).grid(row=0, column=1, padx=4)

        self.output = scrolledtext.ScrolledText(frm, width=100, height=32, font=("Courier New", 10))
        self.output.grid(row=5, column=0, columnspan=3, sticky="nsew", **pad)
        frm.rowconfigure(5, weight=1)

    def _browse_config(self):
        path = filedialog.askopenfilename(
            title="Select knock.conf",
            filetypes=[("knock.conf files", "*.conf *.conf.example"), ("All files", "*")],
        )
        if path:
            self.config_var.set(path)

    def _channel_id(self) -> int:
        return self.channel_box.current()

    def _write(self, text: str):
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, text)

    def _append(self, text: str):
        self.output.insert(tk.END, text)
        self.output.see(tk.END)

    def _remember_and_persist(self, config_path: str, target: str):
        remember(self.history, "config", config_path)
        remember(self.history, "target", target)
        save_history(self.history, self.history_path)
        self.config_box["values"] = self.history["config"]
        self.target_box["values"] = self.history["target"]

    def _load_inputs(self):
        """Validate + resolve the form into (config_path, target, resolved_target,
        was_alias, cfg, secret), or None (with an error dialog already shown)."""
        config_path = self.config_var.get().strip()
        target = self.target_var.get().strip()
        if not config_path or not target:
            messagebox.showerror("knockc", "Config file and target are required.")
            return None
        try:
            resolved_target, was_alias = resolve_target(target)
            cfg = load_config(config_path)
            secret = load_secret(cfg.keyfile)
        except KeyfilePermissionError as e:
            messagebox.showerror("knockc", str(e))
            return None
        except FileNotFoundError as e:
            messagebox.showerror("knockc", f"File not found: {e.filename or e}")
            return None
        except Exception as e:
            messagebox.showerror("knockc", str(e))
            return None
        return config_path, target, resolved_target, was_alias, cfg, secret

    def _on_preview(self):
        loaded = self._load_inputs()
        if loaded is None:
            return
        config_path, target, resolved_target, was_alias, cfg, secret = loaded

        buf = io.StringIO()
        console = Console(file=buf, width=100)
        try:
            render_preview(secret, config_path, resolved_target, cfg.time_step, cfg.n_ports,
                            cfg.port_low, cfg.port_high, channel_id=self._channel_id(),
                            reveal_secret=self.reveal_var.get(), console=console)
        except Exception as e:
            messagebox.showerror("knockc", str(e))
            return

        header = ""
        if was_alias:
            header = f"resolved target {target!r} via ~/.ssh/config to {resolved_target}\n\n"
        self._write(header + buf.getvalue())
        self._remember_and_persist(config_path, target)

    def _on_send(self):
        loaded = self._load_inputs()
        if loaded is None:
            return
        config_path, target, resolved_target, was_alias, cfg, secret = loaded
        channel_id = self._channel_id()

        if not messagebox.askyesno("knockc", f"Send knock to {resolved_target} on channel {channel_id}?"):
            return

        lines = []
        if was_alias:
            lines.append(f"resolved target {target!r} via ~/.ssh/config to {resolved_target}")

        counter = time_counter(time.time(), cfg.time_step)
        ports = derive_ports(secret, counter, cfg.n_ports, cfg.port_low, cfg.port_high, channel_id)
        lines.append(f"knocking {resolved_target} with {len(ports)} ports "
                     f"(window {counter}, channel {channel_id}): {ports}")
        self._write("\n".join(lines) + "\n")
        self.update_idletasks()

        try:
            send_knocks(cfg.knock_proto, resolved_target, ports, cfg.knock_interval_ms)
        except PermissionError:
            self._append("error: permission denied sending raw packets -- run this GUI as root "
                          "(e.g. `sudo .venv/bin/python -m knockc.gui`) to send knocks.\n")
            return
        except Exception as e:
            self._append(f"error: {e}\n")
            return

        self._append("done\n")
        self._remember_and_persist(config_path, target)


def main() -> int:
    app = KnockGui()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
