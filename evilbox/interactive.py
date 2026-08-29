from __future__ import annotations

import sys
from pathlib import Path


def run_interactive(run_argv) -> int:
    """Menu when evilbox is started with no arguments. run_argv is cli._main."""
    print("Evilbox")
    print("  1) Deobfuscate a file")
    print("  2) PHP sandbox (dump: log eval, do not run payloads)")
    print("  3) PHP sandbox (observe: run in isolated Docker)")
    print("  4) Batch a directory of .js / .php samples")
    print("  5) Quit")
    choice = _ask("Select", "1")
    if choice in {"5", "q", "quit"}:
        return 0
    if choice not in {"1", "2", "3", "4"}:
        print("error: choose 1-5", file=sys.stderr)
        return 2

    if choice == "4":
        folder = _ask_path("Directory of samples")
        if folder is None:
            return 2
        out = _ask("Output directory (blank = ./evilbox-out)", "")
        argv = [folder]
        if out:
            argv.extend(["-o", out])
        return run_argv(argv)

    sample = _ask_path("Sample file")
    if sample is None:
        return 2
    argv = [sample]
    if choice == "1":
        out = _ask("Write cleaned file to (blank = stdout)", "")
        if out:
            argv.extend(["-o", out])
        report = _ask("JSON report path (blank = skip / auto with -o)", "")
        if report:
            argv.extend(["--report", report])
        lang = _ask("Language auto/js/php", "auto")
        if lang in {"js", "php"}:
            argv.extend(["--lang", lang])
        return run_argv(argv)

    logs = _ask("Sandbox logs directory", "./sandbox-logs")
    timeout = _ask("Timeout seconds", "20")
    mode = "dump" if choice == "2" else "observe"
    argv.extend(["--sandbox", mode, "--logs-dir", logs, "--timeout", timeout])
    out = _ask("Write cleaned file to (blank = stdout)", "")
    if out:
        argv.extend(["-o", out])
    return run_argv(argv)


def _ask(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    line = input(f"{label}{suffix}: ").strip()
    return line if line else default


def _ask_path(label: str) -> str | None:
    raw = _ask(label, "")
    if not raw:
        print("error: a path is required", file=sys.stderr)
        return None
    return str(Path(raw).expanduser())


def run_interactive(run_argv) -> int:
    """Menu when evilbox is started with no arguments. run_argv is cli._main."""
    print("Evilbox")
    print("  1) Deobfuscate a file")
    print("  2) PHP sandbox (dump: log eval, do not run payloads)")
    print("  3) PHP sandbox (observe: run in isolated Docker)")
    print("  4) Batch a directory of .js / .php samples")
    print("  5) Quit")
    choice = _ask("Select", "1")
    if choice in {"5", "q", "quit"}:
        return 0
    if choice not in {"1", "2", "3", "4"}:
        print("error: choose 1-5", file=__import__("sys").stderr)
        return 2

    if choice == "4":
        folder = _ask_path("Directory of samples")
        out = _ask("Output directory (blank = ./evilbox-out)", "")
        argv = [folder]
        if out:
            argv.extend(["-o", out])
        return run_argv(argv)

    sample = _ask_path("Sample file")
    argv = [sample]
    if choice == "1":
        out = _ask("Write cleaned file to (blank = stdout)", "")
        if out:
            argv.extend(["-o", out])
        report = _ask("JSON report path (blank = skip / auto with -o)", "")
        if report:
            argv.extend(["--report", report])
        lang = _ask("Language auto/js/php", "auto")
        if lang in {"js", "php"}:
            argv.extend(["--lang", lang])
        return run_argv(argv)

    logs = _ask("Sandbox logs directory", "./sandbox-logs")
    timeout = _ask("Timeout seconds", "20")
    mode = "dump" if choice == "2" else "observe"
    argv.extend(["--sandbox", mode, "--logs-dir", logs, "--timeout", timeout])
    out = _ask("Write cleaned file to (blank = stdout)", "")
    if out:
        argv.extend(["-o", out])
    return run_argv(argv)


def _ask(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    line = input(f"{label}{suffix}: ").strip()
    return line if line else default


def _ask_path(label: str) -> str:
    raw = _ask(label, "")
    if not raw:
        raise SystemExit("error: a path is required")
    return str(Path(raw).expanduser())
