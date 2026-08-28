from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from deobfuscator.detect import detect_language
from deobfuscator.extract import extract_indicators, format_indicators
from deobfuscator.pipeline import deobfuscate
from deobfuscator.sandbox import SandboxError, default_logs_root, run_php_sandbox


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="deobfuscate",
        description="Statically deobfuscate JavaScript or PHP. Optional Docker PHP sandbox for eval dumps and fake-net logging.",
    )
    parser.add_argument("input", help="Input file path, or - for stdin")
    parser.add_argument("-o", "--output", help="Write result to this file (default: stdout)")
    parser.add_argument(
        "--lang",
        choices=("auto", "js", "php"),
        default="auto",
        help="Language (default: auto-detect from path and contents)",
    )
    parser.add_argument("--max-passes", type=int, default=8, help="Maximum unwrap/fold iterations (default: 8)")
    parser.add_argument(
        "--sandbox",
        choices=("dump", "observe"),
        help="Run the sample in an isolated Docker lab. PHP uses evalhook. JavaScript is deobfuscated statically (no PHP sandbox).",
    )
    parser.add_argument(
        "--logs-dir",
        help="Directory for sandbox logs (default: ./sandbox-logs)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Sandbox PHP timeout in seconds (default: 15)",
    )
    args = parser.parse_args(argv)

    path: str | None
    source: str
    if args.input == "-":
        source = sys.stdin.read()
        path = None
    else:
        path = args.input
        source = Path(args.input).read_text(encoding="utf-8", errors="replace")

    lang = detect_language(source, path=path, lang=args.lang)

    if args.sandbox:
        if lang == "js":
            print(
                "warning: --sandbox dump/observe uses the PHP evalhook lab; "
                "this file is JavaScript, so running the JS deobfuscator instead.",
                file=sys.stderr,
            )
            result = deobfuscate(source, language="js", path=path, max_passes=args.max_passes)
            for warning in result.warnings:
                print(f"warning: {warning}", file=sys.stderr)
            _print_indicators(result.indicators)
            _write_iocs(args, result.indicators)
            _write_output(args.output, result.text)
            if not result.parse_ok:
                print("error: parse failed after deobfuscation", file=sys.stderr)
                return 1
            return 0
        return _run_sandbox(args, source, path)

    result = deobfuscate(source, language=lang, path=path, max_passes=args.max_passes)
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    _print_indicators(result.indicators)
    _write_iocs(args, result.indicators)
    _write_output(args.output, result.text)
    if not result.parse_ok:
        print("error: parse failed after deobfuscation", file=sys.stderr)
        return 1
    return 0


def _run_sandbox(args, source: str, path: str | None) -> int:
    logs_root = Path(args.logs_dir) if args.logs_dir else default_logs_root()
    tmp_sample: Path | None = None
    if path is None or args.input == "-":
        logs_root.mkdir(parents=True, exist_ok=True)
        tmp_sample = logs_root / ".stdin-sample.php"
        tmp_sample.write_text(source, encoding="utf-8")
        sample = tmp_sample
    else:
        sample = Path(path)

    try:
        result = run_php_sandbox(sample, mode=args.sandbox, logs_root=logs_root, timeout=args.timeout)
    except SandboxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if tmp_sample is not None:
            tmp_sample.unlink(missing_ok=True)

    print(f"sandbox logs: {result.log_dir}", file=sys.stderr)
    iocs = extract_indicators(result.deobfuscated, extra_domains=result.domains)
    _print_indicators(iocs)
    (result.log_dir / "indicators.json").write_text(
        json.dumps(iocs.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    if result.eval_dumps:
        print("eval dumps: " + ", ".join(p.name for p in result.eval_dumps), file=sys.stderr)
    _write_output(args.output, result.deobfuscated)
    return 0


def _print_indicators(iocs) -> None:
    sys.stderr.write(format_indicators(iocs))


def _write_iocs(args, iocs) -> None:
    if getattr(args, "output", None):
        out = Path(args.output)
        iocs_path = out.with_name(out.stem + ".iocs.json")
        iocs_path.write_text(json.dumps(iocs.to_dict(), indent=2) + "\n", encoding="utf-8")


def _write_output(output: str | None, text: str) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        return
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
