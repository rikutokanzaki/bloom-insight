from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Sequence, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

DEFAULT_MODELS = ("gpt-oss", "gpt-4o", "gpt-5.4")
LOGIN_EVENT = "reverssh.login.attempt"
COMMAND_EVENT = "reverssh.command.input"
SESSION_CLOSE_EVENT = "reverssh.session.close"


@dataclass
class LogStats:
    model: str
    path: Path
    records: int = 0
    login_attempts: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    username_records: int = 0
    password_records: int = 0
    commands: int = 0
    session_closes: int = 0
    first_timestamp: Optional[datetime] = None
    last_timestamp: Optional[datetime] = None
    usernames: Counter = field(default_factory=Counter)
    command_signatures: Counter = field(default_factory=Counter)
    cwd_values: Counter = field(default_factory=Counter)
    daily_counts: DefaultDict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    included_records: int = 0

    def update_timestamp(self, timestamp: Optional[datetime]) -> None:
        if timestamp is None:
            return
        if self.first_timestamp is None or timestamp < self.first_timestamp:
            self.first_timestamp = timestamp
        if self.last_timestamp is None or timestamp > self.last_timestamp:
            self.last_timestamp = timestamp


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare ReverSSH logs across GPT model runs."
    )
    parser.add_argument(
        "--root",
        default=None,
        help="Repository root. Defaults to the bloom-insight project root inferred from this file.",
    )
    parser.add_argument(
        "--models",
        nargs="*",
        default=list(DEFAULT_MODELS),
        help="Model directories to compare under log/raw/.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top usernames and commands to show per model.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        default=None,
        help="Write the full comparison report to this JSON file.",
    )
    parser.add_argument(
        "--first-hours",
        type=float,
        default=None,
        help="Analyze only the first N hours from each log's first timestamp.",
    )
    parser.add_argument(
        "--last-hours",
        type=float,
        default=None,
        help="Analyze only the last N hours from each log's last timestamp.",
    )
    parser.add_argument(
        "--after",
        default=None,
        help="Analyze only records at or after this ISO-8601 timestamp.",
    )
    parser.add_argument(
        "--before",
        default=None,
        help="Analyze only records at or before this ISO-8601 timestamp.",
    )
    return parser.parse_args(argv)


def load_json_lines(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line %s in %s", line_number, path)
                continue
            if isinstance(record, dict):
                yield record


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value))
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_timestamp_arg(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 timestamp: {value}") from exc


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, list):
        return " ".join(as_text(item) for item in value if item is not None)
    return str(value)


def normalize_command(command: str) -> str:
    parts = [segment.strip() for segment in command.splitlines() if segment.strip()]
    if not parts:
        return ""
    flattened = " ; ".join(parts)
    return " ".join(flattened.split())


def short_preview(text: str, width: int = 120) -> str:
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)].rstrip() + "..."


def format_timestamp(value: Optional[datetime]) -> str:
    if value is None:
        return "-"
    return value.isoformat(timespec="seconds")


def format_rate(success: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(success / total) * 100:.1f}%"


def count_unique(counter: Counter) -> int:
    return len([key for key, count in counter.items() if count > 0])


def load_log_bounds(path: Path) -> Tuple[Optional[datetime], Optional[datetime]]:
    first_timestamp: Optional[datetime] = None
    last_timestamp: Optional[datetime] = None

    for record in load_json_lines(path):
        timestamp = parse_timestamp(record.get("timestamp"))
        if timestamp is None:
            continue
        if first_timestamp is None or timestamp < first_timestamp:
            first_timestamp = timestamp
        if last_timestamp is None or timestamp > last_timestamp:
            last_timestamp = timestamp

    return first_timestamp, last_timestamp


def build_time_window(
    first_timestamp: Optional[datetime],
    last_timestamp: Optional[datetime],
    first_hours: Optional[float],
    last_hours: Optional[float],
    after: Optional[datetime],
    before: Optional[datetime],
) -> Tuple[Optional[datetime], Optional[datetime], bool]:
    start = after
    end = before

    if first_timestamp is not None and first_hours is not None:
        first_end = first_timestamp + timedelta(hours=first_hours)
        start = first_timestamp if start is None else max(start, first_timestamp)
        end = first_end if end is None else min(end, first_end)

    if last_timestamp is not None and last_hours is not None:
        last_start = last_timestamp - timedelta(hours=last_hours)
        start = last_start if start is None else max(start, last_start)
        end = last_timestamp if end is None else min(end, last_timestamp)

    if start is not None and end is not None and start > end:
        return start, end, True

    return start, end, False


def analyze_log(
    model: str,
    path: Path,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> LogStats:
    stats = LogStats(model=model, path=path)

    for record in load_json_lines(path):
        timestamp = parse_timestamp(record.get("timestamp"))
        if start is not None and timestamp is not None and timestamp < start:
            continue
        if end is not None and timestamp is not None and timestamp > end:
            continue

        stats.records += 1
        stats.included_records += 1
        stats.update_timestamp(timestamp)

        eventid = as_text(record.get("eventid"))
        day = timestamp.date().isoformat() if timestamp is not None else "unknown"
        stats.daily_counts[day]["records"] += 1

        if eventid == LOGIN_EVENT:
            stats.login_attempts += 1
            stats.daily_counts[day]["login_attempts"] += 1

            raw_username = as_text(record.get("username")).strip()
            username = raw_username or "<unknown>"
            if raw_username:
                stats.username_records += 1
            stats.usernames[username] += 1

            password = as_text(record.get("password")).strip()
            if password:
                stats.password_records += 1

            success_value = record.get("success")
            success = bool(success_value) if isinstance(success_value, bool) else str(success_value).lower() == "true"
            if success:
                stats.successful_logins += 1
                stats.daily_counts[day]["successful_logins"] += 1
            else:
                stats.failed_logins += 1
                stats.daily_counts[day]["failed_logins"] += 1

        elif eventid == COMMAND_EVENT:
            stats.commands += 1
            stats.daily_counts[day]["commands"] += 1

            command_text = normalize_command(as_text(record.get("command")))
            if command_text:
                stats.command_signatures[command_text] += 1

            cwd = as_text(record.get("cwd")).strip()
            if cwd:
                stats.cwd_values[cwd] += 1

        elif eventid == SESSION_CLOSE_EVENT:
            stats.session_closes += 1
            stats.daily_counts[day]["session_closes"] += 1

    return stats


def build_model_report(stats: LogStats, top_n: int) -> Dict[str, Any]:
    top_usernames = [
        {"value": username, "count": count}
        for username, count in stats.usernames.most_common(top_n)
    ]
    top_commands = [
        {"value": short_preview(command), "count": count}
        for command, count in stats.command_signatures.most_common(top_n)
    ]
    top_cwds = [
        {"value": cwd, "count": count}
        for cwd, count in stats.cwd_values.most_common(top_n)
    ]

    return {
        "model": stats.model,
        "path": str(stats.path),
        "records": stats.records,
        "included_records": stats.included_records,
        "window_empty": False,
        "login_attempts": stats.login_attempts,
        "successful_logins": stats.successful_logins,
        "failed_logins": stats.failed_logins,
        "username_records": stats.username_records,
        "password_records": stats.password_records,
        "success_rate": format_rate(stats.successful_logins, stats.login_attempts),
        "commands": stats.commands,
        "session_closes": stats.session_closes,
        "unique_usernames": count_unique(stats.usernames),
        "unique_commands": count_unique(stats.command_signatures),
        "unique_cwds": count_unique(stats.cwd_values),
        "first_timestamp": format_timestamp(stats.first_timestamp),
        "last_timestamp": format_timestamp(stats.last_timestamp),
        "top_usernames": top_usernames,
        "top_commands": top_commands,
        "top_cwds": top_cwds,
        "daily_counts": {
            day: dict(counter)
            for day, counter in sorted(stats.daily_counts.items())
        },
    }


def print_model_summary(report: Dict[str, Any]) -> None:
    print(f"\n=== {report['model']} ===")
    print(f"path: {report['path']}")
    time_window = report.get("time_window", {})
    if time_window:
        if time_window.get("empty"):
            print(
                "time window: empty "
                f"({time_window.get('start') or '-'} -> {time_window.get('end') or '-'})"
            )
        else:
            print(
                "time window: "
                f"{time_window.get('start') or '-'} -> {time_window.get('end') or '-'}"
            )
        if time_window.get("first_timestamp") or time_window.get("last_timestamp"):
            print(
                "full range: "
                f"{time_window.get('first_timestamp') or '-'} -> {time_window.get('last_timestamp') or '-'}"
            )
    print(f"records: {report['records']}")
    if report["included_records"] != report["records"]:
        print(f"included records: {report['included_records']}")
    print(
        f"logins: {report['login_attempts']} "
        f"(success {report['successful_logins']}, failed {report['failed_logins']}, rate {report['success_rate']})"
    )
    print(
        f"username records: {report['username_records']}, "
        f"password records: {report['password_records']}"
    )
    print(f"commands: {report['commands']}")
    print(f"session closes: {report['session_closes']}")
    print(f"unique usernames: {report['unique_usernames']}")
    print(f"unique commands: {report['unique_commands']}")
    print(f"time range: {report['first_timestamp']} -> {report['last_timestamp']}")

    if report['top_usernames']:
        print("top usernames:")
        for item in report['top_usernames']:
            print(f"  - {item['value']}: {item['count']}")

    if report['top_commands']:
        print("top commands:")
        for item in report['top_commands']:
            print(f"  - {item['value']}: {item['count']}")

    if report['top_cwds']:
        print("top cwd values:")
        for item in report['top_cwds']:
            print(f"  - {item['value']}: {item['count']}")


def print_comparison_table(reports: List[Dict[str, Any]]) -> None:
    rows = []
    for report in reports:
        rows.append([
            report['model'],
            str(report['records']),
            str(report['login_attempts']),
            str(report['username_records']),
            str(report['password_records']),
            report['success_rate'],
            str(report['commands']),
            str(report['session_closes']),
            str(report['unique_usernames']),
            str(report['unique_commands']),
        ])

    headers = [
        "model",
        "records",
        "logins",
        "username recs",
        "password recs",
        "success",
        "commands",
        "closes",
        "users",
        "unique cmds",
    ]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def fmt_row(row: List[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))

    print("\n=== Model Comparison ===")
    print(fmt_row(headers))
    print(fmt_row(["-" * width for width in widths]))
    for row in rows:
        print(fmt_row(row))


def build_comparison_report(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_records = sum(report["records"] for report in reports)
    total_included_records = sum(report.get("included_records", report["records"]) for report in reports)
    total_logins = sum(report["login_attempts"] for report in reports)
    total_username_records = sum(report["username_records"] for report in reports)
    total_password_records = sum(report["password_records"] for report in reports)
    total_commands = sum(report["commands"] for report in reports)
    total_closes = sum(report["session_closes"] for report in reports)

    return {
        "models": reports,
        "totals": {
            "records": total_records,
            "included_records": total_included_records,
            "login_attempts": total_logins,
            "username_records": total_username_records,
            "password_records": total_password_records,
            "commands": total_commands,
            "session_closes": total_closes,
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[2]
    after = parse_timestamp_arg(args.after)
    before = parse_timestamp_arg(args.before)

    if args.first_hours is not None and args.first_hours < 0:
        logger.error("--first-hours must be greater than or equal to 0")
        return 1
    if args.last_hours is not None and args.last_hours < 0:
        logger.error("--last-hours must be greater than or equal to 0")
        return 1

    reports: List[Dict[str, Any]] = []
    for model in args.models:
        log_path = root / "log" / "raw" / model / "reverssh" / "reverssh.log"
        if not log_path.exists():
            logger.warning("Log file not found for %s: %s", model, log_path)
            continue

        logger.info("Analyzing %s", log_path)
        first_timestamp, last_timestamp = load_log_bounds(log_path)
        window_start, window_end, window_empty = build_time_window(
            first_timestamp,
            last_timestamp,
            args.first_hours,
            args.last_hours,
            after,
            before,
        )

        if window_start is not None or window_end is not None:
            logger.info(
                "Using time window for %s: %s -> %s",
                model,
                window_start.isoformat() if window_start else "-",
                window_end.isoformat() if window_end else "-",
            )

        if window_empty:
            logger.warning(
                "Empty time window for %s; returning zero counts for this model",
                model,
            )
            stats = LogStats(model=model, path=log_path)
            stats.first_timestamp = first_timestamp
            stats.last_timestamp = last_timestamp
        else:
            stats = analyze_log(model, log_path, window_start, window_end)
        report = build_model_report(stats, args.top)
        report["time_window"] = {
            "start": window_start.isoformat() if window_start else None,
            "end": window_end.isoformat() if window_end else None,
            "first_timestamp": first_timestamp.isoformat() if first_timestamp else None,
            "last_timestamp": last_timestamp.isoformat() if last_timestamp else None,
            "empty": window_empty,
        }
        reports.append(report)
        print_model_summary(report)

    if not reports:
        logger.error("No ReverSSH logs were found under %s", root / "log" / "raw")
        return 1

    print_comparison_table(reports)

    comparison_report = build_comparison_report(reports)
    print("\n=== Overall Totals ===")
    print(json.dumps(comparison_report["totals"], indent=2, ensure_ascii=False))

    if args.json_output:
        output_path = Path(args.json_output)
        output_path.write_text(
            json.dumps(comparison_report, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        logger.info("Wrote JSON report to %s", output_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

