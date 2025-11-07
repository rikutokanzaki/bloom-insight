from pathlib import Path
from parser import parse_date
from evaluator import evaluate_log
import argparse
import os

base_path = Path(__file__).resolve()
openresty_log_file = os.path.join(base_path.parents[1], "log", "raw", "access.log")
heralding_log_file = os.path.join(base_path.parents[1], "log", "raw", "log_session.json")

def _mode_sort_key(name: str) -> tuple[int, str]:
  preferred = ["sakura", "yozakura", "tsubomi", "launcher", "unknown"]

  try:
    idx = preferred.index(name)
  except ValueError:
    idx = len(preferred)

  return (idx, name)

def main():
  parser = argparse.ArgumentParser(description="Group NDJSON access log by mode and count per mode, optionally per day.")
  parser.add_argument("--log", default=str(openresty_log_file), help="Path to access.log (NDJSON)")
  parser.add_argument("--session-log", default=str(heralding_log_file), help="Path to log_session.json (NDJSON) to annotate with mode and split per mode")
  parser.add_argument("--mode-key", default="spring_mode", help="Field name to use as mode (default: spring_mode)")
  parser.add_argument("--out-file-name", default="access.log", help="Output filename per mode directory")
  parser.add_argument("--encoding", default="utf-8", help="Log file text encoding (default: utf-8)")
  parser.add_argument("--errors", default="replace", choices=["strict","ignore","replace","backslashreplace","surrogateescape"], help="Decode error handling (default: replace)")
  parser.add_argument("--start", help="Start time inclusive. Accepts 202511051900, 20251105190030, ISO8601, or epoch seconds.")
  parser.add_argument("--end", help="End time inclusive. Accepts 202511051900, 20251105190030, ISO8601, or epoch seconds.")
  parser.add_argument("--tz", default="JST", help='Time zone for naive inputs like 202511051900. Use "UTC", "local", or offset like +09:00')
  parser.add_argument("--count-policy", default="all", choices=["uri","all"], help="Count rule: 'uri' counts only HTTP-like lines, 'all' counts every line")
  parser.add_argument("--daily", action="store_true", help="Aggregate counts per mode per day")
  parser.add_argument("--session-time-tolerance", type=float, default=1.0, help="Seconds to match session timestamp to nearest access.log entry")
  args = parser.parse_args()

  tzinfo = parse_date.parse_tz(args.tz)
  start_dt = parse_date.parse_dt(args.start, tzinfo)
  end_dt = parse_date.parse_dt(args.end, tzinfo)

  evaluator = evaluate_log.LogEvaluator(args.log, mode_key=args.mode_key, encoding=args.encoding, errors=args.errors)

  if args.daily:
    counts = evaluator.classify_by_mode(
      out_file_name=args.out_file_name,
      start=start_dt,
      end=end_dt,
      count_policy=args.count_policy,
      bucket="day",
      bucket_tz=tzinfo
    )

    days = set()

    for m in counts:
      days.update(counts[m].keys())

    totals_by_mode: dict[str, int] = {}

    for day in sorted(days):
      print(day)

      modes_today = []

      for m in sorted(counts.keys(), key=_mode_sort_key):
        c = counts[m].get(day, 0)

        if c > 0:
          modes_today.append((m, c))
          totals_by_mode[m] = totals_by_mode.get(m, 0) + c

      total = sum(c for _, c in modes_today)

      for m, c in modes_today:
        print(f"{m}: {c}")
      print(f"sum: {total}")
      print("")

    print("--sum--")

    for m in sorted(totals_by_mode.keys(), key=_mode_sort_key):
      print(f"{m}: {totals_by_mode[m]}")

  else:
    counts = evaluator.classify_by_mode(
      out_file_name=args.out_file_name,
      start=start_dt,
      end=end_dt,
      count_policy=args.count_policy
    )

    for mode in sorted(counts.keys(), key=_mode_sort_key):
      print(f"{mode}: {counts[mode]}")

  if args.session_log:
    if args.daily:
      session_counts = evaluator.annotate_and_save_sessions(
        session_file=args.session_log,
        time_tolerance=args.session_time_tolerance,
        out_file_name="log_session.json",
        bucket="day",
        bucket_tz=tzinfo
      )
      days = set()

      for m in session_counts:
        days.update(session_counts[m].keys())

      totals_by_mode: dict[str, dict[str, int]] = {}

      print("--session auth totals (daily)--")
      for day in sorted(days):
        print(day)
        modes_today = []

        for m in sorted(session_counts.keys(), key=_mode_sort_key):
          u = session_counts[m].get(day, {}).get("usernames", 0)
          p = session_counts[m].get(day, {}).get("passwords", 0)

          if u or p:
            modes_today.append((m, u, p))

            if m not in totals_by_mode:
              totals_by_mode[m] = {"usernames": 0, "passwords": 0}
            totals_by_mode[m]["usernames"] += u
            totals_by_mode[m]["passwords"] += p

        sum_u = sum(u for _, u, _ in modes_today)
        sum_p = sum(p for _, _, p in modes_today)

        for m, u, p in modes_today:
          print(f"{m}: usernames={u} passwords={p}")

        print(f"sum: usernames={sum_u} passwords={sum_p}")
        print("")
      print("--session sum--")

      for m in sorted(totals_by_mode.keys(), key=_mode_sort_key):
        u = totals_by_mode[m]["usernames"]
        p = totals_by_mode[m]["passwords"]
        print(f"{m}: usernames={u} passwords={p}")

    else:
      session_counts = evaluator.annotate_and_save_sessions(
        session_file=args.session_log,
        time_tolerance=args.session_time_tolerance,
        out_file_name="log_session.json"
      )

      print("--session auth totals--")

      for mode in sorted(session_counts.keys(), key=_mode_sort_key):
        u = session_counts[mode]["usernames"]
        p = session_counts[mode]["passwords"]
        print(f"{mode}: usernames={u} passwords={p}")

if __name__ == "__main__":
  main()
