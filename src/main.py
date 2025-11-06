from pathlib import Path
from parser import parse_date
from evaluator import evaluate_log
import argparse

def _mode_sort_key(name: str) -> tuple[int, str]:
  preferred = ["sakura", "yozakura", "tsubomi", "launcher", "unknown"]
  try:
    idx = preferred.index(name)
  except ValueError:
    idx = len(preferred)
  return (idx, name)

def main():
  parser = argparse.ArgumentParser(description="Group NDJSON access log by mode and count per mode, optionally per day.")
  parser.add_argument("--log", default=str(Path(__file__).resolve().parents[1] / "log" / "raw" / "access.log"), help="Path to access.log (NDJSON)")
  parser.add_argument("--mode-key", default="spring_mode", help="Field name to use as mode (default: spring_mode)")
  parser.add_argument("--out-file-name", default="access.log", help="Output filename per mode directory")
  parser.add_argument("--encoding", default="utf-8", help="Log file text encoding (default: utf-8)")
  parser.add_argument("--errors", default="replace", choices=["strict","ignore","replace","backslashreplace","surrogateescape"], help="Decode error handling (default: replace)")
  parser.add_argument("--start", help="Start time inclusive. Accepts 202511051900, 20251105190030, ISO8601, or epoch seconds.")
  parser.add_argument("--end", help="End time inclusive. Accepts 202511051900, 20251105190030, ISO8601, or epoch seconds.")
  parser.add_argument("--tz", default="JST", help='Time zone for naive inputs like 202511051900. Use "UTC", "local", or offset like +09:00')
  parser.add_argument("--count-policy", default="all", choices=["uri","all"], help="Count rule: 'uri' counts only HTTP-like lines, 'all' counts every line")
  parser.add_argument("--daily", action="store_true", help="Aggregate counts per mode per day")
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

if __name__ == "__main__":
  main()
