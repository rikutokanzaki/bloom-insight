from pathlib import Path
from parser import parse_date
from evaluator import evaluate_log
import argparse
import os
from analyzer import display_burst

base_path = Path(__file__).resolve()
openresty_log_file = os.path.join(base_path.parents[1], "log", "raw", "access.log")
heralding_log_file = os.path.join(base_path.parents[1], "log", "raw", "log_session.json")
default_burst_out_dir = os.path.join(base_path.parents[1], "log", "bursts")

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

  parser.add_argument("--burst", action="store_true", help="Run burst analysis for access.log")
  parser.add_argument("--burst-host", default="heralding", help='proxy_host filter for burst analysis. Use "any" for all')
  parser.add_argument("--burst-metric", choices=["count", "bytes", "rtime"], default="count")
  parser.add_argument("--burst-top", type=int, default=10, help="Top N minutes to list and extract")
  parser.add_argument("--burst-window", type=int, default=5, help="Sliding window size (minutes)")
  parser.add_argument("--burst-save", action="store_true", help="Also save surrounding logs for top burst minutes")
  parser.add_argument("--burst-save-before", type=int, default=5, help="Minutes before each top minute to include")
  parser.add_argument("--burst-save-after", type=int, default=5, help="Minutes after each top minute to include")
  parser.add_argument("--burst-out-dir", default=str(default_burst_out_dir), help="Directory to save extracted burst logs")
  parser.add_argument("--no-burst-save", action="store_true", help="Do not save logs when --burst is specified")

  args = parser.parse_args()

  tzinfo = parse_date.parse_tz(args.tz)
  start_dt = parse_date.parse_dt(args.start, tzinfo)
  end_dt = parse_date.parse_dt(args.end, tzinfo)

  if args.burst:
    t_from_jst = start_dt.astimezone(display_burst.TZ_JST) if start_dt else None
    t_to_jst = end_dt.astimezone(display_burst.TZ_JST) if end_dt else None

    result = display_burst.analyze_burst(
      path=args.log,
      host=args.burst_host,
      metric=args.burst_metric,
      top=args.burst_top,
      window=args.burst_window,
      t_from_jst=t_from_jst,
      t_to_jst=t_to_jst,
    )

    first, last = result['period']
    if not result['events']:
      print("対象データなし")
      return

    print(f"期間(JST): {first} ～ {last}")
    print(f"host={args.burst_host} metric={args.burst_metric}")

    print("\n分単位 上位:")
    for dtm, v in result['top_minutes']:
      print(f"{dtm} JST  {int(v) if args.burst_metric=='count' else v}")

    print("\n時単位 上位:")
    for dth, v in result['per_hour'].most_common(min(args.burst_top, 10)):
      print(f"{dth} JST  {int(v) if args.burst_metric=='count' else v}")

    wb = result['window_burst']
    if wb:
      print(f"\n最大バースト({args.burst_window}分窓, metric={args.burst_metric}): {wb['start']} ～ {wb['end']} JST に {int(wb['sum']) if args.burst_metric=='count' else wb['sum']} ")

    do_save = (not args.no_burst_save) or args.burst_save
    if do_save and result['top_minutes']:
      created = display_burst.save_logs_for_bursts(
        path=args.log,
        out_dir=args.burst_out_dir,
        host=args.burst_host,
        top_minutes=result['top_minutes'],
        before_min=args.burst_save_before,
        after_min=args.burst_save_after,
      )
      print(f"\n抽出ログを保存しました: {len(created)} ファイル")
      for p in created:
        print(p)

    return

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
