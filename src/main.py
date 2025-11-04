from pathlib import Path
from evaluator import evaluate_log
import argparse

def main():
  parser = argparse.ArgumentParser(description="Group NDJSON access log by mode and count request_uri per mode.")
  parser.add_argument("--log", default=str(Path(__file__).resolve().parents[1] / "log" / "raw" / "access.log"), help="Path to access.log (NDJSON)")
  parser.add_argument("--mode-key", default="spring_mode", help="Field name to use as mode (default: spring_mode)")
  parser.add_argument("--out-file-name", default="access.log", help="Output filename per mode directory")
  parser.add_argument("--encoding", default="utf-8", help="Log file text encoding (default: utf-8)")
  parser.add_argument("--errors", default="replace", choices=["strict","ignore","replace","backslashreplace","surrogateescape"], help="Decode error handling (default: replace)")
  args = parser.parse_args()

  evaluator = evaluate_log.LogEvaluator(args.log, mode_key=args.mode_key, encoding=args.encoding, errors=args.errors)
  counts = evaluator.classify_by_mode(out_file_name=args.out_file_name)

  for mode in sorted(counts.keys()):
    print(f"{mode}: {counts[mode]}")

if __name__ == "__main__":
  main()
