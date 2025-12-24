import sys, json, re, argparse
from datetime import datetime, timezone, timedelta
from collections import Counter, deque
from pathlib import Path

TZ_JST = timezone(timedelta(hours=9))

def parse_json_loose(line: str):
  s = line.strip()
  if not s:
    return None
  try:
    return json.loads(s)
  except json.JSONDecodeError:
    s2 = re.sub(r',\s*}', '}', s)
    try:
      return json.loads(s2)
    except Exception:
      return None

def parse_time_iso8601(ts: str) -> datetime:
  ts = ts.replace('Z', '+00:00')
  return datetime.fromisoformat(ts)

def parse_time_local(tl: str) -> datetime | None:
  try:
    return datetime.strptime(tl, "%d/%b/%Y:%H:%M:%S %z")
  except Exception:
    return None

def analyze_burst(path: str,
          host: str = "heralding",
          metric: str = "count",
          top: int = 20,
          window: int = 5,
          t_from_jst: datetime | None = None,
          t_to_jst: datetime | None = None):

  per_min: Counter[datetime] = Counter()
  per_hour: Counter[datetime] = Counter()
  events: list[tuple[datetime, float]] = []

  with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
      rec = parse_json_loose(line)
      if not rec:
        continue

      if host.lower() != "any":
        if rec.get("proxy_host") != host:
          continue

      dt = None
      ts = rec.get("time_iso8601")
      if ts:
        try:
          dt = parse_time_iso8601(ts)
        except Exception:
          dt = None
      if dt is None:
        tl = rec.get("time_local")
        if tl:
          dt = parse_time_local(tl)
      if dt is None:
        continue

      dt_jst = dt.astimezone(TZ_JST)

      if t_from_jst and dt_jst < t_from_jst:
        continue
      if t_to_jst and dt_jst >= t_to_jst:
        continue

      if metric == "count":
        val = 1.0
      elif metric == "bytes":
        val = float(rec.get("bytes_sent") or rec.get("body_bytes_sent") or 0)
      else:
        try:
          val = float(rec.get("request_time") or 0.0)
        except Exception:
          val = 0.0

      mkey = dt_jst.replace(second=0, microsecond=0)
      hkey = dt_jst.replace(minute=0, second=0, microsecond=0)
      per_min[mkey] += val
      per_hour[hkey] += val
      events.append((dt_jst, val))

  if not events:
    return {
      'per_min': per_min,
      'per_hour': per_hour,
      'events': events,
      'top_minutes': [],
      'window_burst': None,
      'period': (None, None),
    }

  events.sort(key=lambda x: x[0])
  first, last = events[0][0], events[-1][0]

  top_minutes = per_min.most_common(top)

  win = timedelta(minutes=window)
  dq: deque[tuple[datetime, float]] = deque()
  cur_sum = 0.0
  best_sum = 0.0
  best_start = None

  for t, v in events:
    dq.append((t, v))
    cur_sum += v
    while dq and (t - dq[0][0]) >= win:
      t0, v0 = dq.popleft()
      cur_sum -= v0
    if cur_sum > best_sum:
      best_sum = cur_sum
      best_start = dq[0][0]

  window_burst = None
  if best_start:
    window_burst = {'start': best_start, 'end': best_start + win, 'sum': best_sum}

  return {
    'per_min': per_min,
    'per_hour': per_hour,
    'events': events,
    'top_minutes': top_minutes,
    'window_burst': window_burst,
    'period': (first, last),
  }

def save_logs_for_bursts(path: str,
                        out_dir: str | Path,
                        host: str,
                        top_minutes: list[tuple[datetime, float]],
                        before_min: int = 5,
                        after_min: int = 5
                        ) -> list[Path]:

  out_dir = Path(out_dir)
  out_dir.mkdir(parents=True, exist_ok=True)
  created: list[Path] = []

  windows: list[tuple[datetime, datetime, str]] = []
  for i, (dtm, val) in enumerate(top_minutes, start=1):
    start = dtm - timedelta(minutes=before_min)
    end = dtm + timedelta(minutes=1 + after_min)
    fname = f"burst_{i:02d}_{dtm.strftime('%Y%m%d_%H%M')}_{host}.ndjson"
    windows.append((start, end, fname))
  windows.sort(key=lambda x: x[0])

  buffers: dict[str, list[str]] = {fn: [] for _, _, fn in windows}

  with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
      rec = parse_json_loose(line)
      if not rec:
        continue
      if host.lower() != "any" and rec.get("proxy_host") != host:
        continue

      dt = None
      ts = rec.get("time_iso8601")
      if ts:
        try:
          dt = parse_time_iso8601(ts)
        except Exception:
          dt = None
      if dt is None:
        tl = rec.get("time_local")
        if tl:
          dt = parse_time_local(tl)
      if dt is None:
        continue

      dt_jst = dt.astimezone(TZ_JST)

      for start, end, fname in windows:
        if start <= dt_jst < end:
          buffers[fname].append(line)

  for _, _, fname in windows:
    out_path = out_dir / fname
    with open(out_path, 'w', encoding='utf-8', errors='ignore') as wf:
      wf.writelines(buffers[fname])
    created.append(out_path)

  return created

def parse_range_jst(s: str | None) -> datetime | None:
  if not s:
    return None
  fmts = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"]
  for fmt in fmts:
    try:
      return datetime.strptime(s, fmt).replace(tzinfo=TZ_JST)
    except Exception:
      pass
  return None
