import json
import re
from pathlib import Path
from collections import defaultdict, OrderedDict
from typing import IO
from datetime import datetime, timezone
import bisect

class LogEvaluator:
  def __init__(self, log_file: str, mode_key: str = "spring_mode", base_log_dir: str | None = None, encoding: str = "utf-8", errors: str = "replace"):
    self.log_file = Path(log_file)
    self.mode_key = mode_key
    self.base_log_dir = Path(base_log_dir) if base_log_dir else self.log_file.parents[2]
    self.encoding = encoding
    self.errors = errors

  def _sanitize_mode(self, value) -> str:
    name = str(value).strip() if value is not None else ""
    if not name:
      return "unknown"
    name = re.sub(r'[^A-Za-z0-9._-]+', "_", name)
    return name

  def _fix_json_line(self, line: str) -> str:

    return re.sub(r',\s*}$', '}', line)

  def _extract_uri_from_request_data(self, data: str | None) -> str | None:
    if not data:
      return None
    first = str(data).splitlines()[0].strip()

    m = re.match(r'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?$', first, re.IGNORECASE)
    if m:
      return m.group(2)
    return None

  def _parse_obj_time(self, obj: dict) -> datetime | None:
    t = obj.get("time_iso8601")

    if isinstance(t, str) and t:
      s = t.strip()

      if s.endswith("Z"):
        s = s[:-1] + "+00:00"

      try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
          dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
      except Exception:
        pass

    t = obj.get("time_local")
    if isinstance(t, str) and t:
      try:
        dt = datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
      except Exception:
        pass

    t = obj.get("msec")

    if isinstance(t, str) and t:
      try:
        return datetime.fromtimestamp(float(t), tz=timezone.utc)
      except Exception:
        pass

    return None

  def _parse_access_obj_epoch(self, obj: dict) -> float | None:
    msec = obj.get("msec")
    if isinstance(msec, str) and msec:
      try:
        return float(msec)
      except ValueError:
        pass

    dt = self._parse_obj_time(obj)
    return dt.timestamp() if dt else None

  def _parse_session_timestamp_epoch(self, ts: str) -> float | None:
    try:
      dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
      try:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
      except ValueError:
        return None

    dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()

  def classify_by_mode(
      self,
      out_file_name: str = "access.log",
      start: datetime | None = None,
      end: datetime | None = None,
      max_open_files: int = 64,
      count_policy: str = "uri",
      bucket: str = "none",
      bucket_tz = None
    ):

    if count_policy not in ("uri", "all"):
      raise ValueError("count_policy must be 'uri' or 'all'")
    if bucket not in ("none", "day"):
      raise ValueError("bucket must be 'none' or 'day'")
    if bucket_tz is None:
      bucket_tz = timezone.utc

    if bucket == "day":
      counts = defaultdict(lambda: defaultdict(int))
    else:
      counts = defaultdict(int)

    writers: "OrderedDict[str, IO]" = OrderedDict()
    initialized_modes: set[str] = set()

    def _get_writer(mode: str) -> IO:
      if mode in writers:
        fh = writers.pop(mode)
        writers[mode] = fh
        return fh

      mode_dir = self.base_log_dir / mode
      mode_dir.mkdir(parents=True, exist_ok=True)
      out_path = mode_dir / out_file_name

      file_mode = "w" if mode not in initialized_modes else "a"
      fh = open(out_path, file_mode, encoding="utf-8", newline="\n")
      initialized_modes.add(mode)

      writers[mode] = fh

      if max_open_files and len(writers) > max_open_files:
        evict_mode, evict_fh = writers.popitem(last=False)

        try:
          evict_fh.close()
        except Exception:
          pass
      return fh

    try:
      with open(self.log_file, "rb") as f:
        for raw in f:
          line = raw.decode(self.encoding, errors=self.errors).strip()
          if not line:
            continue

          line = self._fix_json_line(line)

          try:
            obj = json.loads(line)
          except json.JSONDecodeError:
            continue

          ts = self._parse_obj_time(obj)

          if start or end:
            if ts is None:
              continue
            if start and ts < start:
              continue
            if end and ts > end:
              continue

          mode_value = obj.get(self.mode_key, "")
          if not mode_value:

            proxy_host = str(obj.get("proxy_host", ""))
            if "launcher" in proxy_host:
              mode_value = "launcher"

          mode = self._sanitize_mode(mode_value)

          fh = _get_writer(mode)
          fh.write(line)
          fh.write("\n")

          should_count = False
          if count_policy == "all":
            should_count = True
          else:
            uri = obj.get("request_uri") or self._extract_uri_from_request_data(obj.get("request_data"))
            if uri:
              should_count = True

          if not should_count:
            continue

          if bucket == "day":
            if ts is not None:
              day_key = ts.astimezone(bucket_tz).strftime("%Y-%m-%d")
            else:
              day_key = "unknown-date"
            counts[mode][day_key] += 1
          else:
            counts[mode] += 1

    finally:
      for fh in writers.values():
        try:
          fh.close()
        except Exception:
          pass

    if bucket == "day":
      return { m: dict(dmap) for m, dmap in counts.items() }
    return dict(counts)

  def annotate_and_save_sessions(
      self,
      session_file: str,
      time_tolerance: float = 1.0,
      out_file_name: str = "log_session.json",
      bucket: str = "none",
      bucket_tz = timezone.utc
    ) -> dict:

    if bucket not in ("none", "day"):
      raise ValueError("bucket must be 'none' or 'day'")

    access_epochs: list[float] = []
    access_modes: list[str] = []

    with open(self.log_file, "rb") as f:
      for raw in f:
        line = raw.decode(self.encoding, errors=self.errors).strip()

        if not line:
          continue
        line = self._fix_json_line(line)

        try:
          obj = json.loads(line)
        except json.JSONDecodeError:
          continue

        epoch = self._parse_access_obj_epoch(obj)
        if epoch is None:
          continue

        mode_value = obj.get(self.mode_key, "")
        if not mode_value:
          proxy_host = str(obj.get("proxy_host", ""))
          if "launcher" in proxy_host:
            mode_value = "launcher"

        mode = self._sanitize_mode(mode_value)

        access_epochs.append(epoch)
        access_modes.append(mode)

    paired = sorted(zip(access_epochs, access_modes), key=lambda x: x[0])
    access_epochs = [p[0] for p in paired]
    access_modes = [p[1] for p in paired]

    def find_mode_for_epoch(epoch: float) -> str:
      if not access_epochs:
        return "unknown"

      pos = bisect.bisect_left(access_epochs, epoch)
      cand_idx = []

      if pos < len(access_epochs):
        cand_idx.append(pos)
      if pos > 0:
        cand_idx.append(pos - 1)

      best = ("unknown", None)

      for i in cand_idx:
        diff = abs(access_epochs[i] - epoch)
        if diff <= time_tolerance and (best[1] is None or diff < best[1]):
          best = (access_modes[i], diff)

      return best[0]

    writers: dict[str, IO] = {}

    if bucket == "day":
      counts: dict[str, dict[str, dict[str, int]] ] = {}
    else:
      counts: dict[str, dict[str, int]] = {}

    def get_writer(mode: str) -> IO:
      if mode in writers:
        return writers[mode]

      mode_dir = self.base_log_dir / mode
      mode_dir.mkdir(parents=True, exist_ok=True)
      out_path = mode_dir / out_file_name
      fh = open(out_path, "a", encoding="utf-8", newline="\n")
      writers[mode] = fh

      return fh

    try:
      with open(session_file, "r", encoding="utf-8", errors="replace") as sf:
        for line in sf:
          line = line.strip()

          if not line:
            continue

          try:
            obj = json.loads(line)
          except json.JSONDecodeError:
            continue

          ts_str = obj.get("timestamp")
          epoch = self._parse_session_timestamp_epoch(ts_str) if ts_str else None
          mode = find_mode_for_epoch(epoch) if epoch is not None else "unknown"
          obj["mode"] = mode

          attempts = obj.get("auth_attempts") or []
          u_cnt = 0
          p_cnt = 0

          for a in attempts:
            if isinstance(a, dict):
              if a.get("username"):
                u_cnt += 1
              if a.get("password"):
                p_cnt += 1

          if bucket == "day":
            if epoch is not None:
              day_key = datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone(bucket_tz).strftime("%Y-%m-%d")
            else:
              day_key = "unknown-date"

            if mode not in counts:
              counts[mode] = {}

            if day_key not in counts[mode]:
              counts[mode][day_key] = {"usernames": 0, "passwords": 0}
            counts[mode][day_key]["usernames"] += u_cnt
            counts[mode][day_key]["passwords"] += p_cnt

          else:
            if mode not in counts:
              counts[mode] = {"usernames": 0, "passwords": 0}
            counts[mode]["usernames"] += u_cnt
            counts[mode]["passwords"] += p_cnt

          fh = get_writer(mode)
          fh.write(json.dumps(obj, ensure_ascii=False))
          fh.write("\n")

    finally:
      for fh in writers.values():
        try:
          fh.close()
        except Exception:
          pass

    return counts
