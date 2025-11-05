import json
from pathlib import Path
import re
from collections import defaultdict, OrderedDict
from typing import IO
from datetime import datetime, timezone

class LogEvaluator:
  def __init__(self, log_file: str, mode_key: str = "spring_mode", base_log_dir: str | None = None, encoding: str = "utf-8", errors: str = "replace"):
    self.log_file = Path(log_file)
    self.mode_key = mode_key
    self.base_log_dir = Path(base_log_dir) if base_log_dir else self.log_file.parent.parent
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

  def classify_by_mode(self, out_file_name: str = "access.log", start: datetime | None = None, end: datetime | None = None, max_open_files: int = 64) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)

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

          # Period filter (inclusive). Skip lines without timestamp when a range is set.
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

          if obj.get("request_uri"):
            counts[mode] += 1

    finally:
      for fh in writers.values():
        try:
          fh.close()
        except Exception:
          pass

    return dict(counts)
