import json
from pathlib import Path
import re
from collections import defaultdict, OrderedDict
from typing import IO

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
    reserved = {"CON","PRN","AUX","NUL","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"}

    if name.upper() in reserved:
      name = f"_{name}_"
    return name

  def _fix_json_line(self, line: str) -> str:
    return re.sub(r',\s*}$', '}', line)

  def classify_by_mode(self, out_file_name: str = "access.log", max_open_files: int = 64) -> dict[str, int]:
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
