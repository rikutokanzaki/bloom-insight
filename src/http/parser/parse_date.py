from datetime import datetime, timezone, timedelta
import re
import argparse

def parse_tz(tz_str: str | None):
  if not tz_str:
    return timezone.utc

  tz = tz_str.strip()

  if tz.upper() in ("UTC", "Z"):
    return timezone.utc

  if tz.lower() == "local":
    now = datetime.now().astimezone()
    return timezone(now.utcoffset() or timedelta(0))

  if tz.upper() in ("JST", "ASIA/TOKYO"):
    return timezone(timedelta(hours=9))

  m = re.fullmatch(r'([+-])(\d{2})(?::?(\d{2}))?', tz)
  if not m:
    raise argparse.ArgumentTypeError(f"Invalid tz offset: {tz_str}")

  sign = 1 if m.group(1) == "+" else -1
  hh = int(m.group(2))
  mm = int(m.group(3) or "0")

  return timezone(sign * timedelta(hours=hh, minutes=mm))

def parse_dt(value: str | None, default_tz) -> datetime | None:
  if not value:
    return None
  s = value.strip()

  if s.isdigit() and len(s) in (12, 14):
    year = int(s[0:4]); month = int(s[4:6]); day = int(s[6:8])
    hour = int(s[8:10]); minute = int(s[10:12])
    second = int(s[12:14]) if len(s) == 14 else 0
    dt = datetime(year, month, day, hour, minute, second, tzinfo=default_tz)
    return dt.astimezone(timezone.utc)

  try:
    return datetime.fromtimestamp(float(s), tz=timezone.utc)
  except ValueError:
    pass

  if s.endswith("Z"):
    s = s[:-1] + "+00:00"

  try:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
      dt = dt.replace(tzinfo=default_tz)
    return dt.astimezone(timezone.utc)
  except Exception as e:
    raise argparse.ArgumentTypeError(f"Invalid datetime: {value}") from e
