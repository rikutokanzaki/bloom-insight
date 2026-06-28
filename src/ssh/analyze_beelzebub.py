#!/usr/bin/env python3
"""Analyze beelzebub-style logs and estimate OpenAI API token usage.

The script is intentionally defensive:
- It accepts JSON arrays, JSON objects, and JSONL/NDJSON logs.
- It prefers explicit usage fields when they exist.
- When token counts are not present, it estimates them from text content.
- It skips repeated commands within the same session to model cache hits.

Usage examples:
  python src/ssh/analyze_beelzebub.py path/to/beelzebub.json
  python src/ssh/analyze_beelzebub.py path/to/beelzebub.json --top 20
  python src/ssh/analyze_beelzebub.py path/to/beelzebub.json --json report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


INPUT_KEYS = (
  "input",
  "prompt",
  "question",
  "query",
  "instruction",
  "command",
  "Command",
  "user_input",
  "user_message",
  "text",
)

OUTPUT_KEYS = (
  "output",
  "response",
  "completion",
  "answer",
  "generated_text",
  "assistant_message",
  "model_output",
  "CommandOutput",
)

SESSION_KEYS = (
  "session",
  "session_id",
  "conversation_id",
  "chat_id",
  "uuid",
  "trace_id",
  "ID",
)

USAGE_TOKEN_KEYS = {
  "prompt_tokens": "prompt_tokens",
  "completion_tokens": "completion_tokens",
  "total_tokens": "total_tokens",
  "input_tokens": "prompt_tokens",
  "output_tokens": "completion_tokens",
}


@dataclass
class Usage:
  prompt_tokens: int = 0
  completion_tokens: int = 0
  total_tokens: int = 0
  prompt_chars: int = 0
  completion_chars: int = 0
  total_chars: int = 0
  explicit: bool = False

  def add(self, other: "Usage") -> None:
    self.prompt_tokens += other.prompt_tokens
    self.completion_tokens += other.completion_tokens
    self.total_tokens += other.total_tokens
    self.prompt_chars += other.prompt_chars
    self.completion_chars += other.completion_chars
    self.total_chars += other.total_chars
    self.explicit = self.explicit or other.explicit


@dataclass
class RecordResult:
  index: int
  session_id: str
  prompt_text: str
  response_text: str
  prompt_preview: str
  response_preview: str
  usage: Usage
  counted: bool
  skip_reason: str
  source_keys: List[str] = field(default_factory=list)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description="Analyze beelzebub logs and estimate OpenAI API token usage."
  )
  parser.add_argument(
    "path",
    nargs="?",
    default="../../log/raw/beelzebub/beelzebub.json",
    help="Path to the beelzebub log file.",
  )
  parser.add_argument(
    "--encoding",
    default="o200k_base",
    help="Tokenizer encoding name used for estimation when tiktoken is available.",
  )
  parser.add_argument(
    "--top",
    type=int,
    default=10,
    help="Number of sessions to show in the ranked summary.",
  )
  parser.add_argument(
    "--json",
    dest="json_output",
    default=None,
    help="Write the full report to this JSON file.",
  )
  parser.add_argument(
    "--merged-input-file",
    default=None,
    help="Write the merged input strings for counted records to this text file.",
  )
  parser.add_argument(
    "--merged-output-file",
    default=None,
    help="Write the merged output strings for counted records to this text file.",
  )
  return parser.parse_args(argv)


def load_json_records(path: Path) -> List[Any]:
  raw = path.read_text(encoding="utf-8", errors="replace").strip()
  if not raw:
    return []

  try:
    payload = json.loads(raw)
  except json.JSONDecodeError:
    payload = None

  if payload is not None:
    return normalize_payload(payload)

  records: List[Any] = []
  for line in raw.splitlines():
    line = line.strip()
    if not line:
      continue
    try:
      records.append(json.loads(line))
    except json.JSONDecodeError:
      continue
  return records


def normalize_payload(payload: Any) -> List[Any]:
  if isinstance(payload, list):
    return payload

  if isinstance(payload, dict):
    for key in ("records", "events", "items", "logs", "data", "sessions"):
      value = payload.get(key)
      if isinstance(value, list):
        return value
    return [payload]

  return [payload]


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


def first_text(record: Dict[str, Any], keys: Iterable[str]) -> str:
  for key in keys:
    if key not in record:
      continue
    value = record.get(key)
    text = as_text(value).strip()
    if text:
      return text
  return ""


def short_preview(text: str, width: int = 180) -> str:
  text = " ".join(text.split())
  if len(text) <= width:
    return text
  return text[: max(0, width - 1)].rstrip() + "…"


def find_session_id(record: Dict[str, Any]) -> str:
  for key in SESSION_KEYS:
    value = record.get(key)
    if value not in (None, ""):
      return str(value)

  event = record.get("event")
  if isinstance(event, dict):
    for key in SESSION_KEYS:
      value = event.get(key)
      if value not in (None, ""):
        return str(value)

  return "unknown"


def try_extract_usage(record: Dict[str, Any]) -> Optional[Usage]:
  usage = Usage()
  found = False

  for key, attr in USAGE_TOKEN_KEYS.items():
    value = record.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
      setattr(usage, attr, int(value))
      found = True

  usage_block = record.get("usage")
  if isinstance(usage_block, dict):
    for key, attr in USAGE_TOKEN_KEYS.items():
      value = usage_block.get(key)
      if isinstance(value, (int, float)) and not isinstance(value, bool):
        setattr(usage, attr, int(value))
        found = True

  event = record.get("event")
  if isinstance(event, dict):
    for key, attr in USAGE_TOKEN_KEYS.items():
      value = event.get(key)
      if isinstance(value, (int, float)) and not isinstance(value, bool):
        setattr(usage, attr, int(value))
        found = True

    usage_block = event.get("usage")
    if isinstance(usage_block, dict):
      for key, attr in USAGE_TOKEN_KEYS.items():
        value = usage_block.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
          setattr(usage, attr, int(value))
          found = True

  if not found:
    return None

  if usage.total_tokens <= 0:
    usage.total_tokens = usage.prompt_tokens + usage.completion_tokens
  usage.explicit = True
  return usage


def get_token_counter(encoding_name: str):
  try:
    import tiktoken  # type: ignore
  except Exception:
    return None

  try:
    encoding = tiktoken.get_encoding(encoding_name)
  except Exception:
    try:
      encoding = tiktoken.get_encoding("o200k_base")
    except Exception:
      return None

  def count(text: str) -> int:
    return len(encoding.encode(text))

  return count


def estimate_text_tokens(text: str, counter) -> int:
  if not text:
    return 0
  if counter is not None:
    return counter(text)
  raise RuntimeError("tiktoken is required to estimate token counts")


def estimate_message_tokens(text: str, counter) -> int:
  return estimate_text_tokens(text, counter)


def normalize_command(text: str) -> str:
  return " ".join(text.split()).strip()


def analyze_record(index: int, record: Any, counter) -> RecordResult:
  if not isinstance(record, dict):
    text = as_text(record)
    chars = len(text)
    usage = Usage(
      prompt_tokens=estimate_message_tokens(text, counter),
      completion_tokens=0,
      total_tokens=estimate_message_tokens(text, counter),
      prompt_chars=chars,
      completion_chars=0,
      total_chars=chars,
      explicit=False,
    )
    return RecordResult(
      index=index,
      session_id="unknown",
      prompt_text=text,
      response_text="",
      prompt_preview=short_preview(text),
      response_preview="",
      usage=usage,
      counted=True,
      skip_reason="",
      source_keys=[],
    )

  explicit_usage = try_extract_usage(record)
  session_id = find_session_id(record)
  event = record.get("event")
  payload = event if isinstance(event, dict) else record

  prompt = first_text(payload, INPUT_KEYS)
  response = first_text(payload, OUTPUT_KEYS)
  source_keys: List[str] = []

  if prompt:
    source_keys.append("input")
  if response:
    source_keys.append("output")

  if (not prompt and not response) and isinstance(payload.get("messages"), list):
    user_parts: List[str] = []
    assistant_parts: List[str] = []
    for item in payload["messages"]:
      if not isinstance(item, dict):
        continue
      role = str(item.get("role", "")).lower()
      content = as_text(item.get("content")).strip()
      if not content:
        continue
      if role in ("user", "system", "tool"):
        user_parts.append(content)
      elif role in ("assistant", "developer"):
        assistant_parts.append(content)
    prompt = "\n".join(user_parts).strip()
    response = "\n".join(assistant_parts).strip()
    if prompt:
      source_keys.append("messages.user")
    if response:
      source_keys.append("messages.assistant")

  if not prompt and not response:
    prompt, response = _extract_openai_chat_payload(payload)
    if prompt:
      source_keys.append("openai.messages.user")
    if response:
      source_keys.append("openai.messages.assistant")

  if not prompt:
    prompt = _recursive_pick_text(payload, INPUT_KEYS)
  if not response:
    response = _recursive_pick_text(payload, OUTPUT_KEYS)

  prompt_chars = len(prompt)
  completion_chars = len(response)

  if explicit_usage is not None:
    usage = explicit_usage
    usage.prompt_chars = prompt_chars
    usage.completion_chars = completion_chars
    usage.total_chars = prompt_chars + completion_chars
  else:
    prompt_tokens = estimate_message_tokens(prompt, counter)
    completion_tokens = estimate_message_tokens(response, counter)
    usage = Usage(
      prompt_tokens=prompt_tokens,
      completion_tokens=completion_tokens,
      total_tokens=prompt_tokens + completion_tokens,
      prompt_chars=prompt_chars,
      completion_chars=completion_chars,
      total_chars=prompt_chars + completion_chars,
      explicit=False,
    )

  return RecordResult(
    index=index,
    session_id=session_id,
    prompt_text=prompt,
    response_text=response,
    prompt_preview=short_preview(prompt),
    response_preview=short_preview(response),
    usage=usage,
    counted=True,
    skip_reason="",
    source_keys=source_keys,
  )


def _extract_openai_chat_payload(record: Dict[str, Any]) -> Tuple[str, str]:
  prompt_parts: List[str] = []
  response_parts: List[str] = []

  for key in ("input", "messages", "prompt", "conversation"):
    value = record.get(key)
    if isinstance(value, list):
      for item in value:
        if not isinstance(item, dict):
          continue
        role = str(item.get("role", "")).lower()
        content = as_text(item.get("content")).strip()
        if not content:
          continue
        if role in ("user", "system", "tool"):
          prompt_parts.append(content)
        elif role in ("assistant", "developer"):
          response_parts.append(content)

  choices = record.get("choices")
  if isinstance(choices, list):
    for choice in choices:
      if not isinstance(choice, dict):
        continue
      message = choice.get("message")
      if isinstance(message, dict):
        content = as_text(message.get("content")).strip()
        if content:
          response_parts.append(content)
      text = as_text(choice.get("text")).strip()
      if text:
        response_parts.append(text)

  return "\n".join(prompt_parts).strip(), "\n".join(response_parts).strip()


def _recursive_pick_text(value: Any, keys: Iterable[str], depth: int = 0, max_depth: int = 4) -> str:
  if depth > max_depth:
    return ""

  if isinstance(value, dict):
    for key in keys:
      if key in value:
        text = as_text(value.get(key)).strip()
        if text:
          return text
    for nested in value.values():
      text = _recursive_pick_text(nested, keys, depth + 1, max_depth)
      if text:
        return text
    return ""

  if isinstance(value, list):
    for item in value:
      text = _recursive_pick_text(item, keys, depth + 1, max_depth)
      if text:
        return text

  return ""


def select_counted_records(results: List[RecordResult]) -> Tuple[List[RecordResult], int]:
  counted: List[RecordResult] = []
  skipped = 0
  seen_commands_by_session: Dict[str, set[str]] = defaultdict(set)

  for result in results:
    command_key = normalize_command(result.prompt_text)
    if not command_key:
      result.counted = False
      result.skip_reason = "empty command"
      skipped += 1
      continue

    seen_commands = seen_commands_by_session[result.session_id]
    if command_key in seen_commands:
      result.counted = False
      result.skip_reason = "cached duplicate command in same session"
      skipped += 1
      continue

    seen_commands.add(command_key)
    result.counted = True
    result.skip_reason = ""
    counted.append(result)

  return counted, skipped


def summarize(results: List[RecordResult]) -> Dict[str, Any]:
  counted_results, skipped_count = select_counted_records(results)
  totals = Usage()
  explicit_count = 0
  sessions: Dict[str, Usage] = defaultdict(Usage)
  skipped_reasons: Dict[str, int] = defaultdict(int)

  for result in results:
    if not result.counted and result.skip_reason:
      skipped_reasons[result.skip_reason] += 1

  for result in counted_results:
    totals.add(result.usage)
    if result.usage.explicit:
      explicit_count += 1
    sessions[result.session_id].add(result.usage)

  ranked_sessions = sorted(
    sessions.items(),
    key=lambda item: (item[1].total_tokens, item[1].prompt_tokens, item[0]),
    reverse=True,
  )

  return {
    "records": len(results),
    "counted_records": len(counted_results),
    "skipped_records": skipped_count,
    "skipped_reasons": dict(sorted(skipped_reasons.items(), key=lambda item: item[0])),
    "explicit_usage_records": explicit_count,
    "estimated_prompt_tokens": totals.prompt_tokens,
    "estimated_completion_tokens": totals.completion_tokens,
    "estimated_total_tokens": totals.total_tokens,
    "estimated_prompt_chars": totals.prompt_chars,
    "estimated_completion_chars": totals.completion_chars,
    "estimated_total_chars": totals.total_chars,
    "sessions": {
      session_id: {
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens,
        "prompt_chars": usage.prompt_chars,
        "completion_chars": usage.completion_chars,
        "total_chars": usage.total_chars,
        "explicit": usage.explicit,
      }
      for session_id, usage in ranked_sessions
    },
    "ranked_sessions": [
      {
        "session_id": session_id,
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens,
        "prompt_chars": usage.prompt_chars,
        "completion_chars": usage.completion_chars,
        "total_chars": usage.total_chars,
        "explicit": usage.explicit,
      }
      for session_id, usage in ranked_sessions
    ],
  }


def build_merged_text(results: List[RecordResult]) -> Tuple[str, str]:
  counted_results, _ = select_counted_records(results)
  merged_input = "\n".join(result.prompt_text for result in counted_results if result.prompt_text)
  merged_output = "\n".join(result.response_text for result in counted_results if result.response_text)
  return merged_input, merged_output


def _first_nonempty_result(results: List[RecordResult]) -> List[RecordResult]:
  return [
    result
    for result in results
    if result.counted and (result.usage.total_tokens > 0 or result.prompt_preview or result.response_preview)
  ]


def print_report(results: List[RecordResult], summary: Dict[str, Any], top_n: int) -> None:
  print("Beelzebub token analysis")
  print(f"Records: {summary['records']}")
  print(f"Counted records: {summary['counted_records']}")
  print(f"Skipped records: {summary['skipped_records']}")
  if summary["skipped_reasons"]:
    print("Skipped reasons:")
    for reason, count in summary["skipped_reasons"].items():
      print(f"- {reason}: {count}")
  print(f"Records with explicit usage: {summary['explicit_usage_records']}")
  print(f"Estimated prompt tokens: {summary['estimated_prompt_tokens']}")
  print(f"Estimated completion tokens: {summary['estimated_completion_tokens']}")
  print(f"Estimated total tokens: {summary['estimated_total_tokens']}")
  print(f"Estimated prompt chars: {summary['estimated_prompt_chars']}")
  print(f"Estimated completion chars: {summary['estimated_completion_chars']}")
  print(f"Estimated total chars: {summary['estimated_total_chars']}")
  print()
  print(f"Top {min(top_n, len(summary['ranked_sessions']))} sessions by estimated total tokens:")

  for item in summary["ranked_sessions"][:top_n]:
    print(
      f"- {item['session_id']}: total={item['total_tokens']} "
      f"prompt={item['prompt_tokens']} completion={item['completion_tokens']} "
      f"chars_in={item['prompt_chars']} chars_out={item['completion_chars']} "
      f"explicit={item['explicit']}"
    )

  print()
  print("Sample records:")
  sample_results = _first_nonempty_result(results)
  if not sample_results:
    sample_results = results
  for result in sample_results[: min(5, len(sample_results))]:
    print(
      f"- #{result.index} session={result.session_id} "
      f"prompt={result.usage.prompt_tokens} completion={result.usage.completion_tokens} "
      f"total={result.usage.total_tokens} "
      f"chars_in={result.usage.prompt_chars} chars_out={result.usage.completion_chars}"
    )
    if result.prompt_preview:
      print(f"  prompt: {result.prompt_preview}")
    if result.response_preview:
      print(f"  response: {result.response_preview}")
    if result.skip_reason:
      print(f"  skip_reason: {result.skip_reason}")


def main(argv: Sequence[str]) -> int:
  args = parse_args(argv)
  path = Path(args.path)

  if not path.exists():
    print(f"Input file not found: {path}", file=sys.stderr)
    return 1

  counter = get_token_counter(args.encoding)
  if counter is None:
    print("tiktoken is required, but it could not be imported or initialized.", file=sys.stderr)
    return 1

  records = load_json_records(path)
  results = [analyze_record(index + 1, record, counter) for index, record in enumerate(records)]
  summary = summarize(results)
  merged_input, merged_output = build_merged_text(results)

  print_report(results, summary, args.top)

  merged_input_path = Path(args.merged_input_file) if args.merged_input_file else path.with_name(f"{path.stem}.merged_prompt.txt")
  merged_output_path = Path(args.merged_output_file) if args.merged_output_file else path.with_name(f"{path.stem}.merged_response.txt")
  merged_input_path.write_text(merged_input, encoding="utf-8")
  merged_output_path.write_text(merged_output, encoding="utf-8")

  if args.json_output:
    output_path = Path(args.json_output)
    payload = {
      "input_path": str(path),
      "encoding": args.encoding,
      "summary": summary,
      "merged_input_file": str(merged_input_path),
      "merged_output_file": str(merged_output_path),
      "records": [
        {
          "index": result.index,
          "session_id": result.session_id,
          "prompt_text": result.prompt_text,
          "response_text": result.response_text,
          "prompt_preview": result.prompt_preview,
          "response_preview": result.response_preview,
          "usage": {
            "prompt_tokens": result.usage.prompt_tokens,
            "completion_tokens": result.usage.completion_tokens,
            "total_tokens": result.usage.total_tokens,
            "prompt_chars": result.usage.prompt_chars,
            "completion_chars": result.usage.completion_chars,
            "total_chars": result.usage.total_chars,
            "explicit": result.usage.explicit,
          },
          "counted": result.counted,
          "skip_reason": result.skip_reason,
          "source_keys": result.source_keys,
        }
        for result in results
      ],
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

  return 0


if __name__ == "__main__":
  raise SystemExit(main(sys.argv[1:]))
