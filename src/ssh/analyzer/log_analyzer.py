from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict
import json
import logging

logger = logging.getLogger(__name__)


class ParamikoLogAnalyzer:
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.daily_stats: Dict[str, Dict[str, Dict]] = defaultdict(
            lambda: defaultdict(lambda: {
                'credentials': set(),
                'commands': []
            })
        )

    def parse_log_file(self) -> None:
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        log_entry = json.loads(line)
                        self._process_log_entry(log_entry)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse log line: {e}")
                        continue
        except FileNotFoundError:
            logger.error(f"Log file not found: {self.log_file_path}")
            raise
        except Exception as e:
            logger.error(f"Error reading log file: {e}")
            raise

    def _process_log_entry(self, log_entry: Dict) -> None:
        timestamp_str = log_entry.get('timestamp')
        eventid = log_entry.get('eventid')
        mode = log_entry.get('mode', 'unknown')

        if not timestamp_str:
            return

        date = self._extract_date(timestamp_str)
        if not date:
            return

        if eventid == 'paramiko.login.attempt':
            self._process_login_attempt(log_entry, date, mode)
        elif eventid == 'paramiko.command.input':
            self._process_command(log_entry, date, mode)

    def _extract_date(self, timestamp_str: str) -> str:
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d')
        except (ValueError, AttributeError):
            logger.warning(f"Invalid timestamp format: {timestamp_str}")
            return None

    def _process_login_attempt(self, log_entry: Dict, date: str, mode: str) -> None:
        username = log_entry.get('username')
        password = log_entry.get('password')

        if username and password:
            credential = (username, password)
            self.daily_stats[date][mode]['credentials'].add(credential)

    def _process_command(self, log_entry: Dict, date: str, mode: str) -> None:
        command = log_entry.get('command')
        if command:
            self.daily_stats[date][mode]['commands'].append(command)

    def get_daily_statistics(self) -> Dict[str, Dict[str, Dict[str, int]]]:
        result = {}
        for date in sorted(self.daily_stats.keys()):
            result[date] = {}
            for mode in sorted(self.daily_stats[date].keys()):
                stats = self.daily_stats[date][mode]
                result[date][mode] = {
                    'credentials_count': len(stats['credentials']),
                    'commands_count': len(stats['commands'])
                }
        return result

    def get_detailed_statistics(self) -> Dict[str, Dict[str, Dict]]:
        result = {}
        for date in sorted(self.daily_stats.keys()):
            result[date] = {}
            for mode in sorted(self.daily_stats[date].keys()):
                stats = self.daily_stats[date][mode]
                result[date][mode] = {
                    'credentials_count': len(stats['credentials']),
                    'credentials': [
                        {'username': cred[0], 'password': cred[1]}
                        for cred in sorted(stats['credentials'])
                    ],
                    'commands_count': len(stats['commands']),
                    'commands': stats['commands']
                }
        return result

    def get_mode_summary(self) -> Dict[str, Dict[str, int]]:
        mode_summary = defaultdict(lambda: {'credentials': set(), 'commands_count': 0})

        for date_stats in self.daily_stats.values():
            for mode, stats in date_stats.items():
                mode_summary[mode]['credentials'].update(stats['credentials'])
                mode_summary[mode]['commands_count'] += len(stats['commands'])

        result = {}
        for mode in sorted(mode_summary.keys()):
            result[mode] = {
                'total_credentials': len(mode_summary[mode]['credentials']),
                'total_commands': mode_summary[mode]['commands_count']
            }
        return result
