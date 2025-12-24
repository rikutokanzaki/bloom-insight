from pathlib import Path
from analyzer.log_analyzer import ParamikoLogAnalyzer
import json
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    log_file_path = Path(__file__).parents[2] / 'log' / 'tsubomi' / 'paramiko.log'

    if not log_file_path.exists():
        logger.error(f"Log file not found: {log_file_path}")
        return

    try:
        analyzer = ParamikoLogAnalyzer(str(log_file_path))

        logger.info("Parsing log file...")
        analyzer.parse_log_file()

        logger.info("Generating daily statistics by mode...")
        daily_stats = analyzer.get_daily_statistics()

        print("\n=== Daily Statistics by Mode ===")
        print(json.dumps(daily_stats, indent=2, ensure_ascii=False))

        print("\n=== Mode Summary ===")
        mode_summary = analyzer.get_mode_summary()
        print(json.dumps(mode_summary, indent=2, ensure_ascii=False))

        print("\n=== Overall Summary ===")
        total_credentials = 0
        total_commands = 0
        for date_stats in daily_stats.values():
            for mode_stats in date_stats.values():
                total_credentials += mode_stats['credentials_count']
                total_commands += mode_stats['commands_count']

        print(f"Total credentials (all modes): {total_credentials}")
        print(f"Total commands (all modes): {total_commands}")
        print(f"Total days analyzed: {len(daily_stats)}")

    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        raise


if __name__ == '__main__':
    main()
