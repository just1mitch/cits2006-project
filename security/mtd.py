import argparse
import asyncio
import signal
from typing import List
import os
from pathlib import Path


from yara_engine.YaraEngine_new import YaraEngine
from scanner import start

VIRUS_TOTAL_API_KEY = os.environ.get('VIRUS_TOTAL_API_KEY')

def check_paths(paths: List[str]) -> List[str] | bool:
    for path in paths:
        if not os.path.isdir(path):
            print(f"Error: {path} is not a valid directory.")
            return False
    return [os.path.abspath(path) for path in paths]

def check_quarantine_directory(quarantine: str) -> bool:
    # Check if the quarantine directory is owned by the current user
    if os.stat(quarantine).st_uid != os.getuid():
        print(f"Error: {quarantine} is not owned by the current user.")
        return False

    # Check if only the current user can write, access and execute it
    if os.stat(quarantine).st_mode & 0o777 != 0o700:
        print(f"Error: {quarantine} permissions are not set to 700.")
        return False

    return True

def main(monitored: List[str], sensitive: List[str], quarantine: str, yara_rules: List[str] = [], malicious_threshold: int = 5):
    Path(quarantine).mkdir(parents=False, exist_ok=True)
    monitored = check_paths(monitored)
    sensitive = check_paths(sensitive)
    quarantine = check_paths([quarantine])
    yara_rules = check_paths(yara_rules)

    if not monitored or not sensitive or not yara_rules or not quarantine:
        return
    
    if not VIRUS_TOTAL_API_KEY:
        print("Alert: No VirusTotal API key found. Will not submit file hashes to VirusTotal.")

    yara_engine = YaraEngine(yara_rules, VIRUS_TOTAL_API_KEY)

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, loop.stop)

    try:
        loop.create_task(start(yara_engine, monitored))
        loop.run_forever()
    except KeyboardInterrupt:
        tasks = asyncio.all_tasks(loop=loop)
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        loop.close()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='RapidoBank MTD System',
                    description='Entrypoint for the RapidoBank MTD System',
                    epilog='Created by Daniel Jennings (23064976), Isobelle Scott (23105336)... ')
    parser.add_argument('-m', '--monitored', nargs='+', required=True,
                        help='Monitored directories')
    parser.add_argument('-s', '--sensitive', nargs='+', required=True,
                        help='Sensitive directories')
    parser.add_argument('-q', '--quarantine', nargs='?', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine"), help='Quarantine directory')
    parser.add_argument('-y', '--yara-rules', nargs='+', default=[os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_engine/yararules")], help='Path to additional YARA files directories')
    parser.add_argument('--malicious-threshold', type=int, default=5, help='Threshold for the number of VirusTotal providers that must flag a file as malicious before quarantining action is taken.')
    args = parser.parse_args()
    main(args.monitored, args.sensitive, args.quarantine, args.yara_rules, args.malicious_threshold)
