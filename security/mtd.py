import argparse
import asyncio
import signal
from typing import List
import os
from pathlib import Path


from yara_engine.YaraEngine_new import YaraEngine
from scanner import start

DEFAULT_YARA_RULES = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_engine/yararules/")]
VIRUS_TOTAL_API_KEY = os.environ.get('VIRUS_TOTAL_API_KEY')

def check_paths(paths: List[str]):
    for path in paths:
        if not os.path.isdir(path):
            print(f"Error: {path} is not a valid directory.")
            return False
    return [os.path.abspath(path) for path in paths]

def main(monitored: List[str], sensitive: List[str], yara_rules: List[str] = []):
    monitored = check_paths(monitored)
    sensitive = check_paths(sensitive)
    yara_rules = check_paths((yara_rules if yara_rules else []) + DEFAULT_YARA_RULES)

    if not monitored or not sensitive or not yara_rules:
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
    parser.add_argument('-y', '--yara-rules', nargs='+', help='Path to additional YARA files directories')
    args = parser.parse_args()

    main(args.monitored, args.sensitive, args.yara_rules)
