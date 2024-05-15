import argparse
from typing import List
import os

from YaraEngine import YaraEngine

DEFAULT_YARA_RULES = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara/yararules/")]

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


    VIRUS_TOTAL_API_KEY = os.environ.get('VIRUS_TOTAL_API_KEY')
    if not VIRUS_TOTAL_API_KEY:
        print("Alert: No VirusTotal API key found. Will not submit file hashes to VirusTotal.")


    yara_engine = YaraEngine(yara_rules, VIRUS_TOTAL_API_KEY)

    for path in monitored:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                if yara_engine.scan(file_path):
                    print(f"Alert: {file_path} matched a YARA rule.")



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
