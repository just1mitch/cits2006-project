import argparse
import asyncio
import signal
from typing import List
import os
import vt
from pathlib import Path
import json
import hashlib


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

def md5_hash_file(file_path):
    """Calculate the MD5 hash of a file."""
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Uses VirusTotal API to scan a malicious file passed by file_path
def virus_total_scan(file_path):
    print(f"\nGetting scan results for {file_path} (may take up to 5 minutes)")
    # See if file has been scanned recently - if so, use that info instead
    hash = md5_hash_file(file_path)
    with vt.Client(VIRUS_TOTAL_API_KEY) as vt_client:
        try:
            scan = vt_client.get_json(f"/files/{hash}")
        except vt.error.APIError:
            # If the file hasn't been scanned, send it for scanning
            with open(f"{file_path}", "rb") as f:
                vt_client.scan_file(f, wait_for_completion=True)
            scan = vt_client.get_json(f"/files/{hash}")

    attributes = scan["data"]["attributes"]
    Path(os.path.abspath('./scan_results')).mkdir(exist_ok=True)
    save_path = f"{os.path.abspath('./scan_results')}/{attributes['md5']}.json"
    print(f"""Scan Results:\nName: {attributes["meaningful_name"]}\nAnalysis Stats: {attributes["last_analysis_stats"]}\nFull Analysis saved to {save_path}\n""")
    with open(save_path, 'w') as f:
        json.dump(scan, f, indent=4)

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
