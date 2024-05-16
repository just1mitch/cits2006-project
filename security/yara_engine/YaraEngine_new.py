import yara
import os
import vt
import json
from pathlib import Path
import sys
from cryptography.include.hashes.md5 import MD5


class YaraEngine:
    def __init__(self, rule_directories: list[str], virus_total_key=None):
        self.rules = {}

        for directory in rule_directories:
            yara_files = [f for f in os.listdir(directory) if f.endswith('.yar') or f.endswith('.yara')]
            for yara_file in yara_files:
                file_path = os.path.join(directory, yara_file)
                self.rules[yara_file] = yara.compile(filepath=file_path)

        self.virus_total_key = virus_total_key
    
    def scan(self, path: str) -> bool:
        for i, rule in enumerate(self.rules):
            matches = self.rules[rule].match(filepath=path)
            if matches:
                return True
        return False
    
    # Uses VirusTotal API to scan a malicious file passed by file_path
    def virus_total_scan(self, file_path):
        print(f"\nGetting scan results for {file_path} (may take up to 5 minutes)")
        # See if file has been scanned recently - if so, use that info instead
        hash = MD5(file_path)
        with vt.Client(self.virus_total_key) as vt_client:
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