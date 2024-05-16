import asyncio
import hashlib
import os
import time
from typing import Dict, List
from yara_engine.YaraEngine_new import YaraEngine
import datetime

class Whitelist:
    def __init__(self, whitelist: str):
        self.whitelist = whitelist


    def check_hash(self, hash: str) -> bool | tuple[str, str]:
        with open(self.whitelist, "r") as f:
            for line in f:
                if hash in line:
                    timestamp = line.split(" ")[2]
                    malicious_count = int(line.split(" ")[1])
                    date = datetime.datetime.fromtimestamp(int(timestamp))
                    return (malicious_count, date)
        return False
    
    def add_hash(self, hash: str, malicious_count: int):
        if not self.check_hash(hash):
            with open(self.whitelist, "a") as f:
                timestamp = str(int(time.time()))
                malicious_count = str(malicious_count)
                f.write(hash + " " + malicious_count + " " + timestamp + "\n")

    def hash_file(self, file_path: str) -> str:
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()

class Quarantiner:
    def __init__(self, quarantine: str):
        self.quarantine = quarantine

    def quarantine(self, file_path: str):
        hash = hashlib.md5(file_path.encode()).hexdigest()
        new_path = os.path.join(self.quarantine, f"{hash}-" + os.path.basename(file_path))
        print(f"Quarantining {file_path}. Moving from {file_path} to {new_path}")
        os.rename(file_path, new_path)
        #change the file permissions to read-only
        os.chmod(os.path.join(self.quarantine, new_path), 0o400)
        self.add_to_quarantine_file(hash, file_path)

    def unquarantine(self, hash: str):
        with open(self.quarantine, "r") as f:
            lines = f.readlines()
        for line in lines:
            if hash in line:
                original_file_path = line.split(" ")[1]
                new_path = os.path.join(os.path.dirname(original_file_path), os.path.basename(original_file_path).split("-")[1])
                os.rename(original_file_path, new_path)
                os.chmod(new_path, 0o600)
                self.remove_from_quarantine_file(hash)
                return
        print(f"Error: {hash} not found in quarantine file")

    def add_to_quarantine_file(self, hash: str, original_file_path: str):
        with open(self.quarantine, "a") as f:
            f.write(hash + " " + original_file_path + "\n")

    def remove_from_quarantine_file(self, hash: str):
        with open(self.quarantine, "r") as f:
            lines = f.readlines()
        with open(self.quarantine, "w") as f:
            for line in lines:
                if hash not in line:
                    f.write(line)

async def start(engine: YaraEngine, monitored: List[str], whitelist: Whitelist, quarantine: str):
    while True:
        try:
            for_quarantine = await scanner(engine, monitored, whitelist)
            quarantiner = Quarantiner(quarantine)
            for file_path in for_quarantine:
                quarantiner.quarantine(file_path)
        except Exception as e:
            print(f"Error: {e}")
        await asyncio.sleep(5)

async def scanner(engine: YaraEngine, monitored: List[str], whitelist: Whitelist):
    dangerous_files: Dict[str, List[str]] = {}
    for_quarantine = []
    for path in monitored:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_result = engine.scan(file_path)
                if scan_result:
                    dangerous_files[file_path] = scan_result
                    print(f"Alert: {file_path} matched a YARA rules {scan_result}")
    for _, file_path in enumerate(dangerous_files):
        file_hash = whitelist.hash_file(file_path)
        if not whitelist.check_hash(file_hash):
            should_quarantine = await engine.virus_total_scan(file_path)
            if should_quarantine[0]:
                for_quarantine.append(file_path)
            else:
                whitelist.add_hash(file_hash, should_quarantine[1])
    return for_quarantine
