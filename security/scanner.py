import asyncio
import hashlib
import os
import time
from typing import Dict, List
from encryptor import Encryptor
from yara_engine.YaraEngineClass import YaraEngine
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
        self.quarantine_dir = quarantine

    def quarantine(self, file_path: str):
        hash = hashlib.md5(file_path.encode()).hexdigest()
        new_path = os.path.join(self.quarantine_dir, f"{hash}-" + os.path.basename(file_path))
        print(f"Quarantining {file_path}. Moving from {file_path} to {new_path}")
        os.rename(file_path, new_path)
        #change the file permissions to read-only
        os.chmod(os.path.join(self.quarantine_dir, new_path), 0o400)
        self.add_to_quarantine_file(hash, file_path)

    def unquarantine(self, hash: str):
        with open(self.quarantine_dir + "/.quarantine", "r") as f:
            lines = f.readlines()
        for line in lines:
            if hash in line:
                original_file_path = line.split(" ", maxsplit=1)[1].replace("\n", "")
                print(f"{hash}-" + os.path.basename(original_file_path))
                current_file_path = os.path.join(self.quarantine_dir, f"{hash}-" + os.path.basename(original_file_path))
                os.rename(current_file_path, original_file_path)
                os.chmod(original_file_path, 0o600)
                self.remove_from_quarantine_file(hash)
                return
        print(f"Error: {hash} not found in quarantine file")

    def delete(self, hash: str):
        with open(self.quarantine_dir + "/.quarantine", "r") as f:
            lines = f.readlines()
        for line in lines:
            if hash in line:
                original_file_path = line.split(" ", maxsplit=1)[1].replace("\n", "")
                current_file_path = os.path.join(self.quarantine_dir, f"{hash}-" + os.path.basename(original_file_path))
                os.remove(current_file_path)
                self.remove_from_quarantine_file(hash)
                return
        print(f"Error: {hash} not found in quarantine file")

    def add_to_quarantine_file(self, hash: str, original_file_path: str):
        with open(self.quarantine_dir + "/.quarantine", "a") as f:
            f.write(hash + " " + original_file_path + "\n")

    def remove_from_quarantine_file(self, hash: str):
        with open(self.quarantine_dir + "/.quarantine", "r") as f:
            lines = f.readlines()
        with open(self.quarantine_dir + "/.quarantine", "w") as f:
            for line in lines:
                if hash not in line:
                    f.write(line)
    
    def get_quarantined_files(self):
        return_list = []
        with open(self.quarantine_dir + "/.quarantine", "r") as f:
            for line in f:
                return_list.append((line.split(" ", maxsplit=1)[0], line.split(" ", maxsplit=1)[1]))
        return return_list

async def start(engine: YaraEngine, monitored: List[str], whitelist: Whitelist, quarantine: str, encryptor: Encryptor):
    while True:
        try:
            for_quarantine = await scanner(engine, monitored, whitelist)
            quarantiner = Quarantiner(quarantine)
            for file_path in for_quarantine:
                quarantiner.quarantine(file_path)
            if for_quarantine:
                print("Rotating encryption of sensitive files due to quarantined threat.")
                encryptor.shuffle_encryption()
        except Exception as e:
            print(f"Error: {e}")
        await asyncio.sleep(5)

async def encrypt_unencrypted(encryptor: Encryptor):
    while True:
        try:
            encryptor.encrypt_unencrypted()
        except Exception as e:
            print(f"Error: {e}")
        await asyncio.sleep(5)

async def periodic_shuffle(encryptor: Encryptor):
    while True:
        try:
            encryptor.shuffle_encryption()
        except Exception as e:
            print(f"Error: {e}")
        await asyncio.sleep(86400)

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
