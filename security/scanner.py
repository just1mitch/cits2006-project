import asyncio
import os
from typing import Dict, List
from yara_engine.YaraEngine_new import YaraEngine

async def start(engine: YaraEngine, monitored: List[str]):
    while True:
        try:
            for_quarantine = await scanner(engine, monitored)
        except Exception as e:
            print(f"Error: {e}")
        await asyncio.sleep(5)

async def scanner(engine: YaraEngine, monitored: List[str]):
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
        should_quarantine = await engine.virus_total_scan(file_path)
        if should_quarantine:
            for_quarantine.append(file_path)
    return for_quarantine

async def quarantiner(dangerous_files: Dict[str, List[str]], quarantine: str):
    for file_path in dangerous_files:
        os.rename(file_path, os.path.join(quarantine, os.path.basename(file_path)))