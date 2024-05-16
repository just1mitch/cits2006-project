import asyncio
import os
from typing import Dict, List
from yara_engine.YaraEngine_new import YaraEngine

async def start(engine: YaraEngine, monitored: List[str]):
    while True:
        try:
            await scanner(engine, monitored)
        except Exception as e:
            print(f"Error: {e}")
        await asyncio.sleep(5)

async def scanner(engine: YaraEngine, monitored: List[str]):
    dangerous_files: Dict[str, List[str]] = {}
    files_to_upload = []
    for path in monitored:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_result = engine.scan(file_path)
                if scan_result:
                    dangerous_files[file_path] = scan_result
                    files_to_upload.append(file_path)
                    print(f"Alert: {file_path} matched a YARA rules {scan_result}")
    for file_path in files_to_upload:
        await engine.virus_total_scan(file_path)
    return dangerous_files