import asyncio
import os
from typing import Dict, List
from yara_engine.YaraEngine_new import YaraEngine

async def start(engine: YaraEngine, monitored: List[str]):
    while True:
        await scanner(engine, monitored)
        await asyncio.sleep(5)

async def scanner(engine: YaraEngine, monitored: List[str]):
    dangerous_files: Dict[str, List[str]] = {}
    for path in monitored:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_result = engine.scan(file_path)
                if scan_result:
                    dangerous_files[file_path] = scan_result
                    print(f"Alert: {file_path} matched a YARA rules {scan_result}")
    return dangerous_files