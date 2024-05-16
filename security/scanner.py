import asyncio
import os
from typing import List
from yara_engine.YaraEngine_new import YaraEngine

async def start(engine: YaraEngine, monitored: List[str]):
    while True:
        await scanner(engine, monitored)
        await asyncio.sleep(5)

async def scanner(engine: YaraEngine, monitored: List[str]):
    alert = False
    for path in monitored:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                if engine.scan(file_path):
                    alert = True
                    print(f"Alert: {file_path} matched a YARA rule.")
    return alert