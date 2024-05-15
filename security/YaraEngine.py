import yara
import os

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