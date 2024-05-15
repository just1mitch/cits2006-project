import yara


class YaraEngine:
    def __init__(self, rules: list[str], virus_total_key=None):
        self.rules = yara.compile(filepaths=rules)
    
    def scan(self, path: str) -> bool:
        matches = self.rules.match(path)
        return bool(matches)