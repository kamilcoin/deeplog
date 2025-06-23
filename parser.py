import re
import pandas as pd

def parse_log(filepath):
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\w+) (?P<url>[^ ]+)'
    logs = []
    with open(filepath, 'r', encoding='utf-8') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                logs.append(match.groupdict())

    return pd.DataFrame(logs)
