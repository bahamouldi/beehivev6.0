import re
from waf.rules_extended import CACHE_POISONING

target_header = "x-forwarded-host:secure.idts.dpc.com.tn"
target_header_space = "x-forwarded-host: secure.idts.dpc.com.tn"

print(f"Testing target: '{target_header}'")

for pattern in CACHE_POISONING:
    regex = re.compile(pattern, re.IGNORECASE)
    if regex.search(target_header):
        print(f"MATCH: {pattern}")
    if regex.search(target_header_space):
        print(f"MATCH (space): {pattern}")

print("Done.")
