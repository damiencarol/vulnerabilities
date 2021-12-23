"""This module provide tests in a black box way

It requires that the lib is already installed and reports for semgrep were generated before.
"""

from vulnerabilities.tools.semgrep.parser import parse
from vulnerabilities.sarif import parse as parse_sarif

# JSON ouput
testfile = open("tests/scans/semgrep/latest.json")
success, message, findings = parse(testfile)
findings = list(findings)
assert success, message
assert findings is not None

# SARIF output
testfile = open("tests/scans/sarif/semgrep_latest.sarif")
success, message, findings = parse_sarif(testfile)
findings = list(findings)
assert success, message
assert findings is not None

# test pandas loading
import pandas as pd
df = pd.DataFrame.from_dict(findings)
