import base64
from pathlib import Path
import sys
import urllib

print(urllib.parse.quote(base64.b64encode(Path(Path(__file__).parent, sys.argv[1]).read_bytes()).decode()))
