import json

import requests


def main() -> None:
    print(json.dumps({"requests": requests.__name__}))
