from __future__ import annotations

import argparse
import json
from .detector import detect


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan prompt text with ThreatSight.")
    parser.add_argument("text", help="Prompt text to analyze")
    args = parser.parse_args()
    print(json.dumps({"findings": [item.to_dict() for item in detect(args.text)]}, indent=2))


if __name__ == "__main__":
    main()
