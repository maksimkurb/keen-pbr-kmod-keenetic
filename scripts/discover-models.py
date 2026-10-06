#!/usr/bin/env python3
"""Inventory exact Keenetic KN model configs from the pinned SDK."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from model_tools import atomic_json, discover_inventory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        inventory = discover_inventory(args.sdk)
        atomic_json(args.output, inventory)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"model discovery failed: {exc}", file=sys.stderr)
        return 1
    print(f"Found {len(inventory['models'])} pinned SDK models in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
