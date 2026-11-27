#!/usr/bin/env python3
"""List compiler-recorded helpers and their call sites in one saved Kuna functions inventory."""

import argparse
import json
import sys


def helper_report(inventory, name):
    if inventory["error"] is not None:
        raise ValueError(f"inventory error: {inventory['error']}")
    functions = inventory["functions"]
    if not isinstance(functions, list) or inventory["count"] != len(functions):
        raise ValueError("function list does not match inventory count")

    groups = {}
    caller_counts = []
    for caller in functions:
        count = 0
        for site in caller.get("inline_sites", []):
            if name is not None and name != site["name"]:
                continue
            count += 1
            key = (site["source"], site["id"])
            if key not in groups:
                groups[key] = dict(source=site["source"], id=site["id"], name=site["name"], sites=[])
            helper = groups[key]
            if helper["name"] != site["name"]:
                raise ValueError(f"conflicting names for {key}")
            helper["sites"].append({
                "caller": caller["name"],
                "caller_address": caller["address_hex"],
                "depth": site["depth"],
                "ranges": site["ranges"],
            })

        if count:
            caller_counts.append(dict(caller=caller["name"], address=caller["address_hex"], sites=count))

    for helper in groups.values():
        helper["sites"].sort(key=lambda site: (int(site["caller_address"], 16), site["depth"],
                                               site["ranges"], site["caller"]))
        helper["site_count"] = len(helper["sites"])

    report = {
        "binary": inventory["binary"],
        "inventory_count": len(functions),
        "inventory_total": inventory["total"],
        "helpers": [groups[key] for key in sorted(groups)],
        "caller_counts": sorted(caller_counts, key=lambda row: (int(row["address"], 16), row["caller"])),
    }
    for field in ("limits", "notes"):
        if field in inventory:
            report[field] = inventory[field]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", nargs="?", type=argparse.FileType("r", encoding="utf-8"),
                        default=sys.stdin, help="JSON from kuna functions --json (default: stdin)")
    parser.add_argument("--name", help="return helpers with this exact name")
    args = parser.parse_args()
    try:
        with args.inventory as source:
            report = helper_report(json.load(source), args.name)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        parser.exit(1, f"inline_helpers: invalid inventory: {error}\n")
    try:
        print(json.dumps(report, separators=(",", ":")), flush=True)
    except BrokenPipeError:
        sys.stdout = None


if __name__ == "__main__":
    main()
