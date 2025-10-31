import os
import re
import json
from pathlib import Path


# =============================================================
# Load configuration from file
# =============================================================
CONFIG_FILE = "config.json"

try:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)
except Exception as e:
    print(f"[ERROR] Cannot read {CONFIG_FILE}: {e}")
    input("Press Enter to exit...")
    raise SystemExit

# Extract values
BASE_DIR = Path(config.get("base_dir", ""))
TARGET_LOG = config.get("target_log", "installed_programs_registry.txt")
SEARCH_KEYWORDS = config.get("search_keywords", [])

if not BASE_DIR.exists():
    print(f"[ERROR] Base directory does not exist: {BASE_DIR}")
    input("Press Enter to exit...")
    raise SystemExit


# =============================================================
# Main logic
# =============================================================
def find_programs():
    results = {kw: {"found": [], "missing": []} for kw in SEARCH_KEYWORDS}

    for folder in sorted(BASE_DIR.iterdir()):
        if not folder.is_dir():
            continue

        log_path = folder / TARGET_LOG
        if not log_path.exists():
            print(f"[!] Folder {folder.name} does not contain {TARGET_LOG}")
            for kw in SEARCH_KEYWORDS:
                results[kw]["missing"].append(folder.name)
            continue

        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            print(f"[!] Error reading {log_path}")
            continue

        for kw in SEARCH_KEYWORDS:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            if pattern.search(text):
                # Extract matched program names
                full_matches = re.findall(r"Name:\s*(.+)", text, re.IGNORECASE)
                matches = [m for m in full_matches if re.search(pattern, m)]
                results[kw]["found"].append((folder.name, matches))
            else:
                results[kw]["missing"].append(folder.name)

    return results


def print_summary(results):
    print("\n=== Scan summary ===")
    for kw, data in results.items():
        print(f"\n🔹 Keyword: {kw}")
        if data["found"]:
            print(f"  Found in ({len(data['found'])} folders):")
            for name, matches in data["found"]:
                print(f"    {name}: {', '.join(matches) if matches else '(no extracted names)'}")
        else:
            print("  Not found in any folder.")

        if data["missing"]:
            print(f"  Missing in ({len(data['missing'])} folders): {', '.join(data['missing'])}")


def main():
    results = find_programs()
    print_summary(results)

    # Save results to file
    out_path = BASE_DIR / "results_summary.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for kw, data in results.items():
            f.write(f"\n=== {kw} ===\n")
            f.write("Found in:\n")
            for name, matches in data["found"]:
                f.write(f"  {name}: {', '.join(matches)}\n")
            f.write(f"Missing in:\n  {', '.join(data['missing'])}\n")

    print(f"\nResults saved to {out_path}")
    input("Press Enter to exit...")


if __name__ == "__main__":
    main()
