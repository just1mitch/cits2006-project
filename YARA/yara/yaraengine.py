import os
import argparse
import yara

# Function to scan a file with Yara rules
def scan_file(file_path, yara_rules_path):
    rules = yara.compile(filepath=yara_rules_path)
    #print(f"Scanning {file_path}")
    matches = rules.match(filepath=file_path)
    if matches:
        print(f"Yara match found in {file_path}: {matches}")

# CLI Interface
def main():
    parser = argparse.ArgumentParser(description="Scan files and folders with Yara rules.")
    parser.add_argument("path", help="Path to the file or folder to scan.")
    args = parser.parse_args()

    # Path to scan and load Yara rules
    path = args.path
    yara_rules_path = "yararules.yara"  # Path to Yara rules file
    if os.path.isfile(yara_rules_path):
        print("Yara rules file not found.")
        return

    # Recursively scan files if it's a directory
    if os.path.isfile(path):
        # If it's a single file
        scan_file(path, yara_rules_path)
    elif os.path.isdir(path):
        # Recursively scan all files in the directory
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path, yara_rules_path)
    else:
        print("Invalid path provided. Please provide a valid file or folder path.")

if __name__ == "__main__":
    main()