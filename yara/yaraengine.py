import os
import argparse
import yara
import platform
import ctypes

WIN_FILE_ATTRIBUTE_HIDDEN = 0x02

yararules_dir = "yararules"
MALWARE_YARA = os.path.abspath(os.path.join(yararules_dir, "malware.yara"))
SENSINFO_YARA = os.path.abspath(os.path.join(yararules_dir, "sensitiveinfo.yara"))
SCRIPTS_YARA = os.path.abspath(os.path.join(yararules_dir, "scripts.yara"))
NETWORK_YARA = os.path.abspath(os.path.join(yararules_dir, "netresource.yara"))
MALURL_YARA = os.path.abspath(os.path.join(yararules_dir, "malURL.yara"))
CUSTOMSIGN_YARA = os.path.abspath(os.path.join(yararules_dir, "customsignature.yara"))


def check_yaras():
    flag = 0
    if not os.path.isfile(MALWARE_YARA):
        print(f"Malware yara rules file not found. Please check {MALWARE_YARA} exists")
        flag = 1
    if not os.path.isfile(SENSINFO_YARA):
        print(f"Sensitive Info yara rules file not found. Please check {SENSINFO_YARA} exists")
        flag = 1
    if not os.path.isfile(SCRIPTS_YARA):
        print(f"Scripting yara rules file not found. Please check {SCRIPTS_YARA} exists")
        flag = 1
    if not os.path.isfile(NETWORK_YARA):
        print(f"Network usage yara rules file not found. Please check {NETWORK_YARA} exists")
        flag = 1
    if not os.path.isfile(MALURL_YARA):
        print(f"Malicious URL yara rules file not found. Please check {MALURL_YARA} exists")
        flag = 1
    if not os.path.isfile(CUSTOMSIGN_YARA):
        print(f"Custom signatures yara rules file not found. Please check {CUSTOMSIGN_YARA} exists")
        flag = 1
    return flag

# Function to scan a file with Yara rules
def scan_file(file_path, yara_rules_path):
    rules = yara.compile(filepath=yara_rules_path)
    #print(f"Scanning {file_path}")
    matches = rules.match(filepath=file_path)
    if matches:
        print(f"Yara match found in {file_path}: {matches}")

# Function to determine if a file is hidden
# Returns 1 on hidden, 0 on visible
def is_hidden(file_path):
    '''Function to determine if a file is hidden
    Returns 1 on hidden, 0 on visible'''
    if platform.system() == "Windows":
        attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
        return attrs != -1 and (attrs & WIN_FILE_ATTRIBUTE_HIDDEN) != 0
    else:
        # For Unix-based systems
        return os.path.basename(file_path).startswith(".")
    
# Function to determine if a file is an executable or not
# Returns 1 on executable, 0 on not-executable
def is_executable(file_path):
    '''Function to determine if a file is executable
    Returns 1 on executable, 0 on not-executable'''
    if platform.system() == "Windows":
        return 1
    elif platform.system() == "Linux":
        is_executable = os.access(file_path, os.X_OK)

# CLI Interface
def main():
    print("Current working directory:", os.getcwd())
    if check_yaras():
        return
    parser = argparse.ArgumentParser(description="Scan files and folders with Yara rules.")
    parser.add_argument("path", help="Path to the file or folder to scan.")
    args = parser.parse_args()

    # Path to scan and load Yara rules
    path = args.path

    # Recursively scan files if it's a directory
    if os.path.isfile(path):
        # If it's a single file
        if is_hidden(path):
            scan_file(path, SENSINFO_YARA)
        else:
            scan_file(path, SCRIPTS_YARA)
    elif os.path.isdir(path):
        # Recursively scan all files in the directory
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                if is_hidden(path):
                    scan_file(path, SENSINFO_YARA)
                else:
                    scan_file(path, MALWARE_YARA)
                    scan_file(path, SCRIPTS_YARA)
                    scan_file(path, NETWORK_YARA)
                    scan_file(path, SCRIPTS_YARA)
    else:
        print("Invalid path provided. Please provide a valid file or folder path.")

if __name__ == "__main__":
    main()