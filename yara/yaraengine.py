import os
import argparse
import yara
import platform
import ctypes
import stat
import requests

WIN_FILE_ATTRIBUTE_HIDDEN = 0x02
VIRUS_TOTAL_API = "07742de74b63fd6bce3c7ae8c21000b3d7b777d070f3872e952774d3daf88127"
VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/files"

yararules_dir = "yara/yararules"
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
    '''Scans a file with the specified yara rule
    #### Returns 1 on hit, 0 on no hit'''
    rules = yara.compile(filepath=yara_rules_path)
    #print(f"Scanning {file_path}")
    matches = rules.match(filepath=file_path)
    if matches:
        print(f"Yara match found in {file_path}: {matches}")
        return 1
    else:
        return 0
    
# Function to run all scans
def run_scans(file_path):
    # Hidden Files
    if is_hidden(file_path):
        scan_file(file_path, SENSINFO_YARA)
    # Executable Files
    elif is_executable(file_path):
        scan_file(file_path, NETWORK_YARA)
        scan_file(file_path, MALURL_YARA)
    # High entropy files
    elif scan_file(file_path, MALWARE_YARA):
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            headers = {
                'x-apikey': VIRUS_TOTAL_API,
            }
            response = requests.post(VIRUS_TOTAL_URL, headers=headers, files=files)
            if response.status_code == 200:
                print(f"File '{file_path}' sent to VirusTotal.")
            else:
                print(f"Failed to send '{file_path}' to VirusTotal.")
    else:
        scan_file(file_path, SCRIPTS_YARA)               
        scan_file(file_path, CUSTOMSIGN_YARA)

# Function to determine if a file is hidden
# Returns 1 on hidden, 0 on visible
def is_hidden(file_path):
    '''Function to determine if a file is hidden
    #### Returns 1 on hidden, 0 on visible'''
    if platform.system() == "Windows":
        attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
        return attrs != -1 and (attrs & WIN_FILE_ATTRIBUTE_HIDDEN) != 0
    else:
        # For Unix-based systems
        return os.path.basename(file_path).startswith(".")
    
# Function to determine if a file is an executable or not
# Returns 1 on executable, 0 on not-executable
def is_executable(file_path):
    '''Function to determine if a file is executable. Only supports Windows and Linux.
    #### Returns 1 on executable, 0 on not-executable'''
    if platform.system() == "Windows":
        try:
            with open(file_path, 'rb') as file:
                magic_number = file.read(2)  # Read the first 2 bytes
                return magic_number == b'MZ'  # Check for "MZ" magic number
        except Exception:
            return False
    elif platform.system() == "Linux":
        file_stat = os.stat(file_path)
        return bool(file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

# CLI Interface
def main():
    # Check if we can find all yara files.
    if check_yaras():
        return
    parser = argparse.ArgumentParser(description="Scan files and folders with Yara rules.")
    parser.add_argument("path", help="Path to the file or folder to scan.")
    args = parser.parse_args()

    # Path to scan and load Yara rules
    path = args.path

    # Scan file(s)
    if os.path.isfile(path):
        # If it's a single file
        run_scans(path)
    elif os.path.isdir(path):
        # Recursively scan all files in the directory
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                run_scans(file_path)
    else:
        print("Invalid path provided. Please provide a valid file or folder path.")

if __name__ == "__main__":
    main()