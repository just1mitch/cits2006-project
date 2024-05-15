import os
import argparse
import yara
import platform
import ctypes
import stat
import hashlib
import json
import vt
from pathlib import Path

WIN_FILE_ATTRIBUTE_HIDDEN = 0x02
VIRUS_TOTAL_API = os.environ["VIRUS_TOTAL_API"]
VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/files"

yararules = {}
malware_hashes_folder = ""

# Function to scan a file with Yara rules
def scan_file(file_path, yara_rule):
    '''Scans a file with the specified yara rule
    #### Returns 1 on hit, 0 on no hit'''
    rule = yararules[yara_rule]
    matches = rule.match(filepath=file_path)
    if matches:
        print(f"Yara match found in {file_path}: {matches}")
        return 1
    else:
        return 0
    
# Function to run all scans
def run_scans(file_path):
    safe = 0 # If safe is true, we won't send it to VirusTotal to check
    if scan_for_malware(file_path):
        print(f"HASH MATCH FOR MALWARE: {file_path}")
    # Hidden Files
    if is_hidden(file_path):
        # Not sending file to be scanned if it contains sensitive information
        scan_file(file_path, "SENSINFO_YARA")
    # Executable Files
    if is_executable(file_path):
        if scan_file(file_path, "NETWORK_YARA") or scan_file(file_path, "MALURL_YARA"):
            safe = 1
    # High entropy files
    if scan_file(file_path, "MALWARE_YARA"):
        safe = 1
    if scan_file(file_path, "SCRIPTS_YARA"):
        safe = 1
    if "CUSTOMSIG_YARA" in yararules:
        scan_file(file_path, "CUSTOMSIG_YARA")
    return safe

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

def md5_hash_file(file_path):
    """Calculate the MD5 hash of a file."""
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def scan_for_malware(file_path):
    """Check if the MD5 hash of the file matches any known malware hash."""
    file_md5 = md5_hash_file(file_path)

    # Iterate through all files in the malwarehashes folder
    for root, _, files in os.walk(malware_hashes_folder):
        for filename in files:
            file_path = os.path.join(root, filename)

            with open(file_path, "r") as f:
                # Skip the header lines
                while f.readline().startswith("#"):
                    continue

                # Now, read the MD5 hashes from the remaining lines
                hashes = f.read().splitlines()

                # Check if the calculated MD5 is in the list of known malware hashes
                if file_md5 in hashes:
                    return 1

    return 0

# Uses VirusTotal API to scan a malicious file passed by file_path
def virus_total_scan(file_path):
    print(f"\nGetting scan results for {file_path} (may take up to 5 minutes)")
    # See if file has been scanned recently - if so, use that info instead
    hash = md5_hash_file(file_path)
    with vt.Client(VIRUS_TOTAL_API) as vt_client:
        try:
            scan = vt_client.get_json(f"/files/{hash}")
        except vt.error.APIError:
            # If the file hasn't been scanned, send it for scanning
            with open(f"{file_path}", "rb") as f:
                vt_client.scan_file(f, wait_for_completion=True)
            scan = vt_client.get_json(f"/files/{hash}")

    attributes = scan["data"]["attributes"]
    Path(os.path.abspath('./scan_results')).mkdir(exist_ok=True)
    save_path = f"{os.path.abspath('./scan_results')}/{attributes['md5']}.json"
    print(f"""Scan Results:\nName: {attributes["meaningful_name"]}\nAnalysis Stats: {attributes["last_analysis_stats"]}\nFull Analysis saved to {save_path}\n""")
    with open(save_path, 'w') as f:
        json.dump(scan, f, indent=4)

# Creates a custom yara rule using the strings
# Takes a path to a newline separated list of custom strings
# Compiles and returns the yara rules to detect these strings
def create_custom_rule(path_to_list):
    try:
        with open(os.path.abspath(path_to_list), 'r') as file:
            string_list = file.readlines()
        string_list = [string.replace('\n', '') for string in string_list]
        yara_string = "".join([f"$string{i} = \"{string_list[i]}\"\n" for i in range(len(string_list))])[:-1]
        rule = f"rule custom_string {{\n\tstrings:\n{yara_string}\ncondition: any of them\n}}"
        custom_rule = yara.compile(source=rule)
        
    except:
        raise
    return custom_rule

# CLI Interface
def main():
    parser = argparse.ArgumentParser(description="Scan files and folders with Yara rules.")
    parser.add_argument("rules", help="Directory to YARA Rules.")
    parser.add_argument("scan_path", help="Path to the file or folder to scan.")
    parser.add_argument('-c', '--custom-signatures', action='store', help="Path to a list of custom signatures to check files for (each string should be separated by a newline character \\n)")
    args = parser.parse_args()

    # Path to scan and load Yara rules
    scan_path = os.path.abspath(args.scan_path)
    yararules_dir = os.path.abspath(args.rules)

    MALWARE_YARA = os.path.join(yararules_dir, "malware.yara")
    SENSINFO_YARA = os.path.join(yararules_dir, "sensitiveinfo.yara")
    SCRIPTS_YARA = os.path.join(yararules_dir, "scripts.yara")
    NETWORK_YARA = os.path.join(yararules_dir, "netresource.yara")
    MALURL_YARA = os.path.join(yararules_dir, "malURL.yara")
    global malware_hashes_folder
    malware_hashes_folder = os.path.join(yararules_dir, "malwarehashes")
    
    global yararules
    yararules = {
        "MALWARE_YARA": yara.compile(filepath=MALWARE_YARA),
        "SENSINFO_YARA": yara.compile(filepath=SENSINFO_YARA),
        "SCRIPTS_YARA": yara.compile(filepath=SCRIPTS_YARA),
        "NETWORK_YARA": yara.compile(filepath=NETWORK_YARA),
        "MALURL_YARA": yara.compile(filepath=MALURL_YARA),
    }

    # Potentially malicious files to upload to VirusTotal
    files_to_upload = []

    # If -c flag passed, compile the custom signatures yara rule
    if args.custom_signatures is not None:
        customsig_yara = create_custom_rule(args.custom_signatures)
        yararules["CUSTOMSIG_YARA"] = customsig_yara

    # Scan file(s)
    if os.path.isfile(scan_path):
        # If it's a single file
        if run_scans(scan_path):
            files_to_upload.append(scan_path)
    elif os.path.isdir(scan_path):
        # Recursively scan all files in the directory
        for root, dirs, files in os.walk(scan_path):
            # Ignore the Security folder at root of rapidobank directory
            # as our file structure has the security folder for project implementation
            if(root.split("/")[-1] == 'rapidobank'):
                dirs.remove("Security")
                
            for file in files:
                file_path = os.path.join(root, file)
                if run_scans(file_path):
                    files_to_upload.append(file_path)
    else:
        print("Invalid path provided. Please provide a valid file or folder path.")
    
    # For all potentially malicious files, send them to VirusTotal for scanning
    for file_path in files_to_upload:
        virus_total_scan(file_path)

if __name__ == "__main__":
    main()