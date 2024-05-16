import argparse
import asyncio
import signal
from typing import List
import os
from pathlib import Path
import cmd


from encryptor import Encryptor
from cryptography.cryptoclasses import Cipher
from cryptography.include.encrypt import Ciphers
from yara_engine.YaraEngine_new import YaraEngine
from scanner import Quarantiner, Whitelist, start

VIRUS_TOTAL_API_KEY = os.environ.get('VIRUS_TOTAL_API_KEY')

def check_paths(paths: List[str]) -> List[str] | bool:
    for path in paths:
        if not os.path.isdir(path):
            print(f"Error: {path} is not a valid directory.")
            return False
    return [os.path.abspath(path) for path in paths]

def check_path(path: str) -> str | bool:
    if not os.path.isdir(path):
        print(f"Error: {path} is not a valid directory.")
        return False
    return os.path.abspath(path)

def check_quarantine_directory(quarantine: str) -> bool:
    # Check if the quarantine directory is owned by the current user
    if os.stat(quarantine).st_uid != os.getuid():
        print(f"Error: {quarantine} is not owned by the current user.")
        return False

    # Check if only the current user can write, access and execute it
    if os.stat(quarantine).st_mode & 0o777 != 0o700:
        print(f"Error: {quarantine} permissions are not set to 700.")
        return False

    return True

def check_paths_rwx(paths: List[str]) -> bool:
    for path in paths:
        if not os.path.isdir(path):
            print(f"Error: {path} is not a valid directory.")
            return False
        for root, dirs, files in os.walk(path):
            for dir in dirs:
                dir_path = os.path.join(root, dir)
                if not os.access(dir_path, os.R_OK | os.W_OK | os.X_OK):
                    print(f"Error: {dir_path} does not have rwx permissions for the current user.")
                    return False
            for file in files:
                file_path = os.path.join(root, file)
                if not os.access(file_path, os.R_OK | os.W_OK):
                    print(f"Error: {file_path} does not have rw permissions for the current user.")
                    return False
    return True

def main(monitored: List[str], sensitive: List[str], quarantine: str, yara_rules: List[str], malicious_threshold: int, whitelist: str):
    Path(quarantine).mkdir(parents=False, exist_ok=True)
    monitored = check_paths(monitored)
    sensitive = check_paths(sensitive)
    quarantine = check_path(quarantine)
    yara_rules = check_paths(yara_rules)
    whitelist = check_path(whitelist)
    Path(whitelist + '/.whitelist').touch(exist_ok=True)
    Path(quarantine + '/.quarantine').touch(exist_ok=True)
    Path(quarantine + '/.encryption').touch(exist_ok=True)


    if not monitored or not sensitive or not yara_rules or not quarantine or not whitelist:
        return
    
    if not check_quarantine_directory(quarantine):
        return
    
    if not check_paths_rwx(monitored) or not check_paths_rwx(sensitive):
        return

    if not VIRUS_TOTAL_API_KEY:
        print("Alert: No VirusTotal API key found. Will not submit file hashes to VirusTotal.")

    whitelist = Whitelist(whitelist + '/.whitelist')
    yara_engine = YaraEngine(yara_rules, VIRUS_TOTAL_API_KEY)
    encryptor = Encryptor(quarantine)

    encryptor.encrypt(sensitive[0] + "/super secret file!!!")
    encryptor.decrypt(sensitive[0] + "/super secret file!!!")
    #Cipher(newkeysize=50).encrypt(sensitive[0] + "/super secret file!!!", cipher=Ciphers.XOR)
    return 0

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, loop.stop)

    try:
        loop.create_task(start(yara_engine, monitored, whitelist, quarantine, encryptor))
        loop.run_forever()
    except KeyboardInterrupt:
        tasks = asyncio.all_tasks(loop=loop)
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        loop.close()


class QuarantineMenu(cmd.Cmd):
    prompt = '(quarantine)'

    def __init__(self, quarantiner: Quarantiner):
        super().__init__()
        self.quarantiner = quarantiner
        self.do_help(None)

    def do_list(self, args):
        """List quarantined files."""
        for hash, directory in self.quarantiner.get_quarantined_files():
            print(f'{hash}: {directory}')

    def do_delete(self, hash):
        """Delete a quarantined file by its hash."""
        if len(hash) != 32:
            print('Invalid hash')
            return
        
        self.quarantiner.delete(hash)
        print('File deleted')

    def do_restore(self, hash):
        """Restore a quarantined file by its hash."""
        if len(hash) != 32:
            print('Invalid hash')
            return
        self.quarantiner.unquarantine(hash)
        print("File restored")
    
    def do_quit(self, args):
        """Quit the quarantine menu."""
        return True

def quarantiner(quarantine: str):
    quarantiner_obj = Quarantiner(quarantine)
    QuarantineMenu(quarantiner_obj).cmdloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='RapidoBank MTD System',
        description='Entrypoint for the RapidoBank MTD System',
        epilog='Created by Daniel Jennings (23064976) and Isobelle Scott (23105336). ')

    subparsers = parser.add_subparsers(dest='mode')

    # Normal mode parser
    normal_parser = subparsers.add_parser('normal')
    normal_parser.add_argument('-m', '--monitored', nargs='+', required=True,
                               help='Monitored directories')
    normal_parser.add_argument('-s', '--sensitive', nargs='+', required=True,
                               help='Sensitive directories')
    normal_parser.add_argument('-q', '--quarantine', nargs='?', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine"), help='Quarantine directory')
    normal_parser.add_argument('-y', '--yara-rules', nargs='+', default=[os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_engine/yararules")], help='Path to additional YARA files directories')
    normal_parser.add_argument('--whitelist', nargs='?', default=os.path.join(os.path.dirname(os.path.abspath(__file__))), help='Path to directory where .whitelist file will be stored.')
    normal_parser.add_argument('--malicious-threshold', type=int, default=5, help='Threshold for the number of VirusTotal providers that must flag a file as malicious before quarantining action is taken.')

    # Quarantiner mode parser
    quarantiner_parser = subparsers.add_parser('quarantiner')
    quarantiner_parser.add_argument('-q', '--quarantine', nargs='?', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine"), help='Quarantine directory')

    args = parser.parse_args()
    if (args.mode == 'quarantiner'):
        quarantiner(args.quarantine)
    elif (args.mode == 'normal'):
        main(args.monitored, args.sensitive, args.quarantine, args.yara_rules, args.malicious_threshold, args.whitelist)
    else:
        #Show help
        parser.print_help()
