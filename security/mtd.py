import argparse
from typing import List
import os

def check_paths(paths: List[str]):
    for path in paths:
        if not os.path.isdir(path):
            print(f"Error: {path} is not a valid directory.")
            return False
    return [os.path.abspath(path) for path in paths]

def main(monitored: List[str], sensitive: List[str]):
    monitored = check_paths(monitored)
    sensitive = check_paths(sensitive)

    if not monitored or not sensitive:
        return




if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='RapidoBank MTD System',
                    description='Entrypoint for the RapidoBank MTD System',
                    epilog='Created by Daniel Jennings (23064976), Isobelle Scott (23105336)... ')
    parser.add_argument('-m', '--monitored', nargs='+', required=True,
                        help='Monitored directories')
    parser.add_argument('-s', '--sensitive', nargs='+', required=True,
                        help='Sensitive directories')
    args = parser.parse_args()

    main(args.monitored, args.sensitive)
