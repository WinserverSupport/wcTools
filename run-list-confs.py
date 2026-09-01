#!/usr/bin/env python
# run-list-confs.py -- convenience wrapper around list-confs.py
#
# Runs list-confs.py and captures its output, which is handy when you
# want the conference list from another script, a scheduled task, or a
# wcTaskMgr event rather than from a console.
#
# list-confs.py is located next to this file, so wcTools works wherever
# it is unpacked -- no path to edit.
#
# Usage:
#   python run-list-confs.py [options passed through to list-confs.py]
#
# Examples:
#   python run-list-confs.py
#   python run-list-confs.py --server NTBBS
#   python run-list-confs.py --server NTBBS --type mtListServeForum
#
# Revision History:
# 500.2  09/01/26  generalized: no hardcoded path, server or working dir

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, 'list-confs.py')


def main():
    if not os.path.exists(TOOL):
        print("ERROR: list-confs.py not found next to this script:")
        print("       %s" % TOOL)
        sys.exit(1)

    # Everything after the script name is passed straight through, so
    # this wrapper needs no change when list-confs.py gains options.
    cmd = [sys.executable, TOOL] + sys.argv[1:]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stdout:
        print(result.stdout, end='')
    if result.stderr:
        print("STDERR:", result.stderr, file=sys.stderr)

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
