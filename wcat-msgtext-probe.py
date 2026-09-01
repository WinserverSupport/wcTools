#!/usr/bin/env python
# wcat-msgtext-probe.py -- probe wc:\CONF(#)\MESSAGE(...) name forms
#
# Determines which wc:\ virtual name actually opens a message body, and
# dumps the leading lines so the real header layout can be seen.  Used to
# settle Id-vs-Number in the MESSAGE() name and to confirm that \FULLTEXT
# returns the RFC 5322 headers.
#
# Usage:
#   python wcat-msgtext-probe.py <conf#> [--server <name>] [--count <n>]
#
# Revision History:
# 500.2  08/27/26  Initial version

import ctypes
import sys
import argparse

import wcpapi
from wcpapi.wcserver_h import *
from wcpapi.wcserror_h import *
from wcpapi.wctype_h import *
from wcpapi.wctype_constants_h import *

try:
    sys.stdout.reconfigure(encoding='cp437', errors='replace')
    sys.stderr.reconfigure(encoding='cp437', errors='replace')
except (AttributeError, ValueError):
    pass

GENERIC_READ    = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING   = 3
WCLINE_MAX      = 1024

INVALID = ctypes.wintypes.HANDLE(-1).value

def try_open(fn, dump_lines=0):
    """Open fn, optionally dump leading lines. Returns (ok, nlines, err)."""
    h = WcCreateFile(fn, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING)
    if h == INVALID or not h:
        return (False, 0, ctypes.GetLastError())

    buf  = ctypes.create_string_buffer(WCLINE_MAX)
    pbuf = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))
    n = 0
    try:
        while n < 200 and WcReadLine(h, pbuf, WCLINE_MAX - 1):
            line = buf.value.decode('cp437', errors='replace')
            if n < dump_lines:
                print("        | {}".format(line.rstrip()))
            n += 1
            if dump_lines and n >= dump_lines:
                print("        | ...")
                break
    finally:
        WcCloseHandle(h)
    return (True, n, 0)

def main():
    parser = argparse.ArgumentParser(description="Probe wc:\\ message name forms")
    parser.add_argument('conf',       type=int)
    parser.add_argument('--server',   default='')
    parser.add_argument('--count',    type=int, default=3, help="messages to probe")
    parser.add_argument('--dump',     type=int, default=12, help="lines to dump on success")
    args = parser.parse_args()

    if not WildcatServerConnectSpecific(None, args.server):
        print("ERROR: Cannot connect to WC server '{}'.".format(args.server))
        sys.exit(1)
    if not WildcatServerCreateContext():
        print("ERROR: WildcatServerCreateContext failed.")
        sys.exit(1)

    try:
        if not LoginSystem():
            print("ERROR: LoginSystem failed ({:08X}).".format(ctypes.GetLastError()))
            sys.exit(1)

        cnum = args.conf
        print("Conference {}  Low={}  High={}".format(
            cnum, GetLowMessageNumber(cnum), GetHighMessageNumber(cnum)))

        msg = TMsgHeader()
        msg.Conference = cnum

        seen = 0
        while seen < args.count and GetNextMessage(ctypes.byref(msg)):
            seen += 1
            print("\n--- Number={}  Id={}  MsgSize={} ---".format(
                msg.Number, msg.Id, msg.MsgSize))

            forms = [
                ("Id      + FULLTEXT", "wc:\\CONF({})\\MESSAGE({})\\FULLTEXT".format(cnum, msg.Id)),
                ("Number  + FULLTEXT", "wc:\\CONF({})\\MESSAGE({})\\FULLTEXT".format(cnum, msg.Number)),
                ("Id      plain",      "wc:\\CONF({})\\MESSAGE({})".format(cnum, msg.Id)),
                ("Number  plain",      "wc:\\CONF({})\\MESSAGE({})".format(cnum, msg.Number)),
            ]

            first_ok = True
            for label, fn in forms:
                ok, n, err = try_open(fn, 0)
                print("  {:<20} {:<52} {}".format(
                    label, fn,
                    "OK  {} lines".format(n) if ok else "FAIL err={:08X}".format(err)))
                if ok and first_ok and args.dump:
                    first_ok = False
                    print("      -- first {} lines --".format(args.dump))
                    try_open(fn, args.dump)

            # cross-check the one-shot API on the same name
            bufsize = 65536
            gbuf = ctypes.create_string_buffer(bufsize)
            got  = DWORD(0)
            gfn  = "wc:\\CONF({})\\MESSAGE({})\\FULLTEXT".format(cnum, msg.Id)
            rc   = GetText(gfn, gbuf, bufsize, ctypes.byref(got))
            print("  {:<20} GetText rc={} retsize={}".format("Id      + FULLTEXT", rc, got.value))

    finally:
        WildcatServerDeleteContext()

if __name__ == "__main__":
    main()
