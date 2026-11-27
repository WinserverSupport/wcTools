#!/usr/bin/env python
# wcMenuDump.py -- Dump a Wildcat! menu file (wildcat.mnu, TMenu records)
# Usage: py wcMenuDump.py [--server NAME] [--mw] [--pwd PASSWORD]
#                         [--lang NAME] [--path WCPATH]
#                         [--file LOCALFILE] [--menu N ...] [--find TEXT]
#
# Source (one of):
#   default   server read: LoginSystem + WcCreateFile/WcReadFile
#   --mw      server read in a Makewild session (MwLogin); --pwd implies it
#   --file    raw local read, no server (e.g. the stock default
#             Z:\Builds\parts\current\default\language\wildcat.mnu)
#
# --server  WC server name (default: local)
# --lang    language name: wc:\lang\lang(NAME)\wildcat.mnu
#           (default: wc:\language\wildcat.mnu)
# --path    any wc: menu file path (overrides --lang)
# --menu    dump only these menu numbers (1-based record numbers, as #N)
# --find    show only items whose selection, description, command or
#           parameters contain TEXT (case-insensitive)
#
# A command "#N" goes to menu N; its description is shown beside it.
# 500.4  26.11.26  initial

import sys
import ctypes
import ctypes.wintypes
import argparse

try:
    from wcpapi.wcserver_h import *
    from wcpapi.wctype_h import *
    from wcpapi.wcserror_h import *
    from wcpapi.wcsmw_h import *
except ImportError as e:
    print("ERROR: wcpapi package not found: {}".format(e))
    sys.exit(1)

GENERIC_READ      = 0x80000000
FILE_SHARE_READ   = 0x00000001
FILE_SHARE_WRITE  = 0x00000002
OPEN_EXISTING     = 3
INVALID_HANDLE    = ctypes.wintypes.HANDLE(-1).value

MENU_SIZE = ctypes.sizeof(TMenu)

def s(b):
    if isinstance(b, str):              # PropertyStruct decodes c_char fields
        return b.split("\0", 1)[0]
    return b.split(b"\0", 1)[0].decode("cp437", errors="replace")

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Dump a Wildcat! menu file (wildcat.mnu)")
parser.add_argument('--server', default='', help="WC server name (default: local)")
parser.add_argument('--mw',     action='store_true', help="Makewild session (MwLogin)")
parser.add_argument('--pwd',    default='', help="Makewild password; implies --mw")
parser.add_argument('--lang',   default='', help="language name (default: wc:\\language)")
parser.add_argument('--path',   default='', help="wc: menu file path (overrides --lang)")
parser.add_argument('--file',   default='', help="local menu file, raw read (no server)")
parser.add_argument('--menu',   nargs='+', type=int, default=[], help="menu number(s), 1-based")
parser.add_argument('--find',   default='', help="only items containing TEXT")
args = parser.parse_args()
if args.pwd:
    args.mw = True

if args.path:
    wcpath = args.path
elif args.lang:
    wcpath = "wc:\\lang\\lang({})\\wildcat.mnu".format(args.lang)
else:
    wcpath = "wc:\\language\\wildcat.mnu"

# ---------------------------------------------------------------------------
# Read the file
# ---------------------------------------------------------------------------

def fail(what):
    err = ctypes.GetLastError()
    print("ERROR: {} failed".format(what))
    print("  {}".format(GetWildcatErrorStr(err)))
    if what == "MwLogin":
        if err == WC_USER_ALREADY_LOGGED_IN:
            print("  Another Makewild client holds the session lock.")
            print("  Close wcConfig.exe (or other Makewild client), or use --file.")
        elif err == WC_INCORRECT_PASSWORD:
            print("  Password is incorrect. Use --pwd to supply the Makewild password.")
        elif err == WC_ACCESS_DENIED:
            print("  Access denied: config\\nowcconfig.sem exists, or a remote")
            print("  connection without srvWcxMwLogin.")
    sys.exit(1)

def read_server():
    if not WildcatServerConnectSpecific(None, args.server):
        err = ctypes.GetLastError()
        print("ERROR: Cannot connect to server {!r}".format(args.server))
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)
    buf = ctypes.create_string_buffer(MAX_PATH)
    GetConnectedServer(buf, MAX_PATH)
    server = buf.value.decode('cp437', errors='replace')
    if not WildcatServerCreateContext():
        fail("WildcatServerCreateContext")
    try:
        if args.mw:
            if not MwLogin(args.pwd):
                fail("MwLogin")
        elif not LoginSystem():
            fail("LoginSystem")
        h = WcCreateFile(wcpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING)
        if not h or h == INVALID_HANDLE:
            fail("WcCreateFile {}".format(wcpath))
        try:
            size = WcGetFileSize(h)
            data = ctypes.create_string_buffer(size)
            got = ctypes.c_ulong(0)
            pdata = ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))
            if not WcReadFile(h, pdata, size, ctypes.byref(got)):
                fail("WcReadFile {}".format(wcpath))
            raw = data.raw[:got.value]
        finally:
            WcCloseHandle(h)
    finally:
        WildcatServerDeleteContext()
    session = "MwLogin" if args.mw else "LoginSystem"
    return raw, "{} {} ({})".format(server, wcpath, session)

def read_local():
    try:
        with open(args.file, "rb") as f:
            return f.read(), "{} (raw)".format(args.file)
    except OSError as e:
        print("ERROR: {}".format(e))
        sys.exit(1)

raw, source = read_local() if args.file else read_server()

count = len(raw) // MENU_SIZE
menus = [TMenu.from_buffer_copy(raw, i * MENU_SIZE) for i in range(count)]

print("wcMenuDump.py")
print("  Source : {}".format(source))
print("  Size   : {} bytes, {} menus (TMenu = {} bytes)".format(len(raw), count, MENU_SIZE))
if len(raw) % MENU_SIZE:
    print("  WARNING: {} trailing bytes (not a whole TMenu)".format(len(raw) % MENU_SIZE))
print()

# ---------------------------------------------------------------------------
# Dump
# ---------------------------------------------------------------------------

def goto_text(cmd):
    if cmd.startswith("#"):
        try:
            n = int(cmd[1:])
        except ValueError:
            return ""
        if 1 <= n <= count:
            return "-> " + s(menus[n - 1].Description)
        return "-> (no menu {})".format(n)
    return ""

find = args.find.lower()
for n, m in enumerate(menus, 1):
    if args.menu and n not in args.menu:
        continue
    items = []
    for i in range(min(m.Count, MAX_MENU_ITEMS)):
        it = m.Items[i]
        row = (s(it.Selection), s(it.Description), s(it.Command), s(it.Parameters))
        if find and not any(find in f.lower() for f in row):
            continue
        items.append(row)
    if find and not items:
        continue
    print("Menu #{}  {}".format(n, s(m.Description)))
    print("  DisplayName={}  ObjectId=0x{:08X}  Flags=0x{:08X}  Items={}  FastLogin={}  Security={}".format(
        s(m.DisplayName), m.ObjectId, m.Flags, m.Count,
        repr(chr(m.FastLoginChar)) if 32 < m.FastLoginChar < 127 else m.FastLoginChar,
        s(m.SecurityEntryName) or "-"))
    print("    {:<6} {:<32} {:<24} {}".format("Sel", "Description", "Command", "Parameters"))
    for sel, desc, cmd, parms in items:
        line = "    {:<6} {:<32} {:<24} {}".format(sel, desc, cmd, parms)
        g = goto_text(cmd)
        if g:
            line = line.rstrip() + "  " + g
        print(line.rstrip())
    print()
