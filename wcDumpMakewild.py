#!/usr/bin/env python
# wcDumpMakewild.py -- Dump TMakewild fields from a Wildcat! server
# Usage: py wcDumpMakewild.py [--server NAME] [--mw] [--pwd PASSWORD]
#                             [--field NAME ...] [--all]
#
# --server  WC server name (default: local)
# --mw      Makewild session: MwLogin + MwGetMakewild
#           (TWildcatServerPrivateConfig; TMakewild is its Public member).
#           Default: LoginSystem + GetMakewild (TMakewild)
# --pwd     Makewild password (default: none); implies --mw
# --field   field(s) to dump, dotted for members (SSHConfig.Port).  With
#           --mw, a TMakewild field name also finds Public.<name>.
#           Default: DefaultColors
# --all     Dump every field
#
# DefaultColors is shown per @X@ color letter: value, foreground on
# background, blink.  Other fields are dumped as name = value; structs
# and arrays are expanded.
#
# Session: LoginSystem + GetMakewild, or MwLogin + MwGetMakewild (--mw).
# --mw needs the Makewild session lock: close wcConfig.exe first.
# 500.4  26.11.24  initial (DefaultColors); --mw from Test-MwLogin.py

import sys
import ctypes
import argparse

try:
    from wcpapi.wcserver_h import *
    from wcpapi.wctype_h import *
    from wcpapi.wcserror_h import *
    from wcpapi.wcsmw_h import *
    from wcpapi.wctypemw_h import *
except ImportError as e:
    print("ERROR: wcpapi package not found: {}".format(e))
    sys.exit(1)

COLOR_NAMES = ["black", "blue", "green", "cyan", "red", "magenta", "brown",
               "lightgray", "darkgray", "lightblue", "lightgreen",
               "lightcyan", "lightred", "lightmagenta", "yellow", "white"]

def color_text(c):
    s = "{} on {}".format(COLOR_NAMES[c & 0x0F], COLOR_NAMES[(c >> 4) & 0x07])
    if c & 0x80:
        s += ", blink"
    return s

def dump_colors(colors):
    print("DefaultColors ({} entries)".format(len(colors)))
    print("  Letter  Value  Color")
    for i, c in enumerate(colors):
        letter = "@{}@".format(chr(65 + i)) if i < 26 else "[{}]".format(i)
        print("  {:<6}  0x{:02X}   {}".format(letter, c, color_text(c)))

def fmt_scalar(v):
    if isinstance(v, bytes):
        return repr(v.split(b"\0", 1)[0].decode("cp437", errors="replace"))
    return str(v)

def dump_value(name, v, indent=""):
    if isinstance(v, ctypes.Structure):
        print("{}{}:".format(indent, name))
        for fname, _ in v._fields_:
            dump_value(fname, getattr(v, fname), indent + "  ")
    elif isinstance(v, ctypes.Array) and not isinstance(v, (bytes, str)):
        items = list(v)
        if items and isinstance(items[0], ctypes.Structure):
            for i, item in enumerate(items):
                dump_value("{}[{}]".format(name, i), item, indent)
        else:
            print("{}{} = {}".format(indent, name, " ".join(fmt_scalar(x) for x in items)))
    else:
        print("{}{} = {}".format(indent, name, fmt_scalar(v)))

def get_field(mw, path):
    v = mw
    for part in path.split("."):
        if not hasattr(v, part):
            raise AttributeError(path)
        v = getattr(v, part)
    return v

def resolve(mw, path):
    try:
        return get_field(mw, path)
    except AttributeError:
        if hasattr(mw, "Public"):
            return get_field(mw.Public, path)
        raise

def dump_field(mw, path):
    v = resolve(mw, path)
    if path.split(".")[-1] == "DefaultColors":
        dump_colors(list(v))
    else:
        dump_value(path, v)

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Dump TMakewild fields")
parser.add_argument('--server', default='', help="WC server name (default: local)")
parser.add_argument('--mw',     action='store_true',
                    help="Makewild session (MwLogin + MwGetMakewild)")
parser.add_argument('--pwd',    default='', help="Makewild password (default: none); implies --mw")
parser.add_argument('--field',  nargs='+', default=['DefaultColors'],
                    help="TMakewild field(s), dotted for members (default: DefaultColors)")
parser.add_argument('--all',    action='store_true', help="dump every TMakewild field")
args = parser.parse_args()
if args.pwd:
    args.mw = True

# ---------------------------------------------------------------------------
# Connect and login
# ---------------------------------------------------------------------------

if not WildcatServerConnectSpecific(None, args.server):
    err = ctypes.GetLastError()
    print("ERROR: Cannot connect to server {!r}".format(args.server))
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)

buf = ctypes.create_string_buffer(MAX_PATH)
GetConnectedServer(buf, MAX_PATH)
print("wcDumpMakewild.py")
print("  Server  : {}".format(buf.value.decode('cp437', errors='replace')))
print("  Session : {}".format("MwLogin + MwGetMakewild" if args.mw
                              else "LoginSystem + GetMakewild"))
print()

if not WildcatServerCreateContext():
    err = ctypes.GetLastError()
    print("ERROR: WildcatServerCreateContext failed")
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)

def fail(what):
    err = ctypes.GetLastError()
    print("ERROR: {} failed".format(what))
    print("  {}".format(GetWildcatErrorStr(err)))
    if what == "MwLogin":
        if err == WC_USER_ALREADY_LOGGED_IN:
            print("  Another Makewild client holds the session lock.")
            print("  Close wcConfig.exe (or other Makewild client) and retry.")
        elif err == WC_INCORRECT_PASSWORD:
            print("  Password is incorrect. Use --pwd to supply the Makewild password.")
        elif err == WC_ACCESS_DENIED:
            print("  Access denied: config\\nowcconfig.sem exists, or a remote")
            print("  connection without srvWcxMwLogin.")
    sys.exit(1)

try:
    if args.mw:
        if not MwLogin(args.pwd):
            fail("MwLogin")
        mw = TWildcatServerPrivateConfig()
        if not MwGetMakewild(ctypes.byref(mw)):
            fail("MwGetMakewild")
    else:
        if not LoginSystem():
            fail("LoginSystem")
        mw = TMakewild()
        if not GetMakewild(ctypes.byref(mw)):
            fail("GetMakewild")

    fields = [f for f, _ in mw._fields_] if args.all else args.field
    rc = 0
    for f in fields:
        try:
            dump_field(mw, f)
        except AttributeError:
            print("ERROR: no TMakewild field {!r}".format(f))
            rc = 1
    sys.exit(rc)
finally:
    WildcatServerDeleteContext()
