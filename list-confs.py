#!/usr/bin/env python
# list-confs.py -- List Wildcat! conferences with number, name, type, and options
# Usage: py list-confs.py [--server NAME] [--pwd PASSWORD] [--type TYPE ...] [--options]
#
# --server  WC server name (default: local)
# --pwd     Makewild password (default: none)
# --type    Filter by MailType: number(s) or name(s), e.g. --type 7 or --type mtInternetMailingList
#           Multiple values allowed: --type 0 1 2
#           Names are case-insensitive; prefix "mt" is optional.
# --options Show Options flags for each conference
#
# Session: MwLogin (clSessionConfig) -- bulk fetch via MwGetConfDescs
# Note: Close wcConfig.exe before running (only one Makewild client at a time).
# Empty slot detection: ObjectId == 0 (conference 0 is valid personal mail).
# 500.2  2026-03-12

import sys
import ctypes
import argparse

try:
    from wcpapi.wcserver_h import *
    from wcpapi.wctype_h import *
    from wcpapi.wctype_constants_h import *
    from wcpapi.wcserror_h import *
    from wcpapi.wcsmw_h import *
    from wcpapi.wctypemw_h import *
    from wcpapi.wctypemw_constants_h import *
except ImportError as e:
    print("ERROR: wcpapi package not found: {}".format(e))
    sys.exit(1)

# MailType numeric -> name table
MAILTYPE_NAMES = {
    mtNormalPublicPrivate       : 'mtNormalPublicPrivate',
    mtNormalPublic              : 'mtNormalPublic',
    mtNormalPrivate             : 'mtNormalPrivate',
    mtFidoNetmail               : 'mtFidoNetmail',
    mtEmailOnly                 : 'mtEmailOnly',
    mtUsenetNewsgroup           : 'mtUsenetNewsgroup',
    mtUsenetNewsgroupModerated  : 'mtUsenetNewsgroupModerated',
    mtInternetMailingList       : 'mtInternetMailingList',
    mtFidoEcho                  : 'mtFidoEcho',
    mtListServeForum            : 'mtListServeForum',
    mtUserEmail                 : 'mtUserEmail',
}

# Name -> numeric (strip optional "mt" prefix, case-insensitive)
def _build_name_map():
    m = {}
    for val, name in MAILTYPE_NAMES.items():
        m[name.lower()] = val
        m[name[2:].lower()] = val   # without "mt" prefix
    return m

MAILTYPE_BY_NAME = _build_name_map()


def get_connected_server_name():
    buf = ctypes.create_string_buffer(MAX_PATH)
    if GetConnectedServer(buf, MAX_PATH):
        return buf.value.decode('cp437', errors='replace')
    return '(unknown)'

# OPTIONS flags for display
OPTIONS_FLAGS = [
    (maAllowMailSnooping,  'AllowMailSnooping'),
    (maPreserveMime,       'PreserveMime'),
    (maAllowReplyOnly,     'AllowReplyOnly'),
    (maAllowMacros,        'AllowMacros'),
    (maAllowMsgDelete,     'AllowMsgDelete'),
    (maAllowDupes,         'AllowDupes'),
]


def print_type_list():
    print("Available MailTypes:")
    for val in sorted(MAILTYPE_NAMES):
        print("  {:>2}  {}".format(val, MAILTYPE_NAMES[val]))


def parse_type_filter(type_args):
    """Parse --type arguments into a set of MailType integers, or None for no filter."""
    if type_args is None:
        return None
    if not type_args:           # --type with no values
        print_type_list()
        sys.exit(0)
    result = set()
    for t in type_args:
        key = t.strip().lower()
        if key in MAILTYPE_BY_NAME:
            result.add(MAILTYPE_BY_NAME[key])
        else:
            try:
                result.add(int(t))
            except ValueError:
                print("ERROR: Unknown MailType {!r}".format(t))
                print()
                print_type_list()
                sys.exit(1)
    return result


def format_options(opts):
    bits = [label for flag, label in OPTIONS_FLAGS if opts & flag]
    return ', '.join(bits) if bits else '(none)'


def mailtype_str(mt):
    return MAILTYPE_NAMES.get(mt, 'mt?({})'.format(mt))


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if '/?' in sys.argv:
    sys.argv[sys.argv.index('/?')] = '--help'

parser = argparse.ArgumentParser(description="List Wildcat! conferences")
parser.add_argument('--server', default='', help="WC server name (default: local)")
parser.add_argument('--pwd',    default='', help="Makewild password (default: none)")
parser.add_argument('--type',   metavar='TYPE', nargs='*',
                    help=("Filter by MailType number(s) or name(s). "
                          "Available types: "
                          "0=mtNormalPublicPrivate, "
                          "1=mtNormalPublic, "
                          "2=mtNormalPrivate, "
                          "3=mtFidoNetmail, "
                          "4=mtEmailOnly, "
                          "5=mtUsenetNewsgroup, "
                          "6=mtUsenetNewsgroupModerated, "
                          "7=mtInternetMailingList, "
                          "8=mtFidoEcho, "
                          "9=mtListServeForum, "
                          "10=mtUserEmail"))
parser.add_argument('--options', action='store_true',
                    help="Show Options flags for each conference")
args = parser.parse_args()

type_filter = parse_type_filter(args.type)

print("list-confs.py")
if type_filter is not None:
    print("  Filter  : {}".format(', '.join(mailtype_str(t) for t in sorted(type_filter))))
print("  Password: {}".format("(set)" if args.pwd else "(none)"))

# ---------------------------------------------------------------------------
# Connect and login
# ---------------------------------------------------------------------------
if not WildcatServerConnectSpecific(None, args.server):
    err = ctypes.GetLastError()
    print("ERROR: Cannot connect to server {!r}".format(args.server))
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)

print("  Server  : {}".format(get_connected_server_name()))
print()

if not WildcatServerCreateContext():
    err = ctypes.GetLastError()
    print("ERROR: WildcatServerCreateContext failed")
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)

try:
    if not MwLogin(args.pwd):
        err = ctypes.GetLastError()
        print("ERROR: MwLogin failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        if err == WC_USER_ALREADY_LOGGED_IN:
            print("  Another Makewild client holds the session lock.")
            print("  Close wcConfig.exe (or other Makewild client) and retry.")
        elif err == WC_INCORRECT_PASSWORD:
            print("  Password is incorrect. Use --pwd to supply the Makewild password.")
        elif err == WC_ACCESS_DENIED:
            print("  Access denied. Check config\\nowcconfig.sem or srvWcxMwLogin flag.")
        sys.exit(1)

    count = GetConferenceCount()
    if count == 0:
        print("No conferences found (GetConferenceCount returned 0).")
        sys.exit(0)

    # Bulk fetch all conference slots in one RPC call.
    # GetConferenceCount() includes slot 0 (personal mail); fetchable slots are 1..count-1.
    # Empty slots have ObjectId == 0; skip them.
    fetch = count - 1
    arr = (TWildcatServerPrivateConfDesc * fetch)()
    if not MwGetConfDescs(1, fetch, arr):
        err = ctypes.GetLastError()
        print("ERROR: MwGetConfDescs failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    # Header
    if args.options:
        print("{:>5}  {:<40}  {:<32}  {}".format(
            "Num", "Name", "MailType", "Options"))
        print("{:-<5}  {:-<40}  {:-<32}  {:-<40}".format('', '', '', ''))
    else:
        print("{:>5}  {:<40}  {}".format("Num", "Name", "MailType"))
        print("{:-<5}  {:-<40}  {:-<32}".format('', '', ''))

    listed = 0
    total  = 0
    for i in range(fetch):
        cd = arr[i]
        pub = cd.Public
        if pub.ObjectId == 0:
            continue      # empty slot
        total += 1
        mt = pub.MailType
        if type_filter is not None and mt not in type_filter:
            continue
        name    = pub.Name if pub.Name else ''
        mt_name = mailtype_str(mt)
        if args.options:
            opts_str = format_options(pub.Options)
            print("{:>5}  {:<40}  {:<32}  {}".format(pub.Number, name, mt_name, opts_str))
        else:
            print("{:>5}  {:<40}  {}".format(pub.Number, name, mt_name))
        listed += 1

    print()
    if type_filter is not None:
        print("{} conference(s) of {} total match filter.".format(listed, total))
    else:
        print("{} conference(s) total.".format(listed))

finally:
    WildcatServerDeleteContext()
