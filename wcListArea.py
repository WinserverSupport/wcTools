#!/usr/bin/env python
# wcListArea.py -- Show backend storage paths for FILE or MAIL areas,
#                  or the FILEGROUP -> file area membership tree
# Usage: py wcListArea.py FILE|MAIL|FILEGROUP [--area N] [--all]
#                          [--format table|csv|json|xml]
#                          [--server NAME] [--pwd PASSWORD]
#
# --area    Show only this area/conference number (FILE/MAIL), or only this
#           group number (FILEGROUP). Default: all.
# --all     Also show empty slots (ObjectId == 0). Default: skip empty slots.
# --format  Output format: table (default), csv, json, xml
# --server  WC server name (default: local)
# --pwd     Makewild password (default: none)
#
# Marks the storage path with '?' when the backend directory is not
# reachable (MwCheckPath fails) -- e.g. an expired NETBIOS UNC such as
# \\ntbbs\fido, or a missing folder (Win32 ERROR_PATH_NOT_FOUND). FILE areas
# are checked against their Path; MAIL conferences are checked against their
# MsgDatabase path (primary message storage; blank means inherited default).
#
# The csv/json/xml formats emit the same field set the table does, plus the
# raw diagnostic fields (PathOK/ErrorCode/ErrorText) -- laid down as the
# groundwork for a future wcConfig file/mail area import/export tool, which
# will consume the Number/ObjectId/Title-or-Name/Path fields and can ignore
# the diagnostic ones.
#
# Python port of the internal-use C++ diagnostic wcListFilePaths.exe
# (c:\bin\wcListFilePaths.cpp, MAIN4, not part of the stock distribution),
# generalized here to cover mail conferences as well.
#
# Session: MwLogin (clSessionConfig) -- bulk fetch via MwGetFileAreas / MwGetConfDescs
# Note: Close wcConfig.exe before running (only one Makewild client at a time).
# 500.2  2026-07-17
# 500.2  2026-07-17  --format table|csv|json|xml (wcConfig import/export groundwork)
# 500.2  26.8.6      FILEGROUP kind -- group/area membership tree
#
# ---------------------------------------------------------------------------
# FILEGROUP notes (measured against NTBBS, 30 group slots / 501 area slots)
#
# - GetFileGroupCount() is the allocated group SLOT count, not the defined
#   count -- same convention as GetFileAreaCount(). Undefined slots come back
#   with ObjectId == 0 and a blank Name.
#
# - MwGetFileGroups(1, count-1, arr) fills arr[i] with group number i+1.
#   Group 0 is NOT included: it is the built-in "All files" pseudo-group
#   (ObjectId 0x05000001), reachable only via GetFileGroup(0, fg). It has no
#   stored membership -- every defined area is implicitly a member -- so it is
#   reported here as built-in with an implicit member list.
#
# - MwGetFileGroupBits(group, bytes, bits) returns the area membership bitmap
#   for one group: BIT INDEX == AREA NUMBER (not a 0-based slot index). Bit 0
#   is always set and is reserved/unused -- area numbering starts at 1 -- so
#   it is masked off. The call fails with 0x2000001C on an undefined group
#   slot, which is why undefined slots are skipped before fetching bits.
#
# - IsFileAreaInGroup(group, area) gives the same answer one area at a time
#   and needs no Makewild session, but costs areas*groups round trips (~15,000
#   here). Over a network link that is minutes versus one call per group, so
#   the bitmap is used instead.
# ---------------------------------------------------------------------------

import sys
import ctypes
import argparse
import csv
import json
import io
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

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

FA_FLAGS = [
    (faIsVolume,          'V'),
    (faAllowPrivateFiles, 'F'),
    (faAllowFolderWatch,  'W'),
    (faAllowFileComments, 'C'),
]


def get_connected_server_name():
    buf = ctypes.create_string_buffer(MAX_PATH)
    if GetConnectedServer(buf, MAX_PATH):
        return buf.value.decode('cp437', errors='replace')
    return '(unknown)'


def path_exists(path):
    """(ok, err) -- err is GetLastError() from the failed MwCheckPath call.
    Wildcat! error codes have a base of 0x20000000; anything below that is
    a plain Win32 error surfaced by the underlying call."""
    if not path:
        return False, 0
    p = path.rstrip('\\')
    ok = bool(MwCheckPath(p, False))
    err = 0 if ok else ctypes.GetLastError()
    return ok, err


def format_error(err):
    if err >= 0x20000000:
        return "0x{:08X} {}".format(err, GetWildcatErrorStr(err))
    return "0x{:08X} (Win32)".format(err)


def fa_options_str(pub):
    bits = ''.join(label if (pub.Options & flag) else '-' for flag, label in FA_FLAGS)
    bits += 'E' if pub.ExcludeFromNewFiles else '-'
    bits += 'P' if pub.PromptForPasswordProtect else '-'
    return bits


def serialize_struct(inst):
    """Recursively walk a ctypes.Structure's _fields_ into a plain dict.
    Nested structures (e.g. Public/Paths) recurse; BYTE/DWORD arrays
    (Reserved padding, TLogonHours.day) are hex-encoded since they are raw
    bit/byte blobs, not text. String fields decode via PropertyStruct
    already. Used for --setup: a complete field-for-field dump of the
    Public+Private structures, not just the curated display subset."""
    d = {}
    for fname, ftype in inst._fields_:
        val = getattr(inst, fname)
        if isinstance(val, ctypes.Structure):
            d[fname] = serialize_struct(val)
        elif isinstance(val, ctypes.Array):
            elems = list(val)
            if elems and isinstance(elems[0], int):
                elem_size = ctypes.sizeof(ftype._type_)
                mask = (1 << (elem_size * 8)) - 1
                raw = bytearray()
                for e in elems:
                    raw += (e & mask).to_bytes(elem_size, 'little')
                d[fname] = '0x' + raw.hex().upper()
            else:
                d[fname] = elems
        else:
            d[fname] = val
    return d


def flatten_dict(d, parent_key='', sep='.'):
    """Flatten a nested dict (from serialize_struct) for CSV, e.g.
    {'Public': {'Name': 'x'}} -> {'Public.Name': 'x'}."""
    items = {}
    for k, v in d.items():
        key = "{}{}{}".format(parent_key, sep, k) if parent_key else k
        if isinstance(v, dict):
            items.update(flatten_dict(v, key, sep))
        elif isinstance(v, list):
            items[key] = ','.join(str(x) for x in v)
        else:
            items[key] = v
    return items


# ---------------------------------------------------------------------------
# Data collection -- builds plain-dict records, independent of display format
# ---------------------------------------------------------------------------

def build_file_records(area_filter, show_all):
    # GetFileAreaCount() is the total slot count (allocated, including open
    # slots not yet defined) -- not the effective/defined-area count. Open
    # slots have ObjectId == 0 and/or a blank Name; len(records) below is
    # the effective count after skipping those (unless --all).
    count = GetFileAreaCount()
    if count == 0:
        return []
    fetch = count - 1
    arr = (TWildcatServerPrivateFileArea * fetch)()
    if not MwGetFileAreas(1, fetch, arr):
        err = ctypes.GetLastError()
        print("ERROR: MwGetFileAreas failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    records = []
    for i in range(fetch):
        fa = arr[i]
        pub = fa.Public
        if not show_all and (pub.ObjectId == 0 or not pub.Name):
            continue
        if area_filter is not None and pub.Number != area_filter:
            continue
        ok, err = path_exists(fa.Path)
        records.append({
            'Number':                   pub.Number,
            'ObjectId':                 pub.ObjectId,
            'Title':                    pub.Name,
            'Path':                     fa.Path,
            'IsVolume':                 bool(pub.Options & faIsVolume),
            'AllowPrivateFiles':        bool(pub.Options & faAllowPrivateFiles),
            'AllowFolderWatch':         bool(pub.Options & faAllowFolderWatch),
            'AllowFileComments':        bool(pub.Options & faAllowFileComments),
            'ExcludeFromNewFiles':      bool(pub.ExcludeFromNewFiles),
            'PromptForPasswordProtect': bool(pub.PromptForPasswordProtect),
            'PathOK':                   ok,
            'ErrorCode':                err if not ok else None,
            'ErrorText':                format_error(err) if not ok and err else None,
        })
    return records


def build_mail_records(area_filter, show_all):
    # Per-conference MsgDatabase is an override; blank means "inherit the
    # server default conference path" -- resolve that default up front so
    # a blank override isn't mistaken for a broken/missing path.
    mw = TWildcatServerPrivateConfig()
    default_path = ''
    if MwGetMakewild(ctypes.byref(mw)):
        default_path = mw.DefaultConferencePaths.MsgDatabase
    else:
        err = ctypes.GetLastError()
        print("WARNING: MwGetMakewild failed, cannot resolve default conference path")
        print("  {}".format(GetWildcatErrorStr(err)))

    count = GetConferenceCount()
    if count == 0:
        return []
    fetch = count - 1
    arr = (TWildcatServerPrivateConfDesc * fetch)()
    if not MwGetConfDescs(1, fetch, arr):
        err = ctypes.GetLastError()
        print("ERROR: MwGetConfDescs failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    records = []
    for i in range(fetch):
        cd = arr[i]
        pub = cd.Public
        if not show_all and (pub.ObjectId == 0 or not pub.Name):
            continue
        if area_filter is not None and pub.Number != area_filter:
            continue
        override = cd.Paths.MsgDatabase
        path = override if override else default_path
        is_default = not override
        if not path:
            ok, err = None, None
        else:
            ok, err = path_exists(path)
        records.append({
            'Number':      pub.Number,
            'ObjectId':    pub.ObjectId,
            'Name':        pub.Name,
            'MsgDatabase': path,
            'IsDefault':   is_default,
            'PathOK':      ok,
            'ErrorCode':   err if (err is not None and not ok) else None,
            'ErrorText':   format_error(err) if (err is not None and not ok and err) else None,
        })
    return records


def _file_area_names():
    """{area number: title} for defined file areas -- used to label group
    members. Returns ({}, 0) if the area table cannot be read."""
    count = GetFileAreaCount()
    if count == 0:
        return {}, 0
    fetch = count - 1
    arr = (TWildcatServerPrivateFileArea * fetch)()
    if not MwGetFileAreas(1, fetch, arr):
        err = ctypes.GetLastError()
        print("ERROR: MwGetFileAreas failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)
    names = {}
    for i in range(fetch):
        pub = arr[i].Public
        if pub.ObjectId and pub.Name:
            names[pub.Number] = pub.Name
    return names, count


def _group_members(number, area_slots):
    """Area numbers in one group, from the MwGetFileGroupBits bitmap.
    Bit index == area number; bit 0 is reserved and masked off.
    Returns (members, errcode) -- errcode 0 on success."""
    nbytes = (area_slots + 7) // 8 + 8
    buf = ctypes.create_string_buffer(nbytes)
    if not MwGetFileGroupBits(number, nbytes, buf):
        return [], ctypes.GetLastError()
    raw = buf.raw
    return [a for a in range(1, area_slots + 1)
            if raw[a // 8] & (1 << (a % 8))], 0


def build_filegroup_records(group_filter, show_all):
    """One record per file group slot, each carrying its member area list.
    Group 0 ("All files") is emitted first and flagged built-in: it has no
    stored bitmap, so its membership is the full set of defined areas."""
    area_names, area_slots = _file_area_names()
    all_areas = sorted(area_names)

    count = GetFileGroupCount()
    if count == 0:
        return []

    records = []

    fg0 = TFileGroup()
    if GetFileGroup(0, fg0) and fg0.ObjectId and \
       (group_filter is None or group_filter == 0):
        records.append({
            'Number':      0,
            'ObjectId':    fg0.ObjectId,
            'Name':        fg0.Name,
            'BuiltIn':     True,
            'MemberCount': len(all_areas),
            'Members':     all_areas,
            'MemberNames': [area_names[a] for a in all_areas],
            'ErrorCode':   None,
            'ErrorText':   None,
        })

    fetch = count - 1
    arr = (TFileGroup * fetch)()
    if not MwGetFileGroups(1, fetch, arr):
        err = ctypes.GetLastError()
        print("ERROR: MwGetFileGroups failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    for i in range(fetch):
        g = arr[i]
        defined = bool(g.ObjectId) and bool(g.Name)
        if not show_all and not defined:
            continue
        # arr[i] is group number i+1; an undefined slot reports Number 0
        number = g.Number if defined else i + 1
        if group_filter is not None and number != group_filter:
            continue
        if defined:
            members, err = _group_members(number, area_slots)
        else:
            members, err = [], 0
        records.append({
            'Number':      number,
            'ObjectId':    g.ObjectId,
            'Name':        g.Name,
            'BuiltIn':     False,
            'MemberCount': len(members),
            'Members':     members,
            'MemberNames': [area_names.get(a, '(undefined area)') for a in members],
            'ErrorCode':   err or None,
            'ErrorText':   format_error(err) if err else None,
        })
    return records


def build_file_setup_records(area_filter, show_all):
    """Complete field-for-field export of TWildcatServerPrivateFileArea
    (Public TFileArea + private Path/Reserved), for --setup. One record per
    area; diagnostics (PathOK/ErrorCode/ErrorText) merged in alongside."""
    count = GetFileAreaCount()
    if count == 0:
        return []
    fetch = count - 1
    arr = (TWildcatServerPrivateFileArea * fetch)()
    if not MwGetFileAreas(1, fetch, arr):
        err = ctypes.GetLastError()
        print("ERROR: MwGetFileAreas failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    records = []
    for i in range(fetch):
        fa = arr[i]
        pub = fa.Public
        if not show_all and pub.ObjectId == 0:
            continue
        if area_filter is not None and pub.Number != area_filter:
            continue
        ok, err = path_exists(fa.Path)
        rec = serialize_struct(fa)
        rec['Diagnostics'] = {
            'PathOK':    ok,
            'ErrorCode': err if not ok else None,
            'ErrorText': format_error(err) if not ok and err else None,
        }
        records.append(rec)
    return records


def build_mail_setup_records(area_filter, show_all):
    """Complete field-for-field export of TWildcatServerPrivateConfDesc
    (Public TConfDesc + private Paths/TConferencePaths), for --setup. One
    record per conference; diagnostics merged in against the resolved
    (override-or-default) MsgDatabase path."""
    mw = TWildcatServerPrivateConfig()
    default_path = ''
    if MwGetMakewild(ctypes.byref(mw)):
        default_path = mw.DefaultConferencePaths.MsgDatabase
    else:
        err = ctypes.GetLastError()
        print("WARNING: MwGetMakewild failed, cannot resolve default conference path")
        print("  {}".format(GetWildcatErrorStr(err)))

    count = GetConferenceCount()
    if count == 0:
        return []
    fetch = count - 1
    arr = (TWildcatServerPrivateConfDesc * fetch)()
    if not MwGetConfDescs(1, fetch, arr):
        err = ctypes.GetLastError()
        print("ERROR: MwGetConfDescs failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    records = []
    for i in range(fetch):
        cd = arr[i]
        pub = cd.Public
        if not show_all and (pub.ObjectId == 0 or not pub.Name):
            continue
        if area_filter is not None and pub.Number != area_filter:
            continue
        override = cd.Paths.MsgDatabase
        path = override if override else default_path
        is_default = not override
        if not path:
            ok, err = None, None
        else:
            ok, err = path_exists(path)
        rec = serialize_struct(cd)
        rec['Diagnostics'] = {
            'ResolvedMsgDatabase': path,
            'IsDefault':           is_default,
            'PathOK':              ok,
            'ErrorCode':           err if (err is not None and not ok) else None,
            'ErrorText':           format_error(err) if (err is not None and not ok and err) else None,
        }
        records.append(rec)
    return records


# ---------------------------------------------------------------------------
# Rendering -- table (human), csv/json/xml (machine, wcConfig import/export)
# ---------------------------------------------------------------------------

def render_table_file(records):
    hdr = "{:>4}  {:<8}  {:<6}  {:<30}  {}".format("AREA", "OID", "ATTR", "TITLE", "PATH")
    print(hdr)
    print('-' * len(hdr))
    for r in records:
        attr = (('V' if r['IsVolume'] else '-') +
                ('F' if r['AllowPrivateFiles'] else '-') +
                ('W' if r['AllowFolderWatch'] else '-') +
                ('C' if r['AllowFileComments'] else '-') +
                ('E' if r['ExcludeFromNewFiles'] else '-') +
                ('P' if r['PromptForPasswordProtect'] else '-'))
        line = "{:>4}  {:<8X}  {:<6}  {:<30}  {}{}".format(
            r['Number'], r['ObjectId'], attr, r['Title'],
            ' ' if r['PathOK'] else '?', r['Path'])
        if not r['PathOK'] and r['ErrorText']:
            line += "  [{}]".format(r['ErrorText'])
        print(line)
    print()
    print("{} file area(s) listed.".format(len(records)))


def render_table_mail(records):
    hdr = "{:>4}  {:<8}  {:<40}  {}".format("CONF", "OID", "NAME", "MSGDATABASE PATH")
    print(hdr)
    print('-' * len(hdr))
    for r in records:
        if not r['MsgDatabase']:
            marker, shown = ' ', '(no default path set)'
        else:
            marker = ' ' if r['PathOK'] else '?'
            shown = r['MsgDatabase'] + ('  [default]' if r['IsDefault'] else '')
            if not r['PathOK'] and r['ErrorText']:
                shown += "  [{}]".format(r['ErrorText'])
        print("{:>4}  {:<8X}  {:<40}  {}{}".format(
            r['Number'], r['ObjectId'], r['Name'], marker, shown))
    print()
    print("{} mail conference(s) listed.".format(len(records)))


def render_tree_filegroup(records, complete=True):
    """Groups/Areas tree. An area may appear under several groups (membership
    is many-to-many), so the trailing orphan list -- defined areas in no
    user-defined group -- is the reorganization-relevant part. That list is
    only meaningful over the whole group set, so it is suppressed when
    --area narrowed the output to a single group."""
    print("FILE GROUPS -> AREAS")
    print('=' * 72)

    covered = set()
    for r in records:
        tag = '  [built-in, implicit]' if r['BuiltIn'] else ''
        if not r['ObjectId']:
            print("\n[{:>2}] (open slot)".format(r['Number']))
            continue
        print("\n[{:>2}] {}  ({} area(s)){}".format(
            r['Number'], r['Name'], r['MemberCount'], tag))
        if r['ErrorText']:
            print("      !! membership unavailable: {}".format(r['ErrorText']))
            continue
        if not r['MemberCount']:
            print("      (empty)")
            continue
        for num, name in zip(r['Members'], r['MemberNames']):
            print("      +- {:>4}  {}".format(num, name))
        if not r['BuiltIn']:
            covered.update(r['Members'])

    print()
    print('=' * 72)
    print("{} group(s) listed.".format(len(records)))
    if not complete:
        print("(orphan area report suppressed -- needs the full group set)")
        return
    all_areas, _ = _file_area_names()
    orphans = sorted(set(all_areas) - covered)
    print("{} defined area(s) in no user-defined group:".format(len(orphans)))
    for num in orphans:
        print("      -- {:>4}  {}".format(num, all_areas[num]))


def render_csv_filegroup(records):
    """Normalized edge list -- one row per (group, area) membership -- rather
    than the nested form used by json/xml. Area titles contain commas
    ("WC! Networks, LANtastic/Novel"), so a comma-joined member list inside a
    quoted CSV field would be ambiguous; one row per edge also pivots and
    diffs directly, which is the point of a reorganization export.
    Groups with no members emit a single row with a blank AreaNumber."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['GroupNumber', 'GroupName', 'GroupObjectId', 'BuiltIn',
                'AreaNumber', 'AreaName'])
    for r in records:
        if not r['Members']:
            w.writerow([r['Number'], r['Name'], '{:08X}'.format(r['ObjectId']),
                        r['BuiltIn'], '', ''])
            continue
        for num, name in zip(r['Members'], r['MemberNames']):
            w.writerow([r['Number'], r['Name'], '{:08X}'.format(r['ObjectId']),
                        r['BuiltIn'], num, name])
    sys.stdout.write(out.getvalue())


def render_csv(records):
    if not records:
        return
    flat = [flatten_dict(r) for r in records]
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=list(flat[0].keys()))
    w.writeheader()
    w.writerows(flat)
    sys.stdout.write(out.getvalue())


def render_json(records):
    print(json.dumps(records, indent=2))


def _xml_build(parent, key, val):
    if isinstance(val, dict):
        child = ET.SubElement(parent, key)
        for k, v in val.items():
            _xml_build(child, k, v)
    elif isinstance(val, list):
        child = ET.SubElement(parent, key)
        child.text = ','.join(str(x) for x in val)
    else:
        child = ET.SubElement(parent, key)
        child.text = '' if val is None else str(val)


XML_TAGS = {
    'FILE':      ('FileAreas',  'FileArea'),
    'MAIL':      ('MailAreas',  'MailArea'),
    'FILEGROUP': ('FileGroups', 'FileGroup'),
}


def render_xml(kind, records):
    root_tag, item_tag = XML_TAGS[kind]
    root = ET.Element(root_tag)
    for r in records:
        item = ET.SubElement(root, item_tag)
        for key, val in r.items():
            _xml_build(item, key, val)
    pretty = minidom.parseString(ET.tostring(root, encoding='utf-8')).toprettyxml(indent='  ')
    print(pretty)


def render(kind, fmt, records, complete=True):
    if fmt == 'table':
        if kind == 'FILE':
            render_table_file(records)
        elif kind == 'FILEGROUP':
            render_tree_filegroup(records, complete)
        else:
            render_table_mail(records)
    elif fmt == 'csv':
        if kind == 'FILEGROUP':
            render_csv_filegroup(records)
        else:
            render_csv(records)
    elif fmt == 'json':
        render_json(records)
    elif fmt == 'xml':
        render_xml(kind, records)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if '/?' in sys.argv:
    sys.argv[sys.argv.index('/?')] = '--help'

parser = argparse.ArgumentParser(
    description="Show backend storage paths for FILE or MAIL areas, "
                "or the FILEGROUP -> file area membership tree")
parser.add_argument('kind', choices=['FILE', 'MAIL', 'FILEGROUP',
                                     'file', 'mail', 'filegroup'],
                    help="What to list: FILE, MAIL, or FILEGROUP (group/area tree)")
parser.add_argument('--area', type=int, default=None,
                    help="Show only this area/conference number "
                         "(FILEGROUP: only this group number)")
parser.add_argument('--all', action='store_true', help="Also show empty slots (ObjectId == 0)")
parser.add_argument('--format', choices=['table', 'csv', 'json', 'xml'], default='table',
                    help="Output format (default: table)")
parser.add_argument('--setup', action='store_true',
                    help=("Complete field-for-field export of the Public+Private "
                          "structures (TFileArea/TConfDesc + backend Path/Paths), "
                          "not just the curated display columns. Requires "
                          "--format csv|json|xml (not table)."))
parser.add_argument('--server', default='', help="WC server name (default: local)")
parser.add_argument('--pwd',    default='', help="Makewild password (default: none)")
args = parser.parse_args()

if args.setup and args.format == 'table':
    print("ERROR: --setup requires --format csv|json|xml (table cannot show nested structures).")
    sys.exit(1)

kind = args.kind.upper()

if args.setup and kind == 'FILEGROUP':
    print("ERROR: --setup does not apply to FILEGROUP (TFileGroup has no private side; "
          "the default output is already the complete record plus membership).")
    sys.exit(1)

quiet = args.format != 'table'   # keep machine formats free of banner/status noise

if not quiet:
    print("wcListArea.py [{}]".format(kind))
    print("  Password: {}".format("(set)" if args.pwd else "(none)"))

if not WildcatServerConnectSpecific(None, args.server):
    err = ctypes.GetLastError()
    print("ERROR: Cannot connect to server {!r}".format(args.server))
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)

if not quiet:
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

    if kind == 'FILEGROUP':
        records = build_filegroup_records(args.area, args.all)
    elif kind == 'FILE':
        records = build_file_setup_records(args.area, args.all) if args.setup \
                   else build_file_records(args.area, args.all)
    else:
        records = build_mail_setup_records(args.area, args.all) if args.setup \
                   else build_mail_records(args.area, args.all)

    render(kind, args.format, records, complete=args.area is None)

finally:
    WildcatServerDeleteContext()
