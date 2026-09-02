#!/usr/bin/env python
# wcat-ListFiles.py -- Wildcat! File Area Lister
# Displays TFileRecord entries via the wcPAPI file-record traversal
# functions (GetFirstFileRec/GetNextFileRec, SearchFileRecByXxx).
#
# Usage:
#   python wcat-ListFiles.py [--area #] [--info] [--sort ordinal]
#                            [--find string | --search words] [--server name]
#
# Options:
#   --area #     List only this file area. Default: all areas.
#   --info       Also display the long description under each file.
#   --search     Indexed search via FileSearch(): the server queries the
#                file database word index (name, description and long
#                description) and returns only the hits.  Matches whole
#                WORDS.  Use this in preference to --find.
#   --find       Substring match, but walks EVERY record in the base and
#                tests it here.  Slow across a network -- pair it with
#                --area, or use --search.
#   --sort       Sort/traversal key ordinal (default 1):
#                  0 = Name+Area
#                  1 = Area+Name (default)
#                  2 = Area+Date
#                  3 = Uploader
#                  4 = Date+Area
#   --server     WC server name (default: "")
#
# Revision History:
# 500.2  26.6.21  Initial version
# 500.2  26.6.21  YYYY-MM-DD date, 36-wide file name, --sort, --find
# 500.2  26.8.6   Force CP437 stdout so redirected output cannot raise
#                 UnicodeEncodeError on extended (line-draw) characters
# 500.2  26.9.2   --search: indexed lookup via FileSearch() instead of
#                 walking every record.  0.035s vs 120s+ over the network.

import ctypes
import sys
import argparse
import datetime

import wcpapi
from wcpapi.wcserver_h import *
from wcpapi.wcserror_h import *
from wcpapi.wctype_h import *
from wcpapi.wctype_constants_h import *

# ---------------------------------------------------------------------------
# Output encoding
#
# File/long descriptions are stored as CP437 (OEM) bytes and are decoded to
# Unicode by decode_wc().  When stdout is redirected to a file, Python picks
# the ANSI locale codepage (cp1252) which has no mapping for the CP437
# line-draw/graphic range, so print() raises UnicodeEncodeError.  Emit CP437
# instead -- it round-trips what the BBS stored and matches the OEM editor.
# ---------------------------------------------------------------------------

try:
    sys.stdout.reconfigure(encoding='cp437', errors='replace')
    sys.stderr.reconfigure(encoding='cp437', errors='replace')
except (AttributeError, ValueError):
    pass

# ---------------------------------------------------------------------------
# Sort/traversal keys
# - Ordinals 1 and 2 have Area as the leading key component, so a specific
#   area can be seeked to directly and the traversal stopped once Area
#   changes.
# - Ordinals 0, 3, 4 do not have Area leading, so an --area filter on those
#   requires a full scan with a Python-side Area check (no seek, no early
#   stop).
# ---------------------------------------------------------------------------

SORT_METHODS = {
    0: ("Name+Area",  FileNameAreaKey),
    1: ("Area+Name",  FileAreaNameKey),
    2: ("Area+Date",  FileAreaDateKey),
    3: ("Uploader",   FileUploaderKey),
    4: ("Date+Area",  FileDateAreaKey),
}
AREA_LEADING_SORTS = (1, 2)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FILETIME_EPOCH = datetime.datetime(1601, 1, 1)

def filetime_to_str(ft):
    if ft.dwHighDateTime == 0 and ft.dwLowDateTime == 0:
        return ''
    ticks = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    dt = FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def decode_wc(b):
    if isinstance(b, (bytes, bytearray)):
        return b.decode('cp437', errors='replace').rstrip('\x00').strip()
    return str(b).strip()

def get_long_description(frec):
    full = TFullFileRecord()
    if not GetFullFileRec(frec, full):
        return []
    if not full.Info.HasLongDescription:
        return []
    lines = []
    for item in full.LongDescription:
        line = decode_wc(item.Item)
        if line:
            lines.append(line)
    return lines

# ---------------------------------------------------------------------------
# Table format
# Columns: conf | size | date/time | dcount | file name | description
# ---------------------------------------------------------------------------

NAME_WIDTH = 36

TABLE_HDR = "{:>4} {:>10} {:19} {:>6} {:<{w}} {}".format(
    "conf", "size", "date/time", "dcount", "file name", "description",
    w=NAME_WIDTH)
TABLE_SEP = "-" * 100

def print_table_row(frec, name, desc):
    date = filetime_to_str(frec.FileTime)

    print("{:>4} {:>10} {:19} {:>6} {:<{w}} {}".format(
        frec.Area,
        frec.Size,
        date,
        frec.Downloads,
        name,
        desc,
        w=NAME_WIDTH))

def print_long_description(lines):
    for line in lines:
        print("     {}".format(line))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Indexed search (--search)
#
# FileSearch() queries the file database's word index, which covers the
# name, description and long description.  The server does the work and
# returns only the hits, instead of this tool pulling every record and
# testing it here.
#
# Measured against NTBBS over the network, looking for one file:
#
#     --find  (whole base, ~2000 records)   over 120 seconds
#     --find  with --area 44                     6.8 seconds
#     --search                                   0.035 seconds
#
# The C prototype is
#
#     BOOL FileSearch(const char *s, DWORD &n, unsigned __int64 *&p);
#
# where p is an OUT pointer the server allocates: an array of 64-bit
# values, high 32 bits = file area, low 32 bits = absolute record ref.
# ---------------------------------------------------------------------------

def free_search_buffer(p):
    """Release the buffer FileSearch() handed us.

    wcsrv2.dll allocates it with its own CRT, so it can only be freed on
    that side of the boundary.  WcFreeMemory() exists for exactly this
    (wcServer\\wcsrv.cpp, 500.3) and is the only correct way to do it
    from Python.

    Guarded with getattr because wcPAPI may be newer than the installed
    wcsrv2.dll.  Against a pre-500.3 DLL the export is absent; the
    buffer is then left alone, which is what this tool did before the
    function existed -- 8 bytes per hit in a process about to exit.
    """
    fn = globals().get('WcFreeMemory', None)
    if fn is not None and p:
        fn(p)


def indexed_search(spec, area_filter):
    """Return [(area, ref), ...] from the file database index."""
    # The stock binding declares p as POINTER(c_ulonglong); the prototype
    # takes it by reference, so re-declare to let ctypes pass byref(ptr).
    FileSearch.argtypes = [CString,
                           ctypes.POINTER(DWORD),
                           ctypes.POINTER(ctypes.POINTER(ctypes.c_ulonglong))]

    n = DWORD(0)
    p = ctypes.POINTER(ctypes.c_ulonglong)()
    if not FileSearch(spec, ctypes.byref(n), ctypes.byref(p)):
        return []

    hits = []
    for i in range(n.value):
        v = p[i]
        ref  = v & 0xFFFFFFFF
        area = (v >> 32) & 0xFFFFFFFF
        if area_filter is not None and area != area_filter:
            continue
        hits.append((area, ref))

    # Sort on the index values we already hold, so ordering is stable
    # without fetching every record first just to sort it.
    hits.sort()

    free_search_buffer(p)

    # Ownership, traced 2026-09-02 -- freed above by WcFreeMemory():
    #
    # Each process supplies its own RPC allocator pair, matched within
    # its own CRT:
    #
    #   wcserver.exe   WildcatServer.cpp:131/136  malloc / free
    #   wcsrv2.dll     wcsrv.cpp:776/785          malloc / free
    #                  (built by wcServer\wcsrv2.vcxproj)
    #
    #   SERVER  wcServer\wcsdbf.cpp WcsFileSearch() mallocs into the
    #           [ref][out] parameter.  Once the RPC server stub has
    #           marshalled the reply it releases that pointer through
    #           WildcatServer.cpp's midl_user_free, matching the malloc.
    #           This happens inside wcserver.exe whatever the client
    #           does, so a client that never frees CANNOT leak server
    #           memory -- local or remote, the server is a separate
    #           process.
    #
    #   CLIENT  the RPC client stub allocates the receive buffer with
    #           wcsrv2.dll's own midl_user_allocate, and the caller owns
    #           it.  That is the free(p) in testfilesearch.cpp.
    #
    # The leak was therefore client-side only.  wcsrv2.dll 500.3 adds
    # WcFreeMemory(), which frees on the DLL's own side of the CRT
    # boundary -- the one thing a ctypes caller cannot do itself -- so
    # free_search_buffer() above now closes it.
    return hits


def main():
    if '/?' in sys.argv:
        sys.argv[sys.argv.index('/?')] = '--help'

    sort_help = "Sort/traversal key ordinal (default 1): " + \
        ", ".join("{}={}".format(k, v[0]) for k, v in sorted(SORT_METHODS.items()))

    parser = argparse.ArgumentParser(description="Wildcat! File Area Lister")
    parser.add_argument('--area',   type=int,            help="List only this file area")
    parser.add_argument('--info',   action='store_true', help="Show long description under each file")
    parser.add_argument('--sort',   type=int, default=1, choices=sorted(SORT_METHODS), help=sort_help)
    parser.add_argument('--find',   default=None,        help="Only list files matching this string (name/description/long description). Walks EVERY record; slow over a network. Add --area to scope it, or prefer --search.")
    parser.add_argument('--search', default=None,        help="Indexed search of the file database (name/description/long description words). Far faster than --find; matches whole words, not substrings.")
    parser.add_argument('--server', default='',     help="WC server name")
    args = parser.parse_args()

    keyname, keynum = SORT_METHODS[args.sort]

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

        # --search: ask the server's index instead of walking the base
        if args.search is not None:
            hits = indexed_search(args.search, args.area)
            print("Search: {!r}  (indexed)".format(args.search))
            print(TABLE_HDR)
            print(TABLE_SEP)
            count = 0
            for area, ref in hits:
                frec = TFileRecord()
                if not GetFileRecAbsolute(ref, ctypes.byref(frec)):
                    continue
                name = decode_wc(frec.Name)
                desc = decode_wc(frec.Description)
                print_table_row(frec, name, desc)
                if args.info:
                    print_long_description(get_long_description(frec))
                count += 1
            print(TABLE_SEP)
            print("Displayed: {}".format(count))
            return

        frec = TFileRecord()
        tid  = DWORD()

        seek_by_area = args.area is not None and args.sort in AREA_LEADING_SORTS

        if seek_by_area:
            if args.sort == 1:
                found = SearchFileRecByAreaName(args.area, "", frec, tid)
            else:
                found = SearchFileRecByAreaDate(args.area, FILETIME(), frec, tid)
        else:
            found = GetFirstFileRec(keynum, frec, tid)

        findstr = args.find.lower() if args.find else None

        print("Sort: {} ({})".format(args.sort, keyname))
        print(TABLE_HDR)
        print(TABLE_SEP)

        count = 0
        while found:
            if seek_by_area and frec.Area != args.area:
                break

            if not seek_by_area and args.area is not None and frec.Area != args.area:
                found = GetNextFileRec(keynum, frec, tid)
                continue

            name = decode_wc(frec.Name)
            desc = decode_wc(frec.Description)
            longdesc = get_long_description(frec) if args.info else []

            if findstr is not None:
                hay = (name + ' ' + desc + ' ' + ' '.join(longdesc)).lower()
                if findstr not in hay:
                    found = GetNextFileRec(keynum, frec, tid)
                    continue

            print_table_row(frec, name, desc)
            if args.info:
                print_long_description(longdesc)
            count += 1
            found = GetNextFileRec(keynum, frec, tid)

        print(TABLE_SEP)
        print("Displayed: {}".format(count))

    finally:
        WildcatServerDeleteContext()

if __name__ == "__main__":
    main()
