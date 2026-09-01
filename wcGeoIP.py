#!/usr/bin/env python
# wcGeoIP.py -- GeoIP lookup via the Wildcat! platform (WcGetGeoIP RPC)
# Usage: py wcGeoIP.py <ip | @listfile> [--server NAME | --path LOCATION]
#                      [--access INIFILE] [--full] [--col N]
#
# <ip>       IP address to look up.
# @listfile  Read addresses from a file, one per line. Blank lines and
#            lines starting with # or ; are skipped. Each line is cut at
#            the first space, so log lines mostly work as-is.
#
# --server   Wildcat! computername for the RPC lookup. Default "" = local.
# --path     Read wcGeoIP.mmdb DIRECTLY with the geoip2 module instead of
#            asking a server. Accepts a directory (wcGeoIP.mmdb appended)
#            or a full file path. NOT valid with --server.
# --access   Full path to an access.ini. Adds Access/Rule columns showing
#            the SIMULATED filter verdict for each address.
# --full     Dump all 12 TWildcatGeoIP fields instead of one line per IP.
# --col N    Skip N characters at the start of each @listfile line before
#            parsing the address (same idea as ListGeoLoc's [#colpos]).
#
# Session: WildcatServerConnectSpecific + WildcatServerCreateContext.
# No MwLogin -- GeoIP needs no Makewild session (cf. ListGeoLoc.cpp).
#
# Why two modes: --server reports what a RUNNING Wildcat! actually has
# loaded, which is what accepts or blocks a caller. --path interrogates a
# specific .mmdb file. Comparing them answers "is this server's database
# stale?" -- e.g. an AUP caller geo-blocked on an out-of-date build.
#
# --access simulation mirrors CheckNetworkAddress() in wcotelnt.cpp:
#     if not [whitelist] ip:
#         if [blacklist] ip      -> DENY
#         if not [countries] cc  -> DENY
#     -> PASS
# NOTE this DEFAULTS TO DENY for a country that is not listed. CheckGeo.wcc
# reads only [countries] with iniGetBoolean(...,true,...), i.e. defaults to
# ALLOW, so it reports Pass where the server actually denies. This tool
# follows the server, not CheckGeo.wcc.
# NOTE the server also applies CheckClientAddress()/ipaccess.dat AFTER
# these rules. That layer is NOT simulated here.
#
# Companions in wcSDK: c:\wc10beta32\ListGeoLoc.cpp, testwcgeoip.cpp,
# testwcGeoIP.wcc, showgeoip.wcc, CheckGeo.wcc,
# http\public\TestGeoIP.wct.
# 500.3  26.8.21

import sys
import os
import ctypes
import argparse

VERSION = "26.8.21"

# TWildcatGeoIP field order, per wctype.h
GEO_FIELDS = [
    'ipaddr', 'city', 'continent', 'country', 'latitude', 'longitude',
    'metro_code', 'tzone', 'postal', 'country_code', 'region_code',
    'region_name',
]

BASE_HDR = "{:<16} {:<3} {:<22} {:<18} {:<11} {:<11}".format(
    "IP", "CC", "Country", "City", "Latitude", "Longitude")
BASE_SEP = "{:-<16} {:-<3} {:-<22} {:-<18} {:-<11} {:-<11}".format(
    '', '', '', '', '', '')
ACC_HDR = " {:<6} {}".format("Access", "Rule")
ACC_SEP = " {:-<6} {:-<28}".format('', '')


def as_text(v):
    """PropertyStruct fields may come back as str or bytes."""
    if isinstance(v, bytes):
        return v.decode('cp437', errors='replace')
    return '' if v is None else str(v)


# ---------------------------------------------------------------------------
# Minimal INI reader. Deliberately not configparser: these files can carry
# duplicate keys and bare lines that configparser rejects, and Windows INI
# lookups are case-insensitive for both section and key.
# ---------------------------------------------------------------------------
class IniFile(object):
    def __init__(self, filename):
        self.filename = filename
        self.sections = {}
        section = ''
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line[0] in ';#':
                    continue
                if line[0] == '[' and line.endswith(']'):
                    section = line[1:-1].strip().lower()
                    self.sections.setdefault(section, {})
                    continue
                if '=' not in line:
                    continue
                key, val = line.split('=', 1)
                self.sections.setdefault(section, {})[key.strip().lower()] = val.strip()

    def has(self, section, key):
        if not key:
            return False
        return key.strip().lower() in self.sections.get(section.lower(), {})

    def get_int(self, section, key, default=0):
        if not key:
            return default
        val = self.sections.get(section.lower(), {}).get(key.strip().lower())
        if val is None:
            return default
        # GetPrivateProfileInt stops at the first non-numeric character.
        num = ''
        for ch in val:
            if ch.isdigit() or (ch == '-' and not num):
                num += ch
            else:
                break
        try:
            return int(num)
        except ValueError:
            return default


def access_verdict(rec, ini):
    """Mirror CheckNetworkAddress() in wcotelnt.cpp. Returns (status, rule)."""
    ip = rec.get('ipaddr', '')
    cc = rec.get('country_code', '')
    if ini.get_int('whitelist', ip, 0):
        return 'Pass', 'whitelist'
    if ini.get_int('blacklist', ip, 0):
        return 'DENY', 'blacklist'
    if not ini.get_int('countries', cc, 0):
        if ini.has('countries', cc):
            # Explicitly rejected. access.ini enumerates every country code
            # with 1=allow / 0=reject, so this is the usual DENY, not a gap.
            return 'DENY', 'country {} = 0'.format(cc)
        return 'DENY', 'country {} not listed'.format(cc if cc else '?')
    return 'Pass', 'country {}'.format(cc)


def print_full(rec, source, verdict):
    print("# source      : {}".format(source))
    print("# has_data    : {}".format(rec.get('has_data', '')))
    for name in GEO_FIELDS:
        print("- {:<12}: [{}]".format(name, rec.get(name, '')))
    if verdict:
        print("= access      : {}  ({})".format(verdict[0], verdict[1]))
    print("")


def print_row(rec, verdict):
    line = "{:<16} {:<3} {:<22} {:<18} {:<11} {:<11}".format(
        rec.get('ipaddr', '')[:16],
        rec.get('country_code', '')[:3],
        rec.get('country', '')[:22],
        rec.get('city', '')[:18],
        rec.get('latitude', '')[:11],
        rec.get('longitude', '')[:11])
    if verdict:
        line += " {:<6} {}".format(verdict[0], verdict[1])
    print(line)


def read_list(spec, col):
    """Expand '@file' into a list of addresses."""
    fn = spec[1:]
    out = []
    try:
        with open(fn, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line[0] in '#;':
                    continue
                if col:
                    line = line[col:]
                sp = line.find(' ')
                if sp > 0:
                    line = line[:sp]
                line = line.strip()
                if line:
                    out.append(line)
    except IOError as e:
        print("ERROR: cannot read {!r}: {}".format(fn, e))
        sys.exit(1)
    return out


# ---------------------------------------------------------------------------
# Lookup backends. Both return (rec_dict_or_None, error_string_or_None).
# ---------------------------------------------------------------------------

def lookup_server(ip):
    gip = TWildcatGeoIP()
    if not WcGetGeoIP(ip, ctypes.byref(gip), "en"):
        err = ctypes.GetLastError()
        if err == WC_DBASE_NOT_AVAILABLE:
            return None, ("WC_DBASE_NOT_AVAILABLE - the server has no GeoIP "
                          "database loaded (check data\\wcGeoIP.mmdb)")
        return None, "{:08X}  {}".format(err, GetWildcatErrorStr(err))
    rec = {'has_data': int(getattr(gip, 'has_data', 0) or 0)}
    for name in GEO_FIELDS:
        rec[name] = as_text(getattr(gip, name, ''))
    if not rec['ipaddr']:
        rec['ipaddr'] = ip
    return rec, None


def lookup_path(ip, reader):
    try:
        r = reader.city(ip)
    except Exception as e:
        return None, "{}: {}".format(type(e).__name__, e)
    rec = {'has_data': 1, 'ipaddr': ip}
    rec['city']         = as_text(r.city.name)
    rec['continent']    = as_text(r.continent.name)
    rec['country']      = as_text(r.country.name)
    rec['latitude']     = as_text(r.location.latitude)
    rec['longitude']    = as_text(r.location.longitude)
    rec['metro_code']   = as_text(r.location.metro_code)
    rec['tzone']        = as_text(r.location.time_zone)
    rec['postal']       = as_text(r.postal.code)
    rec['country_code'] = as_text(r.country.iso_code)
    sub = r.subdivisions.most_specific
    rec['region_code']  = as_text(sub.iso_code)
    rec['region_name']  = as_text(sub.name)
    return rec, None


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
if '/?' in sys.argv:
    sys.argv[sys.argv.index('/?')] = '--help'

parser = argparse.ArgumentParser(
    description="GeoIP lookup via Wildcat! (WcGetGeoIP) or a local .mmdb")
parser.add_argument('target', metavar='ip|@listfile',
                    help="IP address, or @file holding one per line")
parser.add_argument('--server', default='',
                    help="Wildcat! server name (default: local)")
parser.add_argument('--path', default='',
                    help="Read wcGeoIP.mmdb directly. Not valid with --server.")
parser.add_argument('--access', default='', metavar='INIFILE',
                    help="access.ini to simulate the filter verdict against")
parser.add_argument('--full', action='store_true',
                    help="Dump all TWildcatGeoIP fields")
parser.add_argument('--col', type=int, default=0,
                    help="Skip N chars at the start of each @listfile line")
parser.add_argument('--version', action='version',
                    version='wcGeoIP.py {}'.format(VERSION))
args = parser.parse_args()

if args.path and args.server:
    print("ERROR: --path and --server are mutually exclusive.")
    print("  --server asks a running Wildcat!; --path reads an .mmdb file.")
    sys.exit(1)

ini = None
if args.access:
    if not os.path.isfile(args.access):
        print("ERROR: access file {!r} not found.".format(args.access))
        sys.exit(1)
    try:
        ini = IniFile(args.access)
    except IOError as e:
        print("ERROR: cannot read {!r}: {}".format(args.access, e))
        sys.exit(1)

targets = read_list(args.target, args.col) if args.target.startswith('@') \
          else [args.target]
if not targets:
    print("ERROR: no addresses to look up.")
    sys.exit(1)

HDR = BASE_HDR + (ACC_HDR if ini else '')
SEP = BASE_SEP + (ACC_SEP if ini else '')

found = 0
missing = 0
failed = 0
denied = 0
passed = 0


def banner(source):
    print("wcGeoIP.py {}".format(VERSION))
    print("  Source  : {}".format(source))
    if ini:
        n_w = len(ini.sections.get('whitelist', {}))
        n_b = len(ini.sections.get('blacklist', {}))
        n_c = len(ini.sections.get('countries', {}))
        print("  Access  : {}".format(ini.filename))
        print("            whitelist={}  blacklist={}  countries={}".format(
            n_w, n_b, n_c))
    print("")
    if not args.full:
        print(HDR)
        print(SEP)


# ---------------------------------------------------------------------------
# --path : direct .mmdb read
# ---------------------------------------------------------------------------
if args.path:
    try:
        import geoip2.database
    except ImportError:
        print("ERROR: --path needs the geoip2 module (pip install geoip2).")
        print("  Omit --path to use the Wildcat! server instead.")
        sys.exit(1)

    dbfn = args.path
    if os.path.isdir(dbfn):
        dbfn = os.path.join(dbfn, 'wcGeoIP.mmdb')
    if not os.path.isfile(dbfn):
        print("ERROR: {!r} not found.".format(dbfn))
        sys.exit(1)

    import time
    stamp = time.strftime('%m/%d/%Y %H:%M:%S',
                          time.localtime(os.path.getmtime(dbfn)))
    source = "{}  ({:,} bytes, {})".format(dbfn, os.path.getsize(dbfn), stamp)
    banner(source)

    reader = geoip2.database.Reader(dbfn)
    try:
        for ip in targets:
            rec, err = lookup_path(ip, reader)
            if err:
                print("ERROR: {}  IP: {}".format(err, ip))
                missing += 1
                continue
            found += 1
            verdict = access_verdict(rec, ini) if ini else None
            if verdict:
                if verdict[0] == 'DENY':
                    denied += 1
                else:
                    passed += 1
            if args.full:
                print_full(rec, source, verdict)
            else:
                print_row(rec, verdict)
    finally:
        reader.close()

# ---------------------------------------------------------------------------
# default / --server : wcPAPI RPC
# ---------------------------------------------------------------------------
else:
    try:
        from wcpapi.wcserver_h import *
        from wcpapi.wctype_h import *
        from wcpapi.wctype_constants_h import *
        from wcpapi.wcserror_h import *
    except ImportError as e:
        print("ERROR: wcpapi package not found: {}".format(e))
        print("  pip install -e c:\\local\\wcPython")
        sys.exit(1)

    def connected_name():
        buf = ctypes.create_string_buffer(MAX_PATH)
        if GetConnectedServer(buf, MAX_PATH):
            return buf.value.decode('cp437', errors='replace')
        return '(unknown)'

    if not WildcatServerConnectSpecific(None, args.server):
        err = ctypes.GetLastError()
        print("ERROR: Cannot connect to server {!r}".format(args.server))
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    if not WildcatServerCreateContext():
        err = ctypes.GetLastError()
        print("ERROR: WildcatServerCreateContext failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    try:
        source = "server {}".format(connected_name())
        banner(source)

        for ip in targets:
            rec, err = lookup_server(ip)
            if err:
                print("ERROR: {}  IP: {}".format(err, ip))
                failed += 1
                continue
            if not rec['has_data']:
                print("{:<16} (no data in database)".format(ip[:16]))
                missing += 1
                continue
            found += 1
            verdict = access_verdict(rec, ini) if ini else None
            if verdict:
                if verdict[0] == 'DENY':
                    denied += 1
                else:
                    passed += 1
            if args.full:
                print_full(rec, source, verdict)
            else:
                print_row(rec, verdict)
    finally:
        WildcatServerDeleteContext()

# ---------------------------------------------------------------------------
if len(targets) > 1 or missing or failed:
    print("")
    print("{} found, {} with no data, {} error(s), {} total.".format(
        found, missing, failed, len(targets)))
    if ini:
        print("{} pass, {} DENY.".format(passed, denied))

sys.exit(0 if found and not failed else 1)
