#!/usr/bin/env python
# wcSmtpLogSummary.py -- Summarize wcSMTP daily log files (wcsmtp<date>.log)
# Usage: py wcSmtpLogSummary.py [--dir PATH] [--date YYYYMMDD [YYYYMMDD]]
#                                [--server NAME] [--top N] [--format text|json]
#
# --dir      Directory containing wcsmtp<date>.log files (default: .)
# --date     One value: a date glob, e.g. 20260718 (one day) or 202607*
#            (a whole month). Default: today's date (YYYYMMDD).
#            Two values: an explicit start/end date range (both plain
#            YYYYMMDD, no wildcards), e.g. --date 20260710 20260718 --
#            matches every calendar day in that inclusive range whether or
#            not a log exists for it (missing days are just skipped).
# --server   Filter to a specific server suffix, e.g. NTBBS
#            (matches wcsmtp<date>*.<SERVER>.log, case-insensitive). Default: all.
# --top      Number of entries to show in each ranked list (default: 15)
# --format   text (default, human report) or json (machine-readable)
#
# The filename pattern is always anchored as wcsmtp<date>*.log (or
# wcsmtp<date>*.<server>.log) -- deliberately NOT a bare wcsmtp*.log, since
# that would also sweep up the wcSMTPTrace / wcSMTPSendTrace session trace
# logs, which are a different file family entirely.
#
# Pure log-file analysis -- no wcPAPI/server connection required, just
# reads the wcSMTP text logs (one file per day, format:
# YYYYMMDD HH:MM:SS.mmm (TAG) message).
#
# Categorizes each line into:
#   fwblock   -- (RCVR) SMTP FIREWALL BLOCK IP: x.x.x.x
#                Pre-thread reject: IP already on the blocklist.
#   wcxblock  -- IP x.x.x.x blocked by smtpcmd-connect.wcx (reply.code: nnn)
#                Thread was allocated, then the connect script rejected it.
#   drop      -- ! connection drop - error: nnnnn state: ... lastcmd: ...
#                Remote side aborted/reset mid-session (often bot probing).
#   ehlo      -- EHLO: Incoming connection: host [ip]
#   accepted  -- Accepted message from [...] to [...]
#   queued    -- Queued(x) msgid for: recipient
#
# Also tracks distinct per-minute thread-tag activity as a connection-load
# proxy for the Maximum Accept Connections / Maximum Accept Load settings --
# NOTE: this counts distinct thread tags seen within a minute, which is a
# turnover-rate proxy, not verified simultaneous concurrency (a single
# source firing serial connect/EHLO/drop cycles inflates it the same as
# genuine concurrent load would; check the underlying lines for the source
# IP spread before concluding it's a real capacity concern).
#
# Grew out of an ad hoc 9-day NTBBS analysis (2026-07-10 .. 2026-07-18) that
# found one repeat-offender IP hammering with garbage EHLO hostnames and
# never once caught by the firewall blocklist -- this script exists to
# make that kind of pass repeatable.
# 500.2  2026-07-18

import sys
import os
import re
import glob
from datetime import datetime, timedelta
import json
import argparse
import collections

RE_TS      = re.compile(r'^(\d{8}) (\d{2}):(\d{2}):(\d{2})\.\d+ \((\S+)\) (.*)$')
RE_FWBLOCK = re.compile(r'SMTP FIREWALL BLOCK IP: (\S+)')
RE_WCXBLK  = re.compile(r'IP (\S+) blocked by smtpcmd-connect\.wcx \(reply\.code: (\d+)\)')
RE_DROP    = re.compile(r'! connection drop - error: (\d+) state: (\S+) lastcmd:\s*(\S*)')
RE_EHLO    = re.compile(r'EHLO: Incoming connection: (\S+) \[(\S+)\]')
RE_ACCEPT  = re.compile(r'Accepted message from')
RE_QUEUED  = re.compile(r'Queued\(\S+\) \S+ for: (\S+)')
RE_RCPTREJ = re.compile(r'RCPT: Recipient Rejected')


def analyze(files):
    day_stats = collections.OrderedDict()
    fw_ips = collections.Counter()
    wcx_ips = collections.Counter()
    wcx_codes = collections.Counter()
    drop_errs = collections.Counter()
    drop_cmds = collections.Counter()
    ehlo_hosts = collections.Counter()
    thread_ids_per_day = collections.defaultdict(set)
    minute_thread_set = collections.defaultdict(set)

    total = collections.Counter()

    for fpath in files:
        base = os.path.basename(fpath)
        m = re.search(r'(\d{8})', base)
        day = m.group(1) if m else base
        st = day_stats.setdefault(day, collections.Counter())
        with open(fpath, 'r', errors='replace') as f:
            for line in f:
                st['lines'] += 1
                total['lines'] += 1
                m = RE_TS.match(line)
                if not m:
                    continue
                _, hh, mm, ss, tag, rest = m.groups()

                if tag not in ('RCVR', 'ROUT'):
                    thread_ids_per_day[day].add(tag)
                    minute_thread_set[(day, hh, mm)].add(tag)

                mfw = RE_FWBLOCK.search(rest)
                if mfw:
                    st['fwblock'] += 1
                    total['fwblock'] += 1
                    fw_ips[mfw.group(1)] += 1
                    continue

                mwcx = RE_WCXBLK.search(rest)
                if mwcx:
                    st['wcxblock'] += 1
                    total['wcxblock'] += 1
                    wcx_ips[mwcx.group(1)] += 1
                    wcx_codes[mwcx.group(2)] += 1
                    continue

                mdrop = RE_DROP.search(rest)
                if mdrop:
                    st['drop'] += 1
                    total['drop'] += 1
                    drop_errs[mdrop.group(1)] += 1
                    drop_cmds[mdrop.group(3) or '(none)'] += 1
                    continue

                mehlo = RE_EHLO.search(rest)
                if mehlo:
                    st['ehlo'] += 1
                    total['ehlo'] += 1
                    ehlo_hosts[mehlo.group(1)] += 1
                    continue

                if RE_ACCEPT.search(rest):
                    st['accepted'] += 1
                    total['accepted'] += 1
                    continue

                mq = RE_QUEUED.search(rest)
                if mq:
                    st['queued'] += 1
                    total['queued'] += 1
                    continue

                if RE_RCPTREJ.search(rest):
                    st['rcpt_rejected'] += 1
                    total['rcpt_rejected'] += 1
                    continue

    return {
        'day_stats': day_stats,
        'total': total,
        'fw_ips': fw_ips,
        'wcx_ips': wcx_ips,
        'wcx_codes': wcx_codes,
        'drop_errs': drop_errs,
        'drop_cmds': drop_cmds,
        'ehlo_hosts': ehlo_hosts,
        'thread_ids_per_day': thread_ids_per_day,
        'minute_thread_set': minute_thread_set,
    }


def render_text(res, top):
    day_stats = res['day_stats']
    total = res['total']
    thread_ids_per_day = res['thread_ids_per_day']

    print("=" * 78)
    print("PER-DAY SUMMARY  (FW=firewall-list block, WCX=smtpcmd-connect.wcx block)")
    print("=" * 78)
    hdr = "{:<10} {:>7} {:>8} {:>8} {:>7} {:>7} {:>9} {:>8} {:>10}".format(
        "DAY", "LINES", "FWBLOCK", "WCXBLK", "DROP", "EHLO", "ACCEPTED", "QUEUED", "THREADS")
    print(hdr)
    print("-" * len(hdr))
    for day in sorted(day_stats):
        st = day_stats[day]
        nthreads = len(thread_ids_per_day[day])
        print("{:<10} {:>7} {:>8} {:>8} {:>7} {:>7} {:>9} {:>8} {:>10}".format(
            day, st['lines'], st['fwblock'], st['wcxblock'], st['drop'],
            st['ehlo'], st['accepted'], st['queued'], nthreads))
    print("-" * len(hdr))
    total_threads_alldays = sum(len(v) for v in thread_ids_per_day.values())
    print("{:<10} {:>7} {:>8} {:>8} {:>7} {:>7} {:>9} {:>8} {:>10}".format(
        "TOTAL", total['lines'], total['fwblock'], total['wcxblock'], total['drop'],
        total['ehlo'], total['accepted'], total['queued'], total_threads_alldays))

    print()
    print("=" * 78)
    print("TOP {} FIREWALL-LIST BLOCKED IPs (RCVR-level, pre-thread, blacklist hits)".format(top))
    print("=" * 78)
    for ip, c in res['fw_ips'].most_common(top):
        print("  {:>6}  {}".format(c, ip))
    print("  ... {} distinct IPs total, {} total hits".format(len(res['fw_ips']), sum(res['fw_ips'].values())))

    print()
    print("=" * 78)
    print("TOP {} smtpcmd-connect.wcx BLOCKED IPs (thread allocated, then rejected)".format(top))
    print("=" * 78)
    for ip, c in res['wcx_ips'].most_common(top):
        print("  {:>6}  {}".format(c, ip))
    print("  ... {} distinct IPs total, {} total hits".format(len(res['wcx_ips']), sum(res['wcx_ips'].values())))
    print("  Reply codes:", dict(res['wcx_codes']))

    print()
    print("=" * 78)
    print("CONNECTION DROPS (error code / last command)")
    print("=" * 78)
    print("  By error code:", dict(res['drop_errs']))
    print("  By last command:", dict(res['drop_cmds']))

    print()
    print("=" * 78)
    print("TOP {} EHLO SOURCE HOSTS (legitimate inbound senders)".format(top))
    print("=" * 78)
    for host, c in res['ehlo_hosts'].most_common(top):
        print("  {:>6}  {}".format(c, host))
    print("  ... {} distinct hosts total, {} total EHLO events".format(
        len(res['ehlo_hosts']), sum(res['ehlo_hosts'].values())))

    print()
    print("=" * 78)
    print("PEAK PER-MINUTE THREAD ACTIVITY (top {}) -- MAC/MAL turnover-rate proxy".format(top))
    print("(distinct thread tags per minute; a single hot IP can inflate this --")
    print(" check the source IP spread in the raw log before treating it as real")
    print(" concurrency. See module docstring.)")
    print("=" * 78)
    peakm = sorted(((len(v), k) for k, v in res['minute_thread_set'].items()), reverse=True)[:top]
    for cnt, (day, hh, mm) in peakm:
        print("  {:>3} distinct threads  {} {}:{}".format(cnt, day, hh, mm))

    print()
    print("Overall totals: accepted={} queued={} rcpt_rejected={}".format(
        total['accepted'], total['queued'], total['rcpt_rejected']))


def render_json(res, top):
    out = {
        'per_day': {day: dict(st) for day, st in res['day_stats'].items()},
        'threads_per_day': {day: len(ids) for day, ids in res['thread_ids_per_day'].items()},
        'total': dict(res['total']),
        'top_firewall_blocked_ips': res['fw_ips'].most_common(top),
        'top_wcx_blocked_ips': res['wcx_ips'].most_common(top),
        'wcx_reply_codes': dict(res['wcx_codes']),
        'drop_error_codes': dict(res['drop_errs']),
        'drop_last_commands': dict(res['drop_cmds']),
        'top_ehlo_hosts': res['ehlo_hosts'].most_common(top),
        'peak_minute_thread_activity': [
            {'day': day, 'hour': hh, 'minute': mm, 'distinct_threads': cnt}
            for cnt, (day, hh, mm) in
            sorted(((len(v), k) for k, v in res['minute_thread_set'].items()), reverse=True)[:top]
        ],
    }
    print(json.dumps(out, indent=2))


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if '/?' in sys.argv:
    sys.argv[sys.argv.index('/?')] = '--help'

parser = argparse.ArgumentParser(description="Summarize wcSMTP daily log files")
parser.add_argument('--dir', default='.', help="Directory containing wcsmtp<date>.log files (default: .)")
parser.add_argument('--date', nargs='+', default=[datetime.now().strftime('%Y%m%d')],
                    help=("One value: a date glob, e.g. 20260718 or 202607* (default: today). "
                          "Two values: an explicit start/end YYYYMMDD range, e.g. 20260710 20260718."))
parser.add_argument('--server', default=None,
                    help="Filter to a specific server suffix (matches wcsmtp<date>*.<SERVER>.log)")
parser.add_argument('--top', type=int, default=15, help="Entries per ranked list (default: 15)")
parser.add_argument('--format', choices=['text', 'json'], default='text', help="Output format")
args = parser.parse_args()

if len(args.date) > 2:
    print("ERROR: --date takes at most 2 values (start [end]), got {}: {}".format(
        len(args.date), args.date))
    sys.exit(1)

if len(args.date) == 2:
    try:
        start = datetime.strptime(args.date[0], '%Y%m%d')
        end = datetime.strptime(args.date[1], '%Y%m%d')
    except ValueError as e:
        print("ERROR: --date range values must be plain YYYYMMDD (no wildcards): {}".format(e))
        sys.exit(1)
    if end < start:
        start, end = end, start
    date_globs = []
    d = start
    while d <= end:
        date_globs.append(d.strftime('%Y%m%d'))
        d += timedelta(days=1)
else:
    date_globs = [args.date[0]]

files = []
for dg in date_globs:
    if args.server:
        pattern = "wcsmtp{}*.{}.log".format(dg, args.server)
    else:
        pattern = "wcsmtp{}*.log".format(dg)
    files.extend(glob.glob(os.path.join(args.dir, pattern)))
files = sorted(set(files))

if not files:
    print("ERROR: No log files matched date(s) {} in {!r}".format(args.date, args.dir))
    sys.exit(1)

if args.format == 'text':
    print("wcSmtpLogSummary.py -- {} file(s) in {}".format(len(files), args.dir))
    for f in files:
        print("  {}".format(os.path.basename(f)))
    print()

result = analyze(files)

if args.format == 'text':
    render_text(result, args.top)
else:
    render_json(result, args.top)
