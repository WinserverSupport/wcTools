#!/usr/bin/env python
# wcat-spool2smtp.py -- turn Wildcat! spool files into wcSmtpUser scripts
#
# Converts a stored message back into the SMTP transaction that produced
# it, for replay with:
#
#     wcsmtpuser
#     smtp> test2 <script>
#
# Two input formats are recognized automatically:
#
#  A. HOST SPOOL pair -- spool\<host>\done\064129W.D + .x
#
#         Return-Path: <forwardingalgorithm@ietf.org>   <- 5321.MAIL FROM
#         Received: by winserver.com ...                <- payload starts
#
#     The .x file carries the envelope recipient(s):
#
#         C rmail ietf-drafts@isdg.net
#
#     The Return-Path line is REMOVED from the payload: it is added by
#     the receiver on delivery and is not part of the original DATA.
#     Long-standing practice strips it from final storage too.
#
#  B. PRESPOOL / reject copy -- spool\<host>\new\smt*.tmp and
#     <psf>.reject.<hook>
#
#         FROM: <bounce_...@cp20.com>
#         TO: <hector.santos@winserver.com>
#         USERID: 7037
#         DATA:
#         {payload}
#
#     Everything up to and including the "DATA:" line is the envelope
#     preamble and is stripped; the payload is what follows.  (This is
#     the same envelope/mail split sfGetHeaderLineEx() uses, keyed on
#     the "data:" line -- see smtpfilterhlp.wcc.)
#
# Output is a test2 script:
#
#     MAIL FROM: <...>
#     RCPT TO: <...>            (one line per recipient)
#     DATA
#     {payload}
#     .
#
# Usage:
#   python wcat-spool2smtp.py <file-or-dir> [options]
#
#   done\ and new\ hold tens of thousands of files (40k / 68k on
#   NTBBS), so narrow with --date-range before generating anything.
#
# Options:
#   --out <dir>       write scripts here (default: alongside the input)
#   --rcpt <addr>     override every RCPT TO (redirect the test)
#   --from <addr>     override MAIL FROM
#   --date-range D1 [D2]
#                     restrict by file modification date, YYYYMMDD.
#                     One date = SINCE that date.  Two = D1 through D2
#                     inclusive.
#   --limit <n>       stop after N inputs
#   --stdout          print one script instead of writing files
#   --list            show what would be produced, write nothing
#
# Revision History:
# 500.2  08/30/26  Initial version

import os
import re
import sys
import glob
import argparse
import datetime

try:
    sys.stdout.reconfigure(encoding='cp437', errors='replace')
    sys.stderr.reconfigure(encoding='cp437', errors='replace')
except (AttributeError, ValueError):
    pass

CRLF = b'\r\n'


def read_lines(path):
    """Read as raw bytes, split into lines, keep the payload untouched."""
    with open(path, 'rb') as f:
        data = f.read()
    data = data.replace(b'\r\n', b'\n')
    lines = data.split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    return lines


def strip_brackets(s):
    s = s.strip()
    if s.startswith('<') and s.endswith('>'):
        s = s[1:-1]
    return s.strip()


def find_x(dfile):
    base = os.path.splitext(dfile)[0]
    for ext in ('.X', '.x'):
        if os.path.exists(base + ext):
            return base + ext
    return None


def rcpts_from_x(xfile):
    """Envelope recipients from the .X 'C rmail <addr>' lines.

    There may be SEVERAL -- that is how a multi-recipient message is
    represented, and replaying all of them is the point.
    """
    out = []
    for raw in read_lines(xfile):
        s = raw.decode('cp437', 'replace').strip()
        if s[:1].upper() == 'C' and 'rmail' in s.lower():
            for p in s.split()[1:]:
                if p.lower() == 'rmail':
                    continue
                if '@' in p:
                    out.append(strip_brackets(p))
    return out


def parse(path):
    """-> (mailfrom, [rcpt,...], [payload lines as bytes], format letter)"""
    lines = read_lines(path)
    if not lines:
        return None

    first = lines[0].decode('cp437', 'replace')

    # Format B: envelope preamble terminated by a "DATA:" line
    if first.upper().startswith('FROM:'):
        mailfrom, rcpts, start = '', [], None
        for i, raw in enumerate(lines):
            s = raw.decode('cp437', 'replace')
            low = s.lower()
            if low.startswith('data:'):
                start = i + 1
                break
            if low.startswith('from:'):
                mailfrom = strip_brackets(s.split(':', 1)[1])
            elif low.startswith('to:'):
                rcpts.append(strip_brackets(s.split(':', 1)[1]))
        if start is None:
            return None
        return mailfrom, rcpts, lines[start:], 'B'

    # Format A: .D with Return-Path, recipients in the .x partner
    if first.lower().startswith('return-path:'):
        mailfrom = strip_brackets(first.split(':', 1)[1])
        payload = lines[1:]
    else:
        mailfrom, payload = '', lines

    x = find_x(path)
    rcpts = rcpts_from_x(x) if x else []
    return mailfrom, rcpts, payload, 'A'


def build_script(mailfrom, rcpts, payload):
    """Assemble the test2 script.

    Two things are mandatory and easy to get wrong:

      1. DOT-STUFFING.  Any payload line beginning with '.' must be sent
         as '..' or the message ends early at that line (RFC 5321 4.5.2).
         Real mail hits this -- quoted text and signature separators.

      2. The terminator is a line containing only '.', and the command
         is DATA, not "DATA:" (the colon belongs to the prespool
         preamble, not to SMTP).
    """
    out = []
    out.append(('MAIL FROM: <%s>' % mailfrom).encode('cp437', 'replace'))
    for r in rcpts:
        out.append(('RCPT TO: <%s>' % r).encode('cp437', 'replace'))
    out.append(b'DATA')
    for ln in payload:
        out.append(b'.' + ln if ln.startswith(b'.') else ln)
    out.append(b'.')
    return CRLF.join(out) + CRLF


SPOOL_EXT = ('.d', '.tmp')


def want_file(name):
    low = name.lower()
    if low.endswith('.x'):
        return False                 # the .X partner, not an input itself
    if low.endswith('.smtp'):
        return False                 # our own output
    if '.reject.' in low or '.smtpfilter.metadata' in low:
        return '.metadata' not in low
    return os.path.splitext(low)[1] in SPOOL_EXT


def fmt_range(dr):
    if not dr:
        return ''
    if len(dr) == 1:
        return "since %s" % dr[0].strftime('%Y-%m-%d')
    return "%s..%s" % (dr[0].strftime('%Y-%m-%d'), dr[1].strftime('%Y-%m-%d'))


def parse_date(s):
    """YYYYMMDD -> (year, month, day).  Separators are tolerated."""
    d = re.sub(r'\D', '', s or '')
    if len(d) != 8:
        raise argparse.ArgumentTypeError(
            "date must be YYYYMMDD (got '%s')" % s)
    return datetime.datetime(int(d[0:4]), int(d[4:6]), int(d[6:8]))


def collect(target, date_range=None):
    """Spool inputs, optionally restricted by file modification date.

    done\\ and new\\ hold tens of thousands of files (40k / 68k observed
    on NTBBS), so this uses os.scandir and reads mtime from the directory
    entry -- no extra stat per file -- and filters before building the
    list.
    """
    if not os.path.isdir(target):
        return [target]

    lo = hi = None
    if date_range:
        lo = date_range[0].timestamp()
        if len(date_range) > 1:
            # inclusive end: through 23:59:59 of date2
            hi = (date_range[1] + datetime.timedelta(days=1)).timestamp()
        # one date only == "since that date"

    out = []
    with os.scandir(target) as it:
        for e in it:
            try:
                if not e.is_file() or not want_file(e.name):
                    continue
                if lo is not None:
                    mt = e.stat().st_mtime
                    if mt < lo or (hi is not None and mt >= hi):
                        continue
                out.append(e.path)
            except OSError:
                continue
    out.sort()
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Convert Wildcat! spool files to wcSmtpUser test2 scripts")
    ap.add_argument('target', help="spool file or directory")
    ap.add_argument('--out', default='', help="output directory")
    ap.add_argument('--rcpt', default='', help="override every RCPT TO")
    ap.add_argument('--from', dest='mfrom', default='', help="override MAIL FROM")
    ap.add_argument('--date-range', nargs='+', metavar='YYYYMMDD',
                    dest='date_range', type=parse_date,
                    help="restrict by file date: one date means SINCE that "
                         "date, two means date1 through date2 inclusive")
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--stdout', action='store_true')
    ap.add_argument('--list', action='store_true')
    args = ap.parse_args()

    if args.date_range and len(args.date_range) > 2:
        ap.error("--date-range takes one or two dates")
    files = collect(args.target, args.date_range)
    if not files:
        print("No spool files found in %s%s" % (
            args.target,
            (" for %s" % fmt_range(args.date_range)) if args.date_range else ""))
        sys.exit(1)

    if args.date_range:
        print("%d file(s) match %s" % (len(files), fmt_range(args.date_range)))

    if args.out and not os.path.isdir(args.out):
        os.makedirs(args.out)

    n = 0
    for path in files:
        if path.lower().endswith(('.x',)):
            continue
        got = parse(path)
        if not got:
            print("SKIP %s -- unrecognized format" % os.path.basename(path))
            continue
        mailfrom, rcpts, payload, fmt = got

        if args.mfrom:
            mailfrom = args.mfrom
        if args.rcpt:
            rcpts = [args.rcpt]
        if not mailfrom:
            print("SKIP %s -- no MAIL FROM found" % os.path.basename(path))
            continue
        if not rcpts:
            print("SKIP %s -- no RCPT TO found (missing .x?)  use --rcpt"
                  % os.path.basename(path))
            continue

        script = build_script(mailfrom, rcpts, payload)
        stuffed = sum(1 for l in payload if l.startswith(b'.'))

        if args.list:
            print("%-20s [%s] from=%-38s rcpt=%d lines=%d dotstuffed=%d"
                  % (os.path.basename(path), fmt, mailfrom[:38],
                     len(rcpts), len(payload), stuffed))
        elif args.stdout:
            sys.stdout.buffer.write(script)
        else:
            base = os.path.basename(path) + '.smtp'
            dest = os.path.join(args.out or os.path.dirname(path) or '.', base)
            with open(dest, 'wb') as f:
                f.write(script)
            print("%-20s -> %-28s from=%s rcpt=%d%s"
                  % (os.path.basename(path), base, mailfrom[:34], len(rcpts),
                     ("  (%d dot-stuffed)" % stuffed) if stuffed else ""))
        n += 1
        if args.limit and n >= args.limit:
            break

    if not args.stdout:
        print("")
        print("%d script(s).  Replay with:  wcsmtpuser  then  test2 <script>" % n)


if __name__ == "__main__":
    main()
