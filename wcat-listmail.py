#!/usr/bin/env python
# wcat-listmail.py -- Wildcat! Message Header Lister
# Displays TMsgHeader fields for messages in a conference.
# Default: compact table (one line per message).
# --detail: full field dump per message.
#
# Usage:
#   python wcat-listmail.py <conf#> [options]
#
# Options:
#   --server <name>   WC server name (default: null)
#   --from-msg <n>    Start from message Number (default: first)
#   --limit <n>       Stop after N messages
#   --detail          Full per-message field dump instead of table
#   --last <n>        Show last N messages (walks backward from high)
#   --find <f>=<s>    Show only messages whose field <f> matches <s>
#   --show-match      Echo the header line(s) that satisfied --find header=
#
# --find fields:  to  from  subject   (TMsgHeader -- free, no extra RPC)
#                 header              (RFC 5322 header block -- reads the msg)
#
#   The match is case-insensitive.  '*' is a wildcard matching any run of
#   characters (including none); every other character -- including '?',
#   '[', ']' -- is literal, so subjects like "[STN:2021307001]" can be
#   pattern-matched without escaping.  With no '*' the match is exact.
#
#   Repeat --find to AND conditions together.
#
#   'header' differs from the other fields in two ways:
#     - It matches as a SUBSTRING, so "header=for hsantos@isdg.net" hits
#       without needing surrounding '*'.  (to/from/subject with no '*' are
#       exact matches.)  '*' spans line breaks, so a folded header can be
#       matched across the fold.
#     - It costs an RPC per message, so it is evaluated LAST: the to/from/
#       subject conditions are checked first and the message text is only
#       read when all of them already pass.  Pair it with a cheap field
#       to keep a large sweep affordable.
#
# Examples:
#   wcat-listmail.py 9 --find to=hsantos*
#       To.Name begins with "hsantos"
#   wcat-listmail.py 9 --find from=ft707414@yahoo.com.au
#       From.Name is exactly that address
#   wcat-listmail.py 9 --find subject=*drone*
#       Subject contains "drone"
#   wcat-listmail.py 9 --find from=*@aim.com --find subject=Re:*
#       both conditions must hold
#   wcat-listmail.py 0 --find to=h*santos --find "header=Received:*for *@isdg.net"
#       recover the envelope recipient wcSMTP recorded, for the messages
#       that reached either HSANTOS or HECTOR SANTOS
#   wcat-listmail.py 0 --find to=h*santos --find "header=Received:*for *@santronics.com" --show-match
#       ...and show which santronics.com address each one was sent to
#
#   Anchor envelope queries to Received: as shown above.  A bare
#   "header=for *@isdg.net" also matches a Subject or X- header that
#   merely mentions such an address -- text the SENDER controls.  The
#   Received: header is written by our own router and is the only
#   trustworthy record of the envelope recipient.
#
# Revision History:
# 500.2  03/09/26  Initial version
# 500.2  07/22/26  change --server default to ''
# 500.2  08/27/26  force CP437 stdout/stderr (redirection codec error)
# 500.2  08/27/26  add --find field=string

import ctypes
import sys
import argparse
import datetime
import re

import wcpapi
from wcpapi.wcserver_h import *
from wcpapi.wcserror_h import *
from wcpapi.wctype_h import *
from wcpapi.wctype_constants_h import *

# ---------------------------------------------------------------------------
# Output encoding
#
# Message header text (From/To/Subject/Network) is raw 8-bit bytes as the BBS
# stored it, decoded here as CP437.  When stdout is a console Python encodes
# with the console codepage, but when stdout is REDIRECTED to a file it falls
# back to the ANSI locale codepage (cp1252), which has no mapping for large
# parts of the CP437 upper range -- print() then raises UnicodeEncodeError and
# the run dies partway through.
#
# Note this also covers subjects that were stored as UTF-8 by a mail/news
# feed: those bytes decode under CP437 into characters like U+0393 (Gamma)
# which cp1252 cannot encode.  Re-encoding to CP437 restores the original
# bytes, so the output file is byte-faithful to what is in the message base.
# ---------------------------------------------------------------------------

try:
    sys.stdout.reconfigure(encoding='cp437', errors='replace')
    sys.stderr.reconfigure(encoding='cp437', errors='replace')
except (AttributeError, ValueError):
    pass

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FILETIME_EPOCH = datetime.datetime(1601, 1, 1)

def filetime_to_str(ft, short=False):
    if ft.dwHighDateTime == 0 and ft.dwLowDateTime == 0:
        return ''
    ticks = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    dt = FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)
    if short:
        return dt.strftime('%Y%m%d')
    return dt.strftime('%Y%m%d %H:%M:%S')

def decode_wc(b):
    if isinstance(b, (bytes, bytearray)):
        return b.decode('cp437', errors='replace').rstrip('\x00').strip()
    return str(b).strip()

def fido_addr(fa):
    if fa.Zone == 0 and fa.Net == 0 and fa.Node == 0:
        return ''
    if fa.Point:
        return '{}:{}/{}.{}'.format(fa.Zone, fa.Net, fa.Node, fa.Point)
    return '{}:{}/{}'.format(fa.Zone, fa.Net, fa.Node)

def bool_flag(v, char):
    return char if v else '.'

# ---------------------------------------------------------------------------
# --find support
#
# Patterns are compiled to a regex rather than handed to fnmatch: fnmatch
# also honors '?' and '[...]', and both occur constantly in real subject
# lines ("are you there?", "[STN:2021307001]").  Here only '*' is special,
# so a pattern pasted straight out of a subject line behaves as a literal.
# ---------------------------------------------------------------------------

FIND_FIELDS = ('to', 'from', 'subject', 'header')

# Fields answerable from TMsgHeader alone -- no server round trip.
FIND_CHEAP_FIELDS = ('to', 'from', 'subject')

# ---------------------------------------------------------------------------
# RFC 5322 header block reader
#
# Read via WcCreateFile/WcReadLine/WcCloseHandle rather than GetText(): the
# headers sit at the TOP of the message, so a line reader can stop at the
# blank line that ends the header block instead of dragging the whole body
# across the wire.  On a big conference that is the difference between
# pulling a few hundred bytes per candidate and pulling entire messages.
#
# The name must be the \FULLTEXT form.  Plain wc:\CONF(#)\MESSAGE(id)
# filters RFC 5322 headers and ctrl-A kludge lines according to the logged-in
# User.ShowEmailHeaders setting -- which would strip the very Received: line
# being matched.  \FULLTEXT is unfiltered and therefore deterministic.
# \SNOOP would avoid touching read counters but applies the same filter, so
# it cannot be used here.
#
# 'id' in the path is TMsgHeader.Id (the value wcWEB takes as msgid=), not
# TMsgHeader.Number.
# ---------------------------------------------------------------------------

GENERIC_READ      = 0x80000000
FILE_SHARE_READ   = 0x00000001
OPEN_EXISTING     = 3

WCLINE_MAX        = 1024   # per-line buffer, matches common\TextSetupFile.cpp
MAX_HEADER_LINES  = 500    # safety valve: message with no blank separator

def read_msg_headers(conf, msgid):
    """Return the message's leading header block as text, or None."""
    fn = "wc:\\CONF({})\\MESSAGE({})\\FULLTEXT".format(conf, msgid)
    h = WcCreateFile(fn, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING)
    if h == ctypes.wintypes.HANDLE(-1).value or not h:
        return None

    lines = []
    buf   = ctypes.create_string_buffer(WCLINE_MAX)
    pbuf  = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))
    try:
        n = 0
        while n < MAX_HEADER_LINES and WcReadLine(h, pbuf, WCLINE_MAX - 1):
            n += 1
            line = buf.value.decode('cp437', errors='replace')
            # A blank line terminates the RFC 5322 header block.  Anything
            # before it -- including ctrl-A FTN kludges -- is searchable.
            if not line.strip():
                break
            # Unfold: a line starting with space/tab continues the previous
            # header.  wcSMTP folds its own Received: this way, putting the
            # "for <envelope-recipient>;" clause on the continuation --
            # joining them makes one logical header that a single pattern
            # can match end to end.
            if line[:1] in (' ', '\t') and lines:
                lines[-1] = lines[-1].rstrip() + ' ' + line.strip()
            else:
                lines.append(line)
    finally:
        WcCloseHandle(h)
    return '\n'.join(lines)

def find_field_value(msg, field, hdrtext):
    if field == 'to':
        return decode_wc(msg.To.Name)
    if field == 'from':
        return decode_wc(msg.From.Name)
    if field == 'subject':
        return decode_wc(msg.Subject)
    return hdrtext or ''

def compile_find(spec):
    """Parse '[!]field=pattern' into (field, regex, spec, negate)."""
    if '=' not in spec:
        raise argparse.ArgumentTypeError(
            "--find needs field=string (fields: {})".format(', '.join(FIND_FIELDS)))
    field, pattern = spec.split('=', 1)
    field = field.strip().lower()
    # Leading '!' negates: "!header=List-Id:" selects messages with no
    # List-Id at all -- the complement of an accept rule, i.e. the set a
    # reject rule has to be written against.
    negate = field.startswith('!')
    if negate:
        field = field[1:].strip()
    if field not in FIND_FIELDS:
        raise argparse.ArgumentTypeError(
            "--find field '{}' unknown (fields: {})".format(field, ', '.join(FIND_FIELDS)))
    rx = '.*'.join(re.escape(p) for p in pattern.split('*'))
    if field == 'header':
        # Substring, but deliberately NOT re.DOTALL: headers are unfolded
        # before matching, so '*' never needs to cross a newline -- and
        # confining it to one logical header stops "for *@domain" from
        # pairing a 'for' in one header with a domain in an unrelated one.
        return (field, re.compile(rx, re.IGNORECASE), spec, negate)
    return (field, re.compile('\\A' + rx + '\\Z', re.IGNORECASE), spec, negate)

def match_find(msg, finds, hdrtext=None):
    for field, rx, _, negate in finds:
        hit = bool(rx.search(find_field_value(msg, field, hdrtext)))
        if hit == negate:
            return False
    return True

def match_lines(rx, hdrtext, limit=1):
    """Header line(s) satisfying rx, for --show-match.

    Stops at the first hit by default: the condition is met, and echoing
    every matching hop made the output count lines rather than messages
    (a message with three Received: hops produced three rows).
    """
    out = []
    for line in (hdrtext or '').split('\n'):
        if rx.search(line):
            out.append(line.strip())
            if len(out) >= limit:
                break
    return out

def mailflags_str(mf):
    flags = []
    if mf & 0x0001: flags.append('MIME')
    if mf & 0x0002: flags.append('HTML')
    if mf & 0x0004: flags.append('ATTACH')
    if mf & 0x0020: flags.append('MULTI')
    return ','.join(flags) if flags else ''

# ---------------------------------------------------------------------------
# Table format (default)
# Columns: Number Id Date Flags RC Ref AddedBy Size Network From To Subject
# ---------------------------------------------------------------------------

TABLE_HDR = (
    "{:>6} {:>10} {:8} {:7} {:>2} {:>8} {:>8} {:>6} {:12} {:24} {:24} {}"
).format(
    "Number", "Id", "Date", "FLGmxPR", "RC", "Ref", "AddedBy",
    "Size", "Network", "From", "To", "Subject"
)
TABLE_SEP = "-" * 140

def print_table_row(msg):
    from_name = decode_wc(msg.From.Name)[:24]
    to_name   = decode_wc(msg.To.Name)[:24]
    subject   = decode_wc(msg.Subject)[:48]
    network   = decode_wc(msg.Network)[:12]
    date      = filetime_to_str(msg.PostedTimeGMT, short=True) or \
                filetime_to_str(msg.MsgTime, short=True)

    flags = (
        mailflags_str(msg.MailFlags)[:4].ljust(4) +
        bool_flag(msg.MailFlags & 0x0001, 'm') +
        bool_flag(msg.Exported,           'x') +
        bool_flag(msg.Private,            'P') +
        bool_flag(msg.Received,           'R')
    )

    print("{:>6} {:>10} {:8} {:7} {:>2} {:>8} {:>8} {:>6} {:12} {:24} {:24} {}".format(
        msg.Number,
        msg.Id,
        date,
        flags,
        msg.ReplyCount,
        msg.Reference,
        msg.AddedByUserId,
        msg.MsgSize,
        network,
        from_name,
        to_name,
        subject
    ))

# ---------------------------------------------------------------------------
# Detail format (--detail)
# ---------------------------------------------------------------------------

def print_detail(msg):
    from_name = decode_wc(msg.From.Name)
    to_name   = decode_wc(msg.To.Name)
    subject   = decode_wc(msg.Subject)
    network   = decode_wc(msg.Network)

    print()
    print("  #{:<6}  Id={:<12}  Conf={}".format(msg.Number, msg.Id, msg.Conference))
    print("  From     : {:36}  Id={}".format(from_name[:36], msg.From.Id))
    print("  To       : {:36}  Id={}".format(to_name[:36], msg.To.Id))
    print("  Subject  : {}".format(subject))
    print("  Network  : {}".format(network if network else "(none)"))
    print("  PostedGMT: {}  MsgTime: {}  ReadTime: {}".format(
        filetime_to_str(msg.PostedTimeGMT),
        filetime_to_str(msg.MsgTime),
        filetime_to_str(msg.ReadTime)))
    flags = (
        bool_flag(msg.Private,           'P') +
        bool_flag(msg.Received,          'R') +
        bool_flag(msg.ReceiptRequested,  'r') +
        bool_flag(msg.Deleted,           'D') +
        bool_flag(msg.Tagged,            'T') +
        bool_flag(msg.Exported,          'X') +
        bool_flag(msg.AllowDisplayMacros,'M')
    )
    print("  Flags    : {}  [P=Private R=Received r=ReqReceipt D=Deleted T=Tagged X=Exported M=Macros]".format(flags))
    print("  MailFlags: 0x{:08X}  {}".format(msg.MailFlags, mailflags_str(msg.MailFlags)))
    print("  MsgSize  : {}  ReplyCount={}  Reference={}  ReadCount={}".format(
        msg.MsgSize, msg.ReplyCount, msg.Reference, msg.ReadCount))
    print("  AddedByUserId={}  PrevUnread={}  NextUnread={}".format(
        msg.AddedByUserId, msg.PrevUnread, msg.NextUnread))
    ff = fido_addr(msg.FidoFrom)
    ft = fido_addr(msg.FidoTo)
    if ff or ft:
        print("  FidoFrom : {}  FidoTo: {}  FidoFlags: 0x{:08X}".format(
            ff or '(none)', ft or '(none)', msg.FidoFlags))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if '/?' in sys.argv:
        sys.argv[sys.argv.index('/?')] = '--help'

    parser = argparse.ArgumentParser(description="Wildcat! Message Header Lister")
    parser.add_argument('conf',            type=int,            help="Conference number")
    parser.add_argument('--server',        default='',          help="WC server name")
    parser.add_argument('--from-msg',      type=int, default=0, help="Start from message Number")
    parser.add_argument('--limit',         type=int, default=0, help="Stop after N messages")
    parser.add_argument('--last',          type=int, default=0, help="Show last N messages")
    parser.add_argument('--detail', '-d',  action='store_true', help="Full per-message field dump")
    parser.add_argument('--find', action='append', default=[], type=compile_find,
                        metavar='FIELD=STRING',
                        help="Show only matching messages; FIELD is one of {}. "
                             "'*' is a wildcard, match is case-insensitive. "
                             "Repeat to AND conditions.".format('/'.join(FIND_FIELDS)))
    parser.add_argument('--show-match', action='store_true',
                        help="Echo the header line(s) matched by --find header=")
    args = parser.parse_args()

    # Cheap conditions first; 'header' costs an RPC so it is evaluated only
    # after every TMsgHeader condition has already passed.
    cheap_finds = [f for f in args.find if f[0] in FIND_CHEAP_FIELDS]
    hdr_finds   = [f for f in args.find if f[0] == 'header']

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

        cnum  = args.conf
        low   = GetLowMessageNumber(cnum)
        high  = GetHighMessageNumber(cnum)
        total = GetTotalMessagesInConference(cnum)
        print("Conference {}  Low={}  High={}  Total={}".format(cnum, low, high, total))
        if args.find:
            # Echo the filter so a redirected capture records what it is.
            print("Filter: {}".format(
                '  AND  '.join(spec for _, _, spec, _neg in args.find)))

        msg = TMsgHeader()
        msg.Conference = cnum

        # --last N: seed cursor to high-N
        if args.last > 0:
            start = max(high - args.last, low - 1)
            seed_id = GetMsgIdFromNumber(cnum, start)
            if seed_id:
                msg.Id = seed_id
        elif args.from_msg > 0:
            seed_id = GetMsgIdFromNumber(cnum, args.from_msg - 1)
            if seed_id:
                msg.Id = seed_id

        if not args.detail:
            print(TABLE_HDR)
            print(TABLE_SEP)

        count   = 0
        scanned = 0
        fetched = 0
        while GetNextMessage(ctypes.byref(msg)):
            scanned += 1

            if cheap_finds and not match_find(msg, cheap_finds):
                continue

            hdrtext = None
            if hdr_finds:
                hdrtext = read_msg_headers(cnum, msg.Id)
                fetched += 1
                if hdrtext is None or not match_find(msg, hdr_finds, hdrtext):
                    continue

            if args.detail:
                print_detail(msg)
            else:
                print_table_row(msg)
            if args.show_match and hdr_finds:
                for _, rx, _spec, negate in hdr_finds:
                    if negate:
                        continue        # nothing matched, by definition
                    for ln in match_lines(rx, hdrtext):
                        print("       > {}".format(ln))
            count += 1
            # --limit caps messages DISPLAYED, so with --find it keeps
            # scanning until N matches are found (or the base runs out).
            if args.limit > 0 and count >= args.limit:
                break

        if not args.detail:
            print(TABLE_SEP)
        if hdr_finds:
            print("Displayed: {}  (scanned {}, read {})".format(count, scanned, fetched))
        elif args.find:
            print("Displayed: {}  (scanned {})".format(count, scanned))
        else:
            print("Displayed: {}".format(count))

    finally:
        WildcatServerDeleteContext()

if __name__ == "__main__":
    main()
