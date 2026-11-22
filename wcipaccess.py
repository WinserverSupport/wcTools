## File : wcipaccess.py
## // 500.4 26.11.21
## Version: 1.8
## About:
##
## Consolidated ipaccess-*.dat management tool. Replaces three scripts:
##
##   merge-ipaccess.py          smtpcmd\learn\{ip}.log      -> ipaccess-smtp.dat
##   merge-ipaccess-http.py     wchttp-unauth-post*.log     -> ipaccess-http.dat
##   merge-iptrack-ipaccess.py  iptrack\{PROTO}.{ip}.blk    -> ipaccess-{proto}.dat
##
## Two modes:
##
## MERGE - merge abuse sources into config\ipaccess-{protocol}-new.dat
##
##   python wcipaccess.py merge --ipaccess <dir>
##       [--iptrack <dir>]     iptrack\ folder with {PROTO}.{ip}.blk files
##       [--learn <dir>]       smtpcmd\learn folder with {ip}.log files (SMTP)
##       [--log <file> ...]    wchttp-unauth-post*.log file(s) (HTTP)
##       [--reduce c|b]        collapse to /24 or /16 when 2+ IPs share prefix
##       [--delete]            delete processed .blk files after merge
##
##   Example:
##     python wcipaccess.py merge --ipaccess config\ --iptrack iptrack\
##     python wcipaccess.py merge --ipaccess config\ --learn smtpcmd\learn
##
## REPORT - worst offender table mined from existing logs (no server changes)
##
##   python wcipaccess.py report [--logdir <dir>] [--top N] [--proto HTTP]
##       [--learn <dir>] [--since YYYYMMDD]
##
##   --since filters out hits older than the given date. Learn files are
##   included/excluded by file modify time (whole file).
##
##   Sources scanned in --logdir (default current directory):
##     wcOnline*-ipblock.*.log      wcohttp/wcoftp/etc listener block hits
##     wchttp-unauth-post*.log      unauthenticated POST rejects
##     wchttp-autobanned*.log       error-rate auto-bans
##     ssi-learnautherror*.log      SMTP auth failures (durable, date-stamped)
##     smtpcmd\learn\{ip}.log       SMTP abuse per IP (auto-detected under
##                                  --logdir, or --learn)
##
##   smtpcmd-AuthError.wcx appends the same record to BOTH the learn file
##   and ssi-learnautherror-*.log; duplicate records are counted once
##   (dedup on timestamp+IP+seq).
##
## PROCESS LOG
##
##   Every run (merge or report) appends to wcipaccess-merge-YYYYMMDD.log
##   in the current directory: BEGIN/END markers with the command line,
##   one "read:" line per source file processed (ipblock, unauth-post,
##   autobanned, autherror, learn, .blk), merge results per protocol,
##   and "deleted:" lines for consumed .blk files.
##
##   PROTO column: BlockAllHost=1 bans an IP on ALL listeners, so one IP
##   can show hits under HTTP,FTP,POP3,TELNET simultaneously. SMTP runs
##   as a standalone process; its hits come only from smtpcmd\learn.
##
##   Example:
##     python wcipaccess.py report --logdir d:\wc5 --top 25

import os
import glob
import ipaddress
import sys
import argparse
from datetime import datetime

## Revision History:
##   1.8  11/21/26  report: skip truncated log lines that end right after
##                  "BLOCK IP:" or "IP:" (IndexError on WCAWS2).
##   1.7  09/02/26  -h now shows every argument, both subcommands, plus
##                  worked examples and the .blk lifecycle notes.
##                  "merge -h" / "report -h" still give the narrow view.

VERSION = "1.8"


# ------------------------------------------------------------------
# process log: wcipaccess-merge-YYYYMMDD.log (current directory)
# records each run, every source file read, every output written
# ------------------------------------------------------------------

_logfp = None

def wlog(msg):
    global _logfp
    if _logfp is None:
        fname = "wcipaccess-merge-%s.log" % datetime.now().strftime("%Y%m%d")
        _logfp = open(fname, "at")
    _logfp.write("%s %s\n" % (datetime.now().strftime("%H:%M:%S"), msg))


# ------------------------------------------------------------------
# shared: reduce helpers
# ------------------------------------------------------------------

def reduce_class_b(ip_list):
    groups = {}
    for ip in ip_list:
        key = '.'.join(str(ip.network_address).split('.')[:2])
        groups.setdefault(key, []).append(ip)
    final_list = []
    for key, ips in groups.items():
        if len(ips) >= 2:
            ips = [ipaddress.ip_network(key + '.0.0/16', strict=False)]
        final_list += ips
    return final_list


def reduce_class_c(ip_list):
    groups = {}
    for ip in ip_list:
        key = '.'.join(str(ip.network_address).split('.')[:3])
        groups.setdefault(key, []).append(ip)
    final_list = []
    for key, ips in groups.items():
        if len(ips) >= 2:
            ips = [ipaddress.ip_network(key + '.0/24', strict=False)]
        final_list += ips
    return final_list


# ------------------------------------------------------------------
# shared: source readers
# ------------------------------------------------------------------

def read_ipaccess(file_path):
    """Read existing ipaccess-*.dat -> list of ip_network."""
    ip_list = []
    if not os.path.exists(file_path):
        return ip_list
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            line = line.lstrip('+-').replace(' ', '/')
            try:
                ip_list.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    return ip_list


def scan_blk_files(iptrack_dir):
    """iptrack\{PROTO}.{ip}.blk -> {PROTO: [(ip_network, blk_path), ...]}
    Last octet 0 = BlockClassC ban -> /24 block."""
    by_proto = {}
    for fname in os.listdir(iptrack_dir):
        if not fname.lower().endswith('.blk'):
            continue
        parts = fname.split('.')
        if len(parts) < 6:       # need proto + 4 octets + blk
            continue
        proto = parts[0].upper()
        ip_str = '.'.join(parts[1:-1])
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if parts[-2] == '0':
            net = ipaddress.ip_network(ip_str + '/24', strict=False)
        else:
            net = ipaddress.ip_network(ip_str, strict=False)
        blk_path = os.path.join(iptrack_dir, fname)
        wlog("read: %s" % blk_path)
        by_proto.setdefault(proto, []).append((net, blk_path))
    return by_proto


def scan_learn_files(learn_dir):
    """smtpcmd\learn\{ip}.log -> list of ip_network (/32)."""
    ip_list = []
    for fname in os.listdir(learn_dir):
        if not fname.lower().endswith('.log'):
            continue
        ip_str = fname[:-4]
        try:
            ip_list.append(ipaddress.ip_network(ip_str, strict=False))
            wlog("read: %s" % os.path.join(learn_dir, fname))
        except ValueError:
            pass
    return ip_list


def read_event_log_ips(log_file):
    """wchttp-unauth-post*.log / wchttp-autobanned*.log -> list of ip_network.
    Line format: TIMESTAMP [HOST: x] IP: x [ERRS: n] URL: x"""
    ip_list = []
    if not os.path.exists(log_file):
        return ip_list
    wlog("read: %s" % log_file)
    with open(log_file, 'r') as f:
        for line in f:
            if ' IP: ' not in line:
                continue
            try:
                ip_part = line.split(' IP: ')[1].split(' ')[0].strip()
                ip_list.append(ipaddress.ip_network(ip_part, strict=False))
            except (IndexError, ValueError):
                pass
    return ip_list


# ------------------------------------------------------------------
# merge mode
# ------------------------------------------------------------------

def merge_protocol(proto, new_ips, blk_paths, ipaccess_dir, reduce_opt, do_delete):
    proto_lower = proto.lower()
    ipaccess_file = os.path.join(ipaccess_dir, "ipaccess-%s.dat" % proto_lower)
    out_file      = os.path.join(ipaccess_dir, "ipaccess-%s-new.dat" % proto_lower)

    existing = read_ipaccess(ipaccess_file)
    merged = list(set(existing + new_ips))
    merged = sorted(merged, key=lambda x: x.network_address)

    if 'b' in reduce_opt:
        merged = reduce_class_b(merged)
    if 'c' in reduce_opt:
        merged = reduce_class_c(merged)

    merged = sorted(merged, key=lambda x: x.network_address)

    with open(out_file, 'w') as f:
        f.write("# Created by wcipaccess.py on %s\n" % datetime.now())
        f.write("# ipaccess file : %s\n" % ipaccess_file)
        f.write("# new source ips: %d\n" % len(new_ips))
        f.write("# total entries : %d\n" % len(merged))
        for ip in merged:
            if ip.prefixlen == 32:
                f.write("-%s\n" % ip.network_address)
            else:
                f.write("-%s\n" % ip)

    msg = ("[%s] %d source + %d existing -> %d entries -> %s"
           % (proto, len(new_ips), len(existing), len(merged), out_file))
    print(msg)
    wlog(msg)

    if do_delete:
        for blk_path in blk_paths:
            try:
                os.remove(blk_path)
                print("  deleted %s" % blk_path)
                wlog("deleted: %s" % blk_path)
            except OSError as e:
                print("  WARNING: could not delete %s: %s" % (blk_path, e),
                      file=sys.stderr)
                wlog("WARNING: could not delete %s: %s" % (blk_path, e))


def do_merge(args):
    if not (args.iptrack or args.learn or args.log):
        print("ERROR: merge needs at least one source: --iptrack, --learn, or --log",
              file=sys.stderr)
        sys.exit(1)

    # collect per-protocol: {PROTO: (ips, blk_paths)}
    sources = {}

    # a machine may legitimately lack a source folder (e.g. no smtpcmd\learn
    # when SMTP clients never reach AUTH) -- warn and skip, do not abort
    if args.iptrack:
        if not os.path.isdir(args.iptrack):
            print("WARNING: iptrack directory not found, skipped: %s"
                  % args.iptrack, file=sys.stderr)
            wlog("WARNING: iptrack directory not found, skipped: %s"
                 % args.iptrack)
        else:
            for proto, entries in scan_blk_files(args.iptrack).items():
                ips, paths = sources.setdefault(proto, ([], []))
                for net, blk_path in entries:
                    ips.append(net)
                    paths.append(blk_path)

    if args.learn:
        if not os.path.isdir(args.learn):
            print("WARNING: learn directory not found, skipped: %s"
                  % args.learn, file=sys.stderr)
            wlog("WARNING: learn directory not found, skipped: %s"
                 % args.learn)
        else:
            ips, paths = sources.setdefault("SMTP", ([], []))
            ips += scan_learn_files(args.learn)

    if args.log:
        ips, paths = sources.setdefault("HTTP", ([], []))
        for pattern in args.log:
            for log_file in (glob.glob(pattern) or [pattern]):
                ips += read_event_log_ips(log_file)

    if not sources:
        print("No source IPs found.")
        sys.exit(0)

    for proto in sorted(sources.keys()):
        ips, blk_paths = sources[proto]
        merge_protocol(proto, ips, blk_paths, args.ipaccess,
                       args.reduce, args.delete)


# ------------------------------------------------------------------
# report mode
# ------------------------------------------------------------------

def tally(offenders, ip_str, source, stamp, proto, hits=1, since=None):
    if since and stamp[:8] < since:
        return
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return
    rec = offenders.setdefault(ip_str, {'hits': 0, 'last': '',
                                        'sources': set(), 'protos': set()})
    rec['hits'] += hits
    rec['sources'].add(source)
    rec['protos'].add(proto)
    if stamp > rec['last']:
        rec['last'] = stamp


def scan_ipblock_logs(logdir, offenders, proto_filter, since):
    """wcOnline*-ipblock.*.log lines:
    YYYYMMDD hh:mm:ss : WCOHTTP: HTTP TEMPORARY BLOCK IP: x.x.x.x
    Protocol is the word before FIREWALL/TEMPORARY."""
    count = 0
    for log_file in glob.glob(os.path.join(logdir, "wcOnline*-ipblock.*.log")):
        count += 1
        wlog("read: %s" % log_file)
        with open(log_file, 'r', errors='replace') as f:
            for line in f:
                if ' BLOCK IP: ' not in line:
                    continue
                head, tail = line.split(' BLOCK IP: ', 1)
                fields = tail.split()
                if not fields:        ## truncated line, no IP
                    continue
                ip_str = fields[0]
                words = head.split()
                proto = words[-2].upper() if len(words) >= 2 else '?'
                if proto_filter and proto != proto_filter:
                    continue
                stamp = ' '.join(words[:2])
                tally(offenders, ip_str, 'ipblock', stamp, proto, since=since)
    return count


def scan_event_logs(logdir, pattern, source, offenders, since):
    """wchttp-unauth-post*.log / wchttp-autobanned*.log lines:
    TIMESTAMP HOST: h IP: x [ERRS: n] URL: u"""
    count = 0
    for log_file in glob.glob(os.path.join(logdir, pattern)):
        count += 1
        wlog("read: %s" % log_file)
        with open(log_file, 'r', errors='replace') as f:
            for line in f:
                if ' IP: ' not in line:
                    continue
                fields = line.split(' IP: ')[1].split()
                if not fields:        ## truncated line, no IP
                    continue
                ip_str = fields[0]
                stamp = ' '.join(line.split()[:2])
                tally(offenders, ip_str, source, stamp, 'HTTP', since=since)
    return count


def parse_auth_record(line):
    """Pipe-delimited smtpcmd AuthError record:
      timestamp |IP |errcode |n |authtype |username |...|seq |
    Returns (dedup_key, stamp, ip_str) or None if not this format.
    dedup_key uses the full ms timestamp + IP + seq because the same
    record is appended to BOTH smtpcmd\learn\{ip}.log and
    ssi-learnautherror-YYYYMMDD.log."""
    if '|' not in line:
        return None
    parts = line.split('|')
    if len(parts) < 3:
        return None
    full_stamp = parts[0].strip()
    ip_str = parts[1].strip()
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    seq = parts[-2].strip()
    return (full_stamp, ip_str, seq), full_stamp[:17], ip_str


def scan_autherror_logs(logdir, offenders, since, seen):
    """ssi-learnautherror-YYYYMMDD.log -- durable date-stamped copy of the
    smtpcmd AuthError records (survives the learn zip+delete practice)."""
    count = 0
    for log_file in glob.glob(os.path.join(logdir, "ssi-learnautherror*.log")):
        count += 1
        wlog("read: %s" % log_file)
        with open(log_file, 'r', errors='replace') as f:
            for line in f:
                rec = parse_auth_record(line)
                if not rec:
                    continue
                key, stamp, ip_str = rec
                if key in seen:
                    continue
                seen.add(key)
                tally(offenders, ip_str, 'autherror', stamp, 'SMTP',
                      since=since)
    return count


def scan_learn_dir(learn_dir, offenders, since, seen):
    """smtpcmd\learn\{ip}.log -- filename is the IP, one record line per
    hit. Records also present in ssi-learnautherror-*.log are deduped via
    the shared seen set. Lines not in the pipe record format fall back to
    one hit stamped with the file modify time. SMTP is a standalone
    process; these hits never appear in the wcOnline ipblock logs."""
    count = 0
    for log_file in glob.glob(os.path.join(learn_dir, "*.log")):
        ip_file = os.path.basename(log_file)[:-4]
        try:
            ipaddress.ip_address(ip_file)
        except ValueError:
            continue
        count += 1
        wlog("read: %s" % log_file)
        mtime_stamp = datetime.fromtimestamp(
            os.path.getmtime(log_file)).strftime("%Y%m%d %H:%M:%S")
        with open(log_file, 'r', errors='replace') as f:
            for line in f:
                if not line.strip():
                    continue
                rec = parse_auth_record(line)
                if rec:
                    key, stamp, ip_str = rec
                    if key in seen:
                        continue
                    seen.add(key)
                    tally(offenders, ip_str, 'learn', stamp, 'SMTP',
                          since=since)
                else:
                    tally(offenders, ip_file, 'learn', mtime_stamp, 'SMTP',
                          since=since)
    return count


def do_report(args):
    offenders = {}
    proto = args.proto.upper() if args.proto else None
    since = args.since
    if since:
        if len(since) != 8 or not since.isdigit():
            print("ERROR: --since must be YYYYMMDD (e.g. 20260601)",
                  file=sys.stderr)
            sys.exit(1)

    n1 = scan_ipblock_logs(args.logdir, offenders, proto, since)
    n2 = n3 = n4 = 0
    if not proto or proto == 'HTTP':
        n2 = scan_event_logs(args.logdir, "wchttp-unauth-post*.log",
                             "unauth-post", offenders, since)
        n3 = scan_event_logs(args.logdir, "wchttp-autobanned*.log",
                             "autobanned", offenders, since)
    n5 = 0
    if not proto or proto == 'SMTP':
        seen = set()
        n5 = scan_autherror_logs(args.logdir, offenders, since, seen)
        learn_dir = args.learn
        if not learn_dir:
            probe = os.path.join(args.logdir, "smtpcmd", "learn")
            if os.path.isdir(probe):
                learn_dir = probe
        if learn_dir and os.path.isdir(learn_dir):
            n4 = scan_learn_dir(learn_dir, offenders, since, seen)

    print("# wcipaccess.py v%s report on %s" % (VERSION, datetime.now()))
    print("# logdir : %s" % os.path.abspath(args.logdir))
    if since:
        print("# since  : %s" % since)
    print("# scanned: %d ipblock, %d unauth-post, %d autobanned logs,"
          " %d learn files, %d autherror logs" % (n1, n2, n3, n4, n5))
    print("# unique IPs: %d" % len(offenders))
    wlog("report: %d ipblock, %d unauth-post, %d autobanned logs,"
         " %d learn files, %d autherror logs, %d unique IPs"
         % (n1, n2, n3, n4, n5, len(offenders)))
    print()

    if not offenders:
        print("No offender entries found.")
        return

    ranked = sorted(offenders.items(),
                    key=lambda kv: kv[1]['hits'], reverse=True)

    print("%6s  %-17s  %-20s  %-30s  %s"
          % ("HITS", "LAST SEEN", "PROTO", "SOURCES", "IP"))
    print("%6s  %-17s  %-20s  %-30s  %s"
          % ("-" * 6, "-" * 17, "-" * 20, "-" * 30, "-" * 15))
    for ip_str, rec in ranked[:args.top]:
        srcs = ','.join(sorted(rec['sources']))
        protos = ','.join(sorted(rec['protos']))
        print("%6d  %-17s  %-20s  %-30s  %s"
              % (rec['hits'], rec['last'], protos, srcs, ip_str))


# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------

class FullHelpParser(argparse.ArgumentParser):
    """ArgumentParser whose -h also prints each subcommand's options.

    By default argparse hides subcommand arguments behind a second
    "<prog> <mode> -h", so a sysop meeting this tool has to ask three
    times to see what it can do.  For a two-mode tool that is friction
    with no benefit, so -h shows everything at once.  "merge -h" and
    "report -h" still work for the narrow view.
    """

    def __init__(self, *args, **kwargs):
        self._subcommands = []
        argparse.ArgumentParser.__init__(self, *args, **kwargs)

    def track_sub(self, sub_parser):
        self._subcommands.append(sub_parser)
        return sub_parser

    def format_help(self):
        text = argparse.ArgumentParser.format_help(self)
        for p in self._subcommands:
            text += "\n" + ("-" * 70) + "\n"
            text += p.format_help()
        return text


EXAMPLES = """
examples:

  Look first -- report changes nothing:

    cd \\wcat
    wcipaccess.py report --logdir .
    wcipaccess.py report --logdir . --since 20260801 --top 50

  Merge the accumulated blocks into the permanent firewall lists.
  This writes ipaccess-{proto}-new.dat; it does not replace the live
  file.  Promote it yourself, or let do-ipaccess-merge.cmd do it:

    wcipaccess.py merge --ipaccess config\\ --iptrack iptrack\\
    wcipaccess.py merge --ipaccess config\\ --iptrack iptrack\\ \\
                        --learn smtpcmd\\learn --delete

  Normally you would run the batch wrapper instead, which reports,
  waits for confirmation, then merges and promotes:

    do-ipaccess-merge.cmd
    do-ipaccess-merge.cmd /auto        (unattended, wcTaskMgr)

notes:

  --delete removes a .blk only AFTER its IP has been merged, so the
  block is promoted from a temporary IP Tracking block to a permanent
  ipaccess entry rather than lost.  Omit --delete to keep the .blk
  files; re-merging the same IP is harmless, the merge is a set union.

  Block Time 0 under wcConfig IP Tracking/Blocking tells wcServer not
  to expire and auto-delete .blk files, so they accumulate until you
  merge them.
"""


def main():
    parser = FullHelpParser(
        description="ipaccess-*.dat management: merge abuse sources, report offenders",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version",
        version="wcipaccess.py %s" % VERSION)
    sub = parser.add_subparsers(dest="mode")

    p_merge = parser.track_sub(sub.add_parser("merge",
        help="merge abuse sources into ipaccess-{protocol}-new.dat",
        description="Merge abuse sources into ipaccess-{protocol}-new.dat"))
    p_merge.add_argument("--ipaccess", required=True,
        help="Directory containing ipaccess-*.dat files (e.g. config\\)")
    p_merge.add_argument("--iptrack",
        help="Directory containing {PROTO}.{ip}.blk files (e.g. iptrack\\)")
    p_merge.add_argument("--learn",
        help="Directory containing {ip}.log files (e.g. smtpcmd\\learn) -> SMTP")
    p_merge.add_argument("--log", nargs='+',
        help="wchttp-unauth-post*.log file(s) or glob(s) -> HTTP")
    p_merge.add_argument("--reduce", choices=["b", "c"], default="c",
        help="Reduce to class B (/16) or C (/24) when 2+ IPs share prefix (default: c)")
    p_merge.add_argument("--delete", action="store_true",
        help="Delete processed .blk files after merging")

    p_report = parser.track_sub(sub.add_parser("report",
        help="worst offender table from wcOnline*-ipblock and wchttp event logs",
        description="Worst offender table from wcOnline*-ipblock and wchttp "
                    "event logs.  Read-only: changes nothing."))
    p_report.add_argument("--logdir", default=".",
        help="Directory containing the log files (default: current directory)")
    p_report.add_argument("--top", type=int, default=25,
        help="Show top N offenders (default: 25)")
    p_report.add_argument("--proto",
        help="Filter hits by protocol (e.g. HTTP, SMTP)")
    p_report.add_argument("--learn",
        help="smtpcmd\\learn directory for SMTP hit weights "
             "(default: <logdir>\\smtpcmd\\learn if it exists)")
    p_report.add_argument("--since",
        help="Only count hits on/after this date, YYYYMMDD (learn files "
             "filtered by file modify time)")

    args = parser.parse_args()
    if args.mode in ("merge", "report"):
        wlog("BEGIN v%s %s" % (VERSION, ' '.join(sys.argv[1:])))
        if args.mode == "merge":
            do_merge(args)
        else:
            do_report(args)
        wlog("END %s" % args.mode)
    else:
        parser.print_help()
        sys.exit(1)


main()
