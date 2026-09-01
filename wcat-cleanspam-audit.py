#!/usr/bin/env python
# wcat-cleanspam-audit.py -- audit smtpfilter-cleanspam decisions
#
# Answers the two questions an empty spam folder cannot:
#
#   1. Is the rule producing FALSE REJECTS?  A rejection whose message
#      carried a non-empty List-Id (especially an ietf.org one) is mail
#      that should have been accepted.  Empty List-Id on a reject is the
#      expected spam shape.
#
#   2. Is the rule actually DOING the work?  Zero spam arriving is also
#      consistent with the spam having stopped upstream (greylist, SPF,
#      autowhite) or the senders moving on.  The accept/reject counts
#      show whether cleanspam is the reason.
#
# Reads smtpfilter-cleanspam<date>[.<cn>].log, which records per message:
#
#     5321.rcptto  : hsantos@isdg.net
#     5322.From    : ...
#     5322.List-Id : dnsop.ietf.org
#     Accepted for hsantos@isdg.net by: Accept-If auth: *dkim=pass ...*
#     Rejecting mail for hsantos@isdg.net (...)
#
# Usage:
#   python wcat-cleanspam-audit.py [--logs <dir>] [--date <YYYYMMDD|*>]
#                                  [--rcpt <addr>] [--show-rejects]
#
# Run it from the wcServer folder (d:\wc5) or pass --logs.
#
# Revision History:
# 500.2  08/31/26  Initial version

import os
import re
import sys
import glob
import argparse
import collections

try:
    sys.stdout.reconfigure(encoding='cp437', errors='replace')
    sys.stderr.reconfigure(encoding='cp437', errors='replace')
except (AttributeError, ValueError):
    pass

RE_FIELD  = re.compile(r'\s(5321\.rcptto|5322\.From|5322\.List-Id|5322\.Subject)\s*:\s*(.*)$')
RE_ACCEPT = re.compile(r'Accepted for (\S+) by:\s*(.*)$')
RE_REJECT = re.compile(r'Rejecting mail for (\S+)')
RE_BANNER = re.compile(r'#\s*smtpfilter-cleanspam')
RE_RULE   = re.compile(r'rule (address|section)\s*:\s*(.*)$')


class Rec(object):
    def __init__(self):
        self.rcpt = self.frm = self.listid = self.subj = ''
        self.verdict = ''          # 'accept' | 'reject'
        self.why = ''
        self.date = ''
        self.kind = ''         # 'txt' (flat, unconditional) | 'ini' (conditional)
        self.rule = ''


def scan(paths):
    recs = []
    cur = None
    for p in paths:
        day = re.search(r'(\d{8})', os.path.basename(p))
        day = day.group(1) if day else ''
        with open(p, 'rb') as f:
            for raw in f:
                line = raw.decode('cp437', 'replace').rstrip('\r\n')
                if RE_BANNER.search(line):
                    cur = Rec()
                    cur.date = day
                    recs.append(cur)
                    continue
                if cur is None:
                    continue
                m = RE_FIELD.search(line)
                if m:
                    k, v = m.group(1), m.group(2).strip()
                    if k == '5321.rcptto':
                        cur.rcpt = v.lower()
                    elif k == '5322.From':
                        cur.frm = v
                    elif k == '5322.List-Id':
                        cur.listid = v
                    elif k == '5322.Subject':
                        cur.subj = v
                    continue
                k = RE_RULE.search(line)
                if k:
                    cur.kind = 'txt' if k.group(1) == 'address' else 'ini'
                    cur.rule = k.group(2).strip()
                    continue
                a = RE_ACCEPT.search(line)
                if a:
                    cur.verdict, cur.why = 'accept', a.group(2).strip()
                    continue
                r = RE_REJECT.search(line)
                if r:
                    cur.verdict = 'reject'
    return [r for r in recs if r.verdict]


def main():
    ap = argparse.ArgumentParser(description="Audit smtpfilter-cleanspam decisions")
    ap.add_argument('--logs', default='.')
    ap.add_argument('--date', default='*', help="YYYYMMDD, or * for every log")
    ap.add_argument('--rcpt', default='', help="restrict to one recipient")
    ap.add_argument('--show-rejects', action='store_true',
                    help="list every rejection, not just suspicious ones")
    args = ap.parse_args()

    pat = os.path.join(args.logs, 'smtpfilter-cleanspam%s*.log' % args.date)
    paths = sorted(glob.glob(pat))
    if not paths:
        print("No logs matching %s" % pat)
        sys.exit(1)
    print("Auditing %d log file(s)" % len(paths))

    recs = scan(paths)
    if args.rcpt:
        want = args.rcpt.lower()
        recs = [r for r in recs if r.rcpt == want]
    if not recs:
        print("No cleanspam decisions found.")
        return

    acc = [r for r in recs if r.verdict == 'accept']
    rej = [r for r in recs if r.verdict == 'reject']

    print("")
    print("decisions : %d   accepted: %d   rejected: %d" % (len(recs), len(acc), len(rej)))

    print("")
    print("-- by recipient --")
    per = collections.defaultdict(lambda: [0, 0])
    for r in recs:
        per[r.rcpt][0 if r.verdict == 'accept' else 1] += 1
    for k, (a, d) in sorted(per.items(), key=lambda kv: -(kv[1][0] + kv[1][1])):
        print("  %-40s accept=%-6d reject=%d" % (k, a, d))

    if acc:
        print("")
        print("-- which Accept-If did the work --")
        for k, n in collections.Counter(r.why for r in acc).most_common():
            print("  %-6d %s" % (n, k[:96]))

    # THE check: a CONDITIONAL rejection whose message carried a List-Id.
    #
    # Only .ini rules can produce a false reject.  A .txt flat-list entry
    # is unconditional BY DESIGN -- rejecting list mail sent to such an
    # address is the intended behaviour, not a defect, so those are
    # counted separately rather than flagged.
    suspect = [r for r in rej if r.listid.strip() and r.kind != 'txt']
    bytxt   = [r for r in rej if r.listid.strip() and r.kind == 'txt']
    print("")
    print("-- FALSE REJECT CHECK --")
    print("  conditional (.ini) rejects with a List-Id : %d" % len(suspect))
    if bytxt:
        print("  (%d further List-Id reject(s) came from the .txt flat list," % len(bytxt))
        print("   which is unconditional by design -- not counted as false)")
    if suspect:
        print("  These were list mail rejected by a CONDITIONAL rule -- review:")
        for r in suspect:
            print("    %s  %-28s [%s %s] List-Id: %s"
                  % (r.date, r.rcpt, r.kind, r.rule[:20], r.listid))
            print("           from: %-38s %s" % (r.frm[:38], r.subj[:40]))
    else:
        print("  None.  Every conditionally-rejected message had an empty")
        print("  List-Id, which is the expected shape for bulk spam.")

    if args.show_rejects and rej:
        print("")
        print("-- all rejections --")
        for r in rej:
            print("  %s  %-28s from: %-34s %s"
                  % (r.date, r.rcpt, r.frm[:34], r.subj[:36]))


if __name__ == "__main__":
    main()
