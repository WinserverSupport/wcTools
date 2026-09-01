#!/usr/bin/env python
# wcat-trace.py -- Wildcat! mail transaction tracer
#
# Follows one inbound SMTP payload (or one outbound queue entry) across
# every stage of the Wildcat! mail system using only the stock logs.
#
# Reference: c:\local\claude\wcTools\wcmail-trace-map.md
#
# ---------------------------------------------------------------------
# REQUIREMENTS -- what the sysop must enable for a full trace
# ---------------------------------------------------------------------
#
# 1) wcSMTP session trace logging.
#    wcConfig | Mail Server | Log Options | SMTP Server | Log Options:
#
#        wcSMTP Log Period: Daily
#        [X] Enable Session Trace
#        [X] Enable Verbose Logging
#
#    Without this there is no wcSmtpTrace log: no SMTP dialog, and no
#    full RCPT TO list (smtpfilter records only the FIRST recipient),
#    so a multi-recipient message cannot be traced per recipient.
#
#    Session trace line prefixes:
#        "C: "   client command
#        "S: "   server response
#        "** "   meta -- WCX calls and other session events, including
#                the prespool file name this tool keys on
#
# 2) NOTHING ELSE on wcSMTP 10.0.500.3 or later.
#
#    As of 500.3 (smtpserv.cpp:3189) the prespool file name is logged
#    permanently, to both wcsmtp and the session trace:
#
#        (0930) Starting prespool file: \spool\santronics\new\SMT2693.tmp
#        ** Starting prespool file: \spool\santronics\new\SMT2693.tmp
#
#    The "** " form sits inside the session block, so the psf->session
#    link is exact by construction -- no thread-id matching at all.
#
#    OLDER BUILDS / OLDER LOGS ONLY: before 500.3 that line was gated by
#    the registry DWORD HKLM\SOFTWARE\SSI\Wildcat\EnableDeepDebug (set
#    with: wcregedit /value:wcSMTP\EnableDeepDebug /dword:1), which is
#    deliberately undocumented in auphelp.  This tool still reads that
#    older "DEEP_DEBUG: szPrespoolFileName:" spelling, so historical
#    logs keep tracing.  Without it, every message still resolves, but
#    the session link is INFERRED (first recipient + time) rather than
#    EXACT -- measured 0/100 exact vs 99/100 exact on 2026-08-28.
#
# IDENTIFIER MODEL (measured 2026-08-28/29 on NTBBS -- read this first)
#
#   cid   is NOT a transaction id.  It is the wcServer connection of the
#         PROCESS: wcsmtp.exe=1, wcmail=3, wcnntpserver=4, wclistserve=5.
#         All wcSMTP threads (Receiver, Router, Sender) share that one
#         context, so GetConnectionId() returns 00000001 inside every
#         smtpfilter hook and 436 connection banners in one day all read
#         "cid: 00000001".  Grouping by cid merges the whole day.
#
#   tid   is the SMTP session thread.  Unique while a session is open,
#         but recycled -- 291 distinct tids served 436 sessions in a day.
#         Usable only together with a time window.
#
#   psf   the prespool file name is the real per-message key
#         (100 distinct across 101 filter runs in a day).
#
#   spool name  keys everything from the router onward, and is logged
#         WITHOUT its leading zero: file 064129W.D -> log "64129W".
#
# Stage keys:
#   1-3 receiver / envelope / DATA filters   psf   (session dialog: tid)
#   4   routing                              spool name + rcpt
#   5   local delivery (wcMail)              spool name -> msg# conf.num
#   6   remote send                          spool name + tid
#
# The psf -> spool-name hop has NO shared key in any log.  It is bridged
# on (recipient, time) and is always reported as INFERRED.
#
# Usage:
#   python wcat-trace.py [--logs <dir>] [--date YYYYMMDD] <selector>
#
#   Logs default to the CURRENT DIRECTORY, so run it from the wcServer
#   folder (d:\wc5, c:\wcat, c:\wc10beta32, ...).  Otherwise pass
#   --logs d:\wc5 explicitly.
#
# Selectors:
#   --psf <name>       trace a message, e.g. smtce4f.tmp
#   --spool <name>     trace by host spool name, e.g. 64173W / 064173W
#   --rcpt <addr>      trace messages for an envelope recipient
#   --msg <conf.num>   find the wcListServe distribution of a message
#   --list             list every message found for the date
#
# Options:
#   --computer <name>  log computer tag (NTBBS, MAIN4) -- needed when one
#                      folder holds logs from several computers.  NOTE:
#                      --server is deliberately NOT used for this; the
#                      wcPAPI scripts reserve --server for the
#                      WildcatServerConnectSpecific(0,szComputerName)
#                      connection, and this tool reads logs offline.
#   --include-untagged with --computer, also read logs whose filename
#                      carries no computer tag
#   --window <secs>    bridge window for the inferred hop (default 120)
#   --verbose          include the SMTP dialog and full send trace
#
# Revision History:
# 500.2  08/29/26  Initial version
# 500.2  08/29/26  rekeyed on psf; cid proved to be per-process not
#                  per-transaction (wcsrvmon: wcsmtp.exe holds cid 1)
# 500.2  08/29/26  --computer log filter; seed messages from the 500.3
#                  permanent prespool line so a receiver-only run with
#                  SMTPFILTER OFF still traces

import os
import re
import sys
import glob
import argparse

try:
    sys.stdout.reconfigure(encoding='cp437', errors='replace')
    sys.stderr.reconfigure(encoding='cp437', errors='replace')
except (AttributeError, ValueError):
    pass

# Default to the current directory: this normally runs from a wcServer
# folder (c:\wcat, d:\wc5, c:\wc10beta32, c:\wc6, ...) where the logs
# already live.  Use --logs to point elsewhere.
# NOTE: not r'.\' -- a raw string cannot end in a backslash.
DEFAULT_LOGS = '.'
EXACT    = "EXACT"
INFERRED = "INFERRED"


def spool_key(name):
    """Normalize a spool name; the router drops the leading zero."""
    if not name:
        return ''
    n = os.path.basename(name.strip().strip('[]'))
    for ext in ('.D', '.X', '.d', '.x'):
        if n.endswith(ext):
            n = n[:-2]
    return n.lstrip('0').upper()


def psf_key(name):
    if not name:
        return ''
    return os.path.basename(name.strip()).lower()


def tid_key(t):
    """Normalize a thread id.

    wcsmtp writes 4 hex digits -- "(1770)" -- while the wcSmtpTrace
    banner writes 8 -- "tid: 00001770".  Compare them unpadded or the
    exact psf->session link silently never matches.
    """
    if not t:
        return ''
    return t.strip().lstrip('0').upper() or '0'


def hhmmss(line):
    m = re.search(r'(\d{2}):(\d{2}):(\d{2})', line)
    if not m:
        return None
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))


def tstr(line):
    m = re.search(r'(\d{2}:\d{2}:\d{2})', line)
    return m.group(1) if m else '        '


def clock(secs):
    if secs is None:
        return '        '
    return "%02d:%02d:%02d" % (secs // 3600, (secs % 3600) // 60, secs % 60)


def strip_addr(s):
    s = (s or '').strip().strip(',;')
    if s.startswith('<') and s.endswith('>'):
        s = s[1:-1]
    return s.strip().lower()


FAMILY_PATTERNS = [
    ('sendtrace',  r'^wcsmtpsendtrace'),
    ('smtptrace',  r'^wcsmtptrace'),
    ('wcsmtp',     r'^wcsmtp\d'),
    ('wcsap',      r'^wcsap'),
    ('smtpfilter', r'^smtpfilter\d'),
    ('dkimverify', r'^wcdkim-verify'),
    ('dkimsigner', r'^wcdkim-signer'),
    ('wcmail',     r'^wcmail'),
    ('listserve',  r'^wclistserve'),
]


def family_of(fname):
    low = os.path.basename(fname).lower()
    for fam, pat in FAMILY_PATTERNS:
        if re.match(pat, low):
            return fam
    if low.startswith('smtpfilter-'):
        m = re.match(r'smtpfilter-([a-z0-9]+?)-?\d{8}', low)
        return 'hook:' + (m.group(1) if m else '?')
    return None


RE_SERVERTAG = re.compile(r'\.([A-Za-z0-9_-]+)\.log$', re.I)


def server_tag(path):
    """Server name embedded in a log filename, or '' if untagged.

    wcsmtp20260829.NTBBS.log -> NTBBS
    smtpfilter20260829.ntbbs.log -> NTBBS
    wcdkim-verify20260829.log -> ''   (cannot be attributed)
    """
    m = RE_SERVERTAG.search(os.path.basename(path))
    return m.group(1).upper() if m else ''


class LogSet(object):
    """Log files for one date, optionally restricted to one computer.

    Some families tag the computer in the filename
    (wcsmtp20260829.NTBBS.log) and some do not
    (smtpfilter-cleanspam20260829.log).  Untagged files cannot be
    attributed.

    Running ON a server there is only one set, so everything is included
    and no --computer is needed.  --computer exists for a COLLECTION
    folder holding several computers' logs, and there an untagged file is
    more likely to belong to another computer than to the one asked for
    -- so it is dropped unless --include-untagged says otherwise.
    """

    def __init__(self, logdir, date, computer='', include_untagged=False):
        self.dir, self.date, self.files = logdir, date, {}
        self.computer = (computer or '').upper()
        self.tags = set()
        self.untagged = []
        self.dropped = []
        for path in glob.glob(os.path.join(logdir, '*%s*.log' % date)):
            fam = family_of(path)
            if not fam:
                continue
            tag = server_tag(path)
            if tag:
                self.tags.add(tag)
            else:
                self.untagged.append(os.path.basename(path))
            if self.computer:
                if tag and tag != self.computer:
                    continue
                if not tag and not include_untagged:
                    self.dropped.append(os.path.basename(path))
                    continue
            self.files.setdefault(fam, []).append(path)

    def lines(self, fam):
        for path in self.files.get(fam, []):
            try:
                with open(path, 'rb') as f:
                    for raw in f:
                        yield raw.decode('cp437', 'replace').rstrip('\r\n')
            except IOError:
                continue

    def families(self):
        return sorted(self.files)

    def hooks(self):
        return sorted(f for f in self.files if f.startswith('hook:'))


RE_CONN     = re.compile(r'Connection Time:\s*(\d{8})\s+(\d{2}:\d{2}:\d{2})\s+cid:\s*([0-9A-Fa-f]+)\s+tid:\s*([0-9A-Fa-f]+)')
RE_PSF      = re.compile(r'(?:psf=|msf:\s*|file:\s*|fname\s*:\s*|szPrespoolFileName:\s*)([^\s&]+\.tmp)', re.I)
RE_ENV      = re.compile(r'#\s*ip:\s*(\S+)\s+trcpt:\s*(\d+)\s+rcpt:\s*(\S+)\s+from:\s*(\S+)')
RE_RCPTTO   = re.compile(r'C:\s*RCPT TO:\s*(<[^>]*>)', re.I)
RE_MAILFROM = re.compile(r'C:\s*MAIL FROM:\s*(<[^>]*>)', re.I)
RE_QUEUED   = re.compile(r'\(ROUT\)\s+Queued\((\w)\)\s+(\S+)\s+for:\s*(\S+)')
RE_SEND     = re.compile(r'\((\w{4})\)\s+SEND>\s+(.*)$')
RE_SENDNAME = re.compile(r'\[([0-9A-Za-z]+W)\]')
# Two spellings accepted.  Current wcSMTP emits the DEEP_DEBUG form;
# the "Starting prespool file:" form is the proposed permanent line.
RE_DEEPPSF  = re.compile(
    r'\((\w{4})\)\s+(?:DEEP_DEBUG:\s*szPrespoolFileName:|Starting prespool file:)\s*(\S+)', re.I)

# Same line as a wcSmtpTrace "**" meta record (proposed).  When present
# it names the psf INSIDE the session block, making the psf->session
# link exact by construction -- no tid matching needed.
RE_TRACEPSF = re.compile(r'\*\*\s*Starting prespool file:\s*(\S+)', re.I)
RE_SIGNER   = re.compile(r'\*\s*Message:\s*Incoming\s+(\S+)', re.I)
RE_MSGQUEUE = re.compile(r'Message Queue:\s*(\S+)', re.I)
RE_WCMAILFN = re.compile(r'\*\*\*\s*File\s+(\S+?)\s+moved', re.I)
RE_NEWMSG   = re.compile(r'\+\s*New msg#\s*(\d+)\.(\d+)', re.I)
RE_LISTSENT = re.compile(r'Sent List\s+(\S+)\s+Msg=(\d+)\s+Conference=(\d+)', re.I)
RE_FILTRES  = re.compile(r'\*\s*filter result:\s*(\S+)')
RE_RUNFILT  = re.compile(r'\+\s*run filter:\s*(\S+)')
RE_HOOKFN   = re.compile(r'fname\s*:\s*(\S+)', re.I)


class Msg(object):
    """One message, keyed by its prespool file."""
    def __init__(self, key):
        self.key = key
        self.name = key
        self.t = None
        self.ip = self.mailfrom = self.first_rcpt = ''
        self.trcpt = 0
        self.filters = []          # [(filter, result)]
        self.verdicts = []         # [(hook, line)]
        self.hooklines = {}        # hook -> [lines]


class Index(object):
    def __init__(self, logs):
        self.logs = logs
        self.msgs = {}             # psfkey -> Msg
        self.episodes = []         # [{'t','tid','rcpts','from','lines'}]
        self.psf_tid = {}          # psfkey -> tid (exact, from DEEP_DEBUG)
        self.queued = []           # [(t, tag, spoolkey, rcpt, line)]
        self.signer = {}
        self.wcmail = {}
        self.msgnum = {}
        self.send = {}
        self.sendtrace = {}
        self.listserve = []
        self._build()

    def msg(self, k):
        if k not in self.msgs:
            self.msgs[k] = Msg(k)
        return self.msgs[k]

    def _build(self):
        # ---- smtpfilter: the chain, one run per message
        cur, pend = None, None
        for line in self.logs.lines('smtpfilter'):
            p = RE_PSF.search(line)
            if p:
                cur = self.msg(psf_key(p.group(1)))
                cur.name = p.group(1)
                if cur.t is None:
                    cur.t = hhmmss(line)
            if cur is None:
                continue
            e = RE_ENV.search(line)
            if e:
                cur.ip = e.group(1)
                cur.trcpt = int(e.group(2))
                cur.first_rcpt = strip_addr(e.group(3))
                cur.mailfrom = strip_addr(e.group(4))
            r = RE_RUNFILT.search(line)
            if r:
                pend = os.path.basename(r.group(1))
            f = RE_FILTRES.search(line)
            if f and pend:
                cur.filters.append((pend, f.group(1)))
                pend = None

        # ---- per-hook logs: keyed by their own fname: line
        for fam in self.logs.hooks() + ['dkimverify']:
            cur = None
            for line in self.logs.lines(fam):
                p = RE_HOOKFN.search(line) or RE_PSF.search(line)
                if p and p.group(1).lower().endswith('.tmp'):
                    cur = self.msg(psf_key(p.group(1)))
                    cur.name = cur.name or p.group(1)
                    if cur.t is None:
                        cur.t = hhmmss(line)
                if cur is None:
                    continue
                cur.hooklines.setdefault(fam, []).append(line)
                if 'Rejecting' in line or 'Accepted for' in line:
                    cur.verdicts.append((fam.replace('hook:', ''), line))

        # ---- wcSmtpTrace: session episodes (tid + full RCPT list)
        ep = None
        for line in self.logs.lines('smtptrace'):
            c = RE_CONN.search(line)
            if c:
                ep = {'t': hhmmss(line), 'tid': tid_key(c.group(4)),
                      'cid': c.group(3).upper(), 'rcpts': [], 'from': '',
                      'psf': '', 'lines': []}
                self.episodes.append(ep)
                continue
            if ep is None:
                continue
            ep['lines'].append(line)
            tp = RE_TRACEPSF.search(line)
            if tp:
                ep['psf'] = psf_key(tp.group(1))
                mm = self.msg(ep['psf'])
                mm.name = mm.name or tp.group(1)
                if mm.t is None:
                    mm.t = hhmmss(line) or ep['t']
            r = RE_RCPTTO.search(line)
            if r:
                ep['rcpts'].append(strip_addr(r.group(1)))
            m = RE_MAILFROM.search(line)
            if m:
                ep['from'] = strip_addr(m.group(1))

        # ---- wcsmtp: router Queued, sender SEND>, DEEP_DEBUG psf<->tid
        for line in self.logs.lines('wcsmtp'):
            t = hhmmss(line)
            d = RE_DEEPPSF.search(line)
            if d:
                k = psf_key(d.group(2))
                self.psf_tid[k] = tid_key(d.group(1))
                # Seed the message from this line too.  With SMTPFILTER
                # disabled there is no smtpfilter log at all, and this is
                # then the ONLY record naming the prespool file.
                mm = self.msg(k)
                mm.name = mm.name or d.group(2)
                if mm.t is None:
                    mm.t = hhmmss(line)
                continue
            q = RE_QUEUED.search(line)
            if q:
                self.queued.append((t, q.group(1), spool_key(q.group(2)),
                                    strip_addr(q.group(3)), line))
                continue
            s = RE_SEND.search(line)
            if s:
                nm = RE_SENDNAME.search(s.group(2))
                if nm:
                    self.send.setdefault(spool_key(nm.group(1)), []).append((t, tid_key(s.group(1)), line))

        # ---- wcdkim-signer
        k = None
        for line in self.logs.lines('dkimsigner'):
            m = RE_SIGNER.search(line)
            if m:
                k = spool_key(m.group(1))
                self.signer.setdefault(k, []).append(line)
            elif k and line.strip().startswith('-'):
                self.signer[k].append(line)

        # ---- wcmail
        last = None
        for line in self.logs.lines('wcmail'):
            n = RE_NEWMSG.search(line)
            if n:
                last = "%s.%s" % (n.group(1), n.group(2))
            f = RE_WCMAILFN.search(line)
            if f:
                kk = spool_key(f.group(1))
                self.wcmail.setdefault(kk, []).append(line)
                if last:
                    self.msgnum.setdefault(kk, last)

        # ---- wcSmtpSendTrace
        k = None
        for line in self.logs.lines('sendtrace'):
            m = RE_MSGQUEUE.search(line)
            if m:
                k = spool_key(m.group(1))
                self.sendtrace.setdefault(k, [])
            if k:
                self.sendtrace[k].append(line)

        # ---- wcListServe
        for line in self.logs.lines('listserve'):
            m = RE_LISTSENT.search(line)
            if m:
                self.listserve.append((hhmmss(line), m.group(1), m.group(2), m.group(3), line))

    # -------- linking ---------------------------------------------------

    def episode_for(self, m):
        """Session dialog for a message.  Exact when DEEP_DEBUG gave the
        tid, otherwise the nearest earlier episode offering that rcpt."""
        # Best case: the session block names the psf itself.
        for e in self.episodes:
            if e.get('psf') and e['psf'] == m.key:
                return e, EXACT

        tid = self.psf_tid.get(m.key)
        cands = [e for e in self.episodes if e['t'] is not None and m.t is not None
                 and e['t'] <= m.t + 5]
        if tid:
            byt = [e for e in cands if e['tid'] == tid]
            if byt:
                return byt[-1], EXACT
        if m.first_rcpt:
            byr = [e for e in cands if m.first_rcpt in e['rcpts']]
            if byr:
                return byr[-1], INFERRED
        return None, None

    def rcpts_for(self, m):
        ep, _ = self.episode_for(m)
        if ep and ep['rcpts']:
            return ep['rcpts']
        return [m.first_rcpt] if m.first_rcpt else []

    def bridge(self, m, window):
        want = set(self.rcpts_for(m))
        if m.t is None:
            return []
        out = [q for q in self.queued
               if q[0] is not None and q[3] in want and m.t - 5 <= q[0] <= m.t + window]
        out.sort()
        return out


# ---------------------------------------------------------------------------

def hdr(s):
    print("")
    print(s)
    print("-" * len(s))


def show_message(ix, m, verbose):
    hdr("STAGE 1-3  receiver / envelope / DATA filters   [%s: psf key]" % EXACT)
    print("  prespool   : %s" % m.name)
    print("  time       : %s" % clock(m.t))
    ep, how = ix.episode_for(m)
    if ep:
        # display padded, the way the trace banner writes it
        print("  session    : tid %s   (%s)   [process cid %s]"
              % (ep['tid'].rjust(8, '0'), how, ep['cid']))
    else:
        print("  session    : (no wcSmtpTrace episode matched)")
    print("  client ip  : %s" % (m.ip or '?'))
    print("  mail from  : %s" % (m.mailfrom or (ep or {}).get('from', '?')))

    rl = ix.rcpts_for(m)
    if m.trcpt:
        print("  recipients : %d   (filters saw only the first: %s)" % (m.trcpt, m.first_rcpt))
    if rl:
        for r in rl[:10]:
            print("               %s" % r)
        if len(rl) > 10:
            print("               ... and %d more" % (len(rl) - 10))

    if m.filters:
        print("  filters    :")
        for name, res in m.filters:
            print("               %-34s %s" % (name, res))
            if res.lower().startswith('accept_final'):
                print("               ^ chain ENDED here; later hooks did not run")
    for hook, line in m.verdicts:
        parts = line.split(None, 3)
        print("  verdict    : [%s] %s" % (hook, parts[-1] if len(parts) > 3 else line))

    if verbose and ep:
        print("  dialog     :")
        for l in ep['lines']:
            if ' C: ' in l or ' S: ' in l:
                print("               %s" % l.strip()[:110])


def show_route(ix, bridged, verbose, window):
    if not bridged:
        hdr("STAGE 4-6  no router record")
        print("  Nothing queued for these recipients within %ds." % window)
        print("  If the message was REJECTED at stage 3 that is correct --")
        print("  a rejected message never reaches the router.")
        return

    hdr("STAGE 4    routing   [%s: bridged on (recipient, time)]" % INFERRED)
    print("  %d spool file(s) queued -- one per recipient" % len(bridged))
    for t, tag, key, rcpt, line in bridged:
        where = "sender queue (remote)" if tag.upper() == 'R' else "host spool (local)"
        print("    %-8s %-10s %-34s %s" % (clock(t), key, rcpt, where))

    for t, tag, key, rcpt, line in bridged:
        hdr("SPOOL %s -> %s   [%s: keyed by spool name]" % (key, rcpt, EXACT))
        for l in ix.signer.get(key, [])[:5]:
            print("  signer   %s" % l.strip()[:104])
        if tag.upper() == 'I':
            for l in ix.wcmail.get(key, []):
                print("  wcmail   %s" % l.strip()[:104])
            mn = ix.msgnum.get(key)
            print("  DELIVERED: msg# %s" % mn if mn else "  (no wcMail record)")
        else:
            sends = ix.send.get(key, [])
            for st, tid, l in sends:
                print("  send     %s" % l.strip()[:104])
            blk = ix.sendtrace.get(key, [])
            for l in (blk if verbose else blk[:7]):
                if l.strip():
                    print("  trace    %s" % l.strip()[:104])
            fin = [s for s in sends if 'done:' in s[2] or 'Sent [' in s[2]]
            if fin:
                print("  FINAL    %s" % fin[-1][2].strip()[:104])
            elif not sends:
                print("  (queued, no send record -- pending or deferred)")


def do_list(ix):
    hdr("Messages found")
    print("  %-9s %-16s %-6s %-32s %s" % ("time", "prespool", "rcpts", "mail from", "outcome"))
    for k in sorted(ix.msgs, key=lambda x: (ix.msgs[x].t or 0)):
        m = ix.msgs[k]
        out = ''
        for name, res in m.filters:
            if 'final' in res.lower() or 'discard' in res.lower() or 'reject' in res.lower():
                out = "%s=%s" % (name.replace('smtpfilter-', '').replace('.wcx', ''), res)
        if m.verdicts:
            hook, line = m.verdicts[-1]
            out = "%s=%s" % (hook, "REJECT" if 'Rejecting' in line else "accept")
        print("  %-9s %-16s %-6s %-32s %s" % (clock(m.t), os.path.basename(m.name)[:16],
                                              m.trcpt or '?', (m.mailfrom or '')[:32], out))
    print("")
    print("  messages: %d   queued spool files: %d   listserve sends: %d"
          % (len(ix.msgs), len(ix.queued), len(ix.listserve)))
    print("  sessions (wcSmtpTrace episodes): %d" % len(ix.episodes))


def show_listserve(ix, sel):
    conf, _, num = sel.partition('.')
    hits = [r for r in ix.listserve if r[2] == num and r[3] == conf]
    hdr("wcListServe distribution of msg# %s   [%s: Msg=/Conference= key]" % (sel, EXACT))
    if not hits:
        print("  No wcListServe record for that message on this date.")
        return
    for t, lst, msg, cf, line in hits:
        print("  %s  list %s  Msg=%s Conference=%s" % (clock(t), lst, msg, cf))
    print("")
    print("  wcListServe re-injects via SMTP, so the distribution appears")
    print("  next as an INBOUND session from this server's own IP.")


def main():
    ap = argparse.ArgumentParser(description="Wildcat! mail transaction tracer")
    ap.add_argument('--logs', default=DEFAULT_LOGS)
    ap.add_argument('--date', default='')
    ap.add_argument('--computer', default='',
                    help="log computer tag, e.g. NTBBS or MAIN4 -- needed "
                         "when one folder holds logs from several computers. "
                         "(--server is reserved for a wcPAPI connection.)")
    ap.add_argument('--include-untagged', action='store_true',
                    help="with --computer, also read logs whose filename "
                         "carries no computer tag (they may belong to another)")
    ap.add_argument('--psf')
    ap.add_argument('--spool')
    ap.add_argument('--rcpt')
    ap.add_argument('--msg')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--window', type=int, default=120)
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    date = args.date
    if not date:
        cand = sorted(set(re.findall(r'(\d{8})', ' '.join(
            os.path.basename(p) for p in glob.glob(os.path.join(args.logs, '*.log'))))))
        if not cand:
            print("ERROR: no dated logs in %s; pass --date" % args.logs)
            sys.exit(1)
        date = cand[-1]
        print("(no --date; using %s)" % date)

    logs = LogSet(args.logs, date, args.computer, args.include_untagged)
    if not logs.files:
        print("ERROR: no logs matching *%s*.log in %s" % (date, args.logs))
        sys.exit(1)

    print("Wildcat! mail trace   logs=%s  date=%s%s"
          % (args.logs, date, ("  computer=%s" % logs.computer) if logs.computer else ""))
    print("families: %s" % ', '.join(logs.families()))

    if not logs.computer and len(logs.tags) > 1:
        print("")
        print("WARNING: this folder holds logs from %d computers: %s"
              % (len(logs.tags), ', '.join(sorted(logs.tags))))
        print("         They are being read TOGETHER, which mixes unrelated")
        print("         transactions.  Pass --computer <name> to separate them.")
    if logs.dropped:
        print("")
        print("NOTE: %d log(s) carry no computer tag, so they cannot be attributed"
              % len(logs.dropped))
        print("      to %s and were EXCLUDED: %s"
              % (logs.computer, ', '.join(logs.dropped[:4])))
        print("      Add --include-untagged to read them anyway.")
    ix = Index(logs)

    if args.list:
        do_list(ix)
        return
    if args.msg:
        show_listserve(ix, args.msg)
        return
    if args.spool:
        key = spool_key(args.spool)
        q = [r for r in ix.queued if r[2] == key]
        if not q:
            print("\nNo router record for spool '%s'." % args.spool)
            sys.exit(2)
        show_route(ix, q, args.verbose, args.window)
        return

    m = None
    if args.psf:
        m = ix.msgs.get(psf_key(args.psf))
        if not m:
            print("\nNo message found for prespool '%s'." % args.psf)
            sys.exit(2)
    elif args.rcpt:
        want = strip_addr(args.rcpt)
        hits = [mm for mm in ix.msgs.values() if want in ix.rcpts_for(mm)]
        if not hits:
            print("\nNo message found for recipient '%s'." % want)
            sys.exit(2)
        hits.sort(key=lambda x: (x.t or 0))
        print("\n%d message(s) for %s:" % (len(hits), want))
        for h in hits:
            print("   %s  %s" % (clock(h.t), os.path.basename(h.name)))
        m = hits[0]
        print("tracing the first; use --psf to pick another")
    else:
        ap.error("one selector required: --psf/--spool/--rcpt/--msg/--list")

    show_message(ix, m, args.verbose)
    show_route(ix, ix.bridge(m, args.window), args.verbose, args.window)

    print("")
    print("Confidence: stages 1-3 keyed by psf, stages 4-6 by spool name;")
    print("the psf -> spool hop is INFERRED on (recipient, time).")
    print("Note cid is per-PROCESS (wcsmtp.exe=1), never a transaction id.")


if __name__ == "__main__":
    main()
