#!/usr/bin/env python
# wcMultiConnTest.py -- Test whether one process can hold RPC connections to
# multiple wcServers at once (per-thread) vs one-at-a-time (process-global handle).
#
# Modes:
#   --mode concurrent   spawn one thread per server, all connect together (the
#                       hypothesis). Exposes the implicit_handle process-global
#                       clobber if it exists.
#   --mode sequential   one thread per server, run to completion one at a time
#                       (baseline: each should individually succeed).
#   --mode subprocess   spawn one child PROCESS per server (option 1). Each has
#                       its own DLL globals -> should be fully independent.
#   --single NAME       internal: probe one server, print one JSON record.
#   --makewild          also MwLogin('') + GetConferenceCount, to test whether
#                       the CONFIG interface (WildcatMakewildIfHandle) follows a
#                       reconnect. Conf counts must differ per server (ntbbs=104)
#                       if config re-points; all-equal means the handle is stuck.
#                       Note: a Makewild context is 1-connect-per-server, so this
#                       is only run sequential/subprocess (never concurrent).
#
# Each probe is READ-ONLY: Connect -> CreateContext -> identity reads -> hold ->
# re-read -> DeleteContext (which also releases any Makewild session). No config
# is modified. WcGetWildcatServerGuid is avoided (mints a fresh GUID per call);
# identity is GetConnectionId + GetConnectedServer.
# 500.2  26.8.3

import sys
import ctypes
import argparse
import threading
import subprocess
import json
import time

try:
    from wcpapi.wcserver_h import *
    from wcpapi.wctype_h import *
    from wcpapi.wctype_constants_h import *
    from wcpapi.wcserror_h import *
    from wcpapi.wcsmw_h import *
except ImportError as e:
    print("ERROR: wcpapi package not found: {}".format(e))
    sys.exit(1)

# No default server list: an unqualified run must not attempt to reach
# machines the operator did not name.  With no --servers, the local
# server is probed (empty name = this computer, as elsewhere in wcPAPI).
DEFAULT_SERVERS = ['']


def get_connected_server():
    buf = ctypes.create_string_buffer(MAX_PATH)
    if GetConnectedServer(buf, MAX_PATH):
        return buf.value.decode('cp437', errors='replace')
    return '(unknown)'


def probe(target, hold, makewild=False):
    """Read-only identity probe of one server. Returns a plain dict.
    Reads identity twice around a hold window so a peer thread stealing the
    process-global binding shows up as connected/connid drift."""
    rec = {'target': target, 'tid': threading.get_ident()}
    if not WildcatServerConnectSpecific(None, target):
        rec['step'] = 'connect'
        rec['err'] = '{:08X}'.format(ctypes.GetLastError())
        return rec
    if not WildcatServerCreateContext():
        rec['step'] = 'createcontext'
        rec['err'] = '{:08X}'.format(ctypes.GetLastError())
        return rec
    try:
        rec['connected1'] = get_connected_server()
        rec['connid1']    = GetConnectionId()
        if makewild:
            if MwLogin(''):
                rec['mwlogin']   = 'ok'
                rec['confcount'] = GetConferenceCount()
            else:
                rec['mwlogin']   = '{:08X}'.format(ctypes.GetLastError())
                rec['confcount'] = -1
        time.sleep(hold)                       # window for peers to steal the global binding
        rec['connected2'] = get_connected_server()
        rec['connid2']    = GetConnectionId()
        rec['stolen']     = (rec['connected1'] != rec['connected2']) or (rec['connid1'] != rec['connid2'])
    finally:
        WildcatServerDeleteContext()           # releases the Makewild session too
    return rec


def run_concurrent(servers, hold, makewild):
    barrier = threading.Barrier(len(servers))
    results = [None] * len(servers)

    def worker(i, name):
        try:
            barrier.wait()                     # release all threads together
        except threading.BrokenBarrierError:
            pass
        results[i] = probe(name, hold, makewild)

    threads = [threading.Thread(target=worker, args=(i, n)) for i, n in enumerate(servers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def run_sequential(servers, hold, makewild):
    results = []
    for n in servers:
        holder = {}
        t = threading.Thread(target=lambda: holder.update(r=probe(n, hold, makewild)))
        t.start()
        t.join()
        results.append(holder.get('r'))
    return results


def run_subprocess(servers, makewild):
    results = []
    for n in servers:
        cmd = [sys.executable, __file__, '--single', n]
        if makewild:
            cmd.append('--makewild')
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60)
            line = out.decode('cp437', errors='replace').strip().splitlines()[-1]
            results.append(json.loads(line))
        except Exception as e:
            results.append({'target': n, 'err': 'subprocess: {}'.format(e)})
    return results


def render(mode, results, makewild):
    print()
    print("MODE: {}{}".format(mode, "  [+makewild]" if makewild else ""))
    hdr = "{:<8}  {:<10}  {:<9}  {:<9}  {:<8}  {:<6}  {}".format(
        "ASKED", "CONNECTED", "CONNID", "MWLOGIN", "CONFCNT", "STOLEN", "ERROR")
    print(hdr)
    print('-' * len(hdr))
    for r in results:
        if r is None:
            print("(no result)")
            continue
        err = r.get('err', '')
        if err:
            err = "{} @ {}".format(err, r.get('step', '?'))
        print("{:<8}  {:<10}  {:<9}  {:<9}  {:<8}  {:<6}  {}".format(
            r.get('target', '?'),
            str(r.get('connected1', '-'))[:10],
            str(r.get('connid1', '-')),
            str(r.get('mwlogin', '-')),
            str(r.get('confcount', '-')),
            str(r.get('stolen', '-')),
            err))

    ok = [r for r in results if r and not r.get('err')]
    names = [str(r.get('connected1', '')).upper() for r in ok]
    distinct = len(set(n for n in names if n and n != '(UNKNOWN)'))
    stolen_any = any(r.get('stolen') for r in ok)
    print()
    print("  probes ok        : {} / {}".format(len(ok), len(results)))
    print("  distinct servers : {} (by connected name; expect {} if independent)".format(distinct, len(results)))
    print("  binding stolen   : {}".format(stolen_any))
    if makewild:
        counts = [r.get('confcount') for r in ok if r.get('confcount') not in (None, -1)]
        distinct_counts = len(set(counts))
        print("  conf counts      : {}  (distinct={})".format(counts, distinct_counts))
        if counts and distinct_counts > 1:
            print("  CONFIG VERDICT: Makewild interface FOLLOWS the reconnect (counts differ per server).")
        elif counts and distinct_counts == 1 and len(counts) > 1:
            print("  CONFIG VERDICT: Makewild handle STUCK (every node returned the same count).")
        else:
            print("  CONFIG VERDICT: inconclusive (need >=2 nodes with a successful MwLogin).")
    if stolen_any or (len(ok) > 1 and distinct < len(ok)):
        print("  VERDICT: single-connection clobber -- threads share one process-global binding.")
    elif len(ok) > 1 and distinct == len(ok) and not stolen_any:
        print("  VERDICT: independent connections held (sequentially or per-process).")
    else:
        print("  VERDICT: inconclusive (too few reachable servers).")


# ---------------------------------------------------------------------------
if '/?' in sys.argv:
    sys.argv[sys.argv.index('/?')] = '--help'

parser = argparse.ArgumentParser(description="Test multi-wcServer RPC from one process")
parser.add_argument('--servers', nargs='*', default=DEFAULT_SERVERS,
                    help="server names to probe; default is the local server")
parser.add_argument('--mode', choices=['concurrent', 'sequential', 'subprocess'], default='concurrent')
parser.add_argument('--hold', type=float, default=2.0, help="seconds to hold the connection open (race window)")
parser.add_argument('--makewild', action='store_true', help="also MwLogin+GetConferenceCount (config reconnect test)")
parser.add_argument('--single', default=None, help="internal: probe one server, emit JSON")
args = parser.parse_args()

if args.single:
    print(json.dumps(probe(args.single, 0.0, args.makewild)))
    sys.exit(0)

if args.makewild and args.mode == 'concurrent':
    print("Refusing --makewild with concurrent mode: a Makewild context is 1-connect-per-server;")
    print("concurrent logins would collide and risk leaving a server locked. Use sequential/subprocess.")
    sys.exit(2)

print("wcMultiConnTest.py  servers={}  hold={}s".format(','.join(args.servers), args.hold))

if args.mode == 'concurrent':
    render('concurrent (threads)', run_concurrent(args.servers, args.hold, args.makewild), args.makewild)
elif args.mode == 'sequential':
    render('sequential (threads)', run_sequential(args.servers, args.hold, args.makewild), args.makewild)
else:
    render('subprocess (per server)', run_subprocess(args.servers, args.makewild), args.makewild)
