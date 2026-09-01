#!/usr/bin/env python
# Test-MwLogin.py -- Test MwLogin (clSessionConfig) connectivity
# Usage: py Test-MwLogin.py [--server NAME] [--pwd PASSWORD]
#
# Confirms:
#   - wcsmw.dll loads and registers via WcsrvRegisterDll
#   - MwLogin succeeds (clSessionConfig session)
#   - Reads BBSName and DomainName from TWildcatServerPrivateConfig
#   - Reports named WC error constants on failure

import sys
import ctypes
import argparse

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

parser = argparse.ArgumentParser(description="Test MwLogin (Makewild config session)")
parser.add_argument('--server', default='', help="WC server name (default: local)")
parser.add_argument('--pwd',    default='', help="Makewild password (default: none)")
args = parser.parse_args()

print("Test-MwLogin.py")
print("  Server  : {!r}".format(args.server if args.server else "(local)"))
print("  Password: {}".format("(set)" if args.pwd else "(none)"))
print()

# Connect
print("WildcatServerConnectSpecific({!r}) ...".format(args.server))
if not WildcatServerConnectSpecific(None, args.server):
    err = ctypes.GetLastError()
    print("ERROR: Cannot connect to server {!r}".format(args.server))
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)
print("  Connected.")

print("WildcatServerCreateContext() ...")
if not WildcatServerCreateContext():
    err = ctypes.GetLastError()
    print("ERROR: WildcatServerCreateContext failed")
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)
print("  Context created.")

try:
    print("MwLogin({!r}) ...".format(args.pwd if args.pwd else ""))
    ok = MwLogin(args.pwd)
    if not ok:
        err = ctypes.GetLastError()
        print("ERROR: MwLogin failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        if err == WC_USER_ALREADY_LOGGED_IN:
            print("  Another Makewild client holds the session lock.")
            print("  Close wcConfig.exe (or other Makewild client) and retry.")
        elif err == WC_ALREADY_LOGGED_IN:
            # Server-side: cc->LoggedIn() was true before SetMwLogin().
            # Possible server bug -- should check cc->MwLogged() not cc->LoggedIn().
            print("  This context is already logged in (WC_ALREADY_LOGGED_IN).")
            print("  Possible server-side bug: WcsMwLogin checks LoggedIn() instead")
            print("  of MwLogged() -- may trigger if LoginUser was called first.")
        elif err == WC_INCORRECT_PASSWORD:
            print("  Password is incorrect. Use --pwd to supply the Makewild password.")
        elif err == WC_ACCESS_DENIED:
            print("  Access denied. Possible causes:")
            print("    - config\\nowcconfig.sem semaphore file exists (emergency lockout)")
            print("    - Remote connection and srvWcxMwLogin flag is not set")
            print("      (flag only applies to remote PeerAddress != 0 connections;")
            print("       local connections always bypass this check)")
        sys.exit(1)

    session = WildcatLoggedIn(None)
    print("  MwLogin succeeded.")
    print("  WildcatLoggedIn() = {} ({})".format(
        session,
        {0: "clSessionNone", 1: "clSessionUser",
         2: "clSessionSystem", 3: "clSessionConfig"}.get(session, "unknown")))
    print()

    # Read config
    print("MwGetMakewild() ...")
    mw = TWildcatServerPrivateConfig()
    if not MwGetMakewild(ctypes.byref(mw)):
        err = ctypes.GetLastError()
        print("ERROR: MwGetMakewild failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        sys.exit(1)

    pub = mw.Public
    print("  BBSName          : {}".format(pub.BBSName))
    print("  SysopName        : {}".format(pub.SysopName))
    print("  DefaultDomain    : {}".format(pub.DefaultDomain))
    print("  DomainName       : {}".format(pub.DomainName))
    print("  FileDatabasePath : {}".format(mw.FileDatabasePath))
    print("  UserDatabasePath : {}".format(mw.UserDatabasePath))
    print()
    opts = mw.dwServerOptions
    print("  dwServerOptions  : 0x{:08X}".format(opts))
    print("    srvFingerServer  : {}".format(bool(opts & srvFingerServer)))
    print("    srvWcxMwLogin    : {} (remote-only restriction; local always allowed)".format(
        bool(opts & srvWcxMwLogin)))
    print("    srvWcxIpCheck    : {}".format(bool(opts & srvWcxIpCheck)))
    print("    srvOnlyLocalRPC  : {}".format(bool(opts & srvOnlyLocalRPC)))
    print("    srvEnableGeoIP   : {}".format(bool(opts & srvEnableGeoIP)))
    print()
    print("MwLogin test PASSED.")

finally:
    WildcatServerDeleteContext()
    print("Context deleted.")
