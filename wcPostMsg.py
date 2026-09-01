#!/usr/bin/env python
# wcPostMsg.py  --  Wildcat! Post Message CLI
# Post a message to a Wildcat! conference (or personal mail) from the command line.
#
# Usage:
#   python wcPostMsg.py --to <name> --subj <subject> --cnum <n> [options]
#
# Options:
#   --to <name>        Recipient name or email address (required)
#   --from <name>      Sender name or email address (default: mailer-daemon)
#   --subj <text>      Message subject (required)
#   --body <text|file> Message body: inline text or path to a text file
#   --cnum <n>         Conference/area number (required)
#   --server <name>    WC server hostname (default: auto-discover via WildcatServer env or UDP port 4012)
#   --pvt              Mark message as private (default: public)
#   --nodupe           Disable duplicate checking
#   --mime             Mark message as MIME-saved
#   --file <path>      Attachment file path
#   --fidoto <addr>    FidoNet destination address z:n/n[.p] (netmail confs)
#   --fidofrom <addr>  FidoNet origin address z:n/n[.p]
#   --fidoflags <n>    FidoFlags (hex 0x.. or decimal). Default when --fidoto
#                      is given: 0x0402 = Immediate|Crash (no KillMsg)
#   --dry-run          Show what would be posted without posting
#
# FidoFlags bits (pxtype.pas _obXxx):
#   0x0001 Hold  0x0002 Immed  0x0004 Direct  0x0010 KillMsg
#   0x0020 KillFile  0x0080 FileReq  0x0100 FileAtt  0x0400 Crash
#
# Examples:
#   wcPostMsg.py --to "All" --from "Sysop" --subj "Hello" --body "Hello world" --cnum 137
#   wcPostMsg.py --to "All" --subj "Announce" --body c:\temp\announce.txt --cnum 137
#   wcPostMsg.py --server main4 --to "All" --subj "Hello" --body "text" --cnum 137
#   wcPostMsg.py --server main4 --cnum 2 --to "Robert Wolfe" --from "Hector Santos"
#       --subj "PX setup" --body note.txt --fidofrom 99:1/999 --fidoto 99:1/6
#
# Revision History:
# 500.2  03/10/26  Initial version, modeled on wcpostmsg.wcc
# 500.2  07/06/26  FidoNet netmail support: --fidoto/--fidofrom/--fidoflags
#                  (TMsgHeader.FidoTo/FidoFrom/FidoFlags, post-fidonetmail.py
#                  pattern; mtFidoNetmail confs: NTBBS conf 3, MAIN4 conf 2).
#                  mtFidoNetmail conferences REQUIRE --fidoto/--fidofrom
#                  (GetConfDesc MailType check after login).

import ctypes
import sys
import os
import argparse

import wcpapi
from wcpapi.wcserver_h import *
from wcpapi.wcserror_h import *
from wcpapi.wctype_h   import *
from wcpapi.wctype_constants_h import *

PRODUCT_VERSION = "1.1"

# FidoFlags defaults for netmail (pxtype.pas _obXxx)          # 500.2 07/06/26
obImmed = 0x0002
obCrash = 0x0400

# Conference MailType (wctype.pas)                            # 500.2 07/06/26
mtFidoNetmail = 3

# ---------------------------------------------------------------------------
# parse_fido_addr -- 'z:n/n' or 'z:n/n.p' -> (zone, net, node, point)
# ---------------------------------------------------------------------------

def parse_fido_addr(s):                                       # 500.2 07/06/26
    """Parse a 3D/4D FTN address string. Domain (@xxx) is ignored."""
    a = s.split('@')[0].strip()
    try:
        zone, rest = a.split(':', 1)
        net, rest  = rest.split('/', 1)
        if '.' in rest:
            node, point = rest.split('.', 1)
        else:
            node, point = rest, '0'
        return (int(zone), int(net), int(node), int(point))
    except (ValueError, IndexError):
        print("ERROR: Bad FidoNet address '{}' (expected z:n/n or z:n/n.p)".format(s))
        sys.exit(1)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog='wcPostMsg.py',
        description='Post a message to a Wildcat! conference or mailbox.')
    parser.add_argument('--to',     required=True,  help='Recipient name or email')
    parser.add_argument('--from',   dest='frm',
                        default='mailer-daemon',     help='Sender name or email (default: mailer-daemon)')
    parser.add_argument('--subj',   required=True,  help='Message subject')
    parser.add_argument('--body',   default='',     help='Body text or path to a text file')
    parser.add_argument('--cnum',   type=int, required=True,
                                                    help='Conference/area number')
    parser.add_argument('--server', default='',
                                                    help='WC server hostname (default: auto-discover via env WildcatServer or UDP broadcast)')
    parser.add_argument('--pvt',    action='store_true',
                                                    help='Mark message as private')
    parser.add_argument('--nodupe', action='store_true',
                                                    help='Disable dupe checking')
    parser.add_argument('--mime',   action='store_true',
                                                    help='Mark as MIME-saved')
    parser.add_argument('--file',   default='',     help='Attachment file path')
    parser.add_argument('--fidoto',   default='',   help='FidoNet destination z:n/n[.p]')     # 500.2 07/06/26
    parser.add_argument('--fidofrom', default='',   help='FidoNet origin z:n/n[.p]')           # 500.2 07/06/26
    parser.add_argument('--fidoflags', default='',  help='FidoFlags hex 0x.. or decimal (default 0x0402 Immed|Crash when --fidoto given)')  # 500.2 07/06/26
    parser.add_argument('--dry-run', action='store_true',
                                                    help='Show what would be posted, do not post')
    args = parser.parse_args()

    # -- Resolve fidonet fields ---------------------------------------------  # 500.2 07/06/26
    fido_to   = parse_fido_addr(args.fidoto)   if args.fidoto   else None
    fido_from = parse_fido_addr(args.fidofrom) if args.fidofrom else None
    fido_flags = 0
    if args.fidoflags:
        fido_flags = int(args.fidoflags, 16) if args.fidoflags.lower().startswith('0x') \
                     else int(args.fidoflags)
    elif fido_to:
        fido_flags = obImmed | obCrash    # standard outgoing netmail: no KillMsg

    # -- Resolve body text --------------------------------------------------
    body_text = args.body
    if body_text and os.path.isfile(body_text):
        try:
            with open(body_text, 'r', errors='replace') as f:
                body_text = f.read()
        except IOError as e:
            print("ERROR: Cannot read body file: {}".format(e))
            sys.exit(1)
    else:
        # Allow \n escape in inline body text
        body_text = body_text.replace('\\n', '\n')

    # -- Resolve attachment -------------------------------------------------
    attachment_name = ''
    if args.file:
        if not os.path.isfile(args.file):
            print("ERROR: Attachment not found: {}".format(args.file))
            sys.exit(1)
        attachment_name = os.path.basename(args.file)

    # -- Dry-run preview ----------------------------------------------------
    if args.dry_run:
        print("wcPostMsg v{} -- DRY RUN".format(PRODUCT_VERSION))
        print("  To      : {}".format(args.to))
        print("  From    : {}".format(args.frm))
        print("  Subject : {}".format(args.subj))
        print("  Conf    : {}".format(args.cnum))
        print("  Server  : {}".format(args.server or '(auto-discover)'))
        print("  Private : {}".format(args.pvt))
        print("  NoDupe  : {}".format(args.nodupe))
        print("  MIME    : {}".format(args.mime))
        if fido_to:                                                            # 500.2 07/06/26
            print("  FidoTo  : {}:{}/{}.{}".format(*fido_to))
            if fido_from:
                print("  FidoFrom: {}:{}/{}.{}".format(*fido_from))
            print("  FidoFlgs: 0x{:04X}".format(fido_flags))
        if attachment_name:
            print("  Attach  : {}".format(attachment_name))
        print("  Body ({} chars):".format(len(body_text)))
        for line in body_text.splitlines():
            print("    " + line)
        return

    # -- Connect to WC server and create context ----------------------------
    if not WildcatServerConnectSpecific(None, args.server):
        print("ERROR: WildcatServerConnectSpecific('{}') failed ({:08X})".format(
            args.server or 'auto', ctypes.GetLastError()))
        sys.exit(1)

    if not WildcatServerCreateContext():
        print("ERROR: WildcatServerCreateContext() failed ({:08X})".format(
            ctypes.GetLastError()))
        sys.exit(1)

    # -- Login as system ----------------------------------------------------
    if not LoginSystem():
        print("ERROR: LoginSystem() failed ({:08X})".format(ctypes.GetLastError()))
        sys.exit(1)

    # -- Conference type check: netmail areas require fido addressing -------  # 500.2 07/06/26
    cd = TConfDesc()
    if GetConfDesc(args.cnum, ctypes.byref(cd)):
        if cd.MailType == mtFidoNetmail and not (fido_to and fido_from):
            print("ERROR: Conference {} is a FidoNet netmail area (mtFidoNetmail) -- "
                  "--fidoto and --fidofrom are required".format(args.cnum))
            sys.exit(1)

    # -- Build TMsgHeader ---------------------------------------------------
    msg = TMsgHeader()

    msg.To.Name    = args.to[:SIZE_USER_NAME - 1]
    msg.From.Name  = args.frm[:SIZE_USER_NAME - 1]
    msg.Subject    = args.subj[:SIZE_MESSAGE_SUBJECT - 1]
    msg.Conference = args.cnum
    msg.Private    = 1 if args.pvt else 0

    if args.nodupe:
        msg.MailFlags = msg.MailFlags | mfNoDupeChecking
    if args.mime:
        msg.MailFlags = msg.MailFlags | mfMimeSaved

    if attachment_name:
        msg.Attachment = attachment_name[:SIZE_ATTACH_FILE_NAME - 1]

    # -- FidoNet netmail fields (mtFidoNetmail conferences) ------------------  # 500.2 07/06/26
    if fido_to:
        msg.FidoTo.Zone,  msg.FidoTo.Net,  msg.FidoTo.Node,  msg.FidoTo.Point  = fido_to
    if fido_from:
        msg.FidoFrom.Zone, msg.FidoFrom.Net, msg.FidoFrom.Node, msg.FidoFrom.Point = fido_from
    if fido_flags:
        msg.FidoFlags = fido_flags

    # -- Resolve To/From names to populate Id fields -----------------------
    # Email confs (cnum=0): Id required for routing; conf posts (e.g. "All"): Id=0 is fine
    ui = TUserInfo()
    if LookupName(args.to, ctypes.byref(ui)):
        msg.To = ui
    if LookupName(args.frm, ctypes.byref(ui)):
        msg.From = ui

    # -- Copy attachment to wc:\temp\ if present ---------------------------
    if args.file and attachment_name:
        wc_attach = "wc:\\temp\\" + attachment_name
        try:
            with open(args.file, 'rb') as fin:
                data = fin.read()
            h = WcCreateFile(wc_attach,
                             0x40000000,  # GENERIC_WRITE
                             0,
                             2)           # CREATE_ALWAYS
            if h == ctypes.wintypes.HANDLE(-1).value:
                print("ERROR: Cannot create wc:\\temp\\{} ({:08X})".format(
                    attachment_name, ctypes.GetLastError()))
                sys.exit(1)
            written = ctypes.wintypes.DWORD(0)
            WcWriteFile(h, data, len(data), ctypes.byref(written), None)
            WcCloseHandle(h)
        except Exception as e:
            print("ERROR: Attachment copy failed: {}".format(e))
            sys.exit(1)

    # -- Post message -------------------------------------------------------
    ok = AddMessage(ctypes.byref(msg), body_text)
    if not ok:
        print("ERROR: AddMessage() failed ({:08X})".format(ctypes.GetLastError()))
        sys.exit(1)

    print("+ Message #{} (Id={}) posted to area #{} -- {}".format(
        msg.Number, msg.Id, msg.Conference, args.subj))

    WildcatServerDeleteContext()


if __name__ == '__main__':
    main()
