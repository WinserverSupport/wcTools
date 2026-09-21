#!/usr/bin/env python
# Show-User-Access.py -- Show Wildcat! user/area security access
# Usage: py Show-User-Access.py [--server NAME] [--pwd PASSWORD]
#         --class file|mail|rights|code|domain|user
#        [--user NAME]   show access for a specific user
#        [--area NAME]   show access for a specific area/object name
#        [--sec  NAME]   show access for a specific security group
#
# --class user  shows all classes (file, mail, rights, code, domain) for --user
#
# Session: MwLogin (clSessionConfig)
# Note: Close wcConfig.exe before running (only one Makewild client at a time).
# 500.2  2026-03-13
# 500.3  2026-09-17 - changed WcCloseHandle(ff) to MwFindClose(ff)

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

# ---------------------------------------------------------------------------
# Object class table
# ---------------------------------------------------------------------------

CLASSES = {
    'file'   : OBJECTCLASS_FILEAREA,
    'mail'   : OBJECTCLASS_CONFERENCE,
    'rights' : OBJECTCLASS_RIGHTS,
    'code'   : OBJECTCLASS_CODE,
    'domain' : OBJECTCLASS_DOMAINS,
}

# For --class user, show all of these in order
USER_CLASSES = ['rights', 'domain', 'mail', 'file', 'code']

# ---------------------------------------------------------------------------
# Access flag decoder
# ---------------------------------------------------------------------------

def make_flags_str(dwClass, flags):
    """Return 4-char access string (e.g. JRWS, LUDS, or hex for others)."""
    if dwClass == OBJECTCLASS_CONFERENCE:
        return (('J' if flags & OBJECTFLAGS_CONFERENCE_JOIN  else '-') +
                ('R' if flags & OBJECTFLAGS_CONFERENCE_READ  else '-') +
                ('W' if flags & OBJECTFLAGS_CONFERENCE_WRITE else '-') +
                ('S' if flags & OBJECTFLAGS_CONFERENCE_SYSOP else '-'))
    if dwClass == OBJECTCLASS_FILEAREA:
        return (('L' if flags & OBJECTFLAGS_FILEAREA_LIST     else '-') +
                ('D' if flags & OBJECTFLAGS_FILEAREA_DOWNLOAD else '-') +
                ('U' if flags & OBJECTFLAGS_FILEAREA_UPLOAD   else '-') +
                ('S' if flags & OBJECTFLAGS_FILEAREA_SYSOP    else '-'))
    return '{:08X}'.format(flags)

# ---------------------------------------------------------------------------
# Globals populated by init_maps()
# ---------------------------------------------------------------------------

group_names   = []          # list of str, indexed by group position
map_users     = {}          # user_name(str) -> [sec_name, ...]
map_user_secs = {}          # sec_name(str)  -> [user_name, ...]

def init_maps():
    """Load all users + security groups into memory maps."""
    global group_names

    # --- Walk all users -------------------------------------------------------
    u   = TUser()
    tid = DWORD(0)
    if GetFirstUser(UserIdKey, ctypes.byref(u), ctypes.byref(tid)):
        while True:
            uname = u.Info.Name
            if uname:
                secs = []
                for i in range(NUM_USER_SECURITY):
                    s = u.Security[i].Item
                    if s:
                        secs.append(s)
                map_users[uname] = secs
            if not GetNextUser(UserIdKey, ctypes.byref(u), ctypes.byref(tid)):
                break

    # --- Load security group names --------------------------------------------
    gc  = MwGetGroupCount()
    arr = (TSecurityName * gc)()
    MwGetGroupNames(arr)
    group_names = [arr[i].Name for i in range(gc)]

    # --- Build inverse map: sec -> [users] ------------------------------------
    for gname in group_names:
        map_user_secs[gname] = []
    for uname, secs in map_users.items():
        for s in secs:
            key = s.upper()
            for gname in group_names:
                if gname.upper() == key:
                    map_user_secs[gname].append(uname)
                    break

# ---------------------------------------------------------------------------
# Shared flags array (allocated once after init_maps)
# ---------------------------------------------------------------------------

group_flags = None   # (DWORD * len(group_names))()

def alloc_flags():
    global group_flags
    group_flags = (DWORD * len(group_names))()

def get_object_flags(oid):
    """Fill group_flags with flags for this objectid across all groups."""
    ctypes.memset(group_flags, 0, ctypes.sizeof(group_flags))
    return MwGetObjectFlagsInGroups(oid, group_flags)

# ---------------------------------------------------------------------------
# View 1: By area -- for each object show which groups/users have access
# ---------------------------------------------------------------------------

def show_area_security(dwClass, szObjectName=''):
    """For each object (filtered by name), show access groups and their users."""
    ob  = TObjectName()
    tid = DWORD(0)
    if not GetObjectByName(dwClass, szObjectName, ctypes.byref(ob), ctypes.byref(tid)):
        print("  (no objects found)")
        return

    while True:
        name = ob.Name if ob.Name else ''
        print("  area: {:5d}  {}".format(ob.Number, name))

        if not get_object_flags(ob.ObjectId):
            print("    ERROR: MwGetObjectFlagsInGroups failed ({:08X})".format(
                ctypes.GetLastError()))
        else:
            for i, gname in enumerate(group_names):
                f = group_flags[i]
                if f:
                    fstr = make_flags_str(dwClass, f)
                    users_in_group = map_user_secs.get(gname, [])
                    print("    {} | sec: {}  ({} user(s))".format(
                        fstr, gname, len(users_in_group)))
                    for uname in users_in_group:
                        print("           user: {}".format(uname))

        if szObjectName or not GetNextObjectByName(ctypes.byref(ob), ctypes.byref(tid)):
            break
    print()

# ---------------------------------------------------------------------------
# View 2: By security group -- list accessible objects for a group
# ---------------------------------------------------------------------------

def list_areas_by_security(dwClass, szSecName):
    """List all objects accessible to a specific security group."""
    gi = next((i for i, n in enumerate(group_names)
               if n.upper() == szSecName.upper()), None)
    if gi is None:
        print("  (security group not found: {})".format(szSecName))
        return

    ob  = TObjectName()
    tid = DWORD(0)
    if not GetObjectByName(dwClass, '', ctypes.byref(ob), ctypes.byref(tid)):
        print("  (no objects found)")
        return

    found = 0
    while True:
        if not get_object_flags(ob.ObjectId):
            if not GetNextObjectByName(ctypes.byref(ob), ctypes.byref(tid)):
                break
            continue
        f = group_flags[gi]
        if f:
            name = ob.Name if ob.Name else ''
            fstr = make_flags_str(dwClass, f)
            print("  {} | area: {:5d}  {}".format(fstr, ob.Number, name))
            found += 1
        if not GetNextObjectByName(ctypes.byref(ob), ctypes.byref(tid)):
            break

    if not found:
        print("  (no access)")
    print()

# ---------------------------------------------------------------------------
# User header -- primary security + additional access profiles
# ---------------------------------------------------------------------------

def show_user_header(szUserName):
    """Print user's primary security profile and additional access profiles."""
    uname_key = next((k for k in map_users if k.upper() == szUserName.upper()), None)
    if uname_key is None:
        print("User not found: {}".format(szUserName))
        return
    secs = map_users[uname_key]
    primary    = secs[0] if len(secs) > 0 else '(none)'
    additional = secs[1:] if len(secs) > 1 else []
    print("--- USER: {} ---".format(uname_key))
    print()
    print("  Primary security profile : {}".format(primary))
    if additional:
        print("  Additional access profiles:")
        for s in additional:
            print("    + {}".format(s))
    else:
        print("  Additional access profiles: (none)")
    print()

# ---------------------------------------------------------------------------
# View 3: By user -- show a user's groups, then their accessible objects
# ---------------------------------------------------------------------------

def show_user_security(dwClass, szUserName):
    """For a user, list security group memberships then accessible objects."""
    uname_key = next((k for k in map_users if k.upper() == szUserName.upper()), None)
    if uname_key is None:
        print("  (user not found: {})".format(szUserName))
        return

    secs = map_users[uname_key]
    if not secs:
        print("  (no security groups assigned)")
        return

    for sec in secs:
        print("  sec: {}".format(sec))
        if dwClass in (OBJECTCLASS_FILEAREA, OBJECTCLASS_CONFERENCE):
            list_areas_by_security(dwClass, sec)
        elif dwClass == OBJECTCLASS_RIGHTS:
            list_rights_by_security(sec)
        elif dwClass == OBJECTCLASS_DOMAINS:
            list_domains_by_security(sec)
        elif dwClass == OBJECTCLASS_CODE:
            list_code_by_security(sec)

# ---------------------------------------------------------------------------
# View 4: Rights -- show RIGHTS objectids enabled for a security group
# ---------------------------------------------------------------------------

# Named RIGHTS object IDs (from wctype_constants_h)
RIGHTS_OBJECTS = [
    (OBJECTID_BULLETINS_OPTIONAL,          'BulletinsOptional'),
    (OBJECTID_CHANGE_PHONE,                'ChangePhone'),
    (OBJECTID_CHANGE_BIRTHDATE,            'ChangeBirthdate'),
    (OBJECTID_QWK_ALLOW_BULLETINS,         'QwkAllowBulletins'),
    (OBJECTID_QWK_ALLOW_NEWS,              'QwkAllowNews'),
    (OBJECTID_QWK_ALLOW_FILES,             'QwkAllowFiles'),
    (OBJECTID_QWK_DETAIL_DOWNLOAD,         'QwkDetailDownload'),
    (OBJECTID_QWK_CHECK_DUPES,             'QwkCheckDupes'),
    (OBJECTID_QWK_SAVE_PACKETS,            'QwkSavePackets'),
    (OBJECTID_MASTER_SYSOP,                'MasterSysop'),
    (OBJECTID_RATIO_ACTION,                'RatioAction'),
    (OBJECTID_ALLOW_FAST_LOGIN,            'AllowFastLogin'),
    (OBJECTID_ALLOW_OVERWRITE_FILES,       'AllowOverwriteFiles'),
    (OBJECTID_SHOW_PASSWORD_FILES,         'ShowPasswordFiles'),
    (OBJECTID_ALLOW_OFFLINE_FILE_REQUESTS, 'AllowOfflineFileRequests'),
    (OBJECTID_ALLOW_UPLOAD_OVER_TIME,      'AllowUploadOverTime'),
    (OBJECTID_ALLOW_DOWNLOAD_OVER_TIME,    'AllowDownloadOverTime'),
    (OBJECTID_ALLOW_UPLOADER_MODIFY_FILE,  'AllowUploaderModifyFile'),
    (OBJECTID_QWK_NETSTATUS,               'QwkNetStatus'),
    (OBJECTID_SYSOP_READ_PRIVATE_MAIL,     'SysopReadPrivateMail'),
    (OBJECTID_ALLOW_INTERNET_EMAIL,        'AllowInternetEmail'),
    (OBJECTID_ALLOW_ANY_TELNET,            'AllowAnyTelnet'),
    (OBJECTID_ALLOW_ANY_FTP,               'AllowAnyFtp'),
    (OBJECTID_ALLOW_HTTP_PROXY,            'AllowHttpProxy'),
    (OBJECTID_ALLOW_ALL_IP,                'AllowAllIp'),
    (OBJECTID_ALLOW_DEFAULT_IP,            'AllowDefaultIp'),
    (OBJECTID_ALLOW_PPP,                   'AllowPpp'),
    (OBJECTID_IGNORE_TIME_ONLINE,          'IgnoreTimeOnline'),
    (OBJECTID_IGNORE_IDLE_TIME,            'IgnoreIdleTime'),
    (OBJECTID_ALLOW_SMTP_AUTH,             'AllowSmtpAuth'),
    (OBJECTID_ALLOW_NNTP_ACCESS,           'AllowNntpAccess'),
    (OBJECTID_USERBIN_ACCESS,              'UserbinAccess'),
    (OBJECTID_ALLOW_FTP_ACCESS,            'AllowFtpAccess'),
    (OBJECTID_ALLOW_WEB_ACCESS,            'AllowWebAccess'),
    (OBJECTID_ALLOW_TELNET_ACCESS,         'AllowTelnetAccess'),
    (OBJECTID_CHANGE_EMAILADDRESS,         'ChangeEmailAddress'),
    (OBJECTID_CHANGE_SMTPFORWARD,          'ChangeSmtpForward'),
    (OBJECTID_ALLOW_CC_GROUPS,             'AllowCcGroups'),
]

def list_rights_by_security(szSecName):
    gi = next((i for i, n in enumerate(group_names)
               if n.upper() == szSecName.upper()), None)
    if gi is None:
        return

    found = 0
    for oid, name in RIGHTS_OBJECTS:
        if MwGetObjectFlags(gi, oid):
            print("  [X] {}".format(name))
            found += 1
    if not found:
        print("  (no rights)")
    print()

# ---------------------------------------------------------------------------
# View 5: Domains
# ---------------------------------------------------------------------------

def list_domains_by_security(szSecName):
    gi = next((i for i, n in enumerate(group_names)
               if n.upper() == szSecName.upper()), None)
    if gi is None:
        return

    count = WcGetDomainCount()
    found = 0
    buf   = ctypes.create_string_buffer(128)
    for i in range(count):
        if WcGetDomain(i, buf, ctypes.sizeof(buf)):
            domain = buf.value.decode('cp437', errors='replace')
            oid    = GetStringObjectId(OBJECTCLASS_DOMAINS, domain)
            ctypes.memset(group_flags, 0, ctypes.sizeof(group_flags))
            MwGetObjectFlagsInGroups(oid, group_flags)
            if group_flags[gi]:
                print("  [X] domain: {}".format(domain))
                found += 1
    if not found:
        print("  (no domains)")
    print()

# ---------------------------------------------------------------------------
# View 6: Code (wcx scripts)
# ---------------------------------------------------------------------------

def list_code_by_security(szSecName):
    gi = next((i for i, n in enumerate(group_names)
               if n.upper() == szSecName.upper()), None)
    if gi is None:
        return

    # Enumerate wc:\code\*.wcx using MwFindFirstFile (WIN32_FIND_DATA, not DATAA)
    INVALID_HANDLE = ctypes.c_void_p(-1).value
    fd  = WIN32_FIND_DATA()
    ff  = MwFindFirstFile('wc:\\code\\*.wcx', ctypes.byref(fd))
    if ff is None or ctypes.cast(ff, ctypes.c_void_p).value == INVALID_HANDLE:
        print("  (no wcx files found)")
        return

    names_oids = []
    while True:
        fname = fd.cFileName
        oid   = GetStringObjectId(OBJECTCLASS_CODE, fname)
        # strip .wcx extension for display
        display = fname[:-4] if fname.lower().endswith('.wcx') else fname
        names_oids.append((display, oid))
        if not MwFindNextFile(ff, ctypes.byref(fd)):
            break
    #WcCloseHandle(ff)
    MwFindClose(ff)    # 500.3 fixes wcserver abort - does not work

    if not names_oids:
        print("  (no wcx files)")
        print()
        return

    found = 0
    for display, oid in names_oids:
        if MwGetObjectFlags(gi, oid):
            print("  [X] {}".format(display))
            found += 1
    if not found:
        print("  (no code access)")
    print()

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

if '/?' in sys.argv:
    sys.argv[sys.argv.index('/?')] = '--help'

parser = argparse.ArgumentParser(description="Show Wildcat! user/area security access")
parser.add_argument('--server',  default='',   help="WC server name (default: local)")
parser.add_argument('--pwd',     default='',   help="Makewild password (default: none)")
parser.add_argument('--class',   dest='oclass', required=True,
                    choices=['file','mail','rights','code','domain','user'],
                    help="Object class to query (user = all classes)")
parser.add_argument('--user',    default='',   help="Filter: specific user name")
parser.add_argument('--area',    default='',   help="Filter: specific area/object name")
parser.add_argument('--sec',     default='',   help="Filter: specific security group name")
args = parser.parse_args()

# Validate: --class user requires --user
if args.oclass == 'user' and not args.user:
    parser.error("--class user requires --user NAME")

# Validate: --area and --sec only make sense with area-based classes
if args.area and args.oclass in ('rights', 'code', 'user'):
    parser.error("--area is not applicable for --class {}".format(args.oclass))

# ---------------------------------------------------------------------------
# Connect and login
# ---------------------------------------------------------------------------

if not WildcatServerConnectSpecific(None, args.server):
    err = ctypes.GetLastError()
    print("ERROR: Cannot connect to server {!r}".format(args.server))
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)

buf = ctypes.create_string_buffer(MAX_PATH)
GetConnectedServer(buf, MAX_PATH)
connected_server = buf.value.decode('cp437', errors='replace')

print("Show-User-Access.py")
print("  Server  : {}".format(connected_server))
print("  Password: {}".format("(set)" if args.pwd else "(none)"))
print("  Class   : {}".format(args.oclass))
if args.user: print("  User    : {}".format(args.user))
if args.area: print("  Area    : {}".format(args.area))
if args.sec:  print("  Sec     : {}".format(args.sec))
print()

if not WildcatServerCreateContext():
    err = ctypes.GetLastError()
    print("ERROR: WildcatServerCreateContext failed")
    print("  {}".format(GetWildcatErrorStr(err)))
    sys.exit(1)

try:
    if not MwLogin(args.pwd):
        err = ctypes.GetLastError()
        print("ERROR: MwLogin failed")
        print("  {}".format(GetWildcatErrorStr(err)))
        if err == WC_USER_ALREADY_LOGGED_IN:
            print("  Another Makewild client holds the session lock.")
            print("  Close wcConfig.exe (or other Makewild client) and retry.")
        elif err == WC_INCORRECT_PASSWORD:
            print("  Password is incorrect. Use --pwd to supply the Makewild password.")
        elif err == WC_ACCESS_DENIED:
            print("  Access denied. Check config\\nowcconfig.sem or srvWcxMwLogin flag.")
        sys.exit(1)

    init_maps()
    alloc_flags()

    print("  Users         : {}".format(len(map_users)))
    print("  Security groups: {}".format(len(group_names)))
    print()

    # Show user profile header once before class breakdown
    if args.user:
        show_user_header(args.user)

    # Determine which class(es) to process
    if args.oclass == 'user':
        class_list = USER_CLASSES
    else:
        class_list = [args.oclass]

    for cls in class_list:
        dwClass = CLASSES[cls]
        print("--- {} ---".format(cls.upper()))
        print()

        if args.user:
            # Show what this user can access in this class
            show_user_security(dwClass, args.user)
        elif args.sec:
            # Show what this security group can access in this class
            if cls in ('rights',):
                list_rights_by_security(args.sec)
            elif cls == 'code':
                list_code_by_security(args.sec)
            elif cls == 'domain':
                list_domains_by_security(args.sec)
            else:
                list_areas_by_security(dwClass, args.sec)
        else:
            # Show all objects with their group/user breakdown
            show_area_security(dwClass, args.area)

finally:
    WildcatServerDeleteContext()
