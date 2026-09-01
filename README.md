# wcTools - Wildcat! Sysop Tools

Command-line tools for Wildcat! sysops, written in Python on top of the
wcPAPI (wcPython) SDK.  They read your server through the same wcSDK RPC
client the C++ and Delphi tools use, or they read the stock log files.

Nothing here modifies your system.  Every tool ships as plain source you
can read before running it.

    (c) Copyright 1998-2026 Santronics Software, Inc.


## What you need

  * Windows, with a Wildcat! v8 or v10 server you administer
  * Python 3.6 or later (3.11 recommended)
  * The wcPAPI package (included in this zip, under `dist\`)

You do NOT need a compiler, Visual Studio, or admin rights beyond what
installing Python requires.


## Step 1 - install Python

Download from https://www.python.org/downloads/ and run the installer.

**On the first installer screen, tick "Add python.exe to PATH".**
This is the single most common thing to get wrong; without it, typing
`python` in a command prompt will not find it.

Verify from a NEW command prompt:

    python --version

You should see `Python 3.11.2` or similar.

### 32-bit or 64-bit?

Either works.  wcPAPI picks the matching Wildcat! DLL automatically:

  * 64-bit Python loads `wcsrv2x64.dll`
  * 32-bit Python loads `wcsrv2.dll`

What matters is that the MATCHING DLL is findable on your PATH.  Both
normally live in your Wildcat! program folder (often `c:\bin`).  Check
with the built-in `where` command:

    where wcsrv2x64.dll        (if your Python is 64-bit)
    where wcsrv2.dll           (if your Python is 32-bit)

If that prints a path, you are set.  If it says the file could not be
found, add the folder holding that DLL to your PATH.

To see which Python you have:

    python -c "import struct; print(struct.calcsize('P')*8, 'bit')"

A bitness mismatch is the usual cause of "Could not find the DLL file"
even when the DLL plainly exists - Python looks only for the one that
matches itself.


## Step 2 - install wcPAPI

The Python installer includes `pip`, so nothing extra is needed.  From
the `dist\` folder in this zip:

    pip install wcpapi-10.0.500.2-py3-none-any.whl

If `pip` is not recognized, use the equivalent form, which always works
when `python` itself is on your PATH:

    python -m pip install wcpapi-10.0.500.2-py3-none-any.whl

or from source:

    pip install wcpapi-10.0.500.2.tar.gz

Verify:

    python -c "import wcpapi; print('wcPAPI ok')"

Source and updates: https://github.com/WinserverSupport/wcPython


## Step 3 - unpack wcTools

Unzip to `c:\local\wcTools` (any folder works; this is the convention
used throughout the docs and examples).

Verify against your server:

    python c:\local\wcTools\list-confs.py

That lists your conferences.  If it prints them, everything is wired up.


## Connecting to a server

Most tools take `--server <computer>`:

    python wcat-listmail.py 0                    (this computer)
    python wcat-listmail.py 0 --server NTBBS     (a remote wcServer)

Omitting `--server` uses the local server.  Remote access uses the same
RPC path as any other wcSDK client, so normal Wildcat! security applies.

The log-reading tools are different: they read files, not the server, and
default to the CURRENT DIRECTORY.  Run them from the wcServer folder
(`d:\wc5`, `c:\wcat`, ...) or pass `--logs <dir>`.


## The tools

Every tool supports `-h` (or `/?`) for full options.

### Mail

    wcat-listmail.py      list message headers in a conference, with
                          --find to=/from=/subject=/header= filtering
                          (wildcards, ! to negate)
    wcat-trace.py         follow one SMTP payload end to end across the
                          wcSMTP receiver, router, wcMail and sender logs
    wcat-cleanspam-audit.py
                          audit smtpfilter-cleanspam accept/reject
                          decisions and check for false rejects.
                          Needs the smtpfilter-cleanspam hook (wcAVS);
                          with no cleanspam logs it simply reports that
                          it found none.
    wcat-spool2smtp.py    turn spool files into wcSmtpUser test scripts
                          so a real message can be replayed
    wcat-spool-args.py    build wcrun nvpair arguments from spool files
    wcat-msgtext-probe.py probe the wc:\CONF(n)\MESSAGE(id) name forms
    wcPostMsg.py          post a message
    wcSmtpLogSummary.py   summarize wcSMTP activity
    test-smtp-sasl.py     test SMTP AUTH / SASL methods

### Files and conferences

    wcat-ListFiles.py     list the file database
    wcListArea.py         file and mail areas, and file GROUPS with
                          their area membership (tree or CSV)
    list-confs.py         list conferences
    run-list-confs.py     batch wrapper for list-confs

### Users and security

    Show-User-Access.py   resolve what a user can actually access
    Test-MwLogin.py       test a Makewild config session

### Network and IP

    wcipaccess.py         manage IP access entries
    merge-iptrack-ipaccess.py
                          merge IP tracking data into IP access
    do-ipaccess-merge.cmd batch driver for the merge
    wcGeoIP.py            wcGeoIP helper

### Other

    parse-pxevts.py       parse PX/WIN event logs


## Notes

**Output is CP437.**  Wildcat! stores 8-bit text as the BBS recorded it.
The tools emit CP437 so redirected output round-trips exactly and reads
correctly in an OEM editor such as Qedit.  Viewing a redirected file in a
Windows editor may show line-draw characters oddly; that is the viewer,
not the data.

**Redirect freely.**

    python wcat-listmail.py 0 --server NTBBS > conf0.txt

**Read before you run.**  These are sysop tools operating on live data.
The source is plain Python, deliberately commented; skim anything you are
unsure about first.


## Support

Post in the Wildcat! support conferences on winserver.com, or see
https://github.com/WinserverSupport
