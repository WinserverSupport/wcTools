@echo off
REM do-ipaccess-merge.cmd  500.2 26.9.1
REM
REM Merge iptrack\*.blk and smtpcmd\learn\* abuse sources into the
REM config\ipaccess-{proto}.dat mini-firewall files using wcipaccess.py.
REM Run from the Wildcat! working directory (wc:\).
REM
REM Interactive:  do-ipaccess-merge [report options]
REM               shows the offender report first, wait32 gate to continue.
REM               Extra options pass to report only (e.g. --since 20260601).
REM
REM Unattended:   do-ipaccess-merge /auto
REM               skips the report and wait32 gate (wcTaskMgr event use).


REM 26.9.1 - locate wcTools
REM
REM Defaults to the folder this .cmd was started from (%~dp0), so a
REM normal install -- wcTools unpacked together in one folder -- needs
REM no configuration.
REM
REM To keep the scripts elsewhere, such as a share serving several
REM servers, set WCTOOLSPATH before calling:
REM
REM     set WCTOOLSPATH=\\myserver\wctools
REM     set WCTOOLSPATH=d:\local\wctools
    setlocal
    set wctoolspath=%WCTOOLSPATH%
    if "%wctoolspath%" == "" set wctoolspath=%~dp0
REM strip any trailing backslash so the paths below build cleanly
    if "%wctoolspath:~-1%" == "\" set wctoolspath=%wctoolspath:~0,-1%
    if not exist "%wctoolspath%\wcipaccess.py" (
       echo NOT FOUND: %wctoolspath%\wcipaccess.py
       echo.
       echo Run this from the folder holding wcipaccess.py, or set
       echo WCTOOLSPATH to the folder where wcTools is installed.
       goto :eof
    )
REM

    if /I "%1"=="/auto" goto :merge

    py "%wctoolspath%\wcipaccess.py" report --logdir . %*

    echo.
    echo ** ANALYZE THE REPORT. HIT ESC TO EXIT or ENTER TO BEGIN THE MERGE PROCESS
    echo.
    wait32 30
    if errorlevel 1 goto :eof

:merge
REM 26.9.1 - clear any stale *-new.dat BEFORE merging.
REM
REM :doit promotes whatever ipaccess-{proto}-new.dat it finds.  It
REM cannot tell a file this run produced from one an earlier, aborted
REM run left behind, so a leftover would be copied over the live
REM firewall file -- silently replacing a current block list with an
REM older, usually smaller one.  Deleting first means :doit can only
REM ever see output from this run.
    for %%p in (http smtp pop3 ftp telnet finger nntp) do (
       if exist config\ipaccess-%%p-new.dat (
          echo Removing stale config\ipaccess-%%p-new.dat from an earlier run
          del /q config\ipaccess-%%p-new.dat
       )
    )

    py "%wctoolspath%\wcipaccess.py" merge --ipaccess config\ --iptrack iptrack\ --learn smtpcmd\learn --delete
    if errorlevel 1 goto :eof

    call :doit http
    call :doit smtp
    call :doit pop3
    call :doit ftp
    call :doit telnet
    call :doit finger
    call :doit nntp
    goto :eof


:doit
    if not exist config\ipaccess-%1-new.dat goto :eof
    if exist config\ipaccess-%1.dat bcopy config\ipaccess-%1.dat
    copy config\ipaccess-%1-new.dat config\ipaccess-%1.dat /Y
    del config\ipaccess-%1-new.dat
    goto :eof
