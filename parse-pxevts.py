import struct, sys

# TEventRecType layout (pxtype.pas, {$A-} byte-aligned)
# Offset Size  Field
# 0      4     status (longint)
# 4      1     Active (boolean)
# 5      2     TaskNumber (SmallInt)
# 7      2     Eventnum (word)
# 9      2     AliasNum (Word)
# 11     26    Comment (String[25] = 1 len byte + 25 chars)
# 37     1     EventKind (byte enum: 0=level,1=mailer,2=exec,3=execwait,4=pxcode)
# 38     1     SlideEvent (Boolean)
# 39     1     Critical (Boolean)
# 40     1     ReleasePort (Boolean)
# 41     4     EventFlag1 (longint)
# 45     4     EventFlag2 (longint)
# 49     1     Days (Byte)
# 50     2     StartDate (Word)
# 52     4     StartTime (Longint, seconds since midnight)
# 56     4     StopTime (Longint, seconds since midnight)
# 60     1     WhenKind (byte enum: 0=daily,1=monthly,2=hourly,3=yearly)
# 61     2     StopDate (Word)
# 63     2     TrimKeepDays (SmallInt)
# 65     2     hourInc (Word)
# 67     14    extra2 (14 bytes)
# 81     4     LastRunTime (Longint)
# 85     2     LastRunDate (Word)
# 87     81    ExecFile (String[80] = 1+80)
# 168    2     MinCost (smallint)
# 170    2     MaxCost (smallint)
# 172    4     MinimumBaud (Longint)
# 176    2     BusyTries (word)
# 178    4     RunStartTime (Longint)
# 182    4     RunStopTime (Longint)
# 186    2     TimeoutTries (Word)
# 188    2     ConnectTries (Word)
# 190    2     BadPollLimit (Word)
# 192    46    extra (46 bytes)
# Total: 238 bytes

REC_SIZE = 238

_efRunOnceOnly = 0x00001000
_efScanB4      = 0x00000001
_efAutoToss    = 0x00000002
_efAllowFreq   = 0x00000100

WHEN_KIND = ['daily','monthly','hourly','yearly']
EVENT_KIND = ['level','mailer','exec','execwait','pxcode']

def pascal_str(data, offset, maxlen):
    n = data[offset]
    if n > maxlen:
        n = maxlen
    return data[offset+1:offset+1+n].decode('cp437', errors='replace')

def secs_to_hhmm(s):
    if s < 0 or s > 172800:
        return '??:??'
    h = (s // 3600) % 24
    m = (s % 3600) // 60
    return '%02d:%02d' % (h, m)

def show_flags(ef):
    flags = []
    if ef & _efScanB4:      flags.append('Scan')
    if ef & _efAutoToss:    flags.append('Toss')
    if ef & _efAllowFreq:   flags.append('Freq')
    if ef & _efRunOnceOnly: flags.append('RunOnceOnly')
    return ', '.join(flags) if flags else '(none)'

fn = r'c:\pxwin\system\PXEVTS.DAT'
with open(fn, 'rb') as f:
    data = f.read()

total = len(data) // REC_SIZE
print('PXEVTS.DAT - %d records (%d bytes each)' % (total, REC_SIZE))
print()

for i in range(total):
    rec = data[i*REC_SIZE:(i+1)*REC_SIZE]
    if len(rec) < REC_SIZE:
        break

    active   = rec[4]
    if not active:
        continue

    tasknum  = struct.unpack_from('<h', rec, 5)[0]
    eventnum = struct.unpack_from('<H', rec, 7)[0]
    comment  = pascal_str(rec, 11, 25)
    evtkind  = rec[37]
    flag1    = struct.unpack_from('<l', rec, 41)[0]
    days     = rec[49]
    starttime= struct.unpack_from('<l', rec, 52)[0]
    stoptime = struct.unpack_from('<l', rec, 56)[0]
    whenkind = rec[60]
    hourinc  = struct.unpack_from('<H', rec, 65)[0]
    lastruntime = struct.unpack_from('<l', rec, 81)[0]
    lastrundate = struct.unpack_from('<H', rec, 85)[0]

    wk = WHEN_KIND[whenkind] if whenkind < len(WHEN_KIND) else str(whenkind)
    ek = EVENT_KIND[evtkind] if evtkind < len(EVENT_KIND) else str(evtkind)

    print('Event #%d  Task=%d  "%s"' % (eventnum, tasknum, comment))
    print('  Kind:     %s (%s)' % (wk, ek))
    print('  Days:     0x%02x' % days)
    print('  Start:    %s  Stop: %s' % (secs_to_hhmm(starttime), secs_to_hhmm(stoptime)))
    print('  HourInc:  %d' % hourinc)
    print('  Flag1:    0x%08x  [%s]' % (flag1, show_flags(flag1)))
    print('  RunOnce:  %s' % ('YES' if (flag1 & _efRunOnceOnly) else 'NO'))
    print('  LastRun:  %s  date=0x%04x' % (secs_to_hhmm(lastruntime), lastrundate))
    print()
