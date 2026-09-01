## File : test-smtp-sasl.py
## // 500.2 26.8.4
## About:
##
## Manual SMTP AUTH mechanism tester -- speaks PLAIN, LOGIN, CRAM-MD5, and
## DIGEST-MD5 (RFC 2831) directly over a raw socket, independent of any
## mail client library (Python smtplib, .NET MailKit/win-acme, etc).
##
## Purpose: isolate whether an AUTH failure is caused by wcSMTP's SASL
## module (saslDIGESTMD5.dll etc, loaded from c:\local\wc10\wcSASL) or by
## a quirk in a specific client's mechanism implementation. If this script
## succeeds where another client fails using the same mechanism/creds
## against the same server, the bug is client-side; if this script also
## fails, the bug (or a genuine incompatibility) is server-side.
##
## Usage:
##   python test-smtp-sasl.py --host NTBBS --user agent --password secret
##       [--mech digest-md5|cram-md5|plain|login]   (default: digest-md5)
##       [--port 25] [--starttls] [--realm ""] [--digest-uri smtp/<host>]
##       [--verbose]
##
## Example:
##   python test-smtp-sasl.py --host ntbbs.example.com --user jdoe ^
##       --password "hunter2" --mech digest-md5 --verbose
##
## Prints the full C:/S: protocol exchange (passwords/hashes not printed
## in cleartext -- only the base64 wire bytes) so a challenge/response
## can be compared byte-for-byte against a wcSMTPTrace session log.

import argparse
import base64
import hashlib
import hmac
import re
import socket
import ssl
import sys
import uuid


def log(direction, text):
    print("%s: %s" % (direction, text))


class SmtpSession(object):
    def __init__(self, host, port, use_starttls, timeout, verbose):
        self.verbose = verbose
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.rfile = self.sock.makefile('rb')
        self.host = host
        greeting = self._read_multiline()
        if use_starttls:
            self._cmd("EHLO %s" % socket.gethostname())
            self._cmd_expect("STARTTLS", '220')
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)
            self.rfile = self.sock.makefile('rb')
        self._cmd("EHLO %s" % socket.gethostname())

    def _read_line(self):
        raw = self.rfile.readline()
        if not raw:
            raise IOError("connection closed by server")
        line = raw.decode('utf-8', 'replace').rstrip('\r\n')
        log("S", line)
        return line

    def _read_multiline(self):
        lines = [self._read_line()]
        while len(lines[-1]) >= 4 and lines[-1][3:4] == '-':
            lines.append(self._read_line())
        return lines

    def send_raw(self, text, mask=False):
        log("C", ("*" * len(text)) if mask else text)
        self.sock.sendall((text + "\r\n").encode('utf-8'))

    def _cmd(self, text, mask=False):
        self.send_raw(text, mask)
        return self._read_multiline()

    def _cmd_expect(self, text, code, mask=False):
        lines = self._cmd(text, mask)
        if not lines[-1].startswith(code):
            raise RuntimeError("expected %s, got: %s" % (code, lines[-1]))
        return lines

    def auth_step(self, text, mask=False):
        """Send one AUTH continuation line, return (code, decoded-payload)."""
        self.send_raw(text, mask)
        lines = self._read_multiline()
        last = lines[-1]
        code = last[:3]
        payload_b64 = last[4:].strip()
        payload = ''
        if payload_b64:
            try:
                payload = base64.b64decode(payload_b64).decode('utf-8', 'replace')
            except Exception:
                payload = ''
        return code, payload

    def close(self):
        try:
            self.send_raw("QUIT")
            self._read_line()
        except Exception:
            pass
        self.sock.close()


def parse_digest_challenge(decoded):
    """RFC 2831 challenge: comma-separated key=value or key="value" pairs."""
    parts = {}
    for m in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|[^,]*)', decoded):
        k, v = m.group(1), m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        parts[k] = v
    return parts


def md5hex(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


def md5bin(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).digest()


def build_digest_md5_response(challenge, username, password, digest_uri,
                               realm_override=None, cnonce=None):
    """RFC 2831 SASL DIGEST-MD5 client response (qop=auth only)."""
    nonce = challenge.get('nonce', '')
    realm = realm_override if realm_override is not None else challenge.get('realm', '')
    qop = 'auth'
    if cnonce is None:
        cnonce = uuid.uuid4().hex
    nc = '00000001'

    a1_bytes = md5bin("%s:%s:%s" % (username, realm, password))
    a1_bytes += (":%s:%s" % (nonce, cnonce)).encode('utf-8')
    ha1 = md5hex(a1_bytes)

    a2 = "AUTHENTICATE:%s" % digest_uri
    ha2 = md5hex(a2)

    kd_input = "%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2)
    response = md5hex(kd_input)

    fields = [
        'username="%s"' % username,
        'realm="%s"' % realm,
        'nonce="%s"' % nonce,
        'cnonce="%s"' % cnonce,
        'nc=%s' % nc,
        'qop=%s' % qop,
        'digest-uri="%s"' % digest_uri,
        'response=%s' % response,
        'charset=utf-8',
    ]
    return ",".join(fields), response, ha1, ha2


def do_digest_md5(session, user, password, digest_uri, realm_override, verbose):
    code, payload = session.auth_step("AUTH DIGEST-MD5")
    if code != '334':
        print("FAIL: server did not offer a DIGEST-MD5 challenge (%s %s)" % (code, payload))
        return False
    challenge = parse_digest_challenge(payload)
    if verbose:
        print("-- decoded challenge: %s" % challenge)

    resp_str, response, ha1, ha2 = build_digest_md5_response(
        challenge, user, password, digest_uri, realm_override)
    if verbose:
        print("-- client response fields: %s" % resp_str)
        print("-- HA1=%s HA2=%s response=%s" % (ha1, ha2, response))

    b64resp = base64.b64encode(resp_str.encode('utf-8')).decode('ascii')
    code, payload = session.auth_step(b64resp, mask=True)

    if code == '235':
        print("SUCCESS: authenticated (no rspauth step, or server folded it in)")
        return True
    if code == '334':
        if payload.startswith('rspauth='):
            if verbose:
                print("-- server rspauth: %s" % payload)
            code2, payload2 = session.auth_step("")
            if code2 == '235':
                print("SUCCESS: authenticated (rspauth verified)")
                return True
            print("FAIL: rspauth step rejected: %s %s" % (code2, payload2))
            return False
        print("FAIL: unexpected 334 continuation: %s" % payload)
        return False
    print("FAIL: server rejected response: %s %s" % (code, payload))
    return False


def do_cram_md5(session, user, password, verbose):
    code, payload = session.auth_step("AUTH CRAM-MD5")
    if code != '334':
        print("FAIL: no CRAM-MD5 challenge (%s %s)" % (code, payload))
        return False
    if verbose:
        print("-- challenge: %s" % payload)
    digest = hmac.new(password.encode('utf-8'), payload.encode('utf-8'),
                       hashlib.md5).hexdigest()
    resp = "%s %s" % (user, digest)
    b64resp = base64.b64encode(resp.encode('utf-8')).decode('ascii')
    code, payload = session.auth_step(b64resp, mask=True)
    if code == '235':
        print("SUCCESS: authenticated")
        return True
    print("FAIL: %s %s" % (code, payload))
    return False


def do_plain(session, user, password, verbose):
    msg = "\0%s\0%s" % (user, password)
    b64 = base64.b64encode(msg.encode('utf-8')).decode('ascii')
    code, payload = session.auth_step("AUTH PLAIN %s" % b64, mask=True)
    if code == '235':
        print("SUCCESS: authenticated")
        return True
    print("FAIL: %s %s" % (code, payload))
    return False


def do_login(session, user, password, verbose):
    code, payload = session.auth_step("AUTH LOGIN")
    if code != '334':
        print("FAIL: no LOGIN username prompt (%s %s)" % (code, payload))
        return False
    b64user = base64.b64encode(user.encode('utf-8')).decode('ascii')
    code, payload = session.auth_step(b64user)
    if code != '334':
        print("FAIL: no LOGIN password prompt (%s %s)" % (code, payload))
        return False
    b64pass = base64.b64encode(password.encode('utf-8')).decode('ascii')
    code, payload = session.auth_step(b64pass, mask=True)
    if code == '235':
        print("SUCCESS: authenticated")
        return True
    print("FAIL: %s %s" % (code, payload))
    return False


def main():
    ap = argparse.ArgumentParser(
        description="Manual SMTP AUTH mechanism tester (PLAIN/LOGIN/CRAM-MD5/DIGEST-MD5)")
    ap.add_argument('--host', required=True)
    ap.add_argument('--port', type=int, default=25)
    ap.add_argument('--user', required=True)
    ap.add_argument('--password', required=True)
    ap.add_argument('--mech', choices=['digest-md5', 'cram-md5', 'plain', 'login'],
                     default='digest-md5')
    ap.add_argument('--starttls', action='store_true')
    ap.add_argument('--realm', default=None,
                     help="Override realm in DIGEST-MD5 response (default: use server's)")
    ap.add_argument('--digest-uri', default=None,
                     help='digest-uri for DIGEST-MD5 (default: "smtp/<host>")')
    ap.add_argument('--timeout', type=float, default=15.0)
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    digest_uri = args.digest_uri or ("smtp/%s" % args.host)

    session = SmtpSession(args.host, args.port, args.starttls, args.timeout, args.verbose)
    try:
        if args.mech == 'digest-md5':
            ok = do_digest_md5(session, args.user, args.password, digest_uri,
                                args.realm, args.verbose)
        elif args.mech == 'cram-md5':
            ok = do_cram_md5(session, args.user, args.password, args.verbose)
        elif args.mech == 'plain':
            ok = do_plain(session, args.user, args.password, args.verbose)
        else:
            ok = do_login(session, args.user, args.password, args.verbose)
    finally:
        session.close()

    sys.exit(0 if ok else 1)


main()
