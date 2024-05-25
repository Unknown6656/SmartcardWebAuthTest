import typing
import subprocess
import sys
import ssl
import os
import re

import OpenSSL
import OpenSSL.SSL
import OpenSSL.crypto

import werkzeug
import werkzeug.serving

from flask import Flask, request, jsonify, send_file, send_from_directory, redirect, render_template


CURRENT_DIR : str
OPENSSL_PATH : str

CERTIFICATE_DIR = 'cert'
CERTIFICATE_SERVER_PUB_KEY : str = f'{CERTIFICATE_DIR}/server.crt'
CERTIFICATE_SERVER_SEC_KEY : str = f'{CERTIFICATE_DIR}/server.key'
CERTIFICATE_SERVER_PASSWD = b'018ef1d6-921f-704a-8cd7-54f1f3d415b4' # TODO : change me.
CERTIFICATE_SERVER_C = 'CH'
CERTIFICATE_SERVER_S = 'Bern'
CERTIFICATE_SERVER_L = 'Bern'
CERTIFICATE_SERVER_O = 'Schweizerische Eidgenossenschaft'
CERTIFICATE_SERVER_OU = 'VBS / DDPS'
CERTIFICATE_SERVER_CN = 'Test'
CERTIFICATE_SERVER_E = 'info@admin.ch'
CERTIFICATE_CLIENT_ROOT_P7B : str = f'{CERTIFICATE_DIR}/swissgov-root-ca1.p7b'
CERTIFICATE_CLIENT_ROOT_PEM : str = CERTIFICATE_CLIENT_ROOT_P7B[:-4] + '.pem'
CERTIFICATE_CLIENT_KEYCHAIN_P7B : str = f'{CERTIFICATE_DIR}/swissgov-enhanced-ca02.p7b'
CERTIFICATE_CLIENT_KEYCHAIN_PEM : str = CERTIFICATE_CLIENT_KEYCHAIN_P7B[:-4] + '.pem'

# this is only for debugging reasons. set it to 'False' in production
CERTIFICATE_CLIENT_ALLOW_ANY = False

X509_OID_SERVER_AUTH = b'1.3.6.1.5.5.7.3.1'
X509_OID_CLIENT_AUTH = b'1.3.6.1.5.5.7.3.2'
X509_OID_BASIC_CONSTRAINTS = b'2.5.29.19'
X509_OID_SUBJECT_ALT_NAME = b'2.5.29.17'
X509_OID_KEY_USAGE = b'2.5.29.15'
X509_OID_EMPOLYEE_NUMBER = '2.16.840.1.113730.3.1.3'

WEBSERVER_PORT : int = 6996
ALLOWED_STATIC_FILES : list[str] = ['js', 'css', 'html', 'ttf', 'png', 'svg']



def find_openssl() -> str:
    try:
        for path in  [
            r"C:\OpenSSL-Win64\bin\openssl.exe",
            r"C:\OpenSSL-Win32\bin\openssl.exe",
            r"C:\Program Files\OpenSSL\bin\openssl.exe",
            r"C:\Program Files (x86)\OpenSSL\bin\openssl.exe",
            r"C:\Program Files\Git\usr\bin\openssl.exe",
            r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        ]:
            if os.path.exists(path):
                return path

        return subprocess.run(
            ['where' if os.name == 'nt' else 'which', 'openssl'],
            capture_output = True,
            text = True,
            check = True
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return None

def convert_p7b_to_pem(p7b_path : str, pem_path) -> None:
    pem : str = subprocess.run(
        [OPENSSL_PATH, 'pkcs7', '-inform', 'DER', '-outform', 'PEM', '-in', p7b_path, '-print_certs'],
        capture_output = True,
        text = True,
        check = True
    ).stdout.strip()

    with open(pem_path, 'w') as f:
        f.write(pem)

def create_ssl_keypair() -> None:
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 4086)

    req = OpenSSL.crypto.X509Req()
    subj : OpenSSL.crypto.X509Name = req.get_subject()
    subj.C = CERTIFICATE_SERVER_C
    subj.ST = CERTIFICATE_SERVER_S
    subj.L = CERTIFICATE_SERVER_L
    subj.O = CERTIFICATE_SERVER_O
    subj.OU = CERTIFICATE_SERVER_OU
    subj.CN = CERTIFICATE_SERVER_CN
    subj.emailAddress = CERTIFICATE_SERVER_E

    req.set_pubkey(pkey)
    req.sign(pkey, 'sha256')

    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 3600)
    # cert.add_extensions([
    #     OpenSSL.crypto.X509Extension(X509_OID_BASIC_CONSTRAINTS, False, b'CA:TRUE'),
    #     OpenSSL.crypto.X509Extension(X509_OID_KEY_USAGE, False, b'keyCertSign, cRLSign'), # TODO
    #     OpenSSL.crypto.X509Extension(X509_OID_SUBJECT_ALT_NAME, False, b'DNS: *'),
    # ])
    cert.set_issuer(req.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(pkey, 'sha256')

    seckey : str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey, passphrase = CERTIFICATE_SERVER_PASSWD).decode('ascii')
    pubkey : str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode('ascii')

    with open(CERTIFICATE_SERVER_PUB_KEY, 'w') as f:
        f.write(pubkey)

    with open(CERTIFICATE_SERVER_SEC_KEY, 'w') as f:
        f.write(seckey)

def get_x509_name(x509name : OpenSSL.crypto.X509Name) -> dict[str, str]:
    raw : list[str] = re.search('\'(?P<C>[^\']*)\'', str(x509name).replace('"', '\'')).group('C').split('/')

    return {key: value for key, value in [token.split('=') for token in raw if '=' in token]}


class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    def make_environ(self) -> dict[str, typing.Any]:
        environ : dict[str, typing.Any] = super(PeerCertWSGIRequestHandler, self).make_environ()
        environ['wsgi.url_scheme'] = 'https'
        environ['user_cert'] = None

        x509_binary : bytes | None = self.connection.getpeercert(True)

        if x509_binary is not None:
            environ['user_cert'] = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)

        return environ


os.chdir(CURRENT_DIR := os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, template_folder = f'{CURRENT_DIR}/html')

@app.route('/')
def route_index():
    if request.environ['user_cert'] is None:
        return render_template('401.html'), 401

    cert : OpenSSL.SSL.X509 = request.environ['user_cert']
    subject : dict[str, str] = get_x509_name(cert.get_subject())
    issuer : dict[str, str] = get_x509_name(cert.get_issuer())

    # TODO : check if issuer is CERTIFICATE_CLIENT_ROOT_PEM or CERTIFICATE_CLIENT_KEYCHAIN_PEM
    # TODO : check if cert is valid / not revoked
    # TODO : compare subject with database of allowed users

    return render_template(
        'success.html',
        cert = cert,
        issuer = issuer,
        subject = subject
    ), 200

@app.route('/<path:filename>', methods = ['GET', 'POST'])
def serve_static_files(filename):
    if len(filename or '') == 0:
        return redirect('/', 301)
    elif filename.lower()[filename.rfind('.') + 1:] in ALLOWED_STATIC_FILES:
        if request.method == 'GET':
            return send_from_directory('.', filename)
        else:
            return jsonify(request.data)
    else:
        return render_template('403.html', filename = filename), 403


if __name__ == '__main__':
    OPENSSL_PATH = find_openssl() or 'openssl'

    if not os.path.exists(CERTIFICATE_DIR):
        os.makedirs(CERTIFICATE_DIR)

    if not(os.path.exists(CERTIFICATE_SERVER_PUB_KEY) and os.path.exists(CERTIFICATE_SERVER_SEC_KEY)):
        create_ssl_keypair()

    if not(os.path.exists(CERTIFICATE_CLIENT_ROOT_PEM)):
        convert_p7b_to_pem(CERTIFICATE_CLIENT_ROOT_P7B, CERTIFICATE_CLIENT_ROOT_PEM)

    if not(os.path.exists(CERTIFICATE_CLIENT_KEYCHAIN_PEM)):
        convert_p7b_to_pem(CERTIFICATE_CLIENT_KEYCHAIN_P7B, CERTIFICATE_CLIENT_KEYCHAIN_PEM)

    sslctx : ssl.SSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile = None if CERTIFICATE_CLIENT_ALLOW_ANY else CERTIFICATE_CLIENT_KEYCHAIN_PEM)
    sslctx.load_cert_chain(CERTIFICATE_SERVER_PUB_KEY, CERTIFICATE_SERVER_SEC_KEY, CERTIFICATE_SERVER_PASSWD)

    if not CERTIFICATE_CLIENT_ALLOW_ANY:
        sslctx.load_verify_locations(CERTIFICATE_CLIENT_ROOT_PEM)

    sslctx.verify_mode = ssl.CERT_OPTIONAL
    sslctx.check_hostname = False

    app.run(
        host = '0.0.0.0',
        port = WEBSERVER_PORT,
        debug = False,
        threaded = True,
        ssl_context = sslctx,
        request_handler = PeerCertWSGIRequestHandler
    )