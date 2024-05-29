import urllib.request
import typing
import shutil
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
OPENSSL_SEARCH_LOCATIONS : list[str] = [
    r"C:\OpenSSL-Win64\bin\openssl.exe",
    r"C:\OpenSSL-Win32\bin\openssl.exe",
    r"C:\Program Files\OpenSSL\bin\openssl.exe",
    r"C:\Program Files (x86)\OpenSSL\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
]
CERTIFICATE_DIR = 'cert'
CERTIFICATE_ROOT_DIR : str = f'{CERTIFICATE_DIR}/root'
CERTIFICATE_CLIENT_DIR : str = f'{CERTIFICATE_DIR}/user'
CERTIFICATE_SERVER_PUB_KEY : str = f'{CERTIFICATE_DIR}/server.cer'
CERTIFICATE_SERVER_SEC_KEY : str = f'{CERTIFICATE_DIR}/server.key'
CERTIFICATE_SERVER_PASSWD = b'018ef1d6-921f-704a-8cd7-54f1f3d415b4' # TODO : change me.
CERTIFICATE_SERVER_C = 'CH'
CERTIFICATE_SERVER_S = 'Bern'
CERTIFICATE_SERVER_L = 'Bern'
CERTIFICATE_SERVER_O = 'Schweizerische Eidgenossenschaft'
CERTIFICATE_SERVER_OU = 'VBS'
CERTIFICATE_SERVER_CN = 'Test'
CERTIFICATE_SERVER_E = 'info@admin.ch'
CERTIFICATE_EXTENSIONS : set[str] = {'.cer', '.pem', '.crt', '.pfx', '.p7b', '.p7c', '.p12', '.key'}
CERTIFICATE_CLIENT_ROOT : OpenSSL.crypto.X509
# CERTIFICATE_CLIENT_ROOT_PEM : str = f'{CERTIFICATE_ROOT_DIR}/swissgov-root-ca1.pem'
# CERTIFICATE_CLIENT_ROOT_DOWNLOAD = 'https://www.bit.admin.ch/dam/bit/de/dokumente/SwissGov-PKI-V2/Root-Zertifikate/swiss-governemt_root_ca-i/swiss_governmentrootcai.crt.download.crt/swiss_governmentrootcai.crt'
CERTIFICATE_CLIENT_ROOT_PEM : str = f'{CERTIFICATE_ROOT_DIR}/swissgov-enhanced-ca02.pem'
CERTIFICATE_CLIENT_ROOT_DOWNLOAD = 'https://www.bit.admin.ch/dam/bit/en/dokumente/SwissGov-PKI-V2/Root-Zertifikate/swiss-governemt_root_ca-i/swiss_governmentenhancedca02.cer.download.cer/swiss_governmentenhancedca02.cer'
CERTIFICATE_CLIENT_ALLOW_ANY = False # Set this to 'True' only for debugging reasons. Set it to 'False' in production!
CERTIFICATE_CLIENTS : dict[str, str] = { }
CERTIFICATE_ROOTS : dict[str, str] = { }

# TODO : implement certificate revocation list (CRL) support


X509_CERTIFICATE_HEADER = b'-----BEGIN CERTIFICATE-----'
X509_OID_SERVER_AUTH = b'1.3.6.1.5.5.7.3.1'
X509_OID_CLIENT_AUTH = b'1.3.6.1.5.5.7.3.2'
X509_OID_BASIC_CONSTRAINTS = b'2.5.29.19'
X509_OID_SUBJECT_ALT_NAME = b'2.5.29.17'
X509_OID_KEY_USAGE = b'2.5.29.15'
X509_OID_EMPOLYEE_NUMBER = '2.16.840.1.113730.3.1.3'

# make sure to exclude certificate extensions from being served as static files
WEBSERVER_ALLOWED_STATIC_FILES : set[str] = {'js', 'css', 'html', 'ttf', 'png', 'svg'} - CERTIFICATE_EXTENSIONS
WEBSERVER_PORT : int = 6996



def find_openssl() -> str:
    try:
        for path in OPENSSL_SEARCH_LOCATIONS:
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

def convert_cer_to_pem(cer_path : str, pem_path) -> None:
    subprocess.run(
        [OPENSSL_PATH, 'x509', '-inform', 'DER', '-outform', 'PEM', '-in', cer_path, '-out', pem_path],
        capture_output = True,
        text = True,
        check = True
    ).stdout.strip()

def ensure_correct_format(pem_path : str) -> bool:
    if not(os.path.exists(pem_path)):
        for ext in CERTIFICATE_EXTENSIONS:
            if os.path.exists(in_path := (pem_path[:-4] + ext)):
                with open(in_path, 'rb') as f:
                    if X509_CERTIFICATE_HEADER in f.read():
                        shutil.copy2(in_path, pem_path)
                        return True

                if ext == '.cer' or ext == '.crt':
                    convert_cer_to_pem(in_path, pem_path)
                elif ext == '.p7b' or ext == '.p7c' or ext == '.p12' or ext == '.pfx':
                    convert_p7b_to_pem(in_path, pem_path)
                # TODO : handle .pfx, .key, .der
                else:
                    shutil.copy2(in_path, pem_path)

                return True
        return False
    return True

def get_x509_name(x509name : OpenSSL.crypto.X509Name) -> dict[str, str]:
    raw : list[str] = re.search('\'(?P<C>[^\']*)\'', str(x509name).replace('"', '\'')).group('C').split('/')

    return {key: value for key, value in [token.split('=') for token in raw if '=' in token]}

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

def is_certificate_root(cert : OpenSSL.crypto.X509, root : OpenSSL.crypto.X509) -> bool:
    return False

def load_client_certificates() -> None:
    for root, _, files in os.walk(CERTIFICATE_CLIENT_DIR):
        for file in files:
            for ext in CERTIFICATE_EXTENSIONS:
                if file.endswith(ext):
                    if ext == '.p7b':
                        convert_p7b_to_pem(f'{root}/{file}', f'{root}/{file[:-4]}.pem')
                        file : str = f'{file[:-4]}.pem'

                    with open(f'{root}/{file}', 'rb') as f:
                        cert : OpenSSL.crypto.X509 = None

                        for format in [OpenSSL.crypto.FILETYPE_ASN1, OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_TEXT]:
                            try:
                                cert = OpenSSL.crypto.load_certificate(format, f.read())
                            except:
                                pass

                        if cert is None:
                            continue

                        subject : dict[str, str] = get_x509_name(cert.get_subject())
                        issuer : dict[str, str] = get_x509_name(cert.get_issuer())
                        serial : str = f'{cert.get_serial_number():032x}'

                        if not is_certificate_root(cert, CERTIFICATE_CLIENT_ROOT_PEM):
                            print(f'The certificate "{file}" ({serial}, issuer) is not signed by the root certificate "{CERTIFICATE_CLIENT_ROOT_PEM}" and will therefore be ignored.')
                        else:
                            CERTIFICATE_CLIENTS[subject['CN']] = {
                                'cert': cert,
                                'serial': serial,
                                'issuer': issuer,
                                'subject': subject,
                            }

def verify_client_certificate(cert : OpenSSL.crypto.X509, subject : dict[str, str], issuer : dict[str, str]) -> bool:
    for cn in CERTIFICATE_CLIENTS:
        known : dict[str] = CERTIFICATE_CLIENTS[cn]
        serial : str = f'{cert.get_serial_number():032x}'

        if known['serial'] == serial:
            return True
        elif not is_certificate_root(known['cert'], CERTIFICATE_CLIENT_ROOT_PEM):
            return False

        if known['subject'] == subject and known['issuer'] == issuer:
            return True

    # TODO : check if cert is valid / not revoked

    return False

class request_handler(werkzeug.serving.WSGIRequestHandler):
    def make_environ(self) -> dict[str, typing.Any]:
        environ : dict[str, typing.Any] = super(request_handler, self).make_environ()
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

    if not verify_client_certificate(cert, subject, issuer):
        return render_template('401-cert.html', cert = cert, issuer = issuer, subject = subject), 401

    return render_template('success.html', cert = cert, issuer = issuer, subject = subject), 200

@app.route('/<path:filename>', methods = ['GET', 'POST'])
def serve_static_files(filename):
    if len(filename or '') == 0:
        return redirect('/', 301)
    elif filename.lower()[filename.rfind('.') + 1:] in WEBSERVER_ALLOWED_STATIC_FILES:
        if request.method == 'GET':
            return send_from_directory('.', filename)
        else:
            return jsonify(request.data)
    else:
        return render_template('403.html', filename = filename), 403


if __name__ == '__main__':
    OPENSSL_PATH = find_openssl() or 'openssl'

    for dir in [CERTIFICATE_DIR, CERTIFICATE_ROOT_DIR, CERTIFICATE_CLIENT_DIR]:
        if not os.path.exists(dir):
            os.makedirs(dir)

    if not ensure_correct_format(CERTIFICATE_CLIENT_ROOT_PEM):
        try:
            urllib.request.urlretrieve(CERTIFICATE_CLIENT_ROOT_DOWNLOAD, CERTIFICATE_CLIENT_ROOT_PEM[:-4] + '.cer')
            ensure_correct_format(CERTIFICATE_CLIENT_ROOT_PEM)
        except:
            print(f'Failed to resolve/read root certificate "{CERTIFICATE_CLIENT_ROOT_PEM}" or to download it from "{CERTIFICATE_CLIENT_ROOT_DOWNLOAD}".')
            exit(-1)

    with open(CERTIFICATE_CLIENT_ROOT_PEM, 'rb') as f:
        CERTIFICATE_CLIENT_ROOT = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())

    load_client_certificates()

    if not(os.path.exists(CERTIFICATE_SERVER_PUB_KEY) and os.path.exists(CERTIFICATE_SERVER_SEC_KEY)):
        create_ssl_keypair()

    sslctx : ssl.SSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile = None if CERTIFICATE_CLIENT_ALLOW_ANY else CERTIFICATE_CLIENT_ROOT_PEM)
    sslctx.load_cert_chain(CERTIFICATE_SERVER_PUB_KEY, CERTIFICATE_SERVER_SEC_KEY, CERTIFICATE_SERVER_PASSWD)

    if not CERTIFICATE_CLIENT_ALLOW_ANY:
        sslctx.load_verify_locations(CERTIFICATE_CLIENT_ROOT_PEM)
        sslctx.verify_mode = ssl.CERT_REQUIRED
    else:
        sslctx.verify_mode = ssl.CERT_OPTIONAL

    sslctx.check_hostname = False

    app.run(
        host = '0.0.0.0',
        port = WEBSERVER_PORT,
        debug = False,
        threaded = True,
        ssl_context = sslctx,
        request_handler = request_handler
    )