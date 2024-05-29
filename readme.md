# Smartcard-based web authentication using Python/Flask
This is a demo server. **It will only work with smart-cards isseud by the Swiss Government.**
The aim of this demo project is to authenticate users using only their smart-card and their browser against the server without any other 3rd-party software required (except of course the smart-card drivers).

Only minor modifications are necessary for this project to work with other (i.e., non-SwissGov) smart-cards:

1. Replace `<project-root>/cert/root/swissgov-root-ca1.p7b` with the issuing root X.509 certificate.
2. Replace `<project-root>/cert/root/swissgov-enhanced-ca02.p7b` with the issuing certificate chain. This file may also be identical to `<project-root>/cert/root/swissgov-root-ca1.p7b`.
3. Change the following lines in `<project-root>/root/server.py` if needed:
    ```diff
    - CERTIFICATE_CLIENT_ROOT_P7B : str = f'{CERTIFICATE_ROOT_DIR}/swissgov-root-ca1.p7b'
    + CERTIFICATE_CLIENT_ROOT_P7B : str = f'{CERTIFICATE_ROOT_DIR}/your-certificate-root.p7b'
    CERTIFICATE_CLIENT_ROOT_PEM : str = CERTIFICATE_CLIENT_ROOT_P7B[:-4] + '.pem'
    - CERTIFICATE_CLIENT_KEYCHAIN_P7B : str = f'{CERTIFICATE_ROOT_DIR}/swissgov-enhanced-ca02.p7b'
    + CERTIFICATE_CLIENT_KEYCHAIN_P7B : str = f'{CERTIFICATE_ROOT_DIR}/your-certificate-chain.p7b'
    CERTIFICATE_CLIENT_KEYCHAIN_PEM : str = CERTIFICATE_CLIENT_KEYCHAIN_P7B[:-4] + '.pem'
    ```
4. Note that you can also exclusively use the `.pem` format instead of `.p7b`, but that would require also removing the following lines:
    ```diff
    - if not(os.path.exists(CERTIFICATE_CLIENT_ROOT_PEM)):
    -     convert_p7b_to_pem(CERTIFICATE_CLIENT_ROOT_P7B, CERTIFICATE_CLIENT_ROOT_PEM)
    -
    - if not(os.path.exists(CERTIFICATE_CLIENT_KEYCHAIN_PEM)):
    -     convert_p7b_to_pem(CERTIFICATE_CLIENT_KEYCHAIN_P7B, CERTIFICATE_CLIENT_KEYCHAIN_PEM)
    ```

## Instructions

1.  Install the smart-card drivers for the cards issued by the Swiss Government. You can find them on [the Thales website](https://cpl.thalesgroup.com/access-management/security-applications/credentialing-safenet-minidriver).
2.  [Install python](https://www.python.org/downloads/).
3.  Run the following commands in your terminal:
    ```bash
    git clone https://github.com/Unknown6656/SmartcardWebAuthTest
    pip install pyopenssl werkzeug flask
    mkdir cert/user
    mkdir cert/root
    ```
4.  Download the Swiss Government X.509 root certificates from https://www.bit.admin.ch/bit/en/home/themes/swiss-government-pki/certificate-service-provider-csp/rootzertifikate/swiss-government-root-ca-i.html and place them in the directory `cert/root`.
    - `Swiss Government Root CA I`
    - `Swiss Government Enhanced CA 01`
    - `Swiss Government Enhanced CA 02`
5.  Download all X.509 certificates of users you want to "whitelist" from the following pages. Place the user certificates in `cert/user`.
    - https://admindir.verzeichnisse.admin.ch/ [Swiss Intranet only]
    - https://staatskalender.admin.ch/ [Public]
6.  Run the following command in your terminal to start the webserver.
    ```bash
    python server.py
    ```
7.  Navigate to `https://localhost:6996/`
8.  Connect your smart-card issued by the Swiss Government.
9.  Select the smart-card certificate you want to use for the authentication:<br/>
    ![](img/screenshot-1.png)
10. Enter your PIN:<br/>
    ![](img/screenshot-2.png)
11. Success.<br/>
    ![](img/screenshot-3.png)
12. If unsuccessful, the following message is displayed:<br/>
    ![](img/screenshot-4.png)