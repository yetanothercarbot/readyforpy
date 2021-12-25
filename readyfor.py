#!/usr/bin/python3

import sys

try:
    import argparse, datetime, hashlib, json, netifaces, os, platform, qrcode
    import random, re, shlex, ssl, string, subprocess, time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError as err:
    print(f"Unable to load {err.name} - have you installed library dependencies?")
    sys.exit(1)

VER_STRING = "1.6.60"
EXPIRY_PERIOD = 60
RAND_VALID_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits
HTTP_PORT = 9833

XFREERDP_INSTRUCTIONS = "https://github.com/FreeRDP/FreeRDP/wiki/PreBuilds"
XFREERDP_RE = re.compile(r"\d+")
XFREERDP_COMMAND = "{} /v:{} /cert:ignore /size:{} /u:{} /p:{}"

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="Show debugging messages", action="count", default=0)
parser.add_argument("--no-check-freerdp", help="Skip freerdp presence & version checks", action="store_true")
parser.add_argument("--freerdp-path", help="Specify an alternative path for freerdp", default="/opt/freerdp-nightly/bin/xfreerdp")
parser.add_argument("-r", "--resolution", help="Set custom resolution for RDP connection", default="1280x720")
args = parser.parse_args()

def check_freerdp():
    if platform.system() == 'Linux':
        # Check if a xfreerdp is installed
        try:
            xfreerdp_result = subprocess.run(
                shlex.split(f'{args.freerdp_path} --version'),
                stdout = subprocess.PIPE,
                stderr = subprocess.DEVNULL,
                universal_newlines=True
            )
            version = XFREERDP_RE.findall(xfreerdp_result.stdout)
            if (int(version[0]) < 3):
                print(f"The provided version of xfreerdp is too old ({'.'.join(version[:3])}). Please update to 3.0.0 or newer")
                print("(if this was a mistake, run with --no-check-freerdp)")
                sys.exit(1)
            elif args.verbose >= 1:
                print(f"[ReadyForPy] Detected freerdp version {'.'.join(version[:3])}")
        except FileNotFoundError as err:
            print("The nightly release of xfreerdp does not appear to be",
                f"installed. Please see {XFREERDP_INSTRUCTIONS} for details",
                "on installing")
            sys.exit(1)
    elif platform.system() == 'Windows':
        print("Windows has not yet been tested - rerun with the --no-check-freerdp flag and specify a location for freerdp with --freerdp-path")
        sys.exit(2)
    else:
        print("You are currently not on a tested platform. You will need freerdp",
            "(3.0.0 or newer). To test, rerun with --no-check-freerdp and specify",
            "the location of freerdp with --freerdp-path")
        sys.exit(2)

# Generates a new certificate
def generate_cert():
    X509 = dict()
    # Generate key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    key_data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Must be written to file for Python's SSL library
    with open("selfsigned.key", "wb") as f:
        f.write(key_data)
    X509['key'] = key_data.decode()
    if args.verbose >= 2:
        print(X509['key'])
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"MBG"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Lenovo"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Lenovo"),
    ])

    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=365)).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
    # Must be written to file for Python's SSL library
    with open("selfsigned.cert", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    X509['cert'] = cert.public_bytes(serialization.Encoding.PEM).decode()
    if args.verbose >= 2:
        print(X509['cert'])
    X509['fp'] = ''.join(f'{b:02x}' for b in cert.fingerprint(hashes.SHA256()))
    if args.verbose >= 2:
        print(X509['fp'])
    return X509

def get_ip_addresses():
    addresses = []
    for iface in netifaces.interfaces():
        for k,v in netifaces.ifaddresses(iface).items():
            if v[0]['addr'] != '127.0.0.1' and len(v[0]['addr'].split('.')) == 4:
                # Valid address!
                addresses.append(v[0]['addr'])
    # Return first available IP address
    if len(addresses) == 0:
        print("Unable to find valid IP address. Are you connected and have an",
                "IPv4 address?")
        sys.exit(3)
    if args.verbose >= 1:
        print("[ReadyForPy] IP addresses: ", ", ".join(addresses))
    return addresses

# Generates the host info dictionary that will be processed for the qr code
def generate_host_info(keycert):
    host_info = {}
    host_info['fp'] = keycert['fp']
    host_info['authLevel'] = 2
    host_info['sn'] = 0
    host_info['ips'] = get_ip_addresses();
    host_info['timestamp'] = int(time.time())
    host_info['user'] = ''.join(random.choices(RAND_VALID_CHARS, k=16))
    host_info['pass'] = ''.join(random.choices(RAND_VALID_CHARS, k=16))
    host_info['version'] = VER_STRING
    content = ("Moto@lenovo.com"
                + VER_STRING
                + str(host_info['timestamp'])
                + host_info['user']
                + host_info['pass']
                + str(EXPIRY_PERIOD) + "[\"" + host_info['ips'][0] + "\"]")
    host_info['token'] = hashlib.sha256(content.encode()).hexdigest()[:16]
    return host_info

def generate_qr(host_info):
    qr_content = "motorolardpconnection" + json.dumps(host_info, separators=(',', ':'))
    if args.verbose >= 1:
        print("[ReadyForPy] QR content:", qr_content)
    qr = qrcode.make(qr_content)
    qr.show()


class ReadyForHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/rdp/connect":
            raw_data = self.rfile.read().decode('utf8')
            if args.verbose >= 2:
                print("[ReadyForPy] Payload:", raw_data)
            phone_info = {}
            for kv_pair in raw_data.split('&'):
                split = kv_pair.split('=')
                phone_info[split[0]] = split[1]
                if args.verbose >= 1:
                    print("[ReadyForPy]", split[0] + ": " + split[1])

            if phone_info['token'] == host_info['token']:
                print("*** You can close the QR code window now ***")
                self.protocol_version = "HTTP/1.1"
                self.send_response(200)
                self.send_header("Content-Length", len("success"))
                self.end_headers()
                self.wfile.write(bytes("success", "utf8"))
                if args.verbose >= 2:
                    subprocess.run(
                        shlex.split(XFREERDP_COMMAND.format(
                            args.freerdp_path,
                            phone_info['phoneIp'],
                            args.resolution,
                            host_info['user'],
                            host_info['pass']
                        )),
                        universal_newlines=True
                    )
                else:
                    # Suppress output
                    subprocess.run(
                        shlex.split(XFREERDP_COMMAND.format(
                            args.freerdp_path,
                            phone_info['phoneIp'],
                            args.resolution,
                            host_info['user'],
                            host_info['pass']
                        )),
                        stdout = subprocess.DEVNULL,
                        stderr = subprocess.DEVNULL,
                        universal_newlines=True
                    )
                sys.exit(0)
        elif self.path == "/rdp/connect/success":
            print("Success!")
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", len("success"))
            self.end_headers()
            self.wfile.write(bytes("success", "utf8"))

if not args.no_check_freerdp:
    check_freerdp()
keycert = generate_cert()
host_info = generate_host_info(keycert)
generate_qr(host_info)
try:
    httpd = HTTPServer(('', HTTP_PORT), ReadyForHandler)
    # TODO: ssl.wrap_socket is deprecated with Py 3.7+
    httpd.socket = ssl.wrap_socket(httpd.socket,
        keyfile="selfsigned.key",
        certfile="selfsigned.cert",
        server_side=True)
    httpd.serve_forever()
except KeyboardInterrupt as interrupt:
    print("\nQuitting...")
