#!/usr/bin/python3

import sys

try:
    import datetime, hashlib, json, netifaces, os, random, shlex, ssl, string
    import subprocess, time
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

def check_deps():
    # Check if qr encode is available
    # Best way to check if it is available is to run it
    try:
        qrencode_return_code = subprocess.run(shlex.split('qrencode'),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            universal_newlines=True)
    except FileNotFoundError as err:
        print(f"Unable to execute {err.filename}. Is it installed?")
        sys.exit(1)
    return True

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
    fingerprint = cert.fingerprint(hashes.SHA256())
    X509['fp'] = ''.join(f'{b:02x}' for b in fingerprint)
    return X509

def get_ip_addresses():
    addresses = []
    for iface in netifaces.interfaces():
        for k,v in netifaces.ifaddresses(iface).items():
            if v[0]['addr'] != '127.0.0.1' and len(v[0]['addr'].split('.')) == 4:
                # Valid address!
                addresses.append(v[0]['addr'])
    # Return first available IP address
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
    print("Generated token:", host_info['token'])
    return host_info

def generate_qr(host_info):
    qr_content = "motorolardpconnection" + json.dumps(host_info, separators=(',', ':'))
    print(qr_content)
    qr = subprocess.run(shlex.split(f"qrencode -t utf8 '{qr_content}'"),
        stdout=subprocess.PIPE,
        universal_newlines=True)
    print(qr.stdout)


class ReadyForHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        print(self.path)
        if self.path == "/rdp/connect":
            raw_data = self.rfile.read().decode('utf8')
            print(raw_data)
            phone_info = {}
            for kv_pair in raw_data.split('&'):
                split = kv_pair.split('=')
                phone_info[split[0]] = split[1]
                print(split[0] + ": " + split[1])

            if phone_info['token'] == host_info['token']:
                self.protocol_version = "HTTP/1.1"
                self.send_response(200)
                self.send_header("Content-Length", len("success"))
                self.end_headers()
                self.wfile.write(bytes("success", "utf8"))
                subprocess.run(shlex.split(f"/opt/freerdp-nightly/bin/xfreerdp /v:{phone_info['phoneIp']} /cert:ignore /size:1280x720 /u:{host_info['user']} /p:{host_info['pass']}"),
                universal_newlines=True)
        elif self.path == "/rdp/connect/success":
            print("Success!")
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", len("success"))
            self.end_headers()
            self.wfile.write(bytes("success", "utf8"))

check_deps()
keycert = generate_cert()
host_info = generate_host_info(keycert)
generate_qr(host_info)

httpd = HTTPServer(('', HTTP_PORT), ReadyForHandler)
# TODO: ssl.wrap_socket is deprecated with Py 3.7+
httpd.socket = ssl.wrap_socket(httpd.socket,
    keyfile="selfsigned.key",
    certfile="selfsigned.cert",
    server_side=True)
httpd.serve_forever()
