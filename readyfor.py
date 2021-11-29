#!/usr/bin/python3

import sys

try:
    import hashlib, json, netifaces, os, random, shlex, ssl, string, subprocess, time
    from http.server import BaseHTTPRequestHandler, HTTPServer

except ImportError as err:
    print(f"Unable to load {err.name} - have you installed library dependencies?")
    sys.exit(1)

CERT_GEN_CMD = 'openssl req -new -newkey rsa:2048 -x509 -sha256 -nodes -days 730 -nodes -x509 -subj "/C=CN/O=Lenovo/OU=MBG/CN=Lenovo" -keyout selfsigned.key -out selfsigned.cert'
CERT_GET_FP = 'openssl x509 -in selfsigned.cert -noout -fingerprint -sha256'
VER_STRING = "1.6.60"
EXPIRY_PERIOD = 60
RAND_VALID_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits
HTTP_PORT = 9833

def check_deps():
    # TODO: Check if OpenSSL, qrencode, etc are available
    # Best way to check if they are available is to run them
    try:
        openssl_return_code = subprocess.run(shlex.split('openssl help'),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            universal_newlines=True).returncode
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
    # First, remove old files if necessary
    if os.path.exists("selfsigned.key"):
        os.remove("selfsigned.key")
    if os.path.exists("selfsigned.cert"):
        os.remove("selfsigned.cert")
    X509 = dict()
    # Don't care about CLI output
    subprocess.run(shlex.split(CERT_GEN_CMD),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        universal_newlines=True)
    fingerprint = subprocess.run(shlex.split(CERT_GET_FP),
        stdout=subprocess.PIPE,
        universal_newlines=True)
    with open('selfsigned.key') as f:
        X509['key'] = f.readlines()
    with open('selfsigned.cert') as f:
        X509['cert'] = f.readlines()
    X509['fp'] = fingerprint.stdout[19:].replace(':', '').lower()

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
    host_info['fp'] = keycert['fp'][:-1]
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

def generate_qr(keycert):
    qr_content = "motorolardpconnection" + json.dumps(generate_host_info(keycert), separators=(',', ':'))
    print(qr_content)
    qr = subprocess.run(shlex.split(f"qrencode -t utf8 '{qr_content}'"),
        stdout=subprocess.PIPE,
        universal_newlines=True)
    print(qr.stdout)


class MotoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        return_message = "success"
        print(self.rfile.read())

        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.send_header("Content-Length", len(return_message))
        self.end_headers()
        self.wfile.write(bytes(return_message, "utf8"))



check_deps()
keycert = generate_cert()
generate_qr(keycert)

httpd = HTTPServer((get_ip_addresses()[0], HTTP_PORT), MotoHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
    keyfile="selfsigned.key",
    certfile="selfsigned.cert",
    server_side=True)
httpd.serve_forever()
