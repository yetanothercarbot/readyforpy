#!/usr/bin/python3

import os, pyqrcode, shlex, subprocess

CERT_GEN_CMD = 'openssl req -new -newkey rsa:2048 -x509 -sha256 -nodes -days 730 -nodes -x509 -subj "/C=CN/O=Lenovo/OU=MBG/CN=Lenovo" -keyout selfsigned.key -out selfsigned.cert'
CERT_GET_FP = 'openssl x509 -in selfsigned.cert -noout -fingerprint -sha256'

# Generates a new certificate
def generate_cert():
    # First, remove old files if necessary
    if os.path.exists("selfsigned.key"):
        os.remove("selfsigned.key")
    if os.path.exists("selfsigned.cert"):
        os.remove("selfsigned.cert")
    X509 = dict()
    # Don't care about the output tbh, it's output to a file
    subprocess.run(shlex.split(CERT_GEN_CMD), 
        stdout=subprocess.PIPE, 
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
    
X509 = generate_cert()
print(X509)
