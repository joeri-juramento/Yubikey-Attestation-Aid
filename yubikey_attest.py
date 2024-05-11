#!/usr/bin/python3
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID
import datetime
import binascii

def load_certificate(file_path):
    with open(file_path, 'rb') as file:
        return x509.load_pem_x509_certificate(file.read(), default_backend())

def load_csr(file_path):
    with open(file_path, 'rb') as file:
        return x509.load_pem_x509_csr(file.read(), default_backend())

def verify_certificate(attestation_cert, intermediate_cert, root_cert):
    pad = padding.PKCS1v15()
    hash_algorithm = hashes.SHA256()

    try:
        intermediate_cert.public_key().verify(
            attestation_cert.signature,
            attestation_cert.tbs_certificate_bytes,
            pad,
            hash_algorithm
        )
        print("Attestation certificate is validly signed by the intermediate certificate. ✅" )
    except Exception as e:
        print(f"Verification with intermediate certificate failed: {e} ❌")
        return

    try:
        root_cert.public_key().verify(
            intermediate_cert.signature,
            intermediate_cert.tbs_certificate_bytes,
            pad,
            hash_algorithm
        )
        print("Intermediate certificate is validly signed by the root certificate. ✅" + '\n')
    except Exception as e:
        print(f"Verification with root certificate failed: {e} ❌")
        return

    current_time = datetime.datetime.utcnow()
    for cert in [attestation_cert, intermediate_cert, root_cert]:
        if cert.not_valid_before <= current_time <= cert.not_valid_after:
            print(f"Certificate {cert.subject} is valid. ✅")
        else:
            print(f"Certificate {cert.subject} is not valid. ❌")

def check_public_key(csr, attestation_cert):
    csr_public_key_bytes = csr.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    attestation_public_key_bytes = attestation_cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if csr_public_key_bytes == attestation_public_key_bytes:
        print("Public key in CSR and attestation certificate are the same. ✅" + '\n')
    else:
        print("Public key in CSR and attestation certificate are different. ❌")

def decode_yubikey_info(attestation_cert):
    firmware_version = serial_number = pin_policy = touch_policy = "Not Found"
    for ext in attestation_cert.extensions:
        if ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.3":
            # Decode Firmware Version
            ext_data = binascii.hexlify(ext.value.value).decode('utf-8')
            firmware_version = f"{int(ext_data[:2], 16)}.{int(ext_data[2:4], 16)}.{int(ext_data[4:6], 16)}"
        elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.7":
            # Decode Serial Number
            ext_data = ext.value.value
            # Assuming the first two bytes are not part of the serial number, skip them
            serial_number = int(binascii.hexlify(ext_data[2:]), 16)
        elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.8":
            # Decode Pin Policy and Touch Policy
            ext_data = binascii.hexlify(ext.value.value).decode('utf-8')
            pin_policy = {"01": "never", "02": "once per session", "03": "always"}.get(ext_data[:2], "Unknown")
            touch_policy = {"01": "never", "02": "always", "03": "cached for 15s"}.get(ext_data[2:4], "Unknown")

    print(f"Firmware Version: {firmware_version}")
    print(f"Serial Number: {serial_number}")
    print(f"Pin Policy: {pin_policy}, Touch Policy: {touch_policy}")

def main():
    if len(sys.argv) < 5:
        print("Usage: python script.py <csr_file> <attestation_file> <intermediate_ca_file> <root_ca_file>")
        sys.exit(1)

    csr_file, attestation_file, intermediate_ca_file, root_ca_file = sys.argv[1:5]

    csr = load_csr(csr_file)
    attestation_cert = load_certificate(attestation_file)
    intermediate_cert = load_certificate(intermediate_ca_file)
    root_cert = load_certificate(root_ca_file)

    verify_certificate(attestation_cert, intermediate_cert, root_cert)
    check_public_key(csr, attestation_cert)
    decode_yubikey_info(attestation_cert)

if __name__ == "__main__":
    main()
