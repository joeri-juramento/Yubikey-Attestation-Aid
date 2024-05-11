#!/usr/bin/python3
def expected_yubikeys():
    # Here you may type serials of yubikeys that you know to soft-mitigate the limits of this script:
    # If a match is found, the script will finish, otherwise you will be prompted to enter the serial.
    trusted_yubikey_serials = [
        [00000000, "Example 1 - Owner or Reference"],
        [00000000, "Example 2 - Owner or Reference"]
        ]
    # Optionally load from vars
    book_json = os.getenv('ybook')
    if book_json:
        book = json.loads(book_json)
    else:
        book = []
    combined_list = trusted_yubikey_serials + book
    return combined_list

def compliant_policies():
    # Define what you want to mark as compliant behaviour by uncommenting that one: 
    preferred_pin_policy = (
        #"never"
        #"once per session"
        "always"
        #"any"
    )
    preferred_touch_policy = (
        #"never"
        #"always"
        "cached for 15s"
        #"any"
    )
    return preferred_pin_policy, preferred_touch_policy



# =========================================================================================

# Packages that can be imported without any pip installs:
import sys
import os # for cls
import json # for environment variable
import datetime
import binascii
import subprocess # for auto package installer

# For packages that require pip installs:
packages_to_install = [
    "cryptography",
    "tabulate"
    ]

def install_packages(packages):
    for package in packages:
        try:
            __import__(package)
            #print(f"{package} is already installed.")
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call(["pip", "install", package])
            print(f"{package} has been installed.")

install_packages(packages_to_install)
#manual note: pip3 install cryptography tabulate

# Imports after auto-installer.
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID
from tabulate import tabulate

# ========================================================================================

def load_certificate(file_path):
    try:
        with open(file_path, 'rb') as file:
            return x509.load_pem_x509_certificate(file.read(), default_backend())
    except FileNotFoundError:
        print(f"Error: Certificate file '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading certificate: {e}")
        sys.exit(1)

def load_csr(file_path):
    try:
        with open(file_path, 'rb') as file:
            return x509.load_pem_x509_csr(file.read(), default_backend())
    except FileNotFoundError:
        print(f"Error: CSR file '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading CSR: {e}")
        sys.exit(1)

def verify_certificate(attestation_cert, intermediate_cert, root_cert, StatusKeeper):
    pad = padding.PKCS1v15()
    hash_algorithm = hashes.SHA256()

    try:
        intermediate_cert.public_key().verify(
            attestation_cert.signature,
            attestation_cert.tbs_certificate_bytes,
            pad,
            hash_algorithm
        )
        print("✅ Attestation certificate is validly signed by the intermediate certificate." )
        StatusKeeper.SignCheck.Root2Intermediate = True
    except Exception as e:
        print(f"❌ Verification with intermediate certificate failed: {e}")
        return

    try:
        root_cert.public_key().verify(
            intermediate_cert.signature,
            intermediate_cert.tbs_certificate_bytes,
            pad,
            hash_algorithm
        )
        print("✅ Intermediate certificate is validly signed by the root certificate." + '\n')
        StatusKeeper.SignCheck.Intermediate2AttestationCertFromSlot = True
    except Exception as e:
        print(f"❌ Verification with root certificate failed: {e}")
        return

    current_time = datetime.datetime.now(datetime.timezone.utc)
    for cert in [attestation_cert, intermediate_cert, root_cert]:
        if cert.not_valid_before_utc <= current_time <= cert.not_valid_after_utc:
            print(f"✅ ({cert.not_valid_after_utc}) Certificate {cert.subject} is valid.")
            if StatusKeeper.ValidityCheck.Overall == None: StatusKeeper.ValidityCheck.Overall = True 
        else:
            print(f"(❌ {cert.not_valid_after_utc}) Certificate {cert.subject} is not valid.")
            StatusKeeper.ValidityCheck.Overall = False
            return
    StatusKeeper.ValidityCheck.AttestationCertFromSlot = True if (attestation_cert.not_valid_before_utc <= current_time <= attestation_cert.not_valid_after_utc) else False
    StatusKeeper.ValidityCheck.Intermediate = True if (intermediate_cert.not_valid_before_utc <= current_time <= intermediate_cert.not_valid_after_utc) else False 
    StatusKeeper.ValidityCheck.Root = True if (root_cert.not_valid_before_utc <= current_time <= root_cert.not_valid_after_utc) else False 
    print("\n")

def check_public_key(csr, attestation_cert, StatusKeeper):
    csr_public_key_bytes = csr.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    attestation_public_key_bytes = attestation_cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if csr_public_key_bytes == attestation_public_key_bytes:
        print(f"✅ Public key in CSR and attestation certificate are the same." + '\n' + f"({StatusKeeper.Filename.csr} <-pub-> {StatusKeeper.Filename.attestation_cert})\n")
        StatusKeeper.MATCH_PublicKeys = True
    else:
        print("❌ Public key in CSR and attestation certificate are different." + '\n' + f"({StatusKeeper.Filename.csr} <-!pub!-> {StatusKeeper.Filename.attestation_cert})\n")
        StatusKeeper.MATCH_PublicKeys = False

def decode_yubikey_info(attestation_cert, StatusKeeper):
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
    #ORIGINAL print(f"Serial Number: {serial_number}")
    #print("\n")
    #ORIGNAL print(f"Pin Policy: {pin_policy}, Touch Policy: {touch_policy}")

    StatusKeeper.Data.serial_number = serial_number
    StatusKeeper.Data.pin_policy = pin_policy
    StatusKeeper.Data.touch_policy = touch_policy
    
def is_policy_compliant(pin_policy, touch_policy, StatusKeeper):

    # Check if the pin and touch policies match the preferred policies
    preferred_pin_policy, preferred_touch_policy = compliant_policies()

    pin_compliant = (pin_policy == preferred_pin_policy or preferred_pin_policy == "any")
    touch_compliant = (touch_policy == preferred_touch_policy or preferred_touch_policy == "any")

    StatusKeeper.Compliancy.PinPolicy = pin_compliant
    StatusKeeper.Compliancy.TouchPolicy = touch_compliant

    return pin_compliant, touch_compliant, preferred_pin_policy, preferred_touch_policy

def print_policies_and_compliance_report(StatusKeeper):
# Check if the policies comply with preferred policies
    pin_policy = StatusKeeper.Data.pin_policy
    touch_policy = StatusKeeper.Data.touch_policy
    
    pin_compliant, touch_compliant, preferred_pin_policy, preferred_touch_policy = is_policy_compliant(pin_policy, touch_policy, StatusKeeper)

    # Gather compliance status with preferred policies using emojis
    pin_status = "✅ compliant" if pin_compliant else "❌ not compliant"
    touch_status = "✅ compliant" if touch_compliant else "❌ not compliant"
    headers = ["Type of Policy", "Policy attested source CSR *", "Compliant Policy (set in .py)", "Result"]
    tabledata = [
        ["Pin", pin_policy, preferred_pin_policy, pin_status],
        ["Touch", touch_policy, preferred_touch_policy, touch_status]
        ]
    
    #Display compliancy result table
    print("\n::Complicancy of Policy Regarding Private Key Protections::")
    print("\n")
    print(tabulate(tabledata, headers=headers))
    print("\n")
    print("* These policies were retrieved from the Attestation (Slot) Certificate related to the CertSignRequest(CSR).\n" +
        "Pin & Touch policies can only be set during cert creation (or import) in Yubikey's PIV applet, not afterwards.\n" + #This in contrast to Yubikey's PGP applet.
        "If a policy is not compliant, do not sign the CSR. \n" +
        "Regenerate a new key and CSR with correct policy switches; collect the new CSR and new Attestation (Slot) Cert.\n")
    
    
def compare_key_serials(StatusKeeper, serial_override):
    print(f"::Yubikey (Device) Identification Check::\n")
    serial_AttCert = StatusKeeper.Data.serial_number
    serial_AttCert_Short = str(serial_AttCert)[:3] + "XXXXX"
    trusted_yubikeys = expected_yubikeys() if serial_override == None else [[serial_override, "Override"]]
    match = False
    prompt_done = False 
    for inner_key in trusted_yubikeys:
        if serial_AttCert == inner_key[0] :
            match = True
            print(f"Automated check: \n✅ The serial from the Attestation Cert exists in your Expected Yubikey list. ({serial_AttCert} - {inner_key[1]})")
            StatusKeeper.MATCH_Serial = True
            prompt_done = True
            break
    if match == False:
        print(f"Automated check: \n🟠 - The Yubikey serial from the Attestation Cert was not found in your expected Yubikey list. - 🟠\n")

    
    def clear():
        # Clear the terminal screen
        os.system('cls' if os.name == 'nt' else 'clear')

    # Prompt the user for input
    count = 0
    while prompt_done == False :
        print("\n" + "So, via a secure channel: \nPlease retrieve the Serial of the Yubikey you assume the CSR to have come from and enter it.\n")
        
        if StatusKeeper.Compliancy.PinPolicy == False or StatusKeeper.Compliancy.TouchPolicy == False:
            print(f"\n(❌ - Tip: \n" +
                    "Due to the Compliancy issues: If you intend to verify/ask/retrieve the serial anyway, \n" +
                    "combine it with a request for a new CSR + Attest with compliant policies.)\n")
        
        prompted_number = input("Serial (of ~8 digits or help/skip): ") if count == 0 else input("Serial (of ~8 digits or help/skip/nomatch): ")
        
        if prompted_number == 'help':
            helpmessage_limitation_script = (      
                "\nHelp: This script validates the following: \n" +
                "> Valid signing chain of Attestation Certs (2); \n" +
                "> The validity of each Attestation Cert (3); \n" +
                "> If the CSR's and the Attestation Cert's Public Keys actually match (1). \n" +
                "  (Or all previous checks are not about the provided CSR(!)).\n" +
                "> If Pin & Touch Policies were configured in compliance with what was chosen in the script.\n" +
                "This makes 8 automated checks. \n\n" +
                #NEWLINE
                "The Serial prompt is the 9th check which makes it difficult: \n" +
                "- For anybody/anything (un)knowingly switching the CSR file + Attest Certs \n" +
                "  with a different set generated on a different Yubikey.\n" +
                "- For anybody having a CSR signed by pretending to be somebody who they are not.\n" +
                "- To accidentially sign a CSR generated on the 'wrong' Yubikey.\n\n" +
                #NEWLINE
                "In other words: Attestation proves that the CSR and related non-shared private key \n" +
                "were generated inside a certain Yubikey; it does NOT proof that the CSR was actually \n" +
                "generated on a specific Yubikey _in possesion of_ a trusted co-worker or source you expect.\n" +
                "That is were this 9th check comes in.\n\n\n" +
                "The Serial you enter will be compared with the Serial 'inside' the Attestation Certificate,\n" +
                "If they are identical, one can state that the CSR truly comes the expected device.\n\n\n" +
                #NEWLINE3
                "(A YubiKey Serial number is printed on the key and can be read via various Yubico apps. \n" +
                "~ You can pre-define serials in the .py script; \n" +
                "~ Define a list [[serial,\"ref\"]] as a local variable (see .py); \n" +
                "~ Restart this .py script with the serial as the last argument; \n" +
                "~ Type in the serial during run time when prompted.)" 
                )
            
            clear()
            print(f"{helpmessage_limitation_script}")
            print(f"The serial retrieved from the Attestation Cert is: {serial_AttCert_Short}")
            ready = input("\nPress enter to continue...")
            print("\n ------------------ ")
            print_policies_and_compliance_report(StatusKeeper)
            #rewind
        elif prompted_number == 'skip':
            StatusKeeper.MATCH_Serial = "skip"
            prompt_done = True
            break
        elif prompted_number == 'nomatch':
            StatusKeeper.MATCH_Serial = False
            prompt_done = True
            break
        elif str(prompted_number) == str(serial_AttCert):
            print(f"✅ The serial from the Attestation Certificate matches what you entered.\n " +
                  "(Sanity-display: From Att Slot Cert: {serial_AttCert} = From you: {prompted_number})\n")
            StatusKeeper.MATCH_Serial = True
            prompt_done = True
            break
        elif str(prompted_number) != str(serial_AttCert):
            print(f"❌ Your entered number does not match the one from the Attestation Certificate. The CSR was not generated on the expected device.\n" +
                  f"{serial_AttCert_Short} (From Att Slot Cert.) \n" +
                  f"{prompted_number} (From you.)")
        count = count+1

def print_report_table(StatusKeeper):
    headers = ["Validation", "Result"]
    if (StatusKeeper.MATCH_PublicKeys):
        tabledata = [
            ["Serial Trusted?", "✅" if StatusKeeper.MATCH_Serial == True else ("⚠️ (skip)" if StatusKeeper.MATCH_Serial == "skip" else "❌") ],
            ["CSR & Attest Cert Public key match", "✅" if StatusKeeper.MATCH_PublicKeys else "❌"],
            ["Root signed Intermediate (Model)", "✅" if StatusKeeper.SignCheck.Root2Intermediate else "❌"],
            ["Intermediate signed Attestation Cert (Slot)", "✅" if StatusKeeper.SignCheck.Intermediate2AttestationCertFromSlot else "❌"],
            ["Valid Root", "✅" if StatusKeeper.ValidityCheck.Root else "❌"],
            ["Valid Intermediate (Model)", "✅" if StatusKeeper.ValidityCheck.Intermediate else "❌"],
            ["Valid Attestation Cert (Slot x)", "✅" if StatusKeeper.ValidityCheck.AttestationCertFromSlot else "❌"],
            ["Touch Policy Compliancy", "✅" if StatusKeeper.Compliancy.TouchPolicy else "❌"],
            ["Pin Policy Compliancy", "✅" if StatusKeeper.Compliancy.PinPolicy else "❌"]
        ]
    elif (StatusKeeper.MATCH_PublicKeys == False)  :
        tabledata = [
            ["Serial Trusted?", "⍻" if StatusKeeper.MATCH_Serial == True else ("⚠️ (skip)" if StatusKeeper.MATCH_Serial == "skip" else "❌") ],
            ["CSR & Attest Cert Public key match", "⍻" if StatusKeeper.MATCH_PublicKeys else "❌"],
            ["Root signed Intermediate (Model)", "⍻" if StatusKeeper.SignCheck.Root2Intermediate else "❌"],
            ["Intermediate signed Attestation Cert (Slot)", "⍻" if StatusKeeper.SignCheck.Intermediate2AttestationCertFromSlot else "❌"],
            ["Valid Root", "⍻" if StatusKeeper.ValidityCheck.Root else "❌"],
            ["Valid Intermediate (Model)", "⍻" if StatusKeeper.ValidityCheck.Intermediate else "❌"],
            ["Valid Attestation Cert (Slot x)", "⍻" if StatusKeeper.ValidityCheck.AttestationCertFromSlot else "❌"],
            ["Touch Policy Compliancy", "⍻" if StatusKeeper.Compliancy.TouchPolicy else "❌"],
            ["Pin Policy Compliancy", "⍻" if StatusKeeper.Compliancy.PinPolicy else "❌"]
        ]

    print("\n")
    print("::Report::")    
    print(tabulate(tabledata, headers=headers))
    print("------------------------------------------------------")
    if (StatusKeeper.MATCH_PublicKeys == False) : print(f"(✅ = OK. ⍻ = Is not valid for CSR '{StatusKeeper.Filename.csr}'.)\n") 
    else: print("")
    

def inform_user_how_to_proceed(StatusKeeper):

    if ( StatusKeeper.ValidityCheck.Overall == True and
         StatusKeeper.SignCheck.Root2Intermediate == True and
         StatusKeeper.SignCheck.Intermediate2AttestationCertFromSlot == True and
         StatusKeeper.Compliancy.PinPolicy == True and 
         StatusKeeper.Compliancy.TouchPolicy == True and 
         StatusKeeper.MATCH_PublicKeys == True):
        #THEN:
        if StatusKeeper.MATCH_Serial == True :
            StatusKeeper.RESULT_Can_I_safely_sign_this_CertificateSigningRequest_based_on_all_checks = "YES 8x✅ + Serial Trusted ✅"
        elif StatusKeeper.MATCH_Serial == "skip" :
            StatusKeeper.RESULT_Can_I_safely_sign_this_CertificateSigningRequest_based_on_all_checks = "Maybe: 8x ✅ - Serial unknown ⚠️"
        elif StatusKeeper.MATCH_Serial == False :
            StatusKeeper.RESULT_Can_I_safely_sign_this_CertificateSigningRequest_based_on_all_checks = "🛑 No."
    else :
        StatusKeeper.RESULT_Can_I_safely_sign_this_CertificateSigningRequest_based_on_all_checks = "🛑 No."


    #REPORT
    print("Reminder: Is the exchange of CSR and Attestation Certs secure?\n")
    print(f"Based on all script checks... \n" +
          f"Can this CSR be safely signed?  -----------> {StatusKeeper.RESULT_Can_I_safely_sign_this_CertificateSigningRequest_based_on_all_checks}")
    print("\n\n") if StatusKeeper.MATCH_Serial != "skip" else print(f"\n(⚠️  Whose Yubikey's CSR are you about the sign? Sure? ⚠️  )\n\n") #😇

    return
    
    

def main():
    if len(sys.argv) != 5 and len(sys.argv) != 6:
        print("Usage: python script.py <csr_file> <attestation_file> <intermediate_ca_file> <root_ca_file> <optional serial>")
        sys.exit(1)
    serial_override = None
    if len(sys.argv) == 5:
        csr_file, attestation_file, intermediate_ca_file, root_ca_file = sys.argv[1:5]
    if len(sys.argv) == 6:
        csr_file, attestation_file, intermediate_ca_file, root_ca_file, serial_override = sys.argv[1:6]
    
    class OutputStatus:
        class SignCheck:
            Root2Intermediate = None
            Intermediate2AttestationCertFromSlot = None
        class ValidityCheck:
            Root = None
            Intermediate = None
            AttestationCertFromSlot = None
            Overall = None
        class Compliancy:
            PinPolicy = None
            TouchPolicy = None
        class Data: # Is this subclass a programmer's "One Should Not"? 
            pin_policy = None
            touch_policy = None
            serial_number = None
        class Filename :
            csr = None
            attestation_cert = None
        MATCH_Publickeys = None # Retired Loud name: Does_the_public_key_from_CSR_equal_the_public_key_from_the_Attestation_Certificate_FromSlot = None
        MATCH_Serial = None
        """
        Contains the information about whether the public key in the Certificate Signing Request (CSR)
        matches the public key in the Attestation Certificate retrieved from the Slot.
        """
        RESULT_Can_I_safely_sign_this_CertificateSigningRequest_based_on_all_checks = False
    
    StatusKeeper = OutputStatus()

    print("\n")
    
    csr = load_csr(csr_file)
    attestation_cert = load_certificate(attestation_file)
    intermediate_cert = load_certificate(intermediate_ca_file)
    root_cert = load_certificate(root_ca_file)
    StatusKeeper.Filename.csr = os.path.basename(csr_file)
    StatusKeeper.Filename.attestation_cert = os.path.basename(attestation_file)

    verify_certificate(attestation_cert, intermediate_cert, root_cert, StatusKeeper)
    check_public_key(csr, attestation_cert, StatusKeeper)
    decode_yubikey_info(attestation_cert, StatusKeeper)
    
    print_policies_and_compliance_report(StatusKeeper) 
    
    compare_key_serials(StatusKeeper, serial_override) 

    print_report_table(StatusKeeper)
    inform_user_how_to_proceed(StatusKeeper)
    

if __name__ == "__main__":
    main()


# ##################################################################################
#  Special Thanks to the author who wrote the base version of yuibkey_attest.ph.
#  
#  Source base version:
#  https://go.juramento.nl/specialthanks_yubikey-attestation
#  https://go.juramento.nl/specialthanks_yubikey-attestation_medium
# ##################################################################################
#  Version 2 
#  The following features were added to the base version:
#
#  - Explicit Advice/Guide if signing CSR is wise.
#  - Configurable Pin & Touch Policies for compliance check.
#  - Explict Report card regarding checks and policies.
#  - Yubikey Serial comparison (annoying, but needed).
#  - Support for known Serials 'address book' in user's environment variable.
#  - Informative Help page.
#
#  Links to this script:
#  https://go.juramento.nl/Yubikey-Attestation-Aid
#  https://go.juramento.nl/yubiattest
# ##################################################################################
# Future
#  ~Maybe a GUI
# ##################################################################################