import datetime
import os
import subprocess
import tempfile

HOST_PLATFORM_OS = subprocess.run(["lsb_release","-is"], capture_output=True).stdout.strip()
HOST_PLATFORM_VERSION = subprocess.run(["lsb_release", "-rs"], capture_output=True).stdout.strip()

def matchKeyPair(priv, pub):
    priv_mod = subprocess.run(
        ['openssl', 'rsa', '-noout', '-modulus'],
        capture_output=True,
        input=priv
    )
    assert priv_mod.returncode == 0, "Invalid private key generated"
    pub_mod = subprocess.run(
        ['openssl', 'rsa', '-pubin', '-noout', '-modulus'],
        capture_output=True,
        input=pub
    )
    assert pub_mod.returncode == 0, "Invalid public key generated"
    assert priv_mod.stdout == pub_mod.stdout, "The private key & public key do not match"

def matchEncryptedKey(priv, enc_priv, passwd):
    priv_mod = subprocess.run(
        ['openssl', 'rsa', '-noout', '-modulus'],
        capture_output=True,
        input=priv
    )
    assert priv_mod.returncode == 0, "Invalid private key generated"
    enc_priv_mod = subprocess.run(
        ['openssl', 'rsa', '-noout', '-modulus', '-passin', 'pass:{}'.format(passwd)],
        capture_output=True,
        input=enc_priv
    )
    assert enc_priv_mod.returncode == 0, "Invalid encrypted private key"
    assert priv_mod.stdout == enc_priv_mod.stdout, "Encrypted private key does not match"

def matchCertAndKey(cert, priv):
    priv_mod = subprocess.run(
        ['openssl', 'rsa', '-noout', '-modulus'],
        capture_output=True,
        input=priv
    )
    cert_mod = subprocess.run(
        ['openssl', 'x509', '-noout', '-modulus'],
        capture_output=True,
        input=cert
    )
    assert cert_mod.stdout == priv_mod.stdout

def validateSubject(cert, subject):
    actual_subject = ''
    if HOST_PLATFORM_OS == b'Ubuntu' and HOST_PLATFORM_VERSION == b'20.04':
        # THE OUTPUT FORMATTING ON OPENSSL 1.1.1 (PACKAGED WITH U20) HAS BEEN CHANGED
        # THIS IF BLOCK ENSURES THE SUBJECT IS FORMATTED CORRECTLY FOR UTS.
        actual_subject = subprocess.run(
            ['openssl', 'x509', '-noout', '-subject', '-nameopt', 'compat'],
            capture_output=True,
            input=cert
        )
        actual_subject = actual_subject.stdout.rstrip().decode().replace("subject=", "subject= ")

    else:
        actual_subject = subprocess.run(
            ['openssl', 'x509', '-noout', '-subject'],
            capture_output=True,
            input=cert
        )
        actual_subject = actual_subject.stdout.rstrip().decode()
    assert actual_subject  == subject, \
        "Subject name is {} instead of {}".format(actual_subject.stdout.rstrip(),subject)

def validateIssuer(cert, issuer):
    if HOST_PLATFORM_OS == b'Ubuntu' and HOST_PLATFORM_VERSION == b'20.04':
        # THE OUTPUT FORMATTING ON OPENSSL 1.1.1 (PACKAGED WITH U20) HAS BEEN CHANGED
        # THIS IF BLOCK ENSURES THE ISSUER IS FORMATTED CORRECTLY FOR UTS. 
        actual_issuer = subprocess.run(
            ['openssl', 'x509', '-noout', '-issuer', '-nameopt', 'compat'],
            capture_output=True,
            input=cert
        )
        actual_issuer = actual_issuer.stdout.rstrip().decode().replace("issuer=", "issuer= ")
    else:
        actual_issuer = subprocess.run(
            ['openssl', 'x509', '-noout', '-issuer'],
            capture_output=True,
            input=cert
        )
        actual_issuer = actual_issuer.stdout.rstrip().decode()
    assert actual_issuer == issuer, "Issuer name is not {}".format(issuer)

def validateSerial(cert, serial):
    actual_serial = getSerial(cert)
    assert actual_serial == serial, "Serial is not {}".format(serial)

def checkStartDate(cert):
    start_date_op = subprocess.run(
        ['openssl', 'x509', '-noout', '-startdate'],
        capture_output=True,
        input=cert
    )
    start_date = start_date_op.stdout.decode().split('=')[1]
    start_date_parts = start_date.split()
    assert (
        int(start_date_parts[1]) == datetime.datetime.utcnow().day and \
        start_date_parts[0] == datetime.datetime.utcnow().strftime("%b") and \
        int(start_date_parts[3]) == datetime.datetime.utcnow().year
    ), "Start date is not today - {}".format(start_date)

def checkEndDate(cert, validity):
    end_date_op = subprocess.run(
        ['openssl', 'x509', '-noout', '-enddate'],
        capture_output=True,
        input=cert
    )
    end_date = end_date_op.stdout.decode().split('=')[1]
    end_date_parts = end_date.split()
    expected_end_date = datetime.datetime.utcnow() + datetime.timedelta(days=validity)
    assert (
        int(end_date_parts[1]) == expected_end_date.day and \
        end_date_parts[0] == expected_end_date.strftime("%b") and \
        int(end_date_parts[3]) == expected_end_date.year
    ), "Start date is not today - {}".format(end_date)

def checkCA(cert):
    x509 = subprocess.run(
        ['openssl', 'x509', '-text'],
        capture_output=True,
        input=cert
    )
    return 'CA:TRUE' in x509.stdout.decode()

def checkCAPathlen(cert, pathlen=-1):
    x509 = subprocess.run(
        ['openssl', 'x509', '-text'],
        capture_output=True,
        input=cert
    )
    if pathlen>=0:
        assert f'pathlen:{pathlen}' in x509.stdout.decode(), "Mismatched pathlen"
    else:
        assert 'pathlen' not in x509.stdout.decode(), "pathlen present for negative val"

def checkExtension(cert, extension):
    x509 = subprocess.run(
        ['openssl', 'x509', '-text'],
        capture_output=True,
        input=cert
    )
    return extension in x509.stdout.decode()

def validateSelfSigned(cert):
    self_signed = subprocess.run(
        ['openssl', 'verify', '-check_ss_sig'],
        capture_output=True,
        input=cert
    )
    return 'OK' in self_signed.stdout.decode()

def validateCert(cert, ca):
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as caFd:
            caFd.write(ca)
        is_signed = subprocess.run(
            ['openssl', 'verify', '-CAfile', path],
            capture_output=True,
            input=cert
        )
        return 'OK' in is_signed.stdout.decode()
    finally:
        os.remove(path)

def convertP12ToPem(cert, passwd):
    fp, path = tempfile.mkstemp()
    try:
        if passwd == '' and HOST_PLATFORM_OS == b'Ubuntu' and HOST_PLATFORM_VERSION == b'20.04':

            # This if block has been added to support UTs for u20. openssl 1.1.1 does not seem to accept python empty string as valid empty password
            pem_out = subprocess.run(
                    ['openssl', 'pkcs12', '-passin', 'pass:', '--passout', 'pass:{}', '-out', path],
                capture_output=True,
                input=cert
            )
        else:
            pem_out = subprocess.run(
                ['openssl', 'pkcs12', '-passin', 'pass:{}'.format(passwd), '-passout', 'pass:{}'.format(passwd), '-out', path],
                capture_output=True,
                input=cert
            )
        assert pem_out.returncode == 0, 'Unable to convert PKCS12 to PEM'
        with open(path, 'rb') as certFp:
            return certFp.read()
    finally:
        os.remove(path)

def matchPemCerts(cert1, cert2):
    pub_key1 = subprocess.run(
        ['openssl', 'pkey'],
        capture_output=True,
        input=cert1
    )
    assert pub_key1.returncode == 0, 'Unable to get private key for certificate'
    pub_key2 = subprocess.run(
        ['openssl', 'pkey'],
        capture_output=True,
        input=cert2
    )
    assert pub_key2.returncode == 0, 'Unable to get private key for certificate'
    assert pub_key1.stdout == pub_key2.stdout, "Private key does not match"

    x509_1 = subprocess.run(
        ['openssl', 'x509'],
        capture_output=True,
        input=cert1
    )
    assert x509_1.returncode == 0, "Unable to parse certificate"
    x509_2 = subprocess.run(
        ['openssl', 'x509'],
        capture_output=True,
        input=cert2
    )
    assert x509_2.returncode == 0, "Unable to parse certificate"
    assert x509_1.stdout == x509_2.stdout, "Certificates dont match"

def getSerial(cert):
    serial = subprocess.run(
        ['openssl', 'x509', '-noout', '-serial'],
        capture_output=True,
        input=cert
    )
    return serial.stdout.rstrip().decode()
