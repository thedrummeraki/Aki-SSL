from M2Crypto.SMIME import *
from M2Crypto import *
import sys
import os.path as path

#######################

def verify(args, pkcs7_buff, ca_cert):
    if pkcs7_buff is None or len(pkcs7_buff) == 0:
        return 2

    bio = BIO.MemoryBuffer()
    bio.write(pkcs7_buff)
    pkcs7 = load_pkcs7_bio(bio)
    if pkcs7 is None:
        return 1

    cert_stack = X509.X509_Stack()
    signers = pkcs7.get0_signers(cert_stack)
    if len(signers) > 0:
        signer_cert = signers[0]
        subject = str(signer_cert.get_subject())
        issuer = str(signer_cert.get_issuer())

        # if the subject and the issuer are equal, then verify the
        # self-signed certificate
        if subject == issuer:
            self_signed_verify = pkcs7.verify_self_signed()
            return self_signed_verify
        else:
            if ca_cert is None:
                print "%s - Missing option -ca or invalid CA certificate file." % (args[0])
                print usage
                sys.exit(1)

            ca_certificate = M2Crypto.SMIME.X509.load_cert_string(ca_cert)
            # Check that the request is signed by the CA
            cert_stack = X509.X509_Stack()
            cert_store = X509.X509_Store()
            cert_store.add_x509(ca_certificate)
            pkcs7.verify(cert_stack, cert_store)
            return 0
    else:
        return 3

#######################

args = sys.argv

usage = '''
    Usage: python %s -in file.p7b -cert file.cert
''' % args[0]

if len(args) < 2:
    print usage
    sys.exit(1)

arg1 = args[1]
try:
    arg2 = args[3]
except:
    arg2 = None

if arg2 is None:
    if arg1 != '-in':
        print "%s - Invalid option: %s" % (args[0], arg1)
        print usage
        sys.exit(127)
else:
    if arg1 != "-in" or arg2 != "-in":
        print "%s - Missing option -in." % (args[0])
        print usage
        sys.exit(1)

if "-in" not in args:
    print "%s - Missing option -in." % (args[0])
    print usage
    sys.exit(1)

try:
    pkcs7_file = args[args.index("-in")+1]
except:
    print "%s - Missing file." % (args[0])
    print usage
    sys.exit(1)

if arg2 is not None:
    cert_file = args[args.index("-cert")+1]
else:
    cert_file = None

if not path.exists(pkcs7_file):
    print "%s - The file %s doesn't exist." % (args[0], pkcs7_file)
    sys.exit(2)

if cert_file is not None and not path.exists(cert_file):
    print "%s - The file %s doesn't exist." % (args[0], cert_file)
    sys.exit(2)

code = verify(
    args=args,
    pkcs7_buff=open(pkcs7_file).read(),
    ca_cert=open(cert_file).read() if cert_file is not None else None
)

sys.exit(code)