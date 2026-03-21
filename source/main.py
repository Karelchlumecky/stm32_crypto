"""
Tool for generation and work with SHA256 hash and RSA encryption
For STM32.
"""

import argparse
from intelhex import IntelHex
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

class DebugInfo:
    Verbosity = False

    @classmethod
    def set_verbosity(cls, arg_verbosity):
        cls.Verbosity = arg_verbosity

    @classmethod
    def debug_print(cls, arg_text):
        if cls.Verbosity:
            print(arg_text)

class VaribleBank:
    Sign_address = 0
    S_address = 0
    E_address = 0
    Hex_file = ""
    Action = ""
    Hash = ""
    Public_key_file_pem = ""
    Private_key_file_pem = ""

    @classmethod
    def load_args(cls, args):
        if args.sign:
            cls.Action = "Sign"
            (cls.Hex_file,
             cls.Sign_address,
             cls.S_address,
             cls.E_address,
             cls.Hash,
             cls.Private_key_file_pem) = args.sign

        elif args.authenticate:
            cls.Action = "Authenticate"
            (cls.Hex_file,
             cls.Sign_address,
             cls.S_address,
             cls.E_address,
             cls.Hash,
             cls.Public_key_file_pem) = args.verify

        elif args.generate:
            cls.Action = "Generate"
            (cls.Private_key_file_pem,
             cls.Public_key_file_pem) = args.generate

        elif args.print:
            cls.Action = "Print"

    @classmethod
    def get_args(cls):
        return f"""
              Action: {cls.Action}
              Hex: {cls.Hex_file}
              Sign Address: {cls.Sign_address}
              Start Address: {cls.S_address}
              End Address: {cls.E_address}
              Hash: {cls.Hash}
              Private key: {cls.Private_key_file_pem}
              Public key: {cls.Public_key_file_pem}"""

def print_supported_hashes():
    print("""
        Hashes:
        SHA224, SHA256, SHA384, SHA512,
        SHA3-224, SHA3-256, SHA3-384, SHA3-512,
        SHAKE128_X -> X = Number of bytes
        SHAKE256_X -> X = Number of bytes
          
        Encryption:
        Asymetrical RSA-2048
    """)

def choose_hash():
    if VaribleBank.Hash == "SHA224":
        return hashes.SHA224()
    elif VaribleBank.Hash == "SHA256":
        return hashes.SHA256()
    elif VaribleBank.Hash == "SHA384":
        return hashes.SHA384()
    elif VaribleBank.Hash == "SHA512":
        return hashes.SHA512()
    elif VaribleBank.Hash == "SHA3-224":
        return hashes.SHA3_224()
    elif VaribleBank.Hash == "SHA3-256":
        return hashes.SHA3_256()
    elif VaribleBank.Hash == "SHA3-384":
        return hashes.SHA3_384()
    elif VaribleBank.Hash == "SHA3-512":
        return hashes.SHA3_512()
    elif "SHAKE128" in VaribleBank.Hash:
        _, size = VaribleBank.Hash.split("_")
        return hashes.SHAKE128(size)
    elif "SHAKE256" in VaribleBank.Hash:
        _, size = VaribleBank.Hash.split("_")
        return hashes.SHAKE256(size)
    else:
        print("Wrong hash choosed")

def authenticate():
    print("nvm")

def sign():
    ih = IntelHex(VaribleBank.Hex_file)
    data = ih.tobinarray(int(VaribleBank.S_address, 16), int(VaribleBank.E_address, 16))

def generate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open(VaribleBank.Private_key_file_pem, "wb") as file:
        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(VaribleBank.Public_key_file_pem, "wb") as file:
        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def parse_input_params():

    parser = argparse.ArgumentParser("Cyber security program")

    pars_group = parser.add_mutually_exclusive_group(required=True)
    pars_group.add_argument("-g", "--generate", nargs = 2,
                            metavar = ("Private_key_file", "Public_key_file"),
                            help = "Generate private and public key")
    pars_group.add_argument("-s", "--sign", nargs=6,
                        metavar = ("Hex_file", "Sign_address", "Start_address",
                                   "End_address", "Hash", "Private_key_file"),
                        help="Sign your program")
    pars_group.add_argument("-a", "--authenticate", nargs=6,
                        metavar = ("Hex_file", "Sign_address", "Start_address",
                                    "End_address", "Hash", "Public_key_file"),
                        help="authenticate your program")
    pars_group.add_argument("-p", "--print", action="store_true",
                            help = "Print all supported hashes")
    parser.add_argument("-v", "--verbosity", action="store_true",
                        help="Make the program more loud")

    args = parser.parse_args()
    DebugInfo.set_verbosity(args.verbosity)
    VaribleBank.load_args(args)

def main():
    parse_input_params()
    DebugInfo.debug_print(VaribleBank.get_args())

    if VaribleBank.Action == "Sign":
        sign()

    elif VaribleBank.Action == "Authenticate":
        authenticate()

    elif VaribleBank.Action == "Generate":
        generate()

    elif VaribleBank.Action == "Print":
        print_supported_hashes()

    else:
        print("Unrecognized action")

if __name__ == "__main__":
    main()
