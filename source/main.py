"""
Tool for generation and work with SHA256 hash and RSA encryption
For STM32.
"""

import argparse
from intelhex import IntelHex
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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

        elif args.verify:
            cls.Action = "Verify"
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

    @classmethod
    def print_args(cls):
        print(f"""
              Action: {cls.Action}
              Hex: {cls.Hex_file}
              Sign Address: {cls.Sign_address}
              Start Address: {cls.S_address}
              End Address: {cls.E_address}
              Hash: {cls.Hash} 
              Private key:{cls.Private_key_file_pem}
              Public key: {cls.Public_key_file_pem}""")

def verify():
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
                            metavar = ("Private_key_file", "Public_key_file"))
    pars_group.add_argument("-s", "--sign", nargs=6,
                        metavar = ("Hex_file", "Sign_address", "Start_address",
                                   "End_address", "Hash", "Private_key_file"),
                        help="Sign your program")
    pars_group.add_argument("-v", "--verify", nargs=6,
                        metavar = ("Hex_file", "Sign_address", "Start_address",
                                    "End_address", "Hash", "Public_key_file"))
    args = parser.parse_args()
    VaribleBank.load_args(args)

def main():
    parse_input_params()
    VaribleBank.print_args()

    if VaribleBank.Action == "Sign":
        sign()

    elif VaribleBank.Action == "Verify":
        verify()

    elif VaribleBank.Action == "Generate":
        generate()

    else:
        print("Unrecognized action")

if __name__ == "__main__":
    main()
