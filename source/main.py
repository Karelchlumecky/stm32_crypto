"""
Tool for generation and work with SHA256 hash and RSA encryption
For STM32.
"""

import os
import argparse
from intelhex import IntelHex
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
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
             cls.Private_key_file_pem,
             cls.Public_key_file_pem) = args.sign

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

def string_to_hex_file(hex_obj, data, address, length):
    if isinstance(address, str):
        address = int(address, 16)

    if isinstance(data, bytes):
        if len(data) != length:
            raise ValueError("Wrong data length")
        hex_obj.frombytes(data, offset=address)
        return

    if isinstance(data, str):
        value = int(data, 16)
    else:
        value = int(data)

    if value >= (1 << (length * 8)):
        raise ValueError("Wrong data length")

    hex_obj.frombytes(value.to_bytes(length, "little"), offset=address)

def authenticate():
    ih = IntelHex(VaribleBank.Hex_file)


def sign():
    ih = IntelHex(VaribleBank.Hex_file)
    start_address = int(VaribleBank.S_address, 16)
    end_address = int(VaribleBank.E_address, 16)
    data = ih.tobinarray(start = start_address, end = end_address)
    DebugInfo.debug_print(f"""
        Header start: {hex(int(VaribleBank.Sign_address, 16))}
        start: {hex(start_address)}
        end:   {hex(end_address)}
        len:   {hex(len(data))}
    """)

    hash_func = hashes.Hash(choose_hash())
    hash_func.update(data)
    hashed_hex = hash_func.finalize()

    with open(VaribleBank.Private_key_file_pem, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    signature = private_key.sign(
        hashed_hex,
        padding.PKCS1v15(),
        Prehashed(choose_hash())
    )

    offset = int(VaribleBank.Sign_address, 16)
    string_to_hex_file(ih, "0x12345678", offset, 4)
    string_to_hex_file(ih, VaribleBank.S_address, offset + 0x10, 4)
    string_to_hex_file(ih, VaribleBank.E_address, offset + 0x14, 4)
    string_to_hex_file(ih, signature, offset + 0x20, 256)

    with open(VaribleBank.Public_key_file_pem, "rb") as f:
        pem_data = f.read()

    public_key = serialization.load_pem_public_key(pem_data)

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Not RSA key")

    numbers = public_key.public_numbers()
    n = numbers.n  # modulus
    e = numbers.e  # exponent

    modulus_bytes = n.to_bytes(256, byteorder="little")
    exponent_bytes = e.to_bytes(4, byteorder="little")

    string_to_hex_file(ih, exponent_bytes, offset + 0x130, 4)
    string_to_hex_file(ih, modulus_bytes, offset + 0x140, 256)

    base = os.path.basename(VaribleBank.Hex_file)
    name, ext = os.path.splitext(base)
    output_file = "../output/" + name + "_signed" + ext
    ih.write_hex_file(output_file)

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
    pars_group.add_argument("-s", "--sign", nargs=7,
                        metavar = ("Hex_file", "Sign_address", "Start_address",
                                   "End_address", "Hash", "Private_key_file", "Public_key_file"),
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
