import argparse
import base64
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def gen_key(size: int) -> bytes:
    if size not in (16, 24, 32):
        raise ValueError("Tamanho inválido. Use 16/24/32 bytes (128/192/256 bits).")
    return os.urandom(size)


def encrypt_bytes(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> tuple[bytes, bytes]:
    if len(key) not in (16, 24, 32):
        raise ValueError("Chave AES inválida. Use 16/24/32 bytes.")
    nonce = os.urandom(12)  # recomendado no GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct  # ct já inclui TAG (no final)


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("Chave AES inválida. Use 16/24/32 bytes.")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def read_input(text: Optional[str], infile: Optional[str]) -> bytes:
    if infile:
        return Path(infile).read_bytes()
    if text is not None:
        return text.encode("utf-8")
    raise SystemExit("Use --in <arquivo> OU --text <texto>.")


def write_output(data: bytes, outfile: Optional[str]) -> None:
    if outfile:
        Path(outfile).write_bytes(data)
    else:
        try:
            print(data.decode("utf-8"))
        except UnicodeDecodeError:
            print(b64e(data))


def main() -> None:
    p = argparse.ArgumentParser(description="AES-GCM encrypt/decrypt (exemplo correto e didático).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pg = sub.add_parser("gen-key", help="Gera uma chave AES e imprime em base64url")
    pg.add_argument("--bytes", type=int, default=32, help="16/24/32 (default: 32)")

    pe = sub.add_parser("encrypt", help="Criptografa (AES-GCM) e imprime nonce/ct em base64url")
    pe.add_argument("--key-b64", required=True, help="Chave AES em base64url")
    pe.add_argument("--in", dest="infile", help="Arquivo de entrada (opcional)")
    pe.add_argument("--text", help="Texto de entrada (opcional)")
    pe.add_argument("--aad", help="AAD opcional (texto) para autenticação extra")

    pd = sub.add_parser("decrypt", help="Descriptografa (AES-GCM) e retorna o plaintext")
    pd.add_argument("--key-b64", required=True, help="Chave AES em base64url")
    pd.add_argument("--nonce-b64", required=True, help="Nonce em base64url")
    pd.add_argument("--ct-b64", required=True, help="Ciphertext+tag em base64url")
    pd.add_argument("--aad", help="AAD opcional (texto) usado na criptografia")
    pd.add_argument("--out", dest="outfile", help="Arquivo de saída (opcional)")

    args = p.parse_args()

    if args.cmd == "gen-key":
        key = gen_key(args.bytes)
        print(b64e(key))
        return

    key = b64d(args.key_b64)

    if args.cmd == "encrypt":
        plaintext = read_input(args.text, args.infile)
        aad = args.aad.encode("utf-8") if args.aad else None
        nonce, ct = encrypt_bytes(key, plaintext, aad=aad)
        print(f"nonce_b64={b64e(nonce)}")
        print(f"ct_b64={b64e(ct)}")

    elif args.cmd == "decrypt":
        nonce = b64d(args.nonce_b64)
        ct = b64d(args.ct_b64)
        aad = args.aad.encode("utf-8") if args.aad else None
        pt = decrypt_bytes(key, nonce, ct, aad=aad)
        write_output(pt, args.outfile)


if __name__ == "__main__":
    main()


