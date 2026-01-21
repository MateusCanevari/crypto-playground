#!/usr/bin/env python3
import argparse
import base64
import hashlib
import os
from dataclasses import dataclass

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

@dataclass
class KDFOutput:
    salt_b64: str
    key_b64: str

def derive_pbkdf2(password: str, salt: bytes, iterations: int, dklen: int, algo: str) -> bytes:
    if iterations < 10_000:
        #em produção normalmente é bem maior (ex: 100k+), depende de política/performance
        raise ValueError("iterations muito baixo. Use >= 10000 (preferível 100000+).")
    pw_bytes = password.encode("utf-8")
    return hashlib.pbkdf2_hmac(algo, pw_bytes, salt, iterations, dklen=dklen)

def main() -> None:
    p = argparse.ArgumentParser(description="PBKDF2 (hashlib.pbkdf2_hmac) - derivação de chave a partir de senha.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pg = sub.add_parser("gen-salt", help="Gera um salt aleatório (base64url)")
    pg.add_argument("--bytes", type=int, default=16, help="Tamanho do salt em bytes (default: 16)")

    pd = sub.add_parser("derive", help="Deriva uma chave usando PBKDF2-HMAC")
    pd.add_argument("--password", required=True, help="Senha (use com cuidado em histórico de terminal)")
    pd.add_argument("--salt-b64", help="Salt em base64url (se não passar, gera automaticamente)")
    pd.add_argument("--iterations", type=int, default=200_000, help="Iterações (default: 200000)")
    pd.add_argument("--dklen", type=int, default=32, help="Tamanho da chave derivada em bytes (default: 32)")
    pd.add_argument("--algo", default="sha256", choices=["sha256", "sha512"], help="Hash subjacente (default: sha256)")

    args = p.parse_args()

    if args.cmd == "gen-salt":
        salt = os.urandom(args.bytes)
        print(b64e(salt))
        return

    # derive
    if args.salt_b64:
        salt = b64d(args.salt_b64)
        generated = False
    else:
        salt = os.urandom(16)
        generated = True

    key = derive_pbkdf2(
        password=args.password,
        salt=salt,
        iterations=args.iterations,
        dklen=args.dklen,
        algo=args.algo,
    )

    print(f"algo={args.algo}")
    print(f"iterations={args.iterations}")
    print(f"dklen={args.dklen}")
    if generated:
        print(f"salt_b64={b64e(salt)}")
    else:
        print(f"salt_b64={args.salt_b64}")
    print(f"key_b64={b64e(key)}")

if __name__ == "__main__":
    main()
