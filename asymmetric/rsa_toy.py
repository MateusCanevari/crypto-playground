#!/usr/bin/env python3
"""
RSA (toy) - implementação educacional.
NÃO usar em produção (sem padding seguro, sem tamanho de chave adequado, etc).
"""

import argparse
import base64
import secrets
from dataclasses import dataclass


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Sem inverso modular.")
    return x % m


def is_probable_prime(n: int, k: int = 16) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False

    # Miller-Rabin
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    if bits < 256:
        raise ValueError("bits muito baixo para demonstração. Use >= 256 (toy).")
    while True:
        candidate = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if is_probable_prime(candidate):
            return candidate


@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    d: int


def keygen(bits: int = 512, e: int = 65537):
    half = bits // 2
    p = gen_prime(half)
    q = gen_prime(half)
    while q == p:
        q = gen_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    if phi % e == 0:
        return keygen(bits, e)

    d = modinv(e, phi)
    return PublicKey(n=n, e=e), PrivateKey(n=n, d=d)


def sign_int(m: int, priv: PrivateKey) -> int:
    return pow(m, priv.d, priv.n)


def verify_int(sig: int, pub: PublicKey) -> int:
    return pow(sig, pub.e, pub.n)


def hash_to_int_sha256(data: bytes) -> int:
    import hashlib
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big")


def main() -> None:
    p = argparse.ArgumentParser(description="RSA toy: keygen + sign/verify (educacional).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keygen", help="Gera chaves RSA (toy) e imprime em base64url")
    pk.add_argument("--bits", type=int, default=512, help="Tamanho total da chave (default: 512)")

    ps = sub.add_parser("sign", help="Assina SHA-256(file) e imprime assinatura base64url")
    ps.add_argument("--n", required=True, help="n em decimal")
    ps.add_argument("--d", required=True, help="d em decimal")
    ps.add_argument("--file", required=True, help="Arquivo a assinar")

    pv = sub.add_parser("verify", help="Verifica assinatura: compara SHA-256(file) com RSA(pub, sig)")
    pv.add_argument("--n", required=True, help="n em decimal")
    pv.add_argument("--e", required=True, help="e em decimal")
    pv.add_argument("--sig-b64", required=True, help="assinatura em base64url")
    pv.add_argument("--file", required=True, help="Arquivo a verificar")

    args = p.parse_args()

    if args.cmd == "keygen":
        pub, priv = keygen(bits=args.bits)
        print("Public:")
        print(f"n={pub.n}")
        print(f"e={pub.e}")
        print("Private:")
        print(f"n={priv.n}")
        print(f"d={priv.d}")
        return

    file_bytes = open(args.file, "rb").read()
    m = hash_to_int_sha256(file_bytes)

    if args.cmd == "sign":
        priv = PrivateKey(n=int(args.n), d=int(args.d))
        sig_int = sign_int(m, priv)
        sig_bytes = sig_int.to_bytes((sig_int.bit_length() + 7) // 8, "big")
        print(f"sig_b64={b64e(sig_bytes)}")

    elif args.cmd == "verify":
        pub = PublicKey(n=int(args.n), e=int(args.e))
        sig_bytes = b64d(args.sig_b64)
        sig_int = int.from_bytes(sig_bytes, "big")
        recovered = verify_int(sig_int, pub)

        if recovered == m:
            print("OK: assinatura válida (toy).")
        else:
            print("ERRO: assinatura inválida!")
            raise SystemExit(1)


if __name__ == "__main__":
    main()
