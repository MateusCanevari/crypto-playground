import argparse
import base64
import hashlib
import hmac
import os
from pathlib import Path

CHUNK_SIZE = 1024 * 1024
DEFAULT_ALGO = "sha256"

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def compute_hmac(path: Path, key: bytes, algo: str) -> bytes:
    mac = hmac.new(key, digestmod=algo)
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            mac.update(chunk)
    return mac.digest()

def main() -> None:
    p = argparse.ArgumentParser(description="Assina e verifica arquivos usando HMAC.")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("sign", help="Gera HMAC do arquivo")
    ps.add_argument("file", help="Arquivo a assinar")
    ps.add_argument("--key-b64", help="Chave em base64url (se não informar, gera uma)")
    ps.add_argument("--algo", default=DEFAULT_ALGO, help="Algoritmo de hash (default: sha256)")

    pv = sub.add_parser("verify", help="Verifica HMAC do arquivo")
    pv.add_argument("file", help="Arquivo a verificar")
    pv.add_argument("--key-b64", required=True, help="Chave em base64url")
    pv.add_argument("--mac-b64", required=True, help="HMAC esperado em base64url")
    pv.add_argument("--algo", default=DEFAULT_ALGO, help="Algoritmo de hash (default: sha256)")

    args = p.parse_args()
    path = Path(args.file)

    if not path.exists() or not path.is_file():
        raise SystemExit("Arquivo não encontrado (ou não é arquivo).")

    if args.cmd == "sign":
        if args.key_b64:
            key = b64d(args.key_b64)
            generated = False
        else:
            key = os.urandom(32)  # 256 bits
            generated = True

        mac_bytes = compute_hmac(path, key, args.algo)
        print(f"algo={args.algo}")
        if generated:
            print(f"key_b64={b64e(key)}")
        print(f"mac_b64={b64e(mac_bytes)}")

    elif args.cmd == "verify":
        key = b64d(args.key_b64)
        expected = b64d(args.mac_b64)
        actual = compute_hmac(path, key, args.algo)

        if hmac.compare_digest(expected, actual):
            print("OK: HMAC válido (integridade e autenticidade confirmadas).")
        else:
            print("ERRO: HMAC inválido!")
            raise SystemExit(1)

if __name__ == "__main__":
    main()
