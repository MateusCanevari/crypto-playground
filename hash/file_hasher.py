#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path

ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "md5": hashlib.md5,  
}

def hash_file(path: Path, algo: str, chunk_size: int = 1024 * 1024) -> str:
    """Calcula o hash do arquivo lendo em chunks para suportar arquivos grandes."""
    h = ALGORITHMS[algo]()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def main() -> None:
    p = argparse.ArgumentParser(
        description="Calcula hash de um arquivo (SHA256/SHA512/MD5).",
    )
    p.add_argument("file", help="Caminho do arquivo")
    p.add_argument("--algo", choices=ALGORITHMS.keys(), default="sha256", help="Algoritmo")
    p.add_argument("--chunk", type=int, default=1024 * 1024, help="Tamanho do chunk (bytes)")
    args = p.parse_args()

    path = Path(args.file)
    if not path.exists() or not path.is_file():
        raise SystemExit("Arquivo não encontrado (ou não é arquivo).")

    digest = hash_file(path, args.algo, args.chunk)
    print(f"{args.algo.upper()}  {digest}  {path}")

if __name__ == "__main__":
    main()
