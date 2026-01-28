#!/usr/bin/env python3
import argparse

def sanitize(s: str) -> str:
    # remove carriage return que pode vir em copy/paste no Windows
    return s.replace("\r", "")

def caesar_shift(text: str, shift: int) -> str:
    shift %= 26
    out = []

    for ch in text:
        o = ord(ch)

        # A-Z
        if 65 <= o <= 90:
            out.append(chr(((o - 65 + shift) % 26) + 65))
        # a-z
        elif 97 <= o <= 122:
            out.append(chr(((o - 97 + shift) % 26) + 97))
        else:
            out.append(ch)

    return "".join(out)

def main() -> None:
    p = argparse.ArgumentParser(description="Cifra de César (educacional).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encrypt", help="Criptografa com deslocamento (shift)")
    pe.add_argument("--shift", type=int, required=True, help="Deslocamento (ex: 3)")
    pe.add_argument("--text", required=True, help="Texto para criptografar")

    pd = sub.add_parser("decrypt", help="Descriptografa com deslocamento (shift)")
    pd.add_argument("--shift", type=int, required=True, help="Deslocamento usado na cifra")
    pd.add_argument("--text", required=True, help="Texto para descriptografar")

    pb = sub.add_parser("bruteforce", help="Tenta todos shifts (0..25) no texto cifrado")
    pb.add_argument("--text", required=True, help="Texto para brute force")

    args = p.parse_args()
    text = sanitize(args.text)

    if args.cmd == "encrypt":
        print(caesar_shift(text, args.shift))

    elif args.cmd == "decrypt":
        print(caesar_shift(text, -args.shift))

    elif args.cmd == "bruteforce":
        # para cada shift, aplicamos "decrypt" equivalente = shift negativo
        for s in range(26):
            candidate = caesar_shift(text, -s)
            print(f"shift={s:2d}: {candidate}")

if __name__ == "__main__":
    main()
