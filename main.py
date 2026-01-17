import argparse
import sys
import os
from avax_crypt import AvaxCipher

def main():
    parser = argparse.ArgumentParser(
        description="AvaxCrypt: A tool to hide and encrypt files inside other files."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- 'hide' command arguments ---
    hide_parser = subparsers.add_parser("hide", help="Hide a secret file inside a cover file")
    hide_parser.add_argument("-c", "--cover", required=True, help="Path to the cover file (e.g., image.jpg)")
    hide_parser.add_argument("-s", "--secret", required=True, help="Path to the secret file to hide")
    hide_parser.add_argument("-p", "--password", required=True, help="Password for encryption")
    hide_parser.add_argument("-o", "--output", help="Path for the output file (optional)")

    # --- 'extract' command arguments ---
    extract_parser = subparsers.add_parser("extract", help="Extract a secret file from a avax file")
    extract_parser.add_argument("-f", "--file", required=True, help="Path to the avax file containing hidden data")
    extract_parser.add_argument("-p", "--password", required=True, help="Password for decryption")
    extract_parser.add_argument("-d", "--outdir", default=".", help="Directory to save extracted file (default: current dir)")

    args = parser.parse_args()
    cipher = AvaxCipher()

    try:
        if args.command == "hide":
            # Auto-generate output filename if not provided
            output_path = args.output
            if not output_path:
                base, ext = os.path.splitext(args.cover)
                output_path = f"{base}_avax{ext}"

            print(f"[*] Encrypting and hiding data...")
            cipher.hide(args.cover, args.secret, output_path, args.password)
            print(f"[+] Success! Output saved to: {output_path}")

        elif args.command == "extract":
            print(f"[*] Attempting to decrypt and extract...")
            saved_name = cipher.extract(args.file, args.password, args.outdir)
            print(f"[+] Success! Extracted file: {saved_name}")

    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()