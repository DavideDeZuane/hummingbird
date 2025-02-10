#!/usr/bin/env python3

import csv
import sys

def parse_ikev2_keys(input_file, output_file):
    try:
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
            reader = csv.reader(infile)
            for row in reader:
                if len(row) < 8:
                    continue  # Salta righe incomplete
                spi_i, spi_r, sk_ei, sk_er, enc_alg, sk_ai, sk_ar, auth_alg = row
                
                # Scrive le chiavi derivate nel file di output con i loro nomi e algoritmi
                outfile.write(f"SK_ei: {sk_ei}\n")
                outfile.write(f"SK_er: {sk_er}\n")
                outfile.write(f"SK_ai: {sk_ai}\n")
                outfile.write(f"SK_ar: {sk_ar}\n")
                outfile.write(f"Encryption Algorithm: {enc_alg}\n")
                outfile.write(f"Authentication Algorithm: {auth_alg}\n\n")
        print(f"Chiavi derivate estratte in: {output_file}")
    except Exception as e:
        print(f"Errore: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Uso: {sys.argv[0]} <file_di_input> <file_di_output>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    parse_ikev2_keys(input_file, output_file)

