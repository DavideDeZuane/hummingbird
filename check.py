import os
import re
import math 
import subprocess

files_to_reset = ['srv/log/charon.log', 'srv/log/ikev2_decryption_table', 'key.txt']

def clean_hex_string(line):
    cleaned_line = re.sub(r'(\s{2,}).*$', '', line)
    return cleaned_line

def reset_files(files):
    for file in files:
        with open(file, 'w') as f:
            f.write('')  # Scrive una stringa vuota nel file, troncandolo

def extract_relevant_content(input_text):
    # Split del testo in righe
    lines = input_text.splitlines()
    
    relevant_lines = []
    capturing = False  # Flag per sapere se siamo nella sezione da catturare

    # Iteriamo su tutte le righe
    for line in lines:
        # Inizia a catturare dalla riga che contiene 'key exchange secret'
        if re.search(r"key exchange secret\s*=>", line):
            capturing = True
        
        # Se siamo nella sezione da catturare, aggiungiamo la riga
        if capturing:
            relevant_lines.append(line)
        
        # Termina la cattura quando troviamo 'Sk_pr secret'
        if re.search(r"message parsing failed*", line):
            capturing = False

    return "\n".join(relevant_lines)

def extract_and_modify_ike_lines(input_text):
    # Dividiamo il testo in righe
    lines = input_text.splitlines()
    
    # Lista per memorizzare le righe modificate
    modified_lines = []
    
    # Iteriamo su ogni riga
    for line in lines:
        # Se la riga contiene [IKE], rimuoviamo il prefisso numerico e [IKE]
        if '[IKE]' in line:
            # Rimuoviamo il prefisso numerico e [IKE] dalla riga
            modified_line = re.sub(r"^\d+\[IKE\]\s*", "", line)  # Rimuove numeri iniziali e '[IKE]'
            modified_lines.append(modified_line)
    
    # Ritorniamo il testo modificato con le righe modificate
    return "\n".join(modified_lines)


def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def extract_key_lengths(input_text):
    
    lines = input_text.splitlines()
    shared_key = {}

    for line in lines:
        match = re.match(r"^(key exchange secret|SKEYSEED|Sk_[a-z]+ secret)\s*=>\s*(\d+)\s*bytes", line)
        if match:
            key_name = match.group(1)
            
            key_length = int(match.group(2))
            shared_key[key_name] = key_length

    return shared_key

def extract_key_values(input_text, key_lengths):
    lines = input_text.splitlines()
    key_values = {}

    i = 0
    while i < len(lines):
        line = lines[i]

        # Verifica se la riga contiene una chiave
        match = re.match(r"^(key exchange secret|SKEYSEED|Sk_[a-z]+ secret)\s*=>\s*(\d+)\s*bytes", line)
        if match:
            key_name = match.group(1).strip()  # Nome della chiave
            key_name = re.sub(r"\bsecret\b", "", key_name).strip()
            key_length = int(match.group(2))  # Lunghezza della chiave

            # Calcola quante righe leggere in base alla lunghezza della chiave
            num_lines = (key_length + 15) // 16  # Divisione arrotondata per 16 righe

            hex_value = ""

            # Leggi le righe per il valore esadecimale
            for j in range(i + 1, i + 1 + num_lines):
                if j < len(lines):  # Assicurati di non superare la fine delle righe
                    line_data = lines[j]
                    cleaned_line = clean_hex_string(line_data)  # Pulisci la riga
                    # Estrai la parte esadecimale dopo "0:"
                    hex_value += ' '.join(re.findall(r'[0-9A-Fa-f]{2}', cleaned_line.split(":", 1)[1]))

            # Aggiungi il valore esadecimale nel dizionario
            hex_value = re.sub(r"\s+", "", hex_value)
            key_values[key_name] = hex_value

            # Salta le righe già lette
            i += num_lines
        else:
            i += 1  # Vai alla riga successiva se non è una chiave

    return key_values


if __name__ == "__main__":
    # call to reset file
    log_file = "srv/log/charon.log"
    input_text = read_file(log_file)
    
    extracted_content = extract_and_modify_ike_lines(input_text)
    parse = extract_relevant_content(extracted_content)
    key_lengths = extract_key_lengths(parse)
    key_values = extract_key_values(parse, key_lengths)

    print("\n")
    print("##################################################")
    print("Keys from srv/log/charon.log")
    print("##################################################")

    for key_name, hex_value in key_values.items():
        print(f"{key_name}: \t{hex_value}")
