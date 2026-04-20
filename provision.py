import qrcode
import yaml
import argparse
import base64
import json
import os
import sys
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuration de l'URL de base
BASE_URL = "https://qr-password.gordios.net/"

def derive_key(password: str, salt: bytes) -> bytes:
    """Dérivation de clé simple et identique au JavaScript (SHA256)."""
    hash_gen = hashlib.sha256()
    hash_gen.update(password.encode('utf-8') + salt)
    return hash_gen.digest()

def generate_payload(data_dict, password):
    """Chiffre les données en AES-CTR avec un Salt et un Nonce de 16 octets."""
    salt = os.urandom(16)
    nonce = os.urandom(16)
    key = derive_key(password, salt)
    
    # Configuration AES-CTR
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    
    # Préparation du JSON compact
    data_json = json.dumps(data_dict, separators=(',', ':')).encode('utf-8')
    ciphertext = encryptor.update(data_json) + encryptor.finalize()
    
    # Pack: Salt(16) + Nonce(16) + Ciphertext
    packed_data = salt + nonce + ciphertext
    return base64.b64encode(packed_data).decode('utf-8')

def main():
    # --- PASSAGE 1 : Récupération du schéma ---
    initial_parser = argparse.ArgumentParser(add_help=False)
    initial_parser.add_argument("-s", "--schema", required=True)
    
    try:
        temp_args, remaining_argv = initial_parser.parse_known_args()
    except:
        print("Erreur : L'argument -s/--schema est obligatoire.")
        sys.exit(1)

    # Chargement du fichier YAML
    try:
        with open(temp_args.schema, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            schema = config.get('schema', {})
            id_field = config.get('identity_field', 'id')
    except Exception as e:
        print(f"Erreur lors de la lecture du schéma : {e}")
        sys.exit(1)

    # --- PASSAGE 2 : Parser dynamique ---
    parser = argparse.ArgumentParser(description=f"Gordios Universal Provisioner - Schema: {temp_args.schema}")
    parser.add_argument("-s", "--schema", help="Déjà chargé", dest="duplicate_schema")
    parser.add_argument("--yubi-secret", required=True, help="Secret Yubikey")
    parser.add_argument("--backup-pass", required=True, help="Secret de secours")

    # Ajout des arguments définis dans le YAML
    for field, specs in schema.items():
        arg_type = int if specs.get('type') == 'int' else str
        parser.add_argument(f"--{field}", type=arg_type, required=True, help=specs.get('help', ''))

    args = parser.parse_args(remaining_argv)

    # --- TRAITEMENT DES DONNÉES ---
    
    # 1. On récupère la valeur pour le nom du fichier image (ex: nom de la ferme)
    file_id_value = getattr(args, id_field, "export")

    # 2. On construit le dictionnaire chiffré en utilisant 'help' comme clé
    data_to_encrypt = {}
    for field, specs in schema.items():
        valeur_saisie = getattr(args, field)
        display_label = specs.get('help', field) # Utilise 'help', sinon le nom technique
        data_to_encrypt[display_label] = valeur_saisie

    # 3. Génération des payloads chiffrés
    payload_yubi = generate_payload(data_to_encrypt, args.yubi_secret)
    payload_backup = generate_payload(data_to_encrypt, args.backup_pass)
    
    # Construction de l'URL finale
    final_url = f"{BASE_URL}#{payload_yubi}.{payload_backup}"

    # 4. Génération du QR Code
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4
    )
    qr.add_data(final_url)
    qr.make(fit=True)
    
    # Sauvegarde de l'image
    filename = f"qr_{file_id_value}.png"
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    
    print(f"\n--- GÉNÉRATION RÉUSSIE ---")
    print(f"Schéma utilisé   : {temp_args.schema}")
    print(f"Identifiant      : {file_id_value}")
    print(f"Fichier créé     : {filename}")
    print(f"Données incluses :")
    for label in data_to_encrypt.keys():
        print(f"  - {label}")

if __name__ == "__main__":
    main()
