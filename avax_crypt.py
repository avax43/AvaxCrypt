import os
import struct
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AvaxCipher:
    """
    A class to handle AES-256 encryption and steganographic hiding of files.
    """

    # Magic bytes to identify the start of hidden data (Hex signature)
    SEPARATOR = b'\x41\x56\x41\x58\x5F\x45\x4E\x44'  # "AVAX_END" in ASCII
    SALT_SIZE = 16
    NONCE_SIZE = 12
    ITERATIONS = 100_000

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derives a 32-byte key from the password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=AvaxCipher.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def hide(self, cover_path: str, secret_path: str, output_path: str, password: str) -> None:
        """
        Encrypts a secret file and appends it to a cover file.
        """
        if not os.path.exists(cover_path):
            raise FileNotFoundError(f"Cover file '{cover_path}' not found.")
        if not os.path.exists(secret_path):
            raise FileNotFoundError(f"Secret file '{secret_path}' not found.")

        # 1. Read secret file and prepare metadata
        filename = os.path.basename(secret_path).encode('utf-8')
        with open(secret_path, 'rb') as f:
            secret_data = f.read()

        # Pack metadata: [Name Length (4 bytes)] + [Filename] + [File Content]
        packed_data = struct.pack(f'I{len(filename)}s', len(filename), filename) + secret_data

        # 2. Prepare encryption
        salt = os.urandom(self.SALT_SIZE)
        key = self._derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(self.NONCE_SIZE)

        # Encrypt the packed data (metadata + content)
        encrypted_data = aesgcm.encrypt(nonce, packed_data, None)

        # 3. Read cover and append data
        with open(cover_path, 'rb') as f:
            cover_data = f.read()

        # Final layout: [Cover] + [Separator] + [Salt] + [Nonce] + [Encrypted Blob]
        final_payload = cover_data + self.SEPARATOR + salt + nonce + encrypted_data

        with open(output_path, 'wb') as f:
            f.write(final_payload)

    def extract(self, avax_path: str, password: str, output_dir: str = ".") -> str:
        """
        Extracts and decrypts a hidden file from a avax file.
        Returns the name of the extracted file.
        """
        if not os.path.exists(avax_path):
            raise FileNotFoundError(f"Avax file '{avax_path}' not found.")

        with open(avax_path, 'rb') as f:
            file_data = f.read()

        # 1. Locate the hidden data
        split_index = file_data.rfind(self.SEPARATOR)
        if split_index == -1:
            raise ValueError("No hidden data found in this file.")

        hidden_block_start = split_index + len(self.SEPARATOR)
        hidden_data = file_data[hidden_block_start:]

        # 2. Extract components
        if len(hidden_data) < (self.SALT_SIZE + self.NONCE_SIZE):
            raise ValueError("Corrupted data block.")

        salt = hidden_data[:self.SALT_SIZE]
        nonce = hidden_data[self.SALT_SIZE : self.SALT_SIZE + self.NONCE_SIZE]
        ciphertext = hidden_data[self.SALT_SIZE + self.NONCE_SIZE :]

        # 3. Decrypt
        key = self._derive_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            decrypted_payload = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Decryption failed. Incorrect password or corrupted data.")

        # 4. Unpack metadata and save file
        # Read the first 4 bytes to get the filename length
        filename_len = struct.unpack('I', decrypted_payload[:4])[0]
        
        # Extract filename and content
        filename = decrypted_payload[4 : 4 + filename_len].decode('utf-8')
        original_content = decrypted_payload[4 + filename_len :]

        output_path = os.path.join(output_dir, filename)
        
        with open(output_path, 'wb') as f:
            f.write(original_content)

        return filename