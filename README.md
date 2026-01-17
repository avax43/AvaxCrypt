# AvaxCrypt

**AvaxCrypt** is a CLI tool for encrypting and hiding files inside other files using steganography combined with AES-256-GCM encryption.

Hide sensitive data by embedding encrypted files within images, videos, or any other file format while maintaining the cover file's original functionality.

---

## Features

- **Strong Encryption**: AES-256-GCM with PBKDF2 key derivation (100,000 iterations)
- **Steganographic Hiding**: Hidden data is invisible to casual inspection
- **Cryptographically Secure**: Each encryption uses unique salt and nonce
- **Format Agnostic**: Works with any file type as cover (images, videos, documents, etc.)
- **Password Protection**: Password-based encryption
- **Metadata Preservation**: Automatically saves original filename
- **Simple CLI Interface**: Easy-to-use command-line interface
- **Reversible Process**: Extract and decrypt hidden files with the correct password

---

## Technical Details

### Encryption Specifications

| Component | Specification |
|-----------|--------------|
| **Cipher** | AES-256-GCM (Authenticated Encryption) |
| **Key Derivation** | PBKDF2-HMAC-SHA256 |
| **Iterations** | 100,000 |
| **Key Size** | 256 bits (32 bytes) |
| **Salt Size** | 128 bits (16 bytes) |
| **Nonce Size** | 96 bits (12 bytes) |
| **Authentication** | Built-in (GCM mode) |

### How It Works

1. **Hiding Process:**
   - Read the secret file and its metadata (filename)
   - Derive a 256-bit key from password using PBKDF2
   - Encrypt the data using AES-256-GCM
   - Append encrypted data to the cover file with a separator
   - Output file looks and functions like the original cover file

2. **Extraction Process:**
   - Locate the hidden data block using the separator
   - Extract salt, nonce, and encrypted data
   - Derive the same key from the password
   - Decrypt and verify the data
   - Restore the original file with its name

---

## Installation

### Prerequisites

- Python 3.7 or higher
- pip 

### Install Dependencies

```bash
git clone https://github.com/avax43/AvaxCrypt.git
cd AvaxCrypt
pip install -r requirements.txt
```

---

## Usage

AvaxCrypt has two main commands: `hide` and `extract`

### Basic Syntax

```bash
python main.py <command> [arguments]
```

---

## Commands Guide

### Hide Command

Hide and encrypt a secret file inside a cover file.

```bash
python main.py hide -c <cover_file> -s <secret_file> -p <password> [-o <output_file>]
```

#### Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--cover` | `-c` | Yes | Path to the cover file (e.g., `image.jpg`, `video.mp4`) |
| `--secret` | `-s` | Yes | Path to the secret file you want to hide |
| `--password` | `-p` | Yes | Password for encryption |
| `--output` | `-o` | No | Output file path (auto-generated if not specified) |

#### Example

```bash
# Hide a document inside an image
python main.py hide -c photo.jpg -s secret_document.pdf -p MyStr0ngP@ssw0rd

# Output: photo_avax.jpg (the original image, contains encrypted PDF)
```

```bash
# Hide a file with custom output name
python main.py hide -c video.mp4 -s passwords.txt -p SecurePass123 -o vacation_video.mp4
```

---

### Extract Command

Extract and decrypt a hidden file from a steganographic file.

```bash
python main.py extract -f <avax_file> -p <password> [-d <output_directory>]
```

#### Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--file` | `-f` | Yes | Path to the file containing hidden data |
| `--password` | `-p` | Yes | Password used during encryption |
| `--outdir` | `-d` | No | Directory to save the extracted file (default: current directory) |

#### Example

```bash
# Extract hidden file
python main.py extract -f photo_avax.jpg -p MyStr0ngP@ssw0rd

# Output: secret_document.pdf (extracted to current directory)
```

```bash
# Extract to specific directory
python main.py extract -f vacation_video.mp4 -p SecurePass123 -d ./extracted_files
```

---

## Real-World Examples

### Example 1: Secure File Sharing

```bash
# Hide sensitive documents before uploading to cloud storage
python main.py hide -c background.png -s confidential_report.docx -p MySuper@Secret

# Share background_avax.png - only those with the password can extract
python main.py extract -f background_avax.png -p MySuper@Secret
```

### Example 2: Steganographic Backup

```bash
# Hide your SSH keys inside a video file
python main.py hide -c movie.mp4 -s ssh_private_key -p BackupPassword123
```

---

## Security Notes

### Strong Points

- Uses industry-standard AES-256-GCM encryption
- PBKDF2 with 100,000 iterations protects against brute-force attacks
- Each encryption session uses unique random salt and nonce
- Authenticated encryption prevents tampering

### Important Considerations

1. **Password Strength**: Use strong, unique passwords (+6 characters recommended)
2. **Password Safety**: Never share your password through insecure channels
3. **Backup**: Keep encrypted files backed up - data loss means permanent loss
4. **Cover File**: The cover file should be larger than the secret file
5. **Forensics**: While files are hidden from standard view, advanced forensic analysis may reveal appended data. This tool provides encryption and obfuscation, not absolute invisibility against forensic experts.

### Best Practices

- Use passwords with uppercase, lowercase, numbers, and symbols
- Don't reuse passwords across different files
- Use password generator
- Store passwords in a secure password manager
- Verify extraction works before deleting original secret files

---
