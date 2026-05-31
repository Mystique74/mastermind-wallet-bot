#!/usr/bin/env python3
"""
privkey_address_matcher.py
Match Bitcoin private keys (WIF, Hex) to addresses (1, 3, bc1)
Supports: P2PKH, P2SH, SegWit (native)
"""

import argparse
import hashlib
import re
import binascii
from ecdsa import SigningKey, NIST256p

# Bitcoin constants
MAINNET_P2PKH = 0x00
MAINNET_P2SH = 0x05
CHARSET_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def sha256(data):
    """Double SHA256 hash"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def base58_encode(data):
    """Encode bytes to Base58"""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    encoded = ""
    num = int.from_bytes(data, 'big')
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    # Handle leading zeros
    for byte in data:
        if byte == 0:
            encoded = alphabet[0] + encoded
        else:
            break
    return encoded

def base58_decode(s):
    """Decode Base58 string to bytes"""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    decoded = 0
    for char in s:
        decoded = decoded * 58 + alphabet.index(char)
    return decoded.to_bytes(25, 'big')

def bech32_polymod(values):
    """Internal function for Bech32 checksum"""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_encode(hrp, witver, witprog):
    """Encode SegWit address (Bech32)"""
    values = [ord(x) >> 5 for x in hrp] + [0] + [witver] + [x >> 5 for x in witprog] + [x & 31 for x in witprog]
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return hrp + '1' + ''.join(CHARSET_BECH32[(polymod >> (5 * (5 - i))) & 31] for i in range(6))

def privkey_to_pubkey(privkey_bytes):
    """Convert private key bytes to compressed public key"""
    sk = SigningKey.from_string(privkey_bytes, curve=NIST256p, hashfunc=hashlib.sha256)
    # Get uncompressed public key
    uncompressed = sk.get_verifying_key().to_string()
    # Compress: prefix + x-coordinate
    prefix = b'\x02' if uncompressed[-1] % 2 == 0 else b'\x03'
    return prefix + uncompressed[:32]

def pubkey_to_p2pkh(pubkey):
    """Convert compressed public key to P2PKH address (type 1)"""
    # Hash pubkey: RIPEMD160(SHA256(pubkey))
    h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    # Add version byte and checksum
    versioned = bytes([MAINNET_P2PKH]) + h160
    checksum = sha256(versioned)[:4]
    return base58_encode(versioned + checksum)

def pubkey_to_p2sh(pubkey):
    """Convert compressed public key to P2SH address (type 3)"""
    # Create witness program: OP_0 <20-byte-hash>
    h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    script = b'\x00\x14' + h160  # OP_0 + PUSH 20
    # Hash the script
    script_hash = hashlib.new('ripemd160', hashlib.sha256(script).digest()).digest()
    versioned = bytes([MAINNET_P2SH]) + script_hash
    checksum = sha256(versioned)[:4]
    return base58_encode(versioned + checksum)

def pubkey_to_segwit(pubkey):
    """Convert compressed public key to SegWit address (bc1)"""
    h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    # Bech32 encoding with witness version 0 and program
    return bech32_encode('bc', 0, h160)

def parse_privkey(key_str):
    """Parse private key from WIF, Hex, or other formats"""
    key_str = key_str.strip()
    
    # WIF format (uncompressed: 51 chars, compressed: 52 chars)
    if key_str.startswith('5') or key_str.startswith('K') or key_str.startswith('L'):
        try:
            decoded = base58_decode(key_str)
            # Check version byte (0x80 for mainnet)
            if decoded[0] != 0x80:
                return None
            # Verify checksum
            checksum = sha256(decoded[:-4])[:4]
            if checksum != decoded[-4:]:
                return None
            # Return private key (skip version, optionally compression flag)
            if len(decoded) == 34:  # Compressed WIF
                return decoded[1:33]
            elif len(decoded) == 33:  # Uncompressed WIF
                return decoded[1:33]
            return None
        except:
            return None
    
    # Hex format (64 chars = 32 bytes)
    if re.match(r'^[0-9a-fA-F]{64}$', key_str):
        try:
            return binascii.unhexlify(key_str)
        except:
            return None
    
    return None

def derive_addresses(privkey_hex):
    """Derive all three address types from private key"""
    try:
        privkey_bytes = binascii.unhexlify(privkey_hex) if isinstance(privkey_hex, str) else privkey_hex
        pubkey = privkey_to_pubkey(privkey_bytes)
        
        return {
            'p2pkh': pubkey_to_p2pkh(pubkey),  # Type 1
            'p2sh': pubkey_to_p2sh(pubkey),    # Type 3
            'segwit': pubkey_to_segwit(pubkey) # bc1
        }
    except:
        return None

def load_privkeys(path):
    """Load private keys from file"""
    privkeys = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            key = line.strip()
            if key:
                privkeys.append(key)
    return privkeys

def load_addresses(path):
    """Load addresses from file"""
    addrs = set()
    with open(path, "r", errors="ignore") as f:
        for line in f:
            addr = line.strip()
            if addr:
                addrs.add(addr)
    return addrs

def main():
    ap = argparse.ArgumentParser(description="Match Bitcoin private keys to addresses")
    ap.add_argument("--privkeys", required=True, help="File with private keys (WIF or Hex)")
    ap.add_argument("--addresses", required=True, help="File with Bitcoin addresses")
    ap.add_argument("--output", help="Optional output file for matches")
    ap.add_argument("--verbose", action="store_true", help="Show all derived addresses")
    args = ap.parse_args()

    print("Loading private keys and addresses…")
    try:
        privkeys = load_privkeys(args.privkeys)
        addresses = load_addresses(args.addresses)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1

    print(f"Loaded {len(privkeys)} private keys")
    print(f"Loaded {len(addresses)} target addresses\n")

    matches = []
    invalid_keys = 0

    for privkey_str in privkeys:
        privkey_bytes = parse_privkey(privkey_str)
        if not privkey_bytes:
            invalid_keys += 1
            continue

        privkey_hex = binascii.hexlify(privkey_bytes).decode()
        addrs = derive_addresses(privkey_hex)

        if not addrs:
            continue

        # Check if any derived address matches
        for addr_type, addr in addrs.items():
            if addr in addresses:
                matches.append({
                    'privkey': privkey_str,
                    'privkey_hex': privkey_hex,
                    'address': addr,
                    'type': addr_type
                })
                print(f"✓ MATCH FOUND!")
                print(f"  Private Key: {privkey_str}")
                print(f"  Address: {addr} ({addr_type})")
                if args.verbose:
                    print(f"  All derived: P2PKH={addrs['p2pkh']}, P2SH={addrs['p2sh']}, SegWit={addrs['segwit']}")
                print()

    print(f"\n{'='*60}")
    print(f"Total matches: {len(matches)}")
    print(f"Invalid keys skipped: {invalid_keys}")

    if matches and args.output:
        with open(args.output, "w") as f:
            for match in matches:
                f.write(f"{match['privkey']}|{match['address']}|{match['type']}\n")
        print(f"Saved to {args.output}")
    elif not matches:
        print("No matches found.")

if __name__ == "__main__":
    main()
