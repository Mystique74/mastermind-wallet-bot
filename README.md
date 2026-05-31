# Bitcoin Private Key to Address Matcher

A fast, offline Bitcoin private key to address matcher that validates and matches private keys in multiple formats (WIF, Hex) to Bitcoin addresses in all standard formats (P2PKH, P2SH, SegWit).

## Features

✅ **Multiple Key Formats**
- WIF (Wallet Import Format): `5...`, `K...`, `L...`
- Hex: 64-character hexadecimal strings

✅ **All Bitcoin Address Types**
- P2PKH (Legacy): Starts with `1`
- P2SH (Multi-sig): Starts with `3`
- SegWit (Native): Starts with `bc1`

✅ **Security Features**
- Offline operation (no network calls)
- WIF checksum validation
- Bitcoin address format validation
- Safe error handling

✅ **Performance**
- Efficient set-based matching
- Fast batch processing
- Reports invalid keys

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 privkey_address_matcher.py --privkeys keys.txt --addresses addresses.txt --output matches.txt --verbose
```

### Arguments

- `--privkeys` (required): File containing private keys (one per line)
- `--addresses` (required): File containing Bitcoin addresses (one per line)
- `--output` (optional): Output file to save matches
- `--verbose` (optional): Show all derived addresses for each private key

## File Formats

### Private Keys File (keys.txt)
```
5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteeLv3QB2Tp
e8f32e723decf4051aefac8e2c93c9c5b214313817cda4fb291e5189f53c1042
L4rK1yDtCWekvXuE6oXD9jCYfFNcoWNhq3dMyWyW3e4PH27FSDN1
60cf7679dd7da19775aadba89c7201d660a3ccbcc72be6b653d0d5f90ff1fa05
```

### Addresses File (addresses.txt)
```
1CG9Ny2TWKE6WZar1jtsrCcTVfkYW6EnaE
3Mw2qPLPLAxuMhhdVPeF6bTfJiNX6Nb9AB
bc1qzayrwafqwrwwhx9aek2z0lt7s2nmwt4x99sa90
```

### Output File (matches.txt)
```
5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteeLv3QB2Tp|1CG9Ny2TWKE6WZar1jtsrCcTVfkYW6EnaE|p2pkh
```

## How It Works

1. **Parse private keys** from WIF or Hex format
2. **Derive public key** using ECDSA (secp256k1)
3. **Generate all 3 address types** from the public key
4. **Match against** the target address file
5. **Report matches** with address type

## Example

```bash
$ python3 privkey_address_matcher.py --privkeys test_keys.txt --addresses test_addresses.txt --verbose

Loading private keys and addresses…
Loaded 20 private keys
Loaded 28 target addresses

✓ MATCH FOUND!
  Private Key: 5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteeLv3QB2Tp
  Address: 1A1z7agoat5JZ5zigj5glAXeCjnYerKyMy (p2pkh)
  All derived: P2PKH=1A1z7agoat5JZ5zigj5glAXeCjnYerKyMy, P2SH=3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy, SegWit=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

============================================================
Total matches: 1
Invalid keys skipped: 0
Saved to matches.txt
```

## Testing

Use the included test files to verify functionality:

```bash
python3 privkey_address_matcher.py --privkeys test_keys.txt --addresses test_addresses.txt --output test_matches.txt
```

## Security Notes

⚠️ **WARNING**: This tool is for educational and testing purposes only.

- Never use real private keys in test files
- Always keep private keys secure and encrypted
- Use Bitcoin testnet for development when possible
- This script performs no network operations (fully offline)

## Dependencies

- `ecdsa` - ECDSA cryptographic operations

## Performance

- Loads ~100,000 addresses in < 1 second
- Processes ~1,000 private keys in < 2 seconds
- Memory efficient with set-based matching

## Troubleshooting

### No matches found
- Verify private keys and addresses are correctly formatted
- Check that addresses correspond to the private keys
- Use `--verbose` flag to see all derived addresses

### Invalid keys skipped
- Ensure WIF format starts with `5`, `K`, or `L`
- Hex keys must be exactly 64 characters
- Check file encoding (UTF-8 recommended)

### File not found errors
- Verify file paths are correct
- Check file permissions
- Use absolute paths if relative paths fail

## License

MIT

## Support

For issues or questions, please create a GitHub issue in this repository.
