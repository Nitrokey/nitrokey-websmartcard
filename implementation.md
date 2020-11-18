# High level description

## Overview table



| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0 | STATUS | None | `{UNLOCKED,VERSION,SLOTS,PIN_ATTEMPTS}` | + | - |
| 1 | TEST_PING | Any / Raw | Any / Raw | - | - |
| 2 | TEST_CLEAR | None | None | - | - |
| 3 | TEST_REBOOT | None | None | - | - |
| 4 | LOGIN | TBD | TBD | - | + |
| 5 | LOGOUT | None | None | - | - |
| 6 | FACTORY_RESET | None | None | - | + |
| 7 | PIN_ATTEMPTS | None | `{PIN_ATTEMPTS}` | - | - |
| 10 | INITIALIZE_SEED | None | `{MASTER,SALT}` | + | + |
| 11 | RESTORE_FROM_SEED | `{MASTER,SALT}` | `{HASH}` | + | + |
| 12 | GENERATE_KEY | None | `{PUBKEY,KEYHANDLE}` | + | - |
| 13 | SIGN | `{HASH,KEYHANDLE}` | `{SIGNATURE,INHASH}` | + | - |
| 14 | DECRYPT | `{DATA,KEYHANDLE,HMAC,ECCEKEY}` | `{DATA}` | + | - |
| 15 | GENERATE_KEY_FROM_DATA | `{HASH}` | `{PUBKEY,KEYHANDLE}` | + | - |

where for the given command:
- ID is a hexadecimal integer;
- `TEST_` prefixed commands are available only in the development firmware;
- plus `+` sign means a requirement for operation named by this specific column, whereas minus `-` sign is the opposite;
- column `Au`, short from authentication, marks authentication requirement with the `LOGIN` command, before using this command;
- column `Bt`, short from button, marks touch-button press requirement after the command is called, to proceed further.


## Initialize (INITIALIZE_SEED)
 
## Restore from seed (RESTORE_FROM_SEED)

## Generate non-resident key

### From hash (GENERATE_KEY_FROM_DATA)

For the actual key generation the FIDO U2F key generation mechanism was reused. The received Argon2 hash is mixed through PBKDF2 with device's salt, then HMAC'ed with the Webcrypt's master key along with the authentication tag. Finally it is encrypted through another secret key. 

```text
# Browser
hash[32] = Argon2(passphrase)
# Device
hash_f[32] = PBKDF2(hash, salt, 100)
key_pub, key_priv = wc_new_keypair(hash_f, appid)
```

Reused FIDO U2F implementation below:

```text
# wc_new_keypair() implementation
tag[16] = HMAC(WC_MASTER_KEY, hash_f|appid)
key_priv_plain[32] = HMAC(WC_MASTER_KEY, tag|hash_f)
key_priv[32] = AES(WC_MASTER_ENC_KEY, key_priv_plain)
key_pub[64] = ECC_compute_public_key(key_priv)
```

Work in progress.
In discussion: to remove the additional master encryption secret, and replace HMAC with AES GCM or ChaCha20/ChaCha20-Poly1305. Introduce MAC-then-encrypt or MAC-then-pad-then-encrypt. 

### Random (GENERATE_KEY)
Random key generation follows the same path as from hash with the excerpt, that instead of the hash a randomized 32 bytes value is used.

## Read public key of resident keys
To be done. Command not implemented yet.

## Sign
(to_be_signed_data_hash, public_key, hash, origin)

## Decrypt
(to_be_decrypted_data, public_key, hash, origin)

## Status 
(Unlocked, version, available resident key slots)

## Configure
TBD

## Write resident key
TBD


# Protocol

## Overview

## Commands
