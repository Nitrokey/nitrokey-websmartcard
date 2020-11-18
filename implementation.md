# High level description

## Overview table



| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0 | STATUS | None | `{UNLOCKED,VERSION,SLOTS,PIN_ATTEMPTS}` | - | - |
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
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 10 | INITIALIZE_SEED | None | `{MASTER,SALT}` | + | + |

Sets random values (sourced from the HWRNG) to the Webcrypt's secrets - master key and PBKDF2 salt - and returns them to the caller. 

### Input description
None

### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `MASTER` | 32 | Webcrypt's master secret |
| `SALT` | 8 | PBKDF2 salt |


### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |





## Restore from seed (RESTORE_FROM_SEED)
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 11 | RESTORE_FROM_SEED | `{MASTER,SALT}` | `{HASH}` | + | + |

Sets Webcrypt's secret values as received from the caller. For verification calculates SHA256 hash of the input and returns as `HASH`. 

### Input description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `MASTER` | 32 | Webcrypt's master secret |
| `SALT` | 8 | PBKDF2 salt |

### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `HASH` | 32 | SHA256 hash of the sent `MASTER+SALT` |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF3 | ERR_BAD_FORMAT | Incoming data are malformed |
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |






## Generate non-resident key
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 12 | GENERATE_KEY | None | `{PUBKEY,KEYHANDLE}` | + | - |
| 15 | GENERATE_KEY_FROM_DATA | `{HASH}` | `{PUBKEY,KEYHANDLE}` | + | - |


### From hash (GENERATE_KEY_FROM_DATA)

For the actual key generation the FIDO U2F key generation and wrapping mechanism was reused. The passphrase is processed through a hash function (e.g. Argon2) with known parameters client side, and the hash result is sent to the device. The received hash is mixed through PBKDF2 with device's salt, then HMAC'ed with the Webcrypt's master key `WC_MASTER_KEY` along with the authentication tag. Finally it is encrypted through another secret key - `WC_MASTER_ENC_KEY`. 

```text
# Browser
hash[32] = Argon2(passphrase)
# Device
key_data_raw[32] = PBKDF2(hash, salt, 100)
key_pub, key_priv = wc_new_keypair(key_data_raw, appid)
```

Reused FIDO U2F key-wrapping implementation below:

```text
# wc_new_keypair() implementation
tag[16] = HMAC(WC_MASTER_KEY, key_data_raw|appid)
key_priv_plain[32] = HMAC(WC_MASTER_KEY, tag|key_data_raw)
key_priv[32] = AES256(WC_MASTER_ENC_KEY, key_priv_plain)
key_pub[64] = ECC_compute_public_key(key_priv)
key_handle[48] = tag|key_data_raw
```


#### Input description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `HASH` | 32 | Source data for key generation |

#### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `PUBKEY` | 64 | Raw ECC public key |
| `KEYHANDLE` | 48 | Key handle |

### Errors
Both commands return the same errors listed below.

| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF3 | ERR_BAD_FORMAT | Incoming data are malformed |
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during key generation or preparing output |
| 0xFA | ERR_INTERNAL_ERROR | Unexpected condition encountered |


### Random (GENERATE_KEY)
Random key generation follows the same path as from the hash, except that instead of the `key_data_raw` a randomized 32 bytes value is used, sourced from the device's HWRNG. Resulting KEYHANDLE can be stored off-device for the later use, e.g. locally in the browser (localStorage / cookie), or on a remote server. 

```text
# Device
random_data[32] = HWRNG(32)
key_pub, key_priv = wc_new_keypair(random_data, appid)
```



#### Input description
None

#### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `PUBKEY` | 64 | Raw ECC public key |
| `KEYHANDLE` | 48 | Key handle |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during key generation or preparing output |
| 0xFA | ERR_INTERNAL_ERROR | Unexpected condition encountered |




### General comments
Work in progress.

To implement:
- Add cross-origin keys;
- Key attributes (encoded in TAG part);
To discuss: 
- Remove the additional master encryption secret, and replace HMAC with AES GCM or ChaCha20/ChaCha20-Poly1305; 
- Introduce MAC-then-encrypt/MAC-then-pad-then-encrypt if needed. 



## Read public key of resident keys
To be done (Milestone 3). Command not implemented yet.




## Sign

| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 13 | SIGN | `{HASH,KEYHANDLE}` | `{SIGNATURE,INHASH}` | + | - |

Using key encoded in `KEYHANDLE` parameter command makes signature over the input hash `HASH` using ECDSA. Returns `SIGNATURE` as a result, as well as the sent hash named `INHASH`. 
The curve used by default is `secp256r1` (NIST P-256 Random). 

Implementation is reused from the FIDO U2F key-wrapped authentication. In pseudocode:
```text
tag[16], key_data_raw[32] = keyhandle[48]
key_pub, key_priv = wc_new_keypair(key_data_raw, appid)
signature = ECC_SIGN(key_priv, hash)
```

To implement:
- Support `secp256k1` curve (NIST P-256 Koblitz).
- Support other algorithms.


### Input description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `HASH` | 32 | Raw data to sign, typically SHA256 hash |
| `KEYHANDLE` | 48 | Key handle |


### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `SIGNATURE` | 64 | ECC signature |
| `INHASH` | 32 | Key handle |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- |
| 0xF3 | ERR_BAD_FORMAT | Incoming data are malformed |
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |




## Decrypt
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 14 | DECRYPT | `{DATA,KEYHANDLE,HMAC,ECCEKEY}` | `{DATA}` | + | - |

Decrypts data given in the `DATA` field, using `KEYHANDLE` key handle for regenerating the private key, and `ECCEKEY` ephemeral ECC public key for deriving the shared secret. Before that command verifies the data using calculating HMAC over all the fields and comparing with `HMAC`.
Requires PKCS#7 ([RFC 5652]) padded data to the length of multiple of 32.
Work in progress.

Pseudocode:
```text
# in: DATA,KEYHANDLE,HMAC_in,ECCEKEY
tag[16], key_data_raw[32] = KEYHANDLE[48]
key_pub, key_priv = wc_new_keypair(key_data_raw, appid)
shared_secret = ecc256_shared_secret(ECCEKEY)
data_len = len(DATA)
hmac_calc = HMAC(shared_secret, DATA|ECCEKEY|data_len|KEYHANDLE)
if hmac_calc != HMAC_in: abort
plaintext = AES256(shared_secret, DATA)
```

[RFC 5652]: https://tools.ietf.org/html/rfc5652#section-6.3



### Input description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `DATA` | 32-128* | Data to decrypt |
| `KEYHANDLE` | 48 | Key handle |
| `HMAC` | 32 | Calculated HMAC |
| `ECCEKEY` | 64 | Raw ECC public key |

### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `DATA` | 32-128* | Decrypted data |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF3 | ERR_BAD_FORMAT | Incoming data are malformed |
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |


- `*` - work in progress: - maximum data length will be increased.


## Status 
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0 | STATUS | None | `{UNLOCKED,VERSION,SLOTS,PIN_ATTEMPTS}` | - | - |


Command requires authentication: no.


### Input description
None

### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `UNLOCKED` | 1 | FIDO U2F transport only - whether user has logged in with `LOGIN` command (Milestone 4) |
| `VERSION` | 1 | implemented Webcrypt's version |
| `SLOTS` | 1 | number of available Resident Keys slots |
| `PIN_ATTEMPTS` | 1 | FIDO2 PIN attempt counter's current value |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |



## Configure
To be done (Milestone 4). Command not implemented yet.


## Write resident key
To be done (Milestone 3). Command not implemented yet.

## Test commands

| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 1 | TEST_PING | Any / Raw | Any / Raw | - | - |
| 2 | TEST_CLEAR | None | None | - | - |
| 3 | TEST_REBOOT | None | None | - | - |

These test commands are introduced to help in the development of the client applications, and are available only in the development version of the firmware:
`TEST_PING` - send and receive data for transport tests (loopback). 

Not implemented at the moment:
- `TEST_CLEAR` - clear current Webcrypt's state;
- `TEST_REBOOT` - reboot device.






# Protocol

## Overview

## Commands


# FIDO2 relationship
On FIDO2 factory reset Webcrypt's secrets are reinitialized to random values.

# JS handling


# TODO
1. Describe error codes for commands
2. Add some diagrams