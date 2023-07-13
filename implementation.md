# Nitrokey Webcrypt Implementation Documentation

This documentation provides an overview of the implemented Nitrokey Webcrypt interface in Nitrokey 3. It includes
high-level descriptions of the commands and low-level protocol details. Please note that this implementation is in the
early stages and may undergo changes in the future.

## Commands Overview Table



| ID   | Mnemonic                 | Parameters                        | Returns                                 | Au  | Bt  |
|------|--------------------------|-----------------------------------|-----------------------------------------|-----|-----|
| 0x0  | STATUS                   | None                              | `{UNLOCKED,VERSION,SLOTS,PIN_ATTEMPTS}` | -   | -   |
| 0x1  | TEST_PING                | Any / Raw                         | Any / Raw                               | -   | -   |
| 0x2  | TEST_CLEAR               | None                              | None                                    | -   | -   |
| 0x3  | TEST_REBOOT              | None                              | None                                    | -   | -   |
| 0x4  | LOGIN                    | `{PIN}`                           | `{TP}`                                  | -   | +   |
| 0x5  | LOGOUT                   | None                              | None                                    | -   | -   |
| 0x6  | FACTORY_RESET            | None                              | None                                    | -   | +   |
| 0x7  | *RESERVED*               | -                                 | -                                       | -   | +   |
| 0x8  | SET_CONFIGURATION        | `{CONFIRMATION}`                  | None                                    | -   | +   |
| 0x9  | GET_CONFIGURATION        | None                              | `{CONFIRMATION}`                        | -   | +   |
| 0x0A | SET_PIN                  | `{PIN}`                           | None                                    | -   | +   |
| 0x0B | CHANGE_PIN               | `{PIN,NEWPIN}`                    | None                                    | -   | +   |
| 0x10 | INITIALIZE_SEED          | `{ENTROPY}`                       | `{MASTER,SALT}`                         | +   | +   |
| 0x11 | RESTORE_FROM_SEED        | `{MASTER,SALT}`                   | `{HASH}`                                | +   | +   |
| 0x12 | GENERATE_KEY             | None                              | `{PUBKEY,KEYHANDLE}`                    | +   | +   |
| 0x13 | SIGN                     | `{HASH,KEYHANDLE}`                | `{SIGNATURE,INHASH}`                    | +   | +   |
| 0x14 | DECRYPT                  | `{DATA,KEYHANDLE,[HMAC,ECCEKEY]}` | `{DATA}`                                | +   | +   |
| 0x15 | GENERATE_KEY_FROM_DATA   | `{HASH}`                          | `{PUBKEY,KEYHANDLE}`                    | +   | +   |
| 0x16 | GENERATE_RESIDENT_KEY    | None                              | `{PUBKEY,KEYHANDLE}`                    | +   | +   |
| 0x17 | READ_RESIDENT_KEY_PUBLIC | `{KEYHANDLE}`                     | `{PUBKEY,KEYHANDLE}`                    | +   | +   |
| 0x18 | DISCOVER_RESIDENT_KEYS   | TBD                               | TBD                                     | +   | +   |
| 0x19 | WRITE_RESIDENT_KEY       | `{RAW_KEY_DATA,[KEY_TYPE]}`       | `{PUBKEY,KEYHANDLE}`                    | +   | +   |



Where for the given command:
- ID is a hexadecimal integer;
- `TEST_` prefixed commands are available only in the development firmware;
- the TBD acronym means that the work for that command is planned
- plus `+` sign means a requirement for operation named by this specific column, whereas minus `-` sign is the opposite;
- column `Au`, short from authentication, marks authentication requirement with the `LOGIN` command, before using this command;
- column `Bt`, short from button, marks touch-button press requirement after the command is called, to proceed further.

Note that OpenPGP specific commands are missing from this description (to be updated).


## Initialize (INITIALIZE_SEED)
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0x10 | INITIALIZE_SEED | `{ENTROPY}` | `{MASTER,SALT}` | + | + |

Sets random values (sourced from the HWRNG) to the Nitrokey Webcrypt's secrets - *Master Key* and *Salt* - and returns them to the caller for the backup purposes. The device produced random values are XOR'ed with the incoming ENTROPY field. 

On the client application side these binary secrets should be translated to human readable word-based representation, *Word Seed*, similarly to [BIP#39], e.g.:
```
   witch collapse practice feed shame open despair creek road again ice least
```

In the future the secret will be returned in one field instead of two.

[BIP#39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

Note: Nitrokey Webcrypt's secrets should be guaranteed to always be initialized. It should not be possible to use them however unless confirmed that user has his backup *Word Seed* saved. 

```
random_data[40] = HWRNG(40)
MASTER[32],SALT[8] = random_data[40] ^ ENTROPY[40]
```


### Input description
| Field     | Size [B] | Description                                        |
|-----------|----------|----------------------------------------------------|
| `ENTROPY` | 40       | Client-sourced bytes to be mixed with HWRNG result |

### Output description
| Field    | Size [B] | Description                         |
|----------|----------|-------------------------------------|
| `MASTER` | 32       | Nitrokey Webcrypt's *Master Secret* |
| `SALT`   | 8        | Salt                                |


### Errors
| ID   | Mnemonic                | Description                   |
|------|-------------------------|-------------------------------|
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |





## Restore from seed (RESTORE_FROM_SEED)
| ID   | Mnemonic          | Parameters      | Returns  | Au  | Bt  |
|------|-------------------|-----------------|----------|-----|-----|
| 0x11 | RESTORE_FROM_SEED | `{MASTER,SALT}` | `{HASH}` | +   | +   |

Sets Nitrokey Webcrypt's secret values as received from the caller. For verification calculates SHA256 hash of the input and returns as `HASH`. 


```
HASH = SHA256(MASTER|SALT)
```

### Input description
| Field    | Size [B] | Description                       |
|----------|----------|-----------------------------------|
| `MASTER` | 32       | Nitrokey Webcrypt's Master Secret |
| `SALT`   | 8        | Salt                              |

### Output description
| Field  | Size [B] | Description                           |
|--------|----------|---------------------------------------|
| `HASH` | 32       | SHA256 hash of the sent `MASTER+SALT` |

### Errors
| ID   | Mnemonic                | Description                   |
|------|-------------------------|-------------------------------|
| 0xF3 | ERR_BAD_FORMAT          | Incoming data are malformed   |
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |



## Key Handle description

### Wrapping

The wrapping operation is reused from the fido-authenticator crate:
1. The private key is wrapped using a persistent wrapping key using ChaCha20-Poly1305 AEAD algorithm.
2. The wrapped key is embedded into a KeyHandle data structure, containing additional metadata (RP ID, Usage Flags).
3. The serialized KeyHandle structure is finally CBOR serialized and encrypted, resulting in a binary blob to be used with other commands.


```text
key_private - private key structure
Encrypt = ChaCha20-Poly1305
Serialize = CBOR
key_private_enc = Encrypt(Serialize(key_private))
key_handle = Encrypt(Serialize(key_private_enc))  
key_pub[64] = ECC_compute_public_key(key_private)
PUBKEY = key_pub
KEYHANDLE = key_handle
```

### Unwrapping

The deserialization method of the KeyHandle is reused from the fido-authenticator project.
1. The encrypted KeyHandle is decrypted and deserialized to a KeyHandle structure using persistent encryption key.
2. From the resulting KeyHandle structure the wrapped private key is decrypted and deserialized
3. Finally, the wrapped private key is imported to the volatile in-memory keystore, and used for the further operations.

```text
key_handle - serialized and encrypted KeyHandle structure
Decrypt = ChaCha20-Poly1305
Deserialize = CBOR
key_private_enc = Decrypt(Deserialize(key_handle))  
key_private = Decrypt(Deserialize(key_private_enc))
```

### Resident Keys

The KeyHandles for Resident Keys are a serialized internal KeyID (16 B) identifier, along with some metadata fields reserved for the future use. This might change in the future.

## Generate non-resident key
| ID   | Mnemonic               | Parameters | Returns              | Au    | Bt  |
|------|------------------------|------------|----------------------|-------|-----|
| 0x12 | GENERATE_KEY           | None       | `{PUBKEY,KEYHANDLE}` | +     | +   |
| 0x15 | GENERATE_KEY_FROM_DATA | `{HASH}`   | `{PUBKEY,KEYHANDLE}` | +     | +   |


### From hash (GENERATE_KEY_FROM_DATA)

For the actual key generation the FIDO U2F / FIDO2 key generation and wrapping mechanism was reused. The passphrase is processed through a hash function (e.g. Argon2) with known parameters client side, and the hash result is sent to the device. The received hash is HMAC'ed with the Nitrokey Webcrypt's master key `WC_MASTER_KEY`.

The hash function selection, use and parameters will be standardized in the future.

```text
# Browser
hash[32] = Argon2(passphrase)
# Device
key_data_raw[32] = HMAC256(hash)
key_pub, key_priv = wc_new_keypair(key_data_raw, appid)
```

See the wrapping algorithm in the Key Handle description chapter.

To discuss:
- hash function selection and parameters;
- introducing a KDF-DO like object, containing parameters needed to calculate the hash from the passphrase client side.

#### Input description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `HASH` | 32 | Source data for key generation |

#### Output description
| Field       | Size [B] | Description |
|-------------|----------| ---------- | 
| `PUBKEY`    | 64       | Raw ECC public key |
| `KEYHANDLE` | 250      | Key handle |

### Errors
Both commands return the same errors listed below.

| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF3 | ERR_BAD_FORMAT | Incoming data are malformed |
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during key generation or preparing output |
| 0xFA | ERR_INTERNAL_ERROR | Unexpected condition encountered |


### Random (GENERATE_KEY)
Random key generation follows the same path as from the hash, except that instead of the `key_data_raw` a randomized 32 bytes value is used, sourced from the device's HWRNG. Resulting `KEYHANDLE` can be stored off-device for the later use, e.g. locally in the browser (localStorage / cookie), or on a remote server. 

See *From hash (GENERATE_KEY_FROM_DATA)* chapter for the full pseudocode, specifically key wrapping.

```text
# Device
random_data[32] = HWRNG(32)
key_pub, key_priv = wc_new_keypair(random_data, appid)
```



#### Input description
None

#### Output description
| Field       | Size [B] | Description |
|-------------|----------| ---------- | 
| `PUBKEY`    | 64       | Raw ECC public key |
| `KEYHANDLE` | 250      | Key handle |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during key generation or preparing output |
| 0xFA | ERR_INTERNAL_ERROR | Unexpected condition encountered |




### General comments
Work in progress.

To implement:
- Add cross-origin keys;
- Key attributes;
To discuss: 
- Replace HMAC with AES GCM or ChaCha20/ChaCha20-Poly1305; 
- Introduce MAC-then-encrypt/MAC-then-pad-then-encrypt if needed. 



## Sign (SIGN)

| ID | Mnemonic | Parameters | Returns             | Au | Bt |
| --- | ------ | ---------- |---------------------| --- | --- |
| 0x13 | SIGN | `{HASH,KEYHANDLE}` | `{SIGNATURE,INHASH}` | + | + |


Returns `SIGNATURE` as a result, as well as the incoming hash `HASH`.
`KEYHANDLE` authenticity (whether it was generated with given *Master Key* and to use for given *Origin*) is verified before use.
Incoming `HASH` data is repeated on the output for signature confirmation.
See the wrapping algorithm in the Key Handle description chapter.

The type of the `SIGNATURE` signature depends on the used key algorithm, encoded in the keyhandle.

In pseudocode:
```text
SIGNATURE = Sign(KEYHANDLE, hash)
INHASH = HASH
```


### ECC keys
Using key encoded in `KEYHANDLE` parameter command makes signature over the input hash `HASH` using ECDSA.  
The curve used by default is `secp256r1` (NIST P-256 Random). 



### RSA keys
Signing operation for RSA keys uses PKCSv15 padding and SHA256 as the hash.
The only supported size for the RSA keys is RSA 2048.

To implement:
- Support `secp256k1` curve (NIST P-256 Koblitz).
- Support other algorithms.


### Input description
| Field        | Size [B] | Description |
|--------------|----------| ---------- | 
| `HASH`       | 32       | Raw data to sign, typically SHA256 hash |
| `KEYHANDLE`  | 250      | Key handle |


### Output description
| Field       | Size [B] | Description |
|-------------| ------ | ---------- | 
| `SIGNATURE` | 64 | ECC signature |
| `INHASH`    | 32 | Incoming raw data to sign |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- |
| 0xF3 | ERR_BAD_FORMAT | Incoming data are malformed |
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |




## Decrypt (DECRYPT)
| ID   | Mnemonic | Parameters                          | Returns  | Au  | Bt  |
|------|----------|-------------------------------------|----------|-----|-----|
| 0x14 | DECRYPT  | `{DATA,KEYHANDLE,[HMAC,ECCEKEY]}` | `{DATA}` | +   | +   |


The type of the operation done on the `DATA` ciphertext depends on the used key algorithm, encoded in the keyhandle.
`KEYHANDLE` authenticity (whether it was generated with given *Master Key* and to use for given *Origin*) is verified before use.
See the wrapping algorithm in the Key Handle description chapter.

### ECC keys
Decrypts data given in the `DATA` field, using `KEYHANDLE` *Key Handle* for regenerating the private key, and `ECCEKEY` ephemeral ECC public key for deriving the shared secret using ECDH. Before that this command verifies the data by calculating HMAC over all the fields and comparing with incoming `HMAC` field.

Requires PKCS#7 ([RFC 5652]) padded data to the length of multiple of 32.

Pseudocode:
```text
shared_secret = ecc256_shared_secret(ECCEKEY)
data_len = len(DATA)
hmac_calc = HMAC256(shared_secret, DATA|ECCEKEY|data_len|KEYHANDLE)
if hmac_calc != HMAC: abort
plaintext = Decrypt(AES256, shared_secret, DATA)
```

[RFC 5652]: https://tools.ietf.org/html/rfc5652#section-6.3


### RSA keys
Decrypts data given in the `DATA` field, using `KEYHANDLE` *Key Handle* for regenerating the private key.
`KEYHANDLE` authenticity (whether it was generated with given *Master Key* and to use for given *Origin*) is verified before use.
The ciphertext should be encoded with PKCS#1v15 padding. `HMAC` and `ECCEKEY` should not be provided.
HMAC is not checked. 

Pseudocode:
```text
plaintext = Decrypt(RSA2048, KEYHANDLE, DATA)
DATA = plaintext
```



### Input description
| Field        | Size [B] | Description                   |
|--------------|----------|-------------------------------| 
| `DATA`       | 32-128*  | Data to decrypt               |
| `KEYHANDLE`  | 250+     | Key handle                    |
| `HMAC`       | 32     | Calculated HMAC (ECC only)      |
| `ECCEKEY`    | 64     | Raw ECC public key (ECC only)   |

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


## Status (STATUS)
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0x0 | STATUS | None | `{UNLOCKED,VERSION,SLOTS,PIN_ATTEMPTS}` | - | - |


Command requires authentication: no.

#### To discuss
- should `SLOTS` number not be hidden to avoid fingerprinting.

### Input description
None

### Output description

| Field | Size [B] | Description                                             |
| --- | ------ |---------------------------------------------------------| 
| `VERSION` | 1 | implemented Nitrokey Webcrypt's version                 |
| `SLOTS` | 1 | number of left available Webcrypt's Resident Keys slots |
| `PIN_ATTEMPTS` | 1 | PIN attempt counter's current value                     |
| `UNLOCKED` | 1 | Return true if the session is open                      |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |





## Login (LOGIN)

| ID     | Mnemonic | Parameters          | Returns             | Au   | Bt   |
|--------|----------|---------------------|---------------------|------|------|
| 0x4  | LOGIN    | `{PIN}`             | `{TP}`              | - | + |


This command allows to establish session by returning a session token upon presenting the correct PIN.
If the PIN is invalid, the PIN attempt counter will be decreased. Once the latter reaches 0, the only further available
operation will be FACTORY_RESET. 

### Input description

| Field   | Size [B] | Description            | 
|---------|----------|------------------------|  
| `PIN`   | 4-64     | Current Webcrypt's PIN |

### Output description

| Field  | Size [B] | Description                              |
|--------|----------|------------------------------------------| 
| `TP`   | 32       | Session token, a.k.a. temporary password |

### Errors

| ID       | Mnemonic                | Description                        |
|----------|-------------------------|------------------------------------| 
| 0xF1     | ERR_INVALID_PIN         | The presented PIN is invalid       |
| 0xF2     | ERR_NOT_ALLOWED         | The PIN attempt counter is used up |
| 0xF5     | ERR_FAILED_LOADING_DATA | Error during preparing output      |



## Logout (LOGOUT)

| ID     | Mnemonic   | Parameters    | Returns                 | Au   | Bt   |
|--------|------------|---------------|-------------------------|------|------|
| 0x5  | LOGOUT     | None          | None                    | - | - |

Clear all session related data, and remove all secrets from the memory.

### Errors

None

## Factory reset (FACTORY_RESET)

| ID     | Mnemonic            | Parameters  | Returns             | Au   | Bt   |
|--------|---------------------|-------------|---------------------|------|------|
| 0x6  | FACTORY_RESET       | None        | None                | - | + |

Removes all the currently stored user data, and prepares the device for the new use.

Note: this command does not need PIN confirmation or session set.

### Errors
None



## Get and Set configuration (GET_CONFIGURATION, SET_CONFIGURATION)

| ID     | Mnemonic              | Parameters  | Returns         | Au   | Bt   |
|--------|-----------------------|-------------|-----------------|------|------|
| 0x8  | SET_CONFIGURATION     | `{CONFIRMATION}`                | None                                    | - | + |
| 0x9  | GET_CONFIGURATION     | None                            | `{CONFIRMATION}`                        | - | + |


This command allows to change the user settings in Webcrypt.
Work in progress.

### Input/output description

|  Field    | Size [B] | Description             | 
|-----------|----------|-------------------------|  
| `CONFIRMATION` | 1        | Confirmation mode (WIP) |

### Errors

| ID      | Mnemonic                | Description                   |
|---------|-------------------------|-------------------------------| 
| 0xF5    | ERR_FAILED_LOADING_DATA | Error during preparing output |





## PIN management (SET_PIN, CHANGE_PIN)


| ID     | Mnemonic        | Parameters            | Returns            | Au   | Bt   |
|--------|-----------------|-----------------------|--------------------|------|------|
| 0x0A | SET_PIN         | `{PIN}`               | None               | - | + |
| 0x0B | CHANGE_PIN      | `{PIN,NEWPIN}`        | None               | - | + |


The SET_PIN and CHANGE_PIN commands are for the PIN handling. The former allows to set the PIN, when there is none (e.g. just after factory reset operation), but afterwards it is not allowed to work. The further PIN changes require CHANGE_PIN command to be used.
The PIN can be of length between 4 and 64 bytes.

### Input description

|  Field    | Size [B] | Description                        | 
|-----------|----------|------------------------------------|  
| `PIN` | 4-64     | SET_PIN: the current PIN to be set |
| `PIN` | 4-64     | CHANGE_PIN: the current PIN        |
| `NEWPIN` | 4-64       | CHANGE_PIN: the new PIN            |

### Output description
None

### Errors

| ID      | Mnemonic                | Description                                                         |
|---------|-------------------------|---------------------------------------------------------------------| 
| 0xF5    | ERR_FAILED_LOADING_DATA | Error during preparing output                                       |
| 0xF1    | INVALID_PIN             | The provided PIN is invalid, or wrong length                        |
| 0xF2    | ERR_NOT_ALLOWED         | SET_PIN: command use is not allowed, because the PIN is already set |



## Resident Keys Handling

| ID   | Mnemonic                 | Parameters                  | Returns              | Au  | Bt  |
|------|--------------------------|-----------------------------|----------------------|-----|-----|
| 0x16 | GENERATE_RESIDENT_KEY    | None                        | `{PUBKEY,KEYHANDLE}` | +   | +   |
| 0x17 | READ_RESIDENT_KEY_PUBLIC | `{KEYHANDLE}`               | `{PUBKEY,KEYHANDLE}` | +   | +   |
| 0x18 | DISCOVER_RESIDENT_KEYS   | TBD                         | TBD                  | +   | +   |
| 0x19 | WRITE_RESIDENT_KEY       | `{RAW_KEY_DATA,[KEY_TYPE]}` | `{PUBKEY,KEYHANDLE}` | +   | +   |


Resident Keys (RK) are the keys stored on the device, allowing to be identified with a shorter keyhandle, or instead used as a storage means for the Relying Party, relieving it from the keeping of the secret material completely.
Resident Keys can be generated, imported and used in the same way as their derived counterparts with the SIGN and DECRYPT commands.


Detailed description:
- GENERATE_RESIDENT_KEY - generates a RK on the device using local means, and returns a keyhandle to it (ECC only);
- READ_RESIDENT_KEY_PUBLIC - allows to read a public key of the given RK;
- DISCOVER_RESIDENT_KEYS - lists all the RKs available for the given Relying Party (work in progress);
- WRITE_RESIDENT_KEY - writes raw key data, as received from the RP, and returns a keyhandle to it.


### Input description

| Field          | Size [B] | Description                                                                                 | 
|----------------|----------|---------------------------------------------------------------------------------------------|  
| `KEYHANDLE`    | 250+     | The keyhandle bytes, allowing to either identify the Resident Key or the Derived Key        |
| `RAW_KEY_DATA` | 32+      | Raw key data, to be saved as a Resident Key. RSA raw keys have to be encoded in PKCS#8 DER. |
| `KEY_TYPE`     | 2        | Key type, encoded in int16: 0 = P256 , 1 = RSA 2K. Optional. Default: 0.                    |

### Output description

| Field          | Size [B] | Description                                                                                 |
|----------------|----------|---------------------------------------------------------------------------------------------| 
| `PUBKEY`       | 65+       | The calculated public key for the given keyhandle. RSA public key is encoded in PKCS#8 DER. |
| `KEYHANDLE`    | 250+     | The keyhandle bytes, allowing to either identify the Resident Key or the Derived Key        |

### Errors

| ID      | Mnemonic                | Description                   |
|---------|-------------------------|-------------------------------| 
| 0xF5    | ERR_FAILED_LOADING_DATA | Error during preparing output |



## Test commands

| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0x1 | TEST_PING | Any / Raw | Any / Raw | - | - |
| 0x2 | TEST_CLEAR | None | None | - | - |
| 0x3 | TEST_REBOOT | None | None | - | - |

These test commands are introduced to help in the development of the client applications, and are available only in the development version of the firmware:
`TEST_PING` - send and receive data for transport tests (loopback). 

Not implemented at the moment:
- `TEST_CLEAR` - clear the current Nitrokey Webcrypt's state;
- `TEST_REBOOT` - reboot device.


## Common errors table
Following errors are common to all commands requiring authorization.

| ID | Mnemonic                  | Description                                                    |
| --- |---------------------------|----------------------------------------------------------------|
| 0xF0 | ERR_REQ_AUTH              | Command needs to be authorized by PIN *                        |
| 0xF1 | ERR_INVALID_PIN           | Provided PIN is invalid                                        |
| 0xF2 | ERR_NOT_ALLOWED            | The given key's origin does not match the one of the request   |
| 0xF3 | ERR_BAD_FORMAT            | The given key's origin does not match the one of the request   |
| 0xF4 | ERR_USER_NOT_PRESENT      | User has not pressed touch button in time                      |
| 0xF5 | ERR_FAILED_LOADING_DATA   | There was an error while preparing the result of the execution |
| 0xFD | ERR_BAD_ORIGIN            | The given key's origin does not match the one of the request   |

Notes:
- (*) `ERR_REQ_AUTH` should be returned, when: for FIDO U2F the session token was not provided in the data, for FIDO2 the PIN was not requested from the user (`userVerification: "discouraged"`)


# Protocol

Communication is based on the [Webauthn] / [FIDO2] API, which by itself allows to communicate with FIDO Security Keys in FIDO2 enabled browsers on all platforms, as well as through NFC and Bluetooth. Such feature is here reused as a an universal communication tunnel to the Nitrokey Webcrypt enabled device, making it plug-and-play and working out of the box with many configurations.

This chapter is still a work in progress.

[Webauthn]: https://www.w3.org/TR/webauthn/
[FIDO2]: https://fidoalliance.org/specifications/
[CTAP]: https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html

## Overview

Nitrokey Webcrypt's communication is based on the Request-Response message exchange pattern, where communication is initiated always by the host, and each data update requires sending the request.

Each Nitrokey Webcrypt's request is sent over Webauthn using MakeAssertion operation. It allows to transfer 255 bytes to the device, and receive 73 bytes back. The data fields used are:
- `key handle` for sending to device;
- `signature` for receiving from device.


## Commands
For low-level communication two commands are required:
- `WRITE` - to write to the Nitrokey Webcrypt's incoming buffer on the device;
- `READ` - to read from the Nitrokey Webcrypt's outgoing buffer on the device; 

Last packet of the `WRITE` protocol operation executes the command. If there are any results, these will be available in the outgoing buffer, from which client can download the content using `READ` commands. 
in the future this might be minimalized by removing the redundant first call to `READ` by moving first part of the results to the `WRITE` operation response (similarly to [CTAP]).


## Packet structure
| Offset | Length    | Mnemonic       | Comments                                                          |
|--------|-----------|----------------|-------------------------------------------------------------------|
| 0      | 1         | WEBCRYPT_CONST | Always equal to `0x22`.                                           |
| 1      | 4         | __HEADER       | Nitrokey Webcrypt's magic value to recognize extension over FIDO2 |
| 5      | 1         | COMM_ID        | Operation: WRITE (`0x01`) or READ (`0x02`)                        |
| 6      | 1         | PACKET_NUM     | This packet number, 0-255                                         |
| 7      | 1         | PACKET_CNT     | Total packet count, 0-255                                         |
| 8      | 1         | CHUNK_SIZE     | Size of the data chunk, 0-255                                     |
| 9      | 1         | CHUNK_LEN      | Length of the given data chunk, 0-CHUNK_SIZE                      |
| 10     | CHUNK_LEN | DATA           | Data to send                                                      |

Notes:
- Having dynamic `CHUNK_SIZE` allows to change the communication parameters on the fly, and depending on the platform conditions.
- Introducing redundant information in the form of the packet number and count allows identifying potential transmission issues, like doubled packets (Windows 10 Webauthn handling issue).
- Magic value is: `__HEADER = 0x8C2790F6`.
- In the future packet format might be modified to be more compact by removing redundant information (e.g. removing packet sequence information and the current chunk length, but leaving the chunk size; similarly to [CTAP]).



## Data packet structure

| Offset | Length | Mnemonic | Comments |
| ------ | ------ | -------  |  ------- |
| 0  | 1 | COMMAND_ID | Command ID to execute |
| 1  | CHUNK_LEN-1 | DATA | CBOR encoded arguments to the command |


## Incoming packet format for WRITE
| Offset | Length | Mnemonic | Comments |
| ------ | ------ | -------  |  ------- |
| 0  | 1 | RESULT | Result code |

Execution's result code are described under each command description.

## Incoming packet format for READ
| Offset | Length | Mnemonic | Comments |
| ------ | ------ | -------  |  ------- |
| 0  | 2 | DATA_LEN | Data length N |
| 2  | 1 | CMD_ID | Command ID that produced result |
| 3  | DATA_LEN | DATA | Data received |


## Encoding

All parameters to the commands sent in the `DATA` field of the data packet are [CBOR](Concise Binary Object Representation, RFC7049) encoded key-value maps. This method was chosen due to following:
- FIDO2 requires CBOR encoded parameters as well, hence parser and encoder are provided already for FIDO2 supporting devices.
- CBOR handling libraries are available for all major languages, including JavaScript, where the client applications are meant to be developed.

[CBOR]: https://tools.ietf.org/html/rfc7049

## Full packet example

Following is an example Nitrokey Webcrypt packet with `WRITE` operation for the `STATUS` command.
This packet should be provided as an argument for the Webauthn MakeAssertion's `allowCredentials::id` parameter.

![Packet diagram](./images/packet.svg)


# FIDO2 actions relationship
The following are connections between the FIDO2 and Nitrokey Webcrypt:
- On FIDO2 factory reset the Nitrokey Webcrypt's secrets should be reinitialized to random values. 
- The PIN is shared between the FIDO2 and Nitrokey Webcrypt. 
- The secrets are separated and never cross-used between FIDO2 and Nitrokey Webcrypt. 
- The FIDO2 PIN attempt counter should decrease on failed login over Nitrokey Webcrypt.
- The FIDO2 use counter should not change during the use of Nitrokey Webcrypt.

# Javascript Usage

Below is an example of Javascript API usage with OpenPGP.js.

```typescript

    class WebCryptHardwareKeysPlugin {
      async serialNumber() {
        return new Uint8Array(16).fill('A'.charCodeAt(0));
      }

      date() {
        return this.webcrypt_date ? new Date(this.webcrypt_date) : new Date(2019, 1, 1);
      } // the default WebCrypt date for the created keys

      async init() {
        if (this.public_sign === undefined) {
          await WEBCRYPT_LOGIN(WEBCRYPT_DEFAULT_PIN, statusCallback);
          const res = await WEBCRYPT_OPENPGP_INFO(statusCallback);
          this.public_encr = res.encr_pubkey;
          this.public_sign = res.sign_pubkey;
          this.webcrypt_date = res.date;
        }
      }

      async agree({ curve, V, Q, d }) {
        console.log({ curve, V, Q, d });
        const agreed_secret = await WEBCRYPT_OPENPGP_DECRYPT(statusCallback, V);
        return { secretKey: d, sharedKey: agreed_secret };
      }

      async sign({ oid, hashAlgo, data, Q, d, hashed }) {
        const res = await WEBCRYPT_OPENPGP_SIGN(statusCallback, data);
        const resb = hexStringToByte(res);
        const r = resb.slice(0, 32);
        const s = resb.slice(32, 64);
        const reso = { r, s };
        return reso;
      }

      async generate({ algorithmName, curveName, rsaBits }) {
        let selected_pk = this.public_sign;
        if (algorithmName === openpgp.enums.publicKey.ecdh) {
          selected_pk = this.public_encr;
          console.warn(`Selecting subkey: ${selected_pk} for encryption`);
        } else if (algorithmName === openpgp.enums.publicKey.ecdsa) {
          console.warn(`Selecting main: ${selected_pk} for signing`);
        } else {
          console.error(`Not supported algorithm: ${algorithmName}`);
          throw new Error(`Not supported algorithm: ${algorithmName}`);
        }
        return { publicKey: selected_pk, privateKey: null };
      }
    }

    const plugin = new WebCryptHardwareKeysPlugin();

    WebcryptConnection(statusCallback){
        await Webcrypt_Logout(statusCallback);
        await Webcrypt_FactoryReset(statusCallback);
        await Webcrypt_Status(statusCallback);
        await Webcrypt_SetPin(statusCallback, new CommandSetPinParams(new_pin));
        await Webcrypt_Login(statusCallback, new CommandLoginParams(new_pin));
        await plugin.init();
        const { privateKey: webcrypt_privateKey, publicKey: webcrypt_publicKey } = await openpgp.generateKey({
            curve: 'p256',
            userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }],
            format: 'object',
            date: plugin.date(),
            config: { hardwareKeys: plugin }
      });
    }
```
