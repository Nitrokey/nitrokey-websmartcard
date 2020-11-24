# Nitrokey Webcrypt Implementation Documentation

This is a documentation of the implemented Nitrokey Webcrypt Milestone 1 interface in the Nitrokey FIDO2. Below a high level description of the commands, as well as low-level protocol details can be found. 

Note: this implementation is early and is subject to change.

## Commands Overview Table



| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0x0 | STATUS | None | `{UNLOCKED,VERSION,SLOTS,PIN_ATTEMPTS}` | - | - |
| 0x1 | TEST_PING | Any / Raw | Any / Raw | - | - |
| 0x2 | TEST_CLEAR | None | None | - | - |
| 0x3 | TEST_REBOOT | None | None | - | - |
| 0x4 | LOGIN | TBD | TBD | - | + |
| 0x5 | LOGOUT | None | None | - | - |
| 0x6 | FACTORY_RESET | None | None | - | + |
| 0x10 | INITIALIZE_SEED | `{ENTROPY}` | `{MASTER,SALT}` | + | + |
| 0x11 | RESTORE_FROM_SEED | `{MASTER,SALT}` | `{HASH}` | + | + |
| 0x12 | GENERATE_KEY | None | `{PUBKEY,KEYHANDLE}` | + | + |
| 0x13 | SIGN | `{HASH,KEYHANDLE}` | `{SIGNATURE,INHASH}` | + | + |
| 0x14 | DECRYPT | `{DATA,KEYHANDLE,HMAC,ECCEKEY}` | `{DATA}` | + | + |
| 0x15 | GENERATE_KEY_FROM_DATA | `{HASH}` | `{PUBKEY,KEYHANDLE}` | + | + |

where for the given command:
- ID is a hexadecimal integer;
- `TEST_` prefixed commands are available only in the development firmware;
- plus `+` sign means a requirement for operation named by this specific column, whereas minus `-` sign is the opposite;
- column `Au`, short from authentication, marks authentication requirement with the `LOGIN` command, before using this command;
- column `Bt`, short from button, marks touch-button press requirement after the command is called, to proceed further.




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
| --- | ------ | ---------- | 
| `ENTROPY` | 40 | Client-sourced bytes to be mixed with HWRNG result |

### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `MASTER` | 32 | Nitrokey Webcrypt's *Master Secret* |
| `SALT` | 8 | Salt |


### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- | 
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |





## Restore from seed (RESTORE_FROM_SEED)
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0x11 | RESTORE_FROM_SEED | `{MASTER,SALT}` | `{HASH}` | + | + |

Sets Nitrokey Webcrypt's secret values as received from the caller. For verification calculates SHA256 hash of the input and returns as `HASH`. 


```
HASH = SHA256(MASTER|SALT)
```

### Input description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `MASTER` | 32 | Nitrokey Webcrypt's Master Secret |
| `SALT` | 8 | Salt |

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
| 0x12 | GENERATE_KEY | None | `{PUBKEY,KEYHANDLE}` | + | + |
| 0x15 | GENERATE_KEY_FROM_DATA | `{HASH}` | `{PUBKEY,KEYHANDLE}` | + | + |


### From hash (GENERATE_KEY_FROM_DATA)

For the actual key generation the FIDO U2F / FIDO2 key generation and wrapping mechanism was reused, but with different constants set. The passphrase is processed through a hash function (e.g. Argon2) with known parameters client side, and the hash result is sent to the device. The received hash is mixed through PBKDF2 with device's salt, then HMAC'ed with the Nitrokey Webcrypt's master key `WC_MASTER_KEY` along with the authentication tag. Finally it is encrypted through another secret key - `WC_MASTER_ENC_KEY`. 

The hash function selection, use and parameters will be standardized in the future.

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
PUBKEY = key_pub
KEYHANDLE = key_handle
```

To discuss:
- if `WC_MASTER_ENC_KEY` use is required to derive a strong key. From the UX perspective it might require user to store another 20-24 words of the backup *Word Seed*, which is not desired.

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




## Sign (SIGN)

| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0x13 | SIGN | `{HASH,KEYHANDLE}` | `{SIGNATURE,HASH}` | + | + |

Using key encoded in `KEYHANDLE` parameter command makes signature over the input hash `HASH` using ECDSA. Returns `SIGNATURE` as a result, as well as the incoming hash `HASH`. 
`KEYHANDLE` authenticity (whether it was generated with given *Master Key* and to use for given *Origin*) is verified before use.
Incoming `HASH` data is repeated on the output for signature confirmation.
The curve used by default is `secp256r1` (NIST P-256 Random). 

Implementation is reused from the FIDO U2F key-wrapped authentication. In pseudocode:
```text
tag[16], key_data_raw[32] = keyhandle[48]
if not authentic(tag): abort
key_pub, key_priv = wc_new_keypair(key_data_raw, appid)
signature = ECC_SIGN(key_priv, hash)
HASH=HASH
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
| `HASH` | 32 | Incoming raw data to sign |

### Errors
| ID | Mnemonic | Description |
| --- | ------ | ---------- |
| 0xF3 | ERR_BAD_FORMAT | Incoming data are malformed |
| 0xF5 | ERR_FAILED_LOADING_DATA | Error during preparing output |




## Decrypt (DECRYPT)
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0x14 | DECRYPT | `{DATA,KEYHANDLE,HMAC,ECCEKEY}` | `{DATA}` | + | + |

Decrypts data given in the `DATA` field, using `KEYHANDLE` *Key Handle* for regenerating the private key, and `ECCEKEY` ephemeral ECC public key for deriving the shared secret using ECDH. Before that this command verifies the data by calculating HMAC over all the fields and comparing with incoming `HMAC` field.
`KEYHANDLE` authenticity (whether it was generated with given *Master Key* and to use for given *Origin*) is verified before use.

Requires PKCS#7 ([RFC 5652]) padded data to the length of multiple of 32.
Work in progress.

Pseudocode:
```text
# in: DATA,KEYHANDLE,HMAC_in,ECCEKEY
tag[16], key_data_raw[32] = KEYHANDLE[48]
if not authentic(tag): abort
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


## Status (STATUS)
| ID | Mnemonic | Parameters | Returns | Au | Bt |
| --- | ------ | ---------- | ---------- | --- | --- |
| 0x0 | STATUS | None | `{VERSION,SLOTS,PIN_ATTEMPTS}` | - | - |


Command requires authentication: no.
Work in progress.

To discuss:
- should `SLOTS` number not be hidden to avoid fingerprinting.

### Input description
None

### Output description
| Field | Size [B] | Description |
| --- | ------ | ---------- | 
| `VERSION` | 1 | implemented Nitrokey Webcrypt's version |
| `SLOTS` | 1 | number of left available Resident Keys slots |
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
| 0x1 | TEST_PING | Any / Raw | Any / Raw | - | - |
| 0x2 | TEST_CLEAR | None | None | - | - |
| 0x3 | TEST_REBOOT | None | None | - | - |

These test commands are introduced to help in the development of the client applications, and are available only in the development version of the firmware:
`TEST_PING` - send and receive data for transport tests (loopback). 

Not implemented at the moment:
- `TEST_CLEAR` - clear current Nitrokey Webcrypt's state;
- `TEST_REBOOT` - reboot device.






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

Last packet of the `WRITE` protocol operation executes the command. If there are any results, these will be available in the outgoing buffer, from which client can download the content using `READ` commands. In future this might be minimalized by removing redundant first call to `READ` (similarly to [CTAP]).


## Packet structure
| Offset | Length | Mnemonic | Comments |
| ------ | ------ | -------  |  ------- |
| 0  | 1 | WEBCRYPT_CONST | Always equal to `0x22`. |
| 1  | 4 | NULL_HEADER | Nitrokey Webcrypt's magic value to recognize extension over FIDO2 |
| 5  | 1 | COMM_ID | WRITE (`0x01`) or READ (`0x02`) |
| 6  | 1 | PACKET_NUM | This packet number, 0-255 |
| 7  | 1 | PACKET_CNT | Total packet count, 0-255 |
| 8  | 1 | CHUNK_SIZE | Size of the data chunk, 0-255|
| 9  | 1 | CHUNK_LEN | Length of the given data chunk, 0-CHUNK_SIZE |
| 10 | CHUNK_LEN | DATA | Data to send  |

Notes:
- Having dynamic `CHUNK_SIZE` allows to change the communication parameters on the fly, and depending on the platform conditions.
- Introducing redundant information in the form of the packet number and count allows to identify potential transmission issues, like doubled packets (Windows 10 Webauthn handling issue).
- Magic value is: `8C 27 90 F6`.
- In future packet format might be modified to be more compact by removing redundant information (similarly to [CTAP]).



## Data packet structure

| Offset | Length | Mnemonic | Comments |
| ------ | ------ | -------  |  ------- |
| 0  | 1 | COMMAND_ID | Command ID to execute |
| 1  | variable | DATA | CBOR encoded arguments to the command |


## Encoding

All parameters to the commands sent in the `DATA` field of the data packet are [CBOR](Concise Binary Object Representation, RFC7049) encoded key-value maps. This method was chosen due to following:
- FIDO2 requires CBOR encoded parameters as well, hence parser and encoder are provided already for FIDO2 supporting devices.
- CBOR handling libraries are available for all major languages, including JavaScript, where the client applications are meant to be developed.

[CBOR]: https://tools.ietf.org/html/rfc7049

## Full packet example


![Packet diagram](./images/packet.svg)


# FIDO2 actions relationship
Following are connections between the FIDO2 and Nitrokey Webcrypt:
- On FIDO2 factory reset the Nitrokey Webcrypt's secrets should be reinitialized to random values. 
- The PIN is shared between the FIDO2 and Nitrokey Webcrypt. 
- The secrets are separeted, and never cross-used between FIDO2 and Nitrokey Webcrypt. 
- The FIDO2 PIN attempt counter should decrease on failed login over Nitrokey Webcrypt.
- The FIDO2 use counter should not change during the use of Nitrokey Webcrypt.

# JS handling

Javascript interface reuses regular FIDO2 calls realized through `navigator.credentials.get()`.
See details at [Webauthn-intro].
Encoding and decoding functions will be shared at a later stage (Milestone 7). 

[Webauthn-intro]: https://www.w3.org/TR/webauthn/#intro

```typescript

  const keyhandle = encode_ctaphid_request_as_keyhandle(cmd, addr, data);
  const challenge = window.crypto.getRandomValues(new Uint8Array(32));

  const request_options:PublicKeyCredentialRequestOptions = {
      challenge: challenge,
      allowCredentials: [{
          id: keyhandle,
          type: 'public-key',
      }],
      timeout: timeout,
      userVerification: "required"  // for FIDO2 PIN verification
      // userVerification: "discouraged"    // for FIDO U2F compatibility
  }

  try {
        const result = await navigator.credentials.get({
            publicKey: request_options
        });
        const response = decode_ctaphid_response_from_signature(assertion.response!);
        return response.data;
  }
  catch (error){
        return Promise.resolve();  // error;
  };
```
