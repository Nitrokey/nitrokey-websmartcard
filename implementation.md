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


## Initialize
 
## Restore from seed

## Generate non-resident key

## Read public key of resident keys

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
