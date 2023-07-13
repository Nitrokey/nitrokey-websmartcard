# Milestones

## Deliverables

* Firmware containing the WebCrypt feature.
* A JavaScript library to be used by arbitrary web applications to use Nitrokey WebCrypt.
* Patch to openpgp.js, adding our WebCrypt library and make use of the device key store.
* Documentation

## Options

* OpenPGP Card interface
* RSA support
* OpenPGP.js integration

### A. Firmware

#### I. Establishing PoC

* Communication layer over FIDO2. Estimation assumes no code reuse.
* Initial design and structure for commands - Setting up code structure and design for commands and implementations
* Initialize and restore from seed - Master seed handling. Additional time for security analysis. Basic tests included.
* Generate non-resident key - Key generation. Additional time for security analysis. Basic tests included.
* Sign(to_be_signed_data_hash, key_handle, HMAC, origin) - Expecting simple implementation. Basic tests included.
* Decrypt(to_be_decrypted_data, key_handle, HMAC, origin) - Expecting simple implementation. Basic tests included.
* Status (Unlocked, version, available resident key slots) - Expecting simple implementation. Basic tests included.
* Additional firmware tests - Tests for everyday usage, edge cases, invalid use cases.

#### II. Encrypted storage

* Encrypted resident keys and master key (for derived keys) - for all user data entities

#### III. Resident keys feature

* Write resident key - for external keys only - Expecting simple implementation. Basic tests included.
* Read public key of resident keys - Expecting simple implementation. Basic tests included.

#### IV. FIDO U2F support

* CTAP1 transport layer (for backward compatibility)
* Unlock - For U2F compatibility - Expecting simple implementation. Basic tests included.
* Reset - For U2F compatibility - Expecting simple implementation. Basic tests included.
* Configure - U2F and other options - Expecting simple implementation. Basic tests included.
    * PIN's use - each action, or once per session

#### V. RSA support

* RSA support - firmware side - tests included. For resident keys only.
* RSA support - Nitrokey JS library - Add support to JS library
* RSA support - OpenPGP.js - Add support to 3rd party JS library

#### VI. NFC support

* NFC tests and bug fixes - Tests for NFC interactions (PC/Mobile)

#### B. JavaScript library for web applications

* API design - API design for the JS Nitrokey WebCrypt library
* API implementation - Library implementation
* Tests: both automatic and manual Javascript tests
* JS Demo Application - Demo application, similar to the OnlyKey’s demo + additional features if time permits

#### C. Documentation

* Firmware: Commands and Features - Examples of use (developers-centric, to pick-up framework)
* JavaScript library - Focus on use cases

## Extensions

#### D. OpenPGP Card Interface

* Basic integration - CCID (GnuPG + etc.) and our custom access, assuming Solo’s OpenPGP card integration.
* ECDSA support - Signing function already provided, but the format parsing is to be implemented. Usable for ECC
  encryption.
* ECC decryption
* Feature completion and improvements of given implementation
* Security review and improvements

#### E. OpenPGP.js patch

Patch for OpenPGP.js to use Nitrokey WebCrypt extension (to use our device as key storage, instead of host storage)

* First implementation – decryption operation - JavaScript implementation of the library
* Tests Javascript automatic and manual tests
* Signing
* Key handling:
    * import
    * generation
* Reserved time for additional corrections, developers input
* Documentation of OpenPGP patch changes - Documentation for OpenPGP.js developers/users, to be included by them
