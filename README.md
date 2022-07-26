# Nitrokey WebCrypt

## Summary

Nitrokey is an open source hardware USB key for data encryption and two-factor authentication with FIDO. While FIDO is supported by web browsers, using Nitrokey as a secure key store for email and (arbitrary) data encryption requires native software. Therefore email encryption in webmail has not been possible with the Nitrokey until now. At the same time strong end-to-end encryption in web applications all share the same challenge: To store users’ private keys securely and conveniently. Therefore secure end-to-end encryption usually requires native software as well (e.g. instant messenger app) or – less secure – store the user keys password-encrypted on servers. Nitrokey aims to solve these issues by developing a way to use Nitrokey with web applications. To avoid the necessity of device drivers, browser add-on or separate software this project is going to utilize the FIDO (CTAP) protocol. As a result the solution will work with any modern browser (which all support WebAuthn), on any operating system even on Android. This will give any web application the option to store a users’ private keys locally on a Nitrokey they control.

## Terminology

* *Device* refers to a WebCrypt-compliant device, which usually is in the possession of a user and connected via USB, NFC or Bluetooth.
* *Web application* is Javascript-based application, running in browser and potentially communicating between it and the servers in the internet.
* *Client software* is any software communicating with the WebCrypt-compliant device, directly or through a browser. 
* *Browser* is one of the platforms running the *Client software*.
* *Master key* is the main secret key stored on the device. Can be represented by *Word Seed* for backup purposes.
* *Resident key* is different to FIDO's resident keys, but the concept is similar. Webcrypt's Resident Keys are stored on the device, created either by importing or generation.
* *Derived key* is different to FIDO's derived keys, but the concept is similar. The keys are derived from the master secret and given service metadata like using RPID (including domain name) or users additional passphrase.
* *Seed*, or *Word Seed*, is a 24-30 words closed-dictionary phrase, which allows to restore the *Master key* on any device.
* *PIN* is an attempt-count limited password or passphrase, which unlocks the device and allows to run Webcrypt operations.
* *Backup* is a data structure allowing to restore the state of the device on the same or another instance.
* *KDF* stands for key derivation function and is a cryptographic hash function deriving a secret key from the input like passphrase using pseudorandom function.

## Solution

* This solution is inspired by [OnlyKey’s WebCrypt](https://crp.to/2017/11/introduction-onlykey-webcrypt/) proof-of-concept.
* [CTAP2 (FIDO2)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html) is used for future-proofness and avoiding incompatibilities in the long run. [CTAP1 (FIDO U2F)](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html) may be added for backward-compatibility.
* To reduce complexity and increase usability, we focus on ECC only. RSA may be added later and be used only for importing existing keys.
* Hence, integration with GNUK is not important. Given conflicting licenses, we aim to implement an own OpenPGP Card interface optionally.
* Solution should work via USB and NFC and ordinary web browser.

### Keys

This solution will support multiple keys. Keys can be derived on the fly from a master key or imported and stored in the device (resident keys). All key operations (sign, decrypt) require the public key as a parameter. These operations follow this scheme:
1) Check if public key or key handle matches any stored (resident) key and origin. If not, continue with step 2, otherwise step 3.
2) Derive key: key = KDF(master key, key_handle, origin) and verify it's validity against HMAC.
3) Compute key operation with payload.
4) Return result.

* Keys' attributes contain usage flag: encryption/decryption, signing, and both. (TODO: Should this be delegated to web application via key handle or key ID?)
* Master key is 256 bit long.

#### Cross and same origin keys

Keys can be configurable to be used per-origin only which avoids a (potential) privacy risk. Use cases where keys are used among different origins (e.g. email encryption) can disable this option for their keys.

For same-origin resident keys, the origin is stored along with the secret key. When accessing the key and an origin is stored (hence, it's a same-origin key), the device verifies the origin.

For same-origin derived keys, the origin is provided as input to the KDF. This way same-origin and cross-origin cases result in different keys.

When calling an operation, the web application chooses (by parameter) if a same-origin or cross-origin key is addressed. The actual origin is provided by the browser (not by the web application).

### PIN

The PIN is required to authenticate the user during authorizing key operations. I suggest that it be made configurable if a) the PIN is required for every operation or b) PIN is required only once per device session. In any case, a touch confirmation (button press) is required to authorize every sign and decrypt operation.

We use WebAuthn's PIN mechanism because it promises better interoperability and higher security (PIN is not exposed to JavaScript). The caveat is that this will work with MS Edge only for now. We expect other web browsers will support PIN handling in the future. For now we may need to have it backward compatible and handle the PIN entry in JavaScript. This will be a configuration option so that Edge-only users could disable it and therefore protect their device PIN from DoS.

### Backup and Seed

The seed is setup during initializing the device and used to derive a master key which is used to derive keys (and as a source to encrypt resident keys). All device-generated keys can be re-generated by providing the seed, which acts as a backup. A seed allows to recover the entire device on its own. The only exception are keys which are imported by the user. Those are not restored by the seed but it's assumed that a key backup exists already. [Here is a POC](https://github.com/skeeto/passphrase2pgp) for generating ECC keys from passphrase/seed, and storing them in an OpenPGP format.

### Commands

* Initialize or restore from seed
* Generate non-resident key
* Write resident key - for externally existing keys only
* Read public key of resident and derived keys
* Sign(to_be_signed_data_hash, key_handle, HMAC, origin)
* Decrypt(to_be_decrypted_data, key_handle, HMAC, origin)
* Status (Unlocked, version, available resident key slots)
* Configure (see above)
* Unlock - For U2F compatibility.
* Reset - For U2F compatibility.

## Questions & Answers

#### Reasoning for Derived Keys

Using derived keys (as opposed to resident keys) by default provides the following benefits:

* For encryption use cases such as we want to enable with WebCrypt, a backup mechanism is a fundamental prerequisite. At the same time the entire solution should be as easy to use as possible. Therefore we aim to provide an easy to use backup mechanism. A seed phrase or backup phrase is the most easy mechanism we could think of. For technical reasons a backup seed demands derived keys in ECC format (not RSA). As opposed to a backup seed, a classical file backup would have these disadvantages:
  * A backup file needs to be stored separately and (usually) protected with a passphrase.
  * A new backup file needs to be created and stored again and again after generating a new key. 
  * Practice proofs that backups are often not executed properly. This might result in user frustration when they can't access their encrypted data anymore.
* Having a single or few resident keys might enable malicious websites to track users' devices which could violate their privacy. Therefore it's beneficial to assume derived keys as the default.
* With resident keys, the amount of keys  (key storage) would be limited. As opposed to this an unlimited amount of derived keys could be used.

## Deliverables

* Firmware containing the WebCrypt feature.
* A JavaScript library to be used by arbitrary web applications to use Nitrokey WebCrypt. 
* Optional: Patch to openpgp.js adding our WebCrypt library and make use of the device key store.
* Documentation

## Options

* OpenPGP Card interface
* RSA support
* OpenPGP.js integration

## Milestones

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
* ECDSA support - Signing function already provided, but the format parsing is to be implemented. Usable for ECC encryption.
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
