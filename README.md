# go-filenc

This package is a utility package designed for one specific flow: to go from a user-provided passphrase to a persisted Tink AES256CTRHMACSHA256 keyset stored on the filesystem. It does not provide much flexibility in tweaking various parameters aside from file location and salt. It also has not been audited by third-parties or even myself thoroughly.

Here are some potential security pitfalls:

* Key material may be persisted in memory (derived AEAD key, initial passphrase, decrypted keyset)
* Key material rotation is untested and possibly nonfunctional
* Hardcoded parameters may be insecure (can be tweaked in constants.go) 