# gpg-fingerprint-filter

Generate an OpenPGP key whose fingerprint matches a specific pattern.

Get your lucky key!

```
$ gpg-fingerprint-filter 'FFFFFF$' out.pem
TIMESTAMP = 1581310126
FINGERPRINT = 4a2095b5167a1a2078e4215dc9c3dce9f0ffffff
KEY written to out.pem
$ export PEM2OPENPGP_KEY_TIMESTAMP=1581310126
$ pem2openpgp NONAME < out.pem \
    | gpg --list-packets \
    | grep -Po 'keyid: \K[[:xdigit:]]+$'
C9C3DCE9F0FFFFFF
```
