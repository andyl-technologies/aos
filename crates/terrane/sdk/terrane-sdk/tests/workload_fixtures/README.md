# Instance identity fixture key

`instance-test-key.pem` is public RSA test material generated with the AOS-built
OpenSSL tool; `instance-jwks.json` contains its matching public key. It signs synthetic GCE-shaped identities in the integration tests.
It must never be configured as production signing authority or used with live
Google credentials. No real Google identity or private operational key is stored
here.
