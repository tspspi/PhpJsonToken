# PHP JSON web token class

This is a small class that uses the openssl and hash PHP extensions to implement
JSON web tokens (JWS) - currently without encryption or nesting support.

The class allows to create a simple keychain file that can be distributed to
all systems that verify signatures. Note that this distributed file should not
contain private keys for RSA signatures.

The class checks some basic constraints like issuer, expiration date, not valid
before date and an valid issued at date. It supports signature verification via
the HMAC mechanisms HS256, HS384 and HS512 as well as RSA signatures RS256, RS384
and RS512