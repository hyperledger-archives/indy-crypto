0.5.0
-  Added new indy_crypto_set_logger endpoint that allows application to register custom log handler. To register default logger application can use indy_crypto_set_default_logger endpoint.
- Incorporated platform-independent serialization of BIG in AMCL to fix a bug with serialization on 32 and 64 bit platforms. NOTE: revocations from older indy-crypto versions will be no longer supported and older versions are not supporting new serialization. Migration is possible, see [IS-1097](https://jira.hyperledger.org/browse/IS-1097)

0.4.4, 0.4.5
- Python wrapper deb now depends on fixed version of libindy-crypto deb

0.4.3
- BLS: add proof of possession functionality
- Remove custom JsonEncodable/Decodable trait from API
- Avoid secrets tracing

0.4.2
- BLS: verification optimization
- Rust API enhancements (add more Clone derives for structures)
- CL: update link-secrets logic - allow to use multiply link-secrets as non-schema attributes

Note:
This version of Indy Crypto can process artifacts from previous one.
But in reason of multiply link-secrets support older versions can't consume CL output of 0.4.2.

0.4.1
- Bugfix: correct format of KeyCorrectness proof JSON representation

0.4.0
- Anoncreds API refactoring for better revocation support


0.3.0
- Revocation support for anoncreds CL


0.2.0
- Anoncreds CL added to the library


0.1.0
- Initial release
- BLS multisignature support.
