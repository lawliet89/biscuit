# Supported Features

The crate, does not support all, and probably will never support all of
the features described in the various RFCs, including some algorithms and verification.

A checkmark (✔) usually indicates that the particular feature is supported in the library, although
there might be caveats. Refer to the remark for the feature.

A cross (✘) usually indicates that the feature is _not_ supported by the library. If there is no
intention to ever support it, it will be noted in the remark.

A field that can be serialized or deserialized by the library, but with no particular handling can
either be supported, or unsuppported. See the remark for more details.

## JWT Registered Claims

JWT Registered Claims is defined in [Section 4 of RFC 7519](https://tools.ietf.org/html/rfc7519#section-4).

| Registered Claim | Support |           Remarks           |
|:----------------:|:-------:|:---------------------------:|
|       `iss`      |    ✔    | Validation is left to user. |
|       `sub`      |    ✔    | Validation is left to user. |
|       `aud`      |    ✔    | Validation is left to user. |
|       `exp`      |    ✔    |     Validation provided.    |
|       `nbf`      |    ✔    |     Validation provided.    |
|       `iat`      |    ✔    |     Validation provided.    |
|       `jti`      |    ✔    | Validation is left to user. |

## JWT Private Claims

Optional private claims are supported as part of the [`biscuit::ClaimsSet`](https://lawliet89.github.io/biscuit/biscuit/struct.ClaimsSet.html)
struct. (_as of v0.0.2_)

## JSON Web Signature (JWS)

JWS is defined in [RFC 7515](https://tools.ietf.org/html/rfc7515).

## JWS Registered Headers

The headers are defined in [Section 4](https://tools.ietf.org/html/rfc7515#section-4).

| Registered Header | Support |                               Remarks                              |
|:-----------------:|:-------:|:------------------------------------------------------------------:|
|       `alg`       |    ✔    |                Not all algorithms supported — see below.           |
|       `jku`       |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |
|       `jwk`       |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |
|       `kid`       |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |
|       `x5u`       |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |
|       `x5c`       |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |
|       `x5t`       |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |
|     `x5t#S256`    |    ✘    |                      Cannot be (de)serialized.                     |
|       `typ`       |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |
|       `cty`       |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |
|       `crit`      |    ✘    | Can be (de)serialized, but no processing is handled at the moment. |

## JWS Private Headers

Supported as part of [`biscuit::jws::Header`](https://lawliet89.github.io/biscuit/biscuit/jws/struct.Header.html) (_as of v0.0.2_)

### JWS Algorithms

The algorithms are described [here](https://tools.ietf.org/html/rfc7518#section-3) and additionally
[here](https://tools.ietf.org/html/rfc8037).

| Algorithm | Support |                                Remarks                               |
|:---------:|:-------:|:--------------------------------------------------------------------:|
|   `none`  |    ✔    |                                                                      |
|  `HS256`  |    ✔    |                                                                      |
|  `HS384`  |    ✔    |                                                                      |
|  `HS512`  |    ✔    |                                                                      |
|  `RS256`  |    ✔    |                                                                      |
|  `RS384`  |    ✔    |                                                                      |
|  `RS512`  |    ✔    |                                                                      |
|  `ES256`  |    ✘    | Only verification of signature                                       |
|  `ES384`  |    ✘    | [No plan to support.](https://github.com/briansmith/ring/issues/268) |
|  `ES512`  |    ✘    | Only verification of signature                                       |
|  `PS256`  |    ✔    |                                                                      |
|  `PS384`  |    ✔    |                                                                      |
|  `PS512`  |    ✔    |                                                                      |
|  `EdDSA`  |    ✘    |                                                                      |

### JWS Serialization

| Format         | Support | Remarks |
|----------------|---------|---------|
| Compact        |    ✔    |         |
| General JSON   |    ✘    |         |
| Flattened JSON |    ✘    |         |
