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

## JSON Web Key (JWK)

JWK is defined in [RFC 7517](https://tools.ietf.org/html/rfc7517).

Both `JWK` and `JWKSet`are supported (_as of v0.0.2_).

[JWK Thumbprint](https://tools.ietf.org/html/rfc7638) is not supported.

JWK Common Parameters are defined in
[RFC 7517 Section 4](https://tools.ietf.org/html/rfc7517#section-4).

Additional key type specific parameters are defined in
[RFC 7518 Section 6](https://tools.ietf.org/html/rfc7518#section-6), and additionally in
[RFC 8037](https://tools.ietf.org/html/rfc8037).

JWK is currently not used in signing JWS, pending features in `ring`. See this
[issue](https://github.com/briansmith/ring/issues/445) in `ring`.

### JWK Common Parameters

|  Parameter | Support |                                    Remarks                                   |
|:----------:|:-------:|:----------------------------------------------------------------------------:|
|    `kty`   |    ✔    | Used during cryptographic operations to ensure the key is of the right type. The `OKP` value defined in [RFC 8037](https://tools.ietf.org/html/rfc8037) is not supported yet. |
|    `use`   |    ✘    |              Can be (de)serialized; but usage is not validated.              |
|  `key_ops` |    ✘    |          Can be (de)serialized; but key operation is not validated.          |
|    `alg    |    ✘    |       Can be (de)serialized; but usage with algorithm is not validated.      |
|    `kid`   |    ✘    |                   Can be (de)serialized; but not processed.                  |
|    `x5u`   |    ✘    |      Can be (de)serialized; but no processing is handled at the moment.      |
|    `x5c`   |    ✘    |      Can be (de)serialized; but no processing is handled at the moment.      |
|    `x5t`   |    ✘    |      Can be (de)serialized; but no processing is handled at the moment.      |
| `x5t#S256` |    ✘    |                           Cannot be (de)serialized.                          |

### JWK Parameters for Elliptic Curve Keys

| Parameter | Support |                                                 Remarks                                                |
|:---------:|:-------:|:------------------------------------------------------------------------------------------------------:|
|   `crv`   |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|    `x`    |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|    `y`    |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |

### JWK Parameters for RSA Keys

|  Parameter  | Support | Remarks                                                                                                |
|:-----------:|:-------:|--------------------------------------------------------------------------------------------------------|
|     `n`     |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|     `e`     |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|     `d`     |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|     `p`     |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|     `q`     |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|     `dp`    |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|     `dq`    |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|     `qi`    |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
|    `oth`    |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
| `oth` → `r` |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
| `oth` → `d` |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |
| `oth` → `t` |    ✘    | Can be (de)serialized; but cannot be used in signing and verification yet pending support from `ring`. |

### JWK Parameters for Symmetric Keys

| Parameter | Support | Remarks |
|:---------:|:-------:|:-------:|
|    `k`    |    ✔    |         |

### JWK Parameters for Octet Key Pair

| Parameter | Support | Remarks |
|:---------:|:-------:|:-------:|
|   `crv`   |    ✘    |         |
|    `x`    |    ✘    |         |
|    `d`    |    ✘    |         |

## JSON Web Signature (JWS)

JWS is defined in [RFC 7515](https://tools.ietf.org/html/rfc7515).

## JWS Registered Headers

The headers are defined in [RFC 7515Section 4](https://tools.ietf.org/html/rfc7515#section-4).

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

Supported as part of [`biscuit::jws::Header`](https://lawliet89.github.io/biscuit/biscuit/jws/struct.Header.html)
(_as of v0.0.2_)

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

## JSON Web Encryption (JWE)
