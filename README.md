# Go JWT Server

[![Go JWT Server CI](https://github.com/spdeepak/go-jwt-server/actions/workflows/go.yml/badge.svg)](https://github.com/spdeepak/go-jwt-server/actions/workflows/go.yml)

## Features

* 🔐 **Secure Key Management**: Supports either a user-provided secret key or a master key that generates, encrypts (with the master key), and stores a Base64-encoded secret key in the database for signing JWT tokens, enabling an additional security layer by default.

* 🔁 **Refresh Token Rotation**: Implements automatic refresh token rotation — each time a refresh token is used to obtain a new token pair, the existing refresh token is revoked and replaced, reducing the risk of replay attacks and token leakage.

* 🆔 **Token Fingerprinting**: Binds tokens to individual clients using a fingerprint generated from IP address, device name, and user-agent data. This fingerprint is stored in the database and verified on each request to prevent token theft and unauthorized reuse.


## Configuration

### Environment variables

| variable name  | Type                    | Required | Default | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|----------------|-------------------------|----------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| JWT_MASTER_KEY | base64-encoded `string` | No¹      |         | If provided, the server generates a secure random secret key internally, encrypts it using the decoded value of JWT_MASTER_KEY, and stores the encrypted key (base64-encoded) in the database. The decoded master key will be used at runtime to decrypt the stored secret and sign JWT tokens. This provides an extra layer of security by not storing the signing secret in plaintext. It should be 32 bytes long for AES-256. |
| JWT_SECRET_KEY | base64-encoded `string` | No¹      |         | Used directly (after decoding) as the key to sign JWT tokens. Required if JWT_MASTER_KEY is not set. Ensure this key is strong and securely managed.                                                                                                                                                                                                                                                                             |

¹ Note: Either JWT_MASTER_KEY or JWT_SECRET_KEY must be provided. If both are provided, JWT_MASTER_KEY takes precedence,
and the secret key will be internally managed as described above.