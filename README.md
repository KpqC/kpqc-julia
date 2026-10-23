# KpqC

KpqC provides synchronous Julia APIs for the AIMer and HAETAE signature
schemes and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs).
This Julia package is independently maintained and is not an official
distribution from the algorithm authors.

## Runtime support

- Julia 1.10 or newer
- A C11 compiler
- macOS or Linux

The package bundles its native algorithm sources and builds them locally. It
does not download native libraries during compilation.

## Install

Install the registered package with Julia's package manager:

```julia
pkg> add KpqC
```

To work from a source checkout, use the package manager from the repository
root:

```julia
pkg> develop .
pkg> build KpqC
```

## Available schemes

| Algorithm | Type | Values |
| --- | --- | --- |
| **AIMer** | Signature | `AIMer128f`, `AIMer128s`, `AIMer192f`, `AIMer192s`, `AIMer256f`, `AIMer256s` |
| **HAETAE** | Signature | `HAETAE2`, `HAETAE3`, `HAETAE5` |
| **NTRU+** | KEM | `NTRUPlus768`, `NTRUPlus864`, `NTRUPlus1152` |
| **SMAUG&#8209;T** | KEM | `SMAUGT128`, `SMAUGT192`, `SMAUGT256`, `TiMER` |

### Signatures

```julia
using KpqC

keys = generate_keypair(AIMer128f)
message = Vector{UInt8}(codeunits("release-manifest:v3"))
signature = sign(AIMer128f, message, keys.secret_key)
@assert verify(AIMer128f, message, signature, keys.public_key)
```

`sign` and `verify` accept an optional `context` keyword containing at most 255
bytes. Verification fails when the supplied context differs from the signing
context.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```julia
using KpqC

recipient = generate_keypair(SMAUGT192)
outbound = encapsulate(SMAUGT192, recipient.public_key)
inbound = decapsulate(
    SMAUGT192,
    outbound.ciphertext,
    recipient.secret_key,
)
@assert inbound == outbound.shared_secret
```

## Data and failures

Keys, signatures, ciphertexts, messages, contexts, and shared secrets are
represented as `Vector{UInt8}` values. Secret values are redacted from the
default display of `KeyPair` and `EncapsulatedSecret`. Native operation failures
raise `KpqCError`; unexpected native output lengths raise
`KpqCOutputSizeError`; invalid argument lengths raise `DimensionMismatch`.
Invalid signatures return `false`.

NTRU+ rejects non-canonical public keys and invalid ciphertexts. SMAUG-T uses
implicit rejection and returns a replacement secret for an invalid ciphertext;
it will not equal the sender's shared secret.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Value | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `AIMer128f` | 32 | 48 | 6,944 |
| `AIMer128s` | 32 | 48 | 4,704 |
| `AIMer192f` | 48 | 72 | 15,408 |
| `AIMer192s` | 48 | 72 | 10,320 |
| `AIMer256f` | 64 | 96 | 31,360 |
| `AIMer256s` | 64 | 96 | 20,224 |
| `HAETAE2` | 992 | 1,408 | 1,474 |
| `HAETAE3` | 1,472 | 2,112 | 2,349 |
| `HAETAE5` | 2,080 | 2,752 | 2,948 |

#### KEMs

| Value | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `NTRUPlus768` | 1,152 | 2,336 | 1,152 | 32 |
| `NTRUPlus864` | 1,296 | 2,624 | 1,296 | 32 |
| `NTRUPlus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `SMAUGT128` | 672 | 832 | 672 | 32 |
| `SMAUGT192` | 1,088 | 1,312 | 992 | 32 |
| `SMAUGT256` | 1,440 | 1,728 | 1,376 | 32 |
| `TiMER` | 672 | 832 | 608 | 32 |

## Tests

```sh
julia --project=. -e 'using Pkg; Pkg.build(); Pkg.test()'
```

The optional known-answer suite validates all 1,600 records from the pinned
[KpqC/kpqc-test-vectors at commit d75490bf824f](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da):

```sh
KPQC_TEST_ENTROPY=1 julia --project=. deps/build.jl
KPQC_TEST_ENTROPY=1 KPQC_TEST_VECTORS=../kpqc-test-vectors \
  julia --project=. test/kat.jl
```

The KAT build uses a separate Scratch space, so it does not replace the normal
native library. Deterministic entropy hooks are available only when
`KPQC_TEST_ENTROPY=1` is set.

## Security

The native cores are compiled from the upstream reference implementations.
This package has not received an independent security audit and does not
guarantee constant-time execution. Julia-managed secret byte arrays are not
guaranteed to be scrubbed when reclaimed. Assess these constraints before using
the package with sensitive production keys. Equality comparisons on secret byte
arrays are not guaranteed to run in constant time.

Algorithm encodings and parameter sizes follow the exact upstream revisions
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and may differ from
other revisions of the same algorithms.
