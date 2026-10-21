module KpqC

using Libdl
using Scratch
import Base: show, showerror, sign

export Algorithm,
    SignatureAlgorithm,
    KEMAlgorithm,
    SignatureSizes,
    KEMSizes,
    KeyPair,
    EncapsulatedSecret,
    KpqCError,
    KpqCOutputSizeError,
    AIMer128f,
    AIMer128s,
    AIMer192f,
    AIMer192s,
    AIMer256f,
    AIMer256s,
    HAETAE2,
    HAETAE3,
    HAETAE5,
    NTRUPlus768,
    NTRUPlus864,
    NTRUPlus1152,
    SMAUGT128,
    SMAUGT192,
    SMAUGT256,
    TiMER,
    algorithm_id,
    signature_algorithms,
    kem_algorithms,
    signature_sizes,
    kem_sizes,
    generate_keypair,
    sign,
    verify,
    encapsulate,
    decapsulate

"""A supported KpqC digital-signature parameter set."""
@enum SignatureAlgorithm::UInt8 begin
    AIMer128f = 1
    AIMer128s
    AIMer192f
    AIMer192s
    AIMer256f
    AIMer256s
    HAETAE2
    HAETAE3
    HAETAE5
end

"""A supported KpqC key-encapsulation parameter set."""
@enum KEMAlgorithm::UInt8 begin
    NTRUPlus768 = 1
    NTRUPlus864
    NTRUPlus1152
    SMAUGT128
    SMAUGT192
    SMAUGT256
    TiMER
end

"""Union of the supported signature and key-encapsulation algorithms."""
const Algorithm = Union{SignatureAlgorithm, KEMAlgorithm}

"""Byte lengths used by a signature algorithm."""
struct SignatureSizes
    public_key::Int
    secret_key::Int
    signature::Int
end

"""Byte lengths used by a key-encapsulation algorithm."""
struct KEMSizes
    public_key::Int
    secret_key::Int
    ciphertext::Int
    shared_secret::Int
end

"""
    KeyPair

A generated public and secret key. The default display redacts the secret key.
"""
struct KeyPair
    public_key::Vector{UInt8}
    secret_key::Vector{UInt8}
end

"""
    EncapsulatedSecret

A KEM ciphertext and its shared secret. The default display redacts the secret.
"""
struct EncapsulatedSecret
    ciphertext::Vector{UInt8}
    shared_secret::Vector{UInt8}
end

"""Error returned by a native KpqC operation."""
struct KpqCError <: Exception
    operation::Symbol
    status::Int
end

"""Error raised when a native operation returns an unexpected output length."""
struct KpqCOutputSizeError <: Exception
    operation::Symbol
    expected::Int
    actual::Int
end

showerror(io::IO, error::KpqCError) =
    print(io, "KpqC ", error.operation, " failed with status ", error.status)

showerror(io::IO, error::KpqCOutputSizeError) = print(
    io,
    "KpqC ",
    error.operation,
    " returned ",
    error.actual,
    " bytes; expected ",
    error.expected,
)

show(io::IO, keys::KeyPair) = print(
    io,
    "KeyPair(public_key=<",
    length(keys.public_key),
    " bytes>, secret_key=<redacted>)",
)

show(io::IO, value::EncapsulatedSecret) = print(
    io,
    "EncapsulatedSecret(ciphertext=<",
    length(value.ciphertext),
    " bytes>, shared_secret=<redacted>)",
)

const SIGNATURE_METADATA = Dict(
    AIMer128f => (id = "aimer-128f", prefix = "kpqc_aimer128f", sizes = SignatureSizes(32, 48, 6944)),
    AIMer128s => (id = "aimer-128s", prefix = "kpqc_aimer128s", sizes = SignatureSizes(32, 48, 4704)),
    AIMer192f => (id = "aimer-192f", prefix = "kpqc_aimer192f", sizes = SignatureSizes(48, 72, 15408)),
    AIMer192s => (id = "aimer-192s", prefix = "kpqc_aimer192s", sizes = SignatureSizes(48, 72, 10320)),
    AIMer256f => (id = "aimer-256f", prefix = "kpqc_aimer256f", sizes = SignatureSizes(64, 96, 31360)),
    AIMer256s => (id = "aimer-256s", prefix = "kpqc_aimer256s", sizes = SignatureSizes(64, 96, 20224)),
    HAETAE2 => (id = "haetae-mode2", prefix = "kpqc_haetae2", sizes = SignatureSizes(992, 1408, 1474)),
    HAETAE3 => (id = "haetae-mode3", prefix = "kpqc_haetae3", sizes = SignatureSizes(1472, 2112, 2349)),
    HAETAE5 => (id = "haetae-mode5", prefix = "kpqc_haetae5", sizes = SignatureSizes(2080, 2752, 2948)),
)

const KEM_METADATA = Dict(
    NTRUPlus768 => (id = "NTRU+768", prefix = "kpqc_ntruplus768", sizes = KEMSizes(1152, 2336, 1152, 32)),
    NTRUPlus864 => (id = "NTRU+864", prefix = "kpqc_ntruplus864", sizes = KEMSizes(1296, 2624, 1296, 32)),
    NTRUPlus1152 => (id = "NTRU+1152", prefix = "kpqc_ntruplus1152", sizes = KEMSizes(1728, 3488, 1728, 32)),
    SMAUGT128 => (id = "SMAUG-T128", prefix = "kpqc_smaugt128", sizes = KEMSizes(672, 832, 672, 32)),
    SMAUGT192 => (id = "SMAUG-T192", prefix = "kpqc_smaugt192", sizes = KEMSizes(1088, 1312, 992, 32)),
    SMAUGT256 => (id = "SMAUG-T256", prefix = "kpqc_smaugt256", sizes = KEMSizes(1440, 1728, 1376, 32)),
    TiMER => (id = "TiMER", prefix = "kpqc_timer", sizes = KEMSizes(672, 832, 608, 32)),
)

const LIBRARY_PATH = Ref{String}()
const LIBRARY_HANDLE = Ref{Ptr{Cvoid}}(C_NULL)

function __init__()
    test_entropy = lowercase(get(ENV, "KPQC_TEST_ENTROPY", "")) in
                   ("1", "true", "yes")
    scratch_suffix = test_entropy ? "-kat" : ""
    scratch_key = "native-$(Base.pkgversion(@__MODULE__))$(scratch_suffix)"
    scratch_root = @get_scratch!(scratch_key)
    library_path = joinpath(scratch_root, "lib", "libkpqc_julia.$(Libdl.dlext)")
    isfile(library_path) || error(
        "KpqC native library is missing; run `import Pkg; Pkg.build(\"KpqC\")`",
    )
    LIBRARY_PATH[] = library_path
    LIBRARY_HANDLE[] = Libdl.dlopen(library_path)
end

"""Return every supported signature algorithm."""
signature_algorithms() = collect(instances(SignatureAlgorithm))

"""Return every supported key-encapsulation algorithm."""
kem_algorithms() = collect(instances(KEMAlgorithm))

"""Return the stable textual identifier for `algorithm`."""
algorithm_id(algorithm::SignatureAlgorithm) = SIGNATURE_METADATA[algorithm].id
algorithm_id(algorithm::KEMAlgorithm) = KEM_METADATA[algorithm].id

"""Return the public-key, secret-key, and signature sizes for `algorithm`."""
signature_sizes(algorithm::SignatureAlgorithm) = SIGNATURE_METADATA[algorithm].sizes

"""Return the public-key, secret-key, ciphertext, and shared-secret sizes."""
kem_sizes(algorithm::KEMAlgorithm) = KEM_METADATA[algorithm].sizes

prefix(algorithm::SignatureAlgorithm) = SIGNATURE_METADATA[algorithm].prefix
prefix(algorithm::KEMAlgorithm) = KEM_METADATA[algorithm].prefix

function native_symbol(algorithm::Algorithm, operation::AbstractString)
    LIBRARY_HANDLE[] == C_NULL && error("KpqC native library is not loaded")
    return Libdl.dlsym(LIBRARY_HANDLE[], Symbol(prefix(algorithm), "_", operation))
end

bytes(value::AbstractVector{UInt8}) = value isa Vector{UInt8} ? value : collect(value)

function require_size(value::AbstractVector{UInt8}, expected::Int, label::String)
    length(value) == expected || throw(DimensionMismatch(
        "$label must contain $expected bytes, received $(length(value))",
    ))
end

function require_context(context::AbstractVector{UInt8})
    length(context) <= 255 || throw(ArgumentError("context must not exceed 255 bytes"))
end

function check_status(operation::Symbol, status::Integer)
    status == 0 || throw(KpqCError(operation, Int(status)))
end

"""
    generate_keypair(algorithm) -> KeyPair

Generate a public and secret key pair for a signature or KEM algorithm.
"""
function generate_keypair(algorithm::SignatureAlgorithm)
    sizes = signature_sizes(algorithm)
    public_key = Vector{UInt8}(undef, sizes.public_key)
    secret_key = Vector{UInt8}(undef, sizes.secret_key)
    status = ccall(
        native_symbol(algorithm, "keypair"),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
    check_status(:keypair, status)
    return KeyPair(public_key, secret_key)
end

function generate_keypair(algorithm::KEMAlgorithm)
    sizes = kem_sizes(algorithm)
    public_key = Vector{UInt8}(undef, sizes.public_key)
    secret_key = Vector{UInt8}(undef, sizes.secret_key)
    status = ccall(
        native_symbol(algorithm, "keypair"),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
    check_status(:keypair, status)
    return KeyPair(public_key, secret_key)
end

"""
    sign(algorithm, message, secret_key; context=UInt8[]) -> Vector{UInt8}

Create a detached signature. `context` may contain at most 255 bytes.
"""
function sign(
    algorithm::SignatureAlgorithm,
    message_value::AbstractVector{UInt8},
    secret_key_value::AbstractVector{UInt8};
    context::AbstractVector{UInt8} = UInt8[],
)
    sizes = signature_sizes(algorithm)
    require_size(secret_key_value, sizes.secret_key, "secret key")
    require_context(context)

    message = bytes(message_value)
    secret_key = bytes(secret_key_value)
    context_bytes = bytes(context)
    signature = Vector{UInt8}(undef, sizes.signature)
    signature_length = Ref{UInt64}(0)
    status = ccall(
        native_symbol(algorithm, "sign"),
        Cint,
        (Ptr{UInt8}, Ref{UInt64}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_length,
        message,
        length(message),
        context_bytes,
        length(context_bytes),
        secret_key,
    )
    check_status(:sign, status)
    Int(signature_length[]) == sizes.signature || throw(KpqCOutputSizeError(
        :sign,
        sizes.signature,
        Int(signature_length[]),
    ))
    return signature
end

"""
    verify(algorithm, message, signature, public_key; context=UInt8[]) -> Bool

Verify a detached signature. Invalid signatures return `false`.
"""
function verify(
    algorithm::SignatureAlgorithm,
    message_value::AbstractVector{UInt8},
    signature_value::AbstractVector{UInt8},
    public_key_value::AbstractVector{UInt8};
    context::AbstractVector{UInt8} = UInt8[],
)
    sizes = signature_sizes(algorithm)
    require_size(public_key_value, sizes.public_key, "public key")
    require_context(context)
    length(signature_value) == sizes.signature || return false

    message = bytes(message_value)
    signature = bytes(signature_value)
    public_key = bytes(public_key_value)
    context_bytes = bytes(context)
    status = ccall(
        native_symbol(algorithm, "verify"),
        Cint,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        length(signature),
        message,
        length(message),
        context_bytes,
        length(context_bytes),
        public_key,
    )
    status == 0 && return true
    status == -1 && return false
    throw(KpqCError(:verify, Int(status)))
end

"""
    encapsulate(algorithm, public_key) -> EncapsulatedSecret

Create a ciphertext and shared secret for the holder of `public_key`.
"""
function encapsulate(algorithm::KEMAlgorithm, public_key_value::AbstractVector{UInt8})
    sizes = kem_sizes(algorithm)
    require_size(public_key_value, sizes.public_key, "public key")

    public_key = bytes(public_key_value)
    ciphertext = Vector{UInt8}(undef, sizes.ciphertext)
    shared_secret = Vector{UInt8}(undef, sizes.shared_secret)
    status = ccall(
        native_symbol(algorithm, "encapsulate"),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
    check_status(:encapsulate, status)
    return EncapsulatedSecret(ciphertext, shared_secret)
end

"""
    decapsulate(algorithm, ciphertext, secret_key) -> Vector{UInt8}

Recover the shared secret using the recipient's secret key.
"""
function decapsulate(
    algorithm::KEMAlgorithm,
    ciphertext_value::AbstractVector{UInt8},
    secret_key_value::AbstractVector{UInt8},
)
    sizes = kem_sizes(algorithm)
    require_size(ciphertext_value, sizes.ciphertext, "ciphertext")
    require_size(secret_key_value, sizes.secret_key, "secret key")

    ciphertext = bytes(ciphertext_value)
    secret_key = bytes(secret_key_value)
    shared_secret = Vector{UInt8}(undef, sizes.shared_secret)
    status = ccall(
        native_symbol(algorithm, "decapsulate"),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
    check_status(:decapsulate, status)
    return shared_secret
end

end
