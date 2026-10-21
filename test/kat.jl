using KpqC
using Libdl
using Test

const VECTOR_ROOT = get(ENV, "KPQC_TEST_VECTORS", "")
isempty(VECTOR_ROOT) && error("KPQC_TEST_VECTORS is not set")
isdir(VECTOR_ROOT) || error("KPQC_TEST_VECTORS does not name a directory")
const SCRATCH_VARIANT = basename(dirname(dirname(KpqC.LIBRARY_PATH[])))
endswith(SCRATCH_VARIANT, "-kat") || error(
    "KATs require a deterministic-entropy build; set KPQC_TEST_ENTROPY=1",
)

function read_vectors(path::String)
    vectors = Dict{String,String}[]
    current = Dict{String,String}()
    for line in eachline(path)
        parts = split(line, " = "; limit = 2)
        length(parts) == 2 || continue
        if parts[1] == "count" && !isempty(current)
            push!(vectors, current)
            current = Dict{String,String}()
        end
        current[parts[1]] = parts[2]
    end
    isempty(current) || push!(vectors, current)
    return vectors
end

field(vector::Dict{String,String}, name::String) = hex2bytes(vector[name])

function entropy_symbol(algorithm::Algorithm, operation::String)
    return KpqC.native_symbol(algorithm, operation)
end

function set_entropy(algorithm::Algorithm, entropy::Vector{UInt8})
    status = ccall(
        entropy_symbol(algorithm, "set_test_entropy"),
        Cint,
        (Ptr{UInt8}, Csize_t),
        entropy,
        length(entropy),
    )
    status == 0 || error("could not install deterministic entropy")
end

function entropy_remaining(algorithm::Algorithm)
    return Int(ccall(
        entropy_symbol(algorithm, "test_entropy_remaining"),
        Csize_t,
        (),
    ))
end

function clear_entropy(algorithm::Algorithm)
    ccall(entropy_symbol(algorithm, "clear_test_entropy"), Cvoid, ())
end

function with_exact_entropy(operation, algorithm::Algorithm, entropy::Vector{UInt8})
    set_entropy(algorithm, entropy)
    try
        result = operation()
        remaining = entropy_remaining(algorithm)
        remaining == 0 || error("deterministic entropy has $remaining unused bytes")
        return result
    finally
        clear_entropy(algorithm)
    end
end

mutable struct DRBG
    key::Vector{UInt8}
    counter::Vector{UInt8}
end

copy_drbg(state::DRBG) = DRBG(copy(state.key), copy(state.counter))

function increment_counter(counter::Vector{UInt8})
    result = copy(counter)
    for index in reverse(eachindex(result))
        result[index] += 0x01
        result[index] == 0x00 || break
    end
    return result
end

function aes256(key::Vector{UInt8}, input::Vector{UInt8})
    output = Vector{UInt8}(undef, 16)
    symbol = Libdl.dlsym(KpqC.LIBRARY_HANDLE[], :kpqc_test_aes256_ecb)
    ccall(symbol, Cvoid, (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}), output, key, input)
    return output
end

function generate_blocks!(state::DRBG, count::Int)
    output = Vector{UInt8}[]
    for _ in 1:count
        state.counter = increment_counter(state.counter)
        push!(output, aes256(state.key, state.counter))
    end
    return output
end

function update!(state::DRBG, provided::Vector{UInt8})
    length(provided) <= 48 || error("DRBG update data must not exceed 48 bytes")
    material = vcat(generate_blocks!(state, 3)...)
    padded = vcat(provided, zeros(UInt8, 48 - length(provided)))
    material .⊻= padded
    state.key = material[1:32]
    state.counter = material[33:48]
    return state
end

function DRBG(seed::Vector{UInt8})
    length(seed) == 48 || error("CTR-DRBG seed must contain 48 bytes")
    return update!(DRBG(zeros(UInt8, 32), zeros(UInt8, 16)), seed)
end

function generate!(state::DRBG, length_value::Int)
    blocks = cld(length_value, 16)
    output = blocks == 0 ? UInt8[] : vcat(generate_blocks!(state, blocks)...)
    update!(state, UInt8[])
    return output[1:length_value]
end

function with_repeated_entropy(
    operation,
    algorithm::Algorithm,
    state::DRBG,
    call_bytes::Int;
    max_calls::Int = 128,
)
    probe = copy_drbg(state)
    entropy = vcat([generate!(probe, call_bytes) for _ in 1:max_calls]...)
    set_entropy(algorithm, entropy)
    try
        result = operation()
        consumed = length(entropy) - entropy_remaining(algorithm)
        consumed > 0 || error("deterministic entropy was not consumed")
        consumed % call_bytes == 0 || error("entropy consumption was not aligned")
        for _ in 1:(consumed ÷ call_bytes)
            generate!(state, call_bytes)
        end
        return result
    finally
        clear_entropy(algorithm)
    end
end

const SIGNATURE_CONFIGURATIONS = [
    (AIMer128f, "aimer/128f", false, 16),
    (AIMer128s, "aimer/128s", false, 16),
    (AIMer192f, "aimer/192f", false, 24),
    (AIMer192s, "aimer/192s", false, 24),
    (AIMer256f, "aimer/256f", false, 32),
    (AIMer256s, "aimer/256s", false, 32),
    (HAETAE2, "haetae/mode2", true, 32),
    (HAETAE3, "haetae/mode3", true, 32),
    (HAETAE5, "haetae/mode5", true, 32),
]

const KEM_CONFIGURATIONS = [
    (NTRUPlus768, "ntruplus/768", 0, 96),
    (NTRUPlus864, "ntruplus/864", 0, 108),
    (NTRUPlus1152, "ntruplus/1152", 0, 144),
    (SMAUGT128, "smaugt/mode1", 2, 32),
    (SMAUGT192, "smaugt/mode3", 2, 32),
    (SMAUGT256, "smaugt/mode5", 2, 32),
    (TiMER, "smaugt/modet", 2, 16),
]

@testset "known-answer tests" begin
    total = 0

    for (algorithm, relative_path, is_haetae, seed_bytes) in SIGNATURE_CONFIGURATIONS
        vectors = read_vectors(joinpath(VECTOR_ROOT, relative_path, "kat.rsp"))
        @test length(vectors) == 100
        for vector in vectors
            state = DRBG(field(vector, "seed"))
            keys = if is_haetae
                with_exact_entropy(
                    () -> generate_keypair(algorithm),
                    algorithm,
                    generate!(state, seed_bytes),
                )
            else
                with_repeated_entropy(
                    () -> generate_keypair(algorithm),
                    algorithm,
                    state,
                    seed_bytes,
                )
            end
            @test keys.public_key == field(vector, "pk")
            @test keys.secret_key == field(vector, "sk")

            message = field(vector, "msg")
            expected_signature = if haskey(vector, "sig")
                field(vector, "sig")
            else
                field(vector, "sm")[(length(message) + 1):end]
            end
            signing_entropy = generate!(state, seed_bytes)
            context = if is_haetae
                context_length = Int(only(generate!(state, 1)))
                generate!(state, context_length)
            else
                UInt8[]
            end
            signature = with_exact_entropy(
                () -> sign(algorithm, message, keys.secret_key; context),
                algorithm,
                signing_entropy,
            )
            @test signature == expected_signature
            @test verify(algorithm, message, expected_signature, keys.public_key; context)
        end
        total += length(vectors)
    end

    for (algorithm, relative_path, key_calls, encapsulation_bytes) in KEM_CONFIGURATIONS
        vectors = read_vectors(joinpath(VECTOR_ROOT, relative_path, "kat.rsp"))
        @test length(vectors) == 100
        for vector in vectors
            state = DRBG(field(vector, "seed"))
            keys = if key_calls == 0
                with_repeated_entropy(
                    () -> generate_keypair(algorithm),
                    algorithm,
                    state,
                    32,
                )
            else
                key_entropy = vcat([generate!(state, 32) for _ in 1:key_calls]...)
                with_exact_entropy(
                    () -> generate_keypair(algorithm),
                    algorithm,
                    key_entropy,
                )
            end
            @test keys.public_key == field(vector, "pk")
            @test keys.secret_key == field(vector, "sk")

            outbound = with_exact_entropy(
                () -> encapsulate(algorithm, keys.public_key),
                algorithm,
                generate!(state, encapsulation_bytes),
            )
            @test outbound.ciphertext == field(vector, "ct")
            @test outbound.shared_secret == field(vector, "ss")
            @test decapsulate(algorithm, outbound.ciphertext, keys.secret_key) ==
                  outbound.shared_secret
        end
        total += length(vectors)
    end

    @test total == 1600
end
