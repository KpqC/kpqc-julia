using KpqC
using Test

const MESSAGE = Vector{UInt8}(codeunits("release-manifest:v3"))
const CONTEXT = Vector{UInt8}(codeunits("kpqc-julia"))

@testset "metadata" begin
    @test length(signature_algorithms()) == 9
    @test length(kem_algorithms()) == 7
    @test algorithm_id(AIMer128f) == "aimer-128f"
    @test algorithm_id(NTRUPlus768) == "NTRU+768"
    @test signature_sizes(HAETAE5) == SignatureSizes(2080, 2752, 2948)
    @test kem_sizes(TiMER) == KEMSizes(672, 832, 608, 32)
    @test Base.Docs.doc(generate_keypair) !== nothing
    @test Base.Docs.doc(encapsulate) !== nothing

    output_error = KpqCOutputSizeError(:sign, 64, 63)
    @test sprint(showerror, output_error) ==
          "KpqC sign returned 63 bytes; expected 64"
end

@testset "signatures" begin
    for algorithm in signature_algorithms()
        sizes = signature_sizes(algorithm)
        keys = generate_keypair(algorithm)
        @test length(keys.public_key) == sizes.public_key
        @test length(keys.secret_key) == sizes.secret_key

        signature = sign(algorithm, MESSAGE, keys.secret_key; context = CONTEXT)
        @test length(signature) == sizes.signature
        @test verify(
            algorithm,
            MESSAGE,
            signature,
            keys.public_key;
            context = CONTEXT,
        )
        @test !verify(algorithm, MESSAGE, signature, keys.public_key)

        altered = copy(signature)
        altered[1] ⊻= 0x01
        @test !verify(
            algorithm,
            MESSAGE,
            altered,
            keys.public_key;
            context = CONTEXT,
        )
    end

    keys = generate_keypair(AIMer128f)
    @test_throws DimensionMismatch sign(AIMer128f, MESSAGE, UInt8[])
    @test !verify(AIMer128f, MESSAGE, UInt8[], keys.public_key)
    @test_throws DimensionMismatch verify(
        AIMer128f,
        MESSAGE,
        zeros(UInt8, signature_sizes(AIMer128f).signature),
        UInt8[],
    )
    @test_throws ArgumentError sign(
        AIMer128f,
        MESSAGE,
        keys.secret_key;
        context = zeros(UInt8, 256),
    )

    empty_signature = sign(AIMer128f, UInt8[], keys.secret_key)
    @test verify(AIMer128f, UInt8[], empty_signature, keys.public_key)

    maximum_context = collect(UInt8, 0:254)
    contextual_signature = sign(
        AIMer128f,
        MESSAGE,
        keys.secret_key;
        context = maximum_context,
    )
    @test verify(
        AIMer128f,
        MESSAGE,
        contextual_signature,
        keys.public_key;
        context = maximum_context,
    )

    padded_message = vcat(0x00, MESSAGE, 0x00)
    padded_secret_key = vcat(0x00, keys.secret_key, 0x00)
    message_view = @view padded_message[2:(end - 1)]
    secret_key_view = @view padded_secret_key[2:(end - 1)]
    view_signature = sign(AIMer128f, message_view, secret_key_view)
    @test verify(AIMer128f, message_view, view_signature, keys.public_key)
    @test !occursin(bytes2hex(keys.secret_key), sprint(show, keys))
end

@testset "key encapsulation" begin
    for algorithm in kem_algorithms()
        sizes = kem_sizes(algorithm)
        keys = generate_keypair(algorithm)
        @test length(keys.public_key) == sizes.public_key
        @test length(keys.secret_key) == sizes.secret_key

        outbound = encapsulate(algorithm, keys.public_key)
        @test length(outbound.ciphertext) == sizes.ciphertext
        @test length(outbound.shared_secret) == sizes.shared_secret
        @test decapsulate(algorithm, outbound.ciphertext, keys.secret_key) ==
              outbound.shared_secret
        @test !occursin(
            bytes2hex(outbound.shared_secret),
            sprint(show, outbound),
        )
    end

    keys = generate_keypair(NTRUPlus768)
    @test_throws DimensionMismatch encapsulate(NTRUPlus768, UInt8[])
    @test_throws DimensionMismatch decapsulate(
        NTRUPlus768,
        UInt8[],
        keys.secret_key,
    )
    @test_throws DimensionMismatch decapsulate(
        NTRUPlus768,
        zeros(UInt8, kem_sizes(NTRUPlus768).ciphertext),
        UInt8[],
    )
    @test !occursin(bytes2hex(keys.secret_key), sprint(show, keys))

    for algorithm in (NTRUPlus768, NTRUPlus864, NTRUPlus1152)
        sizes = kem_sizes(algorithm)
        keys = generate_keypair(algorithm)
        outbound = encapsulate(algorithm, keys.public_key)
        invalid_ciphertext = copy(outbound.ciphertext)
        invalid_ciphertext[1] = xor(invalid_ciphertext[1], 0x01)

        @test_throws KpqCError decapsulate(
            algorithm,
            invalid_ciphertext,
            keys.secret_key,
        )
        @test_throws KpqCError encapsulate(
            algorithm,
            fill(0xff, sizes.public_key),
        )
    end

    for algorithm in (SMAUGT128, SMAUGT192, SMAUGT256, TiMER)
        keys = generate_keypair(algorithm)
        outbound = encapsulate(algorithm, keys.public_key)
        invalid_ciphertext = copy(outbound.ciphertext)
        invalid_ciphertext[1] = xor(invalid_ciphertext[1], 0x01)
        replacement_secret = decapsulate(
            algorithm,
            invalid_ciphertext,
            keys.secret_key,
        )

        @test length(replacement_secret) == kem_sizes(algorithm).shared_secret
        @test replacement_secret != outbound.shared_secret
    end
end
