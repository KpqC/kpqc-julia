using Libdl
using Scratch

const PACKAGE_ROOT = normpath(joinpath(@__DIR__, ".."))
const PACKAGE_UUID = Base.UUID("45a0656f-097c-4f7c-a983-00b6d77854d4")
const NATIVE_ROOT = joinpath(PACKAGE_ROOT, "native")
const PROJECT_CONTENTS = read(joinpath(PACKAGE_ROOT, "Project.toml"), String)
const VERSION_MATCH = match(r"(?m)^version\s*=\s*\"([^\"]+)\"", PROJECT_CONTENTS)
VERSION_MATCH === nothing && error("Project.toml does not contain a package version")
const TEST_ENTROPY = lowercase(get(ENV, "KPQC_TEST_ENTROPY", "")) in
                     ("1", "true", "yes")
const SCRATCH_SUFFIX = TEST_ENTROPY ? "-kat" : ""
const SCRATCH_KEY = "native-$(only(VERSION_MATCH.captures))$(SCRATCH_SUFFIX)"
const SCRATCH_ROOT = get_scratch!(PACKAGE_UUID, SCRATCH_KEY)
const LIBRARY_ROOT = joinpath(SCRATCH_ROOT, "lib")
const LIBRARY_PATH = joinpath(LIBRARY_ROOT, "libkpqc_julia.$(Libdl.dlext)")

function include_paths(source::String)
    name = basename(source)
    third_party = joinpath(NATIVE_ROOT, "third_party")

    if startswith(name, "core_haetae")
        return [joinpath(third_party, "HAETAE", "include")]
    elseif name == "core_ntruplus768.c"
        return [joinpath(third_party, "NTRUplus", "NTRU+768")]
    elseif name == "core_ntruplus864.c"
        return [joinpath(third_party, "NTRUplus", "NTRU+864")]
    elseif name == "core_ntruplus1152.c"
        return [joinpath(third_party, "NTRUplus", "NTRU+1152")]
    elseif startswith(name, "core_smaugt") || name == "core_timer.c"
        return [joinpath(third_party, "SMAUG-T", "include")]
    end

    return String[]
end

function compile_native_library()
    Sys.iswindows() && error("Windows source builds are not supported yet")

    compiler = Base.shell_split(get(ENV, "CC", "cc"))
    isempty(compiler) && error("CC must name a compiler executable")
    sources = sort(filter(
        path -> startswith(basename(path), "core_") && endswith(path, ".c"),
        readdir(NATIVE_ROOT; join = true),
    ))
    isempty(sources) && error("no native KpqC sources were found")

    mkpath(LIBRARY_ROOT)
    rm(LIBRARY_PATH; force = true)

    common_flags = ["-c", "-O2", "-std=c11", "-fPIC"]
    append!(common_flags, Base.shell_split(get(ENV, "CFLAGS", "")))
    if TEST_ENTROPY
        push!(common_flags, "-DKPQC_TEST_ENTROPY")
        append!(sources, [
            joinpath(NATIVE_ROOT, "test", "aes.c"),
            joinpath(NATIVE_ROOT, "test", "aes_bridge.c"),
        ])
    end

    mktempdir(SCRATCH_ROOT; prefix = "build-") do build_root
        objects = String[]
        for source in sources
            object = joinpath(build_root, replace(basename(source), ".c" => ".o"))
            includes = ["-I$path" for path in include_paths(source)]
            run(Cmd([compiler; common_flags; includes; "-o"; object; source]))
            push!(objects, object)
        end

        link_flag = Sys.isapple() ? "-dynamiclib" : "-shared"
        linker_flags = Base.shell_split(get(ENV, "LDFLAGS", ""))
        temporary_library = joinpath(build_root, basename(LIBRARY_PATH))
        run(Cmd([
            compiler;
            link_flag;
            objects;
            linker_flags;
            "-lm";
            "-o";
            temporary_library;
        ]))
        mv(temporary_library, LIBRARY_PATH; force = true)
    end
    println("Built $LIBRARY_PATH")
end

compile_native_library()
