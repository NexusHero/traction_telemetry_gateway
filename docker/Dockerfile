# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: build. Debian 12 is chosen to match the glibc of the distroless
# runtime below - a binary built against a newer glibc than the runtime ships
# fails at load time. Conan dependencies come from ConanCenter.
# ---------------------------------------------------------------------------
FROM debian:12-slim AS build

ENV DEBIAN_FRONTEND=noninteractive \
    CONAN_HOME=/opt/conan2

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates \
        python3 python3-venv pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Conan in a venv so the system Python stays untouched (PEP 668 safe).
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install "conan>=2.0" \
    && ln -s /opt/venv/bin/conan /usr/local/bin/conan

WORKDIR /src

# Pull dependencies first so this layer can be cached independently of source
# changes. build_tests=False keeps the production image free of test code.
#
# conan.lock is committed and required: the image contains exactly the recipe
# revisions that passed the CVE and licence gates, never whatever ConanCenter
# serves at build time. A missing lockfile fails the COPY instead of silently
# resolving a different, unreviewed graph.
COPY conanfile.py conan.lock ./
RUN conan profile detect --force \
    && conan install . --lockfile=conan.lock --build=missing -of build \
         -s build_type=Release -o build_tests=False

COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src

# libstdc++ and libgcc are linked statically so the runtime image needs
# nothing beyond glibc (see stage 2). Both are covered by the GCC Runtime
# Library Exception, which permits static linking into any binary.
RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
        -DTTG_BUILD_TESTS=OFF \
    && cmake --build build --target ttg_server

# ---------------------------------------------------------------------------
# Stage 2: runtime. A distroless image keeps the attack surface minimal - no
# shell, no package manager, no unused tooling.
#
# base-nossl rather than cc: the server speaks plain HTTP (TLS terminates in
# front of it, see docs/threat-model.md) and never loads libssl, but cc ships
# libssl3 anyway. Every OpenSSL advisory then lands on this image without
# being reachable - grype flagged CVE-2026-75803 that way. A library that is
# not in the image cannot be vulnerable in it.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/base-nossl-debian12:nonroot

COPY --from=build /src/build/ttg_server /usr/local/bin/ttg_server

EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/ttg_server"]
