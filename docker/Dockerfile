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
COPY conanfile.py ./
RUN conan profile detect --force \
    && conan install . --build=missing -of build -s build_type=Release -o build_tests=False

COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src

RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
        -DTTG_BUILD_TESTS=OFF \
    && cmake --build build --target ttg_server

# ---------------------------------------------------------------------------
# Stage 2: runtime. A distroless image keeps the attack surface minimal - no
# shell, no package manager, no unused tooling.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build /src/build/ttg_server /usr/local/bin/ttg_server

EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/ttg_server"]
