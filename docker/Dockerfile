# syntax=docker/dockerfile:1

FROM debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS build

ENV DEBIAN_FRONTEND=noninteractive \
    CONAN_HOME=/opt/conan2

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates \
        python3 python3-venv pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY ci/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --require-hashes -r /tmp/requirements.txt \
    && ln -s /opt/venv/bin/conan /usr/local/bin/conan

WORKDIR /src

COPY conanfile.py conan.lock ./
RUN conan profile detect --force \
    && conan install . --lockfile=conan.lock --build=missing -of build \
         -s build_type=Release -o build_tests=False

COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY scripts/check_hardening.sh ./scripts/

RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
        -DTTG_BUILD_TESTS=OFF \
    && cmake --build build --target ttg_server \
    && scripts/check_hardening.sh build/ttg_server

FROM build AS test

RUN conan install . --lockfile=conan.lock --build=missing -of build-test \
         -s build_type=Release -o build_tests=True

COPY tests ./tests
RUN cmake -S . -B build-test -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=build-test/conan_toolchain.cmake \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
        -DTTG_WARNINGS_AS_ERRORS=ON \
    && cmake --build build-test \
    && ctest --test-dir build-test --output-on-failure

FROM gcr.io/distroless/base-nossl-debian12:nonroot@sha256:be40c00dfabd86576d92666e87e406714d5618342de1a0c213ad232de255172e

COPY --from=build /src/build/ttg_server /usr/local/bin/ttg_server

EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/ttg_server"]
