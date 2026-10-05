from conan import ConanFile


class TtgConan(ConanFile):
    name = "traction-telemetry-gateway"
    version = "0.1.0"
    license = "MIT"
    author = "Suhay Sevinc"
    description = "Hardened C++ REST gateway for traction telemetry frames - DevSecOps reference pipeline"
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeToolchain", "CMakeDeps"
    options = {"build_tests": [True, False]}
    default_options = {"build_tests": True}

    def requirements(self):
        self.requires("cpp-httplib/0.56.0")
        self.requires("nlohmann_json/3.12.0")
        if self.options.build_tests:
            self.requires("gtest/1.17.0")
