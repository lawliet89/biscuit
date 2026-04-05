# Agent Instructions

This document provides instructions for AI agents working on this repository to ensure consistency with the project's CI/CD standards.

## Testing Requirements

Before making changes or verifying the codebase, you MUST read the project's CI configuration in [.github/workflows/rust.yml](.github/workflows/rust.yml).

1.  **Test Matrix**: Identify the Rust toolchains (e.g., stable, beta, nightly, MSRV) and operating systems defined in the `matrix` section of the workflow.
2.  **Execution Environment**: The project supports multiple operating systems (typically Linux, Windows, and macOS).
    - **Restriction**: Only test on the operating systems available in your current environment. Ignore any operating systems that you cannot access (e.g., if you are running on Linux, do not attempt to run Windows or macOS specific tests unless cross-compilation is explicitly required).
3.  **Verification Steps**: Follow the commands defined in the `steps` section of the workflow (e.g., `cargo fmt`, `cargo clippy`, `cargo build`, `cargo test`, `cargo doc`). Ensure you use the correct flags as specified in the workflow.

By following the workflow file directly, you ensure that your verification process stays aligned with the project's latest CI/CD configuration.
