# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.7] - 2026-08-04

### Added

- Professionalize repository structure to match ANSSI-FR/MLA conventions

### Fixed

- Modernize CI/CD workflows: replace deprecated `actions-rs/*` with `dtolnay/rust-toolchain`, direct cargo commands, `rustsec/audit-check`
- Replace deprecated release actions with `actions/create-release` + `actions/upload-release-asset`
- Fix release workflow version extraction and `cargo_arg` bug
- Add `.cargo/config.toml` for Windows static linking
- Bump dependencies to fix 11 security vulnerabilities

## [0.4.6] - 2026-02-21

### Added

- Optimize runtime performance at compilation

### Fixed

- Bump and minimize dependencies

## [0.4.5] - 2025-03-03

### Fixed

- Bump dependencies
- Fix for new github release workflow

## [0.4.4] - 2025-01-03

### Added

- Add `Cargo.lock`
- Pin all github actions

### Fixed

- Bump dependencies
- Release github workflow

## [0.4.3] - 2024-06-13

### Added

- Added philosophy and some performances

### Fixed

- Bump dependencies

## [0.4.2] - 2023-05-29

### Fixed

- Size optimization for release mode
- Bump dependencies

## [0.4.1] - 2023-03-10

### Fixed

- Size optimization for release mode
- Bump dependencies

## [0.4.0] - 2022-12-21

### Added

- Idiomatic Rust with Error Handling

### Fixed

- Major codebase refactors and fixes to work with idiomatic Rust

## [0.3.5] - 2022-09-29

### Fixed

- Bump dependencies

## [0.3.4] - 2022-09-21

### Fixed

- Results folder creation fixes

## [0.3.3] - 2022-07-20

### Fixed

- Dependencies update

## [0.3.1] - 2022-07-18

### Fixed

- Profile fetching minor fixes

## [0.3.0] - 2022-07-16

### Added

- Get emails from a GitHub profile
- Unauthenticated requests added
- CI/CD workflow implemented
- Documentation from `cargo` generated

### Fixed

- Code quality improved

## [0.2.0] - 2022-06-08

### Added

- Get emails from a GitHub repository
- Aggregate repositories from a metadata search to retrieve their author emails
- Parse author from several GitHub repository URLs formats
- Parse repository from several GitHub repository URLs formats
