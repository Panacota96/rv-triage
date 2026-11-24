# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [0.4.1](https://github.com/Panacota96/rv-triage/compare/v0.4.0...v0.4.1) (2026-11-24)


### Performance Improvements

* **verify:** stream the audit log instead of holding every entry ([#15](https://github.com/Panacota96/rv-triage/issues/15)) ([d25b8d2](https://github.com/Panacota96/rv-triage/commit/d25b8d2fa3c4d5ae656730d3581d67a85b511df6))

## [0.4.0](https://github.com/Panacota96/rv-triage/compare/v0.3.1...v0.4.0) (2026-11-21)


### Features

* **update:** check for a newer release (update-check, start-up banner) ([#13](https://github.com/Panacota96/rv-triage/issues/13)) ([f6955b7](https://github.com/Panacota96/rv-triage/commit/f6955b7178ec52b668c841d7de8c3b6077b5ba64))

## [0.3.1](https://github.com/Panacota96/rv-triage/compare/v0.3.0...v0.3.1) (2026-11-19)


### Bug Fixes

* **deps:** drop the unmaintained chrono dependency (RUSTSEC-2026-0543); every date written or read is golden-tested byte-identical ([b608790](https://github.com/Panacota96/rv-triage/commit/b608790c8d927496f94612e83d51b85d21de65de))

## [0.3.0](https://github.com/Panacota96/rv-triage/compare/v0.2.0...v0.3.0) (2026-11-17)


### Features

* **core:** the package manifest names its collection run ([#9](https://github.com/Panacota96/rv-triage/issues/9)) ([98a11c9](https://github.com/Panacota96/rv-triage/commit/98a11c99e7486bb77e7bc0ed8d8350e9e1fe934a))

## [0.2.0](https://github.com/Panacota96/rv-triage/compare/v0.1.0...v0.2.0) (2026-11-16)


### Features

* RV Triage v0.1 — live Windows collection ([#6](https://github.com/Panacota96/rv-triage/issues/6)) ([edabfee](https://github.com/Panacota96/rv-triage/commit/edabfee9742f62b2ed2ae36876407f26f7c031ea))


### Bug Fixes

* **core:** late audit entries and redirected run folders cannot hide an edited output ([10f26ee](https://github.com/Panacota96/rv-triage/commit/10f26eeedd550907cef42f8bb173f4b1b3a62117))
* **core:** re-hash the outputs a run's audit log records in verify-log and verify-case ([d51d588](https://github.com/Panacota96/rv-triage/commit/d51d5884c84bef3b07197a5901de9471cacb0d6d))
* verify-log and verify-case re-hash the outputs the audit log records ([b0ce351](https://github.com/Panacota96/rv-triage/commit/b0ce351e447ef5b65d5d49c218dade50fd1cfdaf))

## [Unreleased]

### Added
- Project scaffolded with rakvor-tool-forge (rust profile) on 2026-11-11.
