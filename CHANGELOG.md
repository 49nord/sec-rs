# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2021-04-05

Note: This version was not released on `crates.io`, as it depends on an unreleased `rocket` version.

### Added

- Add a [rocket 0.5](https://github.com/SergioBenitez/Rocket/milestone/8) feature (currently using a dev version).

### Changed

- Rename the `serialize`/`deserialize` feature to `serde`.
- Rename the `diesel_sql` feature to `diesel`.

## [1.0.0] - 2021-04-05

### Added

- Add `test.sh` to run tests.

### Changed

- Use Rust 2018.
- Diesel version supported by the `diesel` feature is now version `1`.
- Switch from Travis CI to Github Actions.
