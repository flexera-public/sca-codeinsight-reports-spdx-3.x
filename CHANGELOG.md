# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.3.2] - 2026-08-28
### Changed
- Inclusion of License Expression and File Hash Fixes

## [6.3.1] - 2024-10-09
### Changed
-Check for vim-vim component, API takes a long time due to the massive number of versions

## [6.3.0] - 2023-10-16
### Changed
- Move to common submodule with support for tomcat upgrade
- Update to common 3.6.8 env

## [6.2.0] - 2023-03-21
### Changed
- Common registration script with registration_config.json file

## [6.1.0] - 2023-02-01
### Changed
- Logo update

## [6.0.13] - 2022-12-06
### Fixed
- Support for component versions without a name

## [6.0.12] - 2022-11-03
### Fixed
- Natural sort for versions back

## [6.0.11] - 2022-09-28
### Fixed
- Updated requirements for common report env
- Fixed issue when single vesion in ignore list (unknown, etc)

## [6.0.10] - 2022-05-23
### Fixed
- Registration updates

## [6.0.9] - 2022-03-30
### Added
- Inventory roll up colors for project hierarchy

## [6.0.8] - 2022-02-10
### Added
- Support for self signed certificates

## [6.0.7] - 2021-12-15
### Fixed 
- jstree project hierarchy display

## [6.0.6] - 2021-12-15
### Changed
- Updated requirements

## [6.0.5] - 2021-12-01
### Changed
- Update submodules to flexera-public repos

## [6.0.4] - 2021-11-16
### Changed
- Fixed support for server_properties.json file

## [6.0.3] - 2021-11-05
### Added
- Migrate to branding submodule for xlsx support
- Clean up unknown license/versions and add complaince message
- Standardize report name and time stamps for all artifacts
- Break out report artifact formats into separate files
### Changed
- Fix xlsx based hierarchy sorting

## [6.0.2] - 2021-10-26
### Added
- Update name of common config file to reflect it is a json file vs a prop file
- Improved logging for collecting data and creating artifacts
- Invalid version support for compliance

## [6.0.1] - 2021-10-25
### Added
- First release to support installer based installation of reports
- Updated registration to use core.server.properties file
- Updated report generation script to use core.server.properties file
- Updaete README.md to reflect changes

## [5.0.1] - 2021-09-30
### Added
- Merge compliance report details into inventory report
- Clean up output
- Add report version to artifacts

## [4.0.1] - 2021-09-09
### Added
- Include xlxs report to artifacts
- Update artifact names to include project name
- Update to SPDX license vs full license name

## [3.0.4] - 2021-06-07
### Added
- Artifact file name changes based on project ID and time
- RESTAPI submodule update

## [3.0.3] - 2021-06-01
### Added
- Add update capability to registration script
- Add ability to read from common config file

## [3.0.2] - 2021-05-20
### Added
- Modified data table display option to include all inventory items

## [3.0.1] - 2021-05-16
### Added
- Added report option for including child projects
- Added report option for CVSS version
- Modify report artifact names based on project name

## [2.2.0] - 2021-03-16
### Added
- Bumped APIs for 2021R1 support due to vulnerability key changes

## [2.1.0] - 2020-12-15
### Added
- Bumped APIs for 2020R4 support
- Using roll up APIs from 2020R4
- Misc cleanup

## [2.0.0] - 2020-10-20
### Added
- Incorperated child project information
- Added application summary view
- Added project summary view
- Added project hierarchy tree


## [1.0.3] - 2020-09-24
### Added
- Initial public release of project inventory report
- Summary table for inventory items within a project