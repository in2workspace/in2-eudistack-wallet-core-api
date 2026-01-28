# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.0.3](https://github.com/in2workspace/in2-wallet-api/releases/tag/v2.0.2)
### Added
- Added notification endpoint implementation

## [v2.0.2](https://github.com/in2workspace/in2-wallet-api/releases/tag/v2.0.2)
### Fixed
- Fixed did for delete endpoint

## [v2.0.1](https://github.com/in2workspace/in2-wallet-api/releases/tag/v2.0.1)
### Changed
- Set vault's secret mounts as environment variable.

## [v2.0.0](https://github.com/in2workspace/in2-wallet-api/releases/tag/v2.0.0)
### Changed
- Add a condition to make the credential request with or without cryptographic binding
- Added lifeCycleStatus
- Added credential in GET response
- Added credential status check

### Fixed
- Fixed credential request wf
- Label credential request
- Machine credential delete
- Call credential status endpoint without Authorization header

## [v1.4.9](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.9)
### Fixed
- Fixed credentials delete endpoint: Changed @RequestParam for @PathVariable

## [v1.4.8](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.8)
### Fixed
- Fixed credentials delete endpoint: now returns 204 NO CONTENT instead of 200 OK

## [v1.4.7](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.7)
### Fixed
- Error on credential request DTO 

## [v1.4.6](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.6)
### Changed
- Added additional validations for `credentialIssuer` and `credentialConfigurationsIds` fields in `CredentialOfferServiceImpl`, along with new unit tests.
- Refactored and fixed several tests to ensure proper error handling in credential flows.
- Removed the `ConfigProviderName` and `VaultProviderEnum` enums, along with all related Azure logic and configuration (including entries and comments in `application.yml`, `application-test.yaml`, and associated classes).

## [v1.4.5](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.5)
### Changed
- Prepared support for dcql_query (left commented) and removed all remaining presentation_definition logic.
- Added validations for credential format and id.
- Introduced new custom exceptions for OID4VP.

## [v1.4.4](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.4)
### Changed
- Add CORS configuration to health, prometheus and pin endpoints.
- Remove Spring Webflux basepath parameter.

## [v1.4.3](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.3)
### Changed
- Change configurations, make some parameters constants.

## [v1.4.2](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.2)
### Fixed
- Fixed DB type.

## [v1.4.1](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.0)
### Added
- compose.yaml to test the application locally.
### Fixed
- Add the `default-schema` property within the application config file to avoid creating flyway_schema_history table in the public schema.

## [v1.4.0](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.4.0)
### Changed
- Removed support for Context Broker.
- Now the application is using database connection for data storage.

## [v1.3.10](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.3.10)
### Changed
- Changed request-credential endpoint to route requests dynamically between EBSI and common workflows based on the credential offer URI.
- Rename request object to "CredentialOfferRequest".
- Add a timeout property for pin code

## [v1.3.9](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.3.9)
### Fixed
- Create staging profile

## [v1.3.8](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.3.8)
### Fixed
- Update credential contract

## [v1.3.7](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.3.7)
### Fixed
- Fix url in CORS

## [v1.3.6](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.3.6)
### Fixed
- CORS configured internally in the application

## [v1.3.5](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.3.5)
### Fixed
- Change way to get the cors allowed origin urls

## [v1.3.4](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.3.4)
### Fixed
- Update production cors to allow:
    - https://wallet.dome-marketplace-prd.org
    - https://wallet.dome-marketplace.org
    - https://wallet.dome-marketplace.eu

## [v1.3.3](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.3.3)
### Fixed
- Support for different html response codes in attestation

## [v1.3.2]
### Fixed
- LEARCredentialEmployee adapted to W3C DATA MODEL v2.0
### Removed
- Delete Relying Party validation on OID4VP flow.

## [v1.3.1]
### Fixed
- Data models for new cases in credential response

## [v1.3.0]
### Added
- Data models for new cases in credential response
- Support for immediate(sync) issuance for DOME
### Changed
- Added sending of the signed VP using the ES256
### Removed
- Custom logic for the DOME verifier removed

## [v1.2.0](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.2.0) - 2024-05-22
### Added
- Feature for requesting the Signed Credential described in the [OIDC4VCI DOME Profile Deferred Flow - 8 February 2024](https://dome-marketplace.github.io/OpenID4VCI-DOMEprofile/openid-4-verifiable-credential-issuance-wg-draft.html).
- Implement lifecycle status management for the credentials based on [EUDI DOC ARF v1.3.0](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/docs/arf.md#422-pid-and-qeaa-lifecycles).
- Enable automatic update for dependencies.
- Enable Spring security against to authorization server
### Changed
- New Context Broker entities model.

## [v1.1.3](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.2.0) - 2024-04-25
### Fixed
- Added WebClient bean
- Modify post-request in the process of sending the authorization response during the standard presentation flow

## [v1.1.2](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.1.2) - 2024-04-04
### Fixed
- Change the return value from an exception to an empty list when the user doesn't have any credentials.
- Added the logic for selecting the credential that is wanted to be presented during the DOME presentation flow.

## [v1.1.1](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.1.1) - 2024-04-02
### Fixed
- Change the versioning of the api endpoints from v2 to v1
- Change hardcoded verifiable presentation expiration to dynamic variable

## [v1.1.0](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.1.0) - 2024-3-26
### Added
- Support Verifiable Credentials in cwt format
- Introduced the authentication process for Verifiable Presentations flow [OpenID.VP] combined with the Self-Issued OP v2 specification [OpenID.SIOP2]
- Introduced the Verifiable Presentation flow for CWT (Cbor web token) format
- Introduced the abstraction of the configuration and the vault
- Compatibility with the attestation exchange of the DOME marketplace.

## [v1.0.0](https://github.com/in2workspace/in2-wallet-api/releases/tag/v1.0.0) - 2024-2-19
### Added
- Implemented key pair generation using the secp256r1 algorithm.
- Generate did:key identifier from ES256 key algorithm.
- Generate did:key:jwk_jcs-pub identifier from ES256 key algorithm.
- Support Scorpio Context Broker (v.4.1.14).
- Support Orion-LD.
- Support Hashicorp Vault.
- Support AZ Key Vault.
- Introduced EBSI-compliant flows for issuing and presenting digital credentials.
- Developed functionalities for QR content interpretation and credential offer management.
- Enabled the ability to interpret presentation submission filters for credential verification against user criteria.
- Creational Patterns, utilization of the Builder pattern.
- Structural Patterns, implementation of the Facade pattern.
- Factory and Adapter Patterns: Current use of the Factory pattern combined with the Adapter pattern, enhancing the flexibility and reusability of object creation and interaction within the system.
- Type Interpretation in Presentation Definition Filters: Added the ability to interpret the type of Verifiable Credential in Presentation Definition filters, allowing for more precise selection and verification of the credentials presented by the user. This enhancement facilitates adaptation to various use cases where verifying the specific type of the user's verifiable credential is required.
