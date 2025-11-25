# Changelog

## [Unreleased] - Branch `auth-project`

### Added
- **Password Grant Support**: Implemented custom classes (`PasswordGrantAuthenticationConverter`, `PasswordGrantAuthenticationProvider`, `PasswordGrantAuthenticationToken`) to enable the OAuth2 Resource Owner Password Credentials Grant flow. This was required for integration with the clinic client registration microservice.
- **JDBC Authorization Service**: Configured `JdbcOAuth2AuthorizationService` and `JdbcOAuth2AuthorizationConsentService` to persist authorization data in the PostgreSQL database.
- **JWT Key Generation**: Added dynamic RSA key pair generation for signing JWTs (`JWKSource`).

### Changed
- **Server Port**: Changed the application server port from `8080` to `9000` to avoid conflicts and match the clinic microservice's expectations.
- **Security Configuration**: heavily refactored `SecurityConfig.java` to include the new authentication providers, token generators, and JDBC services.
- **Client Registration**: Updated the in-memory registered client to support `REFRESH_TOKEN` grant type and `read`/`write` scopes.
- **Auth Controller**: Updated `AuthController` to point to the local token endpoint on port 9000 and added error handling for the internal OAuth2 call.
- **Security**: Switched to `DelegatingPasswordEncoder` to ensure compatibility with standard Spring Security client authentication mechanisms.
