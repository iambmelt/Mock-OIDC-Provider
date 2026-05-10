# Changelog

All notable changes to the Mock OIDC Provider project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-10

### Added

#### Phase 1: Foundation (May 2026)
- Initial Flask-based OIDC Provider implementation
- Core OAuth 2.0 and OpenID Connect flow support
- Authorization code grant flow with PKCE support
- Token generation with JWT and cryptographic signing
- OpenID Connect Discovery endpoint (/.well-known/openid-configuration)
- JWKS (JSON Web Key Set) endpoint for key distribution
- User authentication and consent flows via templates
- Request ID middleware for request tracing
- Structured logging with structlog (JSON and console output modes)
- Token introspection endpoint
- Token revocation endpoint
- Refresh token flow support
- Client credential validation (Basic Auth and form-encoded)

#### Phase 2: Multi-User & Configuration (May 2026)
- User configuration loading from JSON files
- Client configuration with dynamic redirect URIs
- Support for user attributes (name, email, groups)
- Configurable token TTLs (auth codes, access tokens, ID tokens, refresh tokens)
- PKCE enforcement via CLI flag
- Custom issuer URI override
- User and client JSON file loading

#### Phase 3: Advanced Security (May 2026)
- Refresh token rotation and revocation
- JTI (JWT ID) tracking for token revocation
- Scope validation and enforcement
- PKCE edge cases and validation improvements
- Concurrent operation handling
- Rate limiting preparation

#### Phase 4: Testing & Quality (May 2026)
- Comprehensive test suite with 336+ tests
- Test coverage >85% across codebase
- Tests for all OAuth 2.0 grant types
- PKCE validation and edge case tests
- Concurrent operation tests
- Error handling and edge case coverage
- Test fixtures and configuration utilities

#### Phase 5: Polish & Features (May 2026)
- Client secret handling improvements
- Error messaging enhancements
- Response type validation
- Callback endpoint improvements
- Convenience functions for token exchange
- Request/response formatting improvements
- Configuration validation

#### Phase 6: Deployment (May 2026)
- **Docker Support**
  - Multi-stage Dockerfile using Python 3.12-slim
  - Layer caching optimization (dependencies installed first)
  - Non-root user execution for security (UID 1000)
  - Health check endpoint at /health with uptime tracking
  - Final image size <150MB
  - Self-signed SSL certificate generation with --ssl-quickboot

- **Docker Compose**
  - Service definition with port mapping (4567:4567)
  - Health check configuration
  - Volume mounting for custom user/client configuration
  - CLI override examples in comments
  - Sensible defaults for development

- **/health Endpoint**
  - HTTP 200 response with JSON payload
  - Returns uptime in seconds since application startup
  - Used by container orchestration systems for health monitoring
  - Lightweight and fast endpoint

- **GitHub Actions CI/CD**
  - Matrix testing across Python 3.10, 3.11, 3.12
  - Automated linting with black and ruff
  - Type checking with mypy
  - Security scanning with bandit
  - Coverage enforcement at 85% threshold
  - Docker image build and smoke test
  - Container startup verification
  - Health endpoint verification
  - Automatic caching of build artifacts

- **GitHub Actions Release Workflow**
  - Tag-triggered releases (v*) 
  - Automatic Docker image build and push to GitHub Container Registry (GHCR)
  - Semantic versioning support
  - Latest tag management on main branch
  - Automatic release notes generation
  - Release assets (Dockerfile, docker-compose.yml, CHANGELOG.md)
  - GitHub Release creation with metadata

- **Container Security**
  - Non-root user (app) with UID 1000
  - Read-only recommendations in comments
  - No hardcoded secrets in workflows
  - GitHub Secrets integration for GHCR authentication
  - Security scanning in CI pipeline

### Technical Details

#### Test Coverage
- **Phase 1-5**: 336+ tests with >85% code coverage
- All tests continue to pass in Phase 6

#### Python Support
- Python 3.10, 3.11, 3.12 (primary: 3.12)
- Single codebase, multiple version testing via CI

#### Dependencies
- **Runtime**: Flask 3.0+, PyJWT 2.8+, cryptography 42+, structlog 24+
- **Development**: pytest 8+, pytest-flask 1.3+, coverage 7+, black, ruff, mypy, bandit

#### Docker Image Specifications
- **Base Image**: python:3.12-slim
- **Target Size**: <150MB (achieved through multi-stage build)
- **Default Port**: 4567
- **Default Entrypoint**: `mock-oidc --ssl-quickboot`
- **Health Check**: HTTP GET /health every 10 seconds
- **User**: Non-root user 'app' (UID 1000)

### Breaking Changes
None in Phase 6. All endpoints remain backward compatible.

### Deprecations
None in Phase 6.

### Security Considerations
1. Containers run as non-root user (app/UID 1000)
2. GitHub Actions workflows use GITHUB_TOKEN for authentication
3. GHCR pushed only on version tags from main branch
4. CI pipeline includes security scanning (bandit)
5. No hardcoded credentials in repository
6. Health endpoint available to orchestration systems for monitoring

### Known Limitations
1. Docker Compose health check requires curl in base image (not installed by default)
   - Alternative: Remove curl requirement or build custom health check image
2. Self-signed certificates with --ssl-quickboot are for development only
3. No persistent storage between container restarts without volume mounting
4. Read-only root filesystem requires additional configuration beyond current Dockerfile

### Migration Guide
No migration required from Phase 5 to Phase 6. All existing functionality remains unchanged.

---

## Summary of All Phases

| Phase | Feature | Status | Date |
|-------|---------|--------|------|
| 1 | Foundation: Core OIDC Provider | Complete | May 2026 |
| 2 | Multi-User & Configuration | Complete | May 2026 |
| 3 | Advanced Security | Complete | May 2026 |
| 4 | Testing & Quality | Complete | May 2026 |
| 5 | Polish & Features | Complete | May 2026 |
| 6 | Deployment: Docker & CI/CD | Complete | May 2026 |

### Coverage Timeline
- Phase 1-2: Initial implementation, basic tests
- Phase 3-4: Comprehensive testing, >85% coverage achieved
- Phase 5: Feature refinement, coverage maintained
- Phase 6: Deployment infrastructure, coverage maintained >85%

[Unreleased]: https://github.com/yourusername/mock-oidc-provider/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/mock-oidc-provider/releases/tag/v0.1.0
