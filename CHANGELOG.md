# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-20

### Added
- Initial release of @rezzed.ai/dual-auth
- Dual authentication supporting both API keys and Firebase tokens
- AES-256-CBC encryption utilities for secure data handling
- Pluggable API key store system for flexible storage backends
- PBKDF2 key derivation (100,000 iterations, SHA-256) for encryption keys
- Full TypeScript support with complete type definitions
- Dual ESM and CommonJS module support
- Core authentication features:
  - `authenticate()` - Unified authentication for API keys and tokens
  - `hashKey()` - SHA-256 key hashing
  - `deriveEncryptionKey()` - PBKDF2-based key derivation
- Encryption utilities:
  - `encrypt()` - AES-256-CBC encryption with IV
  - `decrypt()` - AES-256-CBC decryption
  - `isEncrypted()` - Encrypted string detection
- Firebase Auth integration via `createFirebaseValidator()`
- Session-specific encryption keys in `AuthContext`
- Custom token validator support
- Comprehensive test suite using Node.js built-in test runner

---

Built by [Rezzed.ai](https://rezzed.ai)
