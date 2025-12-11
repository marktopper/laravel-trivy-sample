# GitHub Actions Workflows

## Trivy Filesystem Scan

The `trivy-fs-scan.yml` workflow performs security scanning on the codebase using Trivy.

### Test Vulnerabilities

This repository intentionally includes vulnerable packages for testing the Trivy scanner:

- **Livewire 2.12.0** (in `composer.json`) - Has known security vulnerabilities (PKSA-9tny-xycd-bd72)
- **Axios 0.21.1** (in `package.json`) - Has known security vulnerabilities

These packages are included solely for testing purposes to verify that the Trivy scanner correctly detects vulnerabilities. In a production environment, these should be removed and replaced with secure versions.

