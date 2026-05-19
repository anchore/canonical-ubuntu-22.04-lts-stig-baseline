# Changelog

All notable changes to the `canonical-ubuntu-22.04-lts-stig-baseline` InSpec profile will be documented in this file.

## [Unreleased] - V2R8 Update

### Added

New controls aligned to DISA STIG for Canonical Ubuntu 22.04 LTS V2R8 (Benchmark Date: 01 Apr 2026):

| Control | STIG ID | Severity | Title |
|---------|---------|----------|-------|
| SV-274860 | UBTU-22-432011 | medium | Ubuntu 22.04 LTS must require users to provide a password for privilege escalation. |
| SV-274861 | UBTU-22-654224 | medium | The operating system must restrict privilege elevation to authorized personnel. |
| SV-274862 | UBTU-22-654041 | medium | Ubuntu 22.04 LTS must audit any script or executable called by cron as root or by any privileged user. |
| SV-274864 | UBTU-22-254010 | medium | Ubuntu 22.04 LTS must have the "SSSD" package installed. |
| SV-274865 | UBTU-22-254030 | medium | Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication. |
| SV-274866 | UBTU-22-254015 | medium | Ubuntu 22.04 LTS must use the "SSSD" package for multifactor authentication services. |
| SV-274867 | UBTU-22-254020 | medium | Ubuntu 22.04 LTS must ensure SSSD performs certificate path validation, including revocation checking, against a trusted anchor for PKI-based authentication. |
| SV-278951 | UBTU-22-211000 | high | Ubuntu 22.04 LTS must be a vendor-supported release. |
| SV-279937 | UBTU-22-215040 | high | Ubuntu 22.04 LTS must not have the nfs-kernel-server package installed. |

### Removed

Controls no longer present in the V2R8 XCCDF XML (removed from DISA baseline):

| Control | Title |
|---------|-------|
| SV-260468 | Ubuntu 22.04 LTS must deploy an Endpoint Security Solution. |
| SV-260544 | Ubuntu 22.04 LTS must allow the use of a temporary password for system logons with an immediate change to a permanent password. |
| SV-260551 | Ubuntu 22.04 LTS must display the date and time of the last successful account logon upon logon. |
| SV-260568 | Ubuntu 22.04 LTS must prohibit password reuse for a minimum of five generations. |

### Changed

- `inspec.yml`: Added `/etc/cron.d` and `/var/spool/cron` to the `audit_rule_keynames` input hash with key `cronjobs` to support the new SV-274862 cron audit control.
- `README.md`: Corrected profile documentation from RHEL9 template to Canonical Ubuntu 22.04 LTS content.

---

## [1.0.0] - Initial Release

Initial InSpec profile release aligned to DISA STIG for Canonical Ubuntu 22.04 LTS V1R1 through V2R7.

### Profile Coverage

- 183 InSpec controls mapped to DISA STIG requirements
- Container-aware testing: 78 controls skip automatically when running inside a Docker container via `virtualization.system.eql?('docker')` guards
- SSH-conditional controls (`container-conditional`) run inside containers only when OpenSSH server is present
- Custom `libraries/` helpers for PAM, sudoers, and system matchers
- Input-driven configuration via `inspec.yml` for sudoers paths, SSH settings, audit key names, and more
