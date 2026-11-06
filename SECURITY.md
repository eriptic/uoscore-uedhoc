# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities through
[GitHub Private Vulnerability Reporting](https://github.com/eriptic/uoscore-uedhoc/security/advisories/new).

Do not report security vulnerabilities in public issues, discussions, or pull requests. Please include:
- The affected version, commit, platform, and build configuration.
- The security impact and conditions needed to reproduce it.
- A minimal proof of concept or test case, if available.
- Any relevant details about the cryptographic backend or hardware.

Please avoid including real secrets, production keys, or sensitive device data in a report.

## Scope

Reports are especially useful for issues involving:
- Out-of-bounds access, memory corruption, or unsafe handling of malformed CBOR or protocol messages.
- Cryptographic key handling, entropy, or EDHOC authentication.
- OSCORE nonce reuse, sender sequence numbers, or replay protection.
- Security-relevant behavior in the library’s cryptographic or transport integration.

Issues in downstream applications or platform-specific integrations may need to be reported to their maintainers as well.

## Supported versions

Security fixes are applied to the latest code on the `main` branch. This project has no LTS branches, and previous releases are not maintained or guaranteed to receive backported security fixes. Users should upgrade to a release that includes the fix or use the latest code from `main`.

## Response and disclosure

Maintainers will acknowledge reports and coordinate investigation, fixes, and public disclosure with the reporter. Please allow time for a fix to be prepared before sharing details publicly.

We aim to acknowledge reports within 15 business days and provide an update at least every 30 business days.
