# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in SafeStay, please
**do not open a public GitHub issue**. Instead, use one of the following
channels:

- GitHub's private vulnerability reporting:
  <https://github.com/Cuzeth/airbnb-safety-tools/security/advisories/new>
- Or open a minimal public issue with no details asking for a private
  contact channel.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- The version of SafeStay you tested (`safestay --version`).
- Your operating system, architecture, and network setup as relevant.

You should expect an acknowledgement within seven days. SafeStay is
maintained on a best-effort basis; there is no formal service-level
agreement for response or remediation time.

## Scope

In scope:

- Code in this repository under `cmd/` and `internal/`.
- The release-artifact build pipeline in `.github/workflows/`.
- The install script `install.sh`.

Out of scope:

- Vulnerabilities in dependencies. Please report those to the dependency
  upstream first. If a SafeStay configuration meaningfully widens the
  blast radius of a dependency issue, that is in scope.
- Findings in the third-party hosts SafeStay connects to during a scan
  (the local network and its devices). SafeStay is the messenger, not the
  target.
- Issues that require physical access to the user's machine or a
  malicious local user with sudo.
- Reports based on running SafeStay against networks you do not own or
  have authorization to scan.

## Supported versions

Only the most recent tagged release is supported. There are no backported
fixes for older releases.

## Verifying release artifacts

Release binaries published at
<https://github.com/Cuzeth/airbnb-safety-tools/releases> are accompanied
by a `checksums.txt` file containing SHA-256 hashes. The file is hosted
over HTTPS but is **not** cryptographically signed — verification protects
against transport corruption, not against a compromised release. To verify
manually:

```bash
curl -L -o safestay-linux-amd64 \
  https://github.com/Cuzeth/airbnb-safety-tools/releases/latest/download/safestay-linux-amd64
curl -L -o checksums.txt \
  https://github.com/Cuzeth/airbnb-safety-tools/releases/latest/download/checksums.txt
shasum -a 256 -c <(grep safestay-linux-amd64 checksums.txt)
```
