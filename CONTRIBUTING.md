# Contributing

Thank you for considering a contribution to SafeStay. This repository is
maintained on a best-effort basis. The notes below are short by design:
keep changes focused, keep PRs small, and read the disclaimer in
`DISCLAIMER.md` before working on anything that could change the tool's
risk profile.

## Licensing of contributions

By submitting a pull request to this repository, you agree that your
contribution is licensed under the same MIT terms as the rest of the
project (this is the standard inbound-equals-outbound convention used by
projects hosted on GitHub).

## Building

```bash
make build       # builds ./safestay for the current platform
make build-all   # cross-compiles for macOS/Linux/Windows (amd64+arm64)
```

CI runs `go vet ./...` and `go test -race -count=1 ./...`. Please run the
same locally before opening a PR.

## Style

- Go code follows `gofmt` and standard `go vet` conventions.
- Comments explain *why*, not *what*; the surrounding code already shows
  what.
- New detection rules (vendors, OUI prefixes, ports) should cite a
  publicly verifiable source in the commit message — IEEE OUI registry
  entry, vendor documentation, CVE, security write-up, etc.

## Adding new detection rules

There are three places to extend detection:

- `internal/oui/oui.go` — known camera-brand OUIs and chipset OUIs, plus
  the vendor-name keyword map.
- `internal/oui/mac-vendors.txt` — fallback OUI-to-vendor list (see
  "Regenerating OUI data" below).
- `internal/model/ports.go` — camera-related port database.

Each detection rule should:

1. Be defensibly accurate. False positives erode trust in the tool.
2. Be backed by public references (linked in the PR description).
3. Be paired with at least one test in the corresponding `_test.go`.

## Regenerating OUI data

`internal/oui/mac-vendors.txt` is derived from the IEEE MA-L public OUI
registry. To regenerate it from the authoritative source:

```bash
# Download the current IEEE OUI registry
curl -fsSL https://standards-oui.ieee.org/oui/oui.txt -o /tmp/ieee-oui.txt

# Convert IEEE's text format to the "PREFIX:Vendor Name" form used here.
# (Implementation left to contributors; sketch:)
#   - Find lines of the form "AA-BB-CC   (hex)        Vendor Name"
#   - Emit "AABBCC:Vendor Name"
#   - Sort and write to internal/oui/mac-vendors.txt
```

When you regenerate, please update the date in `NOTICE` and call out the
diff in your PR description.

## Reporting security issues

Do **not** open a public GitHub issue for a security finding. See
`SECURITY.md` for the disclosure channel.

## What is in scope for this project

- Detection of cameras and camera-adjacent devices on the local subnet.
- Physical-check guidance for threats a network scan cannot see.
- Reporting and export functionality.

What is out of scope:

- Active exploitation (default-credential bruteforce, frame grabbing,
  authentication bypass attempts). SafeStay is a passive detector; it
  must not become an offensive tool.
- Cloud or platform integrations (Airbnb API, etc.).
- Cross-subnet, VLAN-hopping, or layer-2 attacks.

PRs adding those capabilities will be declined.
