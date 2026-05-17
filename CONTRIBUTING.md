# Contributing

Thank you for considering a contribution. This repository is maintained on a
best-effort basis. Keep changes focused and PRs small.

## Licensing of contributions

By submitting a pull request, you agree your contribution is licensed under
the same MIT terms as the rest of the project (inbound-equals-outbound, the
standard GitHub convention).

## Building

```bash
make build       # builds ./safestay for the current platform
make build-all   # cross-compiles for macOS/Linux/Windows (amd64+arm64)
```

CI runs `go vet ./...` and `go test -race -count=1 ./...`. Please run the
same locally before opening a PR.

## Style

- Go code follows `gofmt` and standard `go vet` conventions.
- Comments explain *why*, not *what*.
- New detection rules (vendors, OUI prefixes, ports) should cite a publicly
  verifiable source in the commit message — IEEE OUI registry entry, vendor
  documentation, CVE, security write-up, etc.

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
registry. To regenerate from the source:

```bash
curl -fsSL https://standards-oui.ieee.org/oui/oui.txt -o /tmp/ieee-oui.txt
# Convert IEEE's text format to the "PREFIX:Vendor Name" form used here.
# (Implementation left to contributors.)
```

## Reporting security issues

Do **not** open a public GitHub issue for a security finding. See
`SECURITY.md` for the disclosure channel.

## Scope

In scope:

- Detection of cameras and camera-adjacent devices on the local subnet.
- Physical-check guidance for threats a network scan cannot see.
- Reporting and export functionality.

Out of scope (PRs will be declined):

- Active exploitation of discovered devices: default-credential brute force,
  frame grabbing, authentication bypass, RCE. SafeStay sends ARP/ICMP/TCP/UDP
  probes and TCP connect scans on a fixed port list; it never interacts with
  a discovered service beyond opening and closing a connection.
- Cloud or platform integrations (Airbnb API, etc.).
- Cross-subnet, VLAN-hopping, or layer-2 attacks.
