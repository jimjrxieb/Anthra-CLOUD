# OSCAL — Machine-Readable Compliance

[OSCAL](https://pages.nist.gov/OSCAL/) (Open Security Controls Assessment Language)
is NIST's standard for machine-readable security compliance documentation.

FedRAMP requires OSCAL-formatted SSPs for new authorizations.

## Files

| File | Purpose |
|------|---------|
| `ssp-profile.json` | System Security Plan referencing FedRAMP Moderate baseline |
| `component-definitions/iron-legion.json` | Iron Legion as OSCAL component with control satisfaction statements |

## Usage

```bash
# Validate OSCAL with compliance-trestle (follow-up Gemini task)
trestle validate -f ssp-profile.json
```

## Next Steps (Gemini Tasks)

- Expand SSP with full 323-control coverage
- Generate POA&M in OSCAL format
- Import into compliance-trestle workspace
- Generate human-readable SSP from OSCAL source
