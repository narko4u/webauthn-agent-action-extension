# Contributing

Thanks for looking. This repository holds a draft **specification** and its
reference implementation, so contributions fall into two kinds with different
bars.

## Inbound licence (please read first)

By contributing you agree that your contribution is licensed on the same terms
as the material you are contributing to:

- **Specification text and reference implementation** — MIT, matching
  [LICENSE](LICENSE). This is inbound = outbound; there is no CLA to sign.
- **Explanatory prose** (README and other documentation) — CC BY 4.0.

Please sign off your commits (`git commit -s`), certifying the
[Developer Certificate of Origin](https://developercertificate.org/). That is
the whole of the paperwork.

**Do not contribute material you cannot license on these terms.** In particular,
do not paste in code from a third-party project without checking its licence and
saying so in the pull request — see [README § Third-party
material](README.md#third-party-material).

## Invariants

Two things will be rejected regardless of merit:

1. **The pairwise WebAuthn credential must never be used for third-party
   verification.** That is a core privacy property of WebAuthn, and the whole
   reason this profile verifies against a separate, published signing key
   instead. Changes that reintroduce third-party use of the credential are out
   of scope.
2. **The WebAuthn extension identifier used here is `sign`.** This repository
   does not propose, register or rename an extension identifier. See
   [PROVENANCE.md](PROVENANCE.md) for the naming position.

## Changing the specification

The spec file keeps a **constant filename** for link stability, so the content
version and the filename are deliberately out of step. If you change the
specification:

- **Do not rename** `spec/webauthn-agent-authorization-extension-draft-v0.2.md`.
- **Add a row to §11 Revision History** describing the change, with the date.
- Keep attribution current — if you add a third-party reference, add it to the
  acknowledgements *and* the [Third-party material](README.md#third-party-material)
  list, with its actual licence.

Revisions are identified **by commit**, not by date or filename. If your change
matters, say so in [PROVENANCE.md](PROVENANCE.md).

## Changing the implementation

```sh
python3 -m pip install -e ".[test]"
python3 -m pytest -q
```

CI runs the same suite plus a link/asset validation gate. Please make sure both
pass locally before opening a pull request, and add tests for behaviour changes:
the reference implementation exists largely to keep the specification honest,
and a claim in the spec without a test exercising it is a claim we cannot back.

## Pull requests

Small and focused beats large and sweeping. For a substantive spec change,
opening an issue with the rationale first will usually get you a faster and more
useful answer than a large patch.

## Conduct

Be straightforward and be kind. Technical disagreement is welcome and expected;
anything that makes this repository unpleasant to work in is not.
