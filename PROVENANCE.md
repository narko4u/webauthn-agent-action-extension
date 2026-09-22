# Provenance

This file records where the text in this repository came from and which revision
you are reading, so that both can be traced from the bytes rather than
reconstructed from anyone's memory — including ours.

## Origin

|  |  |
|---|---|
| Published by | **Empire Labs Pty Ltd** |
| First published | **2026-08-01** |
| Canonical home | https://github.com/narko4u/webauthn-agent-action-extension |
| First commit | `b9736b4` — 2026-08-01T01:05:02Z |
| Licence | MIT — see [LICENSE](LICENSE) and [README § License](README.md#license) |

Written as part of the **Empire Stack** (ACI / AIP / AJSON), three open
specifications for autonomous agent commerce.

## Revision map

The specification file keeps a **constant filename** so that links into it stay
stable, while its content has been revised several times. The filename therefore
does **not** tell you which revision you are reading. This table does.

| Content version | Date | Commit | Change |
|---|---|---|---|
| v0.1 | 2026-08-01 | — (not committed) | Internal draft, pre-publication |
| v0.2 | 2026-08-01 | `b9736b4` | First public revision |
| v0.3 | 2026-08-04 | `51a167e` | ES256-first algorithm policy; canonical digest moved to deterministic CBOR (RFC 8949 §4.2.1) |
| v0.4 | 2026-08-04 | `cab0dcb` | Application-profile reframe: adopts the WebAuthn [`sign` extension](https://github.com/w3c/webauthn/pull/2078) as the cryptographic layer |
| v0.4 | 2026-09-22 | `4dcb616` | Acknowledgements corrected; independent projects credited |

- **Path:** `spec/webauthn-agent-authorization-extension-draft-v0.2.md`
- **Content version:** v0.4

To cite a specific revision, address it **by commit**, not by date or by
filename. The revision history is also recorded in the specification itself
(§11).

## Naming and registry position

Stated plainly so that the position is not reconstructed later from prose:

- The **WebAuthn extension identifier** used by this work is **`sign`**,
  specified upstream in the W3C Web Authentication Working Group
  ([w3c/webauthn PR #2078](https://github.com/w3c/webauthn/pull/2078), by Emil
  Lundberg). It is not ours and not ours to register.
- **`txAuthAgent`** is the name of the **application profile** defined here, and
  of the application-layer audit record it defines. The profile tag is
  `txauthagent/sign/v1`.
- **No WebAuthn extension identifier is proposed or registered under the name
  `txAuthAgent`.** Our public proposal of 2026-08-01 asked the Working Group to
  consider registering that identifier; following reviewer feedback on
  2026-08-03 the work was reframed on 2026-08-04 as a profile on top of `sign`,
  which is what it has been since v0.4.
- `txAuthAgent` is distinct from the registered transaction-authorization
  extensions `txAuthSimple` and `txAuthGeneric`, which confirm *human*
  transactions (see §3.3 of the specification).
- We claim no exclusive right in the name. We ask only that work implementing
  this profile cite it by the canonical URL above.

## Public record

All of the following are immutable and independently citable:

| Date (UTC) | Event | Archive |
|---|---|---|
| 2026-08-01 05:42 | Proposal posted to `public-webauthn@w3.org` | [0002.html](https://lists.w3.org/Archives/Public/public-webauthn/2026Aug/0002.html) |
| 2026-08-03 13:11 | Reviewer feedback (pairwise-credential privacy) | [0003.html](https://lists.w3.org/Archives/Public/public-webauthn/2026Aug/0003.html) |
| 2026-08-04 04:14 | Reframe as an application profile on `sign` | [0005.html](https://lists.w3.org/Archives/Public/public-webauthn/2026Aug/0005.html) |

Acknowledgement permission was granted on 2026-08-04, **conditional on the
credit not being framed as an endorsement**. See
[README § Acknowledgments](README.md#acknowledgments).

## How to verify

Nothing above needs to be taken on trust:

```sh
git clone https://github.com/narko4u/webauthn-agent-action-extension
cd webauthn-agent-action-extension
git log --follow --date=iso --format='%h %ad %s' -- spec/
git show -s --format='%aI %s' b9736b4
git show cab0dcb --stat          # the v0.4 reframe
```

## Scope

This file records authorship and revision only. It asserts no rights over the
WebAuthn `sign` extension, the WebAuthn specification, or any third-party
project named in the acknowledgements, each of which retains its own terms and
licence. See [README § License](README.md#license).
