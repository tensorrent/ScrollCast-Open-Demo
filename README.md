# SCROLLCAST — open demo

[Experience Scrollcast](https://tensorrent.github.io/ScrollCast-Open-Demo/)

This repository is generated from the private Scrollcast source with `npm run
site`. The page has a Three.js screening entrance, a real signed Big Buck Bunny
stream, byte verification before decoding, and a local sealed-file demo.

## Pro studio preview

Scenes, picture stems and audio stems reference preserved originals. Every edit
adds a signed revision with contributor attribution. End credits retain the
people behind earlier versions. Owners can choose a minimum revenue share—50%
to start, 75%, 0%, or custom—and collaborators divide the remainder. Conflicting
minimums over 100% prevent monetization. Sales and payouts are not connected.

The studio keeps files locally and can produce an encrypted creator backup.
Its invitation controls preview nested Scrollcast access tokens, hot-swapped
references and revocation. **The protected account service is not connected to
this public page.** Real Pro invitations grant view/edit/share permissions to
media in one protected project folder; they do not attach the original file.
Creator-copy export tools are separate and make a downloadable copy.

The private source includes an authenticated Pro API with encrypted originals,
per-account contributions, counted admissions and per-fragment access checks.
That API and its hosted invitation/player integration must be deployed before
remote privacy and revocation can be used from this page.

## What is real on this page

- `scrollcast.json` is an Ed25519-signed manifest for the actual sample media.
- The verifier checks publisher signature, substrate addresses and SHA-256
  before passing each received segment to the decoder.
- “Change one byte” corrupts an actual segment and the actual verifier refuses it.
- The own-file demo signs and encrypts local video, audio or images, supports
  single/custom play counts in that browser's storage, and optional visible
  assigned viewer IDs. Browser-local counts do not enforce a global quota.
- The studio signs append-only editorial history, evaluates revenue minimums,
  previews permission policy and verifies/restores encrypted creator archives.

## Limits

Local identities are self-declared. Visible viewer watermarks can be removed and
are not forensic watermarking. A 0% revenue floor is not a copyright waiver.
Browser storage can be cleared; preserve a private project backup. Revocation
cannot recall already buffered, downloaded or recorded media. This is not DRM,
a DCP replacement, a multitrack NLE, a payment service, or proof of rights ownership.

Big Buck Bunny © 2008 Blender Foundation, used under
[CC BY 3.0](https://creativecommons.org/licenses/by/3.0/).
