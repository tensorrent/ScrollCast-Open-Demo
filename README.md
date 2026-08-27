# SCROLLCAST — open briefing

Public briefing on sealed media delivery and revocable access, for festivals,
sales agents, and rights holders.

**Live page:** https://tensorrent.github.io/ScrollCast-Open-Demo/

## What this repository is

Published output. Every file here is generated from the private SCROLLCAST
source repo by `npm run site` and pushed as static HTML. Nothing is written by
hand in this tree, so send pull requests to the source repo rather than here.

It is a briefing, so it is plainly readable on purpose: crawlable HTML, a real
link-preview card, self-hosted fonts, and no third-party requests. There is no
obfuscation, and none is claimed — a public marketing page has nothing to
protect, and pretending otherwise would undercut the one thing this project is
actually selling.

## The demo is the real thing

The verification demo in the hero is not a mockup or an animation:

- `scrollcast.json` is a real manifest for a real stream, signed with a real
  Ed25519 publisher key.
- `media/` holds real CMAF segments produced by the real packager.
- `scrollcast-verify.js` is the shipping codec, bundled from source with the
  publisher key compiled in. It exposes the same verification entry points the
  packager and the offline prover use.
- The page checks the manifest signature before fetching a single media byte,
  then re-derives both addresses — the 16-hex substrate root and the sha256 —
  from the bytes that actually arrived, and hands only verified segments to the
  decoder.
- **Change one byte** flips a real byte in a real segment before verification
  runs. The halt, and the two disagreeing addresses it prints, are the verifier
  rejecting it. Nothing about that outcome is scripted.

You are meant to check this. Open devtools and watch the fetches, or take
`media/main/seg003.m4s`, flip a byte, and confirm its digest stops matching the
entry in `scrollcast.json`.

## What is not here

No packager, no player source, no keys, no tests — those stay in the private
repo. What ships here is the briefing plus the small sample stream it verifies.

## Not claimed

Not a compression codec. Not a DCP replacement for the booth. Not Widevine or
FairPlay. No forensic watermarking. Tickets govern the next redemption; they do
not make a play that already happened unrecordable. The limits are stated on the
page itself, in the same type size as everything else.
