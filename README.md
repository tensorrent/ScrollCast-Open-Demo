# SCROLLCAST Open Demo

Public briefing for digital media ownership, distribution, and role-based access.

**This repository does not contain SCROLLCAST source.** Packager, player, keys, and tests stay in a private repo. Every published asset here is **ciphertext at rest**; the briefing is decrypted in the browser by an **obfuscated loader**.

Live page (GitHub Pages): once enabled, `https://tensorrent.github.io/ScrollCast-Open-Demo/`

## What you are looking at

Festivals and rights holders already keep control in the theater (DCP + KDM). Online delivery usually does not: a Drive link, a WeTransfer, a USB, a downloaded screener is a copy, and a copy does not expire when you change a password.

SCROLLCAST sends a sealed package and issues **tickets** (N plays, until a date, or until you cancel). Integrity is enforced **before decode**: a swapped byte ends playback.

Industry terms, limits (including the clear-key ceiling), and the side-by-side with file share / Vimeo / DCP / DRM are on the decrypted page — not in this README, and not as readable source in this tree.

## Layout (what GitHub hosts)

| Path | What it is |
|---|---|
| `index.html` | Shell only. No briefing markup. |
| `assets/payload.bin` | AES-256-GCM ciphertext of the briefing. |
| `assets/boot.js` | Obfuscated Web Crypto loader. |

Readable HTML/CSS/JS is not committed.

## Not claimed

Not a compression codec. Not a DCP replacement for the booth. Not Widevine / FairPlay. Tickets govern the next redemption; they do not make a completed play unrecordable.
