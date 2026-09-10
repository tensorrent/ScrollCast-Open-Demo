// byo.js — seal your own film or photo, and open one someone sent you.
// All of it inside the visitor's browser, with no server anywhere.
//
// SEAL. Read the file in chunks; encrypt each with AES-128-CTR using the
// shipping deriveSegmentCounter, so the keystream is byte-identical to the one
// the node packager produces; address the CIPHERTEXT with the shipping
// addressSegment (verify-then-decrypt, same order as the real player); sign the
// resulting manifest with a throwaway Ed25519 key; and write one .scrollcast
// container the visitor can download. The content key is shown separately as a
// code and is NOT written into the container.
//
// OPEN. Parse a container, verify its signature, then refuse anything whose
// code does not match keyId = sha256(key) — checked BEFORE a single byte is
// decrypted. Then per chunk: re-derive both addresses from the ciphertext that
// actually arrived, and only decrypt what verified.
//
// So the file and the code travel on different channels, which is the entire
// claim: hand someone the container by AirDrop or WeTransfer, send the code by
// text, and the container is inert to anyone who has only one of the two.
//
// Signed viewing terms are honoured by this browser. Counts survive reloads
// in localStorage, but cross-device enforcement needs the hosted ticket gate.
// Visible watermarks identify an assigned recipient; they are not embedded
// forensic marks or proof of an authenticated identity.
//
// Nothing is uploaded. There is no fetch, XHR, beacon or FormData in this file
// and a test fails the build if one appears.

"use strict";

(function () {
  var SC = window.ScrollcastVerify;
  var $ = function (id) { return document.getElementById(id); };
  var el = {
    panel: $("byo"),
    // seal
    input: $("byo-file"), drop: $("byo-drop"),
    stage: $("byo-stage"), media: $("byo-media"), video: $("byo-video"), image: $("byo-image"),
    strip: $("byo-strip"), badge: $("byo-badge"), name: $("byo-name"),
    halt: $("byo-halt"), haltSeg: $("byo-halt-seg"),
    haltExpect: $("byo-halt-expect"), haltGot: $("byo-halt-got"),
    statChunks: $("byo-stat-chunks"), statBlocks: $("byo-stat-blocks"), statBytes: $("byo-stat-bytes"),
    note: $("byo-note"), progress: $("byo-progress"),
    tamper: $("byo-tamper"), reset: $("byo-reset"),
    share: $("byo-share"), download: $("byo-download"), code: $("byo-code"), copy: $("byo-copy"),
    ruleChips: $("byo-rule-chips"), roleChips: $("byo-role-chips"), shareRule: $("byo-share-rule"),
    playCount: $("byo-play-count"), countField: $("byo-count-field"),
    watermarkToggle: $("byo-watermark-toggle"), viewerId: $("byo-viewer-id"),
    allowance: $("byo-play-allowance"), playStatus: $("byo-play-status"), replay: $("byo-replay"), ended: $("byo-ended"),
    audioArt: $("byo-audio-art"),
    // open
    openInput: $("byo-open-file"), openDrop: $("byo-open-drop"),
    openCode: $("byo-open-code"), openGo: $("byo-open-go"), openResult: $("byo-open-result"),
    openTerms: $("byo-open-terms"), openSave: $("byo-open-save"),
  };

  if (!SC || !el.panel || !SC.generateKeypair || !SC.keyCommitment) return;

  var MAGIC = "SCRLCST1";
  var MAX_BYTES = 24 * 1024 * 1024;
  var MAX_HEADER_BYTES = 256 * 1024;
  var TARGET_CHUNKS = 24;
  var MIN_CHUNK = 256 * 1024;

  var IMAGE_RE = /\.(jpe?g|png|webp|avif|gif|heic|heif|tiff?|bmp)$/i;
  var VIDEO_RE = /\.(mp4|mov|m4v|webm|mkv|avi)$/i;
  var AUDIO_RE = /\.(mp3|m4a|aac|wav|ogg|opus|flac)$/i;

  var DEFAULT_NOTE = el.note ? el.note.textContent : "";
  var fmt = function (n) { return n.toLocaleString("en-US"); };
  var mib = function (n) { return (n / 1048576).toFixed(2); };
  var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
  var hex = function (bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
    return out;
  };
  var randomHex = function (n) { return hex(crypto.getRandomValues(new Uint8Array(n))); };

  var run = 0;
  var phase = "idle";
  var file = null, sealed = null, chunks = [], armAt = -1, nextIndex = 0;
  var totals = { chunks: 0, blocks: 0, bytes: 0 };
  var cells = [], objectUrls = [];
  var recipient = null;
  var proMetadata = null;

  // ── terms ────────────────────────────────────────────────────────────────
  //
  // Same vocabulary as the hosted app's admission rules (tools/app/admission.mjs),
  // so a container sealed here describes its terms the way a ticket does there.
  // The difference is where they bind: there a gate holds the key and enforces
  // them; here they ride inside the signed manifest, which makes them
  // tamper-evident but only as binding as the opener chooses to be. The page
  // says so rather than implying otherwise.
  var ROLE_LABEL = { play: "play only", share: "play and pass on", edit: "play and download" };

  function pickedFrom(group, attr, fallback) {
    var on = group && group.querySelector(".is-on");
    return (on && on.dataset[attr]) || fallback;
  }
  var selectedRule = function () { return pickedFrom(el.ruleChips, "rule", "count:1"); };
  var selectedRole = function () { return pickedFrom(el.roleChips, "role", "play"); };

  function buildAccess(now) {
    var spec = selectedRule(), m, rule;
    if (spec === "forever") rule = { kind: "forever" };
    else if (spec === "count:custom") rule = { kind: "count", max: Number(el.playCount.value) };
    else if ((m = spec.match(/^count:(\d+)$/))) rule = { kind: "count", max: +m[1] };
    else if ((m = spec.match(/^until:(\d+)$/))) {
      rule = { kind: "until", days: +m[1], until: new Date(now + (+m[1]) * 86400000).toISOString() };
    } else throw new Error("Choose a play count or viewing window.");
    if (rule.kind === "count" && (!Number.isSafeInteger(rule.max) || rule.max < 1 || rule.max > 100000)) throw new Error("Choose a whole-number play count from 1 to 100000.");
    var access = { rule: rule, role: selectedRole() };
    if (el.watermarkToggle && el.watermarkToggle.checked) {
      var id = el.viewerId.value.trim();
      if (!/^[A-Za-z0-9][A-Za-z0-9._@+\-]{0,63}$/.test(id)) throw new Error("Enter a viewer ID of 1–64 letters, numbers, dots, @, +, hyphens or underscores.");
      if (!window.ScrollcastMedia) throw new Error("The viewer-ID player is unavailable. Reload this page before sealing.");
      access.watermark = { mode: "visible", viewerId: id };
    }
    if (proMetadata) {
      SC.validateRights(proMetadata.rights);
      access.rights = proMetadata.rights;
      access.segmentReceipt = proMetadata.receipt;
      access.role = proMetadata.rights.permissions.edit ? "edit" : proMetadata.rights.permissions.share ? "share" : "play";
    }
    return access;
  }

  function describeAccess(a) {
    if (!a || !a.rule) return "no limit \u00b7 play only";
    var r = a.rule, when;
    if (r.kind === "count") when = r.max === 1 ? "single play" : r.max + " plays";
    else if (r.kind === "until") when = "until " + new Date(r.until).toLocaleString();
    else when = "no time limit";
    return when + " \u00b7 " + (ROLE_LABEL[a.role] || "play only") + (a.watermark ? " \u00b7 viewer ID: " + a.watermark.viewerId : "");
  }

  // "1 open" is remembered per browser, keyed by the container's key
  // commitment — never the key itself. A different browser is a different
  // count, which is exactly why the page does not call this enforcement.
  var opensKey = function (keyId) { return "sc-open:" + String(keyId || "").slice(0, 32); };
  function opensSoFar(keyId) {
    try {
      var raw = localStorage.getItem(opensKey(keyId)) || "0", count = Number(raw);
      if (!/^\d+$/.test(raw) || !Number.isSafeInteger(count) || count < 0) throw new Error("invalid counter");
      return count;
    } catch (e) { throw new Error("Browser storage is unavailable or invalid. Counted playback cannot start here."); }
  }
  function noteOpen(keyId) {
    var count = opensSoFar(keyId) + 1;
    try { localStorage.setItem(opensKey(keyId), String(count)); }
    catch (e) { throw new Error("This browser cannot save the play count. Nothing was displayed."); }
  }

  /** null when the container may be opened, else the reason it may not. */
  function refuseReason(header) {
    var a = header && header.access;
    if (!a || !a.rule) return null;             // sealed before terms existed
    if (a.rights && !a.rights.permissions.play) return "Playback is not granted in this segment’s recipient permissions.";
    var r = a.rule;
    if (r.kind === "until" && r.until) {
      if (Date.now() > Date.parse(r.until)) {
        return "this code expired on " + new Date(r.until).toLocaleString() + " \u2014 nothing was decrypted";
      }
    }
    if (r.kind === "count") {
      var used = opensSoFar((header.encryption || {}).keyId);
      if (used >= r.max) {
        return r.max === 1
          ? "The single play has been used. No plays remain — nothing was decrypted."
          : "All " + r.max + " plays have been used — nothing was decrypted.";
      }
    }
    return null;
  }

  function kindOf(f) {
    if (/^image\//.test(f.type) || IMAGE_RE.test(f.name)) return "image";
    if (/^audio\//.test(f.type) || AUDIO_RE.test(f.name)) return "audio";
    if (/^video\//.test(f.type) || VIDEO_RE.test(f.name)) return "video";
    return null;
  }
  function trackUrl(u) { objectUrls.push(u); return u; }
  function releaseUrls() {
    objectUrls.forEach(function (u) { try { URL.revokeObjectURL(u); } catch (e) {} });
    objectUrls = [];
  }

  function setBadge(t, k) { el.badge.textContent = t; el.badge.className = "sc-badge" + (k ? " is-" + k : ""); }
  function setNote(t) { if (el.note) el.note.textContent = t; }
  function paintStats() {
    el.statChunks.textContent = fmt(totals.chunks);
    el.statBlocks.textContent = fmt(totals.blocks);
    el.statBytes.textContent = mib(totals.bytes);
  }
  function buildStrip(n) {
    el.strip.innerHTML = ""; cells = [];
    for (var i = 0; i < n; i++) {
      var c = document.createElement("span");
      c.className = "sc-cell";
      el.strip.appendChild(c); cells.push(c);
    }
  }
  function paintCell(i, root, failed) {
    var c = cells[i];
    if (!c) return;
    if (failed) { c.className = "sc-cell is-fail"; return; }
    var colors = SC.rootColors(root), r = 0, g = 0, b = 0;
    for (var k = 0; k < colors.length; k++) {
      r += (colors[k] >> 16) & 255; g += (colors[k] >> 8) & 255; b += colors[k] & 255;
    }
    var n = colors.length || 1;
    c.style.background = "rgb(" + Math.round(r / n) + "," + Math.round(g / n) + "," + Math.round(b / n) + ")";
    c.className = "sc-cell is-ok";
  }

  function showMedia(kind, url, watermark) {
    if (window.ScrollcastMedia) window.ScrollcastMedia.setWatermark("byo", watermark || null, kind);
    else if (watermark) throw new Error("The viewer-ID player is unavailable. Nothing was displayed.");
    el.video.hidden = kind === "image";
    el.image.hidden = kind !== "image";
    if (el.audioArt) el.audioArt.hidden = kind !== "audio";
    if (kind === "video" || kind === "audio") { el.video.src = url; el.video.play().catch(function () {}); }
    else { el.image.src = url; }
  }

  // ── crypto ───────────────────────────────────────────────────────────────
  var _key = null, _keyHex = null;
  async function importKey(keyHex) {
    if (_key && _keyHex === keyHex) return _key;
    _key = await crypto.subtle.importKey("raw", SC.hexToBytes(keyHex), { name: "AES-CTR" }, false, ["encrypt", "decrypt"]);
    _keyHex = keyHex;
    return _key;
  }
  // CTR is symmetric, so one routine covers both directions. renditionOrdinal
  // is 0: a sealed container has exactly one rendition.
  async function crypt(bytes, keyHex, ivHex, index, dir) {
    var key = await importKey(keyHex);
    var counter = SC.deriveSegmentCounter(ivHex, 0, index);
    var out = await crypto.subtle[dir]({ name: "AES-CTR", counter: counter, length: 64 }, key, bytes);
    return new Uint8Array(out);
  }

  // ── container ────────────────────────────────────────────────────────────
  function packContainer(header, payloads) {
    var headerBytes = new TextEncoder().encode(JSON.stringify(header));
    var len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, headerBytes.length, false);
    var parts = [new TextEncoder().encode(MAGIC), len, headerBytes].concat(payloads);
    return new Blob(parts, { type: "application/octet-stream" });
  }
  async function readContainer(f) {
    if (f.size < 13 || f.size > MAX_BYTES + MAX_HEADER_BYTES + 12) throw new Error("Choose a complete .scrollcast file with up to 24 MiB of media.");
    var head = new Uint8Array(await f.slice(0, 12).arrayBuffer());
    if (new TextDecoder().decode(head.subarray(0, 8)) !== MAGIC) {
      throw new Error("that is not a sealed SCROLLCAST file");
    }
    var headerLen = new DataView(head.buffer, head.byteOffset).getUint32(8, false);
    if (!headerLen || headerLen > MAX_HEADER_BYTES || 12 + headerLen >= f.size) throw new Error("This container has an invalid header or is incomplete.");
    var headerBytes = await f.slice(12, 12 + headerLen).arrayBuffer();
    var header = JSON.parse(new TextDecoder().decode(headerBytes));
    if (!header || header.format !== "scrollcast-sealed" || header.version !== 1 || !["image", "video", "audio"].includes(header.kind)) throw new Error("Unsupported sealed-file format.");
    if (typeof header.title !== "string" || typeof header.mime !== "string" || !Array.isArray(header.segments) || !header.segments.length || header.segments.length > 128) throw new Error("Invalid sealed-file manifest.");
    var encryption = header.encryption || {};
    if (encryption.scheme !== "aes-ctr-fullseg" || !/^[0-9a-f]{64}$/i.test(encryption.keyId || "") || !/^[0-9a-f]{32}$/i.test(encryption.iv || "")) throw new Error("Invalid encryption information.");
    var total = 0;
    header.segments.forEach(function (entry, index) {
      if (!entry || entry.index !== index || !Number.isSafeInteger(entry.bytes) || entry.bytes <= 0 || entry.bytes > MAX_BYTES) throw new Error("Invalid media chunk.");
      total += entry.bytes;
      if (total > MAX_BYTES) throw new Error("This file exceeds the browser demo's 24 MiB limit.");
    });
    if (total !== header.coveredBytes || total !== header.totalBytes || 12 + headerLen + total !== f.size) throw new Error("This sealed file is incomplete. Seal a complete file of 24 MiB or less.");
    if (header.access) {
      var rule = header.access.rule;
      if (!rule || !["count", "until", "forever"].includes(rule.kind) || !["play", "share", "edit"].includes(header.access.role)) throw new Error("Invalid viewing terms.");
      if (rule.kind === "count" && (!Number.isSafeInteger(rule.max) || rule.max < 1 || rule.max > 100000)) throw new Error("Invalid viewing count.");
      if (rule.kind === "until" && !Number.isFinite(Date.parse(rule.until))) throw new Error("Invalid viewing window.");
      var watermark = header.access.watermark;
      if (watermark && (watermark.mode !== "visible" || typeof watermark.viewerId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._@+\-]{0,63}$/.test(watermark.viewerId))) throw new Error("Invalid viewer watermark.");
      if (header.access.rights) SC.validateRights(header.access.rights);
    }
    return { header, base: 12 + headerLen };
  }

  function setBusy(busy) {
    el.input.disabled = busy; el.openInput.disabled = busy; el.openGo.disabled = busy;
    if (el.playCount) el.playCount.disabled = busy;
    if (el.watermarkToggle) el.watermarkToggle.disabled = busy;
    if (el.viewerId) el.viewerId.disabled = busy || !el.watermarkToggle.checked;
    [el.ruleChips, el.roleChips].forEach(function (group) {
      if (group) group.querySelectorAll(".byo-chip").forEach(function (chip) { chip.disabled = busy; });
    });
    el.panel.setAttribute("aria-busy", String(busy));
  }

  function clearPreview() {
    recipient = null;
    if (el.allowance) el.allowance.hidden = true;
    if (el.ended) el.ended.hidden = true;
    if (el.audioArt) el.audioArt.hidden = true;
    if (window.ScrollcastMedia) window.ScrollcastMedia.setWatermark("byo", null);
    releaseUrls();
    try { el.video.pause(); el.video.removeAttribute("src"); el.video.load(); } catch (e) {}
    el.image.removeAttribute("src"); el.image.hidden = true;
    el.halt.classList.remove("is-shown");
    el.share.hidden = true; el.code.value = ""; el.download.removeAttribute("href");
    if (el.openSave) { el.openSave.hidden = true; el.openSave.removeAttribute("href"); }
    el.tamper.disabled = true;
  }

  // ── seal ─────────────────────────────────────────────────────────────────
  async function seal(chosen, tamperAtIndex) {
    var myRun = ++run;
    var access = buildAccess(Date.now());
    setBusy(true);
    clearPreview();
    incoming = null;
    file = chosen;
    var kind = kindOf(file);
    phase = "sealing"; armAt = -1; nextIndex = 0;
    totals = { chunks: 0, blocks: 0, bytes: 0 };
    paintStats(); releaseUrls();
    el.halt.classList.remove("is-shown");
    el.tamper.disabled = true;
    el.stage.hidden = false;
    el.share.hidden = true;
    el.name.textContent = file.name;
    setNote(DEFAULT_NOTE);

    var covered = file.size;
    var chunkSize = Math.max(MIN_CHUNK, Math.ceil(covered / TARGET_CHUNKS));
    chunks = [];
    for (var off = 0; off < covered; off += chunkSize) {
      chunks.push({ index: chunks.length, start: off, bytes: Math.min(chunkSize, covered - off) });
    }
    buildStrip(chunks.length);

    var keyHex = randomHex(16);          // the code
    var ivHex = randomHex(16);
    var payloads = [];

    setBadge("sealing…", null);
    for (var i = 0; i < chunks.length; i++) {
      if (myRun !== run) return;
      var plain = new Uint8Array(await file.slice(chunks[i].start, chunks[i].start + chunks[i].bytes).arrayBuffer());
      if (myRun !== run) return;
      var ct = await crypt(plain, keyHex, ivHex, i, "encrypt");
      if (myRun !== run) return;
      // Address the CIPHERTEXT: the player verifies what arrived on the wire
      // and decrypts only what verified, so the address must cover the same
      // bytes it will later re-derive.
      var addr = SC.addressSegment(ct);
      chunks[i].root = addr.root; chunks[i].sha256 = addr.sha256; chunks[i].blocks = addr.blocks;
      payloads.push(ct);
      el.progress.textContent = "sealing " + (i + 1) + " / " + chunks.length;
      await sleep(0);
    }
    if (myRun !== run) return;

    var kp = SC.generateKeypair();
    var header = SC.signManifest({
      format: "scrollcast-sealed", version: 1,
      title: file.name, mime: file.type || "", kind: kind,
      createdAt: new Date().toISOString(),
      // Signed with everything else, so the window and the role cannot be
      // edited after the fact without the container failing to verify.
      access: access,
      coveredBytes: covered, totalBytes: file.size,
      // No `key` field. The commitment is here so a wrong code is rejected
      // before decryption; the key itself travels separately, by hand.
      encryption: { scheme: "aes-ctr-fullseg", keyId: SC.keyCommitment(keyHex), iv: ivHex },
      segments: chunks.map(function (c) {
        return { index: c.index, uri: "sealed:" + c.index, bytes: c.bytes, durationSec: 0,
                 root: c.root, sha256: c.sha256, blocks: c.blocks };
      }),
    }, kp.privateKey);

    if (!SC.verifyManifestWith(header, kp.publicKey).valid) {
      throw new Error("The new manifest did not verify. Nothing was sealed.");
    }

    sealed = { header: header, blob: packContainer(header, payloads), keyHex: keyHex, payloads: payloads };

    setBadge("sealed · " + kp.publicKey.slice(0, 12) + "…", "ok");
    el.progress.textContent = "sealed all " + mib(covered) + " MiB in " + chunks.length + " chunks";

    el.download.href = trackUrl(URL.createObjectURL(sealed.blob));
    el.download.download = file.name.replace(/\.[^.]+$/, "") + ".scrollcast";
    el.code.value = keyHex;
    if (el.shareRule) el.shareRule.textContent = describeAccess(access);
    el.share.hidden = false;
    setBusy(false);
    // The code used to render below a full-size player, off the bottom of the
    // screen, so people reported that sealing never gave them one. Put it in
    // front of them.
    try { el.share.scrollIntoView({ behavior: "smooth", block: "center" }); } catch (e) { el.share.scrollIntoView(); }

    // Show the original locally so there is something on screen while the
    // verification pass runs. The recipient's copy comes from the container.
    showMedia(kind, trackUrl(URL.createObjectURL(file)), access.watermark);

    // ── verify the sealed bytes back, exactly as a recipient would ──────────
    phase = "playing";
    if (typeof tamperAtIndex === "number") armAt = Math.min(Math.max(0, tamperAtIndex), chunks.length - 1);
    el.tamper.disabled = false;
    setNote("Verifying the sealed bytes the same way a recipient would. Change one byte and it stops.");

    var pace = Math.max(120, Math.min(700, Math.round(14000 / Math.max(1, chunks.length))));
    for (var j = 0; j < chunks.length; j++) {
      if (myRun !== run || phase === "halted") return;
      nextIndex = j;
      await sleep(pace);
      if (myRun !== run || phase === "halted") return;

      var ct2 = payloads[j].slice();
      var tampered = false;
      if (j === armAt) { ct2[Math.floor(ct2.length / 2)] ^= 0x01; armAt = -1; tampered = true; }

      var res = SC.verifySegment(ct2, header.segments[j]);
      if (!res.ok) { halt(j, res.failure, chunks[j].bytes); return; }
      if (tampered) { halt(j, { kind: "root", expected: chunks[j].root, derived: res.derived.root }, chunks[j].bytes); return; }

      totals.chunks += 1; totals.blocks += res.derived.blocks; totals.bytes += res.derived.bytes;
      paintCell(j, chunks[j].root, false); paintStats();
    }
    if (myRun !== run) return;
    phase = "complete";
    el.tamper.textContent = "Seal it again, tampered";
    setBadge("every byte verified", "ok");
    setNote("Sealed and verified. Send the file one way and the code another — the file plays nothing without it.");
  }

  function halt(i, failure, entryBytes) {
    phase = "halted";
    try { el.video.pause(); } catch (e) {}
    paintCell(i, null, true);
    setBadge("playback stopped", "halt");
    el.haltSeg.textContent = "chunk " + String(i + 1).padStart(2, "0") + " — one byte changed out of " + fmt(entryBytes);
    if (failure && failure.kind === "root") {
      el.haltExpect.textContent = failure.expected; el.haltGot.textContent = failure.derived;
    } else if (failure && failure.kind === "sha256") {
      el.haltExpect.textContent = failure.expected.slice(0, 16) + "…"; el.haltGot.textContent = failure.derived.slice(0, 16) + "…";
    } else if (failure && failure.kind === "length") {
      el.haltExpect.textContent = fmt(failure.expected) + " bytes"; el.haltGot.textContent = fmt(failure.got) + " bytes";
    }
    el.halt.classList.add("is-shown");
    el.tamper.disabled = true;
    setNote("One byte changed. Its address no longer matches the signed manifest, so the verification stopped.");
  }

  // ── open ─────────────────────────────────────────────────────────────────
  var incoming = null;
  function openStatus(msg, kind) {
    el.openResult.textContent = msg;
    el.openResult.className = "byo-open-result" + (kind ? " is-" + kind : "");
  }

  async function chooseSealed(f) {
    if (!f) return;
    var myRun = ++run;
    incoming = null; file = null; phase = "selecting";
    clearPreview(); el.stage.hidden = true; setBusy(true);
    if (el.openTerms) el.openTerms.hidden = true;
    try {
      var parsed = await readContainer(f);
      if (myRun !== run) return;
      var v = SC.verifyManifestWith(parsed.header, (parsed.header.signature || {}).publicKey || "");
      if (!v.valid) throw new Error("This container's signature does not verify. It has been altered.");
      incoming = { file: f, header: parsed.header, base: parsed.base };
      if (el.openTerms) {
        el.openTerms.textContent = "terms: " + describeAccess(parsed.header.access);
        el.openTerms.hidden = false;
      }
      phase = "ready";
      openStatus(parsed.header.title + " · " + parsed.header.segments.length + " chunks · enter the code to open it", null);
    } catch (e) {
      if (myRun !== run) return;
      incoming = null; phase = "idle";
      openStatus(e.message || "Could not read this sealed file.", "bad");
    } finally {
      if (myRun === run) setBusy(false);
    }
  }

  async function openSealed() {
    if (phase === "opening" || phase === "sealing" || phase === "selecting") return;
    if (!incoming) return openStatus("choose a .scrollcast file first", "bad");
    var code = (el.openCode.value || "").trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(code)) return openStatus("a code is 32 hex characters", "bad");
    if (SC.keyCommitment(code) !== incoming.header.encryption.keyId) return openStatus("wrong code — nothing was decrypted", "bad");
    var refusal;
    try { refusal = refuseReason(incoming.header); }
    catch (e) { return openStatus(e.message, "bad"); }
    if (refusal) return openStatus(refusal, "bad");
    if (incoming.header.access && incoming.header.access.watermark && !window.ScrollcastMedia) return openStatus("The viewer-ID player is unavailable. Reload this page before opening.", "bad");

    var myRun = ++run, current = incoming;
    phase = "opening"; setBusy(true); clearPreview(); el.stage.hidden = true;
    try {
      openStatus("code accepted · verifying…", "ok");
      var segs = current.header.segments, offset = current.base, plainParts = [];
      for (var i = 0; i < segs.length; i++) {
        var ct = new Uint8Array(await current.file.slice(offset, offset + segs[i].bytes).arrayBuffer());
        if (myRun !== run) return;
        offset += segs[i].bytes;
        var res = SC.verifySegment(ct, segs[i]);
        if (!res.ok) throw new Error("Chunk " + (i + 1) + " failed verification. The file was not opened.");
        plainParts.push(await crypt(ct, code, current.header.encryption.iv, i, "decrypt"));
        if (myRun !== run) return;
        openStatus("verified and decrypted " + (i + 1) + " / " + segs.length, "ok");
        await sleep(0);
      }
      if (myRun !== run) return;
      var blob = new Blob(plainParts, { type: current.header.mime || "application/octet-stream" });
      var acc2 = current.header.access || {};
      if (acc2.segmentReceipt) {
        var receipt = acc2.segmentReceipt, revision = receipt.revision;
        if (receipt.format !== "scrollcast-segment-receipt" || !revision || revision.action.type !== "export-segment" || !SC.verifyManifestWith(revision, (revision.signature || {}).publicKey || "").valid) throw new Error("The excerpt provenance signature does not verify.");
        var decodedAddress = SC.addressSegment(new Uint8Array(await blob.arrayBuffer()));
        if (myRun !== run) return;
        if (decodedAddress.sha256 !== revision.action.output.sha256 || blob.size !== revision.action.output.bytes || JSON.stringify(acc2.rights) !== JSON.stringify(revision.action.rights)) throw new Error("The opened excerpt does not match its signed source receipt.");
      }
      // Recheck after asynchronous verification, then record the admission
      // before exposing media. Pause/resume within that session costs no play.
      var finalRefusal = refuseReason(current.header);
      if (finalRefusal) throw new Error(finalRefusal);
      if (acc2.rule && acc2.rule.kind === "count") noteOpen(current.header.encryption.keyId);
      var url = trackUrl(URL.createObjectURL(blob));
      el.stage.hidden = false; el.name.textContent = current.header.title;
      buildStrip(segs.length);
      for (var k = 0; k < segs.length; k++) paintCell(k, segs[k].root, false);
      totals = { chunks: segs.length, blocks: segs.reduce(function (a,s) { return a+s.blocks; },0), bytes: current.header.totalBytes };
      paintStats();
      recipient = current;
      showAllowance(current.header);
      setBadge("opened · every byte verified", "ok");
      el.progress.textContent = "opened from a sealed container with the code";
      showMedia(current.header.kind, url, acc2.watermark);
      if (el.openSave) {
        var downloadAllowed = acc2.rights ? acc2.rights.permissions.edit : acc2.role === "edit";
        el.openSave.hidden = !downloadAllowed;
        if (downloadAllowed) { el.openSave.href = url; el.openSave.download = current.header.title; }
      }
      setNote("Every chunk verified and decrypted before the file was opened. Browser viewing terms are not server-enforced tickets.");
      openStatus("opened — every chunk verified before it was decrypted" + (acc2.role ? " · " + ROLE_LABEL[acc2.role] : ""), "ok");
      el.stage.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      if (myRun === run) openStatus(e.message || "Could not open this file. Try selecting it again.", "bad");
    } finally {
      if (myRun === run) { phase = "ready"; setBusy(false); }
    }
  }

  // ── controls ─────────────────────────────────────────────────────────────
  function showAllowance(header) {
    if (!el.allowance) return;
    var rule = (header.access || {}).rule || { kind: "forever" };
    var used = rule.kind === "count" ? opensSoFar(header.encryption.keyId) : 0;
    el.allowance.hidden = false;
    el.playStatus.textContent = rule.kind === "count"
      ? "Play " + used + " of " + rule.max + " · " + Math.max(0, rule.max - used) + " remaining after this screening"
      : describeAccess(header.access);
    el.replay.disabled = rule.kind === "count" && used >= rule.max;
    el.replay.textContent = el.replay.disabled ? "No plays remaining" : "Start next play";
  }
  el.video.addEventListener("ended", function () {
    if (!recipient) return; // The sender's original preview does not use plays.
    el.video.pause(); el.video.removeAttribute("src"); el.video.load();
    el.video.hidden = true;
    releaseUrls();
    if (el.openSave) { el.openSave.hidden = true; el.openSave.removeAttribute("href"); }
    if (el.ended) el.ended.hidden = false;
    if (window.ScrollcastMedia) window.ScrollcastMedia.setWatermark("byo", (recipient.header.access || {}).watermark || null, "ended");
    showAllowance(recipient.header);
  });
  if (el.replay) el.replay.addEventListener("click", function () { openSealed(); });
  function choose(f, metadata) {
    if (!f) return;
    if (phase === "sealing" || phase === "opening" || phase === "selecting") return;
    proMetadata = metadata || null;
    if (!f.size || f.size > MAX_BYTES || !kindOf(f)) {
      run++; phase = "idle"; file = null; incoming = null; clearPreview();

      el.stage.hidden = false;
      setBadge(f.size > MAX_BYTES ? "file too large" : "unsupported file", "halt");
      setNote(f.size > MAX_BYTES ? "Choose a complete clip or photo up to 24 MiB. Nothing was sealed or truncated." : "Choose a non-empty video or photo your browser can play.");
      return;
    }
    el.tamper.textContent = "Change one byte";
    launchSeal(f);
  }

  function launchSeal(f, tamperIndex) {
    var expected = run + 1;
    seal(f, tamperIndex).catch(function (error) {
      if (run !== expected) return;
      phase = "idle"; setBusy(false); el.tamper.disabled = true;
      setBadge("could not seal file", "halt");
      setNote(error.message || "Sealing failed. Try a smaller clip or another browser.");
    });
  }

  // Terms are chosen before sealing because they are signed into the manifest.
  // Changing one after the fact therefore has to re-seal, which also issues a
  // new code — the old one would otherwise still open the old container.
  [[el.ruleChips, "rule"], [el.roleChips, "role"]].forEach(function (pair) {
    var group = pair[0];
    if (!group) return;
    group.addEventListener("click", function (e) {
      var chip = e.target.closest(".byo-chip");
      if (!chip || chip.disabled || chip.classList.contains("is-on")) return;
      group.querySelectorAll(".byo-chip").forEach(function (c) {
        var on = c === chip;
        c.classList.toggle("is-on", on);
        c.setAttribute("aria-checked", on ? "true" : "false");
      });
      if (el.countField) el.countField.hidden = selectedRule() !== "count:custom";
      if (file && phase !== "sealing") launchSeal(file);
    });
    group.addEventListener("keydown", function (e) {
      var chip = e.target.closest(".byo-chip");
      if (!chip || !["ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
      var list = Array.from(group.querySelectorAll(".byo-chip"));
      if (chip.disabled) return;
      e.preventDefault();
      var index = list.indexOf(chip), next;
      if (e.key === "Home") next = 0;
      else if (e.key === "End") next = list.length - 1;
      else next = (index + (["ArrowRight", "ArrowDown"].includes(e.key) ? 1 : -1) + list.length) % list.length;
      list[next].focus(); list[next].click();
    });
  });

  [el.playCount, el.viewerId, el.watermarkToggle].forEach(function (control) {
    if (!control) return;
    control.addEventListener("change", function () {
      el.viewerId.disabled = !el.watermarkToggle.checked;
      if (file && phase !== "sealing") launchSeal(file);
    });
  });

  el.input.addEventListener("change", function (e) { choose(e.target.files && e.target.files[0]); });
  document.addEventListener("scrollcast:seal-excerpt", async function (e) {
    try {
      if (phase === "sealing" || phase === "opening" || phase === "selecting") throw new Error("Finish the current file operation before sealing an excerpt.");
      var detail = e.detail, receipt = detail.receipt, revision = receipt.revision;
      SC.validateRights(detail.rights);
      if (receipt.format !== "scrollcast-segment-receipt" || revision.action.type !== "export-segment" || !SC.verifyManifestWith(revision, revision.signature.publicKey).valid) throw new Error("The segment receipt does not verify.");
      var address = SC.addressSegment(new Uint8Array(await detail.file.arrayBuffer()));
      if (address.sha256 !== revision.action.output.sha256 || detail.file.size !== revision.action.output.bytes || JSON.stringify(detail.rights) !== JSON.stringify(revision.action.rights)) throw new Error("The excerpt or rights do not match the signed receipt.");
      choose(detail.file, { rights: detail.rights, receipt: receipt });
    } catch (error) { el.stage.hidden = false; setBadge("could not seal excerpt", "halt"); setNote(error.message); }
  });
  el.openInput.addEventListener("change", function (e) { chooseSealed(e.target.files && e.target.files[0]); });

  [[el.drop, choose], [el.openDrop, chooseSealed]].forEach(function (pair) {
    var zone = pair[0], handler = pair[1];
    if (!zone) return;
    ["dragenter", "dragover"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add("is-over"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove("is-over"); });
    });
    zone.addEventListener("drop", function (e) {
      handler(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]);
    });
  });

  el.openGo.addEventListener("click", function () { openSealed(); });
  el.openCode.addEventListener("keydown", function (e) { if (e.key === "Enter") openSealed(); });

  el.copy.addEventListener("click", async function () {
    el.code.select();
    try {
      await navigator.clipboard.writeText(el.code.value);
      el.copy.textContent = "copied";
      setTimeout(function () { el.copy.textContent = "copy"; }, 1600);
    } catch (e) { el.copy.textContent = "Select & copy"; setNote("The code is selected. Copy it with your device’s copy command."); }
  });

  el.tamper.addEventListener("click", function () {
    if (phase === "playing" && nextIndex < chunks.length - 1) {
      armAt = nextIndex + 1;
      el.tamper.disabled = true;
      setNote("Armed. One byte of the next chunk will be changed before it is verified.");
    } else if (file) {
      el.tamper.textContent = "Change one byte";
      launchSeal(file, 2);
    }
  });

  el.reset.addEventListener("click", function () {
    run++; phase = "idle"; file = null; sealed = null; incoming = null; proMetadata = null;
    setBusy(false); clearPreview();
    if (el.openTerms) el.openTerms.hidden = true;
    el.input.value = ""; el.openInput.value = ""; el.openCode.value = "";
    el.stage.hidden = true; el.share.hidden = true; el.progress.textContent = "";
    openStatus("", null);
    releaseUrls();
    try { el.video.pause(); el.video.removeAttribute("src"); el.video.load(); } catch (e) {}
    el.image.removeAttribute("src");
    setNote(DEFAULT_NOTE);
  });
})();
