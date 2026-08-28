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
// WHAT THIS CANNOT DO, and the page says so. Play counts, expiry and
// revocation are not here, because they cannot be enforced by a page. A rule
// only binds at a gate the key must pass through, and a static site has no
// gate — src/player.ts makes the same point where it resolves a key: the
// ticket resolver belongs to the hosted app, and "the static demo has no
// resolver". Anything counting plays in here would be a decoration, and this
// project does not ship those.
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
    // open
    openInput: $("byo-open-file"), openDrop: $("byo-open-drop"),
    openCode: $("byo-open-code"), openGo: $("byo-open-go"), openResult: $("byo-open-result"),
    openTerms: $("byo-open-terms"), openSave: $("byo-open-save"),
  };

  if (!SC || !el.panel || !SC.generateKeypair || !SC.keyCommitment) return;

  var MAGIC = "SCRLCST1";
  var MAX_BYTES = 24 * 1024 * 1024;
  var TARGET_CHUNKS = 24;
  var MIN_CHUNK = 256 * 1024;

  var IMAGE_RE = /\.(jpe?g|png|webp|avif|gif|heic|heif|tiff?|bmp)$/i;
  var VIDEO_RE = /\.(mp4|mov|m4v|webm|mkv|avi)$/i;

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
  var selectedRule = function () { return pickedFrom(el.ruleChips, "rule", "until:3"); };
  var selectedRole = function () { return pickedFrom(el.roleChips, "role", "play"); };

  function buildAccess(now) {
    var spec = selectedRule(), m, rule;
    if (spec === "forever") rule = { kind: "forever" };
    else if ((m = spec.match(/^count:(\d+)$/))) rule = { kind: "count", max: +m[1] };
    else if ((m = spec.match(/^until:(\d+)$/))) {
      rule = { kind: "until", days: +m[1], until: new Date(now + (+m[1]) * 86400000).toISOString() };
    } else rule = { kind: "forever" };
    return { rule: rule, role: selectedRole() };
  }

  function describeAccess(a) {
    if (!a || !a.rule) return "no limit \u00b7 play only";
    var r = a.rule, when;
    if (r.kind === "count") when = r.max === 1 ? "one open" : r.max + " opens";
    else if (r.kind === "until") when = "until " + new Date(r.until).toLocaleString();
    else when = "no time limit";
    return when + " \u00b7 " + (ROLE_LABEL[a.role] || "play only");
  }

  // "1 open" is remembered per browser, keyed by the container's key
  // commitment — never the key itself. A different browser is a different
  // count, which is exactly why the page does not call this enforcement.
  var opensKey = function (keyId) { return "sc-open:" + String(keyId || "").slice(0, 32); };
  function opensSoFar(keyId) {
    try { return parseInt(localStorage.getItem(opensKey(keyId)) || "0", 10) || 0; } catch (e) { return 0; }
  }
  function noteOpen(keyId) {
    try { localStorage.setItem(opensKey(keyId), String(opensSoFar(keyId) + 1)); } catch (e) {}
  }

  /** null when the container may be opened, else the reason it may not. */
  function refuseReason(header) {
    var a = header && header.access;
    if (!a || !a.rule) return null;             // sealed before terms existed
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
          ? "this code was set to open once, and it already has \u2014 nothing was decrypted"
          : "this code allowed " + r.max + " opens and all of them are used \u2014 nothing was decrypted";
      }
    }
    return null;
  }

  function kindOf(f) {
    if (/^image\//.test(f.type) || IMAGE_RE.test(f.name)) return "image";
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

  function showMedia(kind, url) {
    el.video.hidden = kind !== "video";
    el.image.hidden = kind !== "image";
    if (kind === "video") { el.video.src = url; el.video.play().catch(function () {}); }
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
    var head = new Uint8Array(await f.slice(0, 12).arrayBuffer());
    if (new TextDecoder().decode(head.subarray(0, 8)) !== MAGIC) {
      throw new Error("that is not a sealed SCROLLCAST file");
    }
    var headerLen = new DataView(head.buffer, head.byteOffset).getUint32(8, false);
    var headerBytes = await f.slice(12, 12 + headerLen).arrayBuffer();
    var header = JSON.parse(new TextDecoder().decode(headerBytes));
    return { header, base: 12 + headerLen };
  }

  // ── seal ─────────────────────────────────────────────────────────────────
  async function seal(chosen, tamperAtIndex) {
    var myRun = ++run;
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

    var covered = Math.min(file.size, MAX_BYTES);
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
      var ct = await crypt(plain, keyHex, ivHex, i, "encrypt");
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
    var access = buildAccess(Date.now());
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
      setBadge("signature invalid", "halt");
      setNote("The manifest this page produced did not verify, which should be impossible. Nothing was sealed.");
      return;
    }

    sealed = { header: header, blob: packContainer(header, payloads), keyHex: keyHex, payloads: payloads };

    setBadge("sealed · " + kp.publicKey.slice(0, 12) + "…", "ok");
    el.progress.textContent =
      (covered < file.size ? "sealed the first " + mib(covered) + " MiB of " + mib(file.size) + " MiB"
                           : "sealed all " + mib(covered) + " MiB")
      + " in " + chunks.length + " chunks";

    el.download.href = trackUrl(URL.createObjectURL(sealed.blob));
    el.download.download = file.name.replace(/\.[^.]+$/, "") + ".scrollcast";
    el.code.value = keyHex;
    if (el.shareRule) el.shareRule.textContent = describeAccess(access);
    el.share.hidden = false;
    // The code used to render below a full-size player, off the bottom of the
    // screen, so people reported that sealing never gave them one. Put it in
    // front of them.
    try { el.share.scrollIntoView({ behavior: "smooth", block: "center" }); } catch (e) { el.share.scrollIntoView(); }

    // Show the original locally so there is something on screen while the
    // verification pass runs. The recipient's copy comes from the container.
    showMedia(kind, trackUrl(URL.createObjectURL(file)));

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
    setNote("That is your own sealed file failing its own signature — one byte changed, and the address it derives no longer matches the one that was signed.");
  }

  // ── open ─────────────────────────────────────────────────────────────────
  var incoming = null;
  function openStatus(msg, kind) {
    el.openResult.textContent = msg;
    el.openResult.className = "byo-open-result" + (kind ? " is-" + kind : "");
  }

  async function chooseSealed(f) {
    if (!f) return;
    try {
      incoming = { file: f, ...(await readContainer(f)) };
    } catch (e) {
      incoming = null;
      openStatus(e.message, "bad");
      return;
    }
    var v = SC.verifyManifestWith(incoming.header, (incoming.header.signature || {}).publicKey || "");
    if (!v.valid) {
      incoming = null;
      if (el.openTerms) el.openTerms.hidden = true;
      return openStatus("this container's signature does not verify — it has been altered", "bad");
    }
    // The terms verified along with everything else, so they are safe to show
    // before a code is entered.
    if (el.openTerms) {
      var acc = incoming.header.access;
      el.openTerms.textContent = acc ? "terms: " + describeAccess(acc) : "terms: none — sealed before terms existed";
      el.openTerms.hidden = false;
    }
    if (el.openSave) el.openSave.hidden = true;
    openStatus(incoming.header.title + " · " + incoming.header.segments.length + " chunks · enter the code to open it", null);
  }

  async function openSealed() {
    if (!incoming) return openStatus("choose a .scrollcast file first", "bad");
    var code = (el.openCode.value || "").trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(code)) return openStatus("a code is 32 hex characters", "bad");

    // The commitment check happens BEFORE any decryption. A wrong code never
    // gets to feed garbage into a decoder.
    if (SC.keyCommitment(code) !== incoming.header.encryption.keyId) {
      return openStatus("wrong code — nothing was decrypted", "bad");
    }

    // Terms are checked after the code, so a stranger holding the file but not
    // the code learns nothing about them, and still before any decryption.
    var refusal = refuseReason(incoming.header);
    if (refusal) return openStatus(refusal, "bad");

    openStatus("code accepted · verifying…", "ok");
    var segs = incoming.header.segments;
    var offset = incoming.base;
    var plainParts = [];
    for (var i = 0; i < segs.length; i++) {
      var ct = new Uint8Array(await incoming.file.slice(offset, offset + segs[i].bytes).arrayBuffer());
      offset += segs[i].bytes;
      var res = SC.verifySegment(ct, segs[i]);
      if (!res.ok) return openStatus("chunk " + (i + 1) + " failed verification — the file has been altered, nothing was decrypted", "bad");
      plainParts.push(await crypt(ct, code, incoming.header.encryption.iv, i, "decrypt"));
      openStatus("verified and decrypted " + (i + 1) + " / " + segs.length, "ok");
      await sleep(0);
    }

    var blob = new Blob(plainParts, { type: incoming.header.mime || "application/octet-stream" });
    var url = trackUrl(URL.createObjectURL(blob));
    el.stage.hidden = false;
    el.name.textContent = incoming.header.title;
    buildStrip(segs.length);
    for (var k = 0; k < segs.length; k++) paintCell(k, segs[k].root, false);
    totals = { chunks: segs.length, blocks: segs.reduce(function (a, s) { return a + s.blocks; }, 0),
               bytes: segs.reduce(function (a, s) { return a + s.bytes; }, 0) };
    paintStats();
    noteOpen(incoming.header.encryption.keyId);

    var acc2 = incoming.header.access || {};
    setBadge("opened · every byte verified", "ok");
    el.progress.textContent = "opened from a sealed container with the code";
    showMedia(incoming.header.kind === "image" ? "image" : "video", url);

    // The role decides what the page offers. Someone determined can still reach
    // the decoded blob through devtools — this is what the role means in the
    // interface, not a claim about what it prevents.
    if (el.openSave) {
      var mayKeep = acc2.role === "edit";
      el.openSave.hidden = !mayKeep;
      if (mayKeep) { el.openSave.href = url; el.openSave.download = incoming.header.title || "original"; }
    }
    openStatus("opened — every chunk verified before it was decrypted"
      + (acc2.role ? " · " + (ROLE_LABEL[acc2.role] || "play only") : ""), "ok");
  }

  // ── controls ─────────────────────────────────────────────────────────────
  function choose(f) {
    if (!f) return;
    if (!kindOf(f)) {
      el.stage.hidden = false;
      setBadge("unsupported file", "halt");
      setNote("That is not a video or photo this page can read. Try an mp4, mov, webm, jpg, png or webp.");
      return;
    }
    el.tamper.textContent = "Change one byte";
    seal(f);
  }

  // Terms are chosen before sealing because they are signed into the manifest.
  // Changing one after the fact therefore has to re-seal, which also issues a
  // new code — the old one would otherwise still open the old container.
  [[el.ruleChips, "rule"], [el.roleChips, "role"]].forEach(function (pair) {
    var group = pair[0];
    if (!group) return;
    group.addEventListener("click", function (e) {
      var chip = e.target.closest(".byo-chip");
      if (!chip || chip.classList.contains("is-on")) return;
      group.querySelectorAll(".byo-chip").forEach(function (c) {
        var on = c === chip;
        c.classList.toggle("is-on", on);
        c.setAttribute("aria-checked", on ? "true" : "false");
      });
      if (file && phase !== "sealing") seal(file);
    });
  });

  el.input.addEventListener("change", function (e) { choose(e.target.files && e.target.files[0]); });
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

  el.copy.addEventListener("click", function () {
    el.code.select();
    try {
      navigator.clipboard.writeText(el.code.value);
      el.copy.textContent = "copied";
      setTimeout(function () { el.copy.textContent = "copy"; }, 1600);
    } catch (e) { /* the field is selected; the viewer can copy by hand */ }
  });

  el.tamper.addEventListener("click", function () {
    if (phase === "playing" && nextIndex < chunks.length - 1) {
      armAt = nextIndex + 1;
      el.tamper.disabled = true;
      setNote("Armed. One byte of the next chunk will be changed before it is verified.");
    } else if (file) {
      el.tamper.textContent = "Change one byte";
      seal(file, 2);
    }
  });

  el.reset.addEventListener("click", function () {
    run++; phase = "idle"; file = null; sealed = null; incoming = null;
    el.input.value = ""; el.openInput.value = ""; el.openCode.value = "";
    el.stage.hidden = true; el.share.hidden = true; el.progress.textContent = "";
    openStatus("", null);
    releaseUrls();
    try { el.video.pause(); el.video.removeAttribute("src"); el.video.load(); } catch (e) {}
    el.image.removeAttribute("src");
    setNote(DEFAULT_NOTE);
  });
})();
