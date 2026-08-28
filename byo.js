// byo.js — "run it on your own film", entirely inside the visitor's browser.
//
// What this genuinely does, on bytes the visitor chose:
//   1. reads the file in chunks and addresses each one with the SHIPPING
//      addressSegment — the same 216-byte block motif Merkle root and sha256
//      the packager writes into a real manifest
//   2. mints a throwaway Ed25519 keypair and REALLY signs the manifest it just
//      derived
//   3. verifies that signature, then re-reads every chunk and re-derives both
//      addresses with the shipping verifySegment
//   4. on "change one byte", flips a real byte in a real chunk before
//      verification, so the halt is the verifier refusing it
//
// What it deliberately does NOT do, and says so on the page:
//   - it does not transcode to CMAF. Real packaging runs ffmpeg server-side;
//     here the file is chunked by byte range and played from a blob, so
//     verification runs ALONGSIDE playback rather than gating the decoder.
//   - it does not upload anything. There is no fetch of the visitor's bytes
//     anywhere in this file, which is the whole reason it is safe to hand to
//     someone protecting an unreleased film.
//   - it does not produce a shareable link. That needs somewhere to put the
//     bytes, and a static page has nowhere.
//
// The signing key is a throwaway. It is labelled as one everywhere it appears,
// because a page about publisher identity must not imply the visitor just
// acquired one.

"use strict";

(function () {
  var SC = window.ScrollcastVerify;
  var $ = function (id) { return document.getElementById(id); };
  var el = {
    panel: $("byo"),
    input: $("byo-file"),
    drop: $("byo-drop"),
    stage: $("byo-stage"),
    video: $("byo-video"),
    strip: $("byo-strip"),
    badge: $("byo-badge"),
    halt: $("byo-halt"),
    haltSeg: $("byo-halt-seg"),
    haltExpect: $("byo-halt-expect"),
    haltGot: $("byo-halt-got"),
    name: $("byo-name"),
    statChunks: $("byo-stat-chunks"),
    statBlocks: $("byo-stat-blocks"),
    statBytes: $("byo-stat-bytes"),
    note: $("byo-note"),
    tamper: $("byo-tamper"),
    reset: $("byo-reset"),
    progress: $("byo-progress"),
  };

  if (!SC || !el.panel || !SC.generateKeypair) return;

  // Addressing runs at a few MiB/s, so a feature film would sit here for
  // minutes. Cover a prefix and say exactly how much was covered rather than
  // sampling the file and implying the whole thing was checked.
  var MAX_BYTES = 24 * 1024 * 1024;
  var TARGET_CHUNKS = 24;
  var MIN_CHUNK = 256 * 1024;

  var DEFAULT_NOTE = el.note ? el.note.textContent : "";
  var fmt = function (n) { return n.toLocaleString("en-US"); };
  var mib = function (n) { return (n / 1048576).toFixed(2); };
  var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

  var run = 0;
  var phase = "idle";           // idle | addressing | playing | halted | complete
  var file = null, manifest = null, chunks = [];
  var armAt = -1, nextIndex = 0;
  var totals = { chunks: 0, blocks: 0, bytes: 0 };
  var cells = [];
  var blobUrl = null;

  function setBadge(text, kind) {
    el.badge.textContent = text;
    el.badge.className = "sc-badge" + (kind ? " is-" + kind : "");
  }
  function setNote(t) { if (el.note) el.note.textContent = t; }
  function paintStats() {
    el.statChunks.textContent = fmt(totals.chunks);
    el.statBlocks.textContent = fmt(totals.blocks);
    el.statBytes.textContent = mib(totals.bytes);
  }
  function buildStrip(n) {
    el.strip.innerHTML = "";
    cells = [];
    for (var i = 0; i < n; i++) {
      var c = document.createElement("span");
      c.className = "sc-cell";
      el.strip.appendChild(c);
      cells.push(c);
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

  // Read one byte range of the chosen file. Slicing keeps memory flat no
  // matter how large the film is.
  async function readChunk(entry) {
    var buf = await file.slice(entry.start, entry.start + entry.bytes).arrayBuffer();
    return new Uint8Array(buf);
  }

  function halt(i, failure, entryBytes) {
    phase = "halted";
    try { el.video.pause(); } catch (e) {}
    paintCell(i, null, true);
    setBadge("playback stopped", "halt");
    el.haltSeg.textContent = "chunk " + String(i + 1).padStart(2, "0") +
      " — one byte changed out of " + fmt(entryBytes);
    if (failure && failure.kind === "root") {
      el.haltExpect.textContent = failure.expected;
      el.haltGot.textContent = failure.derived;
    } else if (failure && failure.kind === "sha256") {
      el.haltExpect.textContent = failure.expected.slice(0, 16) + "…";
      el.haltGot.textContent = failure.derived.slice(0, 16) + "…";
    } else if (failure && failure.kind === "length") {
      el.haltExpect.textContent = fmt(failure.expected) + " bytes";
      el.haltGot.textContent = fmt(failure.got) + " bytes";
    }
    el.halt.classList.add("is-shown");
    el.tamper.disabled = true;
    setNote("That is your own file failing its own signature. One byte changed out of " +
      fmt(entryBytes) + ", and the address it derives no longer matches the one that was signed.");
  }

  async function begin(chosen, tamperAtIndex) {
    var myRun = ++run;
    file = chosen;
    phase = "addressing";
    armAt = -1; nextIndex = 0;
    totals = { chunks: 0, blocks: 0, bytes: 0 };
    paintStats();
    el.halt.classList.remove("is-shown");
    el.tamper.disabled = true;
    el.stage.hidden = false;
    el.name.textContent = file.name;
    setNote(DEFAULT_NOTE);

    var covered = Math.min(file.size, MAX_BYTES);
    var chunkSize = Math.max(MIN_CHUNK, Math.ceil(covered / TARGET_CHUNKS));

    chunks = [];
    for (var off = 0; off < covered; off += chunkSize) {
      chunks.push({ index: chunks.length, start: off, bytes: Math.min(chunkSize, covered - off) });
    }
    buildStrip(chunks.length);

    // ── 1. address every chunk with the shipping codec ──────────────────────
    setBadge("addressing…", null);
    for (var i = 0; i < chunks.length; i++) {
      if (myRun !== run) return;
      var bytes = await readChunk(chunks[i]);
      var addr = SC.addressSegment(bytes);
      chunks[i].root = addr.root;
      chunks[i].sha256 = addr.sha256;
      chunks[i].blocks = addr.blocks;
      el.progress.textContent = "addressing " + (i + 1) + " / " + chunks.length +
        " · " + mib((i + 1) * chunkSize) + " MiB";
      await sleep(0);   // keep the tab responsive between chunks
    }
    if (myRun !== run) return;

    // ── 2. sign it for real, with a throwaway identity ──────────────────────
    el.progress.textContent = "signing…";
    var kp = SC.generateKeypair();
    manifest = SC.signManifest({
      format: "scrollcast-byo",
      title: file.name,
      createdAt: new Date().toISOString(),
      coveredBytes: covered,
      totalBytes: file.size,
      segments: chunks.map(function (c) {
        return { index: c.index, uri: "local:" + c.index, bytes: c.bytes, durationSec: 0,
                 root: c.root, sha256: c.sha256, blocks: c.blocks };
      }),
    }, kp.privateKey);

    var verdict = SC.verifyManifestWith(manifest, kp.publicKey);
    if (!verdict.valid) {
      setBadge("signature invalid", "halt");
      setNote("The manifest this page just produced did not verify, which should be impossible. Nothing is played.");
      return;
    }
    setBadge("signed · " + kp.publicKey.slice(0, 12) + "…", "ok");
    el.progress.textContent =
      (covered < file.size
        ? "addressed the first " + mib(covered) + " MiB of " + mib(file.size) + " MiB"
        : "addressed all " + mib(covered) + " MiB")
      + " in " + chunks.length + " chunks";

    // ── 3. play it, verifying each chunk against what was signed ────────────
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    blobUrl = URL.createObjectURL(file);
    el.video.src = blobUrl;
    el.video.play().catch(function () { /* autoplay refused; the pass still runs */ });

    phase = "playing";
    // Arm here rather than at entry: the chunk list does not exist until the
    // addressing pass has run, so an index chosen by the caller is only
    // meaningful now.
    if (typeof tamperAtIndex === "number") {
      armAt = Math.min(Math.max(0, tamperAtIndex), chunks.length - 1);
    }
    el.tamper.disabled = false;
    setNote("Verifying your file against the signature this page just made. Change one byte and it stops.");

    var pace = Math.max(150, Math.min(900, Math.round(20000 / Math.max(1, chunks.length))));
    for (var j = 0; j < chunks.length; j++) {
      if (myRun !== run || phase === "halted") return;
      nextIndex = j;
      await sleep(pace);
      if (myRun !== run || phase === "halted") return;

      var raw = await readChunk(chunks[j]);
      var tampered = false;
      if (j === armAt) { raw[Math.floor(raw.length / 2)] ^= 0x01; armAt = -1; tampered = true; }

      var res = SC.verifySegment(raw, manifest.segments[j]);
      if (!res.ok) { halt(j, res.failure, chunks[j].bytes); return; }
      if (tampered) {
        halt(j, { kind: "root", expected: chunks[j].root, derived: res.derived.root }, chunks[j].bytes);
        return;
      }

      totals.chunks += 1;
      totals.blocks += res.derived.blocks;
      totals.bytes += res.derived.bytes;
      paintCell(j, chunks[j].root, false);
      paintStats();
    }

    if (myRun !== run) return;
    phase = "complete";
    el.tamper.textContent = "Run it again, tampered";
    setBadge("every byte verified", "ok");
    setNote("Every chunk of your file re-derived the address that was signed. Nothing was uploaded — this all ran in your browser.");
  }

  // ── controls ─────────────────────────────────────────────────────────────
  function choose(f) {
    if (!f) return;
    if (!/^video\//.test(f.type) && !/\.(mp4|mov|m4v|webm|mkv)$/i.test(f.name)) {
      setNote("That does not look like a video file. Any mp4, mov or webm will do.");
      el.stage.hidden = false;
      setBadge("not a video", "halt");
      return;
    }
    el.tamper.textContent = "Change one byte";
    begin(f);
  }

  el.input.addEventListener("change", function (e) { choose(e.target.files && e.target.files[0]); });

  ["dragenter", "dragover"].forEach(function (ev) {
    el.drop.addEventListener(ev, function (e) { e.preventDefault(); el.drop.classList.add("is-over"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    el.drop.addEventListener(ev, function (e) { e.preventDefault(); el.drop.classList.remove("is-over"); });
  });
  el.drop.addEventListener("drop", function (e) {
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    choose(f);
  });

  el.tamper.addEventListener("click", function () {
    if (phase === "playing" && nextIndex < chunks.length - 1) {
      armAt = nextIndex + 1;
      el.tamper.disabled = true;
      setNote("Armed. One byte of the next chunk will be changed before it is verified.");
    } else if (file) {
      // Finished (or not yet playing) — run it again with a chunk already
      // marked, so the button always produces the halt it promises.
      el.tamper.textContent = "Change one byte";
      begin(file, 2);
    }
  });

  el.reset.addEventListener("click", function () {
    run++;
    phase = "idle";
    file = null;
    el.input.value = "";
    el.stage.hidden = true;
    el.progress.textContent = "";
    if (blobUrl) { URL.revokeObjectURL(blobUrl); blobUrl = null; }
    try { el.video.pause(); el.video.removeAttribute("src"); el.video.load(); } catch (e) {}
    setNote(DEFAULT_NOTE);
  });
})();
