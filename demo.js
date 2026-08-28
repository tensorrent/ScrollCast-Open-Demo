// demo.js — the hero verification demo.
//
// Everything shown here is real. The page loads the signed manifest that
// tools/pack.mjs produced, checks its Ed25519 signature against the publisher
// key compiled into scrollcast-verify.js, then fetches each CMAF segment and
// re-derives BOTH addresses (the 16-hex substrate root and the sha256) from the
// bytes that actually arrived. Only segments that verify are handed to the
// decoder. "Change one byte" flips a real byte in a real segment before
// verification runs, so the halt you see is the shipping verifier rejecting it,
// not a scripted animation.
//
// There is no code path in this file that reports a pass without calling
// ScrollcastVerify.verifySegment on the fetched bytes.

"use strict";

(function () {
  var SC = window.ScrollcastVerify;
  var $ = function (id) { return document.getElementById(id); };
  var el = {
    video: $("sc-video"),
    strip: $("sc-strip"),
    badge: $("sc-badge"),
    halt: $("sc-halt"),
    haltSeg: $("sc-halt-seg"),
    haltExpect: $("sc-halt-expect"),
    haltGot: $("sc-halt-got"),
    statSegs: $("sc-stat-segs"),
    statBlocks: $("sc-stat-blocks"),
    statBytes: $("sc-stat-bytes"),
    note: $("sc-note"),
    tamper: $("sc-tamper"),
    restart: $("sc-restart"),
    stage: $("sc-stage"),
  };

  if (!SC || !el.stage) return;

  var BASE = (document.currentScript && document.currentScript.dataset.base) || "";

  // Verification runs ahead of the playhead by this many segments and no more.
  // That is what the real player does (a bounded buffer window rather than
  // fetching the whole ladder), and it is also what makes the demo legible:
  // the strip fills at the pace of playback instead of completing in a blink.
  var AHEAD_SEGMENTS = 3;
  // Pace when there is no playhead to follow (no MSE, or autoplay blocked).
  var FALLBACK_PACE_MS = 900;
  // A SourceBuffer that never fires updateend must not wedge the pump.
  var APPEND_TIMEOUT_MS = 8000;
  // If MSE has produced nothing at all by now, stop trusting it and run the
  // verification against the still frame instead. This page is sent cold to
  // people on browsers nobody here can test; it must never sit at zero.
  var MSE_WATCHDOG_MS = 9000;

  var DEFAULT_NOTE = el.note ? el.note.textContent : "";

  var fmt = function (n) { return n.toLocaleString("en-US"); };
  var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

  // ── state ────────────────────────────────────────────────────────────────
  var manifest = null, rendition = null, segs = [];
  var run = 0;              // bumped on every (re)start; stale async work bails
  var armAt = -1;           // segment index to corrupt, or -1
  var nextIndex = 0;        // next segment the pump will fetch
  var phase = "idle";       // idle | running | halted | complete
  var totals = { segs: 0, blocks: 0, bytes: 0 };
  var cells = [];
  var ms = null, sourceBuffer = null, mseMode = false;
  var forceNoPlayback = false;   // set by the watchdog after MSE fails to deliver

  var MediaSourceCtor = window.ManagedMediaSource || window.MediaSource || null;

  function setBadge(text, kind) {
    el.badge.textContent = text;
    el.badge.className = "sc-badge" + (kind ? " is-" + kind : "");
  }
  function setNote(text) { if (el.note) el.note.textContent = text; }

  function paintStats() {
    el.statSegs.textContent = fmt(totals.segs);
    el.statBlocks.textContent = fmt(totals.blocks);
    el.statBytes.textContent = (totals.bytes / 1048576).toFixed(2);
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

  // Cell tint comes from the REAL root, through the same charToColor the
  // substrate renders with — so the strip is a picture of the address, not decor.
  function paintCell(i, root, failed) {
    var c = cells[i];
    if (!c) return;
    if (failed) { c.className = "sc-cell is-fail"; return; }
    var colors = SC.rootColors(root);
    var r = 0, g = 0, b = 0;
    for (var k = 0; k < colors.length; k++) {
      r += (colors[k] >> 16) & 255; g += (colors[k] >> 8) & 255; b += colors[k] & 255;
    }
    var n = colors.length || 1;
    c.style.background = "rgb(" + Math.round(r / n) + "," + Math.round(g / n) + "," + Math.round(b / n) + ")";
    c.className = "sc-cell is-ok";
  }

  function setTamperLabel() {
    el.tamper.textContent = phase === "complete" ? "Run it again, tampered" : "Change one byte";
  }

  // ── the halt ─────────────────────────────────────────────────────────────
  function halt(segIndex, failure, segBytes) {
    phase = "halted";
    try { el.video.pause(); } catch (e) {}
    paintCell(segIndex, null, true);
    setBadge("playback stopped", "halt");
    el.haltSeg.textContent =
      "segment " + String(segIndex + 1).padStart(2, "0") +
      " — one byte changed out of " + fmt(segBytes);

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
    el.restart.hidden = false;
    setNote("The decoder never received those bytes. Verification happens before decode, so a corrupted or substituted segment ends the stream instead of quietly degrading it.");
  }

  // ── media pipeline ───────────────────────────────────────────────────────
  function canUseMse(mimeCodec) {
    if (forceNoPlayback) return false;
    if (!MediaSourceCtor) return false;
    try { return MediaSourceCtor.isTypeSupported(mimeCodec); } catch (e) { return false; }
  }

  function openMediaSource(mimeCodec) {
    return new Promise(function (resolve, reject) {
      ms = new MediaSourceCtor();
      // ManagedMediaSource (Safari 17+, iOS) requires this on the element it
      // is attached to; harmless for plain MediaSource.
      try { el.video.disableRemotePlayback = true; } catch (e) { /* older engines */ }
      el.video.src = URL.createObjectURL(ms);
      var to = setTimeout(function () { reject(new Error("MediaSource open timed out")); }, 5000);
      ms.addEventListener("sourceopen", function () {
        clearTimeout(to);
        try {
          // Leave SourceBuffer.mode at its default ("segments"): the packager
          // emits fMP4 with correct baseMediaDecodeTime, and this matches the
          // sequence the shipping player is device-verified against.
          sourceBuffer = ms.addSourceBuffer(mimeCodec);
          resolve();
        } catch (e) { reject(e); }
      }, { once: true });
    });
  }

  function appendBuffer(bytes) {
    return new Promise(function (resolve, reject) {
      if (!sourceBuffer) return resolve();
      var timer = setTimeout(function () {
        cleanup();
        reject(new Error("SourceBuffer append timed out"));
      }, APPEND_TIMEOUT_MS);
      var done = function () { cleanup(); resolve(); };
      var fail = function (e) { cleanup(); reject(e instanceof Error ? e : new Error("append failed")); };
      var cleanup = function () {
        clearTimeout(timer);
        sourceBuffer.removeEventListener("updateend", done);
        sourceBuffer.removeEventListener("error", fail);
      };
      sourceBuffer.addEventListener("updateend", done);
      sourceBuffer.addEventListener("error", fail);
      try { sourceBuffer.appendBuffer(bytes); } catch (e) { fail(e); }
    });
  }

  function waitForIdle() {
    return new Promise(function (resolve) {
      if (!sourceBuffer || !sourceBuffer.updating) return resolve();
      sourceBuffer.addEventListener("updateend", function h() {
        sourceBuffer.removeEventListener("updateend", h);
        resolve();
      });
    });
  }

  // ── the run ──────────────────────────────────────────────────────────────
  async function fetchBytes(uri) {
    var res = await fetch(BASE + uri, { cache: "force-cache" });
    if (!res.ok) throw new Error("fetch " + uri + " -> " + res.status);
    return new Uint8Array(await res.arrayBuffer());
  }

  // A real mutation of the real bytes. Nothing downstream is told it happened.
  function flipOneByte(bytes) {
    var i = Math.floor(bytes.length / 2);
    bytes[i] = bytes[i] ^ 0x01;
  }

  // Hold the pump inside a bounded window ahead of the playhead.
  async function holdForWindow(i, myRun) {
    if (!mseMode) { await sleep(FALLBACK_PACE_MS); return; }
    for (;;) {
      if (myRun !== run || phase === "halted") return;
      // If playback is not actually running — autoplay refused, low power
      // mode, the viewer paused it — there is no playhead to follow and
      // gating on currentTime would stall the demo permanently. Pace on a
      // timer instead so verification still visibly proceeds.
      if (el.video.paused) { await sleep(FALLBACK_PACE_MS); return; }
      var t = el.video.currentTime || 0;
      // Before playback actually starts, let a few segments through so there
      // is something to decode; after that, follow the playhead.
      if (t === 0 && i < AHEAD_SEGMENTS) return;
      var segDur = segs[i].durationSec || 2;
      if ((i * segDur) - t < AHEAD_SEGMENTS * segDur) return;
      await sleep(150);
    }
  }

  async function verifyOne(entry, i, myRun) {
    var bytes = await fetchBytes(entry.uri);
    if (myRun !== run) return false;

    var tampered = false;
    if (i === armAt) { flipOneByte(bytes); armAt = -1; tampered = true; }

    // The shipping verifier: length gate first, then both addresses re-derived
    // from these exact bytes.
    var verdict = SC.verifySegment(bytes, entry);

    if (!verdict.ok) {
      halt(i, verdict.failure, entry.bytes);
      return false;
    }
    if (tampered) {
      // Unreachable unless the verifier is broken. Say so rather than
      // reporting a pass we did not earn.
      halt(i, { kind: "root", expected: entry.root, derived: verdict.derived.root }, entry.bytes);
      return false;
    }

    totals.segs += 1;
    totals.blocks += verdict.derived.blocks;
    totals.bytes += verdict.derived.bytes;
    paintCell(i, entry.root, false);
    paintStats();

    if (mseMode) await appendBuffer(bytes);
    return true;
  }

  // Nothing verified after MSE_WATCHDOG_MS means the decoder path is wedged on
  // an engine we could not test. Give up on it and restart without playback so
  // the verification — the actual point of the demo — still runs.
  function armWatchdog(myRun) {
    setTimeout(function () {
      if (myRun !== run || phase !== "running" || totals.segs > 0) return;
      forceNoPlayback = true;
      start();
    }, MSE_WATCHDOG_MS);
  }

  async function start(tamperAtIndex) {
    var myRun = ++run;
    phase = "running";
    armAt = typeof tamperAtIndex === "number" ? tamperAtIndex : -1;
    nextIndex = 0;
    totals = { segs: 0, blocks: 0, bytes: 0 };
    paintStats();
    el.halt.classList.remove("is-shown");
    el.restart.hidden = true;
    el.tamper.disabled = false;
    el.stage.classList.remove("is-noplayback");
    sourceBuffer = null; ms = null;
    setTamperLabel();

    var raw;
    try {
      raw = await (await fetch(BASE + "scrollcast.json", { cache: "force-cache" })).json();
      manifest = SC.normalizeManifest(raw);
    } catch (e) {
      setBadge("demo unavailable", "halt");
      setNote("Could not load the signed manifest: " + e.message);
      return;
    }
    if (myRun !== run) return;

    // 1. Trust gate. No media byte is fetched until the manifest's signature
    //    verifies against the publisher key compiled into the bundle.
    var sig = SC.verifyManifest(raw);
    if (!sig.valid) {
      setBadge("signature invalid", "halt");
      setNote("The manifest signature did not verify, so no media is fetched. " + (sig.reason || ""));
      return;
    }
    if (SC.pin && !sig.trusted) {
      setBadge("wrong publisher", "halt");
      setNote("Valid signature, but not from the pinned publisher key. Nothing is fetched.");
      return;
    }
    setBadge("publisher verified", "ok");

    rendition = manifest.renditions[0];
    segs = rendition.segments;
    buildStrip(segs.length);

    // 2. MSE is the real article: only verified bytes are ever appended, so a
    //    rejected segment simply never reaches the decoder. Where MSE is
    //    unavailable the verification still runs on the same real bytes.
    mseMode = canUseMse(rendition.mimeCodec);
    if (mseMode) {
      try { await openMediaSource(rendition.mimeCodec); }
      catch (e) { mseMode = false; }
    }
    if (mseMode) armWatchdog(myRun);
    if (!mseMode) {
      el.stage.classList.add("is-noplayback");
      setNote("This browser will not stream through MediaSource, so the picture is a still frame. The verification below is running for real on the same signed segments.");
    }
    if (myRun !== run) return;

    try {
      if (mseMode) {
        var initBytes = await fetchBytes(rendition.init.uri);
        if (myRun !== run) return;
        if (!SC.verifySegment(initBytes, rendition.init).ok) {
          setBadge("init rejected", "halt");
          setNote("The initialization segment failed verification, so playback never starts.");
          return;
        }
        await appendBuffer(initBytes);
        // Deliberately NOT awaited. WebKit leaves the play() promise pending
        // while the element has no playable data, and the only thing that can
        // supply that data is the loop below — so awaiting it here deadlocks
        // the demo at zero segments on Safari. Start playback and move on.
        el.video.play().catch(function () { /* autoplay refused; the pump copes */ });
      }

      for (var i = 0; i < segs.length; i++) {
        if (myRun !== run || phase === "halted") return;
        nextIndex = i;
        await holdForWindow(i, myRun);
        if (myRun !== run || phase === "halted") return;
        var ok = await verifyOne(segs[i], i, myRun);
        if (!ok) return;
      }

      if (myRun !== run) return;
      if (mseMode) {
        await waitForIdle();
        try { if (ms && ms.readyState === "open") ms.endOfStream(); } catch (e) {}
      }
      phase = "complete";
      setTamperLabel();
      setBadge("every byte verified", "ok");
      setNote("Every segment was re-addressed from the bytes that arrived and matched the signed manifest. Change one byte and the run ends instead of continuing.");
    } catch (e) {
      if (myRun !== run) return;
      setBadge("demo error", "halt");
      setNote(String(e && e.message ? e.message : e));
    }
  }

  // ── controls ─────────────────────────────────────────────────────────────
  // The tamper button must always do something. Mid-run it corrupts the next
  // segment; once the stream has finished it restarts with a segment already
  // marked for corruption, so a visitor who arrives late still sees the halt.
  el.tamper.addEventListener("click", function () {
    if (phase === "running" && nextIndex < segs.length - 1) {
      armAt = nextIndex + 1;
      el.tamper.disabled = true;
      setNote("Armed. One byte of the next segment will be changed in transit.");
    } else {
      start(Math.min(2, Math.max(0, segs.length - 1)));
    }
  });

  el.restart.addEventListener("click", function () {
    setNote(DEFAULT_NOTE);
    forceNoPlayback = false;   // give the decoder another chance on an explicit retry
    start();
  });

  // Recovery for a browser that refused autoplay: let the viewer start it.
  el.video.addEventListener("click", function () {
    if (phase === "halted") return;
    if (el.video.paused) { el.video.play().catch(function () {}); }
    else { el.video.pause(); }
  });

  start();
})();
