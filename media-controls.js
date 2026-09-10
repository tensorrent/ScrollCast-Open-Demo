// Keep a visible viewer mark and playback controls in the same fullscreen
// surface. Native video fullscreen / picture-in-picture omit sibling overlays.
(() => {
  const $ = id => document.getElementById(id);
  const players = new Map();
  function mount(prefix) {
    const video = $(prefix + '-video'), frame = $(prefix + '-frame');
    if (!video || !frame) return;
    const mark = $(prefix + '-watermark'), controls = $(prefix + '-media-controls');
    const play = $(prefix + '-play'), seek = $(prefix + '-seek');
    const sound = $(prefix + '-sound'), full = $(prefix + '-fullscreen');
    const clock = $(prefix + '-clock'), feedback = $(prefix + '-media-feedback');
    let kind = 'video', enabled = false;
    const time = seconds => `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, '0')}`;
    function update() {
      const duration = Number.isFinite(video.duration) ? video.duration : 0;
      play.textContent = video.paused ? 'Play' : 'Pause';
      play.setAttribute('aria-label', video.paused ? 'Play film' : 'Pause film');
      seek.disabled = !['video', 'audio'].includes(kind) || duration <= 0;
      seek.value = duration ? String((video.currentTime || 0) / duration * 1000) : '0';
      clock.textContent = `${time(video.currentTime || 0)} / ${time(duration)}`;
      sound.textContent = video.muted ? 'Sound off' : 'Sound on';
      sound.setAttribute('aria-pressed', String(!video.muted));
    }
    play.addEventListener('click', () => {
      if (video.paused) video.play().catch(() => { feedback.textContent = 'Playback could not start. Try restarting the screening.'; });
      else video.pause();
    });
    sound.addEventListener('click', () => { video.muted = !video.muted; update(); });
    seek.addEventListener('input', () => {
      if (Number.isFinite(video.duration) && video.duration > 0) video.currentTime = Number(seek.value) / 1000 * video.duration;
    });
    full.disabled = typeof frame.requestFullscreen !== 'function';
    if (full.disabled) full.title = 'This browser keeps the watermarked player inline.';
    full.addEventListener('click', async () => {
      try {
        if (document.fullscreenElement === frame) await document.exitFullscreen();
        else await frame.requestFullscreen();
      } catch { feedback.textContent = 'Fullscreen is unavailable. The viewer ID remains visible here.'; }
    });
    document.addEventListener('fullscreenchange', () => {
      full.textContent = document.fullscreenElement === frame ? 'Exit fullscreen' : 'Fullscreen';
    });
    for (const event of ['play', 'pause', 'timeupdate', 'durationchange', 'volumechange', 'emptied', 'ended']) video.addEventListener(event, update);
    players.set(prefix, {
      set(watermark, mediaKind = 'video') {
        kind = mediaKind;
        enabled = !!watermark;
        mark.hidden = !enabled || kind === 'ended';
        controls.hidden = !enabled;
        video.controls = !enabled && ['video', 'audio'].includes(kind);
        video.disablePictureInPicture = enabled;
        video.disableRemotePlayback = true;
        frame.classList.toggle('has-watermark', enabled);
        if (enabled) {
          for (const label of mark.querySelectorAll('[data-viewer-id]')) label.textContent = watermark.viewerId;
          mark.setAttribute('aria-label', 'Visible viewer ID: ' + watermark.viewerId);
        }
        play.hidden = seek.hidden = sound.hidden = clock.hidden = !['video', 'audio'].includes(kind);
        feedback.textContent = '';
        update();
      },
    });
  }
  mount('sc'); mount('byo');
  window.ScrollcastMedia = {
    setWatermark(prefix, watermark, kind) {
      if (!players.has(prefix)) throw new Error('The viewer-ID player is unavailable. Reload this page.');
      players.get(prefix).set(watermark, kind);
    },
  };

  // Sample identity is deliberately labelled as a demo assignment. A real
  // recipient's mark is taken from the signed container by byo.js.
  const toggle = $('sc-watermark-toggle'), identity = $('sc-viewer-id');
  function sample() {
    const id = identity.value.trim();
    if (toggle.checked && !/^[A-Za-z0-9][A-Za-z0-9._@+\-]{0,63}$/.test(id)) {
      identity.setCustomValidity('Use 1–64 letters, numbers, dots, @, +, hyphens or underscores.');
      identity.reportValidity(); return;
    }
    identity.setCustomValidity('');
    identity.disabled = !toggle.checked;
    window.ScrollcastMedia.setWatermark('sc', toggle.checked ? { mode: 'visible', viewerId: id } : null);
    document.dispatchEvent(new CustomEvent('scrollcast:screening-options'));
  }
  toggle?.addEventListener('change', sample);
  identity?.addEventListener('change', sample);
  if (toggle && identity) sample();
})();
