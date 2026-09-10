// One continuous entrance into the real player and the real local file tools.
// Reparent live elements instead of duplicating players, inputs, or verifier state.
(() => {
  const $ = id => document.getElementById(id);
  const dialog = $('experience');
  if (!dialog || typeof dialog.showModal !== 'function') return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const stage = $('sc-stage'), video = $('sc-video'), cinema = $('cinema');
  const own = document.querySelector('#byo > .wide');
  const watch = $('experience-watch'), create = $('experience-create');
  const portal = $('experience-portal'), next = $('experience-next');
  const stay = $('experience-stay'), status = $('experience-status');
  const progress = $('experience-progress');
  const PREVIEW_SECONDS = 12;
  let state = 'closed', session = 0, autoAdvance = true, opener;
  let timers = [], animations = [], homes = [];

  const signal = (name, detail) => document.dispatchEvent(new CustomEvent(name, { detail }));
  function later(fn, delay) {
    const token = session;
    timers.push(setTimeout(() => { if (session === token) fn(); }, delay));
  }
  function animate(element, frames, options) {
    if (element.animate) animations.push(element.animate(frames, options));
  }
  function move(element, destination) {
    const marker = document.createComment('Scrollcast experience home');
    element.before(marker);
    homes.push({ element, marker, style: element.getAttribute('style') });
    destination.append(element);
  }
  function setState(value) {
    state = value;
    dialog.dataset.scene = value;
  }
  function keepWatching() {
    autoAdvance = false;
    stay.hidden = true;
    status.textContent = 'Take your time. Your film is next whenever you’re ready.';
  }
  function close() {
    if (state === 'closed') return;
    ++session;
    timers.forEach(clearTimeout); timers = [];
    animations.forEach(animation => animation.cancel()); animations = [];
    signal('scrollcast:sample', { action: 'stop' });
    $('byo-video').pause();
    for (const { element, marker, style } of homes.reverse()) {
      marker.replaceWith(element);
      if (style === null) element.removeAttribute('style');
      else element.setAttribute('style', style);
    }
    homes = [];
    signal('scrollcast:cinema', { action: 'reset' });
    document.body.classList.remove('experience-open');
    setState('closed');
    if (dialog.open) dialog.close();
    opener?.focus({ preventScroll: true });
  }
  function makeYours() {
    if (state !== 'watching') return;
    autoAdvance = false;
    setState('dissolving');
    video.pause();
    create.hidden = false;
    create.inert = true;
    const duration = reduced.matches ? 100 : 1300;
    animate(watch, [
      { opacity: 1, transform: 'none', filter: 'blur(0px)' },
      { opacity: 0, transform: reduced.matches ? 'none' : 'scale(1.12) translateY(-30px)', filter: reduced.matches ? 'none' : 'blur(18px)' },
    ], { duration, easing: 'cubic-bezier(.4,0,.2,1)', fill: 'forwards' });
    animate(create, [
      { opacity: 0, transform: reduced.matches ? 'none' : 'translateY(80px) scale(.93)', filter: reduced.matches ? 'none' : 'blur(12px)' },
      { opacity: 1, transform: 'none', filter: 'blur(0px)' },
    ], { duration, delay: reduced.matches ? 0 : 350, easing: 'cubic-bezier(.16,1,.3,1)', fill: 'both' });
    later(() => {
      signal('scrollcast:sample', { action: 'stop' });
      watch.hidden = true;
      create.inert = false;
      setState('own');
      $('experience-chapter').textContent = '02 / YOUR FILM';
      dialog.scrollTop = 0;
      own.querySelector('h2').focus({ preventScroll: true });
    }, duration + (reduced.matches ? 0 : 350));
  }
  function enter(event) {
    if (event.button > 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (state !== 'closed') { event.preventDefault(); return; }
    event.preventDefault();
    opener = event.currentTarget;
    ++session;
    autoAdvance = true;
    stay.hidden = false;
    status.textContent = 'A 12-second first look. Then, your film.';
    progress.style.setProperty('--preview-progress', '0');
    $('experience-chapter').textContent = '01 / THE SCREENING';
    const rect = cinema.getBoundingClientRect();
    move(stage, $('experience-player'));
    move(own, create);
    move(cinema, portal);
    watch.hidden = false;
    watch.inert = true;
    create.hidden = true;
    portal.hidden = false;
    setState('diving');
    document.body.classList.add('experience-open');
    dialog.showModal();
    dialog.scrollTop = 0;
    $('experience-close').focus({ preventScroll: true });
    signal('scrollcast:sample', { action: 'start' });

    const duration = reduced.matches ? 120 : 2300;
    // The same ribbon leaves its hero position, fills the screen, then melts
    // past the camera. The player is already warming up behind it.
    cinema.style.cssText = 'position:absolute;inset:0;opacity:1;width:100%;height:100%;';
    if (!reduced.matches) {
      animate(cinema, [
        { left: `${rect.left}px`, top: `${rect.top}px`, width: `${rect.width}px`, height: `${rect.height}px` },
        { left: '0px', top: '0px', width: '100%', height: '100%' },
      ], { duration: 1000, easing: 'cubic-bezier(.65,0,.25,1)' });
      signal('scrollcast:cinema', { action: 'dive', duration });
      animate(portal, [
        { opacity: 1, filter: 'blur(0px)', offset: 0 },
        { opacity: 1, filter: 'blur(0px)', offset: .5 },
        { opacity: 0, filter: 'blur(20px)', offset: 1 },
      ], { duration, fill: 'forwards' });
    }
    animate(watch, [
      { opacity: 0, transform: reduced.matches ? 'none' : 'perspective(1000px) translateY(35vh) translateZ(-350px) rotateX(14deg)', filter: reduced.matches ? 'none' : 'blur(16px)' },
      { opacity: 1, transform: 'none', filter: 'blur(0px)' },
    ], { duration: reduced.matches ? 120 : 1500, delay: reduced.matches ? 0 : 800, easing: 'cubic-bezier(.16,1,.3,1)', fill: 'both' });
    later(() => {
      portal.hidden = true;
      watch.inert = false;
      signal('scrollcast:cinema', { action: 'rest' });
      setState('watching');
      $('experience-title').focus({ preventScroll: true });
    }, duration);
  }

  document.querySelectorAll('[data-experience]').forEach(link => link.addEventListener('click', enter));
  next.addEventListener('click', makeYours);
  stay.addEventListener('click', keepWatching);
  // Give people exploring verification or seeking the film control of pacing.
  $('sc-tamper').addEventListener('click', keepWatching);
  $('sc-restart').addEventListener('click', keepWatching);
  video.addEventListener('seeking', () => { if (state === 'watching') keepWatching(); });
  function followPlayback() {
    if (state !== 'watching' || document.hidden || document.fullscreenElement || video.webkitDisplayingFullscreen) return;
    if (video.ended) { makeYours(); return; }
    if (!autoAdvance) return;
    const elapsed = Math.max(0, video.currentTime || 0);
    progress.style.setProperty('--preview-progress', String(Math.min(1, elapsed / PREVIEW_SECONDS)));
    const remaining = Math.max(0, Math.ceil(PREVIEW_SECONDS - elapsed));
    status.textContent = remaining > 0 ? `Your film in ${remaining}s · or keep watching` : 'Next, make it your film.';
    if (elapsed >= PREVIEW_SECONDS) makeYours();
  }
  video.addEventListener('timeupdate', followPlayback);
  video.addEventListener('ended', followPlayback);
  video.addEventListener('webkitendfullscreen', followPlayback);
  document.addEventListener('fullscreenchange', followPlayback);
  document.addEventListener('visibilitychange', followPlayback);
  document.addEventListener('scrollcast:sample-state', event => {
    if (state === 'closed') return;
    if (event.detail.kind === 'halt' || event.detail.kind === 'fallback') {
      keepWatching();
      status.textContent = event.detail.kind === 'fallback'
        ? 'Still-frame verification on this browser. You can try your film below.'
        : 'The player needs attention. You can restart, or try your own film.';
    }
  });
  $('experience-close').addEventListener('click', close);
  dialog.addEventListener('cancel', event => { event.preventDefault(); close(); });
  dialog.addEventListener('close', close);
  // This link lives in the moved file panel. Restore the page before navigating.
  dialog.addEventListener('click', event => {
    if (event.target.closest('a[href="#limits"]')) close();
  });
  own.querySelector('h2').setAttribute('tabindex', '-1');
})();
