'use strict';

/* ------------------------------------------------------------------ *
 *  Les données du traitement (médicaments, doses, conseils) ne sont   *
 *  pas dans ce code : elles sont chiffrées dans data.enc              *
 *  (AES-256-GCM, clé PBKDF2-SHA256 dérivée du mot de passe).          *
 * ------------------------------------------------------------------ */
let MEDS = [], SOINS = [], DATA = null;

/* ---------------- utils ---------------- */
const H = 36e5;
const $ = s => document.querySelector(s);
const pad = n => String(n).padStart(2, '0');
const dkey = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const fromKey = (k, t = '00:00') => {
  const [y, m, d] = k.split('-').map(Number);
  const [h, mi] = t.split(':').map(Number);
  return new Date(y, m - 1, d, h, mi);
};
const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };
const dayDiff = (a, b) => Math.round((fromKey(dkey(b)) - fromKey(dkey(a))) / 864e5);
const hm = ts => { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const dur = ms => {
  ms = Math.max(0, ms);
  const m = Math.ceil(ms / 6e4), h = Math.floor(m / 60);
  return h ? `${h} h ${pad(m % 60)}` : `${m} min`;
};
const clock = ms => {
  ms = Math.max(0, ms);
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 3600)}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
};
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const DAYS = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
const MONTHS = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];
const longDate = d => `${DAYS[d.getDay()]} ${d.getDate()} ${MONTHS[d.getMonth()]}`;
const shortDate = d => `${d.getDate()} ${MONTHS[d.getMonth()].slice(0, 4)}.`;
const uid = () => Math.random().toString(36).slice(2, 10);
const relDay = ts => {
  const n = dayDiff(new Date(), new Date(ts));
  return n === 0 ? '' : n === 1 ? 'demain ' : n === -1 ? 'hier ' : shortDate(new Date(ts)) + ' ';
};

/* ---------------- state ---------------- */
const KEY = 'suivi-medocs-v1';
const DATA_KEY = 'suivi-medocs-data';
const DEFAULT = () => ({
  start: DATA.start,
  perfusion: false,
  times: Object.fromEntries(MEDS.filter(m => m.times).map(m => [m.id, [...m.times]])),
  stock: Object.fromEntries(MEDS.map(m => [m.id, m.stock ?? null])),
  log: [],
  alerts: {},
  notified: {},
  push: { on: false, hash: '', at: 0, err: '' },
});
let S = null;
const save = () => { try { if (S) localStorage.setItem(KEY, JSON.stringify(S)); } catch { /* storage unavailable */ } };
function loadState() {
  try { S = Object.assign(DEFAULT(), JSON.parse(localStorage.getItem(KEY) || '{}')); } catch { S = DEFAULT(); }
  delete S.ntfy;
  save();
}

/* ---------------- encrypted data ---------------- */
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function fetchEnc() {
  const r = await fetch('data.enc?' + Date.now(), { cache: 'no-store' });
  if (!r.ok) throw new Error('absent');
  return r.json();
}
async function decrypt(enc, password) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64(enc.salt), iterations: enc.iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(enc.iv) }, key, b64(enc.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
function setData(d, rev) {
  DATA = d; DATA.rev = rev;
  MEDS = d.meds; SOINS = d.soins || [];
}
function lockScreen(msg = '') {
  document.body.classList.add('locked');
  $('#title').textContent = 'Médocs';
  $('#subtitle').textContent = 'Données chiffrées';
  $('#view').innerHTML = `<form class="card lock" id="lockForm">
    <div class="lockico">🔒</div>
    <div class="name">Mot de passe</div>
    <div class="gen">Nécessaire une seule fois sur cet appareil.</div>
    <input type="password" id="pw" autocomplete="current-password" required placeholder="Mot de passe">
    <button class="btn full" type="submit">Déverrouiller</button>
    <div class="status no" id="lockMsg">${esc(msg)}</div>
  </form>`;
  $('#lockForm').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.disabled = true; btn.textContent = 'Déchiffrement…'; $('#lockMsg').textContent = '';
    try {
      const enc = await fetchEnc();
      const d = await decrypt(enc, $('#pw').value);
      try { localStorage.setItem(DATA_KEY, JSON.stringify({ rev: enc.rev, data: d })); } catch { /* ignore */ }
      setData(d, enc.rev);
      start();
    } catch (err) {
      $('#lockMsg').textContent = err.message === 'absent' ? 'Données introuvables (data.enc).' : 'Mot de passe incorrect.';
      btn.disabled = false; btn.textContent = 'Déverrouiller';
    }
  });
}
function lock() {
  if (!confirm('Verrouiller ? Le mot de passe sera redemandé. Ton historique est conservé.')) return;
  try { localStorage.removeItem(DATA_KEY); } catch { /* ignore */ }
  location.reload();
}
// If data.enc was republished, ask the password again
async function checkRev() {
  try {
    const enc = await fetchEnc();
    if (DATA && enc.rev !== DATA.rev) {
      try { localStorage.removeItem(DATA_KEY); } catch { /* ignore */ }
      DATA = null; S = null;
      lockScreen('Traitement mis à jour : entre à nouveau le mot de passe.');
    }
  } catch { /* offline */ }
}

/* ---------------- logic ---------------- */
const med = id => MEDS.find(m => m.id === id);
const dayIdx = (d = new Date()) => dayDiff(fromKey(S.start), d);
const active = (m, d = new Date()) => { const i = dayIdx(d); return i >= 0 && i < m.days; };
const endDate = m => addDays(fromKey(S.start), m.days - 1);
const logsOf = id => S.log.filter(l => l.med === id && !l.skip).sort((a, b) => b.t - a.t);
const stockLeft = id => S.stock[id] == null || S.stock[id] === '' ? null : S.stock[id] - S.log.filter(l => l.med === id && !l.skip).length;

function slotsOn(d) {
  const k = dkey(d), out = [];
  for (const m of MEDS) {
    if (m.type !== 'fixed' || !active(m, d)) continue;
    for (const t of (S.times[m.id] || [])) out.push({ m, t, key: `${m.id}|${k}|${t}`, ts: +fromKey(k, t) });
  }
  return out.sort((a, b) => a.ts - b.ts);
}
const taken = key => S.log.find(l => l.slot === key);
// Unchecked slots from the previous days (to catch up forgotten check-ins)
function missedSlots(days = 3) {
  const out = [];
  for (let i = days; i >= 1; i--) out.push(...slotsOn(addDays(new Date(), -i)).filter(s => !taken(s.key)));
  return out;
}

function nextPending(now = Date.now()) {
  for (let i = 0; i < 4; i++) {
    const s = slotsOn(addDays(new Date(), i)).find(s => !taken(s.key) && s.ts > now);
    if (s) return s;
  }
  return null;
}

// When can this med be taken again (gap + 24h cap)
function medStatus(m, now = Date.now()) {
  const ls = logsOf(m.id), last = ls[0];
  const in24 = ls.filter(l => l.t > now - 24 * H);
  let next = 0, why = '', since = 0;
  if (m.gapH && last) {
    const g = last.t + m.gapH * H;
    if (g > next) { next = g; since = last.t; why = `${m.gapH} h entre 2 prises`; }
  }
  if (m.max24 && in24.length >= m.max24) {
    const oldest = in24[in24.length - 1];
    const g = oldest.t + 24 * H;
    if (g > next) { next = g; since = oldest.t; why = `max ${m.max24} / 24 h atteint`; }
  }
  const blocked = !!(m.perf && S.perfusion);
  const ended = !active(m);
  return { last, count: in24.length, next, since, why, blocked, ended, ok: !blocked && !ended && next <= now };
}

function take(id, slot) {
  const m = med(id), now = Date.now();
  const st = medStatus(m, now);
  if (m.type === 'prn') {
    if (st.blocked && !confirm(`Perfusion en cours : ${m.rx} ne doit pas être pris. Enregistrer quand même ?`)) return;
    if (!st.ok && !st.blocked && st.next > now &&
        !confirm(`${m.rx} : ${st.why}. Possible à ${hm(st.next)} (dans ${dur(st.next - now)}).\n\nEnregistrer quand même ?`)) return;
  } else if (m.gapH && st.last && now - st.last.t < m.gapH * H &&
      !confirm(`${m.rx} : dernière prise il y a ${dur(now - st.last.t)} (${m.gapH} h conseillé).\n\nEnregistrer quand même ?`)) return;
  S.log.push({ id: uid(), med: id, t: now, slot: slot || null });
  delete S.alerts[id];
  save();
  toast(`✓ ${m.rx} pris à ${hm(now)}`);
  render();
  syncPush();
}

function takeAt(id, slot) {
  const s = slot.split('|'), m = med(id);
  const when = +fromKey(s[1], s[2]);
  if (taken(slot)) return;
  S.log.push({ id: uid(), med: id, t: when, slot });
  save();
  toast(`✓ ${m.rx} noté pris ${relDay(when)}à ${s[2]}`);
  render();
}

function skip(id, slot) {
  if (!confirm(`Passer cette prise de ${med(id).rx} ?\n(déjà prise ailleurs, ou sautée sur avis médical)`)) return;
  S.log.push({ id: uid(), med: id, t: Date.now(), slot, skip: true });
  save(); render();
}

function untake(logId) {
  const l = S.log.find(x => x.id === logId);
  if (!l || !confirm(l.skip ? `Remettre la prise de ${med(l.med).rx} à faire ?` : `Annuler la prise de ${med(l.med).rx} à ${hm(l.t)} ?`)) return;
  S.log = S.log.filter(x => x.id !== logId);
  save(); render();
}

function editTime(logId) {
  const l = S.log.find(x => x.id === logId);
  if (!l) return;
  const v = prompt('Heure réelle de la prise (HH:MM)', hm(l.t));
  if (!v || !/^\d{1,2}:\d{2}$/.test(v.trim())) return;
  const [h, mi] = v.trim().split(':').map(Number);
  const d = new Date(l.t); d.setHours(h, mi, 0, 0);
  if (+d > Date.now()) { toast('Heure dans le futur'); return; }
  l.t = +d; save(); render();
}

/* ---------------- notifications ---------------- */
const canNotify = () => 'Notification' in window;
async function notify(title, body, tag) {
  if (!canNotify() || Notification.permission !== 'granted') return;
  try {
    const r = await navigator.serviceWorker?.getRegistration();
    if (r) await r.showNotification(title, { body, tag, icon: 'icon-192.png', badge: 'icon-192.png' });
    else new Notification(title, { body, tag });
  } catch { /* ignore */ }
}

/* ---------------- web push (own Cloudflare server) ---------------- */
const PUSH = () => DATA && DATA.push;
const pushSupported = () => 'serviceWorker' in navigator && 'PushManager' in window && canNotify();
const b64uDec = str => { const t = str.replace(/-/g, '+').replace(/_/g, '/'); return Uint8Array.from(atob(t + '='.repeat((4 - t.length % 4) % 4)), c => c.charCodeAt(0)); };
const b64uEnc = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function api(path, body) {
  const p = PUSH();
  const r = await fetch(p.url.replace(/\/$/, '') + path, {
    method: body ? 'POST' : 'GET',
    headers: { Authorization: 'Bearer ' + p.token, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
  return j;
}

function pushJobs() {
  const now = Date.now(), jobs = [];
  for (let i = 0; i < 8; i++) {
    for (const s of slotsOn(addDays(new Date(), i))) {
      if (taken(s.key)) continue;
      if (s.ts > now) jobs.push({ at: s.ts, title: `💊 ${s.m.rx} — ${s.t}`, body: `${s.m.gen} · ${s.m.meal}. ${s.m.recos[0]}`, tag: s.key });
      const again = s.ts + 30 * 6e4;
      if (again > now) jobs.push({ at: again, title: `⏰ Oubli ? ${s.m.rx}`, body: `Prévu à ${s.t}, pas encore coché dans Médocs.`, tag: s.key });
    }
  }
  for (const [id, ts] of Object.entries(S.alerts)) {
    if (ts <= now) continue;
    const m = med(id);
    jobs.push({ at: ts, title: `✓ ${m.rx} possible`, body: `Tu peux reprendre ${m.gen} si besoin · ${m.meal}.`, tag: 'alert-' + id });
  }
  return jobs.sort((a, b) => a.at - b.at);
}

let pushBusy = false, pushAgain = false;
async function syncPush(force) {
  if (!S || !S.push.on || !PUSH() || !navigator.onLine) return;
  if (pushBusy) { pushAgain = true; return; }
  const jobs = pushJobs(), hash = JSON.stringify(jobs);
  if (!force && hash === S.push.hash) return;
  pushBusy = true;
  try { await api('/schedule', { jobs }); S.push.hash = hash; S.push.err = ''; S.push.at = Date.now(); }
  catch (e) { S.push.err = String(e.message || e); }
  save();
  pushBusy = false;
  if (pushAgain) { pushAgain = false; syncPush(); }
}

async function enablePush() {
  if (!pushSupported()) { toast('Ouvre Médocs depuis l\'icône de l\'écran d\'accueil'); return; }
  const perm = await Notification.requestPermission(); // must be first (user gesture)
  if (perm !== 'granted') { toast('Refusé — Réglages iPhone › Notifications › Médocs'); render(); return; }
  try {
    const reg = await navigator.serviceWorker.ready;
    const { publicKey } = await api('/vapid');
    let sub = await reg.pushManager.getSubscription();
    const cur = sub && sub.options && sub.options.applicationServerKey;
    if (sub && cur && b64uEnc(cur) !== publicKey) { await sub.unsubscribe(); sub = null; }
    if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64uDec(publicKey) });
    await api('/subscribe', { subscription: sub.toJSON() });
    S.push.on = true; S.push.hash = ''; save();
    await syncPush(true);
    toast('🔔 Notifications activées');
  } catch (e) { S.push.err = String(e.message || e); save(); toast('Erreur : ' + S.push.err); }
  render();
}

async function disablePush() {
  S.push.on = false; save();
  try { await api('/schedule', { jobs: [] }); } catch { /* ignore */ }
  toast('Notifications coupées'); render();
}

function checkLocalAlerts() {
  const now = Date.now();
  for (const s of slotsOn(new Date())) {
    if (!taken(s.key) && s.ts <= now && now - s.ts < 3 * H && !S.notified[s.key]) {
      S.notified[s.key] = 1;
      notify(`💊 ${s.m.rx}`, `${s.t} — ${s.m.gen} · ${s.m.meal}`, s.key);
    }
  }
  for (const [id, ts] of Object.entries(S.alerts)) {
    if (ts <= now) {
      delete S.alerts[id];
      const m = med(id);
      notify(`${m.rx} possible`, `Tu peux reprendre ${m.gen} si besoin.`, 'alert-' + id);
      toast(`🔔 ${m.rx} possible maintenant`);
    }
  }
  save();
}

function cleanup() {
  const lim = Date.now() - 5 * 864e5;
  for (const k of Object.keys(S.notified)) { const p = k.split('|'); if (p[1] && +fromKey(p[1]) < lim) delete S.notified[k]; }
  save();
}

/* ---------------- calendar (.ics) ---------------- */
const icsEsc = s => String(s).replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\n/g, '\\n');
function buildICS() {
  const L = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Suivi Medocs//FR', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH'];
  const stamp = new Date().toISOString().replace(/[-:]/g, '').slice(0, 15) + 'Z';
  const today = new Date();
  for (const m of MEDS.filter(m => m.type === 'fixed')) {
    const first = dayIdx(today) < 0 ? fromKey(S.start) : today;
    const n = m.days - dayIdx(first);
    if (n <= 0) continue;
    for (const t of S.times[m.id]) {
      let f = first, cnt = n;
      if (+fromKey(dkey(f), t) < Date.now()) { f = addDays(f, 1); cnt--; }
      if (cnt <= 0) continue;
      const dt = dkey(f).replace(/-/g, '') + 'T' + t.replace(':', '') + '00';
      L.push('BEGIN:VEVENT', `UID:${m.id}-${t.replace(':', '')}-${dkey(f)}@suivi-medocs`, `DTSTAMP:${stamp}`,
        `DTSTART:${dt}`, 'DURATION:PT15M', `RRULE:FREQ=DAILY;COUNT=${cnt}`,
        `SUMMARY:${icsEsc('💊 ' + m.rx + ' — ' + m.meal)}`,
        `DESCRIPTION:${icsEsc(m.gen + '\n' + m.recos.join('\n'))}`,
        'BEGIN:VALARM', 'ACTION:DISPLAY', 'TRIGGER:PT0M', `DESCRIPTION:${icsEsc(m.rx)}`, 'END:VALARM', 'END:VEVENT');
    }
  }
  L.push('END:VCALENDAR');
  return L.join('\r\n');
}
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/* ---------------- views ---------------- */
let tab = 'today';
const mealTag = m => `<span class="tag meal">${esc(m.meal)}</span>`;
const cd = (ts, fmt = 'dur') => `<span data-cd="${ts}" data-fmt="${fmt}">${fmt === 'clock' ? clock(ts - Date.now()) : dur(ts - Date.now())}</span>`;

function ring(m, since, next) {
  const now = Date.now(), total = next - since, p = Math.min(1, Math.max(0, (now - since) / total));
  const R = 26, C = 2 * Math.PI * R;
  return `<svg class="ring" viewBox="0 0 64 64" data-ring="${since}|${next}" aria-hidden="true">
    <circle cx="32" cy="32" r="${R}" fill="none" stroke="var(--line)" stroke-width="6"/>
    <circle cx="32" cy="32" r="${R}" fill="none" stroke="${m.color}" stroke-width="6" stroke-linecap="round"
      stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - p)}" transform="rotate(-90 32 32)"/></svg>`;
}

function viewToday() {
  const now = Date.now(), d = new Date();
  const slots = slotsOn(d);
  const late = slots.filter(s => !taken(s.key) && s.ts <= now);
  const nx = nextPending(now);
  let h = '';

  if (dayIdx(d) < 0) {
    h += `<div class="card infobox">Traitement prévu à partir du ${longDate(fromKey(S.start))}. Modifiable dans Réglages.</div>`;
  }

  // Hero
  if (late.length) {
    h += `<div class="card hero late"><div class="lbl">À prendre maintenant</div>
      <div class="big">${late.map(s => esc(s.m.rx.split(' ')[0])).join(' + ')}</div>
      <div class="sub">Prévu à ${late.map(s => s.t).join(', ')} — en retard</div></div>`;
  } else if (nx) {
    h += `<div class="card hero"><div class="lbl">Prochaine prise ${relDay(nx.ts)}à ${nx.t}</div>
      <div class="big">${cd(nx.ts, 'clock')}</div>
      <div class="sub">${esc(nx.m.rx)} · ${esc(nx.m.meal)}</div></div>`;
  } else {
    h += `<div class="card hero done"><div class="lbl">Aujourd'hui</div><div class="big">Tout est pris ✓</div></div>`;
  }

  // Forgotten check-ins from previous days
  const missed = missedSlots();
  if (missed.length) {
    h += `<h2>Non cochées les jours d'avant</h2>`;
    if (missed.length > 1) h += `<div class="card"><div class="row"><div class="grow"><div class="name">${missed.length} prises non cochées</div>
      <div class="gen">Tu les as prises mais pas notées ?</div></div>
      <button class="btn" data-a="takeAllMissed">Tout noter pris</button></div></div>`;
    for (const s of missed) {
      h += `<div class="card slot"><div class="row">
        <div class="time">${s.t}</div><span class="dot" style="background:${s.m.color}"></span>
        <div class="grow"><div class="name">${esc(s.m.rx)}</div>
          <div class="gen">${longDate(new Date(s.ts))}</div></div></div>
        <div class="btns">
          <button class="btn ghost" data-a="takeAt" data-id="${s.m.id}" data-slot="${s.key}">Pris à ${s.t}</button>
          <button class="btn ghost" data-a="skip" data-id="${s.m.id}" data-slot="${s.key}">Pas pris</button>
        </div></div>`;
    }
  }

  // Timers (gap-based)
  const timers = MEDS.map(m => ({ m, st: medStatus(m, now) })).filter(x => x.st.next > now && !x.st.blocked);
  if (timers.length) {
    h += `<h2>Minuteurs</h2>`;
    for (const { m, st } of timers) {
      h += `<div class="card"><div class="row">
        <div class="ringwrap">${ring(m, st.since, st.next)}</div>
        <div class="grow"><div class="name">${esc(m.rx)}</div>
          <div class="gen">${esc(st.why)} · dernière prise ${relDay(st.last.t)}${hm(st.last.t)}</div>
          <div class="timer">${cd(st.next, 'clock')}</div>
          <div class="gen">Possible ${relDay(st.next)}à ${hm(st.next)}</div></div></div></div>`;
    }
  }

  // Schedule
  h += `<h2>Programme du jour</h2>`;
  if (!slots.length) h += `<div class="card empty">Aucune prise programmée aujourd'hui.</div>`;
  for (const s of slots) {
    const l = taken(s.key), isLate = !l && s.ts <= now;
    h += `<div class="card slot ${l ? 'is-done' : ''} ${isLate ? 'is-late' : ''}"><div class="row">
      <div class="time">${s.t}</div><span class="dot" style="background:${s.m.color}"></span>
      <div class="grow"><div class="name">${esc(s.m.rx)}</div>
        <div class="gen">= ${esc(s.m.gen)}</div>
        <div class="tags">${mealTag(s.m)}${s.m.gapH ? `<span class="tag">⏱ ${s.m.gapH} h</span>` : ''}</div>
        ${l ? `<div class="status ${l.skip ? 'wait' : 'ok'}">${l.skip ? 'Passée' : 'Pris à ' + hm(l.t)}</div>`
            : isLate ? `<div class="status no">En retard de ${dur(now - s.ts)} · <button class="lnk" data-a="skip" data-id="${s.m.id}" data-slot="${s.key}">Passer</button></div>`
            : `<div class="status wait">Dans ${cd(s.ts)}</div>`}
      </div>
      <button class="chk ${l ? 'on' : ''} ${l && l.skip ? 'skip' : ''}" data-a="${l ? 'untake' : 'take'}" data-id="${l ? l.id : s.m.id}" data-slot="${s.key}" aria-label="${l ? 'Annuler' : 'Marquer pris'}">${l ? (l.skip ? '–' : '✓') : ''}</button>
    </div></div>`;
  }

  // PRN
  h += `<h2>Si douleur</h2>`;
  h += `<div class="card"><div class="row"><div class="grow"><div class="name">Perfusion en cours</div>
    <div class="gen">Bloque ${MEDS.filter(m => m.perf).map(m => esc(m.rx)).join(', ')} tant qu'elle est active</div></div>
    <label class="switch"><input type="checkbox" data-set="perfusion" ${S.perfusion ? 'checked' : ''}><span></span></label></div></div>`;
  for (const m of MEDS.filter(m => m.type === 'prn')) {
    const st = medStatus(m, now);
    let status;
    if (st.ended) status = `<div class="status no">${dayIdx() < 0 ? 'Pas encore commencé' : 'Traitement terminé'}</div>`;
    else if (st.blocked) status = `<div class="status no">⛔ Pas pendant la perfusion</div>`;
    else if (st.ok) status = `<div class="status ok">✓ Possible maintenant</div>`;
    else status = `<div class="status wait">Possible à ${hm(st.next)} — dans ${cd(st.next)}<br><span class="small muted">${esc(st.why)}</span></div>`;
    const alertOn = S.alerts[m.id];
    h += `<div class="card"><div class="row"><span class="dot" style="background:${m.color}"></span>
      <div class="grow"><div class="name">${esc(m.rx)}</div><div class="gen">= ${esc(m.gen)}</div></div>
      <div class="count">${st.count}<span class="muted">/${m.max24}</span><div class="small muted">24 h</div></div></div>
      <div class="tags">${mealTag(m)}${m.gapH ? `<span class="tag">⏱ ${m.gapH} h min</span>` : ''}<span class="tag">max ${m.max24}/24 h</span></div>
      ${status}
      ${st.last ? `<div class="small muted" style="margin-top:4px">Dernière prise : ${relDay(st.last.t)}${hm(st.last.t)}</div>` : ''}
      <div class="btns">
        <button class="btn ${st.ok ? '' : 'ghost'}" data-a="take" data-id="${m.id}">J'ai pris 1 comprimé</button>
        ${!st.ok && !st.blocked && !st.ended && st.next > now
          ? `<button class="btn ghost" data-a="alert" data-id="${m.id}">${alertOn ? '🔔 Prévu ' + hm(alertOn) : '🔔 Me prévenir'}</button>` : ''}
      </div></div>`;
  }

  if (!isStandalone()) h += installCard();
  return h;
}

function viewMeds() {
  const di = dayIdx();
  let h = `<div class="card infobox small">Les boîtes reçues sont des génériques : même molécule que l'ordonnance, liées ici.
    Conseils issus de l'ordonnance, des annotations pharmacie et des notices. Doute → pharmacien.</div>`;
  for (const m of MEDS) {
    const done = Math.min(m.days, Math.max(0, di + 1));
    const left = stockLeft(m.id);
    const st = active(m) ? `Jour ${di + 1} / ${m.days}` : di < 0 ? 'Pas commencé' : 'Terminé ✓';
    h += `<div class="card"><div class="row"><span class="dot" style="background:${m.color}"></span>
      <div class="grow"><div class="name">${esc(m.rx)}</div><div class="gen">${esc(m.role)}</div></div>
      <span class="tag">${m.type === 'prn' ? 'si douleur' : 'programmé'}</span></div>
      <div class="link"><span class="muted">Ordonnance</span><b>${esc(m.rx)}</b><span class="arrow">⇄</span><span class="muted">Boîte</span><b>${esc(m.gen)}</b></div>
      <dl>
        <dt>Molécule</dt><dd>${esc(m.dci)}</dd>
        <dt>Forme</dt><dd>${esc(m.form)}</dd>
        <dt>Posologie</dt><dd>${esc(m.poso)}</dd>
        <dt>Repas</dt><dd><b>${esc(m.meal)}</b></dd>
        ${m.type === 'fixed' ? `<dt>Heures</dt><dd>${(S.times[m.id] || []).join(' · ')}</dd>` : ''}
        <dt>Jusqu'au</dt><dd>${longDate(endDate(m))}</dd>
        ${left != null ? `<dt>Stock</dt><dd>${left} restant${left > 1 ? 's' : ''}</dd>` : ''}
      </dl>
      <ul class="recos">${m.recos.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
      ${m.warn ? `<div class="warnbox">⚠︎ ${esc(m.warn)}</div>` : ''}
      <div class="bar"><i style="width:${(done / m.days) * 100}%"></i></div>
      <div class="small muted" style="margin-top:6px">${st}</div></div>`;
  }
  h += `<h2>Soins (non suivis)</h2><div class="card small muted">${SOINS.map(esc).join('<br>')}</div>`;
  return h;
}

function viewHistory() {
  const logs = S.log.filter(l => !l.skip).sort((a, b) => b.t - a.t);
  if (!logs.length) return `<div class="card empty">Aucune prise enregistrée.</div>`;
  let h = '', cur = '';
  for (const l of logs) {
    const k = dkey(new Date(l.t));
    if (k !== cur) { if (cur) h += '</div>'; cur = k; h += `<h2>${longDate(new Date(l.t))}</h2><div class="card">`; }
    const m = med(l.med);
    h += `<div class="hrow"><div class="time">${hm(l.t)}</div><span class="dot" style="background:${m.color}"></span>
      <div class="grow"><div class="name">${esc(m.rx)}</div><div class="gen">${l.slot ? 'Prévu ' + l.slot.split('|')[2] : 'Si douleur'}</div></div>
      <button class="x" data-a="edit" data-id="${l.id}" aria-label="Modifier l'heure">✎</button>
      <button class="x" data-a="untake" data-id="${l.id}" aria-label="Supprimer">✕</button></div>`;
  }
  return h + '</div>';
}

function viewSettings() {
  const perm = canNotify() ? Notification.permission : 'indisponible';
  let h = `<h2>Traitement</h2><div class="card">
    <div class="field"><span>Début du traitement</span><input type="date" data-set="start" value="${S.start}"></div>
    <div class="field"><span>Perfusion en cours</span><label class="switch"><input type="checkbox" data-set="perfusion" ${S.perfusion ? 'checked' : ''}><span></span></label></div>
  </div>
  <h2>Heures des prises</h2><div class="card">`;
  for (const m of MEDS.filter(m => m.type === 'fixed')) {
    h += `<div class="field"><span>${esc(m.rx)}<br><span class="small muted">${esc(m.meal)}</span></span><div class="times">
      ${(S.times[m.id] || []).map((t, i) => `<input type="time" data-set="time" data-id="${m.id}" data-i="${i}" value="${t}">`).join('')}</div></div>`;
  }
  h += `</div><h2>Stock de départ</h2><div class="card">`;
  for (const m of MEDS) {
    h += `<div class="field"><span>${esc(m.gen)}</span><input type="number" min="0" inputmode="numeric" data-set="stock" data-id="${m.id}" value="${S.stock[m.id] ?? ''}" placeholder="—"></div>`;
  }
  h += `</div>
  <h2>Notifications</h2>
  <div class="card">
    <div class="name">Notifications push</div>
    <div class="gen">Chaque prise à l'heure, relance 30 min après si pas cochée, et « possible maintenant » pour les minuteurs. Même appli fermée.</div>
    ${!PUSH() ? `<div class="warnbox small">Serveur de notifications non configuré.</div>`
      : !isStandalone() ? `<div class="warnbox small">Installe d'abord Médocs sur l'écran d'accueil, puis ouvre-la depuis l'icône.</div>`
      : `${S.push.on
          ? (S.push.err ? `<div class="status no">Erreur : ${esc(S.push.err)}</div>` : `<div class="status ok">✓ Activées${S.push.at ? ' · synchro ' + relDay(S.push.at) + hm(S.push.at) : ''}</div>`)
          : `<div class="status wait">Désactivées</div>`}
        <div class="btns">
          <button class="btn ${S.push.on ? 'ghost' : ''}" data-a="pushOn">${S.push.on ? 'Réactiver' : 'Activer'}</button>
          ${S.push.on ? `<button class="btn ghost" data-a="pushTest">Tester</button><button class="btn danger" data-a="pushOff">Couper</button>` : ''}
        </div>`}
  </div>
  <div class="card">
    <div class="name">Calendrier iPhone (secours, hors ligne)</div>
    <div class="gen">Ajoute toutes les prises programmées avec alarme dans Calendrier. À refaire si tu changes les heures.</div>
    <div class="btns"><button class="btn ghost" data-a="ics">Ajouter au Calendrier</button></div>
  </div>
  <h2>Données</h2><div class="card"><div class="btns">
    <button class="btn ghost" data-a="export">Exporter</button>
    <button class="btn ghost" data-a="import">Importer</button>
    <button class="btn ghost" data-a="lock">Verrouiller</button>
    <button class="btn danger" data-a="reset">Tout effacer</button></div>
    <div class="small muted" style="margin-top:8px">Données stockées uniquement sur ce téléphone.</div></div>`;
  if (!isStandalone()) h += installCard();
  return h;
}

const isStandalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const installCard = () => `<h2>Installer sur l'iPhone</h2><div class="card small">
  <ol><li>Ouvre cette page dans <b>Safari</b></li><li>Bouton <b>Partager</b> ⬆︎</li>
  <li><b>Sur l'écran d'accueil</b> → Ajouter</li><li>Ouvre « Médocs » depuis l'icône</li></ol></div>`;

const TITLES = { today: 'Aujourd\'hui', meds: 'Traitement', history: 'Historique', settings: 'Réglages' };
function render() {
  const d = new Date(), di = dayIdx(d);
  $('#title').textContent = TITLES[tab];
  $('#subtitle').textContent = longDate(d) + (di >= 0 ? ` · jour ${di + 1} du traitement` : '');
  const y = scrollY;
  $('#view').innerHTML = { today: viewToday, meds: viewMeds, history: viewHistory, settings: viewSettings }[tab]();
  scrollTo(0, y);
  document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === tab));
  syncPush();
}

// live countdowns, every second, no full re-render
let lastMin = -1;
function tickSecond() {
  const now = Date.now();
  let cross = false;
  document.querySelectorAll('[data-cd]').forEach(el => {
    const ts = +el.dataset.cd;
    if (ts <= now) cross = true;
    el.textContent = el.dataset.fmt === 'clock' ? clock(ts - now) : dur(ts - now);
  });
  document.querySelectorAll('[data-ring]').forEach(svg => {
    const [a, b] = svg.dataset.ring.split('|').map(Number);
    const c = svg.querySelectorAll('circle')[1];
    const C = 2 * Math.PI * 26;
    c.setAttribute('stroke-dashoffset', C * (1 - Math.min(1, Math.max(0, (now - a) / (b - a)))));
  });
  const min = Math.floor(now / 6e4);
  if (min !== lastMin) { lastMin = min; checkLocalAlerts(); if (tab === 'today') render(); }
  else if (cross && tab === 'today') render();
}

/* ---------------- events ---------------- */
let toastT;
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 2600);
}

document.addEventListener('click', async e => {
  if (!S) return;
  const tb = e.target.closest('[data-tab]');
  if (tb) { tab = tb.dataset.tab; scrollTo(0, 0); render(); return; }
  const b = e.target.closest('[data-a]');
  if (!b) return;
  const id = b.dataset.id;
  switch (b.dataset.a) {
    case 'take': take(id, b.dataset.slot); break;
    case 'untake': untake(id); break;
    case 'skip': skip(id, b.dataset.slot); break;
    case 'takeAt': takeAt(id, b.dataset.slot); break;
    case 'takeAllMissed': {
      const ms = missedSlots();
      if (!confirm(`Noter ces ${ms.length} prises comme prises à l'heure prévue ?\n\n` + ms.map(x => `${shortDate(new Date(x.ts))} ${x.t} — ${x.m.rx}`).join('\n'))) break;
      for (const x of ms) S.log.push({ id: uid(), med: x.m.id, t: x.ts, slot: x.key });
      save(); toast(`✓ ${ms.length} prises notées`); render();
      break;
    }
    case 'edit': editTime(id); break;
    case 'alert': {
      const st = medStatus(med(id));
      if (S.alerts[id]) { delete S.alerts[id]; toast('Rappel annulé'); }
      else {
        S.alerts[id] = st.next;
        toast(`🔔 Rappel à ${hm(st.next)}`);
        if (canNotify() && Notification.permission === 'default') await Notification.requestPermission();
      }
      save(); render(); syncPush(); break;
    }
    case 'perm':
      if (canNotify()) { const p = await Notification.requestPermission(); toast('Notifications : ' + p); render(); }
      break;
    case 'testlocal': notify('💊 Test', 'Les notifications marchent.', 'test'); toast('Notification envoyée'); break;
    case 'ics': download('suivi-medocs.ics', buildICS(), 'text/calendar'); break;
    case 'pushOn': enablePush(); break;
    case 'pushOff': disablePush(); break;
    case 'pushTest':
      try { const r = await api('/test', {}); toast(r.ok ? 'Envoyé — regarde tes notifications' : 'Échec : ' + (r.error || r.status)); }
      catch (e) { toast('Erreur : ' + e.message); }
      break;
    case 'export': download(`medocs-${dkey(new Date())}.json`, JSON.stringify(S, null, 2), 'application/json'); break;
    case 'import': $('#importFile').click(); break;
    case 'lock': lock(); break;
    case 'reset':
      if (confirm('Effacer tout l\'historique et les réglages ? Irréversible.')) {
        localStorage.removeItem(KEY); loadState(); render();
      }
      break;
  }
});

document.addEventListener('change', e => {
  if (!S) return;
  const el = e.target, k = el.dataset.set;
  if (!k) return;
  if (k === 'perfusion') S.perfusion = el.checked;
  else if (k === 'start' && el.value) { S.start = el.value; }
  else if (k === 'time' && el.value) { S.times[el.dataset.id][+el.dataset.i] = el.value; S.times[el.dataset.id].sort(); }
  else if (k === 'stock') S.stock[el.dataset.id] = el.value === '' ? null : +el.value;
  save(); render(); syncPush();
});

$('#importFile').addEventListener('change', async e => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const data = JSON.parse(await f.text());
    if (!Array.isArray(data.log)) throw 0;
    S = Object.assign(DEFAULT(), data); save(); render(); toast('Importé');
  } catch { toast('Fichier invalide'); }
  e.target.value = '';
});

document.addEventListener('visibilitychange', () => { if (!document.hidden && S) { render(); checkLocalAlerts(); syncPush(); checkRev(); } });

/* ---------------- boot ---------------- */
let timer = null;
function start() {
  document.body.classList.remove('locked');
  loadState();
  cleanup();
  render();
  checkLocalAlerts();
  syncPush();
  if (!timer) timer = setInterval(() => { if (S) tickSecond(); }, 1000);
}

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
let cached = null;
try { cached = JSON.parse(localStorage.getItem(DATA_KEY) || 'null'); } catch { /* ignore */ }
if (cached && cached.data) { setData(cached.data, cached.rev); start(); checkRev(); }
else lockScreen();
