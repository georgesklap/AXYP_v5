/* ΑΞΥΠ — εφαρμογή μόνο προβολής.
 * Διαβάζει ΕΝΑ κρυπτογραφημένο αρχείο (data/axyp.json) που δημοσιεύει το Excel.
 * Δεν κάνει κανέναν υπολογισμό ρεπό, νυχτερινών ή πενθημέρων: εμφανίζει τις τιμές του Excel.
 * Κρυπτογράφηση: PBKDF2-SHA256 -> AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC). */
'use strict';
const DATA_URL = 'data/axyp.json';
const SCHEMA = 1;
const MONTHS = ['Ιανουάριος','Φεβρουάριος','Μάρτιος','Απρίλιος','Μάιος','Ιούνιος','Ιούλιος','Αύγουστος','Σεπτέμβριος','Οκτώβριος','Νοέμβριος','Δεκέμβριος'];
const MONTHS_GEN = ['Ιανουαρίου','Φεβρουαρίου','Μαρτίου','Απριλίου','Μαΐου','Ιουνίου','Ιουλίου','Αυγούστου','Σεπτεμβρίου','Οκτωβρίου','Νοεμβρίου','Δεκεμβρίου'];
const MON_SHORT = ['Ιαν','Φεβ','Μαρ','Απρ','Μάι','Ιουν','Ιουλ','Αυγ','Σεπ','Οκτ','Νοε','Δεκ'];
const WD = ['Δευ','Τρί','Τετ','Πέμ','Παρ','Σάβ','Κυρ'];
const WD_LONG = ['Δευτέρα','Τρίτη','Τετάρτη','Πέμπτη','Παρασκευή','Σάββατο','Κυριακή'];
const CODE_DESC = { 'Κ':'Κανονική άδεια', 'Β':'Βραχεία άδεια', 'ΑΝ':'Αναρρωτική άδεια', 'ΑΙΜ':'Αιμοδοτική άδεια', 'ΕΙΔ':'Ειδική άδεια', 'ΓΟΝ':'Γονική άδεια',
  'Π':'Πρωί', 'Α':'Απόγευμα', 'Ν':'Νύχτα', 'Ρ':'Ρεπό', 'ΧΡ':'Χρωστούμενο ρεπό', 'Α/Α':'Αδιάθετο', 'Α/Δ':'Αδιάθετο' };
const LEAVE_CODES = ['Κ','Β','ΑΝ','ΑΙΜ','ΕΙΔ','ΓΟΝ'];

const S = { env:null, data:null, keys:null, offline:false, tab:'leave', month:0, selDay:null, weekStart:0, nyx:'nights' };
const $ = sel => document.querySelector(sel);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const norm = c => String(c || '').trim().toLocaleUpperCase('el-GR');

/* ---------------- κρυπτογραφία ---------------- */
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
function concat(...arrs) { const n = arrs.reduce((a, x) => a + x.length, 0), out = new Uint8Array(n); let o = 0; for (const x of arrs) { out.set(x, o); o += x.length; } return out; }
async function deriveKeys(password, saltB64, iterations) {
  const pw = new TextEncoder().encode(password.normalize('NFC'));
  const base = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name:'PBKDF2', salt:b64(saltB64), iterations, hash:'SHA-256' }, base, 512));
  const enc = await crypto.subtle.importKey('raw', bits.slice(0, 32), { name:'AES-CBC' }, false, ['decrypt']);
  const mac = await crypto.subtle.importKey('raw', bits.slice(32, 64), { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
  bits.fill(0);
  return { enc, mac, salt:saltB64, iterations };
}
async function decryptEnvelope(env, keys) {
  if (!env || env.format !== 'axyp-enc-1' || env.cipher !== 'AES-256-CBC' || env.mac !== 'HMAC-SHA256') throw new Error('format');
  const iv = b64(env.iv), ct = b64(env.ct), tag = b64(env.tag);
  const macInput = concat(new TextEncoder().encode('axyp-enc-1:' + env.kdf.iterations + ':'), b64(env.kdf.salt), iv, ct);
  const ok = await crypto.subtle.verify('HMAC', keys.mac, tag, macInput);
  if (!ok) throw new Error('badkey');
  const plain = await crypto.subtle.decrypt({ name:'AES-CBC', iv }, keys.enc, ct);
  return JSON.parse(new TextDecoder().decode(plain));
}

/* ---------------- αποθήκευση κλειδιού στη συσκευή (μη εξαγώγιμο κλειδί, όχι ο κωδικός) ---------------- */
function idb() { return new Promise((res, rej) => { const r = indexedDB.open('axyp', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
async function idbOp(mode, fn) { const db = await idb(); return new Promise((res, rej) => { const tx = db.transaction('k', mode); const st = tx.objectStore('k'); const r = fn(st); tx.oncomplete = () => res(r && r.result); tx.onerror = () => rej(tx.error); }); }
const saveKeys = k => idbOp('readwrite', st => st.put(k, 'keys'));
const loadKeys = () => idbOp('readonly', st => st.get('keys')).catch(() => null);
const forgetKeys = () => idbOp('readwrite', st => st.delete('keys')).catch(() => null);

/* ---------------- φόρτωση δεδομένων ---------------- */
async function fetchEnvelope() {
  S.offline = false;
  try {
    const r = await fetch(DATA_URL + '?t=' + Date.now(), { cache:'no-store' });
    if (r.status === 404) return { missing:true };
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const txt = await r.text();
    try { const c = await caches.open('axyp-data'); await c.put(DATA_URL, new Response(txt, { headers:{ 'Content-Type':'application/json' } })); } catch (e) {}
    return { env:JSON.parse(txt) };
  } catch (e) {
    try { const c = await caches.open('axyp-data'); const m = await c.match(DATA_URL); if (m) { S.offline = true; return { env:JSON.parse(await m.text()) }; } } catch (e2) {}
    return { error:e };
  }
}
function validData(d) {
  if (!d || d.schema !== SCHEMA || !Array.isArray(d.colleagues) || !d.colleagues.length) return false;
  const n = d.colleagues.length;
  return ['leave','shifts','nights','pent','owed'].every(k => Array.isArray(d[k]) && d[k].length === n) &&
    d.leave.every(a => a.length === d.dayCount) && d.shifts.every(a => a.length === d.dayCount) && d.owed.every(a => a.length === 12);
}
async function start() {
  $('#main').innerHTML = '<div class="msg">Φόρτωση…</div>';
  const f = await fetchEnvelope();
  if (f.missing) { show('<div class="msg">Δεν υπάρχουν ακόμη δημοσιευμένα δεδομένα.<br>Θα εμφανιστούν μετά την πρώτη ΔΗΜΟΣΙΕΥΣΗ από το Excel.</div>'); return; }
  if (f.error) { show('<div class="msg err">Δεν ήταν δυνατή η φόρτωση των δεδομένων.<br>Ελέγξτε τη σύνδεση και πατήστε ⟳.</div>'); return; }
  S.env = f.env;
  if (!S.keys) {
    const k = await loadKeys();
    if (k && k.salt === S.env.kdf.salt && k.iterations === S.env.kdf.iterations) S.keys = k;
  }
  if (!S.keys) { lockScreen(); return; }
  try { await openData(); }
  catch (e) { S.keys = null; await forgetKeys(); lockScreen(e.message === 'badkey' ? 'Ο κωδικός άλλαξε. Πληκτρολογήστε τον νέο κωδικό.' : ''); }
}
async function openData() {
  const d = await decryptEnvelope(S.env, S.keys);
  if (!validData(d)) throw new Error('data');
  const first = S.data == null;
  S.data = d;
  const dt = d.publishedAt.replace('T', ' ').split(/[- :]/);
  $('#pub').innerHTML = 'Τελευταία δημοσίευση:<br><b>' + dt[2] + '/' + dt[1] + '/' + dt[0] + ' ' + dt[3] + ':' + dt[4] + '</b>';
  $('#tabs').hidden = false;
  if (first) initPositions();
  render();
}
function lockScreen(note) {
  $('#tabs').hidden = true; $('#pub').textContent = '';
  show(`<div class="lock"><img src="icons/icon-192.png" alt="ΑΞΥΠ"><h2>Κωδικός πρόσβασης</h2>
    <p class="note">Πληκτρολογήστε τον κοινό κωδικό των συναδέλφων ΑΞΥΠ.</p>
    ${note ? '<p class="msg err" style="padding:6px">' + esc(note) + '</p>' : ''}
    <form id="lf"><input type="password" id="pw" autocomplete="current-password" required>
    <label><input type="checkbox" id="rem" checked> Να θυμάται αυτή η συσκευή</label>
    <button class="primary" id="go">Είσοδος</button></form><p class="msg err" id="lerr" style="padding:8px"></p></div>`);
  $('#lf').onsubmit = async ev => {
    ev.preventDefault();
    const btn = $('#go'); btn.disabled = true; btn.textContent = 'Έλεγχος…'; $('#lerr').textContent = '';
    const remember = $('#rem').checked;            // διαβάζεται πριν αλλάξει η οθόνη
    try {
      const keys = await deriveKeys($('#pw').value, S.env.kdf.salt, S.env.kdf.iterations);
      S.keys = keys; await openData();
      if (remember) { try { await saveKeys(keys); } catch (e) {} }
    } catch (e) {
      S.keys = null; btn.disabled = false; btn.textContent = 'Είσοδος';
      $('#lerr').textContent = e.message === 'badkey' ? 'Λάθος κωδικός.' : 'Τα δεδομένα δεν μπορούν να διαβαστούν.';
    }
  };
}
function show(html) { $('#main').innerHTML = html; }

/* ---------------- ημερομηνίες (UTC, χωρίς θέματα θερινής ώρας) ---------------- */
const DAY = 86400000;
const d0 = () => Date.UTC(S.data.year, 0, 1);
const dateOf = i => new Date(d0() + i * DAY);
const idxOf = dt => Math.round((dt - d0()) / DAY);
const wdOf = i => (dateOf(i).getUTCDay() + 6) % 7;            // 0 = Δευτέρα
function todayIdx() { const t = new Date(); return idxOf(Date.UTC(t.getFullYear(), t.getMonth(), t.getDate())); }
function initPositions() {
  const t = todayIdx(), n = S.data.dayCount;
  const i = (t >= 0 && t < n) ? t : 0;
  S.month = dateOf(i).getUTCMonth(); S.selDay = i; S.weekStart = i - wdOf(i);
}
function textOn(hex) {
  const h = (hex || '#ffffff').replace('#', ''); const r = parseInt(h.substr(0, 2), 16), g = parseInt(h.substr(2, 2), 16), b = parseInt(h.substr(4, 2), 16);
  return (0.299 * r + 0.587 * g + 0.114 * b) > 150 ? '#111' : '#fff';
}
const dot = c => `<span class="dot" style="background:${esc(c)}"></span>`;
/* ονόματα: αλλαγή γραμμής μόνο στα κενά, ποτέ μέσα σε λέξη (π.χ. «Υ/Β.ΤΡΑΝΑΚΟΣ») */
const nm = n => String(n).split(' ').map(t => `<span class="nw">${esc(t)}</span>`).join(' ');
const longDate = i => { const d = dateOf(i); return WD_LONG[wdOf(i)] + ' ' + d.getUTCDate() + ' ' + MONTHS_GEN[d.getUTCMonth()] + ' ' + S.data.year; };
function monthSelect(id) { return `<select class="big" id="${id}">` + MONTHS.map((m, i) => `<option value="${i}"${i === S.month ? ' selected' : ''}>${m} ${S.data.year}</option>`).join('') + '</select>'; }

/* ---------------- καρτέλες ---------------- */
function render() {
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === S.tab));
  const off = S.offline ? '<div class="offline">Χωρίς σύνδεση — εμφανίζεται η τελευταία αποθηκευμένη δημοσίευση.</div>' : '';
  show(off + ({ leave:viewLeave, shifts:viewShifts, nights:viewNights, owed:viewOwed })[S.tab]());
  bind();
}
function viewLeave() {
  const d = S.data, y = d.year, m = S.month;
  const first = idxOf(Date.UTC(y, m, 1)), days = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  let cells = WD.map(w => `<div class="h">${w.substr(0, 1)}</div>`).join('');
  for (let k = 0; k < wdOf(first); k++) cells += '<div class="day empty"></div>';
  for (let dd = 0; dd < days; dd++) {
    const i = first + dd, who = [];
    d.colleagues.forEach((c, p) => { const code = (d.leave[p][i] || '').trim(); if (code) who.push({ c, code }); });
    const segs = who.map(w => `<div class="seg" style="background:${esc(w.c.color)};color:${textOn(w.c.color)}">${esc(w.code)}</div>`).join('');
    cells += `<button class="day${who.length ? ' has' : ''}${wdOf(i) >= 5 ? ' we' : ''}${i === S.selDay ? ' sel' : ''}" data-day="${i}" aria-label="${dd + 1}"><span class="num">${dd + 1}</span>${segs}</button>`;
  }
  let det = '';
  if (S.selDay != null && dateOf(S.selDay).getUTCMonth() === m) {
    const i = S.selDay, list = [];
    d.colleagues.forEach((c, p) => { const code = (d.leave[p][i] || '').trim(); if (code) list.push(`<li>${dot(c.color)}<span>${nm(c.name)}</span><span class="badge" title="${esc(CODE_DESC[norm(code)] || code)}">${esc(code)}</span></li><li style="border:0;padding-top:0;margin-top:-8px;font-size:14px;color:var(--mute);padding-left:34px">${esc(CODE_DESC[norm(code)] || 'Κωδικός: ' + code)}</li>`); });
    det = `<div class="card"><b>${longDate(i)}</b>${list.length ? '<ul class="list">' + list.join('') + '</ul>' : '<div class="note">Καμία άδεια.</div>'}</div>`;
  }
  const legend = '<div class="legend">' + d.colleagues.map(c => `<span class="chip">${dot(c.color)}<span>${nm(c.name)}</span></span>`).join('') + '</div>';
  return `<div class="nav"><button class="arrow" id="mPrev" ${m === 0 ? 'disabled' : ''} aria-label="Προηγούμενος μήνας">‹</button><div class="title">${MONTHS[m]} ${y}</div><button class="arrow" id="mNext" ${m === 11 ? 'disabled' : ''} aria-label="Επόμενος μήνας">›</button></div>
    ${monthSelect('mSel')}<div class="wk" style="margin-top:10px">${cells}</div>${det}<div class="card"><b>Υπόμνημα</b>${legend}</div>`;
}
function groupOf(code) {
  const c = norm(code);
  if (!c) return 'none';
  if (c === 'Π') return 'P'; if (c === 'Α') return 'A'; if (c === 'Ν') return 'N';
  if (c === 'Ρ' || c === 'ΧΡ') return 'R';
  if (LEAVE_CODES.includes(c)) return 'L';
  if (c === 'Α/Α' || c === 'Α/Δ') return 'AD';
  return 'X';
}
function viewShifts() {
  const d = S.data, n = d.dayCount;
  const ws = S.weekStart, we = ws + 6;
  const a = dateOf(Math.max(ws, -400)), b = dateOf(we);
  const title = `${a.getUTCDate()} ${MON_SHORT[a.getUTCMonth()]} – ${b.getUTCDate()} ${MON_SHORT[b.getUTCMonth()]} ${S.data.year}`;
  let days = '';
  for (let k = 0; k < 7; k++) { const i = ws + k, ok = i >= 0 && i < n; days += `<button data-sday="${i}" class="${i === S.selDay ? 'sel' : ''}" ${ok ? '' : 'disabled'}>${WD[k]}<b>${dateOf(i).getUTCDate()}</b></button>`; }
  const i = S.selDay, G = { P:[], A:[], N:[], R:[], L:[], AD:[], X:[], none:[] };
  d.colleagues.forEach((c, p) => { const code = (d.shifts[p][i] || '').trim(); G[groupOf(code)].push({ c, code }); });
  const item = (x, badge) => `<li><span>${nm(x.c.name)}</span>${badge ? `<span class="badge">${esc(x.code)}</span>` : ''}</li>`;
  const grp = (title, arr, badgeFn, always) => (!arr.length && !always) ? '' :
    `<div class="card grp"><h3>${title}</h3>${arr.length ? '<ul class="list">' + arr.map(x => item(x, badgeFn(x))).join('') + '</ul>' : '<div class="none">—</div>'}</div>`;
  return `<div class="nav"><button class="arrow" id="wPrev" ${ws <= 0 ? 'disabled' : ''} aria-label="Προηγούμενη εβδομάδα">‹</button><div class="title" style="font-size:17px">${title}</div><button class="arrow" id="wNext" ${we >= n - 1 ? 'disabled' : ''} aria-label="Επόμενη εβδομάδα">›</button></div>
    <div class="days7">${days}</div><div class="note" style="margin:0 0 4px"><b>${longDate(i)}</b></div>
    ${grp('Πρωί', G.P, () => false, true)}${grp('Απόγευμα', G.A, () => false, true)}${grp('Νύχτα', G.N, () => false, true)}
    ${grp('Αδιάθετο (Α/Α)', G.AD, () => false, true)}${grp('Ρεπό', G.R, x => norm(x.code) === 'ΧΡ', true)}${grp('Άδεια', G.L, () => true, true)}
    ${grp('Άλλος κωδικός', G.X, () => true, false)}${grp('Χωρίς καταχώριση', G.none, () => false, false)}`;
}
function viewNights() {
  const d = S.data, m = S.month, src = S.nyx === 'nights' ? d.nights : d.pent;
  const rows = d.colleagues.map((c, p) => {
    const v = src[p].months[m], col = src[p].colors[m];
    const st = col ? `background:${esc(col)};color:${textOn(col)}` : '';
    return `<li><span>${nm(c.name)}</span><span class="num-badge" style="${st}">${esc(v)}</span></li>`;
  }).join('');
  return `${monthSelect('mSel')}<div class="seg2"><button id="nN" class="${S.nyx === 'nights' ? 'on' : ''}">Νυχτερινά</button><button id="nP" class="${S.nyx === 'pent' ? 'on' : ''}">Πενθήμερα</button></div>
    <div class="card"><b>${S.nyx === 'nights' ? 'Νυχτερινά' : 'Πενθήμερα'} — ${MONTHS[m]} ${d.year}</b><ul class="list">${rows}</ul></div>
    <div class="note">Οι αριθμοί και τα χρώματα είναι ακριβώς αυτά της καρτέλας ΝΥΧΤΕΡΙΝΑ του Excel.</div>`;
}
function viewOwed() {
  const d = S.data, m = S.month;
  const fmt = v => v > 0 ? '+' + v : String(v);
  const rows = d.colleagues.map((c, p) => {
    const o = d.owed[p][m];
    if (!o.filled) return `<tr><td><span class="who"><span>${nm(c.name)}</span></span></td><td class="n">—</td><td class="n">—</td></tr>`;
    const cls = o.total > 0 ? 'pos' : (o.total < 0 ? 'neg' : '');
    return `<tr><td><span class="who"><span>${nm(c.name)}</span></span></td><td class="n"><span>${esc(o.new)}</span></td><td class="n"><span class="${cls}">${esc(fmt(o.total))}${o.flag ? ' *' : ''}</span></td></tr>`;
  }).join('');
  return `${monthSelect('mSel')}<div class="card" style="padding:6px 8px"><table class="owed"><thead><tr><th>Συνάδελφος</th><th class="n">Μήνας</th><th class="n">Σύνολο</th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="note"><b>Μήνας</b>: νέα οφειλόμενα ρεπό που δημιουργήθηκαν μέσα στον μήνα.<br><b>Σύνολο</b>: όσα οφείλονται στο τέλος του μήνα, αφού αφαιρεθούν τα ΧΡ (+ οφείλει η Υπηρεσία, − δόθηκαν ΧΡ προκαταβολικά).<br>* περίπτωση προς έλεγχο στο Excel · — ο μήνας δεν έχει καταχωρίσεις.</div>`;
}
function bind() {
  const on = (id, f) => { const e = document.getElementById(id); if (e) e.onclick = f; };
  on('mPrev', () => { S.month = Math.max(0, S.month - 1); render(); });
  on('mNext', () => { S.month = Math.min(11, S.month + 1); render(); });
  const ms = document.getElementById('mSel'); if (ms) ms.onchange = () => { S.month = +ms.value; render(); };
  document.querySelectorAll('[data-day]').forEach(b => b.onclick = () => { S.selDay = +b.dataset.day; render(); });
  document.querySelectorAll('[data-sday]').forEach(b => b.onclick = () => { S.selDay = +b.dataset.sday; render(); });
  on('wPrev', () => { S.weekStart -= 7; S.selDay = Math.max(0, S.weekStart); render(); });
  on('wNext', () => { S.weekStart += 7; S.selDay = Math.min(S.data.dayCount - 1, Math.max(0, S.weekStart)); render(); });
  on('nN', () => { S.nyx = 'nights'; render(); });
  on('nP', () => { S.nyx = 'pent'; render(); });
}
function wire() {
  document.querySelectorAll('#tabs button').forEach(b => b.onclick = () => {
    S.tab = b.dataset.tab;
    if (S.tab === 'shifts' && S.selDay != null) S.weekStart = S.selDay - wdOf(S.selDay);
    render(); window.scrollTo(0, 0);
  });
  $('#btnRefresh').onclick = () => start();
  $('#btnLock').onclick = async () => {
    if (!confirm('Να ξεχάσει αυτή η συσκευή τον κωδικό; Θα χρειαστεί να τον πληκτρολογήσετε ξανά.')) return;
    await forgetKeys(); S.keys = null; S.data = null; start();
  };
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && S.data) start(); });
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  start();
}
if (typeof document !== 'undefined') wire();
if (typeof module !== 'undefined') module.exports = { deriveKeys, decryptEnvelope, validData };   /* για δοκιμές σε Node */
