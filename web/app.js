"use strict";

const THEMES = [
  { id: "signal", name: "signal" },
  { id: "bios", name: "bios" },
  { id: "druck", name: "druck" },
  { id: "bernstein", name: "bernstein" },
];
const STEPS = [["network", "netz"], ["peer", "freund"], ["sources", "ordner"], ["recovery", "notfall-kit"]];
const VIEWS = [["status", "status"], ["versions", "versionen"], ["settings", "einstellungen"], ["care", "wartung"]];
const OP_LABELS = {
  backup: "sichert gerade", snapshots: "liest versionen", files: "liest dateien", check: "prüft backup",
  maintenance: "räumt auf", "restore-test": "testet wiederherstellung", restore: "stellt wieder her",
  unlock: "entsperrt", retire: "entfernt alte versionen",
};

const S = { csrf: "", status: null, view: "status", key: "", refresh: null, timer: null };
const root = document.getElementById("app");
const connection = h0("div", "msg err");
connection.hidden = true;
root.before(connection);

function h0(tag, className) { const el = document.createElement(tag); el.className = className; return el; }

// ---- helpers ----------------------------------------------------------------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k in el && k !== "list") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c);
  return el;
}

class ApiError extends Error {
  constructor(message, status, code) { super(message); this.status = status; this.code = code; }
}

async function api(method, path, body) {
  const options = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") {
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = S.csrf;
    options.body = JSON.stringify(body === undefined ? {} : body);
  }
  let response;
  try {
    response = await fetch("/api/v1" + path, options);
  } catch {
    throw new ApiError("Keine Verbindung zum NAS.", 0, "offline");
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError((data && data.error && data.error.message) || "Unerwarteter Fehler.", response.status, data && data.error && data.error.code);
  }
  return data;
}

const isZero = (t) => !t || String(t).startsWith("0001-");
function when(t) {
  if (isZero(t)) return "-";
  const d = new Date(t);
  const now = new Date();
  const hm = d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(d) - day(now)) / 86400000);
  if (diff === 0) return "heute " + hm;
  if (diff === 1) return "morgen " + hm;
  if (diff === -1) return "gestern " + hm;
  return d.toLocaleDateString("de-DE") + " " + hm;
}
function bytes(n) {
  if (n === undefined || n === null) return "-";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i && n < 100 ? n.toFixed(1) : Math.round(n)).toString().replace(".", ",") + " " + units[i];
}
const bar = (fraction, width) => {
  const f = Math.max(0, Math.min(1, fraction || 0));
  const n = Math.round(f * width);
  return "[" + "#".repeat(n) + ".".repeat(width - n) + "] " + Math.round(f * 100) + "%";
};
const box = (title, ...children) => h("div", { class: "box" }, h("span", { class: "legend" }, "[ " + title + " ]"), ...children);
const row = (a, b) => h("div", { class: "row" }, h("span", { class: "dim" }, a), h("span", {}, b));
const field = (label, input) => h("label", { class: "field" }, h("span", {}, label), input);
const btn = (text, onclick, primary, extra) => h("button", { class: "btn" + (primary ? " primary" : ""), type: "button", onclick, ...(extra || {}) }, "> " + text);
const check = (text, attrs) => h("label", { class: "check" }, h("input", { type: "checkbox", ...attrs }), h("span", { class: "mark" }), h("span", {}, text));

function messenger() {
  const el = h("div", { class: "msg", role: "status" });
  el.ok = (t) => { el.className = "msg dim"; el.textContent = t; };
  el.err = (e) => { el.className = "msg err"; el.textContent = "[!!] " + (e.message || e); };
  el.clear = () => { el.textContent = ""; };
  return el;
}

// Runs an async action with the button disabled; errors land in the messenger.
function action(button, msg, fn) {
  return async () => {
    msg.clear();
    if (button.current) button.current.disabled = true;
    try { await fn(); } catch (e) {
      if (e.status === 401) return showLogin();
      if (e.status === 403 && e.code === "csrf") await loadCsrf();
      msg.err(e);
    } finally { if (button.current) button.current.disabled = false; }
  };
}
function actionButton(text, msg, fn, primary) {
  const ref = {};
  ref.current = btn(text, action(ref, msg, fn), primary);
  return ref.current;
}

function save(filename, data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = h("a", { href: url, download: filename });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// navigator.clipboard needs HTTPS; the UI usually runs on plain LAN HTTP.
async function copy(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  const area = h("textarea", { value: text });
  document.body.append(area); area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) throw new Error("Kopieren nicht möglich, bitte von Hand markieren.");
}

const groups = (fp) => (fp || "").replace(/(.{8})/g, "$1 ").trim();
const readFile = (file) => file.text();

function parseJson(text, what) {
  try { return JSON.parse(text); } catch { throw new Error(what + " ist kein gültiges JSON."); }
}

async function loadCsrf() {
  const auth = await api("GET", "/auth");
  S.csrf = auth.csrf_token;
  return auth;
}

// ---- operations ---------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function runOperation(body) {
  const started = await api("POST", "/operations", body);
  for (;;) {
    await sleep(1200);
    const op = await api("GET", "/operations/current");
    if (!op || op.id !== started.id) throw new Error("Vorgang wurde abgelöst.");
    if (op.state !== "running") {
      if (op.state === "error") throw new Error(op.error || "Vorgang fehlgeschlagen.");
      return op.result;
    }
  }
}

function progressNode(op) {
  const p = op.progress || {};
  const label = OP_LABELS[op.kind] || op.kind;
  const lines = [row(label, when(op.started))];
  if (typeof p.percent_done === "number") lines.push(h("div", { class: "bar" }, bar(p.percent_done, 28)));
  if (p.total_bytes) lines.push(row("daten", bytes(p.bytes_done || 0) + " / " + bytes(p.total_bytes)));
  if (p.seconds_remaining) lines.push(row("rest", Math.ceil(p.seconds_remaining / 60) + " min"));
  const msg = messenger();
  return box("läuft", ...lines, h("div", { class: "actions" }, actionButton("abbrechen", msg, () => api("POST", "/operations/cancel"))), msg);
}

// ---- auth screens --------------------------------------------------------------

function mount(key, build) {
  if (S.key === key) { if (S.refresh) S.refresh(S.status); return; }
  S.key = key;
  S.refresh = null;
  root.replaceChildren(build());
  if (S.refresh) S.refresh(S.status);
}

const header = (right) => h("div", { class: "top" }, h("span", {}, "buddybackup"), h("span", { class: "dim" }, right || ""));
const hero = (prompt, text, sub) => h("div", { class: "hero" },
  h("div", { class: "dim" }, "$ " + prompt),
  h("div", { class: "big" }, text, h("span", { class: "cursor" })),
  sub ? h("div", { class: "dim" }, sub) : null);

function showSetup() {
  clearInterval(S.timer);
  S.key = "setup"; S.refresh = null;
  const name = h("input", { autocomplete: "off", maxLength: 31, autofocus: true });
  const pass = h("input", { type: "password", autocomplete: "new-password" });
  const pass2 = h("input", { type: "password", autocomplete: "new-password" });
  const quota = h("input", { type: "number", min: 1, value: 500 });
  const msg = messenger();
  const submit = actionButton("einrichten", msg, async () => {
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,30}$/.test(name.value.trim())) throw new Error("Der Name darf nur Buchstaben, Ziffern und Bindestriche enthalten.");
    if (pass.value.length < 12) throw new Error("Das Passwort braucht mindestens 12 Zeichen.");
    if (pass.value !== pass2.value) throw new Error("Die Passwörter stimmen nicht überein.");
    await api("POST", "/setup", { name: name.value.trim(), password: pass.value, quota_bytes: Math.round(Number(quota.value) * 1024 ** 3) });
    await startApp();
  }, true);
  root.replaceChildren(header("erster start"),
    hero("init", "willkommen", "gegenseitige, verschlüsselte backups mit einem freund"),
    box("dieses nas",
      field("name, für deinen freund sichtbar (buchstaben, ziffern, bindestrich)", name),
      h("div", { class: "grid" }, field("passwort, min. 12 zeichen", pass), field("nochmal", pass2)),
      field("platz für die backups deines freundes, in gb", quota),
      h("div", { class: "actions" }, submit), msg));
}

function showLogin() {
  clearInterval(S.timer);
  S.key = "login"; S.refresh = null;
  const pass = h("input", { type: "password", autocomplete: "current-password", autofocus: true });
  const msg = messenger();
  const submit = actionButton("anmelden", msg, async () => {
    await loadCsrf();
    await api("POST", "/login", { password: pass.value });
    await startApp();
  }, true);
  pass.addEventListener("keydown", (e) => { if (e.key === "Enter") submit.click(); });
  root.replaceChildren(header(""), hero("login", "gesperrt"), box("anmelden", field("passwort", pass), h("div", { class: "actions" }, submit), msg));
  pass.focus();
}

// ---- wizard --------------------------------------------------------------------

function trail(current) {
  const index = STEPS.findIndex(([id]) => id === current);
  return h("div", { class: "steps" }, STEPS.map(([id, label], i) =>
    h("span", { class: i === index ? "now" : "" }, (i < index ? "[x] " : i === index ? "[>] " : "[ ] ") + label)));
}
const wizardFrame = (s, step, title, ...content) =>
  h("div", {}, header(s.name ? "nas: " + s.name : ""), trail(step), hero("setup " + step, title), ...content);

function viewNetwork(s) {
  const msg = messenger();
  const live = h("div", {});
  S.refresh = (st) => {
    if (st.network.auth_url) {
      live.replaceChildren(h("p", {}, "öffne diesen link und melde dich bei tailscale an:"),
        h("p", {}, h("a", { href: st.network.auth_url, target: "_blank", rel: "noopener noreferrer", class: "mono-wrap" }, st.network.auth_url)),
        h("p", { class: "dim" }, "warte auf anmeldung ..."));
    } else live.replaceChildren();
  };
  return wizardFrame(s, "network", "privates netz",
    box("tailscale",
      h("p", {}, "buddybackup bekommt ein eigenes gerät in deinem tailscale-konto. dein freund sieht später nur dieses gerät."),
      h("p", { class: "dim" }, "noch kein konto? bei tailscale.com kostenlos anlegen."),
      live,
      h("div", { class: "actions" }, actionButton("anmeldung starten", msg, () => api("POST", "/network/login"), true)), msg));
}

function invitationBox(s) {
  const out = h("div", {});
  const msg = messenger();
  const load = actionButton("einladung erzeugen", msg, async () => {
    const data = await api("GET", "/invitation");
    const copyFp = actionButton("fingerabdruck kopieren", msg, async () => { await copy(data.fingerprint); msg.ok("kopiert."); });
    out.replaceChildren(
      h("p", { class: "dim" }, "fingerabdruck, sag ihn deinem freund auf einem anderen weg als die einladung, zum beispiel am telefon:"),
      h("p", { class: "mono-wrap" }, groups(data.fingerprint)),
      h("div", { class: "actions" },
        btn("datei speichern", () => save("buddybackup-einladung-" + (s.name || "nas") + ".json", data.invitation), true),
        actionButton("text kopieren", msg, async () => { await copy(JSON.stringify(data.invitation)); msg.ok("kopiert."); }),
        copyFp));
    load.hidden = true;
  }, true);
  return box("2. deine einladung",
    h("p", {}, "schick sie privat an deinen freund, sie gibt zugang zu deinem backup-speicher."),
    h("p", { class: "dim" }, "dein schlüssel ist nicht enthalten."), out, h("div", { class: "actions" }, load), msg);
}

function peerImportForm(buttonText, replace, confirmText) {
  const area = h("textarea", { placeholder: "einladung einfügen", spellcheck: false });
  const file = h("input", { type: "file", accept: ".json,application/json" });
  file.addEventListener("change", async () => { if (file.files[0]) area.value = await readFile(file.files[0]); });
  const fp = h("input", { autocomplete: "off", spellcheck: false, placeholder: "64 zeichen" });
  const confirmBox = confirmText ? check(confirmText, {}) : null;
  const msg = messenger();
  const submit = actionButton(buttonText, msg, async () => {
    if (confirmBox && !confirmBox.querySelector("input").checked) throw new Error("Bitte zuerst bestätigen.");
    const parsed = parseJson(area.value, "Die Einladung");
    const invitation = parsed.invitation || parsed;
    const fingerprint = fp.value.replace(/[\s:]/g, "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(fingerprint)) throw new Error("Der Fingerabdruck muss genau 64 Hex-Zeichen lang sein.");
    await api("POST", "/peer", { invitation, fingerprint, replace });
    msg.ok("gespeichert.");
    await tick();
  }, true);
  return [area, h("p", {}, file), field("fingerabdruck, von deinem freund auf einem anderen weg", fp), confirmBox, h("div", { class: "actions" }, submit), msg];
}

function recoveryImportForm() {
  const file = h("input", { type: "file", accept: ".json,application/json" });
  const msg = messenger();
  const submit = actionButton("notfall-kit einspielen", msg, async () => {
    if (!file.files[0]) throw new Error("Bitte zuerst die Datei wählen.");
    const parsed = parseJson(await readFile(file.files[0]), "Das Notfall-Kit");
    if (!parsed.kit || !parsed.fingerprint) throw new Error("Das ist keine vollständige Notfall-Kit-Datei.");
    await api("POST", "/recovery/import", { kit: parsed.kit, fingerprint: parsed.fingerprint, confirm: "IMPORT_RECOVERY" });
    msg.ok("kit eingespielt. deine versionen findest du gleich unter 'versionen'.");
    await tick();
  });
  return [h("p", { class: "dim" }, "stellt verbindung und schlüssel wieder her. es wird nie ein neues backup angelegt."), h("p", {}, file), h("div", { class: "actions" }, submit), msg];
}

function viewPeer(s) {
  return wizardFrame(s, "peer", "freund verbinden",
    box("1. gerät teilen",
      h("p", {}, "in der ", h("a", { href: "https://login.tailscale.com/admin/machines", target: "_blank", rel: "noopener noreferrer" }, "tailscale-konsole"),
        " bei ", h("span", { class: "tag" }, "buddy-" + (s.name || "").toLowerCase()), " auf share gehen und den link an deinen freund schicken."),
      h("p", { class: "dim" }, "dein freund macht dasselbe. ihr müsst beide den link des anderen annehmen."),
      h("p", { class: "dim" }, "stell dort auch \"disable key expiry\" für das gerät ein, sonst läuft die anmeldung nach einigen monaten ab.")),
    invitationBox(s),
    box("3. einladung deines freundes", ...peerImportForm("verbinden", false)),
    h("details", {}, h("summary", {}, "neues nas? notfall-kit einspielen"), box("wiederherstellen", ...recoveryImportForm())));
}

function settingsForm(s, submitText, afterSave) {
  const current = s.settings || {};
  const sourceList = h("div", {}, h("p", { class: "dim" }, "lese ordner ..."));
  const selected = new Set(current.sources || []);
  api("GET", "/sources").then(({ sources }) => {
    sourceList.replaceChildren(...(sources.length ? sources.map((src) => {
      const line = check(src.path.replace(/^\/sources\//, "") + (src.valid ? "" : "  (" + (src.message || "ungültig") + ")"), { checked: selected.has(src.path), disabled: !src.valid });
      line.querySelector("input").addEventListener("change", (e) => { e.target.checked ? selected.add(src.path) : selected.delete(src.path); });
      return line;
    }) : [h("p", {}, "noch keine ordner freigegeben.")]));
    selected.forEach((path) => { if (!sources.some((src) => src.path === path && src.valid)) selected.delete(path); });
    sourceList.append(h("p", { class: "dim" }, "weitere ordner: in truenas unter apps > buddybackup > edit im yaml einen eintrag nach /sources/<name> ergänzen."));
  }).catch((e) => sourceList.replaceChildren(h("p", { class: "msg err" }, "[!!] " + e.message)));
  const num = (value, min, max) => h("input", { type: "number", value, min, max });
  const interval = num(current.interval_hours || 24, 1, 168);
  const daily = num(current.keep_daily ?? 7, 0, 3650);
  const weekly = num(current.keep_weekly ?? 4, 0, 3650);
  const monthly = num(current.keep_monthly ?? 12, 0, 3650);
  const upload = num(current.upload_kib ?? 0, 0, 10000000);
  const stale = num(current.stale_hours || 48, 1, 87600);
  const ntfy = h("input", { type: "url", value: current.ntfy_url || "", placeholder: "https://ntfy.sh/mein-thema" });
  const direct = check("nur direkte verbindung, sonst pausieren", { checked: !!current.direct_only });
  const msg = messenger();
  const submit = actionButton(submitText, msg, async () => {
    if (!selected.size) throw new Error("Bitte mindestens einen Ordner wählen.");
    await api("POST", "/settings", {
      sources: [...selected], interval_hours: Number(interval.value), keep_daily: Number(daily.value), keep_weekly: Number(weekly.value),
      keep_monthly: Number(monthly.value), direct_only: direct.querySelector("input").checked, upload_kib: Number(upload.value),
      ntfy_url: ntfy.value.trim(), stale_hours: Number(stale.value),
    });
    msg.ok("gespeichert.");
    if (afterSave) await afterSave();
  }, true);
  return h("div", {},
    box("ordner", sourceList),
    box("zeitplan", field("alle wie viele stunden sichern", interval)),
    h("details", {}, h("summary", {}, "mehr optionen"),
      box("aufbewahrung", h("div", { class: "grid" }, field("täglich", daily), field("wöchentlich", weekly), field("monatlich", monthly))),
      box("verbindung", field("upload-limit in kib/s, 0 = unbegrenzt", upload), direct),
      box("benachrichtigung", field("ntfy-adresse für fehler", ntfy), field("warnen nach wie vielen stunden ohne sicherung", stale))),
    h("div", { class: "actions" }, submit), msg);
}

const invitationAgain = (s) => h("details", {}, h("summary", {}, "deine einladung nochmal anzeigen"), invitationBox(s));
const viewSources = (s) => wizardFrame(s, "sources", "was sichern?", settingsForm(s, "weiter", tick), invitationAgain(s));

function viewRecovery(s) {
  const out = h("div", {});
  const msg = messenger();
  const exportButton = actionButton("notfall-kit herunterladen", msg, async () => {
    const data = await api("POST", "/recovery/export");
    save("buddybackup-notfallkit-" + (s.name || "nas") + ".json", data);
    const word = h("input", { autocomplete: "off", placeholder: "gesichert" });
    const confirmButton = actionButton("bestätigen", msg, async () => {
      if (word.value.trim().toLowerCase() !== "gesichert") throw new Error("Bitte das Wort gesichert eintippen.");
      await api("POST", "/recovery/ack", { fingerprint: data.fingerprint, connection_fingerprint: data.connection_fingerprint, confirm: "SAVED_OFFLINE" });
      await tick();
    }, true);
    out.replaceChildren(h("p", { class: "hot" }, "kopiere die datei jetzt an einen sicheren ort außerhalb dieses nas."),
      field("tippe gesichert", word), h("div", { class: "actions" }, confirmButton));
    exportButton.hidden = true;
  }, true);
  return wizardFrame(s, "recovery", "notfall-kit",
    box("wichtig",
      h("p", {}, "das kit enthält deinen schlüssel. ohne es sind deine backups wertlos, wenn das nas ausfällt."),
      h("p", { class: "dim" }, "wer es hat, kann deine backups lesen. nicht an deinen freund geben."),
      out, h("div", { class: "actions" }, exportButton), msg),
    box("schutz beim freund", h("p", { class: "dim" }, s.snapshot_instructions || "")),
    invitationAgain(s));
}

// ---- main views ------------------------------------------------------------------

function nav() {
  return h("nav", { class: "nav" }, VIEWS.map(([id, label], i) =>
    h("button", { type: "button", "aria-current": S.view === id ? "page" : undefined, onclick: () => go(id) }, "[" + (i + 1) + "] " + label)));
}
function go(view) { S.view = view; S.key = ""; draw(); }

function appFrame(s, ...content) {
  return h("div", {}, header((s.peer ? s.name + " <-> " + s.peer.name : s.name) || ""), nav(), ...content,
    h("div", { class: "foot" }, "1-4 ansicht · b sichern · t theme"));
}

function viewStatus(s) {
  const heroSlot = h("div", {});
  const live = h("div", {});
  const msg = messenger();
  const backup = actionButton("jetzt sichern", msg, () => api("POST", "/operations", { kind: "backup" }).then(tick), true);
  const peerState = h("span", { class: "dim" }, "prüfe ...");
  if (s.peer) api("POST", "/peer/check").then((r) => {
    peerState.replaceChildren(r.reachable
      ? h("span", {}, h("span", { class: "tag" }, "OK"), " " + (r.route === "direct" ? "direkt" : r.route === "relay" ? "über relay" : "erreichbar"))
      : h("span", {}, h("span", { class: "tag bad" }, "NEIN"), " nicht erreichbar"));
    if (!r.reachable && r.message) peerState.title = r.message;
  }).catch(() => peerState.replaceChildren("-"));
  const relogin = messenger();
  const reloginButton = actionButton("bei tailscale anmelden", relogin, () => api("POST", "/network/login"), true);
  S.refresh = (st) => {
    const running = st.operation && st.operation.state === "running" ? st.operation : null;
    const hasWarnings = st.warnings && st.warnings.length;
    const title = running ? OP_LABELS[running.kind] || running.kind : hasWarnings ? "achtung" : st.recovery_only ? "daten zurückholen" : isZero(st.last_success) ? "noch keine sicherung" : "alles gesichert";
    const sub = st.recovery_only ? "backups pausieren, bis du ordner wählst" : "letzte " + when(st.last_success) + " · nächste " + when(st.next_run);
    heroSlot.replaceChildren(hero("status", title, sub));
    const r = st.receiver || {};
    const nodes = [];
    if (running) nodes.push(progressNode(running));
    if (hasWarnings) nodes.push(box("warnungen", st.warnings.map((w) => h("p", { class: "hot" }, "[!!] " + w))));
    if (!st.network.ready) {
      nodes.push(box("tailscale", st.network.auth_url ? h("p", {}, h("a", { href: st.network.auth_url, target: "_blank", rel: "noopener noreferrer", class: "mono-wrap" }, st.network.auth_url)) : h("p", { class: "dim" }, "neu anmelden, wenn die verbindung nicht von selbst zurückkommt."),
        h("div", { class: "actions" }, reloginButton), relogin));
    }
    if (st.peer) nodes.push(box("freund", h("div", { class: "row" }, h("span", {}, st.peer.name), peerState)));
    const fraction = r.quota_bytes ? (r.used_bytes || 0) / r.quota_bytes : 0;
    nodes.push(box("speicher für " + (st.peer ? st.peer.name : "deinen freund"),
      row("belegt", bytes(r.used_bytes || 0) + " / " + bytes(r.quota_bytes)),
      h("div", { class: "bar" }, bar(fraction, 28))));
    live.replaceChildren(...nodes);
    backup.disabled = !!running;
  };
  return appFrame(s, heroSlot, live, h("div", { class: "actions" }, backup, h("button", { class: "btn", type: "button", onclick: () => go("versions") }, "[r] wiederherstellen")), msg);
}

function fileTree(entries, selected) {
  const rootNode = { children: new Map() };
  for (const entry of entries) {
    let node = rootNode;
    const parts = entry.path.split("/").filter(Boolean);
    parts.forEach((part, i) => {
      if (!node.children.has(part)) node.children.set(part, { name: part, path: "/" + parts.slice(0, i + 1).join("/"), children: new Map(), entry: null });
      node = node.children.get(part);
    });
    node.entry = entry;
  }
  const renderList = (node, depth, parentCovered) => {
    const sorted = [...node.children.values()].sort((a, b) => (b.children.size > 0) - (a.children.size > 0) || a.name.localeCompare(b.name, "de"));
    return h("ul", {}, sorted.map((child) => {
      const isDir = child.children.size > 0;
      const li = h("li", {});
      let open = depth < 2;
      let sub = null;
      const fold = h("button", { class: "fold", type: "button", "aria-label": "aufklappen" }, isDir ? (open ? "-" : "+") : "");
      let line;
      const sync = () => {
        fold.textContent = open ? "-" : "+";
        if (open && !sub) { sub = renderList(child, depth + 1, line.querySelector("input").checked); li.append(sub); }
        if (sub) sub.hidden = !open;
      };
      // A selected folder restores everything below it, so its children must show that and stay locked.
      const cover = () => {
        const input = line.querySelector("input");
        if (!sub) return;
        sub.querySelectorAll("input").forEach((box) => {
          box.disabled = input.checked || input.disabled;
          box.checked = input.checked || input.disabled || selected.has(box.dataset.path);
        });
      };
      if (isDir) fold.addEventListener("click", () => { open = !open; sync(); cover(); });
      const size = child.entry && child.entry.type === "file" ? "  " + bytes(child.entry.size) : "";
      line = check(child.name + size, { "data-path": child.path, disabled: parentCovered });
      if (parentCovered) line.querySelector("input").checked = true;
      line.querySelector("input").addEventListener("change", (e) => {
        if (e.target.checked) {
          selected.add(child.path);
          for (const path of [...selected]) if (path.startsWith(child.path + "/")) selected.delete(path);
        } else selected.delete(child.path);
        cover();
      });
      li.append(h("div", { class: "node" }, fold, line));
      if (isDir) sync();
      else fold.tabIndex = -1;
      return li;
    }));
  };
  return renderList(rootNode, 0, false);
}

function restorePanel(snapshot, msgOuter) {
  const panel = h("div", {});
  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
  const folder = h("input", { value: "restore-" + stamp, autocomplete: "off" });
  const selected = new Set();
  const treeSlot = h("div", {}, h("p", { class: "dim" }, "ganze version, oder einzelne dateien wählen:"));
  const msg = messenger();
  const browse = actionButton("dateien anzeigen", msg, async () => {
    msg.ok("lese dateien ...");
    const result = await runOperation({ kind: "files", snapshot: snapshot.id });
    msg.clear();
    selected.clear();
    treeSlot.replaceChildren(h("div", { class: "tree" }, fileTree(result.entries, selected)));
    if (result.truncated) treeSlot.append(h("p", { class: "hot" }, "liste gekürzt, sehr viele dateien."));
    browse.hidden = true;
  });
  const go2 = actionButton("wiederherstellen", msg, async () => {
    msg.ok("stelle wieder her ...");
    const result = await runOperation({ kind: "restore", snapshot: snapshot.id, folder: folder.value.trim(), paths: [...selected] });
    msg.ok("fertig: " + (result.host_path || result.path));
  }, true);
  panel.append(treeSlot, h("div", { class: "actions" }, browse), field("neuer ordner unter /restore", folder), h("div", { class: "actions" }, go2), msg);
  return panel;
}

function viewVersions(s) {
  const list = h("div", {}, h("p", { class: "dim" }, "lade versionen ..."));
  const msg = messenger();
  const load = async () => {
    list.replaceChildren(h("p", { class: "dim" }, "lade versionen ..."));
    const rows = await runOperation({ kind: "snapshots" });
    if (!rows.length) return list.replaceChildren(h("p", {}, "noch keine versionen."));
    list.replaceChildren(...[...rows].reverse().map((snapshot, i) => {
      const pending = (snapshot.tags || []).includes("buddybackup-pending");
      const detail = h("details", { class: "version", open: false },
        h("summary", {}, snapshot.id.slice(0, 8) + "  " + when(snapshot.time) + (pending ? "  [teilweise]" : "")),
        h("p", { class: "dim mono-wrap" }, (snapshot.paths || []).map((p) => p.replace(/^\/sources\//, "")).join(", ")));
      let built = false;
      detail.addEventListener("toggle", () => { if (detail.open && !built) { built = true; detail.append(restorePanel(snapshot, msg)); } });
      return detail;
    }));
  };
  const firstLoad = load().catch((e) => {
    list.replaceChildren();
    if (/Repository fehlt/.test(e.message) && isZero(S.status.last_success)) return list.replaceChildren(h("p", {}, "noch keine versionen."));
    msg.err(e);
  });
  void firstLoad;
  return appFrame(s, hero("versionen", "wiederherstellen"), box("versionen", list),
    h("div", { class: "actions" }, actionButton("neu laden", msg, load)), msg);
}

function viewSettings(s) {
  const themeBox = box("theme", THEMES.map((t) => {
    const line = h("label", { class: "check" }, h("input", { type: "radio", name: "theme", checked: currentTheme() === t.id }), h("span", { class: "mark" }), h("span", {}, t.name));
    line.querySelector("input").addEventListener("change", () => setTheme(t.id));
    return line;
  }));
  const kitMsg = messenger();
  const kitButton = actionButton("notfall-kit neu exportieren", kitMsg, async () => {
    const data = await api("POST", "/recovery/export");
    save("buddybackup-notfallkit-" + (s.name || "nas") + ".json", data);
    kitMsg.ok("gespeichert. kopiere die datei außerhalb dieses nas.");
  });
  const oldPass = h("input", { type: "password", autocomplete: "current-password" });
  const newPass = h("input", { type: "password", autocomplete: "new-password" });
  const passMsg = messenger();
  const passButton = actionButton("passwort ändern", passMsg, async () => {
    if (newPass.value.length < 12) throw new Error("Das neue Passwort braucht mindestens 12 Zeichen.");
    await api("POST", "/password", { old_password: oldPass.value, new_password: newPass.value });
    oldPass.value = newPass.value = "";
    passMsg.ok("geändert.");
  });
  const quotaInput = h("input", { type: "number", min: 1, value: Math.round(((s.receiver && s.receiver.quota_bytes) || 0) / 1024 ** 3) });
  const quotaMsg = messenger();
  const quotaButton = actionButton("speichern", quotaMsg, async () => {
    await api("POST", "/quota", { quota_bytes: Math.round(Number(quotaInput.value) * 1024 ** 3) });
    quotaMsg.ok("gespeichert.");
    await tick();
  });
  const logoutMsg = messenger();
  const logout = actionButton("abmelden", logoutMsg, async () => { await api("POST", "/logout"); await startApp(); });
  const setsSlot = h("div", {});
  api("GET", "/source-sets").then(({ source_sets }) => {
    const retired = source_sets.filter((x) => x.retired && !x.deleted);
    setsSlot.replaceChildren(...retired.map((set) => {
      const msg = messenger();
      return h("div", {}, h("p", { class: "mono-wrap" }, set.paths.join(", ")),
        actionButton("alte versionen löschen", msg, async () => {
          if (!confirm("Alle Versionen dieser alten Ordnerauswahl endgültig löschen?")) return;
          await api("POST", "/source-sets/retire", { id: set.id, confirm: "DELETE_RETIRED_SNAPSHOTS" });
          msg.ok("wird entfernt, siehe status.");
        }), msg);
    }));
    if (!retired.length) setsSlot.replaceChildren(h("p", { class: "dim" }, "keine alten ordnerauswahlen."));
  }).catch(() => {});
  return appFrame(s, hero("config", "einstellungen"), settingsForm(s, "speichern", tick), themeBox,
    box("freund",
      s.peer ? row("name", s.peer.name) : null,
      s.peer ? row("adresse", s.peer.ip) : null,
      h("p", { class: "dim mono-wrap" }, groups(s.peer_fingerprint))),
    h("details", {}, h("summary", {}, "erweitert"),
      invitationBox(s),
      box("speicher für deinen freund", field("in gb", quotaInput), h("div", { class: "actions" }, quotaButton), quotaMsg),
      box("freund ersetzen", h("p", { class: "hot" }, "erzeugt einen neuen schlüssel und ein neues backup. das alte kit brauchst du für alte daten weiterhin."),
        ...peerImportForm("freund ersetzen", true, "ich will meinen freund wirklich ersetzen")),
      box("notfall-kit", h("div", { class: "actions" }, kitButton), kitMsg),
      box("alte ordnerauswahlen", setsSlot),
      box("zfs-snapshots", h("p", {}, s.snapshot_instructions || "")),
      box("passwort", h("div", { class: "grid" }, field("bisher", oldPass), field("neu, min. 12 zeichen", newPass)), h("div", { class: "actions" }, passButton), passMsg),
      box("sitzung", h("div", { class: "actions" }, logout), logoutMsg)));
}

function viewCare(s) {
  const out = messenger();
  const op = (text, body, done) => actionButton(text, out, async () => {
    out.ok(text + " läuft ...");
    const result = await runOperation(body);
    out.ok((result && result.detail) || done || "fertig.");
    await tick();
  });
  return appFrame(s, hero("wartung", "werkzeuge", "letzte wartung " + when(s.last_maintenance) + " · nächste " + when(s.next_maintenance)),
    box("prüfen",
      h("p", { class: "dim" }, "der kurze test sichert 64 kib testdaten und holt sie wieder zurück."),
      h("div", { class: "actions" }, op("wiederherstellung testen", { kind: "restore-test" }), op("struktur prüfen", { kind: "check" }, "struktur ist in ordnung."))),
    h("details", {}, h("summary", {}, "bei problemen"),
      box("aufräumen",
        h("div", { class: "actions" }, op("aufräumen", { kind: "maintenance" }), op("aufräumen bei vollem speicher", { kind: "maintenance", low_space: true }))),
      box("vollständig prüfen",
        h("p", { class: "dim" }, "lädt das ganze backup einmal herunter und kann lange dauern."),
        h("div", { class: "actions" }, op("alle daten prüfen", { kind: "check", read_data: true }, "alle daten sind in ordnung."))),
      box("sperren",
        h("p", { class: "dim" }, "nur nach einem absturz nötig."),
        h("div", { class: "actions" }, op("alte sperren lösen", { kind: "unlock", confirm: "UNLOCK_STALE_LOCKS" })))),
    out);
}

// ---- theme, loop --------------------------------------------------------------------

const currentTheme = () => document.documentElement.dataset.theme;
function setTheme(id) {
  document.documentElement.dataset.theme = id;
  try { localStorage.setItem("buddybackup-theme", id); } catch {}
}

function draw() {
  const s = S.status;
  if (!s) return;
  const views = { network: viewNetwork, peer: viewPeer, sources: viewSources, recovery: viewRecovery };
  if (s.wizard in views) return mount("wizard:" + s.wizard, () => views[s.wizard](s));
  const main = { status: viewStatus, versions: viewVersions, settings: viewSettings, care: viewCare };
  mount("view:" + S.view, () => main[S.view](s));
}

async function tick() {
  try {
    S.status = await api("GET", "/status");
    S.lastContact = new Date();
    connection.hidden = true;
    draw();
  } catch (e) {
    if (e.status === 401) return showLogin();
    connection.textContent = "[!!] keine verbindung zum nas. angezeigter stand von " + (S.lastContact ? S.lastContact.toLocaleTimeString("de-DE") : "-");
    connection.hidden = false;
  }
}

async function startApp() {
  clearInterval(S.timer);
  S.key = ""; S.refresh = null;
  const auth = await loadCsrf();
  if (!auth.initialized) return showSetup();
  try {
    S.status = await api("GET", "/status");
  } catch (e) {
    if (e.status === 401) return showLogin();
    throw e;
  }
  draw();
  S.timer = setInterval(tick, 2000);
}

document.addEventListener("keydown", (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
  if (e.key === "t") {
    const i = THEMES.findIndex((t) => t.id === currentTheme());
    return setTheme(THEMES[(i + 1) % THEMES.length].id);
  }
  if (!S.status || S.status.wizard !== "ready") return;
  const n = Number(e.key);
  if (n >= 1 && n <= VIEWS.length) go(VIEWS[n - 1][0]);
  if (e.key === "r") go("versions");
  if (e.key === "b") api("POST", "/operations", { kind: "backup" }).then(tick).catch(() => {});
});

try {
  const saved = localStorage.getItem("buddybackup-theme");
  if (THEMES.some((t) => t.id === saved)) document.documentElement.dataset.theme = saved;
} catch {}

startApp().catch(() => { root.replaceChildren(h("p", { class: "msg err" }, "[!!] NAS nicht erreichbar.")); });
