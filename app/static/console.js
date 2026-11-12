"use strict";
// Incident Shield console. Plain DOM, no libraries, no innerHTML: every value from the server is set as text.
const $ = (id) => document.getElementById(id);
const store = {
  get(k) { try { return localStorage.getItem(k) || ""; } catch (e) { return ""; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } },
};
const state = { token: store.get("is_token"), key: "", device: store.get("is_device"), cfg: {}, me: null, tab: "overview", caseId: null, chat: [] };
const started = Date.now();
const beh = { keys: 0, first: 0, last: 0, pasted: false, blur: 0, pauses: 0 };
window.addEventListener("blur", () => { beh.blur += 1; });

function h(tag, props, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") n.className = v; else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else if (v !== false && v != null) n.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) n.append(kid);
  return n;
}
const money = (v) => "$" + Number(v).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const nice = (s) => String(s == null ? "" : s).replace(/_/g, " ");
const when = (iso) => (iso ? iso.replace("T", " ").slice(0, 16) : "");
function tone(s) {
  if (["allow", "captured", "refunded", "ok"].includes(s)) return "ok";
  if (["block", "blocked", "held", "hold_review", "watch_stop", "failed", "declined", "refund_declined"].includes(s)) return "bad";
  if (["step_up", "warn_and_delay", "delayed", "awaiting_confirmation", "awaiting_approval", "capturing", "scored", "in_review", "manual_review", "fast_tracked", "awaiting_second_approval"].includes(s)) return "warn";
  return "";
}
const tag = (s, t) => h("span", { class: "tag " + (t || tone(s)), text: nice(s) });
function toast(msg) { const t = $("toast"); t.textContent = msg; t.classList.remove("hide"); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add("hide"), 5000); }
function newDevice() { const a = new Uint8Array(16); crypto.getRandomValues(a); state.device = Array.from(a, (b) => b.toString(16).padStart(2, "0")).join(""); store.set("is_device", state.device); }
if (!state.device) newDevice();

async function api(path, method, body) {
  const headers = { "Content-Type": "application/json" };
  if (state.token) headers.Authorization = "Bearer " + state.token;
  if (state.key) headers["X-API-Key"] = state.key;
  const r = await fetch(path, { method: method || "GET", headers, body: body ? JSON.stringify(body) : undefined });
  let data = {}; try { data = await r.json(); } catch (e) { /* no body */ }
  if (!r.ok) { const err = new Error(typeof data.detail === "string" ? data.detail : "Request failed (" + r.status + ")"); err.status = r.status; throw err; }
  return data;
}
function askText(title, text, placeholder) {
  return new Promise((resolve) => {
    $("ask-title").textContent = title; $("ask-text").textContent = text || ""; const input = $("ask-input"); input.value = ""; input.placeholder = placeholder || "";
    const done = (v) => { $("ask").close(); $("ask-ok").onclick = null; $("ask-cancel").onclick = null; resolve(v); };
    $("ask-ok").onclick = () => done(input.value.trim()); $("ask-cancel").onclick = () => done(null);
    $("ask").showModal(); input.focus();
  });
}
function kv(pairs) { const dl = h("dl", { class: "kv" }); for (const [k, v] of pairs) if (v != null && v !== "") dl.append(h("dt", { text: k }), v instanceof Node ? h("dd", {}, v) : h("dd", { text: String(v) })); return dl; }
function table(cols, rows, onRow) {
  const t = h("table", { class: "resp" }, h("thead", {}, h("tr", {}, cols.map((c) => h("th", { text: c })))));
  const body = h("tbody");
  for (const r of rows) { const tr = h("tr", onRow ? { class: "click", tabindex: "0", onclick: () => onRow(r), onkeydown: (e) => { if (e.key === "Enter") onRow(r); } } : {}); for (const cell of r.cells) tr.append(cell instanceof Node ? h("td", {}, cell) : h("td", { text: cell == null ? "" : String(cell) })); body.append(tr); }
  t.append(body); return t;
}
const empty = (text) => h("p", { class: "mute", text });
const needAccess = () => h("div", { class: "note w", text: "This screen needs reviewer access. Open Settings and enter a reviewer or owner key (not needed when the site runs in public demo mode)." });
async function guarded(build) { try { return await build(); } catch (e) { return e.status === 401 ? needAccess() : h("p", { class: "err", text: e.message }); } }

// ------------------------------------------------------------------ tabs
const TABS = [
  ["overview", "Overview", "▦"], ["pay", "Send money", "➜"], ["transactions", "Transactions", "≡"], ["cases", "Cases", "⚑"],
  ["watch", "AI watch", "◉"], ["risk", "Risk engine", "◈"], ["evidence", "Evidence", "⛓"], ["copilot", "AI Copilot", "✦"],
  ["audit", "Audit log", "☰"], ["settings", "Settings", "⚙"],
];
function nav() {
  $("nav").replaceChildren(...TABS.map(([id, label, icon]) => h("button", { "aria-current": state.tab === id ? "page" : false, onclick: () => go(id) }, h("span", { class: "ic", "aria-hidden": "true", text: icon }), label)));
}
async function go(tab) {
  state.tab = tab; nav(); $("side").classList.remove("open");
  $("crumb").textContent = TABS.find((t) => t[0] === tab)[1];
  const page = $("page"); page.replaceChildren(h("p", { class: "mute", text: "Loading…" }));
  const view = await guarded(VIEWS[tab]); if (state.tab === tab) { page.replaceChildren(view); page.focus(); }
}
function head(title, sub, ...actions) { return h("div", {}, h("div", { class: "row" }, h("div", { class: "f" }, h("h1", { text: title }), h("p", { class: "sub", text: sub })), actions)); }

// ------------------------------------------------------------------ overview
async function overview() {
  const o = await api("/review/overview");
  const kpi = (v, l, n) => h("div", { class: "card kpi" }, h("div", { class: "v", text: v }), h("div", { class: "l", text: l }), h("div", { class: "n", text: n }));
  const max = Math.max(1, ...o.last_7_days.map((d) => d.payments));
  const days = h("div", { class: "days", role: "img", "aria-label": "Payments per day for the last 7 days" }, o.last_7_days.map((d) => {
    const col = h("div", { class: "col", title: d.payments + " payments, " + d.flagged + " flagged" }); col.style.height = Math.round((d.payments / max) * 100) + "%";
    if (d.flagged) { const f = h("i"); f.style.height = Math.round((d.flagged / Math.max(1, d.payments)) * 100) + "%"; col.append(f); }
    return h("div", { class: "d" }, h("span", { class: "small num", text: String(d.payments) }), col, h("span", { class: "small mute", text: d.day.slice(5) }));
  }));
  const total = Math.max(1, Object.values(o.risk_distribution).reduce((a, b) => a + b, 0));
  const dist = Object.entries(o.risk_distribution).map(([band, n]) => { const b = h("div", { class: "bar " + (band === "allow" ? "" : band === "step_up" ? "w" : "b") }, h("i")); b.firstChild.style.width = Math.round((n / total) * 100) + "%"; return h("div", { class: "sp" }, h("div", { class: "row" }, h("span", { class: "f", text: nice(band) }), h("span", { class: "num", text: String(n) })), b); });
  return h("div", {}, head("Overview", "Every payment is scored and sealed. Figures come from stored records; demo-history rows are excluded.", h("button", { class: "btn sec", text: "Refresh", onclick: () => go("overview") }), h("button", { class: "btn", text: "Send a payment", onclick: () => go("pay") })),
    modeNote(),
    h("div", { class: "grid g4" }, kpi(String(o.total_payments), "Total payments", o.sealed_records + " sealed decision records"), kpi(String(o.flagged_payments), "Flagged payments", "scored 30 or more"), kpi(money(o.funds_on_hold), "Funds on hold", o.payments_on_hold + " payment(s) paused"), kpi(String(o.open_cases), "Open cases", money(o.refunded) + " refunded so far")),
    h("div", { class: "grid g2" }, h("div", { class: "card" }, h("h3", { text: "Payments, last 7 days" }), h("p", { class: "small mute", text: "Blue: all payments. Red: the flagged share." }), days), h("div", { class: "card" }, h("h3", { text: "Risk distribution" }), h("p", { class: "small mute", text: "What the engine scored, whether or not it was allowed to act." }), dist)));
}
function modeNote() {
  const c = state.cfg; const parts = [];
  parts.push(c.enforcement === "monitor" ? "Monitor mode: payments are scored, sealed and recorded, and are not stopped by the score." : "Enforce mode: a high score can require confirmation, hold or block a payment.");
  if (c.watch_outflow_usd > 0) parts.push("AI watch: a payment scoring " + c.watch_score + "+ puts the account on watch for " + c.watch_hours + " hours; payments pause once more than $" + c.watch_outflow_usd + " has gone out.");
  parts.push("Money moves through the PayPal sandbox. Crediting the payee is a ledger entry.");
  return h("div", { class: "note", text: parts.join(" ") });
}

// ------------------------------------------------------------------ send money
const SIMS = { active_call: "On a phone call", remote_access_or_overlay: "Remote-access tool", device_compromised: "Device compromised", credentials_in_breach: "Credentials in a breach", anonymising_asn: "VPN / anonymising network", network_risk_score_high: "Network flagged high risk" };
const SCENARIOS = [
  ["Normal payment", { handle: "demo_shop", name: "Demo Shop", amount: "20", ref: "invoice 2231", sims: [] }],
  ["Coached scam", { handle: "demo_stranger", name: "Demo Stranger", amount: "45", ref: "move to safe account", sims: ["active_call"] }],
  ["Reworded scam (AI reads it)", { handle: "demo_stranger", name: "Demo Stranger", amount: "45", ref: "shift my savings into the protected holding acct", sims: ["active_call"] }],
  ["Large payment to a stranger", { handle: "demo_stranger", name: "Demo Stranger", amount: "200", ref: "", sims: ["device_compromised", "remote_access_or_overlay"] }],
];
async function ensureMe() { if (!state.token) { state.me = null; return null; } try { state.me = await api("/app/me"); } catch (e) { state.me = null; state.token = ""; store.set("is_token", ""); } chips(); return state.me; }
function chips() { $("chip-user").textContent = state.me ? "@" + state.me.handle : "not signed in"; $("chip-mode").textContent = (state.cfg.enforcement === "monitor" ? "Monitor" : "Enforce") + (state.cfg.public_demo ? " · public demo" : ""); }
async function startDemo() {
  const handle = "judge_" + Math.random().toString(36).slice(2, 8);
  const r = await api("/app/signup", "POST", { handle, display_name: "Demo Judge" }); state.token = r.token; store.set("is_token", r.token);
  if (state.cfg.simulation) { try { await api("/app/demo/history", "POST", { device_id: state.device }); } catch (e) { /* history is optional */ } }
  await ensureMe(); toast("Demo account @" + handle + " is ready, with a payment history.");
}
async function pay() {
  await ensureMe();
  if (!state.me) return h("div", {}, head("Send money", "Start with a ready-made demo account. No sign-up form, no keys."), h("div", { class: "card" }, h("h3", { text: "Start the demo" }), h("p", { class: "mute", text: "Creates a demo account for this browser with four past payments, so the fraud scenarios behave like an established customer's." }), h("button", { class: "btn", text: "Start demo", onclick: async (e) => { e.target.disabled = true; try { await startDemo(); go("pay"); } catch (err) { toast(err.message); e.target.disabled = false; } } })));
  const f = { handle: h("input", { id: "p-handle", maxlength: "24", autocomplete: "off" }), name: h("input", { id: "p-name", maxlength: "80", autocomplete: "off" }), amount: h("input", { id: "p-amount", inputmode: "decimal", autocomplete: "off" }), ref: h("input", { id: "p-ref", maxlength: "140", autocomplete: "off" }) };
  for (const n of Object.values(f)) { n.addEventListener("keydown", () => { const t = Date.now(); if (!beh.first) beh.first = t; if (beh.last && t - beh.last > 5000) beh.pauses += 1; beh.last = t; beh.keys += 1; }); n.addEventListener("paste", () => { beh.pasted = true; }); }
  const boxes = {}; const simRow = h("div", { class: "row" });
  for (const [k, label] of Object.entries(SIMS)) { boxes[k] = h("input", { type: "checkbox", id: "sim-" + k }); boxes[k].style.width = "auto"; simRow.append(h("label", { for: "sim-" + k }, boxes[k], " " + label)); }
  const result = h("div", { id: "result" }); const msg = h("span", { class: "err", role: "alert" });
  const fill = (s) => { f.handle.value = s.handle; f.name.value = s.name; f.amount.value = s.amount; f.ref.value = s.ref; for (const k of Object.keys(SIMS)) boxes[k].checked = s.sims.includes(k); };
  const submit = h("button", { class: "btn", text: "Check and pay", onclick: async () => {
    msg.textContent = ""; submit.disabled = true; submit.textContent = "Scoring…";
    const span = beh.last && beh.first ? (beh.last - beh.first) / 1000 : 0; const simulated = {};
    for (const k of Object.keys(SIMS)) if (boxes[k].checked) simulated[k] = true;
    try {
      const r = await api("/app/payments", "POST", { payee_handle: f.handle.value.trim(), payee_name: f.name.value.trim(), amount: f.amount.value.trim(), reference: f.ref.value, device_id: state.device,
        fingerprint: { ua: navigator.userAgent, platform: navigator.platform || "", lang: navigator.language || "", tz: Intl.DateTimeFormat().resolvedOptions().timeZone || "", screen: screen.width + "x" + screen.height },
        behaviour: { typing_cps: span > 0.5 ? Math.round((beh.keys / span) * 10) / 10 : null, paste_used: beh.pasted, seconds_on_page: Math.round((Date.now() - started) / 100) / 10, blur_count: beh.blur, pause_count: beh.pauses }, simulated });
      result.replaceChildren(decisionCard(r)); await ensureMe(); mine.replaceChildren(myPayments());
    } catch (e) { msg.textContent = e.message; await ensureMe(); mine.replaceChildren(myPayments()); } finally { submit.disabled = false; submit.textContent = "Check and pay"; }
  } });
  const mine = h("div", {}, myPayments());
  return h("div", {}, head("Send money", "Every payment is scored before it reaches PayPal, and the decision is sealed."), modeNote(),
    h("div", { class: "card" }, h("h3", { text: "Try a scenario" }), h("div", { class: "row" }, SCENARIOS.map(([label, s]) => h("button", { class: "btn sec sm", text: label, onclick: () => fill(s) })))),
    h("div", { class: "card" }, h("h3", { text: "Payment" }), h("div", { class: "row" }, h("div", { class: "f" }, h("label", { for: "p-handle", text: "Payee handle" }), f.handle), h("div", { class: "f" }, h("label", { for: "p-name", text: "Payee name, as you know it" }), f.name), h("div", { class: "f" }, h("label", { for: "p-amount", text: "Amount (USD)" }), f.amount)), h("label", { for: "p-ref", text: "Payment reference" }), f.ref,
      state.cfg.simulation ? h("div", { class: "sp" }, h("p", { class: "small mute", text: "Simulated signals: things only a phone network or the device itself could tell a real provider. Switch them on to see the engine react. They are recorded as simulated." }), simRow) : null,
      h("p", { class: "sp" }, submit, " ", msg)),
    result, h("div", { class: "card" }, h("h3", { text: "Your payments" }), mine));
}
function decisionCard(r) {
  const d = r.decision; const card = h("div", { class: "card", role: "status" }, h("h3", { text: "Decision" }), h("p", { text: r.message }));
  if (d) {
    card.append(h("div", { class: "row" }, h("div", {}, h("div", { class: "score", text: String(d.score) }), h("div", { class: "small mute", text: "risk score out of 100" })), h("div", { class: "f" }, kv([["Engine's decision", tag(r.engine_action)], ["What was applied", tag(r.action)], ["Reasons", d.reason_codes.map(nice).join(", ") || "nothing unusual"], ["Pattern", d.typology ? nice(d.typology) : ""], ["Signals fired", d.signals_fired.map(nice).join(", ") || "none"], ["Simulated by you", d.simulated_fields.join(", ")], ["AI read the reference", d.ai_reference_read && d.ai_reference_read.status === "ai" ? (Object.entries(d.ai_reference_read).filter(([, v]) => v === true).map(([k]) => nice(k)).join(", ") || "nothing concerning") : ""]]))));
    if (r.engine_action !== r.action && r.action === "allow") card.append(h("div", { class: "note", text: "Monitor mode: the engine would have chosen \"" + nice(r.engine_action) + "\", but the payment was not stopped. The decision is sealed for any later complaint." }));
    card.append(h("p", { class: "small mute", text: d.missing_data.length + " inputs were unknown and scored 0, because a website can't see them." }));
  }
  if (r.watch) card.append(h("div", { class: "note w", text: "This account is on AI watch: " + money(r.watch.money_out) + " has gone out against a limit of $" + r.watch.limit + "." }));
  const row = h("p", { class: "row" });
  if (r.approve_url) { let ok = false; try { ok = new URL(r.approve_url).hostname.endsWith(".paypal.com"); } catch (e) { /* bad url */ } if (ok) row.append(h("a", { class: "btn", href: r.approve_url, rel: "noopener", text: "Pay with PayPal sandbox" })); }
  row.append(h("button", { class: "btn sec", text: "Show the sealed record", onclick: () => showSealed(r.payment_id) })); card.append(row);
  return card;
}
async function showSealed(id) {
  try { const s = await api("/app/payments/" + id + "/sealed");
    openDrawer("Sealed record for payment #" + id, h("div", {}, h("div", { class: "note", text: "This is everything stored about the decision. The score and evidence are inside the ciphertext; without the server's key nobody can read or alter them unnoticed." }),
      kv([["Record number", s.record_number], ["Method", s.how], ["Key id", s.key_id], ["Previous record hash", h("span", { class: "mono", text: s.previous_record_hash })], ["This record hash", h("span", { class: "mono", text: s.this_record_hash })], ["Signature", h("span", { class: "mono", text: s.signature })], ["Ciphertext (" + s.ciphertext_bytes + " bytes)", h("span", { class: "mono", text: s.ciphertext_preview })], ["Encrypted inside", s.inside_encrypted.join(", ")]])));
  } catch (e) { toast(e.message); }
}
function myPayments() {
  const rows = (state.me ? state.me.payments : []).map((p) => {
    const act = h("div", { class: "row" });
    if (p.demo_history) act.append(h("span", { class: "small mute", text: "demo history" }));
    if (p.status === "awaiting_approval" || p.status === "scored") act.append(h("button", { class: "btn sm", text: "Continue to PayPal", onclick: async () => { try { const r = await api("/app/payments/" + p.id + "/approve-link"); location.href = r.approve_url; } catch (e) { toast(e.message); } } }));
    if (p.status === "capturing") act.append(h("button", { class: "btn sm", text: "Finish payment", onclick: () => capture(p.id) }));
    if (p.status === "awaiting_confirmation" || p.status === "delayed") act.append(h("button", { class: "btn sm", text: "Confirm payee", onclick: async () => { const v = await askText("Confirm who you are paying", "Type the payee's handle.", "handle"); if (!v) return; try { const r = await api("/app/payments/" + p.id + "/confirm", "POST", { typed_handle: v }); location.href = r.approve_url; } catch (e) { toast(e.message); } } }));
    if (["awaiting_approval", "awaiting_confirmation", "delayed"].includes(p.status)) act.append(h("button", { class: "btn sec sm", text: "Cancel", onclick: async () => { try { await api("/app/payments/" + p.id + "/cancel", "POST"); go("pay"); } catch (e) { toast(e.message); } } }));
    if (p.status === "captured" && !p.demo_history) act.append(h("button", { class: "btn sec sm", text: "Report a problem", onclick: () => report(p) }));
    if (!p.demo_history) act.append(h("button", { class: "btn sec sm", text: "Sealed record", onclick: () => showSealed(p.id) }));
    return { cells: ["#" + p.id, "@" + p.payee, h("span", { class: "num", text: money(p.amount) }), tag(p.status), act] };
  });
  return rows.length ? table(["Payment", "To", "Amount", "Status", "Actions"], rows) : empty("No payments yet. Pick a scenario and press Check and pay.");
}
async function capture(id) { try { await api("/app/payments/" + id + "/capture", "POST"); toast("Payment #" + id + " completed through the PayPal sandbox."); } catch (e) { toast("Could not complete payment #" + id + ": " + e.message); } }
function report(p) {
  const claim = h("select", { id: "c-claim" }, h("option", { value: "unauthorised", text: "I didn't make this payment" }), h("option", { value: "scam", text: "I was tricked into making it" }));
  const text = h("textarea", { id: "c-text", rows: "4", maxlength: "1000", placeholder: "What happened? For example: who contacted you, whether it's still going on, what the money was for." }); const out = h("p", { role: "status" });
  openDrawer("Report payment #" + p.id, h("div", {}, h("p", { class: "mute", text: money(p.amount) + " to @" + p.payee }), h("label", { for: "c-claim", text: "What happened?" }), claim, h("label", { for: "c-text", text: "Tell us more (optional). The AI reads this into yes/no notes for the reviewer." }), text,
    h("p", { class: "row sp" }, h("button", { class: "btn", text: "Send report", onclick: async (e) => { e.target.disabled = true; try { const r = await api("/app/payments/" + p.id + "/complaint", "POST", { claim: claim.value, text: text.value }); out.className = "okc"; out.textContent = r.message + " Open the Cases tab to see how it was assessed."; await ensureMe(); } catch (err) { out.className = "err"; out.textContent = err.message; e.target.disabled = false; } } })), out));
}

// ------------------------------------------------------------------ transactions and cases
async function transactions() {
  const t = await api("/review/transactions?limit=100"); const q = h("input", { id: "tx-q", placeholder: "Search by id, handle or status", "aria-label": "Search transactions" }); const holder = h("div");
  const draw = () => { const needle = q.value.trim().toLowerCase(); const rows = t.transactions.filter((x) => !needle || [x.id, x.payer, x.payee, x.status, x.band].join(" ").toLowerCase().includes(needle)).map((x) => ({ id: x.id, cells: ["#" + x.id, "@" + x.payer + " → @" + x.payee, h("span", { class: "num", text: money(x.amount) }), h("span", { class: "num", text: x.score == null ? "" : String(x.score) }), x.engine_action ? tag(x.engine_action) : "", tag(x.status), when(x.created_at)] })); holder.replaceChildren(rows.length ? table(["Payment", "From → to", "Amount", "Risk score", "Engine said", "Status", "Created"], rows, (r) => openCase(r.id)) : empty("No transactions match.")); };
  q.addEventListener("input", draw); draw();
  return h("div", {}, head("Transactions", "Every payment attempt with its score. Select a row for the full record."), h("div", { class: "card" }, q, h("div", { class: "sp" }, holder)));
}
async function cases() {
  const q = await api("/review/queue"); const rows = [];
  for (const p of q.held_payments) rows.push({ id: p.id, cells: ["#" + p.id, tag("held"), money(p.amount) + " to @" + p.payee, "Paused before PayPal. Release or decline.", when(p.created_at)] });
  for (const c of q.open_complaints) rows.push({ id: c.payment_id, cells: ["#" + c.payment_id, tag(c.status), nice(c.claim) + " claim", "Priority " + c.queue_priority + " = evidence " + c.consistency_score + (c.ai_priority_bonus ? " + AI " + c.ai_priority_bonus : ""), when(c.filed_at)] });
  return h("div", {}, head("Cases", "Held payments and customer reports, most urgent first. A person decides every one."), h("div", { class: "card" }, rows.length ? table(["Payment", "Status", "Type", "Detail", "Since"], rows, (r) => openCase(r.id)) : empty("Nothing is waiting. Make a payment, complete it at PayPal, then use Report a problem.")));
}
async function openCase(id) {
  state.caseId = id; state.chat = []; openDrawer("Payment #" + id, h("p", { class: "mute", text: "Loading…" }));
  let c; try { c = await api("/review/payments/" + id); } catch (e) { $("drawer-body").replaceChildren(e.status === 401 ? needAccess() : h("p", { class: "err", text: e.message })); return; }
  const body = h("div"); const d = c.decision || {}; const say = h("p", { role: "status" });
  const act = async (fn, okText) => { try { const r = await fn(); say.className = "okc"; say.textContent = typeof okText === "function" ? okText(r) : okText; openCase(id); } catch (e) { say.className = "err"; say.textContent = e.message; } };
  body.append(kv([["Payment", money(c.amount) + " from @" + c.payer + " to @" + c.payee], ["Reference", c.reference || "(none)"], ["Status", tag(c.status)], ["Created", when(c.created_at)]]));
  if (d.score !== undefined) body.append(h("h3", { text: "Decision at the time (opened from the sealed record)" }), h("div", { class: "row" }, h("div", {}, h("div", { class: "score", text: String(d.score) }), tag(d.action)), h("div", { class: "f" }, kv([["Reasons", d.reason_codes.map(nice).join(", ") || "none"], ["Pattern", d.typology ? nice(d.typology) : "none"], ["Combination rules", d.floors_triggered.map(nice).join(", ") || "none"], ["Signals fired", d.signals_fired.map(nice).join(", ") || "none"], ["Simulated in the demo", d.simulated_fields.join(", ")], ["Unknown inputs", String(d.missing_data.length)], ["Sealed at", when(d.sealed_at)]]))), h("p", { class: "small mute", text: d.evidence_note || "" }));
  else if (d.error) body.append(h("p", { class: "err", text: d.error }));
  if (c.status === "held") body.append(h("p", { class: "row" }, h("button", { class: "btn", text: "Release", onclick: () => act(() => api("/review/payments/" + id + "/release", "POST"), "Released. The payer still has to approve at PayPal.") }), h("button", { class: "btn danger", text: "Decline", onclick: () => act(() => api("/review/payments/" + id + "/decline", "POST"), "Declined.") })));
  const k = c.complaint;
  if (k && k.id) {
    const pr = k.queue_priority || {};
    body.append(h("h3", { text: "Customer report" }), kv([["Claim", nice(k.claim)], ["Status", tag(k.status)], ["Customer wrote", k.text || "(nothing)"], ["AI-read notes", Object.entries(k.ai_read_claims || {}).filter(([, v]) => v === true).map(([a]) => nice(a)).join(", ") || (k.ai_status === "ai" ? "none" : "AI not available")], ["Consistency with the sealed record", k.consistency.consistency_score + " / 100 → " + nice(k.consistency.outcome)], ["Queue priority", pr.priority == null ? "" : pr.priority + " = evidence " + pr.from_evidence + " + AI " + pr.ai_bonus + (pr.ai_reasons && pr.ai_reasons.length ? " (" + pr.ai_reasons.join("; ") + ")" : "")], ["Complaint to refund", k.time_to_return_seconds == null ? "" : k.time_to_return_seconds + " seconds"]]));
    body.append(table(["Points", "Check", "Meaning"], k.consistency.checks.map((x) => ({ cells: [(x.points > 0 ? "+" : "") + x.points, x.check, x.meaning] }))));
    if (["fast_tracked", "in_review", "manual_review", "awaiting_second_approval"].includes(k.status)) {
      const amt = h("input", { id: "amt", placeholder: "Type " + c.amount + " to confirm", "aria-label": "Type the amount to confirm the refund" });
      if (k.needs_second_approval) body.append(h("div", { class: "note w", text: k.first_approver ? "First approval by " + k.first_approver + ". A different reviewer must give the second." : "Refunds of this size need two different reviewers." }));
      body.append(h("div", { class: "row sp" }, h("div", { class: "f" }, amt), h("button", { class: "btn", text: "Approve refund", onclick: () => act(() => api("/review/complaints/" + k.id + "/approve", "POST", { confirm_amount: amt.value }), (r) => (r.status === "refunded" ? "Refunded through PayPal in " + r.seconds_from_complaint_to_refund + " seconds." : "First approval recorded.")) }), h("button", { class: "btn danger", text: "Decline", onclick: () => act(() => api("/review/complaints/" + k.id + "/decline", "POST"), "Declined.") })));
    }
  }
  body.append(say, h("h3", { text: "Ask the AI about this case" }), chatBox(id), h("h3", { text: "Timeline" }), table(["When", "Who", "What"], c.timeline.map((e) => ({ cells: [when(e.at), e.actor + (e.details && e.details.by ? " (" + e.details.by + ")" : ""), nice(e.action)] }))));
  $("drawer-body").replaceChildren(body);
}
const QUESTIONS = ["Summarise this case in two sentences.", "Why did the engine score it this way?", "What does the customer's report say, and does the record support it?", "What is missing from the evidence?"];
function chatBox(id, askPath) {
  const log = h("div", { class: "chat", "aria-live": "polite" }); const input = h("input", { placeholder: "Ask a question about this record", "aria-label": "Question for the AI" });
  const send = async (q) => { if (!q) return; log.append(h("div", { class: "msg q", text: q })); input.value = ""; const wait = h("div", { class: "msg a", text: "Thinking…" }); log.append(wait); log.scrollTop = log.scrollHeight;
    try { const r = await api(askPath || "/review/payments/" + id + "/ask", "POST", { question: q }); wait.textContent = r.text; wait.append(h("span", { class: "src", text: r.source === "ai_checked" ? "AI-written from the record, passed the fabrication checks. It can't approve, decline or move money." : "Shown from the record itself (" + r.rejected_because.join("; ") + ")." })); } catch (e) { wait.textContent = e.message; wait.classList.add("err"); } log.scrollTop = log.scrollHeight; };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") send(input.value.trim()); });
  return h("div", {}, h("div", { class: "row" }, QUESTIONS.map((q) => h("button", { class: "btn sec sm", text: q, onclick: () => send(q) }))), log, h("div", { class: "row" }, h("div", { class: "f" }, input), h("button", { class: "btn", text: "Ask", onclick: () => send(input.value.trim()) })));
}
async function copilot() {
  const t = await api("/review/transactions?limit=30"); const pick = h("select", { id: "cp-pick", "aria-label": "Choose a payment" }, t.transactions.map((x) => h("option", { value: x.id, text: "#" + x.id + " · " + money(x.amount) + " · @" + x.payer + " → @" + x.payee + " · " + nice(x.status) }))); const holder = h("div");
  const draw = () => holder.replaceChildren(pick.value ? chatBox(pick.value) : empty("No payments yet."));
  pick.addEventListener("change", draw); draw();
  return h("div", {}, head("AI Copilot", "Ask about any payment. Answers are written from that payment's record and checked before you see them."), h("div", { class: "note", text: "The AI explains; it never decides. An answer containing a number that isn't in the record, or a verdict, is replaced by the plain record." }), h("div", { class: "card" }, h("label", { for: "cp-pick", text: "Payment" }), pick, h("div", { class: "sp" }, holder)));
}

// ------------------------------------------------------------------ watch, risk, evidence, audit, settings
async function watch() {
  const w = await api("/review/watch"); const cards = w.accounts.map((a) => {
    const bar = h("div", { class: "bar " + (a.stopped ? "b" : "w") }, h("i")); bar.firstChild.style.width = Math.min(100, Math.round((Number(a.money_out_since) / Math.max(1, a.limit)) * 100)) + "%";
    return h("div", { class: "card" }, h("div", { class: "row" }, h("h3", { class: "f", text: "@" + a.account }), a.stopped ? tag("payments paused", "bad") : tag("watching", "warn"), h("button", { class: "btn sec sm", text: "End watch", onclick: async () => { try { await api("/review/watch/" + a.account + "/clear", "POST"); go("watch"); } catch (e) { toast(e.message); } } })),
      kv([["On watch since", when(a.on_watch_since)], ["Triggered by", "a payment scoring " + a.trigger_score + " (" + (a.trigger_reasons || []).map(nice).join(", ") + ")"], ["Money out since", money(a.money_out_since) + " of a $" + a.limit + " limit, in " + a.payments_since + " attempt(s)"]]), bar,
      h("h3", { class: "sp", text: "Where the money went (crawler)" }), a.where_it_went.length ? table(["Account", "Received", "Then paid", "Graph findings"], a.where_it_went.map((x) => ({ cells: ["@" + x.account, money(x.received_from_watched_account), x.then_paid.join(", ") || "nothing yet", x.findings.join("; ") || "none"] }))) : empty("Nothing has left the account since the watch began."),
      h("h3", { class: "sp", text: "Ask the AI about this account" }), chatBox(null, "/review/watch/" + a.account + "/ask"));
  });
  return h("div", {}, head("AI watch", "After a risky payment the account is watched. Payments pause only when too much money leaves.", h("button", { class: "btn sec", text: "Refresh", onclick: () => go("watch") })),
    h("div", { class: "note", text: w.enabled ? "A payment scoring " + w.watch_score + " or more starts a " + w.hours + "-hour watch. Once more than $" + w.outflow_limit_usd + " has gone out, further payments are paused and the crawler traces where the money went." : "The watch is switched off on this server (WATCH_OUTFLOW_USD is 0)." }), cards.length ? cards : h("div", { class: "card" }, empty("No account is on watch. In Send money, run \"Coached scam\" and then send more payments from the same account.")));
}
async function risk() {
  const c = state.cfg;
  return h("div", {}, head("Risk engine", "47 named signals in 9 categories, fixed points, a cap per category, and combination rules."),
    h("div", { class: "grid g2" }, h("div", { class: "card" }, h("h3", { text: "Score bands" }), table(["Score", "Level", "Engine's action"], [["0–29", "Low", "allow"], ["30–59", "Medium", "step_up"], ["60–79", "High", "hold_review"], ["80–100", "Critical", "block"]].map((r) => ({ cells: [r[0], r[1], tag(r[2])] }))), h("p", { class: "small mute", text: c.enforcement === "monitor" ? "This server is in monitor mode: the action is recorded, not applied." : "This server applies the action." })),
      h("div", { class: "card" }, h("h3", { text: "Combination rules (minimum scores)" }), table(["Rule", "Minimum"], [["Account takeover", 85], ["Mule account", 80], ["Card testing", 80], ["Device farm", 75], ["Authorised (coached) scam", 70], ["Confirmed-fraud recipient", 60]].map((r) => ({ cells: r }))))),
    h("div", { class: "card" }, h("h3", { text: "What the engine can see" }), table(["Signals", "Source"], [["26", "Computed from this app's own ledger and the browser"], ["7", "Simulated by the demo switches, and recorded as simulated"], ["14", "Never available here (card, issuer, location, identity checks): scored 0"]].map((r) => ({ cells: r })))),
    h("div", { class: "note w", text: "Measured on simulated payments (see BENCHMARK.md in the repository): on fraud the rules were not written around, the engine slowed or stopped 0% of cases. A score is a reason to look, never a confirmed fraud finding." }));
}
async function evidence() {
  const out = h("pre", { class: "mono wrap", role: "status" }); const show = async (fn) => { try { out.textContent = JSON.stringify(await fn(), null, 2); } catch (e) { out.textContent = e.status === 401 ? "Reviewer access is needed (see Settings)." : e.message; } };
  let cp = null;
  return h("div", {}, head("Evidence", "Each decision is encrypted, signed and chained to the one before it. So is the audit log."),
    h("div", { class: "card" }, h("h3", { text: "Check the records" }), h("div", { class: "row" }, h("button", { class: "btn", text: "Verify decision chain", onclick: () => show(() => api("/risk/verify", "POST", { checkpoint: cp })) }), h("button", { class: "btn sec", text: "Take a checkpoint", onclick: () => show(async () => { cp = await api("/risk/checkpoint"); return { ...cp, note: "Kept in this tab. Verify again to check against it; in real use, save it outside the database." }; }) }), h("button", { class: "btn sec", text: "Verify audit chain", onclick: () => show(() => api("/review/audit/verify" + (cp ? "?expected_count=" + cp.audit_count : ""))) }), h("button", { class: "btn sec", text: "Measured outcomes", onclick: () => show(() => api("/risk/labels")) }), h("button", { class: "btn sec", text: "Scam library", onclick: () => show(() => api("/risk/scam-library")) })), out),
    h("div", { class: "note", text: "To see one sealed record, open Send money and press \"Sealed record\" on any payment. Limit: the keys are held by this server, so the records are tamper-evident against database changes, not against someone who controls the server." }));
}
async function auditLog() {
  const a = await api("/review/audit?include_reads=true&limit=200"); const q = h("input", { placeholder: "Filter by person, action or payment", "aria-label": "Filter the audit log" }); const holder = h("div");
  const draw = () => { const n = q.value.trim().toLowerCase(); const rows = a.actions.filter((x) => !n || [x.by, x.action, x.subject].join(" ").toLowerCase().includes(n)).map((x) => ({ cells: [when(x.at), x.by, nice(x.action), x.subject, x.reason || ""] })); holder.replaceChildren(rows.length ? table(["When (UTC)", "Who", "Action", "Subject", "Reason"], rows) : empty("No entries.")); };
  q.addEventListener("input", draw); draw();
  return h("div", {}, head("Audit log", "Who did what and who opened which case. Entries are chained and signed, and nothing here can edit them."), h("div", { class: "card" }, q, h("div", { class: "sp" }, holder)));
}
async function settings() {
  await ensureMe(); const key = h("input", { id: "key", type: "password", autocomplete: "off", value: state.key }); const flag = h("input", { id: "flag", placeholder: "handle, e.g. demo_shop" });
  return h("div", {}, head("Settings", "This browser's demo account and access."),
    h("div", { class: "card" }, h("h3", { text: "Demo account" }), state.me ? kv([["Signed in as", "@" + state.me.handle], ["This browser's device id", state.device.slice(0, 8) + "…"]]) : empty("No account yet."),
      h("div", { class: "row" }, !state.me ? h("button", { class: "btn", text: "Start demo", onclick: async () => { try { await startDemo(); go("settings"); } catch (e) { toast(e.message); } } }) : null,
        h("button", { class: "btn sec", text: "Pretend to use a different device", onclick: () => { newDevice(); toast("New device id for this browser."); go("settings"); } }),
        state.me ? h("button", { class: "btn sec", text: "Record a password change", onclick: async () => { try { await api("/app/me/credentials", "POST", { device_id: state.device }); toast("Recorded: password changed from this device."); } catch (e) { toast(e.message); } } }) : null,
        state.me ? h("button", { class: "btn sec", text: "Start over with a new account", onclick: () => { state.token = ""; store.set("is_token", ""); state.me = null; chips(); go("pay"); } }) : null)),
    h("div", { class: "card" }, h("h3", { text: "Reviewer access" }), h("p", { class: "mute", text: state.cfg.public_demo ? "Public demo mode is on: reviewer screens are open to everyone as \"judge\". No key is needed." : "Enter a reviewer or owner key. It is kept in this tab only." }), state.cfg.public_demo ? null : h("div", { class: "row" }, h("div", { class: "f" }, h("label", { for: "key", text: "Key" }), key), h("button", { class: "btn", text: "Use key", onclick: () => { state.key = key.value.trim(); toast("Key set for this tab."); } }))),
    h("div", { class: "card" }, h("h3", { text: "Reset between demo runs" }), h("p", { class: "mute", text: "After a refund is approved, the payee counts as confirmed fraud and later payments to it are paused. Clearing the flag is recorded in the audit log." }), h("div", { class: "row" }, h("div", { class: "f" }, flag), h("button", { class: "btn sec", text: "Clear fraud flag", onclick: async () => { try { await api("/risk/fraud-flag/" + encodeURIComponent(flag.value.trim()) + "/clear", "POST", { reason: "demo reset from the console" }); toast("Cleared."); } catch (e) { toast(e.message); } } }))),
    h("div", { class: "card" }, h("h3", { text: "This server" }), kv([["Environment", state.cfg.environment], ["Mode", state.cfg.enforcement], ["AI watch", state.cfg.watch_outflow_usd > 0 ? "score " + state.cfg.watch_score + "+, limit $" + state.cfg.watch_outflow_usd + ", " + state.cfg.watch_hours + " hours" : "off"], ["Two-person refunds from", "$" + state.cfg.refund_second_approval_usd], ["Classic pages", h("span", {}, h("a", { href: "/review", text: "/review" }), " · ", h("a", { href: "/docs", text: "API docs" }))]])));
}
const VIEWS = { overview, pay, transactions, cases, watch, risk, evidence, copilot, audit: auditLog, settings };

function openDrawer(title, body) { $("drawer-title").textContent = title; $("drawer-body").replaceChildren(body); $("drawer").classList.remove("hide"); $("drawer-close").focus(); }
$("drawer-close").addEventListener("click", () => { $("drawer").classList.add("hide"); if (["cases", "transactions", "pay"].includes(state.tab)) go(state.tab); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("drawer").classList.add("hide"); });
$("menu").addEventListener("click", () => $("side").classList.toggle("open"));

(async function boot() {
  try { state.cfg = await api("/app/config"); } catch (e) { state.cfg = {}; }
  await ensureMe(); nav(); chips();
  const q = new URLSearchParams(location.search);
  if (q.get("pay") && state.token) { history.replaceState(null, "", "/app"); await capture(parseInt(q.get("pay"), 10)); await ensureMe(); return go("pay"); }
  if (q.get("cancel") && state.token) { history.replaceState(null, "", "/app"); try { await api("/app/payments/" + parseInt(q.get("cancel"), 10) + "/cancel", "POST"); } catch (e) { /* already closed */ } return go("pay"); }
  go(state.me ? "overview" : "pay");
})();
