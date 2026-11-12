"use strict";
const $ = (id) => document.getElementById(id);
const store = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } },
};
const SIM_FIELDS = {
  active_call: "On a phone call", remote_access_or_overlay: "Remote-access tool or overlay",
  device_compromised: "Device flagged compromised", credentials_in_breach: "Credentials in a known breach",
  anonymising_asn: "VPN / anonymising network", on_negative_list: "Payee on a shared fraud list",
  network_risk_score_high: "Network flagged high risk",
};
let token = store.get("is_token");
let deviceId = store.get("is_device") || newDeviceId();
let demo = false;
const started = Date.now();
const beh = { keys: 0, firstKey: 0, lastKey: 0, pasted: false, blur: 0, pauses: 0 };

function newDeviceId() {
  const a = new Uint8Array(16); crypto.getRandomValues(a);
  const id = Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
  store.set("is_device", id); return id;
}
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
async function api(path, method, body) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  const r = await fetch(path, { method: method || "GET", headers, body: body ? JSON.stringify(body) : undefined });
  let data = {}; try { data = await r.json(); } catch (e) { /* no body */ }
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request failed (" + r.status + ")");
  return data;
}

// ---- behaviour measurements: aggregates only, never the keys themselves
for (const id of ["p-handle", "p-name", "p-amount", "p-ref"]) {
  const n = $(id);
  n.addEventListener("keydown", () => {
    const t = Date.now();
    if (!beh.firstKey) beh.firstKey = t;
    if (beh.lastKey && t - beh.lastKey > 5000) beh.pauses += 1;
    beh.lastKey = t; beh.keys += 1;
  });
  n.addEventListener("paste", () => { beh.pasted = true; });
}
window.addEventListener("blur", () => { beh.blur += 1; });
function behaviour() {
  const span = beh.lastKey && beh.firstKey ? (beh.lastKey - beh.firstKey) / 1000 : 0;
  return {
    typing_cps: span > 0.5 ? Math.round((beh.keys / span) * 10) / 10 : null,
    paste_used: beh.pasted, seconds_on_page: Math.round((Date.now() - started) / 100) / 10,
    blur_count: beh.blur, pause_count: beh.pauses,
  };
}
function fingerprint() {
  return { ua: navigator.userAgent, platform: navigator.platform || "", lang: navigator.language || "",
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone || "", screen: screen.width + "x" + screen.height };
}

// ---- screens
function show(id, on) { $(id).classList.toggle("hide", !on); }
async function loadMe() {
  const me = await api("/app/me");
  demo = me.demo_mode;
  $("me-handle").textContent = "@" + me.handle; $("me-name").textContent = me.display_name;
  $("device-line").textContent = "This browser's device id: " + deviceId.slice(0, 8) + "…";
  show("signup", false); show("account", true); show("pay", true); show("payments", true); show("sim", demo); show("guide", demo); show("demo-hist", demo && me.payments.length === 0);
  const tbody = $("pay-rows"); tbody.replaceChildren();
  for (const p of me.payments) {
    const tr = el("tr");
    tr.append(el("td", String(p.id)), el("td", "@" + p.payee), el("td", "$" + p.amount));
    const st = el("td"); st.append(el("span", p.status.replace(/_/g, " "), "pill " + p.status)); tr.append(st);
    const act = el("td");
    if (p.status === "awaiting_confirmation" || p.status === "delayed") act.append(button("Confirm payee", () => confirmFlow(p)));
    if (p.status === "capturing") act.append(button("Finish payment", async () => { try { await api("/app/payments/" + p.id + "/capture", "POST"); await loadMe(); } catch (e) { alert(e.message); } }));
    if (p.status === "awaiting_approval" || p.status === "scored") act.append(button("Continue to PayPal", () => resumeOrder(p.id)));
    if (p.status === "captured") act.append(button("Report a problem", () => openComplaint(p.id)));
    if (["awaiting_confirmation", "delayed", "awaiting_approval"].includes(p.status)) act.append(" ", button("Cancel", () => cancelPay(p.id), "ghost"));
    tr.append(act); tbody.append(tr);
  }
}
function button(label, fn, cls) { const b = el("button", label, cls); b.addEventListener("click", fn); return b; }

function renderDecision(res) {
  const box = $("result-body"); box.replaceChildren(); show("result", true);
  box.append(el("p", res.message));
  const d = res.decision;
  if (d) {
    const top = el("div", undefined, "row");
    const s = el("div"); s.append(el("div", String(d.score), "score"), el("span", d.action.replace(/_/g, " "), "pill " + d.band));
    const w = el("div"); w.append(el("div", "Why", "mute"), el("div", d.reason_codes.join(", ") || "nothing unusual"));
    if (d.typology) w.append(el("div", "Looks like: " + d.typology.replace(/_/g, " "), "mute"));
    top.append(s, w); box.append(top);
    if (d.floors_triggered.length) box.append(el("p", "Combination rule triggered: " + d.floors_triggered.join(", "), "mute"));
    box.append(el("p", "Signals fired: " + (d.signals_fired.join(", ") || "none"), "mute mono"));
    if (d.ai_reference_read && d.ai_reference_read.status === "ai") box.append(el("p", "AI read your reference: " + (Object.entries(d.ai_reference_read).filter(([k, v]) => v === true).map(([k]) => k.replace(/_/g, " ")).join(", ") || "nothing concerning"), "mute"));
    if (d.simulated_fields.length) box.append(el("p", "Simulated by you: " + d.simulated_fields.join(", "), "tag"));
    box.append(el("p", d.missing_data.length + " inputs were unknown and scored 0 (the app can't see them); this decision is sealed and can't be edited afterwards.", "mute"));
  }
  if (res.approve_url) {
    let okUrl = false; try { okUrl = new URL(res.approve_url).hostname.endsWith(".paypal.com"); } catch (e) { /* bad url */ }
    if (!okUrl) { box.append(el("p", "PayPal returned an unexpected link, so it was not opened.", "err")); return; }
    const go = el("a", "Pay with PayPal sandbox →"); go.href = res.approve_url; go.rel = "noopener"; go.className = "pill allow"; box.append(go);
    box.append(el("p", "Approve with a sandbox buyer account. You'll come back here and the payment completes.", "mute"));
  }
}
async function confirmFlow(p) {
  const handle = prompt("Type the payee's handle to confirm who you are paying:");
  if (!handle) return;
  try { renderDecision({ message: "Confirmed.", ...(await api("/app/payments/" + p.id + "/confirm", "POST", { typed_handle: handle })) }); await loadMe(); }
  catch (e) { alert(e.message); }
}
async function resumeOrder(id) {
  try { const r = await api("/app/payments/" + id + "/approve-link"); renderDecision({ message: "Continue to PayPal to pay.", approve_url: r.approve_url }); }
  catch (e) { alert(e.message); }
}
async function cancelPay(id) { try { await api("/app/payments/" + id + "/cancel", "POST"); await loadMe(); } catch (e) { alert(e.message); } }
let complaintFor = null;
function openComplaint(id) { complaintFor = id; $("c-id").textContent = "#" + id; $("c-msg").textContent = ""; show("complaint", true); $("complaint").scrollIntoView(); }

$("su-go").addEventListener("click", async () => {
  $("su-err").textContent = "";
  try {
    const r = await api("/app/signup", "POST", { handle: $("su-handle").value.trim(), display_name: $("su-name").value.trim() });
    token = r.token; store.set("is_token", token); await loadMe();
  } catch (e) { $("su-err").textContent = e.message; }
});
$("demo-hist").addEventListener("click", async () => { try { await api("/app/demo/history", "POST", { device_id: deviceId }); await loadMe(); } catch (e) { alert(e.message); } });
$("new-device").addEventListener("click", () => { deviceId = newDeviceId(); $("device-line").textContent = "New device id: " + deviceId.slice(0, 8) + "…"; });
$("chg-cred").addEventListener("click", async () => { try { await api("/app/me/credentials", "POST", { device_id: deviceId }); alert("Recorded: password changed from this device."); } catch (e) { alert(e.message); } });
for (const [k, label] of Object.entries(SIM_FIELDS)) {
  const w = el("label"); const c = document.createElement("input"); c.type = "checkbox"; c.id = "sim-" + k; c.style.width = "auto"; c.style.marginRight = "6px";
  w.append(c, label); $("sim-boxes").append(w);
}
$("pay-go").addEventListener("click", async () => {
  $("pay-err").textContent = ""; $("pay-go").disabled = true;
  const simulated = {};
  if (demo) {
    for (const k of Object.keys(SIM_FIELDS)) if ($("sim-" + k).checked) simulated[k] = true;
    const swap = $("sim-swap").value.trim(); if (swap !== "" && /^\d+$/.test(swap)) simulated.sim_swap_days_ago = parseInt(swap, 10);
  }
  try {
    const res = await api("/app/payments", "POST", {
      payee_handle: $("p-handle").value.trim(), payee_name: $("p-name").value.trim(), amount: $("p-amount").value.trim(),
      reference: $("p-ref").value, device_id: deviceId, fingerprint: fingerprint(), behaviour: behaviour(), simulated,
    });
    renderDecision(res); await loadMe();
  } catch (e) { $("pay-err").textContent = e.message; } finally { $("pay-go").disabled = false; }
});
$("c-go").addEventListener("click", async () => {
  try {
    const r = await api("/app/payments/" + complaintFor + "/complaint", "POST", { claim: $("c-claim").value, text: $("c-text").value });
    $("c-msg").textContent = r.message;
  } catch (e) { $("c-msg").textContent = e.message; }
});
$("c-cancel").addEventListener("click", () => show("complaint", false));

// ---- coming back from PayPal: ?pay=<id> means approved, ?cancel=<id> means the payer backed out
(async function init() {
  if (!token) return;
  try { await loadMe(); } catch (e) { token = null; store.set("is_token", ""); return; }
  const q = new URLSearchParams(location.search);
  if (q.get("pay")) {
    history.replaceState(null, "", "/app");
    try { const r = await api("/app/payments/" + parseInt(q.get("pay"), 10) + "/capture", "POST"); renderDecision({ message: "Payment completed through the PayPal sandbox. The payee was credited in this app's ledger (simulated)." }); await loadMe(); }
    catch (e) { renderDecision({ message: "Could not complete the payment: " + e.message }); }
  } else if (q.get("cancel")) {
    history.replaceState(null, "", "/app"); try { await api("/app/payments/" + parseInt(q.get("cancel"), 10) + "/cancel", "POST"); await loadMe(); } catch (e) { /* already closed */ }
  }
})();
