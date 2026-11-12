"use strict";
const $ = (id) => document.getElementById(id);
let key = "";
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function button(label, fn, cls) { const b = el("button", label, cls); b.addEventListener("click", fn); return b; }
function show(id, on) { $(id).classList.toggle("hide", !on); }
async function api(path, method, body) {
  const r = await fetch(path, { method: method || "GET", headers: { "Content-Type": "application/json", "X-API-Key": key }, body: body ? JSON.stringify(body) : undefined });
  let data = {}; try { data = await r.json(); } catch (e) { /* no body */ }
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request failed (" + r.status + ")");
  return data;
}
function pill(status) { return el("span", status.replace(/_/g, " "), "pill " + status); }

async function loadQueue() {
  const q = await api("/review/queue");
  show("queue", true); show("recent", true); show("chain", true);
  const rows = $("q-rows"); rows.replaceChildren();
  for (const p of q.held_payments) {
    const tr = el("tr"); tr.append(el("td", "#" + p.id), el("td", "Held payment"), el("td", "$" + p.amount + " to @" + p.payee));
    const a = el("td"); a.append(button("Open", () => openCase(p.id))); tr.append(a); rows.append(tr);
  }
  for (const c of q.open_complaints) {
    const tr = el("tr"); tr.append(el("td", "#" + c.payment_id), el("td"), el("td", "consistency " + c.consistency_score + " · " + c.claim));
    tr.children[1].append(pill(c.status));
    const a = el("td"); a.append(button("Open", () => openCase(c.payment_id))); tr.append(a); rows.append(tr);
  }
  $("q-empty").textContent = rows.children.length ? "" : "Nothing waiting.";
  const rec = $("r-rows"); rec.replaceChildren();
  for (const p of q.recent_payments) {
    const tr = el("tr"); tr.append(el("td", String(p.id)), el("td", "@" + p.payee), el("td", "$" + p.amount));
    const s = el("td"); s.append(pill(p.status)); tr.append(s);
    const a = el("td"); a.append(button("Open", () => openCase(p.id), "ghost")); tr.append(a); rec.append(tr);
  }
}
function kv(label, value, cls) { const p = el("p"); p.append(el("span", label + ": ", "mute"), el("span", value, cls)); return p; }

async function openCase(id) {
  const c = await api("/review/payments/" + id);
  const body = $("case-body"); body.replaceChildren(); show("case", true);
  $("case-id").textContent = "#" + id;
  body.append(kv("Payment", "$" + c.amount + " " + c.currency + " from @" + c.payer + " to @" + c.payee), kv("Reference", c.reference || "(none)"), kv("Status", c.status));
  const d = c.decision;
  if (d && d.score !== undefined) {
    body.append(el("h2", "Decision at the time (sealed)"));
    const row = el("div", undefined, "row"); const s = el("div"); s.append(el("div", String(d.score), "score"), pill(d.action));
    const w = el("div"); w.append(kv("Reasons", d.reason_codes.join(", ") || "none"), kv("Type", d.typology || "none"), kv("Combination rules", d.floors_triggered.join(", ") || "none"), kv("Trust reductions", (d.reductions || []).join(", ") || "none"));
    row.append(s, w); body.append(row);
    body.append(kv("Signals fired", d.signals_fired.join(", ") || "none", "mono"), kv("Unknown inputs (scored 0)", d.missing_data.join(", ") || "none", "mono"));
    if (d.evidence_note) body.append(el("p", d.evidence_note, "tag"));
    if (d.simulated_fields.length) body.append(kv("Simulated in the demo", d.simulated_fields.join(", "), "tag"));
  } else if (d) body.append(el("p", d.error, "err"));
  if (c.complaint) {
    const k = c.complaint; body.append(el("h2", "Complaint"));
    body.append(kv("Claim", k.claim), kv("Customer wrote (untrusted text)", k.text || "(nothing)"), kv("Status", k.status));
    const ai = Object.entries(k.ai_read_claims).map(([a, b]) => a + "=" + b).join(", ") || "none";
    body.append(kv("AI-read notes (" + (k.ai_status || "n/a") + ")", ai, "mono"));
    body.append(kv("Consistency with the sealed record", k.consistency.consistency_score + "/100 → " + k.consistency.outcome.replace(/_/g, " ")));
    const t = el("table"); t.append(Object.assign(el("thead"), {}));
    for (const ch of k.consistency.checks) { const tr = el("tr"); tr.append(el("td", (ch.points > 0 ? "+" : "") + ch.points), el("td", ch.check), el("td", ch.meaning, "mute")); t.append(tr); }
    body.append(t);
    if (k.time_to_return_seconds !== undefined) body.append(kv("Complaint to refund", k.time_to_return_seconds + " seconds", "pill refunded"));
    if (["fast_tracked", "in_review", "manual_review"].includes(k.status)) {
      const amt = el("input"); amt.placeholder = "Type " + c.amount + " to confirm"; amt.style.maxWidth = "200px";
      const msg = el("span", "", "mute"); body.append(el("p"));
      const act = el("p"); act.append(amt, " ",
        button("Approve refund (PayPal sandbox)", async () => { try { const r = await api("/review/complaints/" + k.id + "/approve", "POST", { confirm_amount: amt.value }); msg.textContent = "Refunded in " + r.seconds_from_complaint_to_refund + "s"; await openCase(id); await loadQueue(); } catch (e) { msg.textContent = e.message; msg.className = "err"; } }), " ",
        button("Decline", async () => { try { await api("/review/complaints/" + k.id + "/decline", "POST"); await openCase(id); await loadQueue(); } catch (e) { msg.textContent = e.message; msg.className = "err"; } }, "ghost"), " ", msg);
      body.append(act);
    }
  }
  if (c.status === "held") {
    const msg = el("span", "", "mute"); const act = el("p");
    act.append(button("Release (payer still approves at PayPal)", async () => { try { await api("/review/payments/" + id + "/release", "POST"); await openCase(id); await loadQueue(); } catch (e) { msg.textContent = e.message; } }), " ",
      button("Decline", async () => { try { await api("/review/payments/" + id + "/decline", "POST"); await openCase(id); await loadQueue(); } catch (e) { msg.textContent = e.message; } }, "ghost"), " ", msg);
    body.append(act);
  }
  body.append(el("h2", "Timeline"));
  const tl = el("table");
  for (const e of c.timeline) { const tr = el("tr"); tr.append(el("td", e.at.replace("T", " ").slice(0, 19), "mono"), el("td", e.actor), el("td", e.action.replace(/_/g, " "))); tl.append(tr); }
  body.append(tl); $("case").scrollIntoView();
}
$("load").addEventListener("click", async () => {
  $("err").textContent = ""; key = $("key").value.trim();
  try { await loadQueue(); } catch (e) { $("err").textContent = e.message; }
});
$("verify").addEventListener("click", async () => {
  const saved = prompt("Paste a saved checkpoint (JSON) to also detect removed records, or leave empty:");
  let cp = null; if (saved) { try { cp = JSON.parse(saved); } catch (e) { alert("That isn't valid JSON."); return; } }
  try { $("chain-out").textContent = JSON.stringify(await api("/risk/verify", "POST", { checkpoint: cp }), null, 2); } catch (e) { $("chain-out").textContent = e.message; }
});
$("ckpt").addEventListener("click", async () => { try { $("chain-out").textContent = JSON.stringify(await api("/risk/checkpoint"), null, 2) + "\n\nSave this OUTSIDE the database."; } catch (e) { $("chain-out").textContent = e.message; } });
$("lib").addEventListener("click", async () => { try { $("chain-out").textContent = JSON.stringify(await api("/risk/scam-library"), null, 2); } catch (e) { $("chain-out").textContent = e.message; } });
