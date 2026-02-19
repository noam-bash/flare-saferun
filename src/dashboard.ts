import { createServer } from "http";
import { readFileSync } from "fs";
import { resolve } from "path";
import { homedir } from "os";
import { createJsonlStore, type LogStore, type LogQuery } from "./log-store.js";

const DEFAULT_LOG_PATH = resolve(homedir(), ".flare", "logs", "assess.jsonl");

function getLogPath(): string {
  const arg = process.argv[2];
  if (arg) return resolve(arg);

  try {
    const configPath = resolve(import.meta.dirname ?? ".", "..", "config.json");
    const config = JSON.parse(readFileSync(configPath, "utf-8"));
    if (typeof config.logFile === "string" && config.logFile) {
      const p = config.logFile;
      if (p.startsWith("~/")) return resolve(homedir(), p.slice(2));
      return resolve(p);
    }
  } catch {}

  return DEFAULT_LOG_PATH;
}

function parseQuery(url: URL): LogQuery {
  const q: LogQuery = {};
  const p = url.searchParams;
  if (p.has("search")) q.search = p.get("search")!;
  if (p.has("risk")) q.risk = p.get("risk") as LogQuery["risk"];
  if (p.has("action")) q.action = p.get("action") as LogQuery["action"];
  if (p.has("partial")) q.partial = p.get("partial") === "true";
  if (p.has("from")) q.from = p.get("from")!;
  if (p.has("to")) q.to = p.get("to")!;
  if (p.has("sort")) q.sort = p.get("sort")!;
  if (p.has("order")) q.order = p.get("order") as "asc" | "desc";
  if (p.has("limit")) q.limit = parseInt(p.get("limit")!, 10);
  if (p.has("offset")) q.offset = parseInt(p.get("offset")!, 10);
  if (p.has("after")) q.after = p.get("after")!;
  return q;
}

function startServer(store: LogStore, port: number) {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);

    if (url.pathname === "/api/logs") {
      const query = parseQuery(url);
      const result = store.query(query);
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(result));
      return;
    }

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(HTML);
  });

  server.listen(port, "127.0.0.1", () => {
    console.log(`Flare dashboard → http://localhost:${port}`);
    console.log(`Reading logs from: ${logPath}`);
  });
}

const logPath = getLogPath();
const store = createJsonlStore(logPath);
const PORT = parseInt(process.env.PORT ?? "6040", 10);
startServer(store, PORT);

// ---------------------------------------------------------------------------
// Inline HTML dashboard
// ---------------------------------------------------------------------------
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Flare</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #fafafa;
    --surface: #fff;
    --border: #e2e2e2;
    --text: #1a1a1a;
    --text-dim: #666;
    --mono: "SF Mono", "Cascadia Code", "Fira Code", Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --none: #8b8b8b;
    --low: #3b82f6;
    --medium: #d97706;
    --high: #dc2626;
    --critical: #7c2d12;
    --radius: 4px;
  }

  body { font-family: var(--sans); font-size: 13px; color: var(--text); background: var(--bg); line-height: 1.5; }

  header {
    padding: 12px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    display: flex;
    align-items: center;
    gap: 12px;
  }
  header h1 { font-size: 14px; font-weight: 600; letter-spacing: -0.01em; }
  .meta { color: var(--text-dim); font-size: 12px; }

  .controls {
    padding: 10px 24px;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  .controls input, .controls select {
    font-family: var(--sans); font-size: 12px; padding: 5px 8px;
    border: 1px solid var(--border); border-radius: var(--radius);
    background: var(--bg); color: var(--text); outline: none;
  }
  .controls input:focus, .controls select:focus { border-color: #999; }
  .controls input[type="text"] { width: 220px; }
  .controls input[type="date"] { width: 130px; }
  .controls select { min-width: 80px; }
  .controls label { font-size: 11px; color: var(--text-dim); margin-right: 2px; }
  .fg { display: flex; align-items: center; gap: 4px; }
  .spacer { flex: 1; }
  .live { font-size: 11px; color: var(--text-dim); display: flex; align-items: center; gap: 4px; }
  .dot { width: 6px; height: 6px; border-radius: 50%; background: #22c55e; animation: pulse 2s ease-in-out infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }

  main { padding: 0 24px; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left; font-size: 11px; font-weight: 500; color: var(--text-dim);
    text-transform: uppercase; letter-spacing: .04em; padding: 10px 8px;
    border-bottom: 1px solid var(--border); position: sticky; top: 0;
    background: var(--bg); cursor: pointer; user-select: none; white-space: nowrap;
  }
  th:hover { color: var(--text); }
  th .arr { font-size: 10px; margin-left: 2px; opacity: .35; }
  th .arr.on { opacity: 1; }
  td { padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: #f5f5f5; }
  .c-time { width: 150px; white-space: nowrap; }
  .c-risk { width: 72px; }
  .c-act  { width: 52px; }
  .c-ms   { width: 54px; text-align: right; }
  .c-cmd  { font-family: var(--mono); font-size: 12px; word-break: break-all; }
  .c-p    { width: 20px; text-align: center; }

  .badge {
    display: inline-block; font-size: 11px; font-weight: 600;
    padding: 1px 6px; border-radius: var(--radius);
    text-transform: uppercase; letter-spacing: .02em;
  }
  .r-none     { color: var(--none); background: #f0f0f0; }
  .r-low      { color: var(--low); background: #eff6ff; }
  .r-medium   { color: var(--medium); background: #fffbeb; }
  .r-high     { color: var(--high); background: #fef2f2; }
  .r-critical { color: var(--critical); background: #fef2f2; font-weight: 700; }
  .act { font-size: 11px; color: var(--text-dim); }
  .ms  { font-family: var(--mono); font-size: 12px; color: var(--text-dim); }
  .pw  { color: var(--medium); font-size: 12px; cursor: help; }
  .xp  { cursor: pointer; }

  .dr td { padding: 0 8px 8px; background: #fafafa; border-bottom: 1px solid var(--border); }
  .dr:hover td { background: #fafafa; }
  .db { font-size: 12px; line-height: 1.6; padding: 8px 0; }
  .db .f  { margin-bottom: 4px; }
  .db .fl { font-weight: 500; color: var(--text-dim); margin-right: 4px; }
  .db .fi {
    padding: 4px 8px; margin: 2px 0; background: var(--surface);
    border: 1px solid var(--border); border-radius: var(--radius); font-size: 12px;
  }
  .fs { font-size: 10px; font-weight: 600; text-transform: uppercase; margin-right: 4px; }

  .pager {
    padding: 12px 24px; display: flex; align-items: center; gap: 12px;
    border-top: 1px solid var(--border); font-size: 12px; color: var(--text-dim);
  }
  .pager button {
    font-family: var(--sans); font-size: 12px; padding: 4px 10px;
    border: 1px solid var(--border); border-radius: var(--radius);
    background: var(--surface); color: var(--text); cursor: pointer;
  }
  .pager button:disabled { opacity: .4; cursor: default; }
  .pager button:hover:not(:disabled) { border-color: #999; }

  .empty { text-align: center; padding: 60px 20px; color: var(--text-dim); }
  .empty p { margin-top: 8px; font-size: 12px; }
</style>
</head>
<body>

<header>
  <h1>Flare</h1>
  <span class="meta" id="meta"></span>
</header>

<div class="controls">
  <div class="fg">
    <label>Search</label>
    <input type="text" id="f-search" placeholder="command, cwd, category...">
  </div>
  <div class="fg">
    <label>Risk</label>
    <select id="f-risk"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="none">None</option></select>
  </div>
  <div class="fg">
    <label>Action</label>
    <select id="f-action"><option value="">All</option><option value="ask">Ask</option><option value="warn">Warn</option><option value="run">Run</option></select>
  </div>
  <div class="fg">
    <label>From</label>
    <input type="date" id="f-from">
  </div>
  <div class="fg">
    <label>To</label>
    <input type="date" id="f-to">
  </div>
  <div class="fg">
    <label>Partial</label>
    <select id="f-partial"><option value="">All</option><option value="true">Partial only</option><option value="false">Complete only</option></select>
  </div>
  <div class="spacer"></div>
  <div class="live"><span class="dot"></span> live</div>
</div>

<main>
  <table>
    <thead>
      <tr>
        <th class="c-time" data-s="time">Time <span class="arr on" id="a-time">&darr;</span></th>
        <th class="c-risk" data-s="risk">Risk <span class="arr" id="a-risk"></span></th>
        <th class="c-act" data-s="action">Action <span class="arr" id="a-action"></span></th>
        <th class="c-cmd" data-s="cmd">Command <span class="arr" id="a-cmd"></span></th>
        <th class="c-ms" data-s="ms">ms <span class="arr" id="a-ms"></span></th>
        <th class="c-p">&sim;</th>
      </tr>
    </thead>
    <tbody id="tb"></tbody>
  </table>
  <div class="empty" id="empty" style="display:none">
    <strong>No log entries</strong>
    <p>Waiting for assess_command calls...</p>
  </div>
</main>

<div class="pager" id="pager" style="display:none">
  <button id="p-prev">&larr; Prev</button>
  <span id="p-info"></span>
  <button id="p-next">Next &rarr;</button>
</div>

<script>
const PAGE = 100;
let sort = "time", order = "desc", offset = 0, total = 0, cursor = "";
let entries = [], expandedId = null;
let debounceTimer = null;

function $(id) { return document.getElementById(id); }

function buildParams() {
  const p = new URLSearchParams();
  const search = $("f-search").value;
  const risk = $("f-risk").value;
  const action = $("f-action").value;
  const from = $("f-from").value;
  const to = $("f-to").value;
  const partial = $("f-partial").value;
  if (search) p.set("search", search);
  if (risk) p.set("risk", risk);
  if (action) p.set("action", action);
  if (from) p.set("from", new Date(from).toISOString());
  if (to) {
    const d = new Date(to);
    d.setDate(d.getDate() + 1);
    p.set("to", d.toISOString());
  }
  if (partial) p.set("partial", partial);
  p.set("sort", sort);
  p.set("order", order);
  p.set("limit", String(PAGE));
  p.set("offset", String(offset));
  return p;
}

async function fetchPage() {
  const p = buildParams();
  const resp = await fetch("/api/logs?" + p.toString());
  const data = await resp.json();
  entries = data.entries;
  total = data.total;
  if (data.cursor) cursor = data.cursor;
  render();
}

async function pollNew() {
  if (!cursor) { setTimeout(pollNew, 2000); return; }
  try {
    const p = new URLSearchParams();
    p.set("after", cursor);
    p.set("limit", "1000");
    const resp = await fetch("/api/logs?" + p.toString());
    const data = await resp.json();
    if (data.entries.length > 0) {
      cursor = data.cursor;
      fetchPage();
    }
  } catch {}
  setTimeout(pollNew, 2000);
}

function fmt(iso) {
  const d = new Date(iso);
  const p = n => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth()+1) + "-" + p(d.getDate())
    + " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
}

function esc(s) { const e = document.createElement("span"); e.textContent = s; return e.innerHTML; }

function detailHtml(e) {
  const a = e.assessment;
  let h = '<div class="db">';
  h += '<div class="f"><span class="fl">cwd:</span>' + esc(e.cwd) + '</div>';
  h += '<div class="f"><span class="fl">summary:</span>' + esc(a.summary) + '</div>';
  h += '<div class="f"><span class="fl">recommendation:</span>' + esc(a.recommendation) + '</div>';
  if (a.partial) h += '<div class="f"><span class="fl" style="color:var(--medium)">partial:</span>score may be incomplete — an API call failed</div>';
  if (a.details.length > 0) {
    h += '<div class="f"><span class="fl">findings:</span></div>';
    for (const d of a.details) {
      h += '<div class="fi"><span class="fs r-' + d.severity + '">' + esc(d.severity) + '</span> '
        + '<span style="color:var(--text-dim)">[' + esc(d.category) + ']</span> '
        + esc(d.description) + '</div>';
    }
  }
  return h + '</div>';
}

function render() {
  const tb = $("tb"), em = $("empty"), pg = $("pager");
  $("meta").textContent = total + " entries" + (total !== entries.length ? " (" + entries.length + " shown)" : "");

  if (entries.length === 0) {
    tb.innerHTML = ""; em.style.display = "block"; pg.style.display = "none"; return;
  }
  em.style.display = "none";

  let h = "";
  for (const e of entries) {
    const rl = e.assessment.risk_level;
    const exp = expandedId === e.id;
    h += '<tr class="xp" data-id="' + e.id + '">'
      + '<td class="c-time">' + fmt(e.timestamp) + '</td>'
      + '<td class="c-risk"><span class="badge r-' + rl + '">' + rl + '</span></td>'
      + '<td class="c-act"><span class="act">' + e.assessment.action + '</span></td>'
      + '<td class="c-cmd">' + esc(e.command) + '</td>'
      + '<td class="c-ms"><span class="ms">' + e.duration_ms + '</span></td>'
      + '<td class="c-p">' + (e.assessment.partial ? '<span class="pw" title="Partial — API call failed">!</span>' : '') + '</td>'
      + '</tr>';
    if (exp) h += '<tr class="dr"><td colspan="6">' + detailHtml(e) + '</td></tr>';
  }
  tb.innerHTML = h;

  const pages = Math.ceil(total / PAGE);
  const page = Math.floor(offset / PAGE) + 1;
  if (pages > 1) {
    pg.style.display = "flex";
    $("p-info").textContent = "Page " + page + " of " + pages;
    $("p-prev").disabled = offset === 0;
    $("p-next").disabled = offset + PAGE >= total;
  } else {
    pg.style.display = "none";
  }
}

$("tb").addEventListener("click", ev => {
  const row = ev.target.closest("tr.xp");
  if (!row) return;
  const id = row.dataset.id;
  expandedId = expandedId === id ? null : id;
  render();
});

document.querySelector("thead").addEventListener("click", ev => {
  const th = ev.target.closest("th[data-s]");
  if (!th) return;
  const key = th.dataset.s;
  if (sort === key) { order = order === "desc" ? "asc" : "desc"; }
  else { sort = key; order = key === "cmd" ? "asc" : "desc"; }
  document.querySelectorAll(".arr").forEach(el => { el.classList.remove("on"); el.innerHTML = ""; });
  const arrow = $("a-" + key);
  if (arrow) { arrow.classList.add("on"); arrow.innerHTML = order === "asc" ? "&uarr;" : "&darr;"; }
  offset = 0; expandedId = null;
  fetchPage();
});

$("p-prev").addEventListener("click", () => { offset = Math.max(0, offset - PAGE); expandedId = null; fetchPage(); });
$("p-next").addEventListener("click", () => { if (offset + PAGE < total) { offset += PAGE; expandedId = null; fetchPage(); } });

["f-search", "f-risk", "f-action", "f-from", "f-to", "f-partial"].forEach(id => {
  $(id).addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => { offset = 0; expandedId = null; fetchPage(); }, 200);
  });
  $(id).addEventListener("change", () => { offset = 0; expandedId = null; fetchPage(); });
});

fetchPage().then(() => pollNew());
</script>
</body>
</html>`;
