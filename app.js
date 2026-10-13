const express = require("express");
const { spawn } = require("child_process");
const readline = require("readline");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 8000;
const IDLE_FLUSH_MS = 500; // finish a packet this long after its last trace line
const HISTORY_LIMIT = 200;
const MAX_LINES_PER_PACKET = 200;
const DEBUG = !!process.env.DEBUG;

// ---------------------------------------------------------------------------
// xtables-monitor feed
// ---------------------------------------------------------------------------
const child = spawn("xtables-monitor", ["--trace"], {
  stdio: ["ignore", "pipe", "pipe"],
});

const out = readline.createInterface({ input: child.stdout });

// Raw feed (kept for anything that still wants the plain text lines).
out.on("line", (line) => {
  if (DEBUG) console.error(`Got line: ${line}`);
  io.emit("trace-line", line);
});

child.stderr.on("data", (data) => process.stderr.write(data));
child.on("error", (err) => console.error("Could not start xtables-monitor:", err));
child.on("exit", (code) => console.error(`xtables-monitor exited with code ${code}`));

// ---------------------------------------------------------------------------
// Network interfaces (dynamic)
// ---------------------------------------------------------------------------
function getInterfaces() {
  let names = [];
  try {
    names = fs.readdirSync("/sys/class/net");
  } catch (_e) {
    names = Object.keys(os.networkInterfaces());
  }
  const addrs = os.networkInterfaces();
  return names.sort().map((name) => ({
    name,
    addresses: (addrs[name] || []).map((a) => a.address),
  }));
}

let lastInterfaces = JSON.stringify(getInterfaces());
setInterval(() => {
  const now = JSON.stringify(getInterfaces());
  if (now !== lastInterfaces) {
    lastInterfaces = now;
    io.emit("interfaces", JSON.parse(now));
  }
}, 3000);

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------
const VERDICTS = new Set(["ACCEPT", "DROP", "RETURN", "CONTINUE", "QUEUE", "STOLEN", "REPEAT"]);
const HOP_RE = /^(raw|mangle|nat|filter|security):([^:\s]+):(policy|rule|return)(?::(\S*))?$/i;

function parseLine(line) {
  const match = line.trim().match(/^(PACKET|TRACE):\s+(\S+)\s+([0-9a-fA-F]+)(?:\s+(.*))?$/);
  if (!match) return null;
  return {
    type: match[1],
    family: match[2],
    hash: match[3],
    rest: match[4] || "",
    line: line.trim(),
  };
}

// Pulls KEY=value pairs (IN=, OUT=, SRC=, DST=, PROTO=, SPT=, DPT=, ...)
function parseInfo(rest) {
  const info = {};
  for (const m of rest.matchAll(/\b([A-Z]+)=(\S*)/g)) info[m[1]] = m[2];
  return info;
}

// One TRACE line = one hop through a table:chain.
// Examples:  filter:OUTPUT:policy:ACCEPT   filter:FORWARD:rule:0x5:DROP
function parseHop(rest) {
  for (const tok of rest.split(/\s+/)) {
    const m = tok.match(HOP_RE);
    if (!m) continue;

    const parts = (m[4] || "").split(":").filter(Boolean);
    let verdict = parts.length ? parts[parts.length - 1].toUpperCase() : null;
    if (verdict && !VERDICTS.has(verdict)) verdict = null;
    if (!verdict && m[3].toLowerCase() === "return") verdict = "RETURN";

    // Fallback: explicit jump targets in the rule text.
    if (!verdict) {
      if (/(?:^|\s)-j\s+DROP(?:\s|$)/i.test(rest)) verdict = "DROP";
      else if (/(?:^|\s)-j\s+ACCEPT(?:\s|$)/i.test(rest)) verdict = "ACCEPT";
    }

    return {
      table: m[1].toLowerCase(),
      chain: m[2],
      kind: m[3].toLowerCase(),
      verdict,
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Packet grouping
// A packet passes through MANY chains, so ACCEPT in raw:PREROUTING does not
// mean the packet is finished. We collect hops and flush when the packet is
// dropped or when it has been quiet for IDLE_FLUSH_MS.
// ---------------------------------------------------------------------------
const packetGroups = new Map();
const history = [];
let packetCounter = 0;

function getGroup(parsed) {
  const key = `${parsed.family}:${parsed.hash}`;
  if (!packetGroups.has(key)) {
    packetGroups.set(key, {
      key,
      family: parsed.family,
      hash: parsed.hash,
      in: "",
      out: "",
      info: {},
      hops: [],
      lines: [],
      timer: null,
    });
  }
  return packetGroups.get(key);
}

function flush(g) {
  clearTimeout(g.timer);
  packetGroups.delete(g.key);
  if (!g.hops.length) return; // PACKET with no TRACE hops: nothing to draw

  let verdict = "PASS";
  if (g.hops.some((h) => h.verdict === "DROP")) verdict = "DROP";
  else if (g.hops[g.hops.length - 1].verdict === "ACCEPT") verdict = "ACCEPT";

  const packet = {
    id: ++packetCounter,
    key: g.key,
    family: g.family,
    hash: g.hash,
    in: g.in,
    out: g.out,
    info: g.info,
    verdict,
    hops: g.hops,
    lines: g.lines,
    time: new Date().toLocaleTimeString(),
  };

  history.push(packet);
  if (history.length > HISTORY_LIMIT) history.shift();
  io.emit("completed-packet", packet);
}

function processLine(line) {
  const parsed = parseLine(line);
  if (!parsed) return;

  const g = getGroup(parsed);
  if (g.lines.length < MAX_LINES_PER_PACKET) {
    g.lines.push({ type: parsed.type, line: parsed.line, time: new Date().toLocaleTimeString() });
  }

  const info = parseInfo(parsed.rest);
  if (info.IN) g.in = info.IN;
  if (info.OUT) g.out = info.OUT; // OUT only becomes known after routing
  for (const k of ["SRC", "DST", "PROTO", "SPT", "DPT", "LEN"]) {
    if (info[k]) g.info[k] = info[k];
  }

  if (parsed.type === "TRACE") {
    const hop = parseHop(parsed.rest);
    if (hop) {
      g.hops.push(hop);
      if (hop.verdict === "DROP") return flush(g); // nothing can follow a drop
    }
  }

  clearTimeout(g.timer);
  g.timer = setTimeout(() => flush(g), IDLE_FLUSH_MS);
}

out.on("line", processLine);

let shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.error(`${signal} received, stopping xtables-monitor...`);

  child.kill("SIGTERM");   // ask it to exit
  io.close();              // disconnect browsers
  server.close(() => process.exit(0));

  // Fallback if something hangs
  setTimeout(() => {
    child.kill("SIGKILL");
    process.exit(0);
  }, 2000).unref();
}

for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => shutdown(sig));
}

// Last resort for normal exits and crashes
process.on("exit", () => child.kill());

// ---------------------------------------------------------------------------
// Web
// ---------------------------------------------------------------------------
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

io.on("connection", (socket) => {
  socket.emit("interfaces", getInterfaces());
  socket.emit("history", history);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`iptables trace viewer listening on port ${PORT}`);
});