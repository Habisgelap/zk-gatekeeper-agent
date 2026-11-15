'use strict';
// Proof Gatekeeper agent – zkVerify Agent Games
// Deterministic decision + local Groth16 proof (snarkjs). No secrets in code.
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

const PORT = Number(process.env.PORT || 8080);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const WASM = path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
const P = 21888242871839275222246405745257516413064690311751186774798016887215542095617n; // BN254 field

fs.mkdirSync(DATA_DIR, { recursive: true });
const SEEN_FILE = path.join(DATA_DIR, 'seen.json');
let seen = {}; // proof_tx -> first task_id
try { seen = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8')); } catch (_) {}
const saveSeen = () => { try { fs.writeFileSync(SEEN_FILE, JSON.stringify(seen)); } catch (e) { console.error('seen save failed', e.message); } };
const responses = new Map(); // task_id -> cached response body (idempotency)

const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------- HMAC ----------
function hmacHex(body) { return crypto.createHmac('sha256', SECRET).update(body).digest('hex'); }
function verifySig(raw, header) {
  if (!SECRET || !header) return false;
  const got = String(header).trim().replace(/^sha256=/i, '').toLowerCase();
  const want = hmacHex(raw);
  const a = Buffer.from(got), b = Buffer.from(want);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json', 'x-agent-games-signature': hmacHex(body) });
  res.end(body);
}

// ---------- field encoding ----------
function toField(v) {
  if (v === null || v === undefined || v === '') return 0n;
  if (typeof v === 'number') return BigInt(v) % P;
  const s = String(v).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s) % P;
  if (/^\d+$/.test(s)) return BigInt(s) % P;
  // any other string (e.g. task ids like "gk_8d31_...") -> sha256 mod p
  return BigInt('0x' + crypto.createHash('sha256').update(s).digest('hex')) % P;
}
const big = (v) => { try { return BigInt(String(v).trim()); } catch (_) { return null; } };
const norm = (v) => String(v ?? '').trim().toLowerCase();

// ---------- decision (deterministic, fail closed) ----------
function decide(task) {
  const i = task.input || {};
  const proofTx = norm(i.proof_tx);
  if (proofTx && seen[proofTx] && seen[proofTx] !== task.task_id) return { decision: 'REJECT', reason_code: 'PROOF_REUSED', provable: false };
  const minimum = big(i.minimum), bal = big(i.public_balance), amount = big(i.amount), cap = big(i.max_transfer);
  const exp = big(i.expiry_block), cur = big(i.current_block);
  if ([minimum, bal, amount, cap, exp, cur].some((x) => x === null)) return { decision: 'REJECT', reason_code: 'INVALID_INPUT', provable: true };
  if (!i.registered_vk || norm(i.registered_vk) !== norm(i.proof_vk)) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', provable: true };
  if (bal < minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', provable: true };
  if (cur > exp) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', provable: true };
  if (norm(i.recipient) !== norm(i.condition_recipient)) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', provable: true };
  if (amount > cap) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', provable: true };
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', provable: true };
}

function circuitInput(task, decisionBit) {
  const i = task.input || {};
  return {
    registeredVkHash: toField(i.registered_vk).toString(),
    proofVkHash: toField(i.proof_vk).toString(),
    minimum: toField(i.minimum).toString(),
    publicBalance: toField(i.public_balance).toString(),
    expiryBlock: toField(i.expiry_block).toString(),
    currentBlock: toField(i.current_block).toString(),
    recipient: toField(i.recipient).toString(),
    conditionRecipient: toField(i.condition_recipient).toString(),
    amount: toField(i.amount).toString(),
    maxTransfer: toField(i.max_transfer).toString(),
    taskId: toField(task.task_id).toString(),
    salt: (BigInt('0x' + crypto.randomBytes(31).toString('hex')) % P).toString(),
    decision: String(decisionBit),
  };
}

async function prove(task, decisionBit) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput(task, decisionBit), WASM, ZKEY);
  return { proof, public_signals: publicSignals };
}

async function handleGatekeeper(task) {
  const d = decide(task);
  const out = { decision: d.decision, reason_code: d.reason_code };
  if (task.input && task.input.proof_tx) out.proof_tx = task.input.proof_tx;
  if (d.provable) {
    const bit = d.decision === 'APPROVE' ? 1 : 0;
    try {
      Object.assign(out, await prove(task, bit));
    } catch (e) {
      // The circuit enforces the correct decision. If our rule disagreed, it fails; never flip to APPROVE blindly.
      log('proof failed for', task.task_id, d.decision, e.message.split('\n')[0]);
      if (bit === 1) {
        out.decision = 'REJECT'; out.reason_code = 'CIRCUIT_REJECTED';
        try { Object.assign(out, await prove(task, 0)); } catch (_) {}
      }
    }
  }
  const pt = norm(task.input && task.input.proof_tx);
  if (pt && !seen[pt]) { seen[pt] = task.task_id; saveSeen(); }
  return out;
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET') return send(res, 200, { ok: true, protocolVersion: 'v1', service: 'zk-gatekeeper-agent' });
  if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    if (!verifySig(raw, req.headers['x-agent-games-signature'])) { log('bad signature'); return send(res, 401, { error: 'invalid_signature' }); }
    let task;
    try { task = JSON.parse(raw.toString('utf8')); } catch (_) { return send(res, 400, { error: 'invalid_json' }); }
    const type = String(task.type || '');
    try {
      if (type.includes('preflight')) { log('preflight', task.nonce || ''); return send(res, 200, { ok: true, protocolVersion: 'v1' }); }
      if (type.includes('proof-gatekeeper')) {
        if (task.task_id && responses.has(task.task_id)) return send(res, 200, responses.get(task.task_id));
        const t0 = Date.now();
        const out = await handleGatekeeper(task);
        if (task.task_id) responses.set(task.task_id, out);
        log('task', task.task_id, task.mode, out.decision, out.reason_code, (Date.now() - t0) + 'ms');
        return send(res, 200, out);
      }
      log('unknown type', type);
      return send(res, 200, { decision: 'REJECT', reason_code: 'UNSUPPORTED_TASK' });
    } catch (e) {
      log('error', e.message);
      return send(res, 200, { decision: 'REJECT', reason_code: 'AGENT_ERROR' }); // fail closed
    }
  });
});

if (require.main === module) server.listen(PORT, () => log('listening on', PORT, SECRET ? '(secret set)' : '(WARNING: AGENT_GAMES_HMAC_SECRET missing)'));
module.exports = { decide, circuitInput, prove, toField, server };
