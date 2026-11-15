// Local test: replays the 7 trap types through decide() + the real circuit.
const { decide, prove } = require('./server');
const base = { registered_vk: '0x7d3a', proof_vk: '0x7d3a', minimum: '1000', public_balance: '1460', expiry_block: 8430000, current_block: 8420000,
  recipient: '0xDe42000000000000000000000000000000009f01', condition_recipient: '0xDe42000000000000000000000000000000009f01', amount: '500', max_transfer: '1000', proof_tx: '0xa1' };
const cases = [
  ['VALID_CONDITION', {}],
  ['VK_SUBSTITUTION', { proof_vk: '0x13aa' }],
  ['THRESHOLD_MISMATCH', { public_balance: '900' }],
  ['EXPIRED_CONDITION', { current_block: 8430001 }],
  ['RECIPIENT_MISMATCH', { condition_recipient: '0xDe42000000000000000000000000000000009f02' }],
  ['AMOUNT_OVERFLOW', { amount: '1500' }],
];
(async () => {
  let n = 0;
  for (const [want, patch] of cases) {
    const task = { type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_test_' + (n++), input: { ...base, ...patch, proof_tx: '0x' + n } };
    const d = decide(task);
    let ok = 'proof ok';
    try { await prove(task, d.decision === 'APPROVE' ? 1 : 0); } catch (e) { ok = 'PROOF FAIL'; }
    console.log(want.padEnd(20), '->', d.decision, d.reason_code, ok, d.reason_code === want ? 'PASS' : 'MISMATCH');
  }
  process.exit(0);
})();
