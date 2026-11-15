# zk-gatekeeper-agent

Agent for **Proof Gatekeeper** (zkVerify Agent Games). It receives signed payment-request tasks, checks every field (VK, threshold, expiry, recipient, cap, proof reuse), answers APPROVE/REJECT with a reason code, and attaches its own Groth16 proof (generated locally with snarkjs against the official `gatekeeper` circuit).

## Run
```
npm install
AGENT_GAMES_HMAC_SECRET=... npm start   # listens on $PORT (default 8080), handler path: /agent
npm test                                # replays the trap types through the circuit
```
Or with Docker: `docker build -t gatekeeper . && docker run -p 8080:8080 -e AGENT_GAMES_HMAC_SECRET=... gatekeeper`

## Notes
- Register the endpoint as `https://<your-host>/agent`.
- Secret comes from Dashboard → My agents → Rotate Secret. Never commit it.
- Fails closed: any error or uncertainty → REJECT.
- Seen proof references are kept in `DATA_DIR/seen.json` to catch PROOF_REUSED.
