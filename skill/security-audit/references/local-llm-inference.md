# Local / self-hosted LLM inference - audit checklist

Load this when Phase 0 finds a local inference runtime (Ollama, LM Studio, llama.cpp / llamafile,
vLLM, TGI, text-generation-webui, Jan, GPT4All, etc.) OR when the project sends data to a model on
`localhost`. This is a DIFFERENT surface from an app that calls a hosted LLM API - the model, the
server, and the logs are all on the user's machine, so "it is local, therefore private" is false.

Every finding still goes through the normal triage gate, confidence calibration, and PoC verification
in `references/rules.md`. This file only adds the local-inference-specific checks.

## 1. Network exposure of the inference server (highest priority)
- **Bind address.** The server must listen on `127.0.0.1` / `::1`, not `0.0.0.0`. Check for
  `OLLAMA_HOST=0.0.0.0`, `--host 0.0.0.0`, `--listen`, `server.bind`, a `0.0.0.0` in a compose file,
  or a UI "network/remote access" toggle. Verify at runtime: `netstat -ano | findstr <port>` (Windows)
  / `ss -ltnp | grep <port>` (Linux). Default ports: Ollama 11434, LM Studio 1234, TGI 3000, vLLM 8000,
  text-generation-webui 7860/5000.
- **Auth.** Most local runtimes have NO authentication. If the port is reachable beyond loopback (LAN,
  a bound container, a `docker -p 0.0.0.0:11434:11434`, a reverse proxy, a tunnel like ngrok/cloudflared),
  anyone who reaches it can run inference, read loaded models, and on some runtimes pull/delete models
  or hit debug endpoints - treat an unauthenticated bound port as a critical finding.
- **SSRF reach.** If the app lets user input influence the inference URL, or a hosted backend calls a
  local model, an SSRF can pivot to `localhost:11434` and drive it. Check that the endpoint is fixed.
- **Auto-starting the server (process spawn).** An app that launches the runtime for the user (e.g.
  spawns `ollama serve`) adds a spawn surface: (a) it must resolve the binary safely - a bare `ollama`
  taken from PATH is a hijack surface if an attacker can prepend a directory; prefer an absolute/known
  path or accept the documented low risk. (b) It must NOT go through a shell (`sh -c "..."`), which
  turns any interpolated value into command injection - use a direct argv spawn. (c) It should only
  auto-start a LOOPBACK endpoint; auto-starting or "reconnecting" to a configured remote host is both a
  network-exposure and an SSRF-adjacent risk. (d) There should be an off switch, so an audited/locked
  environment can forbid the app from spawning processes at all.

## 2. Model supply chain (the model is untrusted input)
- **Provenance.** Pull only from official libraries/registries and pin tags/digests. A random
  HuggingFace repo or a third-party Ollama tag is untrusted. Prefer a checksum/digest check.
- **Modelfile / config as code.** An Ollama `Modelfile`, a chat template, or a `SYSTEM` prompt ships
  WITH the model and can inject instructions, set a malicious system prompt, or (via `ADAPTER`/`FROM`)
  pull remote content. Review any committed Modelfile / template the same way you review code.
- **Code-execution-on-load formats.** Legacy PyTorch checkpoints (`.bin` / `.pt`) use a Python
  serialization format that runs arbitrary code when the weights are loaded - flag any path that loads
  them from an untrusted source. The `.gguf` and `.safetensors` formats are data-only; prefer them.
- **Poisoning / backdoors.** A fine-tuned or community model may carry trigger-phrase backdoors or
  baked-in data exfiltration behavior. Do not treat local model output as trusted; the app's own
  prompt-injection and output-handling defenses must still hold (see the standard LLM checks).

## 3. Data at rest and in transit (why "local" is not "private")
- **Prompt / response logs.** Many runtimes and UIs write full prompts and completions to disk in
  plaintext (Ollama server logs, LM Studio/webui chat histories, LangChain/LlamaIndex debug logs,
  `~/.ollama`, app SQLite stores). If sensitive data is sent to the model, these logs are a disclosure
  sink - check they are disabled or access-controlled, and excluded from backups/sync.
- **Model / KV cache on disk.** Downloaded weights and any on-disk cache live unencrypted unless
  full-disk encryption (BitLocker/FileVault/LUKS) is on. At-rest app-level encryption (e.g. DPAPI) of
  sensitive artifacts protects files copied off the machine, NOT data in use.
- **In-use exposure.** During inference, prompts and context sit in RAM/VRAM; local malware running as
  the user can scrape process memory. The realistic mitigations are host hygiene, full-disk encryption,
  and not running untrusted local software - not anything the app can do alone.
- **Loopback is not encrypted but is not on the wire.** Traffic to `127.0.0.1` does not traverse the
  network; do not flag "no TLS on localhost" by itself, but DO flag any non-loopback bind without TLS.

## 4. Resource / availability
- **DoS.** No token/context/concurrency limits on a local endpoint lets one caller exhaust VRAM/CPU or
  OOM the host. Check for request size caps, `num_ctx` bounds, and a concurrency limit.
- **Arbitrary model pull/load.** If the app or endpoint lets a caller trigger `pull`/`load` of an
  arbitrary model name, that is remote disk-fill + supply-chain risk in one - restrict to an allowlist.

## Quick verification commands
- Bound interface: `netstat -ano | findstr 11434` (Win) / `ss -ltnp | grep 11434` (Linux) - expect
  `127.0.0.1`, never `0.0.0.0`.
- What is loaded / on GPU: `ollama ps`. Installed models: `ollama list`.
- Reachability from off-box (should FAIL): from another host, `curl http://<machine-ip>:11434/api/tags`.
- Plaintext-log check: search the runtime's data dir and any UI history store for recent prompt text.
