# Vulnerability Reference: LLM & AI Application Security

_Load in Phase 1 for apps using LLMs, agentic tool calls, RAG, vector databases, MCP servers, or AI automation. Aligned with **OWASP Top 10 for LLM Applications** and **OWASP Top 10 for Agentic Applications (2026)**._

---

## LLM Application Vulnerabilities

### 1. Prompt Injection
- **Direct:** system prompt override or jailbreak via chat, search, or form input
- **Indirect:** untrusted third-party content (scraped pages, emails, PDFs, DB records, calendar events) overriding instructions during retrieval/RAG
- **Multi-turn:** gradual manipulation across turns to bypass guardrails
- **Encoded:** payloads in base64, Unicode, HTML entities, or markdown that decode during processing

### 2. Unsafe Tool/Function Calling
- System commands, DB queries, or file operations run straight from model text without validation
- No JSON schema enforcement on tool arguments
- No human approval for destructive or irreversible actions
- Tools reaching resources beyond the user's permission scope
- One tool's output becoming another's unvalidated input

### 3. Excessive Agency
- Agents with broad permissions (filesystem, network, code execution)
- No scope boundary: access to data or systems unrelated to the task
- Auto-approval of dangerous actions; no sandbox for agent-generated code
- Inner agent inheriting the outer agent's full permissions

### 4. Vector DB & RAG
- **Access control leaks:** queries returning embeddings without tenant or document-level permission checks
- **RAG poisoning:** instruction payloads planted in indexed sources
- **Embedding inversion:** recovering source text from vectors
- **Context poisoning:** manipulating retrieval ranking to inject context
- **Metadata leakage:** results exposing file paths, user IDs, access levels

### 5. Output Validation & Data Exposure
- System prompt extraction ("repeat your instructions")
- Model output treated as trusted HTML, SQL, code, or commands (XSS via model output; sanitize before rendering)
- Model emitting sensitive training data (PII, credentials, internal URLs)
- Raw chain-of-thought with internal details exposed

### 6. Training Data & Model Supply Chain
- Poisoned training data (backdoors, bias)
- Model files from untrusted sources without integrity checks
- Unsafe deserialization in model loading (arbitrary code via malicious Python-serialized `.pkl` model files; prefer safetensors)
- No provenance tracking of the deployed model version
- Fine-tuned models inheriting base-model flaws

---

## Agentic Application Vulnerabilities (OWASP 2026)

### 7. Memory Poisoning
- Malicious input persisting in agent memory across sessions
- Conversation history manipulation altering later behavior
- Memory shared between agents (cross-contamination) or between user sessions (no sanitization)

### 8. Cascading Tool Permissions
- Sub-agents inheriting full parent permissions; tool chains where intermediate results escalate access
- No least privilege in multi-agent orchestration
- Agent A calls Agent B calls Tool C, with permission checks only at A

### 9. MCP Server Security
- Tools exposed without authentication
- No input validation on tool parameters
- Tool descriptions carrying prompt injection payloads
- Servers granting broad filesystem or network access
- No rate limiting on tool invocations

### 10. Denial of Wallet
- Inputs built to maximize token use; recursive agent loops burning credits
- No budget or cost controls on LLM API calls
- Context-window stuffing to slow or overflow responses

---

## Cross-Cutting Checks

**Input:** inputs length-limited? Content filtering? Uploads (PDFs, images) scanned before the model? RAG results filtered by user permission?

**Output:** output sanitized before rendering? Tool arguments schema-validated? Human approval for irreversible actions? Outputs logged for audit?

**System:** agent permissions minimal? Cost cap on API usage? Model version pinned? Monitoring for anomalous behavior?
