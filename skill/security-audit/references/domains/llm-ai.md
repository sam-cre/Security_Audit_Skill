# Vulnerability Reference: LLM & AI Application Security

_Load this during Phase 1 when auditing applications using Large Language Models, agentic tool calls, RAG pipelines, vector databases, MCP servers, or AI-powered automation. Aligned with **OWASP Top 10 for LLM Applications** and **OWASP Top 10 for Agentic Applications (2026)**._

---

## LLM Application Vulnerabilities

### 1. Direct & Indirect Prompt Injection
- **Direct Injection:** System prompt override or jailbreaking via untrusted user inputs in chat, search, or form fields
- **Indirect Injection:** Untrusted third-party content (scraped web pages, ingested emails, uploaded PDFs, database records, calendar events) overriding model instructions during retrieval/RAG
- **Multi-turn Injection:** Gradual prompt manipulation across conversation turns to bypass guardrails
- **Encoded Injection:** Payloads hidden in base64, Unicode, HTML entities, or markdown that decode during model processing

### 2. Unsafe Tool/Function Calling
- Executing system commands (`os.system`, `subprocess`), database queries, or file operations directly from model-generated text without validation
- Missing JSON schema enforcement on tool call arguments
- Missing human-in-the-loop approval for destructive/irreversible tool actions
- Tool calls that can access resources beyond the user's permission scope
- Chained tool calls where output of one tool becomes unvalidated input to another

### 3. Excessive Agency & Autonomy
- Agent systems with overly broad permissions (file system access, network access, code execution)
- Missing scope boundaries — agent can access data/systems unrelated to the user's task
- Auto-approval of dangerous actions without user confirmation
- Missing execution sandboxing for agent-generated code
- Cascading permissions: inner agent inherits outer agent's full permission set

### 4. Vector Database & RAG Security
- **Access Control Leaks:** Vector DB queries returning document embeddings without enforcing user tenant or document-level access permissions
- **RAG Poisoning:** Injecting malicious instruction payloads into data sources indexed by vector databases
- **Embedding Inversion:** Extracting original text content from embedding vectors
- **Context Window Poisoning:** Manipulating retrieval ranking to inject malicious context into the prompt
- **Metadata Leakage:** Vector DB query results exposing source document metadata (file paths, user IDs, access levels)

### 5. Model Output Validation & Data Exposure
- System prompt extraction via prompt leak attacks ("repeat your instructions")
- Treating unverified model output as trusted HTML, SQL, code, or system commands
- Model hallucinating sensitive data from training set (PII, credentials, internal URLs)
- Missing output sanitization before rendering in web UI (XSS via model output)
- Exposing raw model responses containing chain-of-thought reasoning with internal details

### 6. Training Data & Model Supply Chain
- Poisoned training data introducing backdoors or biased behavior
- Model files downloaded from untrusted sources without integrity verification
- Pickle deserialization in model loading (arbitrary code execution via malicious `.pkl` files)
- Missing model provenance tracking (which model version is deployed?)
- Fine-tuned models inheriting and amplifying base model vulnerabilities

---

## Agentic Application Vulnerabilities (OWASP 2026)

### 7. Memory Poisoning
- Agent memory/context window poisoned by malicious user input persisting across sessions
- Conversation history manipulation to alter agent behavior in future turns
- Shared memory between agents allowing cross-contamination
- Missing memory sanitization between different user sessions

### 8. Cascading Tool Permissions
- Inner agents/sub-agents inheriting full permission sets from parent agents
- Tool chains where intermediate results grant escalated access
- Missing principle of least privilege in multi-agent orchestration
- Agent A calls Agent B which calls Tool C — permission checks only at Agent A level

### 9. MCP (Model Context Protocol) Server Security
- MCP servers exposing tools without authentication
- Missing input validation on MCP tool parameters
- MCP tool descriptions containing prompt injection payloads
- Overly permissive MCP server configurations granting file system or network access
- Missing rate limiting on MCP tool invocations

### 10. Denial of Wallet / Resource Exhaustion
- Malicious inputs designed to maximize token consumption (cost attacks)
- Recursive agent loops consuming unbounded API credits
- Missing budget/cost controls on LLM API calls
- Large context window stuffing to slow response or exceed limits

---

## Cross-Cutting AI Security Checks

### Input Controls
- [ ] Are user inputs length-limited before reaching the model?
- [ ] Is there content filtering on inputs (harmful content detection)?
- [ ] Are file uploads (PDFs, images) scanned before being processed by the model?
- [ ] Are RAG retrieval results filtered by user permissions?

### Output Controls
- [ ] Is model output sanitized before rendering in UI?
- [ ] Are tool call arguments validated against a strict schema?
- [ ] Is there a human-in-the-loop for irreversible actions?
- [ ] Are model outputs logged for audit trail?

### System Controls
- [ ] Are agent permissions scoped to the minimum needed?
- [ ] Is there a cost/budget cap on LLM API usage?
- [ ] Is the model version pinned (not auto-updating)?
- [ ] Is there monitoring for anomalous model behavior?
