# Data Flow Inventory

_Generated during Phase 0. Maps every untrusted input source to every dangerous execution sink, with the intermediate call chain. This is the attack surface contract — Phase 1 walks this map systematically rather than free-reading files._

---

## How to Build This

1. Start from the entry points identified in `project-profile.md`
2. For each entry point, trace the data through function calls, middleware, and transformations
3. Identify where the data reaches a "sink" — a function that executes, queries, renders, writes, or transmits
4. Record the full chain: Source → Handler → [Intermediate Functions] → Sink
5. Note which sanitizers/validators exist along the path (or flag their absence)

---

## Source Categories

| Category | Examples | How to Find |
|---|---|---|
| HTTP Input | Request body, query params, headers, cookies, URL path segments | Route definitions, controller parameters, `req.body`, `request.form` |
| File Input | Uploaded files, config files read at runtime, imported data files | `open()`, `fs.readFile`, `multipart` handlers, hot-reload file watchers |
| CLI Input | Command-line arguments, stdin, environment variables | `argparse`, `sys.argv`, `process.env`, `os.environ`, `getopt` |
| Database Input | User-generated content read back from DB | SELECT queries where data was originally user-supplied |
| External API | Responses from third-party services, webhook payloads | HTTP client calls, webhook route handlers |
| AI/LLM Input | User prompts, RAG retrieval results, tool call outputs | LLM API calls, vector DB queries, agent tool responses |
| IPC / Sockets / D-Bus | Unix domain sockets, named pipes (FIFO), gRPC, D-Bus messages | Socket listeners, IPC handlers, D-Bus interfaces, RPC handlers |
| Shared Memory / Signals | Mmap regions, shared memory segments, OS signals | `shmget`, `mmap`, `signal()` / `sigaction()` handlers |

## Sink Categories

| Category | Risk | Examples |
|---|---|---|
| SQL/NoSQL Query | Injection | Raw string queries, template literals in queries, `$where` |
| Shell Execution | Command Injection | `exec()`, `subprocess`, `child_process.exec`, backticks, `os.system` |
| File System Write | Path Traversal, Arbitrary Write | `open(path, 'w')`, `fs.writeFile`, `shutil.copy` |
| File System Read | Path Traversal, Information Disclosure | `open(user_path)`, `fs.readFile(user_input)` |
| Temp File Creation | Symlink Attack, Predictable Temp File | `mkstemp()` misuse, `/tmp/file` creation without O_EXCL |
| Privilege Escalation | SUID / Capabilities Abuse | `setuid()`, `setgid()`, `sudo` invocations, cap_set_proc |
| HTML/Template Render | XSS | `innerHTML`, `dangerouslySetInnerHTML`, `|safe`, `Markup()` |
| HTTP Response | Information Leakage, Header Injection | Direct echo of input in response body/headers |
| Deserialization | RCE | `pickle.loads`, `yaml.load`, `JSON.parse` with reviver, `ObjectInputStream` |
| Crypto Operations | Key/IV Misuse | User-controlled keys, user data as IV/nonce |
| Redirect/Forward | Open Redirect | `redirect(user_url)`, `Location` header from input |
| LLM Prompt Construction | Prompt Injection | String concatenation into system/user prompts |
| Logging / Syslog | Sensitive Data Exposure, Log Injection | Logging user input containing PII/secrets or CRLF injection |

---

## Data Flow Map

<!-- For each flow, document the full chain. Use this format: -->

### Flow [N]: [Short Description]
- **Source:** [Category] — [specific location, e.g., `POST /api/login` body parameter `username`]
- **Handler:** [file:function:line, e.g., `src/routes/auth.py:login_handler:45`]
- **Intermediate Steps:**
  1. [file:function:line] — [what happens to the data: validated? transformed? passed through?]
  2. [file:function:line] — [next step]
- **Sink:** [Category] — [specific location, e.g., `src/db/queries.py:find_user:12` — SQL query]
- **Sanitization Present:** Yes / No / Partial
- **Sanitization Details:** [If yes, what sanitization: parameterized query? regex validation? allowlist?]
- **Risk Assessment:** [If no sanitization: what vulnerability class does this expose?]

---

## Coverage Verification

After completing the data flow map, verify:

- [ ] Every entry point from `project-profile.md` has at least one flow documented
- [ ] Every trust boundary from `threat-model.md` appears as a source→sink crossing
- [ ] Flows with no sanitization are flagged as Phase 1 investigation targets
- [ ] Flows where sanitization exists are noted (Phase 1 verifies the sanitization is correct)

---

## Untraced Paths

<!-- List any data paths you identified but couldn't fully trace (e.g., dynamic dispatch, 
     reflection, callback-based architectures where the flow isn't statically determinable).
     These become "Requires Manual Review" items in Phase 1. -->
