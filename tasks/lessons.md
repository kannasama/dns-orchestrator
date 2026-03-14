# Lessons Learned

## 2026-02-26 — Indentation changes must include code blocks

**Pattern:** When asked to update indentation standards in documentation, the scope includes
indentation *inside fenced code blocks* (` ``` `), not just prose bullet lists and inline references.

**Rule:** Before marking an indentation task complete, always scan for 4-space-indented lines
inside code fences (` ```cpp `, ` ```sql `, ` ```bash `, ` ```json `, ` ``` `, etc.) across
all affected files.

**Verification step to add:** After prose changes, run a regex search for lines matching
`^    ` (4 leading spaces) inside code blocks to catch missed indentation.

## 2026-03-04 — Follow existing file naming conventions for plans

**Pattern:** When creating new plan documents, check the existing `docs/plans/` directory for
the naming convention before choosing a filename. The project uses date-prefixed names like
`2026-02-28-phase-4-authentication.md`, not flat names like `PHASE5_PLAN.md`.

**Rule:** Before creating any new document in an existing directory, run `ls` on that directory
first and match the established naming pattern (date prefix, kebab-case, descriptive slug).

**Verification step to add:** After creating a plan file, confirm its name matches the pattern
of sibling files in the same directory.

## 2026-03-04 — Communication

**Mistake**: After writing a plan the user explicitly said they would not execute, presented
execution options ("Subagent-Driven or Parallel Session?") anyway — copying the writing-plans
skill's "Execution Handoff" section verbatim.

**Pattern**: Blindly following a skill template without adapting to user-stated intent.

**Rule**: When the user says they won't execute now or plan to execute with another tool, skip
the execution handoff entirely. Just confirm the plan is saved and committed. The skill template
is a default, not a mandate — always defer to the user's explicit instructions.

**Applied**: Any skill with a handoff/next-steps section (writing-plans, brainstorming, etc.).
Read the user's request fully before appending boilerplate.

## 2026-03-05 — Crow integration test: three bugs in test harness

**Bug 1 — Connection pool exhaustion in SetUp():**
`ConnectionPool` was created with size 2. `SetUp()` checked out two `ConnectionGuard`s (`cg` and `cg2`) in the same scope, then called `authenticateLocal()` which needed a third connection — exhausting the pool after 30 seconds.

**Fix:** Wrap each `ConnectionGuard` block in its own `{}` scope so the guard is destroyed (connection returned) before the next checkout.

**Rule:** When using a fixed-size connection pool in tests, always ensure `ConnectionGuard` objects go out of scope before any subsequent DB operation that needs a connection. Never hold multiple guards in the same scope unless the pool size exceeds the number of simultaneous guards.

**Bug 2 — Crow router not compiled before handle_full():**
`handle_full()` requires `app.validate()` to be called first to compile the trie. Without it, all routes return 404.

**Fix:** Call `_app->validate()` immediately after `_apiServer->registerRoutes()` in `SetUp()`.

**Rule:** In Crow integration tests using `handle_full()` directly (without starting the server), always call `app.validate()` after registering all routes.

**Bug 3 — Query string included in req.url breaks trie routing:**
Crow's HTTP parser strips the query string from `req.url` (path only) and stores it in `req.url_params`. When constructing a `crow::request` manually in tests, setting `req.url = "/api/v1/zones?view_id=5"` causes the trie to fail to match because it only has `/api/v1/zones` registered.

**Fix:** In the test `handle()` helper, split the URL on `?` — set `req.url` to the path portion and `req.url_params = crow::query_string(fullUrl)` for the query portion.

**Rule:** When manually constructing `crow::request` objects for testing, always split the URL: `req.url` = path only, `req.url_params` = `crow::query_string(fullUrl)`, `req.raw_url` = full URL.

## 2026-03-05 — Always commit changes at end of session

**Pattern:** Code changes, plan documents, lessons updates, and any other modifications made
during a session should be committed to the repository before the session ends.

**Rule:** When any code changes are made, plans are written or executed, or lessons are updated,
all changes must be committed to the repo at the end of each session. Do not leave uncommitted work.

**Verification step:** Before completing a session, run `git status` to confirm no unstaged or
uncommitted changes remain for work done in that session.

## 2026-03-07 — Honor pause instructions across context compaction

**Mistake:** User said "Pause" and I acknowledged it. After context was compacted (conversation
summary replaced earlier messages), the continuation prompt said to "resume directly" and I
began working again — ignoring the user's pause instruction that was only preserved in the
summary text, not as an active directive.

**Pattern:** Context compaction loses the imperative force of user instructions. The summary
records *that* the user paused, but the continuation framing ("pick up where you left off")
overrides it.

**Rule:** When a conversation summary mentions the user requested a pause or stop, treat that
as still active. Do not resume work until the user explicitly says to continue. The summary is
context, not a new instruction to proceed.

**Applied:** Any session continuation after compaction. Always check the summary for
pause/stop/wait directives before taking action.

## 2026-03-13 — Use `vue-tsc -b` not `vue-tsc --noEmit` for Docker-parity type checking

**Mistake:** Verified TypeScript compilation locally with `vue-tsc --noEmit` which passed, but
the Docker build uses `vue-tsc -b` (project references / build mode) which has stricter checking.
The build failed in Docker with TS2532 (`Object is possibly 'undefined'`) on array index access
`tabs[e.index].key` that `--noEmit` did not flag.

**Pattern:** Different `vue-tsc` invocation modes have different strictness levels. The Docker
build script runs `vue-tsc -b && vite build`, so local verification must match.

**Rule:** When verifying TypeScript compilation for Vue projects, always use `vue-tsc -b` (the
same command the CI/Docker build uses) rather than `vue-tsc --noEmit`. Check the project's
`package.json` `build` script to confirm the exact command.

**Verification step:** Before committing Vue/TS changes, run the exact build command from
`package.json` (`npm run build` or `vue-tsc -b && vite build`) to catch strictness differences.

## 2026-03-13 — Never use `git commit --amend` after pushing

**Mistake:** After pushing a commit, used `git commit --amend` to fix a TS error instead of
making a new fix commit. This rewrote the already-pushed commit hash, causing local/remote
divergence that required a rebase with merge conflicts to resolve — turning a simple one-line
fix into a multi-step conflict resolution exercise.

**Pattern:** `--amend` rewrites history. Once a commit is pushed, its hash is shared state.
Amending it creates a new hash locally while the old one exists on the remote, guaranteeing
divergence.

**Rule:** Never use `git commit --amend` on commits that have already been pushed. Always create
a new commit for fixes. A clean `git push` is worth more than a pretty `git log`.

**Applied:** All post-push fixes. Use a new commit (`fix: ...`) instead of amending.

## 2026-03-14 — Use `txn.exec()` with `pqxx::params{}`, not `txn.exec_params()`

**Mistake:** Wrote `GitRepoRepository` using `txn.exec_params("query", arg1, arg2, ...)` which
is deprecated in the project's version of libpqxx. Build failed with `-Werror` because
`exec_params` triggers a deprecation warning.

**Pattern:** The codebase uses `txn.exec("query", pqxx::params{arg1, arg2, ...})` consistently
across all other repositories (ProviderRepository, ZoneRepository, etc.).

**Rule:** Always use `txn.exec("query", pqxx::params{...})` for parameterized queries, never
`txn.exec_params()`. Check existing DAL files for the correct API pattern before writing new
repository code.

**Applied:** All new DAL repository implementations.
