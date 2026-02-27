# Lessons Learned

## 2026-02-26 — Indentation changes must include code blocks

**Pattern:** When asked to update indentation standards in documentation, the scope includes
indentation *inside fenced code blocks* (` ``` `), not just prose bullet lists and inline references.

**Rule:** Before marking an indentation task complete, always scan for 4-space-indented lines
inside code fences (` ```cpp `, ` ```sql `, ` ```bash `, ` ```json `, ` ``` `, etc.) across
all affected files.

**Verification step to add:** After prose changes, run a regex search for lines matching
`^    ` (4 leading spaces) inside code blocks to catch missed indentation.
