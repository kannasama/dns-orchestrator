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
