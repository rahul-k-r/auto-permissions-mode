---
description: Enforce structured interactive option resolution for planning branch points and action denials
always_on: true
---

# Interactive Decisions & Remediation Rules

## 1. Inline Alternatives on Risky Actions
When an action is classified `deny`, `ask`, or `force_ask` by the security gatekeeper:
- NEVER ask open-ended questions in plain chat markdown (e.g. "What would you like me to do?").
- NEVER attempt the same blocked/flagged command with slight syntax tweaks.
- ALWAYS invoke `ask_question` immediately, on the first presentation of the decision — do not show a plain
  block/confirmation message and wait for the user to decline before offering alternatives. The user should never
  have to click "No" and then separately ask what else they could do.
  - Populate options directly from the gatekeeper's suggested alternatives.
  - For `ask`/`force_ask`, include the gatekeeper's originally-proposed action as one of the selectable options
    (it's a confirmation gate, not a hard block — the user can still choose to proceed as originally asked).
  - Prefix the gatekeeper-recommended option with `(Recommended)`.
  - Format options from the user's perspective with concise, high-context impact descriptions (1 sentence, 10–25 words per option, e.g., "(Recommended) Dry-run preview: lists untracked files without modifying anything"). Avoid both cryptic 3-word labels and bloated essays.
- Execute the chosen option immediately upon user selection.

## 2. Planning Branch Points ("The Fine Line")
During planning, invoke `ask_question` ONLY when:
- There are confident, divergent architectural or structural path branches (e.g., library selection, data schema model, destructive vs non-destructive migration).
- The prompt is underspecified on that point.
- Keep to a MAXIMUM of 1 modal per planning session (max 2 questions).
- For routine implementation choices, assume the best practice, proceed autonomously, and document the decision in the plan.

## 3. Upfront Scoping & Variation Resolution
Before proposing actions that have multiple viable scopes, execution targets, or variations:
- High-impact scope choices (e.g. `--global` system install vs project/local install vs virtualenv).
- Tooling or package managers (`npm` vs `pnpm` vs `yarn`, `pytest` vs `unittest`).
- Test suite scopes (running entire repository tests vs fast unit test targeting).
- Cleanup or migration modes (clean build vs incremental, hard wipe vs backup).
DO NOT assume, guess, or execute a high-impact variant (such as `--global` or destructive flags) blindly.
ALWAYS invoke `ask_question` UPFRONT so the user selects their preferred variation before any command is executed.
