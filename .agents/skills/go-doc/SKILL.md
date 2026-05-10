---
name: go-doc
description: |
  Documentation Rules for go code.
  You must follow this rule when generating documentation for go code in addition to [general documentation rule](/.agents/skills/doc/SKILL.md).
---

## Rules

- "Doc comments" should appear immediately before top-level package, const,
  func, type, and var declarations with no intervening newlines.
- Every exported (capitalized) name should have a doc comment.
- Go doc comments must use complete sentences. The first sentence should start
  with the name of the symbol being declared.
- For a package comment, the first sentence should begin with "Package"
  followed by the package name.
- For a command, the first sentence should begin with the capitalized name of
  the program itself.
- A type’s doc comment should explain what each instance of that type
  represents or provides. If the zero value has a useful meaning, it should be
  documented.
- A function’s doc comment should explain what the function returns or, for
  functions called for side effects, what it does.
- Named parameters and results can be referred to directly in the comment,
  without any special syntax like backquotes.
