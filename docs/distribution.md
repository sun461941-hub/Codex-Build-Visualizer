# Distribution

Build a skills-only plugin ZIP for local installation or marketplace staging:

```bash
python3 -B scripts/package_plugin.py \
  --mode plugin --version 1.0.0 --output /existing/directory/codex-build-visualizer.zip
```

The archive has one plugin root and contains only the required manifest plus the runtime allowlist:

```text
.codex-plugin/plugin.json
skills/codex-build-visualizer/SKILL.md
skills/codex-build-visualizer/agents/openai.yaml
skills/codex-build-visualizer/assets/icon.svg
skills/codex-build-visualizer/assets/viewer.html
skills/codex-build-visualizer/scripts/trace.py
```

Build a repository-ready ZIP instead:

```bash
python3 -B scripts/package_plugin.py \
  --mode repo --version 1.0.0 --output /existing/directory/codex-build-visualizer-repo.zip
```

Repository mode adds a repo-scoped `.agents/plugins/marketplace.json`, the plugin under `plugins/codex-build-visualizer/`, maintainer tests, distribution documentation, and a GitHub Actions matrix for Ubuntu, macOS, and Windows with Python 3.9 and 3.12. A separate pinned Playwright job installs Chromium and checks CSP execution, mobile overflow, focus preservation, literal search, finite chart geometry, the 100-node timeline bound, and zero standalone subresource requests. Extract it at a new repository root, review the generated files, then add the marketplace with `codex plugin marketplace add owner/repository` after publishing the repository.

The builder uses an explicit file allowlist, fixed ZIP timestamps and modes, normalized LF text, stable member ordering, and stored entries, so repeated builds from identical sources are byte-identical. It rejects links, reparse points, non-regular sources, invalid SemVer, unsafe output parents, and an output path that already exists. Runtime traces, `.codex-visualizer`, Git data, bytecode, caches, and unrelated files are never discovered or packaged.

The generated manifest intentionally omits `author`, `developerName`, `license`, repository URLs, and legal URLs instead of inventing publisher metadata. It is a valid minimal manifest for local and repository marketplace testing, not a public-directory submission artifact. Before public submission, add verified publisher identity, the complete install-surface `interface` metadata, root-level logo/composer assets, legal links, and a chosen license as required by the current submission rules. A generated package is never automatically published.

Before a public release, run and pass the generated CI matrix on native Windows as well as macOS and Linux. The current environment may skip the real-browser test when Chromium is absent; the generated GitHub job installs it and must pass. This coverage does not by itself prove Windows ACL or every reparse-point race, and the browser check is a focused compatibility/performance probe rather than a complete accessibility audit.
