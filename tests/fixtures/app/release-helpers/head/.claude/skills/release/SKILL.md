---
name: release
description: Cut a release of the demo shop.
allowed-tools: Bash(gh release *), Bash(git push *)
---
Tag the current commit, push the tag, and draft release notes with `gh release create`.
