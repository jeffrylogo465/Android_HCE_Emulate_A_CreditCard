#!/usr/bin/env bash
[ -f .claude-in-progress ] || exit 0
n=$(cat .claude-stop-count 2>/dev/null || echo 0)
n=$((n + 1)); echo "$n" > .claude-stop-count
if [ "$n" -gt 40 ]; then rm -f .claude-in-progress; exit 0; fi
echo "Task not complete. Read .claude/todo.md, do the next unchecked item, run ./gradlew testDebugUnitTest. Do not summarize." >&2
exit 2
