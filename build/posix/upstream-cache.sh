#!/usr/bin/env bash
# Optional verified donors never replace the canonical prepared source.
chromix_import_upstream_cache() {
  local phase="$1" platform="$2"
  if [ -n "${CHROMIX_UPSTREAM_CACHE_DIR:-}" ]; then
    python3 "$REPO/tools/import_upstream_cache.py" \
      --phase "$phase" --platform "$platform" --arch "$ARCH" \
      --workdir "$WORK" --cache-dir "$CHROMIX_UPSTREAM_CACHE_DIR"
  fi
}

chromix_has_upstream_toolchain() {
  [ -n "${CHROMIX_UPSTREAM_CACHE_DIR:-}" ] || return 1
  python3 - "$WORK/upstream-cache-import.json" <<'PY'
import json
import sys
from pathlib import Path
try:
    phase = json.loads(Path(sys.argv[1]).read_text())["phases"]["toolchain"]
    reused = phase.get("reused", {})
    valid = phase["status"] == "hit" and reused.get("clang") and reused.get("rust")
except (OSError, ValueError, KeyError, TypeError):
    valid = False
sys.exit(0 if valid else 1)
PY
}

chromix_configure_upstream_objects() {
  if [ -n "${CHROMIX_UPSTREAM_CACHE_DIR:-}" ] || [ -f "$WORK/.chromix-object-wrapper" ]; then
    python3 - "$OUT/args.gn" "$REPO/tools/upstream_object_cache.py" "$WORK" "${CHROMIX_UPSTREAM_CACHE_DIR:-}" <<'PY'
import json
from pathlib import Path
import shlex
import sys
path = Path(sys.argv[1])
marker = Path(sys.argv[3]) / ".chromix-object-wrapper"
if not marker.exists():
    try:
        result = json.loads((Path(sys.argv[4]) / "result.json").read_text())
        if result.get("status") != "hit" or result.get("extraction_scope") != "source-and-objects":
            sys.exit(0)
    except (OSError, ValueError, AttributeError):
        sys.exit(0)
command = "python3 " + shlex.quote(sys.argv[2]) + " compile --"
with path.open("a", encoding="utf-8") as output:
    output.write("cc_wrapper = " + json.dumps(command) + "\n")
marker.touch()
PY
  fi
}

chromix_select_restored_ninja() {
  CHROMIX_NINJA=ninja
  if [ -f "$SRC/.chromix-upstream-restored.json" ]; then
    CHROMIX_NINJA="$(python3 "$REPO/tools/restore_ninja.py" \
      --workdir "$WORK" --platform "$1" --arch "$ARCH")" || return 1
    export NINJA="$CHROMIX_NINJA"
  fi
}

chromix_build_restored_target() {
  local platform="$1" jobs="$2" rc=0 evidence_rc=0 target
  shift 2
  local evidence_args=(--workdir "$WORK" --platform "$platform" --arch "$ARCH"
    --ninja "$CHROMIX_NINJA")
  for target in "$@"; do
    evidence_args+=(--target "$target")
  done
  if [ -f "$SRC/.chromix-upstream-restored.json" ]; then
    python3 "$REPO/tools/restored_reuse_evidence.py" --phase before "${evidence_args[@]}" || return 1
  fi
  "$CHROMIX_NINJA" -C "$OUT" -j "$jobs" "$@" || rc=$?
  if [ "$rc" -eq 0 ] && [ "$platform" = linux ] &&
      [ -n "${GITHUB_OUTPUT:-}" ] && [ -x "$OUT/chrome" ]; then
    for target in "$@"; do
      if [ "$target" = chrome ]; then
        # Preserve compile progress independently of post-build reuse validation.
        printf 'compiled_ready=true\n' >> "$GITHUB_OUTPUT"
        break
      fi
    done
  fi
  if [ -f "$SRC/.chromix-upstream-restored.json" ]; then
    python3 "$REPO/tools/restored_reuse_evidence.py" --phase after "${evidence_args[@]}" \
      --exit-code "$rc" || evidence_rc=$?
  fi
  [ "$rc" -eq 0 ] || return "$rc"
  return "$evidence_rc"
}

chromix_report_upstream_plan() {
  if [ -n "${CHROMIX_UPSTREAM_CACHE_DIR:-}" ] || [ -f "$WORK/src/.chromix-upstream-restored.json" ]; then
    # A dry run records planned work; it cannot establish elapsed-time savings.
    "${CHROMIX_NINJA:-ninja}" -C "$OUT" -n "$@" > "$WORK/upstream-cache-plan.log" 2>&1
  fi
}
