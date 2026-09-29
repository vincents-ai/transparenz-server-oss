#!/usr/bin/env bash
# Clean-room release gate.
#
# A release must be constructible from a fresh clone with access to nothing but
# declared module registries:
#
#     git clone <repo> && nix build
#
# A filesystem `replace` directive in go.mod silently breaks that guarantee: the
# build succeeds on a developer workstation with adjacent checkouts and fails on
# a clean runner. This gate fails the build instead.
#
# It also rejects the absolute-path replaces that are worse still, because they
# hardcode one developer's home directory into a published module.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

status=0

# Deliberate filesystem replaces, one module path per line, in a file named
# clean-room-allow next to this script. These are reviewed exceptions, not a
# loophole: a private sibling repository cannot be consumed as a versioned Go
# module, because the public proxy cannot fetch private repositories, so a
# filesystem replace is sometimes the only workable pattern. What matters is
# that it is declared rather than discovered, so a new one still fails.
ALLOW_FILE="$(dirname "${BASH_SOURCE[0]}")/clean-room-allow"
declare -A ALLOWED=()
if [[ -f "$ALLOW_FILE" ]]; then
	while IFS= read -r line; do
		line="${line%%#*}"
		line="$(echo "$line" | tr -d '[:space:]')"
		[[ -z "$line" ]] && continue
		ALLOWED["$line"]=1
	done < "$ALLOW_FILE"
fi

report() {
	printf '  %s\n' "$*"
}

echo "==> Clean-room release gate: ${REPO_ROOT}"

# --- 1. No filesystem replace directives -------------------------------------
echo "==> Checking go.mod for filesystem replace directives"

found_replace=0
while IFS= read -r modfile; do
	rel="${modfile#"$REPO_ROOT"/}"
	dir="$(dirname "$rel")"

	# Strip line comments before matching so documentation examples in go.mod
	# do not trip the gate.
	replaces="$(sed 's|//.*||' "$modfile" | grep -E '^[[:space:]]*replace' || true)"
	if [[ -z "$replaces" ]]; then
		continue
	fi

	# Each replace is either single-line `replace X => Y` or a block form.
	# Deliberate entries named in clean-room-allow are reported but not failed.
	offending="$(sed 's|//.*||' "$modfile" \
		| grep -E '(^|[[:space:]])(=>)[[:space:]]*(\.\.?/|/|[A-Za-z]:\\)' || true)"
	offending="$(
		while IFS= read -r line; do
			[[ -z "$line" ]] && continue
			mod="$(echo "$line" | awk '{print $2}')"
			if [[ -n "${ALLOWED[$mod]:-}" ]]; then
				# stderr, so the notice is not captured into $offending below
				printf '    allowed: %s\n' "$line" >&2
			else
				echo "$line"
			fi
		done <<< "$offending"
	)"

	if [[ -n "$offending" ]]; then
		found_replace=1
		printf '\n  FAIL: %s contains a filesystem replace directive\n' "$rel"
		echo "$offending" | while IFS= read -r line; do
			report "    $line"
		done
	fi

	# Block-form replaces (`replace (` ... `)`) are legal only when every target
	# is a module path or version, never a directory.
	if grep -qE '^replace[[:space:]]*\(' "$modfile"; then
		report "  note: $rel uses block-form replace - review manually"
	fi
done < <(find . -name go.mod -not -path './.git/*' -not -path '*/node_modules/*')

if [[ "$found_replace" -eq 0 ]]; then
	echo "  OK: no filesystem replace directives"
else
	echo
	echo "  A release built from these go.mod files depends on directories that"
	echo "  will not exist on a clean runner. Either publish the dependency and"
	echo "  use a tagged version, or vendor it."
	echo "  If the dependency is a private repository and a local checkout is"
	echo "  genuinely required, declare it in scripts/clean-room-allow so the"
	echo "  exception is explicit and reviewed."
	status=1
fi

# --- 2. No hardcoded absolute developer paths --------------------------------
echo
echo "==> Checking for hardcoded absolute paths in go.mod files"
abs_hits=0
while IFS= read -r modfile; do
	rel="${modfile#"$REPO_ROOT"/}"
	if sed 's|//.*||' "$modfile" | grep -qE '/home/[a-z]|/Users/'; then
		printf '  FAIL: %s hardcodes a developer home directory\n' "$rel"
		abs_hits=1
	fi
done < <(find . -name go.mod -not -path './.git/*' -not -path '*/node_modules/*')

[[ "$abs_hits" -eq 0 ]] && echo "  OK: no hardcoded home directories"
[[ "$abs_hits" -eq 1 ]] && status=1

# --- 3. No go.work committed -----------------------------------------------
# A committed go.work is workstation-only glue. It makes local builds succeed
# while release builds fail, which is the exact failure this gate exists to
# catch. go.work.sum is likewise workspace state.
echo
echo "==> Checking for committed workspace files"
if git rev-parse --git-dir >/dev/null 2>&1; then
	ws_tracked="$(git ls-files | grep -E '^go\.work(\.sum)?$' || true)"
	if [[ -n "$ws_tracked" ]]; then
		printf '  FAIL: workspace file(s) committed to the repository:\n'
		echo "$ws_tracked" | while IFS= read -r line; do
			report "    $line"
		done
		report "  Add go.work and go.work.sum to .gitignore and remove them from the index."
		status=1
	else
		echo "  OK: no committed go.work"
	fi
else
	echo "  SKIP: not a git repository"
fi


# --- Nix release build must actually work ---------------------------------
# A stale vendorHash breaks `nix build` while every other check still passes,
# because the hash is the only place the vendored dependency set is verified.
# That happened: go.mod moved to v0.2.7, the hash did not, and this gate
# reported PASS for a repository whose release build could not run.
echo
echo "==> Checking the Nix release build"
if command -v nix >/dev/null 2>&1 && [ -f flake.nix ]; then
	if [[ "${CLEAN_ROOM_SKIP_NIX:-0}" == "1" ]]; then
		echo "  SKIP: CLEAN_ROOM_SKIP_NIX=1"
	else
		if nix build .#server --no-link >/dev/null 2>&1; then
			echo "  OK: nix build .#server succeeds"
		else
			echo "  FAIL: nix build .#server does not succeed."
			echo "        A stale vendorHash is the usual cause; recompute it with"
			echo "          nix build .#server   (set vendorHash = lib.fakeHash first)"
			echo "        and copy the 'got:' hash into flake.nix. Set CLEAN_ROOM_SKIP_NIX=1"
			echo "        to skip this when nix is unavailable."
			status=1
		fi
	fi
else
	echo "  SKIP: nix not available, or no flake.nix"
fi

# --- Result -----------------------------------------------------------------
echo
if [[ "$status" -eq 0 ]]; then
	echo "PASS: repository is buildable from a clean checkout."
else
	echo "FAIL: see above. A release from this state is not reproducible."
fi
exit "$status"
