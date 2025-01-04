#!/bin/bash

# Get number of CPUs for parallel processing
NR_CPUS=$(nproc)

# Debug mode flag
DEBUG=0
if [[ "${@-}" == *"--debug"* ]]; then
    DEBUG=1
fi

# Debug logging function
debug_log() {
    if [[ "${DEBUG-0}" == "1" ]]; then
        echo "[DEBUG] $*" >&2
    fi
}

# Function to extract the first SHA1 from changelog body
extract_sha1() {
    local content="$1"
    # Look for 40-character hex string in the entire content
    local sha1=$(echo "$content" | grep -o '[0-9a-f]\{40\}' | head -n 1 || echo "NO_SHA")
    debug_log "Extracted SHA1: $sha1"
    echo "$sha1"
}

# Function to check if a file was moved rather than deleted
is_moved() {
    local file="$1"
    local commit="$2"
    local ver="$3"

    debug_log "Checking if $file was moved in commit $commit for version $ver"
    # Check if the file appears in the same commit with R status (rename)
    # Look in both queue-${ver} and releases/${ver}.*
    local result=$(git log -1 --format=%H --full-history --diff-filter=R -- "$file" "releases/${ver}.*" | grep -q "$commit"; echo $?)
    if [ $result -eq 0 ]; then
        debug_log "File was moved"
    else
        debug_log "File was not moved"
    fi
    return $result
}

# Function to check if upstream id exists in releases directory
is_readded() {
    local ver="$1"
    local upstream_id="$2"

    debug_log "Checking if $upstream_id was readded for version $ver"
    # Recursive grep on releases/${ver}.* pattern
    local result=$(grep -r -q "$upstream_id" releases/${ver}.* 2>/dev/null; echo $?)
    if [ $result -eq 0 ]; then
        debug_log "Found readded in releases"
    else
        debug_log "Not found in releases"
    fi
    return $result
}

# Function to check if entry already exists in dropped_commits
is_known_drop() {
    local ver="$1"
    local upstream_id="$2"
    local dropped_commits="$3"

    local result=$(grep -q "^$ver $upstream_id\$" "$dropped_commits"; echo $?)
    if [ $result -eq 0 ]; then
        debug_log "Already known drop: $ver $upstream_id"
    else
        debug_log "New drop found: $ver $upstream_id"
    fi
    return $result
}

# Function to get the commit range to process
get_commit_range() {
    local dropped_commits="$1"

    debug_log "Getting commit range from $dropped_commits"

    if [ ! -f "$dropped_commits" ] || [ ! -s "$dropped_commits" ]; then
        debug_log "No dropped_commits file or empty file"
        echo "Processing full history" >&2
        echo ""  # Return empty string to indicate full history
        return 0
    fi

    # Get the last line and trim whitespace
    local last_line=$(tail -n 1 "$dropped_commits" | tr -d '[:space:]')
    debug_log "Last line from dropped_commits: $last_line"

    # Check if last_line is empty
    if [ -z "$last_line" ]; then
        debug_log "Last line is empty"
        echo "Last line is empty, processing full history" >&2
        echo ""
        return 0
    fi

    # Check if the last line is a valid commit
    if echo "$last_line" | grep -qE '^[0-9a-f]{40}$' && git rev-parse --verify "$last_line^{commit}" >/dev/null 2>&1; then
        debug_log "Valid commit found: $last_line"
        echo "Processing commits from $last_line..HEAD" >&2
        echo "$last_line..HEAD"
        return 0
    fi

    debug_log "Invalid commit in last line"
    echo "Last line is not a valid commit, processing full history" >&2
    echo ""
}

# Function to process a single commit
process_commit() {
    local ver="$1"
    local commit="$2"
    local tmpfile="$3"
    local dropped_commits="$4"

    debug_log "Processing commit $commit for version $ver"

    # Skip empty commits
    [ -z "$commit" ] && {
        debug_log "Skipping empty commit"
        return
    }

    # Get the files deleted in this commit
    debug_log "Getting deleted files for commit $commit"
    git show --diff-filter=D --name-only --pretty="" "$commit" -- "queue-${ver}" | \
    while IFS= read -r file; do
        # Skip empty lines
        [ -z "$file" ] && continue

        debug_log "Processing deleted file: $file"

        # Get commit content and SHA1
        debug_log "Getting content for $file from parent commit"
        local content=$(git show --format="%B" "$commit^:$file" 2>/dev/null)
        if [ $? -ne 0 ]; then
            debug_log "Failed to get content for $file"
            continue
        fi

        local sha1=$(extract_sha1 "$content")
        if [ "$sha1" = "NO_SHA" ]; then
            debug_log "No SHA1 found in content"
            continue
        fi

        # Skip if already known
        if [ -f "$dropped_commits" ] && is_known_drop "$ver" "$sha1" "$dropped_commits"; then
            debug_log "Skipping known drop: $ver $sha1"
            continue
        fi

        # Check if file was moved rather than deleted
        if ! is_moved "$file" "$commit" "$ver"; then
            # Check if file exists in the latest commit
            if ! git show HEAD:"$file" &>/dev/null; then
                debug_log "File not in HEAD"
                # Only output if the patch wasn't readded
                if ! is_readded "$ver" "$sha1"; then
                    debug_log "Adding new drop: $ver $sha1"
                    # Use flock for thread-safe file writing
                    (
                        flock -x 200
                        echo "$ver $sha1" >&3
                    ) 200>"$tmpfile.lock"
                fi
            else
                debug_log "File exists in HEAD"
            fi
        else
            debug_log "File was moved, skipping"
        fi
    done
}
export -f process_commit extract_sha1 is_moved is_readded is_known_drop debug_log

# Main processing
process_repo() {
    local tmpfile=$(mktemp)
    local dropped_commits="scripts/dropped_commits"

    debug_log "Starting process_repo with tmpfile: $tmpfile"

    # Create scripts directory if it doesn't exist
    mkdir -p scripts
    touch "$dropped_commits"

    # Get commit range to process
    local commit_range=$(get_commit_range "$dropped_commits")

    debug_log "Got commit range: $commit_range"

    # Process versions and collect new entries
    exec 3>"$tmpfile"
    while IFS= read -r ver; do
        # Skip empty lines and comments
        [[ -z "$ver" || "$ver" =~ ^# ]] && continue

        debug_log "Processing version $ver"

        # Get all commits that deleted files
        local git_log_cmd="git log --diff-filter=D --format=%H"
        if [ -n "$commit_range" ]; then
            git_log_cmd="$git_log_cmd $commit_range"
        fi
        git_log_cmd="$git_log_cmd -- queue-${ver}"

        debug_log "Git log command: $git_log_cmd"

        # Execute git log and ensure non-empty output
        local commits=$(eval "$git_log_cmd")
        if [ $? -ne 0 ]; then
            debug_log "git log failed for version $ver"
            continue
        fi

        if [ -z "$commits" ]; then
            debug_log "No commits found for version $ver"
            continue
        else
            debug_log "Found commits for version $ver: $commits"
        fi

        # Process commits (parallel only in non-debug mode)
        if [[ "${DEBUG-0}" == "1" ]]; then
            echo "$commits" | while read -r commit; do
                process_commit "$ver" "$commit" "$tmpfile" "$dropped_commits"
            done
        else
            echo "$commits" | \
            parallel --halt now,fail=1 -j "$NR_CPUS" --line-buffer \
                process_commit "$ver" {} "$tmpfile" "$dropped_commits"
        fi

    done < "active_kernel_versions"
    exec 3>&-

    debug_log "Processing complete, creating sorted file"

    # Create new sorted file with unique entries
    {
        if [ -s "$dropped_commits" ]; then
            debug_log "Keeping existing entries from dropped_commits"
            head -n -1 "$dropped_commits"
        fi
        debug_log "Adding new entries from tmpfile"
        cat "$tmpfile"
    } | sort -rV -k1,1 -k2,2 | uniq > "${tmpfile}.sorted"

    # Add current HEAD commit as the last line
    git rev-parse HEAD >> "${tmpfile}.sorted"

    # Only update if there are changes
    if ! cmp -s "${tmpfile}.sorted" "$dropped_commits"; then
        debug_log "Changes detected, updating dropped_commits"
        mv "${tmpfile}.sorted" "$dropped_commits"
        echo "Updated scripts/dropped_commits with new entries" >&2
    else
        debug_log "No changes detected"
        echo "No new entries to add to scripts/dropped_commits" >&2
        rm -f "${tmpfile}.sorted"
    fi

    # Cleanup
    rm -f "$tmpfile" "$tmpfile.lock"
}

# Ensure we're in a git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: Not in a git repository" >&2
    exit 1
fi

# Ensure active_kernel_versions file exists
if [ ! -f "active_kernel_versions" ]; then
    echo "Error: active_kernel_versions file not found" >&2
    exit 1
fi

# Ensure GNU parallel is available
if ! command -v parallel >/dev/null 2>&1; then
    echo "Error: GNU parallel is not installed" >&2
    exit 1
fi

# Export debug flag for parallel
export DEBUG="${DEBUG-0}"

# Run the main process
process_repo
