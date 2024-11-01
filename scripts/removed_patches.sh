#!/bin/bash

# Get number of CPUs for parallel processing
NR_CPUS=$(nproc)

# Function to extract the first SHA1 from changelog
extract_sha1() {
    local content="$1"
    # Look for first 40-character hex string in the content
    echo "$content" | grep -o -m 1 '[0-9a-f]\{40\}' || echo "NO_SHA"
}

# Function to check if a file was moved rather than deleted
is_moved() {
    local file="$1"
    local commit="$2"
    
    # Check if the file appears in the same commit with R status (rename)
    git log -1 --format=%H --full-history --diff-filter=R -- "$file" | grep -q "$commit"
}

# Function to check if upstream id exists in releases directory
is_readded() {
    local ver="$1"
    local upstream_id="$2"
    
    # Look for any file in releases/{ver}.* that contains the upstream id
    while read -r file; do
        if grep -q "$upstream_id" "$file" 2>/dev/null; then
            return 0  # Found a match
        fi
    done < <(find "releases" -type f -path "releases/${ver}.*" 2>/dev/null)
    return 1  # No match found
}

# Function to check if entry already exists in dropped_commits
is_known_drop() {
    local ver="$1"
    local upstream_id="$2"
    local dropped_commits="$3"
    
    grep -q "^$ver $upstream_id\$" "$dropped_commits"
    return $?
}

# Function to process a single commit
process_commit() {
    local ver="$1"
    local commit="$2"
    local tmpfile="$3"
    local dropped_commits="$4"
    
    # Get the files deleted in this commit
    git show --diff-filter=D --name-only --pretty="" "$commit" -- "queue-${ver}" | \
    while IFS= read -r file; do
        # Skip empty lines
        [ -z "$file" ] && continue
        
        # Get commit content and SHA1 first to minimize git operations
        content=$(git show "$commit^:$file" 2>/dev/null) || continue
        sha1=$(extract_sha1 "$content")
        [ "$sha1" = "NO_SHA" ] && continue
        
        # Skip if already known
        if [ -f "$dropped_commits" ] && is_known_drop "$ver" "$sha1" "$dropped_commits"; then
            continue
        fi
        
        # Check if file was moved rather than deleted
        if ! is_moved "$file" "$commit"; then
            # Check if file exists in the latest commit
            if ! git show HEAD:"$file" &>/dev/null; then
                # Only output if the patch wasn't readded
                if ! is_readded "$ver" "$sha1"; then
                    # Use flock for thread-safe file writing
                    (
                        flock -x 200
                        echo "$ver $sha1" >&3
                    ) 200>"$tmpfile.lock"
                fi
            fi
        fi
    done
}
export -f process_commit extract_sha1 is_moved is_readded is_known_drop

# Main processing
process_repo() {
    local tmpfile=$(mktemp)
    local dropped_commits="scripts/dropped_commits"
    
    # Create scripts directory if it doesn't exist
    mkdir -p scripts
    touch "$dropped_commits"
    
    # Process versions and collect new entries
    exec 3>"$tmpfile"
    while IFS= read -r ver; do
        # Skip empty lines and comments
        [[ -z "$ver" || "$ver" =~ ^# ]] && continue
        
        echo "Processing version $ver..." >&2
        
        # Get all commits that deleted files
        commits=$(git log --diff-filter=D --format="%H" -- "queue-${ver}")
        
        # Process commits in parallel
        echo "$commits" | \
        parallel --halt now,fail=1 -j "$NR_CPUS" --line-buffer \
            process_commit "$ver" {} "$tmpfile" "$dropped_commits"
        
    done < "active_kernel_versions"
    exec 3>&-
    
    # Create new sorted file with unique entries
    {
        cat "$dropped_commits"
        cat "$tmpfile"
    } | sort -V -k1,1 -k2,2 | uniq > "${tmpfile}.sorted"
    
    # Only update if there are changes
    if ! cmp -s "${tmpfile}.sorted" "$dropped_commits"; then
        mv "${tmpfile}.sorted" "$dropped_commits"
        echo "Updated scripts/dropped_commits with new entries" >&2
    else
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

# Run the main process
process_repo
