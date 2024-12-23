#!/bin/bash
#set -x
# Enable error tracing but don't exit on error for the whole script
set -E

# Global variables
LINUX_DIR="$HOME/linux"
TEMP_PATCH=""
PENDING_DIR="$HOME/pending/series"

# Function to generate unique message ID
generate_message_id() {
    local timestamp=$(date +%Y%m%d%H%M%S)
    local random=$(openssl rand -hex 8)
    echo "<${timestamp}-${random}@stable.kernel.org>"
}

# Function to generate unique response filename
generate_response_filename() {
    local mbox_file="$1"
    local base_dir="$HOME/Mail/stable/respo"
    local subject=$(formail -xSubject: < "$mbox_file" | tr '\n' ' ')
    local sender=$(formail -xFrom: < "$mbox_file" | tr -dc '[:alnum:]@.<> _-')
    local date_str=$(formail -xDate: < "$mbox_file")
    local timestamp=$(date -d "$date_str" +%Y%m%d%H%M%S 2>/dev/null || date +%Y%m%d%H%M%S)
    local message_id=$(formail -xMessage-ID: < "$mbox_file" | tr -dc '[:alnum:]@._-')

    # Clean subject (take first 30 chars, remove special chars)
    local clean_subject=$(echo "$subject" | tr -dc '[:alnum:] ' | tr ' ' '_' | cut -c1-30)

    # Clean sender email (extract just the email part if possible, otherwise use whole string)
    local clean_sender=$(echo "$sender" | grep -o '[^< ]*@[^> ]*' || echo "$sender" | tr -dc '[:alnum:]@._-')

    # Create unique filename
    local filename="${clean_sender}-${timestamp}-${clean_subject}-${message_id}.response"

    echo "${base_dir}/${filename}"
}

check_response_exists() {
    local mbox_file="$1"
    local response_file=$(generate_response_filename "$mbox_file")

    if [ -f "$response_file" ]; then
        echo "Response file already exists: $response_file"
        return 0
    fi
    return 1
}

# Function to check if we should ignore this mail based on sender
should_ignore_mail() {
    local mbox_file="$1"
    local from=$(formail -xFrom: < "$mbox_file" | sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$//g')

    if check_response_exists "$MBOX_FILE"; then
        exit 0
    fi

    # List of authors to ignore
    if [[ "$from" =~ ^"Sasha Levin".*$ ]] || \
       [[ "$from" =~ ^"Linux Kernel Distribution System".*$ ]] || \
       [[ "$from" =~ ^"Greg Kroah-Hartman".*$ ]]; then
        return 0
    fi
    return 1
}

# Function to check if mail contains a git patch
is_git_patch() {
    local mbox_file="$1"

    # We need to use formail -c to process the entire email including headers and body
    formail -c < "$mbox_file" | awk '
        BEGIN {
            found=0
            p=0
            in_headers=1
            has_patch_subject=0
            has_diff=0
        }

        # Track when we move from email headers to body
        in_headers && /^$/ { in_headers=0; next }

        # Look for [PATCH] in subject line while in headers
        in_headers && /^Subject:.*\[PATCH/ { has_patch_subject=1; next }

        # Look for patch separator
        !in_headers && /^---$/ { p=NR; next }

        # Look for diff or index after separator
        p && (/^diff --git/ || /^index [0-9a-f]/) { has_diff=1; exit }

        # Exit if we go too far past the separator
        NR > p+20 && p { exit }

        END { exit !(has_patch_subject && has_diff) }
    '
}

# Function to decode UTF-8 email subject
decode_subject() {
    local encoded_subject="$1"
    # Check if subject is UTF-8 encoded
    if echo "$encoded_subject" | grep -q "=?UTF-8?"; then
        # Use perl to decode the subject
        echo "$encoded_subject" | perl -MEncode -CS -ne '
            while (/=\?UTF-8\?[Bb]\?([^?]+)\?=/g) {
                my $decoded = decode("MIME-Header", $&);
                s/\Q$&\E/$decoded/;
            }
            print;
        '
    else
        echo "$encoded_subject"
    fi
}

# Function to extract series info from subject
extract_series_info() {
    local subject="$1"
    # Pattern to match [PATCH X/N] format
    local part_pattern='\[PATCH.*[[:space:]]([0-9]+)/([0-9]+)\]'
   
    if [[ $subject =~ $part_pattern ]]; then
        local current="${BASH_REMATCH[1]}"
        local total="${BASH_REMATCH[2]}"
        echo "$current $total"
        return 0
    fi
    return 1
}

# Function to get message ID from mail
get_message_id() {
    local mbox_file="$1"
    formail -xMessage-ID: < "$mbox_file" | tr -d '[:space:]'
}

# Function to get in-reply-to ID from mail
get_in_reply_to() {
    local mbox_file="$1"
    formail -xIn-Reply-To: < "$mbox_file" | tr -d '[:space:]'
}

# Function to generate series directory name
get_series_dir() {
    local message_id="$1"
    local in_reply_to="$2"

    # Use the first message's ID (either this message if it's first, or the one it replies to)
    local series_id="${in_reply_to:-$message_id}"

    # Create a safe directory name from the message ID
    echo "${series_id}" | sed 's/[<>]//g' | tr -c '[:alnum:]' '_'
}

# Function to generate a more unique patch filename
generate_patch_filename() {
    local base_dir="$1"
    local part="$2"
    local subject="$3"
    local sender="$4"
    local timestamp="$5"
    local message_id="$6"

    # Clean subject to use in filename (take first 30 chars, remove special chars)
    local clean_subject=$(echo "$subject" | tr -dc '[:alnum:] ' | tr ' ' '_' | cut -c1-30)

    # Clean sender email (extract just the email part if possible, otherwise use whole string)
    local clean_sender=$(echo "$sender" | grep -o '[^< ]*@[^> ]*' || echo "$sender" | tr -dc '[:alnum:]@._-')

    # Create unique filename combining all elements
    local clean_message_id=$(echo "$message_id" | tr -dc '[:alnum:]@._-')
    echo "${part}-${clean_sender}-${timestamp}-${clean_subject}-${clean_message_id}.mbox"
}

# Function to strip leading zeros from a number
strip_leading_zeros() {
    local num="$1"
    echo "$((10#$num))"  # Force base-10 interpretation
}

# Function to store patch in series directory
store_patch() {
    local mbox_file="$1"
    local series_dir="$2"
    local part=$(strip_leading_zeros "$3")

    # Extract additional information for filename
    local subject=$(formail -xSubject: < "$mbox_file" | tr '\n' ' ')
    local sender=$(formail -xFrom: < "$mbox_file" | tr -dc '[:alnum:]@.<> _-')
    local date_str=$(formail -xDate: < "$mbox_file")
    local timestamp=$(date -d "$date_str" +%Y%m%d%H%M%S 2>/dev/null || date +%Y%m%d%H%M%S)
    local message_id=$(formail -xMessage-ID: < "$mbox_file")

    # Generate unique filename
    local filename=$(generate_patch_filename "$series_dir" "$part" "$subject" "$sender" "$timestamp" "$message_id")

    mkdir -p "$series_dir"
    cp "$mbox_file" "$series_dir/$filename"

    # Create a symlink with just the part number for backward compatibility
    ln -sf "$filename" "$series_dir/$part.mbox"
}

# Function to check if series is complete
is_series_complete() {
    local series_dir="$1"
    local total_parts="$2"

    for ((i=1; i<=total_parts; i++)); do
        if [ ! -f "$series_dir/$i.mbox" ]; then
            return 1
        fi
    done
    return 0
}

# Function to clean subject for searching
clean_subject() {
    local subject="$1"
    local cleaned_subject

    # Special handling for FAILED patch subjects
    if [[ "$subject" =~ FAILED:.*\"([^\"]+)\".*failed[[:space:]]to[[:space:]]apply ]]; then
        # Extract the actual patch subject from within quotes
        cleaned_subject="${BASH_REMATCH[1]}"
    else
        # Regular subject cleaning
        cleaned_subject=$(echo "$subject" | \
            sed -E 's/\[[^]]*\]//g' | \
            tr '\n' ' ' | \
            tr -s ' ' | \
            sed -E 's/^[[:space:]]+|[[:space:]]+$//g')  # Trim whitespace
    fi

    # Remove leading "Re: " if present
    cleaned_subject=$(echo "$cleaned_subject" | sed -E 's/^Re: *//')

    echo "$cleaned_subject"
}

# Function to find commit by subject in origin/master
find_commit_by_subject() {
    local subject="$1"
    local linux_dir="$2"
    local cleaned_subject

    cd "$linux_dir"
    cleaned_subject=$(clean_subject "$subject")
    cleaned_subject=$(printf '%s' "$cleaned_subject" | sed 's/[[\.*^$/]/\\&/g')

    git log origin/master --format="%H" --grep="^${cleaned_subject}$" -1
}

# Function to apply previous patches in series
apply_series_patches() {
    local series_dir="$1"
    local current_part="$2"
    local linux_dir="$3"

    cd "$linux_dir"

    # Apply all patches up to but not including the current one
    for ((i=1; i<current_part; i++)); do
        local patch_file="$series_dir/$i.mbox"
        if [ ! -f "$patch_file" ] || ! git am "$patch_file" >/dev/null 2>&1; then
            echo "Error: Failed to apply patch $i in series"
            git am --abort >/dev/null 2>&1
            return 1
        fi
    done

    return 0
}

# Function to extract kernel versions from subject
extract_kernel_versions() {
    local subject="$1"
    local active_versions_file="$HOME/stable-queue/active_kernel_versions"
    local found_versions=()
    local decoded_subject

    decoded_subject=$(decode_subject "$subject")

    while IFS= read -r version; do
        # Check for both with and without v prefix
        if echo "$decoded_subject" | grep -q "\\b${version}\\b\|${version}[.-]\|\\bv${version}\\b\|v${version}[.-]"; then
            found_versions+=("$version")
        fi
    done < <(sort -rV "$active_versions_file")

    if [ ${#found_versions[@]} -gt 0 ]; then
        echo "${found_versions[*]}"
        return 0
    fi

    cat "$active_versions_file"
}

# Function to extract commit SHA1 from email body
extract_commit_sha1() {
    local email_body="$1"
    local sha1=""

    sha1=$(echo "$email_body" | grep -E "commit [0-9a-f]{40} upstream" | \
           sed -E 's/.*commit ([0-9a-f]{40}) upstream.*/\1/')

    if [ -n "$sha1" ]; then
        echo "$sha1"
        return 0
    fi

    sha1=$(echo "$email_body" | grep -E "\[ Upstream commit [0-9a-f]{40} \]" | \
           sed -E 's/.*\[ Upstream commit ([0-9a-f]{40}) \].*/\1/')

    if [ -n "$sha1" ]; then
        echo "$sha1"
        return 0
    fi

    return 1
}

# Function to get commit author information
get_commit_author() {
    local linux_dir="$1"
    local sha1="$2"

    cd "$linux_dir"
    git log -1 --format="%an <%ae>" "$sha1"
}

# Function to get sorted kernel versions
get_sorted_versions() {
    sort -rV "$HOME/stable-queue/active_kernel_versions"
}

# Function to check if version1 is newer than version2
is_version_newer() {
    local v1="$1"
    local v2="$2"
   
    if [ "$(echo -e "$v1\n$v2" | sort -V | tail -n1)" = "$v1" ]; then
        return 0
    fi
    return 1
}

# Function to check newer kernels for commit
check_newer_kernels() {
    local sha1="$1"
    local target_versions="$2"
    local linux_dir="$3"
    local -n c_results=$4
   
    cd "$linux_dir"
    local all_versions=($(get_sorted_versions))
    local target_array=($target_versions)
    local newest_target=${target_array[0]}
    local temp_dir=$(mktemp -d)
    local pids=()
   
    # Function to check a single branch and write results to temp file
    check_single_branch() {
        local version="$1"
        local branch="pending-${version}"
        local result_file="$temp_dir/$version"
       
        # Check if branch exists
        if ! git rev-parse --verify "$branch" >/dev/null 2>&1; then
            echo "$version.y | Branch not found" > "$result_file"
            return
        fi
       
        # Check if commit is an ancestor using merge-base
        if [ "$(git merge-base "$branch" "$sha1")" = "$sha1" ]; then
            echo "$version.y | Present (exact SHA1)" > "$result_file"
            return
        fi
       
        # Try to find by subject if SHA1 not found
        local subject
        subject=$(git log -1 --format=%s "$sha1")
        if [ -n "$subject" ]; then
            # Search in the specific branch
            local found_commit
            found_commit=$(git log "$branch" --format=%H --grep="^${subject}$" -1)
            if [ -n "$found_commit" ]; then
                echo "$version.y | Present (different SHA1: ${found_commit:0:12})" > "$result_file"
            else
                echo "$version.y | Not found" > "$result_file"
            fi
        else
            echo "$version.y | Not found" > "$result_file"
        fi
    }
   
    # Launch parallel processes for each relevant version
    for version in "${all_versions[@]}"; do
        if is_version_newer "$version" "$newest_target"; then
            check_single_branch "$version" &
            pids+=($!)
        fi
    done
   
    # Wait for all processes to complete
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
   
    # Collect results in order
    local results=()
    for version in "${all_versions[@]}"; do
        if is_version_newer "$version" "$newest_target"; then
            if [ -f "$temp_dir/$version" ]; then
                results+=("$(cat "$temp_dir/$version")")
            fi
        fi
    done
   
    # Clean up
    rm -rf "$temp_dir"
   
    if [ ${#results[@]} -gt 0 ]; then
        c_results+=("")
        c_results+=("Status in newer kernel trees:")
        c_results+=("${results[@]}")
    fi
}

# Function to validate commit exists in upstream
validate_commit() {
    local sha1="$1"
    local linux_dir="$2"

    cd "$linux_dir"
    git rev-list origin/master | grep -q "^$sha1"
}

# Function to compare patch with upstream
compare_with_upstream() {
    local mbox_file="$1"
    local sha1="$2"
    local linux_dir="$3"
    local debug_output=()

    if [[ ! $sha1 =~ ^[0-9a-f]{40}$ ]] || [ "$sha1" = "0000000000000000000000000000000000000000" ]; then
        return 0
    fi

    cd "$linux_dir"
   
    # Extract subject to determine target kernel versions
    local subject=$(formail -xSubject: < "$mbox_file")
    local kernel_versions=($(extract_kernel_versions "$subject"))
   
    if [ ${#kernel_versions[@]} -eq 0 ]; then
        debug_output+=("No kernel versions found in subject, cannot compare")
        printf '%s\n' "${debug_output[@]}"
        return 1
    fi
   
    # Use the newest version for comparison since it's closest to upstream
    local version=${kernel_versions[0]}
    local stable_branch="stable/linux-${version}.y"
    local temp_branch="temp-compare-${version}-$(date +%s)"
    local current_branch=$(git rev-parse --abbrev-ref HEAD)
   
    # Try to check out the stable branch
    if ! git checkout -q "$stable_branch" 2>/dev/null; then
        debug_output+=("Failed to find stable branch ${stable_branch}")
        printf '%s\n' "${debug_output[@]}"
        return 1
    fi
   
    # Create temporary branch based on the stable branch
    git checkout -b "$temp_branch" >/dev/null 2>&1
   
    if git am "$mbox_file" >/dev/null 2>&1; then
        # Get the SHA1 of our newly applied patch
        local new_sha1=$(git rev-parse HEAD)
       
        debug_output+=("")
       
        # Compare the ranges using range-diff
        if ! git range-diff "${sha1}^".."$sha1" "${new_sha1}^".."$new_sha1"; then
            debug_output+=("Failed to generate range-diff")
        fi
       
        # Clean up after range-diff
        git checkout -q "$current_branch"
        git branch -D "$temp_branch" >/dev/null 2>&1
    else
        # Clean up failed git-am
        git am --abort >/dev/null 2>&1
        git checkout -q "$current_branch"
        git branch -D "$temp_branch" >/dev/null 2>&1
       
        debug_output+=("Failed to apply patch cleanly, falling back to interdiff...")
        debug_output+=("")
       
        # Fall back to interdiff
        TEMP_PATCH=$(mktemp)
        UPSTREAM_PATCH=$(mktemp)
        FILTERED_PATCH=$(mktemp)
        FILTERED_UPSTREAM=$(mktemp)
       
        # Extract patch content from mbox
        formail -I "" < "$mbox_file" | sed '1,/^$/d' > "$TEMP_PATCH"
       
        # Get upstream patch
        git format-patch -k --stdout --no-signature "${sha1}^..${sha1}" | \
        sed '1,/^$/d' > "$UPSTREAM_PATCH"
       
        # Filter out metadata lines that might cause comparison issues
        for file in "$TEMP_PATCH" "$UPSTREAM_PATCH"; do
            output_file="${file/PATCH/FILTERED}"
            sed -E '/^(index |diff --git |new file mode |deleted file mode |old mode |new mode )/d' "$file" > "$output_file"
        done
       
        # Run interdiff
        if ! interdiff "$FILTERED_UPSTREAM" "$FILTERED_PATCH" 2>"${TEMP_PATCH}.err"; then
            # If interdiff fails, include error output
            if [ -s "${TEMP_PATCH}.err" ]; then
                debug_output+=("interdiff error output:")
                debug_output+=("$(cat "${TEMP_PATCH}.err")")
            fi
           
            # Fall back to standard diff
            debug_output+=("interdiff failed, falling back to standard diff...")
            if ! diff -u "$FILTERED_UPSTREAM" "$FILTERED_PATCH" >"${TEMP_PATCH}.diff"; then
                if [ -s "${TEMP_PATCH}.diff" ]; then
                    debug_output+=("$(cat "${TEMP_PATCH}.diff")")
                fi
            fi
        fi
       
        # Clean up temporary files
        rm -f "$TEMP_PATCH" "$UPSTREAM_PATCH" "$FILTERED_PATCH" "$FILTERED_UPSTREAM" "${TEMP_PATCH}.err" "${TEMP_PATCH}.diff"
    fi
   
    printf '%s\n' "${debug_output[@]}"
}

# Function to test commit on a branch
test_commit_on_branch() {
    local sha1="$1"
    local version="$2"
    local linux_dir="$3"
    local mbox_file="$4"
    local series_dir="$5"
    local current_part="$6"
    local -n results=$7
    local -n errors=$8
    local result=0

    cd "$linux_dir"
    local branch="stable/linux-${version}.y"
    local temp_branch="temp-${version}-${sha1:0:8}"

    # Try to checkout the stable branch
    if ! git checkout -q "$branch" 2>/dev/null; then
        results+=("stable/linux-${version}.y | Failed (branch not found) | N/A")
        return 1
    fi

    git checkout -b "$temp_branch"

    # Apply series patches if needed
    if [ -n "$series_dir" ] && [ "$current_part" -gt 1 ]; then
        if ! apply_series_patches "$series_dir" "$current_part" "$linux_dir"; then
            results+=("stable/linux-${version}.y | Failed (series apply) | N/A")
            git checkout -q "$branch"
            git branch -D "$temp_branch"
            return 1
        fi
    fi

    # Apply current patch
    if ! git am "$mbox_file" >/dev/null 2>&1; then
        git am --abort >/dev/null 2>&1
        results+=("stable/linux-${version}.y | Failed | N/A")
        git checkout -q "$branch"
        git branch -D "$temp_branch"
        return 1
    fi

    # Run build test
    if ! ~/pulls/build-next.sh; then
        if [ -f ~/errors-linus-next ]; then
            local build_error=$(cat ~/errors-linus-next)
            results+=("stable/linux-${version}.y | Success | Failed")
            errors+=("Build error for ${branch}:")
            errors+=("$(echo "$build_error" | sed 's/^/    /')")
            errors+=("")
        else
            results+=("stable/linux-${version}.y | Success | Failed (no log)")
        fi
        result=1
    else
        results+=("stable/linux-${version}.y | Success | Success")
    fi

    git checkout -q "$branch"
    git branch -D "$temp_branch"

    return $result
}

# Function to extract patch author
extract_patch_author() {
    local mbox_file="$1"
    formail -xFrom: < "$mbox_file" | sed -e 's/^[ \t]*//'
}

# Function to process single patch or series patch
process_patch() {
    local mbox_file="$1"
    local series_dir="$2"
    local current_part="$3"
    local -n p_results=$4
    local -n p_errors=$5
    local failed=0

    # If this is part of a series and not the first patch, verify previous patches can be applied
    if [ -n "$series_dir" ] && [ "$current_part" -gt 1 ]; then
        # Try to apply previous patches in a temporary branch
        cd "$LINUX_DIR"
        local temp_branch="temp-series-check-$(date +%s)"
        local current_branch=$(git rev-parse --abbrev-ref HEAD)
       
        git checkout -b "$temp_branch" >/dev/null 2>&1
       
        if ! apply_series_patches "$series_dir" "$current_part" "$LINUX_DIR"; then
            git checkout -q "$current_branch"
            git branch -D "$temp_branch" >/dev/null 2>&1
            p_results+=("All branches | Failed (previous patches in series failed to apply) | N/A")
            p_errors+=("Error: Cannot proceed - previous patches in series failed to apply")
            return 1
        fi
       
        git checkout -q "$current_branch"
        git branch -D "$temp_branch" >/dev/null 2>&1
    fi

    # Extract subject to get kernel versions
    local subject=$(formail -xSubject: < "$mbox_file")
    local kernel_versions=$(extract_kernel_versions "$subject")

    # Extract email body
    local email_body=$(formail -I "" < "$mbox_file")
    local claimed_sha1=$(extract_commit_sha1 "$email_body" || true)
    local found_sha1=""
    local author_mismatch=""
    local diff_output=""

    # Find or validate SHA1
    if [ -z "$claimed_sha1" ]; then
        found_sha1=$(find_commit_by_subject "$subject" "$LINUX_DIR")
    else
        if validate_commit "$claimed_sha1" "$LINUX_DIR"; then
            found_sha1="$claimed_sha1"
        else
            found_sha1=$(find_commit_by_subject "$subject" "$LINUX_DIR")
        fi
    fi

    # Use temporary SHA1 if none found
    if [ -z "$found_sha1" ]; then
        found_sha1="0000000000000000000000000000000000000000"
    fi

    # Compare authors if we found a commit
    if [ -n "$found_sha1" ] && [ "$found_sha1" != "0000000000000000000000000000000000000000" ]; then
        local patch_author=$(extract_patch_author "$mbox_file")
        local commit_author=$(get_commit_author "$LINUX_DIR" "$found_sha1")
        if [ "$patch_author" != "$commit_author" ]; then
            author_mismatch="Backport author: $patch_author"$'\n'"Commit author: $commit_author"
        fi
    fi

    # Compare with upstream if we have a valid SHA1
    if [[ "$found_sha1" =~ ^[0-9a-f]{40}$ ]] && [ "$found_sha1" != "0000000000000000000000000000000000000000" ]; then
        diff_output=$(compare_with_upstream "$mbox_file" "$found_sha1" "$LINUX_DIR")
    fi

    # Test on each kernel version
    for version in $kernel_versions; do
        if ! test_commit_on_branch "$found_sha1" "$version" "$LINUX_DIR" "$mbox_file" \
                                  "$series_dir" "$current_part" p_results p_errors; then
            failed=1
        fi
    done

    # Check newer kernels if we have a valid SHA1
    local -a newer_kernel_results=()
    if [[ "$found_sha1" =~ ^[0-9a-f]{40}$ ]] && [ "$found_sha1" != "0000000000000000000000000000000000000000" ]; then
        check_newer_kernels "$found_sha1" "$kernel_versions" "$LINUX_DIR" newer_kernel_results
    fi

    # Generate response for this patch
    generate_response "$mbox_file" "$claimed_sha1" "$found_sha1" \
                     "$(printf '%s\n' "${p_results[@]}")" "$diff_output" \
                     "$author_mismatch" "$(printf '%s\n' "${p_errors[@]}")" \
                     "$(printf '%s\n' "${newer_kernel_results[@]}")"

    return $failed
}

# Function to test complete series
test_series() {
    local series_dir="$1"
    local total_parts="$2"
    local linux_dir="$3"
    local failed=0

    # Process each patch in the series
    for ((i=1; i<=total_parts; i++)); do
        local mbox_file="$series_dir/$i.mbox"
        declare -a patch_results=()
        declare -a patch_errors=()

        if ! process_patch "$mbox_file" "$series_dir" "$i" patch_results patch_errors; then
            failed=1
            # Early return on series failure to prevent infinite loop
            return $failed
        fi
    done

    return $failed
}

# Function to generate email response
generate_response() {
    local mbox_file="$1"
    local claimed_sha1="$2"
    local found_sha1="$3"
    local results="$4"
    local diff_output="$5"
    local author_mismatch="$6"
    local build_errors="$7"
    local newer_kernel_results="$8"
    local response_file=$(generate_response_filename "$mbox_file")

    {
        # Get the From, Subject, Message-ID, and Date from original email for threading
        formail -X From: -X Subject: < "$mbox_file"
	echo "Message-ID: $(generate_message_id)"
	echo "Date: $(date -R)"
        echo "In-Reply-To: $(formail -xMessage-ID: < "$mbox_file")"
        echo "From: $(git config user.name) <$(git config user.email)>"

        # Use original subject line directly from the email, just add Re: if needed
        local orig_subject=$(formail -xSubject: < "$mbox_file" | \
            tr '\n' ' ' | \
            tr -s ' ' | \
            sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$//g')

        # Only add "Re: " if it's not already there
        if [[ ! "$orig_subject" =~ ^Re: ]]; then
            echo "Subject: Re: $orig_subject"
        else
            echo "Subject: $orig_subject"
        fi

        echo
        echo "[ Sasha's backport helper bot ]"
        echo
        echo "Hi,"
        echo

        # Report on SHA1 verification and commit status
        if [ -n "$claimed_sha1" ]; then
            if [ "$claimed_sha1" = "$found_sha1" ]; then
                echo "The upstream commit SHA1 provided is correct: $claimed_sha1"
                if [ -n "$author_mismatch" ]; then
                    echo
                    echo "WARNING: Author mismatch between patch and upstream commit:"
                    echo "$author_mismatch"
                fi
            else
                echo "The claimed upstream commit SHA1 ($claimed_sha1) was not found."
                if [ -n "$found_sha1" ] && [ "$found_sha1" != "0000000000000000000000000000000000000000" ]; then
                    echo "However, I found a matching commit: $found_sha1"
                    if [ -n "$author_mismatch" ]; then
                        echo
                        echo "WARNING: Author mismatch between patch and found commit:"
                        echo "$author_mismatch"
                    fi
                fi
            fi
        elif [ -n "$found_sha1" ] && [ "$found_sha1" != "0000000000000000000000000000000000000000" ]; then
            echo "Found matching upstream commit: $found_sha1"
            if [ -n "$author_mismatch" ]; then
                echo
                echo "WARNING: Author mismatch between patch and found commit:"
                echo "$author_mismatch"
            fi
        else
            echo "No upstream commit was identified. Using temporary commit for testing."
        fi
        echo

        # Add newer kernel check results if available
        if [ -n "$newer_kernel_results" ]; then
            echo "$newer_kernel_results"
            echo
        fi

        # Add diff if there are differences and we have a valid SHA1
        if [ -n "$diff_output" ] && [[ "$found_sha1" =~ ^[0-9a-f]{40}$ ]] && \
           [ "$found_sha1" != "0000000000000000000000000000000000000000" ]; then
            echo "Note: The patch differs from the upstream commit:"
            echo "---"
            echo "$diff_output"
            echo "---"
            echo
        fi

        # Print results table
        echo "Results of testing on various branches:"
        echo
        printf "| %-25s | %-11s | %-10s |\n" "Branch" "Patch Apply" "Build Test"
        echo "|---------------------------|-------------|------------|"
        while IFS='|' read -r branch status build; do
            if [ -n "$branch" ]; then
                printf "| %-25s | %-11s | %-10s |\n" "$branch" "$status" "$build"
            fi
        done <<< "$results"

        # Add build errors if any
        if [ -n "$build_errors" ]; then
            echo
            echo "Build Errors:"
            echo "$build_errors"
        fi

    } > "$response_file"

    echo "Response written to $response_file"
}

# Cleanup function to restore git state
cleanup() {
    if [ -d "$LINUX_DIR" ]; then
        cd "$LINUX_DIR"
        if [ -f ".git/rebase-apply/patch" ]; then
            git am --abort >/dev/null 2>&1 || true
        fi
        # Clean up any temporary branches
        git branch | grep '^temp-' | xargs -r git branch -D >/dev/null 2>&1 || true
        rm -f "$TEMP_PATCH" 2>/dev/null || true
    fi
}

# Main script
main() {
    if [ $# -ne 1 ]; then
        echo "Usage: $0 <mbox_file>"
        exit 1
    fi

    MBOX_FILE="$1"
    local diff_output=""
    local failed=0

    echo "Looking at $MBOX_FILE"

    # Validate inputs
    if [ ! -f "$MBOX_FILE" ]; then
        echo "Error: File '$MBOX_FILE' not found"
        exit 1
    fi

    if [ ! -d "$LINUX_DIR" ]; then
        echo "Error: Linux git tree not found at $LINUX_DIR"
        exit 1
    fi

    if [ ! -f "$HOME/stable-queue/active_kernel_versions" ]; then
        echo "Error: Active kernel versions file not found at ~/stable-queue/active_kernel_versions"
        exit 1
    fi

    # Check if we should ignore this mail
    if should_ignore_mail "$MBOX_FILE"; then
        echo "Skipping mail from ignored author"
        exit 0
    fi

    # Check if mail contains a git patch
    if ! is_git_patch "$MBOX_FILE"; then
        echo "Skipping mail: not a git patch"
        exit 0
    fi

    # Extract subject and series information
    subject=$(formail -xSubject: < "$MBOX_FILE")
    if [ -z "$subject" ]; then
        echo "Error: Could not extract subject from mbox"
        exit 1
    fi

    # Get kernel versions to process
    kernel_versions=$(extract_kernel_versions "$subject")
    local has_specific_versions=0
    if [ "$kernel_versions" != "$(cat $HOME/stable-queue/active_kernel_versions)" ]; then
        has_specific_versions=1
    fi

    # Extract email body
    email_body=$(formail -I "" < "$MBOX_FILE")

    # Try to find SHA1 in the email body
    claimed_sha1=$(extract_commit_sha1 "$email_body" || true)
    found_sha1=""

    # If we didn't find SHA1 in the body, try to find it by subject
    if [ -z "$claimed_sha1" ]; then
        found_sha1=$(find_commit_by_subject "$subject" "$LINUX_DIR")
    else
        if validate_commit "$claimed_sha1" "$LINUX_DIR"; then
            found_sha1="$claimed_sha1"
        else
            found_sha1=$(find_commit_by_subject "$subject" "$LINUX_DIR")
        fi
    fi

    # Skip if we have no SHA1 and no specific kernel versions
    if [ -z "$found_sha1" ] && [ $has_specific_versions -eq 0 ]; then
        echo "No commit SHA1 found and no specific kernel versions in subject. Skipping patch."
        exit 0
    fi

    # Check if this is part of a series
    series_info=$(extract_series_info "$subject")
    if [ -n "$series_info" ]; then
        read current_part total_parts <<< "$series_info"

        # Skip 0/N patches
        if [ "$current_part" -eq 0 ]; then
            echo "Skipping 0/$total_parts patch"
            exit 0
        fi

        # Get message IDs and determine series directory
        message_id=$(get_message_id "$MBOX_FILE")
        in_reply_to=$(get_in_reply_to "$MBOX_FILE")
        series_dir="$PENDING_DIR/$(get_series_dir "$message_id" "$in_reply_to")"

        # Store this patch
        store_patch "$MBOX_FILE" "$series_dir" "$current_part"

        echo "Processing part $current_part of $total_parts"

        # Check if series is now complete
        if is_series_complete "$series_dir" "$total_parts"; then
            echo "Series complete, testing all patches..."
            if ! test_series "$series_dir" "$total_parts" "$LINUX_DIR"; then
                failed=1
            fi
            # Clean up series directory regardless of result
            rm -rf "$series_dir"
            exit $failed
        else
            echo "Series incomplete, waiting for remaining patches..."
            exit 0
        fi
    else
        # Single patch processing
        declare -a patch_results=()
        declare -a patch_errors=()
        if ! process_patch "$MBOX_FILE" "" "1" patch_results patch_errors; then
            failed=1
        fi
    fi

    exit $failed
}

# Set up trap for cleanup
trap cleanup EXIT ERR

# Run main script
main "$@"
