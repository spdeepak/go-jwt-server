#!/bin/bash

OWNER="spdeepak"
REPO="go-jwt-server"

if [[ -z "$OWNER" || -z "$REPO" ]]; then
    echo "Usage: ./run.sh <GitHub-Owner> <GitHub-Repo>"
    exit 1
fi

if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed"
    exit 1
fi

# Disable paging explicitly
export GH_PAGER=

echo "🔍 Fetching workflow run IDs for $OWNER/$REPO..."
workflow_runs=$(gh api "repos/$OWNER/$REPO/actions/runs" --paginate -q '.workflow_runs[].id')

if [[ -z "$workflow_runs" ]]; then
    echo "ℹ️ No workflow runs found for $OWNER/$REPO."
    exit 0
fi

# Loop and delete each run
echo "$workflow_runs" | while read -r run_id; do
    echo "🗑️ Deleting workflow run ID: $run_id"
    gh api -X DELETE "repos/$OWNER/$REPO/actions/runs/$run_id"
done

echo "✅ All workflow runs have been deleted."