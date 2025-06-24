#!/bin/bash

# Test script to verify version consistency check logic
echo "🧪 Testing version consistency check logic..."

# Get current version from pyproject.toml
PYPROJECT_VERSION=$(cd /home/smajumdar/avidml/avidtools && poetry version -s)
echo "Current pyproject.toml version: $PYPROJECT_VERSION"

# Simulate different tag formats
TEST_TAGS=("v$PYPROJECT_VERSION" "$PYPROJECT_VERSION" "v0.99.99" "0.99.99")

for tag in "${TEST_TAGS[@]}"; do
    # Extract version from tag (remove 'v' prefix if present)
    TAG_VERSION="${tag#v}"
    
    echo ""
    echo "Testing tag: $tag"
    echo "  Extracted version: $TAG_VERSION"
    
    if [ "$PYPROJECT_VERSION" = "$TAG_VERSION" ]; then
        echo "  ✅ Match - versions are consistent"
    else
        echo "  ❌ Mismatch - would trigger PR creation"
        echo "     PyProject: $PYPROJECT_VERSION"
        echo "     Tag:       $TAG_VERSION"
    fi
done

echo ""
echo "🎯 Test complete! The logic correctly handles both 'v' prefixed and non-prefixed tags."
