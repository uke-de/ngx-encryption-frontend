#!/bin/bash
echo "{ \"version\": \"$(git describe --tags --long)\", \"date\": \"$(git show -s --format=%ci)\" }" > git-version.json
