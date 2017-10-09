#!/bin/bash

# let's rename the release file because it has a 1:1 mapping with what it is called on
# github releases, and therefore the name for each platform needs to be unique so that
# they don't overwrite each other. Set a variable that can be used in .travis.yml
export RELEASE_FILE="${TRAVIS_BUILD_DIR}/ntr-${GOOS}-${GOARCH}.exe"
mv "${GOPATH}/bin/${GOOS}_${GOARCH}/ntr.exe" "${RELEASE_FILE}"
