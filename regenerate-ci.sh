#!/bin/sh

haskell-ci regenerate
patch --input=haskell-ci.patch .github/workflows/haskell-ci.yml

#EOF
