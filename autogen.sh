#!/bin/bash

function bailout()
{
  echo "ERROR: $1"
  exit 1
}

echo "Re-generating autoconf/automake files adding missing stuff"
autoreconf -i || bailout "autoreconf FAILED"
echo "DONE. Run './configure && make && sudo make install' now"
echo "Hint: Use './configure --help' to see more build options."
