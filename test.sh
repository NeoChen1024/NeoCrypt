#!/usr/bin/env sh
set -eu

msg_echo()
{
	printf "\033[44m==>>\033[0m \033[1;33m%s\033[0m\n" "$1"
}

response()
{
	printf "\033[30;43m<<==\033[0m \033[1;32m%s\033[0m\n" "$1"
}

msg_echo "Crude test"
./neocrypt -i "neocrypt" -o "a" -k "TEST"
./neocrypt -i "a" -o "b" -k "TEST"
cmp "neocrypt" "b" && response "PASS" || response "FAIL"
rm -f "a" "b"
