#!/bin/bash
cd <WORKSPACE>/rollout/rev-final-protocol/attachments || exit 1
printf '%s' 'NEX{c0nstruct0r_rc4_t34_m4st3r}' | ./final_protocol > /tmp/good.txt 2>&1; echo "good rc=$?" >> /tmp/good.txt
printf '%s' 'NEX{aaaaaaaaaaaaaaaaaaaaaaaaaa}' | ./final_protocol > /tmp/bad.txt 2>&1; echo "bad rc=$?" >> /tmp/bad.txt
printf '%s\n' '=== good ==='; tail -3 /tmp/good.txt
printf '%s\n' '=== bad ==='; tail -3 /tmp/bad.txt
printf '%s\n' '=== under strace (anti-debug) ==='
printf '%s' 'NEX{c0nstruct0r_rc4_t34_m4st3r}' | strace -f -o /tmp/tr.txt ./final_protocol > /tmp/st.txt 2>&1; echo "strace rc=$?" >> /tmp/st.txt
tail -2 /tmp/st.txt
