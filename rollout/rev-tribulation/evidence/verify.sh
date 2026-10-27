#!/bin/bash
cd <WORKSPACE>/rollout/rev-tribulation/attachments || exit 1
printf '%s' 'NEX{ud2_1s_n0t_a_cr4sh}' > /tmp/good.in
printf '%s' 'NEX{aaaaaaaaaaaaaaaaaa}' > /tmp/bad.in
for f in good bad; do
  strace -f -o /tmp/tr.txt ./tribulation < /tmp/$f.in > /tmp/out.txt 2>&1
  rc=$?
  echo "$f rc=$rc sigill=$(grep -c SIGILL /tmp/tr.txt) verdict=$(grep -o 'ACCESS_[A-Z]*' /tmp/out.txt || echo none)"
done
