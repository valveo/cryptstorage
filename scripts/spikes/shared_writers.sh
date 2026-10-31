#!/bin/bash
# Spike for docs/design-sharing.md section 5.1: two gocryptfs mounts (two "machines") on one
# ciphertext directory over two SSHFS mounts. Prepare first: sshd on 127.0.0.1:2222, /srv/share/c
# mounted at /tmp/spike/s1 and /tmp/spike/s2 with sshfs, gocryptfs -init on it with /tmp/spike/pw.
# Needs root and FUSE. Usage: shared_writers.sh <label> [gocryptfs flags, e.g. -sharedstorage]
W=/tmp/spike; L=$1; shift
fusermount -u -z $W/m1 2>/dev/null; fusermount -u -z $W/m2 2>/dev/null
gocryptfs -q -nosyslog -noprealloc "$@" -passfile $W/pw $W/s1 $W/m1 || exit 1
gocryptfs -q -nosyslog -noprealloc "$@" -passfile $W/pw $W/s2 $W/m2 || exit 1
D=$L; mkdir -p $W/m1/$D
r(){ printf '%-48s %s\n' "$1" "$2"; }
# 1 new file visible
echo hello > $W/m1/$D/new.txt
for t in 0 1 2 5 10 20; do sleep $t; c=$(cat $W/m2/$D/new.txt 2>&1); [ "$c" = hello ] && break; done
r "1 A writes new file, B reads" "$c (after ~${t}s)"
# 2 dir created by A, B writes into it
mkdir $W/m1/$D/sub; sleep 1; echo fromB > $W/m2/$D/sub/b.txt 2>&1; echo fromA > $W/m1/$D/sub/a.txt
sleep 2; r "2 both write into dir made by A: A reads b" "$(cat $W/m1/$D/sub/b.txt 2>&1)"
r "  B reads a" "$(cat $W/m2/$D/sub/a.txt 2>&1)"
# 3 overwrite with shorter/longer content
cat $W/m2/$D/new.txt >/dev/null; echo "a much longer replacement line" > $W/m1/$D/new.txt
ok=""; for t in 0 1 2 5 10 20 30; do sleep $t; c=$(cat $W/m2/$D/new.txt 2>&1); [ "$c" = "a much longer replacement line" ] && { ok=1; break; }; done
r "3 A overwrites, B reads" "$c (after ~${t}s)"
# 4 parallel writers, different files
( for i in $(seq 1 100); do head -c $((RANDOM*3)) /dev/urandom > $W/m1/$D/a_$i; done ) &
( for i in $(seq 1 100); do head -c $((RANDOM*3)) /dev/urandom > $W/m2/$D/b_$i; done ) &
wait
(cd $W/m1/$D && sha256sum a_* > $W/sumA_$L); (cd $W/m2/$D && sha256sum b_* > $W/sumB_$L)
# 5 same file, both write at once
head -c 200000 /dev/urandom > $W/x1; head -c 300000 /dev/urandom > $W/x2
for i in $(seq 1 20); do cp $W/x1 $W/m1/$D/same.bin & cp $W/x2 $W/m2/$D/same.bin & wait; done
# 6 rename by A, B looks
echo r > $W/m1/$D/old.txt; sleep 1; cat $W/m2/$D/old.txt >/dev/null; mv $W/m1/$D/old.txt $W/m1/$D/renamed.txt
sleep 2; r "6 A renames, B lists" "$(ls $W/m2/$D | grep -E 'old|renamed' | tr '\n' ' ')"
# 7 long name
N=$(printf 'n%.0s' $(seq 1 200)); echo long > $W/m1/$D/$N; sleep 1; r "7 long name (200 chars), B reads" "$(cat $W/m2/$D/$N 2>&1)"
fusermount -u $W/m1; fusermount -u $W/m2
# verify from a fresh local mount on the server copy
mkdir -p $W/v; gocryptfs -q -nosyslog -ro -passfile $W/pw /srv/share/c $W/v
(cd $W/v/$D && sha256sum -c --quiet $W/sumA_$L 2>&1 | head -3; sha256sum -c --quiet $W/sumB_$L 2>&1 | head -3) > $W/chk_$L
r "4 200 parallel files intact on server" "$( [ -s $W/chk_$L ] && head -2 $W/chk_$L || echo yes)"
s=$(sha256sum < $W/v/$D/same.bin 2>&1 | cut -c1-16); a=$(sha256sum < $W/x1 | cut -c1-16); b=$(sha256sum < $W/x2 | cut -c1-16)
r "5 same file written by both 20x: result" "$( [ "$s" = "$a" ] && echo 'A wins, intact' || { [ "$s" = "$b" ] && echo 'B wins, intact' || echo "CORRUPT/other: $s"; }) size $(stat -c %s $W/v/$D/same.bin 2>&1)"
fusermount -u $W/v
gocryptfs -fsck -q -passfile $W/pw /srv/share/c > $W/fsck_$L 2>&1; r "fsck" "exit $? $(grep -ci error $W/fsck_$L) error lines"
