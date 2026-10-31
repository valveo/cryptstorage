#!/bin/bash
# Spike for docs/design-features.md section 5.1: rclone bisync between a local folder and the
# mounted plaintext view of a gocryptfs volume, for two "machines" on one ciphertext directory.
# Prepare first (root, FUSE): sshd on 127.0.0.1:2222; /srv/share/sync mounted twice with
#   sshfs -o dir_cache=no,reconnect at /tmp/spike/s1 and /tmp/spike/s2; gocryptfs -init on s1;
#   gocryptfs -sharedstorage s1 -> /tmp/spike/m1 and s2 -> /tmp/spike/m2 (passphrase in /tmp/spike/pw).
# Needs rclone 1.64 or newer (tested with 1.71.1).
W=/tmp/spike; R=${RCLONE:-rclone}
F="--create-empty-src-dirs --compare size,modtime,checksum --resilient --recover --max-lock 2m
   --conflict-resolve none --conflict-loser num --modify-window 1s --exclude .secdisk-sync-lock/ -q"
A(){ $R bisync $W/L1 $W/m1 --workdir $W/wdA $F "$@"; }
B(){ $R bisync $W/L2 $W/m2 --workdir $W/wdB $F "$@"; }
# Server-side lock: mkdir in the shared ciphertext directory is atomic over SFTP.
lock(){ until mkdir $W/$1/.secdisk-sync-lock 2>/dev/null; do sleep 0.3; done; }
unlock(){ rmdir $W/$1/.secdisk-sync-lock; }
LA(){ lock s1; A; unlock s1; }
LB(){ lock s2; B; unlock s2; }
r(){ printf '%-52s %s\n' "$1" "$2"; }

rm -rf $W/L1 $W/L2 $W/wdA $W/wdB; mkdir -p $W/L1 $W/L2
echo base > $W/L1/base.txt; A --resync; B --resync
mkdir -p $W/L1/docs; echo one > $W/L1/docs/one.txt; echo two > $W/L1/two.txt
A; B; r "1 A adds files and a directory" "$(cat $W/L2/docs/one.txt $W/L2/two.txt 2>&1 | tr '\n' ' ')"
sleep 1; echo "edit by A" > $W/L1/two.txt; echo "edit by B" > $W/L2/two.txt
A; B; A; r "2 both edit two.txt" "$(cd $W/L1 && ls two* | tr '\n' ' ')"
rm $W/L2/docs/one.txt; B; A; r "3 B deletes, A after sync" "$([ -e $W/L1/docs/one.txt ] && echo 'still there' || echo deleted)"
echo kept > $W/L1/base.txt; rm $W/L2/base.txt; sleep 1; A; B; A
r "4 A edits, B deletes the same file" "A: $(cat $W/L1/base.txt), B: $([ -e $W/L2/base.txt ] && echo has it || echo gone)"
mkdir -p $W/L1/bulk; for i in $(seq 1 1000); do echo $i > $W/L1/bulk/f$i; done
t0=$(date +%s); A; t1=$(date +%s); B; t2=$(date +%s); A; t3=$(date +%s)
r "5 1000 small files: up / down / unchanged scan" "$((t1-t0)) s / $((t2-t1)) s / $((t3-t2)) s"
for i in $(seq 1 8); do echo "A$i" > $W/L1/p$i.txt; echo "B$i" > $W/L2/p$i.txt; A & B & wait; A; B; A; done
r "6 simultaneous runs, no lock: a version vanished" "$(for i in $(seq 1 8); do [ $(ls $W/L1/p$i.txt* | wc -l) -lt 2 ] && echo $i; done | wc -l)/8 rounds"
for i in $(seq 1 8); do echo "A$i" > $W/L1/q$i.txt; echo "B$i" > $W/L2/q$i.txt; LA & LB & wait; LA; LB; LA; done
r "7 simultaneous runs, with lock: a version vanished" "$(for i in $(seq 1 8); do [ $(ls $W/L1/q$i.txt* | wc -l) -lt 2 ] && echo $i; done | wc -l)/8 rounds"
r "  trees equal" "$(diff -r $W/L1 $W/L2 >/dev/null && echo yes || echo NO)"
