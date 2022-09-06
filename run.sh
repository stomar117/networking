#!/bin/bash

cargo build
ecode=$?
if [[ $ecode -ne 0 ]]; then
    exit $ecode
fi

/usr/bin/sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/tcpr
cargo run &
pid=$!
sleep 1
/usr/bin/sudo ip addr add dev tun0 192.168.1.1/24
/usr/bin/sudo ip link set up tun0
trap "kill $pid" INT TERM
wait $pid
