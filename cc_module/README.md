# Compiling, loading and using

Will only compile on systems using the modified Linux 4.13 kernel for chirping.

compile:         make
load:            make load
unload:          make unload
Set default:     sysctl -w net.ipv4.tcp_congestion_control=chirping

v3 does not fully implement Paced Chirping yet.
