# Latest kernel
The latest kernel can be cloned from
[github.com/JoakimMisund/net-next](https://www.github.com/JoakimMisund/net-next).

The most up to date (experimental) implementation of Paced Chirping is in branch tcp\_prague. The implementation is so that any congestion control can easily use it. An example integration can be found in tcp\_prague.c, and paced\_chirping.h provides some guidelines on integration.

# Latest DCTCP congestion control module
The latest DCTCP implementation with Paced Chirping integrated is located in the tcp\_prague branch.

Use with sysctl -w net.ipv4.tcp_congestion_control=dctcp; echo 1 | sudo tee /sys/module/tcp_dctcp/parameters/paced_chirping_enabled
