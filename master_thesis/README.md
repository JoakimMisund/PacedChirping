# Roadmap
This directory contains code used for Joakims master thesis and the
paper "Paced Chirping: Rapid flow start with very low queuing delay" [Coming]().

The code is based on kernel version 4.13.16.
There are three versions of the code and each is described below.


# Versions
- v1: Used in the thesis and named paper.
- v2: Changed the code from operating in rate to operate in time gaps. Reduces
  the number of division done in the cc module and in the kernel. The algorithm
  is the same as in v2.
- v3: Moved from pacing gap list to having a callback and rate calculation in
  the kernel. Does not fully implement original Paced Chirping algorithm. Should
  not be used, look in latest directory instead.
  

# To rebuild the kernel do the following: (from http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.13.16/)

git clone git://git.launchpad.net/~ubuntu-kernel-test/ubuntu/+source/linux/+git/mainline-crack v4.13.16

cd v4.13.16;git checkout v4.13.16

wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.13.16/{0001-base-packaging.patch,0002-UBUNTU-SAUCE-add-vmlinux.strip-to-BOOT_TARGETS1-on-p.patch,0003-UBUNTU-SAUCE-tools-hv-lsvmbus-add-manual-page.patch,0004-UBUNTU-SAUCE-no-up-disable-pie-when-gcc-has-it-enabl.patch,0005-debian-changelog.patch,0006-configs-based-on-Ubuntu-4.13.0-11.12.patch}


git apply 0001-base-packaging.patch 0002-UBUNTU-SAUCE-add-vmlinux.strip-to-BOOT_TARGETS1-on-p.patch 0003-UBUNTU-SAUCE-tools-hv-lsvmbus-add-manual-page.patch 0004-UBUNTU-SAUCE-no-up-disable-pie-when-gcc-has-it-enabl.patch 0005-debian-changelog.patch 0006-configs-based-on-Ubuntu-4.13.0-11.12.patch


git apply ../PATCH
where PATCH in [paced-chirping-v1.patch, paced-chirping-v2.patch, paced-chirping-v3.patch]

Then compile and install using your preferred way. One option is to create a deb
for installation which makes it simple to distribute the kernel on multiple
machines as described [here](https://wiki.ubuntu.com/KernelTeam/GitKernelBuild).



# Compiling, loading and using congestion control module

Will only compile on systems using the modified Linux 4.13 kernel for chirping.

- compile:         make
- load:            make load
- unload:          make unload
- Set default:     sysctl -w net.ipv4.tcp_congestion_control=chirping
