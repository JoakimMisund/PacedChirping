# To rebuild the kernel do the following: (from http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.13.16/)

git clone git://git.launchpad.net/~ubuntu-kernel-test/ubuntu/+source/linux/+git/mainline-crack v4.13.16

cd v4.13.16;git checkout v4.13.16

wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.13.16/{0001-base-packaging.patch,0002-UBUNTU-SAUCE-add-vmlinux.strip-to-BOOT_TARGETS1-on-p.patch,0003-UBUNTU-SAUCE-tools-hv-lsvmbus-add-manual-page.patch,0004-UBUNTU-SAUCE-no-up-disable-pie-when-gcc-has-it-enabl.patch,0005-debian-changelog.patch,0006-configs-based-on-Ubuntu-4.13.0-11.12.patch}


git apply 0001-base-packaging.patch 0002-UBUNTU-SAUCE-add-vmlinux.strip-to-BOOT_TARGETS1-on-p.patch 0003-UBUNTU-SAUCE-tools-hv-lsvmbus-add-manual-page.patch 0004-UBUNTU-SAUCE-no-up-disable-pie-when-gcc-has-it-enabl.patch 0005-debian-changelog.patch 0006-configs-based-on-Ubuntu-4.13.0-11.12.patch


git apply ../0001-Paced-Chirping.patch

Then compile and install using your preferred way. You also have to create a .config file, I suggest using your current one located in /boot.
To compile and install I have created and installed the kernel as a deb following the instructions here: https://wiki.ubuntu.com/KernelTeam/GitKernelBuild
