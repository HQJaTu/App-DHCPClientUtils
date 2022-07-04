# App-DHCPClientUtils
App::DHCPClientUtils Perl applications for utilizing ISC dhclient lease information

## Installation
```bash
cpan -i App::DHCPClientUtils
```

## Net::Interface issue with AArch64
This package won't build on Raspberry Pi 4 when running 64-bit mode.

## Net::Interface issue with CentOS 8
This package won't build on CentOS 8. Fix:
```bash
./configure --enable-shared
perl -I. Makefile.PL
make
sudo make install
```

For details, see: https://stackoverflow.com/a/61601803/1548275