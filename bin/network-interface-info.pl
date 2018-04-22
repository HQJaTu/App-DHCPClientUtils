#!/usr/bin/env perl

# vim: tabstop=4 shiftwidth=4 softtabstop=4 expandtab:

use Net::Interface qw(full_inet_ntop ipV6compress type :afs :iffs :iffIN6 :iftype :scope);
use Net::IP;
use Net::ISC::DHCPClient;
use POSIX qw();
use Getopt::Long;
use Pod::Usage;
use Data::Dumper;

use warnings;
use strict;

=head1 NAME

network-interface-info.pl - ISC dhclient lease information

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';



sub DisplayInterfaceInfo($)
{
    my ($interfaces) = @_;

    my @paths_to_attempt = ('/var/lib/dhclient', '/var/lib/dhcp', '/var/lib/NetworkManager');

    for my $if (@$interfaces) {
        my $info = $if->info();
        my $flags = $if->flags();
        next if (!$info->{Net::Interface->af_inet()});

        print "interface = $if\n========================\n";
        my $hwaddr = join(':', (length($info->{mac}) ? unpack('H*', $info->{mac}) : '') =~ m/../g);
        $hwaddr = "none" if (!$hwaddr);
        printf("hwaddr = %s\n", $hwaddr);

        # Query DHCP-information (if any is available)
        my $dhclient = Net::ISC::DHCPClient->new(
                    leases_path => \@paths_to_attempt,
                    interface   => $if->{name},
                    af          => ['inet', 'inet6']
                );

        # IPv4
        my $ipv4_addrs = $info->{Net::Interface->af_inet()}->{number};
        $ipv4_addrs = 0 if (!$ipv4_addrs);
        printf("IPv4 addrs = %d\n", $ipv4_addrs);
        my @v4addresses = $if->address(Net::Interface->af_inet());
        my @v6addresses = $if->address(Net::Interface->af_inet6());
        print "  addr =      ", Net::Interface::inet_ntoa($v4addresses[0]), "\n",
              "  broadcast = ", Net::Interface::inet_ntoa($if->broadcast(Net::Interface->af_inet())), "\n",
              "  netmask =   ", Net::Interface::inet_ntoa($if->netmask(Net::Interface->af_inet())), "\n";
        if ($dhclient->is_dhcp('inet')) {
            my $lease = @{$dhclient->leases_af_inet()}[0];
            print "  gateway =   ", $lease->option()->{routers}, " (from DHCP)\n";
        }

        print "IPv4 flags:\n";
        print "  is running\n"     if $flags & IFF_RUNNING;
        print "  is broadcast\n"   if $flags & IFF_BROADCAST;
        print "  is p-to-p\n"      if $flags & IFF_POINTOPOINT;
        print "  is loopback\n"    if $flags & IFF_LOOPBACK;
        print "  is promiscuous\n" if $flags & IFF_PROMISC;
        print "  is multicast\n"   if $flags & IFF_MULTICAST;
        print "  is notrailers\n"  if $flags & IFF_NOTRAILERS;
        print "  is noarp\n"       if $flags & IFF_NOARP;

        if ($dhclient->is_dhcp('inet')) {
            print "  is DHCP, ";

            my $now = time();
            my $lease = @{$dhclient->leases_af_inet()}[0];
            if ($lease->expire >= $now) {
                printf("lease will expire at: %s\n",
                        POSIX::strftime("%F %X", localtime($lease->expire)));
            } else {
                print("lease is expired\n");
            }
        }

        # IPv6
        my $ipv6_addrs = $info->{Net::Interface->af_inet6()}->{number};
        $ipv6_addrs = 0 if (!$ipv6_addrs);
        printf("IPv6 addrs = %d\n", $ipv6_addrs);
        my $addrNro = 0;
        foreach my $ip (@v6addresses) {
            ++$addrNro;
            my $prefix = unpack('%B128', $if->netmask(Net::Interface->af_inet6()));
            my $scope = '-something-unknown-';
            $scope = RFC2373_NODELOCAL if ($if->scope() == 0x1);
            $scope = RFC2373_LINKLOCAL if ($if->scope() == 0x2);
            $scope = RFC2373_SITELOCAL if ($if->scope() == 0x5);
            $scope = RFC2373_ORGLOCAL if ($if->scope() == 0x8);
            $scope = RFC2373_GLOBAL if ($if->scope() == 0xe);

            my @types = ();
            push(@types, "any") if (type($ip) & IPV6_ADDR_ANY);
            push(@types, "unicast") if (type($ip) & IPV6_ADDR_UNICAST);
            push(@types, "multicast") if (type($ip) & IPV6_ADDR_MULTICAST);
            push(@types, "anycast") if (type($ip) & IPV6_ADDR_ANYCAST);
            push(@types, "loopback") if (type($ip) & IPV6_ADDR_LOOPBACK);
            push(@types, "link-local") if (type($ip) & IPV6_ADDR_LINKLOCAL);
            push(@types, "site-local") if (type($ip) & IPV6_ADDR_SITELOCAL);
            push(@types, "compat-v4") if (type($ip) & IPV6_ADDR_COMPATv4);
            push(@types, "scope-local") if (type($ip) & IPV6_ADDR_SCOPE_MASK);
            push(@types, "mapped") if (type($ip) & IPV6_ADDR_MAPPED);
            push(@types, "reserved") if (type($ip) & IPV6_ADDR_RESERVED);
            push(@types, "uniq-lcl-unicast") if (type($ip) & IPV6_ADDR_ULUA);
            push(@types, "6to4") if (type($ip) & IPV6_ADDR_6TO4);
            push(@types, "6bone") if (type($ip) & IPV6_ADDR_6BONE);
            push(@types, "global-unicast") if (type($ip) & IPV6_ADDR_AGU);
            push(@types, "unspecified") if (type($ip) & IPV6_ADDR_UNSPECIFIED);
            push(@types, "solicited-node") if (type($ip) & IPV6_ADDR_SOLICITED_NODE);
            push(@types, "ISATAP") if (type($ip) & IPV6_ADDR_ISATAP);
            push(@types, "productive") if (type($ip) & IPV6_ADDR_PRODUCTIVE);
            push(@types, "6to4-ms") if (type($ip) & IPV6_ADDR_6TO4_MICROSOFT);
            push(@types, "teredo") if (type($ip) & IPV6_ADDR_TEREDO);
            push(@types, "orchid") if (type($ip) & IPV6_ADDR_ORCHID);
            push(@types, "non-routeable-doc") if (type($ip) & IPV6_ADDR_NON_ROUTE_DOC);

            printf(" %d: addr =    %s/%s\n  scope =     %s\n  type =      %s\n",
                $addrNro,
                ipV6compress(full_inet_ntop($ip)), $prefix,
                $scope, join(', ', @types)
            );
        }
        if ($dhclient->is_dhcp('inet6')) {
            print "  is DHCP, ";

            my $now = time();
            my $lease = @{$dhclient->leases_af_inet6()}[0];
            my $starts = $lease->starts('non-temporary');
            my $max_life = $lease->max_life('non-temporary');
            if ($starts + $max_life >= $now) {
                printf("lease will expire at: %s,\n                         now is: %s\n",
                        POSIX::strftime("%F %H:%M:%S", localtime($starts + $max_life)),
                        POSIX::strftime("%F %H:%M:%S", localtime($now))
                );
            } else {
                print("lease is expired\n");
            }
        }

        # IPv4 and IPv6 done.
        print "\n";
    }
}

sub main()
{
    my %opts;
    GetOptions (\%opts,
                "help|h",
                "version|v",
                "show|s",
                "interface|i=s@"
    ) or die "Malformed arguments! Stopped.";

    pod2usage(-exitval => 0, -verbose => 1) if (defined($opts{help}));

    my @interfaces = Net::Interface->interfaces();
    DisplayInterfaceInfo(\@interfaces);
}

main();

__END__
=head1 AUTHOR

Jari Turkia, C<< <jatu at hqcodeshop.fi> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-app-dhcpclientutils at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=App-DHCPClientUtils>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc App::DHCPClientUtils


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=App-DHCPClientUtils>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/App-DHCPClientUtils>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/App-DHCPClientUtils>

=item * Search CPAN

L<http://search.cpan.org/dist/App-DHCPClientUtils/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2018 Jari Turkia.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

=head1 SYNOPSIS

network-interface-info.pl [options] [file ...]
 Options:
   -help            brief help message
   -man             full documentation

=head1 OPTIONS

=over 8

=item B<-help>
Print a brief help message and exits.

=item B<-man>
Prints the manual page and exits.

=back

=head1 DESCRIPTION
B<This program> will read the given input file(s) and do something
useful with the contents thereof.
=cut
