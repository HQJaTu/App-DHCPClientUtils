#!/usr/bin/env perl

# vim: tabstop=4 shiftwidth=4 softtabstop=4 expandtab:

use 5.006;
use strict;
use warnings;


=head1 NAME

multi-homed-routing.pl - Policy-based IPv4 routing generator

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


use Net::Interface qw(:afs :iffs :iffIN6);
use Net::IP;
use Net::ISC::DHCPClient;
use POSIX qw();
use Template;
use Getopt::Long;
use Pod::Usage;
use Cwd qw ( realpath );



my @paths_to_attempt = ('/var/lib/dhclient', '/var/lib/dhcp', '/var/lib/NetworkManager');
my $rt_table_path = '/etc/iproute2/rt_tables';
my $rt_table_start_number = 10;
my $rt_rule_start_number = 50;
my @orig_args;
my $bash_reserved_characters_re = qr([ !"#\$&'()*;<>?\[\\`{|~\t\n]);

use constant POLICY_EQUAL    => 'equal';
use constant POLICY_WEIGHTED => 'weighted';
use constant POLICY_SINGLE   => 'single';

use constant RESERVED_TABLES    => {
                                    255 => 'local',
                                    254 => 'main',
                                    253 => 'default'
                                };


sub DisplayInterfaceInfo($)
{
    my ($interfaces) = @_;

    for my $if (@$interfaces) {
        my $info = $if->info();
        next if (!$info->{Net::Interface->af_inet()});
        print "interface = $if->name\n========================\n";
        print "IPv4 addrs= ", $info->{Net::Interface->af_inet()}->{number}, "\n";
        my @ipv4_addresses = $if->address(Net::Interface->af_inet());
        print "addr =      ", Net::Interface::inet_ntoa($ipv4_addresses[0]), "\n",
              "broadcast = ", Net::Interface::inet_ntoa($if->broadcast(Net::Interface->af_inet())), "\n",
              "netmask =   ", Net::Interface::inet_ntoa($if->netmask(Net::Interface->af_inet())), "\n",
              "hwaddr =    ", join(':', (length($info->{mac}) ? unpack('H*', $info->{mac}) : '') =~ m/../g), "\n";

        my $flags = $if->flags();
        print "is running\n"     if $flags & IFF_RUNNING;
        print "is broadcast\n"   if $flags & IFF_BROADCAST;
        print "is p-to-p\n"      if $flags & IFF_POINTOPOINT;
        print "is loopback\n"    if $flags & IFF_LOOPBACK;
        print "is promiscuous\n" if $flags & IFF_PROMISC;
        print "is multicast\n"   if $flags & IFF_MULTICAST;
        print "is notrailers\n"  if $flags & IFF_NOTRAILERS;
        print "is noarp\n"       if $flags & IFF_NOARP;

        my $dhclient = Net::ISC::DHCPClient->new(
                    leases_path => \@paths_to_attempt,
                    interface   => $if->name
                );
        if ($dhclient->is_dhcp()) {
            print "is DHCP, ";

            my $now = time();
            my $lease = @{$dhclient->leases()}[0];
            if ($lease->expire >= $now) {
                printf("%s lease will expire at: %s\n",
                        $lease->interface,
                        POSIX::strftime("%F %H:%M:%S", localtime($lease->expire)));
            } else {
                print("lease is expired\n");
            }

            # Note: RFC2132 specifies, that there can exist multiple routers.
            # https://tools.ietf.org/html/rfc2132
            print "gateway =   ", $lease->option()->{routers}, "\n";
        }
        print "\n";
    }
}


sub SuggestSettings($)
{
    my ($interfaces) = @_;
    my @cmd = ();

    my $rt_table_idx = $rt_table_start_number;
    my $rt_table = _read_routing_tables();
    my $first_suggestion = 1;
    for my $if (@$interfaces) {
        my $info = $if->info();
        next if (!$info->{Net::Interface->af_inet()});
        my $flags = $if->flags();
        next if ($flags & IFF_LOOPBACK);
        next if (!$flags & IFF_RUNNING);

        push(@cmd, '--interface', $if->name);

        my $dhclient = Net::ISC::DHCPClient->new(
                    leases_path => \@paths_to_attempt,
                    interface   => $if->name
                );
        if ($dhclient->is_dhcp() && $dhclient->leases()) {
            # Nice! The required settings can be detected from most recent lease.
            my $lease = @{$dhclient->leases()}[0];
            push(@cmd, '--gateway', "$if=<add it here>") if (!$lease->option()->{routers});
        } else {
            # Add the gateway for a staticly configured interface
#           push(@cmd, '--gateway', "$if=<add it here>");
        }
        push(@cmd, '--routing-table');
        if (defined($rt_table->{$rt_table_idx})) {
            push(@cmd, "$if=" . $rt_table->{$rt_table_idx});
        } else {
            my $table_name = "Table_" . $if->name;
            warn sprintf("Suggestion: Edit file %s, and add following lines:\n", $rt_table_path) if ($first_suggestion);
            $first_suggestion = 0;
            warn sprintf("%d %s\n", $rt_table_idx, $table_name);
            push(@cmd, $if->name . "=$rt_table_idx");
        }

        ++$rt_table_idx;
    }
    
    die "Detect failed!" if (!@cmd);

    print "\n" if (!$first_suggestion);
    printf("Run commad:\n%s %s\n", $0, join(' ', @cmd));
}


sub _read_routing_tables()
{
    # For table syntax, see: http://linux-ip.net/html/routing-tables.html
    my $tables = {};
    my $rt_table_re = qr/^\s*(\d+)\s+(\S+)/;
    open(RT_TABLE, $rt_table_path) or
        die "Failed to read IProuting2 table! Error: $!";
    while (<RT_TABLE>) {
        chomp();
        next if (!/$rt_table_re/);
        my $table_nro = $1;
        my $table_name = $2;
        next if ($table_nro <= 0 || $table_nro >= 253);
        if ($table_nro < 0 || $table_nro > 255) {
            die sprintf("IP route2 table %s contains invalid value %d in line '%s'",
                        $rt_table_path, $table_nro, $_);
        }
        if (defined($tables->{$table_nro})) {
            die sprintf("IP route2 table %s contains has value %d twice. Second line is '%s'",
                        $rt_table_path, $table_nro, $_);
        }
        $tables->{$table_nro} = $table_name;
    }
    close(RT_TABLE);

    return $tables;
}


#
# @param    $interfaces
#           Array of interface-objects:
#           device =>   Interface device name, eg. eth0
#           table =>    Routing-table to use from /etc/iproute2/rt_tables
#           address =>  IPv4 address of the interface
#           network =>  Network of the interface in the form, IPv4-address/netmask
#           gateway =>  IPv4 address of the gateway
#           weight =>   Weight of the route
sub routing_rules($$)
{
    my ($interfaces, $default_policy) = @_;

    my $config = {
        INTERPOLATE => 1,               # expand "$var" in plain text
        EVAL_PERL   => 1,               # evaluate Perl code blocks
        PRE_CHOMP   => 0,
        POST_CHOMP  => 1,
    };

    # create Template object
    my $tt = Template->new($config);
    my $template = <<END_OF_FILE
#!/bin/bash


# This script is output of command:
# \\\$ [% cmd_line %]


# Id for this ruleset:
RULES_ID="[% rules_id %]"

# Save existing, if running the first time:
if [ ! -e "\\\$RULES_ID.original" ]; then
    SAVE_FILENAME="\\\$RULES_ID.original"
    echo "# Rules saved at: \\\$(date +"%F %H:%M:%S")" > "\\\$SAVE_FILENAME"
    echo "# ip rule list:" >> "\\\$SAVE_FILENAME"
    ip rule list >> "\\\$SAVE_FILENAME"
    echo "# ip route show all" >> "\\\$SAVE_FILENAME"
    ip route show all >> "\\\$SAVE_FILENAME"
[% FOREACH if IN interfaces %]
    echo "# ip route show all table [% if.table %]" >> "\\\$SAVE_FILENAME"
    ip route show all table [% if.table %] >> "\\\$SAVE_FILENAME"
[% END %]
fi

# Clear previous routing
ip route flush all
[% FOREACH if IN interfaces %]
ip route flush table [% if.table %]

[% END %]

# Set up my interfaces

# Set up my main routing table
[% FOREACH if IN interfaces %]
[% IF if.in_main_table %]
ip route add [% if.network %] dev [% if.device %] src [% if.address %] table main
[% END %]
[% END %]

[% FOREACH if IN interfaces %]
# Table: [% if.table %]

[% FOREACH if2 IN interfaces %]
[% other_device = if2.device %][% IF if.device == if2.device %]
ip route add [% if2.network %] dev [% if2.device %] src [% if2.address %] table [% if.table %]

[% ELSIF if.crossref.\$other_device == 1 %]
ip route add [% if2.network %] dev [% if2.device %] table [% if.table %]

[% ELSE %]
# Not adding. Shares same network [% if.network %]:
#ip route add [% if2.network %] dev [% if2.device %] table [% if.table %]

[% END %]
[% END %]
[% FOREACH route IN if.add_routes %]
ip route add [% route %] table [% if.table %]

[% END %]
ip route add 127.0.0.0/8 dev lo table [% if.table %]

[% IF if.gateway %]
ip route add default via [% if.gateway %] table [% if.table %]
[% END %]


[% END %]
# Set up my routing rules to connect the routing tables into reality
[% FOREACH if IN interfaces %]
ip rule del from [% if.address %]

ip rule add from [% if.address %] table [% if.table %] prio [% rules_count %][% rules_count = rules_count +1 %]

[% END %]


# Set up the policy
# Input validation:
POLICY="\\\$1"
IFACE="\\\$2"
case "\\\$POLICY" in
    --policy-equal|--policy-weighted|--policy-single)
        POLICY=\\\${POLICY:9}
        if [ "\\\${POLICY}" == "single" ] && [ -z "\\\${IFACE}" ]; then
            echo "--policy-single needs interface. Using default policy!"
            POLICY=[% default_policy %]

        fi
        ;;
    *)
        POLICY=[% default_policy %]

esac

# Policy setup:
# proto static = the route was installed by the administrator to override dynamic routing
case "\\\$POLICY" in
equal)
    # Equal weight
    # This will kill SSH and websites whose session depends on IP-address :-(
    echo "Policy: Equal weight"

    ip route add default table main proto static scope global[% FOREACH if IN interfaces -%][% IF if.gateway %] \\
        nexthop via [% if.gateway %] dev [% if.device %]
[% END %]
[% END %]

    ;;

weighted)
    # Weighted balancing
    echo "Policy: Equal weight"

    ip route add default table main proto static scope global[% FOREACH if IN interfaces %][% IF if.gateway %] \\
        nexthop via [% if.gateway %] dev [% if.device %] weight [% if.weight %]
[% END %]
[% END %]

    ;;

single)
    # Single gateway
    echo "Policy: Single gateway via \\\$IFACE"

    case "\\\$IFACE" in
[% FOREACH if IN interfaces %]
[% IF if.gateway %]
    [% if.device %])
        ip route add default table main proto static scope global \\
            via [% if.gateway %] dev [% if.device %]

        ;;
[% END %]
[% END %]
    esac
    ;;
esac

END_OF_FILE
    ;

    my $cmd_line = '';
    unshift(@orig_args, realpath($0));
    foreach (@orig_args) {
        $cmd_line .= ' ' if ($cmd_line);
        if (/$bash_reserved_characters_re/) {
            my $quoted = s/'/'"'"'/gr;
            $cmd_line .= "'$quoted'";
        } else {
            $cmd_line .= $_;
        }
    }
    my $rules = "";
    my $values = {
        cmd_line        => $cmd_line,
        interfaces      => $interfaces,
        default_policy  => $default_policy,
        rules_id        => 'rules-' . POSIX::strftime("%FT%H:%M:%S", gmtime()),
        rules_count     => $rt_rule_start_number
    };

    # Go create a setup-file from the template!
    $tt->process(\$template, $values, $rules) or
        die sprintf("Template error: %s", $tt->error());

    # To-do: Write the rules to a file.
    # Print the rules to screen
    print $rules;
    return;
}


sub _calculate_network($$)
{
    my ($ipv4_address, $netmask) = @_;

    my $net = new Net::IP($ipv4_address) or
        die "Failed to construct Net::IP. Error: " . Net::IP::Error();
    my $mask = new Net::IP($netmask);

    # Do IPv4 32-bit arithmetic:
    # Use the netmask to mask off "host" bits from the address.
    # Remaining bits are the "network" bits.
    my $net_ip = $net->intip() & $mask->intip();

    # Convert the 32-bit int into string.
    my $net_ip_str = Net::Interface::inet_ntoa(pack('N', $net_ip));

    # Convert netmask into count of bits
    $mask = $mask->binip(); # Convert mask into bits
    $mask =~ s/0+$//;       # Drop off zeros at the end
    $mask = length($mask);  # String length tells the number of bits in mask

    # Finalize the operation:
    my $network = "$net_ip_str/$mask";
    
    return $network;
}


sub main()
{
    my %opts;
    $opts{'accept-private-dhcp-addresses'} = 0;
    @orig_args = @ARGV;
    GetOptions(\%opts,
                "help|h",
                "version|V",
                "show|s",
                "detect|d",
                "interface|i=s@",
                "routing-table|t=s@",
                "weight|w=s@",
                "gateway=s@",
                "accept-private-dhcp-addresses!",
                "add-route=s@"
    ) or die "Malformed arguments! Stopped.";

    pod2usage(-exitval => 0, -verbose => 1) if (defined($opts{help}));

    # Go detect the interfaces
    my @interfaces = Net::Interface->interfaces();

    # Options given?
    # Just do what was requested in option and quit.
    if ($opts{version}) {
        printf("Version: %s\n", $VERSION);
        return;
    }
    if ($opts{show}) {
        DisplayInterfaceInfo(\@interfaces);
        return;
    }
    if ($opts{detect}) {
        SuggestSettings(\@interfaces);
        return;
    }

    # No option given, if interfaces given, go create routing configuration.
    if (!$opts{interface} || !scalar(@{$opts{interface}})) {
        # No option given and no interfaces given. Go help!
        pod2usage(-exitval => 0, -verbose => 1);
        
        return;
    }

    # Has interfaces.
    die "Using this script without two or more network interfaces makes no sense!" if (scalar(@{$opts{interface}}) < 2);
    die "Using this script without two or more routing tables makes no sense! None given." if (!$opts{'routing-table'});
    die "Using this script without two or more routing tables makes no sense!" if (scalar(@{$opts{'routing-table'}}) < 2);

    my @ifs_to_use = ();
    my $rt_table = _read_routing_tables();
    my %rt_table_values = map { $rt_table->{$_} => $_ } keys(%$rt_table);

    # Try to make sense of the given arguments:
    # Match the routing table arguments with interfaces.
    for my $if_in (@{$opts{interface}}) {
        my $info;
        my @ipv4_addresses;
        my $netmask;
        my $flags;
        for my $if (@interfaces) {
            next if ($if_in ne $if->name);
            $info = $if->info();
            $flags = $if->flags();
            next if (!$info || !$flags);
            next if ($flags & IFF_LOOPBACK);
            next if (!$flags & IFF_RUNNING);

            @ipv4_addresses = $if->address(Net::Interface->af_inet());
            $netmask = Net::Interface::inet_ntoa($if->netmask(Net::Interface->af_inet()));
            last;
        }
        die sprintf("Error! --interface %s given cannot be found in system. Stopped.\n", $if_in) if (!$info);
        die sprintf("Error! --interface %s given doesn't have any addresses. Stopped.\n", $if_in) if (!@ipv4_addresses);
        die sprintf("Error! --interface %s given is a loopback interface. Refusing to use it. Stopped.\n", $if_in) if ($flags & IFF_LOOPBACK);

        # Network = gateway / netmask
        my $ipv4_address = Net::Interface::inet_ntoa($ipv4_addresses[0]);
        my $network = _calculate_network($ipv4_address, $netmask);
        my $rt_table = undef;
        my $gateway = undef;

        # RT table given?
        if ($opts{'routing-table'} && scalar(@{$opts{'routing-table'}})) {
            for my $table_in (@{$opts{'routing-table'}}) {
                next if ($table_in !~ /^\Q$if_in\E=(.+)$/);
                my $table = $1;

                # Table "name" can be an integer, or a name from rt_table
                # This is good stuff!
                if ($table =~ /^\d+$/) {
                    # All numbers
                    if (defined($rt_table->{$table})) {
                        # Use the name from table
                        $rt_table = $rt_table->{$table};
                    } else {
                        # Use the number
                        $rt_table = $table;
                    }
                    last;
                } else {
                    # String given
                    if (!defined($rt_table_values{$table})) {
                        die sprintf("Error! --routing-table %s given refers to a name, but not found in %s. Refusing to use it. Stopped.\n", $table_in, $rt_table_path);
                    }
                    $rt_table = $table;
                    last;
                }
            }
        }

        # Gateway given?
        if ($opts{gateway} && scalar(@{$opts{gateway}})) {
            for my $gw_in (@{$opts{gateway}}) {
                next if ($gw_in !~ /^\Q$if_in\E=(.+)$/);
                my $ipv4 = new Net::IP($1) or
                    die "Failed to given gateway IP-address $1. Error: " . Net::IP::Error();

                # This is good stuff!
                $gateway = $1;
                last;
            }
        }
        if (!$gateway) {
            # No gateway given in command-line.
            my $dhclient = Net::ISC::DHCPClient->new(
                                    leases_path => \@paths_to_attempt,
                                    interface   => $if_in
                            );
            if ($dhclient->is_dhcp() && $dhclient->leases()) {
                # Nice! The required settings can be detected from most recent lease.
                my $lease = @{$dhclient->leases()}[0];
                $gateway = $lease->option()->{routers} if ($lease->option()->{routers});
            }
        }

        if ($rt_table) {
            die sprintf("Cannot use table ID %d, it is reserved!", $rt_table) if (defined(RESERVED_TABLES->{$rt_table}));
            my %reserved_table_names = map { $_ => 1} values(%{+RESERVED_TABLES()});
            die sprintf("Cannot use table name '%s', it is reserved!", $rt_table) if (defined($reserved_table_names{$rt_table}));
        } else {
            die "Error! This setup doesn't make any sense. All interfaces need --routing-table.";
        }

        # Gateway given?
        my $additional_routes = [];
        if ($opts{'add-route'} && scalar(@{$opts{'add-route'}})) {
            for my $route_in (@{$opts{'add-route'}}) {
                next if ($route_in !~ /^\Q$if_in\E=(.+)$/);

                # Split the route from the router
                my $additional_route = $1;
                if ($additional_route !~ m:^([0-9.]+/[0-9]+),([0-9.]+)$:) {
                    warn sprintf("Fail! --add-route %s is not valid!", $route_in);
                    next;
                }

                # This is good stuff!
                push(@$additional_routes, "$1 via $2");
            }
        }

        # Collect interface information
        my $if_info = {
            device =>   $if_in,
            table =>    $rt_table,
            address =>  $ipv4_address,
            network =>  $network,
            gateway =>  $gateway,
            weight =>   -100,
            crossref => {},
            add_routes => $additional_routes,
            in_main_table => 0,
        };
        push(@ifs_to_use, $if_info);
    }

    # Crete table cross-references
    my %networks = ();
    for my $if_info (@ifs_to_use) {
        # First device to claim a network gets it into the main table.
        $networks{$if_info->{network}} = $if_info->{device} if (!defined($networks{$if_info->{network}}));
        my $crossrefs = {};
        for my $if2_info (@ifs_to_use) {
            # No need to cross-reference own table
            next if ($if_info->{device} eq $if2_info->{device});

            # Don't cross-reference tables, if using same networks
            next if ($if_info->{network} eq $if2_info->{network});

            $crossrefs->{$if2_info->{device}} = 1;
        }

        $if_info->{crossref} = $crossrefs;
        $if_info->{in_main_table} = 1 if ($networks{$if_info->{network}} eq $if_info->{device});
    }

    # Information gathering done!
    # Go figure out the routing
#   my $policy = POLICY_WEIGHTED;
    my $policy = POLICY_EQUAL;
    routing_rules(\@ifs_to_use, $policy);
}

main();

=head1 AUTHOR

Jari Turkia, C<< <jatu at hqcodeshop.fi> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-isc-dhcpclient at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-ISC-DHCPClient>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::ISC::DHCPClient


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-ISC-DHCPClient>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-ISC-DHCPClient>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-ISC-DHCPClient>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-ISC-DHCPClient/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2017 Jari Turkia.

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

__END__
=head1 NAME

multi-homed-routing.pl - Using Getopt::Long and Pod::Usage

=head1 SYNOPSIS

network-interface-info.pl [options] [file ...]
 Options:
   -h|--help        brief help message
   -v|--version     show version information
   -s|--show        show what is known about network interface
   -d|--detect      suggest how to run this
   -i|--interface   network interfaces to use
   --gateway        <interface>=<IP-address> network gateway address

=head1 OPTIONS

=over 8

=item B<--help>
Print 2 a brief help message and exits.

=item B<--show>
Show information about detected network interfaces.

=item B<--detect>
Detect network interfaces and suggest what to do.

=item B<--interface>
Print 2 a brief help message and exits.

=back

=head1 DESCRIPTION
B<This program> will read the given input file(s) and do something
useful with the contents thereof.
=cut