package WebService::Livedoor::SpamChampuru::DNSBL;
# $Id: DNSBL.pm 768 2008-10-02 09:47:37Z i-ihara $
use warnings;
use strict;

use Net::DNS::Resolver;
use IO::Select;

=head1 NAME

WebService::Livedoor::SpamChampuru::DNSBL - Perl interface of SpamChampuru DNSBL WebService

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

my $DNSBL_DOMAIN = "dnsbl.spam-champuru.livedoor.com";
my $DNSBL_ANS = "127.0.0.2";
my $TIMEOUT = 0.1;


=head1 SYNOPSIS

    use WebService::Livedoor::SpamChampuru::DNSBL;
    my $dnsbl = WebService::Livedoor::SpamChampuru::DNSBL->new(timeout => 1);
    my $res = $dnsbl->lookup($ip_addr);

=head1 METHODS

=head2 new

Creates an WebService::Livedoor::SpamChampuru::DNSBL instance.

  $dnsbl = WebService::Livedoor::SpamChampuru::DNSBL->new(timeout => $timeout, [nameservers => \@nameservers]);

=cut

sub new {
    my $class = shift;
    my $self = bless {
        @_,
    }, $class;
    $self->{timeout} ||= $TIMEOUT;
    return $self;
}

=head2 lookup

Sends a DNS query to SpamChampuru DNSBL Server and checks if $ip_addr is classified as a source of spam.
C<lookup> returns 1 for SPAM, 0 for HAM.

  my $res = $dnsbl->lookup($ip_addr);

=cut

sub lookup {
    my ($self, $ip_addr) = @_;
    my $score = 0;

    my $reverse_ip_addr = join('.', reverse split /\./, $ip_addr);
    my $dnsbl_request = join('.', $reverse_ip_addr, $DNSBL_DOMAIN);

    if (my $res = $self->_dnslookup_with_timeout($dnsbl_request, $self->{timeout})) {
        if ($res eq $DNSBL_ANS) {
            $score = 1;
        }
    }
    return $score;
}

sub _dnslookup_with_timeout {
    my ($self, $dnsbl_request, $timeout) = @_;
    my $result;
    my $resolver;

    if (defined $self->{nameservers}) {
        $resolver = Net::DNS::Resolver->new(
            nameservers => $self->{nameservers},
        );
    }
    else {
        $resolver = Net::DNS::Resolver->new;
    }

    my $bgsock = $resolver->bgsend($dnsbl_request);
    my $sel = IO::Select->new($bgsock);

    my @ready = $sel->can_read($timeout);
    if (@ready) {
        foreach my $sock (@ready) {
            if ($sock == $bgsock) {
                my $packet = $resolver->bgread($bgsock);
                if ($packet) {
                    foreach my $rr ($packet->answer) {
                        next unless $rr->type eq "A";
                        $result = $rr->address;
                        last;
                    }
                }
                $bgsock = undef;
            }
            $sel->remove($sock);
            $sock = undef;
        }
    }
    return $result;
}


=head1 AUTHOR

Kensuke Kaneko, C<< <k-kaneko at livedoor.jp> >>

=head1 SEE ALSO

L<http://spam-champuru.livedoor.com/> (Japanese text only)

L<Net::DNSBLLookup>

=head1 COPYRIGHT & LICENSE

Copyright 2008 livedoor Co., Ltd., all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

1; # End of WebService::Livedoor::SpamChampuru::DNSBL
