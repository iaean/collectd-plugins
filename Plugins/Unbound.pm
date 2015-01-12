#
# Unbound - unbound collectd plugin
# Copyright (C) 2014 Andreas Schulze
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#

package Collectd::Plugins::Unbound;

use threads;
use threads::shared;

=head1 NAME

Collectd::Plugins::Unbound - Plugin for unbound DNS statistics

=head1 SYNOPSIS

         <LoadPlugin perl>
           Globals true
         </LoadPlugin>
         <Plugin perl>
           IncludeDir "/path/to/perl/plugins"
           BaseName "Collectd::Plugins"
           LoadPlugin "Unbound"
           <Plugin Unbound>
             CmdPath "/usr/sbin/unbound-control"
             CfgPath "/etc/unbound.conf"
             Server  "server[:port]"
           </Plugin>
         </Plugin>
         TypesDB "/path/to/types.db.custom"

         # types.db.custom
         unbound_memory			total_sbrk:GAUGE:0:U, cache_rrset:GAUGE:0:U, cache_message:GAUGE:0:U, \
                                        mod_iterator:GAUGE:0:U, mod_validator:GAUGE:0:U
         unbound_queries_by_flag	QR:COUNTER:0:U, AA:COUNTER:0:U, TC:COUNTER:0:U, RD:COUNTER:0:U, RA:COUNTER:0:U, \
                                        Z:COUNTER:0:U, AD:COUNTER:0:U, CD:COUNTER:0:U, eDNS_present:COUNTER:0:U, eDNS_DO:COUNTER:0:U
         unbound_queries_by_type	A:COUNTER:0:U, AAAA:COUNTER:0:U, PTR:COUNTER:0:U, SOA:COUNTER:0:U, NS:COUNTER:0:U, \
                                        MX:COUNTER:0:U, SRV:COUNTER:0:U, TXT:COUNTER:0:U, CNAME:COUNTER:0:U, Other:COUNTER:0:U
         unbound_answers_by_type	NOERROR:COUNTER:0:U, NXDOMAIN:COUNTER:0:U, SERVFAIL:COUNTER:0:U, \
                                        nodata:COUNTER:0:U, secure:COUNTER:0:U, bogus:COUNTER:0:U
         unbound_thread			queries:COUNTER:0:U, cachehits:COUNTER:0:U, cachemiss:COUNTER:0:U, prefetch:COUNTER:0:U, recursive:COUNTER:0:U, \
                                        rql_avg:GAUGE:0:U, rql_max:COUNTER:0:U, rql_overwritten:COUNTER:0:U, rql_exceeded:COUNTER:0:U, \
                                        rql_current_all:COUNTER:0:U, rql_current_user:COUNTER:0:U, \
                                        rcrsn_time_avg:GAUGE:0:U, rcrsn_time_median:GAUGE:0:U
         unbound_total			queries:COUNTER:0:U, cachehits:COUNTER:0:U, cachemiss:COUNTER:0:U, prefetch:COUNTER:0:U, recursive:COUNTER:0:U, \
                                        rql_avg:GAUGE:0:U, rql_max:COUNTER:0:U, rql_overwritten:COUNTER:0:U, rql_exceeded:COUNTER:0:U, \
                                        rql_current_all:COUNTER:0:U, rql_current_user:COUNTER:0:U, \
                                        rcrsn_time_avg:GAUGE:0:U, rcrsn_time_median:GAUGE:0:U, \
                                        query_tcp:COUNTER:0:U, query_ipv6:COUNTER:0:U, \
                                        rrset_bogus:COUNTER:0:U, unwanted_replies:COUNTER:0:U, unwanted_queries:COUNTER:0:U

=head1 DESCRIPTION

This Perl-module is simply a little stats collector for the unbound's
monitoring capability accessed via unbound-control(8).
Refer the unbound documentation on how to enabling this feature.

To check that your setup is working, simply run
  unbound-control [-c cfgfile | -s server] stats_noreset
with no errors.

=head1 TODO

1st: add the histogram
2nd: implement 'Server' config 
Nth: more error checking during init()

=cut

use strict;
use warnings;

my %config = (
  CmdPath => '/usr/sbin/unbound-control',
  CfgPath => '/etc/unbound.conf',
  Server => undef,
);

my $unboundStats = {
 memory => { # GAUGE
   stat => ['mem.total.sbrk','mem.cache.rrset','mem.cache.message','mem.mod.iterator','mem.mod.validator'],
   type => 'unbound_memory total_sbrk:GAUGE:0:U, cache_rrset:GAUGE:0:U, cache_message:GAUGE:0:U, mod_iterator:GAUGE:0:U, mod_validator:GAUGE:0:U',
 },
 queries_by_flag => { # COUNTER
   stat => ['num.query.flags.QR','num.query.flags.AA','num.query.flags.TC','num.query.flags.RD','num.query.flags.RA','num.query.flags.Z','num.query.flags.AD','num.query.flags.CD','num.query.edns.present','num.query.edns.DO'],
   type => 'unbound_queries_by_flag QR:COUNTER:0:U, AA:COUNTER:0:U, TC:COUNTER:0:U, RD:COUNTER:0:U, RA:COUNTER:0:U, Z:COUNTER:0:U, AD:COUNTER:0:U, CD:COUNTER:0:U, eDNS_present:COUNTER:0:U, eDNS_DO:COUNTER:0:U',
 },
 queries_by_type => { # COUNTER
   stat => ['num.query.type.A','num.query.type.AAAA','num.query.type.PTR','num.query.type.SOA','num.query.type.NS','num.query.type.MX','num.query.type.SRV','num.query.type.TXT','num.query.type.CNAME','num.query.type.other'],
   type => 'unbound_queries_by_type A:COUNTER:0:U, AAAA:COUNTER:0:U, PTR:COUNTER:0:U, SOA:COUNTER:0:U, NS:COUNTER:0:U, MX:COUNTER:0:U, SRV:COUNTER:0:U, TXT:COUNTER:0:U, CNAME:COUNTER:0:U, Other:COUNTER:0:U',
 },
 answers_by_type => { # COUNTER
   stat => ['num.answer.rcode.NOERROR','num.answer.rcode.NXDOMAIN','num.answer.rcode.SERVFAIL','num.answer.rcode.nodata','num.answer.secure','num.answer.bogus'],
   type => 'unbound_answers_by_type NOERROR:COUNTER:0:U, NXDOMAIN:COUNTER:0:U, SERVFAIL:COUNTER:0:U, nodata:COUNTER:0:U, secure:COUNTER:0:U, bogus:COUNTER:0:U',
 },
 total => { # GAUGE|COUNTER
   stat => ['total.num.queries','total.num.cachehits','total.num.cachemiss','total.num.prefetch','total.num.recursivereplies','total.requestlist.avg','total.requestlist.max','total.requestlist.overwritten','total.requestlist.exceeded','total.requestlist.current.all','total.requestlist.current.user','total.recursion.time.avg','total.recursion.time.median','num.query.tcp','num.query.ipv6','num.rrset.bogus','unwanted.replies','unwanted.queries'],
   type => 'unbound_total queries:COUNTER:0:U, cachehits:COUNTER:0:U, cachemiss:COUNTER:0:U, prefetch:COUNTER:0:U, recursive:COUNTER:0:U, rql_avg:GAUGE:0:U, rql_max:COUNTER:0:U, rql_overwritten:COUNTER:0:U, rql_exceeded:COUNTER:0:U, rql_current_all:COUNTER:0:U, rql_current_user:COUNTER:0:U, rcrsn_time_avg:GAUGE:0:U, rcrsn_time_median:GAUGE:0:U, query_tcp:COUNTER:0:U, query_ipv6:COUNTER:0:U, rrset_bogus:COUNTER:0:U, unwanted_replies:COUNTER:0:U, unwanted_queries:COUNTER:0:U',
 },
 thread => { # GAUGE|COUNTER
   stat => ['num.queries','num.cachehits','num.cachemiss','num.prefetch','num.recursivereplies','requestlist.avg','requestlist.max','requestlist.overwritten','requestlist.exceeded','requestlist.current.all','requestlist.current.user','recursion.time.avg','recursion.time.median'],
   type => 'unbound_thread queries:COUNTER:0:U, cachehits:COUNTER:0:U, cachemiss:COUNTER:0:U, prefetch:COUNTER:0:U, recursive:COUNTER:0:U, rql_avg:GAUGE:0:U, rql_max:COUNTER:0:U, rql_overwritten:COUNTER:0:U, rql_exceeded:COUNTER:0:U, rql_current_all:COUNTER:0:U, rql_current_user:COUNTER:0:U, rcrsn_time_avg:GAUGE:0:U, rcrsn_time_median:GAUGE:0:U',
 },
};

use Collectd qw(:all);
sub plugin_config {
  my $cfg = shift;
  ### printf STDERR "CONFIG: %d\n", threads->self()->tid();
  foreach my $c (@{$cfg->{children}}) {
  $config{lc($c->{key})} = $c->{values}[0]; }
  return 1; }

# see TODO
sub plugin_init {
  ### printf STDERR "INIT: %d\n", threads->self()->tid();
  return 1; }

sub plugin_read {
  my %res = map { if (/^(.+)=(.+)$/) { $1 => $2 } } qx/$config{CmdPath} -c $config{CfgPath} stats_noreset/;
  my $threads = 0;

  foreach my $m (keys %{res}) {
    my @a = split(/\./, $m);
    if ($a[0] =~ /^thread(\d+)$/ && 1+$1 > $threads) { $threads = 1+$1; } }

  while (my ($q, $ref) = each %{$unboundStats}) {
    if ($q =~ /^thread$/) {
      for (my $t = 0; $t < $threads; $t++) {
        my $vl = { time => time(),
                   interval => $interval_g,
                   host => $hostname_g,
                   plugin => 'unbound',
                   plugin_instance => '',
                   type => 'unbound_'.lc($q),
                   type_instance => $t };
        foreach my $m (@{$ref->{stat}}) {
          if (defined $res{'thread'.$t.'.'.$m}) { push @{$vl->{values}}, $res{'thread'.$t.'.'.$m}; }
          else { push @{$vl->{values}}, "U"; } }
        plugin_dispatch_values($vl); } }
    else {
      my $vl = { time => time(),
                 interval => $interval_g,
                 host => $hostname_g,
                 plugin => 'unbound',
                 plugin_instance => '',
                 type => 'unbound_'.lc($q),
                 type_instance => '' };
      foreach my $m (@{$ref->{stat}}) {
        if (defined $res{$m}) { push @{$vl->{values}}, $res{$m}; }
        else { push @{$vl->{values}}, "U"; } }
      plugin_dispatch_values($vl); } }

  %res = ();
  undef %res;
  return 1; }
  
plugin_register(TYPE_CONFIG, 'Unbound', 'plugin_config');
plugin_register(TYPE_INIT,   'Unbound', 'plugin_init');
plugin_register(TYPE_READ,   'Unbound', 'plugin_read');

return 1;

=begin comment

histogram.000000.000000.to.000000.000001=0
histogram.000000.000001.to.000000.000002=0
histogram.000000.000002.to.000000.000004=0
histogram.000000.000004.to.000000.000008=0
histogram.000000.000008.to.000000.000016=0
histogram.000000.000016.to.000000.000032=0
histogram.000000.000032.to.000000.000064=0
histogram.000000.000064.to.000000.000128=0
histogram.000000.000128.to.000000.000256=0
histogram.000000.000256.to.000000.000512=1
histogram.000000.000512.to.000000.001024=0
histogram.000000.001024.to.000000.002048=0
histogram.000000.002048.to.000000.004096=1
histogram.000000.004096.to.000000.008192=3
histogram.000000.008192.to.000000.016384=9
histogram.000000.016384.to.000000.032768=24
histogram.000000.032768.to.000000.065536=4
histogram.000000.065536.to.000000.131072=4
histogram.000000.131072.to.000000.262144=9
histogram.000000.262144.to.000000.524288=14
histogram.000000.524288.to.000001.000000=6
histogram.000001.000000.to.000002.000000=0
histogram.000002.000000.to.000004.000000=0
histogram.000004.000000.to.000008.000000=0
histogram.000008.000000.to.000016.000000=0
histogram.000016.000000.to.000032.000000=1
histogram.000032.000000.to.000064.000000=0
histogram.000064.000000.to.000128.000000=0
histogram.000128.000000.to.000256.000000=0
histogram.000256.000000.to.000512.000000=0
histogram.000512.000000.to.001024.000000=0
histogram.001024.000000.to.002048.000000=0
histogram.002048.000000.to.004096.000000=0
histogram.004096.000000.to.008192.000000=0
histogram.008192.000000.to.016384.000000=0
histogram.016384.000000.to.032768.000000=0
histogram.032768.000000.to.065536.000000=0
histogram.065536.000000.to.131072.000000=0
histogram.131072.000000.to.262144.000000=0
histogram.262144.000000.to.524288.000000=0

=cut
