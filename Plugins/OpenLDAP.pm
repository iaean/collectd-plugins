#
# OpenLDAP - slapd collectd plugin
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

package Collectd::Plugins::OpenLDAP;

use threads;
use threads::shared;

=head1 NAME

Collectd::Plugins::OpenLDAP - Plugin for accessing the monitoring functionality by
OpenLDAP slapd.

=head1 SYNOPSIS

         <LoadPlugin perl>
           Globals true
         </LoadPlugin>
         <Plugin perl>
           IncludeDir "/path/to/perl/plugins"
           BaseName "Collectd::Plugins"
           EnableDebugger ""
           LoadPlugin "OpenLDAP"
           <Plugin OpenLDAP>
             ldapURI "ldap://localhost/"
             bindDN "cn=Monitoring Manager,cn=monitor"
             bindPW "foobar"
           </Plugin>
         </Plugin>
         TypesDB "/path/to/types.db.custom"

         # types.db.custom
         ldap_connections	current:GAUGE:0:U, total:COUNTER:0:U
         ldap_threads		active:GAUGE:0:U, backload:GAUGE:0:U, max:GAUGE:0:U, max_pending:GAUGE:0:U, \
                                open:GAUGE:0:U, pending:GAUGE:0:U, starting:GAUGE:0:U
         ldap_statistics	bytes:COUNTER:0:U, entries:COUNTER:0:U, pdu:COUNTER:0:U, referrals:COUNTER:0:U
         ldap_waiters		read:GAUGE:0:U, write:GAUGE:0:U
         ldap_total_operations	abandon:COUNTER:0:U, add:COUNTER:0:U, bind:COUNTER:0:U, compare:COUNTER:0:U, \
                                delete:COUNTER:0:U, extended:COUNTER:0:U, modify:COUNTER:0:U, modrdn:COUNTER:0:U, \
                                search:COUNTER:0:U, unbind:COUNTER:0:U
         ldap_running_operations abandon:GAUGE:0:U, add:GAUGE:0:U, bind:GAUGE:0:U, compare:GAUGE:0:U, \
                                 delete:GAUGE:0:U, extended:GAUGE:0:U, modify:GAUGE:0:U, modrdn:GAUGE:0:U, \
                                 search:GAUGE:0:U, unbind:GAUGE:0:U

=head1 DESCRIPTION

This Perl-module is simply a little stats collector for the slapd's
cn=monitor functionality. http://www.openldap.org/doc/admin24/monitoringslapd.html
refers to how to enabling this feature.

=cut

use strict;
use warnings;

my %config = (
  ldapuri => 'ldapi:///',
  binddn => undef,
  bindpw => undef,
);

my $ldapQueries = {
 Connections => { # COUNTER|GAUGE
   base => 'cn=Connections,cn=Monitor',
   filter => '(|(cn=Current)(cn=Total))',
   attr => ['monitorCounter'],
   type => 'ldap_connections	current:GAUGE:0:U, total:COUNTER:0:U',
   hook => sub { my ($e, $a) = @_; return $e->get_value($a, alloptions=>0, asref=>0); } },
 Threads => { # GAUGE
   base => 'cn=Threads,cn=Monitor',
   filter => '(|(cn=Active)(cn=Backload)(cn=Max)(cn=Max Pending)(cn=Open)(cn=Pending)(cn=Starting))',
   attr => ['monitoredInfo'],
   type => 'ldap_threads	active:GAUGE:0:U, backload:GAUGE:0:U, max:GAUGE:0:U, max_pending:GAUGE:0:U, open:GAUGE:0:U, pending:GAUGE:0:U, starting:GAUGE:0:U',
   hook => sub { my ($e, $a) = @_; return $e->get_value($a, alloptions=>0, asref=>0); } },
 Statistics => { # COUNTER
   base => 'cn=Statistics,cn=Monitor',
   filter => '(|(cn=Bytes)(cn=Entries)(cn=PDU)(cn=Referrals))',
   attr => ['monitorCounter'],
   type => 'ldap_statistics	bytes:COUNTER:0:U, entries:COUNTER:0:U, pdu:COUNTER:0:U, referrals:COUNTER:0:U',
   hook => sub { my ($e, $a) = @_; return $e->get_value($a, alloptions=>0, asref=>0); } },
 Waiters => { # GAUGE
   base => 'cn=Waiters,cn=Monitor',
   filter => '(|(cn=Read)(cn=Write))',
   attr => ['monitorCounter'],
   type => 'ldap_waiters	read:GAUGE:0:U, write:GAUGE:0:U',
   hook => sub { my ($e, $a) = @_; return $e->get_value($a, alloptions=>0, asref=>0); } },
 Total_Operations => { # COUNTER
   base => 'cn=Operations,cn=Monitor',
   filter => '(|(cn=Abandon)(cn=Add)(cn=Bind)(cn=Compare)(cn=Delete)(cn=Extended)(cn=Modify)(cn=Modrdn)(cn=Search)(cn=Unbind))',
   attr => ['monitorOpCompleted'],
   type => 'ldap_total_operations	abandon:COUNTER:0:U, add:COUNTER:0:U, bind:COUNTER:0:U, compare:COUNTER:0:U, delete:COUNTER:0:U, extended:COUNTER:0:U, modify:COUNTER:0:U, modrdn:COUNTER:0:U, search:COUNTER:0:U, unbind:COUNTER:0:U',
   hook => sub { my ($e, $a) = @_; return $e->get_value($a, alloptions=>0, asref=>0); } },
 Running_Operations => { # GAUGE
   base => 'cn=Operations,cn=Monitor',
   filter => '(|(cn=Abandon)(cn=Add)(cn=Bind)(cn=Compare)(cn=Delete)(cn=Extended)(cn=Modify)(cn=Modrdn)(cn=Search)(cn=Unbind))',
   attr => ['monitorOpInitiated','monitorOpCompleted'],
   type => 'ldap_running_operations	abandon:GAUGE:0:U, add:GAUGE:0:U, bind:GAUGE:0:U, compare:GAUGE:0:U, delete:GAUGE:0:U, extended:GAUGE:0:U, modify:GAUGE:0:U, modrdn:GAUGE:0:U, search:GAUGE:0:U, unbind:GAUGE:0:U',
   hook => sub { my ($e, $a) = @_; return $e->get_value('monitorOpInitiated', alloptions=>0, asref=>0) - $e->get_value('monitorOpCompleted', alloptions=>0, asref=>0); } }
};

use Collectd qw(:all);
sub plugin_config {
  my $cfg = shift;
  ### printf STDERR "CONFIG: %d\n", threads->self()->tid();
  foreach my $c (@{$cfg->{children}}) {
    $config{lc($c->{key})} = $c->{values}[0]; }
  return 1; }

sub plugin_init {
  ### printf STDERR "INIT: %d\n", threads->self()->tid();
  if (defined $config{ldapuri} && defined $config{binddn} && defined $config{bindpw}) {
    my $ldap = ldapBind($config{binddn}, $config{bindpw});
    if (!$ldap) {
      plugin_log(LOG_ERR, "Unable to connect $config{ldapuri}");
      ldapUnbind($ldap);
      return 0; }
    plugin_log(LOG_INFO, "$config{ldapuri} connected");
    ldapUnbind($ldap);
    return 1; }
  plugin_log(LOG_ERR, "Incomplete config for $config{ldapuri}");
  return 0; }

# plugin_dispatch_values (value-list)
#   Submits a value-list to the daemon. If the data-set identified by value-list->{type} is found (and the number of values matches the
#   number of data-sources) then the type, data-set and value-list is passed to all write-callbacks that are registered with the daemon.
#
sub plugin_read {
  my $ldap = ldapBind($config{binddn}, $config{bindpw});
  while (my ($q, $ref) = each %{$ldapQueries}) {
    my $r = [ ldapSearch($ldap, $ref) ];
    if (!defined ${$r}[0]) {
      plugin_log(LOG_ERR, "Search error for $config{ldapuri}");
      ldapUnbind($ldap);
      return 0; }
    my $vl = { time => time(),
               interval => $interval_g,
               host => $hostname_g,
               plugin => 'slapd',
               plugin_instance => '',
               type_instance => '' };
    # IMPORTANT: entries are returned sorted by DN
    #            data sources are build suitable
    foreach my $e (@{$r}) {
      # $e->dn() =~ /^cn=([^,]+),.*$/;
      $vl->{type} = 'ldap_'.lc($q);
      my @al = $e->attributes(nooptions=>1);
      my $v = $ref->{hook}($e,$al[0]);
      push @{$vl->{values}}, $v;
    }
    plugin_dispatch_values($vl);
  }
  ldapUnbind($ldap);
  return 1; }

plugin_register(TYPE_CONFIG, 'OpenLDAP', 'plugin_config');
plugin_register(TYPE_INIT,   'OpenLDAP', 'plugin_init');
plugin_register(TYPE_READ,   'OpenLDAP', 'plugin_read');

return 1;

use Net::LDAP;
sub ldapBind {
  my ($b, $p) = @_;
  my $l = Net::LDAP->new($config{ldapuri});
  if (!$l) { return undef; } # Can't connect
  my $mesg = $l->bind($b, password=>$p);
  if ($mesg->code) { return undef; } # Can't bind $mesg->error
  return $l; }

sub ldapUnbind {
  my $l = shift;
  my $mesg = $l->unbind; }

sub ldapSearch {
  my ($l, $q) = @_;
  my $mesg = undef;
  $mesg = $l->search(base=>$q->{base}, sizelimit=>0, filter=>$q->{filter}, attrs=>$q->{attr});
  if ($mesg->code) { return undef; } # Ooops. Can't search $mesg->error
  return $mesg->sorted('cn'); }
