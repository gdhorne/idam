#!/usr/bin/perl

################################################################################
#
# Script Name: certificate_authority_report.pl
#
# Description: Generates a certificate authority report.
#
# Usage:
#   certificate_authority_report.pl configuration_file
#
# Copyright (c) 2000 Gregory D. Horne (horne at member dot fsf dot org)
# All rights reserved.
#
################################################################################
#
#    This software is released under the BSD 2-Clause License and may be
#    redistributed under the terms specified in the LICENSE file.
#
################################################################################

use Net::LDAP;
use Net::LDAP::Search;

################################################################################
# Function: Read the configuration parameters necessary to access the directory.
#           The parameters may appear in any order within the configuration file
#			provided that the following syntax is used.
#
#           Syntax:
#
#              attribute:value
#
#           where 'attribute' is taken from the set of possible values in the
#			list: base, host, password, port, scope, user for the PKI Directory;
#			and where 'attribute' is taken from the set of possible values in the
#			list: base, host, port, scope for the Enterprise Directory.
################################################################################

sub read_configuration()
{
	%configuration = undef;
	%configuration = ();

	open(FILE_CONFIGURATION, "< $ARGV[0]") ||
	die("Unable to open configuration file [$ARGV[0]]: $!\n");

	my $line;
	while ($line = <FILE_CONFIGURATION>) {
		if (length($line) > 1) {
			($attribute, $value) = split(':', $line, 2);
			chop($value);
			$configuration{$attribute} = $value;
		}
	}

	close(FILE_CONFIGURATION);
}

################################################################################

################################################################################
# Function: Read the contents of the comma-separated values data file provided
#			by the Certificate Authority. This file contains the PKI DN and
#			state of each entry in the PKI Directory.
#
#           Syntax:
#
#              pki_dn,status
################################################################################

sub read_ca_data()
{
	%record = undef;
	%record = ();

	print("\n".$configuration{'data_file'}."\n");

	open(FILE_CA_DATA, "< ./data/".$configuration{'data_file'}) ||
		die("Unable to open data file [$configuration{'data_file'}]: $!\n");

	my $line;
	$line = <FILE_CA_DATA>;
	while ($line = <FILE_CA_DATA>) {
		chomp($line);
		chop($line);
		($dn, $state) = split('",', $line, 2);
		$dn =~ s/"//g;
		$record{$dn} = $state;
	}

	close(FILE_CA_DATA);
}

################################################################################

################################################################################
# Function: Extracts entries of type 'person' from the PKI Directory.
################################################################################

sub process_persons()
{
	# Master transaction log.
	open(FILE_LOG, "> ./logs/pki.$configuration{'ca_host'}.p$configuration{'ca_port'}.log");

	my $ca_server = Net::LDAP->new("$configuration{'ca_host'}:$configuration{'ca_port'}");
	die("Unable to connect to PKI Directory server $configuration{'ca_host'} on port $configuration{'ca_port'}\n")
		unless(defined($ca_server));

	my $ca_transaction = $ca_server->bind("cn=$configuration{'ca_user'}",password=>"$configuration{'ca_password'}");

	# Select only entries of type 'person'.
	my $ca_transaction = $ca_server->search(port=>"$configuration{'ca_port'}", base=>"$configuration{'ca_base'}", scope=>"$configuration{'ca_scope'}", filter=>"(objectclass=person)");

	foreach $entry ($ca_transaction->entries()) {
	if ($entry->get_value('uid')) {
		my $ed_server = Net::LDAP->new("$configuration{'ed_host'}:$configuration{'ed_port'}");
		die("Unable to connect to Enterprise Directory server $configuration{'ed_host'} on port $configuration{'ed_port'}\n")
			unless(defined($ed_server));
		my $ed_transaction = $ed_server->bind("cn=$configuration{'ed_user'}",password=>"$configuration{'ed_password'}");
		my $ed_transaction = $ed_server->search(port=>"$configuration{'ed_port'}", base=>"$configuration{'ed_base'}", scope=>"$configuration{'ed_scope'}", filter=>"(uid=".$entry->get_value('uid').")");
		print(FILE_LOG "person".",\"'".$entry->get_value('uid')."\"");
		foreach $ed_entry ($ed_transaction->entries()) {
			if (($ed_entry->get_value('sn')) && ($ed_entry->get_value('sn') ne _blank)) {
				print(FILE_LOG ",".$ed_entry->get_value('sn').",".$ed_entry->get_value('division'));
			} else {
				if ($entry->get_value('sn') ne _blank) {
					print(FILE_LOG ",".$entry->get_value('sn').",".$ed_entry->get_value('division'));
				} else {
					my ($cn, $dummy) = split(',ou=', $entry->dn(), 2);
					my ($sn, $dummy) = split(',', $cn, 2);
					print(FILE_LOG ",".$sn.",".$ed_entry->get_value('rcmpdiv'));
				}
			}
		}
			
		if ($ed_transaction->count() < 1) {
			print(FILE_LOG ",,");
		}

	} else {
		my ($cn, $dummy) = split(',ou=', $entry->dn(), 2);
		my ($dummy, $dummy, $uid) = split(',', $cn, 3);
		if ((($uid =~ m/^00/) || ($uid =~ m/^E0/)) && (length($uid) == 9)) {
			my $ed_server = Net::LDAP->new("$configuration{'ed_host'}:$configuration{'ed_port'}");
			die("Unable to connect to Enterprise Directory server $configuration{'ed_host'} on port $configuration{'ed_port'}\n")
				unless(defined($ed_server));
			my $ed_transaction = $ed_server->bind("cn=$configuration{'ed_user'}",password=>"$configuration{'ed_password'}");
			my $ed_transaction = $ed_server->search(port=>"$configuration{'ed_port'}", base=>"$configuration{'ed_base'}", scope=>"$configuration{'ed_scope'}", filter=>"(uid=".$entry->get_value('uid').")");
			print(FILE_LOG "person".",\"".$entry->get_value('uid')."\"");
			foreach $ed_entry ($ed_transaction->entries()) {
				if (($ed_entry->get_value('sn')) && ($ed_entry->get_value('sn') ne _blank)) {
					print(FILE_LOG ",".$ed_entry->get_value('sn').",".$ed_entry->get_value('division'));
				} else {
					print(FILE_LOG ",".$entry->get_value('sn').",".$ed_entry->get_value('division'));
				}
			}
		} else {
			if ($entry->get_value('sn') ne _blank) {
				print(FILE_LOG "person".","."".",".$entry->get_value('sn').",");
			} else {
				my ($cn, $dummy) = split(',ou=', $entry->dn(), 2);
				my ($sn, $dummy) = split(',', $cn, 2);
				print(FILE_LOG "person".","."".",".$sn.",");
			}
		}
	}

	
	if ($entry->dn() =~ m/extern/i) {
		print(FILE_LOG ",external");
	} else {
		print(FILE_LOG ",");
	}

	print(FILE_LOG ",\"".$entry->dn());
	
	#Determine the state of the entry in the PKI Directory.
	if ($record{$entry->dn()}) {
		print(FILE_LOG "\",".$record{$entry->dn()}."\n");
	} else {
		print(FILE_LOG "\","."Unknown"."\n");
	}

	$ca_server->unbind();

	print(FILE_LOG "\n");

	close(FILE_LOG);
}

################################################################################

################################################################################
# Function: Extracts entries of type 'device' from the  PKI Directory.
################################################################################

sub process_devices()
{
	# Master transaction log.
	open(FILE_LOG, ">> ./logs/pki.$configuration{'ca_host'}.p$configuration{'ca_port'}.log");

	my $ca_server = Net::LDAP->new("$configuration{'ca_host'}:$configuration{'ca_port'}");
	die("Unable to connect to PKI Directory server $configuration{'ca_host'} on port $configuration{'ca_port'}\n")
		unless(defined($ca_server));

	my $ca_transaction = $ca_server->bind("cn=$configuration{'ca_user'}",password=>"$configuration{'ca_password'}");

	# Select only entries of type 'device'.
	my $ca_transaction = $ca_server->search(port=>"$configuration{'ca_port'}", base=>"$configuration{'ca_base'}", scope=>"$configuration{'ca_scope'}", filter=>"(objectclass=device)");

	foreach $entry ($ca_transaction->entries()) {
		print(FILE_LOG "device".",\"".$entry->dn());
		# Determine the state of the entry in the PKI Directory.
		if ($record{$entry->dn()}) {
			print(FILE_LOG "\",".$record{$entry->dn()}."\n");
		} else {
			print(FILE_LOG "\","."Unknown"."\n");
		}	
	}

	print(FILE_LOG "\n");

	close(FILE_LOG);
}

################################################################################

################################################################################
# Function: Extracts entries of type 'role' from the PKI Directory.
################################################################################

sub process_roles()
{
	# Master transaction log.
	open(FILE_LOG, ">> ./logs/pki.$configuration{'ca_host'}.p$configuration{'ca_port'}.log");

	my $ca_server = Net::LDAP->new("$configuration{'ca_host'}:$configuration{'ca_port'}");
	die("Unable to connect to PKI Directory server $configuration{'ca_host'} on port $configuration{'ca_port'}\n")
		unless(defined($ca_server));

	my $ca_transaction = $ca_server->bind("cn=$configuration{'ca_user'}",password=>"$configuration{'ca_password'}");

	# Select only entries of type 'role'. 
	my $ca_transaction = $ca_server->search(port=>"$configuration{'ca_port'}", base=>"$configuration{'ca_base'}", scope=>"$configuration{'ca_scope'}", filter=>"(ou=roles)");

	foreach $entry ($ca_transaction->entries()) {
		print(FILE_LOG "role".",\"".$entry->dn());
		# Determine the state of the entry in the PKI Directory.
		if ($record{$entry->dn()}) {
			print(FILE_LOG "\",".$record{$entry->dn()}."\n");
		} else {
			print(FILE_LOG "\","."Unknown"."\n");
		}
	}

	print(FILE_LOG "\n");

	close(FILE_LOG);
}

################################################################################

################################################################################
# Function: Gathers selected data about persons, devices, and roles contained in
#			the PKI Directory.
################################################################################

sub process()
{
	process_persons();
	process_devices();
	process_roles();
}

################################################################################

my $numArgs = $#ARGV + 1;
if ($numArgs < 1) {
	print "\nUsage:  certificate_authory_report.pl configuration_file\n\n";
	exit(1);
}

read_configuration();
read_ca_data();
process();

exit(0);

