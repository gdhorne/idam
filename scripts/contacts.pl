#!/usr/bin/perl

################################################################################
#
# Script Name: contacts.pl
#
# Description: Adds the telephone number from the Enterprise Directory to each
#	       record contained in a comma-separated-values (CSV) format file.
#
# Usage:
#   contacts.pl configuration_file data_file_input data_file_output
#
# Copyright (c) 2005 Gregory D. Horne (horne at member dot fsf dot org)
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
#	    provided that the following syntax is used.
#
#           Syntax:
#
#              attribute:value
#
#           where 'attribute' is taken from the set of possible values in the
#	    list: base, host, password, port, scope, user for the Enterprise
#	    Directory.
################################################################################

sub read_configuration()
{
	%configuration = undef;
	%configuration = ();

	open(CONFIG, "< $ARGV[0]") ||
		die("Unable to open configuration file [$ARGV[0]]: $!\n");

	my $line;
	while ($line = <CONFIG>) {
		if (length($line) > 1) {
			($attribute, $value) = split(':', $line, 2);
			chop($value);
			$configuration{$attribute} = $value;
		}
	}

	close(CONFIG);
}

################################################################################

################################################################################
# Function: For each record in the contacts file add the telephone number.
################################################################################

sub process_record()
{
	my %access = ();

	open(FILE_RECORDS, "< ./data/$ARGV[1]");
	open(FILE_CONTACTS, "> ./data/$ARGV[2]");

	my $server = Net::LDAP->new("$configuration{'ed_host'}:$configuration{'ed_port'}");
	die("Unable to connect to Enterprise Directory server $configuration{'ed_host'} on port $configuration{'ed_port'}\n")
		unless(defined($server));

	my $transaction = $server->bind("cn=$configuration{'ed_user'}",password=>"$configuration{'ed_password'}");

	my $line;
	while ($line = <FILE_RECORDS>) {

		$line =~ s/\x0a//;
		$line =~ s/\x0d//;

		# Parse the record to extract the uid
		my ($uid, $dummy) = split(';', $line, 2);
		$uid =~ s/ //g;

		# Query the Enterprise Directory for the record associated with the uid
		$transaction = $server->search(port=>"$configuration{'ed_port'}", base=>"$configuration{'ed_base'}", scope=>"$configuration{'ed_scope'}", filter=>"(uid=$uid)");

		# Rewrite the record
		print(FILE_CONTACTS $line);
		if ($transaction->count > 0) {
			print(FILE_CONTACTS ';'.$transaction->entry->get_value('telephonenumber'));
		}
		print(FILE_CONTACTS "\n");	
	}

	$server->unbind;

	close(FILE_CONTACTS);
	close(FILE_RECORDS);
}

################################################################################

my $numArgs = $#ARGV + 1;
if ($numArgs < 3) {
	print "\nUsage:  contact.pl configuration_file data_file_input data_file_output\n\n";
	exit(1);
}

read_configuration();
process_record();

exit(0);

