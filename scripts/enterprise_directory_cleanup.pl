#!/usr/bin/perl

################################################################################
#
# Script Name: enterprise_directory_cleanup.pl
#
# Description: Sets the attribute 'pkiuserrequired' to 'Yes' for each 
#			   Enterprise Directory entry with a valid HRMIS ID in the PKI
#			   Directory and objectclass 'pkiuser' keyed on attribute 'uid'.
#              Sets the attribute 'garequireduser' to 'Yes' for each Enterprise
#			   Directory entry with a valid HRMIS ID in the GAR Directory keyed
#			   on attribute 'uid'.
#
# Usage: enterprise_directory_cleanup.pl configuration_file
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
#			provided that the following syntax is used.
#
#           Syntax:
#
#              attribute:value
#
#           where 'attribute' is taken from the set of possible values in the
#			list: base, host, password, port, scope, user for the PKI Directory;
#			the Enterprise Directory, and the Web Access Directory.
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
			$configuration{$attribute} = chop($value);
		}
	}

	close(FILE_CONFIGURATION);
}

################################################################################

################################################################################
# Function: Add the attribute 'rcmppkiuserrequired' and set the value to 'Yes'
#			for each Enterprise Directory entry having a corresponding PKI
#			Directory entry with objectclass 'pkiuser' keyed on attribute 'uid'.
################################################################################

sub synchronise_with_pki()
{
	open(FILE_LOG, "> ./logs/ed_sync_pki.$configuration{'ed_host'}.p$configuration{'ed_port'}.log");

	my $ed_server = Net::LDAP->new("$configuration{'ed_host'}:$configuration{'ed_port'}");
	die("Unable to connect to Enterprise Directory server $configuration{'ed_host'} on port $configuration{'ed_port'}\n")
		unless(defined($ed_server));

	my $pki_server = Net::LDAP->new("$configuration{'pki_host'}:$configuration{'pki_port'}");
	die("Unable to connect to PKI Directory server $configuration{'pki_host'} on port $configuration{'pki_port'}\n")
		unless(defined($pki_server));

	my $ed_transaction = $ed_server->bind("cn=$configuration{'ed_user'}",password=>"$configuration{'ed_password'}");
	my $pki_transaction = $pki_server->bind();

	my $count = 0;
	my $errors = 0;

	$pki_transaction = $pki_server->search(port=>"$configuration{'pki_port'}", base=>"$configuration{'pki_base'}", scope=>"$configuration{'pki_scope'}", filter=>"(| (& (objectclass=pkiuser) (uid=00*)) (& (objectclass=pkiuser) (uid=E0*)))");

	if ($pki_transaction->count() > 0) {
		for ($i=0; $i<$pki_transaction->count(); $i++) {
			my $entry = ($pki_transaction->entries)[$i];
			if (($entry->get_value('uid') =~ m/^0[0-9]{8}/) || ($entry->get_value('uid') =~ m/^E[0-9]{8}/))  {
				my $ed_transaction = $ed_server->search(port=>"$configuration{'ed_port'}", base=>"$configuration{'ed_base'}", scope=>"$configuration{'ed_scope'}", filter=>"(uid=".$entry->get_value('uid').")");
				foreach $item ($ed_transaction->entries) {
					if (!$ed_transaction->is_error()) {
						print(FILE_LOG "\n".$item->get_value('uid'));
						$ed_transaction = $ed_server->modify($item->dn(), add => {'rcmppkiuserrequired' => 'Yes'});
						if (!$ed_transaction->is_error()) {
							print(FILE_LOG " Updated\n")
							$count++;
						} else {
							print(FILE_LOG " Not Updated\n");
							$errors++;
						}
					}
				}
			}
		}
	}	


	print(FILE_LOG "\n$count Enterprise Directory entries updated");
	print(FILE_LOG "\n$errors Enterprise Directory entries failed to update");
	print(FILE_LOG "\n");

	$pki_server->unbind();
	$ed_server->unbind();

	close(FILE_LOG);
}

################################################################################

################################################################################
# Function: Add the attribute 'pkiuserrequired' and set the value to 'Yes' for
#			each Enterprise Directory entry having a corresponding Web Access
#			Directory entry keyed on attribute 'uid'.
################################################################################

sub synchronise_with_wa()
{
        open(FILE_LOG, "> ./logs/ed_sync_wa.$configuration{'ed_host'}.p$configuration{'ed_port'}.log");

        my $ed_server = Net::LDAP->new("$configuration{'ed_host'}:$configuration{'ed_port'}");
        die("Unable to connect to Enterprise Directory server $configuration{'ed_host'} on port $configuration{'ed_port'}\n")
                unless(defined($ed_server));

        my $wa_server = Net::LDAP->new("$configuration{'ga_host'}:$configuration{'wa_port'}");
        die("Unable to connect to Web Access Directory server $configuration{'wa_host'} on port $configuration{'wa_port'}\n")
                unless(defined($ga_server));

        my $ed_transaction = $ed_server->bind("cn=$configuration{'ed_user'}",password=>"$configuration{'ed_password'}");
        my $wa_transaction = $wa_server->bind();

        my $count = 0;
        my $errors = 0;

        $wa_transaction = $wa_server->search(port=>"$configuration{'wa_port'}", base=>"$configuration{'wa_base'}", scope=>"$configuration{'wa_scope'}", filter=>"(| (cn=00*) (cn=E0*))");

        if ($wa_transaction->count() > 0) {
                for ($i=0; $i<$wa_transaction->count(); $i++) {
                        my $entry = ($wa_transaction->entries)[$i];
                        if (($entry->get_value('cn') =~ m/^0[0-9]{8}/) || ($entry->get_value('cn') =~ m/^E[0-9]{8}/))  {
                                my $ed_transaction = $ed_server->search(port=>"$configuration{'ed_port'}", base=>"$configuration{'ed_base'}", scope=>"$configuration{'ed_scope'}", filter=>"(uid=".$entry->get_value('cn').")");
                                foreach $item ($ed_transaction->entries) {
                                if (!$ed_transaction->is_error()) {
                                        print(FILE_LOG "\n".$item->get_value('uid'));
                                        $ed_transaction = $ed_server->modify($item->dn(), add => {'wauserrequired' => 'Yes'});
                                        if (!$ed_transaction->is_error()) {
                                                print(FILE_LOG " Updated\n");
                                                $count++;
                                        } else {
                                                print(FILE_LOG " Not Updated\n");
                                                $errors++;
                                        }
                                }
                                }
                        }
                }

        }

        print(FILE_LOG "\n$count Enterprise Directory entries updated");
        print(FILE_LOG "\n$errors Enterprise Directory entries failed to update");
        print(FILE_LOG "\n");

        $wa_server->unbind();
        $ed_server->unbind();

	close(FILE_LOG);
}

################################################################################

################################################################################
# Function: Add the attribute 'pkiuserrequired' and set the value to 'Yes'
#			for each Enterprise Directory entry of employee type Executive.
################################################################################

sub force_ed_update()
{
	open(FILE_LOG, "> ./logs/ed.$configuration{'ed_host'}.p$configuration{'ed_port'}.log");

	my $ed_server = Net::LDAP->new("$configuration{'ed_host'}:$configuration{'ed_port'}");
	die("Unable to connect to Enterprise Directory server $configuration{'ed_host'} on port $configuration{'ed_port'}\n")
		unless(defined($ed_server));

	my $ed_transaction = $ed_server->bind("cn=$configuration{'ed_user'}",password=>"$configuration{'ed_password'}");

	my $count = 0;
	my $errors = 0;

	$ed_transaction = $ed_server->search(port=>"$configuration{'ed_port'}", base=>"$configuration{'ed_base'}", scope=>"$configuration{'ed_scope'}", filter=>"(& (uid=00*) (employeetype=*Exec*))");

	print("\n".$ed_transaction->count()."\n");

	if ($ed_transaction->count > 0) {
		for ($i=0; $i<$ed_transaction->count(); $i++) {
			my $entry = ($ed_transaction->entries)[$i];
			if ($entry->get_value('uid') =~ m/^0[0-9]{8}/) {
				print(FILE_LOG "\n".$entry->get_value('uid'));
				#my $transaction = $ed_server->modify($entry->dn(), add => {'pkiuserrequired' => 'Yes'});
				my $transaction = $ed_server->modify($entry->dn(), add => {'wauserrequired' => 'Yes'});
				if (!$transaction->is_error()) {
					print(FILE_LOG " Updated\n");
					$count++;
				} else {
					print(FILE_LOG " Not Updated\n");
					$errors++;
				}
			}
		}
	}

	print(FILE_LOG "\n$count Enterprise Directory entries updated");
	print(FILE_LOG "\n$errors Enterprise Directory entries failed to update");
	print(FILE_LOG "\n");

	$ed_server->unbind();

	cose(FILE_LOG);
}

################################################################################

my $numArgs = $#ARGV + 1;
if ($numArgs < 1) {
	print "\nUsage:  enterprise_directory_cleanup.pl configuration_file\n\n";
	exit(1);
}

read_configuration();
synchronise_with_pki();
synchronise_with_wa();
force_ed_update();

exit(0);

