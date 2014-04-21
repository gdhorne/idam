#!/usr/bin/perl

################################################################################
#
# Script Name: ga_bulk_load.pl
# Description: Generates a tab-delimited file containing a randomly generated
#              (unique) default password, an LDIF file containing statements to
#              modify the attribute 'gaauthmethod' to include the PKI DN, and a
#              tab-delimited file containing the role for each Entrust GetAccess
#              user identified in the source file.
#
# Usage:
#   ga_bulk_load.pl user_file ga_user_file ga_authentication_file ga_user_roles
#
# Copyright (c) 2004 Gregory D. Horne (horne at member dot fsf dot org)
# All rights reserved.
#
################################################################################
#
#    This software is released under the BSD 2-Clause License and may be
#    redistributed under the terms specified in the LICENSE file.
#
################################################################################

################################################################################
# Input Definition
#
# Format: uid,pki_dn
# 012345678,cn="Doe,John Albert,012345678",ou=people,dc=domain,dc=tld
#
# Output Definition
#
# Format: givenname		sn	uid		password	group
#	      John Albert	Doe	012345678	A0123456	internal
#                                                                       external
#
# Password Generation Rules:
#
# 1. Generate password with prefix "A" followed by seven (7) digits (0..9).
# 2. If password has been allocated previously, then repeat Step 1.
################################################################################

################################################################################
# Function: Generate next available unique 9-character uid for external
#           personnel consisting of prefix "E" followed by eight digits.
#           THIS FUNCTION IS ORGANISATIONALLY DEPENDENT AND SHOULD BE MODIFIED
#           FROM THE GENERIC IMPLEMENTATION.
################################################################################

sub generate_unique_external_identifier()
{
	open(FILE_EXTERNAL_UID, "< ./uid");
	my $line = <FILE_EXTERNAL_UID>;
	close(FILE_EXTERNAL_UID);

	chomp($line);
	my $uid = $line + 1;

	open(FILE_EXTERNAL_UID, "> ./uid");
	print(FILE_EXTERNAL_UID "$uid");
	close(FILE_EXTERNAL_UID);

	# Pad $uid to length of nine (9) numeric characters
	while (length($uid) < 8) {
		$uid = '0'.$uid;
	}
	$uid = 'E'.$uid;
	return $uid;
}

################################################################################

################################################################################
# Function: Generate unique 8-character password consisting of the prefix "A"
#           followed by seven (7) numeric characters (0..9).  For improved
#           security, each password will only be assigned to one user.  In the
#           event of a collision in password assignment, another password is
#           generated and assigned.
################################################################################

sub generate_ga_password {
	my @charset = ("0".."9");
	my $password = join("",@charset[map{rand @charset}(1..7)]);
	while ($list{$password}) {
		$password = join("",@charset[map{rand @charset}(1..7)]);
	}
	$list{$password} = $password;
	return "A".$password;
}

################################################################################

################################################################################
# Function: Produce record suitable for Entrust GetAccess.
#
# Users: Tab-delimited record - one per user
#
#   Field       	Meaning
#   -----       	-------
#   givenname   	givenname
#   sn          	surname
#   uid         	UNIX user id
#   password    	unique 8-character default password
#
# Authentication: LDIF-formatted entry for each user
#
# Roles: Tab-delimited record - one per user
#
#   Field		Meaning
#   -----		-------
#   uid			UNIX user id
#   role		role designator
#   group		group designator
#   group_name		group name
################################################################################

sub processRecord {

	open(FILE_USERS, "< $ARGV[0]");
	open(FILE_GAACCOUNTS, "> $ARGV[1]");
	open(FILE_GAAUTHMETHOD, "> $ARGV[2]");
	open(FILE_GAROLES, "> $ARGV[3]");

	# Seed the pseudo-random number generator and force unique seed selection
	srand;

	my $line;
	while ($line = <FILE_USERS>) {

		chomp($line);
		$line =~ s/\"\"/\"/g;

		my ($uid, $surname, $givenname, $pki_dn) = split(',', $line, 4);

		# Handle accounts for users external to the organisation
		# Organisational specific requirements to be implemented
		if (($uid !~ m/^[0-9]/) && (($uid !~ m/^E/) \
			|| ($uid !~ m/E[0-9]{8}/))) {
			$uid = generate_unique_external_identifier();
		}

		# Pad $uid to length of nine (9) numeric characters
		while (length($uid) < 9) {
			$uid = '0'.$uid;
		}

		# Clean-up surname
		$surname =~ s/^\ //;
		$surname =~ s/\ $//;

		# Clean-up givenname
		$givenname =~ s/^\ //;
		$givenname =~ s/\ $//;
		
		# If the givenname begins wth either 'Joseph' or 'Marie', then take only the
		# last part of the givenname. (e.g.) Marie Louise Joanne => Joanne

		my $name;
		if (($givenname =~ m/^Joseph/) || ($givenname =~ m/^Marie/)) {
			$name = $givenname;
			while (length($givenname) > 0) {
				($name, $givenname) = split(' ', $givenname, 2);
			}
			$givenname = $name;
		} else {
			# Everyone else.
			($givenname, $name) = split(' ', $givenname, 2);
		}

		# Create Entrust GetAccess user record
		print(FILE_GAACCOUNTS $givenname."\t".$surname."\t".$uid."\t".generate_ga_password);
		if ($uid =~ m/^E/) {
			print(FILE_GAACCOUNTS "\texternal\n");
		} else {
			print(FILE_GAACCOUNTS "\tinternal\n");
		}

		# Create Entrust GetAcess user record with authentication method
		my $ga_dn = "dn: cn=".$uid.",ou=gausers,ou=getaccess,dc=domain,dc=tld";
		print(FILE_GAAUTHMETHOD $ga_dn."\n");
		print(FILE_GAAUTHMETHOD "changetype: modify\nadd: gaauthmethod\n");

		# Clean-up pki_dn
		$pki_dn =~ s/\"//g;
		$pki_dn =~ s/^\ //;
		$pki_dn =~ s/\ $//;
		$pki_dn =~ s/\x0d//;
		$pki_dn =~ s/\\//g;	
		$pki_dn =~ s/,\ /,/g;
		$pki_dn =~ s/,/%2C/g;
		$pki_dn =~ s/=/%3D/g;
		$pki_dn =~ tr/\ /\+/;

		print(FILE_GAAUTHMETHOD "gaauthmethod: truepass|".$pki_dn."|".$pki_dn."\n");
		print(FILE_GAAUTHMETHOD "-\n");
		print(FILE_GAAUTHMETHOD "replace: gapwdexpinterval\n");
		print(FILE_GAAUTHMETHOD "gapwdexpinterval: 90\n\n");

		# Create Entrust GetAccess user record with role
		# Organisational specific requirements to be implemented
		print(FILE_GAROLES $uid."\t"."rolecat"."\t"."roleid"."\t"."rolename"."\n");		
	}

	close(FILE_GAAUTHMETHOD);
	close(FILE_GAACCOUNTS);
	close(FILE_USERS);

}

################################################################################

if ($#ARGV + 1 < 4) {
	print("\nUsage: ga_bulk_load.pl ga_users_input_file ga_users_output_file ga_auth_output_file ga_roles_output_file");
	exit(1);
}

processRecord;
exit(0);
