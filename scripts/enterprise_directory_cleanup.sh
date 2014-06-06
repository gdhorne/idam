#!/bin/bash

################################################################################
#
# Script Name: enterprise_directory_cleanup.sh
#
# Description: Sets the attribute 'pkiuserrequired' to 'Yes' for each 
#			   Enterprise Directory entry with a valid HRMIS ID in the PKI
#			   Directory and objectclass 'pkiuser' keyed on attribute 'uid'.
#              Sets the attribute 'garequireduser' to 'Yes' for each Enterprise
#			   Directory entry with a valid HRMIS ID in the GAR Directory keyed
#			   on attribute 'uid'.
#
# Usage: enterprise_directory_cleanup.sh
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

if [ ! -e server.cfg ]
then
	echo "Create a configuration file (server.cfg) as shown."
	echo
	echo "ed_host=ldap.domain.tld"
	echo "ed_port=389"
	echo "ed_base=\"ou=engineering, d=domain, dc=tld\""
	echo "ed_scope=sub"
	echo "ed_user:\"administrator_account\""
	echo "ed_password:password"
	echo "data_file:input_file_name.csv"
	echo "wa_host=pki.domain.tld"
	echo "wa_port=389"
	echo "wa_base=\"ou=engineering, d=domain, dc=tld\""
	echo "wa_scope=sub"
	echo "wa_user:\"administrator_account\""
	echo "wa_password:password"
	echo "pki_host=pki.domain.tld"
	echo "pki_port=389"
	echo "pki_base=\"ou=engineering, d=domain, dc=tld\""
	echo "pki_scope=sub"
	echo "pki_user:\"administrator_account\""
	echo "pki_password:password"
	exit 1
fi

./enterprise_directory_cleanup.pl server.cfg
 
exit 0
