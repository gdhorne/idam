#!/bin/bash

################################################################################
# Script Name: contacts.sh
#
# Description: Adds the telephone number from the Enterprise Directory to each
#	       record contained in a comma-separated-values (CSV) format file.
#
# Usage: contacts.sh

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
	exit 1
fi

# Modify the file names (employees and employees.csv) as necessary
./contacts.pl server.cfg employees employees.csv
