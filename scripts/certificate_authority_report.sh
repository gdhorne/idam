#!/bin/bash

################################################################################
#
# Script Name: certificate_authority_report.sh
#
# Description: Produces a report for the Certificate Authority breaking down the
#              entries in the PKI Directory into the categories of person,
#	       device, or role.
#
# Usage: certificate_authority_report.sh
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
	echo "ca_host=pki.domain.tld"
	echo "ca_port=389"
	echo "ca_base=\"ou=engineering, d=domain, dc=tld\""
	echo "ca_scope=sub"
	echo "ca_user:\"administrator_account\""
	echo "ca_password:password"
	exit 1
fi

./certificate_authority_report.pl server.cfg

# Edit the following filters according to your schema.
grep 'role,' ./logs/*.log | grep -i -v carole > ./data/roles.csv
grep device ./logs/*.log > ./data/devices.csv
grep person ./logs/*.log | grep ',external,' > ./data/persons-external.csv 
grep person ./logs/*.log | grep -v ',external,' > ./data/persons.csv
 
exit 0
