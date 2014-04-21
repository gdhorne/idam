#!/bin/bash

################################################################################
#
# Script Name: ldap_extract_employee_types.sh
# Description: Queries a directory server and returns a list of employee types. 
#
# Copyright (c) 2001 Gregory D. Horne (horne at member dot fsf dot org)
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
	echo "ldap_host=ldap.domain.tld"
	echo "ldap_port=389"
	echo "ldap_base=\"ou=engineering, o=domain.tld\""
	echo "ldap_scope=sub"
	echo "domain=\"o=domain.tld\""
	exit 1
fi

source server.cfg

echo "Employee Types and Counts"
echo
echo -e "Count\tEmployee Type"

ldapsearch \
	-h ${ldap_host} \
	-p ${ldap_port} \
	-b ${ldap_base} \
	-s ${ldap_scope} objectclass=organizationalperson employeetype \
| grep employeetype | cut -d \= -f 2 | sort | uniq | \
while read employee_type
do
	echo -n \
		$(ldapsearch \
			-h ${ldap_host} \
			-p ${ldap_port}\
			-b ${ldap_base} \
			-s ${ldap_scope} employeetype="${exployee_type}" \
		| grep uid= | grep -c -v ${domain})
	echo -n -e "\t"
	echo ${employee_type}
done

exit 0
