#!/bin/bash

################################################################################
#
# Script Name: migrate_accounts_to_ldap.sh
# Description: All four-digit user accounts on the server are migrated to the
#              directory server via an intermediate LDIF file.
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
	echo "ldap_base=\"ou=engineering, d=domain, dc=tld\""
	echo "ldap_scope=sub"
	echo "domain=\"o=domain.tld\""
	exit 1
fi

source server.cfg

SUFFIX=${domain}

echo "Extracting four-digit groups from local server (${HOSTNAME})"
echo

FILE_LDIF='ldapgroup.ldif'

echo -n > ${FILE_LDIF}

for line in `grep "x:[1-9][0-9][0-9][0-9]:" /etc/group`
do
    CN=`echo ${line} | cut -d: -f1`
    GID=`echo ${line} | cut -d: -f3`
    echo "dn: cn=${CN},ou=groups,${SUFFIX}" >> ${FILE_LDIF}
    echo "objectClass: posixGroup" >> ${FILE_LDIF}
    echo "cn: ${CN}" >> ${FILE_LDIF}
    echo "gidNumber: ${GID}" >> ${FILE_LDIF}
    users=`echo ${line} | cut -d: -f4 | sed "s/,/ /g"`
    for user in ${users} ; do
        echo "memberUid: ${user}" >> ${FILE_LDIF}
    done
    echo >> ${FILE_LDIF}
done

echo "Adding groups to directory server"

ldapadd \
    -h ${ldap_host} \
    -p ${ldap_port} \
    -x -W -D 'cn=Manager,${SUFFIX}' -f {FILE_LDIF} -c

echo -n "Group count: "
grep -c "gidNumber:" ${FILE_LDIF}

echo "Extracting four-digit accounts from local server (${HOSTNAME})"
echo

FILE_LDIF='ldapuser.ldif'

echo -n > ${FILE_LDIF}

echo "dn: ou=People,${SUFFIX}" >> ${FILE_LDIF}
echo "ou: People" >> ${FILE_LDIF}
echo "objectClass: top" >> ${FILE_LDIF}
echo "objectClass: organizationalUnit" >> ${FILE_LDIF}
echo "description: Parent object of all UNIX accounts" >> ${FILE_LDIF}

for line in `grep "x:[1-9][0-9][0-9][0-9]:" /etc/passwd | sed -e "s/ /%/g"`
do
    UID=`echo $line | cut -d: -f1`

    NAME=`echo $line | cut -d: -f5 | cut -d, -f1`
    if [ ! "${NAME}" ]
    then
        NAME=${UID}
    else
        NAME=`echo ${NAME} | sed -e "s/%/ /g"`
    fi

	GIVEN=`echo ${NAME} | awk '{print $1}'`
    SN=`echo ${NAME} | awk '{print $2}'`
    if [ ! "${SN}" ]
    then
        SN=${NAME}
    fi

    SUID=`echo $line | cut -d: -f3`
    GID=`echo $line | cut -d: -f4`
   	HOME=`echo $line | cut -d: -f6`
	SHELL=`echo $line | cut -d: -f7` 

	PW=`grep ${UID}: /etc/shadow | cut -d: -f2`
   	LAST=`grep ${UID}: /etc/shadow | cut -d: -f3` 
	MIN=`passwd -S ${UID} | awk '{print $4}'`
    MAX=`passwd -S ${UID} | awk '{print $5}'`
	WARN=`passwd -S ${UID} | awk '{print $6}'`
    EXPIRE=`passwd -S ${UID} | awk '{print $7}'`

    FLAG=`grep ${UID}: /etc/shadow | cut -d: -f9`
    if [ ! "${FLAG}" ]
    then
        FLAG="0"
    fi

    echo "dn: uid=${UID},ou=people,${SUFFIX}" >> ${FILE_LDIF}
    echo "objectClass: inetOrgPerson" >> ${FILE_LDIF}
    echo "objectClass: posixAccount" >> ${FILE_LDIF}
    echo "objectClass: shadowAccount" >> ${FILE_LDIF}
    echo "uid: ${UID}" >> ${FILE_LDIF}
    echo "sn: ${SN}" >> ${FILE_LDIF}
    echo "givenName: ${GIVEN}" >> ${FILE_LDIF}
    echo "cn: ${NAME}" >> ${FILE_LDIF}
    echo "displayName: ${NAME}" >> ${FILE_LDIF}
    echo "uidNumber: ${SUID}" >> ${FILE_LDIF}
    echo "gidNumber: ${GID}" >> ${FILE_LDIF}
    echo "userPassword: {crypt}${PW}" >> ${FILE_LDIF}
    echo "gecos: ${NAME}" >> ${FILE_LDIF}
    echo "loginShell: ${SHELL"} >> ${FILE_LDIF}
    echo "homeDirectory: ${HOME}" >> ${FILE_LDIF}
    echo "shadowExpire: ${EXPIRE}" >> ${FILE_LDIF}
    echo "shadowFlag: ${FLAG}" >> ${FILE_LDIF}
    echo "shadowWarning: ${WARN}" >> ${FILE_LDIF}
    echo "shadowMin: ${MIN}" >> ${FILE_LDIF}
    echo "shadowMax: ${MAX}" >> ${FILE_LDIF}
    echo "shadowLastChange: ${LAST}" >> ${FILE_LDIF}
    echo >> ${FILE_LDIF}
done

echo "Adding accounts to directory server"

ldapadd \
	-h ${ldap_host} \
	-p ${ldap_port} \
	-x -W -D 'cn=Manager,${SUFFIX}' -f {FILE_LDIF} -c

echo -n "User count: "
grep -c -i "sn:" ${FILE_LDIF}

exit 0
