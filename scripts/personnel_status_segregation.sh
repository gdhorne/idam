#!/bin/bash

################################################################################
# Script Name: personnel_status_segregation.sh
#
# Description: Splits the human resources daily dump into two files:
#			    <dump_file>.active and <dump_file>.inactive.
#
# Usage: personnel_status_segregation.sh hr_dump

# Copyright (c) 2004 Gregory D. Horne (horne at member dot fsf dot org)
# All rights reserved.
#
################################################################################
#
#    This software is released under the BSD 2-Clause License and may be
#    redistributed under the terms specified in the LICENSE file.
#
################################################################################

# Specify the daily dump file.
DUMP_FILE=${1}

# Separate the active (A) and inactive (D) human resources records.
if [ -f ./data/${DUMP_FILE} ]
then
   grep ^A ./data/${DUMP_FILE} > ./data/${DUMP_FILE}.active;    # Select records of active staff
   grep ^D ./data/${DUMP_FILE} > ./data/${DUMP_FILE}.inactive;  # Select records of inactive staff
fi

