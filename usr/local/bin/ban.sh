#!/usr/bin/env bash

##    ____                   __         _     __
##   / __ \____  ___  ____  / /_  _____(_)___/ /___ ____
##  / / / / __ \/ _ \/ __ \/ __ \/ ___/ / __  / __ `/ _ \
## / /_/ / /_/ /  __/ / / / /_/ / /  / / /_/ / /_/ /  __/
## \____/ .___/\___/_/ /_/_.___/_/  /_/\__,_/\__, /\___/
##     /_/                                  /____/
##
##
##  Blacklist - Auto Ban
##  ----------------------------------------------------------------------
##  This process will scan a log for hacking attempts and ad the IP's
##  to /etc/hosts.deny. This is then picked up by Proftpd. Includes sync
##  to S3 to allow for sharing across multiple instances.
##
##  For more information on Proftpd visit http://www.proftpd.org
##
##  -------------------------------------------------------------
##  Copyright (C) 2016 Openbridge, Inc. - All Rights Reserved
##  Permission to copy and modify is granted under the Openbridge, Inc. license
##  Last revised 01/20/2016
##  version 1.0
##

set -o errexit
set -o nounset
set -o pipefail

date=$(date +"%Y-%m-%d")
datetime="$(date +'%Y-%m-%dT%H:%M:%S%z')"
file="$(basename "$0")"
filename="${file%.*}"

err() {
  echo "[${datetime}]: ${*}" 2>>/ebs/logs/${filename}/${filename}.log 1>&2 |ts
  exit 1
}

echo "OK: Running the ${filename} on ${date}..."

source /usr/local/bin/logging

context="ob_mode"

sleeptime=$(shuf -i 20-60 -n 1)

echo "OK: Waiting for ${sleeptime} seconds before we run the blacklist sync porcess..."

sleep ${sleeptime}

# AWS S3 config files
s3_whitelist="s3://bucket/etc/ban/"
s3_hostsdeny="s3://bucket/etc/"

###################
# GENERATE BLACKLIST
###################

if [[ ${context} = aws ]]; then

    # Sync whitelist IPs from S3
    aws s3 cp ${s3_whitelist}whitelist.txt /etc/ban/whitelist.txt || err "ERROR [${filename}]: Could run not AWSCLI (code: ${?})"

    # Sync blacklist from S3
    aws s3 cp ${s3_hostsdeny}hosts.deny /etc/hosts.deny || err "ERROR [${filename}]: Could run not AWSCLI (code: ${?})"

    # Update the blacklist
    python /usr/local/bin/ban.py /etc/ban/config.cfg || err "ERROR [${filename}]: Could run not blacklist.py (code: ${?})"

    # Remove any duplicate entries
    sort -u /etc/hosts.deny -o /etc/hosts.deny || err "ERROR [${filename}]: Could run not blacklist.py (code: ${?})"

    # Push the blacklist back to S3
    aws s3 cp /etc/hosts.deny ${s3_hostsdeny}hosts.deny || err "ERROR [${filename}]: Could run not AWSCLI (code: ${?})"

else

    # Update the blacklist
    python /usr/local/bin/blacklist.py || err "ERROR [${filename}]: Could run not blacklist.py (code: ${?})"

    # Remove any duplicate entries
    sort -u /etc/hosts.deny -o /etc/hosts.deny || err "ERROR [${filename}]: Could run not blacklist.py (code: ${?})"

fi

exit 0
