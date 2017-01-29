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

set -o xtrace
set -o nounset
set -o pipefail

source /network

context="$MODE"
sleeptime=$(shuf -i 5-15 -n 1)

echo "OK: Waiting for ${sleeptime} seconds before we run the blacklist sync process..."

sleep ${sleeptime}

###################
# GENERATE BLACKLIST
###################

function get_config() {

if [[ ${context} = aws ]]; then
  # AWS S3 config files
    s3_whitelist="s3://ob_internal/etc/ban"
    s3_hostsdeny="s3://ob_internal/etc"
    # Sync whitelist IPs from S3
    aws s3 cp ${s3_whitelist}/whitelist.txt /etc/ban/whitelist.txt
    # Sync blacklist from S3
    aws s3 cp ${s3_hostsdeny}/hosts.deny /etc/hosts.deny
    # Update the blacklist
    python /usr/bin/ban.py /etc/ban/config.cfg
    # Remove any duplicate entries
    sort -u /etc/hosts.deny -o /etc/hosts.deny
    # Push the blacklist back to S3
    aws s3 cp /etc/hosts.deny ${s3_hostsdeny}/hosts.deny
else
    # Update the blacklist
    python /usr/bin/ban.py
    # Remove any duplicate entries
    sort -u /etc/hosts.deny -o /etc/hosts.deny
fi
}

function update_allowed() {
    while read -r allowed
    do
      name="${allowed}"
      echo "OK: Add $name to ProFTP IP/DNS-based allowed access control table"
      mysql -h ${MYSQL_HOST} -u ${PROFTPD_SYSTEM_USER} -p${PROFTPD_SYSTEM_PASSWORD} -e "use ${PROFTPD_DATABASE}; INSERT IGNORE INTO ftpdallowed (client_ip) VALUES ('$name');"
    done < /etc/ban/whitelist.txt
}

function update_denied() {
    sed 's|ALL:\s||g' /etc/hosts.deny > /etc/banip
    while read -r denied
    do
      name="${denied}"
      echo "OK: Add $name to ProFTP IP/DNS-based denied access control table"
      mysql -h ${MYSQL_HOST} -u ${PROFTPD_SYSTEM_USER} -p${PROFTPD_SYSTEM_PASSWORD} -e "use ${PROFTPD_DATABASE}; INSERT IGNORE INTO ftpddenied (client_ip) VALUES ('$name'); DELETE FROM ftpddenied
      WHERE modified < UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 180 DAY))"
    done < /etc/banip
}

function run_all() {
    echo "STARTING: All Ban processing ..."
    get_config
    update_allowed
    update_denied
}

if [[ -z "${1:-}" ]]; then
    echo "STARTING: Running all processes ..."
    run_all
else
    echo "STARTING: Running ${1} process ..."
    ${1}
fi

exit 0
