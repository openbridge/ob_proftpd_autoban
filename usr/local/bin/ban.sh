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
##  Copyright (C) 2018 Openbridge, Inc. - All Rights Reserved
##  Permission to copy and modify is granted under the Openbridge, Inc. license
##  Last revised 11/13/2018
##  version 1.1
##

set -o xtrace
set -o nounset
set -o pipefail

source /network

context="$MODE"
sleeptime=$(shuf -i 1-5 -n 1)

echo "OK: Waiting for ${sleeptime} seconds before we run the blacklist sync process..."

sleep ${sleeptime}

###################
# GENERATE BLACKLIST
###################

function get_config() {

if [[ ${context} = aws ]]; then
  # AWS S3 config files
    s3_whitelist="s3://ob_internal/etc/ban/"
    s3_hostsdeny="s3://ob_internal/etc/"
    # Sync whitelist IPs from S3
    aws s3 cp ${s3_whitelist}whitelist.txt /etc/ban/whitelist.txt
    # Sync blacklist from S3
    aws s3 cp ${s3_hostsdeny}hosts.deny /etc/hosts.deny
    # Update the blacklist
    python /usr/bin/ban.py /etc/ban/config.cfg
    # Remove any duplicate entries
    sort -u /etc/hosts.deny -o /etc/hosts.deny
    # Push the blacklist back to S3
    aws s3 cp /etc/hosts.deny ${s3_hostsdeny}hosts.deny
else
    # Update the blacklist
    python /usr/bin/ban.py
    # Remove any duplicate entries
    sort -u /etc/hosts.deny -o /etc/hosts.deny
fi
}

function update_denied() {
    sed 's|ALL:\s||g' /etc/hosts.deny > /etc/banip
    while read -r denied
    do
      sleep 0.2
      name="${denied}"
      echo "OK: Add $name to ProFTP IP/DNS-based denied access control table"
      mysql -h ${MYSQL_HOST} -u ${PROFTPD_SYSTEM_USER} -p${PROFTPD_SYSTEM_PASSWORD} -e "use ${PROFTPD_DATABASE}; INSERT IGNORE INTO ftpd_deny (client_ip) VALUES ('$name'); DELETE FROM ftpd_deny
      WHERE modified < UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 30 DAY))"
    done < /etc/banip
}

function update_allowed() {
    while read -r allowed
    do
      sleep 0.2
      name="${allowed}"
      echo "OK: Add $name to ProFTP IP/DNS-based allowed access control table"
      mysql -h ${MYSQL_HOST} -u ${PROFTPD_SYSTEM_USER} -p${PROFTPD_SYSTEM_PASSWORD} -e "use ${PROFTPD_DATABASE}; INSERT IGNORE INTO ftpd_allow (client_ip, accessed, modified) VALUES ('$name', 'NOW()', 'NOW()'); DELETE FROM ftpd_deny WHERE client_ip='$name'"
    done < /etc/ban/whitelist.txt
}

function run_all() {
    get_config
    update_denied
    update_allowed

}

if [[ -z "${1:-}" ]]; then
    echo "STARTING: Running all processes ..."
    run_all
else
    echo "STARTING: Running ${1} process ..."
    ${1}
fi

exit 0
