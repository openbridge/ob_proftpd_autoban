#!/usr/bin/env bash

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

wget --no-check-certificate --directory-prefix=/etc/ban https://raw.githubusercontent.com/openbridge/ob_proftpd_autoban/master/etc/ban/config.cfg

if [[ ${context} = aws ]]; then
  # AWS S3 config files
    # Sync whitelist IPs from S3
    aws s3 cp s3://ob_internal/etc/ban/whitelist.txt /etc/ban/whitelist.txt
    # Sync blacklist from S3
    aws s3 cp s3://ob_internal/etc/hosts.deny /etc/hosts.deny
    # Update the blacklist
    python /usr/bin/ban.py /etc/ban/config.cfg
    # Remove any duplicate entries
    sort -u /etc/hosts.deny -o /etc/hosts.deny
    sort -u /etc/ban/whitelist.txt -o /etc/ban/whitelist.txt
    # Push the blacklist back to S3
    aws s3 cp /etc/hosts.deny s3://ob_internal/etc/hosts.deny
else
    # Update the blacklist
    python /usr/bin/ban.py /etc/ban/config.cfg
    # Remove any duplicate entries
    sort -u /etc/hosts.deny -o /etc/hosts.deny
    sort -u /etc/ban/whitelist.txt -o /etc/ban/whitelist.txt
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
      WHERE modified < UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 3 DAY))"
    done < /etc/banip
}

function update_allowed() {
    while read -r allowed
    do
      sleep 0.2
      name="${allowed}"
      echo "OK: Add $name to ProFTP IP/DNS-based allowed access control table"
      mysql -h ${MYSQL_HOST} -u ${PROFTPD_SYSTEM_USER} -p${PROFTPD_SYSTEM_PASSWORD} -e "use ${PROFTPD_DATABASE}; INSERT IGNORE INTO ftpd_allow (client_ip) VALUES ('$name'); DELETE FROM ftpd_deny WHERE client_ip='$name'"
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
