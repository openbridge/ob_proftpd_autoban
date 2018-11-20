#!/usr/bin/env python
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
import calendar
import collections
import ConfigParser
import datetime
import json
import re
import sys
if len(sys.argv) != 2:
    print 'Usage:', sys.argv[0], '/etc/ban/config.cfg'
    sys.exit(2)
 config = ConfigParser.RawConfigParser()
config.read(sys.argv[1])
 # Attempting to login as those users with no passwords can get you banned
suspicious_users = config.get(
    'DEFAULT', 'suspicious_users').split(' ')
 # Number of attempts to login as users from the setting above that we'll tolerate
suspicious_users_attempts_threshold = config.getint(
    'DEFAULT', 'suspicious_users_attempts_threshold')
 # Number of attempts per period that we can tolerate
login_attempts_threshold = config.getint(
    'DEFAULT', 'login_attempts_threshold')
 # Period for setting above in seconds
login_attempts_period = config.getint('DEFAULT', 'login_attempts_period')
 whitelist = config.get('DEFAULT', 'whitelist')
if whitelist:
    whitelist = [line.strip() for line in file(whitelist) if line.strip()] or []
 ip_re = re.compile('^.*?(?P<ip>([0-9]{1,3}\.){3}[0-9]{1,3}).*$')
 def parse_ips_re(fname):
    ips = set()
    with file(fname) as fhandle:
        for line in fhandle:
            line = line.strip()
            match = ip_re.match(line)
            if match:
                ips.add(match.groupdict()['ip'])
    return ips
 suspicious_re = re.compile(
    '^Password required for (?P<user>{})$'.format('|'.join(suspicious_users)))
 def parse_ips_json(fname, existing):
    banned = existing.copy()
    banned_new = set()
    suspicious = collections.defaultdict(int)
    attempts = collections.defaultdict(list)
     with file(fname) as fhandle:
        for line in fhandle:
            line_limit = line.index('}')
            if line_limit == '-1':
                print 'Malformed line: "{}"'.format(line)
            else:
                line = line[:line_limit + 1]
             try:
                data = json.loads(line)
            except Exception as e:
                print 'Error "{}" loading JSON: "{}"'.format(e, line)
                continue
             ip = data['remote_ip']
             if ip in banned or ip in whitelist or data['response_code'] == '-':
                continue
             if suspicious_re.match(data['client_response']):
                suspicious[ip] += 1
                if suspicious[ip] >= suspicious_users_attempts_threshold:
                    # Yay! We ban you
                    print 'BAN', ip, 'for suspicious logins'
                    banned.add(ip)
                    banned_new.add(ip)
                    if ip in attempts:
                        del attempts[ip]
                    del suspicious[ip]
                    continue
             if data['response_code'] == '530':
                date = calendar.timegm(
                    datetime.datetime.strptime(
                        data['time'].lstrip('[').split(' ')[0],
                        '%d/%b/%Y:%H:%M:%S').timetuple())
                attempts[ip].append(date)
                ip_attempts = [
                    attempt_date for attempt_date in attempts[ip]
                    if attempt_date > date - login_attempts_period]
                if len(ip_attempts) > login_attempts_threshold:
                    print 'BAN', ip, 'for login frequency'
                    banned.add(ip)
                    banned_new.add(ip)
                    if ip in suspicious:
                        del suspicious[ip]
                    del attempts[ip]
                    continue
                else:
                    attempts[ip] = ip_attempts
    return banned_new
 blacklisted_ips = parse_ips_re("/etc/hosts.deny")
print 'Currently banned:', ', '.join(blacklisted_ips)
 source_ips = parse_ips_json("/var/log/proftpd/auth.log", blacklisted_ips)
 with file("/etc/hosts.deny", "a") as hosts_deny:
    for ip in source_ips:
        hosts_deny.write("ALL: %s\n" % ip)
