<h1>Proftpd Autoban</h1>

The purpose of this application is to detect malicious login attempts and ban them. This is similar to what Fail2Ban accomplishes. However, Fail2Ban was not working as expected in a Docker context. This was largely due to the fact Fail2ban wants to run on the host, not inside a container, where it has access to different parts of the networking stack like Iptables. This not to say Fail2Ban can't work, it was simply quicker to create this application. The application, while lightweight, gets the job done. Also, I wanted something that was able to work with the Proftpd mod_wrap2 module.

Proftpd: <url>http://www.proftpd.org/</url><br>
Proftpd mod_wrap2: <url>http://www.proftpd.org/docs/contrib/mod_wrap2.html</url><br>


## Manifest of files
Here are the files included.
```
/usr/local/bin/ban.py
/usr/local/bin/ban.sh
/usr/local/bin/logging
/etc/ban/config.cfg
/etc/ban/whitelist.txt

```

# ban.sh
This script controls the operation of the <code>ban.py</code> application. This is what orchestrates various processes for running <code>ban.py</code> and file sync activities.

#### Using AWS S3 to share the hosts.deny and whitelist.txt
S3 is used as a simple method to share the <code>hosts.deny</code> and <code>whitelist.txt</code> across Proftpd hosts. This is especially useful in clustered environments.

You will need to make sure you edit the script and put in your S3 bucket location. Make sure that Proftpd will have access to this bucket. Also, adjust your subdirectories where you will store both files. The config follows the normal OS path (/etc/..) for the config fiile. Change this however you feel most appropriate.

```
s3_whitelist="s3://bucket/etc/ban/"
s3_hostsdeny="s3://bucket/etc/"
```
#### Sync Operation
The script will make sure that <code>hosts.deny</code> and <code>whitelist.txt</code> are synced first from S3. This is to ensure it has any updates from other nodes. Next, it will run <code>ban.py</code> to scan the <code>AUTH</code> log for suspicious behaviors as defined in the config. If it finds any, those IPs will be appended to the hosts.deny file. Once <code>ban.py</code> is complete, the script will push an update back to S3. While the use of S3 was intended for a cluster it will work for standalone servers as well. It just means your standalone server is the only one reading and writing to those files.

#### Note
You will notice a random <code>sleeptime</code> generated each time the script is run. That is to reduce the possibility that a different node in the cluster may conflict perform the same operation as other nodes.

#### context="aws"
In its current form, everything wants to be run in an AWS context. This is what context="aws" does. Everything will run off of AWS. Just use something like context="local" for testing purposes. You can also replace the S3 commands with something else assuming your want to store those files to a NAS/SAN location.

# ban.py
You  need to edit <code>/usr/local/bin/ban.py</code> to reference the location of your <code>AUTH</code> log. In this example the log is located here: <code>/ebs/logs/proftpd/proftpd_auth.log</code>. Change this to where ever you happen to keep your log.

#### config.cfg

You can control the behavior of the application with the config. For example, you can set the user names, attempts and periods that the application will use to qualify a malicious user to ban.

Example:
```
[DEFAULT]
suspicious_users = root admin administrator
suspicious_users_attempts_threshold = 2
login_attempts_threshold = 5
login_attempts_period = 300
whitelist = /etc/ban/whitelist.txt
```
#### whitelist.txt
Any IP listed here will not be included in the hosts.deny file

Example:
```
0.0.0.0
8.8.8.8
```

#### hosts.deny

In the hosts deny file you will start seeing entries like this:

```
ALL: 222.186.15.104
ALL: 222.186.15.200
ALL: 222.186.34.94
ALL: 222.186.58.136
ALL: 222.187.222.220
ALL: 222.187.224.222
```
These are all from China Telecom.

# mod_wrap2
This requires the use of mod_wrap2. It is responsible for reading the hosts.deny file and blocking access.

http://www.proftpd.org/docs/contrib/mod_wrap2.html

Example configuration statement for mod_wrap2

```

<IfModule mod_wrap2.c>
   WrapEngine           on
   WrapOptions          CheckOnConnect
   WrapDenyMsg          "User '%u' denied by access rules"
   WrapTables           file:/etc/hosts.allow file:/etc/hosts.deny

   <IfClass !localhost>
       WrapLog           /ebs/logs/proftpd/proftpd_wrap.log
   </IfClass>

</IfModule>

```
We are focused on the <code>file:/etc/hosts.deny</code> aspect of the config vs <code>file:/etc/hosts.allow</code>. The hosts.deny file is where we will be storing the banned IPs

## Running

You can do something simple like use CRON. This would be the preferred approach.
```
*/15 * * * * /usr/bin/bash -c '/usr/local/bin/ban.sh' >> /ebs/logs/cron/ban.log 2>&1
```
You can also use a monitoring application. For example, this is a Monit configuration to run whenever someone accesses the server.

```
# Trigger the check of the access log to verify if there are hacking attempts happening
check file ban-logs with path /ebs/logs/proftpd/proftpd_auth.log
      if changed timestamp then exec /usr/bin/bash -c "/usr/local/bin/ban.sh"
```

if logs are rotated frequently and you have light traffic then this option might be ok. However, if you have large log files this can be a bad idea.

You can have Monit run it on a schedule to (vs timestamp checks). This would be similar to CRON.
