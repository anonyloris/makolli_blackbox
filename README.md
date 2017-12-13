# makolli_blackbox
## blackbox
This tool is for collecting artifacts continuously on linux server like blackbox.
Blackbox collect network packet and artifacts written on linux.yaml.
After run the collector, it run as daemon on background.
You can also use memory dump and artifact collecting as single time.

## set logrotate

user should set logrotate rule to fix with Makolli system.

      /etc/logrotate.d/
In this directory, there are ruleset file for every logs on the server.
In those file, user should the log setting 'daily' inside of {} for those logs.

#### 1. rsyslog
 - /var/log/syslog
 - /var/log/daemon.log
 - /var/log/auth.log
 - /var/log/cron.log
 - /var/log/messages

#### 2. apache2
 - /var/log/apache2/*.log

#### 3. postgresql-common
 - /var/log/postgresql/*.log

#### 4. mysql_server
 - /var/log/mysql/*log

## install blackbox
#### 1. sftp check
Download this repository and run configure.py in repository directory.

    python configure.py
Than you should insert agent id, agent password and server ip to check connect to makolli server by sftp.
If you insert wrong information about these three, you cannot progress the install.

#### 2. insert system configure data
After success to connect at makolli server, you should insert configure data to run blackbox module.
If you want to use default data, don't insert anything at insert sign.

#### 3. run blackbox
Than you can run blackbox module.

    python blackbox.py

## blackbox menu
#### 1. start network and artifact daemon
#### 2. stop daemon
#### 3. collect artifacts
#### 4. memory dump
#### 5. send data for today
#### 6. set snort
#### 7. quit
