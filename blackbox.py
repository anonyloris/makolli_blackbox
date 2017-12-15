#!/usr/bin/python
from subprocess import check_output, CalledProcessError, Popen
from snort import Alertpkt
from scapy.all import *
from StringIO import StringIO
from operator import eq
from zipfile import ZipFile
from crontab import CronTab
import ctypes
import logging
import schedule
import time
import glob
import shutil
import yaml
import tarfile
import sys
import os
import datetime
import socket
import threading
import utils
import signal

setting_stream = open("/etc/makolli/makolli_config.yaml", "r")
setting = yaml.load(setting_stream)
setting_stream.close()

size_max_log = 10 * 1024 * 1024
start_fs = '/'
skipped_dir = []

if len(skipped_dir):
    skipped_dir = [os.path.join(start_fs, d) for d in skipped_dir]
mime_filter = []

level_debug = logging.INFO

net_pid_lock = "/var/lock/net_collector.pid"
artifact_pid_lock = "/var/lock/artifact_collector.pid"

# path file to collects
etc_passwd = os.path.join(start_fs, '/etc/passwd')
etc_shadow = os.path.join(start_fs, '/etc/shadow')
etc_bashrc = os.path.join(start_fs, '/etc/bash.bashrc')
etc_profile = os.path.join(start_fs, '/etc/profile')
etc_cron_rep = os.path.join(start_fs, '/etc/cron.*')
etc_cron = os.path.join(start_fs, '/etc/crontab')
etc_folder_d = os.path.join(start_fs, '/etc/*.d')

class Set_Compressor:
    def __init__(self):
        self.comp_time = setting["sending_time"]
        self.cron = CronTab('root')
        self.command = "python /etc/makolli/compressor.py 1"
        
    def set_cron(self):
        cron_job = self.cron.new(command = self.command)
        hour, minute  = self.comp_time.split(":")
        cron_job.hour.on(int(hour))
        cron_job.minute.on(int(minute))
        
        if not cron_job.is_valid():
            print "\ncannot insert cron job\n"
            pass

        self.cron.write()

class Snort_Set:
    def __init__(self):
	self.UNSOCK_FILE = 'snort_alert'
	self.snort_log_dir = setting['root_storage_dir']
	self.server_address = os.path.join(self.snort_log_dir, self.UNSOCK_FILE)

    def snort_setting(self):
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	try:
	    os.remove(self.server_address)
	except OSError:
	    pass

	sock.bind(self.server_address)

	snort_process = Popen(['snort', '-A', 'unsock', '-l', self.snort_log_dir, '-c', '/etc/snort/snort.conf'], close_fds=True)
	alert = Alertpkt()
	try:
	    while True:
		if sock.recv_into(alert) != ctypes.sizeof(alert):
		    break
	except:
	    sys.exit(1)
	finally:
	    sock.close()
	    os.remove(self.server_address)
	    if snort_process.poll() is None:
		snort_process.kill()
		snort_process.wait()

    def start_snort(self):
	pid = os.fork()
	if pid is 0:
	    pid2 = os.fork()
	    if pid2 is 0:
		self.snort_setting()
	    else:
		sys.exit()
	else:
	    os.waitpid(pid, 0)
	pass
	

class Net_Collector:
    def __init__(self):
	self.root_dir = setting['root_storage_dir']
        self.sub_dir = setting['net_collector_dir']
	
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	self.my_ip = s.getsockname()[0]
	s.close()

	schedule.every(1).hours.do(self.check_alive)

    def check_alive(self):
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    s.connect((setting['server_ip'], 50506))
	    alive_data = setting['username']+'/'+self.my_ip+'/net'
	    s.send(alive_data)
	except:
	    print 'socket error'
	    pass
	finally:
	    s.close()

    def get_date_directory(self):
        d = self.root_dir + datetime.date.today().isoformat()+"/"
    
        if not os.path.isdir(d):
            os.mkdir(d)
	if not os.path.isdir(d+self.sub_dir):
	    os.mkdir(d+self.sub_dir)
    
    def packet_callback(self, packet):
        dir_name = self.root_dir + datetime.date.today().isoformat()+"/" + self.sub_dir
    
        self.get_date_directory()

        layer = packet.payload
        if layer.name == "IP":
            if layer.src == self.my_ip:
                dir_name = dir_name + layer.dst
            else:
                dir_name = dir_name + layer.src

        elif layer.name == "ARP":
            if layer.psrc == self.my_ip:
                dir_name = dir_name + layer.pdst
            else:
                dir_name = dir_name + layer.psrc

        dir_name += ".pcap"
        pktdump = PcapWriter(dir_name, append=True, sync=True)
        pktdump.write(packet)
        del pktdump

    def collector(self):
	sniff(prn=self.packet_callback, store=0)

    def start_collecting(self):
        pid = os.fork()
        if pid is 0:
            pid2 = os.fork()
            if pid2 is 0:
		pid = str(os.getpid())
                pidfile = net_pid_lock
                if os.path.isfile(pidfile):
                    print "%s already exists, exiting collector" % pidfile
                    sys.exit()
                file(pidfile, 'w').write(pid)

                while True:
                    th = threading.Thread(target=self.collector)
                    th.start()
                    th.join()
		    schedule.run_pending()
		    time.sleep(1)
		    
	    else:
                sys.exit()
	os.waitpid(pid,0)
        pass

class Artifact_Collector:
    def __init__(self):
        self.yaml_file = setting['artifact_list']
	self.log_root_dir = setting['artifact_collector_dir']

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 80))
	self.my_ip = s.getsockname()[0]
	s.close()

        schedule.every(int(setting['interval'])).hours.do(self.parse_yaml)

    def check_alive(self):
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    s.connect((setting['server_ip'], 50506))
	    alive_data = setting['username']+'/'+self.my_ip+'/artifact'
	    s.send(alive_data)
	except:
	    pass
	finally:
	    s.close()

    def write_readme(self, directory, doc):
    	fd = open(directory + "/README", "a")
        fd.write(doc)
        fd.close()

    def leave_file_log(self, data):
        log_dir = self.log_root_dir+data["name"]
	if data["labels"][0] == "Logs_for_web":
	    log_dir += '_'
        os.mkdir(log_dir)
	
	arti_num = 0
	
        for file_format in data["sources"][0]["attributes"]["paths"]:
            data_file = glob.glob(file_format)
	    arti_num += len(data_file)

            for f in data_file:
                try:
                    if os.path.isdir(f):
                        dir_list = f.split('/')
                        shutil.copytree(f, log_dir+"/"+dir_list[-1])
                    else:
                        shutil.copy(f, log_dir)
                except Exception as e:
		    pass

	if arti_num == 0:
	    self.args['logger'].info(data["name"]+"/False")
	    shutil.rmtree(log_dir, ignore_errors=False, onerror=None)
	else:
	    self.args['logger'].info(data['name']+'/True')
            self.write_readme(log_dir, data["doc"])
                
    def leave_command_log(self, data):
        comm = data["sources"][0]["attributes"]["cmd"]
	if not os.path.isfile(comm):
	    self.args['logger'].info(data['name'] + "/False")
	    return

        file_name = self.log_root_dir+data["name"]
        fd = open(file_name, "a")
        fd.write(data["doc"])
        fd.close()

        for arg in data["sources"][0]["attributes"]["args"]:
            comm = comm + " " + arg

        os.system(comm + " > " + file_name)
	self.args['logger'].info(data['name']+'/True')

    def compress_data(self, directory):
        root_save_dir = os.path.join(setting['root_storage_dir'],str(datetime.date.today()))
        save_dir = os.path.join(root_save_dir, setting['artifact_collector_dir'])+'/'

        if not os.path.isdir(root_save_dir):
            os.mkdir(root_save_dir)
	if not os.path.isdir(save_dir):
            os.mkdir(save_dir)

	now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

        tar = tarfile.open(save_dir+now+".tar.gz", 'w:gz')
        tar.add(directory)
        tar.close()
    
    def parse_yaml(self):
        self.args = utils.set_args('artifact', setting)
	utils.set_output_dir(self.args)
	utils.set_logger(self.args)

        stream = open( self.yaml_file, "r" )
	
        for data in yaml.load_all(stream):
	    data_type = data["sources"][0]["type"]
	    if eq(data_type, "FILE"):
	        self.leave_file_log(data)
	    elif eq(data_type, "COMMAND"):
	        self.leave_command_log(data)
	    else:
	        continue
	
        self.compress_data(self.log_root_dir)
	shutil.rmtree(self.log_root_dir, ignore_errors=False, onerror=None)
	self.check_alive()

    def start_collecting(self):
	pid = os.fork()
        if pid is 0:
            pid2 = os.fork()
            if pid2 is 0:
		pid = str(os.getpid())
                pidfile = artifact_pid_lock

                if os.path.isfile(pidfile):
                    print "%s already exists, exiting collector" % pidfile
                    sys.exit()
                file(pidfile, 'w').write(pid)
		self.parse_yaml()
                while True:
                    schedule.run_pending()
                    time.sleep(1)
	    else:
	    	sys.exit(0)
	os.waitpid(pid,0)
	pass

class Dump(object):
    def __init__(self, args):
        self.args = args
        self._homes = self._get_home()

    def _get_home(self):
        homes = []
        if os.path.isfile(etc_passwd):
            f = open(etc_passwd, 'r')
            homes = [line.split(":")[5] for line in f]
            f.close()
        return homes

    def get_temp(self):
        file_to_zip = []
        for dirName, subdirList, fileList in os.walk(os.path.join(start_fs, '/tmp')):
            file_to_zip.extend([os.path.join(dirName, f) for f in fileList])
        file_to_zip = list(set(file_to_zip))
        self.args['logger'].info('Zip tmp.zip with %s ' % file_to_zip)
        utils.zip_file(file_to_zip, 'tmp.zip', self.args['output_dir'], self.args['logger'])

    def autorun(self):
        file_to_zip = []
        dir_collect = glob.glob(etc_folder_d)
        cron_dir = glob.glob(etc_cron_rep)
        self.args['logger'].info('Collect %s ' % dir_collect)
        for d in dir_collect:
            for dirName, subdirList, fileList in os.walk(d):
                file_to_zip.extend([os.path.join(dirName, f) for f in fileList])
        self.args['logger'].info('Collect %s ' % cron_dir)
        for d in cron_dir:
            for dirName, subdirList, fileList in os.walk(d):
                file_to_zip.extend([os.path.join(dirName, f) for f in fileList])
        file_to_zip.append(etc_cron)
        self.args['logger'].info('Zip file autorun.zip')
        utils.zip_file(list(set(file_to_zip)), 'autorun.zip', self.args['output_dir'], self.args['logger'])

    def collect_users(self):
        list_to_zip = []
        self.args['logger'].info('Collect users')

        if os.path.isfile(etc_passwd):
            list_to_zip.append(etc_passwd)
        if os.path.isfile(etc_shadow):
            list_to_zip.append(etc_shadow)
        if os.path.isfile(etc_bashrc):
            list_to_zip.append(etc_bashrc)
        if os.path.isfile(etc_profile):
            list_to_zip.append(etc_profile)
        for home in self._homes:
            if os.path.exists(home):
                list_to_zip.extend(
                        [p for p in glob.glob(os.path.join(start_fs, os.path.join(home, '.*'))) if os.path.isfile(p)])
        utils.zip_file(list_to_zip, 'users_home.zip', self.args['output_dir'], self.args['logger'])

    def collect_ssh_profile(self):
        self.args['logger'].info('Collect Know Hosts')
        list_knows_host = []
        for home in self._homes:
            if os.path.exists(home):
                list_knows_host.extend(glob.glob(os.path.join(start_fs, os.path.join(home, '.ssh/known_hosts'))))
                if len(list_knows_host) > 0:
                    utils.zip_file(list_knows_host, 'know_hosts.zip', self.args['output_dir'], self.args['logger'])

    def collect_log(self):
        files_list_to_zip = {}
        self.args['logger'].info('Zip of /var/log')
        for dirName, subdirList, fileList in os.walk(os.path.join(start_fs, '/var/log')):
            for fname in fileList:
                absolut_path = os.path.join(dirName, fname)
                size = os.stat(absolut_path).st_size
                if size < size_max_log:
                    files_list_to_zip[os.path.join(dirName, fname)] = size
        files_list_to_zip_sorted = sorted(files_list_to_zip.items(), key=lambda x: x[1])
        utils.zip_file(dict(files_list_to_zip).keys(), 'var_log.zip', self.args['output_dir'], self.args['logger'])
        self.args['logger'].info('Zip of /var log is finished')
        pass

    def dump_dir(self):
        # recupere tous les dossiers que l'on aura mis en arguments
        pass

    def _active_part(self, block, disk):
        for line in block.split("\n"):
            if disk in line and "*" in line:
                return disk

    def _list_disks(self, res):
        disks = []
        for blocks in res:
            matchob = re.match("\n?Dis[a-z]{1,3}\s([^:]+)", blocks)
            if matchob:
                disks.append(matchob.group(1).replace('\xc2\xa0', ''))
        return disks

    def _get_mbr(self, disks):
        for d in disks:
            disk_name = d.replace("/", "_")
            with open(d, "rb") as f:
                with open(os.path.join(self.args['output_dir'], "mbr" + disk_name), "wb") as output:
                    output.write(f.read(512))

    def dump_mbr(self):
        if utils.os_type() == "mac":
            pass
        else:
            self.args['logger'].info('Collect active MBR')
            r = utils.exec_cmd(fdisk, True)
            res = re.split("\\n\\s*\\n", r)
            disks = self._list_disks(res)
            self.args['logger'].debug('Disks name : %s' % str(disks))
            has_active_part = []
            for blocks in res:
                if disks:
                    for d in disks:
                        m = self._active_part(blocks, d)
                        if m:
                            has_active_part.append(m)
            if has_active_part:
                self._get_mbr(has_active_part)

def select_menu():
    print "select collecting menu"
    print "1. start network and artifact daemon"
    print "2. stop daemon"
    print "3. collect artifacts"
    print "4. memory dump"
    print "5. send data for today"
    print "6. set snort"
    print "7. quit"
    selection = raw_input("select menu : ")
    return selection

def main():
    if os.geteuid() != 0:
        print('This program should be run as root.')
        sys.exit(-1)
    
    selection = select_menu()
    if selection is '1':
        
        network = Net_Collector()
        network.start_collecting()
        del network
	        
        artifacts = Artifact_Collector()
        artifacts.start_collecting()
        del artifacts
	
        cron = Set_Compressor()
        cron.set_cron()
        del cron
	
    elif selection is '2':
	try:
            if os.path.isfile(net_pid_lock):
                net_pid = file(net_pid_lock, 'r').read()
                print net_pid
                os.kill(int(net_pid), signal.SIGKILL)
                os.remove(net_pid_lock)

            if os.path.isfile(artifact_pid_lock):
                artifact_pid = file(artifact_pid_lock, 'r').read()
                print artifact_pid
                os.kill(int(artifact_pid), signal.SIGKILL)
                os.remove(artifact_pid_lock)
        except:
            print "error on canciling"
            pass

    elif selection is '3':
	artifacts = Artifact_Collector()
	artifacts.parse_yaml()
	del artifacts

    elif selection is '4':
        args = utils.set_args('dump', setting)
	utils.set_output_dir(args)
        utils.set_logger(args)
	
	c = Dump(args)
	for attr in dir(c):
	   if attr != 'args' and not attr.startswith('_'):
		getattr(c, attr)()

        utils.set_zip_evidences(args)

    elif selection is '5':
	os.system('python /etc/makolli/compressor.py 0')

    elif selection is '6':
	s = Snort_Set()
	s.start_snort()

    elif selection is '7':
        print "\nbye!!\n"
        sys.exit()

    else:
        print "\n****************"
        print "wrong selection"
        print "****************\n"

while True:
    main()

