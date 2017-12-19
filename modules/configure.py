import os
import shutil

def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
	s = os.path.join(src, item)
	d = os.path.join(dst, item)
	if os.path.isdir(s) and not os.path.isdir(d) and not os.path.isfile(d):
	    shutil.copytree(s, d, symlinks, ignore)
	elif os.path.isfile(s) and not os.path.isfile(d):
	    shutil.copy2(s, d)
	else:
	    pass

def install_modules():
    install_dir = os.__file__
    module_dir = 'modules/total/'
    install_dir = install_dir[:install_dir.rfind('/')]
    copytree(module_dir, install_dir)

#install_modules()

import socket
import yaml
import platform
import psutil
import paramiko

data_dic = {
	'username':'user',
	'userpw':'password',
        'artifact_list':'/etc/makolli/linux.yaml',
        'root_storage_dir':'/tmp/makolli/',
        'net_collector_dir':'net_collector/',
        'artifact_collector_dir':'artifact_collector/',
        'dump_collector_dir':'dump/',
        'server_ip':'125.131.189.40',
        'dest_server_dir':'/home/',
        'interval':'6',
        'sending_time':'4:00'
        }

def check_user():
    agent_name = raw_input("\n[*]insert agent name\n")
    agent_password = raw_input("\n[*]insert agent password\n")
    ip_temp = raw_input("\n[*]insert server ip\n(loris.kro.kr for default)\n")

    if ip_temp:
	ip_temp = data_dic['server_ip']

    try:
    	t = paramiko.Transport((ip_temp, 22))
    	t.connect(username=agent_name, password=agent_password)

    	sftp = paramiko.SFTPClient.from_transport(t)

    	sftp.close()
    	t.close()

    	data_dic['server_ip'] = ip_temp
    	data_dic['username'] = agent_name
    	data_dic['userpw'] = agent_password

	return True
    except:
	print 'wrong inputs\n'
	return False


def insert_list(inserted_data):
    if os.path.isfile(inserted_data) and inserted_data.split('.')[-1] is '.yaml':
        data_dic['artifact_list'] = inserted_data

def set_dir(inserted_data, dir_kind):
    try:
        if not os.path.isdir(inserted_data):
            os.mkdir(inserted_data)
            data_dic[dir_kind]=inserted_data
    except:
        pass

def set_num(inserted_data, num_kind):
    try:
        if inserted_data is not '':
            value = int(inserted_data)
            data_dic[num_kind] = inserted_data
    except:
        pass

def set_time(inserted_data):
    try:
	hour, minute = inserted_data.split(":")
	int(hour)
	int(minute)
	data_dic['sending_time'] = inserted_data
    except:
	pass

def server_set():
    try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((data_dic['server_ip'], 50505))
	s.send("config/" + get_myip() + "/" + data_dic['username'])

	agent_data = get_server_data()

	s.send(agent_data)
	s.close()
    except:
	print("fail to server setting")
	pass

def get_myip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    result = s.getsockname()[0]
    s.close()
    return result

def get_server_data():
    os_data = platform.dist()
    os_kind = os_data[0]
    os_version = os_data[1]

    os_bit = platform.machine()
    kernel_bit = platform.architecture()[0]
    kernel_version = platform.release()

    cpu_per = psutil.cpu_percent()
    st = os.statvfs('/')
    disk_storage = st.f_blocks * st.f_frsize

    ram_storage = psutil.virtual_memory().total

    agent_data = os_kind + '/' + str(os_version) + '/' + os_bit + '/' + kernel_version + '/' + kernel_bit + '/' + str(cpu_per) + '/' + str(disk_storage) + '/' + str(ram_storage)
    return agent_data

while not check_user():
    pass

insert_list(raw_input("[*]insert artifact list file\n(/etc/makolli/linux.yaml for default)\n"))
set_dir(raw_input("\n[*]insert main storage directory\n (/etc/makolli/ for default)\n"), 'root_storage_dir')
set_dir(raw_input("\n[*]insert storage directory for network\n(net_collector/ for default)\n"), 'net_collector_dir')
set_dir(raw_input("\n[*]insert storage directory for artifacts\n(artifact_collector/ for default)\n"), 'artifact_collector_dir')
set_dir(raw_input("\n[*]insert storage directory for dumped data\n(dump/ for default)\n"), 'dump_collector_dir')

set_num(raw_input("\n[*]insert time interval for collecting artifacts\n(3(hour) for default)\n"), 'interval')


set_time(raw_input("\n[*]insert time for send logs(4:00 for default)\n"))

data_dic['dest_server_dir'] = os.path.join(data_dic['dest_server_dir'],data_dic['username'],str(get_myip()))+'/'

if not os.path.isdir('/etc/makolli'):
    os.mkdir('/etc/makolli')

with open('/etc/makolli/makolli_config.yaml', 'w') as outfile:
    yaml.dump(data_dic, outfile, default_flow_style=False)


shutil.copy2('linux.yaml', data_dic['artifact_list'])
shutil.copy2('compressor.py', '/etc/makolli/compressor.py')

if not os.path.isdir('/tmp/makolli'):
    os.mkdir('/tmp/makolli')

server_set()
#get_server_data()


