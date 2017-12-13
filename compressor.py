import zipfile
import tarfile
import os
import sys
import datetime
import paramiko
import yaml
import socket
import hashlib

setting_stream = open("/etc/makolli/makolli_config.yaml", "r")
setting = yaml.load(setting_stream)
setting_stream.close()

def unzip_socket(username, userip, unzip_date):
    HOST = setting['server_ip']
    PORT = 50505

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    s.send('unzip/'+userip + "/" + username)
    s.close()

def zip_data(src_path, dest_file):
    with zipfile.ZipFile(dest_file, 'w') as zf:
	rootpath=src_path
	for (path, dir, files) in os.walk(src_path):
            for item in files:
		fullpath = os.path.join(path,item)
		relpath = os.path.relpath(fullpath, rootpath);
		zf.write(fullpath, relpath, zipfile.ZIP_DEFLATED)

def get_myip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    myip = s.getsockname()[0]
    s.close()

    return myip

myip = get_myip()
unzip_date = 0

if sys.argv[1]:
    print 'python compressor.py [data for n days before]'
else:
    try:
	int(sys.argv[1])
    except:
	print 'wrong argument type'
	sys.exit(1)

unzip_date = int(sys.argv[1])

filename = setting['username'] + "_" + myip + "_" + str(datetime.date.fromordinal(datetime.date.today().toordinal() - unzip_date))+".zip"

zip_source = os.path.join(setting['root_storage_dir'], str(datetime.date.fromordinal(datetime.date.today().toordinal() - unzip_date)))

fname = os.path.join(setting['root_storage_dir'], filename)

zip_data(zip_source, fname)

t = paramiko.Transport((setting['server_ip'], 22))

pw = setting['userpw']
username = setting['username']

with connect(username = username, password=pw) as t:
    with paramiko.SFTPClient.from_transport(t) as sftp:
	sftp.put(fname, setting['dest_server_dir']+filename)

os.remove(fname)

unzip_socket(setting['username'], get_myip(), unzip_date)


