from zipfile import ZipFile
from StringIO import StringIO
import shutil
import os
import sys
import datetime
import logging

level_debug = logging.DEBUG

def exec_cmd(cmd, raw_res=False):
    cmd_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not raw_res:
	res = []
        for p in cmd_process.stdout:
            res.append(p.replace("\n", ""))
        return res
    else:
        return cmd_process.stdout.read()

def os_type():
    try:
        return utils.exec_cmd(uname_os_name, True)
    except:
        return "mac"

def zip_file(list_to_zip, zip_filename, output_dir, logger):
    my_zip = ZipFile(os.path.join(output_dir, zip_filename), 'w')
    for path in list_to_zip:
        try:
            my_zip.write(path)
        except Exception as e:
            logger.error(e.strerror + ' ' + path)

    my_zip.close()

def set_logger(args):
    class InfoStreamHandler(logging.StreamHandler):
        def __init__(self, stream):
            logging.StreamHandler.__init__(self, stream)

    logger = logging.getLogger("makolli")
    logger.setLevel(level_debug)

    log_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    fh = logging.FileHandler(os.path.join(args["output_dir"], args['profile'] + ".log"), encoding="UTF-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(log_format)
    logger.addHandler(fh)

    fs = InfoStreamHandler(sys.stdout)
    fs.setFormatter(log_format)
    if 'level_debug' in args:
        fs.setLevel(args['level_debug'])
    logger.addHandler(fs)
    args["logger"] = logger

def set_output_dir(args):
    os.mkdir(args['output_dir'])

    dir_temp = '/'
    dir_list = args['dir_zip'].split('/')

    for i in dir_list:
        dir_temp = os.path.join(dir_temp, i)
        if not os.path.isdir(dir_temp):
            os.mkdir(dir_temp)

def set_args(profile, setting):
    args = {}

    args['output_dir'] = setting[profile + '_collector_dir']
    args['dir_zip'] = os.path.join(setting['root_storage_dir'], str(datetime.date.today()), args['output_dir'])
    args['profile'] = profile

    return args

def set_zip_evidences(args):
    path_output_dir = args['output_dir']
    items = path_output_dir.split(os.path.sep)[::-1]

    name_zip_file = items[0] + '_' + items[1] + '.zip'
    zip_path = os.path.join(args['dir_zip'], name_zip_file)
    args['logger'].info('Create zip File %s ' % name_zip_file)
    my_zip = ZipFile(zip_path, 'w')

    for dirName, subdirList, fileList in os.walk(path_output_dir, topdown=False):
        for fname in fileList:
            my_zip.write(os.path.join(dirName, fname))
    my_zip.close()
    shutil.rmtree(os.path.dirname(path_output_dir))
    args['logger'].info('Delete folder %s' % path_output_dir)
