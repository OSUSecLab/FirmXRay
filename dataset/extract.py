import os
from zipfile import ZipFile
import json
import subprocess
import threading
import thread
import time
import zlib
import struct
import hashlib

apps_dir = 'Documents/NAS_SYN/apks/2019.01/apks/'

APK_DIR = 'Documents/appsHaveNordicLib/'
CURRENT_DIR = 'Desktop/Firmware/APKExtract/'
OUTPUT_DIR = 'Desktop/Firmware/APKExtract/output/'
STR_DIR = 'Desktop/Firmware/APKExtract/strings/'


NEW_APK_LIST = 'Desktop/Firmware/APKExtract/new_app_list'
NEW_APK_DIR = 'Documents/NAS_SYN/apks/2020.2/apks/'
NEW_APK_DIR_SUB = 'Desktop/Firmware/app/'
NEW_NORDIC_DIR = 'Desktop/Firmware/firmware/nordic_new/'
DONE_TXT = 'Desktop/Firmware/APKExtract/done.txt'
NORDIC_FIRMWARE_LIST = 'Desktop/Firmware/APKExtract/nordic_firmware.txt'

NORDIC_DIR = 'Desktop/Firmware/firmware/nordic/'
DIAGLOG_DIR = 'Desktop/Firmware/firmware/diaglog/'
TI_DIR = 'Desktop/Firmware/firmware/ti/'
BIN_DIR = 'Desktop/Firmware/firmware/bin/'


def decomprese():
    apps = []

    for filename in os.listdir(APK_DIR):
        apps.append(filename)

    apps = apps

    for app in apps:
        os.system("apktool d %s" % APK_DIR + app)

        d = app.replace(".apk", "")
        for subdir, dirs, files in os.walk(d):
            for f in files:
                if f.endswith(".zip") or f.endswith(".bin") or f.endswith(".hex"):
                    if not os.path.exists(CURRENT_DIR + "output/" + d):
                        os.makedirs(CURRENT_DIR + "output/" + d)
                    os.system("cp %s %s" % (os.path.join(subdir, f), os.path.join(CURRENT_DIR, "output", d)))

        os.system("rm -rf %s" % d)


def filterFirmware():
    count = 0
    for subdir, dirs, files in os.walk(OUTPUT_DIR):
        # if not os.path.exists(os.path.join(subdir, "firmware")):
        #     os.makedirs(os.path.join(subdir, "firmware"))

        for filename in os.listdir(subdir):
            if filename.endswith(".zip"):
                try:
                    with ZipFile(os.path.join(subdir, filename), 'r') as zipObj:
                        nameList = zipObj.namelist()
                        if "manifest.json" in nameList:
                            count += 1
                            if not os.path.exists(os.path.join(subdir, filename.replace(".zip", ""))):
                                os.makedirs(os.path.join(subdir, filename.replace(".zip", "")))
                            zipObj.extractall(os.path.join(subdir, filename.replace(".zip", "")))
                except Exception as e:
                    print e

    print count


def printAllFirmware():
    count = 0
    # f = open('firmwarelist', 'w')
    for subdir, dirs, files in os.walk(NEW_NORDIC_DIR):
        nordic_flag = False
        for filename in os.listdir(subdir):
            if filename.__contains__('manifest.json'):
                nordic_flag = True

        for filename in os.listdir(subdir):
            if not nordic_flag:
                break
            if filename.endswith(".bin"):
                count += 1
                print subdir + "/" + filename
                # print >> f, subdir + "/" + filename
    # f.close()
    print count


def printAllNordic():
    count = 0
    news = []
    for subdir, dirs, files in os.walk(NORDIC_DIR):
        for filename in os.listdir(subdir):
            if filename.endswith('.bin'):
                count += 1
                print os.path.join(subdir, filename)
                news.append(os.path.join(subdir, filename))
                print os.path.join(subdir, filename)
    print count


    # with open('Desktop/Firmware/IoTFirmwareAnalysis/firmwarelist', 'w') as o:
    #     for new in news:
    #         print >> o, new


def check_len_ti(fileName):
    try:
        size = os.path.getsize(fileName) 
        # print size

        f = open(fileName, 'rb')
        f.read(24)
        len = struct.unpack('<L',f.read(4))[0]
        # print len
        if len == size:
            print size, len

        return len == size

    except Exception:
        return False


def check_len_ti_and_ble(fileName):
    try:
        size = os.path.getsize(fileName) 
        # print size

        f = open(fileName, 'rb')

        # ble
        # f.read(14)
        # is_ble = False
        # wireless_tech = struct.unpack('<L',f.read(4))[0]

        # print hex(wireless_tech)

        # if hex(wireless_tech).endswith("fffe"):
        #     is_ble = True

        # exclude tlink

        f.read(8)
        not_tlink = True
        tlink = f.read(4)

        if tlink == "KNLT":
            not_tlink = False

        # size
        size_equal = False
        f.read(12)
        len = struct.unpack('<L',f.read(4))[0]
        if len == size:
            size_equal = True

        size_equal = True
        # print len
        # if len == size:
        #     print size, len

        return not_tlink & size_equal

    except Exception:
        return False


def extract_ti_firmware():
    output = open('ti_firmware.txt', 'w')
    d = BIN_DIR
    count = 0
    # d = 'Desktop/Firmware/firmware/diaglog/6.0.12.1020.2/SDK/6.0.12.1020.2/binaries/da14531/prod_test/'
    for subdir, dirs, files in os.walk(d):
        for f in files:
            file_path = os.path.join(subdir, f)
            if check_len_ti(file_path):
                print file_path
                count += 1
                print >> output, file_path
    output.close()


def extract_ti_firmware_with_ble():
    i = open('ti_firmware.txt', 'r')
    o = open('ti_firmware_ble.txt', 'w')
    count = 0
    # d = 'Desktop/Firmware/firmware/diaglog/6.0.12.1020.2/SDK/6.0.12.1020.2/binaries/da14531/prod_test/'
    for line in i.readlines():
        app = line.strip()
        if check_len_ti_and_ble(app):
            print >> o, app
            count += 1
    o.close()



def extract_dialog_firmware():
    count = 0
    for subdir, dirs, files in os.walk(BIN_DIR):
        for f in files:
            file_path = os.path.join(subdir, f)
            if f.endswith('.img'):
                try:
                    s = open(file_path, 'rb')
                    b = s.read(2)
                    b0 = hex(ord(b[0]))
                    b1 = hex(ord(b[1]))
                    # print b0, b1, file_path
                    if (b0 == '0x70' and b1 == '0x51') or (b0 == '0x70' and b1 == '0x61'):
                        print file_path
                        count += 1
                except Exception:
                    pass
    print count


def dumpString():
    for subdir, dirs, files in os.walk(OUTPUT_DIR):
        for sd, d, f in os.walk(subdir):
            for filename in os.listdir(sd):
                if filename.endswith(".bin"):
                    strs = os.system("strings %s > %s.txt" % (os.path.join(sd, filename), os.path.join(sd, filename)))
                    pass


def findKey():
    for subdir, dirs, files in os.walk(OUTPUT_DIR):
        for sd, d, f in os.walk(subdir):
            for filename in os.listdir(sd):
                if filename.endswith(".txt"):
                    with open(os.path.join(sd, filename), 'r') as ff:
                        lines = ff.readlines()
                        for line in lines:
                            if line.__contains__("account"):
                                print filename
                                print line
                                print


def binwalk():
    for subdir, dirs, files in os.walk(OUTPUT_DIR):
        for sd, d, f in os.walk(subdir):
            for filename in os.listdir(sd):
                if filename.endswith(".bin"):
                    print filename
                    # os.system("python3 ~/Desktop/Firmware/nrf5x-tools/nrfident.py bin %s" % os.path.join(sd, filename))
                    os.system("binwalk %s" % os.path.join(sd, filename))
                    print


def nordic_result():
    outdir = 'Desktop/Firmware/IoTFirmwareAnalysis/output/'
    total_count = 0
    solved_count = 0
    for filename in os.listdir(outdir):
        f = open(outdir + filename, 'r')
        d = json.load(f)
        values = d['Values']
        total_count += 1
        for value in values:
            if value['Solved'] == True:
                solved_count += 1
                break
    print total_count, solved_count

tids = range(10)


def get_new_app_list():
    apps = os.listdir(NEW_APK_DIR_SUB)
    with open(NEW_APK_LIST, 'w') as i:
        for app in apps:
            print >> i, app


def decompress_all():
    apps = []

    with open(NEW_APK_LIST, 'r') as i:
        for line in i.readlines():
            apps.append(line.strip())

    count = apps.__len__()

    done = []
    with open(DONE_TXT, 'r') as i:
        for line in i.readlines():
            done.append(line.strip().replace('\n', ''))


    '''
    with open('Desktop/Firmware/APKExtract/ble_apps.txt', 'r') as i:
        lines = i.readlines()
        for line in lines:
            try: 
                line = json.loads(line)
                apps.append(line['path'].split('/')[-1].strip())
            except Exception:
                pass

    count = apps.__len__()'''

    for app in apps:
        if app in done:
            print "%s has been done!" % app
            count -= 1
            print count
            continue

        while len(tids) == 0:
            time.sleep(0.1)
        tid = tids.pop()
        thread.start_new_thread( decompress_one, (app, tid) )

        with open(DONE_TXT, 'a') as i:
            print >> i, app
        count -= 1
        print count


def decompress_one(app, tid):
    os.system("apktool d %s" % NEW_APK_DIR_SUB + app)
    d = app.replace(".apk", "")
    for subdir, dirs, files in os.walk(d):
        for f in files:
            if f.endswith(".zip"):
                # nordic
                try:
                    with ZipFile(os.path.join(subdir, f), 'r') as zipObj:
                        nameList = zipObj.namelist()
                        if "manifest.json" in nameList:
                            if not os.path.exists(NEW_NORDIC_DIR + d):
                                os.makedirs(NEW_NORDIC_DIR + d)
                            zipObj.extractall(NEW_NORDIC_DIR + d + "/" + f.replace(".zip", ""))

                except Exception as e:
                    print e

            '''
            elif f.endswith(".bin") or f.endswith(".hex") or f.endswith(".img"):
                # other type
                print f
                if not os.path.exists(BIN_DIR + d):
                    os.makedirs(BIN_DIR + d)''
                os.system("cp %s %s" % (os.path.join(subdir, f), os.path.join(BIN_DIR, d)))

                
                result = subprocess.check_output(['strings', os.path.join(subdir, f)])
                if result.__contains__("Diaglog") or result.__contains__("diaglog"):
                    if not os.path.exists(DIAGLOG_DIR + d):
                        os.makedirs(DIAGLOG_DIR + d)
                    os.system("cp %s %s" % (os.path.join(subdir, f), os.path.join(DIAGLOG_DIR, d)))
                elif result.__contains__("Taxes") or result.__contains__("taxes") or result.__contains__("Taxes Instruments") or result.__contains__("TaxesInstruments"):
                    if not os.path.exists(TI_DIR + d):
                        os.makedirs(TI_DIR + d)
                    os.system("cp %s %s" % (os.path.join(subdir, f), os.path.join(TI_DIR, d)))
                '''

    os.system("rm -rf %s" % d)
    tids.append(tid)


def bin():
    d = BIN_DIR
    # d = 'Desktop/Firmware/firmware/diaglog/6.0.12.1020.2/SDK/6.0.12.1020.2/binaries/da14531/prod_test/'
    for subdir, dirs, files in os.walk(d):
        for f in files:
            file_path = os.path.join(subdir, f)
            # p = subprocess.Popen(["hexdump", "-n4", file_path], stdout=subprocess.PIPE)
            p = subprocess.Popen(["xxd", file_path, '| grep "SBL SFW"'], stdout=subprocess.PIPE)
            out, err = p.communicate()
            try:
                # print out
                if out.strip() != "":
                    print out
                #if out.split(' ')[2].strip() == "07fc":
                #    print file_path
                #    print out
            except Exception:
                pass

def printAllNordicApp():
    count = 0
    for subdir, dirs, files in os.walk(nordic_firmware):
        fs = os.listdir(subdir)
        if fs.__len__() == 0:
            print subdir.split('/')[-1]


def duplicate():
    count = 0
    news = []
    '''
    for subdir, dirs, files in os.walk(NORDIC_DIR):
        for filename in os.listdir(subdir):
            if filename.endswith('.bin'):
                count += 1
                news.append(os.path.join(subdir, filename))
                # print os.path.join(subdir, filename)
    print count'''

    with open(NORDIC_FIRMWARE_LIST, 'r') as i:
        for line in i.readlines():
            news.append(line.strip().replace('\\', ''))

    hashes = {}

    for f in news:
        md5 = hashlib.md5(open(f,'rb').read()).hexdigest()
        if md5 not in hashes.keys():
            hashes[md5] = []
        hashes[md5].append(f)

    # for key in hashes.keys():
    #     if hashes[key].__len__() > 1:
    #         print md5, hashes[md5].__len__()

    for key in hashes.keys():
        if hashes[key].__len__() > 10:
            print key, hashes[key].__len__()
            for f in hashes[key]:
                print f
            print

    with open('nordic_firmware_unique.txt', 'w') as i:
        for h in hashes:
            if hashes[h][0].__contains__("__MACOSX"):
                continue
            i.write(hashes[h][0].strip().replace(' ', '\\ ').replace('(', '\\(').replace(')', '\\)') + "\n") 
    print hashes.__len__()



if __name__ == '__main__':
     decompress_all()

