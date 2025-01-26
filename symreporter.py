#!/usr/bin/python

import csv, sqlite3
import re
import os, errno, pwd
import sys
import string
import glob
import time
import pandas as pd
import numpy as np
import datetime
import collections
import itertools
import ipaddress
import warnings
import urllib2
import requests
import xlsxwriter as xl
from time import sleep
from collections import defaultdict
from collections import OrderedDict
from itertools import izip, count
from operator import itemgetter

#symantec endpoint protection formatted dates
current_date = time.strftime('%Y-%m-%d')
current_ym = time.strftime('%Y-%m')
scan_date = time.strftime('%m')+'/%'+'%/'+time.strftime('%y')

#default values
user_name = pwd.getpwuid( os.getuid() )[ 0 ]
default_name = "SEP-"+current_date+".csv"
outfile_name = ''
unx_desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/')
default_desk = unx_desktop

#csv defaults
csv_finder = glob.glob(default_desk +'*.csv')
csv_default = csv_finder

#current OS versions, put web scraper here

curr_winos = 
curr_macos = 
curr_winsrv = 
curr_winent = 
current_os_list = [curr_winos,curr_macos,curr_winsrv,curr_winent]

#tables
tables_list = []
data_to_print = []

#ip data
pubhostips = {}
pubgwips = {}
pubdnsips = {}
pubdhcpips = {}
identify_ip = []
names = []
ip1 = []
ip2 = []
ip3 = []
ip4 = []


#data retrieve
def get_data(db_file):
	tables = 'select "Computer Name", "Current User", '
	cur = con.cursor()
	cur.execute(tables+'"Infected" from SepData where "Infected" = "Yes";')
	user_inf = cur.fetchall()
	cur.execute(tables+'"Restart Required" from SepData where "Restart Required" = \'Yes\';')
	user_rest = cur.fetchall()
	cur.execute(tables+'"Version" from SepData where "Version" NOT LIKE "' + current_ym + '%/%' + current_sep + '" OR "Version" IS NULL;')
	user_vers = cur.fetchall()
	cur.execute(tables+'"Deployment Status" from SepData where "Deployment Status" LIKE \'The Client%\';')
	user_updt = cur.fetchall()
	cur.execute(tables+'"Last Scan Time" from SepData where "Last Scan Time" NOT LIKE "'+scan_date+'%:%/%"')
	user_scan = cur.fetchall()
	cur.execute(tables+'"MAC Address1", "MAC Address2", "MAC Address3", "MAC Address4" from SepData')
	user_mac = cur.fetchall()
	cur.execute(tables+'"Download Insight On" from SepData where "Download Insight On" NOT LIKE "Enabled%";')
	mod_ins = cur.fetchall()
	cur.execute(tables+'"SONAR On" from SepData where "SONAR On" NOT LIKE "Enabled%";')
	mod_sonar = cur.fetchall()
	cur.execute(tables+'"Memory Exploit Mitigation On" from SepData where "Memory Exploit Mitigation On" NOT LIKE "Enabled%";')
	mod_memex = cur.fetchall()
	cur.execute(tables+'"Tamper Protection On" from SepData where "Tamper Protection On" NOT LIKE "Enabled%";')
	mod_tamper = cur.fetchall()
	cur.execute(tables+'"Intrusion Prevention On" from SepData where "Intrusion Prevention On" NOT LIKE "Enabled%";')
	mod_ips = cur.fetchall()
	cur.execute(tables+'"Service pack" from SepData where "Service pack" NOT LIKE "Enabled%";')
	mod_svc = cur.fetchall()
	cur.execute(tables+'"Network and Host Exploit Mitigation On" from SepData where "Network and Host Exploit Mitigation On" NOT LIKE "Enabled%";')
	mod_hem = cur.fetchall()
	cur.execute(tables+'"IP Address1", "IP Address2", "IP Address3", "IP Address4" from SepData')
	ip_host = cur.fetchall()
	cur.execute(tables+'"Gateway1", "Gateway2", "Gateway3", "Gateway4" from SepData')
	ip_gw = cur.fetchall()
	cur.execute(tables+'"DNS server 1", "DNS server 2", "WINS server 1", "WINS server 2" from SepData')
	ip_dns = cur.fetchall()
	cur.execute(tables+'"DHCP server" from SepData')
	ip_dhcp = cur.fetchall()
	cur.close()
	return user_inf, user_rest, user_vers, user_updt, user_scan,user_mac, mod_ins, mod_sonar, mod_memex, mod_tamper, mod_ips, mod_svc, mod_hem, ip_host, ip_gw, ip_dns, ip_dhcp

def pub_handler(x, name, adict):
	if ipaddress.ip_address(unicode(x)).is_global and name in adict:
		adict[name].append(x)
	elif ipaddress.ip_address(unicode(x)).is_global and name not in adict:
		adict[name] = [x]
	elif not ipaddress.ip_address(unicode(x)).is_global:
		pass

def el_handler(x, alist):
	elist = [el[x] for el in alist]
	return elist

def pub_ip_locate(iplist, outdict):
	names = el_handler(0, iplist)
	ips1 = el_handler(2, iplist)
	ips2 = el_handler(3, iplist)
	ips3 = el_handler(4, iplist)
	ips4 = el_handler(5, iplist)
	for name, a, b, c, d in zip(names, ips1, ips2, ips3, ips4):
		try:
			pub_handler(a, name, outdict)
			pub_handler(b, name, outdict)
			pub_handler(c, name, outdict)
			pub_handler(d, name, outdict)
		except:
			IndexError
			pass

def pub_dhcp_locate(iplist, outdict):
	names = el_handler(0, iplist)
	ips1 = el_handler(2, iplist)
	for name, a in zip(names, ips1):
		try:
			pub_handler(a, name, outdict)
		except:
			TypeError
			pass

def tuple_to_list(tuples):
	conv_list = [list(elem) for elem in tuples]
	return conv_list

def null_remover(alist):
	a_null = ['None','...','8.8.8.8', '1.1.1.1']
	def_ip = '0.0.0.0'
	for items in alist:
		for n,i in enumerate(items):
			if i in a_null:
				items[n] = def_ip
	return alist


def ip_extractor(indict, outlist):
	ips = [item[1] for item in indict.items()]
	for ip in ips:
		for i in ip:
			if i not in outlist:
				outlist.append(i)

#opening credit
print(""" _____                       _            
/  ___|                     | |           
\ `--.  ___ _ __   ___  __ _| |_ ___ _ __ 
 `--. \/ _ \ '_ \ / _ \/ _` | __/ _ \ '__|
/\__/ /  __/ |_) |  __/ (_| | ||  __/ |   
\____/ \___| .__/ \___|\__,_|\__\___|_|   3.0
           | |                            
           |_|                            



(Written by: 'Ryan Horan')""")
print('_____________________________________________')
sleep(1)
#user inputs current symantec version
print ("\nEnter the current SEP version (default/format is rev. 00%)\n")
current_sep = raw_input('SEP: ')
if current_sep.lower() == '':
	current_sep = current_date+"rev. 00%"
	print("Using Default..")
#user inputs OS's that are recent, which should be as easy as copy and paste from SEP
print ("\nEnter current OS's versions.")
print ("Type 'clear' to clear the cache and 'show' to see whats loaded, type 'pop' to remove last")
print ("\nPress 'Enter' when finished")

while True:
	os_entry = raw_input('OS: ')
	current_os_list.append(os_entry)
	if os_entry.lower() == '':
		break
	if os_entry.lower() == 'clear':
		current_os_list = []
	if os_entry.lower() == 'pop':
		current_os_list = current_os_list[:-2]
	if os_entry.lower() == 'show':
		current_os_list = current_os_list[:-1]
		print(', '.join(current_os_list))

#user inputs outputfile name
print ("\nEnter Site (e.g PEK or NYC) This will be used as output name (e.g PEK-YY-MM-DD.xlxs)")
while True: 
	site = raw_input("Name: ")
	if not 3<=len(site)<=3:
		print("Only three characters please")
		continue
	if not site.isalnum():
		print("Please use alpha-numeric characters only")
		continue
	else:
		outfile_name = site+current_date+'.xlsx'
		break


#user inputs their os for file generating purposes
print("Enter your OS (type 'windows' or 'unix', default is unix/mac)")
while True:
	usr_desktop = raw_input("OS: ")
	if usr_desktop.lower() == 'windows':
		print("Using Windows..")
		default_desk = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
		break
		sleep(1)
	if usr_desktop.lower() == 'unix':
		print("Using Unix..")
		break
		sleep(1)
	if usr_desktop.lower() == '':
		print("Using Default..")
		break
		sleep(1)
	else:
		print("Invalid entry")
		sleep(1)

#user inputs path to find their csv
print("Enter the path of your csv file, otherise hit Enter. (Defaults to Desktop/*.csv)")
while True:
	el = 0
	csv_path = raw_input("Path: ")
	if os.path.isfile(csv_path):
		csv_default = csv_path
		break
	elif csv_path.lower() == '':
		if len(csv_default) == 1:
			if os.path.isfile(csv_default[0]):
				print("Using Default..")
				break
		elif len(csv_default) > 1:
			print("Multiple csv files found, which file? (Enter the number)")
			counter = range(len(csv_default))
			for i,file in zip(counter,csv_default):
				print(i,file)
			num = raw_input("Number: ")
			el = int(num)
			if os.path.isfile(csv_default[el]):
				break
	else:
		print(csv_path+' is an invalid path.')

#lets user choose which data to write
print("What data do you wish to export? Press 'Enter' for all or to finish")
print("'1' - Endpoint data\n'2' - Module data\n'3' - IP/GW/DNS data")

while True:
	allowed = ['1','2','3']
	usr_choice = raw_input(": ")
	data_to_print.append(usr_choice)
	if usr_choice == '':
		data_to_print = data_to_print[:-1]
		if len(data_to_print) == 0:
			data_to_print = allowed
			break
		else:
			data_to_print = set(data_to_print) & set(allowed)
			data_to_print = list(data_to_print)
			if len(data_to_print) == 0:
				data_to_print = allowed
			break

print("Opening your csv..")
sleep (1)
df = pd.read_csv(csv_default[el])
df.columns = df.columns.str.strip()

#spins up a sqlite db
print("Spinning up db..")
sleep(1)
con = sqlite3.connect('SepEater.db', detect_types=sqlite3.PARSE_DECLTYPES)
con.text_factory = str
df.to_sql('SepData', con, if_exists='replace')
sql_data = get_data('SepEater.db')

#presorted data
print("Reading data..")
users_infected = tuple_to_list(sql_data[0])
users_restart = tuple_to_list(sql_data[1])
users_vers = tuple_to_list(sql_data[2])
users_noupdate = tuple_to_list(sql_data[3])
users_noscan = tuple_to_list(sql_data[4])
user_macadd = tuple_to_list(sql_data[5])
mod_ins = tuple_to_list(sql_data[6])
mod_sonar = tuple_to_list(sql_data[7])
mod_memex = tuple_to_list(sql_data[8])
mod_tamper = tuple_to_list(sql_data[9])
mod_ips = tuple_to_list(sql_data[10])
mod_svc = tuple_to_list(sql_data[11])
mod_hem = tuple_to_list(sql_data[12])
ip_host = tuple_to_list(sql_data[13])
ip_gw = tuple_to_list(sql_data[14])
ip_dns = tuple_to_list(sql_data[15])
ip_dhcp = tuple_to_list(sql_data[16])

#checks public ips
pub_ip_locate(null_remover(ip_host), pubhostips)
pub_ip_locate(null_remover(ip_gw), pubgwips)
pub_ip_locate(null_remover(ip_dns), pubdnsips)
pub_dhcp_locate(null_remover(ip_dhcp), pubdhcpips)

#nested lists
user_data = [users_infected, users_restart, users_vers, users_noupdate, users_noscan, user_macadd] 
mod_data = [mod_ins, mod_sonar, mod_memex, mod_tamper, mod_ips, mod_svc, mod_hem]
ip_data = [pubhostips, pubgwips, pubdnsips, pubdhcpips]


row = 1
col = 0
workbook = xl.Workbook(outfile_name)
worksheet = workbook.add_worksheet()
bold = workbook.add_format({'bold': 1})
worksheet.write('A1', 'Hostname', bold)
worksheet.write('B1', 'User', bold)
worksheet.write('C1', 'Infected', bold)

for host, user, data in users_infected:
	worksheet.write_string(row, col, host)
	worksheet.write_string(row, col +1, user)
	worksheet.write_string(row, col +2, data)
	row += 1