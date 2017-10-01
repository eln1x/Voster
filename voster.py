#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'Ahmad Mahfouz'
__version__ = "1.0"
__email__='n1x.osx#icloud.com'
__status__='Developemnt'
__license__ ='GNU'
__version__ = "3"
# Voster  ( A Virtual  Host Scanner )
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
try:
	import ipaddr
	import requests
	from bs4 import BeautifulSoup
	from Queue import Queue
	from threading import Thread,Lock
	from datetime import datetime
	import threading
	import time
	import sys
	import argparse
	import random
	import json
except:
	print "[!] Error: please install the requirments , pip install -r requirements.txt"
	import sys
	sys.exit(0)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


banner = """

____    ____  ______        _______.___________. _______ .______      
\   \  /   / /  __  \      /       |           ||   ____||   _  \     
 \   \/   / |  |  |  |    |   (----`---|  |----`|  |__   |  |_)  |    
  \      /  |  |  |  |     \   \       |  |     |   __|  |      /     
   \    /   |  `--'  | .----)   |      |  |     |  |____ |  |\  \----.
    \__/     \______/  |_______/       |__|     |_______|| _| `._____|
                                                                      Version 1.0
								      Author: Ahmad Mahfouz @eln1x
"""
NOTICE = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

print OKBLUE+ banner + ENDC


parser = argparse.ArgumentParser(description="""Voster check misconfigured Cloud-WAF/Load Balancer implementation""" )		
parser.add_argument("-d", "--domain", action='store',  dest='domain', help="target domain name")
parser.add_argument("-p", "--port", dest='port' ,help="target port number",type=int ,action="store", default=80)
parser.add_argument("-m", "--method", action='store',  dest='method', help="target domain name",default="http")
parser.add_argument("-t", "--threads", dest="threads", help="number of threads", type=int, default=10)
parser.add_argument("-s", "--subnet", dest='subnet' ,help="range to scan for domain name example: 192.168.1.1/24")
parser.add_argument("-f", "--fingerprint", dest='fingerprint' ,help="a unique string exist inside the web contenet example: CyberSpace_logo150x150.png", default="Welcome")
parser.add_argument("-x", "--timeout", dest='timeout' ,help="connection timeout", type=int, default=5)
parser.add_argument("-z", "--debug", dest='debug' ,help="print debug messages", type=bool, default=False)

args = parser.parse_args()


domain = args.domain
port = args.port
method = args.method
threads = args.threads
subnet = args.subnet
fingerprint = args.fingerprint
timeout = args.timeout
debug = args.debug

ips = []
dns_ips = []

usage = """
[!] Usage example
	python voster.py -d target-domain.com -s 42.X.X.X/24  -f companyname  -x 5
"""
if not domain:

	print FAIL + usage + ENDC
	sys.exit(1)

def collectips(subnet):
	for addr in subnet.iterhosts():
		if addr not in ips:
			ips.append(str(addr))	

try:
	network = ipaddr.IPv4Network(subnet)
	collectips(network)
except ipaddr.AddressValueError:
	network =[]
	print WARNING + "[!] Warning you didn't provide a subnet mask, \"use -s 62.X.X.X/24\" or let Voster collect the DNS records" + ENDC




## arg input



def DNSIP(domain):

	# MX record IP's
	try:
		mx = requests.get('https://dns-api.org/MX/%s/' %domain , verify=False)
		for row in json.loads(mx.text):

			mx_row = row['value'].split(" ")[1]
			a = requests.get('https://dns-api.org/A/%s/' %mx_row , verify=False)
			for ip in json.loads(a.text):

				targetIP = ip['value']
				dns_ips.append(targetIP)
				print "%s[!] DNS MX: %s has IP:%s %s" %(NOTICE,mx_row,targetIP,ENDC)
		# Name Servers IP's
		ns = requests.get('https://dns-api.org/NS/%s/' %domain , verify=False)
		for row in json.loads(ns.text):

			ns_row = row['value']
			a = requests.get('https://dns-api.org/A/%s/' %ns_row , verify=False)

			for ip in json.loads(a.text):
				targetIP = ip['value']
				dns_ips.append(targetIP)
				print "%s[!] DNS NS: %s has IP:%s %s" %(NOTICE,ns_row,targetIP,ENDC)
	except:
		print FAIL +"[!] Failed to collect DNS information for :" +domain  +ENDC






print """%s
[!] Target Domain : %s
[!] Target Method : %s
[!] Target Port   : %s
[!] Target Subnet : %s
[!] Target Timout : %s 
[!] Total Threads : %s
[!] Total IPs     : %s      
[!] Debug Status  : %s                                                         
%s"""  %(OKBLUE,domain,method,port,subnet,timeout,threads,len(ips),debug,ENDC)


check_dns = raw_input("%s[!] do you want to collect MX/NS records and scan it subnet ? y/n %s" %(OKGREEN,ENDC))

if check_dns.lower() == 'y' or check_dns.lower() == 'yes':

	DNSIP(domain)
	for ip in dns_ips:
		subnet  = str(ip) + str("/24")
		approve_subnet = raw_input("%s[!] do you approve to use this subnet: %s  %s ? y/n "%(WARNING,subnet,ENDC))
	
		if approve_subnet.lower() == 'y' or approve_subnet == 'yes':
			collectips(ipaddr.IPv4Network(subnet))

	print "%s[!] Total IPs : %s%s" %(OKBLUE,len(ips),ENDC)


print "%s[+] Voster Started at %s%s" %(NOTICE,datetime.now(),ENDC)

captured = []
q = Queue(maxsize=0)
lock = Lock()




def Result(status_code,ip,version,redirect=None,redirect_match=False,title=None,found=False,fingerprint=None,length=0,hit=None):

	# Debug

	# print "From debug"
	# print "status_code:%s" %status_code
	# print "ip:%s" %ip
	# print "version:%s" %version
	# print "redirect:%s" %redirect
	# print "title:%s" %title
	# print "found:%s" %found
	# print "redirect_match:%s" %redirect_match
	# print "fingerprint:%s" %fingerprint

	lock.acquire()
	sys.stdout.write("\r")
	sys.stdout.flush()


	if (found or redirect_match) and status_code < 400:

		if status_code >= 200 and status_code < 300:
			msg =  "[+] %s Ok: %s - Banner: %s - Fingerprint: %s - title: %s - Length: %s" %(status_code,ip,version,fingerprint,title,length)
		elif status_code >= 300 and status_code < 400:
			if hit:
				msg = "[+] %s RD: %s - Banner: %s - Redirect %s -  Length: %s - X-Cache: %s " %(status_code,ip,version,redirect,length,hit)
			else:
				msg = "[+] %s RD: %s - Banner: %s - Redirect %s - Length: %s" %(status_code,ip,version,redirect,length)
		print OKGREEN + msg + ENDC

	else:
		if status_code >= 200 and status_code < 300:
			print "[-] %s Ok: %s - Banner: %s - Title: %s - Length: %s" %(status_code,ip,version,title,length)
		elif status_code >= 300 and status_code < 400:
			print "[-] %s RD: %s - Banner: %s - Length: %s" %(status_code,ip,version,length)
		elif status_code >= 400 and status_code < 500:
			print "[-] %s NF: %s - Banner: %s - Length: %s" %(status_code,ip,version,length)
		elif status_code >= 500 and status_code < 600:
			print "[-] %s ER: %s - Banner: %s - Length: %s" %(status_code,ip,version,length)
		else:
			print "[!] %s XX: %s - Banner: %s - Length: %s" %(status_code,ip,version,length)

	lock.release()
	return True
	
def Operator(ip,port):


	art = ['/','\\','-']
	sys.stdout.write("\r%s[+] Vosting Target.. %s %s %s" %(OKGREEN, ip, random.choice(art),ENDC))
	sys.stdout.flush()

	try:

		r = requests.get('%s://%s:%s/' %(method,ip,port),
			headers={
				'host': domain,
				'User-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36'
				}, 
			timeout=timeout, 
			verify=False, 
			allow_redirects = False,
			# proxies=dict(http='http://127.0.0.1:8080')

			)
	#validate request
	except requests.exceptions.ConnectionError:
		return Fale

	except requests.exceptions.TooManyRedirects:
		return False

	except requests.exceptions.ReadTimeout:		
		return False




	#valid request start parsing 
	else:

		# get server banner
		try:
			version = r.headers['Server']
		except:
			version = None
		# get web title
		if len(r.text)>10:
			soup = BeautifulSoup(r.text, 'html.parser')

			try:
				title = soup.find('title').text.encode('utf-8').strip()
			except:
				title = None
		else:
			title = None

		status_code = r.status_code
		length = len(r.text)

		#check fingerprint in the response 
		if fingerprint in r.text:
			found = True
			match = fingerprint

		else:
			found = False
			match = ''

		try:
			redirect = r.headers['Location']
			if domain in redirect:
				redirect_match = True
			else:
				redirect_match = False
		except:
			redirect = None
			redirect_match = False

		try: 
			hit = r.headers['X-Cache']
		except:
			hit = None

		Result(status_code,ip,version,redirect=redirect,redirect_match=redirect_match,title=title,found=found,fingerprint=match,hit=hit,length=length)

	finally:
		pass
		return
	return

def FireThreads(q):
	while True:
		item = q.get()
		Operator(item,port)
		q.task_done()


if len(ips) == 0:
	print FAIL + "[!] Really!!, i have no IPs to scan, going to die "+ ENDC
	sys.exit(0)
for ip in ips:
	q.put(ip)



for i in range(threads):
	worker = Thread(target=FireThreads, args=(q,))
	worker.setDaemon(True)
	worker.start()

q.join()
print ""
print "%s[+] Voster Finished at %s%s" %(NOTICE,datetime.now(),ENDC)
