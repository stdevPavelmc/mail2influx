#!/usr/bin/env python3

import os
import time
import subprocess
import select
import re
import json
from pprint import pprint

try:
	from influxdb import InfluxDBClient
except:
	print("You need to install the influxdb python3 module")
	exit(1)

### user configurable settings:
influxhost = "influx.mydomain.imposible"
influxdb = 'mail'
logfile="/var/log/mail.log"
### End onf the user configrations

# triggers
DEBUG=True
DEVELOP=True

### Just for dev purpose
dev_host="10.0.3.9"
dev_db="mail"
dev_log="./mail.log"

# prod or dev
if DEVELOP:
	influxhost = dev_host
	influxdb = dev_db
	logfile = dev_log

# some constants
match_ip = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# simple vars
post_start = 0
post_reload = 0

# select to hold the data from the log
p = select.poll()

# declare the measurements array
measurements = []

def init_influx(ihost, db):
	try:
		client = InfluxDBClient(host=ihost, port=8086)

		# check if the db exist and creat if not
		dbs = client.get_list_database()
		if not db in dbs:
			client.create_database(db)
		
		# switch to that database
		client.switch_database(db)

		return client
	except:
		#return False
		raise

def get_email(line):
	# match an email in the string, return the first match

	res = re.findall("[\w\-\.\+\%=]{1,63}\@[\w\-\.]{1,63}\.[a-z]{2,63}", line)
	if len(res):
		if len(res[0]):
			return res[0] 

	return ""

def get_user(match):
	# [...] user=<robertoa> [...]
	ruser = str(re.findall(" user=<[a-zA-Z]+>, ", match))

	if len(ruser):
		user = re.findall("<.*>", ruser)
		if len(user):
			return user[0].translate({ord(i): None for i in '<>'})
	
	return ''

def get_ip(match):
	# match the IP on the match string
	rip = re.findall(match_ip, match)
	if len(rip):
		return rip[0]
	else:
		return ""

def get_remote_ip(match):
	# [...] rip=192.168.7.158 [...]

	filter = re.findall(" rip=[0-9\.]+, ", match)
	return get_ip(filter[0])

def get_local_ip(match):
	# [...] lip=192.168.7.158 [...]

	filter = re.findall(" lip=[0-9\.]+, ", match)
	return get_ip(filter[0])

def get_postfix_reloads(line):
	# how many postfix reloads 
	preloads=re.findall(
		"postfix/master.* reload -- version ", line)
	return len(preloads)

def get_postfix_start(line):
	# how many postfix starts
	pstarts=re.findall(
		u"postfix/master.* daemon started -- version", line)
	return len(pstarts)

def filter_postfix(line):
	# make all postfix related filterings

	global post_reload
	global post_start

	# postfix starts
	ps = get_postfix_start(line)
	if ps:
		post_start += 1

	# postfix reloads
	ps = get_postfix_reloads(line)
	if ps:
		post_reload += 1

	filter_by_tag = [
		['postfix_queued',    					"^.* postfix/qmgr\[.* from=.*, size=.*, nrcpt=.*$"],
		['postfix_relayed',   					"^.* postfix/.* to=.*, relay=.*, delay=.*, dsn=.*, status=sent .* queued as .*$"],
		['postfix_delivered', 					"^.* postfix/.* to=.*, relay=.*, delay=.*, dsn=.*, status=sent (delivered via .* service)$"],
		['postfix_sasl_auth', 					"^.* postfix/.* sasl_method=.* sasl_username=.*$"],
		['postfix_temp_fail', 					"^.* postfix/.* (temporary failure).*$"],
		['postfix_connection', 					"^.* postfix.*: connect from .*$"],
		['postfix_tls_connect',					"^.* postfix.*: Anonymous TLS connection established from .*$"],
		['postfix_nq_access_denied_client',		"^.* postfix.*: NOQUEUE: reject: .* Access denied.*$"],
		['postfix_nq_mailbox_full',				"^.* postfix.*: NOQUEUE: reject: .* Buzon de correo lleno / Mailbox is full.*$"],
		['postfix_nq_internal_error',			"^.* postfix.*: NOQUEUE: reject: .* Internal error occurred.*$"],
		['postfix_nq_invalid_user_settings',	"^.* postfix.*: NOQUEUE: reject: .* Invalid user settings.*$"],
		['postfix_nq_server_config_error',		"^.* postfix.*: NOQUEUE: reject: .* Server configuration error.*$"],
		['postfix_nq_user_unknown',				"^.* postfix.*: NOQUEUE: reject: .* User unknown in virtual mailbox table.*$"],
		['postfix_tls_error',					"^.* postfix.*: .* TLS library problem: .*$"],
		['postfix_ssl_error',					"^.* postfix.*: .* SSL_accept error from.*$"],
		['postfix_deferred_noroute', 			"^.* postfix.*: .* status=deferred .* No route to host)$"],
		['postfix_deferred_service_not_available',	"^.* postfix.*: .* status=deferred .*Recipient address rejected.* Service is unavailable .*$"],
		['postfix_deferred_unverified_recipient',	"^.* postfix.*: .* status=deferred .*Recipient address rejected.* unverified address: .*$"],
		['postfix_deferred_over_quota',				"^.* postfix.*: .* status=deferred .*would exceed mailbox quota.*$"],
		['postfix_deferred_domain_not_found',		"^.* postfix.*: .* status=deferred .*Host or domain name not found.*$"],
		['postfix_deferred_timeout',				"^.* postfix.*: .* status=deferred .*Connection timed out.*$"],
		['postfix_deferred_connection_refused',		"^.* postfix.*: .* status=deferred .*Connection refused.*$"],
		['postfix_deferred_greylisting',			"^.* postfix.*: .* status=deferred .*Greylisting enabled.*$"],
		['postfix_deferred_too_many_recipients',	"^.* postfix.*: .* status=deferred .*Too many recipients received from the sender.*$"],
		['postfix_deferred_server_error',			"^.* postfix.*: .* status=deferred .*Client host rejected: Server configuration error.*$"],
		


	]

	#### pure data messages
	for mea, regex in filter_by_tag:
		postfix_filtering(line, mea, regex)

	# timeouts
	postfix_timeouts(line)

def extract_vp_data(line):
	# extract the infos in the format " data=value," and put them in a []
	# full string, delimited by spaces, with comments
	# datas are var=value, if not =, skip
	# trim any "<>" or , in there

	sd = line.split(" ")
	ret = {}

	label = ""
	value = ""

	for p in sd:
		if not "=" in p:
			continue

		# remove garbage
		cp = p.translate({ord(i): None for i in '<>,\n'})
		data = cp.split("=")
		label = data[0]

		# =  in one value, like mails 
		if len(data) > 2:
			ndata = [data[0], '='.join(data[1:])]
			data = ndata

		# unknowns and ips, turn into ip
		if 'unknown[' in data[1]:
			a = data[1]
			data[1] = str(get_ip(a))

		ret[data[0]] = data[1]

	if len(ret):
		return ret
	else:
		return {}

def postfix_filtering(line, mea, regex):
	# multiple with some other non obvious tags

	result = re.findall(regex, line)
	if len(result):
		# declare the tags
		tags = {}

		# Take the IP
		data = result[0]

		# get the IP
		if not "rip=" in data:
			ip = get_ip(data)
			if len(ip):
				tags['rip'] = ip

		# get the method
		m = re.findall("/[a-z]+/", line)
		if len(m):
			method = m[0].translate({ord(i): None for i in '/'})
			tags['method'] = method

		# get the cypher from the data
		cph = re.findall("[\w\.]+ with cipher .*$", line)
		if len(cph):
			tags['cipher'] = cph[0].replace("with cipher", '/')

		extracted = extract_vp_data(data)
		if  len(extracted):
			mea_add([mea, {**tags, **extracted}])
		else:
			mea_add([mea, tags])

def postfix_timeouts(line):
	# timeout messages {AUTH, CONNECT, DATA, END-OF-MESSAGE, STARTTLS}

	mea = "postfix_timeout"
	tags = {}

	result = re.findall("^.* postfix/.* timeout after .*$", line)

	if len(result):
		reason = result[0].split(" ")
		tags['reason'] = reason[5]
		mea_add([mea, tags])

def filter_dovecot(line):
	# will match all dovecot login events

	meamatchs = [
		['dovecot_login_ok', 					'^.* dovecot: .*-login: Login: user=<.*>.*$'],
		['dovecot_auth_failed', 				'^.* dovecot: .*-login:.* Disconnected \(auth failed, \d attempts in \d secs\).*$'],
		['dovecot_drop_no_auth', 				'^.* dovecot: .*-login:.* Disconnected \(no auth attempts in \d secs\).*$'],
		['dovecot_drop_idle', 					'^.* dovecot: .*-login:.* Disconnected: Inactivity \(no auth attempts in \d secs\).*$'],
		['dovecot_client_broke_auth', 			'^.* dovecot: .*-login:.* Disconnected: Auth process broken.*$'],
		['dovecot_auth_process_not_responding', '^.* dovecot: .*-login:.* Warning: Auth process not responding.*$'],
		['dovecot_error_auth_server', 			'^.* dovecot: .*-login:.* Error: Timeout waiting for handshake from auth server.*$'],
		['dovecot_ldap_unreachable', 			'^.* dovecot: .* LDAP: Can\'t connect to server:.*$'],
		['dovecot_quota_error', 				'^.* dovecot: .* User initialization failed: Failed to initialize quota.*$'],
		['dovecot_delivered',					' lda\([^\s]+\:'],
		['dovecot_start', 						' dovecot: master: Dovecot .* starting up for '],
		['dovecot_reload', 						' dovecot: master: Warning: SIGHUP received'],
	]
	
	# process
	for (mea, regex) in meamatchs:
		dove_multiple(line, mea, regex)

def dove_multiple(line, mea, regex):
	'''filter the line using regex and add it to the mea measurement'''

	# create the tags in front
	tags = {}

	# check if match the regex
	match = re.findall(regex, line)

	if len(match):
		# get clean data
		data = match[0]

		# get imap or pop
		if "pop3-login" in data:
			tags['via'] = 'pop3'
		if "imap-login" in data:
			tags['via'] = 'imap'

		# delivereds
		if " lda(" in data:
			tags['to'] = get_email(data)

		extracted = extract_vp_data(data)
		if  len(extracted):
			mea_add([mea, {**tags, **extracted}])
		else:
			mea_add([mea, tags])

def parseline(line):
	# parte the lines and generate measurements

	# postfix filters
	filter_postfix(line)

	# dovecot logins as measurements
	filter_dovecot(line)

def follow(file_path):
	""" Yield each line from a file as they are written. """
	line = ''

	exist = False
	while not exist:
		exist = os.path.exists(file_path)
	readable = False
	while not readable:
		readable = os.access(file_path, os.R_OK)

	# develop or production
	if DEVELOP:
		f = subprocess.Popen(['cat', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	else:
		f = subprocess.Popen(['tail','-F',file_path], stdout=subprocess.PIPE,stderr=subprocess.PIPE)

	p.register(f.stdout)
	
	return f.stdout

def mea_add(measurement, value = 1):
	mea, tags = measurement

	# creat the info
	nmea = {}
	# craft fields
	fields = {}
	# if a size in tag, convert it to field
	try:
		fields['size'] = tags['size']
		del tags['size']
	except: 
		pass
	# if a delay in tag, convert it to field
	try:
		fields['delay'] = tags['delay']
		del tags['delay']
	except: 
		pass
	# adding the default value if needed
	if len(fields) == 0:
		fields['value'] = value
	
	nmea['measurement'] = mea
	nmea['fields'] = fields
	if len(tags):
		nmea['tags'] = tags

	measurements.append(nmea)

def check_statics(post_start, post_reload):
	if post_start:
		mea_add(['postfix_start', ''], post_start)
	if post_reload:
		mea_add(['postfix_reload', ''], post_reload)

def reset_statics():
	global post_start
	global post_reload
	post_start = 0
	post_reload = 0

def send_data(inf, meas):
	# push data to influx

	# develop
	if DEVELOP and DEBUG:
		print(json.dumps(meas))

	inf.write_points(meas)


if __name__ == '__main__':
	f = follow(logfile)

	# setup the influx client
	influx = init_influx(influxhost, influxdb)
	while not influx:
		print("Influxdb server connection error, will try in 3 seconds")
		time.sleep(3)
		influx = init_influx(influxhost, influxdb)

	print("InfluxDB reached and connected!")

	while True:
		# tail parse
		if p.poll(1):
			line = str(f.readline().decode('utf-8'))
			if len(line):
				parseline(line)

			if DEVELOP:
				time.sleep(0.05)
		
		if not DEVELOP:
			time.sleep(1)

		# add static values
		check_statics(post_start, post_reload)

		# time to send measurements if 
		if len(measurements):
			send_data(influx, measurements)
			measurements = []
			reset_statics()
