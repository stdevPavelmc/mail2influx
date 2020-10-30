#!/usr/bin/env python3

# PYLINT instructions
# pylint: disable=W0311,C0301,C0103,W0706,W0702,W0603,R1705,C0114

import os
import time
import subprocess
import select
import re
import json
import sys

try:
	from influxdb import InfluxDBClient
except:
	print(r"You need to install the influxdb python3 module")
	sys.exit()

### user configurable settings:
influxhost = "influx.mydomain.imposible"
influxdb = 'mail'
logfile="/var/log/mail.log"
### End onf the user configrations

# triggers
DEBUG=False
DEVELOP=False

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
match_ip = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# simple vars
post_start = 0
post_reload = 0

# select to hold the data from the log
p = select.poll()

# declare the measurements array
measurements = []

def init_influx(ihost, db):
	'''Connect to the influx server'''

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

def get_email(data):
	'''Match an email in the string, return the first match'''

	res = re.findall(r"[\w\-\.\+\%=]{1,63}\@[\w\-\.]{1,63}\.[a-z]{2,63}", data)
	if len(res) > 0:
		if len(res[0]) > 0:
			return res[0]

	return ""

def get_user(match):
	'''User matchs like [...] user=<robertoa> [...], returns only the username'''

	ruser = str(re.findall(r" user=<[a-zA-Z]+>, ", match))
	if len(ruser) > 0:
		user = re.findall(r"<.*>", ruser)
		if len(user) > 0:
			return user[0].translate({ord(i): None for i in '<>'})

	return ''

def get_ip(match):
	'''match the IP on the match string'''

	rip = re.findall(match_ip, match)
	if len(rip) > 0:
		return rip[0]
	else:
		return ""

def get_remote_ip(match):
	'''Remote ip matchs like [...] rip=192.168.7.158 [...], returns only the IP'''

	fil = re.findall(r" rip=[0-9\.]+, ", match)
	return get_ip(fil[0])

def get_local_ip(match):
	'''Local ip matchs like [...] lip=192.168.7.158 [...], returns only the IP'''

	fil = re.findall(r" lip=[0-9\.]+, ", match)
	return get_ip(fil[0])

def get_postfix_reloads(data):
	'''How many postfix reloads'''

	preloads=re.findall(
		"postfix/master.* reload -- version ", data)
	return len(preloads)

def get_postfix_start(data):
	'''How many postfix starts'''

	pstarts=re.findall(
		u"postfix/master.* daemon started -- version", data)
	return len(pstarts)

def filter_postfix(data):
	'''Make all postfix related filterings '''

	global post_reload
	global post_start

	# postfix starts
	ps = get_postfix_start(data)
	if ps:
		post_start += 1

	# postfix reloads
	ps = get_postfix_reloads(data)
	if ps:
		post_reload += 1

	filter_by_tag = [
		[r'postfix_queued',
			r"^.* postfix/qmgr\[.* from=.*, size=.*, nrcpt=.*$"],
		[r'postfix_relayed',
			r"^.* postfix/.* to=.*, relay=.*, delay=.*, dsn=.*, status=sent .* queued as .*$"],
		[r'postfix_delivered',
			r"^.* postfix/.* to=.*, relay=.*, delay=.*, dsn=.*, status=sent .*delivered via .* service.*$"],
		[r'postfix_sasl_auth',
			r"^.* postfix/.* sasl_method=.* sasl_username=.*$"],
		[r'postfix_temp_fail',
			r"^.* postfix/.* temporary failure.*$"],
		[r'postfix_connection',
			r"^.* postfix.*: connect from .*$"],
		[r'postfix_tls_connect',
			r"^.* postfix.*: Anonymous TLS connection established from .*$"],
		[r'postfix_nq_access_denied_client',
			r"^.* postfix.*: NOQUEUE: reject: .* Access denied.*$"],
		[r'postfix_nq_mailbox_full',
			r"^.* postfix.*: NOQUEUE: reject: .* Buzon de correo lleno / Mailbox is full.*$"],
		[r'postfix_nq_internal_error',
			r"^.* postfix.*: NOQUEUE: reject: .* Internal error occurred.*$"],
		[r'postfix_nq_invalid_user_settings',
			r"^.* postfix.*: NOQUEUE: reject: .* Invalid user settings.*$"],
		[r'postfix_nq_server_config_error',
			r"^.* postfix.*: NOQUEUE: reject: .* Server configuration error.*$"],
		[r'postfix_nq_user_unknown',
			r"^.* postfix.*: NOQUEUE: reject: .* User unknown in virtual mailbox table.*$"],
        [r'postfix_nq_DNSBL',
            r"^.* postfix.*: NOQUEUE: reject: .* Service unavailable; client .* blocked using .*$"],
		[r'postfix_tls_error',
			r"^.* postfix.*: .* TLS library problem: .*$"],
		[r'postfix_ssl_error',
			r"^.* postfix.*: .* SSL_accept error from.*$"],
		[r'postfix_deferred_noroute',
			r"^.* postfix.*: .* status=deferred .* No route to host.*$"],
		[r'postfix_deferred_service_not_available',
			r"^.* postfix.*: .* status=deferred .*Recipient address rejected.* Service is unavailable .*$"],
		[r'postfix_deferred_unverified_recipient',
			r"^.* postfix.*: .* status=deferred .*Recipient address rejected.* unverified address: .*$"],
		[r'postfix_deferred_over_quota',
			r"^.* postfix.*: .* status=deferred .*would exceed mailbox quota.*$"],
		[r'postfix_deferred_over_quota',
			r"^.* postfix.*: .* status=deferred .*Quota exceeded.*$"],
		[r'postfix_deferred_domain_not_found',
			"^.* postfix.*: .* status=deferred .*Host or domain name not found.*$"],
		[r'postfix_deferred_server_say_domain_not_found',
			"^.* postfix.*: .* status=deferred .*Recipient address rejected: Domain not found.*$"],
		[r'postfix_deferred_connection_timeout',
			"^.* postfix.*: .* status=deferred .*Connection timed out.*$"],
		[r'postfix_deferred_timeout_exceeded',
			"^.* postfix.*: .* status=deferred .*Error: timeout exceeded.*$"],
		[r'postfix_deferred_interrupted_while_talking',
			"^.* postfix.*: .* status=deferred .* with .* while .*$"],
		[r'postfix_deferred_connection_refused',
			"^.* postfix.*: .* status=deferred .*Connection refused.*$"],
		[r'postfix_deferred_greylisting',
			"^.* postfix.*: .* status=deferred .*Greylist.*$"],
		[r'postfix_deferred_too_many_recipients',
			"^.* postfix.*: .* status=deferred .*Too many recipients received from the sender.*$"],
		[r'postfix_deferred_server_error',
			"^.* postfix.*: .* status=deferred .*Client host rejected.* Server configuration error.*$"],
		[r'postfix_deferred_TLS_error',
			"^.* postfix.*: .* status=deferred .*Cannot start TLS.*$"],
		[r'postfix_deferred_no_route_to_host',
			"^.* postfix.*: .* status=deferred .*No route to host.*$"],
		[r'postfix_deferred_reject_hostname',
			"^.* postfix.*: .* status=deferred .*Client host rejected: cannot find your hostname.*$"],
		[r'postfix_deferred_temporary_error',
			"^.* postfix.*: .* status=deferred .* Temporary .*$"],
		[r'postfix_deferred_server_unreacheable',
			"^.* postfix.*: .* status=deferred .* Network is unreachable.*$"],
		[r'postfix_deferred_relay_denied',
			"^.* postfix.*: .* status=deferred .*Relay access denied.*$"],
		[r'pmg_virus',
			"^.* pmg-smtp-filter.* virus detected.*clamav.*$"],
	]

	#### pure data messages
	for mea, regex in filter_by_tag:
		if postfix_filtering(data, mea, regex):
			break

	# timeouts
	postfix_timeouts(data)

def extract_vp_data(data):
	'''Extract data as data=value pais from any line and return it as array
	any <> will been trimed away'''

	sd = data.split(r" ")
	ret = {}

	for d in sd:
		if not "=" in d:
			continue

		# remove garbage
		cp = d.translate({ord(i): None for i in '<>,\n'})
		data = cp.split(r"=")

		# =  in one value, like mails
		if len(data) > 2:
			ndata = [data[0], '='.join(data[1:])]
			data = ndata

		# unknowns and ips, turn into ip
		if 'unknown[r' in data[1]:
			a = data[1]
			data[1] = str(get_ip(a))

		ret[data[0]] = data[1]

	if len(ret) > 0:
		return ret
	else:
		return {}

def postfix_filtering(data, mea, regex):
	'''Parse postfix multiple line with some other non obvious tags'''

	result = re.findall(regex, data)
	if len(result) > 0:
		# declare the tags
		tags = {}

		# Take the IP
		data = result[0]

		# get the IP
		if not "rip=" in data:
			ip = get_ip(data)
			if len(ip) > 0:
				tags[r'rip'] = ip

		# get the method
		m = re.findall(r"/[a-z]+/", data)
		if len(m) > 0:
			method = m[0].translate({ord(i): None for i in '/'})
			tags[r'method'] = method

		# get the cypher from the data
		cph = re.findall(r"[\w\.]+ with cipher .*$", data)
		if len(cph) > 0:
			tags[r'cipher'] = cph[0].replace(r"with cipher", '/')

		# get the IP of the bocked by DNSBL and the DNSBL name
		if mea == "postfix_nq_DNSBL":
			# remote ip
			tags[r'rip'] = get_ip(data)

			# name od the dnsbl
			dnsbl = re.findall(r"blocked using .*;", data)
			tags[r'dnsbl'] = dnsbl[0].split(r" ")[2].split(';')[0]

		if mea == "pmg_virus":
			# get the virus name
			tags[r"virus"] = data.split(r" ")[-2]

		extracted = extract_vp_data(data)
		if  len(extracted) > 0:
			mea_add([mea, {**tags, **extracted}])
		else:
			mea_add([mea, tags])

		return True

	# return false as there is no match
	return False

def postfix_timeouts(data):
	'''Parse the timeout messages by postfix'''

	# timeout messages {AUTH, CONNECT, DATA, END-OF-MESSAGE, STARTTLS}

	mea = "postfix_timeout"
	tags = {}

	result = re.findall(r"^.* postfix/.* timeout after .*$", data)

	if len(result) > 0:
		reason = result[0].split(r" ")
		tags[r'reason'] = reason[5]
		mea_add([mea, tags])

def filter_dovecot(data):
	'''Match and add to data all postfix messages'''

	meamatchs = [
		[r'dovecot_login_ok', 					r'^.* dovecot: .*-login: Login: user=<.*>.*$'],
		[r'dovecot_auth_failed', 				r'^.* dovecot: .*-login:.* Disconnected \(auth failed, \d attempts in \d secs\).*$'],
		[r'dovecot_drop_no_auth', 				r'^.* dovecot: .*-login:.* Disconnected \(no auth attempts in \d secs\).*$'],
		[r'dovecot_drop_idle', 					r'^.* dovecot: .*-login:.* Disconnected: Inactivity \(no auth attempts in \d secs\).*$'],
		[r'dovecot_client_broke_auth', 			r'^.* dovecot: .*-login:.* Disconnected: Auth process broken.*$'],
		[r'dovecot_auth_process_not_responding', '^.* dovecot: .*-login:.* Warning: Auth process not responding.*$'],
		[r'dovecot_error_auth_server', 			r'^.* dovecot: .*-login:.* Error: Timeout waiting for handshake from auth server.*$'],
		[r'dovecot_ldap_unreachable', 			r'^.* dovecot: .* LDAP: Can\'t connect to server:.*$'],
		[r'dovecot_quota_error', 				r'^.* dovecot: .* User initialization failed: Failed to initialize quota.*$'],
		[r'dovecot_delivered',					r' lda\([^\s]+\:'],
		[r'dovecot_start', 						r' dovecot: master: Dovecot .* starting up for '],
		[r'dovecot_reload', 						r' dovecot: master: Warning: SIGHUP received'],
	]

	# process
	for (mea, regex) in meamatchs:
		dove_multiple(data, mea, regex)

def dove_multiple(data, mea, regex):
	'''filter the line using regex and add it to the mea measurement'''

	# create the tags in front
	tags = {}

	# check if match the regex
	match = re.findall(regex, data)

	if len(match) > 0:
		# get clean data
		data = match[0]

		# get imap or pop
		if "pop3-login" in data:
			tags[r'via'] = 'pop3'
		if "imap-login" in data:
			tags[r'via'] = 'imap'

		# delivereds
		if " lda(r" in data:
			tags[r'to'] = get_email(data)

		extracted = extract_vp_data(data)
		if len(extracted) > 0:
			mea_add([mea, {**tags, **extracted}])
		else:
			mea_add([mea, tags])

def parseline(data):
	'''Parse the lines to postfix/dovecot filtering'''

	# postfix filters
	filter_postfix(data)

	# dovecot logins as measurements
	filter_dovecot(data)

def follow(file_path):
	'''Yield each line from a file as it's was pushed here'''

	exist = False
	while not exist:
		exist = os.path.exists(file_path)
	readable = False
	while not readable:
		readable = os.access(file_path, os.R_OK)

	# develop or production
	fo = ''
	if DEVELOP:
		fo = subprocess.Popen([r'cat', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	else:
		fo = subprocess.Popen([r'tail','-F',file_path], stdout=subprocess.PIPE,stderr=subprocess.PIPE)

	p.register(fo.stdout)

	return fo.stdout

def mea_add(measurement):
	'''Parse collected data to final measurement'''
	mea, tags = measurement

	# creat the info
	nmea = {}
	# craft fields
	fields = {}

	# convert tags to fields
	tag2field = [r'size', 'delay', 'rip', 'lip', 'session', 'user', 'sasl_username', 'from', 'to', 'helo',
              'conn_use', 'delay', 'delays', 'dsn', 'orig_to', 'relay', 'status', 'nrcpt', 'client']
	for tag in tag2field:
		try:
			fields[tag] = tags[tag]
			del tags[tag]
		except:
			pass

	# usefull tags list
	# method, via, sasl_method, reason (timeout reason), cipher

	# non usefull tags to be removed
	removethistags = [r'mpid']
	for tag in removethistags:
		try:
			del tags[tag]
		except:
			pass

	# adding the default value if needed
	fields[r'value'] = 1

	nmea[r'measurement'] = mea
	nmea[r'fields'] = fields
	if len(tags) > 0:
		nmea[r'tags'] = tags

	measurements.append(nmea)

def check_statics(start, reload):
	'''Add the stats as measurements if active'''
	if start:
		mea_add([r'postfix_start', ''])
	if reload:
		mea_add([r'postfix_reload', ''])

def reset_statics():
	'''Reset statistics'''
	global post_start
	global post_reload
	post_start = 0
	post_reload = 0

def send_data(inf, meas):
	'''Push data to influx'''

	# develop
	if DEVELOP and DEBUG:
		print(json.dumps(meas))

	inf.write_points(meas)


if __name__ == '__main__':
	f = follow(logfile)

	# setup the influx client
	influx = init_influx(influxhost, influxdb)
	while not influx:
		print(r"Influxdb server connection error, will try in 3 seconds")
		time.sleep(3)
		influx = init_influx(influxhost, influxdb)

	print(r"InfluxDB reached and connected!")

	while True:
		# tail parse
		if p.poll(1):
			line = str(f.readline().decode('utf-8'))
			if len(line) > 0:
				parseline(line)

			if DEVELOP:
				time.sleep(0.05)

		if not DEVELOP:
			time.sleep(1)

		# add static values
		check_statics(post_start, post_reload)

		# time to send measurements if
		if len(measurements) > 0:
			send_data(influx, measurements)
			measurements = []
			reset_statics()
