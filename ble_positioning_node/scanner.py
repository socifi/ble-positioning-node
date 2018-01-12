#!/usr/bin/python

####################################################################
# A little work of fine art - Countess looking into her empty room #
####################################################################

import os
import sys
import time
import json
import math
import copy
import boto3
import ntplib
import psutil
import struct
import signal
import socket
import logging
import requests
import schedule
import threading
import subprocess
import collections
import ConfigParser
import pprint as pp
import bluetooth._bluetooth as bluez
from logstash_async.handler import AsynchronousLogstashHandler
from ble_positioning_node.logstash_formatter import ErrorFormatter

###################
# End of fine art #
###################

LE_META_EVENT = 0x3e
OGF_LE_CTL = 0x08
OCF_LE_SET_SCAN_ENABLE = 0x000C
EVT_LE_CONN_COMPLETE = 0x01
EVT_LE_ADVERTISING_REPORT = 0x02

class Scanner:
	def __init__(self):
		logging.addLevelName(25, "NOTICE")
		logging.addLevelName(55, "ALERT")
		# Parse config #
		config = ConfigParser.RawConfigParser()
		config.file = '/etc/ble_positioning_node/config.conf'
		config.read(config.file)

		# setup logging to logstash
		log_level = logging.INFO

		host = config.get('Communication', 'log_proxy')
		port = config.getint('Communication', 'log_proxy_port')

		self.log = logging.getLogger('ble-node-log')
		self.log.setLevel(log_level)
		handler = AsynchronousLogstashHandler(host, port, database_path='logstash.db')
		handler.setFormatter(ErrorFormatter())
		self.log.addHandler(handler)

		self.beacon_statistics = dict()
		self.beacon_list = dict()
		self.beacon_list_age = time.time()

		self.file_config = config

		FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

		logging.basicConfig(format=FORMAT,level=log_level)
		self.state_update("beacon-unknown")

	###############################################################
	# Self register node with it's mac and user defined variables #
	###############################################################

	def node_register(self):
		if(self.file_config.has_option('Communication', 'registered')):
			return

		def form_add(payload, name, value):
			return payload + '------WebKitFormBoundary7MA4YWxkTrZu0gW\nContent-Disposition: form-data; name="%s"\n\n%s\n' % (name, value)
		def form_finalize(payload):
			return payload + '------WebKitFormBoundary7MA4YWxkTrZu0gW--\n'

		url = self.file_config.get('Communication', 'registration')

		payload = ""
		payload = form_add(payload, 'userId', self.file_config.get('User', 'user_id'))
		payload = form_add(payload, 'brandId', self.file_config.get('User', 'brand_id'))
		payload = form_add(payload, 'mac', self.mac)
		if(self.file_config.has_option('User', 'group_id')):
			payload = form_add(payload, 'groupId', self.file_config.get('User', 'group_id'))
		if(self.file_config.has_option('User', 'group_id')):
			payload = form_add(payload, 'name', self.file_config.get('User', 'name'))
		payload = form_finalize(payload)

		headers = {
			'content-type': "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
			'Authorization': "Bearer "+self.file_config.get('User', 'user_key'),
			'Cache-Control': "no-cache"
		}

		response = requests.request("POST", url, data=payload, headers=headers)

		print response
		print s
		s = json.loads(response.text)
		defined = False
		if('errors' in s and s['errors']['code'] == 'mac-already-registered'):
			defined = True
		if(response.status_code == requests.codes.ok or defined == True):
			self.file_config.set('Communication', 'registered', 'true')
			self.file_config.write(open(self.file_config.file, 'wb'))


	##################################
	# Load configuration from server #
	##################################

	def config_get(self):
		r = requests.get(self.file_config.get('Communication', 'configuration')+"?mac="+self.mac)
		if r.status_code != 200:
			timestamp = time.time()
			self.log.critical("Error getting config. Time: %d. Location: %s. Cause of accident: unknown. "
					  "Should someone find this record perhaps it will shed light as to what happened here." %
						(timestamp, self.mac), extra={'timestamp':timestamp, 'mac':self.mac, 'errorinfo': r.text})
			sys.exit(1)

		tmp = json.loads(r.text)
		#FIXME? Old format (should be fixed?)
		self.config = tmp['configuration']
		self.config['white_list'] = tmp['macWhiteList']
		self.config['black_list'] = tmp['macBlackList']
		self.config['node'] = {}
		self.config['node']['mac'] = self.mac
		self.config_update_signal = True

	##############################
	# Initial setup of bluetooth #
	##############################

	def bluetooth_setup(self):
		for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
			signal.signal(sig, self.handler)

		# Reset Bluetooth interface, hci0
		os.system("sudo hciconfig hci0 down")
		os.system("sudo hciconfig hci0 up")

		# Make sure device is up
		interface = subprocess.Popen(["sudo hciconfig"], stdout=subprocess.PIPE, shell=True)
		(output, err) = interface.communicate()

		if "RUNNING" not in output: # Check return of hciconfig to make sure it's up
			timestamp = time.time()
			self.log.critical("Error: hci0 not running. Time: %d. Location: unknown. Cause of accident: unknown. "
					  "Should someone find this record perhaps it will shed light as to what happened here." % timestamp, extra={'timestamp':timestamp})
			sys.exit(1)
		self.log.debug('Bluetooth device running')
		print("Bluetooth on")

	def bluetooth_turn_on(self):
		try:
			self.hci_toggle_le_scan(0x01)
		except:
			self.error_report("Device could not toggle scan", 'critical', exception=True)
			exit(1)

	################################
	# Mac and IP address retrieval #
	################################

	def mac_get(self):
		devId = 0
		try:
			self.sock = bluez.hci_open_dev(devId)
			self.log.debug('Connect to bluetooth device %i', devId)
		except:
			timestamp = time.time()
			self.log.critical("Error: not able to connect to bluetooth device. Time: %d. Location: unknown. Cause of accident: unknown. "
					  "Should someone find this record perhaps it will shed light as to what happened here." % timestamp, extra={'timestamp':timestamp}, exc_info=True)
			sys.exit(1)
		self.mac = self.read_local_bdaddr()
		self.log.info('Retrieved mac address %s.' % self.mac)
		print("Retrieved mac address")

	def ip_get(self):
		# try to connect to server, otherwise we could get only 127.0.0.1 which is useless...
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try:
			print self.log.handlers[0]._host, self.log.handlers[0]._port
			s.connect((self.log.handlers[0]._host, self.log.handlers[0]._port))
			self.remote_ip = s.getsockname()[0]
			s.close()
		except:
			self.error_report("Device could not read it's IP",'error', exception=True)

	#######################################################
	# Update state of node (how much do we know about it) #
	#######################################################

	def state_update(self, state):
		self.config_update_signal = True
		self.state = state

	######################################################
	# Low level functions to connect to bluetooth device #
	######################################################

	def print_packet(self, pkt):
		for c in pkt:
			sys.stdout.write("%02x " % struct.unpack("B",c)[0])

	def packed_bdaddr_to_string(self, bdaddr_packed):
		return "".join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

	def hci_disable_le_scan(self):
		self.hci_toggle_le_scan(0x00)

	def hci_toggle_le_scan(self, enable):
		cmd_pkt = struct.pack("<BB", enable, 0x00)
		bluez.hci_send_cmd(self.sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)

	def handler(self, signum = None, frame = None):
		time.sleep(1)  #here check if process is done
		sys.exit(0)

	def le_handle_connection_complete(self, pkt):
		status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
		device_address = self.packed_bdaddr_to_string(pkt[5:11])
		interval, latency, supervision_timeout, master_clock_accuracy = struct.unpack("<HHHB", pkt[11:])

	def read_local_bdaddr(self):
		flt = bluez.hci_filter_new()
		opcode = bluez.cmd_opcode_pack(bluez.OGF_INFO_PARAM, bluez.OCF_READ_BD_ADDR)
		bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
		bluez.hci_filter_set_event(flt, bluez.EVT_CMD_COMPLETE)
		bluez.hci_filter_set_opcode(flt, opcode)
		self.sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )
		bluez.hci_send_cmd(self.sock, bluez.OGF_INFO_PARAM, bluez.OCF_READ_BD_ADDR )
		pkt = self.sock.recv(255)
		status,raw_bdaddr = struct.unpack("xxxxxxB6s", pkt)
		assert status == 0
		t = [ "%02X" % ord(b) for b in raw_bdaddr ]
		t.reverse()
		bdaddr = "".join(t)
		return bdaddr.lower()

	####################
	# Synchronize time #
	####################

	def time_synchronize(self):
		try:
			client = ntplib.NTPClient()
			response = client.request('pool.ntp.org')
			os.system('date ' + time.strftime('%m%d%H%M%Y.%S',time.localtime(response.tx_time)))
		except:
			print('Could not sync with time server.')
			sys.exit(1)
		print("Node registered")

	############################################
	# Get information about node configuration #
	############################################

	def debug_get(self):
		debug = copy.deepcopy(self.config)
		# Do not send aws keys
		debug.pop('aws_secret', None)
		debug.pop('aws_key', None)
		debug.pop('aws_region', None)
		debug.pop('node', None)
		debug['ble_devices'] = copy.deepcopy(self.beacon_statistics)
		return debug

	def context_get(self):
		if(not hasattr(self, 'config')):
			return {}
		if(self.config_update_signal == True or not hasattr(self, 'tmpconfig')):
			self.tmpconfig = copy.deepcopy(self.config)
			self.config_update_signal = False
		context = {}
		context.update(self.tmpconfig['node'])
		if('debug' in self.tmpconfig):
			context['debug'] = self.debug_get()
		# clear statistics here to prevent overflows...
		self.beacon_statistics.clear()
		return context

	##########################################
	# Information and error report to logger #
	##########################################

	def info_report(self, info_string):
		context = self.context_get()
		context['type'] = "beacon-info-report"
		self.log.info(info_string, extra=context)

	def error_report(self, error_string, severity, exception=False):
		error = self.context_get()
		error['type'] = "beacon-error-report"
		if severity == 'error':
			self.log.error(error_string, extra=error, exc_info=exception)
		elif severity == 'warning':
			self.log.warning(error_string, extra=error, exc_info=exception)
		else:
			self.log.critical(error_string, extra=error, exc_info=exception)

	#################
	# Kinesis setup #
	#################

	def kinesis_setup(self):
		try:
			self.kinesis = boto3.client('kinesis',
				aws_access_key_id=self.config['aws_key'],
				aws_secret_access_key=self.config['aws_secret'],
				region_name=self.config['aws_region']
			)
		except:
			self.error_report("Kinesis error",'critical', exception=True)
			sys.exit(1)

	#############################
	# Queue operating functions #
	#############################

	def add_to_list(self, address, rssi):
		if address not in self.beacon_list:
			# FIXME!: Collection does not change on config change!
			self.beacon_list[address] = collections.deque(maxlen=(self.config['meadian_window']))
		else:
			self.beacon_list[address].append(int(rssi))
		if address not in self.beacon_statistics:
			self.beacon_statistics[address] = 1
		else:
			self.beacon_statistics[address] = self.beacon_statistics[address] + 1

	# delete ~ 1/10 of records to prevent problems when beacon gets out of signal
	def dequeue_del(self, beacon):
		for i in range(self.config['meadian_window']/10+1):
			try:
				self.beacon_list[beacon].popleft()
			except IndexError:
				del self.beacon_list[beacon]
				return True
			return False

	def median(self, mylist):
		sorts = sorted(mylist)
		length = len(sorts)
		if length < 1:
			return float('NaN')
		if not length % 2 and length > 1:
			return (sorts[length / 2] + sorts[length / 2 - 1]) / 2.0
		return sorts[length / 2]

	def average(self, mylist):
		length = len(mylist)
		sum = 0
		for i in range(mylist):
			sum += i	
		return sum/length


	###################################
	# Flush collected data to kinesis #
	###################################

	def flush_list(self):
		records = []
		for beacon in self.beacon_list.keys():
			sendtime = time.time()
			rssi = self.median(self.beacon_list[beacon])
			if math.isnan(rssi):
				continue
#			self.log.info('Sending %s with signal strength %.2f calculated from [%s]' % (beacon, rssi, ', '.join(str(x) for x in self.beacon_list[beacon])))
			# get partition according to mac of beacon
			records.append({
				'Data': json.dumps([self.mac, beacon, str(rssi), str(sendtime), "0"]),
				'PartitionKey': beacon
			})
			# dequeue to prevent beacon from being visible when it gets from range
			self.dequeue_del(beacon)
			self.log.debug('json: %s' %(json.dumps([self.mac, beacon, str(rssi), str(sendtime), "0"])))
		if len(records) > 0:
			self.kinesis.put_records(
				Records=records,
				StreamName='beacons-positioning-dev'
			)
			self.log.debug('%d records were sent to the stream.' % (len(records)))
		else:
			self.log.debug('Nothing sent')
			
		return None


	######################################
	# Black list and whitelist filtering #
	######################################

	def filter(self, macAddressSeen, rssi):
		if (macAddressSeen in self.config['black_list']):
			return
		t = time.time()
#		self.file.write('%s %s\n' % (macAddressSeen, t))
		if (len(self.config['white_list']) == 0 or macAddressSeen in self.config['white_list']):
			self.add_to_list(macAddressSeen, rssi)

	def parse_packets(self):
		old_filter = self.sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
		flt = bluez.hci_filter_new()
		bluez.hci_filter_all_events(flt)
		bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
		self.sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )
		pkt = self.sock.recv(255)
		ptype, event, plen = struct.unpack("BBB", pkt[:3])

		if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
			i = 0
		elif event == bluez.EVT_NUM_COMP_PKTS:
			i = 0 
		elif event == bluez.EVT_DISCONN_COMPLETE:
			i = 0 
		elif event == LE_META_EVENT:
			subevent, = struct.unpack("B", pkt[3])
			pkt = pkt[4:]
			if subevent == EVT_LE_CONN_COMPLETE:
				self.le_handle_connection_complete(pkt)
			elif subevent == EVT_LE_ADVERTISING_REPORT:
				num_reports = struct.unpack("B", pkt[0])[0]
				for i in range(0, num_reports):
					macAddressSeen = self.packed_bdaddr_to_string(pkt[3:9])
					
					rssi = ''.join( c for c in str(struct.unpack("b", pkt[-1])) if c in '-0123456789')
					self.filter(macAddressSeen, rssi)


				if (len(self.beacon_list) > 0 and self.beacon_list_age < time.time() - self.config['update_frequency']):
#					self.log.debug('Flushing list to the stream... Age: %d, Size: %i' % (time.time() - self.beacon_list_age, len(self.beacon_list)))
					self.flush_list()
					self.beacon_list_age = time.time()
		self.sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)

	######################
	# Monitor node alive #
	######################

	def alive(self):
		self.info_report("I'm alive!")

	#################
	# Main function #
	#################

	def scan(self):
		try:
			print("Program start")
			self.time_synchronize()
			self.bluetooth_setup()
			self.mac_get()
			self.state_update("beacon-preliminary")	# Now we know at least mac address of device so it is traceable
			self.node_register()			# Needs to be after mac_get
			self.config_get()
			print("Got config")
			self.state_update("beacon-up")		# Now we have all info from server
			self.ip_get()
			self.bluetooth_turn_on()
			print("Starting scanning")
			self.kinesis_setup()

			# init counter and schedule monitoring
			psutil.cpu_percent(0)
			schedule.every(30).seconds.do(self.config_get)
			schedule.every(3600).seconds.do(self.time_synchronize)
			schedule.every(30).seconds.do(self.alive)

			# Main loop
			while True:
				self.parse_packets()
				schedule.run_pending()

		# Do not log system exit... Why python, why sys.exit() generates exception?!
		except SystemExit:
			pass
		except:
			self.error_report('WORLD IS BURNING, UNHANDLED ERROR!', 'critical', True)

def main():
	scanner = Scanner()
	scanner.scan()

if __name__ == "__main__":
	main()
