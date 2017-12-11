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
import pprint as pp
import bluetooth._bluetooth as bluez
###################
# End of fine art #
###################

LE_META_EVENT = 0x3e
OGF_LE_CTL = 0x08
OCF_LE_SET_SCAN_ENABLE = 0x000C
OCF_LE_SET_SCAN_ENABLE = 0x000C
EVT_LE_CONN_COMPLETE = 0x01
EVT_LE_ADVERTISING_REPORT = 0x02

class BLEScanner:
	def __init__(self, handler, config):
		self.log_handler = handler
		self.log_level = logging.INFO
		self.log = logging.getLogger("beacon-node-log")
		self.log.setLevel(self.log_level)
		self.log.addHandler(self.log_handler)
		self.beacon_statistics = dict()
		self.beacon_list = dict()
		self.beacon_list_age = time.time()
		self.config = config
		FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
		logging.basicConfig(format=FORMAT,level=self.log_level)
		self.state_update("beacon-unknown")
#		self.file = open("stat","w+")

	#####################################
	# Setup bluetooth, mac and local ip #
	#####################################

	def node_register(self):
		if(self.config.has_option('Communication', 'registered')):
			return

		url = self.config.get('Communication', 'registration')
		payload = """------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="userId"

%s
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="brandId"

%s
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="mac"

%s
""" % (	self.config.get('User', 'user_id'),
	self.config.get('User', 'brand_id'),
	self.mac)

		if(self.config.has_option('User', 'group_id')):
			payload += """------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="groupId"

%s
"""
		if(self.config.has_option('User', 'name')):
			payload += """------WebKitFormBoundary7MA4YWxkTrZu0gW--
Content-Disposition: form-data; name="name"

%s
------WebKitFormBoundary7MA4YWxkTrZu0gW--
""" % (	self.config.get('User', 'name'))

		headers = {
			'content-type': "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
			'Authorization': "Bearer "+self.config.get('User', 'user_key'),
			'Cache-Control': "no-cache"
		}

		response = requests.request("POST", url, data=payload, headers=headers)

		print(response.text)
		if(response.status_code == requests.codes.ok):
			self.config.set('Communication', 'registered', 'true')
			self.config.write(open(self.config.file, 'wb'))


	def config_get(self):
		r = requests.get(self.config.get('Communication', 'configuration')+"?mac="+self.mac)
		if r.status_code != 200:
			timestamp = time.time()
			self.log.critical("Error getting config. Time: %d. Location: %s. Cause of accident: unknown. "
					  "Should someone find this record perhaps it will shed light as to what happened here." % (timestamp, self.mac), extra={'timestamp':timestamp, 'mac':self.mac}	)
			sys.exit(1)

		tmp = json.loads(r.text)
		# Old format (should be fixed?)
		self.config = tmp['configuration']
		self.config['white_list'] = tmp['macWhiteList']
		self.config['black_list'] = tmp['macBlackList']
		self.config['node'] = {}
		self.config['node']['mac'] = self.mac
		self.info_update_signal = True

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

	def bluetooth_turn_on(self):
		try:
			self.hci_toggle_le_scan(0x01)
		except:
			self.error_report("Device could not toggle scan", 'critical')
			exit(1)

	def mac_get(self):
		devId = 0
		try:
			self.sock = bluez.hci_open_dev(devId)
			self.log.debug('Connect to bluetooth device %i', devId)
		except:
			timestamp = time.time()
			self.log.critical("Error: not able to connect to bluetooth device. Time: %d. Location: unknown. Cause of accident: unknown. "
					  "Should someone find this record perhaps it will shed light as to what happened here." % timestamp, extra={'timestamp':timestamp})
			sys.exit(1)
		self.mac = self.read_local_bdaddr()
		self.log.info('Got mac address %s.' % self.mac)

	def ip_get(self):
		# try to connect to server, otherwise we could get only 127.0.0.1 which is useless...
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try:
			print self.log_handler.hosts
			s.connect((self.log_handler.hosts[0]['host'],self.log_handler.hosts[0]['port'])) # (LOG_CONN_POINTS)
			self.remote_ip = s.getsockname()[0]
			s.close()
		except:
			self.error_report("Device could not read it's IP",'error')


	def state_update(self, state):
		self.info_update_signal = True
		self.state = state

	############################################
	# Functions to connect to bluetooth device #
	############################################

	def print_packet(self, pkt):
		for c in pkt:
			sys.stdout.write("%02x " % struct.unpack("B",c)[0])

	def packed_bdaddr_to_string(self, bdaddr_packed):
		return "".join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

	def hci_disable_le_scan(self):
		self.hci_toggle_le_scan(self.sock, 0x00)

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
		bluez.hci_filter_set_event(flt, bluez.EVT_CMD_COMPLETE);
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

	def info_get(self):
		if self.info_update_signal == True or not hasattr(self, 'info'):
			self.info = copy.deepcopy(self.config)
			self.info_update_signal = False
		info = copy.deepcopy(self.info)
		# Do not send aws keys
		info.pop('aws_secret', None)
		info.pop('aws_key', None)
		info.pop('aws_region', None)
		info['timestamp'] = time.time()
		return info

	def info_report(self, info_string):
		info = self.info_get()
		info['info'] = info_string
		info['type'] = "beacon-info-report"
#		pp.pprint(info)
		self.log.info('Info report', extra=info)

	def error_report(self, error_string, severity):
		error = self.info_get()
		error['error'] = error_string
		error['type'] = "beacon-error-report"
		if severity == 'error':
			self.log.error('Error report', extra=error)
		elif severity == 'warning':
			self.log.warning('Warning report', extra=error)
		else:
			self.log.critical('Critical report', extra=error)

	def statistics_report(self, statistics):
		stat = self.info_get()
		stat['statistics'] = statistics
		stat['type'] = "beacon-statistics-report"
		pp.pprint(stat)
		self.log.info('Statistics report', extra=stat)

	def kinesis_setup(self):
		try:
			self.kinesis = boto3.client('kinesis',
				aws_access_key_id=self.config['aws_key'],
				aws_secret_access_key=self.config['aws_secret'],
				region_name=self.config['aws_region']
			)
		except:
			self.error_report("Kinesis error",'')
			sys.exit(1)

	def add_to_list(self, address, rssi):
		if address not in self.beacon_list:
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

	########################
	# Monitor various data #
	########################

	def monitor_node(self, pid):
		p = psutil.Process(pid)
		meminfo = psutil.virtual_memory()
		swapinfo = psutil.swap_memory()
		io = psutil.disk_io_counters()
		process_cpu = p.cpu_percent()
		cpu = psutil.cpu_percent(0)
		comp = {'meminfo': dict(meminfo.__dict__), 'swapinfo': dict(swapinfo.__dict__), 'io': dict(io.__dict__), 'process_cpu': process_cpu, 'cpu': cpu}
		return comp

	def report(self, pid):
		comp = self.monitor_node(pid)
		beac = copy.deepcopy(self.beacon_statistics)
		stat = {'node': comp, 'beacon-counts': beac}
#		stat = json.loads(json.dumps(stat))
#		stat = {'cpu': cpu, 'meminfo': meminfo}
#		pp.pprint(json.dumps(stat))
#		pp.pprint('----------------')
#		pp.pprint(dict(io.__dict__))
#		pp.pprint('----------------')
		self.beacon_statistics.clear()
		self.statistics_report(stat)

	def monitor(self):
		pid = os.getpid()
		thread_mon = threading.Thread(target=self.report, args=(pid,))
		thread_mon.start()

	def alive(self):
		self.info_report("I'm alive!")

	def main(self):
		print("Program start")
		self.bluetooth_setup()
		print("Bluetooth setup")
		self.mac_get()
		print("Got mac")
		self.node_register()
		print("Node registered")
		self.state_update("beacon-preliminary") # now we know at least mac address of device
		self.config_get()
		print("Got config")
		self.state_update("beacon-up") # now we have all info from server
		self.ip_get()
		self.bluetooth_turn_on()
		print("Starting scanning")
		self.kinesis_setup()

		# init counter and schedule monitoring
		psutil.cpu_percent(0)
		schedule.every(30).seconds.do(self.monitor)
		schedule.every(30).seconds.do(self.config_get)
		schedule.every(5).seconds.do(self.alive)
		while True:
			self.parse_packets()
			schedule.run_pending()
