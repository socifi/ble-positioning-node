#!/usr/bin/python 
from cmreslogging.handlers import CMRESHandler
from BLEScanner import BLEScanner

import sys
import time
import os
import ConfigParser

version = '0.1.0'

def main(args=None):
	####################
	# Synchronize time #
	####################
	try:
		import ntplib
		client = ntplib.NTPClient()
		response = client.request('pool.ntp.org')
		os.system('date ' + time.strftime('%m%d%H%M%Y.%S',time.localtime(response.tx_time)))
	except:
		print('Could not sync with time server.')


	"""The main routine."""
	if args is None:
		args = sys.argv[1:]
	print "version="+version

	################
	# Parse config #
	################

	config = ConfigParser.RawConfigParser()
	config.file = '/etc/ble_positioning_node/config.conf'
	config.read(config.file)

	###############################
	# We want reporting to kibana #
	###############################

	LOG_CONN_POINTS = [{'host':config.get('Communication', 'elastic'),'port': config.getint('Communication', 'elastic_port')}]

	handler = CMRESHandler(	hosts=LOG_CONN_POINTS,
				auth_type=CMRESHandler.AuthType.NO_AUTH,
				use_ssl=True,
				es_index_name="beacon-scanner")

	scan = BLEScanner(handler, config)
	scan.main()

if __name__ == "__main__":
	main()

