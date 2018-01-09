# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from datetime import date, datetime
import logging
import socket
import sys
import time
import traceback
import psutil
import os
import uuid

import json

# The list contains all the attributes listed in
# http://docs.python.org/library/logging.html#logrecord-attributes
RECORD_FIELD_SKIP_LIST = (
	'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
	'funcName', 'id', 'levelname', 'levelno', 'lineno', 'module',
	'msecs', 'message', 'msg', 'name', 'pathname', 'process',
	'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName')
LOGSTASH_MESSAGE_FIELD_LIST = [
	'@timestamp', '@version', 'host', 'level', 'logsource', 'message',
	'pid', 'program', 'type', 'tags']


class ErrorFormatter(logging.Formatter):

	# ----------------------------------------------------------------------
	def __init__(self, tags=None, fqdn=False, extra_prefix='extra', extra=None):
		super(ErrorFormatter, self).__init__()
		self._tags = tags if tags is not None else []
		self._extra_prefix = extra_prefix
		self._extra = extra

		self._interpreter = None
		self._interpreter_version = None
		self._host = None
		self._logsource = None
		self._program_name = None

		# fetch static information and process related information already as they won't change during lifetime
		self._prefetch_interpreter()
		self._prefetch_interpreter_version()
		self._prefetch_host(fqdn)
		self._prefetch_logsource()
		self._prefetch_program_name()

	# ----------------------------------------------------------------------
	def _prefetch_interpreter(self):
		"""Override when needed"""
		self._interpreter = sys.executable

	# ----------------------------------------------------------------------
	def _prefetch_interpreter_version(self):
		"""Override when needed"""
		self._interpreter_version = u'{}.{}.{}'.format(
			sys.version_info.major,
			sys.version_info.minor,
			sys.version_info.micro)

	# ----------------------------------------------------------------------
	def _prefetch_host(self, fqdn):
		"""Override when needed"""
		if fqdn:
			self._host = socket.getfqdn()
		else:
			self._host = socket.gethostname()

	# ----------------------------------------------------------------------
	def _prefetch_logsource(self):
		"""Override when needed"""
		self._logsource = self._host

	# ----------------------------------------------------------------------
	def _prefetch_program_name(self):
		"""Override when needed"""
		self._program_name = sys.argv[0]

	# ----------------------------------------------------------------------
	def _get_level_no(self, levelno):
		return levelno*10

	def _get_node_info(self):
		load_average = list(os.getloadavg())
		meminfo_full = dict(psutil.virtual_memory().__dict__)
		meminfo = {}
		for key in ['used', 'free', 'total', 'percent']:
			meminfo[key] = meminfo_full[key]
		return {'cpu':load_average, 'meminfo': meminfo}

	def _get_context(self, record):
		context = {}
		record_fields = self._get_record_fields(record)
		for key in ['mac', 'ip', 'debug', 'errorinfo']:
			if(key in record_fields):
				context[key] = record_fields[key]
		context['stats'] = self._get_node_info()
		return context


	# ----------------------------------------------------------------------
	def format(self, record):
		# Get record fields passed in extra
		message = {
				'@timestamp': self._format_timestamp(record.created),
				'@version': '1',
				'level': self._get_level_no(record.levelno),
				'level_name': record.levelname,
				'message': record.getMessage(),
				'type': 'ble-node-status',
			}
		if record.levelno == logging.INFO:
			message['type'] = 'ble-node-status'
		elif record.levelno == logging.DEBUG:
			message['type'] = 'ble-node-debug'
		else:
			message['type'] = 'ble-node-log'

		context = self._get_context(record)
		message['context'] = {}

		if record.exc_info:
			message['context']['exception'] = self._format_exception(record.exc_info)
		message['context'].update(context)

		return self._serialize(message)

	# ----------------------------------------------------------------------
	def _get_record_fields(self, record):
		def value_repr(value):
			if sys.version_info < (3, 0):
				easy_types = (basestring, bool, float, int, long, type(None))
			else:
				easy_types = (str, bool, float, int, type(None))

			if isinstance(value, dict):
				return {k: value_repr(v) for k, v in value.items()}
			elif isinstance(value, (tuple, list)):
				return [value_repr(v) for v in value]
			elif isinstance(value, (datetime, date)):
				return self._format_timestamp(time.mktime(value.timetuple()))
			elif isinstance(value, uuid.UUID):
				return value.hex
			elif isinstance(value, easy_types):
				return value
			else:
				return repr(value)

		fields = {}

		for key, value in record.__dict__.items():
			if key not in RECORD_FIELD_SKIP_LIST:
				fields[key] = value_repr(value)
		return fields


	# ----------------------------------------------------------------------
	def _format_timestamp(self, time_):
		tstamp = datetime.utcfromtimestamp(time_)
		return tstamp.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (tstamp.microsecond / 1000) + "Z"

	# ----------------------------------------------------------------------
	def _format_exception(self, exc_info):
		stack = traceback.extract_stack()
		exception = {'class': exc_info[0].__name__, 'message': exc_info[1].message,
					 'file': "%s:%d" % (os.path.abspath(stack[0][0]), stack[0][1]),
					 'trace': ["%s:%d" % (os.path.abspath(item[0]), item[1]) for item in stack]}
		#		exception['code'] = ''
		return exception

	# ----------------------------------------------------------------------
	def _serialize(self, message):
		if sys.version_info < (3, 0):
			return json.dumps(message)
		else:
			return bytes(json.dumps(message))

