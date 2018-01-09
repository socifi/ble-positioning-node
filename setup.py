from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info
from codecs import open
from os import path
import os
import subprocess

name = 'ble_positioning_node'
servicefile = '/etc/systemd/system/%s.service' % (name)
servicetext = """[Unit]
Description=BLE positioning system setup

[Service]
ExecStart=/usr/local/bin/%s
PIDFile=/tmp/%s.pid
Restart=always
Type=simple

[Install]
WantedBy=default.target
""" % (name, name)


here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
	long_description = f.read()

def install_bluetooth():
	p = subprocess.call(['sudo', 'apt-get', '-y', 'install', 'bluetooth', 'libbluetooth-dev'])

def custom_command():
	directory = os.path.dirname(servicefile)
	if not os.path.exists(directory):
		os.makedirs(directory)	
	with open(servicefile, 'w') as f:
		f.write(servicetext)
	p = subprocess.call(['systemctl', 'enable', name+'.service'])
	p = subprocess.call(['service', name, 'start'])


class CustomInstallCommand(install):
	def run(self):
		install_bluetooth()
		install.run(self)
		custom_command()


class CustomDevelopCommand(develop):
	def run(self):
		install_bluetooth()
		develop.run(self)
		custom_command()


class CustomEggInfoCommand(egg_info):
	def run(self):
		install_bluetooth()
		egg_info.run(self)
		custom_command()


setup(
	name='Ble Positioning Node',
	version='0.1.1',
	description='Beacons Positioning Node is intended as bluetooth signal detector. It collects rssi of each mac address and sends the data to kinesis queue for position calculation.',
	long_description=long_description,
	url='https://github.com/socifi',
	author='Socifi LTd.',
	author_email='code@socifi.com',
	license='MIT',
	classifiers=[
		'Development Status :: 3 - Alpha',
		'Intended Audience :: Developers',
		'Topic :: Software Development :: Build Tools',
		'License :: OSI Approved :: MIT License',
		'Programming Language :: Python :: 2.7',
	],
	cmdclass={
		'install': CustomInstallCommand,
		'develop': CustomDevelopCommand,
		'egg_info': CustomEggInfoCommand,
	},
	keywords='ble bluetooth detection',
	packages=[name],
	install_requires=['requests', 'boto3', 'schedule', 'psutil', 'CMRESHandler', 'pybluez', 'ntplib'],
	entry_points={
		'console_scripts': [
			name+' = '+name+'.scanner:main',
		],
	},
)
