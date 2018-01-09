# Beacons Positioning Node #

This repository is intended for raspberry pi nodes and provides bluetooth signal scanning utility.

### What is this repository for? ###

* Contains code for scanning nearby bluetooth beacons
* Scan data is preprocessed (median over fixed window) and sent to the stream for Beacons Positioning Processor. If there is data in processor, relative received signal strength (rssi) is converted to approximate distance and position relative to mesh of nodes is calculated. Also always the presence analytics is recorded.

* Disclaimer: this package does NOT scan mobile phones and similar devices which need bluetooth authentification. Authentification is time-consuming and not suitable for use in real-time applications

### How do I get set up? ###

This package is not intended for direct installation. Please refer to installer package -- https://github.com/socifi/ble-node-installer

If you still want to install this package, you can do this by installing this package from source:

~~~
git clone https://github.com/socifi/ble-positioning-node
cd ble-positioning-node
sudo pip install -e .
~~~

After this procedure there will be service installed however it will not be configured you'll need to put configuration file to /etc/ble\_positioning\_node/config.conf as in example with filled user\_id, brand\_id, group\_id and name

~~~
[Communication]
log_proxy = ble-logging.socifi.com
log_proxy_port = 9339
registration = https://b.socifi.com/node/register
configuration = https://b.socifi.com/node/configuration

[User]
user_key = The_Key
user_id = 
brand_id = 
group_id = 
name = RPI_at_some_shop
~~~

After that you'll need to restart service:

~~~
sudo service ble_positioning_node restart
~~~
