
# GROWATT-SERVER
Growatt-server is a Perl script used for [Growatt](https://www.ginverter.com/) solar inverters with [ShineWiFi-X](https://www.ginverter.com/Monitoring/10-630.html) modules. Growatt-server can be used to communicate with a solar inverter, decode energy data, and publish these data via MQTT.

## Installation

```bash
git clone https://github.com/knowthelist/ftui/Growatt-server.git
cd Growatt-server
```
If not done before, you need to install some modules

sudo cpanm Net::MQTT::Simple
sudo cpanm Net::MQTT::Constants
sudo cpanm Data::Hexify

## Usage

First, you need to use the Growatt WiFi module administrative interface, go to the "Advanced Setting" and change "Server Address" (default: server.growatt.com) to the name or ip of the system running the
your server.

See [AP-Mode manual](https://static1.squarespace.com/static/524c5ffae4b0bcb12e072ee1/t/5e1e87d8348d0b3315f2dc90/1579059163523/Growatt+ShineWiFi-S+OR+X+WIFI+setup+through+AP+mode.pdf)

```bash
perl growatt_server.pl
```
Finally, you need to configure the ShineWifi-X module to communicate with the computer running this script. You will also need to configure the computer running this script with a static IP address.


## Daemon

To run the script 24x7 as a service, you can use the growattserver.service config for systemd.

```bash
sudo cp growattserver.service /etc/systemd/system/
sudo systemctl enable growattserver
sudo systemctl start growattserver
```


## License
This project is licensed under [MIT](http://www.opensource.org/licenses/mit-license.php).
