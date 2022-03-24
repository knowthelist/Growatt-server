
# GROWATT-SERVER
Growatt-server is a Perl script used for [Growatt](https://www.ginverter.com/) solar inverters with [ShineWiFi-X](https://www.ginverter.com/Monitoring/10-630.html) modules. Growatt-server can be used to communicate with a solar inverter, decode energy data, and publish these data via MQTT.

## Installation

```bash
git clone https://github.com/knowthelist/Growatt-server.git
cd Growatt-server
```
If not done before, you need to install some modules

```bash
sudo cpanm Net::MQTT::Simple
sudo cpanm Net::MQTT::Constants
sudo cpanm Data::Hexify
```

## Usage

First, you need to use the Growatt WiFi module administrative interface, go to the "Advanced Setting" and change "Server Address" (default: server.growatt.com) to the name or ip of the system running this script. You will also need to configure the computer running this script with a static IP address.

See [AP-Mode manual](https://static1.squarespace.com/static/524c5ffae4b0bcb12e072ee1/t/5e1e87d8348d0b3315f2dc90/1579059163523/Growatt+ShineWiFi-S+OR+X+WIFI+setup+through+AP+mode.pdf)

Start the script:

```bash
perl growatt_server.pl
```

For debugging add --debug=N (N: 1-4) parameter:

```bash
perl growatt_server.pl --debug=3
```

## Daemon

To run the script 24x7 as a service, you can use the growattserver.service config for systemd.

```bash
sudo cp growatt_server.pl /usr/local/bin/
sudo cp growattserver.service /etc/systemd/system/
sudo systemctl enable growattserver
sudo systemctl start growattserver
```

## Tested devices

- Growatt MIC-600TL-X Inverter
- Growatt ShineWiFI-X - WiFi-Stick.

## License
This project is licensed under [MIT](http://www.opensource.org/licenses/mit-license.php).
