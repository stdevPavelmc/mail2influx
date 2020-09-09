# Mail2Influx

A simple mail log data parser and influx data injector; crafted to match [MailAD](https://github.com/stdevPavelmc/mailad) logs in Ubuntu and Debian

## Motivation

Telegraf and other solutions do not fill my needs of mail monitoring, so I put python3 and some regex rules to make this parser, it's given as a GPL 3.0 software, so no warranty in you use case; but you can modify it to fit your needs.

## Installation

You need to install python-influxdb support, search it on the repository or use pip for that.

0. Copy the "mail2influx.py" script to `/usr/local/bin/`
1 Make it executable `chmod +x /usr/local/bin/mail2influx.py`
2. Edit the `/usr/local/bin/mail2influx.py` file and change the variable  `influxhost` to your influxdb server
3. Copy "mail2influx.service" file to the systemd folder `cp mail2influx.service /lib/systemd/system/`
4. Activate and start the service
    - `systemctl daemon-reload`
    - `systemctl enable mail2influx`
    - `systemctl start mail2influx`
5. Go to Grafana and create a new dashboard and import the data from the `influx-grafana_dashboard.json` file
    - You may need to update the influxdb source in grafana to make int work

## Known issues

- No authentication against the influxdb, no need on my env
- No ssl/tls against the influxdb, no need on my env
- May contain bugs (code is a work in progress)
- May not be 100% optimized

## About the author

This is free software, see [stdevPavelmc](https://github.com/stdevPavelmc/stdevPavelmc)
