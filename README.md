# Aruba Instant Python API Wrapper

This module provides a Python 3 interface for the Aruba Instant 8.6 REST API.

**Please understand this project is a WIP.  I'd also really appreciate some help testing.  My Instant cluster is my production wifi at home.  I can't thoroughly test certain calls to the API (specifically in the Configuration portion) because breaking the wifi at home would result in an unhappy household.**

For full documentation, see [here](https://support.hpe.com/hpesc/public/docDisplay?docId=a00092466en_us).

The REST API is divided into three secions.  **Monitoring**, **Action**, and **Configuration**.  Details on each section are below.  Logging in and out is handled by the ```login()``` and ```logout()``` methods.  Logging in has a decorator method that will handle logging in if needed.  You will still need to handle logging out.  *See examples below.*

## Monitoring
The monitoring endpoints of the API does is used for, obviously, monitoring.  It is used to gather state, statistics, and logs from master, slave, or standalone Instant APs.  The architecture of this portion of the API is very similar to the cli output of "show" commands.  The currently supported commands are ```show clients``` and ```show aps```.  More will be added shortly.  There is also a generic ```show command``` method that will accept any CLI show commands and return unstructured text.

Feel free to open an issue and request support for more commands if the structured output would be helpful.  I can also add support for different OS versions (at least back to 8.5) if it would be helpful.

    NOTE: The response from the API is currently unstructred text and requires parsing with RegEx.  
    This lends itself to breaking easily between versions.  My current testing has been against 8.6.

## Action
The action endpoints are used for configuring AP specific settings.  See below for supported endpoints.

Endpoint | Method | Description
--- | --- | ---
Hostname | hostname() | Set the hostname of a specific IAP.
Swarm Mode | swarm() | Set an AP to be standalone or part of a swarm cluster.
Static Channel and Power | channel() | Set the tx channel and power of the radios of a specific IAP.
Zone | zone() | Set the zone of a specific IAP.
Antenna Gain | antenna_gain() | Set the specific antenna gain when external antennas are used.
Enable and Disable Radios | radio_state() | Enable or disable a radio in an AP.
Generic Show Command | show_cmd() | Returns unstructured output text from any "show" command provided.

## Configuration
Configuration endpoints are used to configure an Instant Virtual Controller.  See table below for supported endpoints.

When intantiating an instance of InstantVC() the 'templates' directory defaults to the folder in the project.  It is recommended that you create your own templates directory and use this one for reference.

    Note: Due to the complexity of the profiles created using these endpoints, 
    all Configuration methods require a json file as an argument.

    There are examples in the "templates" directory.  
    These example templates were taken directly from the 
    Aruba Instant REST API document referenced above.

Endpoint | Method | Description
---|---|---
VC Country Code | vc_country_code() | Set the virtual controller country code.
VC IP address | vc_ip() | Set the IP of the virtual controller.
NTP Server | ntp() | Set the NTP server of the virtual controller.
Syslocation | syslocation() | Set the syslocation of the virtual controller.
Organization | organization() | Set the virtual controller organization.
Syslog Level | syslog_level() | Set the syslog level for the virtual controller.
Syslog Server | syslog_server() | Set the destination IP for syslog traffic from the virtual controller.
dot11g Radio Profile | radio_11g() | Configure a radio profile for the 2.4GHz antenna.
dot11a Radio Profile | radio_11a() | Configure a radio profile for the 5GHz antenna.
ARM | arm() | Configure an ARM profile for use by the Instant cluster.
SSID Profile | ssid() | Configure an SSID profile for use by the Instant cluster.
RF Band | rf_band() | Configure an RF Band (2.4, 5, all) profile for use by the Instant cluster.
Authentication Server Profile | auth_server() | Configure an authentication server (RADIUS) for the virtual controller.
ACL Profile | acl() | Configure an ACL profile for use by the Intant cluster.
External Captive Portal | ext_captive_portal() | Configure an External Captive Portal profile for use by the Instant cluster.
IDS | ids() | Configure an IDS profile for use by the Instant cluster.
Software Upgrade | os_upgrade() | Initiate an OS Upgrade of the Instant cluster.
Time Zone | clock() | Set clock and timezone of the virtual controller.
AP Reboot | ap_reboot() | Initiate a reboot of a single or all APs in the Instant cluster.
Wired Port Profile | wired_port() | Configure a wired port profile for use by the Instant cluster.
Wired Profile Map | wired_profile_map() | Configure a wired profile to port mapping for use by the Instant cluster.
Management User | mgmt_user() | onfigure management users on the virtual controller.


## Examples:
Login leveraging the @autologin decorator - In this scenario the decorator will login for you when the first API call is made.
```
import instantpy

vc = instantpy.InstantVC('user', 'password', 'VC IP')

result = vc.clients()
...
vc.logout()
```

### Monitoring Endpoint Example
List connected clients
```
import json
import instantpy

vc = instantpy.InstantVC('user', 'password', 'VC IP')
result = vc.clients()
print(json.dumps(result, indent=4))
vc.logout()
```

Arbitrary 'show' command
```
import json
import instantpy

vc = instantpy.InstantVC('user', 'password', 'VC IP')
result = vc.show_command(command="show swarm state")
print(result)
vc.logout()
```

### Action Endpoint Example
Set Hostname of a specfic AP
```
import json
import instantpy

vc = instantpy.InstantVC('user', 'password', 'VC IP')
result = vc.hostname(name="testname", iap_ip="1.2.3.4")
print(json.dumps(result, indent=4))
vc.logout()
```

### Configuration Endpoint Example
Set RADIUS Authentication Server
```
import json
import instantpy

vc = instantpy.InstantVC('user', 'password', 'VC IP')
result = vc.auth_server(template='auth_server_template.json')
print(json.dumps(result, indent=4))
vc.logout()
```
