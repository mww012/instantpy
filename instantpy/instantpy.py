import json
import requests
import re
from time import sleep



def autologin(func):
    # @wraps(func)
    def inner(self, **kwargs):
        if self.logged_in is False:
            self.login()
            return func(self, **kwargs)
        else:
            return func(self, **kwargs)

    return inner


class InstantVC:
    def __init__(
        self,
        ip,
        username,
        password,
        port=4343,
        template_basepath="templates/",
        ssl_verify=True,
    ):
        """Initialize an instance of InstantVC.

        Arguments:
            username {str} -- Username to log into VC
            password {str} -- Password to log into VC
            ip {str} -- IPv4 address of VC

        Keyword Arguments:
            port {int} -- Listening port of the VC webserver (default: {4343})
            template_basepath {str} -- Base path for template configs (default: {"templates/"})
            ssl_verify {bool} -- Verify SSL certificate returned by VC (default: {False})
        """
        self.username = username
        self.password = password
        self.port = port
        self.ip = ip
        self.logged_in = False
        self.sid = None
        self._session = None
        self.baseurl = f"https://{ip}:{port}/rest"
        self.template_basepath = template_basepath
        self.ssl_verify = ssl_verify
        self.headers = {"Content-Type": "application/json"}

    def login(self):
        """Log into the VC.

        This method will generally be automatically called via the @autologin decorator.
        After 15 minutes of inactivity the VC will automatically log the session out.
        """
        url = f"{self.baseurl}/login"
        creds = {"user": self.username, "passwd": self.password}
        try:
            with requests.Session() as session:
                response = session.post(
                    url, json=creds, headers=self.headers, verify=self.ssl_verify
                )
                parsed = response.json()
                if parsed["Status"] == "Success":
                    self.logged_in = True
                    self.sid = parsed["sid"]
                    self.session = session
                    self.params = f"sid={self.sid}"
                return True
        except requests.exceptions.ConnectionError as e:
            return e

    def logout(self):
        """Log out of the VC"""
        url = f"{self.baseurl}/logout"
        data = json.dumps({})
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        parsed = response.json()
        if parsed["Status-code"] == "0":
            self.logged_in = False
            self.sid = ""
            self.session = None
            self.params = None

    @autologin
    def clients(self, mac=None):
        """Get a list of clients currently on the VC.

        Returns:
            dict -- Json formatted response from the VC
        """
        url = f"{self.baseurl}/show-cmd?iap_ip_addr={self.ip}&cmd=show clients&sid={self.sid}"
        regex = r"^(?P<name>\S+)?\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<mac>(?:\S{2}:){5}\S{2})\s+(?P<os>\S+\s?\S+)?\s+(?P<essid>\S+)\s+(?P<ap>\S+)\s+(?P<channel>\d{1,3}[+-]?)\s+(?P<phy>[A-Z]{2})\s+(?P<role>\S+)\s+(?P<ipv6>[a-f0-9:]{5,29}|--)?\s+(?P<signal>\d{1,3})\((?P<signal_text>\S+)\)\s+(?P<speed>\d{1,3})\((?P<speed_text>\S+)\)"
        response = self.session.get(url, verify=self.ssl_verify)
        if response.status_code != 200:
            sleep(0.5)
            response = self.session.get(url, verify=self.ssl_verify)
        devices_result = response.text.split("\\n")
        devices = {}
        for device in devices_result:
            match = re.match(regex, device)
            if match:
                devices[match.group("mac")] = {
                    "name": match.group("name"),
                    "ip": match.group("ip"),
                    "mac": match.group("mac"),
                    "os": match.group("os"),
                    "essid": match.group("essid"),
                    "ap": match.group("ap"),
                    "channel": match.group("channel"),
                    "phy": match.group("phy"),
                    "role": match.group("role"),
                    "ipv6": match.group("ipv6"),
                    "signal": match.group("signal"),
                    "signal_text": match.group("signal_text"),
                    "speed": match.group("speed"),
                    "speed_text": match.group("speed_text"),
                }
        if mac is not None:
            return devices.get(mac)
        else:
            return devices

    @autologin
    def aps(self):
        """Get a list of APs that are members of the instant cluster.

        Returns:
            dict -- json formatted response from VC
        """
        url = (
            f"{self.baseurl}/show-cmd?iap_ip_addr={self.ip}&cmd=show aps&sid={self.sid}"
        )
        regex = r"^(?P<name>\S+)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?P<master>\*)?\s+(?P<mode>\S+)\s+(?P<spectrum>\S+)\s+(?P<clients>\S+)\s+(?P<type>\S+)\s+(?P<ipv6>[a-f0-9:]{5,29}|--)\s+(?P<meshrole>\S+)\s+(?P<zone>\S+)\s+(?P<serial>\S+)\s+(?P<r0chan>\S+)\s+(?P<r0pwr>\S+)\s+(?P<r0util>\S+?)\((?P<r0utiltxt>\S+?)\)\s+(?P<r0noiseflr>\S+?)\((?P<r0noiseflrtxt>\S+)\)\s+(?P<r1chan>\S+)\s+(?P<r1pwr>\S+)\s+(?P<r1util>\S+?)\((?P<r1utiltxt>\S+?)\)\s+(?P<r1noiseflr>\S+?)\((?P<r1noiseflrtxt>\S+)\)\s+(?P<r2chan>\S+)\s+(?P<r2pwr>\S+)\s+(?P<r2util>\S+?)(?:\((?P<r2utiltxt>\S+)\))?\s+(?P<r2noiseflr>\S+?)(?:\((?P<r2noiseflrtxt>\S+)\))?\s+(?P<needantcfg>\S+)\s+(?P<fromport>\S+)\s+(?P<cfgid>\S+)\s+(?P<cfgcsum>\S+)\s+(?P<extssidactive>\S+)\s+(?P<age>\S+)\s+(?P<linklocal>\S+)\s+(?P<uplink>\S+)"
        response = self.session.get(url, verify=self.ssl_verify)
        if response.status_code != 200:
            sleep(0.5)
            response = self.session.get(url, verify=self.ssl_verify)
        devices_result = response.text.split("\\n")
        devices = {}
        for device in devices_result:
            match = re.match(regex, device)
            if match:
                devices[match.group("name")] = {
                    "name": match.group("name"),
                    "ip": match.group("ip"),
                    "master": match.group("master"),
                    "mode": match.group("mode"),
                    "spectrum": match.group("spectrum"),
                    "clients": match.group("clients"),
                    "type": match.group("type"),
                    "ipv6": match.group("ipv6"),
                    "meshrole": match.group("meshrole"),
                    "zone": match.group("zone"),
                    "serial": match.group("serial"),
                    "r0chan": match.group("r0chan"),
                    "r0pwr": match.group("r0pwr"),
                    "r0util": match.group("r0util"),
                    "r0utiltxt": match.group("r0utiltxt"),
                    "r0noiseflr": match.group("r0noiseflr"),
                    "r0noiseflrtxt": match.group("r0noiseflrtxt"),
                    "r1chan": match.group("r1chan"),
                    "r1pwr": match.group("r1pwr"),
                    "r1util": match.group("r1util"),
                    "r1utiltxt": match.group("r1utiltxt"),
                    "r1noiseflr": match.group("r1noiseflr"),
                    "r1noiseflrtxt": match.group("r1noiseflrtxt"),
                    "r2chan": match.group("r2chan"),
                    "r2pwr": match.group("r2pwr"),
                    "r2util": match.group("r2util"),
                    "r2utiltxt": match.group("r2utiltxt"),
                    "r2noiseflr": match.group("r2noiseflr"),
                    "r2noiseflrtxt": match.group("r2noiseflrtxt"),
                    "needantcfg": match.group("needantcfg"),
                    "fromport": match.group("fromport"),
                    "cfgid": match.group("cfgid"),
                    "cfgcsum": match.group("cfgcsum"),
                    "extssidactive": match.group("extssidactive"),
                    "age": match.group("age"),
                    "linklocal": match.group("linklocal"),
                    "uplink": match.group("uplink"),
                }
        return devices

    @autologin
    def runningcfg(self):
        """Get the running configuration of the VC.

        Returns:
            str -- Running configuration formatted as a block of text
        """
        url = f"{self.baseurl}/show-cmd?iap_ip_addr={self.ip}&cmd=show running-config&sid={self.sid}"
        response = self.session.get(url, verify=self.ssl_verify)
        parsed = response.json()["Command output"].splitlines()
        config = ""
        for line in parsed[3:]:
            config = f"{config}{line}\n"
        return config

    @autologin
    def show_command(self, command):
        """Generic command method.  Output will not be parsed.

        Arguments:
            command {str} -- Desired show command. ["show version", "show swarm state", etc.]

        Returns:
            str -- Command output as text
        """
        url = f"{self.baseurl}/show-cmd?iap_ip_addr={self.ip}&cmd={command}&sid={self.sid}"
        response = self.session.get(url, verify=self.ssl_verify)
        parsed = response.json()["Command output"].splitlines()
        output = ""
        for line in parsed[3:]:
            output = f"{output}{line}\n"
        return output

    @autologin
    def hostname(self, name="", iap_ip=""):
        """Set the hostname of a specific IAP.

        Keyword Arguments:
            name {str} -- Desired name of the IAP (default: {''})
            iap_ip {str} -- IPv4 address of the IAP in question (default: {''})

        Returns:
            dict -- Json formatted response from the VC
        """
        url = f"{self.baseurl}/hostname"
        data = json.dumps({"iap_ip_addr": iap_ip, "hostname_info": {"hostname": name}})
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()

    @autologin
    def zone(self, action="", name="", iap_ip=""):
        """Set the zone of a specific IAP.

        Keyword Arguments:
            action {str} -- Action to be performed [create, delete] (default: {''})
            name {str} -- Desired zone name (default: {''})
            iap_ip {str} -- IPv4 address of the IAP (default: {''})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/zone"
        data = json.dumps(
            {"iap_ip_addr": iap_ip, "zone_info": {"action": action, "zonename": name}}
        )
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def swarm(self, iap_ip="", mode=""):
        """Set an AP to be standalone or part of a swarm cluster.

        Keyword Arguments:
            iap_ip {str} -- IPv4 address of IAP (default: {''})
            mode {str} -- Desired Swarm mode [standalone, cluster] (default: {''})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/swarm-mode"
        data = json.dumps({"iap_ip_addr": iap_ip, "swarm-mode": {"swarm-mode": mode,}})
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def channel(
        self, iap_ip="", a_chan_name="", a_tx_pwr="", g_chan_name="", g_tx_pwr=""
    ):
        """Set the tx channel and power of the radios of a specific IAP.

        Keyword Arguments:
            iap_ip {str} -- IPv4 address of the IAP (default: {''})
            a_chan_name {str} -- Name of the desired channel [32, 32+, 32E,...] (default: {''})
            a_tx_pwr {str} -- Tx power level [-51...51] (default: {''})
            g_chan_name {str} -- Name of the desired channel [1...14, 1+...13+] (default: {''})
            g_tx_pwr {str} -- Tx power level [-51...51] (default: {''})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/channel"
        data = json.dumps(
            {
                "iap_ip_addr": iap_ip,
                "channel": {
                    "a-channel": {"channel_name": a_chan_name, "tx_power": a_tx_pwr},
                    "g-channel": {"channel_name": g_chan_name, "tx_power": g_tx_pwr},
                },
            }
        )
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def antenna_gain(self, iap_ip="", a_ext_gain="", g_ext_gain=""):
        """Set the specific antenna gain when external antennas are used.

        Keyword Arguments:
            iap_ip {str} -- IPv4 address of the IAP (default: {''})
            a_ext_gain {str} -- Set gain of external antenna [6, 14] (default: {''})
            g_ext_gain {str} -- Set gain of external antenna [6, 14] (default: {''})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/antenna-gain"
        data = json.dumps(
            {
                "iap_ip_addr": iap_ip,
                "antenna_gain_info": {
                    "a-external-antenna": a_ext_gain,
                    "g-external-antenna": g_ext_gain,
                },
            }
        )
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def radio_state(self, iap_ip="", a_radio_disabled="", g_radio_disabled=""):
        """Enable or disable a radio in an AP.

        Keyword Arguments:
            iap_ip {str} -- IPv4 address of the IAP (default: {''})
            a_radio_disabled {str} -- Disable radio [yes, no] (default: {''})
            g_radio_disabled {str} -- Disable radio [yes, no] (default: {''})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/radio-state"
        data = json.dumps(
            {
                "iap_ip_addr": iap_ip,
                "radio_state": {
                    "dot11a-radio-disable": a_radio_disabled,
                    "dot11g-radio-disable": g_radio_disabled,
                },
            }
        )
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def vc_country_code(self, template="vc_country_code_template.json"):
        """Set the virtual controller country code.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'vc_country_code_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/country-code"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def vc_ip(self, template="vc_ip_template.json"):
        """Set the IP of the virtual controller.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'vc_ip_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/virtual-controller-ip"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def ntp(self, template="ntp_template.json"):
        """Set the NTP server of the virtual controller.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'ntp_template.json'})

        Returns:
            dict -- Json formatted response from VC

        """
        url = f"{self.baseurl}/ntp-server"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def syslocation(self, template="syslocation_template.json"):
        """Set the syslocation of the virtual controller.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'syslocation_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/syslocation"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def organization(self, template="organization_template.json"):
        """Set the virtual controller organization.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'organization_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/organization"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def syslog_level(self, template="syslog_level_template.json"):
        """Set the syslog level for the virtual controller.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'syslog_level_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/syslog-level"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def syslog_server(self, template="syslog_server_template.json"):
        """Set the destination IP for syslog traffic from the virtual controller.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'syslog_server_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/syslog-server"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def radio_11g(self, template="radio_11g_template.json"):
        """Configure a radio profile for the 2.4GHz antenna.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'radio_11g_template.json'})

        Raises:
            ValueError: [description]

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/radio-profile-11g"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def radio_11a(self, template="radio_11a_template.json"):
        """Configure a radio profile for the 5GHz antenna.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'radio_11a_template.json'})

        Returns:
            dict -- Json formmated response from VC
        """
        url = f"{self.baseurl}/syslog-server"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def arm(self, template="arm_template.json"):
        """Configure an ARM profile for use by the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'arm_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/arm"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def ssid(self, template="ssid_template.json"):
        """Configure an SSID profile for use by the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'ssid_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/ssid"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def rf_band(self, template="rf_band_template.json"):
        """Configure an RF Band (2.4, 5, all) profile for use by the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'rf_band_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/rf-band"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def auth_server(self, template="auth_server_template.json"):
        """Configure an authentication server (RADIUS) for the virtual controller.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'auth_server_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/auth-server"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def acl(self, template="acl_template.json"):
        """Configure an ACL profile for use by the Intant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'acl_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/acl-rules"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def ext_captive_portal(self, template="external_captive_portal_template.json"):
        """Configure an External Captive Portal profile for use by the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'external_captive_portal_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/ext-captive-portal-profile"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def ids(self, template="ids_template.json"):
        """Configure an IDS profile for use by the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'ids_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/ids"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def os_upgrade(self, template="os_upgrade_template.json"):
        """Initiate an OS Upgrade of the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'os_upgrade_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/os-upgrade"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def clock(self, template="clock_template.json"):
        """Set clock and timezone of the virtual controller.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'clock_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/clock"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def ap_reboot(self, template="ap_reboot_template.json"):
        """Initiate a reboot of a single or all APs in the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'ap_reboot_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/reboot"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def wired_port(self, template="wired_port_template.json"):
        """Configure a wired port profile for use by the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'wired_port_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/wired-port-profile"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def wired_profile_map(self, template="wired_profile_map_template.json"):
        """Configure a wired profile to port mapping for use by the Instant cluster.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'wired_profile_map_template.json'})

        Raises:
            ValueError: [description]

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/wired-profile-map"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )

    @autologin
    def mgmt_user(self, template="mgmt_user_template.json"):
        """Configure management users on the virtual controller.

        Keyword Arguments:
            template {str} -- Name of template file (default: {'mgmt_user_template.json'})

        Returns:
            dict -- Json formatted response from VC
        """
        url = f"{self.baseurl}/mgmt-user"
        with open(self.template_basepath + template, "r") as f:
            data = f.read()
        response = self.session.post(
            url,
            headers=self.headers,
            params=self.params,
            data=data,
            verify=self.ssl_verify,
        )
        if response.json().get("Status-code") == 0:
            return response.json()
        elif response.json().get("Status-code") != 0:
            raise ValueError(
                f"Error Code: {response.json().get('Status-code')} - {response.json().get('message')}"
            )
