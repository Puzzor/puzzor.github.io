---
published: true
categories: [vulnerability,Linksys]
tags: [Linksys Velop information leak]
---

### Affected Software
The firmware version which I test is 1.1.2.185309
### Product Background
Velop is WHOLE HOMEMESH Wi-Fi system from LINKSYS. It allows users enjoy fast, nonstop Wi-Fi everywhere with Velop’s modular easy-to-use Wi-Fi Mesh system.
There are three categories from their official site :WHW0303,WHW0302,WHW0301. The differences between these three is the pack count: 1, 2 or 3. The system are the same.
### Vulnerability Details
Since the vendor marked this issue as wont fix, so this is only a risk.

There are many information leak problems, one of them is through /sysinfo_json.cgi, requesting this url will leak sensitive information and may lead to authentication bypass.

The Linksys APP will use JNAP to communicate with the router, and  there are many kinds of X-JNAP-Action can be made to request the router, we found the router can handle many actions without authentication. A sample request can be :
~~~http
POST /JNAP/ HTTP/1.1
Host: 192.168.1.1
Accept: application/json; charset=UTF-8
Expires: Fri, 10 Oct 2015 14:19:41 GMT
Accept-Encoding: gzip, deflate
Accept-Language: zh-Hans-CN;q=1, en-CN;q=0.9
Cache-Control: no-cache
Content-Type: application/json; charset=UTF-8
Content-Length: 2
User-Agent: Linksys/2.5.2 (iPhone; iOS 11.2.6; Scale/3.00)
Connection: close
X-JNAP-Action: http://linksys.com/jnap/devicelist/GetDevices

{}
~~~

#### PoC

Beyond action of http://linksys.com/jnap/devicelist/GetDevices , the following actions can be also made without authentication, some of them need parameters while the others not:

- nodes/smartconnect/GetSlaveSetupStatus (TBD see if there is useful information)
- nodes/smartconnect/SmartConnectConfigure (possible RCE)
- firmwareupdate/GetFirmwareUpdateStatus (nothing useful)
- dynamicportforwarding/GetDynamicIPv6ConnectionRules(get ipv6 rules)
- dynamicportforwarding/GetDynamicPortRangeForwardingRules (get forwarding rules)
- dynamicportforwarding/GetDynamicSinglePortForwardingRules (get forwarding rules)
- routerstatus/GetHeartbeatInterval  (nothing useful)
- nodes/setup/GetSerialNumber (TBD serial number may be used to calulate somethin, not sure)
- nodes/setup/GetWANDetectionStatus (some WAN detection status, not too much useful)
- nodes/setup/IsAdminPasswordSetByUser (get to know if users have set ADMIN password)
- nodes/setup/SetAdminPassword(2018.04.04 not useful,reset code cannot be bruteforced)
- nodes/setup/VerifyRouterResetCode(2018.04.04 cannot be bruteforced,10 times limit)
- devicelist/GetDevices(lot of information, such as deviceID,serialNumber,firmwareVersion,isAuthority and so on)
- devicelist/GetDevices3(lot of information, such as deviceID,serialNumber,firmwareVersion,isAuthority and so on)
- devicelist/GetLocalDevice (get deviceID)
- nodes/smartmode/GetDeviceMode(get to know what type of current node it is, like master of slave)
- qos/GetLANQoSSettings (get QoS setting)
- qos/GetQoSSettings (get QoS setting)
- qos/GetQoSSettings2 (get QoS setting)
- qos/GetWLANQoSSettings(get QoS setting)
- routermanagement/GetManagementSettings (get management settings)
- routermanagement/GetManagementSettings2 (get management settings, such as canManageUsingHTTP,canManageUsingHTTPS, isManageWirelesslySupported,canManageWirelessly,canManageRemotely)
- routermanagement/GetRemoteManagementStatus(remote management status)
- httpproxy/RemoveHttpProxyRule(remove a HTTP proxy rule by providing a ruleUUID)
- locale/GetLocalTime (get time)
- locale/GetTimeSettings(get time settings, like timezone,autoAdjustForDST and others)
- ui/GetCloudServerStatus (get to know if current node is accessable to the cloud)
- ui/GetRemoteSetting (get to know if it is enabled)
- ui/SetRemoteSetting(set if it is able to get remote setting)
- wirelessap/GetAdvancedRadioInfo (wireless info, not much useful info)
- wirelessap/GetWPSServerSettings(if the WPS is enabled)
- wirelessap/IsWPSServerAvailable(TBD if WPS server is enabled, not clear what is it)
- routerleds/GetRouterLEDSettings(wireless LED setting)
- ownednetwork/GetOwnedNetworkID(TBD get ownedNetworkID, may be useful)
- core/GetAdminPasswordHint(not too much useful)
- core/GetAdminPasswordRestrictions(not too much useful)
- core/GetDataUploadUserConsent (false by default)
- core/GetDeviceInfo(router info, such as serialNumber,firmwareVersion,hardwareVersion,services)
- core/GetUnsecuredWiFiWarning(not too much useful)
- core/IsAdminPasswordDefault(get to know if users have set ADMIN password)
- core/IsRecoveryCodeProvided(nothing special)
- core/IsServiceSupported(check whether a service is available)
- core/SetUnsecuredWiFiWarning(not too much useful)
- parentalcontrol/GetParentalControlSettings(get to know parent control setting)
- diagnostics/GetDiagnosticsSettings(not too much useful)
- networkconnections/GetNetworkConnections(not too much useful)
- router/GetWANStatus2(not too much useful)
- guestnetwork/GetGuestNetworkClients(get guest network clients)
- guestnetwork/GetGuestNetworkSettings2(guest network settings)
- routerlog/GetDHCPLogEntries(get DHCP log)
- routerlog/GetIncomingLogEntries(get incoming log)
- routerlog/GetOutgoingLogEntries(get outgoin log)
- routerlog/GetSecurityLogEntries(get security log)
- routerlog/GetLogSettings(log setting)
- wirelessscheduler/GetWirelessSchedulerSettings(wireless scheduler settings)
- guestnetwork/Authenticate(TBD interesting, dont know if we can brute force it or there will be vulnerability)
- dynamicsession/GetDynamicSessionInfo(dynamic session info)
- dynamicsession/GetDynamicSessions(dynamic session info)
- ddns/GetDDNSStatus(ddns status)
- ddns/GetDDNSStatus2(ddns status)
- ddns/GetSupportedDDNSProviders(not too much useful)
- router/GetDHCPClientLeases(not too much useful)
- router/GetEthernetPortConnections(not too much useful)
- router/GetExpressForwardingSettings(not too much useful)
- router/GetIPv6Settings(ipv6 settings)
- router/GetIPv6Settings2(ipv6 settings)
- router/GetLANSettings(lan info)
- router/GetMACAddressCloneSettings(MAC clone settings)
- router/GetRoutingSettings(route settings)
- router/GetStaticRoutingTable(routing table)
- router/GetWANStatus(WAN status)
- router/GetWANStatus3(WAN status)
- routerupnp/GetUPnPSettings(UPnP settings)
- firewall/GetALGSettings(ALG settings, but what is ALG?)
- firewall/GetDMZSettings(DMZ Settings)
- firewall/GetFirewallSettings(Firewall settings)
- firewall/GetIPv6FirewallRules(Firewall settings)
- firewall/GetPortRangeForwardingRules(port forward)
- firewall/GetPortRangeTriggeringRules(port rules)
- firewall/GetSinglePortForwardingRules(port formward)



### Timeline

2018-03-04: Discovered
2019-02-05: Reported and the vendor marked this issue wont fix
