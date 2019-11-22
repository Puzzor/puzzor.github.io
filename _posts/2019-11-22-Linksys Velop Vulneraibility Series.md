---
published: true
categories: [vulnerability,Linksys]
tags: [Linksys Velop Command Injection]
---

### Introduction
I was auditing Linksys Velop router before and this post will summarize the previous findings on this router. 

I totally found 4 vulnerbilities in this router, 3 of them are critical which allow the attacker in the LAN to gain admin right without authentication, 1 is information disclosure problem which the vendor think riskless and wont fix.

The following posts will describe them in detail, all the bugs have been reported to the vendor and should be fixed now.

### Links
#### Risk 1(Critical): [Linksys Velop configapssid Command Injection With Preauth](https://puzzor.github.io/Linksys-Velop-configApSsid-command-injection-with-preauth)

No CVE

There is a command injection vulnerability through JNAP action of http://linksys.com/jnap/nodes/smartconnect/SmartConnectConfigure , the vulneraibility may lead to RCE without authentication.

**Timeline**

2018-03-04: Discovered

2019-02-05: Reported, but the vendor has already fixed

#### Risk 2(Critical): [Linksys Velop Authentication Bypass](https://puzzor.github.io/Linksys-Velop-Authentication-bypass)

[CVE-2019-16340](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16340)

A critical authentication bypass bug is found in the firmware and this vulnerability may allow an unauthenticated user get administrator privilege. The problem is caused by the API of **/sysinfo_json.cgi**, requesting this url will leak sensitive information and may lead to authentication bypass.

**Timeline**

25 Feb 2019 03:07:55 UTC: Submitted the problem to vendor

23 Aug 2019 21:01:30 UTC: Fixed && CVE assigned: [CVE-2019-16340](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16340)

#### Risk 3(Critical): [Linksys Velop zbtest Command Injection With Preauth](https://puzzor.github.io/Linksys-Velop-zbtest-command-injection)

CVE-2018-17208 (Although I found this bug independently, another researcher had reported it first, so this CVE doesn't belong to me)

There are a few command injection flaws in /cgi-bin/zbtest.cgi which may lead to RCE without any authentication.

**Timeline**

2018.04.04: Found the bug

2018-09-19: Another researcher published the bug with link: (link)[https://langkjaer.com/velop.html]

#### Risk 4(Won't Fix): [Linksys Velop Information Disclosure](https://puzzor.github.io/Linksys-Velop-Information-Leak)

No CVE

The Linksys APP will use JNAP to communicate with the router, and  there are many kinds of X-JNAP-Action can be made to request the router, we found the router can handle many actions without authentication. Since the vendor think this riskless and wontfix, this may be still in the latest firmware

**Timeline**

2018-03-04: Discovered

2019-02-05: Reported and the vendor marked this issue wont fix