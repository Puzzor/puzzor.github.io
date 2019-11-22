---
published: false
categories: [vulnerability,Linksys]
tags: [Linksys Velop Command Injection]
---

### Introduction
I was auditing Linksys Velop router before and this post will summarize the previous findings on this router. 

I total found 4 security risk in this router, 3 of them are critical which may let attacker in the same LAN gain admin right without authentication, 1 is information disclosure problem which the vendor think riskless and wont fix.

The following posts will describe them in details, all the bugs have been reported to the vendor and should be fixed now.

### Links
#### Risk 1: Linksys Velop command injection with preauth

There is a command injection vulnerability through JNAP action of http://linksys.com/jnap/nodes/smartconnect/SmartConnectConfigure , the vulneraibility may lead to RCE without authentication.

Timeline

2018-03-04: Discovered

2019-02-05: Reported, but the vendor has already fixed

#### Risk 2: Linksys Velop authentication bypass

CVE-2019-16340

A critical authentication bypass bug is found in the firmware and this vulnerability may allow an unauthenticated user get administrator privilege. The problem is caused by the API of **/sysinfo_json.cgi**, requesting this url will leak sensitive information and may lead to authentication bypass.

Timeline

25 Feb 2019 03:07:55 UTC: Submitted the problem to vendor

23 Aug 2019 21:01:30 UTC: Fixed && CVE assigned: CVE-2019-16340

#### Risk 3: Linksys Velop command injection with preauth

CVE-2018-17208 (Although I found this bug independently, another researcher had reported it first, so this CVE dont belong to me)

There are a few command injection flaws in /cgi-bin/zbtest.cgi which may lead to RCE without any authentication.

Timeline

2018.04.04: Found the bug

2018-09-19: Another researcher published the bug with link: (link)[https://langkjaer.com/velop.html]
