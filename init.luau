 local results = {
        Passed = 0,
        Total = 0,
        Missing = {},
        Capabilities = {
            Filesystem = false,
            Hooking = false,
            Drawing = false,
            Debug = false,
            Network = false
        }
    }
    local function check(name, fn)
        results.Total = results.Total + 1
        if fn ~= nil then
            results.Passed = results.Passed + 1
            return true
        else
            table.insert(results.Missing, name)
            return false
        end
    end
    local hasWrite = check("writefile", writefile)
    local hasRead  = check("readfile", readfile)
    local hasFolder = check("makefolder", makefolder)
    results.Capabilities.Filesystem = (hasWrite and hasRead and hasFolder)
    local hasHookFn = check("hookfunction", hookfunction)
    local hasHookMeta = check("hookmetamethod", hookmetamethod)
    local hasCaller = check("checkcaller", checkcaller)
    results.Capabilities.Hooking = (hasHookFn and hasHookMeta and hasCaller)
    if Drawing then
        local hasDraw = check("Drawing.new", Drawing.new)
        results.Capabilities.Drawing = hasDraw
    else
        check("Drawing Library", nil)
    end
    if debug then
        local hasUpvalue = check("debug.setupvalue", debug.setupvalue)
        local hasConstant = check("debug.setconstant", debug.setconstant)
        results.Capabilities.Debug = (hasUpvalue and hasConstant)
    else
        check("Debug Library", nil)
    end
    local hasGetConn = check("getconnections", getconnections or get_signal_cons)
    local hasFireSig = check("firesignal", firesignal or fire_replicate_signal)
    local hasRequest = check("request", request or http.request)
    results.Capabilities.Network = (hasGetConn and hasFireSig and hasRequest)
    results.Percentage = math.floor((results.Passed / results.Total) * 100)
    return results
