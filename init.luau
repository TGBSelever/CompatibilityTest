local results = {
    Passed = 0,
    Total = 0,
    Missing = {},
    Capabilities = {
        Filesystem = false,
        Hooking = false,
        Drawing = false,
        Debug = false,
        Network = false,
        Closure = false,
        Cryptography = false,
        Instances = false,
        Networking = false,
        Miscellaneous = false,
        FalseChecks = false
    },
    Checks = {},
}

local function runCheck(name, fn, reverse)
    results.Total = results.Total + 1
    if not reverse then
        if fn ~= nil then
            results.Passed = results.Passed + 1
            results.Checks[name] = {check = name, suc = true}
            return true
        else
            table.insert(results.Missing, name)
            results.Checks[name] = {check = name, suc = false}
            return false
        end
    else
        if fn == nil then
            results.Passed = results.Passed + 1
            results.Checks[name] = {check = name, suc = false}
            return true
        else
            table.insert(results.Missing, name)
            results.Checks[name] = {check = name, suc = true}
            return false
        end
    end
end

local c_inval = cache and runCheck("cache.invalidate", cache.invalidate) or runCheck("cache.invalidate", nil)
local c_iscached = cache and runCheck("cache.iscached", cache.iscached) or runCheck("cache.iscached", nil)
local c_replace = cache and runCheck("cache.replace", cache.replace) or runCheck("cache.replace", nil)
local c_cloneref = runCheck("cloneref", cloneref)
local c_compare = runCheck("compareinstances", compareinstances)
results.Capabilities.Cache = (c_inval and c_iscached and c_replace and c_cloneref and c_compare)

local cl_caller = runCheck("checkcaller", checkcaller)
local cl_clone = runCheck("clonefunction", clonefunction)
local cl_isc = runCheck("iscclosure", iscclosure)
local cl_isl = runCheck("islclosure", islclosure)
local cl_newc = runCheck("newcclosure", newcclosure)
local cl_script = runCheck("getscriptclosure", getscriptclosure or get_script_function)
results.Capabilities.Closure = (cl_caller and cl_clone and cl_isc and cl_isl and cl_newc and cl_script)

if crypt then
    local cr_b64e = runCheck("crypt.base64encode", crypt.base64encode) or runCheck("crypt.base64_encode", crypt.base64_encode)
    local cr_b64d = runCheck("crypt.base64decode", crypt.base64decode) or runCheck("crypt.base64_decode", crypt.base64_decode)
    local cr_enc = runCheck("crypt.encrypt", crypt.encrypt)
    local cr_dec = runCheck("crypt.decrypt", crypt.decrypt)
    local cr_hash = runCheck("crypt.hash", crypt.hash)
    local cr_bytes = runCheck("crypt.generatebytes", crypt.generatebytes)
    local cr_key = runCheck("crypt.generatekey", crypt.generatekey)
    results.Capabilities.Cryptography = (cr_b64e and cr_b64d and cr_enc and cr_dec and cr_hash and cr_bytes and cr_key)
else
    runCheck("crypt.base64encode", nil) runCheck("crypt.base64decode", nil) runCheck("crypt.encrypt", nil)
    runCheck("crypt.decrypt", nil) runCheck("crypt.hash", nil) runCheck("crypt.generatebytes", nil) runCheck("crypt.generatekey", nil)
end

if debug then
    local d_getcon = runCheck("debug.getconstants", debug.getconstants)
    local d_setcon = runCheck("debug.setconstant", debug.setconstant)
    local d_getup = runCheck("debug.getupvalues", debug.getupvalues)
    local d_setup = runCheck("debug.setupvalue", debug.setupvalue)
    local d_getst = runCheck("debug.getstack", debug.getstack)
    local d_setst = runCheck("debug.setstack", debug.setstack)
    local d_getpr = runCheck("debug.getprotos", debug.getprotos)
    local d_getinfo = runCheck("debug.getinfo", debug.getinfo)
    results.Capabilities.Debug = (d_getcon and d_setcon and d_getup and d_setup and d_getst and d_setst and d_getpr and d_getinfo)
else
    runCheck("debug.getconstants", nil) runCheck("debug.setconstant", nil) runCheck("debug.getupvalues", nil)
    runCheck("debug.setupvalue", nil) runCheck("debug.getstack", nil) runCheck("debug.setstack", nil)
    runCheck("debug.getprotos", nil) runCheck("debug.getinfo", nil)
end

if Drawing then
    local dr_new = runCheck("Drawing.new", Drawing.new)
    local dr_cache = runCheck("cleardrawcache", cleardrawcache)
    local dr_isobj = runCheck("isrenderobj", isrenderobj)
    results.Capabilities.Drawing = (dr_new and dr_cache and dr_isobj)
else
    runCheck("Drawing.new", nil) runCheck("cleardrawcache", nil) runCheck("isrenderobj", nil)
end

local fs_read = runCheck("readfile", readfile)
local fs_write = runCheck("writefile", writefile)
local fs_app = runCheck("appendfile", appendfile)
local fs_isf = runCheck("isfile", isfile)
local fs_isfo = runCheck("isfolder", isfolder)
local fs_make = runCheck("makefolder", makefolder)
local fs_list = runCheck("listfiles", listfiles)
local fs_delf = runCheck("delfile", delfile)
local fs_delfo = runCheck("delfolder", delfolder)
local fs_genv = runCheck("getgenv", getgenv)
local fs_fenv = runCheck("getfenv", getfenv)
local fs_renv = runCheck("getrenv", getrenv)
local fs_reg = runCheck("getreg", getreg or getregistry)
local fs_ast = runCheck("getcustomasset", getcustomasset)
results.Capabilities.Filesystem = (fs_ast and fs_read and fs_write and fs_app and fs_isf and fs_isfo and fs_make and fs_list and fs_delf and fs_delfo and fs_genv and fs_fenv and fs_renv and fs_reg)

local h_fn = runCheck("hookfunction", hookfunction)
local h_meta = runCheck("hookmetamethod", hookmetamethod)
local h_name = runCheck("getnamecallmethod", getnamecallmethod)
local h_setname = runCheck("setnamecallmethod", setnamecallmethod)
results.Capabilities.Hooking = (h_fn and h_meta and h_name and h_setname)

local i_nil = runCheck("getnilinstances", getnilinstances)
local i_instances = runCheck("getinstances", getinstances)
local i_gc = runCheck("getgc", getgc)
local i_scripts = runCheck("getscripts", getscripts)
local i_loaded = runCheck("getloadedmodules", getloadedmodules)
local i_hidden = runCheck("gethiddenproperty", gethiddenproperty)
local i_sethidden = runCheck("sethiddenproperty", sethiddenproperty)
local i_save = runCheck("saveinstance", saveinstance)
results.Capabilities.Instances = (i_nil and i_instances and i_gc and i_scripts and i_loaded and i_hidden and i_sethidden and i_save)

local n_conn = runCheck("getconnections", getconnections or get_signal_cons)
local n_fire = runCheck("firesignal", firesignal or fire_replicate_signal)
local n_click = runCheck("fireclickdetector", fireclickdetector)
local n_prox = runCheck("fireproximityprompt", fireproximityprompt)
local n_touch = runCheck("firetouchinterest", firetouchinterest)
results.Capabilities.Networking = (n_conn and n_fire and n_click and n_prox and n_touch)

runCheck("rconsoleprint", rconsoleprint or rprint)
runCheck("rconsoleclear", rconsoleclear or rclear)
runCheck("rconsolename", rconsolename or rsettitle)
runCheck("rconsoleinput", rconsoleinput)

local m_load = runCheck("loadstring", loadstring)
local m_id = runCheck("identifyexecutor", identifyexecutor or getexecutorname)
local m_clip = runCheck("setclipboard", setclipboard or toclipboard)
local m_req = runCheck("request", request or http.request or http_request)
local m_hwid = runCheck("gethwid", gethwid)
local m_require = runCheck("require", require)
local m_const = runCheck("const", true) -- FIXED: Removed buggy special symbols from name key
local m_game = runCheck("game", game)
local m_service = runCheck("getservice", game:GetService("Players"))
results.Capabilities.Miscellaneous = (m_load and m_id and m_clip and m_req and m_hwid and m_const and m_game and m_service)

local er_1 = runCheck("xyz", xyz, true)
local er_2 = runCheck("fire", fire, true)
local er_3 = runCheck("delete", delete, true)
results.Capabilities.FalseChecks = (er_1 and er_2 and er_3)

results.Percentage = math.floor((results.Passed / results.Total) * 100)

return results
