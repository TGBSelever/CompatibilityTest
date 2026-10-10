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
        },
        Checks = {},
    }
    local function check(name, fn, reverse)
        results.Total = results.Total + 1
        if not reverse then
        if fn ~= nil then
            results.Passed = results.Passed + 1
            results.Checks[name] = {check=name,suc=true}
            return true
        else
            table.insert(results.Missing, name)
            results.Checks[name] = {check=name,suc=false}
            return false
        end
        else
        if fn == nil then
            results.Passed = results.Passed + 1
            results.Checks[name] = {check=name,suc=true}
            return true
        else
            table.insert(results.Missing, name)
            results.Checks[name] = {check=name,suc=false}
            return false
        end
        end
    end
    local c_inval = cache and check("cache.invalidate", cache.invalidate) or check("cache.invalidate", nil)
    local c_iscached = cache and check("cache.iscached", cache.iscached) or check("cache.iscached", nil)
    local c_replace = cache and check("cache.replace", cache.replace) or check("cache.replace", nil)
    local c_cloneref = check("cloneref", cloneref)
    local c_compare = check("compareinstances", compareinstances)
    results.Capabilities.Cache = (c_inval and c_iscached and c_replace and c_cloneref and c_compare)

    local cl_caller = check("checkcaller", checkcaller)
    local cl_clone = check("clonefunction", clonefunction)
    local cl_isc = check("iscclosure", iscclosure)
    local cl_isl = check("islclosure", islclosure)
    local cl_newc = check("newcclosure", newcclosure)
    local cl_script = check("getscriptclosure", getscriptclosure or get_script_function)
    results.Capabilities.Closure = (cl_caller and cl_clone and cl_isc and cl_isl and cl_newc and cl_script)

    if crypt then
        local cr_b64e = check("crypt.base64encode", crypt.base64encode) or check("crypt.base64_encode", crypt.base64_encode)
        local cr_b64d = check("crypt.base64decode", crypt.base64decode) or check("crypt.base64_decode", crypt.base64_decode)
        local cr_enc = check("crypt.encrypt", crypt.encrypt)
        local cr_dec = check("crypt.decrypt", crypt.decrypt)
        local cr_hash = check("crypt.hash", crypt.hash)
        local cr_bytes = check("crypt.generatebytes", crypt.generatebytes)
        local cr_key = check("crypt.generatekey", crypt.generatekey)
        results.Capabilities.Cryptography = (cr_b64e and cr_b64d and cr_enc and cr_dec and cr_hash and cr_bytes and cr_key)
    else
        check("crypt.base64encode", nil) check("crypt.base64decode", nil) check("crypt.encrypt", nil)
        check("crypt.decrypt", nil) check("crypt.hash", nil) check("crypt.generatebytes", nil) check("crypt.generatekey", nil)
    end

    if debug then
        local d_getcon = check("debug.getconstants", debug.getconstants)
        local d_setcon = check("debug.setconstant", debug.setconstant)
        local d_getup = check("debug.getupvalues", debug.getupvalues)
        local d_setup = check("debug.setupvalue", debug.setupvalue)
        local d_getst = check("debug.getstack", debug.getstack)
        local d_setst = check("debug.setstack", debug.setstack)
        local d_getpr = check("debug.getprotos", debug.getprotos)
        local d_getinfo = check("debug.getinfo", debug.getinfo)
        results.Capabilities.Debug = (d_getcon and d_setcon and d_getup and d_setup and d_getst and d_setst and d_getpr and d_getinfo)
    else
        check("debug.getconstants", nil) check("debug.setconstant", nil) check("debug.getupvalues", nil)
        check("debug.setupvalue", nil) check("debug.getstack", nil) check("debug.setstack", nil)
        check("debug.getprotos", nil) check("debug.getinfo", nil)
    end

    if Drawing then
        local dr_new = check("Drawing.new", Drawing.new)
        local dr_cache = check("cleardrawcache", cleardrawcache)
        local dr_isobj = check("isrenderobj", isrenderobj)
        results.Capabilities.Drawing = (dr_new and dr_cache and dr_isobj)
    else
        check("Drawing.new", nil) check("cleardrawcache", nil) check("isrenderobj", nil)
    end

    local fs_read = check("readfile", readfile)
    local fs_write = check("writefile", writefile)
    local fs_app = check("appendfile", appendfile)
    local fs_isf = check("isfile", isfile)
    local fs_isfo = check("isfolder", isfolder)
    local fs_make = check("makefolder", makefolder)
    local fs_list = check("listfiles", listfiles)
    local fs_delf = check("delfile", delfile)
    local fs_delfo = check("delfolder", delfolder)
    local fs_genv = check("getgenv", getgenv)
    local fs_fenv = check("getfenv", getfenv)
    local fs_renv = check("getrenv", getrenv)
    local fs_reg = check("getreg", getreg or getregistry)
    local fs_ast = check("getcustomasset", getcustomasset)
    results.Capabilities.Filesystem = (fs_ast and fs_read and fs_write and fs_app and fs_isf and fs_isfo and fs_make and fs_list and fs_delf and fs_delfo and fs_genv and fs_fenv and fs_renv and fs_reg)

    local h_fn = check("hookfunction", hookfunction)
    local h_meta = check("hookmetamethod", hookmetamethod)
    local h_name = check("getnamecallmethod", getnamecallmethod)
    local h_setname = check("setnamecallmethod", setnamecallmethod)
    results.Capabilities.Hooking = (h_fn and h_meta and h_name and h_setname)

    local i_nil = check("getnilinstances", getnilinstances)
    local i_instances = check("getinstances", getinstances)
    local i_gc = check("getgc", getgc)
    local i_scripts = check("getscripts", getscripts)
    local i_loaded = check("getloadedmodules", getloadedmodules)
    local i_hidden = check("gethiddenproperty", gethiddenproperty)
    local i_sethidden = check("sethiddenproperty", sethiddenproperty)
    local i_save = check("saveinstance", saveinstance)
    results.Capabilities.Instances = (i_nil and i_instances and i_gc and i_scripts and i_loaded and i_hidden and i_sethidden and i_save)

    local n_conn = check("getconnections", getconnections or get_signal_cons)
    local n_fire = check("firesignal", firesignal or fire_replicate_signal)
    local n_click = check("fireclickdetector", fireclickdetector)
    local n_prox = check("fireproximityprompt", fireproximityprompt)
    local n_touch = check("firetouchinterest", firetouchinterest)
    results.Capabilities.Networking = (n_conn and n_fire and n_click and n_prox and n_touch)

    local co_print = check("rconsoleprint", rconsoleprint or rprint)
    local co_clear = check("rconsoleclear", rconsoleclear or rclear)
    local co_name = check("rconsolename", rconsolename or rsettitle)
    local co_input = check("rconsoleinput", rconsoleinput)

    local m_load = check("loadstring", loadstring)
    local m_id = check("identifyexecutor", identifyexecutor or getexecutorname)
    local m_clip = check("setclipboard", setclipboard or toclipboard)
    local m_req = check("request", request or http.request or http_request)
    local m_hwid = check("gethwid", gethwid)
    local m_req = check("require", require)
    local m_con = check("const",const)
    local m_game = check("game",game)
    local m_service = check("GetService", game:GetService("Players"))
    results.Capabilities.Miscellaneous = (m_load and m_id and m_clip and m_req and m_hwid and m_con and m_game and m_service)

    local er_1 = check("xyz (SHOULD ERROR)",xyz,true)
    local er_2 = check("fire (SHOULD ERROR)",fire,true)
    local er_3 = check("delete (SHOULD ERROR)",delete,true)
    results.Capabilities.FalseChecks = (er_1 and er_2 and er_3)

    results.Percentage = math.floor((results.Passed / results.Total) * 100)
    return results
