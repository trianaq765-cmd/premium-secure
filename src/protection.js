// ============================================================
// 🛡️ PROTECTION MODULE v4.3.0 - FIXED (Less False Positives)
// ============================================================

const crypto = require('crypto');

function randomVar(prefix = '_') {
    return prefix + crypto.randomBytes(4).toString('hex');
}

function generateChecksum(script) {
    return crypto.createHash('sha256').update(script).digest('hex').substring(0, 16);
}

// ============================================================
// 🔒 GENERATE PROTECTED SCRIPT
// ============================================================

function generateProtectedScript(originalScript, options = {}) {
    const {
        sessionToken = crypto.randomBytes(16).toString('hex'),
        timestamp = Date.now(),
        clientIP = 'unknown',
        hwid = null,
        playerId = null,
        banEndpoint = ''
    } = options;

    // Generate unique variable names
    const v = {
        main: randomVar('_M'),
        tools: randomVar('_T'),
        detect: randomVar('_D'),
        kick: randomVar('_K'),
        exec: randomVar('_E'),
        decode: randomVar('_DC'),
        chunks: randomVar('_CH'),
        http: randomVar('_H'),
        hwid: randomVar('_HW'),
        loop: randomVar('_LP'),
        run: randomVar('_R'),
        gui: randomVar('_G'),
        check: randomVar('_C'),
    };

    // Encode script to chunks
    const scriptChunks = [];
    const chunkSize = 400;
    for (let i = 0; i < originalScript.length; i += chunkSize) {
        const chunk = originalScript.substring(i, i + chunkSize);
        const encoded = Buffer.from(chunk).toString('base64');
        scriptChunks.push(encoded);
    }

    const protectedScript = `
--[[
    🛡️ Protected Script v4.3
    Less aggressive detection - only real tools
]]

local ${v.main} = (function()
    -- Core references
    local game = game
    local pcall = pcall
    local type = type
    local typeof = typeof
    local tostring = tostring
    local table = table
    local string = string
    local tick = tick
    local wait = task and task.wait or wait
    local spawn = task and task.spawn or spawn
    local pairs = pairs
    local ipairs = ipairs
    local loadstring = loadstring
    local getfenv = getfenv
    local rawget = rawget
    
    -- Services
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local RunService = game:GetService("RunService")
    
    local LocalPlayer = Players.LocalPlayer
    local BAN_ENDPOINT = "${banEndpoint}"
    local HWID = nil
    
    -- ============================================================
    -- 🔧 UTILITY FUNCTIONS
    -- ============================================================
    
    -- Get HWID
    local function ${v.hwid}()
        if HWID then return HWID end
        pcall(function()
            HWID = (gethwid and gethwid()) or
                   (get_hwid and get_hwid()) or
                   (getexecutorname and getexecutorname() .. "_" .. tostring(LocalPlayer.UserId)) or
                   (identifyexecutor and identifyexecutor() .. "_" .. tostring(LocalPlayer.UserId)) or
                   ("EX_" .. tostring(LocalPlayer.UserId))
        end)
        return HWID or "UNKNOWN"
    end
    
    -- HTTP Request
    local function ${v.http}(url, data)
        pcall(function()
            local request = (syn and syn.request) or 
                           (http and http.request) or 
                           request or 
                           (fluxus and fluxus.request) or 
                           http_request
            
            if request then
                request({
                    Url = url,
                    Method = "POST",
                    Headers = {["Content-Type"] = "application/json"},
                    Body = HttpService:JSONEncode(data)
                })
            end
        end)
    end
    
    -- Kick & Ban
    local function ${v.kick}(reason, toolsFound)
        -- Send ban to server
        pcall(function()
            if BAN_ENDPOINT and BAN_ENDPOINT ~= "" then
                ${v.http}(BAN_ENDPOINT, {
                    hwid = ${v.hwid}(),
                    playerId = LocalPlayer.UserId,
                    playerName = LocalPlayer.Name,
                    reason = reason,
                    toolsDetected = toolsFound or {}
                })
            end
        end)
        
        -- Show notification
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⛔ Security Violation",
                Text = reason,
                Duration = 5
            })
        end)
        
        wait(0.3)
        
        -- Kick player
        pcall(function()
            LocalPlayer:Kick("\\n⛔ SECURITY VIOLATION\\n\\n" .. reason .. "\\n\\nYou have been banned.")
        end)
    end
    
    -- ============================================================
    -- 🔍 TOOL DETECTION - ONLY REAL TOOLS, NOT EXECUTOR FUNCTIONS
    -- ============================================================
    
    local ${v.tools} = {
        -- ✅ Only detect actual tool instances, NOT executor functions
        _G_globals = {
            -- Dex variants
            "Dex", "DEX", "DexV2", "DexV3", "DexV4", 
            "DexExplorer", "Dex_Explorer",
            "DarkDex", "DarkDexV3", "Dark_Dex",
            
            -- Infinite Yield
            "InfiniteYield", "Infinite_Yield", "IY_LOADED", "IY",
            
            -- Hydroxide
            "Hydroxide", "HydroxideUI", "HYDROXIDE_LOADED",
            
            -- Spies
            "SimpleSpy", "SimpleSpyExecuted", "SimpleSpy_Loaded",
            "RemoteSpy", "Remote_Spy", "REMOTESPY_LOADED",
            
            -- Other tools
            "BTool", "BTool_Loaded",
            "F3X", "F3X_Loaded",
            "UnnamedESP", "ESP_LOADED",
            
            -- Script dumpers (instances, not functions)
            "ScriptDumper", "SCRIPTDUMP", "ScriptDump_Loaded",
        },
        
        -- CoreGui/PlayerGui children to check
        gui_names = {
            "Dex", "DexV3", "DarkDex", "DarkDexV3",
            "InfiniteYield", "IY", "Infinite Yield",
            "Hydroxide", "SimpleSpy", "RemoteSpy",
            "BTool", "F3X", "Unnamed ESP"
        },
        
        -- Shared table indicators
        shared_indicators = {
            "IYPrefix", "InfiniteYield", "IY",
            "Hydroxide", "SimpleSpy"
        }
    }
    
    local function ${v.detect}()
        local detected = {}
        
        -- ✅ Check _G for TOOL INSTANCES (not functions)
        for _, name in ipairs(${v.tools}._G_globals) do
            pcall(function()
                local val = rawget(_G, name)
                -- Only flag if it's a table (tool instance) or true (loaded flag)
                if val ~= nil then
                    if type(val) == "table" or type(val) == "boolean" then
                        table.insert(detected, name)
                    end
                end
            end)
        end
        
        -- ✅ Check getgenv for TOOL INSTANCES
        pcall(function()
            if getgenv then
                local genv = getgenv()
                for _, name in ipairs(${v.tools}._G_globals) do
                    local val = rawget(genv, name)
                    if val ~= nil then
                        if type(val) == "table" or type(val) == "boolean" then
                            if not table.find(detected, name) then
                                table.insert(detected, name)
                            end
                        end
                    end
                end
            end
        end)
        
        -- ✅ Check CoreGui for tool UIs (MOST RELIABLE)
        pcall(function()
            for _, guiName in ipairs(${v.tools}.gui_names) do
                -- Direct children
                if CoreGui:FindFirstChild(guiName) then
                    local fullName = guiName .. "_UI"
                    if not table.find(detected, fullName) then
                        table.insert(detected, fullName)
                    end
                end
                
                -- Deep search
                local found = CoreGui:FindFirstChild(guiName, true)
                if found and found:IsA("ScreenGui") then
                    local fullName = guiName .. "_GUI"
                    if not table.find(detected, fullName) then
                        table.insert(detected, fullName)
                    end
                end
            end
            
            -- Check for suspicious ScreenGui with known patterns
            for _, child in pairs(CoreGui:GetChildren()) do
                if child:IsA("ScreenGui") then
                    local name = child.Name:lower()
                    -- Very specific patterns for known tools
                    if name:match("^dex") or name:match("darkdex") or
                       name == "infinite yield" or name == "iy" or
                       name == "hydroxide" or name == "simplespy" or
                       name == "remotespy" then
                        if not table.find(detected, child.Name) then
                            table.insert(detected, child.Name .. "_Detected")
                        end
                    end
                end
            end
        end)
        
        -- ✅ Check PlayerGui
        pcall(function()
            if LocalPlayer and LocalPlayer.PlayerGui then
                for _, guiName in ipairs(${v.tools}.gui_names) do
                    if LocalPlayer.PlayerGui:FindFirstChild(guiName) or
                       LocalPlayer.PlayerGui:FindFirstChild(guiName, true) then
                        local fullName = guiName .. "_PlayerGUI"
                        if not table.find(detected, fullName) then
                            table.insert(detected, fullName)
                        end
                    end
                end
            end
        end)
        
        -- ✅ Check shared table
        pcall(function()
            if shared then
                for _, indicator in ipairs(${v.tools}.shared_indicators) do
                    if shared[indicator] ~= nil then
                        if not table.find(detected, indicator .. "_Shared") then
                            table.insert(detected, indicator .. "_Shared")
                        end
                    end
                end
            end
        end)
        
        return detected
    end
    
    -- ============================================================
    -- 🔓 SCRIPT DECODER
    -- ============================================================
    
    local ${v.chunks} = {
        ${scriptChunks.map((chunk, i) => `[${i + 1}] = "${chunk}"`).join(',\n        ')}
    }
    
    local function ${v.decode}()
        local decoded = {}
        local b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        
        for i, chunk in ipairs(${v.chunks}) do
            pcall(function()
                chunk = string.gsub(chunk, '[^'..b64..'=]', '')
                decoded[i] = (chunk:gsub('.', function(x)
                    if x == '=' then return '' end
                    local r, f = '', (b64:find(x) - 1)
                    for j = 6, 1, -1 do 
                        r = r .. (f % 2^j - f % 2^(j-1) > 0 and '1' or '0') 
                    end
                    return r
                end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
                    if #x ~= 8 then return '' end
                    local c = 0
                    for j = 1, 8 do 
                        c = c + (x:sub(j,j) == '1' and 2^(8-j) or 0) 
                    end
                    return string.char(c)
                end))
            end)
        end
        
        return table.concat(decoded)
    end
    
    -- ============================================================
    -- 🚀 MAIN EXECUTION
    -- ============================================================
    
    local function ${v.run}()
        -- Step 1: Tool Detection (ONLY REAL TOOLS)
        local toolsFound = ${v.detect}()
        
        if #toolsFound > 0 then
            local toolList = table.concat(toolsFound, ", ")
            warn("[🛡️] Tools detected:", toolList)
            ${v.kick}("Malicious tools detected: " .. toolList, toolsFound)
            return false
        end
        
        -- Step 2: Decode and execute script
        local scriptContent = ${v.decode}()
        
        if scriptContent and #scriptContent > 0 then
            local loader = loadstring or load
            if not loader then
                warn("[🛡️] Loader not available")
                return false
            end
            
            local fn, err = loader(scriptContent)
            if not fn then
                warn("[🛡️] Compile error:", err)
                return false
            end
            
            -- Execute
            local success, result = pcall(fn)
            if not success then
                warn("[🛡️] Runtime error:", result)
            end
            
            return success
        end
        
        return false
    end
    
    -- ============================================================
    -- 🔄 CONTINUOUS MONITORING (Less aggressive)
    -- ============================================================
    
    local function ${v.loop}()
        spawn(function()
            while wait(10) do -- Check every 10 seconds (less frequent)
                local toolsFound = ${v.detect}()
                if #toolsFound > 0 then
                    local toolList = table.concat(toolsFound, ", ")
                    warn("[🛡️ MONITOR] Tools detected:", toolList)
                    ${v.kick}("Runtime tool detection: " .. toolList, toolsFound)
                    break
                end
            end
        end)
    end
    
    -- Start monitoring
    ${v.loop}()
    
    -- Return main function
    return ${v.run}
end)()

-- Execute
local ${v.result} = ${v.main} and ${v.main}()

-- Cleanup
${v.main} = nil
collectgarbage("collect")
`;

    return protectedScript;
}

module.exports = {
    generateProtectedScript,
    generateChecksum,
    randomVar
};        const encoded = Buffer.from(chunk).toString('base64');
        scriptChunks.push(encoded);
    }

    const protectedScript = `
--[[
    ╔══════════════════════════════════════════════════════════╗
    ║  🛡️ PREMIUM PROTECTED SCRIPT v4.0                       ║
    ║  Session: ${sessionToken.substring(0, 8)}...                                    ║
    ╚══════════════════════════════════════════════════════════╝
--]]

-- 🔒 Immediate Protection Layer
local ${v.main} = (function()
    -- Core references (frozen)
    local _G = _G
    local game = game
    local pcall = pcall
    local xpcall = xpcall
    local type = type
    local typeof = typeof
    local tostring = tostring
    local tonumber = tonumber
    local setmetatable = setmetatable
    local getmetatable = getmetatable
    local rawget = rawget
    local rawset = rawset
    local table = table
    local string = string
    local math = math
    local coroutine = coroutine
    local tick = tick
    local wait = task and task.wait or wait
    local spawn = task and task.spawn or spawn
    local delay = task and task.delay or delay
    local error = error
    local warn = warn
    local pairs = pairs
    local ipairs = ipairs
    local next = next
    local select = select
    local unpack = unpack or table.unpack
    local loadstring = loadstring
    local getfenv = getfenv
    local setfenv = setfenv
    local newproxy = newproxy
    
    -- Services
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local RunService = game:GetService("RunService")
    
    local LocalPlayer = Players.LocalPlayer
    local HWID = nil
    local SESSION = "${sessionToken}"
    local BAN_ENDPOINT = "${banEndpoint || ''}"
    
    -- ============================================================
    -- 🔧 UTILITY FUNCTIONS
    -- ============================================================
    
    local function ${v.http}(url, method, data)
        local success, result = pcall(function()
            if method == "POST" then
                return game:HttpPost(url, HttpService:JSONEncode(data))
            else
                return game:HttpGet(url)
            end
        end)
        
        if not success then
            pcall(function()
                local req = (syn and syn.request) or (http and http.request) or 
                            (request) or (fluxus and fluxus.request) or 
                            (http_request) or (HttpPost and function(params)
                                if params.Method == "POST" then
                                    return {Body = HttpPost(params.Url, params.Body)}
                                end
                                return {Body = game:HttpGet(params.Url)}
                            end)
                
                if req then
                    result = req({
                        Url = url,
                        Method = method or "GET",
                        Headers = {["Content-Type"] = "application/json"},
                        Body = data and HttpService:JSONEncode(data) or nil
                    })
                    result = result.Body or result
                end
            end)
        end
        
        return result
    end
    
    local function ${v.hwid}()
        if HWID then return HWID end
        
        pcall(function()
            HWID = (gethwid and gethwid()) or
                   (get_hwid and get_hwid()) or
                   (HWID_) or
                   (syn and syn.cache_hwid and syn.cache_hwid()) or
                   (getexecutorname and getexecutorname() .. "_" .. tostring(LocalPlayer.UserId)) or
                   (identifyexecutor and identifyexecutor() .. "_" .. tostring(LocalPlayer.UserId)) or
                   ("EX_" .. tostring(LocalPlayer.UserId) .. "_" .. tostring(tick()))
        end)
        
        return HWID or ("UNKNOWN_" .. tostring(LocalPlayer.UserId))
    end
    
    -- ============================================================
    -- 🚫 KICK & BAN FUNCTIONS
    -- ============================================================
    
    local ${v.kick} = function(reason, toolsFound)
        -- Send ban request to server
        pcall(function()
            if BAN_ENDPOINT and BAN_ENDPOINT ~= "" then
                ${v.http}(BAN_ENDPOINT, "POST", {
                    hwid = ${v.hwid}(),
                    playerId = LocalPlayer.UserId,
                    playerName = LocalPlayer.Name,
                    reason = reason,
                    toolsDetected = toolsFound or {}
                })
            end
        end)
        
        -- Show notification
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⛔ Security Violation",
                Text = reason,
                Duration = 10
            })
        end)
        
        -- Multiple kick methods
        wait(0.5)
        
        pcall(function() LocalPlayer:Kick("\\n\\n⛔ SECURITY VIOLATION\\n\\n" .. reason .. "\\n\\nYou have been banned from using this script.") end)
        pcall(function() game:Shutdown() end)
        pcall(function() while true do end end)
    end
    
    -- ============================================================
    -- 🔍 TOOL DETECTION - COMPREHENSIVE LIST
    -- ============================================================
    
    local ${v.tools} = {
        -- 🔴 Explorer/Inspector Tools
        globals = {
            -- Dex Explorer variants
            "Dex", "DexV2", "DexV3", "DexV4", "Dex_Explorer", "DexExplorer",
            "dex", "DEX", "DEXV3", "DarkDex", "DarkDexV3", "Dark_Dex",
            
            -- Other Explorers
            "InfiniteYield", "Infinite_Yield", "IY_LOADED", "InfYield",
            "Hydroxide", "HydroxideUI", "HYDROXIDE_LOADED",
            "SimpleSpy", "SimpleSpyExecuted", "SimpleSpy_Loaded",
            "RemoteSpy", "Remote_Spy", "REMOTESPY_LOADED",
            "ScriptDumper", "Script_Dumper", "SCRIPTDUMP",
            
            -- Hex/Memory tools
            "Hex", "HexEditor", "MemoryEditor", "CheatEngine",
            
            -- Other dangerous tools
            "BTool", "BTool_Loaded", "F3X", "F3X_Loaded",
            "YOUREXECUTOR_NAMESPACE", "UnnamedESP", "ESP_LOADED",
            "FlyScript", "NoclipScript", "SpeedHack",
            "Synapse", "SynapseXen", "XENO_LOADED",
            "LogService_SPY", "spy_table", "_G.spy",
            
            -- Decompilers
            "decompile", "Decompiler", "DECOMPILER_LOADED",
            "getscriptbytecode", "dumpstring", "saveinstance",
            
            -- Anti-cheat bypass indicators
            "BYPASS_LOADED", "AntiCheatBypass", "ACBypass",
            "NoClip_Enabled", "Fly_Enabled", "Speed_Enabled"
        },
        
        -- 🔴 Core GUI Children to check
        coreGuiChildren = {
            "Dex", "DexV3", "DarkDex", "InfiniteYield", "Hydroxide",
            "SimpleSpy", "RemoteSpy", "BTool", "F3X", "ScriptDumper",
            "Unnamed ESP", "ESP", "Aimbot", "SilentAim"
        },
        
        -- 🔴 Executor-specific functions that indicate tool usage
        execFunctions = {
            -- These are fine on their own, but combined with tools = bad
            "hookfunction", "hookmetamethod", "getrawmetatable",
            "setreadonly", "getgenv", "getrenv", "getfenv"
        }
    }
    
    local function ${v.detect}()
        local detectedTools = {}
        
        -- Check _G and getgenv() for tool globals
        local function checkEnv(env, envName)
            if type(env) ~= "table" then return end
            
            for _, toolName in ipairs(${v.tools}.globals) do
                pcall(function()
                    if rawget(env, toolName) ~= nil then
                        table.insert(detectedTools, toolName .. " (in " .. envName .. ")")
                    end
                end)
            end
        end
        
        -- Check _G
        checkEnv(_G, "_G")
        
        -- Check getgenv if available
        pcall(function()
            if getgenv then
                checkEnv(getgenv(), "getgenv")
            end
        end)
        
        -- Check getrenv if available
        pcall(function()
            if getrenv then
                checkEnv(getrenv(), "getrenv")
            end
        end)
        
        -- Check CoreGui for tool UIs
        pcall(function()
            for _, childName in ipairs(${v.tools}.coreGuiChildren) do
                if CoreGui:FindFirstChild(childName) or 
                   CoreGui:FindFirstChild(childName, true) then
                    table.insert(detectedTools, childName .. " (UI in CoreGui)")
                end
            end
            
            -- Check for suspicious ScreenGui count
            local screenGuis = {}
            for _, child in pairs(CoreGui:GetChildren()) do
                if child:IsA("ScreenGui") then
                    table.insert(screenGuis, child.Name)
                end
            end
            
            -- Common tool UI patterns
            local suspiciousPatterns = {
                "spy", "dex", "explorer", "hydroxide", "remote",
                "script", "dump", "infinite", "yield", "cheat",
                "hack", "esp", "aimbot", "silent", "btool"
            }
            
            for _, guiName in ipairs(screenGuis) do
                local lowerName = guiName:lower()
                for _, pattern in ipairs(suspiciousPatterns) do
                    if lowerName:find(pattern) then
                        if not table.find(detectedTools, guiName .. " (Suspicious UI)") then
                            table.insert(detectedTools, guiName .. " (Suspicious UI)")
                        end
                        break
                    end
                end
            end
        end)
        
        -- Check Players GUI
        pcall(function()
            if LocalPlayer and LocalPlayer.PlayerGui then
                for _, childName in ipairs(${v.tools}.coreGuiChildren) do
                    if LocalPlayer.PlayerGui:FindFirstChild(childName) or
                       LocalPlayer.PlayerGui:FindFirstChild(childName, true) then
                        table.insert(detectedTools, childName .. " (UI in PlayerGui)")
                    end
                end
            end
        end)
        
        -- Check for hooked critical functions
        pcall(function()
            local criticalFuncs = {
                {"print", print},
                {"warn", warn},
                {"error", error}
            }
            
            for _, funcData in ipairs(criticalFuncs) do
                local name, func = funcData[1], funcData[2]
                local funcStr = tostring(func)
                if funcStr:lower():find("hooked") or 
                   funcStr:lower():find("detour") or
                   funcStr:lower():find("spy") then
                    table.insert(detectedTools, name .. " is hooked (Spy detected)")
                end
            end
        end)
        
        -- Check for common spy connections
        pcall(function()
            if getconnections then
                local remoteEvent = Instance.new("RemoteEvent")
                local connections = getconnections(remoteEvent.OnClientEvent)
                remoteEvent:Destroy()
                
                if #connections > 0 then
                    -- Suspicious if a new RemoteEvent already has connections
                    -- table.insert(detectedTools, "RemoteEvent spy detected")
                end
            end
        end)
        
        -- Check for Infinite Yield specific
        pcall(function()
            if shared then
                if shared.IYPrefix or shared.InfiniteYield or shared.IY then
                    table.insert(detectedTools, "Infinite Yield (shared)")
                end
            end
        end)
        
        -- Check for Hydroxide
        pcall(function()
            if Hydroxide or HYDROXIDE or _G.Hydroxide then
                table.insert(detectedTools, "Hydroxide")
            end
        end)
        
        -- Check for active script dumping
        pcall(function()
            if saveinstance or SAVEINSTANCE or _G.saveinstance then
                -- Only flag if actively used (check by monitoring)
            end
            
            if decompile and type(decompile) == "function" then
                -- Decompile exists - monitor usage
            end
        end)
        
        return detectedTools
    end
    
    -- ============================================================
    -- 🛡️ ANTI-DEBUG
    -- ============================================================
    
    local function ${v.antiDbg}()
        local suspicious = false
        local reasons = {}
        
        -- Check debug library tampering
        pcall(function()
            local dbg = debug or {}
            if dbg.getinfo then
                local info = dbg.getinfo(1)
                if info and info.source and info.source:find("spy") then
                    suspicious = true
                    table.insert(reasons, "Debug source modified")
                end
            end
        end)
        
        -- Check for step hooks
        pcall(function()
            if debug and debug.sethook then
                -- Someone might be using debug hooks
            end
        end)
        
        return not suspicious, reasons
    end
    
    -- ============================================================
    -- 🛡️ ANTI-DUMP
    -- ============================================================
    
    local function ${v.antiDmp}()
        -- Create honeypot for dump detection
        pcall(function()
            local honeypot = Instance.new("ModuleScript")
            honeypot.Name = "SystemModule_" .. tostring(tick())
            honeypot.Source = "-- Protected"
            
            -- If someone tries to get source, we detect it
        end)
        
        return true
    end
    
    -- ============================================================
    -- 🛡️ ANTI-DECOMPILE STRUCTURES
    -- ============================================================
    
    local function ${v.antiDec}()
        -- Create confusing structures
        local maze = setmetatable({}, {
            __index = function(t, k)
                return function(...) 
                    return setmetatable({...}, getmetatable(t))
                end
            end,
            __call = function(t, ...)
                return t
            end,
            __tostring = function()
                return string.rep(string.char(0), math.random(50, 200))
            end
        })
        
        -- Fake recursion
        local _ = (function(f)
            return function(x)
                return f(f)(x)
            end
        end)(function(f)
            return function(x)
                if x <= 0 then return 1 end
                return x * f(f)(x - 1)
            end
        end)
        
        return true
    end
    
    -- ============================================================
    -- 🛡️ ANTI-TAMPER
    -- ============================================================
    
    local function ${v.antiTmp}()
        -- Verify session
        if SESSION ~= "${sessionToken}" then
            return false, "Session tampered"
        end
        
        -- Verify critical objects
        if not game or not Players or not LocalPlayer then
            return false, "Environment tampered"
        end
        
        return true, "OK"
    end
    
    -- ============================================================
    -- 🔓 SCRIPT DECODER
    -- ============================================================
    
    local ${v.chunks} = {
        ${scriptChunks.map((chunk, i) => `[${i + 1}] = "${chunk}"`).join(',\n        ')}
    }
    
    local function ${v.decode}(chunks)
        local decoded = {}
        local b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        
        for i, chunk in ipairs(chunks) do
            local success, result = pcall(function()
                chunk = string.gsub(chunk, '[^'..b64..'=]', '')
                return (chunk:gsub('.', function(x)
                    if (x == '=') then return '' end
                    local r, f = '', (b64:find(x) - 1)
                    for i = 6, 1, -1 do 
                        r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0') 
                    end
                    return r
                end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
                    if (#x ~= 8) then return '' end
                    local c = 0
                    for i = 1, 8 do 
                        c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0) 
                    end
                    return string.char(c)
                end))
            end)
            
            if success then
                decoded[i] = result
            end
        end
        
        return table.concat(decoded)
    end
    
    -- ============================================================
    -- 🚀 MAIN EXECUTION
    -- ============================================================
    
    local function ${v.run}()
        -- Step 1: Tool Detection (PRIORITY)
        local toolsFound = ${v.detect}()
        
        if #toolsFound > 0 then
            -- TOOLS DETECTED - KICK & BAN
            local toolList = table.concat(toolsFound, ", ")
            warn("[🛡️ SECURITY] Detected tools: " .. toolList)
            ${v.kick}("Malicious tools detected: " .. toolList, toolsFound)
            return false
        end
        
        -- Step 2: Anti-Debug
        local adOk, adReasons = ${v.antiDbg}()
        if not adOk then
            ${v.kick}("Debug manipulation detected", adReasons)
            return false
        end
        
        -- Step 3: Anti-Dump
        ${v.antiDmp}()
        
        -- Step 4: Anti-Decompile
        ${v.antiDec}()
        
        -- Step 5: Anti-Tamper
        local atOk, atMsg = ${v.antiTmp}()
        if not atOk then
            ${v.kick}("Script tampering detected: " .. atMsg, {atMsg})
            return false
        end
        
        -- Step 6: All checks passed - Decode and execute
        local scriptContent = ${v.decode}(${v.chunks})
        
        if scriptContent and #scriptContent > 0 then
            local loader = loadstring or load
            if not loader then
                warn("[🛡️] Loader not available")
                return false
            end
            
            local fn, err = loader(scriptContent)
            if not fn then
                warn("[🛡️] Script compile error:", err)
                return false
            end
            
            -- Execute script
            local success, result = pcall(fn)
            
            if not success then
                warn("[🛡️] Script runtime error:", result)
            end
            
            return success
        end
        
        return false
    end
    
    -- ============================================================
    -- 🔄 CONTINUOUS MONITORING (Background)
    -- ============================================================
    
    local function ${v.loop}()
        spawn(function()
            while true do
                wait(5) -- Check every 5 seconds
                
                local toolsFound = ${v.detect}()
                if #toolsFound > 0 then
                    local toolList = table.concat(toolsFound, ", ")
                    warn("[🛡️ MONITOR] Tools detected: " .. toolList)
                    ${v.kick}("Runtime tool detection: " .. toolList, toolsFound)
                    break
                end
            end
        end)
    end
    
    -- Start monitoring
    ${v.loop}()
    
    -- Return main function
    return ${v.run}
end)()

-- Execute
local ${v.result} = ${v.main} and ${v.main}()

-- Cleanup
${v.main} = nil
collectgarbage("collect")
`;

    return protectedScript;
}

module.exports = {
    generateProtectedScript,
    generateChecksum,
    randomVar
};
