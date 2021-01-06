local json = require('cjson')

local M ={}

function split(string, separator)
    local fields = {}
    local separator = separator or " "
    local pattern = string.format("([^%s]+)", separator)

    string.gsub(string, pattern, function(c) fields[#fields + 1] = c end)
    
    return fields
end

function M.split_token(jwt_token)
    local result = {}

    fields = split(jwt_token, ".")
    result["header"] = fields[1]
    result["payload"] = fields[2]
    result["signature"] = fields[3]

    return result
end

function M.decode_base64url(data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

    data = string.gsub(data, '[^'..b..'=]', '')

    return json.decode((data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end)))
end

return M