local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local jwt = require("kong.plugins.oidc.jwt")
local resty_oidc = require("resty.openidc")

OidcHandler.PRIORITY = 1005


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  local user_name = "unset"
  local user_groups = ""
  local headers = kong.request.get_headers()

  if headers["OAUTH2-ACCESS-TOKEN"] ~= nil then
    local payload, err = resty_oidc.jwt_verify(headers["OAUTH2-ACCESS-TOKEN"], oidcConfig)
    if err then
      utils.exit(403, err, ngx.HTTP_FORBIDDEN) 
    end
    user_name = payload["username"]
    user_groups = payload[oidcConfig.groups_mapping_field]
    kong.response.set_header("X-Username", user_name)
    if table.getn(oidcConfig.groups_authorized_paths) > 0 then
      if not utils.isUserAuthorized(user_groups, oidcConfig.groups_authorized_paths, ngx.var.request_uri) then
        utils.exit(403, "403 Forbidden", ngx.HTTP_FORBIDDEN) 
      end
    end
  else 
    if oidcConfig.introspection_endpoint then
      response = introspect(oidcConfig)
      if response then
        utils.injectUser(response)
      end
    end
  
    if response == nil then
      response = make_oidc(oidcConfig)
      if response then
        if (response.user) then
          utils.injectUser(response.user)
          utils.injectGroups(response.user, oidcConfig.groups_claim)
        end
        if (response.access_token) then
          splitted_token = jwt.split_token(response.access_token)
          decoded_payload = jwt.decode_base64url(splitted_token["payload"])
          user_groups = decoded_payload[oidcConfig.groups_mapping_field]
          user_name = decoded_payload["username"]
          kong.response.set_header("X-Username", user_name)
          if table.getn(oidcConfig.groups_authorized_paths) > 0 then
            if not utils.isUserAuthorized(user_groups, oidcConfig.groups_authorized_paths, ngx.var.request_uri) then
              utils.exit(403, "403 Forbidden", ngx.HTTP_FORBIDDEN) 
            end
          end
        end
        if (response.id_token) then
          user_groups = response.id_token[oidcConfig.groups_mapping_field]
          user_name = decoded_payload["username"]
          kong.response.set_header("X-Username", user_name)
          if table.getn(oidcConfig.groups_authorized_paths) > 0 then
            if not utils.isUserAuthorized(user_groups, oidcConfig.groups_authorized_paths, ngx.var.request_uri) then
              utils.exit(403, "403 Forbidden", ngx.HTTP_FORBIDDEN) 
            end
          end
        end
      end
    end
  end
  
  
  -- Manage headers
  kong.service.request.set_header("X-Username", user_name)
  kong.service.request.set_header("X-Groups", table.concat(user_groups, ", "))
end

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = resty_oidc.authenticate(oidcConfig)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

return OidcHandler
