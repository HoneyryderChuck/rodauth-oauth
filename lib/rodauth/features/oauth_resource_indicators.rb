# frozen-string-literal: true

require "rodauth/oauth/version"
require "rodauth/oauth/ttl_store"

module Rodauth
  Feature.define(:oauth_resource_indicators, :OauthResourceIndicators) do
    depends :oauth_base
  end
end
