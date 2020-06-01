# frozen_string_literal: true

require_relative "./roda_integration"

class HTTPMAcIntegration < RodaIntegration
  def oauth_feature
    :oauth_http_mac
  end

  def setup_application
    rodauth do
      oauth_tokens_table :http_mac_oauth_tokens
    end
    super
  end
end
