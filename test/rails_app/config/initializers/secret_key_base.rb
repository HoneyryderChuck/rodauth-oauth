# frozen_string_literal: true

if Rails.application.respond_to?(:secrets)
  Rails.application.secrets.secret_key_base = "a8457c8003e83577e92708bd56e19bdc4442c689f458f483a30e580611c578a3"
end
