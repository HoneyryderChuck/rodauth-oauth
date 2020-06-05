# frozen_string_literal: true

class AuthorizeController < ApplicationController
  def root
    render inline: flash[:alert] || flash[:notice] || "Unauthorized"
  end

  def callback
    render inline: "Callback"
  end

  def private
    rodauth.require_authentication
    rodauth.require_oauth_authorization

    render inline: flash["error"] || flash["notice"] || "Authorized"
  end
end
