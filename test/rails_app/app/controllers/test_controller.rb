# frozen_string_literal: true

class TestController < ApplicationController
  def root
    render inline: flash[:alert] || flash[:notice] || "Unauthorized"
  end

  def callback
    render inline: "Callback"
  end

  def private
    rodauth.require_authentication
    rodauth.require_oauth_authorization

    flash["error"] || flash["notice"] || "Authorized"
  end
end
