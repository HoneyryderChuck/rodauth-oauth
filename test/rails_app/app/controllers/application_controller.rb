# frozen_string_literal: true

class ApplicationController < ActionController::Base
  def not_found
    render inline: "not found", status: 404
  end
end
