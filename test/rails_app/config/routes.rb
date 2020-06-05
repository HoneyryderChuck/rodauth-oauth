# frozen_string_literal: true

Rails.application.routes.draw do
  root to: "authorize#root"

  controller :authorize do
    get :callback
    get :private
  end
end
