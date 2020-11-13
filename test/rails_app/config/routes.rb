# frozen_string_literal: true

Rails.application.routes.draw do
  root to: "authorize#root"

  controller :authorize do
    post :callback # form_post response mode
    get :callback
    get :private
  end
end
