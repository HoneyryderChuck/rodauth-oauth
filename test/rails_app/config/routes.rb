Rails.application.routes.draw do
  root to: "test#root"

  controller :test do
    get :callback
    get :private
  end
end
