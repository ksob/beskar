Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  devise_for :devise_users
  mount Beskar::Engine => "/beskar"

  get "devise_restricted" => "welcome#devise_restricted"
  get "user_restricted" => "welcome#user_restricted"
  root to: "welcome#index"

  # WAF test routes
  get "waf_test/status", to: "waf_test#status"
  post "waf_test/clear", to: "waf_test#clear_violations"
  post "waf_test/simulate", to: "waf_test#simulate_violations"
  get "waf_test/test", to: "waf_test#test_middleware"

  # Direct WAF test routes (these should trigger the WAF patterns)
  # get "/wp-admin.php", to: "waf_test#trigger_wordpress"
  # get "/wp-login.php", to: "waf_test#trigger_wordpress"
  # get "/.env", to: "waf_test#trigger_config"
end
