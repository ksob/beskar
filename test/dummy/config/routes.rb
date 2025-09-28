Rails.application.routes.draw do
  devise_for :users
  mount Beskar::Engine => "/beskar"

  get "restricted" => "welcome#restricted"
  root to: "welcome#index"
end
