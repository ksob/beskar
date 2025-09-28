require "test_helper"

class WelcomeControllerTest < ActionDispatch::IntegrationTest
  test "should get restricted" do
    get welcome_restricted_url
    assert_response :success
  end
end
