# Beskar

**Beskar** is a comprehensive, Rails-native security engine designed to provide multi-layered, proactive protection for modern web applications. It defends against common threats, bot activity, and account takeovers without requiring external dependencies, integrating seamlessly into your application as a natural extension of the framework.

## Features

-   **Web Application Firewall (WAF):** Real-time protection against common attack vectors like SQL Injection (SQLi) and Cross-Site Scripting (XSS).
-   **Advanced Bot Detection:** Multi-layered defense using JavaScript challenges and invisible honeypots to filter out malicious bots while allowing legitimate ones.
-   **Account Takeover (ATO) Prevention:** Actively monitors and blocks brute-force attacks, credential stuffing, and impossible travel anomalies.
-   **Rails-Native Architecture:** Built as a mountable `Rails::Engine`, it leverages `ActiveJob` and `Rails.cache` for high performance and low overhead.
-   **Real-Time Dashboard (Coming Soon):** A mountable dashboard to visualize security events and monitor threats as they happen.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'beskar'
````

And then execute:

```bash
$ bundle install
```

Next, run the installation generator. This will copy the necessary migrations and create an initializer file.

```bash
$ rails g beskar:install
```

Finally, run the database migrations:

```bash
$ rails db:migrate
```

## Configuration

You can configure Rails Security Shield in the initializer file created by the installer:

```ruby
# config/initializers/beskar.rb
RailsSecurityShield.configure do |config|
  # === Web Application Firewall (WAF) ===
  # Enable or disable the WAF middleware. Defaults to false.
  config.enable_waf = true

  # === Account Protection ===
  # Set the class name of your user model.
  # This is used for tracking security events related to users.
  config.user_class = 'User'

  # More configuration options will be available here.
end
```

## Usage

Once installed and configured, Rails Security Shield works automatically. Its middleware is injected into the Rails request stack to analyze incoming traffic and block threats before they reach your application.

Security events are logged to the `beskar_security_events` table for analysis and will be visualized in the forthcoming security dashboard.

## Development

After checking out the repo, run `bundle install` to install dependencies. The gem contains a dummy Rails application in `test/dummy` for development and testing.

To run the test suite, use the standard Rails command:

```bash
# From the gem's root directory
$ bin/rails test
```

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/prograis/beskar](https://github.com/prograils/beskar). 

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Just be nice to each other.

