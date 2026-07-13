# frozen_string_literal: true

# Defenso — fail-open security middleware for Rack / Rails.
# Alpha scaffold. Full impl: policy fetch + local eval + background attack ingest.
module Defenso
  VERSION = "0.1.0"

  class Middleware
    def initialize(app, token: nil, api_url: "https://app.defen.so")
      @app = app
      @token = token || ENV["DEFENSO_TOKEN"]
      @api_url = api_url
    end

    def call(env)
      # TODO: run policy check; short-circuit on block; async ingest attack log
      @app.call(env)
    end
  end
end
