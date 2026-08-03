# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

# Defenso — fail-open WAF middleware for Rack / Rails.
#
# Design (mirrors the Node / PHP / Python / Go SDKs):
# - Fails open. If Defenso is unreachable or slow, the request is allowed.
# - Policy is cached. Rules are pulled on a background thread and evaluated
#   locally; the request path never blocks on a network call.
# - Logs are fire-and-forget. Block events are queued and flushed async.
module Defenso
  VERSION = "0.2.0"

  class Middleware
    def initialize(app, token: nil, api_url: "https://app.defen.so/api",
                   policy_refresh: 300, timeout: 1.0)
      @app = app
      @token = token || ENV["DEFENSO_TOKEN"]
      @api_url = api_url.chomp("/")
      @policy_refresh = policy_refresh
      @timeout = timeout
      @rules = []
      @queue = []
      @mutex = Mutex.new
      start_refresh! if @token && !@token.empty?
    end

    def call(env)
      return @app.call(env) if @token.nil? || @token.empty?

      match = evaluate(env)
      if match && match[:action] == "block"
        queue_log(match, env)
        body = { error: "Request blocked by Defenso", rule: match[:id] }.to_json
        return [403, { "Content-Type" => "application/json" }, [body]]
      end

      @app.call(env)
    rescue StandardError
      # Any middleware error must fail open — never break the app.
      @app.call(env)
    end

    private

    def start_refresh!
      Thread.new do
        loop do
          refresh_once
          sleep @policy_refresh
        end
      end
    rescue StandardError
      nil
    end

    def refresh_once
      uri = URI("#{@api_url}/policy")
      req = Net::HTTP::Get.new(uri)
      req["Authorization"] = "Bearer #{@token}"
      req["Accept"] = "application/json"
      res = http(uri).request(req)
      return unless res.is_a?(Net::HTTPSuccess)

      data = JSON.parse(res.body)
      compiled = (data["rules"] || []).filter_map do |r|
        opts = r["flags"].to_s.include?("i") ? Regexp::IGNORECASE : 0
        { id: r["id"], action: r["action"], target: r["target"],
          category: r["category"], re: Regexp.new(r["pattern"].to_s, opts) }
      rescue RegexpError
        nil # skip a bad rule, never fatal
      end
      @mutex.synchronize { @rules = compiled }
    rescue StandardError
      # Fail open: keep last-known-good rules.
      nil
    end

    def evaluate(env)
      rules = @mutex.synchronize { @rules }
      query = env["QUERY_STRING"].to_s
      path = env["PATH_INFO"].to_s
      headers = env.select { |k, _| k.start_with?("HTTP_") }
                   .map { |k, v| "#{k}:#{v}" }.join(" ")
      rules.each do |rule|
        hay = case rule[:target]
              when "url" then path
              when "headers" then headers
              else query
              end
        return rule if !hay.empty? && rule[:re].match?(hay)
      end
      nil
    end

    def queue_log(match, env)
      entry = {
        at: Time.now.to_i,
        verdict: { action: "block", rule: { id: match[:id] }, reason: match[:category] },
        request: {
          method: env["REQUEST_METHOD"],
          url: "#{env['PATH_INFO']}?#{env['QUERY_STRING']}",
          ip: env["HTTP_CF_CONNECTING_IP"] || env["REMOTE_ADDR"]
        }
      }
      batch = nil
      @mutex.synchronize do
        @queue << entry
        if @queue.length >= 25
          batch = @queue
          @queue = []
        end
      end
      Thread.new { flush(batch) } if batch
    end

    def flush(batch)
      uri = URI("#{@api_url}/attacks/ingest")
      req = Net::HTTP::Post.new(uri)
      req["Authorization"] = "Bearer #{@token}"
      req["Content-Type"] = "application/json"
      req.body = { logs: batch }.to_json
      http(uri).request(req)
    rescue StandardError
      nil # logs are best-effort
    end

    def http(uri)
      h = Net::HTTP.new(uri.host, uri.port)
      h.use_ssl = uri.scheme == "https"
      h.open_timeout = @timeout
      h.read_timeout = @timeout
      h
    end
  end
end
