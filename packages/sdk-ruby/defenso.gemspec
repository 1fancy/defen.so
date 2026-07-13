Gem::Specification.new do |s|
  s.name        = "defenso"
  s.version     = "0.1.0"
  s.summary     = "Defenso Rack/Rails middleware — fail-open security layer"
  s.description = "WAF, bot detection, deception. One line install. Never blocks a request when Defenso is unreachable."
  s.authors     = ["Defenso"]
  s.email       = ["info@defen.so"]
  s.files       = ["lib/defenso.rb", "README.md"]
  s.homepage    = "https://defen.so"
  s.license     = "MIT"
  s.required_ruby_version = ">= 3.0"
end
