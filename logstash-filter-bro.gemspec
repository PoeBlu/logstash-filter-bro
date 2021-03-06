Gem::Specification.new do |s|
  s.name = 'logstash-filter-bro'
  s.version         = '2.0.2'
  s.licenses = ['Apache License (2.0)']
  s.summary = "This filter parses the default ASCII bro logs into JSON."
  s.description = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Blake Mackey"]
  s.email = 'blake_mackey@hotmail.com'
  s.homepage = "http://github.com/brashendeavours/logstash-filter-bro"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core'
  s.add_development_dependency 'logstash-devutils'
end
