# encoding: utf-8
# *NOTE*: I only somwhat know what I'm doing and this is _slightly_ tested.
#         Use at your own risk (though I welcome assistance)

require "logstash/filters/base"
require "logstash/namespace"
require "logstash/timestamp"
require "logstash/event"

require "awesome_print"
require "csv"
require "bigdecimal"

# The Bro filter takes an event field containing Bro log data, parses it,
# and stores it as individual fields with the names parsed from the header.
class LogStash::Filters::Bro < LogStash::Filters::Base
  config_name "bro"

  # Header done indicates if the header of the file has been successfully read 
  # or not, either by reading the first five lines initially, or reading them after.
  config :filter_initialized, :validate => :boolean, :default => false

  # The CSV data in the value of the `source` field will be expanded into a
  # data structure.
  config :source, :validate => :string, :default => "message"

  # The path pointing to the file that the bro filter is reading from.
  config :path, :validate => :string

  # Define the column separator value. If this is not specified, the default
  # is a tab '  '.
  # Optional.
  config :separator, :validate => :string, :default => "\x09"

  # Define the set separator value. If this is not specified, the default
  # is a comma ','.
  config :set_separator, :validate => :string, :default => ','

  # Define the empty_field value. If this is not specified, the default
  # is "(empty)".
  config :empty_field, :validate => :string, :default => '(empty)'

  # Define the logname (seen as #path in bro log) value. If this is not specified, the default
  # is ''.
  config :logname, :validate => :string, :default => ''

  # Define the unset_field value. If this is not specified, the default
  # is a hyphen '-'.
  config :unset_field, :validate => :string, :default => '-'

  # Define the fields array. If this is not specified, the default
  # is an empty array [].
  config :fields, :validate => :array, :default => []

  # Define the types array. If this is not specified, the default
  # is an empty array [].
  config :types, :validate => :array, :default => []

  public
  def register
    @meta = {}
  end # def register

  public
  def filter(event)
    return unless filter?(event)

    @logger.debug? and @logger.debug("Running bro filter", :event => event)
    matches = 0

    unless event.include?("path")
      @logger.error("The bro filter requires a \"path\" field typically added by the \"file\" input in the input section of the logstash config!")
      event.cancel
      return
    end # event.include?

    if event[@source].start_with?('#')
      event.cancel
      return
    end
    current_event = event["path"]

    unless @meta.has_key?(current_event)
      @meta[current_event] = {}
      @meta[current_event][:filter_initialized] = false
      @meta[current_event][:mutex] = Mutex.new
    end

    unless @meta[current_event][:filter_initialized] 
      initialize_filter(event, current_event)
      print_config(current_event)
    end
    #begin
      event.remove("host")
      event.remove("@version")

      values = event[@source].split(/#{@meta[current_event][:separator]}/)
      values.each_index do |i|

        if values[i].start_with?(@empty_field, @unset_field) then next end

        field_name = @meta[current_event][:fields][i] || "uninitialized#{i+1}"
        field_type = @meta[current_event][:types][i] || "string"


        if field_type.start_with?("interval", "double")
          values[i] = values[i].to_f
        elsif field_type.start_with?("count", "int")
          values[i] = values[i].to_i
        elsif field_type.start_with?("set", "vector")
          if field_type =~ /interval/ || /double/
            values[i] = values[i].split(',').map(&:to_f)      
          elsif field_type =~ /int/ || /count/
            values[i] = values[i].split(',').map(&:to_i)
          elsif field_type =~ /time/
            values[i] = values[i].split(',').map do |block_value|
              # Truncate timestamp to millisecond precision
              secs = BigDecimal.new(block_value)
              msec  = secs * 1000 # convert to whole number of milliseconds
              msec  = msec.to_i
              block_value = Time.at(msec / 1000, (msec % 1000) * 1000).utc
            end
          else
            values[i] = values[i].split(',')
          end
            
        elsif field_type.start_with?("time") # Create an actual timestamp
          # Truncate timestamp to millisecond precision
          secs = BigDecimal.new(values[i])
          event["#{field_name}_secs"] = secs.to_f
          msec  = secs * 1000 # convert to whole number of milliseconds
          msec  = msec.to_i
          values[i] = Time.at(msec / 1000, (msec % 1000) * 1000).utc
        end

        field_array = field_name.split('.')
        field_hash = field_array.reverse.inject(values[i]) { |a, n| { n => a } }
        field_hash = field_hash[field_hash.keys[0]]
        #event[field_name] = values[i]
        if event.include?(field_array[0])
          event[field_array[0]] = event[field_array[0]].to_hash.merge!(field_hash) { |_, v1, v2| [v1,v2] }
        else
          event[field_array[0]] = field_hash
        end
      end

      # Add some additional data
      if event.include?("@timestamp")
        event["ts"]          = event["@timestamp"]
        print "TS:", event["ts"], "\n"
        if event.include?("duration")
          event["ts_end"]    = LogStash::Timestamp.new(event["ts"] + event["duration"].to_f) 
        end
      end
      event["bro_logtype"] = @meta[current_event][:logname]
      filter_matched(event)
    #rescue => e
     # event.tag "_broparsefailure"
     # @logger.warn("Trouble parsing bro", :event => event, :exception => e)
     # print e
     # return
    #end # begin

    @logger.debug("Event after bro filter", :event => event)

  end # def filter

  def print_config(current_event)
    @logger.info("separator:      \"#{@meta[current_event][:separator]}\"")
    @logger.info("set separator:  \"#{@meta[current_event][:set_separator]}\"")
    @logger.info("empty field:    \"#{@meta[current_event][:empty_field]}\"")
    @logger.info("unset field:    \"#{@meta[current_event][:unset_field]}\"")
    @logger.info("logname:        \"#{@meta[current_event][:logname]}\"")
    @logger.info("columns:        \"#{@meta[current_event][:fields]}\"")
    @logger.info("types:          \"#{@meta[current_event][:types]}\"")
  end # def print_path_config

  def initialize_filter(event, current_event)
    @meta[current_event][:mutex].synchronize do
      unless @meta[current_event][:filter_initialized]
        lines = File.foreach(current_event).first(8)
        lines.each do |line|
          startword = line.chomp!.split.first
          case startword
          when "#separator"
            @meta[current_event][:separator]     = line.partition(/ /)[2]
          when "#set_separator"
            @meta[current_event][:set_separator] = line.partition(/#{@meta[current_event][:separator]}/)[2]
          when "#empty_field"
            @meta[current_event][:empty_field]   = line.partition(/#{@meta[current_event][:separator]}/)[2]
          when "#unset_field"
            @meta[current_event][:unset_field]   = line.partition(/#{@meta[current_event][:separator]}/)[2]
          when "#path"
            @meta[current_event][:logname]       = line.partition(/#{@meta[current_event][:separator]}/)[2]
          when "#fields"
            @meta[current_event][:fields]        = line.partition(/#{@meta[current_event][:separator]}/)[2].split(/#{@meta[current_event][:separator]}/)
              #field = @fields.split('.').reverse.inject(22) { |a, n| { n => a } }
          
          when "#types"
            @meta[current_event][:types]         = line.partition(/#{@meta[current_event][:separator]}/)[2].split(/#{@meta[current_event][:separator]}/)
          end
        end # line.each
        @meta[current_event][:filter_initialized] = true
      end # filter_initialized
    end # synchronize
  end # def initialize_filter
end # class LogStash::Filters::Bro# encoding: utf-8