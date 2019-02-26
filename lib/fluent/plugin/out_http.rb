require 'net/http/persistent'
require 'uri'
require 'yajl'
require 'fluent/plugin/output'
require 'faraday'

class Fluent::Plugin::HTTPOutput < Fluent::Plugin::Output
  Fluent::Plugin.register_output('http', self)

  helpers :compat_parameters, :formatter

  DEFAULT_BUFFER_TYPE = "memory"
  DEFAULT_FORMATTER = "json"

  def initialize
    super
  end

  # Endpoint URL ex. http://localhost.local/api/
  config_param :endpoint_url, :string

  # Set Net::HTTP.verify_mode to `OpenSSL::SSL::VERIFY_NONE`
  config_param :ssl_no_verify, :bool, :default => false

  # HTTP method
  config_param :http_method, :enum, list: [:get, :put, :post, :delete], :default => :post

  # form | json | text | raw
  config_param :serializer, :enum, list: [:json, :form, :text, :raw], :default => :form

  # Simple rate limiting: ignore any records within `rate_limit_msec`
  # since the last one.
  config_param :rate_limit_msec, :integer, :default => 0

  # Raise errors that were rescued during HTTP requests?
  config_param :raise_on_error, :bool, :default => true

  # ca file to use for https request
  config_param :cacert_file, :string, :default => ''

  # custom headers
  config_param :custom_headers, :hash, :default => nil

  # 'none' | 'basic' | 'jwt' | 'bearer'
  config_param :authentication, :enum, list: [:none, :basic, :jwt, :bearer],  :default => :none
  config_param :username, :string, :default => ''
  config_param :password, :string, :default => '', :secret => true
  config_param :token, :string, :default => ''
  # Switch non-buffered/buffered plugin
  config_param :buffered, :bool, :default => false

  config_section :buffer do
    config_set_default :@type, DEFAULT_BUFFER_TYPE
    config_set_default :chunk_keys, ['tag']
  end

  config_section :format do
    config_set_default :@type, DEFAULT_FORMATTER
  end

  def configure(conf)
    compat_parameters_convert(conf, :buffer, :formatter)
    super

    @ssl_verify_mode = if @ssl_no_verify
                         OpenSSL::SSL::VERIFY_NONE
                       else
                         OpenSSL::SSL::VERIFY_PEER
                       end

    @ca_file = @cacert_file
    @last_request_time = nil
    raise Fluent::ConfigError, "'tag' in chunk_keys is required." if !@chunk_key_tag && @buffered

    http_methods = [:get, :put, :post, :delete]
    @http_method = if http_methods.include? @http_method.intern
                     @http_method.intern
                   else
                     :post
                   end
    puts @endpoint_url
    @uri = URI.parse(@endpoint_url)
    # ssl_verify = @ssl_no_verify
    url = @uri.scheme  + "://" + @uri.host + ":" + @uri.port.to_s
    @adapter = Faraday.new(url: url, ssl: {verify:false} ) do |f|
      f.request :retry, max:                 5,
        interval:            1,
        interval_randomness: 0.5,
        backoff_factor:      2,
        methods:             @http_method,
        exceptions:          %w(Errno::ETIMEDOUT
                                Faraday::TimeoutError
                                Faraday::Error::TimeoutError
                                Net::ReadTimeout).freeze

      f.adapter :net_http_persistent
    end

    if @formatter_config = conf.elements('format').first
      @formatter = formatter_create
    end
  end

  def start
    super
  end

  def shutdown
    super
  end

  def format_url(tag, time, record)
    @endpoint_url
  end

  def set_body(req, tag, time, record)
    if @serializer == :json
      set_json_body(req, record)
    elsif @serializer == :text
      set_text_body(req, record)
    elsif @serializer == :raw
      set_raw_body(req, record)
    else
      req.set_form_data(record)
    end
    req
  end

  def set_header(req, tag, time, record)
    if @custom_headers
      @custom_headers.each do |k,v|
        req[k] = v
      end
      req
    else
      req
    end
  end

  def set_json_body(req, data)
    req.body = Yajl.dump(data)
    req['Content-Type'] = 'application/json'
  end

  def set_text_body(req, data)
    req.body = data["message"]
    req['Content-Type'] = 'text/plain'
  end

  def set_raw_body(req, data)
    req.body = data.to_s
    req['Content-Type'] = 'application/octet-stream'
  end

  def create_request(tag, time, record)
    url = format_url(tag, time, record)
    uri = URI.parse(url)
    req = Net::HTTP.const_get(@http_method.to_s.capitalize).new(uri.request_uri)
    set_body(req, tag, time, record)
    set_header(req, tag, time, record)
    return req, uri
  end

  def http_opts(uri)
      opts = {
        :use_ssl => uri.scheme == 'https'
      }
      opts[:verify_mode] = @ssl_verify_mode if opts[:use_ssl]
      opts[:ca_file] = File.join(@ca_file) if File.file?(@ca_file)
      opts
  end

  def proxies
    ENV['HTTPS_PROXY'] || ENV['HTTP_PROXY'] || ENV['http_proxy'] || ENV['https_proxy']
  end

  def send_request(record)
    is_rate_limited = (@rate_limit_msec != 0 and not @last_request_time.nil?)
    if is_rate_limited and ((Time.now.to_f - @last_request_time) * 1000.0 < @rate_limit_msec)
      log.info('Dropped request due to rate limiting')
      return
    end

    _ = @adapter.post(@uri.path) do |request|
      request.headers['Content-Type'] = 'application/json'
      request.body = Yajl.dump(record)
      request.options.timeout = 60
      request.options.open_timeout = 60
    end
  end # end send_request

  def handle_record(tag, time, record)
    if @formatter_config
      record = @formatter.format(tag, time, record)
    end
    # req, uri = create_request(tag, time, record)
    send_request(record)
  end

  def prefer_buffered_processing
    @buffered
  end

  def format(tag, time, record)
    [time, record].to_msgpack
  end

  def formatted_to_msgpack_binary?
    true
  end

  def multi_workers_ready?
    true
  end

  def process(tag, es)
    es.each do |time, record|
      handle_record(tag, time, record)
    end
  end

  def write(chunk)
    tag = chunk.metadata.tag
    @endpoint_url = extract_placeholders(@endpoint_url, chunk.metadata)
    chunk.msgpack_each do |time, record|
      handle_record(tag, time, record)
    end
  end
end
