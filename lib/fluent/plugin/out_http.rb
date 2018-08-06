class Fluent::HTTPOutput < Fluent::Output
  Fluent::Plugin.register_output('http', self)

  def initialize
    super
    require 'net/http/persistent'
    require 'uri'
    require 'yajl'
    require 'faraday'
  end

  # Endpoint URL ex. http://localhost.local/api/
  config_param :endpoint_url, :string

  # HTTP method
  config_param :http_method, :string, :default => :post

  # Raise errors that were rescued during HTTP requests?
  config_param :raise_on_error, :bool, :default => true

  # Set Net::HTTP.verify_mode to `OpenSSL::SSL::VERIFY_NONE`-  
  config_param :ssl_no_verify, :bool, :default => false

  def configure(conf)
    super

    http_methods = [:get, :put, :post, :delete]
    @http_method = if http_methods.include? @http_method.intern
                    @http_method.intern
                  else
                    :post
                  end
    puts @endpoint_url
    @uri = URI.parse(@endpoint_url)
    ssl_verify = @ssl_no_verify
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
  end

  def start
    super
  end

  def shutdown
    super
  end

  def set_body(req, tag, time, record)
    if @serializer == :json
      set_json_body(req, record)
    else
      req.set_form_data(record)
    end
    req
  end

  def set_header(req, tag, time, record)
    req
  end

  def set_json_body(req, data)
    req.body = Yajl.dump(data)
    req['Content-Type'] = 'application/json'
  end

  def http_opts(uri)
      opts = {
        :use_ssl => uri.scheme == 'https'
      }
      opts[:verify_mode] = @ssl_verify_mode if opts[:use_ssl]
      opts
  end

  def send_request(record)
    res = @adapter.post(@uri.path) do |request|
      request.headers['Content-Type'] = 'application/json'
      request.body = Yajl.dump(record)
      request.options.timeout = 60
      request.options.open_timeout = 60
    end
  end # end send_request

  def handle_record(tag, time, record)
    send_request(record)
  end

  def emit(tag, es, chain)
    es.each do |time, record|
      handle_record(tag, time, record)
    end
    chain.next
  end
end
