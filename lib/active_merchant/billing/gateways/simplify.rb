require 'json'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class SimplifyGateway < Gateway

      self.test_url = 'https://sandbox.simplify.com/v1/api'
      self.live_url = 'https://api.simplify.com/v1/api'

      self.supported_countries = ['US', 'IE']
      self.default_currency = 'USD'
      self.supported_cardtypes = [:visa, :master, :american_express, :discover]

      self.homepage_url = 'https://www.simplify.com/commerce'
      self.display_name = 'Simplify Commerce'

      STANDARD_ERROR_CODE_MAPPING = {}

      def initialize(options={})
        requires!(options, :private_key, :public_key)
        super
      end

      def purchase(money, payment, options={})
        post = {}
        add_invoice(post, money, options)
        add_payment(post, payment)
        add_address(post, payment, options)
        add_customer_data(post, options)

        commit('sale', post)
      end

      def authorize(money, payment, options={})
        post = {}
        post['amount'] = money
        add_payment(post, payment)
        add_customer_data(post, options)

        commit('authorization', post)
      end

      def capture(money, authorization, options={})
        commit('capture', post)
      end

      def refund(money, authorization, options={})
        commit('refund', post)
      end

      def void(authorization, options={})
        commit('void', post)
      end

      def verify(credit_card, options={})
        MultiResponse.run(:use_first_response) do |r|
          r.process { authorize(100, credit_card, options) }
          r.process(:ignore_result) { void(r.authorization, options) }
        end
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript
      end

      private

      def add_customer_data(post, options)
      end

      def add_address(post, creditcard, options)
      end

      def add_invoice(post, money, options)
        post[:amount] = amount(money)
        post[:currency] = (options[:currency] || currency(money))
      end

      def add_payment(post, payment)
        post['card'] = {
          'number' => payment.number,
          'expMonth' => payment.month,
          'expYear' => payment.year-2000,
          'cvc' => payment.verification_value,
          'name' => "#{payment.first_name} #{payment.last_name}"
        }
      end

      def parse(body)
        {}
      end

      def commit(action, parameters)
        base_url = (test? ? test_url : live_url)
        url = [ base_url, action ].join('/')
        signature = jws_encode(options, url, parameters)
puts signature

        response = parse(ssl_post(url, signature, { 'Content-Type' => 'application/json', 'Accept' => 'application/json' }))

        Response.new(
          success_from(response),
          message_from(response),
          response,
          authorization: authorization_from(response),
          avs_result: AVSResult.new(code: response["some_avs_response_key"]),
          cvv_result: CVVResult.new(response["some_cvv_response_key"]),
          test: test?,
          error_code: error_code_from(response)
        )
      end

      def success_from(response)
      end

      def message_from(response)
      end

      def authorization_from(response)
      end

      def post_data(action, parameters = {})
      end

      def error_code_from(response)
        unless success_from(response)
          # TODO: lookup error code for this response
        end
      end

      def jws_encode(options, url, object_map)
        jws_hdr = {'typ' => 'JWS',
                   'alg' => 'HS256',
                   'kid' => options[:public_key],
		           'api.simplifycommerce.com/uri' => url,
		           'api.simplifycommerce.com/timestamp' => Time.now.to_i * 1000,
       		       'api.simplifycommerce.com/nonce' => SecureRandom.hex}

        hdr = Base64.urlsafe_encode64(jws_hdr.to_json)
        payload = Base64.urlsafe_encode64(object_map.to_json)
        msg = "#{hdr}.#{payload}"
        "#{msg}.#{jws_sign(options[:private_key], msg)}"
      end

      def jws_sign(private_key, msg)
        Base64.urlsafe_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, Base64.decode64(private_key), msg))
      end
    end
  end
end
