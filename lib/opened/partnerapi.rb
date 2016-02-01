require "opened/partnerapi/version"

module Opened
  module Partnerapi
    extend self
    
    def self.included base
      base.extend ClassMethods
    end

    module ClassMethods
      PARTNERAPI_URL = 'https://partner.opened.com'

      def signed_request (params)
        check_for_errors(params)
        envelope              = params
        envelope["client_id"] ||= params[:client_id]
        envelope["algorithm"] ||= 'HMAC-SHA256'
        envelope["token"]     ||= SecureRandom.hex
        
        envelope          = JSON.dump(envelope)
        encoded_envelope  = base64_url_encode(envelope)

        signature         = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, params[:app_secret], encoded_envelope)
        encoded_signature = base64_url_encode(signature)

        return "#{encoded_signature}.#{encoded_envelope}"
      end

      def get_access_token (signed_certificate, url=nil)
        base_url = url || PARTNERAPI_URL
        url = "#{base_url}/oauth/silent_login"
        header = {content_type: 'application/text'}
        RestClient.post url, signed_certificate, header
      end

      private

      def base64_url_encode(str)
        Base64.encode64(str).tr('+/', '-_').gsub(/\s/, '').gsub(/=+\z/, '')
      end

      def check_for_errors (params)
        raise Exception.new "Your must pass a client_id" unless params[:client_id]
        raise Exception.new "Your must pass an app_secret" unless params[:app_secret]
        raise Exception.new "You must pass a username" unless params[:username]
      end
    end

  end
end
