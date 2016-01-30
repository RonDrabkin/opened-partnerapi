require "opened/partnerapi/version"

module Opened
  module Partnerapi
    APP_SECRET = nil
    CLIENT_ID  = nil

    def self.included base
      base.extend ClassMethods
    end

    module ClassMethods

      def signed_request (params)
        check_for_errors(params)
        envelope              = params
        envelope["client_id"] ||= CLIENT_ID
        envelope["algorithm"] ||= 'HMAC-SHA256'
        envelope["token"]     ||= SecureRandom.hex
        
        envelope          = JSON.dump(envelope)
        encoded_envelope  = base64_url_encode(envelope)

        signature         = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, APP_SECRET, encoded_envelope)
        encoded_signature = base64_url_encode(signature)

        return "#{encoded_signature}.#{encoded_envelope}"
      end

      private

      def base64_url_encode(str)
        Base64.encode64(str).tr('+/', '-_').gsub(/\s/, '').gsub(/=+\z/, '')
      end

      def check_for_errors (params)
        raise Exception.new "Your Opened::Partnerapi::APP_SECRET is not set" unless APP_SECRET
        raise Exception.new "Your Opened::Partnerapi::CLIENT_ID is not set" unless CLIENT_ID
        raise Exception.new "You must pass a username" unless params[:username]
      end
    end
  end
end
