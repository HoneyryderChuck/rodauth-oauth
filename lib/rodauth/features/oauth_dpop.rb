# frozen_string_literal: true

require "rodauth/oauth"
require "logger"
require "json/jwt"

module Rodauth
  Feature.define(:oauth_dpop, :OauthDPoP) do
    depends :oauth_base, :oauth_authorize_base, :oauth_jwt_base
    VALID_ALG_CLAIMS = %w[RS PS ES HS].freeze

    auth_value_method :oauth_dpop_bound_access_tokens, false
    auth_value_method :oauth_dpop_bound_authorization_requests, false
    auth_value_method :oauth_dpop_required_error_status, 401
    auth_value_method :oauth_dpop_bound_par_requests, false
    auth_value_method :oauth_use_dpop_nonce, false
    auth_value_method :oauth_token_type, "dpop"
    auth_value_method :oauth_dpop_signing_alg_values_supported,
                      %w[
                        HS256
                        HS384
                        HS512
                        RS256
                        RS384
                        RS512
                        PS256
                        PS384
                        PS512
                        ES256
                        ES384
                        ES512
                        ES256K
                      ]
    auth_value_method :logger, Logger.new(STDOUT)

    auth_value_method :max_param_bytesize, nil if Rodauth::VERSION >= "2.26.0"

    # dpop_bound_authorization_requests WIP: Implement DPoP bound authorization requests
    # dpop_bound_par_requests WIP: Implement DPoP bound pushed authorization requests
    # use_dpop_nonce WIP: Implement DPoP nonce feature
    # The above to be added to the oauth_applications table

    %i[dpop_jkt dpop_bound_access_tokens].each do |column|
      auth_value_method :"oauth_applications_#{column}_column", column
    end

    %i[dpop_jkt dpop_jwk_hash token token_hash].each do |column|
      auth_value_method :"oauth_grants_#{column}_column", column
    end

    private

    # DPoP Bound Access Token Methods
    def oauth_dpop_bound_access_tokens
      dpop = header_value_or_nil("DPoP")
      dpop_present = dpop && !dpop.empty?
      dpop_required unless dpop_present
    end

    def dpop_required
      redirect_response_error("invalid_dpop_proof")
    end

    # WIP: Implement dpop for authz and par requests
    # def dpop_bound_authorization_requests?
    #   return @dpop_bound_authorization_requests if defined?(@dpop_bound_authorization_requests)

    #   @dpop_bound_authorization_requests =
    #     (if oauth_application
    #       oauth_application[
    #         oauth_applications_dpop_bound_authorization_requests_column
    #       ]
    #     end)
    #   @dpop_bound_authorization_requests =
    #     oauth_dpop_bound_authorization_requests if @dpop_bound_authorization_requests.nil?
    #   @dpop_bound_authorization_requests
    # end

    # def dpop_bound_par_requests?
    #   return @dpop_bound_par_requests if defined?(@dpop_bound_par_requests)

    #   @dpop_bound_par_requests =
    #     (if oauth_application
    #       oauth_application[
    #         oauth_applications_dpop_bound_par_requests_column
    #       ]
    #     end)
    #   @dpop_bound_par_requests =
    #     oauth_dpop_bound_par_requests if @dpop_bound_par_requests.nil?
    #   @dpop_bound_par_requests
    # end

    # def require_dpop_proof
    # end

    # Utility Methods
    def extract_jwt_headers(jwt)
      header_encoded = jwt.split(".").first
      JSON.parse(Base64.urlsafe_decode64(header_encoded))
    end

    def generate_jwk_hash(jwk)
      Digest::SHA256.hexdigest(jwk.to_json)
    end

    def generate_expected_jti(iat)
      time_now = iat
      logger.debug("iat: #{iat}")
      logger.debug("jwt_iss: #{authorization_server_url}")

      input_string = "#{authorization_server_url}:#{time_now}"

      Digest::SHA256.hexdigest(input_string)
    end

    def header_value_or_nil(key)
      # Look up the header in a case-insensitive manner.
      header_value =
        request.env.find { |k, _| k.casecmp?("HTTP_#{key.upcase}") }&.last

      # Strip any leading or trailing whitespace.
      header_value&.strip!

      # Return nil if the header is blank.
      redirect_response_error("invalid_dpop_proof") if header_value&.empty?
      header_value unless header_value&.empty?
    end

    # DPoP Processing Methods
    def process_token_request
      catch_error do
        logger.info("Processing token request")
        validate_token_params
        json_response_success(json_access_token_payload(oauth_grant))
      end
      logger.error("Error encountered: Invalid DPoP")
      throw_json_response_error(oauth_invalid_response_status, "invalid_dpop")
    end

    def decoded_dpop_proof
      @decoded_dpop_proof ||= decode_dpop_proof(header_value_or_nil("DPoP"))
    end

    def decode_dpop_proof(dpop)
      jwk = extract_jwt_headers(dpop)["jwk"]
      # raise_error("Failed to decode DPoP header") unless jwk

      public_key = JSON::JWK.new(jwk).to_key
      decoded_jwt =
        JWT.decode(
          dpop,
          public_key,
          true,
          { algorithm: oauth_dpop_signing_alg_values_supported }
        )

      if decoded_jwt.is_a?(Array)
        logger.debug("JWT decoding payload: #{decoded_jwt[0].inspect}")
        logger.debug("JWT decoding header: #{decoded_jwt[1].inspect}")
      else
        logger.error(
          "Unexpected return value from JWT decoding: #{decoded_jwt.inspect}"
        )
        # raise "Failed to decode JWT"
      end

      decoded_jwt
    rescue => e
      logger.error("Failed to decode DPoP header: #{e.message}")
      # raise e
    end

    # def use_dpop_nonce?
    #   return @use_dpop_nonce if defined?(@use_dpop_nonce)

    #   @use_dpop_nonce =
    #     (
    #       if oauth_application
    #         oauth_application[oauth_applications_use_dpop_nonce_column]
    #       end
    #     )
    #   @use_dpop_nonce = oauth_use_dpop_nonce if @use_dpop_nonce.nil?
    #   @use_dpop_nonce
    # end

    def validate_token_params
      logger.info("Started validation of token params")

      dpop = header_value_or_nil("DPoP")
      logger.info("DPoP header: #{dpop}")
      if dpop && dpop.empty?
        logger.error("No DPoP header detected")
        redirect_response_error("invalid_dpop_proof")
      elsif oauth_dpop_bound_access_tokens && !dpop
        redirect_response_error("invalid_dpop_proof")
      end

      claims = decoded_dpop_proof
      logger.debug("Beggining to validate claims: #{claims}")

      validate_dpop_proof_claims(claims, dpop)

      logger.info("Token params validated successfully")
      super
    end

    def validate_authorize_params
      super
      dpop_jkt = param_or_nil("dpop_jkt")
      redirect_response_error("invalid_dpop_proof") unless dpop_jkt

      validate_authorize_dpop_jkt_claim(dpop_jkt)
    end

    def validate_dpop_proof_claims(claims, dpop_proof)
      payload, header = claims

      [
        -> { validate_typ_claim(header["typ"]) },
        -> { validate_alg_claim(header["alg"]) },
        -> { validate_jwk_does_not_contain_private_key(header["jwk"]) },
        lambda do
          validate_jwk_claim_and_verify_signature(
            header["jwk"],
            dpop_proof,
            header["alg"]
          )
        end,
        -> { validate_htm_and_htu_claims(payload["htm"], payload["htu"]) },
        -> { validate_nonce(payload["nonce"]) if payload["nonce"] },
        -> { validate_jwt_iat(payload["iat"]) },
        lambda do
          if payload["ath"].present?
            validate_access_token_binding(payload["ath"], header["jwk"])
          end
        end,
        -> { validate_token_dpop_jkt_claim(header["jkt"]) if header["jkt"] },
        -> { validate_jti(payload["jti"], payload["iat"]) }
      ].each(&:call)
    rescue => e
      logger.error("#{e.message}")
      logger.error("#{e.backtrace_locations}")
    end

    # Individual Validators for DPoP Claims
    def validate_typ_claim(typ)
      logger.debug("beggining to debug #{typ}")
      unless typ == "dpop+jwt"
        logger.error('Invalid "typ" claim detected')
        redirect_response_error('Invalid "typ" claim')
      end
    rescue => e
      logger.error("Failed to decode DPoP typ: #{e.message}")
      logger.error("Failed to decode DPoP typ: #{e.backtrace}")
    end

    def validate_alg_claim(alg)
      # Check if alg is not provided or if it's set to "none"
      if alg.nil? || alg.downcase == "none"
        logger.error(
          'Invalid "alg" claim detected: alg is either missing or set to "none"'
        )
        redirect_response_error('Invalid "alg" claim')
      end

      # Check if alg does not start with any of the VALID_ALG_CLAIMS
      unless VALID_ALG_CLAIMS.any? { |claim| alg.start_with?(claim) }
        logger.error(
          "Invalid \"alg\" claim detected: #{alg} is not one of the valid claims"
        )
        redirect_response_error('Invalid "alg" claim')
      end

      # If we reach here, the alg is valid. No action is needed.
    end

    def validate_jwk_claim_and_verify_signature(jwk, dpop_proof, alg = "ES256")
      logger.debug("Validating JWK claim and verifying signature")

      unless jwk && jwk.is_a?(Hash)
        redirect_response_error("invalid_dpop_proof")
      end

      # Check if JWK contains the necessary components
      unless jwk["kty"] == "EC" && jwk["x"] && jwk["y"]
        logger.error("Invalid or incomplete JWK claim.")
        redirect_response_error('Invalid "jwk" claim')
        return
      end

      begin
        # Initialize the EC group for P-256 curve
        group = OpenSSL::PKey::EC::Group.new("prime256v1") # 'prime256v1' is the OpenSSL name for the P-256 curve

        # Decode x and y components from the jwk
        decoded_x = Base64.urlsafe_decode64(jwk["x"])
        decoded_y = Base64.urlsafe_decode64(jwk["y"])

        # Create a new EC point from the x and y components
        bin_point = "\x04" + decoded_x + decoded_y # "\x04" indicates uncompressed point format
        point =
          OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(bin_point, 2))

        # Create an EC key from the point
        ec_key = OpenSSL::PKey::EC.new(group)
        ec_key.public_key = point

        JWT.decode(dpop_proof, ec_key, true, { algorithm: alg })

        # Create EC key from the point
        public_key = OpenSSL::PKey::EC.new(point.group)
        public_key.public_key = point

        JWT.decode(dpop_proof, public_key, true, { algorithm: alg })
      rescue OpenSSL::PKey::PKeyError => e
        logger.error("Failed to create EC key from JWK: #{e.message}")
        redirect_response_error('Invalid "jwk" claim')
      rescue JWT::DecodeError => e
        logger.error("Failed to verify JWT: #{e.message}")
        redirect_response_error("Invalid JWT signature")
      end
    end

    def validate_authorize_dpop_jkt_claim(dpop_jkt)
      # Check if the path is either "/authorize" or "/par"
      unless %w[/authorize /par].include?(request.path)
        logger.info(
          "Path '#{request.path}' skipped, dpop_jkt validation only applies to /authorize and /par."
        )
        return
      end

      # If dpop_jkt matches what's stored in the oauth_application
      if dpop_jkt == oauth_application[oauth_applications_dpop_jkt_column]
        logger.info("dpop_jkt validated successfully.")
      else
        logger.error("Mismatch in dpop_jkt values. Redirecting with error.")
        redirect_response_error("invalid_dpop_proof")
      end
    end

    def validate_token_dpop_jkt_claim(jwk)
      jwk_thumbprint = jwk_thumbprint(jwk)

      unless jwk_thumbprint ==
               oauth_application[oauth_applications_dpop_jkt_column]
        redirect_response_error("invalid_dpop_proof")
      end
    end

    def validate_htm_and_htu_claims(htm, htu)
      logger.debug("Validating 'htm' and 'htu' claims")

      # Check if htm matches the request method
      unless htm && htm.upcase == request.request_method.upcase
        logger.error(
          "Invalid 'htm' claim detected: expected #{request.request_method.upcase} but got #{htm}"
        )
        redirect_response_error('Invalid "htm" claim')
      end

      # Check if htu matches the request URL
      unless htu && htu == request.url
        logger.error(
          "Invalid 'htu' claim detected: expected #{request.url} but got #{htu}"
        )
        redirect_response_error('Invalid "htu" claim')
      end

      # If we reach here, both claims are valid. No action is needed.
    end

    def validate_jwk_does_not_contain_private_key(jwk)
      logger.debug("Validating that 'jwk' does not contain private key")

      private_key_attributes = %w[d p q dp dq qi]
      if private_key_attributes.any? { |attr| jwk.key?(attr) }
        logger.error("JWK contains private key components")
        redirect_response_error('Invalid "jwk" claim: Contains private key')
      end
    end

    def validate_nonce(claims_nonce)
      server_nonce = retrieve_server_nonce_for_client # TODO: Implement this
      unless claims_nonce == server_nonce
        logger.error("Nonce mismatch detected")
        redirect_response_error("Invalid nonce value")
      end
    end

    def validate_jwt_iat(claims_iat)
      acceptable_window = 5.minutes # Adjust as necessary
      if claims_iat.nil? || Time.at(claims_iat) < Time.now - acceptable_window
        logger.error('"iat" claim is not within acceptable window')
        redirect_response_error('Invalid "iat" claim')
      end
    end

    def validate_access_token_binding(claims_ath, claims_jwk)
      # List of paths that do not require the "ath" claim
      exempted_paths = %w[/par /authorize /token]
      logger.info("Validating request path: #{request.path}")

      access_token = retrieve_access_token_from_request

      # If no access token is retrieved, it's an error.
      unless access_token
        logger.error("Missing or invalid DPoP token in Authorization header")
        redirect_response_error("Invalid DPoP token")
        return
      end

      unless exempted_paths.include?(request.path)
        # Ensure that "ath" claim is present and valid
        unless claims_ath
          logger.error('"ath" claim is missing')
          redirect_response_error('Missing "ath" claim')
          return
        end

        unless claims_ath == generate_token_hash(access_token)
          logger.error("Access token hash mismatch detected")
          redirect_response_error('Invalid "ath" claim')
          return
        end

        # Validate that the access token is correctly bound to the DPoP public key
        unless access_token.embedded_jwk_hash == generate_jwk_hash(claims_jwk)
          logger.error("Access token not bound to DPoP public key")
          redirect_response_error("Invalid token binding")
          return
        end
      end
    end

    def retrieve_access_token_from_request
      # Extract the Authorization header
      auth_header = request.env["HTTP_AUTHORIZATION"]

      # If the header isn't present, respond with an error
      unless auth_header
        logger.error("Missing Authorization header")
        redirect_response_error("Missing Authorization header")
        return nil
      end

      # Split the header to separate the scheme ("DPoP") and the token
      scheme, token = auth_header.split

      # Check for "DPoP" scheme
      if scheme && scheme.downcase == "dpop"
        # Validate the token against the token68 syntax
        if token && token.match?(%r{\A[A-Za-z0-9\-._~+/]+=*\z})
          return token
        else
          logger.error("Invalid DPoP token format")
          redirect_response_error("Invalid DPoP token format")
          return nil
        end
      else
        # Handle cases where the Authorization header does not use the DPoP scheme
        logger.error("Invalid Authorization scheme: expected DPoP")
        redirect_response_error("Invalid Authorization scheme: expected DPoP")
        return nil
      end
    end

    def validate_jti(claims_jti, iat)
      expected_jti = generate_expected_jti(iat.to_i)
      if claims_jti != expected_jti
        error_msg =
          "Invalid jti value. Expected #{expected_jti}, but got #{claims_jti}"
        logger.error(error_msg)
        redirect_response_error('Invalid "jti" claim')
      end
    end

    # Token Generation
    def generate_token_hash(token)
      token_sample = token[0..4] # Taking the first few characters for security reasons
      logger.info("Generating token hash for token: #{token_sample}...")
      Digest::SHA256.hexdigest(token)
    end

    def _generate_token(params, token_column, hash_column)
      token = oauth_unique_id_generator
      claims = decoded_dpop_proof

      unless claims
        logger.error("Failed to decode JWT claims")
        return token
      end

      jwk = claims[1]["jwk"]
      jwk_hash = generate_jwk_hash(jwk)
      base64url_dpop_jkt =
        Base64.urlsafe_encode64([jwk_hash].pack("H*")).tr("=", "")

      params[:dpop_jwk_hash] = jwk_hash
      params[:cnf] = { dpop_jkt: base64url_dpop_jkt }

      if respond_to?(hash_column, true)
        params[hash_column] = generate_token_hash(token)
      else
        params[token_column] = token
      end

      token
    end

    def _generate_jwt_access_token(params = {})
      logger.info("Generating access token...")
      super_result = super
      _generate_token(
        params,
        oauth_grants_token_column,
        oauth_grants_token_hash_column
      )
      super_result
    end

    def _generate_jwt_refresh_token(params)
      logger.info("Generating refresh token...")
      super_result = super
      _generate_token(
        params,
        oauth_grants_refresh_token_column,
        oauth_grants_refresh_token_hash_column
      )
      super_result
    end

    def json_token_introspect_payload(grant_or_claims)
      introspection_response = super

      # Check if the token is DPoP-bound by looking for the cnf claim
      if grant_or_claims["cnf"] && grant_or_claims["cnf"]["dpop_jkt"]
        # Add the cnf claim with the dpop_jkt member to the introspection response
        introspection_response[:cnf] = {
          dpop_jkt: grant_or_claims["cnf"]["dpop_jkt"]
        }
      end

      introspection_response
    end

    def base64url_encode(str)
      Base64.urlsafe_encode64(str).tr("=", "")
    end

    def jwk_thumbprint(jwk)
      # Step 1: Extract and order necessary fields
      case jwk["kty"]
      when "RSA"
        canonical = { kty: jwk["kty"], n: jwk["n"], e: jwk["e"] }
      when "EC"
        canonical = {
          kty: jwk["kty"],
          crv: jwk["crv"],
          x: jwk["x"],
          y: jwk["y"]
        }
        # Add other key types as needed
      else
        raise "Unsupported key type: #{jwk["kty"]}"
      end

      # Step 2: Hash the canonical string
      sha256 = OpenSSL::Digest::SHA256.digest(canonical.to_json)

      # Step 3: Base64url encode
      base64url_encode(sha256)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[
          :dpop_signing_alg_values_supported
        ] = oauth_dpop_signing_alg_values_supported
      end
    end
  end
end
