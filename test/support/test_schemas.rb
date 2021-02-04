# frozen_string_literal: true

require "json-schema"

module TestSchemas
  module Methods
    def assert_schema(name, body)
      schema = TestSchemas.send(name)
      result = JSON::Validator.validate(schema, body)

      assert result, YAML.dump(JSON::Validator.fully_validate(schema, body))
    end
  end

  # rubocop:disable Metrics/MethodLength
  def self.oidc_configuration_response
    {
      type: "object",
      required: %w[
        issuer
        authorization_endpoint
        token_endpoint
        jwks_uri
        response_types_supported
        subject_types_supported
        id_token_signing_alg_values_supported
      ],
      properties: {
        issuer: {
          "$id": "#/properties/issuer",
          type: "string",
          title: "The issuer schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "https://server.example.com"
          ]
        },
        authorization_endpoint: {
          "$id": "#/properties/authorization_endpoint",
          type: "string",
          title: "The authorization_endpoint schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "https://server.example.com/connect/authorize"
          ]
        },
        token_endpoint: {
          "$id": "#/properties/token_endpoint",
          type: "string",
          title: "The token_endpoint schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "https://server.example.com/connect/token"
          ]
        },
        token_endpoint_auth_methods_supported: {
          "$id": "#/properties/token_endpoint_auth_methods_supported",
          type: "array", minItems: 1,
          title: "The token_endpoint_auth_methods_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              client_secret_basic
              private_key_jwt
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/token_endpoint_auth_methods_supported/items",
            anyOf: [
              {
                "$id": "#/properties/token_endpoint_auth_methods_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  client_secret_basic
                  private_key_jwt
                ]
              }
            ]
          }
        },
        token_endpoint_auth_signing_alg_values_supported: {
          "$id": "#/properties/token_endpoint_auth_signing_alg_values_supported",
          type: "array", minItems: 1,
          title: "The token_endpoint_auth_signing_alg_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              RS256
              ES256
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/token_endpoint_auth_signing_alg_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/token_endpoint_auth_signing_alg_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  RS256
                  ES256
                ]
              }
            ]
          }
        },
        userinfo_endpoint: {
          "$id": "#/properties/userinfo_endpoint",
          type: "string",
          title: "The userinfo_endpoint schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "https://server.example.com/connect/userinfo"
          ]
        },
        check_session_iframe: {
          "$id": "#/properties/check_session_iframe",
          type: "string",
          title: "The check_session_iframe schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "https://server.example.com/connect/check_session"
          ]
        },
        end_session_endpoint: {
          "$id": "#/properties/end_session_endpoint",
          type: "string",
          title: "The end_session_endpoint schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "https://server.example.com/connect/end_session"
          ]
        },
        jwks_uri: {
          "$id": "#/properties/jwks_uri",
          type: "string",
          title: "The jwks_uri schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "https://server.example.com/jwks.json"
          ]
        },
        registration_endpoint: {
          "$id": "#/properties/registration_endpoint",
          type: "string",
          title: "The registration_endpoint schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "https://server.example.com/connect/register"
          ]
        },
        scopes_supported: {
          "$id": "#/properties/scopes_supported",
          type: "array", minItems: 1,
          title: "The scopes_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              openid
              profile
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/scopes_supported/items",
            anyOf: [
              {
                "$id": "#/properties/scopes_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  openid
                  profile
                ]
              }
            ]
          }
        },
        response_types_supported: {
          "$id": "#/properties/response_types_supported",
          type: "array", minItems: 1,
          title: "The response_types_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            [
              "code",
              "code id_token"
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/response_types_supported/items",
            anyOf: [
              {
                "$id": "#/properties/response_types_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: [
                  "code",
                  "code id_token"
                ]
              }
            ]
          }
        },
        acr_values_supported: {
          "$id": "#/properties/acr_values_supported",
          type: "array", minItems: 1,
          title: "The acr_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            [
              "urn:mace:incommon:iap:silver",
              "urn:mace:incommon:iap:bronze"
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/acr_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/acr_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: [
                  "urn:mace:incommon:iap:silver",
                  "urn:mace:incommon:iap:bronze"
                ]
              }
            ]
          }
        },
        subject_types_supported: {
          "$id": "#/properties/subject_types_supported",
          type: "array", minItems: 1,
          title: "The subject_types_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              public
              pairwise
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/subject_types_supported/items",
            anyOf: [
              {
                "$id": "#/properties/subject_types_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  public
                  pairwise
                ]
              }
            ]
          }
        },
        userinfo_signing_alg_values_supported: {
          "$id": "#/properties/userinfo_signing_alg_values_supported",
          type: "array", minItems: 1,
          title: "The userinfo_signing_alg_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              RS256
              ES256
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/userinfo_signing_alg_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/userinfo_signing_alg_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  RS256
                  ES256
                ]
              }
            ]
          }
        },
        userinfo_encryption_alg_values_supported: {
          "$id": "#/properties/userinfo_encryption_alg_values_supported",
          type: "array", minItems: 1,
          title: "The userinfo_encryption_alg_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              RSA1_5
              A128KW
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/userinfo_encryption_alg_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/userinfo_encryption_alg_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  RSA1_5
                  A128KW
                ]
              }
            ]
          }
        },
        userinfo_encryption_enc_values_supported: {
          "$id": "#/properties/userinfo_encryption_enc_values_supported",
          type: "array", minItems: 1,
          title: "The userinfo_encryption_enc_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              A128CBC-HS256
              A128GCM
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/userinfo_encryption_enc_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/userinfo_encryption_enc_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  A128CBC-HS256
                  A128GCM
                ]
              }
            ]
          }
        },
        id_token_signing_alg_values_supported: {
          "$id": "#/properties/id_token_signing_alg_values_supported",
          type: "array", minItems: 1,
          title: "The id_token_signing_alg_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              RS256
              ES256
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/id_token_signing_alg_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/id_token_signing_alg_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  RS256
                  ES256
                ]
              }
            ]
          }
        },
        id_token_encryption_alg_values_supported: {
          "$id": "#/properties/id_token_encryption_alg_values_supported",
          type: "array", minItems: 1,
          title: "The id_token_encryption_alg_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              RSA1_5
              A128KW
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/id_token_encryption_alg_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/id_token_encryption_alg_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  RSA1_5
                  A128KW
                ]
              }
            ]
          }
        },
        id_token_encryption_enc_values_supported: {
          "$id": "#/properties/id_token_encryption_enc_values_supported",
          type: "array", minItems: 1,
          title: "The id_token_encryption_enc_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              A128CBC-HS256
              A128GCM
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/id_token_encryption_enc_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/id_token_encryption_enc_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  A128CBC-HS256
                  A128GCM
                ]
              }
            ]
          }
        },
        request_object_signing_alg_values_supported: {
          "$id": "#/properties/request_object_signing_alg_values_supported",
          type: "array", minItems: 1,
          title: "The request_object_signing_alg_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              none
              RS256
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/request_object_signing_alg_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/request_object_signing_alg_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  none
                  RS256
                ]
              }
            ]
          }
        },
        display_values_supported: {
          "$id": "#/properties/display_values_supported",
          type: "array", minItems: 1,
          title: "The display_values_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              page
              popup
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/display_values_supported/items",
            anyOf: [
              {
                "$id": "#/properties/display_values_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  page
                  popup
                ]
              }
            ]
          }
        },
        claim_types_supported: {
          "$id": "#/properties/claim_types_supported",
          type: "array", minItems: 1,
          title: "The claim_types_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              normal
              distributed
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/claim_types_supported/items",
            anyOf: [
              {
                "$id": "#/properties/claim_types_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  normal
                  distributed
                ]
              }
            ]
          }
        },
        claims_supported: {
          "$id": "#/properties/claims_supported",
          type: "array", minItems: 1,
          title: "The claims_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              sub
              iss
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/claims_supported/items",
            anyOf: [
              {
                "$id": "#/properties/claims_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  sub
                  iss
                ]
              }
            ]
          }
        },
        claims_parameter_supported: {
          "$id": "#/properties/claims_parameter_supported",
          type: "boolean",
          title: "The claims_parameter_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: false,
          examples: [
            true
          ]
        },
        service_documentation: {
          "$id": "#/properties/service_documentation",
          type: "string",
          title: "The service_documentation schema",
          description: "An explanation about the purpose of this instance.",
          default: "",
          examples: [
            "http://server.example.com/connect/service_documentation.html"
          ]
        },
        ui_locales_supported: {
          "$id": "#/properties/ui_locales_supported",
          type: "array", minItems: 1,
          title: "The ui_locales_supported schema",
          description: "An explanation about the purpose of this instance.",
          default: [],
          examples: [
            %w[
              en-US
              en-GB
            ]
          ],
          additionalItems: true,
          items: {
            "$id": "#/properties/ui_locales_supported/items",
            anyOf: [
              {
                "$id": "#/properties/ui_locales_supported/items/anyOf/0",
                type: "string",
                title: "The first anyOf schema",
                description: "An explanation about the purpose of this instance.",
                default: "",
                examples: %w[
                  en-US
                  en-GB
                ]
              }
            ]
          }
        }
      },
      additionalProperties: true
    }
  end
  # rubocop:enable Metrics/MethodLength
end
