# Migration Guide v1

This guide is to share a few helpful tips to migrate a production app using `rodauth-oauth` v0.10 to v1. There are quite a few breaking changes which will require some work to pull through, and I'll go 1 by 1.

**Most important tip**: Make sure you're running v0.10.3 before you try to migrate to v1!

## Minimum ruby version: 2.5

Make sure you're at least running ruby 2.5 before considering migrating.

## The Oauth Token Resource was removed

The access and refresh tokens are now stored in the `oauth_grants` table, and the `oauth_tokens` table is no longer necessary.

This means that:

* Both the table, columns and labels config options prefixed by `oauth_tokens` were removed.
* "Oauth Token Revocation" becomes "OAuth Grant Revocation", and all relevant options and text changed accordingly.
* OAuth management plugins also change (i.e. URL path for listing grants is `/oauth-grants`)

### How to migrate

The tl;dr is: you'll need to start by adding the new columns to the `oauth_grants` table, start backfilling the values in runtime, backfill historical grants in the background, then deploy v1.

This example is going to use `token` and `refresh_token` columns as an example, but it's extensible to `token_hash` and `refresh_token_hash`.

Add the required token columns to the `oauth_grants` table and start backfilling themm:

```ruby
# example sequel migration

Sequel.migration do
  up do
    alter_table :oauth_grants do
      String :code, nullable: true # to change the nullable constraint
      String :token, nullable: true, unique: true
      String :refresh_token, nullable: true, unique: true
    end


    # Then the runtime backfilling can happen. You can do that using a trigger on the `oauth_tokens` table

    run <<-SQL
CREATE OR REPLACE FUNCTION copy_tokens_to_grant()
  RETURNS trigger AS
$$
BEGIN
  UPDATE "oauth_grants" SET "oauth_grants"."token" = NEW."token",
    "oauth_grants"."refresh_token" = NEW."refresh_token",
    "oauth_grants"."expires_in" = NEW."expires_in",
    "oauth_grants"."code" = NULL
    WHERE "oauth_grants"."id" = NEW."oauth_grant_id";

RETURN NEW;
END;
$$
LANGUAGE 'plpgsql';

CREATE TRIGGER copy_tokens_to_grant
  AFTER INSERT
  ON oauth_tokens
  FOR EACH ROW
  EXECUTE PROCEDURE copy_tokens_to_grant();
    SQL
  end
end
```

Then you'll need too backfill grants created before the changes above.

```SQL
--- this is how to do it in SQL, but can also be accomplished with a ruby script looping on rows.

UPDATE "oauth_grants"
  INNER JOIN "oauth_tokens" ON "oauth_tokens"."oauth_grant_id" = "oauth_grants"."id"
  SET "oauth_grants"."token" = "oauth_tokens"."token",
    "oauth_grants"."refresh_token" = "oauth_tokens"."refresh_token",
    "oauth_grants"."expires_in" = "oauth_tokens"."expires_in",
    "oauth_grants"."code" = NULL
  WHERE "oauth_grants"."token" IS NULL;
```

And now you can deploy the app with v1 installed (after you've done the required changes).

## renamed options

The following auth config methods were renamed (rename them if you're redefining them):

* `description_param` (replaced by `oauth_applications_description_param`)
* `client_id_param` (replaced by `oauth_applications_client_id_param`)
* `oauth_applications_jws_jwk_column` (replaced by `oauth_applications_jwks_column`)
* `oauth_applications_jws_jwk_label` (replaced by `oauth_applications_jwks_label`)
* `oauth_application_jws_jwk_param` (replaced by `oauth_applications_jwks_param`)
* all config methods terminated in `"_error_status"` are now prefixed by `"oauth_"`
* all config methods terminated in `"_message"` are now prefixed by `"oauth_`
* all config methods terminated in `"_error_code`` are now prefixed by `"oauth"`
* `unique_error_message` config method was removed (not in use)
* `oauth_jwt_token_issuer` renamed to `oauth_jwt_issuer`

## Removed options

### Base options

* `oauth_application_default_scope`: if you were using it to pre-fill scopes in the Authorization form, or the New OAuth Application form, you'll have to do it yourself.

### JWT options

* `oauth_jwt_key`: can be replaced by using it as the value in `oauth_jwt_keys` (```oauth_jwt_keys("RS256" => [privkey])```);
* `oauth_jwt_algorithm`: can be replaced by using it as the key in `oauth_jwt_keys` (```oauth_jwt_keys("RS256" => [privkey])```);
* `oauth_jwt_public_key`:  can be replaced by using it as the value in `oauth_jwt_public_keys` (```oauth_jwt_public_keys("RS256" => [pubkey])```);
* `oauth_jwe_key`: can be replaced by using it as the value in `oauth_jwe_keys` (```oauth_jwe_keys((%w[RSA-OAEP A128CBC-HS256] => [privkey])```);
* `oauth_jwt_jwe_algorithm`: can be replaced by using it as the first element in the key tuple in `oauth_jwe_keys` (```oauth_jwe_keys(%w[RSA-OAEP A128CBC-HS256] => [privkey])```);
* `oauth_jwt_jwe_encryption_method`: can be replaced by using it as the second element in the key tuple in `oauth_jwe_keys` (```oauth_jwe_keys(%w[RSA-OAEP A128CBC-HS256] => [privkey])```);
* `oauth_jwe_public_key`:  can be replaced by using it as the value in `oauth_jwe_public_keys` (```oauth_jwt_public_keys(%w[RSA-OAEP A128CBC-HS256] => [pubkey])```);
* `oauth_jwt_legacy_algorithm`: can be replaced by adding it as a key to `oauth_jwt_public_keys`;
* `oauth_jwt_legacy_public_key`: can be replaced by adding it to the value set of `oauth_jwt_public_keys`, after the current key (```oauth_jwt_public_keys("RS256" => [pubkey, legacy_pubkey])```);

#### `oauth_jwt_key`

## `oauth_device_grant` feature becomes `oauth_device_code_grant`

In case you were using it directly, you should rename it.

## `use_oauth_*_grant` options were removed

One of the main changes in v1.0.0 is that one should enable the features one needs, explicitly. So when you used to have:

```ruby
rodauth do
  enable :oauth
end
```

you should now load the grants you use:


```ruby
rodauth do
  enable :oauth_authorization_code_grant, :oauth_pkce, :oauth_credentials_grant, :oauth_token_introspection
  # or
  enable :oidc, :oauth_implicit_grant
end
```

Now that the features are explicitly enable, there's is no more use for config methods for unsetting them, such as `use_oauth_implicit_grant_type?` or `use_oauth_pkce?`.


## `oauth_jwt_audience` and `oauth_jwt_issuer` repurposed as functions

To maintain legacy behaviour, you can return them in the function body.

```diff
- oauth_jwt_audience legacy_aud
- oauth_jwt_issuer legacy_iss
+ oauth_jwt_audience { legacy_aud }
+ oauth_jwt_issuer { legacy_iss }
```

## JAR (Secured authorization request) segregated in its plugin

It was previously being loaded in the `:oauth_jwt` plugin by default. If you require this funtionality, enable the plugin:

```ruby
enable :oauth_jwt_secured_authorization_request
```
