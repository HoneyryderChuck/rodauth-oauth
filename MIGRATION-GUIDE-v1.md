# Migration Guide v1

This guide is to share a few helpful tips to migrate a production app using `rodauth-oauth` v0.10 to v1. There are quite a few breaking changes which will require some work to pull through, and I'll go 1 by 1.

**Most important tip**: Make sure you're running v0.10.3 before you try to migrate to v1!

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
