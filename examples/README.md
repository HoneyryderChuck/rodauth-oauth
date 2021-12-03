# Example Applications

Once you'll have all dependencies installed, you can run the scripts directly:

```
> ruby authorization_server/app.rb
```

The databases are in-memory (by default, the examples run sqlite). If you want to persist and use your preferred db engine, set the `DATABASE_URL` environment variable in the authorization server process.

The authorization servers allow you to test the following journeys:

* Authorize flow;
* Account creation (this is a rodauth feature);
* OAuth Applications management;

The authorization server is available under `http://localhost:9292`.

The examples encompass 4 use-cases, which are described below.

# 1. Authorization Server / Client Application

This is the most basic setup for the OAuth Server application, which also serves the reources.

## How to run

```
On one shell, do
> ruby authorization_server/app.rb
On another shell, do
> ruby client_application/app.rb
```

## How to use

On your browser, go to `http://localhost:9293`. Click `Authorize` and login in the authorization server with "foo@bar.com" as email address, and "password" as your password. You should see a list of books if you set the right scope for the access token.

## What's relevant to know

You should pay attention to the queries being done in the authorization server, particularly when verifying the token on resource retrieval.


# 2. Authorization Server / Client Application / Resource Server

In this example, the resource server is separate from the authorization server.

## How to run

```
On one shell, do
> ruby authorization_server/app.rb
On another shell, do
> RESOURCE_SERVER="http://localhost:9294" ruby client_application/app.rb
On another
> ruby resource_server/app.rb
```

## How to use

Same as the previous one. However, see how the books are retrieved from a different domain now.

## What's relevant to know

Be aware of the resource/authorization server communication when books are retrieved.

# 3. JWT Authorization Server / Client Application

In this example, the authorization server generates JWT access tokens.

## How to run

```
On one shell, do
> ruby jwt/authorization_server/app.rb
On another shell, do
> ruby jwt/client_application/app.rb
```

## How to use

On your browser, go to `http://localhost:9293`. Click `Authorize` and login in the authorization server with "foo@bar.com" as email address, and "password" as your password. You should see a JWT token being sent in the `Authorization` header of resource retrieval.

## What's relevant to know

As there isn't a token lookup when verifying the token (the signature of the JWT is verified instead), you should see significant improvements here.

# 4. OpenID

This is a setup of an OpenID provider and consumer, where the provider has auto-discovery, and the client uses an omniauth/openid-compatible library to integrate.

## How to run

```
On one shell, do
> ruby oidc/authorization_server.rb
On another shell, do
> ruby oidc/client_application.rb
```

## How to use

On your browser, go to `http://localhost:9293`. Click `Authenticate` and login in the authorization server with "foo@bar.com" as email address, and "password" as your password. You should see the user's name in the top-right corner, besides the same list of books.

## What's relevant to know

The user info is coming from the `id_token`, and is used to identify the user in the UI.

