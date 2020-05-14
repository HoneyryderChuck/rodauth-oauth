# Roda::Oauth Example

This example app is an authorization server, and allows one to set an OAuth application to another test app you might have running locally.

It also sets itself as an Oauth client application, for testing purposes (**only if you are running on port 9292 from localhost**).

# Run the app

```
> bundle exec rackup
```

This will start the server on `http://localhost:9292`. It contains the basic `rodauth` boilerplate to allow one to create an account and login, which should be the first thing you do. By default, it'll create a local `sqlite` database, unless you define a `DATABASE_URL` and run the necessary migrations yourself.

You can then go to the "Oauth applications" navigation bar and set up an OAuth application to test an integration;

Or you can follow the "oauth with myself" link, and see an example of the Authorization form and token generation.

## Authorization flow

Once you have an application set up, the authorization form will be accessible in a URL like this:

```
http://localhost:9292/oauth-authorize?client_id=${CLIENT_ID}&state=${STATE}
```

Pressing "Authorize" will redirect back to the client application redirect URI, where one can generate an oauth token and proceed to using it.

Pressing "Cancel" redirects also back to the application redirect URI, with an "error" query param, as per the spec.