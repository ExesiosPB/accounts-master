# Accounts Server

The repo contains the code for the accounts server, which runs at
https://accounts.placingthebrand.com.

Users are redirected to this URL to log in and log out the dashboard.

## How does logging in work?

1. When not logged in to the dashboard (and when the JWT token expires 3h), the user is redirected to /login on accounts server
2. The user sees a log in form on the accounts server and logs in. The user is redirected to /token, this creates a JWT token agaisnt their email addresses that lasts 3 hours.
3. This token is stored in db.tokens and then they are redirected to dashboard.placingthebrand.com
4. Redux middleware checks if session is valid

## How does logging out work?

1. Go to /logout on dashboard site
2. User's JWT session is destroyed on the dashboard site, then they are redirected to /logout on the accounts server
3. /logout on accounts server destroys their session from the db.session
4. User is then shown the login page on the accounts server

## How is this going to be deployed?

Users will see and be able to go to accounts.placingthebrand.com
For now it will just be a NodeJS application deployed to a server, with the accounts.placingthebrand.com linked to it

## Enviroment Variables

```process.env.DB_HOST, process.env.DB_PORT, process.env.DB_NAME``` Database connection config


https://stackoverflow.com/questions/36948557/how-to-use-redux-to-refresh-jwt-token
