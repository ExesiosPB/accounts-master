# Accounts Server

The repo contains the code for the accounts server, which runs at
https://accounts.placingthebrand.com.

Users are redirected to this URL to log in and log out the dashboard.

## How does logging in work?

1. When not logged in to the dashboard (and when the JWT token expires 3h), the user is redirected to /login on accounts server
2. The user sees a log in form on the accounts server and logs in. The user is redirected to /token, this creates a uuid token that is stored on the db.tokens database, they are then redirected to the dashboard
3. The dashboard checks its session to see if it has a user, if it doesn't it makes a request to /token/:TOKEN on the accounts server
4. This deletes the token in db.tokens and then sends a JWT token back as a JSON response
4. Redux middleware checks if session is valid

## How does logging out work?

1. Dashboard site clears the jwtToken from it's storage, and clears the redux user
2. They are then redirected too /logout on the accounts server
3. /logout on accounts server destroys their session from the db.session
4. User is then shown the login page on the accounts server

## How is this going to be deployed?

Users will see and be able to go to accounts.placingthebrand.com
For now it will just be a NodeJS application deployed to a server, with the accounts.placingthebrand.com linked to it

## Enviroment Variables

```process.env.DASHBOARD_HOST``` - Placing The Brand dashboard app url, should normally be dashboard.placingthebrand.com but defaults to http://localhost:8080

```process.env.DB_HOST``` - Name of the database host defaults to localhost

```process.env.DB_PORT``` - Port that the database is hosted on defaults to 27017

```process.env.DB_NAME``` - Name of the database table defaults too pb_accounts

```process.env.MONGODB_URI``` - The URL of the db that mongodb provides

```process.env.PORT``` - Port number to host server on


https://stackoverflow.com/questions/36948557/how-to-use-redux-to-refresh-jwt-token
