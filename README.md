# ReactJS + Flask (REST API) + PostgreSQL boilerplate with Docker

This project allows to run a quick application with ReactJS (Javascript front-end), Flask (Python backend) and PostgreSQL (relational database) by running it on Docker containers.

This is intended as a quick project starter to avoid the overhead of writing a bunch of simple code to stick together backend + frontend with an authentication system.

### Features

A database named `application` (user: dev / password: mypassword) is initialized when the database container start. These default values can be changed in the `docker-compose.yml` file.
Running `alembic upgrade head` will create the tables for a working authentication system.

The React App has an API library and has some buttons and inputs to call the endpoints needed.

**Hot reloading** is enabled for the React and Flask code, after every code change the container is up-to-date automatically !

### Run the app

Everything is containerized from the client, backend to the database. So all you need is Docker installed, and then you can run :

```
docker-compose up --build
```

And your app will be up on the *port 3000* !

### Special notes

##### Fully Resetting Database
```
docker rm -f -v postgres
docker-compose up --build
alembic upgrade head
```


##### Connecting to development DB
```
psql postgresql://dev:mypassword@localhost:5432/application
```
