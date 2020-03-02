# ReactJS + Flask (REST API) + PostgreSQL boilerplate with Docker

This project allows to run a quick application with ReactJS (Javascript front-end), Flask (Python backend) and PostgreSQL (relational database) by running it on Docker containers.

### Features

A database named `sport_stats` (user: dev / password: mypassword) is initialized when the database container start. These default values can be changed in the `docker-compose.yml` file.
A table `players` with one record is created by copying the file `db/init/init.sql` into the `/docker-entrypoint-initdb.d/` container directory ([see documentation of postgres official image](https://hub.docker.com/_/postgres/)).

The Flask application uses SQLAlchemy to retrieve the content of the `players`, ReactJS call the REST API and display it !

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
