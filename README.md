# RAID App

This project uses Docker Compose for easy setup, building, and deployment.

## Getting Started

1. **Copy the sample Docker Compose file:**

    ```sh
    cp sample-docker-compose.yml docker-compose.yml
    ```

2. **Build and start the application:**

    ```sh
    docker compose up --build
    ```

    This command will build all images and start the required services as defined in `docker-compose.yml`.

    If the container was brought down due to any reason apart from new dependancy changes, run

    ```sh
    docker compose up
    ```

## Stopping the Application

To stop the services, press `Ctrl+C` or run:

```sh
docker compose down
```

## Notes

- Ensure Docker and Docker Compose are installed on your system.
- Update `docker-compose.yml` as needed for your environment.
- If you make changes to the Dockerfile or dependencies, rerun with `docker compose up --build` to rebuild the images.