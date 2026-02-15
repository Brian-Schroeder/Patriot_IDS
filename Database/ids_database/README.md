IDS Database service

This folder contains a small Node.js service that exposes a simple API for storing IDS alerts in MongoDB, plus Dockerfiles to run it together with a MongoDB container.

Quick start:

1. Copy `.env.example` to `.env` and adjust if needed.
2. From this directory run:

```sh
docker compose up --build
```

The service listens on port 3000 inside the container and is mapped to host port 3001 by the compose file. MongoDB is exposed on 27017.

Testing via Docker
------------------

1. Start the stack (detached):

```sh
cd Database/ids_database
docker compose up --build -d
```

2. Verify the app is running and connected to the database:

```sh
docker compose logs -f app
curl http://localhost:3001/health
# expected: {"status":"ok","db":"connected"}
```

Post a test alert from Windows CMD
---------------------------------

Open a Windows Command Prompt (not PowerShell) and run this `curl` command (note the escaping of double quotes):

```cmd
curl -i -X POST "http://localhost:3001/alerts" -H "Content-Type: application/json" -d "{\"alert_type\":\"test\",\"source_ip\":\"1.2.3.4\",\"description\":\"test alert from CMD\",\"level\":\"LOW\"}"
```

Then list recent alerts:

```sh
curl http://localhost:3001/alerts
```

Notes
-----
- If you use MongoDB Atlas via the `MONGODB_URI` in `.env`, ensure your IP is allowed in Atlas Network Access.
- If the POST returns a JSON parse error, use a file payload instead (create `payload.json` and use `-d @payload.json`).
- To stop and remove containers:

```sh
docker compose down
```

