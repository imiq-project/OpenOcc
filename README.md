<div align="center">
  <img src="client/public/logo.png" alt="OpenOcc Logo" width="300">
</div>

[![SDK](https://github.com/imiq-project/OpenOcc/actions/workflows/check-sdk.yml/badge.svg)](https://github.com/imiq-project/OpenOcc/actions/workflows/check-sdk.yml)
[![Server](https://github.com/imiq-project/OpenOcc/actions/workflows/build-server.yml/badge.svg)](https://github.com/imiq-project/OpenOcc/actions/workflows/build-server.yml)
[![Client](https://github.com/imiq-project/OpenOcc/actions/workflows/build-client.yml/badge.svg)](https://github.com/imiq-project/OpenOcc/actions/workflows/build-client.yml)

# OpenOcc

A comprehensive teleoperation and vehicle control platform with real-time communication, mission planning, and remote operation capabilities.

## Overview

OpenOcc is a full-stack application for remote vehicle operation and control. It provides operators with a web-based interface to control vehicles, monitor telemetry, plan missions, and manage vehicle settings through secure WebRTC and WebTransport connections.

### Key Features

- **Real-time Teleoperation**: Control vehicles remotely with low-latency communication
- **Mission Planning**: Create and execute autonomous missions with geofencing support
- **Live Telemetry**: Monitor vehicle status, alerts, and sensor data in real-time
- **Web-Based Interface**: Modern React/Next.js dashboard with 3D visualization and mapping
- **Build on modern Protocols**: WebRTC and WebTransport for reliable communication
- **Python SDK**: Programmatic vehicle control and integration
- **Secure Authentication**: Built-in user authentication and authorization
- **Docker Deployment**: Containerized services for easy deployment

## Architecture
<div align="center">
  <img src="doc/figures/architecture.drawio.svg" alt="OpenOcc Architecture">
</div>

### Component Overview

**Vehicle** — Any entity that can move, whether it's a car, robot, AGV, or drone. OpenOcc provides client libraries in Python for simple integration, allowing vehicles to connect and communicate with the platform seamlessly.

**Operator** — A human who monitors and controls vehicles in real-time. Operators can intervene when needed and use teleoperation to navigate vehicles remotely, making decisions based on live telemetry and video feeds.

**Client** — The user interface designed for operators. The client displays vehicles on a map and provides controls for teleoperation. Multiple clients can be open simultaneously for the same operator, and while OpenOcc includes its own web-based client, the platform is flexible enough to integrate with any compatible interface.

**Server** — Built in Go for stability and performance, the server acts as a central broker. It connects both vehicles and clients via WebTransport, forwarding messages between them in real-time while maintaining efficient, low-latency communication.

## Vehicle SDK Quick Start

### Install Python SDK

Requires Python >= 3.9 and pip >= 24:

```bash
pip install git+https://github.com/imiq-project/OpenOcc.git@main#subdirectory=vehicle-sdk
```

### Basic Usage

```python
import logging
import argparse
import asyncio

from openocc.vehicle import Vehicle, VehicleClient
from openocc.util import animate_rainbow


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)-10.10s - %(levelname)-8.8s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--insecure", action="store_true", default=False)
    args = parser.parse_args()

    class DummyVehicle(Vehicle):
        VEHICLE_ID = "my_vehicle"

        def __init__(self):
            self.front_phase = 0
            self.back_phase = 0

        def set_motion(self, speed, angle):
            pass

        def get_front_camera(self):
            self.front_phase += 0.1
            return animate_rainbow(self.front_phase)

        def get_back_camera(self):
            self.back_phase -= 0.1
            return animate_rainbow(self.back_phase)

        def emergency_halt(self, enable: bool):
            logging.info("Emergency halt triggered!")

    client = VehicleClient(args.host, args.port, args.insecure, DummyVehicle())
    await client.loop()

if __name__ == "__main__":
    asyncio.run(main())
```

See [vehicle-sdk/examples](vehicle-sdk/examples/) for more detailed examples and [Vehicle sdk](doc/vehicle.md) for in-depth documentation.


## Server Quick Start

### Express Turn

We recommend using a STUN/TURN server.
This is not a strict requirement, but heavily recommended as STUN/TURN servers are needed for WebRTC to function properly when connecting peers from different networks.
To get a STUN/TURN server, create a free account at https://www.expressturn.com.

### UDP buffer size

Increase udp buffer size (needed for WebTransport)

```sh
echo -e "net.core.rmem_max = 7500000\nnet.core.wmem_max = 7500000" | sudo tee /etc/sysctl.d/99-openocc.conf
sudo sysctl -p /etc/sysctl.d/99-openocc.conf
```

### Server startup

Create and adapt your `compose.yml` file:

```yaml
services:
  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: occ
      POSTGRES_PASSWORD: occ
      POSTGRES_DB: occ
    volumes:
      - pgdata:/var/lib/postgresql/data

  server:
    image: ghcr.io/imiq-project/openocc-server:latest
    command: ./app --use-acme --hostname your-domain.com
    volumes:
      - certs:/certs
    environment:
      - EXPRESS_TURN_USERNAME=<username>
      - EXPRESS_TURN_PASSWORD=<password>
      - DATABASE_URL=postgres://occ:occ@postgres:5432/occ?sslmode=disable
    ports:
      - 80:80/tcp   # http
      - 443:443/tcp # https
      - 443:443/udp # http/3

  client:
    image: ghcr.io/imiq-project/openocc-client:latest

volumes:
  pgdata:
  certs:
```

Then start the server/client using docker:

```bash
docker compose up -d
```

### Viewing on localhost using Chrome

If you want to test your server out on chrome, you must use a self-signed certificate.
For this, replace the `command` and `volumes` from above as follows:

```yml
    command: ./app
    volumes:
      - ./certs:/certs
```

Certificates are placed in the `certs/` directory. Self-signed certificates are generated automatically if not present.

Additionally you must import the certificate in Chrome's certificate settings at:
chrome://certificate-manager/localcerts/usercerts

Then start Chrome:
```sh
google-chrome --enable-quic --origin-to-force-quic-on=localhost:443 https://localhost
```

## Development Setup

The repository already ships a `compose.yml`suited for a local setup.
Create a `compose.override.yml` to adapt it for your local environment:

```yaml
services:
  server:
    build:
      dockerfile: Dockerfile.dev
    environment:
      - EXPRESS_TURN_USERNAME=<username>
      - EXPRESS_TURN_PASSWORD=<password>
    volumes:
      - ./src:/app
    command: sleep infinity
  client:
    build:
      dockerfile: Dockerfile.dev
    volumes:
      - ./client:/app
```

Then start services:

```bash
docker compose up -d
```

Start the client:

```bash
cd client
npm install
npm run dev
```

Start the server (separate terminal):

```bash
cd src
go build
./src
```

## Troubleshooting

### Error: "failed to sufficiently increase receive buffer size"

This typically occurs on Linux systems with restrictive network buffer limits. Increase them:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

To make permanent:
```bash
echo -e "net.core.rmem_max = 7500000\nnet.core.wmem_max = 7500000" | sudo tee /etc/sysctl.d/99-openocc.conf
sudo sysctl -p /etc/sysctl.d/99-openocc.conf
```

### Database Connection Issues

Ensure PostgreSQL is running and the `DATABASE_URL` is correct:

```bash
docker compose logs postgres
```

### Certificate Errors

Generate self-signed certificates:

```bash
cd certs
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### WebRTC Connection Issues

Check TURN server configuration and ensure ports 443/tcp and 443/udp are accessible.

On Firefox:
about:webrtc

On Chrome:
chrome://webrtc-internals
