# Technical Details

*Please read [Vehicle SDK](vehicle.md) beforehand to understand the overall concept of the Super Vehicle*

Your vehicle is connected to the SteeringWheel server via WebTransport constantly.
Additionally, an operator might open a WebRTC connection for teleoperation.
A vehicle can have at most one WebRTC connection open.

<div align="center">
  <img src="figures/architecture.drawio.svg" alt="SteeringWheel Architecture">
</div>

## IOConf
When defining your own vehicle you select the features of the Super-Vehicle you want to support.
These features are then collected and stored in an *IOConf*.
The IOConf contains all the outgoing data, incoming data and commands your vehicle support.
Assuming you chose to implement `set_motion`, `get_front_camera` and `emergency_halt`, then your IOConf looks as follows:
```json
{
  "incoming": [
    {
      "name": "motion",
      "types": ["int8", "int8"]
    }
  ],
  "outgoing": [
    {
      "name": "front_camera",
      "types": ["video"]
    }
  ],
  "commands": [
    {
      "name": "emergency_halt"
    }
  ]
}
```
Normally, you do not need to define your IOConf manually.
This is done by the `VehicleClient` class internally using reflection.

## Connection Establishment
The following figure shows the initial connection process, which is carried out via WebTransport:

<div align="center">
  <img src="figures/connection.drawio.svg" alt="SteeringWheel Architecture">
</div>

First, the client connects to the server.
After authentication, it receives a list of all registered vehicles including their IOConf.
Additionally, the client receives a list of ICE servers configured.
This will be used later for WebRTC
Second, the vehicle connects to the server.
In the connection attempt, it also sends its IOConf.
After authentication, the server responds with a list of ICE servers configured (as for the client).
From now on, the vehicle also periodically sends its outgoing data as specified in the IOConf.
Additionally, the server informs all clients about the now connected vehicle.
Please note, that the order of registration might be swapped.
This does not change the process.

## Sending Commands
Sending commands is done in a rpc-like procedure:

<div align="center">
  <img src="figures/rpc.drawio.svg" alt="RPC">
</div>

Within this procedure, the SteeringWheel server simply redirects the command and it's parameters to the vehicle and redirects the result back to the client.
The request is formatted as JSON:
```json
{
    "Type": "rpcRequest",
    "From": <client-id>,
    "To": <vehicle-id>,
    "Payload": {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": <counter>
    }
}
```
The response is formatted as follows:
```json
{
    "Type": "rpcResponse",
    "To": <client-id>,
    "From": <vehicle-id>,
    "Payload": {
      "jsonrpc": "2.0",
      "result": <result>,
      "id": <counter>
    }
}
```
For the payload we use JSON-RPC.

## WebRTC Connection
To understand the following section, you should be familiar with basic WebRTC concepts like signaling and ICE gathering (see https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Signaling_and_video_calling for infos).

<div align="center">
  <img src="figures/webrtc.drawio.svg" alt="RPC">
</div>

The WebRTC connection establishment relies on the RPC mechanism explained before.
First, the client generates an SDP offer and sends it to the vehicle.
The vehicle, in turn, generates an SDP answer and returns it as a result of the RPC request.
Now the client starts the ICE gathering process and sends ICE candidates to the vehicle.
Once a matching candidate pair is found, the WebRTC connections is established.
From now on, the vehicle and client have a peer-to-peer connection.
They use it to periodically exchange incoming and outgoing data.
Additionally, the vehicle sends outgoing data via WebTransport so that all clients are informed about the status.

Using these two connections, data is transferred as follows:

|                                   | WebTransport | WebRTC                                             |
|-----------------------------------|--------------|----------------------------------------------------|
| Outgoing (Audio, Video)           | datagram     | WebRTC media track                                 |
| Incoming (Audio, Video)           | -            | WebRTC media track                                 |
| Outgoing (Others)                 | datagram     | Datachannel with ordered: false, maxRetransmits: 0 |
| Incoming (Others)                 | -            | Datachannel with ordered: false, maxRetransmits: 0 |
| Commands                          | stream       | datachannel with ordered: true                     |

## Encoding of outgoing / incoming data
While commands are encoded as JSON, we encode outgoing/incoming data in binary packed data as it is transferred periodically.
Encoding is determined by your IOConf.

Assuming your IOConf looks as follows:
```json
{
  "outgoing": [
    {
      "name": "battery_level",
      "types": ["uint8"]
    },
    {
      "name": "position",
      "types": ["int32", "int32"]
    }
  ]
}
```

Then each outgoing value is put into a flat binary buffer:

<div align="center">
  <img src="figures/coding.drawio.svg" alt="Coding">
</div>
