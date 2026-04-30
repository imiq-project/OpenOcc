# Technical Details

*Please read [Vehicle SDK](vehicle.md) beforehand to understand the overall concept of the Super Vehicle*

Your vehicle is connected to the OpenOcc server via WebTransport constantly.
Additionally, an operator might open a WebRTC connection for teleoperation.

<div align="center">
  <img src="architecture.drawio.svg" alt="OpenOcc Architecture">
</div>

## Protocol
Using these two connections, data is transferred as follows:

|                                   | WebTransport | WebRTC                                             |
|-----------------------------------|--------------|----------------------------------------------------|
| Outgoing (Audio, Video)           | datagram     | WebRTC media track                                 |
| Incoming (Audio, Video)           | -            | WebRTC media track                                 |
| Outgoing (Others)                 | datagram     | Datachannel with ordered: false, maxRetransmits: 0 |
| Incoming (Others)                 | -            | Datachannel with ordered: false, maxRetransmits: 0 |
| Commands                          | stream       | datachannel with ordered: true                     |
