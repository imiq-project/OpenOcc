# Vehicle SDK
*For an in-depth technical description, please refer to [Technical Details](technical.md)*

The vehicle sdk enables you to integrate your vehicle with OpenOcc.
We treat a vehicle as a very broad concept, which can be anything somewhat steer-able.
This includes cars, bikes, robots, drones or even static things like a rotatable camera.
To model all these heterogenous kinds of things, we introduce the abstract concept of a "Super-Vehicle".
The Super-Vehicle has all imaginable features like all sorts of controls and cameras.

When implementing your vehicle for OpenOcc you select a subset of all these features fitting your vehicle.
Using the sdk you then map these features to the correct physical interpretation.
For example you map the concept of steering based on direction and speed to the actual movement of your wheels.
On the other side, an operator can use OpenOcc's client to control any kind of vehicle by controlling it as a subset of the Super-Vehicle.
This means, that we map different input modes to abstract control commands of the Super-Vehicle

<div align="center">
    <img src="supervehicle.drawio.svg" alt="Super Vehicle" width="600">
</div>

## Data model of the Super-Vehicle
All features of the Super-Vehicle fall into three categories:

**Continuous outgoing data**
This data is produced continuously by the vehicle.
Noticeable examples are the gps position, battery level and camera streams.
These data is transferred periodically over an unreliable channel.

**Continuous incoming data**
This data is consumed continuously by the vehicle.
Examples include the speed and steering angle.
These are only transferred to your vehicle during teleoperation and periodically over an unreliable channel.

**Commands**
Many features are modeled as one-shot commands.
Noticeable examples are emergency stop and navigation requests.
Commands are transferred guaranteed one time per request over a reliable channel

Given these categories, we define the following properties for the Super-Vehicle:

| Category | Name | Data types | Comment |
|---|---|---|---|
| Incoming | motion | `Int8, Int8` | Move the vehicle given a speed and angle |
| Outgoing | front_camera | `Video` | Front camera frames |
| Outgoing | back_camera | `Video` | Back camera frames |
| Outgoing | left_camera | `Video` | Left camera frames |
| Outgoing | right_camera |` Video` | Right camera frames |
| Outgoing | position | `UInt64, UInt64` | Vehicle's current position in latitude / longitude |
| Outgoing | battery_level | `UInt8` | Current battery level |
| Command  | emergency_halt | `bool` | Triggers / releases and emergency halt |
| Command  | move_to | `gps-lat, gps-lon` | Instructs the vehicle to move to a certain position |
| Command  | load_cargo | | Loads cargo at the current position onto the vehicle |
| Command  | drop_cargo | | Drops the cargo loaded onto the vehicle |

For further technical description, please refer to [Technical Details](technical.md).