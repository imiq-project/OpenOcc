from ursina import *
from random import randint
import numpy as np
from panda3d.core import GraphicsOutput, Texture
import av
import json

class Car(Entity):

    def __init__(self):
        super().__init__(
            model="cube",
            color=color.red,
            scale=(1.5, 1, 3),
            position=(25, 0.5, 0),
            collider="box",
        )
        self.engine_sound = Audio("engine.mp3", loop=True, autoplay=True)
        self.speed = 0
        self.acceleration = 20
        self.turn_speed = 40
        self.friction = 5
        self.max_speed = 25
        self.hud = Sprite(
            'hud.png',
            parent=camera.ui,
            position = (0,0),
        )
        self.held_keys = set()

    def update(self):
        self.hud.scale=(window.aspect_ratio, 1)

        # Acceleration / braking
        if 'w' in self.held_keys:
            self.speed += self.acceleration * time.dt
        if 's' in self.held_keys:
            self.speed -= self.acceleration * time.dt

        # Clamp speed
        self.speed = clamp(self.speed, -self.max_speed / 2, self.max_speed)

        # Friction
        if 'w' not in self.held_keys and 's' not in self.held_keys:
            if self.speed > 0:
                self.speed -= self.friction * time.dt
            if self.speed < 0:
                self.speed += self.friction * time.dt
        if abs(self.speed) < 0.2:
            self.speed = 0

        # Steering
        if 'd' in self.held_keys:
            self.rotation_y += self.turn_speed * time.dt * (self.speed / self.max_speed)
        if 'a' in self.held_keys:
            self.rotation_y -= self.turn_speed * time.dt * (self.speed / self.max_speed)

        move_vector = self.forward * self.speed * time.dt
        self.position += move_vector

        # Check collision manually with buildings
        hit_info = self.intersects()
        if hit_info.hit:
            self.position -= move_vector  # Undo move if collided
            self.speed = 0

        self.engine_sound.pitch = 1.0 + abs(self.speed) / self.max_speed


class Game:

    def __init__(self) -> None:
        self.app = Ursina()

        window.title = "3D Car City with Collision"
        window.borderless = False

        # -------------------
        # Ground
        # -------------------
        ground_size = 1000
        ground = Entity(
            model="plane",
            scale=ground_size*2,
            texture="grass",
            texture_scale=(20, 20),
            collider=None,  # Ground itself is not blocking
        )
        Sky()

        # -------------------
        # Roads
        # -------------------
        road_spacing = 80
        road_width = 20

        # Vertical roads
        for x in range(-ground_size, ground_size, road_spacing):
            road = Entity(
                model="cube",
                scale=(road_width, 0.1, ground_size),
                position=(x, 0.05, 0),
                color=color.gray,
                collider=None,
            )

        # Horizontal roads
        for z in range(-ground_size, ground_size, road_spacing):
            road = Entity(
                model="cube",
                scale=(ground_size, 0.1, road_width),
                position=(0, 0.05, z),
                color=color.gray,
                collider=None,
            )

        # -------------------
        # Buildings
        # -------------------
        buildings = []
        for x in range(-ground_size, ground_size, road_spacing):
            for z in range(-ground_size, ground_size, road_spacing):
                if randint(0, 3) == 0:  # Randomly place buildings
                    height = randint(4, 12)
                    b = Entity(
                        model="cube",
                        scale=(road_spacing*.25, 12, road_spacing*.25),
                        texture_scale=(10, 10),
                        position=(x + road_spacing/2, height / 2, z + road_spacing/2),
                        texture="brick",
                        collider="box",
                    )
                    buildings.append(b)

        # -------------------
        # Car
        # -------------------
        self.car = Car()

        # -------------------
        # Camera
        # -------------------
        camera.parent = self.car
        camera.position = (0, 2, -1)
        camera.rotation_x = 5
        self.cam_texture = Texture()
        base.win.addRenderTexture(self.cam_texture, GraphicsOutput.RTMCopyRam)

    def get_window_frame(self):
        if not self.cam_texture.hasRamImage():
            self.cam_texture.makeRamImage()
        data = self.cam_texture.getRamImage()

        xsize = self.cam_texture.getXSize()
        ysize = self.cam_texture.getYSize()
        num_components = (
            self.cam_texture.getNumComponents()
        )  # usually 3 (RGB) or 4 (RGBA)

        # Convert raw buffer to numpy array
        np_image = np.frombuffer(data, dtype=np.uint8)
        np_image = np_image.reshape((ysize, xsize, num_components))
        np_image = np.flipud(np_image)
        return np_image

    def run(self):
        self.app.run()

    def ping(self, msg: str):
        self.car.held_keys = set(json.loads(msg))

if __name__ == "__main__":
    game = Game()
    game.run()
