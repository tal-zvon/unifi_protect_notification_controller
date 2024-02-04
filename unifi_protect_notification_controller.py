#!/usr/bin/env python

import asyncio
import httpx
from pydantic import BaseModel
from enum import StrEnum

# SECRETS
USERNAME = ""  # Your Unifi username
PASSWORD = ""  # Your Unifi password
BASE_URL = "https://192.168.1.1"  # The IP of the NVR

# This you'll need to get yourself
# Each key is the name of the camera, as you want to refer to it below
# Each value is the camera ID within unifi
# To get the ID of a camera, login to your NVR in firefox or chrome on a
# Desktop, open the Protect app, go to the "UniFi Devices" page, and look
# at the URL as you click on your different cameras
camera_ids = {
    "garage_camera": "...",
    "back_yard_camera": "...",
}


# URLs
LOGIN_URL = BASE_URL + "/api/auth/login"
CURRENT_USER_INFO_URL = BASE_URL + "/proxy/protect/api/users/self"
NOTIFICATION_URL = BASE_URL + "/proxy/protect/api/users/{USER_ID}/notifications"

####################################
# Pydantic Models for Request Data #
####################################

class NotificationType(StrEnum):
    PUSH = "push"
    EMAIL = "email"

class LoginRequest(BaseModel):
    username: str
    password: str
    rememberMe: bool = False
    token: str = ""

class Trigger(BaseModel):
    when: str = "always"
    location: str = "away"
    sendAnyway: bool = False
    schedules: list = []

class Camera(BaseModel):
    inheritFromParent: bool = True
    camera: str
    trigger: Trigger = Trigger()
    motion: list[NotificationType] = []
    alarmSmoke: list[NotificationType] = []
    alarmCmonx: list[NotificationType] = []
    alarmBabyCry: list[NotificationType] = []
    person: list[NotificationType] = []
    vehicle: list[NotificationType] = []
    animal: list[NotificationType] = []

class DetectionNotifications(BaseModel):
    cameras: list[Camera]

class ChangeNotificationRequest(BaseModel):
    state: str = "on"
    detectionNotifications: DetectionNotifications

############
# Requests #
############

async def login(client, username: str, password: str):
    data = LoginRequest(username=username, password=password)
    return await client.post(LOGIN_URL, json=data.model_dump(mode="json"))

async def get_current_user_info(client):
    return await client.get(CURRENT_USER_INFO_URL)

async def change_notification_settings(client, user_id, camera_id, csrf_token, enable_notifications=False):
    data = ChangeNotificationRequest(
        detectionNotifications=DetectionNotifications(
            cameras=[
                Camera(
                    camera=camera_id,
                    inheritFromParent=enable_notifications,
                )
            ]
        )
    )

    return await client.patch(
        NOTIFICATION_URL.format(USER_ID=user_id),
        json=data.model_dump(mode="json"),
        headers={"X-CSRF-Token": csrf_token}
    )

########
# Main #
########

async def main():
    async with httpx.AsyncClient(verify=False) as client:
        # Login and get CSRF token
        response = await login(client, USERNAME, PASSWORD)
        response.raise_for_status()
        csrf_token = response.headers.get("x-csrf-token")

        # Get current user id
        response = await get_current_user_info(client)
        response.raise_for_status()
        user_id = response.json()["id"]

        # Enable notifications
        response = await change_notification_settings(
            client,
            user_id=user_id,
            camera_id=camera_ids["garage_camera"],
            csrf_token=csrf_token,
            enable_notifications=True
        )
        response.raise_for_status()

        # Disable notifications
        #response = await change_notification_settings(
        #    client,
        #    user_id=user_id,
        #    camera_id=camera_ids["garage_camera"],
        #    csrf_token=csrf_token,
        #    enable_notifications=False
        #)
        #response.raise_for_status()

asyncio.run(main())
