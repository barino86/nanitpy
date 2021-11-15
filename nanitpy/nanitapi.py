"""Module that implements the nanitapi class."""
from __future__ import annotations

import os
from typing import Dict, Any, Union
import json
import logging
import ssl
from datetime import datetime
from types import MethodType

import aiohttp
import certifi
from aiohttp import ClientResponseError

# from .const import (
#     AuthenticationResponse,
#     MfaVerificationResponse,
#     SwitchAttribute,
#     VivintDeviceAttribute,
# )
# from .enums import ArmedState, GarageDoorState, ZoneBypass
# from .exceptions import (
#     VivintSkyApiAuthenticationError,
#     VivintSkyApiError,
#     VivintSkyApiMfaRequiredError,
# )

_LOGGER = logging.getLogger(__name__)

NANIT_API_ENDPOINT = "https://api.nanit.com"


class NanitApi:
    def __init__(self,
                 email: str,
                 password: str,
                 client_session: aiohttp.ClientSession | None = None):
        self.__email = email
        self.__password = password
        self.__client_session = client_session or self.__get_new_client_session()
        self.__has_custom_client_session = client_session is not None

    def is_session_valid(self) -> bool:
        """Return the state of the current session."""
        cookie = self.__client_session.cookie_jar._cookies["www.vivintsky.com"].get("s")
        if not cookie:
            return False
        cookie_expiration = datetime.strptime(
            cookie.get("expires"), "%a, %d %b %Y %H:%M:%S %Z"
        )
        return True if cookie_expiration > datetime.utcnow() else False

    async def connect(self) -> dict:
        """Connect to VivintSky Cloud Service."""
        # if self.__has_custom_client_session and self.is_session_valid():
        #     authuser_data = await self.get_authuser_data()
        # else:
        authuser_data = await self.__get_nanit_session(
            self.__email, self.__password
        )
        if not authuser_data:
            raise Exception("Unable to login to Vivint")
        self.__client_session.headers['Authorization'] = authuser_data.get('access_token')
        return authuser_data

    async def get_babies(self) -> dict:
        babies = await self.__get('babies')
        return babies

    def __get_new_client_session(self) -> aiohttp.ClientSession:
        """Create a new aiohttp.ClientSession object."""
        ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=certifi.where()
        )
        connector = aiohttp.TCPConnector(enable_cleanup_closed=True, ssl=ssl_context)

        return aiohttp.ClientSession(connector=connector)

    async def __get_nanit_session(self, email: str, password: str) -> dict:
        """Login into the Nanit platform with the given username and password.

        Returns auth user data if successful.
        """
        return await self.__post(
            "login",
            headers={"content-type": "application/json"},
            data=json.dumps(
                {
                    "email": email,
                    "password": password
                }
            ).encode("utf-8"),
        )

    async def __get(
            self,
            path: str,
            headers: Dict[str, Any] = None,
            params: Dict[str, Any] = None,
            allow_redirects: bool = None,
    ) -> Union[dict, None]:
        """Perform a get request."""
        return await self.__call(
            self.__client_session.get,
            path,
            headers=headers,
            params=params,
            allow_redirects=allow_redirects,
        )

    async def __post(
            self,
            path: str,
            headers: Dict[str, Any] = None,
            data: bytes = None,
    ) -> Union[dict, None]:
        """Perform a post request."""
        return await self.__call(self.__client_session.post, path, headers=headers, data=data)

    async def __put(
            self,
            path: str,
            headers: Dict[str, Any] = None,
            data: bytes = None,
    ) -> Union[dict, None]:
        """Perform a put request."""
        return await self.__call(
            self.__client_session.put, path, headers=headers, data=data
        )

    async def __call(
            self,
            method: MethodType,
            path: str,
            headers: Dict[str, Any] = None,
            params: Dict[str, Any] = None,
            data: bytes = None,
            allow_redirects: bool = None,
    ) -> Union[dict, None]:
        """Perform a request with supplied parameters and reauthenticate if necessary."""
        if path != "login" and not self.is_session_valid():
            await self.connect()

        if self.__client_session.closed:
            raise Exception("The client session has been closed")

        # is_mfa_request = path == VIVINT_MFA_ENDPOINT

        # if self.__mfa_pending and not is_mfa_request:
        #     raise VivintSkyApiMfaRequiredError(AuthenticationResponse.MFA_REQUIRED)

        resp = await method(
            f"{NANIT_API_ENDPOINT}/{path}",
            headers=headers,
            params=params,
            data=data,
            allow_redirects=allow_redirects,
        )
        async with resp:
            data: dict = await resp.json(encoding="utf-8")
            if resp.status in [200, 201]:
                return data
            # elif resp.status == 302:
            #     return {"location": resp.headers.get("Location")}
            # elif resp.status == 401:
            #     message = (
            #         data.get(MfaVerificationResponse.MESSAGE)
            #         if is_mfa_request
            #         else data.get(AuthenticationResponse.MESSAGE)
            #     )
            #     if message == AuthenticationResponse.MFA_REQUIRED:
            #         self.__mfa_pending = True
            #         raise VivintSkyApiMfaRequiredError(message)
            #     raise VivintSkyApiAuthenticationError(message)
            else:
                resp.raise_for_status()
                return None


if __name__ == '__main__':

    import asyncio
    from pprint import pprint

    # import requests
    # email = os.environ['nanit_email']
    # password = os.environ['nanit_password']
    #
    # resp = requests.post(f"{NANIT_API_ENDPOINT}/login", data=json.dumps({
    #     "email": email,
    #     "password": password
    # }).encode("utf-8"), headers={"content-type": "application/json"})
    # print(json.loads(resp.content))
    async def main():
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Demo started")

        email = os.environ['nanit_email']
        password = os.environ['nanit_password']

        client = NanitApi(email, password)
        data = await client.connect()

        baby_data = await client.get_babies()

        pprint(baby_data)

    asyncio.run(main())


