"""Small API client for the Streamlit dashboard; it never accesses databases."""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests


class DashboardAPIError(RuntimeError):
    def __init__(self, status_code: int | None, message: str):
        super().__init__(message)
        self.status_code = status_code


class DashboardAPI:
    """Authenticated, non-caching client for the Avarna HTTP API."""

    def __init__(self, base_url: str, token: str | None = None, timeout: float = 8.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def request(self, method: str, path: str, *, params: dict | None = None,
                json_body: dict | None = None, form: dict | None = None) -> Any:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = requests.request(
                method, f"{self.base_url}{path}", headers=headers,
                params=params, json=json_body, data=form, timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise DashboardAPIError(None, "The API could not be reached.") from exc

        if response.status_code >= 400:
            message = "The API rejected the request."
            try:
                payload = response.json()
                error = payload.get("error", {})
                if isinstance(error, dict) and isinstance(error.get("message"), str):
                    message = error["message"]
            except (ValueError, AttributeError):
                pass
            raise DashboardAPIError(response.status_code, message)
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise DashboardAPIError(response.status_code,
                                    "The API returned an unreadable response.") from exc

    @staticmethod
    def segment(value: str) -> str:
        return quote(value, safe="")

    def login(self, username: str, password: str) -> dict:
        return self.request("POST", "/auth/token", form={
            "username": username, "password": password,
        })

    def get(self, path: str, *, params: dict | None = None) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: dict | None = None) -> Any:
        return self.request("POST", path, json_body=body)

    def patch(self, path: str, body: dict) -> Any:
        return self.request("PATCH", path, json_body=body)

    def put(self, path: str, body: dict) -> Any:
        return self.request("PUT", path, json_body=body)

    def delete(self, path: str, body: dict) -> Any:
        return self.request("DELETE", path, json_body=body)
