"""IP address and geolocation utilities."""

from typing import Dict, Optional

from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> str:
    """
    Get the client's IP address from the request.

    Handles proxied requests by checking X-Forwarded-For header first.

    Args:
        request: The Django HttpRequest object

    Returns:
        Client IP address as a string
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")

    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first one
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR", "0.0.0.0")

    return ip


# TODO: Este parece que no se está usando en ningún lado
def get_geo_location(ip_address: str) -> Optional[Dict[str, str]]:
    """
    Get geographic location information for an IP address.

    This is a placeholder implementation. In production, you would integrate
    with a geolocation service like MaxMind GeoIP2, IP2Location, or ipapi.co.

    Args:
        ip_address: The IP address to look up

    Returns:
        Dictionary with location data or None if unavailable
        Expected keys: city, region, country, country_code, latitude, longitude
    """
    # Skip for local IPs
    if (
        ip_address.startswith("127.")
        or ip_address.startswith("192.168.")
        or ip_address == "0.0.0.0"
    ):
        return None

    # TODO: Implement actual geolocation lookup
    # Example with ipapi.co (free tier, requires requests):
    #
    # try:
    #     import requests
    #     response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=2)
    #     if response.status_code == 200:
    #         data = response.json()
    #         return {
    #             'city': data.get('city'),
    #             'region': data.get('region'),
    #             'country': data.get('country_name'),
    #             'country_code': data.get('country_code'),
    #             'latitude': data.get('latitude'),
    #             'longitude': data.get('longitude'),
    #         }
    # except Exception:
    #     pass

    return None
