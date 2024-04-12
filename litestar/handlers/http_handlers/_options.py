from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

from litestar.constants import DEFAULT_ALLOWED_CORS_HEADERS
from litestar.datastructures import Headers
from litestar.enums import HttpMethod, MediaType
from litestar.handlers import HTTPRouteHandler
from litestar.response import Response
from litestar.status_codes import HTTP_204_NO_CONTENT, HTTP_400_BAD_REQUEST

if TYPE_CHECKING:
    from litestar.types import Method, Scope


def create_options_handler(path: str, allow_methods: Iterable[Method]) -> HTTPRouteHandler:
    """Args:
        path: The route path
        allow_methods: Methods to be included in the 'Allow' header

    Returns:
        An HTTP route handler for OPTIONS requests.
    """

    def _options_handler(scope: Scope) -> Response:
        """Handler function for OPTIONS requests.

        Args:
            scope: The ASGI Scope.

        Returns:
            Response
        """
        cors_config = scope["app"].cors_config
        request_headers = Headers.from_scope(scope=scope)
        origin = request_headers.get("origin")

        if cors_config and origin:
            pre_flight_method = request_headers.get("Access-Control-Request-Method")
            failures = []

            if not cors_config.is_allow_all_methods and (
                pre_flight_method and pre_flight_method not in cors_config.allow_methods
            ):
                failures.append("method")

            response_headers = cors_config.preflight_headers.copy()

            if not cors_config.is_origin_allowed(origin):
                failures.append("Origin")
            elif response_headers.get("Access-Control-Allow-Origin") != "*":
                response_headers["Access-Control-Allow-Origin"] = origin

            pre_flight_requested_headers = [
                header.strip()
                for header in request_headers.get("Access-Control-Request-Headers", "").split(",")
                if header.strip()
            ]

            if pre_flight_requested_headers:
                if cors_config.is_allow_all_headers:
                    response_headers["Access-Control-Allow-Headers"] = ", ".join(
                        sorted(set(pre_flight_requested_headers) | DEFAULT_ALLOWED_CORS_HEADERS)  # pyright: ignore
                    )
                elif any(header.lower() not in cors_config.allow_headers for header in pre_flight_requested_headers):
                    failures.append("headers")

            return (
                Response(
                    content=f"Disallowed CORS {', '.join(failures)}",
                    status_code=HTTP_400_BAD_REQUEST,
                    media_type=MediaType.TEXT,
                )
                if failures
                else Response(
                    content=None,
                    status_code=HTTP_204_NO_CONTENT,
                    media_type=MediaType.TEXT,
                    headers=response_headers,
                )
            )

        return Response(
            content=None,
            status_code=HTTP_204_NO_CONTENT,
            headers={"Allow": ", ".join(sorted({HttpMethod.OPTIONS, *allow_methods}))},  # pyright: ignore
            media_type=MediaType.TEXT,
        )

    return HTTPRouteHandler(
        path=path,
        http_method=[HttpMethod.OPTIONS],
        include_in_schema=False,
        sync_to_thread=False,
    )(_options_handler)
