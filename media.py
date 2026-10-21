"""Bounded HTTPS QQ image downloads without redirects or private DNS targets."""

import ipaddress
import secrets
import socket
from pathlib import Path

import aiohttp
from aiohttp.resolver import DefaultResolver
from PIL import Image as PillowImage


class PublicResolver(DefaultResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        addresses = await super().resolve(host, port, family)
        if not addresses or any(
            not ipaddress.ip_address(address["host"]).is_global for address in addresses
        ):
            raise PermissionError("Private or special-use image address denied.")
        return addresses


def verify_image(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 12 * 1024 * 1024:
        raise ValueError("Image file exceeds the supported limit.")
    with PillowImage.open(path) as picture:
        if picture.width * picture.height > 25_000_000:
            raise ValueError("Image pixel limit exceeded.")
        picture.verify()


async def download_image(url, root, policy):
    if not policy.validate_media_url(url):
        raise PermissionError("Only official HTTPS QQ image sources are allowed.")
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    target = root / (secrets.token_hex(16) + ".image")
    try:
        connector = aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False)
        async with aiohttp.ClientSession(
            connector=connector,
            trust_env=False,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as client:
            async with client.get(url, allow_redirects=False) as response:
                if response.status != 200:
                    raise ValueError("Image request did not return a direct success.")
                if (
                    response.content_length
                    and response.content_length > 12 * 1024 * 1024
                ):
                    raise ValueError("Image response exceeds the supported limit.")
                size = 0
                with target.open("xb") as handle:
                    async for chunk in response.content.iter_chunked(65536):
                        size += len(chunk)
                        if size > 12 * 1024 * 1024:
                            raise ValueError(
                                "Image response exceeds the supported limit."
                            )
                        handle.write(chunk)
        verify_image(target)
        return target
    except BaseException:
        target.unlink(missing_ok=True)
        raise
