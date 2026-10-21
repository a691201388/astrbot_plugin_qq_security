"""Network-boundary tests use synthetic responses without real requests."""

from types import SimpleNamespace

import pytest
from aiohttp.resolver import DefaultResolver

from astrbot_plugin_qq_security.media import PublicResolver, download_image
from astrbot_plugin_qq_security.security import SecurityPolicy


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address", ["127.0.0.1", "192.168.1.1", "169.254.169.254", "::1"]
)
async def test_official_hostname_cannot_resolve_to_private_targets(
    monkeypatch, address
):
    async def resolve(self, host, port=0, family=0):
        return [{"host": address}]

    monkeypatch.setattr(DefaultResolver, "resolve", resolve)
    resolver = PublicResolver()
    try:
        with pytest.raises(PermissionError):
            await resolver.resolve("gchat.qpic.cn", 443)
    finally:
        await resolver.close()


@pytest.mark.asyncio
async def test_non_qq_source_never_constructs_a_network_client(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("A network client must not be constructed")

    monkeypatch.setattr(
        "astrbot_plugin_qq_security.media.aiohttp.ClientSession", forbidden
    )
    with pytest.raises(PermissionError):
        await download_image("http://127.0.0.1/private", tmp_path, SecurityPolicy({}))


@pytest.mark.asyncio
@pytest.mark.parametrize("status,length", [(302, 0), (200, 13 * 1024 * 1024)])
async def test_redirect_and_oversized_response_are_rejected(
    monkeypatch, tmp_path, status, length
):
    observed = {}

    class Response:
        async def __aenter__(self):
            return SimpleNamespace(status=status, content_length=length)

        async def __aexit__(self, *args):
            return False

    class Client:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            await observed["connector"].close()

        def get(self, url, **kwargs):
            observed.update(kwargs)
            return Response()

    monkeypatch.setattr(
        "astrbot_plugin_qq_security.media.aiohttp.ClientSession", Client
    )
    with pytest.raises(ValueError):
        await download_image(
            "https://gchat.qpic.cn/example", tmp_path, SecurityPolicy({})
        )
    assert observed["allow_redirects"] is False
    assert observed["trust_env"] is False
    assert not list(tmp_path.iterdir())
