"""The streaming body cap, tested directly.

TestClient buffers a generator body before the app sees it, so a TestClient
test can't show how much was read. These tests count chunks pulled from the stream.
"""

from __future__ import annotations

import asyncio

import pytest

from spike.webhook_server import MAX_BODY_BYTES, BodyTooLarge, read_capped

CHUNK = 64 * 1024


class FakeStreamRequest:
    def __init__(self, chunk_count: int, chunk_size: int = CHUNK) -> None:
        self.chunk_count = chunk_count
        self.chunk_size = chunk_size
        self.pulled = 0

    async def stream(self):
        for _ in range(self.chunk_count):
            self.pulled += 1
            yield b"x" * self.chunk_size


def test_oversized_stream_is_abandoned_after_crossing_the_cap() -> None:
    request = FakeStreamRequest(chunk_count=64)  # 4 MB offered
    with pytest.raises(BodyTooLarge):
        asyncio.run(read_capped(request, MAX_BODY_BYTES))
    # 64 KB cap: chunk 1 reaches exactly the cap, chunk 2 crosses it. Nothing more is read.
    assert request.pulled == 2


def test_body_exactly_at_cap_is_accepted() -> None:
    request = FakeStreamRequest(chunk_count=1)
    body = asyncio.run(read_capped(request, MAX_BODY_BYTES))
    assert len(body) == MAX_BODY_BYTES


def test_small_chunks_stop_one_chunk_past_the_cap() -> None:
    request = FakeStreamRequest(chunk_count=10_000, chunk_size=1000)
    with pytest.raises(BodyTooLarge):
        asyncio.run(read_capped(request, MAX_BODY_BYTES))
    assert request.pulled == MAX_BODY_BYTES // 1000 + 1
