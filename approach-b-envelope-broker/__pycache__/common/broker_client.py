"""
Blocking broker RPC client (Approach B).

Each method performs one request/response round-trip on a connected TCP socket.
"""

from __future__ import annotations

import socket
from typing import Final

from . import broker_protocol as bp


class BrokerRequestError(Exception):
    pass


class BrokerClient:
    __slots__ = ("_sock",)

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def _rpc(self, cmd: int, request_body: bytes) -> bytes:
        bp.write_frame(self._sock, cmd, request_body)
        rcmd, body = bp.read_frame(self._sock)
        if rcmd != cmd:
            raise bp.BrokerProtocolError(f"unexpected response cmd {rcmd!r} (expected {cmd!r})")
        ok, rest = bp.parse_status_body(body)
        if not ok:
            raise BrokerRequestError(rest.decode("utf-8", errors="strict"))
        return rest

    def put_chunk(self, *, session_id: bytes, chunk_index: int, ciphertext: bytes) -> None:
        self._rpc(int(bp.Command.PUT_CHUNK), bp.pack_put_chunk(session_id=session_id, chunk_index=chunk_index, ciphertext=ciphertext))

    def get_chunk(self, *, session_id: bytes, chunk_index: int) -> bytes:
        pl = self._rpc(
            int(bp.Command.GET_CHUNK),
            bp.pack_session_chunk_query(session_id=session_id, chunk_index=chunk_index),
        )
        return bp.unpack_get_chunk_response(pl)

    def list_chunks(self, *, session_id: bytes) -> list[int]:
        pl = self._rpc(int(bp.Command.LIST_CHUNKS), bp.pack_list_chunks(session_id))
        return bp.unpack_list_response(pl)

    def put_manifest(self, *, session_id: bytes, manifest_json: bytes, signature: bytes) -> None:
        self._rpc(
            int(bp.Command.PUT_MANIFEST),
            bp.pack_put_manifest(session_id=session_id, manifest_json=manifest_json, signature=signature),
        )

    def get_manifest(self, *, session_id: bytes) -> tuple[bytes, bytes]:
        pl = self._rpc(int(bp.Command.GET_MANIFEST), bp.pack_get_manifest(session_id))
        return bp.unpack_get_manifest_response(pl)


__all__: Final[tuple[str, ...]] = ("BrokerClient", "BrokerRequestError")
