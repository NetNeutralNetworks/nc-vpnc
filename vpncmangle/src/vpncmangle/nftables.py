"""Run nft commands through libnftables, in this process's namespace."""

import ctypes

_LIB: ctypes.CDLL | None = None


class NftablesError(Exception):
    """An nftables command failed."""


def _lib() -> ctypes.CDLL:
    global _LIB  # noqa: PLW0603
    if _LIB is None:
        lib = ctypes.CDLL("libnftables.so.1")
        lib.nft_ctx_new.restype = ctypes.c_void_p
        lib.nft_ctx_new.argtypes = [ctypes.c_uint32]
        lib.nft_ctx_free.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_buffer_output.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_buffer_error.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_get_error_buffer.restype = ctypes.c_char_p
        lib.nft_ctx_get_error_buffer.argtypes = [ctypes.c_void_p]
        lib.nft_run_cmd_from_buffer.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _LIB = lib
    return _LIB


def run(commands: str) -> None:
    """Run nft commands (as in an nft -f file) in one transaction."""
    lib = _lib()
    ctx = lib.nft_ctx_new(0)
    try:
        lib.nft_ctx_buffer_output(ctx)
        lib.nft_ctx_buffer_error(ctx)
        rc = lib.nft_run_cmd_from_buffer(ctx, commands.encode())
        error = (lib.nft_ctx_get_error_buffer(ctx) or b"").decode()
    finally:
        lib.nft_ctx_free(ctx)
    if rc:
        raise NftablesError(error.strip() or f"nft failed ({rc})")
