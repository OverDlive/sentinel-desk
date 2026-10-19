"""Encrypt API credentials with the signed-in Windows user's DPAPI key.

No plaintext key file, third-party packages, or reversible obfuscation.
"""
import base64
import ctypes
import os
from ctypes import wintypes


class Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_byte))]


def _transform(value: bytes, decrypt: bool = False) -> bytes:
    if os.name != "nt":
        raise RuntimeError("API 키 보관은 Windows DPAPI를 사용합니다. Windows에서 실행하세요.")
    buffer = ctypes.create_string_buffer(value)
    source = Blob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    result = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise RuntimeError("Windows 자격 증명 암호화/복호화 실패. 동일 Windows 계정인지 확인하세요.")
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        kernel.LocalFree(result.data)


def seal(value: str) -> str:
    return base64.b64encode(_transform(value.encode("utf-8"))).decode("ascii")


def unseal(value: str) -> str:
    return _transform(base64.b64decode(value), decrypt=True).decode("utf-8") if value else ""
