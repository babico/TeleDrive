"""Extraction target for the move-only split of ``web/s3.py``.

``web/s3.py`` remains the public import path (``web.s3.app`` and the module
attributes tests reach).  Modules here are implementation detail until the
final step of handoff 01 re-exports them from ``web/s3.py``.
"""
