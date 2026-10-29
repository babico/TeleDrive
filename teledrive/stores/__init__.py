"""Typed persistence helpers for the tables the web layer mutates.

Each module takes a :class:`teledrive.db.Database` wrapper, returns plain
dicts and commits once at the end of a logical operation. SQL stays here so
handlers cannot invent a query, and dialect differences stay in one place.
"""
