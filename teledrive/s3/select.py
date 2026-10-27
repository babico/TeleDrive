"""S3 SelectObjectContent: strict request parsing, SQL subset and event stream.

The gateway downloads the real object through the regular storage engine to
an isolated scratch file, then this module evaluates one bounded SQL query.
No object bytes are copied to Telegram and no second storage copy exists.

Supported SQL subset (anything else is a 400, never silently ignored):

    SELECT * | column [, column ...]
    FROM S3Object
    [WHERE <boolean expression>]
    [LIMIT <non-negative integer>]

Boolean expressions support comparisons (``=``, ``<>``/``!=``, ``<``, ``<=``,
``>``, ``>=``) over column references, string/number/boolean/NULL literals,
``AND``, ``OR``, ``NOT`` and parentheses. There is no arithmetic, function,
``LIKE``, ``IN``, ``BETWEEN``, ``CAST``, subquery, join or alias support.

Input is CSV (with FileHeaderInfo USE/IGNORE/NONE) or JSON (DOCUMENT/LINES).
Parquet and compressed inputs return 501. Output is CSV or JSON. Bounds are
enforced explicitly: 256 MiB scanned, 1 MiB per Records event and 64 MiB of
total event-stream output. Crossing a bound returns an error, never silent
truncation.

The response is a real AWS event stream (``application/vnd.amazon.eventstream``)
with Records events, one Stats event and one End event. Each message uses the
AWS binary framing: prelude (total length, headers length, prelude CRC32),
headers, payload and message CRC32 (IEEE, not CRC32C).
"""
from __future__ import annotations

import csv
import io
import json
import re
import struct
import zlib
from dataclasses import dataclass
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import ParseError

MAX_REQUEST_XML_BYTES = 16 * 1024
MAX_SCAN_BYTES = 256 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_SQL_BYTES = 16 * 1024

_STATS_XML = "Stats"
_CONTENT_TYPE_RECORDS = "application/octet-stream"
_CONTENT_TYPE_XML = "text/xml"


class SelectError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class CSVInput:
    file_header_info: str = "NONE"
    field_delimiter: str = ","
    record_delimiter: str = "\n"
    quote_character: str = '"'
    quote_escape_character: str = '"'
    allow_quoted_record_delimiter: bool = False


@dataclass(frozen=True)
class JSONInput:
    type: str = "DOCUMENT"


@dataclass(frozen=True)
class CSVOutput:
    field_delimiter: str = ","
    record_delimiter: str = "\n"
    quote_character: str = '"'
    quote_escape_character: str = '"'
    quote_fields: str = "ASNEEDED"


@dataclass(frozen=True)
class JSONOutput:
    record_delimiter: str = "\n"


@dataclass(frozen=True)
class SelectRequest:
    expression: str
    input: CSVInput | JSONInput
    output: CSVOutput | JSONOutput
    request_progress: bool = False


@dataclass(frozen=True)
class SelectResult:
    records: list[bytes]
    bytes_scanned: int
    bytes_processed: int
    bytes_returned: int


# --- request XML ---------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element) -> list:
    if element.attrib:
        raise SelectError("MalformedXML", "Select request elements cannot carry attributes")
    return list(element)


def _single_text(element) -> str:
    children = _children(element)
    if children:
        raise SelectError("MalformedXML", f"{_local(element.tag)} must be text")
    return (element.text or "").strip()


def _one_character(element, name: str, default: str) -> str:
    value = _single_text(element)
    if len(value) != 1:
        raise SelectError("MalformedXML", f"{name} must be exactly one character")
    return value


def _boolean(element, name: str) -> bool:
    value = _single_text(element)
    if value not in ("true", "false"):
        raise SelectError("MalformedXML", f"{name} must be true or false")
    return value == "true"


def _parse_csv_input(element) -> CSVInput:
    options = {
        "FileHeaderInfo": "NONE",
        "FieldDelimiter": ",",
        "RecordDelimiter": "\n",
        "QuoteCharacter": '"',
        "QuoteEscapeCharacter": '"',
        "AllowQuotedRecordDelimiter": False,
        "Comments": None,
    }
    for child in _children(element):
        name = _local(child.tag)
        if name == "FileHeaderInfo":
            value = _single_text(child)
            if value not in ("USE", "IGNORE", "NONE"):
                raise SelectError("MalformedXML", "Invalid CSV FileHeaderInfo")
            options[name] = value
        elif name == "FieldDelimiter":
            options[name] = _one_character(child, name, ",")
        elif name == "RecordDelimiter":
            options[name] = _one_character(child, name, "\n")
        elif name == "QuoteCharacter":
            options[name] = _one_character(child, name, '"')
        elif name == "QuoteEscapeCharacter":
            options[name] = _one_character(child, name, '"')
        elif name == "AllowQuotedRecordDelimiter":
            options[name] = _boolean(child, name)
        elif name == "Comments":
            # Comments are a real AWS CSV option but skipped rows would make
            # the byte/row accounting ambiguous; fail honestly instead.
            _single_text(child)
            raise SelectError("NotImplemented", "CSV Comments are unsupported", 501)
        else:
            raise SelectError("MalformedXML", f"Unknown CSV input field {name}")
    if options["FieldDelimiter"] == options["RecordDelimiter"]:
        raise SelectError("MalformedXML", "CSV field and record delimiters must differ")
    if options["RecordDelimiter"] not in ("\n", "\r", "\r\n"):
        raise SelectError(
            "NotImplemented", "Only newline CSV record delimiters are supported", 501,
        )
    return CSVInput(
        file_header_info=options["FileHeaderInfo"],
        field_delimiter=options["FieldDelimiter"],
        record_delimiter=options["RecordDelimiter"],
        quote_character=options["QuoteCharacter"],
        quote_escape_character=options["QuoteEscapeCharacter"],
        allow_quoted_record_delimiter=options["AllowQuotedRecordDelimiter"],
    )


def _parse_json_input(element) -> JSONInput:
    kind = "DOCUMENT"
    for child in _children(element):
        name = _local(child.tag)
        if name != "Type":
            raise SelectError("MalformedXML", f"Unknown JSON input field {name}")
        kind = _single_text(child)
        if kind not in ("DOCUMENT", "LINES"):
            raise SelectError("MalformedXML", "JSON Type must be DOCUMENT or LINES")
    return JSONInput(kind)


def _parse_csv_output(element) -> CSVOutput:
    options = {
        "FieldDelimiter": ",",
        "RecordDelimiter": "\n",
        "QuoteCharacter": '"',
        "QuoteEscapeCharacter": '"',
        "QuoteFields": "ASNEEDED",
    }
    for child in _children(element):
        name = _local(child.tag)
        if name in ("FieldDelimiter", "RecordDelimiter",
                    "QuoteCharacter", "QuoteEscapeCharacter"):
            options[name] = _one_character(child, name, options[name])
        elif name == "QuoteFields":
            value = _single_text(child)
            if value not in ("ALWAYS", "ASNEEDED"):
                raise SelectError("MalformedXML", "Invalid CSV QuoteFields")
            options[name] = value
        else:
            raise SelectError("MalformedXML", f"Unknown CSV output field {name}")
    if options["RecordDelimiter"] not in ("\n", "\r", "\r\n"):
        raise SelectError(
            "NotImplemented", "Only newline CSV record delimiters are supported", 501,
        )
    return CSVOutput(
        field_delimiter=options["FieldDelimiter"],
        record_delimiter=options["RecordDelimiter"],
        quote_character=options["QuoteCharacter"],
        quote_escape_character=options["QuoteEscapeCharacter"],
        quote_fields=options["QuoteFields"],
    )


def _parse_json_output(element) -> JSONOutput:
    delimiter = "\n"
    for child in _children(element):
        name = _local(child.tag)
        if name != "RecordDelimiter":
            raise SelectError("MalformedXML", f"Unknown JSON output field {name}")
        delimiter = _one_character(child, name, "\n")
    return JSONOutput(delimiter)


def parse_select_request(body: bytes) -> SelectRequest:
    """Strictly parse one SelectObjectContentRequest XML document."""
    if not body or len(body) > MAX_REQUEST_XML_BYTES:
        raise SelectError("MalformedXML", "Invalid SelectObjectContent XML length")
    try:
        root = SafeET.fromstring(body)
    except (ParseError, DefusedXmlException) as exc:
        raise SelectError("MalformedXML", "Unsafe or malformed Select XML") from exc
    if _local(root.tag) != "SelectObjectContentRequest":
        raise SelectError("MalformedXML", "Expected SelectObjectContentRequest")
    expression = None
    expression_type = None
    input_spec = None
    output_spec = None
    request_progress = False
    for child in _children(root):
        name = _local(child.tag)
        if name == "Expression" and expression is None:
            expression = _single_text(child)
        elif name == "ExpressionType" and expression_type is None:
            expression_type = _single_text(child)
        elif name == "InputSerialization" and input_spec is None:
            input_spec = _parse_input_serialization(child)
        elif name == "OutputSerialization" and output_spec is None:
            output_spec = _parse_output_serialization(child)
        elif name == "RequestProgress" and not request_progress:
            request_progress = _parse_request_progress(child)
        else:
            raise SelectError("MalformedXML", f"Unexpected or repeated field {name}")
    if expression is None or expression_type is None:
        raise SelectError("MalformedXML", "Expression and ExpressionType are required")
    if input_spec is None or output_spec is None:
        raise SelectError(
            "MalformedXML", "InputSerialization and OutputSerialization are required",
        )
    if expression_type != "SQL":
        raise SelectError("NotImplemented", "Only ExpressionType SQL is supported", 501)
    if not expression or len(expression.encode("utf-8")) > MAX_SQL_BYTES:
        raise SelectError("InvalidRequest", "SQL expression is empty or too large")
    return SelectRequest(
        expression=expression,
        input=input_spec,
        output=output_spec,
        request_progress=request_progress,
    )


def _parse_input_serialization(element) -> CSVInput | JSONInput:
    spec = None
    for child in _children(element):
        name = _local(child.tag)
        if name == "Parquet":
            raise SelectError("NotImplemented", "Parquet input is unsupported", 501)
        if name == "CompressionType":
            value = _single_text(child)
            if value != "NONE":
                raise SelectError(
                    "NotImplemented", "Compressed select input is unsupported", 501,
                )
            continue
        if name == "CSV" and spec is None:
            spec = _parse_csv_input(child)
        elif name == "JSON" and spec is None:
            spec = _parse_json_input(child)
        else:
            raise SelectError("MalformedXML", f"Unsupported input serialization {name}")
    if spec is None:
        raise SelectError("MalformedXML", "CSV or JSON input serialization is required")
    return spec


def _parse_output_serialization(element) -> CSVOutput | JSONOutput:
    spec = None
    for child in _children(element):
        name = _local(child.tag)
        if name == "CSV" and spec is None:
            spec = _parse_csv_output(child)
        elif name == "JSON" and spec is None:
            spec = _parse_json_output(child)
        else:
            raise SelectError("MalformedXML", f"Unsupported output serialization {name}")
    if spec is None:
        raise SelectError("MalformedXML", "CSV or JSON output serialization is required")
    return spec


def _parse_request_progress(element) -> bool:
    enabled = False
    for child in _children(element):
        if _local(child.tag) != "Enabled":
            raise SelectError("MalformedXML", "Unknown RequestProgress field")
        enabled = _boolean(child, "Enabled")
    return enabled


# --- SQL parser ----------------------------------------------------------

@dataclass(frozen=True)
class Query:
    columns: tuple[str, ...] | None  # None means *
    where: object | None
    limit: int | None


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str


_TOKEN_RE = re.compile(r"""
    \s+
  | (?P<string>'(?:[^']|'')*')
  | (?P<quoted>"(?:[^"]|"")*")
  | (?P<number>-?(?:\d+(?:\.\d*)?|\.\d+))
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op><=|>=|<>|!=|=|<|>)
  | (?P<punct>[(),*.])
""", re.VERBOSE)


def _tokenize(sql: str) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    while position < len(sql):
        match = _TOKEN_RE.match(sql, position)
        if match is None:
            raise SelectError(
                "InvalidRequest",
                f"Unsupported SQL syntax near {sql[position:position + 20]!r}",
            )
        position = match.end()
        if match.lastgroup is None:
            continue
        kind = match.lastgroup
        raw = match.group(kind)
        if kind == "string":
            tokens.append(_Token("string", raw[1:-1].replace("''", "'")))
        elif kind == "quoted":
            tokens.append(_Token("ident", raw[1:-1].replace('""', '"')))
        else:
            tokens.append(_Token(kind, raw))
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token]):
        self.tokens = tokens
        self.index = 0

    def peek(self) -> _Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> _Token:
        token = self.peek()
        if token is None:
            raise SelectError("InvalidRequest", "Unexpected end of SQL expression")
        self.index += 1
        return token

    def keyword(self, word: str) -> bool:
        token = self.peek()
        return bool(token and token.kind == "ident" and token.value.upper() == word)

    def accept_keyword(self, word: str) -> bool:
        if self.keyword(word):
            self.index += 1
            return True
        return False

    def expect_keyword(self, word: str) -> None:
        if not self.accept_keyword(word):
            raise SelectError("InvalidRequest", f"Expected {word} in SQL expression")

    def accept(self, kind: str, value: str | None = None) -> bool:
        token = self.peek()
        if token is not None and token.kind == kind and (
                value is None or token.value == value):
            self.index += 1
            return True
        return False

    def identifier(self) -> str:
        token = self.take()
        if token.kind != "ident":
            raise SelectError("InvalidRequest", "Expected a column name")
        name = token.value
        # AWS examples qualify columns with the S3Object alias
        # (`SELECT s.name FROM S3Object s`). Accept the dotted form and
        # keep only the column part; the alias itself carries no meaning
        # because there is exactly one source object.
        while self.accept("punct", "."):
            follower = self.take()
            if follower.kind != "ident":
                raise SelectError("InvalidRequest", "Expected a column name")
            name = follower.value
        return name

    def expression(self):
        return self.or_expression()

    def or_expression(self):
        node = self.and_expression()
        while self.accept_keyword("OR"):
            node = ("or", node, self.and_expression())
        return node

    def and_expression(self):
        node = self.not_expression()
        while self.accept_keyword("AND"):
            node = ("and", node, self.not_expression())
        return node

    def not_expression(self):
        if self.accept_keyword("NOT"):
            return ("not", self.not_expression())
        if self.accept("punct", "("):
            node = self.expression()
            if not self.accept("punct", ")"):
                raise SelectError("InvalidRequest", "Missing closing parenthesis")
            return node
        return self.comparison()

    def operand(self):
        token = self.peek()
        if token is None:
            raise SelectError("InvalidRequest", "Missing SQL operand")
        if token.kind == "string":
            self.index += 1
            return ("literal", token.value)
        if token.kind == "number":
            self.index += 1
            return ("literal", float(token.value)
                    if "." in token.value else int(token.value))
        if token.kind == "ident":
            upper = token.value.upper()
            if upper in ("TRUE", "FALSE"):
                self.index += 1
                return ("literal", upper == "TRUE")
            if upper == "NULL":
                self.index += 1
                return ("literal", None)
            if upper in ("AND", "OR", "NOT"):
                raise SelectError("InvalidRequest", "Expected a SQL operand")
            self.index += 1
            name = token.value
            while self.accept("punct", "."):
                follower = self.take()
                if follower.kind != "ident":
                    raise SelectError("InvalidRequest",
                                      "Expected a column name")
                name = follower.value
            return ("column", name)
        raise SelectError("InvalidRequest", "Expected a SQL operand")

    def comparison(self):
        left = self.operand()
        token = self.peek()
        if token is None or token.kind != "op":
            return left
        self.index += 1
        right = self.operand()
        return ("cmp", token.value, left, right)


def parse_select_sql(sql: str) -> Query:
    tokens = _tokenize(sql)
    if not tokens:
        raise SelectError("InvalidRequest", "SQL expression is empty")
    parser = _Parser(tokens)
    parser.expect_keyword("SELECT")
    columns: tuple[str, ...] | None
    if parser.accept("punct", "*"):
        columns = None
    else:
        names = [parser.identifier()]
        while parser.accept("punct", ","):
            names.append(parser.identifier())
        columns = tuple(names)
    parser.expect_keyword("FROM")
    parser.expect_keyword("S3OBJECT")
    # Optional table alias: `FROM S3Object s`. Ignored semantically (one
    # source object), but required for the documented AWS query shape.
    if parser.accept_keyword("AS"):
        parser.identifier()
    else:
        token = parser.peek()
        if (token is not None and token.kind == "ident"
                and token.value.upper() not in ("WHERE", "LIMIT")):
            parser.index += 1
    where = None
    if parser.accept_keyword("WHERE"):
        where = parser.expression()
    limit = None
    if parser.accept_keyword("LIMIT"):
        token = parser.take()
        if token.kind != "number" or "." in token.value or int(token.value) < 0:
            raise SelectError("InvalidRequest", "LIMIT requires a non-negative integer")
        limit = int(token.value)
    if parser.peek() is not None:
        raise SelectError(
            "InvalidRequest",
            "Unsupported SQL construct; only SELECT/FROM S3Object/WHERE/LIMIT "
            "with comparisons, AND, OR, NOT and parentheses is supported",
        )
    return Query(columns=columns, where=where, limit=limit)


# --- evaluation ----------------------------------------------------------

def _numeric(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _evaluate(node, record: dict):
    kind = node[0]
    if kind == "literal":
        return node[1]
    if kind == "column":
        return record.get(node[1])
    if kind == "not":
        return not bool(_evaluate(node[1], record))
    if kind == "and":
        return bool(_evaluate(node[1], record)) and bool(_evaluate(node[2], record))
    if kind == "or":
        return bool(_evaluate(node[1], record)) or bool(_evaluate(node[2], record))
    if kind == "cmp":
        operator, left_node, right_node = node[1], node[2], node[3]
        left = _evaluate(left_node, record)
        right = _evaluate(right_node, record)
        if left is None or right is None:
            return False
        left_number, right_number = _numeric(left), _numeric(right)
        if left_number is not None and right_number is not None:
            left, right = left_number, right_number
        elif isinstance(left, str) and isinstance(right, str):
            pass
        elif isinstance(left, bool) and isinstance(right, bool):
            pass
        elif isinstance(left, str) or isinstance(right, str):
            # A non-numeric string comparison against a numeric/boolean
            # literal is not a silently coerced SQL comparison.
            return False
        if operator == "=":
            return left == right
        if operator in ("<>", "!="):
            return left != right
        if operator == "<":
            return left < right
        if operator == "<=":
            return left <= right
        if operator == ">":
            return left > right
        if operator == ">=":
            return left >= right
    raise SelectError("InvalidRequest", "Unsupported SQL expression")


def _csv_reader(handle, spec: CSVInput):
    return csv.reader(
        handle,
        delimiter=spec.field_delimiter,
        quotechar=spec.quote_character,
        escapechar=(None if spec.quote_escape_character == spec.quote_character
                    else spec.quote_escape_character),
        doublequote=spec.quote_escape_character == spec.quote_character,
        strict=True,
    )


def _records_csv(path: Path, spec: CSVInput):
    header: list[str] | None = None
    first = True
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = _csv_reader(handle, spec)
            for row in reader:
                if first and spec.file_header_info == "USE":
                    if not row or any(not name for name in row):
                        raise SelectError(
                            "InvalidRequest", "CSV header contains an empty name")
                    if len(set(row)) != len(row):
                        raise SelectError(
                            "InvalidRequest", "CSV header names must be unique")
                    header = list(row)
                    first = False
                    continue
                if first and spec.file_header_info == "IGNORE":
                    first = False
                    continue
                first = False
                names = header or [f"_{index + 1}" for index in range(len(row))]
                yield {name: (row[index] if index < len(row) else None)
                       for index, name in enumerate(names)}
    except OSError as exc:
        raise SelectError("InternalError", "Select scratch file unavailable", 500) from exc
    except UnicodeDecodeError as exc:
        raise SelectError("InvalidRequest", "CSV input must be UTF-8") from exc
    except csv.Error as exc:
        raise SelectError("InvalidRequest", f"Malformed CSV input: {exc}") from exc


def _records_json(path: Path, spec: JSONInput):
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SelectError("InternalError", "Select scratch file unavailable", 500) from exc
    try:
        if spec.type == "LINES":
            for line in raw.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise SelectError("InvalidRequest", "JSON LINES records must be objects")
                yield item
        else:
            document = json.loads(raw.decode("utf-8"))
            items = document if isinstance(document, list) else [document]
            for item in items:
                if not isinstance(item, dict):
                    raise SelectError("InvalidRequest", "JSON records must be objects")
                yield item
    except UnicodeDecodeError as exc:
        raise SelectError("InvalidRequest", "JSON input must be UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise SelectError("InvalidRequest", f"Malformed JSON input: {exc.msg}") from exc


def _records(path: Path, spec: CSVInput | JSONInput):
    if isinstance(spec, CSVInput):
        return _records_csv(path, spec)
    return _records_json(path, spec)


def _known_columns(path: Path, spec: CSVInput) -> set[str]:
    if spec.file_header_info != "USE":
        return set()
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            row = next(_csv_reader(handle, spec), None)
    except OSError as exc:
        raise SelectError("InternalError", "Select scratch file unavailable", 500) from exc
    except UnicodeDecodeError as exc:
        raise SelectError("InvalidRequest", "CSV input must be UTF-8") from exc
    except csv.Error as exc:
        raise SelectError("InvalidRequest", f"Malformed CSV header: {exc}") from exc
    if not row:
        return set()
    return set(row)


def _referenced_columns(node) -> set[str]:
    if node is None:
        return set()
    if node[0] == "column":
        return {node[1]}
    if node[0] in ("and", "or"):
        return _referenced_columns(node[1]) | _referenced_columns(node[2])
    if node[0] == "not":
        return _referenced_columns(node[1])
    if node[0] == "cmp":
        return _referenced_columns(node[2]) | _referenced_columns(node[3])
    return set()


def _select_values(record: dict, columns: tuple[str, ...] | None):
    if columns is None:
        return list(record.values()), record
    return [record.get(name) for name in columns], {
        name: record.get(name) for name in columns
    }


def _format_csv_row(row: list, spec: CSVOutput) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(
        buffer,
        delimiter=spec.field_delimiter,
        quotechar=spec.quote_character,
        escapechar=(None if spec.quote_escape_character == spec.quote_character
                    else spec.quote_escape_character),
        doublequote=spec.quote_escape_character == spec.quote_character,
        quoting=(csv.QUOTE_ALL if spec.quote_fields == "ALWAYS"
                 else csv.QUOTE_MINIMAL),
        lineterminator=spec.record_delimiter,
    )
    writer.writerow(["" if value is None else value for value in row])
    return buffer.getvalue().encode("utf-8")


def _format_json_row(record: dict, spec: JSONOutput) -> bytes:
    return (json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            + spec.record_delimiter).encode("utf-8")


def run_select(source: Path, request: SelectRequest, *,
               max_scan: int = MAX_SCAN_BYTES,
               max_event: int = MAX_EVENT_BYTES,
               max_response: int = MAX_RESPONSE_BYTES) -> SelectResult:
    """Evaluate one parsed request against a scratch file."""
    query = parse_select_sql(request.expression)
    try:
        scanned = source.stat().st_size
    except OSError as exc:
        raise SelectError("InternalError", "Select scratch file unavailable", 500) from exc
    if scanned > max_scan:
        raise SelectError(
            "EntityTooLarge",
            f"Select scan exceeds the {max_scan}-byte limit",
            413,
        )
    if isinstance(request.input, CSVInput):
        known = _known_columns(source, request.input)
        referenced = set(query.columns or ()) | _referenced_columns(query.where)
        unknown = sorted(referenced - known) if known else []
        if unknown:
            raise SelectError(
                "InvalidRequest",
                "Unknown CSV column(s): " + ", ".join(unknown),
            )
    records: list[bytes] = []
    returned = 0
    matched = 0
    for record in _records(source, request.input):
        if query.where is not None and not _evaluate(query.where, record):
            continue
        if query.limit is not None and matched >= query.limit:
            break
        values, selected = _select_values(record, query.columns)
        if isinstance(request.output, CSVOutput):
            payload = _format_csv_row(values, request.output)
        else:
            payload = _format_json_row(selected, request.output)
        if len(payload) > max_event:
            raise SelectError(
                "EntityTooLarge",
                f"A select record exceeds the {max_event}-byte event limit",
                413,
            )
        returned += len(payload)
        if returned > max_response:
            raise SelectError(
                "EntityTooLarge",
                f"Select response exceeds the {max_response}-byte limit",
                413,
            )
        records.append(payload)
        matched += 1
    # Pack individual record payloads into Records events, never exceeding
    # the per-event bound and never splitting one record.
    events: list[bytes] = []
    current = bytearray()
    for payload in records:
        if current and len(current) + len(payload) > max_event:
            events.append(bytes(current))
            current.clear()
        current.extend(payload)
    if current:
        events.append(bytes(current))
    return SelectResult(
        records=events,
        bytes_scanned=scanned,
        bytes_processed=scanned,
        bytes_returned=returned,
    )


# --- event stream --------------------------------------------------------

def _event_header(name: str, value: str) -> bytes:
    encoded_name = name.encode("ascii")
    encoded_value = value.encode("ascii")
    if not (0 < len(encoded_name) <= 255) or len(encoded_value) > 0xFFFF:
        raise ValueError("Invalid event-stream header")
    return (bytes([len(encoded_name)]) + encoded_name + b"\x07"
            + struct.pack(">H", len(encoded_value)) + encoded_value)


def encode_event(event_type: str, payload: bytes) -> bytes:
    """Encode one AWS event-stream message with correct prelude/message CRCs."""
    headers = [(":message-type", "event"), (":event-type", event_type)]
    if event_type == "Records":
        headers.append((":content-type", _CONTENT_TYPE_RECORDS))
    elif event_type == "Stats":
        headers.append((":content-type", _CONTENT_TYPE_XML))
    header_bytes = b"".join(_event_header(name, value) for name, value in headers)
    total_length = 12 + len(header_bytes) + len(payload) + 4
    prelude = struct.pack(">II", total_length, len(header_bytes))
    prelude += struct.pack(">I", zlib.crc32(prelude) & 0xFFFFFFFF)
    message = prelude + header_bytes + payload
    message += struct.pack(">I", zlib.crc32(message) & 0xFFFFFFFF)
    return message


def _stats_payload(result: SelectResult) -> bytes:
    root = ET.Element(_STATS_XML)
    ET.SubElement(root, "BytesScanned").text = str(result.bytes_scanned)
    ET.SubElement(root, "BytesProcessed").text = str(result.bytes_processed)
    ET.SubElement(root, "BytesReturned").text = str(result.bytes_returned)
    return ET.tostring(root, encoding="utf-8")


def build_event_stream(result: SelectResult) -> bytes:
    messages = [encode_event("Records", payload) for payload in result.records]
    messages.append(encode_event("Stats", _stats_payload(result)))
    messages.append(encode_event("End", b""))
    body = b"".join(messages)
    if len(body) > MAX_RESPONSE_BYTES:
        raise SelectError(
            "EntityTooLarge",
            f"Select event stream exceeds the {MAX_RESPONSE_BYTES}-byte limit",
            413,
        )
    return body
