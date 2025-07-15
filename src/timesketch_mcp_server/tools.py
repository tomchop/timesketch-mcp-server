from typing import Any, Optional

from .utils import get_timesketch_client
from timesketch_api_client import aggregation, search

from fastmcp import FastMCP

mcp = FastMCP(name="timesketch-tools")

RESERVED_CHARS = [
    "+",
    "-",
    "=",
    "&&",
    "||",
    ">",
    "<",
    "!",
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    "^",
    '"',
    "~",
    "*",
    "?",
    ":",
    "\\",
    "/",
]


def _run_field_bucket_aggregation(sketch: Any, field: str) -> list[dict[str, int]]:
    """
    Helper function to run a field bucket aggregation on a Timesketch sketch.

    Args:
        sketch: The Timesketch sketch object.
        field: The field to aggregate on.

    Returns:
        A list of dictionaries containing the field bucket aggregation results.
    """
    aggregation_result = sketch.run_aggregator(
        aggregator_name="field_bucket",
        aggregator_parameters={
            "field": field,
            "limit": "10000",
        },
    )
    return aggregation_result.data.get("objects")[0]["field_bucket"]["buckets"]


@mcp.tool()
async def discover_data_types(sketch_id: int) -> list[dict[str, int]]:
    """Discover data types in a Timesketch sketch.

    Args:
        sketch_id: The ID of the Timesketch sketch to discover data types from.

    Returns:
        A list of dictionaries containing data type information, including:
        - data_type: The name of the data type.
        - count: The number of events for that data type.
    """

    sketch = get_timesketch_client().get_sketch(sketch_id)
    return _run_field_bucket_aggregation(sketch, "data_type")


@mcp.tool()
async def count_distinct_field_values(
    sketch_id: int, field: str
) -> list[dict[str, int]]:
    """Runs an aggregation to count distinct values for the specified field.

    Args:
        sketch_id: The ID of the Timesketch sketch to run the aggregation on.
        field: The field to count distinct values for, eg. "data_type",
            "source_ip", "yara_match".

    Returns:
        A list of dictionaries containing the aggregation results.
    """

    sketch = get_timesketch_client().get_sketch(sketch_id)
    return _run_field_bucket_aggregation(sketch, field)


@mcp.tool()
async def search_timesketch_events_substrings(
    sketch_id: int,
    substrings: list[str],
    regex: bool = False,
    boolean_operator: str = "AND",
    limit: Optional[int] = None,
    sort: str = "desc",
    starred: bool = False,
) -> list[dict[str, Any]]:
    """Searches timesketch events for specific substrings in the event messages.

    This is the preferred method to use when searching for specific substrings in
    event messages.

    Supports both simple substring matching and regular expression matching.
    Regex matching allows for more complex patterns but is more expensive,
    so use with caution.

    Args:
        sketch_id: The ID of the Timesketch sketch to search.
        substrings: A list of substrings to search for in the event messages.
        regex: If True, treat substrings as regex patterns. If False, treat them as
            simple substrings. Defaults to False.
        boolean_operator: The boolean operator to use for combining multiple
            substring queries. Must be one of "AND" or "OR". Defaults to "AND".
        limit: Optional maximum number of events to return. DANGEROUS: might
            skip important events, do not use unless explicitly needed.
        sort: Sort order for datetime field, either "asc" or "desc". Default is "desc".
            Useful for getting the most recent or oldest events.
        starred: If True, only return starred events. If False, return all events.

    Returns:
        A list of dictionaries representing the events found in the sketch.
        Each dictionary contains fields like datetime, data_type, tag, message,
        and optionally yara_match and sha256_hash if they are present in the results.

        If the query errors, an error string is returned instead.
    """

    if not substrings:
        raise ValueError("Substrings list cannot be empty.")

    if boolean_operator not in ["AND", "OR"]:
        raise ValueError(
            f"Invalid boolean operator: {boolean_operator}. "
            "Must be one of 'AND' or 'OR'."
        )
    boolean_operator = f" {boolean_operator} "

    terms = []

    for substring in substrings:
        if not substring:
            continue

        if regex:
            terms.append(f"message.keyword:/.*{substring}.*/")
        else:
            for char in RESERVED_CHARS:
                substring = substring.replace(char, f"\\{char}")
            terms.append(f"message.keyword:*{substring}*")

    query = boolean_operator.join(terms)
    try:
        return _do_timesketch_search(
            sketch_id=sketch_id,
            query=query,
            limit=limit,
            sort=sort,
            starred=starred,
        )
    except Exception as e:
        return "Error: " + str(e)


@mcp.tool()
async def search_timesketch_events_advanced(
    sketch_id: int,
    query: str,
    limit: Optional[int] = None,
    sort: str = "desc",
    starred: bool = False,
) -> list[dict[str, Any]] | str:
    """
    Search a Timesketch sketch and return a list of event dictionaries.

        Events always contain the following fields:
        • datetime (useful for sorting)
        • data_type (useful for filtering).
        • message

        Always put double quotes around field values in queries (so data_type:"syslog:cron:task_run"
        instead of data_type:syslog:cron:task_run)'

        Examples:
        • Datatype       `data_type:"apache:access_log:entry"`'
        • Field match    `filename:*.docx`
        • Exact phrase   `"mimikatz.exe"`'
        • Boolean        `(ssh AND error) OR tag:bruteforce`
        • Date range     `datetime:[2025-04-01 TO 2025-04-02]`
        • Wildcard       `user:sam*`
        • Regex          `host:/.*\\.google\\.com/`

    Args:
        sketch_id: The ID of the Timesketch sketch to search.
        query: The Lucene/OpenSearch query string to use for searching.
        limit: Optional maximum number of events to return.
        sort: Sort order for datetime field, either "asc" or "desc". Default is "desc".
        starred: If True, only return starred events. If False, return all events.

    Returns:
        A list of dictionaries representing the events found in the sketch.
        Each dictionary contains fields like datetime, data_type, tag, message,
        and optionally yara_match and sha256_hash if they are present in the results.

        If the query errors, an error string is returned instead.
    """

    try:
        return _do_timesketch_search(
            sketch_id=sketch_id,
            query=query,
            limit=limit,
            sort=sort,
            starred=starred,
        )
    except Exception as e:
        return "Error: " + str(e)


def _do_timesketch_search(
    sketch_id: int,
    query: str,
    limit: Optional[int] = None,
    sort: str = "desc",
    starred: bool = False,
) -> list[dict[str, Any]]:
    """Helper function to perform a search on a Timesketch sketch.

    Args:
        sketch_id: The ID of the Timesketch sketch to search.
        query: The Lucene/OpenSearch query string to use for searching.
        limit: Optional maximum number of events to return.
        sort: Sort order for datetime field, either "asc" or "desc". Default is
            "desc".
        starred: If True, only return starred events. If False, return all events.

    Raises:
        ValueError: If the sketch with the given ID does not exist.
        RuntimeError: If the search fails for any reason. Usually due to an invalid query.
    """
    sketch = get_timesketch_client().get_sketch(sketch_id)
    if not sketch:
        raise ValueError(f"Sketch with ID {sketch_id} not found.")

    search_instance = search.Search(sketch=sketch)
    search_instance.query_string = query
    if limit:
        search_instance.max_entries = limit
    search_instance.return_fields = (
        "_id, _index, datetime, message, data_type, tag, yara_match, sha256_hash"
    )
    if sort == "desc":
        search_instance.order_descending()
    else:
        search_instance.order_ascending()

    if starred:
        star_chip = search.LabelChip()
        star_chip.use_star_label()
        search_instance.add_chip(star_chip)

    result_df = search_instance.table

    if result_df.empty:
        return []

    extra_cols = []
    if "yara_match" in result_df.columns:
        result_df["yara_match"] = result_df["yara_match"].fillna("N/A")
        extra_cols.append("yara_match")

    if "sha256_hash" in result_df.columns:
        result_df["sha256_hash"] = result_df["sha256_hash"].fillna("N/A")
        extra_cols.append("sha256_hash")

    results_dict = (
        result_df[["_id", "datetime", "data_type", "tag", "message"] + extra_cols]
        .fillna("N/A")
        .to_dict(orient="records")
    )

    return results_dict
