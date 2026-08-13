from pydantic import BaseModel


class CleanupFilters(BaseModel):
    """Shared shape for the cleanup preview + execute pair.

    ``source`` is one of all/website/windows/linux; ``hostname`` narrows to a
    single agent; ``before`` is the ISO cutoff — only documents strictly older
    than it match.
    """

    source: str = "all"
    hostname: str | None = None
    before: str


class CleanupExecute(CleanupFilters):
    """Delete request: re-validates the count the preview returned."""

    expected_count: int
