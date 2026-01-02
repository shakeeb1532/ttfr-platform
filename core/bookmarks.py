from dataclasses import dataclass
from typing import List


@dataclass
class TimelineBookmark:
    """
    Analyst bookmark tied to a replay timeline.
    """
    start_seq: int
    end_seq: int
    label: str
    notes: str


class BookmarkStore:
    """
    Non-destructive bookmark storage.
    """

    def __init__(self):
        self._bookmarks: List[TimelineBookmark] = []

    def add(
        self,
        start_seq: int,
        end_seq: int,
        label: str,
        notes: str = "",
    ) -> None:
        if start_seq > end_seq:
            raise ValueError("start_seq must be <= end_seq")

        self._bookmarks.append(
            TimelineBookmark(
                start_seq=start_seq,
                end_seq=end_seq,
                label=label,
                notes=notes,
            )
        )

    def all(self) -> List[TimelineBookmark]:
        return list(self._bookmarks)

