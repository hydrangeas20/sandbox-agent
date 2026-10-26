"""A minimal LIFO stack."""


class EmptyStackError(Exception):
    """Raised when popping or peeking an empty stack."""


class Stack:
    def __init__(self) -> None:
        self._items: list[object] = []

    def push(self, item: object) -> None:
        self._items.append(item)

    def pop(self) -> object:
        if not self._items:
            raise EmptyStackError("pop from empty stack")
        return self._items.pop()

    def peek(self) -> object:
        if not self._items:
            raise EmptyStackError("peek at empty stack")
        return self._items[-1]

    def __len__(self) -> int:
        return len(self._items)
