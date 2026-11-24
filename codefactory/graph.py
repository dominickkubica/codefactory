"""The language-neutral graph every analyzer produces and every other part (flags, viewer) reads."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SCHEMA_VERSION = 1


@dataclass
class Function:
    id: str  # "<file path>::<qualname>"
    file: str
    name: str
    qualname: str
    line: int
    end: int
    loc: int
    kind: str = "function"  # function | method | module (top-level code)
    decorated: bool = False
    exported: bool = False  # listed in __all__ or an entry point
    shape: str = ""  # structural hash, for duplicate detection
    dynamic: bool = False  # a method whose name is used as obj.name somewhere we couldn't resolve
    public: bool = False  # TS/JS `export`: in a file nothing imports, a framework's entry point (a route, a screen)
    io: list[str] = field(default_factory=list)  # database, file or network calls it makes itself (callee names)
    tokens: str = ""  # structure tokens for near-duplicate detection; emptied after flags run


@dataclass
class File:
    id: str  # posix path relative to the analyzed root
    module: str
    loc: int
    layer: str = ""


@dataclass
class Edge:
    src: str
    dst: str
    kind: str  # call | ref | import
    count: int = 1


@dataclass
class Site:
    """A notable spot inside a function, for the efficiency checks."""

    fn: str  # function id
    kind: str  # loop_call (a resolved call inside a loop) | loop_io | loop_await | loop_scan
    line: int
    target: str = ""  # loop_call: the function called
    detail: str = ""  # loop_io / loop_scan: what's called ("db.getAllAsync", "items.find")
    bounded: bool = False  # every loop around it goes over a list fixed in the code (a literal, a constant, range(5))


@dataclass
class Flag:
    kind: str
    severity: str  # high | warn | info
    target: str  # a file or function id
    message: str
    related: list[str] = field(default_factory=list)
    line: int = 0  # where to look (the function's line, or the exact call)
    score: float = 0.0  # similar: the highest similarity to another member (0-1)
    reason: str = ""  # silenced: why (from the comment or factory.toml)


@dataclass
class Graph:
    root: str
    language: str
    files: list[File] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    sites: list[Site] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    silenced: list[Flag] = field(default_factory=list)  # issues marked as intended; kept so they can be listed
    layers: list[str] = field(default_factory=list)  # left-to-right order for the viewer
    rules: list[str] = field(default_factory=list)  # "a -> b" pairs that are forbidden

    def to_dict(self) -> dict:
        return {"schema": SCHEMA_VERSION, **asdict(self)}

    def merge(self, other: Graph) -> None:
        self.files += other.files
        self.functions += other.functions
        self.edges += other.edges
        self.sites += other.sites
        if other.language not in self.language.split("+"):
            self.language = f"{self.language}+{other.language}" if self.language else other.language
