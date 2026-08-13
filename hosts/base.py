from abc import ABC, abstractmethod


class Host(ABC):

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass

    @abstractmethod
    async def execute(self, command: str) -> str:
        pass

    @abstractmethod
    async def read_file(self, file: str):
        pass
