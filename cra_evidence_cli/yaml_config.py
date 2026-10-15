"""Safe YAML loading for committed CRA Evidence configuration files."""

from __future__ import annotations

from typing import Any

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

_MERGE_TAG = "tag:yaml.org,2002:merge"
_VALUE_TAG = "tag:yaml.org,2002:value"


class DuplicateMappingKeyError(yaml.YAMLError):
    """A duplicate explicit mapping key, reported without echoing input text."""

    def __init__(self, mark: Any) -> None:
        self.line = mark.line + 1
        self.column = mark.column + 1
        super().__init__(f"duplicate mapping key at line {self.line}, column {self.column}")


class UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects repeated explicit keys before YAML merge flattening."""

    def construct_document(self, node: Any) -> Any:
        visited: set[int] = set()
        self._check_mapping_keys(node, visited)
        return super().construct_document(node)

    def _check_mapping_keys(self, node: Any, visited: set[int]) -> None:
        node_id = id(node)
        if node_id in visited:
            return
        visited.add(node_id)

        if isinstance(node, MappingNode):
            keys: set[Any] = set()
            for key_node, value_node in node.value:
                if key_node.tag == _VALUE_TAG and isinstance(key_node, ScalarNode):
                    key_node.tag = "tag:yaml.org,2002:str"
                if key_node.tag != _MERGE_TAG and isinstance(key_node, ScalarNode):
                    key = self.construct_object(key_node, deep=True)
                    try:
                        hash(key)
                    except TypeError:
                        pass
                    else:
                        if key in keys:
                            raise DuplicateMappingKeyError(key_node.start_mark)
                        keys.add(key)
                self._check_mapping_keys(key_node, visited)
                self._check_mapping_keys(value_node, visited)
        elif isinstance(node, SequenceNode):
            for child in node.value:
                self._check_mapping_keys(child, visited)


def load_yaml(text: str) -> Any:
    """Parse YAML with SafeLoader semantics and explicit-key uniqueness."""
    loader = UniqueKeySafeLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
