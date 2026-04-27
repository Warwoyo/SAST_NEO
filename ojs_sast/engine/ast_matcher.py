"""AST-based matching engine for evaluating Tree-sitter structural queries."""

from typing import Any
from tree_sitter import Query, QueryCursor, Node, Tree
from ojs_sast.categories.source_code.php_parser import _init_parser, _php_language
from ojs_sast.utils.logger import logger


_failed_queries = set()

class ASTMatcher:
    """Executes Tree-sitter queries against an AST to find structural vulnerabilities."""

    def __init__(self, query_string: str) -> None:
        """Initialize the AST matcher with a Tree-sitter S-expression query."""
        import ojs_sast.categories.source_code.php_parser as php_parser
        php_parser._init_parser()
        if not php_parser._php_language:
            raise RuntimeError("Tree-sitter PHP language not initialized.")
        
        self.query = None
        try:
            self.query = Query(php_parser._php_language, query_string)
        except Exception as e:
            if query_string not in _failed_queries:
                logger.debug(f"Failed to compile AST query: {e}\nQuery: {query_string}")
                _failed_queries.add(query_string)

    def match(self, tree: Tree) -> list[dict[str, list[Node]]]:
        """Execute the query against the provided AST.

        Args:
            tree: The parsed tree-sitter Tree.

        Returns:
            A list of capture dictionaries. Each dictionary maps capture names
            (e.g. 'target') to a list of matched tree-sitter Nodes.
        """
        if not tree or not tree.root_node or not self.query:
            return []

        try:
            cursor = QueryCursor(self.query)
            matches = cursor.matches(tree.root_node)
            
            results = []
            for pattern_index, captures in matches:
                results.append(captures)
            return results
        except Exception as e:
            logger.warning(f"Error executing AST query: {e}")
            return []
