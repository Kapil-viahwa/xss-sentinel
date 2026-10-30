import ast
import re
import tree_sitter_javascript as tree_sitter_javascript
from tree_sitter import Language, Parser


JAVASCRIPT_LANGUAGE = Language(tree_sitter_javascript.language())
FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function"}
SINK_CALLS = {"eval", "Function", "document.write", "document.writeln", "setTimeout", "setInterval"}
SOURCE_PATTERNS = {
    "location.search": ("location.search",),
    "location.hash": ("location.hash",),
    "location.href": ("location.href",),
    "document.referrer": ("document.referrer",),
    "window.name": ("window.name",),
    "localStorage": ("localstorage",),
    "sessionStorage": ("sessionstorage",),
    "postMessage event.data": ("event.data",),
}
ENDPOINT_CALLS = {"fetch", "axios", "request", "open", "get", "post", "put", "patch", "delete", "connect", "WebSocket", "EventSource", "Worker", "SharedWorker"}
MAX_OBSERVATIONS = 100


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _string_value(node, source: bytes) -> str | None:
    raw = _text(node, source)
    if node.type == "string":
        try:
            value = ast.literal_eval(raw)
            return value if isinstance(value, str) else None
        except (SyntaxError, ValueError):
            return raw[1:-1] if len(raw) >= 2 else None
    if node.type == "template_string":
        value = raw[1:-1]
        return re.sub(r"\$\{[^}]*\}", "{dynamic}", value)
    return None


def _endpoint_candidate(value: str) -> bool:
    trimmed = value.strip()
    lowered = trimmed.lower()
    if not trimmed or lowered.startswith(("javascript:", "data:")):
        return False
    return (trimmed.startswith(("/", "./", "../", "api/", "graphql/"))
            or lowered.startswith(("ws://", "wss://"))
            or lowered.endswith((".js", ".mjs", ".cjs"))
            or "/api/" in trimmed or "/graphql" in lowered)


def _property_name(node, source: bytes) -> str:
    return _string_value(node, source) or _text(node, source)


def _json_fields(node, source: bytes, object_bindings: dict[str, object], prefix: str = "") -> list[dict]:
    if node.type == "identifier":
        bound = object_bindings.get(_text(node, source))
        return _json_fields(bound, source, object_bindings, prefix) if bound is not None else []
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is not None and _text(function, source).endswith("JSON.stringify") and arguments and arguments.named_children:
            return _json_fields(arguments.named_children[0], source, object_bindings, prefix)
        return []
    if node.type != "object":
        return []
    fields = []
    for child in node.named_children:
        if child.type == "pair":
            key_node = child.child_by_field_name("key")
            value_node = child.child_by_field_name("value")
            if key_node is None or value_node is None:
                continue
            key = _property_name(key_node, source)
            name = f"{prefix}.{key}" if prefix else key
            nested = _json_fields(value_node, source, object_bindings, name)
            if nested:
                fields.extend(nested)
            else:
                fields.append({"name": name, "input_type": value_node.type, "location": "json"})
        elif child.type in {"shorthand_property_identifier", "shorthand_property_identifier_pattern"}:
            key = _text(child, source)
            name = f"{prefix}.{key}" if prefix else key
            fields.append({"name": name, "input_type": "identifier", "location": "json"})
        if len(fields) >= MAX_OBSERVATIONS:
            return fields[:MAX_OBSERVATIONS]
    return fields


def _call_endpoint(node, source: bytes, string_bindings: dict[str, str], object_bindings: dict[str, object]) -> dict | None:
    if node.type not in {"call_expression", "new_expression"}:
        return None
    function_node = node.child_by_field_name("function")
    if function_node is None:
        function_node = node.child_by_field_name("constructor")
    arguments_node = node.child_by_field_name("arguments")
    if function_node is None or arguments_node is None:
        return None
    function_name = _text(function_node, source)
    final_name = function_name.split(".")[-1]
    if final_name not in ENDPOINT_CALLS and not function_name.endswith(".request"):
        return None
    arguments = arguments_node.named_children
    if not arguments:
        return None
    argument_index = 1 if final_name == "open" else 0
    if argument_index >= len(arguments):
        return None
    argument = arguments[argument_index]
    candidate = _string_value(argument, source)
    if candidate is None and argument.type == "identifier":
        candidate = string_bindings.get(_text(argument, source))
    if candidate is None and argument.type in {"binary_expression", "parenthesized_expression"}:
        for child in _walk(argument):
            candidate = _string_value(child, source)
            if candidate and _endpoint_candidate(candidate):
                break
    if not candidate or not _endpoint_candidate(candidate):
        return None
    method = "GET" if final_name in {"fetch", "get"} else (final_name.upper() if final_name in {"post", "put", "patch", "delete"} else "UNKNOWN")
    if final_name == "open" and arguments:
        method = (_string_value(arguments[0], source) or "UNKNOWN").upper()
    elif final_name == "fetch" and len(arguments) > 1:
        options = _text(arguments[1], source)
        match = re.search(r"method\s*:\s*(['\"])(GET|POST|PUT|PATCH|DELETE)\1", options, re.IGNORECASE)
        if match:
            method = match.group(2).upper()
    elif final_name in {"WebSocket", "EventSource"}:
        method = "WS" if final_name == "WebSocket" else "SSE"
    elif final_name in {"Worker", "SharedWorker"}:
        method = "SCRIPT"
    body_node = None
    if final_name == "fetch" and len(arguments) > 1:
        options_node = arguments[1]
        if options_node.type == "object":
            for pair in options_node.named_children:
                if pair.type == "pair":
                    key_node = pair.child_by_field_name("key")
                    if key_node is not None and _property_name(key_node, source) == "body":
                        body_node = pair.child_by_field_name("value")
                        break
    elif final_name in {"post", "put", "patch", "request"} and len(arguments) > 1:
        body_node = arguments[1]
    confidence = "medium" if argument.type == "identifier" else ("low" if argument.type == "binary_expression" else "high")
    inputs = _json_fields(body_node, source, object_bindings) if body_node is not None else []
    return {"path": candidate, "line": node.start_point.row + 1, "method": method, "call": function_name[:120],
            "confidence": confidence, "inputs": inputs}


def _walk_scope(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        for child in reversed(node.children):
            if child is not root and child.type in FUNCTION_TYPES:
                continue
            stack.append(child)


def _source_label(node, source: bytes) -> str | None:
    value = re.sub(r"\s+", "", _text(node, source)).lower()
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        function_text = _text(function, source).lower() if function is not None else ""
        if "localstorage" in function_text:
            return "localStorage"
        if "sessionstorage" in function_text:
            return "sessionStorage"
        return None
    if node.type != "member_expression":
        return None
    for label, patterns in SOURCE_PATTERNS.items():
        if any(value == pattern.lower() or value.endswith("." + pattern.lower()) for pattern in patterns):
            return label
    return None


def _parameter_names(function_node, source: bytes) -> list[str]:
    parameters = function_node.child_by_field_name("parameters")
    if parameters is None:
        parameters = function_node.child_by_field_name("parameter")
    if parameters is None:
        return []
    if parameters.type == "identifier":
        return [_text(parameters, source)]
    names = []
    for parameter in parameters.named_children:
        identifiers = [node for node in _walk(parameter) if node.type == "identifier"]
        if identifiers:
            names.append(_text(identifiers[0], source))
    return names


def _named_functions(root, source: bytes) -> dict[str, object]:
    functions = {}
    for node in _walk(root):
        if node.type in {"function_declaration", "method_definition"}:
            name = node.child_by_field_name("name")
            if name is not None:
                functions[_text(name, source)] = node
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if (name is not None and name.type == "identifier" and value is not None
                    and value.type in FUNCTION_TYPES):
                functions[_text(name, source)] = value
    return functions


def _interprocedural_observations(root, source: bytes) -> list[dict]:
    functions = _named_functions(root, source)
    observations = []
    seen = set()

    def expression_labels(expression, tainted):
        labels = set()
        for item in _walk(expression):
            source_name = _source_label(item, source)
            if source_name:
                labels.add(source_name)
            elif item.type == "identifier":
                labels.update(tainted.get(_text(item, source), ()))
        return labels

    def analyze_scope(scope, initial_taint, stack, depth=0):
        if depth > 6:
            return
        nodes = list(_walk_scope(scope))
        tainted = {name: set(labels) for name, labels in initial_taint.items()}
        for _ in range(min(len(nodes), 32)):
            changed = False
            for node in nodes:
                if node.type == "variable_declarator":
                    name = node.child_by_field_name("name")
                    value = node.child_by_field_name("value")
                elif node.type == "assignment_expression":
                    name = node.child_by_field_name("left")
                    value = node.child_by_field_name("right")
                else:
                    continue
                if name is None or name.type != "identifier" or value is None:
                    continue
                labels = expression_labels(value, tainted)
                identifier = _text(name, source)
                if not labels.issubset(tainted.get(identifier, set())):
                    tainted.setdefault(identifier, set()).update(labels)
                    changed = True
            if not changed:
                break

        for node in nodes:
            sink_name = None
            line = node.start_point.row + 1
            labels = set()
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and left.type == "member_expression":
                    property_node = left.child_by_field_name("property")
                    property_name = _text(property_node, source) if property_node is not None else ""
                    if property_name in {"innerHTML", "outerHTML"} and right is not None:
                        sink_name = property_name
                        labels = expression_labels(right, tainted)
            elif node.type == "jsx_attribute" and "dangerouslySetInnerHTML" in _text(node, source):
                sink_name = "dangerouslySetInnerHTML"
                labels = expression_labels(node, tainted)
            elif node.type in {"call_expression", "new_expression"}:
                call_target = node.child_by_field_name("function")
                if call_target is None:
                    call_target = node.child_by_field_name("constructor")
                arguments = node.child_by_field_name("arguments")
                if call_target is None or arguments is None:
                    continue
                function_name = _text(call_target, source)
                final_name = function_name.split(".")[-1]
                if function_name in SINK_CALLS or final_name in {"eval", "Function", "insertAdjacentHTML"}:
                    sink_name = function_name
                    for argument in arguments.named_children:
                        labels.update(expression_labels(argument, tainted))
            if sink_name:
                for source_name in sorted(labels):
                    key = (source_name, sink_name, line)
                    if key not in seen:
                        seen.add(key)
                        observations.append({
                            "kind": "source_sink",
                            "identifier": f"{source_name} → {sink_name}",
                            "source": source_name,
                            "sink": sink_name,
                            "line": line,
                            "confidence": "low",
                            "evidence": "Heuristic static taint trace, including bounded function-parameter propagation; control flow, sanitization, and runtime behavior are not proven. Browser validation is required.",
                        })
                        if len(observations) >= MAX_OBSERVATIONS:
                            return

        for node in nodes:
            if node.type not in {"call_expression", "new_expression"}:
                continue
            call_target = node.child_by_field_name("function")
            if call_target is None:
                call_target = node.child_by_field_name("constructor")
            arguments = node.child_by_field_name("arguments")
            if call_target is None or arguments is None:
                continue
            function_name = _text(call_target, source).split(".")[-1]
            target = functions.get(function_name)
            if target is None:
                continue
            argument_nodes = arguments.named_children
            parameter_names = _parameter_names(target, source)
            child_taint = {}
            for index, argument in enumerate(argument_nodes[:len(parameter_names)]):
                labels = expression_labels(argument, tainted)
                if labels:
                    child_taint[parameter_names[index]] = labels
            if not child_taint:
                continue
            call_key = (function_name, tuple(sorted((name, tuple(sorted(labels))) for name, labels in child_taint.items())))
            if call_key in stack:
                continue
            analyze_scope(target, child_taint, stack | {call_key}, depth + 1)
            if len(observations) >= MAX_OBSERVATIONS:
                return

    analyze_scope(root, {}, set())
    for function_node in (node for node in _walk(root) if node.type in FUNCTION_TYPES):
        analyze_scope(function_node, {}, set())
        if len(observations) >= MAX_OBSERVATIONS:
            break
    return observations[:MAX_OBSERVATIONS]


def analyze_javascript(source_text: str) -> dict:
    source = source_text.encode("utf-8", errors="replace")
    parser = Parser(JAVASCRIPT_LANGUAGE)
    tree = parser.parse(source)
    string_bindings = {}
    object_bindings = {}
    for node in _walk(tree.root_node):
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is not None and name_node.type == "identifier" and value_node is not None:
                variable_name = _text(name_node, source)
                value = _string_value(value_node, source)
                if value is not None:
                    string_bindings[variable_name] = value
                if value_node.type == "object" or (value_node.type == "call_expression" and "JSON.stringify" in _text(value_node, source)):
                    object_bindings[variable_name] = value_node
    endpoints = []
    seen_endpoints = set()
    for node in _walk(tree.root_node):
        endpoint = _call_endpoint(node, source, string_bindings, object_bindings)
        endpoint_key = (endpoint["path"], endpoint["method"]) if endpoint else None
        if endpoint and endpoint_key not in seen_endpoints:
            seen_endpoints.add(endpoint_key)
            endpoints.append(endpoint)
            if len(endpoints) >= MAX_OBSERVATIONS:
                break

    observations = _interprocedural_observations(tree.root_node, source)
    return {
        "endpoints": endpoints,
        "observations": observations,
        "parse_error": tree.root_node.has_error,
    }
