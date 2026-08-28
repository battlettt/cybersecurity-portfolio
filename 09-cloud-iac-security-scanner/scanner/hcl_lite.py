"""
hcl_lite.py — a deliberately scoped Terraform/HCL parser.

This is NOT a general HCL grammar implementation. Real HCL supports
for_each, dynamic blocks, function calls, variable interpolation, and a
formal grammar that would take a proper parser (or the `python-hcl2`
library) to handle correctly.

What this file actually supports, and why that's enough here:
  - `resource "<type>" "<name>" { ... }` blocks
  - flat `key = value` attributes (strings, numbers, booleans, string lists)
  - one level of nested unlabeled blocks (`ingress { ... }`, `versioning { ... }`)
  - heredoc string assignments (`key = <<TAG ... TAG`), captured as raw text
    so rules can pattern-match inline IAM policy JSON without a full JSON/HCL
    function evaluator

That covers every construct actually used in this project's vulnerable/
and fixed/ fixtures. Anything outside that scope (for_each, modules,
variable refs) is simply not parsed — a real scanner would need a real
HCL parser (or `python-hcl2`) before being pointed at production Terraform.
"""

import re
from dataclasses import dataclass, field


@dataclass
class Resource:
    type: str
    name: str
    attrs: dict = field(default_factory=dict)
    blocks: dict = field(default_factory=dict)  # block_name -> list[Resource-like dict]

    @property
    def address(self):
        return f'{self.type}.{self.name}'


def _find_matching_brace(text, open_brace_index):
    depth = 0
    i = open_brace_index
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError('Unbalanced braces in HCL source')


def _parse_scalar(raw):
    raw = raw.strip()
    if raw == 'true':
        return True
    if raw == 'false':
        return False
    if raw.startswith('[') and raw.endswith(']'):
        inner = raw[1:-1]
        return [item.strip().strip('"').strip("'") for item in inner.split(',') if item.strip()]
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw  # fall back to raw text (e.g. a resource reference like aws_s3_bucket.x.id)


_HEREDOC_PATTERN = re.compile(r'(\w+)\s*=\s*<<(-?)(\w+)\n(.*?)\n\s*\3', re.DOTALL)
_ATTR_LINE_PATTERN = re.compile(r'(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+?)\s*$')
_NESTED_BLOCK_PATTERN = re.compile(r'(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\{')
_RESOURCE_PATTERN = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')


def _extract_heredocs(text):
    """Replace heredoc assignments with a single-line placeholder so brace
    counting elsewhere isn't confused by braces inside embedded JSON, and
    stash the raw heredoc body for rules that need to inspect it as text."""
    heredocs = {}
    counter = [0]

    def repl(match):
        key, body = match.group(1), match.group(4)
        counter[0] += 1
        hid = f'H{counter[0]}'
        heredocs[hid] = body
        return f'{key} = "HEREDOC:{hid}"'

    return _HEREDOC_PATTERN.sub(repl, text), heredocs


def _parse_flat_attrs(text, heredocs):
    attrs = {}
    for m in _ATTR_LINE_PATTERN.finditer(text):
        key, raw_val = m.group(1), m.group(2)
        if raw_val.startswith('"HEREDOC:') and raw_val.endswith('"'):
            hid = raw_val[len('"HEREDOC:'):-1]
            attrs[key] = heredocs.get(hid, '')
        else:
            attrs[key] = _parse_scalar(raw_val)
    return attrs


def _parse_body(text, heredocs):
    blocks = {}
    remaining = text
    while True:
        m = _NESTED_BLOCK_PATTERN.search(remaining)
        if not m:
            break
        block_name = m.group(1)
        brace_index = m.end() - 1
        close_index = _find_matching_brace(remaining, brace_index)
        inner_text = remaining[brace_index + 1:close_index]
        inner_attrs = _parse_flat_attrs(inner_text, heredocs)
        blocks.setdefault(block_name, []).append(Resource(type=block_name, name='', attrs=inner_attrs))
        remaining = remaining[:m.start()] + remaining[close_index + 1:]
    attrs = _parse_flat_attrs(remaining, heredocs)
    return attrs, blocks


def parse_resources(text):
    """Parse `resource "type" "name" { ... }` blocks out of Terraform source
    text and return a list of Resource objects."""
    heredoc_free_text, heredocs = _extract_heredocs(text)
    resources = []
    for m in _RESOURCE_PATTERN.finditer(heredoc_free_text):
        rtype, rname = m.group(1), m.group(2)
        brace_index = m.end() - 1
        close_index = _find_matching_brace(heredoc_free_text, brace_index)
        body = heredoc_free_text[brace_index + 1:close_index]
        attrs, blocks = _parse_body(body, heredocs)
        resources.append(Resource(type=rtype, name=rname, attrs=attrs, blocks=blocks))
    return resources


def parse_file(path):
    with open(path, 'r') as f:
        return parse_resources(f.read())
