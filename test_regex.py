import re
pattern = re.compile(r'\{\$[a-zA-Z0-9_]+(?:->|\.)(?:getLabel\s*\(\s*\)|label|galleyLabel)(?![^\}]*(?:escape|strip_tags))[^\}]*\}')

test_cases = [
    '{$galley->getLabel()}',
    '{$galley->getLabel()|escape}',
    '{$galley->getLabel()|strip_tags}',
    '{$galley->getLabel()|escape|other}',
    '{$galley->label}',
]

for t in test_cases:
    print(f'{t}: {bool(pattern.search(t))}')
