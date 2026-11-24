#!/usr/bin/env python3
"""App translations (app/Madeira/Localizable.xcstrings).

SwiftUI looks up every literal Text/Button/Label/Toggle/Section/... title in the string
catalog, so the app shows German, Spanish, Korean, Brazilian Portuguese, Russian or
Simplified Chinese when the device uses one, and English otherwise (a text the catalog
lacks stays English).

Checks: the catalog is in the app's resources with its languages; every key has all six
languages; links, line breaks and trailing spaces survive translation; and the branch's
UI literals have broad coverage in the catalog (keys for screens upstream added that this
branch left out are harmless and reported as an informational count). A text with
interpolations is keyed with %@ for each one (only String interpolations are translated
this way); its translations use %1$@, %2$@... so the words can move.
"""
from pathlib import Path
import json, re, sys

root = Path(__file__).resolve().parents[2]
app = root / 'app/Madeira'
failures = 0


def check(condition, label):
    global failures
    print(('PASS: ' if condition else 'FAIL: ') + label)
    if not condition:
        failures += 1


catalog = json.loads((app / 'Localizable.xcstrings').read_text(encoding='utf-8'))
project = (app.parent / 'Madeira.xcodeproj/project.pbxproj').read_text(encoding='utf-8')
library = (app / 'Library.swift').read_text(encoding='utf-8')
languages = ['de', 'es', 'ko', 'pt-BR', 'ru', 'zh-Hans']

check(project.count('A1009C03 /* Localizable.xcstrings in Resources */') == 2 and
      project.count('A2009C03 /* Localizable.xcstrings */') == 3, 'the catalog is in the app resources')
regions = re.search(r'knownRegions = \((.*?)\);', project, re.S)
check(regions is not None and all(l in regions.group(1) for l in ['de', 'es', 'ko', '"pt-BR"', 'ru', '"zh-Hans"']),
      'the project knows the languages')
check(catalog.get('sourceLanguage') == 'en', 'English is the source language')
check('func L(_ text: String) -> String {' in library and 'table: "Localizable"' in library,
      'L(_:) looks up non-SwiftUI strings in Localizable')

# The calls whose first argument SwiftUI reads as a LocalizedStringKey, and L("...")
# (Library.swift) for texts built in code: notes, picker titles, statuses, errors.
pattern = re.compile(r'\b(?:Text|Button|Label|Toggle|Section|Picker|navigationTitle|LabeledContent|TextField|Link|NavigationLink|'
                     r'Stepper|Menu|ShareLink|alert|confirmationDialog|SecureField|ContentUnavailableView|DisclosureGroup|ProgressView|L)'
                     r'\(\s*"((?:[^"\\]|\\.)*)"')
text_pattern = re.compile(r'\bText\(\s*"((?:[^"\\]|\\.)*)"')


def normalize_literal(raw):
    text = re.sub(r'\\\([^()"]*\)', '%@', raw)
    text = re.sub(r'\\u\{([0-9A-Fa-f]+)\}', lambda x: chr(int(x.group(1), 16)), text)
    return re.sub(r'\\(["\\nt\'])', lambda x: {'n': '\n', 't': '\t'}.get(x.group(1), x.group(1)), text)


literals = set()
text_literals = set()
for swift in app.glob('*.swift'):
    src = swift.read_text(encoding='utf-8')
    for m in pattern.finditer(src):
        literals.add(normalize_literal(m.group(1)))
    for m in text_pattern.finditer(src):
        text_literals.add(normalize_literal(m.group(1)))

strings = catalog['strings']


# An Int interpolation is keyed %lld by SwiftUI, a String one %@; the source scan sees both as %@.
def shape(key):
    return key.replace('%lld', '%@')


shapes = {shape(k) for k in strings}
matched = [k for k in strings if shape(k) in literals]
upstream_only = [k for k in strings if shape(k) not in literals]
check(len(matched) >= 350, f'{len(matched)} catalog keys match UI literals in this branch ({len(upstream_only)} belong to upstream-only screens)')

missing = [(k, l) for k, v in strings.items() for l in languages
           if not v.get('localizations', {}).get(l, {}).get('stringUnit', {}).get('value')]
check(not missing, 'every text has all six languages' + (f' (missing: {missing[:5]})' if missing else ''))
broken = []
for k, v in strings.items():
    for l in languages:
        t = v['localizations'][l]['stringUnit']['value']
        if ('](' in k) != ('](' in t) or k.count('\n') != t.count('\n') or k.endswith(' ') != t.endswith(' ') or \
                sorted(re.findall(r'%(\d)\$(?:@|lld)', t)) != [str(i + 1) for i in range(shape(k).count('%@'))] or \
                t.count('%') != shape(k).count('%@'):
            broken.append((k[:30], l))
check(not broken, 'links, line breaks and trailing spaces survive' + (f' ({broken[:5]})' if broken else ''))
check(len(strings) >= 700, f'{len(strings)} texts translated')

eligible = {t for t in literals if re.search(r'[A-Za-z]{2}', t) and not re.search(r'\\\(', t)}
covered = {t for t in eligible if t in shapes}
eligible_text = {t for t in text_literals if re.search(r'[A-Za-z]{2}', t) and not re.search(r'\\\(', t)}
covered_text = {t for t in eligible_text if t in shapes}
untranslated = sorted(eligible - shapes)
print(f'NOTE: UI literal coverage: {len(covered)}/{len(eligible)} ({100.0 * len(covered) / max(1, len(eligible)):.1f}%); '
      f'Text("...") literal coverage: {len(covered_text)}/{len(eligible_text)} ({100.0 * len(covered_text) / max(1, len(eligible_text)):.1f}%)')
print(f'NOTE: {len(untranslated)} texts in the app have no translation yet (they show in English):')
for t in untranslated[:30]:
    print('  - ' + t.replace('\n', '\\n'))

print('FAIL' if failures else 'PASS')
sys.exit(1 if failures else 0)
