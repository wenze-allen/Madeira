#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Japanese locale per game: code page 932, extra NLS tables, bundled Noto Sans JP font,
and HKCU\\Software\\Wine\\Fonts\\Replacements (app/Madeira/LibraryPrefs.swift,
app/Madeira/LibraryBCD.swift, app/Madeira/WineProcessBridge.m).
"""
from pathlib import Path
import hashlib, re, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
app = root / 'app/Madeira'
failures = 0


def check(cond, label):
    global failures
    print(('PASS: ' if cond else 'FAIL: ') + label)
    if not cond:
        failures += 1


def block(source, header):
    start = source.index(header)
    brace = source.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


# 1. Bundled font, licence, NLS extra tables, Xcode resources, and notices.
font = app / 'fonts-ja/NotoSansJP-Regular.otf'
ofl = app / 'fonts-ja/LICENSE-NotoSansJP-OFL-1.1.txt'
full_font_sha = 'dff723ba59d57d136764a04b9b2d03205544f7cd785a711442d6d2d085ac5073'
check(font.is_file() and hashlib.sha256(font.read_bytes()).hexdigest() == full_font_sha,
      'NotoSansJP-Regular.otf matches the pinned SHA-256')
check(ofl.is_file() and 'SIL OPEN FONT LICENSE Version 1.1' in ofl.read_text(encoding='utf-8'),
      'SIL OFL 1.1 licence text is bundled beside the font')

for name in ('c_10000.nls', 'c_932.nls', 'c_936.nls', 'c_949.nls', 'c_950.nls'):
    p = app / 'nls/extra' / name
    check(p.is_file() and p.stat().st_size > 0x1000, f'nls/extra/{name} is present and non-trivial')

project = (root / 'app/Madeira.xcodeproj/project.pbxproj').read_text(encoding='utf-8')
check(project.count('A10009A1 /* fonts-ja in Resources */') == 2 and
      project.count('A20009A1 /* fonts-ja */') == 3 and
      'lastKnownFileType = folder; path = "fonts-ja";' in project,
      'fonts-ja is bundled as a folder resource in project.pbxproj')
check(project.count('A1000022 /* nls in Resources */') == 2 and
      'lastKnownFileType = folder; path = nls;' in project,
      'nls (including nls/extra) is bundled as a folder resource in project.pbxproj')

for notice_rel in ('THIRD-PARTY-NOTICES.md', 'app/Madeira/legal/THIRD-PARTY-NOTICES.md'):
    notice = (root / notice_rel).read_text(encoding='utf-8')
    check('Noto Sans JP' in notice and full_font_sha in notice and 'LICENSE-NotoSansJP-OFL-1.1.txt' in notice,
          f'{notice_rel} documents Noto Sans JP, its SHA-256 and its OFL 1.1 licence')

readme = (root / 'README.md').read_text(encoding='utf-8')
check('**Japanese locale** per game' in readme and '(docs/JAPANESE.md)' in readme and (root / 'docs/JAPANESE.md').is_file(),
      'README.md and docs/JAPANESE.md document Japanese locale per game')

# 2. Bridge & UI source checks.
bridge = (app / 'WineProcessBridge.m').read_text(encoding='utf-8')
lib = (app / 'Library.swift').read_text(encoding='utf-8')
prefs = (app / 'LibraryPrefs.swift').read_text(encoding='utf-8')
bcd = (app / 'LibraryBCD.swift').read_text(encoding='utf-8')

seed = block(bridge, 'void madeira_seed_prefix_if_needed(const char *prefix_path)')
check('madeira_japanese_prefix( prefix );' in seed,
      'madeira_seed_prefix_if_needed prepares the Japanese font and user.reg before wineserver starts')
jp_prefix = block(bridge, 'static void madeira_japanese_prefix(NSString *prefix)')
check('drive_c/windows/Fonts' in jp_prefix and 'NotoSansJP-Regular.otf' in jp_prefix
      and '[Software\\\\\\\\Wine\\\\\\\\Fonts\\\\\\\\Replacements]' in jp_prefix
      and 'MS Gothic' in jp_prefix and 'Meiryo' in jp_prefix and 'Yu Gothic' in jp_prefix,
      'madeira_japanese_prefix installs NotoSansJP-Regular.otf and maps Windows Japanese font names')
check('if (madeira_japanese_on()) {' in bridge
      and 'if (!lc || strncmp(lc, "ja", 2)) setenv("LC_ALL", "ja_JP.UTF-8", 1);' in bridge
      and 'setenv("MADEIRA_NLS_EXTRA", "1", 1);' in bridge,
      'wine_process_thread exports LC_ALL=ja_JP.UTF-8 (keeping any ja* LC_ALL) and MADEIRA_NLS_EXTRA=1')
check('LibraryPrefs.setJapanese(on, for: entry.windowsPath)' in lib and '"Japanese locale"' in lib,
      'Game details > Compatibility has the Japanese locale toggle')

# 3. Compile and run LibraryPrefs.japanese + BCDLaunch.applyJapanese on the host.
swift = '''import Foundation
let suite = "madeira.test.jp." + UUID().uuidString
let defaults = UserDefaults(suiteName: suite)!
defer { defaults.removePersistentDomain(forName: suite) }
'''
swift += block(prefs, 'enum LibraryPrefs {').replace('UserDefaults.standard', 'defaults')
swift += '\nenum BCDLaunch {\n' + block(bcd, '    static func applyJapanese(') + '\n}\n'
swift += r'''
func env(_ k: String) -> String? { getenv(k).map { String(cString: $0) } }
let game = "C:\\Games\\VN\\game.exe"
precondition(!LibraryPrefs.japanese(game))
LibraryPrefs.setJapanese(true, for: game)
precondition(LibraryPrefs.japanese(game))
LibraryPrefs.setJapanese(false, for: game)
precondition(!LibraryPrefs.japanese(game))

unsetenv("MADEIRA_JAPANESE"); unsetenv("LC_ALL"); unsetenv("LANG"); unsetenv("MADEIRA_NLS_EXTRA")
BCDLaunch.applyJapanese(true)
precondition(env("MADEIRA_JAPANESE") == "1")

setenv("LC_ALL", "ja_JP.UTF-8", 1); setenv("LANG", "ja_JP.UTF-8", 1); setenv("MADEIRA_NLS_EXTRA", "1", 1)
BCDLaunch.applyJapanese(false)
precondition(env("MADEIRA_JAPANESE") == nil && env("LC_ALL") == nil && env("LANG") == nil && env("MADEIRA_NLS_EXTRA") == nil)

setenv("LC_ALL", "fr_FR.UTF-8", 1); setenv("MADEIRA_NLS_EXTRA", "1", 1)
BCDLaunch.applyJapanese(false)
precondition(env("LC_ALL") == "fr_FR.UTF-8" && env("MADEIRA_NLS_EXTRA") == "1")
print("PASS: LibraryPrefs.japanese and BCDLaunch.applyJapanese")
'''
with tempfile.TemporaryDirectory(prefix='madeira-japanese-') as tmp:
    tmp = Path(tmp)
    (tmp / 'main.swift').write_text(swift, encoding='utf-8')
    subprocess.run(['swiftc', str(tmp / 'main.swift'), '-o', str(tmp / 'jp')], check=True)
    subprocess.run([str(tmp / 'jp')], check=True)

print('FAIL' if failures else 'PASS')
sys.exit(1 if failures else 0)
