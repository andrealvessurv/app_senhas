"""
Corrige o erro "MACOSX_DEPLOYMENT_TARGET is set to 10.15/11.0, but the range of
supported deployment target versions is 12.0 to ..." do Xcode novo.

Uso (na pasta do projeto, depois de uma tentativa de `flet build macos`):
    python3 scripts/corrigir_macos.py
Depois rode `flet build macos` de novo SEM apagar a pasta build.
"""
import pathlib
import re
import shutil
import sys

VERSAO_MINIMA = "12.0"
base = pathlib.Path("build/flutter/macos")

if not base.exists():
    sys.exit("Não achei build/flutter/macos. Rode `flet build macos` uma vez antes "
             "(ele pode falhar no final, tudo bem) e execute este script na pasta do projeto.")

# 1) Podfile: versão mínima e ajuste de todos os pods
podfile = base / "Podfile"
s = podfile.read_text()
s = re.sub(r"platform :(osx|macos), '[0-9.]+'", f"platform :osx, '{VERSAO_MINIMA}'", s)
alvo = "    flutter_additional_macos_build_settings(target)\n"
extra = f"    target.build_configurations.each {{ |c| c.build_settings['MACOSX_DEPLOYMENT_TARGET'] = '{VERSAO_MINIMA}' }}\n"
if extra not in s:
    if alvo not in s:
        sys.exit("Não achei o trecho esperado no Podfile (o modelo do Flet mudou?).")
    s = s.replace(alvo, alvo + extra)
podfile.write_text(s)

# 2) Projeto do Xcode
pbx = base / "Runner.xcodeproj" / "project.pbxproj"
t = pbx.read_text()
t = re.sub(r"MACOSX_DEPLOYMENT_TARGET = [0-9.]+;", f"MACOSX_DEPLOYMENT_TARGET = {VERSAO_MINIMA};", t)
pbx.write_text(t)

# 3) Limpa restos da tentativa anterior
for resto in (base / "Pods", base / "Podfile.lock"):
    if resto.is_dir():
        shutil.rmtree(resto)
    elif resto.exists():
        resto.unlink()

print(f"Pronto: macOS {VERSAO_MINIMA} aplicado.")