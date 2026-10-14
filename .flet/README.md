# Gerador de Senhas Pro

Gerador de senhas (aleatória, frase-senha e PIN), verificador de força com checagem de
vazamentos e cofre criptografado com senha mestra. Feito com Python + [Flet](https://flet.dev).

## Rodar no computador (desenvolvimento)

```bash
pip install "flet==1.0.3" certifi
python app_senhas.py
```

## Baixar o app para Mac (sem instalar nada)

1. Vá na aba **Releases** deste repositório e baixe `GeradorDeSenhasPro-macOS.zip`.
2. Dê dois cliques no `.zip`, arraste o app para **Aplicativos**.
3. **Primeira abertura:** o app não é assinado pela Apple, então o macOS bloqueia. Clique com o
   botão direito no app → **Abrir** → **Abrir**. Se ainda bloquear, rode no Terminal:
   `xattr -dr com.apple.quarantine "/Applications/Gerador de Senhas Pro.app"`

## Gerar uma nova versão (GitHub Actions)

O Mac é construído pelos servidores do GitHub, então você não precisa de Xcode configurado.

```bash
git tag v5.0.0
git push origin v5.0.0
```

Depois de uns 10–20 minutos o arquivo aparece em **Releases**. Também dá para rodar manualmente em
**Actions → Build macOS → Run workflow** (o resultado fica em "Artifacts").

## Gerar no seu próprio Mac

```bash
pip install "flet==1.0.3" "flet-cli==1.0.3"
flet build macos --yes
```

Se aparecer o erro `MACOSX_DEPLOYMENT_TARGET ... 12.0 to ...`:

```bash
python3 scripts/corrigir_macos.py
flet build macos --yes        # NÃO apague a pasta build
```

O app fica em `build/macos/`.

## Ícone

Coloque um PNG quadrado (ideal 1024×1024) em `assets/icon.png`.

## Dados e segurança

- O cofre fica salvo só no aparelho, criptografado com a senha mestra. Se você esquecê-la, não há
  recuperação. Use o ícone de backup para guardar uma cópia criptografada.
- Projeto de estudo: para senhas muito importantes, use um gerenciador profissional (Bitwarden, 1Password...).