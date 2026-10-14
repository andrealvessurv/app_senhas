import ssl

import asyncio
import base64
import hashlib
import hmac
import json
import math
import random
import secrets
import string
import threading
import time
import urllib.request
from datetime import datetime

import flet as ft

# =========================================================
#  CONFIGURAÇÕES E DADOS GERAIS
# =========================================================

# Chaves do armazenamento do aparelho (SharedPreferences do Flet).
# Funciona igual no Windows, macOS, Linux, Android, iOS e navegador.
CHAVE_COFRE = "cofre_v2"
CHAVE_CONFIG = "config_v2"
ITERACOES = 200_000   # quanto mais, mais difícil de quebrar a senha mestra (e mais lento)

VERSAO = "5.0"

# Cores de destaque que a pessoa pode escolher
CORES = {
    "azul": ft.Colors.BLUE,
    "verde": ft.Colors.GREEN,
    "roxo": ft.Colors.DEEP_PURPLE,
    "laranja": ft.Colors.ORANGE,
    "rosa": ft.Colors.PINK,
    "turquesa": ft.Colors.TEAL,
}

# Lista de palavras para o modo "Frase-senha"
PALAVRAS = sorted(set("""
sol lua mar rio casa gato cachorro pedra fogo vento chuva nuvem terra folha flor arvore
fruta banana laranja limao uva pera manga abacaxi cafe leite pao queijo mel sal acucar
arroz feijao carne peixe ovo bolo doce sopa prato copo faca garfo mesa cadeira janela
porta chave livro caneta papel lapis caderno relogio carro barco trem aviao bicicleta
ponte rua praia areia ilha monte vale campo floresta selva deserto neve gelo trovao raio
estrela planeta cometa foguete robo mapa tesouro castelo dragao lobo urso tigre leao
zebra girafa macaco tartaruga coruja aguia pato cavalo vaca ovelha coelho sapo abelha
formiga borboleta aranha cobra jacare baleia golfinho tubarao polvo caranguejo concha
coral violao piano tambor flauta danca festa jogo bola rede gol time premio medalha
camisa chapeu sapato luva casaco meia bolsa
""".split()))

SENHAS_COMUNS = {
    "123456", "12345678", "123456789", "1234567890", "senha", "senha123", "password",
    "qwerty", "abc123", "111111", "000000", "admin", "iloveyou", "brasil", "123123",
    "654321", "mudar123", "teste123", "flamengo", "corinthians", "gabriel", "minhasenha",
}

SEQUENCIAS = ["0123", "1234", "2345", "3456", "4567", "5678", "6789",
              "abcd", "bcde", "cdef", "qwer", "wert", "erty", "asdf", "sdfg", "zxcv"]


# =========================================================
#  FUNÇÕES AUXILIARES (não mexem na interface)
# =========================================================

def calcular_entropia(senha):
    """Estima quantos 'bits de segurança' a senha tem. Quanto mais bits, melhor."""
    if not senha:
        return 0.0

    pool = 0
    if any(c in string.ascii_lowercase for c in senha):
        pool += 26
    if any(c in string.ascii_uppercase for c in senha):
        pool += 26
    if any(c in string.digits for c in senha):
        pool += 10
    if any(c in string.punctuation for c in senha):
        pool += 32
    if any(c not in string.ascii_letters + string.digits + string.punctuation for c in senha):
        pool += 20

    bits = len(senha) * math.log2(pool)

    minuscula = senha.lower()
    if minuscula in SENHAS_COMUNS:
        return min(bits, 10.0)
    if any(seq in minuscula for seq in SEQUENCIAS):
        bits *= 0.7
    repetidos = sum(1 for i in range(1, len(senha)) if senha[i] == senha[i - 1])
    bits -= repetidos * 3
    return max(bits, 0.0)


def classificar(bits):
    """Devolve (nível de 1 a 5, cor, texto)."""
    if bits < 28:
        return 1, ft.Colors.RED_400, "Muito fraca ⛔"
    if bits < 36:
        return 2, ft.Colors.ORANGE_400, "Fraca ⚠️"
    if bits < 60:
        return 3, ft.Colors.AMBER_400, "Média 🟡"
    if bits < 80:
        return 4, ft.Colors.LIGHT_GREEN_400, "Forte 💪"
    return 5, ft.Colors.CYAN_400, "Extrema 🛡️"


def tempo_para_quebrar(bits):
    """Estimativa com 10 bilhões de tentativas por segundo."""
    segundos = (2.0 ** min(bits, 1000)) / 2 / 1e10
    if segundos < 1:
        return "menos de 1 segundo"
    valor = segundos
    for divisor, nome in [(60, "segundos"), (60, "minutos"), (24, "horas"),
                          (365, "dias"), (1000, "anos")]:
        if valor < divisor:
            return f"{valor:,.0f} {nome}".replace(",", ".")
        valor /= divisor
    if valor < 1000:
        return f"{valor:,.0f} mil anos".replace(",", ".")
    return "milhões de anos ou mais"


def checar_vazamento(senha):
    """
    Consulta o serviço 'Have I Been Pwned' usando k-anonimato:
    só os 5 primeiros caracteres do hash SHA-1 saem do computador,
    a senha em si NUNCA é enviada. Devolve quantas vezes ela já vazou.
    """
    sha1 = hashlib.sha1(senha.encode("utf-8")).hexdigest().upper()
    prefixo, sufixo = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefixo}",
        headers={"User-Agent": "GeradorSenhasPro", "Add-Padding": "true"},
    )
    try:                                     # certificados verificados (mais seguro)
        import certifi
        contexto = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        contexto = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=8, context=contexto) as resposta:
        texto = resposta.read().decode("utf-8")
    for linha in texto.splitlines():
        hash_resto, _, qtd = linha.partition(":")
        if hash_resto == sufixo:
            return int(qtd)
    return 0


# ---------- Cofre criptografado ----------
# Usa SOMENTE a biblioteca padrão do Python (sem pip install), então roda em
# qualquer plataforma. Receita: PBKDF2-HMAC-SHA256 para derivar as chaves a partir
# da senha mestra + cifra de fluxo com HMAC-SHA256 + selo HMAC (criptografar e
# depois autenticar). Qualquer alteração nos dados é detectada.

def derivar_chaves(senha_mestra, salt, iteracoes):
    material = hashlib.pbkdf2_hmac("sha256", senha_mestra.encode("utf-8"), salt, iteracoes, dklen=64)
    return material[:32], material[32:]       # (chave de cifrar, chave do selo)


def _fluxo_de_bytes(k_enc, nonce, tamanho):
    saida = bytearray()
    contador = 0
    while len(saida) < tamanho:
        saida += hmac.new(k_enc, nonce + contador.to_bytes(8, "big"), hashlib.sha256).digest()
        contador += 1
    return bytes(saida[:tamanho])


def _xor(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def cifrar_itens(itens, k_enc, k_mac):
    claro = json.dumps(itens, ensure_ascii=False).encode("utf-8")
    nonce = secrets.token_bytes(16)
    cifrado = _xor(claro, _fluxo_de_bytes(k_enc, nonce, len(claro)))
    selo = hmac.new(k_mac, nonce + cifrado, hashlib.sha256).digest()
    return base64.b64encode(nonce + cifrado + selo).decode("ascii")


def decifrar_itens(dados_b64, k_enc, k_mac):
    bruto = base64.b64decode(dados_b64)
    if len(bruto) < 16 + 32 + 1:
        raise ValueError("dados corrompidos")
    nonce, cifrado, selo = bruto[:16], bruto[16:-32], bruto[-32:]
    esperado = hmac.new(k_mac, nonce + cifrado, hashlib.sha256).digest()
    if not hmac.compare_digest(selo, esperado):
        raise ValueError("senha mestra incorreta")
    claro = _xor(cifrado, _fluxo_de_bytes(k_enc, nonce, len(cifrado)))
    return json.loads(claro.decode("utf-8"))


def empacotar(itens, k_enc, k_mac, salt, iteracoes):
    """Gera o texto que fica guardado no aparelho (e que serve de backup)."""
    return json.dumps({
        "v": 2,
        "salt": base64.b64encode(salt).decode("ascii"),
        "it": iteracoes,
        "dados": cifrar_itens(itens, k_enc, k_mac),
    })


def abrir_pacote(texto, senha_mestra):
    """Devolve (itens, k_enc, k_mac, salt, iteracoes). ValueError se a senha estiver errada."""
    pacote = json.loads(texto)
    salt = base64.b64decode(pacote["salt"])
    iteracoes = int(pacote["it"])
    k_enc, k_mac = derivar_chaves(senha_mestra, salt, iteracoes)
    return decifrar_itens(pacote["dados"], k_enc, k_mac), k_enc, k_mac, salt, iteracoes


def validar_pacote(texto):
    """Confere se um texto colado parece um backup válido deste app."""
    try:
        pacote = json.loads(texto)
        return (
            pacote.get("v") == 2
            and isinstance(pacote.get("dados"), str)
            and 10_000 <= int(pacote["it"]) <= 2_000_000
            and len(base64.b64decode(pacote["salt"])) == 16
        )
    except Exception:
        return False


# =========================================================
#  APP
# =========================================================

async def main(page: ft.Page):
    page.title = "Gerador de Senhas Pro"
    page.padding = 16
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    # Tamanho de janela só faz sentido no computador (no celular o app ocupa a tela toda)
    desktop = (not page.web) and page.platform in (
        ft.PagePlatform.WINDOWS, ft.PagePlatform.MACOS, ft.PagePlatform.LINUX)
    if desktop:
        page.window.width = 420
        page.window.height = 860
        page.window.resizable = False

    # ---- Serviços universais: guardar dados e copiar texto em qualquer aparelho ----
    prefs = ft.SharedPreferences()
    clip = ft.Clipboard()

    cfg = {"tema": "dark", "cor": "azul", "limpar_clip": True}
    blob_salvo = None
    try:
        texto_cfg = await prefs.get(CHAVE_CONFIG)
        if texto_cfg:
            cfg.update(json.loads(texto_cfg))
        blob_salvo = await prefs.get(CHAVE_COFRE)
    except Exception:
        pass

    def salvar_config():
        page.run_task(prefs.set, CHAVE_CONFIG, json.dumps(cfg))

    # ---- Estado compartilhado ----
    historico = []                       # lista de (senha, hora)
    senha_atual = {"valor": ""}
    lote_atual = []
    contador = {"geradas": 0}
    estado_cofre = {
        "aberto": False, "k_enc": None, "k_mac": None, "salt": None,
        "it": ITERACOES, "itens": [],
        "blob": blob_salvo if isinstance(blob_salvo, str) and blob_salvo else None,
    }
    visiveis_cofre = set()
    timer_clip = {"t": None}
    gen = {"n": 0}          # controla o efeito de 'decifrar' da senha
    rot = {"a": 0.0}         # ângulo do ícone do botão Gerar

    # ---- Tema ----
    def aplicar_tema():
        semente = CORES.get(cfg["cor"], ft.Colors.BLUE)
        page.theme = ft.Theme(color_scheme_seed=semente)
        page.dark_theme = ft.Theme(color_scheme_seed=semente)
        page.theme_mode = ft.ThemeMode.DARK if cfg["tema"] == "dark" else ft.ThemeMode.LIGHT

    aplicar_tema()

    # ---- Utilidades de interface ----
    def aviso(mensagem):
        page.show_dialog(ft.SnackBar(content=ft.Text(mensagem)))

    def cartao(conteudo, padding=14):
        return ft.Container(
            content=conteudo, padding=padding, border_radius=16,
            bgcolor=ft.Colors.SURFACE_CONTAINER,
        )

    def titulo_secao(icone, texto):
        return ft.Row([
            ft.Icon(icone, color=ft.Colors.PRIMARY, size=24),
            ft.Text(texto, size=20, weight=ft.FontWeight.BOLD),
        ], spacing=10)

    def criar_barra():
        """Barra de força com 5 segmentos."""
        return ft.Row(
            [ft.Container(expand=1, height=7, border_radius=4,
                          bgcolor=ft.Colors.with_opacity(0.15, ft.Colors.ON_SURFACE),
                          animate=ft.Animation(450, ft.AnimationCurve.EASE_OUT))
             for _ in range(5)],
            spacing=4,
        )

    def pintar_barra(barra, nivel, cor):
        for i, seg in enumerate(barra.controls):
            seg.bgcolor = cor if i < nivel else ft.Colors.with_opacity(0.15, ft.Colors.ON_SURFACE)

    # ---- Animações ----
    def preparar_animacao(ctrl):
        """Liga a animação de opacidade e deslocamento de um controle."""
        ctrl.animate_opacity = ft.Animation(380, ft.AnimationCurve.EASE_OUT)
        ctrl.animate_offset = ft.Animation(380, ft.AnimationCurve.EASE_OUT)

    def aparecer(ctrl, dx=0.0, dy=0.06):
        """Mostra um controle com fade + deslizando de leve."""
        ctrl.visible = True
        ctrl.opacity = 0
        ctrl.offset = ft.Offset(dx, dy)
        page.update()
        time.sleep(0.04)
        ctrl.opacity = 1
        ctrl.offset = ft.Offset(0, 0)
        page.update()

    def cascata(controles, passo=0.06, maximo=10):
        """Itens de uma lista entram um depois do outro."""
        alvo = list(controles)[:maximo]
        for c in alvo:
            preparar_animacao(c)
            c.opacity = 0
            c.offset = ft.Offset(0, 0.25)
        page.update()
        time.sleep(0.04)
        for c in alvo:
            c.opacity = 1
            c.offset = ft.Offset(0, 0)
            page.update()
            time.sleep(passo)

    def tremer(ctrl):
        """Balança o controle de um lado para o outro (usado em erros)."""
        ctrl.animate_offset = ft.Animation(70, ft.AnimationCurve.EASE_IN_OUT)
        for dx in (0.03, -0.03, 0.02, -0.02, 0.0):
            ctrl.offset = ft.Offset(dx, 0)
            page.update()
            time.sleep(0.07)

    # ---- Copiar (funciona em celular, PC e navegador) ----
    async def _limpar_depois(texto):
        try:
            await asyncio.sleep(30)
            if (await clip.get()) == texto:      # só limpa se ainda for a nossa senha
                await clip.set("")
        except Exception:
            pass

    async def _copiar_async(texto, mensagem, limpar):
        try:
            await clip.set(texto)
        except Exception:
            aviso("Não consegui copiar automaticamente.")
            return
        if limpar and cfg["limpar_clip"]:
            if timer_clip["t"]:
                timer_clip["t"].cancel()
            timer_clip["t"] = page.run_task(_limpar_depois, texto)
            mensagem += " (some em 30s)"
        aviso(mensagem)

    def copiar(texto, mensagem="Copiado! 📋", limpar=True):
        if not texto:
            return
        page.run_task(_copiar_async, texto, mensagem, limpar)

    # =====================================================
    #  ABA 1: GERAR
    # =====================================================
    txt_senha = ft.Text(
        value="", size=22, weight=ft.FontWeight.BOLD,
        text_align=ft.TextAlign.CENTER, selectable=True,
    )
    barra_forca = criar_barra()
    chip_forca = ft.Text("—", size=13, weight=ft.FontWeight.BOLD)
    lbl_bits = ft.Text("", size=11, color=ft.Colors.ON_SURFACE_VARIANT, text_align=ft.TextAlign.CENTER)

    def colorir_senha(senha):
        """Números em azul, símbolos em rosa, letras na cor normal."""
        spans = []
        for c in senha:
            if c.isdigit():
                spans.append(ft.TextSpan(text=c, style=ft.TextStyle(color=ft.Colors.CYAN_300)))
            elif not c.isalnum():
                spans.append(ft.TextSpan(text=c, style=ft.TextStyle(color=ft.Colors.PINK_300)))
            else:
                spans.append(ft.TextSpan(text=c))
        return spans

    def desenhar_senha():
        senha = senha_atual["valor"]
        if not senha:
            txt_senha.spans = [ft.TextSpan(text="Toque em Gerar",
                                           style=ft.TextStyle(size=16, color=ft.Colors.ON_SURFACE_VARIANT))]
        elif sw_ocultar.value:
            txt_senha.spans = [ft.TextSpan(text="•" * len(senha))]
        else:
            txt_senha.spans = colorir_senha(senha)

    def mostrar_forca(bits):
        nivel, cor, texto = classificar(bits)
        pintar_barra(barra_forca, nivel, cor)
        chip_forca.value = f"Força: {texto}"
        chip_forca.color = cor
        lbl_bits.value = f"≈ {bits:.0f} bits • quebra em {tempo_para_quebrar(bits)}"

    # --- Modo de geração ---
    seg_modo = ft.SegmentedButton(
        selected=["aleatoria"],
        segments=[
            ft.Segment(value="aleatoria", label=ft.Text("Aleatória"), icon=ft.Icon(ft.Icons.SHUFFLE)),
            ft.Segment(value="frase", label=ft.Text("Frase"), icon=ft.Icon(ft.Icons.ABC)),
            ft.Segment(value="pin", label=ft.Text("PIN"), icon=ft.Icon(ft.Icons.PIN)),
        ],
    )

    # --- Painel ALEATÓRIA ---
    lbl_tamanho = ft.Text("Tamanho: 16 caracteres", size=14)

    def mudou_tamanho(e=None):
        lbl_tamanho.value = f"Tamanho: {int(slider_tamanho.value)} caracteres"
        page.update()

    slider_tamanho = ft.Slider(min=6, max=32, divisions=26, value=16, on_change=mudou_tamanho)
    chk_maiusculas = ft.Checkbox(label="Maiúsculas (A-Z)", value=True)
    chk_minusculas = ft.Checkbox(label="Minúsculas (a-z)", value=True)
    chk_numeros = ft.Checkbox(label="Números (0-9)", value=True)
    chk_simbolos = ft.Checkbox(label="Símbolos (!@#$)", value=True)
    chk_ambiguos = ft.Checkbox(label="Excluir difíceis (1, l, I, 0, O)", value=False)
    sw_garantir = ft.Switch(label="Garantir ao menos 1 de cada tipo", value=True)
    sw_sem_repetir = ft.Switch(label="Evitar caracteres iguais lado a lado", value=False)
    campo_simbolos = ft.TextField(
        label="Símbolos permitidos", value=string.punctuation, dense=True,
        helper="Alguns sites só aceitam certos símbolos. Edite aqui.",
    )

    def aplicar_perfil(tamanho, mai, min_, num, simb, amb):
        slider_tamanho.value = tamanho
        chk_maiusculas.value = mai
        chk_minusculas.value = min_
        chk_numeros.value = num
        chk_simbolos.value = simb
        chk_ambiguos.value = amb
        mudou_tamanho()
        gerar()

    perfis = ft.Row([
        ft.Chip(label=ft.Text("📶 Wi-Fi"), on_click=lambda e: aplicar_perfil(12, True, True, True, False, True)),
        ft.Chip(label=ft.Text("🌐 Site"), on_click=lambda e: aplicar_perfil(16, True, True, True, True, False)),
        ft.Chip(label=ft.Text("🏦 Banco"), on_click=lambda e: aplicar_perfil(24, True, True, True, True, False)),
        ft.Chip(label=ft.Text("🛡️ Máxima"), on_click=lambda e: aplicar_perfil(32, True, True, True, True, False)),
    ], wrap=True, spacing=6, run_spacing=0)

    painel_aleatoria = ft.Column([
        ft.Text("Perfis rápidos", size=12, color=ft.Colors.ON_SURFACE_VARIANT),
        perfis,
        lbl_tamanho, slider_tamanho,
        ft.Row([
            ft.Column([chk_maiusculas, chk_numeros]),
            ft.Column([chk_minusculas, chk_simbolos]),
        ], alignment=ft.MainAxisAlignment.SPACE_AROUND),
        chk_ambiguos,
        ft.ExpansionTile(
            title=ft.Text("Opções avançadas", size=13),
            controls=[
                ft.Container(
                    padding=ft.Padding.symmetric(horizontal=12, vertical=6),
                    content=ft.Column([sw_garantir, sw_sem_repetir, campo_simbolos], spacing=8),
                ),
            ],
        ),
    ], spacing=6)

    # --- Painel FRASE ---
    lbl_palavras = ft.Text("Palavras: 6", size=14)

    def mudou_palavras(e=None):
        lbl_palavras.value = f"Palavras: {int(slider_palavras.value)}"
        page.update()

    slider_palavras = ft.Slider(min=4, max=10, divisions=6, value=6, on_change=mudou_palavras)
    dd_separador = ft.Dropdown(
        label="Separador", value="-", width=220,
        options=[
            ft.DropdownOption(key="-", text="Hífen ( - )"),
            ft.DropdownOption(key="_", text="Underline ( _ )"),
            ft.DropdownOption(key=".", text="Ponto ( . )"),
            ft.DropdownOption(key=" ", text="Espaço"),
        ],
    )
    sw_capitalizar = ft.Switch(label="Primeira letra maiúscula", value=True)
    sw_numero = ft.Switch(label="Adicionar número no final", value=True)

    painel_frase = ft.Column([
        lbl_palavras, slider_palavras, dd_separador, sw_capitalizar, sw_numero,
        ft.Text("Nossa lista tem poucas palavras, então use 6 ou mais para ficar forte.",
                size=11, color=ft.Colors.ON_SURFACE_VARIANT),
    ], spacing=6, visible=False)

    # --- Painel PIN ---
    lbl_pin = ft.Text("Dígitos: 6", size=14)

    def mudou_pin(e=None):
        lbl_pin.value = f"Dígitos: {int(slider_pin.value)}"
        page.update()

    slider_pin = ft.Slider(min=4, max=12, divisions=8, value=6, on_change=mudou_pin)
    painel_pin = ft.Column([
        lbl_pin, slider_pin,
        ft.Text("PINs são curtos: use só onde o sistema bloqueia tentativas repetidas.",
                size=11, color=ft.Colors.ON_SURFACE_VARIANT),
    ], spacing=6, visible=False)

    def trocou_modo(e=None):
        modo = seg_modo.selected[0]
        paineis = {"aleatoria": painel_aleatoria, "frase": painel_frase, "pin": painel_pin}
        for nome, painel in paineis.items():
            painel.visible = nome == modo
        aparecer(paineis[modo], dy=0.04)

    seg_modo.on_change = trocou_modo

    # --- Geração ---
    def gerar_aleatoria():
        """Devolve (senha, bits) ou None se nada foi selecionado."""
        grupos = []
        if chk_maiusculas.value:
            grupos.append(string.ascii_uppercase)
        if chk_minusculas.value:
            grupos.append(string.ascii_lowercase)
        if chk_numeros.value:
            grupos.append(string.digits)
        if chk_simbolos.value:
            simbolos = "".join(dict.fromkeys((campo_simbolos.value or "").replace(" ", "")))
            if simbolos:
                grupos.append(simbolos)

        if chk_ambiguos.value:
            grupos = ["".join(c for c in g if c not in "1lI0O") for g in grupos]
        grupos = [g for g in grupos if g]
        if not grupos:
            return None

        tamanho = int(slider_tamanho.value)
        todos = "".join(grupos)

        senha = ""
        for _ in range(60):   # tentativas (só importa se "evitar repetidos" estiver ligado)
            letras = [secrets.choice(g) for g in grupos] if sw_garantir.value else []
            while len(letras) < tamanho:
                letras.append(secrets.choice(todos))
            random.SystemRandom().shuffle(letras)
            senha = "".join(letras)
            if not sw_sem_repetir.value or all(senha[i] != senha[i - 1] for i in range(1, len(senha))):
                break

        bits = len(senha) * math.log2(len(set(todos)))
        return senha, bits

    def gerar_frase():
        qtd = int(slider_palavras.value)
        sep = dd_separador.value or "-"
        palavras = [secrets.choice(PALAVRAS) for _ in range(qtd)]
        if sw_capitalizar.value:
            palavras = [p.capitalize() for p in palavras]
        frase = sep.join(palavras)
        bits = qtd * math.log2(len(PALAVRAS))
        if sw_numero.value:
            frase += sep + str(secrets.randbelow(100)).zfill(2)
            bits += math.log2(100)
        return frase, bits

    def gerar_pin():
        qtd = int(slider_pin.value)
        return "".join(secrets.choice(string.digits) for _ in range(qtd)), qtd * math.log2(10)

    def gerar_uma():
        modo = seg_modo.selected[0]
        if modo == "aleatoria":
            return gerar_aleatoria()
        if modo == "frase":
            return gerar_frase()
        return gerar_pin()

    # --- Histórico ---
    lista_historico = ft.Column(spacing=2)

    def desenhar_historico():
        lista_historico.controls.clear()
        for s, hora in reversed(historico):
            lista_historico.controls.append(ft.Row([
                ft.Text(hora, size=11, color=ft.Colors.ON_SURFACE_VARIANT),
                ft.Text(s, size=12, selectable=True, expand=True),
                ft.IconButton(ft.Icons.COPY, icon_size=16, tooltip="Copiar",
                              on_click=lambda e, t=s: copiar(t)),
            ]))
        if not historico:
            lista_historico.controls.append(
                ft.Text("Nada por aqui ainda.", size=12, color=ft.Colors.ON_SURFACE_VARIANT))

    def limpar_historico(e=None):
        historico.clear()
        desenhar_historico()
        page.update()

    def revelar_senha(senha):
        """Efeito 'decifrando': letras aleatórias vão virando a senha final."""
        gen["n"] += 1
        meu = gen["n"]
        if sw_ocultar.value or not senha:
            desenhar_senha()
            page.update()
            return
        sorteio = string.ascii_letters + string.digits + "!@#$%&*?"
        passos = 12
        for p in range(passos):
            if gen["n"] != meu:          # outra geração começou: abandona esta
                return
            corte = len(senha) * p // passos
            resto = "".join(random.choice(sorteio) for _ in range(len(senha) - corte))
            txt_senha.spans = colorir_senha(senha[:corte]) + [
                ft.TextSpan(text=resto, style=ft.TextStyle(color=ft.Colors.ON_SURFACE_VARIANT))
            ]
            page.update()
            time.sleep(0.03)
        if gen["n"] == meu:
            desenhar_senha()
            page.update()

    def gerar(e=None, animar=True):
        resultado = gerar_uma()
        if resultado is None:
            aviso("Selecione pelo menos um tipo de caractere!")
            return
        senha, bits = resultado
        senha_atual["valor"] = senha
        contador["geradas"] += 1
        mostrar_forca(bits)

        historico.append((senha, datetime.now().strftime("%H:%M")))
        if len(historico) > 8:
            historico.pop(0)
        desenhar_historico()
        atualizar_estatisticas()

        if not animar:
            desenhar_senha()
            page.update()
            return

        rot["a"] += 2 * math.pi              # ícone dá uma volta completa
        icone_gerar.rotate = rot["a"]
        cartao_senha.scale = 0.96            # o cartão "pulsa"
        page.update()
        time.sleep(0.05)
        cartao_senha.scale = 1.0
        revelar_senha(senha)

    def copiar_atual(e=None):
        if not senha_atual["valor"]:
            return
        copiar(senha_atual["valor"])
        icone_copiar.icon = ft.Icons.CHECK           # vira um "check" por instantes
        icone_copiar.icon_color = ft.Colors.GREEN_400
        page.update()

        def voltar():
            icone_copiar.icon = ft.Icons.COPY
            icone_copiar.icon_color = None
            try:
                page.update()
            except Exception:
                pass

        t = threading.Timer(1.3, voltar)
        t.daemon = True
        t.start()

    icone_copiar = ft.IconButton(ft.Icons.COPY, tooltip="Copiar", on_click=copiar_atual)

    def mudou_ocultar(e=None):
        desenhar_senha()
        page.update()

    sw_ocultar = ft.Switch(label="Ocultar senha", value=False, on_change=mudou_ocultar)

    # --- Salvar no cofre (a partir da aba Gerar) ---
    def abrir_salvar(e=None, senha=None):
        senha = senha or senha_atual["valor"]
        if not senha:
            aviso("Gere uma senha primeiro!")
            return
        if not estado_cofre["aberto"]:
            aviso("Abra o cofre primeiro 🔒")
            ir_para_aba(2)
            return

        campo_nome = ft.TextField(label="Nome (ex: Gmail, Instagram)", autofocus=True)

        def confirmar(ev=None):
            nome = (campo_nome.value or "").strip() or "Sem nome"
            estado_cofre["itens"].append({
                "nome": nome, "senha": senha,
                "data": datetime.now().strftime("%d/%m/%Y"),
            })
            gravar_cofre()
            desenhar_cofre()
            page.pop_dialog()
            aviso(f"Salva no cofre como '{nome}' 🔐")

        def cancelar(ev=None):
            page.pop_dialog()

        page.show_dialog(ft.AlertDialog(
            title=ft.Text("Salvar no cofre"),
            content=campo_nome,
            actions=[
                ft.TextButton(content="Cancelar", on_click=cancelar),
                ft.TextButton(content="Salvar", on_click=confirmar),
            ],
        ))

    icone_gerar = ft.Container(
        content=ft.Icon(ft.Icons.REFRESH, color=ft.Colors.ON_PRIMARY),
        rotate=0, animate_rotation=ft.Animation(600, ft.AnimationCurve.EASE_IN_OUT),
    )

    def hover_gerar(e):
        btn_gerar.scale = 1.03 if str(e.data).lower() == "true" else 1.0
        page.update()

    def clicar_gerar(e=None):
        btn_gerar.scale = 0.95               # efeito de "apertar" o botão
        page.update()
        time.sleep(0.08)
        btn_gerar.scale = 1.03
        gerar()

    btn_gerar = ft.Container(
        content=ft.Row([
            icone_gerar,
            ft.Text("Gerar senha", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.ON_PRIMARY),
        ], alignment=ft.MainAxisAlignment.CENTER, spacing=8),
        bgcolor=ft.Colors.PRIMARY, border_radius=14, expand=True, ink=True,
        padding=ft.Padding.symmetric(vertical=14),
        on_click=clicar_gerar, on_hover=hover_gerar,
        scale=1, animate_scale=ft.Animation(160, ft.AnimationCurve.EASE_OUT),
    )

    def botao_icone(icone, dica, acao):
        return ft.Container(
            content=ft.IconButton(icone, tooltip=dica, on_click=acao),
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGH, border_radius=14,
        )

    cartao_senha = ft.Container(
        content=ft.Column([
            ft.Container(content=txt_senha, alignment=ft.Alignment.CENTER, padding=ft.Padding.symmetric(vertical=10)),
            barra_forca,
            ft.Row([chip_forca], alignment=ft.MainAxisAlignment.CENTER),
            ft.Row([lbl_bits], alignment=ft.MainAxisAlignment.CENTER),
        ], spacing=8),
        padding=16, border_radius=18,
        scale=1, animate_scale=ft.Animation(260, ft.AnimationCurve.EASE_OUT_BACK),
        gradient=ft.LinearGradient(
            begin=ft.Alignment.TOP_LEFT, end=ft.Alignment.BOTTOM_RIGHT,
            colors=[ft.Colors.PRIMARY_CONTAINER, ft.Colors.SURFACE_CONTAINER],
        ),
    )

    view_gerar = ft.Column([
        cartao_senha,
        ft.Row([
            btn_gerar,
            ft.Container(content=icone_copiar, bgcolor=ft.Colors.SURFACE_CONTAINER_HIGH, border_radius=14),
            botao_icone(ft.Icons.SAVE, "Salvar no cofre", abrir_salvar),
        ], spacing=8),
        sw_ocultar,
        seg_modo,
        cartao(ft.Column([painel_aleatoria, painel_frase, painel_pin])),
        ft.ExpansionTile(
            title=ft.Text("Histórico (últimas senhas)", size=13),
            controls=[
                ft.Container(content=lista_historico, padding=ft.Padding.symmetric(horizontal=12)),
                ft.TextButton(content="Limpar histórico", icon=ft.Icons.DELETE, on_click=limpar_historico),
            ],
        ),
    ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    # =====================================================
    #  ABA 2: VERIFICAR
    # =====================================================
    campo_verificar = ft.TextField(
        label="Digite uma senha para testar", password=True, can_reveal_password=True,
        prefix_icon=ft.Icons.KEY,
    )
    barra_ver = criar_barra()
    lbl_ver = ft.Text("Digite algo acima 👆", size=16, weight=ft.FontWeight.BOLD)
    lbl_ver_info = ft.Text("", size=12, color=ft.Colors.ON_SURFACE_VARIANT)
    lista_requisitos = ft.Column(spacing=4)
    lista_sugestoes = ft.Column(spacing=2)
    anel_vazamento = ft.ProgressRing(width=18, height=18, stroke_width=2, visible=False)
    resultado_vazamento = ft.Text("", size=13)

    def linha_requisito(ok, texto):
        return ft.Row([
            ft.Icon(ft.Icons.CHECK_CIRCLE if ok else ft.Icons.CANCEL,
                    color=ft.Colors.GREEN_400 if ok else ft.Colors.RED_300, size=18),
            ft.Text(texto, size=13),
        ])

    def verificar(e=None):
        senha = campo_verificar.value or ""
        lista_requisitos.controls.clear()
        lista_sugestoes.controls.clear()
        resultado_vazamento.value = ""

        if not senha:
            pintar_barra(barra_ver, 0, None)
            lbl_ver.value = "Digite algo acima 👆"
            lbl_ver.color = None
            lbl_ver_info.value = ""
            page.update()
            return

        bits = calcular_entropia(senha)
        nivel, cor, texto = classificar(bits)
        pintar_barra(barra_ver, nivel, cor)
        lbl_ver.value = f"Força: {texto}"
        lbl_ver.color = cor
        lbl_ver_info.value = (f"≈ {bits:.0f} bits de entropia\n"
                              f"Tempo estimado para quebrar: {tempo_para_quebrar(bits)}")

        minuscula = senha.lower()
        checks = [
            (len(senha) >= 12, "Pelo menos 12 caracteres", "Aumente o tamanho para 12 ou mais."),
            (any(c.isupper() for c in senha), "Tem letra maiúscula", "Misture letras maiúsculas."),
            (any(c.islower() for c in senha), "Tem letra minúscula", "Misture letras minúsculas."),
            (any(c.isdigit() for c in senha), "Tem número", "Inclua números."),
            (any(c in string.punctuation for c in senha), "Tem símbolo", "Inclua símbolos como ! @ # $."),
            (minuscula not in SENHAS_COMUNS, "Não é uma senha comum", "Essa senha é muito comum: troque já!"),
            (not any(s in minuscula for s in SEQUENCIAS), "Sem sequências (1234, abcd...)",
             "Evite sequências do teclado ou do alfabeto."),
        ]
        for ok, nome, _ in checks:
            lista_requisitos.controls.append(linha_requisito(ok, nome))
        for ok, _, sugestao in checks:
            if not ok:
                lista_sugestoes.controls.append(
                    ft.Text(f"💡 {sugestao}", size=12, color=ft.Colors.ON_SURFACE_VARIANT))
        page.update()

    campo_verificar.on_change = verificar

    def consultar_vazamento(e=None):
        senha = campo_verificar.value or ""
        if not senha:
            aviso("Digite uma senha primeiro.")
            return
        anel_vazamento.visible = True
        resultado_vazamento.value = "Consultando..."
        resultado_vazamento.color = None
        page.update()
        try:
            vezes = checar_vazamento(senha)
            if vezes > 0:
                resultado_vazamento.value = (
                    f"⚠️ Essa senha apareceu em {vezes:,} vazamentos. NÃO use!".replace(",", "."))
                resultado_vazamento.color = ft.Colors.RED_300
            else:
                resultado_vazamento.value = "✅ Não encontrada em vazamentos conhecidos."
                resultado_vazamento.color = ft.Colors.GREEN_400
        except Exception:
            resultado_vazamento.value = "Não foi possível consultar. Verifique sua internet."
            resultado_vazamento.color = ft.Colors.AMBER_400
        anel_vazamento.visible = False
        page.update()

    view_verificar = ft.Column([
        titulo_secao(ft.Icons.VERIFIED_USER, "Verificador"),
        ft.Text("A análise de força acontece no seu computador. Nada é enviado.",
                size=12, color=ft.Colors.ON_SURFACE_VARIANT),
        campo_verificar,
        cartao(ft.Column([barra_ver, lbl_ver, lbl_ver_info], spacing=8)),
        cartao(ft.Column([lista_requisitos, lista_sugestoes], spacing=10)),
        cartao(ft.Column([
            ft.Text("Checar vazamentos", weight=ft.FontWeight.BOLD),
            ft.Text("Consulta o serviço Have I Been Pwned. Só os 5 primeiros caracteres do hash "
                    "da senha são enviados, nunca a senha.",
                    size=11, color=ft.Colors.ON_SURFACE_VARIANT),
            ft.Row([
                ft.OutlinedButton(content=ft.Text("Checar agora"), icon=ft.Icons.GPP_BAD,
                                  on_click=consultar_vazamento),
                anel_vazamento,
            ], spacing=12),
            resultado_vazamento,
        ], spacing=8)),
    ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True, visible=False)

    # =====================================================
    #  ABA 3: COFRE (salvo no próprio aparelho, criptografado)
    # =====================================================
    def gravar_cofre():
        """Criptografa os itens e guarda no armazenamento do aparelho."""
        texto = empacotar(estado_cofre["itens"], estado_cofre["k_enc"], estado_cofre["k_mac"],
                          estado_cofre["salt"], estado_cofre["it"])
        estado_cofre["blob"] = texto
        page.run_task(prefs.set, CHAVE_COFRE, texto)

    anel_cofre = ft.ProgressRing(width=22, height=22, stroke_width=3, visible=False)

    # --- Restaurar um backup (colando o código) ---
    def abrir_restaurar(e=None):
        campo_codigo = ft.TextField(label="Cole aqui o código do backup", multiline=True,
                                    min_lines=4, max_lines=6)

        def confirmar(ev=None):
            texto = (campo_codigo.value or "").strip()
            if not validar_pacote(texto):
                campo_codigo.error = "Código de backup inválido"
                page.update()
                return
            estado_cofre.update({"blob": texto, "aberto": False, "k_enc": None, "k_mac": None,
                                 "salt": None, "itens": []})
            page.run_task(prefs.set, CHAVE_COFRE, texto)
            page.pop_dialog()
            atualizar_painel_cofre(animar=True)
            aviso("Backup restaurado. Digite a senha mestra dele para abrir 🔓")

        def cancelar(ev=None):
            page.pop_dialog()

        page.show_dialog(ft.AlertDialog(
            title=ft.Text("Restaurar backup"),
            content=ft.Column([
                ft.Text("Isso substitui o cofre guardado neste aparelho.", size=12),
                campo_codigo,
            ], tight=True, spacing=10),
            actions=[ft.TextButton(content="Cancelar", on_click=cancelar),
                     ft.TextButton(content="Restaurar", on_click=confirmar)],
        ))

    def copiar_backup(e=None):
        if estado_cofre["blob"]:
            copiar(estado_cofre["blob"], "Backup copiado! Guarde em lugar seguro 💾", limpar=False)

    # --- Criar senha mestra ---
    campo_mestra1 = ft.TextField(label="Crie uma senha mestra", password=True, can_reveal_password=True)
    campo_mestra2 = ft.TextField(label="Repita a senha mestra", password=True, can_reveal_password=True)

    def criar_cofre(e=None):
        m1, m2 = campo_mestra1.value or "", campo_mestra2.value or ""
        campo_mestra1.error = None
        campo_mestra2.error = None
        if len(m1) < 8:
            campo_mestra1.error = "Use pelo menos 8 caracteres"
            page.update()
            return
        if m1 != m2:
            campo_mestra2.error = "As senhas não são iguais"
            page.update()
            return

        anel_cofre.visible = True
        page.update()
        salt = secrets.token_bytes(16)
        k_enc, k_mac = derivar_chaves(m1, salt, ITERACOES)
        estado_cofre.update({"aberto": True, "k_enc": k_enc, "k_mac": k_mac, "salt": salt,
                             "it": ITERACOES, "itens": []})
        gravar_cofre()
        anel_cofre.visible = False
        campo_mestra1.value = campo_mestra2.value = ""
        atualizar_painel_cofre(animar=True)
        desenhar_cofre(animar=True)
        aviso("Cofre criado e protegido 🔐")

    painel_criar = ft.Column([
        cartao(ft.Column([
            ft.Icon(ft.Icons.ENHANCED_ENCRYPTION, size=48, color=ft.Colors.PRIMARY),
            ft.Text("Crie seu cofre", size=18, weight=ft.FontWeight.BOLD),
            ft.Text("Suas senhas ficam salvas só neste aparelho, criptografadas com uma senha mestra. "
                    "Atenção: se você esquecer essa senha, não há como recuperar o cofre.",
                    size=12, color=ft.Colors.ON_SURFACE_VARIANT, text_align=ft.TextAlign.CENTER),
            campo_mestra1, campo_mestra2,
            ft.Row([ft.Button(content=ft.Text("Criar cofre"), icon=ft.Icons.LOCK, on_click=criar_cofre),
                    anel_cofre], alignment=ft.MainAxisAlignment.CENTER, spacing=12),
            ft.TextButton(content="Já tenho um backup", icon=ft.Icons.RESTORE, on_click=abrir_restaurar),
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12), padding=20),
    ], visible=False)

    # --- Desbloquear ---
    campo_login = ft.TextField(label="Senha mestra", password=True, can_reveal_password=True)

    def desbloquear(e=None):
        campo_login.error = None
        anel_cofre.visible = True
        page.update()
        try:
            itens, k_enc, k_mac, salt, it = abrir_pacote(estado_cofre["blob"], campo_login.value or "")
        except ValueError:
            anel_cofre.visible = False
            campo_login.error = "Senha mestra incorreta"
            page.update()
            tremer(campo_login)
            return
        except Exception:
            anel_cofre.visible = False
            campo_login.error = "Não consegui ler os dados do cofre"
            page.update()
            return
        anel_cofre.visible = False
        estado_cofre.update({"aberto": True, "itens": itens, "k_enc": k_enc, "k_mac": k_mac,
                             "salt": salt, "it": it})
        campo_login.value = ""
        visiveis_cofre.clear()
        atualizar_painel_cofre(animar=True)
        desenhar_cofre(animar=True)

    campo_login.on_submit = desbloquear
    campo_mestra2.on_submit = criar_cofre

    painel_login = ft.Column([
        cartao(ft.Column([
            ft.Icon(ft.Icons.LOCK, size=48, color=ft.Colors.PRIMARY),
            ft.Text("Cofre bloqueado", size=18, weight=ft.FontWeight.BOLD),
            campo_login,
            ft.Row([ft.Button(content=ft.Text("Desbloquear"), icon=ft.Icons.LOCK_OPEN, on_click=desbloquear),
                    anel_cofre], alignment=ft.MainAxisAlignment.CENTER, spacing=12),
            ft.TextButton(content="Restaurar de um backup", icon=ft.Icons.RESTORE, on_click=abrir_restaurar),
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12), padding=20),
    ], visible=False)

    # --- Cofre aberto ---
    campo_busca = ft.TextField(label="Buscar no cofre", prefix_icon=ft.Icons.SEARCH, dense=True)
    lista_cofre = ft.Column(spacing=8)
    lbl_total_cofre = ft.Text("", size=12, color=ft.Colors.ON_SURFACE_VARIANT)

    def bloquear(e=None):
        estado_cofre.update({"aberto": False, "k_enc": None, "k_mac": None, "salt": None, "itens": []})
        visiveis_cofre.clear()
        lista_cofre.controls.clear()
        atualizar_painel_cofre(animar=True)
        aviso("Cofre bloqueado 🔒")

    def alternar_visivel(i):
        if i in visiveis_cofre:
            visiveis_cofre.discard(i)
        else:
            visiveis_cofre.add(i)
        desenhar_cofre()
        page.update()

    def apagar_item(i):
        def confirmar(ev=None):
            estado_cofre["itens"].pop(i)
            visiveis_cofre.clear()
            gravar_cofre()
            desenhar_cofre()
            page.pop_dialog()
            aviso("Item removido.")

        def cancelar(ev=None):
            page.pop_dialog()

        nome = estado_cofre["itens"][i]["nome"]
        page.show_dialog(ft.AlertDialog(
            title=ft.Text("Apagar item?"),
            content=ft.Text(f"'{nome}' será removido do cofre."),
            actions=[ft.TextButton(content="Cancelar", on_click=cancelar),
                     ft.TextButton(content="Apagar", on_click=confirmar)],
        ))

    def desenhar_cofre(e=None, animar=False):
        filtro = (campo_busca.value or "").lower().strip()
        itens = estado_cofre["itens"]
        lista_cofre.controls.clear()
        lbl_total_cofre.value = f"{len(itens)} senha(s) guardada(s)"
        achou = False
        for i, item in enumerate(itens):
            if filtro and filtro not in item["nome"].lower():
                continue
            achou = True
            mostrando = i in visiveis_cofre
            lista_cofre.controls.append(cartao(ft.Row([
                ft.CircleAvatar(
                    content=ft.Text(item["nome"][:1].upper(), weight=ft.FontWeight.BOLD),
                    radius=18, bgcolor=ft.Colors.PRIMARY_CONTAINER,
                ),
                ft.Column([
                    ft.Text(item["nome"], weight=ft.FontWeight.BOLD, size=14),
                    ft.Text(item["senha"] if mostrando else "•" * 10, size=12, selectable=True,
                            color=ft.Colors.ON_SURFACE_VARIANT),
                    ft.Text(item.get("data", ""), size=10, color=ft.Colors.ON_SURFACE_VARIANT),
                ], spacing=1, expand=True),
                ft.IconButton(ft.Icons.VISIBILITY_OFF if mostrando else ft.Icons.VISIBILITY,
                              icon_size=20, tooltip="Mostrar/ocultar",
                              on_click=lambda e, i=i: alternar_visivel(i)),
                ft.IconButton(ft.Icons.COPY, icon_size=20, tooltip="Copiar",
                              on_click=lambda e, s=item["senha"]: copiar(s)),
                ft.IconButton(ft.Icons.DELETE, icon_size=20, tooltip="Apagar",
                              icon_color=ft.Colors.RED_300, on_click=lambda e, i=i: apagar_item(i)),
            ], spacing=2), padding=10))
        if not achou:
            lista_cofre.controls.append(
                ft.Text("Nenhuma senha por aqui. Gere uma e toque em 💾.",
                        size=13, color=ft.Colors.ON_SURFACE_VARIANT, text_align=ft.TextAlign.CENTER))
        if animar:
            cascata(lista_cofre.controls)
        else:
            page.update()

    campo_busca.on_change = desenhar_cofre

    painel_aberto = ft.Column([
        ft.Row([
            ft.Text("Cofre aberto 🔓", size=16, weight=ft.FontWeight.BOLD, expand=True),
            ft.IconButton(ft.Icons.BACKUP, tooltip="Copiar backup (criptografado)", on_click=copiar_backup),
            ft.IconButton(ft.Icons.LOCK, tooltip="Bloquear", on_click=bloquear),
        ]),
        ft.Text("Salvo só neste aparelho. Use o ícone de backup para guardar uma cópia criptografada "
                "(cole em um bloco de notas, e-mail ou nuvem).",
                size=11, color=ft.Colors.ON_SURFACE_VARIANT),
        lbl_total_cofre,
        campo_busca,
        lista_cofre,
    ], spacing=10, visible=False)

    def atualizar_painel_cofre(animar=False):
        aberto = estado_cofre["aberto"]
        existe = bool(estado_cofre["blob"])
        painel_criar.visible = not aberto and not existe
        painel_login.visible = not aberto and existe
        painel_aberto.visible = aberto
        if animar:
            alvo = next((pn for pn in (painel_criar, painel_login, painel_aberto) if pn.visible), None)
            if alvo is not None:
                aparecer(alvo, dy=0.04)
                return
        page.update()

    view_cofre = ft.Column([
        titulo_secao(ft.Icons.LOCK, "Cofre"),
        painel_criar, painel_login, painel_aberto,
    ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True, visible=False)

    # =====================================================
    #  ABA 4: FERRAMENTAS (lote, configurações, sobre)
    # =====================================================
    # --- Lote ---
    dd_lote = ft.Dropdown(
        label="Quantidade", value="5", width=130,
        options=[ft.DropdownOption(key=n, text=n) for n in ("5", "10", "20")],
    )
    lista_lote = ft.Column(spacing=2)

    def gerar_lote(e=None):
        lote_atual.clear()
        lista_lote.controls.clear()
        for _ in range(int(dd_lote.value or 5)):
            resultado = gerar_uma()
            if resultado is None:
                aviso("Selecione pelo menos um tipo de caractere na aba Gerar!")
                page.update()
                return
            lote_atual.append(resultado[0])
        contador["geradas"] += len(lote_atual)
        for s in lote_atual:
            lista_lote.controls.append(ft.Row([
                ft.Text(s, size=12, selectable=True, expand=True),
                ft.IconButton(ft.Icons.COPY, icon_size=16, on_click=lambda e, t=s: copiar(t)),
            ]))
        atualizar_estatisticas()
        cascata(lista_lote.controls)

    def copiar_lote(e=None):
        copiar("\n".join(lote_atual), "Lote copiado! 📋")

    # --- Configurações ---
    def mudou_clip(e=None):
        cfg["limpar_clip"] = sw_clip.value
        salvar_config()

    sw_clip = ft.Switch(label="Limpar área de transferência após 30s", value=cfg["limpar_clip"],
                        on_change=mudou_clip)

    bolinhas = ft.Row(spacing=10, wrap=True)

    def escolher_cor(nome):
        cfg["cor"] = nome
        salvar_config()
        aplicar_tema()
        desenhar_bolinhas()
        page.update()

    def desenhar_bolinhas():
        bolinhas.controls.clear()
        for nome, cor in CORES.items():
            selecionada = cfg["cor"] == nome
            bola = ft.Container(
                width=38, height=38, border_radius=19, bgcolor=cor, ink=True,
                border=ft.Border.all(3, ft.Colors.ON_SURFACE) if selecionada else None,
                on_click=lambda e, n=nome: escolher_cor(n),
                tooltip=nome.capitalize(),
                scale=1.15 if selecionada else 1.0,
                animate_scale=ft.Animation(220, ft.AnimationCurve.EASE_OUT_BACK),
            )

            def ao_passar(e, b=bola, sel=selecionada):
                entrou = str(e.data).lower() == "true"
                b.scale = 1.3 if entrou else (1.15 if sel else 1.0)
                page.update()

            bola.on_hover = ao_passar
            bolinhas.controls.append(bola)

    # --- Sobre ---
    lbl_estatisticas = ft.Text("", size=13)

    def atualizar_estatisticas():
        lbl_estatisticas.value = f"🎲 Senhas geradas nesta sessão: {contador['geradas']}"

    view_ferramentas = ft.Column([
        titulo_secao(ft.Icons.BUILD, "Ferramentas"),
        cartao(ft.Column([
            ft.Text("Gerar em lote", weight=ft.FontWeight.BOLD),
            ft.Text("Usa as opções que estão na aba Gerar.", size=11, color=ft.Colors.ON_SURFACE_VARIANT),
            ft.Row([
                dd_lote,
                ft.Button(content=ft.Text("Gerar lote"), icon=ft.Icons.LAYERS, on_click=gerar_lote),
            ], spacing=10),
            lista_lote,
            ft.TextButton(content="Copiar todas", icon=ft.Icons.COPY_ALL, on_click=copiar_lote),
        ], spacing=8)),
        cartao(ft.Column([
            ft.Text("Configurações", weight=ft.FontWeight.BOLD),
            sw_clip,
            ft.Text("Cor de destaque", size=13),
            bolinhas,
        ], spacing=10)),
        cartao(ft.Column([
            ft.Text("Sobre", weight=ft.FontWeight.BOLD),
            lbl_estatisticas,
            ft.Text(f"Gerador de Senhas Pro • versão {VERSAO}", size=12,
                    color=ft.Colors.ON_SURFACE_VARIANT),
        ], spacing=6)),
    ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True, visible=False)

    # =====================================================
    #  ABA 5: DICAS
    # =====================================================
    def dica(icone, titulo, texto):
        return cartao(ft.Row([
            ft.Icon(icone, color=ft.Colors.PRIMARY, size=28),
            ft.Column([
                ft.Text(titulo, weight=ft.FontWeight.BOLD, size=14),
                ft.Text(texto, size=12, color=ft.Colors.ON_SURFACE_VARIANT),
            ], spacing=2, expand=True),
        ], spacing=12))

    view_dicas = ft.Column([
        titulo_secao(ft.Icons.LIGHTBULB, "Dicas de segurança"),
        dica(ft.Icons.STRAIGHTEN, "Tamanho importa mais",
             "Uma senha de 16+ caracteres é muito mais forte que uma curta cheia de símbolos."),
        dica(ft.Icons.ABC, "Frases-senha são ótimas",
             "Várias palavras aleatórias (6+ neste app) são fortes e fáceis de lembrar."),
        dica(ft.Icons.COPY_ALL, "Nunca repita senhas",
             "Se um site vazar, os criminosos testam a mesma senha nos outros serviços."),
        dica(ft.Icons.PHONELINK_LOCK, "Ative a verificação em duas etapas",
             "Mesmo se a senha vazar, o invasor precisa do segundo código."),
        dica(ft.Icons.PERSON_OFF, "Evite dados pessoais",
             "Nome, data de nascimento e time do coração são os primeiros chutes de um invasor."),
        dica(ft.Icons.GPP_BAD, "Cheque vazamentos",
             "Na aba Verificar você descobre se uma senha já apareceu em vazamentos públicos."),
        dica(ft.Icons.KEY, "Proteja a senha mestra",
             "Ela abre o cofre inteiro. Faça uma frase longa e não a anote em lugar óbvio."),
        dica(ft.Icons.BACKUP, "Faça backup do cofre",
             "Os dados ficam só neste aparelho. Copie o backup (já criptografado) e guarde em lugar seguro."),
    ], spacing=10, scroll=ft.ScrollMode.AUTO, expand=True, visible=False)

    # =====================================================
    #  NAVEGAÇÃO
    # =====================================================
    views = [view_gerar, view_verificar, view_cofre, view_ferramentas, view_dicas]

    aba = {"i": 0}

    def trocar_aba(e=None):
        novo = nav.selected_index
        direcao = 1 if novo >= aba["i"] else -1     # desliza para o lado certo
        for i, v in enumerate(views):
            v.visible = i == novo
        aba["i"] = novo
        aparecer(views[novo], dx=0.06 * direcao, dy=0.0)

    def ir_para_aba(indice):
        nav.selected_index = indice
        trocar_aba()

    nav = ft.NavigationBar(
        selected_index=0,
        on_change=trocar_aba,
        destinations=[
            ft.NavigationBarDestination(icon=ft.Icons.PASSWORD, label="Gerar"),
            ft.NavigationBarDestination(icon=ft.Icons.VERIFIED_USER, label="Verificar"),
            ft.NavigationBarDestination(icon=ft.Icons.LOCK, label="Cofre"),
            ft.NavigationBarDestination(icon=ft.Icons.BUILD, label="Mais"),
            ft.NavigationBarDestination(icon=ft.Icons.LIGHTBULB, label="Dicas"),
        ],
    )

    def icone_tema():
        if cfg["tema"] == "dark":
            return ft.Icon(ft.Icons.LIGHT_MODE, key="sol", color=ft.Colors.AMBER_400)
        return ft.Icon(ft.Icons.DARK_MODE, key="lua", color=ft.Colors.INDIGO_300)

    troca_icone = ft.AnimatedSwitcher(
        content=icone_tema(), transition=ft.AnimatedSwitcherTransition.ROTATION,
        duration=450, reverse_duration=200,
    )

    def alternar_tema(e=None):
        cfg["tema"] = "light" if cfg["tema"] == "dark" else "dark"
        salvar_config()
        aplicar_tema()
        troca_icone.content = icone_tema()
        page.update()

    btn_tema = ft.Container(
        content=troca_icone, on_click=alternar_tema, ink=True, padding=10, border_radius=22,
        tooltip="Alternar tema claro/escuro",
    )

    # =====================================================
    #  TELA INICIAL + TELA DO APP
    # =====================================================
    def card_destaque(icone, titulo, texto):
        return ft.Container(
            expand=True, padding=14, border_radius=16, bgcolor=ft.Colors.SURFACE_CONTAINER,
            content=ft.Column([
                ft.Icon(icone, color=ft.Colors.PRIMARY, size=28),
                ft.Text(titulo, weight=ft.FontWeight.BOLD, size=14),
                ft.Text(texto, size=11, color=ft.Colors.ON_SURFACE_VARIANT),
            ], spacing=4),
        )

    def entrar_no_app(e=None):
        tela_inicial.visible = False
        aparecer(tela_app, dy=0.05)

    def voltar_ao_inicio(e=None):
        tela_app.visible = False
        aparecer(tela_inicial, dy=0.05)

    icone_hero = ft.Container(
        content=ft.Icon(ft.Icons.SECURITY, size=64, color=ft.Colors.ON_PRIMARY),
        width=110, height=110, border_radius=55, bgcolor=ft.Colors.PRIMARY,
        alignment=ft.Alignment.CENTER,
        scale=1, animate_scale=ft.Animation(1300, ft.AnimationCurve.EASE_IN_OUT),
    )

    hero = ft.Container(
        padding=ft.Padding.symmetric(vertical=28, horizontal=16),
        border_radius=24,
        gradient=ft.LinearGradient(
            begin=ft.Alignment.TOP_LEFT, end=ft.Alignment.BOTTOM_RIGHT,
            colors=[ft.Colors.PRIMARY_CONTAINER, ft.Colors.SURFACE],
        ),
        content=ft.Column([
            icone_hero,
            ft.Text("Gerador de Senhas Pro", size=28, weight=ft.FontWeight.BOLD,
                    text_align=ft.TextAlign.CENTER),
            ft.Text("Crie, teste e guarde senhas fortes.", size=14,
                    color=ft.Colors.ON_SURFACE_VARIANT, text_align=ft.TextAlign.CENTER),
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12),
    )

    linha_cards_1 = ft.Row([
        card_destaque(ft.Icons.SHUFFLE, "3 modos", "Aleatória, frase-senha e PIN"),
        card_destaque(ft.Icons.VERIFIED_USER, "Verificador", "Força e vazamentos"),
    ], spacing=10)
    linha_cards_2 = ft.Row([
        card_destaque(ft.Icons.ENHANCED_ENCRYPTION, "Cofre", "Salvo no aparelho, com senha mestra"),
        card_destaque(ft.Icons.LAYERS, "Lote", "Várias senhas de uma vez"),
    ], spacing=10)
    btn_comecar = ft.Button(
        content=ft.Text("Começar", size=17), icon=ft.Icons.ARROW_FORWARD, on_click=entrar_no_app,
        style=ft.ButtonStyle(padding=ft.Padding.symmetric(vertical=18, horizontal=40)),
    )
    txt_versao = ft.Text(f"versão {VERSAO}", size=11, color=ft.Colors.ON_SURFACE_VARIANT)

    tela_inicial = ft.Column([
        ft.Container(height=10),
        hero,
        linha_cards_1,
        linha_cards_2,
        ft.Container(height=6),
        btn_comecar,
        txt_versao,
    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12,
        scroll=ft.ScrollMode.AUTO, expand=True, visible=True)

    # Itens que entram um por um quando o app abre
    itens_entrada = [hero, linha_cards_1, linha_cards_2, btn_comecar, txt_versao]

    def animar_entrada():
        try:
            time.sleep(0.25)
            for c in itens_entrada:
                c.opacity = 1
                c.offset = ft.Offset(0, 0)
                page.update()
                time.sleep(0.12)
        except Exception:
            pass

    def pulsar_icone():
        """O ícone da tela inicial 'respira' enquanto ela está visível."""
        grande = False
        while True:
            time.sleep(1.4)
            if not tela_inicial.visible:
                continue
            grande = not grande
            icone_hero.scale = 1.08 if grande else 1.0
            try:
                page.update()
            except Exception:
                break

    cabecalho = ft.Row([
        ft.IconButton(ft.Icons.HOME, tooltip="Tela inicial", on_click=voltar_ao_inicio),
        ft.Column([
            ft.Text("Gerador de Senhas", size=18, weight=ft.FontWeight.BOLD),
            ft.Text("Pro", size=11, color=ft.Colors.PRIMARY),
        ], spacing=0, expand=True),
        btn_tema,
    ])

    tela_app = ft.Column(
        [cabecalho, ft.Column(views, expand=True), nav],
        expand=True, visible=False,
    )

    # Liga as animações dos blocos principais
    for bloco in views + [painel_aleatoria, painel_frase, painel_pin,
                          painel_criar, painel_login, painel_aberto, tela_app, tela_inicial]:
        preparar_animacao(bloco)

    # A tela inicial começa invisível e vai surgindo item por item
    for c in itens_entrada:
        preparar_animacao(c)
        c.opacity = 0
        c.offset = ft.Offset(0, 0.15)

    page.add(ft.SafeArea(
        content=ft.Column([tela_inicial, tela_app], expand=True,
                          horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        expand=True,
    ))

    # Preparação inicial
    desenhar_bolinhas()
    desenhar_historico()
    desenhar_senha()
    atualizar_estatisticas()
    atualizar_painel_cofre()
    gerar(animar=False)

    threading.Thread(target=animar_entrada, daemon=True).start()
    threading.Thread(target=pulsar_icone, daemon=True).start()


ft.run(main)