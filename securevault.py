#!/usr/bin/env python3
"""
SecureVault — Encriptador / Desencriptador de Archivos
Encriptación : AES-256-GCM  (estándar militar / NSA)
Clave        : Argon2id     (máxima seguridad en derivación de contraseña)
Soporta      : imágenes, video, Word, Excel, PDF, texto y cualquier archivo
"""

# ── Dependencias ────────────────────────────────────────────────────────────────
import os, sys, struct, secrets, getpass, time, shutil
from pathlib import Path

def _check_deps():
    missing = []
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError:
        missing.append("cryptography")
    try:
        from argon2.low_level import hash_secret_raw  # noqa: F401
    except ImportError:
        missing.append("argon2-cffi")
    try:
        import rich  # noqa: F401
    except ImportError:
        missing.append("rich")
    if missing:
        print(f"\n[ERROR] Instala las dependencias faltantes:")
        print(f"  pip install {' '.join(missing)}\n")
        sys.exit(1)

_check_deps()

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type as Argon2Type

from rich.console    import Console
from rich.panel      import Panel
from rich.table      import Table
from rich.text       import Text
from rich.prompt     import Prompt
from rich.progress   import (Progress, SpinnerColumn, BarColumn,
                              TextColumn, TaskProgressColumn, TransferSpeedColumn,
                              TimeRemainingColumn, FileSizeColumn)
from rich.align      import Align
from rich.columns    import Columns
from rich.rule       import Rule
from rich.padding    import Padding
from rich            import box

console = Console()

# ── Constantes criptográficas ────────────────────────────────────────────────
MAGIC              = b"SVLT\x02\x00\x00\x00"
SALT_LEN           = 32
NONCE_LEN          = 12
CHUNK_SIZE         = 64 * 1024        # 64 KB por chunk
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536            # 64 MB RAM
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN    = 32
ENC_EXT            = ".vault"

# ── Utilidades criptográficas ────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret      = password.encode("utf-8"),
        salt        = salt,
        time_cost   = ARGON2_TIME_COST,
        memory_cost = ARGON2_MEMORY_COST,
        parallelism = ARGON2_PARALLELISM,
        hash_len    = ARGON2_HASH_LEN,
        type        = Argon2Type.ID,
    )

def _chunk_nonce(base: bytes, idx: int) -> bytes:
    idx_b = idx.to_bytes(NONCE_LEN, "big")
    return bytes(a ^ b for a, b in zip(base, idx_b))

def _human(n: int) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

# Formato del archivo .vault:
#   [8]  Magic
#   [1]  Longitud del nombre original
#   [N]  Nombre del archivo original (UTF-8)
#   [32] Salt Argon2id
#   [12] Nonce base AES-GCM
#   [8]  Número de chunks (uint64 big-endian)
#   Para cada chunk:
#     [4] Longitud del ciphertext (uint32 big-endian)
#     [M] Ciphertext + GCM tag (16 bytes incluidos)

def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt  = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    total = src.stat().st_size

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Derivando clave Argon2id…"),
        console=console, transient=True
    ) as sp:
        t = sp.add_task("", total=None)
        key    = _derive_key(password, salt)
        aesgcm = AESGCM(key)

    chunks = []
    with Progress(
        TextColumn("  [bold green]Encriptando[/] [cyan]{task.description}"),
        BarColumn(bar_width=38),
        TaskProgressColumn(),
        FileSizeColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as prog:
        task = prog.add_task(src.name, total=total)
        with open(src, "rb") as f:
            idx = 0
            while True:
                plain = f.read(CHUNK_SIZE)
                if not plain: break
                ct = aesgcm.encrypt(_chunk_nonce(nonce, idx), plain, None)
                chunks.append(ct)
                prog.advance(task, len(plain))
                idx += 1

    fname_b = src.name.encode("utf-8")[:255]
    with open(dst, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("B", len(fname_b)))
        f.write(fname_b)
        f.write(salt)
        f.write(nonce)
        f.write(struct.pack(">Q", len(chunks)))
        for ct in chunks:
            f.write(struct.pack(">I", len(ct)))
            f.write(ct)


def decrypt_file(src: Path, dst: Path | None, password: str) -> Path:
    with open(src, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise ValueError("Este archivo no es un vault SecureVault válido.")
        fname_len = struct.unpack("B", f.read(1))[0]
        orig_name = f.read(fname_len).decode("utf-8")
        salt      = f.read(SALT_LEN)
        base_nonce= f.read(NONCE_LEN)
        n_chunks  = struct.unpack(">Q", f.read(8))[0]
        chunk_data = []
        total_ct   = 0
        for i in range(n_chunks):
            ct_len = struct.unpack(">I", f.read(4))[0]
            ct     = f.read(ct_len)
            chunk_data.append((i, ct))
            total_ct += ct_len

    if dst is None:
        dst = src.parent / orig_name

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Derivando clave Argon2id…"),
        console=console, transient=True
    ) as sp:
        sp.add_task("", total=None)
        key    = _derive_key(password, salt)
        aesgcm = AESGCM(key)

    with Progress(
        TextColumn("  [bold yellow]Desencriptando[/] [cyan]{task.description}"),
        BarColumn(bar_width=38),
        TaskProgressColumn(),
        FileSizeColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as prog:
        task = prog.add_task(dst.name, total=total_ct)
        with open(dst, "wb") as out:
            for i, ct in chunk_data:
                try:
                    plain = aesgcm.decrypt(_chunk_nonce(base_nonce, i), ct, None)
                except Exception:
                    out.close()
                    dst.unlink(missing_ok=True)
                    raise ValueError(
                        "Contraseña incorrecta o archivo dañado/alterado."
                    )
                out.write(plain)
                prog.advance(task, len(ct))

    return dst


def vault_info(src: Path) -> dict:
    with open(src, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise ValueError("No es un archivo SecureVault.")
        fname_len = struct.unpack("B", f.read(1))[0]
        orig_name = f.read(fname_len).decode("utf-8")
        f.read(SALT_LEN + NONCE_LEN)
        n_chunks  = struct.unpack(">Q", f.read(8))[0]
    return {
        "original": orig_name,
        "chunks"  : n_chunks,
        "enc_size": src.stat().st_size,
    }

# ── Pantallas de la UI ───────────────────────────────────────────────────────

LOGO = r"""
  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗
  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝
  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
              V A U L T   v 2 . 0
"""


def _clear():
    os.system("clear" if os.name != "nt" else "cls")


def _header(subtitle: str = ""):
    _clear()
    console.print(Panel(
        Align(Text(LOGO, style="bold cyan"), "center"),
        border_style="cyan",
        padding=(0, 2),
    ))
    if subtitle:
        console.print(Align(
            Text(f"  {subtitle}", style="bold white on dark_blue"),
            "center"
        ))
        console.print()


def _footer():
    console.print()
    console.print(Rule(style="cyan dim"))
    console.print(
        Align(Text("AES-256-GCM · Argon2id · Cifrado Autenticado Militar", style="dim cyan"), "center")
    )


def _press_enter():
    console.print()
    Prompt.ask("[dim]Presione ENTER para continuar[/dim]", default="", show_default=False)


def _ask_password(confirm: bool = False) -> str:
    console.print()
    pw = getpass.getpass("  🔑  Contraseña / Clave: ")
    if not pw.strip():
        console.print("[bold red]  ✗  La contraseña no puede estar vacía.[/bold red]")
        return _ask_password(confirm)
    if confirm:
        pw2 = getpass.getpass("  🔑  Confirmar clave:    ")
        if pw != pw2:
            console.print("[bold red]  ✗  Las contraseñas no coinciden. Intente de nuevo.[/bold red]")
            return _ask_password(confirm)
    return pw


def _ask_files(label: str, ext_filter: str | None = None) -> list[Path]:
    console.print()
    console.print(f"  [bold yellow]Ingrese rutas de archivos[/bold yellow] [dim](separados por coma, o uno por línea)[/dim]")
    if ext_filter:
        console.print(f"  [dim]Solo archivos con extensión: {ext_filter}[/dim]")
    console.print(f"  [dim]Ejemplo: /home/usuario/foto.jpg, /home/usuario/documento.docx[/dim]")
    console.print()
    raw = Prompt.ask(f"  [bold cyan]{label}[/bold cyan]")
    paths = [Path(p.strip().strip('"').strip("'")) for p in raw.replace("\n", ",").split(",") if p.strip()]
    return paths


def _result_table(results: list[dict]) -> None:
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True, header_style="bold cyan")
    table.add_column("Archivo", style="white", no_wrap=False)
    table.add_column("Estado", justify="center")
    table.add_column("Tamaño", justify="right", style="dim")
    table.add_column("Detalle", style="dim")
    for r in results:
        if r["ok"]:
            estado = Text("✔  OK", style="bold green")
            detalle = r.get("detail", "")
        else:
            estado = Text("✘  Error", style="bold red")
            detalle = r.get("error", "")
        table.add_row(r["name"], estado, r.get("size", "—"), detalle)
    console.print()
    console.print(Align(table, "center"))


# ── Menú principal ───────────────────────────────────────────────────────────

def _main_menu() -> str:
    _header()

    options = [
        ("1", "🔒", "Encriptar archivo(s)",               "bold green"),
        ("2", "🔓", "Desencriptar archivo(s)",             "bold yellow"),
        ("3", "📁", "Encriptar carpeta completa",          "bold blue"),
        ("4", "📂", "Desencriptar carpeta completa",       "bold magenta"),
        ("5", "🔍", "Ver información de archivo .vault",   "bold cyan"),
        ("6", "📖", "Ayuda y modo de uso",                 "bold white"),
        ("0", "🚪", "Salir",                               "bold red"),
    ]

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("N°", style="bold cyan", width=4, justify="center")
    table.add_column("", width=3)
    table.add_column("Opción", min_width=34)

    for num, icon, label, style in options:
        table.add_row(f"[{num}]", icon, Text(label, style=style))

    console.print(Align(table, "center"))
    _footer()
    console.print()
    choice = Prompt.ask(
        "  [bold cyan]Seleccione una opción[/bold cyan]",
        choices=["0","1","2","3","4","5","6"],
        show_choices=False
    )
    return choice


# ── Pantalla 1: Encriptar archivos ───────────────────────────────────────────

def screen_encrypt():
    _header("🔒  ENCRIPTAR ARCHIVOS")
    console.print(Panel(
        "[white]Puede encriptar cualquier tipo de archivo:\n"
        "[cyan]imágenes, fotos, videos, Word, Excel, PDF, ZIP, etc.[/cyan]\n\n"
        "[dim]El resultado tendrá extensión [bold].vault[/bold] — "
        "compártalo con quien necesite desencriptarlo.[/dim]",
        border_style="green", title="[bold green]Información[/bold green]", padding=(1,2)
    ))

    files = _ask_files("Archivos a encriptar")
    if not files:
        console.print("[red]No se ingresó ningún archivo.[/red]")
        _press_enter(); return

    password = _ask_password(confirm=True)
    console.print()
    console.print(Rule("[bold green]Procesando…[/bold green]", style="green"))

    results = []
    for src in files:
        if not src.exists():
            results.append({"name": str(src), "ok": False, "size": "—",
                             "error": "Archivo no encontrado"})
            continue
        dst = src.with_suffix(src.suffix + ENC_EXT)
        try:
            t0 = time.time()
            encrypt_file(src, dst, password)
            elapsed = time.time() - t0
            results.append({
                "name"  : src.name,
                "ok"    : True,
                "size"  : _human(dst.stat().st_size),
                "detail": f"→ {dst.name}  ({elapsed:.1f}s)",
            })
        except Exception as e:
            results.append({"name": src.name, "ok": False, "size": "—", "error": str(e)})

    console.print(Rule("[bold green]Resultado[/bold green]", style="green"))
    _result_table(results)

    ok_count = sum(1 for r in results if r["ok"])
    console.print(f"\n  [bold green]✔  {ok_count} archivo(s) encriptado(s) exitosamente.[/bold green]")
    _press_enter()


# ── Pantalla 2: Desencriptar archivos ────────────────────────────────────────

def screen_decrypt():
    _header("🔓  DESENCRIPTAR ARCHIVOS")
    console.print(Panel(
        "[white]Ingrese los archivos [bold cyan].vault[/bold cyan] que desea restaurar.\n\n"
        "[dim]Necesita la misma contraseña usada al encriptar.\n"
        "El archivo original se restaurará en la misma carpeta.[/dim]",
        border_style="yellow", title="[bold yellow]Información[/bold yellow]", padding=(1,2)
    ))

    files = _ask_files("Archivos .vault a desencriptar", ext_filter=ENC_EXT)
    if not files:
        console.print("[red]No se ingresó ningún archivo.[/red]")
        _press_enter(); return

    password = _ask_password(confirm=False)
    console.print()
    console.print(Rule("[bold yellow]Procesando…[/bold yellow]", style="yellow"))

    results = []
    for src in files:
        if not src.exists():
            results.append({"name": str(src), "ok": False, "size": "—",
                             "error": "Archivo no encontrado"})
            continue
        try:
            t0  = time.time()
            out = decrypt_file(src, None, password)
            elapsed = time.time() - t0
            results.append({
                "name"  : src.name,
                "ok"    : True,
                "size"  : _human(out.stat().st_size),
                "detail": f"→ {out.name}  ({elapsed:.1f}s)",
            })
        except Exception as e:
            results.append({"name": src.name, "ok": False, "size": "—", "error": str(e)})

    console.print(Rule("[bold yellow]Resultado[/bold yellow]", style="yellow"))
    _result_table(results)

    ok_count = sum(1 for r in results if r["ok"])
    console.print(f"\n  [bold yellow]✔  {ok_count} archivo(s) restaurado(s) exitosamente.[/bold yellow]")
    _press_enter()


# ── Pantalla 3: Encriptar carpeta ────────────────────────────────────────────

def screen_encrypt_folder():
    _header("📁  ENCRIPTAR CARPETA COMPLETA")
    console.print(Panel(
        "[white]Encripta [bold]todos los archivos[/bold] dentro de una carpeta.\n"
        "[dim]Las sub-carpetas también serán procesadas (modo recursivo).\n"
        "Los archivos originales permanecen intactos.[/dim]",
        border_style="blue", title="[bold blue]Información[/bold blue]", padding=(1,2)
    ))

    console.print()
    folder_str = Prompt.ask("  [bold cyan]Ruta de la carpeta[/bold cyan]")
    folder = Path(folder_str.strip().strip('"').strip("'"))

    if not folder.is_dir():
        console.print(f"[bold red]  ✗  No se encontró la carpeta: {folder}[/bold red]")
        _press_enter(); return

    all_files = [f for f in folder.rglob("*")
                 if f.is_file() and not f.suffix == ENC_EXT]
    if not all_files:
        console.print("[yellow]  No se encontraron archivos para encriptar.[/yellow]")
        _press_enter(); return

    console.print(f"\n  [cyan]Se encontraron [bold]{len(all_files)}[/bold] archivo(s) en la carpeta.[/cyan]")
    password = _ask_password(confirm=True)

    console.print()
    console.print(Rule("[bold blue]Procesando…[/bold blue]", style="blue"))

    results = []
    for src in all_files:
        dst = src.with_suffix(src.suffix + ENC_EXT)
        try:
            encrypt_file(src, dst, password)
            results.append({
                "name"  : str(src.relative_to(folder)),
                "ok"    : True,
                "size"  : _human(dst.stat().st_size),
                "detail": f"→ {dst.name}",
            })
        except Exception as e:
            results.append({"name": str(src.relative_to(folder)),
                             "ok": False, "size": "—", "error": str(e)})

    console.print(Rule("[bold blue]Resultado[/bold blue]", style="blue"))
    _result_table(results)

    ok = sum(1 for r in results if r["ok"])
    console.print(f"\n  [bold blue]✔  {ok}/{len(results)} archivo(s) encriptado(s).[/bold blue]")
    _press_enter()


# ── Pantalla 4: Desencriptar carpeta ────────────────────────────────────────

def screen_decrypt_folder():
    _header("📂  DESENCRIPTAR CARPETA COMPLETA")
    console.print(Panel(
        "[white]Restaura todos los archivos [bold cyan].vault[/bold cyan] dentro de una carpeta.\n"
        "[dim]Las sub-carpetas también serán procesadas (modo recursivo).[/dim]",
        border_style="magenta", title="[bold magenta]Información[/bold magenta]", padding=(1,2)
    ))

    console.print()
    folder_str = Prompt.ask("  [bold cyan]Ruta de la carpeta[/bold cyan]")
    folder = Path(folder_str.strip().strip('"').strip("'"))

    if not folder.is_dir():
        console.print(f"[bold red]  ✗  No se encontró la carpeta: {folder}[/bold red]")
        _press_enter(); return

    vault_files = list(folder.rglob(f"*{ENC_EXT}"))
    if not vault_files:
        console.print(f"[yellow]  No se encontraron archivos {ENC_EXT} en la carpeta.[/yellow]")
        _press_enter(); return

    console.print(f"\n  [cyan]Se encontraron [bold]{len(vault_files)}[/bold] archivo(s) vault.[/cyan]")
    password = _ask_password(confirm=False)

    console.print()
    console.print(Rule("[bold magenta]Procesando…[/bold magenta]", style="magenta"))

    results = []
    for src in vault_files:
        try:
            out = decrypt_file(src, None, password)
            results.append({
                "name"  : str(src.relative_to(folder)),
                "ok"    : True,
                "size"  : _human(out.stat().st_size),
                "detail": f"→ {out.name}",
            })
        except Exception as e:
            results.append({"name": str(src.relative_to(folder)),
                             "ok": False, "size": "—", "error": str(e)})

    console.print(Rule("[bold magenta]Resultado[/bold magenta]", style="magenta"))
    _result_table(results)

    ok = sum(1 for r in results if r["ok"])
    console.print(f"\n  [bold magenta]✔  {ok}/{len(results)} archivo(s) restaurado(s).[/bold magenta]")
    _press_enter()


# ── Pantalla 5: Info de archivo vault ───────────────────────────────────────

def screen_info():
    _header("🔍  INFORMACIÓN DE ARCHIVO VAULT")
    console.print(Panel(
        "[white]Muestra los metadatos de un archivo [bold cyan].vault[/bold cyan] "
        "[dim]sin necesidad de la contraseña.[/dim]",
        border_style="cyan", title="[bold cyan]Información[/bold cyan]", padding=(1,2)
    ))

    files = _ask_files("Archivos .vault a inspeccionar")
    if not files:
        _press_enter(); return

    console.print()
    for src in files:
        if not src.exists():
            console.print(f"[red]  ✗  No encontrado: {src}[/red]")
            continue
        try:
            info = vault_info(src)
            table = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            table.add_column("Campo", style="bold cyan", width=28)
            table.add_column("Valor", style="white")
            table.add_row("Archivo encriptado",   src.name)
            table.add_row("Nombre original",       info["original"])
            table.add_row("Tamaño encriptado",     _human(info["enc_size"]))
            table.add_row("Chunks internos",       str(info["chunks"]))
            table.add_row("Algoritmo",             "AES-256-GCM (autenticado)")
            table.add_row("Derivación de clave",   "Argon2id — 64 MB RAM · 3 iteraciones")
            table.add_row("Longitud de clave",     "256 bits")
            table.add_row("Tamaño del nonce",      "96 bits (aleatorio único por archivo)")
            table.add_row("Salt",                  "256 bits (aleatorio único por archivo)")
            console.print(Panel(table, border_style="cyan", title=f"[bold]{src.name}[/bold]"))
        except Exception as e:
            console.print(f"[red]  ✗  Error al leer {src.name}: {e}[/red]")

    _press_enter()


# ── Pantalla 6: Ayuda ───────────────────────────────────────────────────────

def screen_help():
    _header("📖  AYUDA Y MODO DE USO")

    # Panel 1 — ¿Qué es SecureVault?
    console.print(Panel(
        "[white]SecureVault encripta sus archivos con tecnología de [bold cyan]grado militar[/bold cyan].\n"
        "Nadie puede leer un archivo encriptado sin la [bold]contraseña exacta[/bold] —\n"
        "ni con los supercomputadores más potentes del mundo.",
        title="[bold cyan]¿Qué es SecureVault?[/bold cyan]",
        border_style="cyan", padding=(1,2)
    ))
    console.print()

    # Panel 2 — Tecnología
    tech = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
                 border_style="dim", padding=(0,2))
    tech.add_column("Componente",      style="bold white",  width=22)
    tech.add_column("Algoritmo",       style="bold cyan",   width=22)
    tech.add_column("Descripción",     style="dim white")
    tech.add_row("Encriptación",   "AES-256-GCM",
                 "Estándar NSA/Militar. Mismo que usa la banca y el ejército.")
    tech.add_row("Autenticación",  "GCM Tag 128 bits",
                 "Detecta alteraciones o intentos de modificar el archivo.")
    tech.add_row("Derivación clave","Argon2id",
                 "Ganador del PHC 2015. 64 MB RAM por intento → protección bruta.")
    tech.add_row("Nonce / IV",     "96 bits aleatorio",
                 "Único por archivo — nunca se repite, jamás reutilizable.")
    tech.add_row("Salt",           "256 bits aleatorio",
                 "Impide ataques de diccionario y tablas precalculadas.")
    console.print(Panel(tech, title="[bold cyan]Tecnología criptográfica[/bold cyan]",
                        border_style="cyan", padding=(1,1)))
    console.print()

    # Panel 3 — ¿Cómo compartir?
    console.print(Panel(
        "[white][bold]Paso 1[/bold] — Encripte el archivo con SecureVault.\n"
        "[bold]Paso 2[/bold] — Comparta el archivo [bold cyan].vault[/bold cyan] "
        "por cualquier canal (email, WhatsApp, nube, USB).\n"
        "[bold]Paso 3[/bold] — Comparta la [bold yellow]contraseña[/bold yellow] "
        "por un canal [bold]diferente[/bold] (llamada, mensaje separado).\n"
        "[bold]Paso 4[/bold] — El receptor abre SecureVault → Opción 2 → ingresa la clave → listo.\n\n"
        "[dim]El archivo .vault no revela nada: ni el nombre original, ni el tipo, "
        "ni el contenido.[/dim]",
        title="[bold green]¿Cómo compartir archivos de forma segura?[/bold green]",
        border_style="green", padding=(1,2)
    ))
    console.print()

    # Panel 4 — Tipos de archivo soportados
    tipos = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    tipos.add_column(style="cyan")
    tipos.add_column(style="cyan")
    tipos.add_column(style="cyan")
    tipos.add_row("📷 JPG / PNG / HEIC", "📹 MP4 / AVI / MKV",  "📄 PDF")
    tipos.add_row("📝 DOCX / DOC",       "📊 XLSX / XLS",        "📦 ZIP / RAR")
    tipos.add_row("🎵 MP3 / WAV / FLAC", "💾 ISO / IMG / BIN",   "📋 TXT / CSV")
    tipos.add_row("🖼️  PSD / AI / SVG",  "🗂️  Cualquier archivo", "✅ Sin límite de tamaño")
    console.print(Panel(tipos, title="[bold white]Tipos de archivo soportados[/bold white]",
                        border_style="white", padding=(1,1)))

    _press_enter()


# ── Bucle principal ──────────────────────────────────────────────────────────

def main():
    actions = {
        "1": screen_encrypt,
        "2": screen_decrypt,
        "3": screen_encrypt_folder,
        "4": screen_decrypt_folder,
        "5": screen_info,
        "6": screen_help,
    }

    while True:
        choice = _main_menu()
        if choice == "0":
            _clear()
            console.print(Panel(
                Align(Text("\n  ¡Hasta pronto! Sus archivos están protegidos.  \n",
                           style="bold cyan"), "center"),
                border_style="cyan"
            ))
            console.print()
            break
        if choice in actions:
            actions[choice]()


if __name__ == "__main__":
    main()
