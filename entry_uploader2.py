import os
import sys
import json
import shutil
import hashlib
import argparse
import time
import signal
import threading
import logging
import subprocess
import getpass
import base64
import ctypes
import uuid
import platform
import hashlib
import urllib.request
import urllib.error
import urllib.parse  # agregado: se usa urllib.parse para normalizar/escapar rutas
try:
    import tkinter as _tk_check  # solo para saber si está disponible
except Exception:
    _tk_check = None

def load_config(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def sha256_file(path, block_size=65536):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            h.update(block)
    return h.hexdigest()

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def next_versioned_name(versions_dir, rel_dir, filename):
    """
    Devuelve una ruta en versions_dir/rel_dir con sufijo #N antes de la extensión,
    donde N es el siguiente entero disponible (1,2,...).
    """
    base, ext = os.path.splitext(filename)
    target_dir = os.path.join(versions_dir, rel_dir) if rel_dir not in ('', '.') else versions_dir
    ensure_dir(target_dir)

    max_n = 0
    for existing in os.listdir(target_dir):
        existing_path = os.path.join(target_dir, existing)
        if not os.path.isfile(existing_path):
            continue
        if existing.startswith(base + '#') and existing.endswith(ext):
            mid = existing[len(base)+1:len(existing)-len(ext)]
            if mid.isdigit():
                try:
                    n = int(mid)
                    if n > max_n:
                        max_n = n
                except ValueError:
                    pass
    return os.path.join(target_dir, f"{base}#{max_n+1}{ext}")

def process_file(src_path, src_root, out_root, versions_base):
    rel_path = os.path.relpath(src_path, src_root)
    rel_dir = os.path.dirname(rel_path)
    dest_path = os.path.join(out_root, rel_path)
    dest_dir = os.path.dirname(dest_path)
    ensure_dir(dest_dir)

    if os.path.exists(dest_path) and os.path.isfile(dest_path):
        try:
            if sha256_file(src_path) == sha256_file(dest_path):
                print(f"SKIP (idéntico): {rel_path}")
                return
        except Exception as e:
            print(f"ERROR calculando hash: {e}", file=sys.stderr)
            # si falla el hashing, tratamos como diferente y seguimos

        # mover la versión antigua a _old_versions
        try:
            versioned = next_versioned_name(versions_base, rel_dir, os.path.basename(dest_path))
            ensure_dir(os.path.dirname(versioned))
            shutil.move(dest_path, versioned)
            print(f"MOVED old -> {_rel_to_base(versioned, versions_base)}")
        except Exception as e:
            print(f"ERROR moviendo versión antigua {dest_path} -> {versioned}: {e}", file=sys.stderr)
            # intentar reemplazo atómico como fallback
            try:
                os.replace(dest_path, versioned)
                print(f"MOVED old (replace) -> {_rel_to_base(versioned, versions_base)}")
            except Exception as e2:
                print(f"FATAL: no se pudo mover la versión antigua: {e2}", file=sys.stderr)
                return

    # copiar nueva versión
    try:
        shutil.copy2(src_path, dest_path)
        print(f"COPIED: {rel_path}")
    except Exception as e:
        print(f"ERROR copiando {src_path} -> {dest_path}: {e}", file=sys.stderr)

def _rel_to_base(path, base):
    try:
        return os.path.relpath(path, base)
    except Exception:
        return path

# Event para detener el bucle de vigilancia de forma limpia
_stop_event = threading.Event()

def _signal_handler(signum, frame):
	_stop_event.set()

def _is_unc_path(path):
    p = path.replace('/', '\\')
    return p.startswith('\\\\')

def _unc_share_root(path):
    p = path.replace('/', '\\')
    if not p.startswith('\\\\'):
        return None
    parts = p.split('\\')
    # parts ejemplo: ['', '', 'server', 'share', 'sub', '...']
    if len(parts) >= 4 and parts[2] and parts[3]:
        return f"\\\\{parts[2]}\\{parts[3]}"
    return None

def _prompt_credentials(share, prefill_user=None):
    """Intentar pedir credenciales con un popup; si falla, caer a entrada por consola."""
    try:
        import tkinter as tk
        from tkinter import simpledialog, messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Autenticación requerida", f"Introduzca credenciales para {share}")
        user = simpledialog.askstring("Usuario", "Usuario:", initialvalue=prefill_user, parent=root)
        pwd = simpledialog.askstring("Contraseña", "Contraseña:", show='*', parent=root)
        root.destroy()
        if user is None:
            return None, None
        return user, pwd
    except Exception:
        # fallback consola
        try:
            if prefill_user:
                user = prefill_user
            else:
                user = input(f"Usuario para {share}: ")
            pwd = getpass.getpass(f"Contraseña para {user}@{share}: ")
            return user, pwd
        except Exception:
            return None, None

def _attempt_net_use(share, user, password):
    """Intenta mapear el recurso UNC usando 'net use' (Windows). Devuelve True si ok."""
    try:
        # net use \\server\share password /user:domain\user
        cmd = ['net', 'use', share, password, f'/user:{user}']
        # Ejecutar sin mostrar salida en consola
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, check=False)
        return res.returncode == 0
    except Exception:
        return False

def _dpapi_protect(data_bytes):
    # Windows DPAPI: CryptProtectData
    try:
        CryptProtectData = ctypes.windll.crypt32.CryptProtectData
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]
        in_blob = DATA_BLOB(len(data_bytes), ctypes.create_string_buffer(data_bytes))
        out_blob = DATA_BLOB()
        if CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            buf = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            return buf
    except Exception:
        pass
    return None

def _dpapi_unprotect(b64bytes):
    try:
        CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]
        raw = base64.b64decode(b64bytes)
        in_blob = DATA_BLOB(len(raw), ctypes.create_string_buffer(raw))
        out_blob = DATA_BLOB()
        if CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            buf = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            return buf
    except Exception:
        pass
    return None

def _fallback_xor_transform(data_bytes):
    # clave derivada de la máquina (no perfecta, pero evita exposición directa)
    node = platform.node() or str(uuid.getnode())
    key = hashlib.sha256(node.encode('utf-8')).digest()
    res = bytearray()
    for i, b in enumerate(data_bytes):
        res.append(b ^ key[i % len(key)])
    return bytes(res)

def encrypt_string(s):
    b = s.encode('utf-8')
    if os.name == 'nt':
        protected = _dpapi_protect(b)
        if protected is not None:
            return {'enc': 'dpapi', 'value': base64.b64encode(protected).decode('ascii')}
    # fallback
    transformed = _fallback_xor_transform(b)
    return {'enc': 'xor', 'value': base64.b64encode(transformed).decode('ascii')}

def decrypt_string(obj):
    # acepta tanto formato antiguo (texto) como nuevo (dict)
    if not obj:
        return None
    if isinstance(obj, dict) and 'enc' in obj and 'value' in obj:
        method = obj.get('enc')
        val = obj.get('value')
        try:
            if method == 'dpapi' and os.name == 'nt':
                dec = _dpapi_unprotect(val)
                if dec is not None:
                    return dec.decode('utf-8')
            elif method == 'xor':
                raw = base64.b64decode(val)
                dec = _fallback_xor_transform(raw)  # XOR is symmetric
                return dec.decode('utf-8')
        except Exception:
            return None
    # si no es dict, puede ser texto en claro (migración)
    return obj

def _ensure_unc_access(path, cfg, config_path):
    """
    Si path es UNC y no es accesible, intenta conectar usando credenciales guardadas
    o pidiéndolas al usuario; guarda en config.json si la autenticación tiene éxito.
    """
    if not _is_unc_path(path):
        return True

    share = _unc_share_root(path)
    if not share:
        return False

    # si ya accesible, nada que hacer
    if os.path.isdir(path):
        return True

    # buscar credenciales en config (pueden estar cifradas)
    creds = cfg.get('credentials', {})
    entry = creds.get(share)
    if entry:
        # des-encriptar si corresponde
        user = decrypt_string(entry.get('user'))
        passwd = decrypt_string(entry.get('password'))
        if user and passwd and os.name == 'nt':
            if _attempt_net_use(share, user, passwd):
                logging.info("Conectado a %s usando credenciales guardadas.", share)
                return True
            else:
                logging.info("Credenciales guardadas para %s inválidas.", share)

    # pedir credenciales al usuario (prefill con usuario descifrado si existe)
    prefill = None
    if entry:
        prefill = decrypt_string(entry.get('user'))
    user, pwd = _prompt_credentials(share, prefill_user=prefill)
    if not user:
        logging.warning("No se proporcionaron credenciales para %s.", share)
        return False

    ok = False
    if os.name == 'nt':
        ok = _attempt_net_use(share, user, pwd)
    else:
        # No hay mecanismo portable incluido; intentar montaje no implementado.
        logging.warning("Autenticación UNC automática sólo soportada en Windows ('net use').")
        ok = False

    if ok:
        # guardar en config.json cifradas
        cfg.setdefault('credentials', {})[share] = {
            'user': encrypt_string(user),
            'password': encrypt_string(pwd)
        }
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            logging.info("Credenciales para %s guardadas en config (cifradas).", share)
        except Exception as e:
            logging.warning("No se pudo guardar credenciales en config.json: %s", e)
        return True
    else:
        logging.error("No se pudo conectar a %s con las credenciales proporcionadas.", share)
        return False

def _get_github_credentials(cfg, config_path):
    """
    Recupera repo (owner/repo) y token de cfg.
    Si token no está, pide al usuario y guarda cifrado en config.json bajo cfg['github']['token'].
    Retorna (repo_fullname_or_None, token_or_None).
    Ahora: no exige que exista 'repo' para obtener/solicitar el token; devuelve token independiente.
    """
    repo = cfg.get('github_repo') or (cfg.get('github') or {}).get('repo')
    token_obj = cfg.get('github_token') or (cfg.get('github') or {}).get('token')
    token = None
    if token_obj:
        token = decrypt_string(token_obj)

    # Si falta token, pedirlo (aunque no haya repo configurado)
    if not token:
        prompt_target = repo or "GitHub"
        try:
            token_input = getpass.getpass(f"Token de GitHub para subir a {prompt_target} (se guardará cifrado en config): ")
        except Exception:
            token_input = None
        if token_input:
            token = token_input
            # Guardar token cifrado en config (no tocar el repo aquí salvo si ya existe)
            try:
                cfg.setdefault('github', {})['token'] = encrypt_string(token)
                if repo:
                    cfg.setdefault('github', {})['repo'] = repo
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
                logging.info("Token de GitHub guardado cifrado en config.json.")
            except Exception as e:
                logging.warning("No se pudo guardar token en config.json: %s", e)

    # Normalizar/validar repo si está presente (si no hay repo, devolvemos (None, token))
    if repo:
        try:
            repo = repo.strip()
            if repo.lower().startswith('http://') or repo.lower().startswith('https://'):
                parsed = urllib.parse.urlparse(repo)
                repo = (parsed.path or repo)
            repo = repo.strip().lstrip('/').rstrip('/')
            if repo.lower().startswith('github.com/'):
                parts = repo.split('/', 1)
                if len(parts) > 1:
                    repo = parts[1]
            if '/' not in repo or repo.count('/') != 1:
                logging.debug("Formato de 'github' en config inválido: '%s'. Debe ser 'owner/repo'.", repo)
                repo = None
        except Exception:
            repo = None

    return repo, token

def _github_api_request(method, url, token, data=None):
    """
    Wrapper mínimo para llamadas a la API de GitHub. data debe ser bytes (JSON).
    Devuelve (status, parsed_json or raw_text).
    """
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'EntryUploader/1.0'
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            try:
                return resp.getcode(), json.loads(raw.decode('utf-8'))
            except Exception:
                return resp.getcode(), raw.decode('utf-8')
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8')
            return e.code, json.loads(body) if body else {'message': 'error'}
        except Exception:
            return e.code, {'message': str(e)}
    except Exception as e:
        return None, {'message': str(e)}

# nuevo: comprobar existencia del repo en GitHub
def _github_repo_exists(owner_repo, token):
    """
    Devuelve True si owner_repo (owner/repo) existe en GitHub (consulta API).
    """
    if not owner_repo or '/' not in owner_repo:
        return False
    url = f"https://api.github.com/repos/{owner_repo}"
    status, body = _github_api_request('GET', url, token)
    return status == 200

def _upload_file_to_github(repo_full, path_in_repo, file_bytes, token, commit_message):
    """
    Crea o actualiza un archivo en el repo GitHub usando la API de contenidos.
    path_in_repo: ruta dentro del repo (posible con subcarpetas).
    """
    # Asegurar repo sin barras iniciales y en formato owner/repo
    owner_repo = (repo_full or '').strip().lstrip('/').rstrip('/')
    # Si por alguna razón vino como URL completa, intentar extraer la ruta
    if owner_repo.lower().startswith('http://') or owner_repo.lower().startswith('https://'):
        try:
            owner_repo = urllib.parse.urlparse(owner_repo).path.lstrip('/')
        except Exception:
            pass
    if not owner_repo or '/' not in owner_repo:
        return None, {'message': f"repo inválido: {repo_full}"}

    api_url = f"https://api.github.com/repos/{owner_repo}/contents/{urllib.parse.quote(path_in_repo)}"
    # comprobar si existe para obtener sha
    status, body = _github_api_request('GET', api_url, token)
    sha = None
    if status == 200 and isinstance(body, dict) and body.get('sha'):
        sha = body.get('sha')
    content_b64 = base64.b64encode(file_bytes).decode('ascii')
    payload = {
        'message': commit_message,
        'content': content_b64
    }
    if sha:
        payload['sha'] = sha
    data = json.dumps(payload).encode('utf-8')
    status2, body2 = _github_api_request('PUT', api_url, token, data=data)
    return status2, body2

def push_folder_to_github(folder_path, repo_full, token, commit_prefix="Update from EntryUploader"):
    """
    Recorre folder_path y sube cada archivo al repo GitHub en la misma ruta relativa.
    Omite archivos cuyo tamaño o lectura falle. Devuelve resumen (ok, errors).
    """
    # Seguridad: evitar subir espacios amplios o subir la carpeta raíz por error
    if not os.path.isdir(folder_path):
        return False, f"No existe carpeta {folder_path}"
    # Evitar subir una ruta que apunte a la raíz del disco o a posiciones inesperadas:
    abs_folder = os.path.abspath(folder_path)
    if abs_folder in (os.path.abspath(os.sep), ''):
        return False, "Ruta de carpeta inválida (raíz)."

    errors = []
    files_uploaded = 0
    for root, dirs, files in os.walk(folder_path):
        for f in files:
            local_path = os.path.join(root, f)
            rel_path = os.path.relpath(local_path, folder_path).replace('\\', '/')
            try:
                with open(local_path, 'rb') as fh:
                    data = fh.read()
            except Exception as e:
                errors.append(f"Leer {local_path}: {e}")
                continue
            msg = f"{commit_prefix}: {rel_path}"
            status, body = _upload_file_to_github(repo_full, rel_path, data, token, msg)
            if status in (200, 201):
                files_uploaded += 1
                logging.info("Subido %s -> %s:%s", local_path, repo_full, rel_path)
            else:
                errors.append(f"Subir {rel_path}: status={status} body={body}")
    ok = len(errors) == 0
    return ok, {"uploaded": files_uploaded, "errors": errors}

def run_scan(cfg, config_path):
	"""
	Ejecuta una pasada completa de escaneo/procesamiento según la configuración.
	Ahora intenta asegurar acceso a rutas UNC solicitando y guardando credenciales.
	Al finalizar, si en config existe 'github_repo' o 'github_owner' o 'github_repos', intenta subir carpetas correspondientes.
	"""
	input_dir = cfg.get('input_dir')
	output_dir = cfg.get('output_dir')
	if not input_dir or not output_dir:
		logging.error("config.json debe contener 'input_dir' y 'output_dir'.")
		return 2

	# intentar asegurar acceso si son UNC
	if _is_unc_path(input_dir):
		if not _ensure_unc_access(input_dir, cfg, config_path):
			logging.error("No se puede acceder a input_dir: %s", input_dir)
			return 3
	if _is_unc_path(output_dir):
		if not _ensure_unc_access(output_dir, cfg, config_path):
			logging.error("No se puede acceder a output_dir: %s", output_dir)
			return 3

	if not os.path.isdir(input_dir):
		logging.error("Input no existe o no es carpeta: %s", input_dir)
		return 3

	ensure_dir(output_dir)
	versions_base = os.path.join(output_dir, '_old_versions')
	ensure_dir(versions_base)

	for root, dirs, files in os.walk(input_dir):
		for f in files:
			if _stop_event.is_set():
				return 0
			src = os.path.join(root, f)
			process_file(src, input_dir, output_dir, versions_base)

	# Al terminar el escaneo, intentar subir carpetas relacionadas con repositorios GitHub
	repo_full, token = _get_github_credentials(cfg, config_path)
	# repos_list sigue disponible
	repos_list = cfg.get('github_repos')  # opcional: lista de "owner/repo" strings

	# --- NUEVO: detección automática de subcarpetas cuando Owner-only está activado ---
	owner, owner_mode = _get_owner_and_mode(cfg)
	if owner_mode:
		if not owner:
			logging.warning("Owner-only activado pero 'github.owner' no está definido en config.json. No se realizará detección automática de subcarpetas.")
		elif not token:
			logging.warning("Owner-only activado pero no hay token de GitHub disponible. Configure github.token (o github_token) con permisos 'repo'.")
		else:
			abs_output = os.path.abspath(output_dir)
			detected = []
			try:
				for entry in os.listdir(output_dir):
					# ignorar versiones y ocultos
					if entry.startswith('_') or entry.startswith('.'):
						continue
					sub = os.path.join(output_dir, entry)
					if not os.path.isdir(sub):
						continue
					# subdirectorio inmediato
					if os.path.dirname(os.path.abspath(sub)) != abs_output:
						continue
					# debe contener archivos
					if not any(files for _, _, files in os.walk(sub)):
						continue
					owner_repo = f"{owner.rstrip('/')}/{entry}"
					# comprobar existencia en GitHub antes de añadir
					try:
						if _github_repo_exists(owner_repo, token):
							detected.append(owner_repo)
						else:
							logging.debug("Detectado '%s' pero no existe en GitHub. No se añade.", owner_repo)
					except Exception as e:
						logging.debug("No se pudo comprobar existencia de %s: %s", owner_repo, e)
			except Exception as e:
				logging.error("Error detectando subcarpetas para owner-only: %s", e)

			# fusionar detectados en github_repos y guardar en config.json
			if detected:
				existing = repos_list if isinstance(repos_list, list) else []
				merged = existing[:]
				for r in detected:
					if r not in merged:
						merged.append(r)
				cfg['github_repos'] = merged
				try:
					with open(config_path, 'w', encoding='utf-8') as f:
						json.dump(cfg, f, indent=2, ensure_ascii=False)
					logging.info("Repositorios detectados añadidos a config.github_repos: %s", detected)
				except Exception as e:
					logging.warning("No se pudo guardar config.json con repos detectados: %s", e)
				# actualizar variable para el resto del flujo
				repos_list = merged
	# --- FIN NUEVO ---

	# 1) Si hay repo_full configurado: comportamiento antiguo (subir carpeta con mismo nombre)
	if repo_full and token:
		# mantener compatibilidad con valor completo o normalizable
		repo_full_norm = repo_full.strip().lstrip('/').rstrip('/')
		if repo_full_norm.lower().startswith('http://') or repo_full_norm.lower().startswith('https://'):
			try:
				repo_full_norm = urllib.parse.urlparse(repo_full_norm).path.lstrip('/').rstrip('/')
			except Exception:
				pass
		repo_name = repo_full_norm.split('/')[-1].strip()
		if repo_name and repo_name not in ('.', '..'):
			target_folder = os.path.join(output_dir, repo_name)
			if os.path.isdir(target_folder):
				# comprobar que contiene archivos
				has_files = any(files for _, _, files in os.walk(target_folder))
				if has_files:
					logging.info("Se detectó carpeta '%s' en output. Intentando subir a GitHub %s.", repo_name, repo_full_norm)
					ok, info = push_folder_to_github(target_folder, repo_full_norm, token)
					if ok:
						logging.info("Subida a GitHub completada: %s archivos.", info.get('uploaded', 0))
					else:
						logging.error("Errores al subir a GitHub: %s", info)
				else:
					logging.info("Carpeta '%s' existe pero está vacía. No se sube.", target_folder)
			else:
				logging.debug("No existe carpeta '%s' en output. No se sube nada.", target_folder)
		else:
			logging.error("Nombre de repo inválido: '%s'. No se realiza la subida.", repo_full)

	# 2) Si se especificó una lista de repos, intentar cada uno (prioridad sobre owner_common)
	if repos_list and token:
		if isinstance(repos_list, list):
			for r in repos_list:
				if not r or not isinstance(r, str):
					continue
				r_norm = r.strip().lstrip('/').rstrip('/')
				if r_norm.lower().startswith('http://') or r_norm.lower().startswith('https://'):
					try:
						r_norm = urllib.parse.urlparse(r_norm).path.lstrip('/').rstrip('/')
					except Exception:
						pass
				if '/' not in r_norm:
					logging.warning("Entrada inválida en github_repos (se espera owner/repo): %s", r)
					continue
				repo_name = r_norm.split('/')[-1]
				target_folder = os.path.join(output_dir, repo_name)
				if os.path.isdir(target_folder):
					has_files = any(files for _, _, files in os.walk(target_folder))
					if has_files:
						logging.info("Subiendo carpeta '%s' -> %s", repo_name, r_norm)
						ok, info = push_folder_to_github(target_folder, r_norm, token)
						if ok:
							logging.info("Subida completada para %s: %s archivos.", r_norm, info.get('uploaded', 0))
						else:
							logging.error("Errores al subir %s: %s", r_norm, info)
					else:
						logging.debug("Carpeta '%s' existe pero no contiene archivos. Saltando %s.", target_folder, r_norm)
				else:
					logging.debug("No existe carpeta '%s' para repo %s. Saltando.", repo_name, r_norm)
		else:
			logging.warning("github_repos debe ser una lista; se omite.")

	# 3) Owner-only mode (opcional): subir cada subcarpeta inmediata de output_dir a owner/<carpeta>
	owner, owner_mode = _get_owner_and_mode(cfg)
	if owner_mode:
		if not owner:
			logging.warning("Owner-only activado pero 'github.owner' no está definido. Omisión de subida owner-only.")
		elif not token:
			logging.warning("Owner-only activado pero no hay token de GitHub disponible. Omisión de subida owner-only.")
		else:
			abs_output = os.path.abspath(output_dir)
			try:
				for entry in os.listdir(output_dir):
					# ignorar versiones y archivos ocultos puntuales
					if entry.startswith('_') or entry.startswith('.'):
						continue
					sub = os.path.join(output_dir, entry)
					if not os.path.isdir(sub):
						continue
					# asegurar subdirectorio inmediato
					abs_sub = os.path.abspath(sub)
					if os.path.dirname(abs_sub) != abs_output:
						continue
					# comprobar que carpeta contiene archivos
					has_files = any(files for _, _, files in os.walk(sub))
					if not has_files:
						logging.debug("Carpeta '%s' vacía. No se sube.", sub)
						continue
					owner_repo = f"{owner.rstrip('/')}/{entry}"
					# comprobar existencia en GitHub antes de intentar subir
					if not _github_repo_exists(owner_repo, token):
						logging.warning("Owner-only: repo no encontrado en GitHub: %s. Se omite.", owner_repo)
						continue
					logging.info("Owner-only: intentando subir carpeta '%s' a %s", entry, owner_repo)
					ok, info = push_folder_to_github(sub, owner_repo, token)
					if ok:
						logging.info("Subida completada para %s: %s archivos.", owner_repo, info.get('uploaded', 0))
					else:
						logging.error("Errores al subir %s: %s", owner_repo, info)
			except Exception as e:
				logging.error("Error al iterar subcarpetas de output para owner-only upload: %s", e)

	return 0

def _coerce_bool(val):
    """Normaliza valores típicos de config a booleano (acepta True/False, 'true','1', int)."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ('1', 'true', 'yes', 'y', 'on')
    try:
        return bool(int(val))
    except Exception:
        return False

def _get_owner_and_mode(cfg):
    """Devuelve (owner_str_or_None, owner_mode_bool). Tolerante a distintas claves de config."""
    gh = cfg.get('github') or {}
    owner = gh.get('owner') or cfg.get('github_owner')
    # preferir la llave explícita en github, si no existe usar la antigua
    if 'owner_mode' in gh:
        owner_mode_raw = gh.get('owner_mode')
    else:
        owner_mode_raw = cfg.get('github_owner_mode')
    return owner, _coerce_bool(owner_mode_raw)

def edit_config_gui(config_path):
    """Abrir una pequeña interfaz para editar input_dir/output_dir del config arrastrado,
    y permitir configurar GitHub (repo + token cifrado)."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, simpledialog
    except Exception:
        logging.error("tkinter no disponible; no se puede abrir la GUI de edición.")
        return 1

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception as e:
        logging.error("No se pudo leer %s: %s", config_path, e)
        cfg = {}

    # Preparar valores iniciales
    gh = cfg.get('github', {})
    repo_init = gh.get('repo') or cfg.get('github_repo', '')
    token_obj = gh.get('token') or cfg.get('github_token')
    token_exists = bool(token_obj)
    token_plain = {'value': None}  # None = no cambiar, '' = borrar, otherwise new token

    # owner y owner_mode (opción owner-only)
    owner_init = (gh.get('owner') or cfg.get('github_owner', '') )
    owner_mode_init = bool((gh.get('owner_mode') or cfg.get('github_owner_mode', False)))

    # lista de repos (si existe) para inicializar el textarea
    repos_cfg = cfg.get('github_repos')
    if isinstance(repos_cfg, list):
        repos_init = '\n'.join(repos_cfg)
    else:
        repos_init = repos_cfg or ''

    root = tk.Tk()
    root.title("Editar config - EntryUploader")

    # Input dir / Output dir
    tk.Label(root, text="Input dir:").grid(row=0, column=0, sticky='w')
    in_var = tk.StringVar(value=cfg.get('input_dir', ''))
    tk.Entry(root, textvariable=in_var, width=60).grid(row=0, column=1)
    def browse_in(): in_var.set(filedialog.askdirectory(initialdir=in_var.get() or os.getcwd()))
    tk.Button(root, text="Browse", command=browse_in).grid(row=0, column=2)

    tk.Label(root, text="Output dir:").grid(row=1, column=0, sticky='w')
    out_var = tk.StringVar(value=cfg.get('output_dir', ''))
    tk.Entry(root, textvariable=out_var, width=60).grid(row=1, column=1)
    def browse_out(): out_var.set(filedialog.askdirectory(initialdir=out_var.get() or os.getcwd()))
    tk.Button(root, text="Browse", command=browse_out).grid(row=1, column=2)

    # GitHub controls: repo + token (existentes)
    tk.Label(root, text="GitHub repo (owner/repo):").grid(row=2, column=0, sticky='w')
    gh_var = tk.StringVar(value=repo_init)
    tk.Entry(root, textvariable=gh_var, width=60).grid(row=2, column=1)

    tk.Label(root, text="Token GitHub:").grid(row=3, column=0, sticky='w')
    token_status_var = tk.StringVar(value="(configurado)" if token_exists else "(no configurado)")
    tk.Label(root, textvariable=token_status_var).grid(row=3, column=1, sticky='w')

    def set_token():
        try:
            t = simpledialog.askstring("Token GitHub", "Introduzca token (se guardará cifrado):", show='*', parent=root)
        except Exception:
            t = None
        if t:
            token_plain['value'] = t
            token_status_var.set("(nueva token establecida)")

    def clear_token():
        token_plain['value'] = ''
        token_status_var.set("(token borrada)")

    tk.Button(root, text="Set token", command=set_token).grid(row=3, column=2, sticky='w')
    tk.Button(root, text="Clear token", command=clear_token).grid(row=3, column=3, sticky='w')

    # Owner-only checkbox + Owner field
    owner_mode_var = tk.BooleanVar(value=owner_mode_init)
    owner_var = tk.StringVar(value=owner_init)
    tk.Checkbutton(root, text="Owner-only mode (sube cada subcarpeta a owner/<carpeta>)", variable=owner_mode_var).grid(row=4, column=0, columnspan=4, sticky='w')
    tk.Label(root, text="Owner (si Owner-only activo):").grid(row=5, column=0, sticky='w')
    tk.Entry(root, textvariable=owner_var, width=60).grid(row=5, column=1, columnspan=2, sticky='w')

    # Lista de repos (multilínea)
    tk.Label(root, text="Lista de repos (owner/repo, una por línea):").grid(row=6, column=0, sticky='nw')
    repos_text = tk.Text(root, width=60, height=6)
    repos_text.grid(row=6, column=1, columnspan=3, sticky='w')
    if repos_init:
        repos_text.insert('1.0', repos_init)

    def on_ok():
        cfg['input_dir'] = in_var.get()
        cfg['output_dir'] = out_var.get()
        # github repo y token (mantener compatibilidad)
        repo_val = gh_var.get().strip()
        if repo_val:
            cfg.setdefault('github', {})['repo'] = repo_val
            if token_plain['value'] is None:
                pass  # mantener token existente
            elif token_plain['value'] == '':
                # borrar token
                cfg.get('github', {}).pop('token', None)
                cfg.pop('github_token', None)
            else:
                try:
                    cfg.setdefault('github', {})['token'] = encrypt_string(token_plain['value'])
                except Exception as e:
                    messagebox.showerror("Error", f"No se pudo cifrar token: {e}")
                    return
        else:
            # eliminar entradas github si repo vacío (no tocar otras claves)
            cfg.get('github', {}).pop('repo', None)
            cfg.pop('github_repo', None)
            # token se mantiene según token_plain

        # owner-only settings
        if owner_mode_var.get():
            owner_val = owner_var.get().strip()
            if owner_val:
                cfg.setdefault('github', {})['owner'] = owner_val
                cfg.setdefault('github', {})['owner_mode'] = True
                cfg.pop('github_owner', None)
                cfg.pop('github_owner_mode', None)
            else:
                messagebox.showerror("Error", "Owner vacío: active Owner-only sólo si indica un owner válido.")
                return
        else:
            # desactivar owner-only y eliminar llave si existe
            if 'github' in cfg:
                cfg['github'].pop('owner', None)
                cfg['github'].pop('owner_mode', None)
            cfg.pop('github_owner', None)
            cfg.pop('github_owner_mode', None)

        # lista de repos (una por línea) -> guardar como lista en cfg['github_repos']
        repos_raw = repos_text.get('1.0', 'end').strip()
        if repos_raw:
            lines = [ln.strip() for ln in repos_raw.splitlines() if ln.strip()]
            cfg['github_repos'] = lines
        else:
            cfg.pop('github_repos', None)

        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Guardado", "config guardado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar: {e}")
        root.destroy()

    def on_cancel():
        root.destroy()

    tk.Button(root, text="OK", command=on_ok).grid(row=7, column=1, sticky='e')
    tk.Button(root, text="Cancel", command=on_cancel).grid(row=7, column=2, sticky='w')
    root.mainloop()
    return 0

def sync_owner_repos(cfg, config_path):
    """
    Escanea immediate subfolders de cfg['output_dir'] y añade "owner/<carpeta>"
    a cfg['github_repos'] (si no existen). Guarda config.json y devuelve (ok, added_list).
    """
    owner, _ = _get_owner_and_mode(cfg)
    if not owner:
        logging.error("No hay 'github.owner' en config.json. Defina github.owner para usar --add-owner-repos.")
        return False, []

    output_dir = cfg.get('output_dir')
    if not output_dir or not os.path.isdir(output_dir):
        logging.error("output_dir inválido o no existe: %s", output_dir)
        return False, []

    abs_output = os.path.abspath(output_dir)
    existing = cfg.get('github_repos') if isinstance(cfg.get('github_repos'), list) else []
    merged = existing[:]  # no mutar la lista original directamente
    added = []

    try:
        for entry in os.listdir(output_dir):
            if entry.startswith('_') or entry.startswith('.'):
                continue
            sub = os.path.join(output_dir, entry)
            if not os.path.isdir(sub):
                continue
            # asegurarse que es subcarpeta inmediata
            if os.path.dirname(os.path.abspath(sub)) != abs_output:
                continue
            repo = f"{owner.rstrip('/')}/{entry}"
            if repo not in merged:
                merged.append(repo)
                added.append(repo)
    except Exception as e:
        logging.error("Error enumerando subcarpetas de output_dir: %s", e)
        return False, []

    if not added:
        logging.info("No hay repos nuevos para añadir. Ninguna entrada añadida.")
        return True, []

    cfg['github_repos'] = merged
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        logging.info("Añadidos %d repositorios a config.github_repos: %s", len(added), added)
        return True, added
    except Exception as e:
        logging.error("No se pudo guardar config.json: %s", e)
        return False, added

def main():
	# Si el primer argumento es un archivo .json (arrastrado sobre el exe) o una carpeta que contenga config.json, abrir GUI de edición
	if len(sys.argv) > 1:
		arg = sys.argv[1]
		if os.path.isfile(arg) and arg.lower().endswith('.json'):
			return edit_config_gui(arg)
		if os.path.isdir(arg):
			candidate = os.path.join(arg, 'config.json')
			if os.path.isfile(candidate):
				return edit_config_gui(candidate)

	parser = argparse.ArgumentParser(description="Entry uploader (modo servicio/daemon via loop).")
	parser.add_argument('--once', action='store_true', help='Ejecutar una sola vez y salir.')
	parser.add_argument('--interval', type=float, default=10.0, help='Intervalo en segundos entre escaneos cuando no --once. (default 10)')
	parser.add_argument('--pid-file', help='Ruta para escribir el PID mientras se ejecuta (opcional).')
	parser.add_argument('--log-file', help='Archivo donde guardar logs (opcional).')
	parser.add_argument('--add-owner-repos', action='store_true', help='Escanea output_dir y añade owner/<carpeta> a github_repos en config.json y sale.')
	args = parser.parse_args()

	# logging básico
	log_handlers = [logging.StreamHandler(sys.stdout)]
	if args.log_file:
		log_handlers.append(logging.FileHandler(args.log_file, encoding='utf-8'))
	logging.basicConfig(level=logging.INFO, handlers=log_handlers, format='%(asctime)s %(levelname)s: %(message)s')

	# cargar config.json (misma ubicación del script)
	script_dir = os.path.dirname(os.path.abspath(__file__))
	config_path = os.path.join(script_dir, 'config.json')
	if not os.path.exists(config_path):
		logging.error("No se encontró config.json en %s. Crear y editar antes de ejecutar.", script_dir)
		return 1

	try:
		cfg = load_config(config_path)
	except Exception as e:
		logging.error("ERROR leyendo config.json: %s", e)
		return 1

	# Si se pidió sincronizar owner/<carpeta> a github_repos, hacerlo y salir
	if args.add_owner_repos:
		ok, added = sync_owner_repos(cfg, config_path)
		if ok:
			if added:
				print("Añadidos repos a config.github_repos:")
				for r in added:
					print("  -", r)
			else:
				print("No se añadieron repos (ya estaban todos).")
			return 0
		else:
			print("Error al sincronizar repos. Ver logs para más detalles.", file=sys.stderr)
			return 1

	# Señales para parada limpia
	try:
		signal.signal(signal.SIGINT, _signal_handler)
		signal.signal(signal.SIGTERM, _signal_handler)
	except Exception:
		# Algunos sistemas/windows pueden fallar en algunas señales; seguir igualmente.
		pass

	# escribir PID si se solicita
	pid_path = args.pid_file
	if pid_path:
		try:
			with open(pid_path, 'w') as pf:
				pf.write(str(os.getpid()))
		except Exception as e:
			logging.warning("No se pudo escribir pid-file %s: %s", pid_path, e)

	exit_code = 0
	if args.once:
		exit_code = run_scan(cfg, config_path)
	else:
		logging.info("Iniciando modo servicio: escaneando cada %.1f segundos. Presione Ctrl+C para detener.", args.interval)
		while not _stop_event.is_set():
			exit_code = run_scan(cfg, config_path)
			if _stop_event.is_set():
				break
			# dormir en trozos pequeños para responder rápido a señales
			total = args.interval
			interval_step = 0.5
			slept = 0.0
			while slept < total and not _stop_event.is_set():
				time.sleep(min(interval_step, total - slept))
				slept += interval_step
		logging.info("Parando servicio.")

	# eliminar pid-file
	if pid_path:
		try:
			os.remove(pid_path)
		except Exception:
			pass

	return exit_code

if __name__ == '__main__':
	sys.exit(main())