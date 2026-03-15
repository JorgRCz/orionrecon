"""
Motor de ejecución paralela. Gestiona el pipeline de módulos.
"""
import subprocess
import shlex
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Any
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from .logger import console, get_logger

log = get_logger("engine")


def run_cmd(
    cmd: str | list,
    timeout: int = 300,
    capture: bool = True,
    env: dict | None = None,
) -> tuple[int, str, str]:
    """
    Ejecuta un comando externo y retorna (returncode, stdout, stderr).
    """
    if isinstance(cmd, str):
        args = shlex.split(cmd)
    else:
        args = cmd

    try:
        proc = subprocess.run(
            args,
            capture_output=capture,
            text=True,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout ({timeout}s) para: {' '.join(args)}"
    except FileNotFoundError:
        return -2, "", f"Herramienta no encontrada: {args[0]}"
    except Exception as e:
        return -3, "", str(e)


def check_tool(name: str) -> bool:
    rc, _, _ = run_cmd(f"which {name}")
    return rc == 0


def check_tools(tools: list[str]) -> dict[str, bool]:
    return {t: check_tool(t) for t in tools}


class Engine:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self._lock = threading.Lock()

    def run_parallel(
        self,
        tasks: list[tuple[Callable, tuple, dict]],
        description: str = "Ejecutando módulos",
    ) -> list[Any]:
        """
        Ejecuta una lista de (func, args, kwargs) en paralelo.
        Retorna lista de resultados en el mismo orden.
        """
        results = [None] * len(tasks)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(description, total=len(tasks))

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_idx = {}
                for i, (func, args, kwargs) in enumerate(tasks):
                    future = executor.submit(func, *args, **kwargs)
                    future_to_idx[future] = i

                for future in as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        results[idx] = future.result()
                    except Exception as e:
                        log.error(f"Error en tarea {idx}: {e}")
                        results[idx] = None
                    progress.advance(task_id)

        return results

    def run_sequential(
        self,
        tasks: list[tuple[Callable, tuple, dict]],
        description: str = "Ejecutando",
    ) -> list[Any]:
        results = []
        for func, args, kwargs in tasks:
            try:
                results.append(func(*args, **kwargs))
            except Exception as e:
                log.error(f"Error en tarea secuencial: {e}")
                results.append(None)
        return results
