from __future__ import annotations

import argparse
from pathlib import Path

from monitoring import run_worker


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Executa verificações somente nos ativos cadastrados no Sentinela."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="executa um ciclo e encerra, adequado ao Agendador de Tarefas",
    )
    arguments = parser.parse_args()
    run_worker(Path(__file__).with_name("netwatch.db"), once=arguments.once)


if __name__ == "__main__":
    main()
