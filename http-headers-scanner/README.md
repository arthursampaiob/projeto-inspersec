# HTTP Headers Scanner

Ferramenta de linha de comando em Python que faz uma requisição a uma URL, avalia cabeçalhos HTTP de segurança e atribui uma pontuação de 0 a 100 e uma nota de A a F. O relatório mostra o estado de cada cabeçalho e recomendações para os que estiverem ausentes ou fracos.

## Cabeçalhos avaliados

| Cabeçalho | Severidade | Pontos possíveis |
| --- | --- | ---: |
| Strict-Transport-Security | Alta | 30 |
| Content-Security-Policy | Alta | 30 |
| X-Content-Type-Options | Média | 15 |
| X-Frame-Options | Média | 15 |
| Referrer-Policy | Baixa | 5 |
| Permissions-Policy | Baixa | 5 |
| Cross-Origin-Opener-Policy | Baixa | 5 |

O scanner classifica cada cabeçalho como `ok`, `weak` ou `missing`. Um cabeçalho `weak` recebe metade dos pontos da sua severidade. A pontuação é normalizada para 100. As notas são A (90–100), B (80–89), C (70–79), D (60–69) e F (abaixo de 60).

O scanner indica configurações que merecem investigação; ele não comprova, por si só, que um site seja seguro ou vulnerável.

## Requisitos e instalação

- Python 3.11 ou superior, conforme `pyproject.toml`.
- Acesso à internet para escanear URLs reais.
- [`just`](https://github.com/casey/just) para executar os atalhos do `justfile`. No Windows, pode ser instalado com `winget install --id Casey.Just --exact`.

No Git Bash, dentro da pasta do projeto:

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -e '.[dev]'
```

No Linux ou macOS, a ativação é `source .venv/bin/activate`. Abra um novo terminal se `just` tiver sido instalado durante a sessão atual e ainda não for encontrado no `PATH`.

## Uso

```bash
just run -- https://example.com
just run -- https://example.com --verbose
just run -- https://example.com --json
just run -- https://example.com --timeout 5
```

O `--verbose` mostra todos os cabeçalhos recebidos antes da tabela. O `--json` substitui a tabela por um objeto JSON com as URLs, o código HTTP, os cabeçalhos recebidos, as avaliações, a pontuação e a nota. É necessário incluir `http://` ou `https://` na URL.

Se o comando `just` não estiver disponível, use diretamente `python http_headers_scanner.py https://example.com --verbose` ou a opção desejada.

### Códigos de saída

| Código | Significado |
| ---: | --- |
| 0 | Nota A ou B |
| 1 | Nota C ou D |
| 2 | Nota F ou erro de rede |

Uma execução que imprime um relatório com nota F pode terminar com código 2; isso faz parte do comportamento da ferramenta.

## Validação

```bash
just test
just lint
```

`just test` executa os testes com respostas HTTP simuladas por `respx`. `just lint` executa Ruff, mypy em modo estrito e Pylint. A demonstração dos resultados e das decisões técnicas está em [DEMO.md](DEMO.md).

## Estrutura

- `http_headers_scanner.py`: regras, requisição HTTP, pontuação e interface de linha de comando.
- `test_http_headers_scanner.py`: testes automatizados da avaliação, das opções e dos códigos de saída.
- `pyproject.toml`: metadados e dependências.
- `justfile`: atalhos para executar, testar e verificar o projeto.
- `DEMO.md`: resultados, explicação e apresentação do projeto.