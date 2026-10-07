# Demonstração — HTTP Headers Scanner

## Contexto e objetivo

Servidores HTTP enviam cabeçalhos que orientam o navegador sobre transporte seguro, carregamento de recursos, incorporação da página e outras proteções. Este projeto consulta uma URL, examina sete cabeçalhos de segurança e resume os resultados em uma pontuação de 0 a 100 e uma nota de A a F. Ele também indica quais configurações precisam ser revisadas.

## O que foi implementado

O scanner usa `httpx` para obter a resposta, aplica regras a cada cabeçalho, calcula a pontuação ponderada e apresenta uma tabela com `rich`. A lógica de avaliação e pontuação fica separada da requisição HTTP, o que permite testá-la com respostas simuladas por `respx`.

Além da base do projeto, foram concluídos os três desafios do MVP:

1. Inclusão de `Cross-Origin-Opener-Policy` como sétimo cabeçalho, com verificação do valor `same-origin`.
2. Opção `--json` para produzir uma saída estruturada, incluindo pontuação, nota e avaliações.
3. Opção `--verbose` para mostrar todos os cabeçalhos brutos antes da tabela.

## Execução e resultados

Comandos demonstrados em 6 de outubro de 2026:

```bash
just run -- https://example.com --verbose
just run -- https://example.com --json
just test
just lint
```

Na resposta recebida de `https://example.com` durante a demonstração, os sete cabeçalhos avaliados estavam ausentes. O scanner apresentou **0/100, nota F**, mostrou os cabeçalhos brutos com `--verbose` e gerou JSON válido com `--json`. O resultado de um site real pode mudar ao longo do tempo ou conforme a resposta recebida.

A suíte terminou com **11 testes passando**. Ruff e mypy (`--strict`) passaram, e o Pylint atribuiu **10,00/10** ao arquivo principal. Os testes incluem os três desafios do MVP e os códigos de saída para notas A, C e F/erro de rede.

## Decisões técnicas e limites

- As severidades têm pesos diferentes: alta (30), média (15) e baixa (5). Um resultado `weak` recebe metade dos pontos. Isso permite resumir vários achados em uma nota sem ocultar os detalhes da tabela.
- As respostas dos testes são simuladas com `respx`, evitando depender de sites externos para validar o comportamento do programa.
- Algumas regras fazem verificações simples: por exemplo, o scanner verifica a presença da Content-Security-Policy, mas não analisa cada diretiva. A nota é um indicador inicial e não substitui uma auditoria de segurança.
- Os códigos de saída são 0 para A/B, 1 para C/D e 2 para F ou erro de rede. Por isso, o `just` pode informar código 2 após imprimir corretamente um relatório de nota F.

## Conclusão

O projeto mostrou como obter cabeçalhos HTTP, transformar verificações individuais em uma avaliação ponderada e disponibilizar resultados para pessoas (tabela) e programas (JSON). Uma possível extensão futura é analisar o conteúdo da política CSP com mais detalhe.

## Vídeo da demonstração individual

https://youtu.be/TlnrhPh0Nr0