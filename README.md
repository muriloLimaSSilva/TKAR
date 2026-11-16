# TKAR — Timed Keyboard Action Runner

Aplicativo local em Python para automação de teclado, com interface Tkinter e PyAutoGUI.

## Recursos

- Automação de teclado com início, pausa e intervalo ajustável.
- Preferências de tema e cores.
- Lista de usuários válidos e registro de acessos.
- Senha definida pelo usuário no primeiro uso e armazenada como hash com salt.

## Executar

Requisitos: Python 3.10 ou superior.

Instale a dependência PyAutoGUI com o comando: python -m pip install pyautogui

Execute com: python TKAR.py

No primeiro uso de um banco novo, informe seu nome e crie uma senha com pelo menos 8 caracteres, incluindo uma letra maiúscula, um número e um símbolo. Esse nome será cadastrado como o primeiro usuário válido; bancos que já têm usuários continuam exigindo um nome autorizado.

## Dados e privacidade

As preferências e os registros são mantidos localmente em %APPDATA%\JumpScreenSoftware\settings.db. A senha é armazenada como hash PBKDF2-HMAC-SHA256 com salt. Os nomes e horários dos acessos ficam em texto no banco local; esta versão não criptografa esses registros. Não inclua dados reais de alunos ou informações confidenciais da escola.

O repositório público contém apenas o código e a documentação. O banco de dados, arquivos de ambiente e saídas de compilação devem permanecer locais.