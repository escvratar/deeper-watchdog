# Deeper Watchdog installer for Windows: Docker on another device over SSH (server, NAS, router),
# Docker Desktop on this computer, or the portable version. Packed into deeper-watchdog-install-windows.bat
# by install/build.sh (the .bat runs this part with PowerShell). Works in Windows PowerShell 5.1 and PowerShell 7.

# Continue: with Stop, Windows PowerShell 5.1 throws on any stderr line of docker/ssh
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest's progress bar: noise, and slow in 5.1
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$Payload = '@@PAYLOAD@@'
$Repo = 'https://github.com/escvratar/deeper-watchdog'
$Image = 'ghcr.io/escvratar/deeper-watchdog:latest'
$Name = 'deeper-watchdog'

function Say($text, $color = 'Gray') { Write-Host $text -ForegroundColor $color }
function Step($text) { Write-Host ''; Write-Host ('▸ ' + $text) -ForegroundColor White }
function Ok($text) { Write-Host ('  ✓ ' + $text) -ForegroundColor Green }
function Warn($text) { Write-Host ('  ! ' + $text) -ForegroundColor Yellow }
function Info($text) { Write-Host ('    ' + $text) }
function Fail($text) { Write-Host ''; Write-Host ('  ✗ ' + $text) -ForegroundColor Red }
function Ask($q, $def) {
    $a = Read-Host ("  {0} [{1}]" -f $q, $def)
    if ([string]::IsNullOrWhiteSpace($a)) { return [string]$def } else { return $a.Trim() }
}
function AskSecret($q) {
    $s = Read-Host ('  ' + $q) -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
function Yes($q, $def = $true) {
    $a = Read-Host ("  {0} [{1}]" -f $q, $(if ($def) { 'Д/н' } else { 'д/Н' }))
    if ([string]::IsNullOrWhiteSpace($a)) { return $def }
    return $a.Trim().ToLower()[0] -in @('д', 'y', '1')
}
function Pause-Exit($code) { Write-Host ''; Read-Host '  Нажмите Enter, чтобы закрыть окно' | Out-Null; exit $code }

# ---------- SSH ----------
function Install-Remote {
    if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
        Fail 'В Windows не найден клиент SSH (ssh.exe).'
        Info 'Параметры → Приложения → Дополнительные компоненты → Добавить компонент → «Клиент OpenSSH».'
        Info 'Или в PowerShell от администратора: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0'
        Pause-Exit 1
    }
    Write-Host ''
    Say '  На устройстве должен быть включён SSH:' White
    Info 'Synology: Панель управления → Терминал и SNMP → Включить службу SSH (вход под администратором)'
    Info 'QNAP: Панель управления → Telnet/SSH → Разрешить SSH'
    Info 'Роутеры: SSH включается в настройках роутера или прошивке (у Xiaomi — отдельная разблокировка)'
    Write-Host ''
    while ($true) {
        $h = Ask 'IP-адрес или имя устройства' '192.168.1.10'
        $p = Ask 'Порт SSH' '22'
        $u = Ask 'Пользователь' 'root'
        Write-Host ''
        Info ("Подключаюсь к {0}@{1}... Пароль SSH спросит программа ssh (при вводе он не виден)." -f $u, $h)
        Info 'При первом подключении ssh спросит «Are you sure you want to continue connecting» — введите yes.'
        Write-Host ''
        # The device unpacks the installer to /tmp, runs it in this window (-t: its questions) and deletes it
        $cmd = "sh -c 'umask 077; T=/tmp/dw-install.`$`$.sh; echo $Payload | { base64 -d 2>/dev/null || openssl base64 -d -A; } | gzip -dc > `$T && DW_SELF=`$T sh `$T; r=`$?; rm -f `$T; exit `$r'"
        & ssh -t -o ConnectTimeout=15 -p $p "$u@$h" $cmd
        $rc = $LASTEXITCODE
        if ($rc -eq 0) { Pause-Exit 0 }
        if ($rc -eq 255) {
            Fail 'Не удалось подключиться по SSH. Частые причины:'
            Info '• Connection refused — SSH на устройстве выключен или другой порт'
            Info '• Connection timed out — неверный адрес или устройство в другой сети'
            Info '• Permission denied — неверный пользователь или пароль'
            Info ("• REMOTE HOST IDENTIFICATION HAS CHANGED — устройство переустановлено: ssh-keygen -R {0}" -f $h)
        }
        Write-Host ''
        if (-not (Yes 'Попробовать снова?' $false)) { Pause-Exit $rc }
    }
}

# ---------- Docker Desktop on this computer ----------
function D { & docker @args 2>&1; }
function Exists { return [bool]((& docker ps -aq --filter "name=^/$Name$" 2>$null) -join '') }
function State { return ((& docker inspect -f '{{.State.Status}}' $Name 2>$null) -join '') }
function StateRu {
    $st = State
    $ru = @{ running = 'работает'; exited = 'остановлен'; restarting = 'перезапускается'; paused = 'на паузе'; created = 'создан, не запущен' }
    if ($ru.ContainsKey($st)) { return $ru[$st] } else { return $st }
}
function HostPort {
    $p = (& docker inspect -f '{{range $p, $c := .HostConfig.PortBindings}}{{if eq $p "8787/tcp"}}{{(index $c 0).HostPort}}{{end}}{{end}}' $Name 2>$null) -join ''
    if ($p) { return $p } else { return '8787' }
}
function MountDir { return ((& docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' $Name 2>$null) -join '') }
# The install folder: a label of the container (Docker Desktop shows bind mounts as /run/desktop/mnt/host/... paths)
function InstallDir {
    $d = (& docker inspect -f '{{index .Config.Labels "dw.dir"}}' $Name 2>$null) -join ''
    if ($d -and $d -ne '<no value>') { return $d }
    $m = MountDir
    if ($m) { return (Split-Path $m -Parent) }
    return ''
}

function Http-Ok($url) {
    try { Invoke-WebRequest -Uri $url -TimeoutSec 6 -UseBasicParsing | Out-Null; return $true }
    catch {
        if ($_.Exception.Response) { return $true }  # 401 and such: something answered
        return $false
    }
}
function Port-Busy($port) {
    $l = $null
    try { $l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, [int]$port); $l.Start(); return $false }
    catch { return $true }
    finally { if ($l) { $l.Stop() } }
}
function Iana-Tz {
    $map = @{
        'Russian Standard Time' = 'Europe/Moscow'; 'Kaliningrad Standard Time' = 'Europe/Kaliningrad'
        'Russia Time Zone 3' = 'Europe/Samara'; 'Ekaterinburg Standard Time' = 'Asia/Yekaterinburg'
        'Omsk Standard Time' = 'Asia/Omsk'; 'N. Central Asia Standard Time' = 'Asia/Novosibirsk'
        'North Asia Standard Time' = 'Asia/Krasnoyarsk'; 'North Asia East Standard Time' = 'Asia/Irkutsk'
        'Yakutsk Standard Time' = 'Asia/Yakutsk'; 'Vladivostok Standard Time' = 'Asia/Vladivostok'
        'Magadan Standard Time' = 'Asia/Magadan'; 'Russia Time Zone 11' = 'Asia/Kamchatka'
        'Belarus Standard Time' = 'Europe/Minsk'; 'FLE Standard Time' = 'Europe/Kiev'
        'Central Asia Standard Time' = 'Asia/Almaty'; 'W. Europe Standard Time' = 'Europe/Berlin'
        'GMT Standard Time' = 'Europe/London'; 'China Standard Time' = 'Asia/Shanghai'; 'UTC' = 'UTC'
    }
    $id = [TimeZoneInfo]::Local.Id
    if ($map.ContainsKey($id)) { return $map[$id] }
    if ($id -like '*/*') { return $id }  # PowerShell 7 on Linux/macOS: already IANA
    return 'Europe/Moscow'
}
function Write-Env($path, $lines) {
    # UTF-8 without BOM and LF: docker reads the file literally
    [IO.File]::WriteAllText($path, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
}

function Wait-Up($port) {
    Step 'Запуск'
    for ($i = 0; $i -lt 45; $i++) {
        $st = State
        if ($st -in @('exited', 'dead')) { break }
        if (Http-Ok "http://127.0.0.1:$port/") { Ok 'Веб-интерфейс отвечает'; return $true }
        Start-Sleep 2
    }
    Warn ("Watchdog не отвечает (контейнер: {0}). Последние строки журнала:" -f (StateRu))
    & docker logs --tail 15 $Name 2>&1 | ForEach-Object { Info $_ }
    return $false
}
function Check-Login {
    for ($i = 0; $i -lt 30; $i++) {
        $log = (& docker logs --tail 200 $Name 2>&1) -join "`n"
        if ($log -match 'Authentication successful') { return 0 }
        if ($log -match 'Login failed') { return 1 }
        if ($log -match 'Failed to fetch tunnels|urlopen error') { return 3 }
        Start-Sleep 2
    }
    return 2
}
function Run-Container($envFile, $dir, $port) {
    $data = Join-Path $dir 'data'
    $out = & docker run -d --name $Name --restart unless-stopped -p "${port}:8787" --env-file $envFile -v "${data}:/data" --label "dw.dir=$dir" `
        --log-opt max-size=10m --log-opt max-file=3 $Image 2>&1
    if ($LASTEXITCODE -eq 0) { return $true }
    $out | Select-Object -Last 3 | ForEach-Object { Info $_ }
    return $false
}
function Pull {
    Step "Загрузка образа $Image"
    for ($n = 1; $n -le 3; $n++) {
        $out = & docker pull $Image 2>&1
        if ($LASTEXITCODE -eq 0) { Ok 'Образ загружен'; return }
        if ($n -lt 3) { Warn 'Не получилось, повтор через 5 с...'; Start-Sleep 5 }
    }
    $out | Select-Object -Last 3 | ForEach-Object { Info $_ }
    Fail 'Не удалось скачать образ'
    Info 'Проверьте интернет и доступ к ghcr.io (если заблокирован: прокси/VPN в настройках Docker Desktop)'
    Pause-Exit 1
}
function Show-Done($port, $webPass) {
    Step 'Готово'
    Write-Host ''
    Write-Host ("  ➜  Откройте: http://127.0.0.1:{0}/" -f $port) -ForegroundColor Green
    $ips = @()
    try { $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -ExpandProperty IPAddress -First 3 } catch {}
    foreach ($ip in $ips) { Info ("С телефона и других устройств: http://{0}:{1}/" -f $ip, $port) }
    if (-not $webPass) { Info 'Первая открытая страница попросит придумать пароль входа.' }
    Info 'Компьютер должен быть включён: Watchdog работает, пока работает Docker Desktop (включите в нём «Start Docker Desktop when you sign in»).'
    try { Start-Process ("http://127.0.0.1:{0}/" -f $port) } catch {}
}

function Ensure-Docker {
    Step 'Docker Desktop'
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Warn 'Docker Desktop не установлен.'
        if ((Get-Command winget -ErrorAction SilentlyContinue) -and (Yes 'Установить его сейчас через winget (понадобится перезагрузка)?')) {
            & winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
            Info 'После установки перезагрузите компьютер, запустите Docker Desktop, дождитесь «Engine running» и запустите этот установщик снова.'
        } else {
            Info 'Скачайте: https://www.docker.com/products/docker-desktop/ — установите, запустите и запустите этот установщик снова.'
            Info 'Нет желания ставить Docker? Выберите portable-версию (пункт 3).'
        }
        Pause-Exit 1
    }
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        $exe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
        if ($env:ProgramFiles -and (Test-Path $exe)) {
            Info 'Docker Desktop не запущен: запускаю, это может занять минуту...'
            Start-Process $exe
        } else {
            Info 'Docker не отвечает: запустите Docker Desktop. Жду до 2 минут...'
        }
        for ($i = 0; $i -lt 60; $i++) {
            Start-Sleep 2
            & docker info *> $null
            if ($LASTEXITCODE -eq 0) { break }
        }
        if ($LASTEXITCODE -ne 0) { Fail 'Docker так и не запустился. Откройте Docker Desktop, дождитесь «Engine running» и повторите.'; Pause-Exit 1 }
    }
    Ok ('Docker ' + ((& docker version --format '{{.Server.Version}}' 2>$null) -join ''))
}

function Do-Install($old) {
    Step 'Настройка'
    Info 'Enter оставляет значение в скобках. Пароли при вводе не видны.'
    $hostIp = if ($old.DEEPER_HOST) { $old.DEEPER_HOST } else { '34.34.34.34' }
    while ($true) {
        $hostIp = Ask 'IP-адрес Deeper Connect' $hostIp
        if (Http-Ok "http://$hostIp/") { Ok "Deeper Connect отвечает ($hostIp)"; break }
        Warn "Deeper Connect по адресу $hostIp не отвечает с этого компьютера"
        Info 'Компьютер должен быть в одной сети с Deeper. Адрес — тот, что открывается в браузере для входа в Deeper'
        if (-not (Yes 'Ввести адрес заново?')) { break }
    }
    $pass = $old.DEEPER_PASS
    while ($true) {
        $a = AskSecret $(if ($pass) { 'Пароль администратора Deeper Connect [Enter: оставить прежний]' } else { 'Пароль администратора Deeper Connect' })
        if ($a) { $pass = $a }
        if ($pass) { break }
        Warn 'Без пароля Watchdog не сможет управлять туннелями (можно задать позже в веб-интерфейсе)'
        if (-not (Yes 'Ввести пароль?')) { break }
    }
    $port = if ($old.PORT) { $old.PORT } else { '8787' }
    while ($true) {
        $port = Ask 'Порт веб-интерфейса' $port
        if ($port -notmatch '^\d+$' -or [int]$port -lt 1 -or [int]$port -gt 65535) { Warn 'Нужно число от 1 до 65535'; $port = '8787'; continue }
        if ((Port-Busy $port) -and -not ((Exists) -and (HostPort) -eq $port)) { Warn "Порт $port занят другой программой"; $port = [string]([int]$port + 1); continue }
        break
    }
    $web = $old.WEB_PASSWORD
    Info 'Пароль входа в веб-интерфейс Watchdog (не пароль Deeper). Можно не задавать: его попросит первая открытая страница'
    while ($true) {
        $a = AskSecret $(if ($web) { 'Пароль веб-интерфейса [Enter: оставить прежний]' } else { 'Пароль веб-интерфейса [Enter: задать в браузере]' })
        if (-not $a) { break }
        if ($a.Length -lt 4) { Warn 'Нужно хотя бы 4 символа'; continue }
        if ((AskSecret 'Повторите пароль') -ne $a) { Warn 'Пароли не совпали'; continue }
        $web = $a; break
    }
    $tz = Ask 'Часовой пояс' $(if ($old.TZ) { $old.TZ } else { Iana-Tz })
    $dir = Ask 'Папка для настроек и журнала' $(if ($old.DIR) { $old.DIR } else { Join-Path $HOME 'deeper-watchdog' })

    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'data') | Out-Null
    $envFile = Join-Path $dir '.env'
    $lines = @('# Deeper Watchdog. Остальные настройки задаются в веб-интерфейсе', "DEEPER_HOST=$hostIp")
    if ($pass) { $lines += "DEEPER_PASS=$pass" }
    if ($web) { $lines += "WEB_PASSWORD=$web" }
    $lines += "TZ=$tz"
    Write-Env $envFile $lines
    Ok "Настройки записаны в $envFile"

    Pull
    if (Exists) { & docker rm -f $Name *> $null; Ok 'Прежний контейнер удалён (данные сохранены)' }
    if (-not (Run-Container $envFile $dir $port)) { Fail 'Контейнер не запустился'; Pause-Exit 1 }
    Ok "Контейнер $Name создан, автозапуск включён"
    if (-not (Wait-Up $port)) { Fail 'Watchdog не запустился'; Pause-Exit 1 }
    if ($pass) {
        Step 'Вход в Deeper Connect'
        while ($true) {
            $r = Check-Login
            if ($r -eq 0) { Ok 'Watchdog вошёл в Deeper Connect'; break }
            if ($r -eq 2) { Warn 'Пока не видно входа в Deeper: проверьте журнал в веб-интерфейсе через пару минут'; break }
            if ($r -eq 3) { Warn "Контейнер не может связаться с Deeper Connect ($hostIp). Адрес можно поменять в веб-интерфейсе: Настройки → Deeper Connect"; break }
            Warn 'Deeper Connect не принял пароль'
            if (-not (Yes 'Ввести пароль Deeper заново?')) { break }
            $pass = AskSecret 'Пароль администратора Deeper Connect'
            $lines = $lines | Where-Object { $_ -notlike 'DEEPER_PASS=*' }
            $lines += "DEEPER_PASS=$pass"
            Write-Env $envFile $lines
            & docker rm -f $Name *> $null
            if (-not (Run-Container $envFile $dir $port) -or -not (Wait-Up $port)) { Fail 'Watchdog не запустился'; Pause-Exit 1 }
        }
    }
    Show-Done $port $web
}

function Do-Update {
    Pull
    Step 'Пересоздание контейнера с прежними настройками'
    $dir = InstallDir; $port = HostPort
    if (-not $dir) { Fail 'Не нашёл папку данных прежнего контейнера'; return }
    $img = (& docker inspect -f '{{.Image}}' $Name) -join ''
    $imgEnv = & docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' $img 2>$null
    $envLines = & docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' $Name | Where-Object { $_ -and ($imgEnv -notcontains $_) }
    $tmp = [IO.Path]::GetTempFileName()
    try {
        Write-Env $tmp $envLines
        & docker stop $Name *> $null
        & docker rename $Name "$Name-old" *> $null
        if ((Run-Container $tmp $dir $port) -and (Wait-Up $port)) {
            & docker rm -f "$Name-old" *> $null
            Ok 'Обновлено, настройки и журнал сохранены'
            Show-Done $port $true
        } else {
            Warn 'Новая версия не запустилась: возвращаю прежнюю'
            & docker rm -f $Name *> $null
            & docker rename "$Name-old" $Name *> $null
            & docker start $Name *> $null
            Fail 'Обновление не удалось, прежняя версия снова работает'
        }
    } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function Read-OldEnv {
    $old = @{}
    $dir = InstallDir
    if ($dir) {
        $old.DIR = $dir
        $f = Join-Path $old.DIR '.env'
        if (Test-Path $f) {
            foreach ($l in [IO.File]::ReadAllLines($f)) { if ($l -match '^([A-Z_]+)=(.*)$') { $old[$Matches[1]] = $Matches[2] } }
        }
        $old.PORT = HostPort
    }
    return $old
}

function Install-Local {
    Ensure-Docker
    if (Exists) {
        Write-Host ''
        Info ("Watchdog уже установлен ({0}). Что сделать?" -f (StateRu))
        Info '1) Обновить до последней версии (настройки сохранятся)'
        Info '2) Переустановить с новыми параметрами'
        Info '3) Показать состояние'
        Info '4) Удалить'
        Info '5) Выход'
        switch (Ask 'Выбор' '1') {
            '1' { Do-Update }
            '2' { Do-Install (Read-OldEnv) }
            '3' {
                Step 'Последние строки журнала'
                & docker logs --tail 12 $Name 2>&1 | ForEach-Object { Info $_ }
                $p = HostPort
                if (Http-Ok "http://127.0.0.1:$p/") { Ok "Веб-интерфейс отвечает: http://127.0.0.1:$p/" } else { Warn 'Веб-интерфейс не отвечает' }
            }
            '4' {
                if (Yes "Удалить контейнер $Name?" $false) {
                    $dir = InstallDir
                    & docker rm -f $Name *> $null; Ok 'Контейнер удалён'
                    & docker rmi $Image *> $null
                    if ($dir -and (Test-Path $dir) -and (Yes "Удалить и настройки с журналом ($dir)?" $false)) {
                        Remove-Item -Recurse -Force $dir; Ok 'Данные удалены'
                    } elseif ($dir) { Info "Данные оставлены в $dir" }
                }
            }
        }
    } else {
        Do-Install @{}
    }
    Pause-Exit 0
}

# ---------- main ----------
Write-Host ''
Write-Host ' Deeper Watchdog — установщик' -ForegroundColor White
Write-Host (' ' + $Repo) -ForegroundColor DarkGray
Write-Host ''
Info 'Куда установить?'
Info '1) На другое устройство по SSH: сервер, NAS (Synology, QNAP), роутер с Docker — рекомендуется, работает круглосуточно'
Info '2) На этот компьютер в Docker Desktop'
Info '3) На этот компьютер без Docker: portable-версия'
Info 'Тот же пункт обновляет, показывает состояние или удаляет уже установленный Watchdog.'
Write-Host ''
try {
    switch (Ask 'Выбор' '1') {
        '1' { Install-Remote }
        '2' { Install-Local }
        '3' {
            Info 'Скачайте deeper-watchdog-portable-windows.zip со страницы релизов, распакуйте и запустите «Запустить Deeper Watchdog.bat».'
            try { Start-Process "$Repo/releases/latest" } catch {}
            Pause-Exit 0
        }
        default { Warn 'Нет такого пункта'; Pause-Exit 1 }
    }
} catch {
    Fail ('Ошибка: ' + $_.Exception.Message)
    Pause-Exit 1
}
