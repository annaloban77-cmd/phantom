# PHANTOM-V2: Архитектурный Документ

## Версия: 1.0
## Дата: 2025-01-XX
## Статус: ЭТАП 1 — Архитектура и Спецификация

---

## 1. ОБЗОР АРХИТЕКТУРЫ

```
┌─────────────────────────────────────────────────────────────────────┐
│                           INTERNET                                   │
│                                                                      │
│  ┌──────────────┐                    ┌──────────────────────────┐   │
│  │   Client     │                    │        Server            │   │
│  │  (Go binary) │                    │      (Go binary)         │   │
│  │              │                    │                          │   │
│  │  ┌────────┐  │  Mode A: TCP       │  ┌────────────────────┐  │   │
│  │  │ SOCKS5 │◄─┼────────────────────┼─►│ Masquerade Site    │  │   │
│  │  └────────┘  │  Encrypted Tunnel  │  │ (static HTML/CSS)  │  │   │
│  │       │      │  + HTTP/2 Framing  │  └────────────────────┘  │   │
│  │  ┌────────┐  │                    │           │              │   │
│  │  │  TUN   │  │  Mode B: CF Worker │  ┌────────▼────────┐    │   │
│  │  └────────┘  │  (Cloudflare)      │  │ TLS Termination │    │   │
│  │       │      │                    │  │ (Let's Encrypt) │    │   │
│  │  ┌────────┐  │  Mode C: WebSocket │  └────────┬────────┘    │   │
│  │  │Browser │  │  (HTTPS Proxy)     │           │              │   │
│  │  └────────┘  │                    │  ┌────────▼────────┐    │   │
│  │       │      │                    │  │ Handshake Auth  │    │   │
│  │  ┌────────┐  │                    │  │ (Challenge-Resp)│    │   │
│  │  │ Shaper │  │                    │  └────────┬────────┘    │   │
│  │  │ +HTTP/2│  │                    │           │              │   │
│  │  └────────┘  │                    │  ┌────────▼────────┐    │   │
│  │       │      │                    │  │ Encrypted Relay │    │   │
│  │  ┌────────┐  │                    │  │ (SOCKS5/TUN)    │    │   │
│  │  │Crypto  │  │                    │  └─────────────────┘    │   │
│  │  └────────┘  │                    │                          │   │
│  └──────────────┘                    └──────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

 DPI (Deep Packet Inspection) видит:
  ✓ Легитимный TLS handshake (JA4 fingerprint = Chrome/Safari/Edge)
  ✓ HTTP/2 frame patterns внутри TLS records
  ✓ Packet size distribution как у реального браузера
  ✓ Inter-packet delays с человеческим jitter
```

---

## 2. МОДЕЛЬ УГРОЗЫ (DETAILED)

### 2.1 Что отслеживает RKN/DPI

| Уровень          | Сигнатура                          | Метод обнаружения                |
|------------------|------------------------------------|----------------------------------|
| Транспорт        | TCP window size, MSS, options      | Passive fingerprinting           |
| TLS              | JA4, JARM, cert chain              | Active probing + passive         |
| TLS Record       | Size distribution, timing          | Statistical analysis             |
| HTTP/2 (inside)  | Frame type ratio, sizes            | Deep inspection (GFW-level)      |
| Поведение        | Request patterns, timing           | ML-based anomaly detection       |
| Активный зонд    | HTTP HEAD, random paths            | Honeypot traps                   |

### 2.2 Методы блокировки

```
1. TCP RST Injection
   - DPI отправляет TCP RST от имени сервера/клиента
   - Обрывает соединение мгновенно
   - Counter: Быстрое переподключение + смена профиля

2. DNS Poisoning
   - Возвращает неправильный IP для домена
   - Counter: Hardcoded IP в конфиге + DoH fallback

3. DPI-triggered Rate Limiting
   - Обнаружил аномалию → throttle до 1 Kbps
   - Counter: Adaptive shaper, cover traffic

4. Honeypot Detection
   - Разворачивает fake server на том же IP
   - Ловит клиентов по сигнатурам протокола
   - Counter: Certificate pinning + timing analysis + response fingerprinting
```

### 2.3 Активные зонды (Active Probing)

```
Зонд 1: HTTP GET на IP
  - Отправляет: GET / HTTP/1.1\nHost: <ip>\n
  - Ожидает: nginx-like ответ (Server: nginx/1.x)
  - Если ответ ≠ nginx → помечает как proxy

Зонд 2: TLS ClientHello probe
  - Отправляет валидный ClientHello
  - Анализирует ServerHello на аномалии
  - Ищет: нестандартные cipher suites, extensions

Зонд 3: Certificate validation
  - Проверяет, что сертификат от известной CA (Let's Encrypt)
  - Self-signed или unknown CA → honeypot flag

Зонд 4: Non-standard path test
  - Отправляет: GET /zzz_random_xyz_abc HTTP/1.1
  - Ожидает: 404 Not Found (как нормальный сайт)
  - Если 403/451/redirect → honeypot (RKN signature)
```

---

## 3. КРИПТОГРАФИЧЕСКИЕ ПРИМИТИВЫ

### 3.1 Алгоритмы (только stdlib)

| Компонент        | Алгоритм                  | Go Package              | Размер ключа |
|------------------|---------------------------|-------------------------|--------------|
| Key Exchange     | X25519 (ECDH)             | `crypto/x25519`         | 32 bytes     |
| KDF              | HKDF-SHA256               | `crypto/hkdf`           | 32 bytes     |
| AEAD             | ChaCha20-Poly1305         | `crypto/cipher`         | 32 + 12 bytes|
| HMAC             | HMAC-SHA256               | `crypto/hmac`           | 32 bytes     |
| Hash             | SHA256                    | `crypto/sha256`         | 32 bytes     |

### 3.2 Запреты

- ❌ Самописная криптография
- ❌ Нестандартные параметры (только RFC-approved)
- ❌ Переиспользование nonce (panic при detect)
- ❌ Логирование ключей/payload

---

## 4. HANDSHAKE ПРОТОКОЛ (Challenge-Response)

### 4.1 Диаграмма последовательности

```
Client                              Server
  │                                   │
  │──── ClientHello ─────────────────>│
  │   {X25519_pub_C, ts_ms, nonce_C}  │
  │                                   │
  │                                   │ [Generate nonce_S]
  │                                   │ [Store nonce_S in replay_window]
  │                                   │ [Compute shared_secret = X25519(priv_S, pub_C)]
  │                                   │
  │<─── ServerHello ──────────────────│
  │   {X25519_pub_S, nonce_S,         │
  │    HMAC_auth}                     │
  │                                   │
  │ [Verify HMAC_auth]                │
  │ [Compute shared_secret = X25519(priv_C, pub_S)]
  │                                   │
  │──── ClientProof ─────────────────>│
  │   {HMAC_client}                   │
  │                                   │ [Verify HMAC_client]
  │                                   │
  │                                   │ [Derive session keys via HKDF]
  │<─── SessionConfirm ───────────────│
  │   {HMAC_confirm}                  │
  │                                   │
  │ [Verify HMAC_confirm]             │
  │ [Derive session keys via HKDF]    │
  │                                   │
  │═══════════ ENCRYPTED SESSION ═══════════
```

### 4.2 Форматы сообщений

#### ClientHello (plaintext, перед TLS)

```
Offset  Size  Field              Description
------  ----  -----------------  ------------------------------------------
0       2     Message Type       0x0001 (ClientHello)
2       32    X25519 Public Key  client ephemeral public key
34      8     Timestamp          uint64, milliseconds since epoch
42      16    Nonce Client       random bytes (crypto/rand)
------  ----  -----------------  ------------------------------------------
Total: 58 bytes
```

**Hex example:**
```
0001                                    ← Message Type (ClientHello)
a1b2c3d4e5f6... (32 bytes)             ← X25519 Pub Key
0000018c5a3f2e10                       ← Timestamp (ms)
7f8e9d0c1b2a39485766758493a2b1c0       ← Nonce Client (16 bytes)
```

#### ServerHello (plaintext, перед TLS)

```
Offset  Size  Field              Description
------  ----  -----------------  ------------------------------------------
0       2     Message Type       0x0002 (ServerHello)
2       32    X25519 Public Key  server ephemeral public key
34      16    Nonce Server       random bytes (unique per handshake)
50      32    HMAC Auth          HMAC-SHA256(PSK, "server_prove" || nonce_S || pub_S)
------  ----  -----------------  ------------------------------------------
Total: 82 bytes
```

**HMAC computation:**
```go
message := append([]byte("server_prove"), nonce_S...)
message = append(message, server_pubkey...)
hmac_auth := HMAC-SHA256(PSK, message)
```

#### ClientProof (encrypted after key derivation)

```
Offset  Size  Field              Description
------  ----  -----------------  ------------------------------------------
0       2     Message Type       0x0003 (ClientProof)
2       32    HMAC Client        HMAC-SHA256(PSK, "client_prove" || nonce_C || pub_C)
------  ----  -----------------  ------------------------------------------
Total: 34 bytes (before encryption)
```

#### SessionConfirm (encrypted)

```
Offset  Size  Field              Description
------  ----  -----------------  ------------------------------------------
0       2     Message Type       0x0004 (SessionConfirm)
2       32    HMAC Confirm       HMAC-SHA256(PSK, "session_confirm" || all_nonces_concat)
------  ----  -----------------  ------------------------------------------
Total: 34 bytes (before encryption)
```

**all_nonces_concat:**
```go
all_nonces := append(nonce_C, nonce_S...)
// 16 + 16 = 32 bytes
```

### 4.3 Key Derivation

```go
// После успешного handshake обе стороны вычисляют:

shared_secret := X25519(private_key, peer_public_key)  // 32 bytes

info := []byte("phantom-v2-session")
salt := append(nonce_S, nonce_C...)  // 32 bytes

hkdf := HKDF-SHA256(shared_secret, salt, info)

// Derive keys (порядок важен!)
encryption_key := read 32 bytes from hkdf  // ChaCha20 key
decryption_key := read 32 bytes from hkdf  // ChaCha20 key (для входящих)
```

**Примечание:** encryption_key и decryption_key меняются местами для клиента и сервера:
- Клиент использует `encryption_key` для отправки, `decryption_key` для получения
- Сервер использует `decryption_key` для получения, `encryption_key` для отправки

### 4.4 Replay Protection

```go
// ReplayWindow хранит использованные nonces
type ReplayWindow struct {
    mu       sync.Mutex
    nonces   map[string]int64  // nonce_S -> timestamp
    maxAge   time.Duration      // 5 минут
}

// При получении ServerHello:
func (rw *ReplayWindow) CheckAndAdd(nonce []byte, ts int64) error {
    rw.mu.Lock()
    defer rw.mu.Unlock()
    
    key := string(nonce)
    
    // Проверка на дубликат
    if _, exists := rw.nonces[key]; exists {
        return ErrReplayDetected
    }
    
    // Очистка старых nonces
    cutoff := time.Now().Add(-rw.maxAge).UnixMilli()
    for n, t := range rw.nonces {
        if t < cutoff {
            delete(rw.nonces, n)
        }
    }
    
    rw.nonces[key] = ts
    return nil
}
```

### 4.5 Timing-safe Comparison

```go
import "crypto/subtle"

func VerifyHMAC(expected, received []byte) bool {
    if len(expected) != len(received) {
        return false
    }
    return subtle.ConstantTimeCompare(expected, received) == 1
}
```

---

## 5. ПАРАМЕТРИЧЕСКАЯ МОДЕЛЬ ТРАФИКА (Shaper)

### 5.1 Packet Size Distribution

**Цель:** Имитировать распределение размеров пакетов реального браузера.

```go
// Seed генерируется из PSK один раз при старте сессии
seed := SHA256(PSK)[:8]  // 8 bytes → uint64
rng := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(seed))))

// Функция вычисления размера пакета
func ComputePacketSize(payloadSize int, rng *rand.Rand) int {
    noiseSigma := math.Max(100, float64(payloadSize)*0.15)
    noise := rng.NormFloat64() * noiseSigma
    
    finalSize := int(math.Ceil(float64(payloadSize) + noise))
    
    // Clamp к диапазону
    minSize := payloadSize - 500
    maxSize := payloadSize + 2000
    if finalSize < minSize {
        finalSize = minSize
    }
    if finalSize > maxSize {
        finalSize = maxSize
    }
    
    return finalSize
}

// Примеры:
// payload=500B   → noise_σ=75B   → final≈480-520B
// payload=10KB   → noise_σ=1.5KB → final≈8.5-12KB
// payload=100B   → final≈200-600B (укрытие малых запросов)
```

**Padding вычисление:**
```go
paddingSize := finalSize - payloadSize
if paddingSize > 0 {
    padding := make([]byte, paddingSize)
    rng.Read(padding)  // random bytes
    packet = append(packet, padding...)
}
```

### 5.2 Inter-packet Delay Distribution

**Цель:** Имитировать задержки между пакетами как у человека.

```go
func ComputeInterPacketDelay(payloadLen int, rng *rand.Rand) time.Duration {
    baseDelayMs := 50 + (payloadLen / 1000)
    
    // Exponential distribution with λ=1/100 (mean=100ms)
    lambda := 1.0 / 100.0
    u := rng.Float64()
    jitterMs := -math.Log(1.0-u) / lambda * 1000  // convert to ms
    
    finalDelayMs := math.Max(0, float64(baseDelayMs)+jitterMs)
    
    return time.Duration(finalDelayMs) * time.Millisecond
}

// Примеры:
// payload=500B  → delay = 50-200ms
// payload=50B   → delay = 50-300ms (имитация "думания")
// payload=10KB  → delay = 60-250ms
```

### 5.3 Cover Traffic (Heartbeat)

```go
// Если нет данных >30 сек, отправить heartbeat
const HeartbeatInterval = 30 * time.Second

type Heartbeat struct {
    Mu       sync.Mutex
    LastSent time.Time
    Timer    *time.Timer
}

func (hb *Heartbeat) Start(sendFunc func()) {
    hb.Mu.Lock()
    defer hb.Mu.Unlock()
    
    hb.Timer = time.AfterFunc(HeartbeatInterval, func() {
        hb.Mu.Lock()
        if time.Since(hb.LastSent) >= HeartbeatInterval {
            // Отправить 1-10 bytes random
            size := 1 + rng.Intn(10)
            data := make([]byte, size)
            rng.Read(data)
            sendFunc(data)  // HEARTBEAT packet
        }
        hb.Timer.Reset(HeartbeatInterval)
        hb.Mu.Unlock()
    })
}
```

---

## 6. HTTP/2 FRAMING SIMULATION

### 6.1 Обоснование

DPI следующего поколения (GFW, RKN TSPU) анализирует паттерны внутри TLS records. Без имитации HTTP/2 трафик выглядит как "один длинный поток данных" = аномалия.

**Реальный Chrome HTTPS:**
- TLS Record 1: 50-100 bytes (HEADERS frame)
- TLS Record 2: 500-16000 bytes (DATA frame)
- TLS Record 3: 50-100 bytes (HEADERS frame)
- Соотношение header:data ≈ 1:10

### 6.2 Типы фреймов

| Frame Type | Size Range    | Frequency         | Purpose                    |
|------------|---------------|-------------------|----------------------------|
| HEADERS    | 50-200 bytes  | 1 на 10 DATA      | Имитация HTTP/2 headers    |
| DATA       | payload       | основной трафик   | Полезная нагрузка          |
| SETTINGS   | 18 bytes      | каждые 30 сек     | Keep-alive                 |
| PING       | 8 bytes       | каждые 120 сек    | Connection health check    |

### 6.3 Детерминированная генерация

```go
// Seed из PSK для детерминированной последовательности
frameSeed := SHA256(append(PSK, nonce_C...))
frameRng := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(frameSeed[:8]))))

type FrameType uint8

const (
    FrameHeaders FrameType = 0x01
    FrameData    FrameType = 0x02
    FrameSettings FrameType = 0x03
    FramePing    FrameType = 0x04
)

func GenerateFrameType(frameCount int, rng *rand.Rand) FrameType {
    // Каждые 10 фреймов — HEADERS
    if frameCount%10 == 0 {
        return FrameHeaders
    }
    
    // Основной трафик — DATA
    return FrameData
}

func GenerateFrameSize(frameType FrameType, payloadSize int, rng *rand.Rand) int {
    switch frameType {
    case FrameHeaders:
        return 50 + rng.Intn(151)  // 50-200 bytes
        
    case FrameData:
        return payloadSize
        
    case FrameSettings:
        return 18  // fixed
        
    case FramePing:
        return 8  // fixed
        
    default:
        return payloadSize
    }
}
```

### 6.4 TLS Record Size Distribution

**Бимодальное распределение:**
- Mode 1 (маленькие): 50-200 bytes (~10% фреймов)
- Mode 2 (большие): 500-16000 bytes (~90% фреймов)

```go
func GenerateTLSRecordSize(rng *rand.Rand) int {
    // 10% chance small, 90% chance large
    if rng.Float64() < 0.1 {
        return 50 + rng.Intn(151)  // small: 50-200
    }
    return 500 + rng.Intn(15501)   // large: 500-16000
}
```

### 6.5 Структура HTTP/2 Frame (симуляция)

```
Для каждого payload packet создаётся "pseudo-HTTP/2 frame":

HEADERS frame:
  Offset  Size  Field           Description
  ------  ----  --------------  ----------------------------------
  0       1     Frame Type      0x01
  1       3     Length          big-endian uint24
  4       1     Flags           0x04 (END_HEADERS)
  5       4     Stream ID       0x00000001 (stream 1)
  9       N     Header Block    HPACK-encoded headers (симуляция)
  
  Пример симулированных headers:
    :method: GET
    :path: /api/data
    :authority: your.server.com
    user-agent: Mozilla/5.0 ...
    accept: application/json

DATA frame:
  Offset  Size  Field           Description
  ------  ----  --------------  ----------------------------------
  0       1     Frame Type      0x02
  1       3     Length          big-endian uint24
  4       1     Flags           0x00 or 0x01 (END_STREAM)
  5       4     Stream ID       0x00000001
  9       N     Data            encrypted payload

SETTINGS frame (every 30s):
  Offset  Size  Field           Description
  ------  ----  --------------  ----------------------------------
  0       1     Frame Type      0x04
  1       3     Length          0x000000
  4       1     Flags           0x00
  5       4     Stream ID       0x00000000
  9       18    Settings        стандартные HTTP/2 settings

PING frame (every 120s):
  Offset  Size  Field           Description
  ------  ----  --------------  ----------------------------------
  0       1     Frame Type      0x06
  1       3     Length          0x000008
  4       1     Flags           0x00
  5       4     Stream ID       0x00000000
  9       8     Payload         random 8 bytes
```

### 6.6 Интеграция с Packet Shaper

```go
type HTTP2Framer struct {
    rng         *rand.Rand
    frameCount  int
    lastSettings time.Time
    lastPing    time.Time
}

func (f *HTTP2Framer) WrapPayload(payload []byte) ([]byte, error) {
    f.frameCount++
    
    // Проверка на SETTINGS/PING таймеры
    now := time.Now()
    if now.Sub(f.lastSettings) >= 30*time.Second {
        f.lastSettings = now
        return f.generateSettingsFrame(), nil
    }
    if now.Sub(f.lastPing) >= 120*time.Second {
        f.lastPing = now
        return f.generatePingFrame(), nil
    }
    
    // Выбор типа фрейма
    frameType := GenerateFrameType(f.frameCount, f.rng)
    
    // Вычисление размера с noise
    frameSize := GenerateFrameSize(frameType, len(payload), f.rng)
    paddingSize := frameSize - len(payload)
    
    // Сборка фрейма
    frame := make([]byte, 0, frameSize+9)  // 9 bytes header
    frame = append(frame, uint8(frameType))
    frame = append(frame, byte(frameSize>>16), byte(frameSize>>8), byte(frameSize))
    frame = append(frame, 0x00)  // flags
    frame = append(frame, 0x00, 0x00, 0x00, 0x01)  // stream ID
    
    frame = append(frame, payload...)
    
    // Add padding
    if paddingSize > 0 {
        padding := make([]byte, paddingSize)
        f.rng.Read(padding)
        frame = append(frame, padding...)
    }
    
    return frame, nil
}
```

---

## 7. TLS FINGERPRINT (JA4 Rotation)

### 7.1 Три профиля

**Профиль выбирается детерминировано из PSK:**
```go
sessionID := SHA256(PSK)
profileIdx := sessionID[0] % 3  // 0, 1, или 2
```

### 7.2 Профиль 1: Chrome 125 on Linux

```yaml
tls_version: TLS 1.3
cipher_suites:
  - 0x1302  # TLS_AES_256_GCM_SHA384
  - 0x1303  # TLS_CHACHA20_POLY1305_SHA256
  - 0x1301  # TLS_AES_128_GCM_SHA256
extensions:
  - 0x0000  # server_name
  - 0x000b  # ec_point_formats
  - 0x000a  # supported_groups (x25519, secp256r1)
  - 0x0023  # session_ticket
  - 0x0010  # alpn (h2, http/1.1)
  - 0x0005  # status_request
  - 0x0017  # extended_master_secret
  - 0xff01  # renegotiation_info
supported_groups:
  - 0x001d  # x25519
  - 0x0017  # secp256r1
  - 0x001e  # secp384r1
ec_point_formats:
  - 0x00  # uncompressed

JA4 Signature: t13d1516h2_8daaf6152771_002f3c
```

### 7.3 Профиль 2: Safari 17.3 on macOS

```yaml
tls_version: TLS 1.3
cipher_suites:
  - 0x1302  # TLS_AES_256_GCM_SHA384
  - 0x1301  # TLS_AES_128_GCM_SHA256
  - 0x1303  # TLS_CHACHA20_POLY1305_SHA256
extensions:
  - 0x0000  # server_name
  - 0x0017  # extended_master_secret
  - 0x000b  # ec_point_formats
  - 0x000a  # supported_groups
  - 0x0010  # alpn (h2, http/1.1)
  - 0x0005  # status_request
supported_groups:
  - 0x001d  # x25519
  - 0x0017  # secp256r1
ec_point_formats:
  - 0x00  # uncompressed

JA4 Signature: t13d0d11h2_5bca8a8e5c5e_002f3c
```

### 7.4 Профиль 3: Edge 125 on Windows

```yaml
tls_version: TLS 1.3
cipher_suites:
  - 0x1302  # TLS_AES_256_GCM_SHA384
  - 0x1303  # TLS_CHACHA20_POLY1305_SHA256
  - 0x1301  # TLS_AES_128_GCM_SHA256
extensions:
  - 0x0000  # server_name
  - 0x000b  # ec_point_formats
  - 0x000a  # supported_groups
  - 0x0023  # session_ticket
  - 0x0010  # alpn (h2, http/1.1)
  - 0x0005  # status_request
  - 0x0017  # extended_master_secret
  - 0xff01  # renegotiation_info
  - 0x002b  # psk_key_exchange_modes
supported_groups:
  - 0x001d  # x25519
  - 0x0017  # secp256r1
  - 0x001e  # secp384r1
ec_point_formats:
  - 0x00  # uncompressed

JA4 Signature: t13d1617h2_8daaf6152771_e5f69d45
```

### 7.5 Реализация TLS Config

```go
func GetTLSProfile(psk []byte) *tls.Config {
    profileIdx := sha256.Sum256(psk)[0] % 3
    
    switch profileIdx {
    case 0:
        return chrome125Config()
    case 1:
        return safari17Config()
    case 2:
        return edge125Config()
    default:
        return chrome125Config()
    }
}

func chrome125Config() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        CipherSuites: []uint16{
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
            tls.TLS_AES_128_GCM_SHA256,
        },
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
            tls.CurveP384,
        },
        Extensions: []uint16{
            0x0000, 0x000b, 0x000a, 0x0023,
            0x0010, 0x0005, 0x0017, 0xff01,
        },
    }
}
```

---

## 8. МАРКЕР ПЕРЕКЛЮЧЕНИЯ В ENCRYPTED MODE

### 8.1 Обоснование

Первые 2 КБ трафика должны выглядеть как легитимный HTTPS:
1. TLS handshake
2. HTTP GET / (маскарад)
3. HTTP Response (статический сайт)

После успешного handshake клиент отправляет маркер, и сервер переключается в tunnel mode.

### 8.2 Маркер

```
Маркер: 4 байта
Hex: 0xFF 0xAA 0xBB 0xCC
Конфигурируемый параметр в YAML
```

### 8.3 Протокол переключения

```
Client                              Server
  │                                   │
  │─── TLS Handshake ────────────────>│
  │   (JA4 profile visible)           │
  │                                   │
  │─── HTTP GET / ───────────────────>│
  │   Host: your.server.com           │
  │                                   │
  │<── HTTP 200 OK ───────────────────│
  │   Content-Type: text/html         │
  │   (статический сайт)              │
  │                                   │
  │─── Marker (0xFFAABBCC) ──────────>│
  │   [4 bytes plaintext]             │
  │                                   │
  │                                   │ [Detect marker]
  │                                   │ [Switch to tunnel mode]
  │                                   │
  │<── ACK (encrypted) ───────────────│
  │   [First encrypted packet]        │
  │                                   │
  │═══════ ENCRYPTED TUNNEL ══════════
```

### 8.4 Детекция маркера на сервере

```go
const Marker = "\xFF\xAA\xBB\xCC"
const MaskModeBytes = 2048  // первые 2KB в mask mode

type ConnectionState struct {
    mu            sync.Mutex
    mode          ConnMode  // MaskMode или TunnelMode
    bytesReceived int
    markerBuf     []byte
}

type ConnMode uint8

const (
    MaskMode ConnMode = iota
    TunnelMode
)

func (cs *ConnectionState) ProcessIncoming(data []byte) ([]byte, error) {
    cs.mu.Lock()
    defer cs.mu.Unlock()
    
    if cs.mode == TunnelMode {
        // Уже в tunnel mode, decrypt
        return cs.decrypt(data)
    }
    
    // Mask mode: проверить на маркер
    cs.markerBuf = append(cs.markerBuf, data...)
    cs.bytesReceived += len(data)
    
    // Проверить наличие маркера
    if bytes.Contains(cs.markerBuf, []byte(Marker)) {
        cs.mode = TunnelMode
        // Всё после маркера — encrypted
        markerIdx := bytes.Index(cs.markerBuf, []byte(Marker))
        encryptedData := cs.markerBuf[markerIdx+4:]
        return cs.decrypt(encryptedData)
    }
    
    // Пока без маркера — обработать как HTTP
    if cs.bytesReceived > MaskModeBytes {
        // Превышен лимит, закрыть соединение (подозрительно)
        return nil, ErrMaskModeExceeded
    }
    
    // Обработать как HTTP запрос
    return cs.handleHTTPRequest(cs.markerBuf)
}
```

---

## 9. ФОРМАТ ЗАШИФРОВАННОГО ПАКЕТА

### 9.1 Структура

```
После переключения в tunnel mode все пакеты имеют формат:

Offset  Size  Field              Description
------  ----  -----------------  ------------------------------------------
0       4     Packet Length      big-endian uint32, включает всё ниже
4       1     Packet Type        0x01=DATA, 0x02=HEARTBEAT, 0x03=CLOSE
5       N     Encrypted Payload  ChaCha20-Poly1305 encrypted
N       16    Poly1305 Tag       authentication tag
------  ----  -----------------  ------------------------------------------

Максимальный размер: 16384 bytes (TLS record limit)
```

### 9.2 Типы пакетов

| Type | Name      | Description                        |
|------|-----------|------------------------------------|
| 0x01 | DATA      | Полезные данные (прокси трафик)    |
| 0x02 | HEARTBEAT | Cover traffic (1-10 bytes random)  |
| 0x03 | CLOSE     | Graceful connection close          |

### 9.3 Шифрование

```go
// ChaCha20-Poly1305 AEAD
func EncryptPacket(key []byte, nonce []byte, packetType uint8, payload []byte) ([]byte, error) {
    aead, err := chacha20poly1305.New(key)
    if err != nil {
        return nil, err
    }
    
    // Assemble plaintext: type + payload
    plaintext := append([]byte{packetType}, payload...)
    
    // Encrypt
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)
    
    // Prepend length
    length := uint32(len(ciphertext) + 1)  // +1 for type byte
    buf := make([]byte, 4, 4+len(ciphertext))
    binary.BigEndian.PutUint32(buf, length)
    buf = append(buf, ciphertext...)
    
    return buf, nil
}

func DecryptPacket(key []byte, nonce []byte, data []byte) (uint8, []byte, error) {
    if len(data) < 4 {
        return 0, nil, ErrInvalidPacket
    }
    
    length := binary.BigEndian.Uint32(data[:4])
    if len(data) < 4+int(length) {
        return 0, nil, ErrIncompletePacket
    }
    
    aead, err := chacha20poly1305.New(key)
    if err != nil {
        return 0, nil, err
    }
    
    ciphertext := data[4 : 4+length]
    plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return 0, nil, ErrAuthenticationFailed
    }
    
    packetType := plaintext[0]
    payload := plaintext[1:]
    
    return packetType, payload, nil
}
```

### 9.4 Nonce Management

```go
// Nonce должен быть уникальным для каждого пакета
type NonceGenerator struct {
    mu    sync.Mutex
    count uint64
}

func (ng *NonceGenerator) Next() []byte {
    ng.mu.Lock()
    defer ng.mu.Unlock()
    
    nonce := make([]byte, 12)  // ChaCha20 nonce = 12 bytes
    binary.BigEndian.PutUint64(nonce[4:], ng.count)
    ng.count++
    
    // Первые 4 bytes можно использовать для random
    if ng.count == 1 {
        crypto.rand.Read(nonce[:4])
    }
    
    return nonce
}
```

---

## 10. HONEYPOT DETECTION

### 10.1 Тест 1: Certificate Pinning

```go
// Ожидаемый hash сертификата в конфиге клиента
expectedCertHash := "sha256:abcdef123456..."

func VerifyCertificate(cert *x509.Certificate, expectedHash string) bool {
    certDER := cert.Raw
    hash := sha256.Sum256(certDER)
    actualHash := hex.EncodeToString(hash[:])
    
    return actualHash == expectedHash
}
```

### 10.2 Тест 2: Timing Analysis

```go
func MeasureResponseTime(conn net.Conn) (time.Duration, bool) {
    start := time.Now()
    
    // Отправить HTTP GET
    _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))
    if err != nil {
        return 0, false
    }
    
    // Читать первый байт ответа
    buf := make([]byte, 1)
    conn.SetReadDeadline(time.Now().Add(60 * time.Second))
    _, err = conn.Read(buf)
    
    elapsed := time.Since(start)
    
    if err != nil {
        return elapsed, false
    }
    
    // Проверка на подозрительно быстрый ответ (<5ms)
    if elapsed < 5*time.Millisecond {
        return elapsed, false  // Подозрительно быстро (honeypot)
    }
    
    // Нормальный диапазон: 20-500ms
    return elapsed, true
}
```

### 10.3 Тест 3: Response Fingerprinting

```go
func TestHoneypotResponse(conn net.Conn) bool {
    // Отправить non-standard path
    randomPath := fmt.Sprintf("/zzz_%x", cryptoRandBytes(8))
    request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: test\r\n\r\n", randomPath)
    
    conn.Write([]byte(request))
    
    // Читать статус
    reader := bufio.NewReader(conn)
    line, err := reader.ReadString('\n')
    if err != nil {
        return false  // Ошибка соединения
    }
    
    // Парсить статус код
    // Ожидается: HTTP/1.1 404 Not Found
    if strings.Contains(line, "404") {
        return true  // Нормальный сайт
    }
    
    // 403/451/redirect → honeypot
    if strings.Contains(line, "403") ||
       strings.Contains(line, "451") ||
       strings.Contains(line, "301") ||
       strings.Contains(line, "302") {
        return false  // Honeypot detected
    }
    
    return true  // По умолчанию считать нормальным
}
```

### 10.4 Тест 4: Certificate Validity

```go
func VerifyCertificateAuthority(cert *x509.Certificate) bool {
    // Проверка, что сертификат от Let's Encrypt или другой стандартной CA
    roots := x509.NewCertPool()
    
    // Добавить стандартные root CA
    roots.AppendCertsFromPEM(letsEncryptRootCA)
    roots.AppendCertsFromPEM(digiCertRootCA)
    // ...
    
    opts := x509.VerifyOptions{
        Roots: roots,
    }
    
    _, err := cert.Verify(opts)
    return err == nil
}
```

### 10.5 Интеграция в клиент

```go
func (c *Client) ConnectAndVerify() error {
    conn, err := tls.Dial("tcp", c.config.Server, c.tlsConfig)
    if err != nil {
        return err
    }
    
    // Тест 1: Certificate pinning
    if !VerifyCertificate(conn.ConnectionState().PeerCertificates[0], c.expectedCertHash) {
        return ErrHoneypotCertMismatch
    }
    
    // Тест 2: Timing
    elapsed, ok := MeasureResponseTime(conn)
    if !ok || elapsed < 5*time.Millisecond {
        return ErrHoneypotTiming
    }
    
    // Тест 3: Response fingerprinting
    if !TestHoneypotResponse(conn) {
        return ErrHoneypotResponse
    }
    
    // Тест 4: CA validation
    if !VerifyCertificateAuthority(conn.ConnectionState().PeerCertificates[0]) {
        return ErrHoneypotUnknownCA
    }
    
    return nil
}
```

---

## 11. АДАПТИВНОЕ УКЛОНЕНИЕ (Evasion)

### 11.1 Сигналы блокировки

| Signal              | Detection Method                    | Action                      |
|---------------------|-------------------------------------|-----------------------------|
| TCP RST             | Connection reset by peer            | Switch mode, rotate profile |
| Timeout >5s         | Previous packets OK, new fail       | Increase cover traffic      |
| HTTP 403/451        | Explicit block response             | Switch mode                 |
| DNS poisoning       | Resolve returns 127.0.0.1/etc       | Use hardcoded IP            |

### 11.2 State Machine

```
                    ┌─────────────┐
                    │   Mode A    │
                    │  Direct TCP │
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    [TCP RST]         [Timeout]         [403/451]
         │                 │                 │
         ▼                 ▼                 ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │   Mode B    │  │   Mode B    │  │   Mode B    │
    │CF Workers   │  │CF Workers   │  │CF Workers   │
    └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
           │                │                │
           │          [CF blocked]           │
           │                │                │
           ▼                ▼                ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │   Mode C    │  │   Mode C    │  │   Mode C    │
    │  WebSocket  │  │  WebSocket  │  │  WebSocket  │
    └─────────────┘  └─────────────┘  └─────────────┘
```

### 11.3 Profile Rotation

```go
func (c *Client) RotateProfile(failureCount int) {
    // session_id_hash_v2 = SHA256(PSK || failure_count)
    input := append(c.psk, byte(failureCount))
    hash := sha256.Sum256(input)
    
    newProfileIdx := hash[0] % 3
    c.tlsConfig = GetTLSProfileByIndex(newProfileIdx)
}
```

### 11.4 Adaptive Cover Traffic

```go
func (c *Client) AdjustCoverTraffic(blockageDetected bool) {
    if blockageDetected {
        // Увеличить частоту heartbeat до 10 сек
        c.heartbeatInterval = 10 * time.Second
    } else {
        // Нормальный режим: 30 сек
        c.heartbeatInterval = 30 * time.Second
    }
}
```

---

## 12. РАЗДЕЛЕНИЕ КОДА (МОДУЛИ)

```
phantom-v2/
├── cmd/
│   ├── server/
│   │   └── main.go              # Server entry point
│   └── client/
│       └── main.go              # Client entry point (SOCKS5/TUN)
│
├── internal/
│   ├── common/
│   │   ├── config.go            # YAML parsing
│   │   └── logger.go            # Structured logging (no keys!)
│   │
│   ├── crypto/
│   │   ├── kdf.go               # HKDF-SHA256
│   │   ├── aead.go              # ChaCha20-Poly1305 wrapper
│   │   └── x25519.go            # X25519 key exchange
│   │
│   ├── handshake/
│   │   ├── client.go            # ClientHello, verification
│   │   ├── server.go            # ServerHello, auth
│   │   └── replay_window.go     # Nonce cache, replay protection
│   │
│   ├── transport/
│   │   ├── mode_a.go            # Direct TCP
│   │   ├── mode_b.go            # CF Workers relay
│   │   └── mode_c.go            # WebSocket fallback
│   │
│   ├── framing/
│   │   ├── packet.go            # Packet structure
│   │   ├── http2_frames.go      # HTTP/2 frame simulation
│   │   └── marshal.go           # Serialization
│   │
│   ├── shaper/
│   │   ├── delay.go             # Inter-packet delays
│   │   ├── sizes.go             # Packet size distribution
│   │   ├── http2.go             # HTTP/2 framing distribution
│   │   └── cover.go             # Heartbeat, cover traffic
│   │
│   ├── masquerade/
│   │   ├── static_site.go       # HTTP server с маскарадом
│   │   ├── tls_config.go        # Let's Encrypt, TLS setup
│   │   └── handlers.go          # GET /, 404, etc.
│   │
│   └── evasion/
│       ├── detector.go          # Honeypot detection
│       ├── adaptive.go          # Mode switching logic
│       └── stats.go             # Metrics for adaptive logic
│
├── configs/
│   ├── server.yaml.example
│   └── client.yaml.example
│
├── systemd/
│   ├── phantom-server.service
│   └── phantom-client.service
│
├── go.mod
├── go.sum
└── README.md
```

---

## 13. КОНФИГУРАЦИЯ (YAML SPEC)

### 13.1 Server Config

```yaml
# /etc/phantom/server.yaml

server:
  listen: "0.0.0.0:443"
  tls:
    cert_path: "/etc/phantom/cert.pem"
    key_path: "/etc/phantom/key.pem"
  masquerade_site: "https://example.com"  # Static site для маскировки
  rate_limit: 100  # req/s per IP
  marker: "0xFFAABBCC"  # Маркер переключения в tunnel mode

auth:
  psk:
    - key: "YOUR_PSK_HERE_32_CHARS_MINIMUM_LENGTH"
      name: "user1"
    - key: "ANOTHER_PSK_HERE_ALSO_32_CHARS_MIN"
      name: "user2"

logging:
  level: "info"  # debug, info, warn, error
  # ВАЖНО: никогда не логировать payload или ключи!
```

### 13.2 Client Config

```yaml
# /etc/phantom/client.yaml

client:
  server: "your.server.com:443"
  psk: "YOUR_PSK_HERE_32_CHARS_MINIMUM_LENGTH"
  
  transport:
    mode: "auto"  # auto | tcp_only | cf_workers | websocket
    
    # Cloudflare Workers (Mode B)
    cf_enabled: false
    cf_endpoint: "your-worker-name.your-account.workers.dev"
    
  local:
    socks5: "127.0.0.1:1080"
    tun: false  # true для TUN mode на Linux
  
  evasion:
    enable: true
    retry_delay_ms: [100, 500, 2000]  # Exponential backoff
    max_retries: 5
    
    # Certificate pinning (опционально)
    cert_hash: "sha256:abcdef123456..."
  
  logging:
    level: "warn"  # Только ошибки/варнинги
```

---

## 14. СИСТЕМНЫЕ ТРЕБОВАНИЯ

### 14.1 Сервер

- **OS:** Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **CPU:** 1 core minimum, 2+ recommended
- **RAM:** 256 MB minimum, 512 MB recommended
- **Disk:** 50 MB for binary + configs
- **Network:** Port 443/tcp open

### 14.2 Клиент

- **OS:** Linux, macOS, Windows 10+
- **CPU:** Any modern CPU
- **RAM:** 64 MB minimum
- **Disk:** 20 MB for binary + config

---

## 15. БЕЗОПАСНОСТЬ

### 15.1 Гарантии

1. **Forward Secrecy:** X25519 ephemeral keys, не переиспользуются
2. **Mutual Authentication:** Обе стороны доказывают знание PSK
3. **Replay Protection:** Nonce cache с 5-минутным окном
4. **Timing-Safe:** Constant-time comparison для HMAC
5. **No Key Logging:** Ключи никогда не пишутся в логи

### 15.2 Ограничения

1. **PSK Compromise:** Если PSK украден, злоумышленник может подключиться
2. **Server Compromise:** Если сервер захвачен, вся безопасность теряется
3. **Quantum:** Не quantum-resistant (X25519 vulnerable to Shor's algorithm)

### 15.3 Best Practices

- PSK минимум 32 символа, случайная генерация
- Регулярная ротация PSK (раз в 30 дней)
- Использовать Let's Encrypt сертификаты
- Включить rate limiting на сервере
- Мониторить логи на предмет атак

---

## 16. ДИАГРАММА ПОТОКА ДАННЫХ

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT                                   │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ Browser  │───>│ SOCKS5   │───>│  Shaper  │───>│  Crypto  │  │
│  │          │    │  Proxy   │    │ +HTTP/2  │    │  (AEAD)  │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                  │              │
│                                                  ▼              │
│                                         ┌──────────────┐       │
│                                         │   Network    │       │
│                                         │   (TCP/443)  │       │
│                                         └──────────────┘       │
└─────────────────────────────────────────────────────────────────┘
                                                   │
                                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                         SERVER                                   │
│                                                                  │
│                                         ┌──────────────┐       │
│                                         │   Network    │       │
│                                         │   (TCP/443)  │       │
│                                         └──────────────┘       │
│                                                  │              │
│                                                  ▼              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ Internet │<───│  Relay   │<───│  Crypto  │<───│ Masquerade│ │
│  │ (SOCKS5) │    │ (Tunnel) │    │  (AEAD)  │    │  +Marker │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 17. ТАБЛИЦА ПАРАМЕТРОВ

| Параметр                  | Значение              | Конфигурируемый |
|---------------------------|-----------------------|-----------------|
| Nonce Client Size         | 16 bytes              | No              |
| Nonce Server Size         | 16 bytes              | No              |
| X25519 Public Key Size    | 32 bytes              | No              |
| HMAC Size                 | 32 bytes (SHA256)     | No              |
| HKDF Output Size          | 64 bytes (2x32)       | No              |
| ChaCha20 Key Size         | 32 bytes              | No              |
| ChaCha20 Nonce Size       | 12 bytes              | No              |
| Poly1305 Tag Size         | 16 bytes              | No              |
| Replay Window Max Age     | 5 minutes             | No              |
| Mask Mode Bytes Limit     | 2048 bytes            | Yes (server)    |
| Marker                    | 0xFFAABBCC            | Yes (server)    |
| Heartbeat Interval        | 30 seconds            | Yes (client)    |
| Packet Size Noise σ       | 15% of payload        | No              |
| Base Delay                | 50ms + payload/1000   | No              |
| Delay Jitter λ            | 1/100 (mean=100ms)    | No              |
| HTTP/2 HEADERS Frequency  | 1 per 10 DATA frames  | No              |
| HTTP/2 SETTINGS Interval  | 30 seconds            | No              |
| HTTP/2 PING Interval      | 120 seconds           | No              |
| TLS Profile Count         | 3                     | No              |
| Rate Limit                | 100 req/s per IP      | Yes (server)    |

---

## 18. EDGE CASES

### 18.1 Handshake Failures

| Scenario                | Detection              | Recovery              |
|-------------------------|------------------------|-----------------------|
| Invalid HMAC            | Verification fails     | Close connection      |
| Replay nonce            | Nonce in cache         | Close + log warning   |
| Timeout during handshake| Read deadline exceeded | Retry with backoff    |
| PSK mismatch            | HMAC verification fail | Close connection      |

### 18.2 Tunnel Mode Issues

| Scenario                | Detection              | Recovery              |
|-------------------------|------------------------|-----------------------|
| Marker not detected     | >2KB without marker    | Close (suspicious)    |
| Decryption failure      | Poly1305 auth fail     | Close + rotate keys   |
| Packet too large        | >16384 bytes           | Fragment or drop      |
| Nonce reuse             | Counter collision      | PANIC + reconnect     |

### 18.3 Masquerade Mode

| Scenario                | Detection              | Recovery              |
|-------------------------|------------------------|-----------------------|
| Invalid HTTP request    | Parse error            | Return 400 Bad Request|
| Path traversal attempt  | "../" in path          | Return 403 Forbidden  |
| Rate limit exceeded     | Counter >100/s         | Return 429 Too Many   |
| Unknown method          | Not GET/HEAD/OPTIONS   | Return 405 Method Not |

---

## 19. МОНИТОРИНГ И ЛОГИРОВАНИЕ

### 19.1 Логи сервера

```json
{"level":"info","ts":"2025-01-XX","msg":"Listening on :443"}
{"level":"info","ts":"2025-01-XX","msg":"TLS cert loaded","path":"/etc/phantom/cert.pem"}
{"level":"info","ts":"2025-01-XX","msg":"PSK users loaded","count":2}
{"level":"info","ts":"2025-01-XX","msg":"New connection","remote":"1.2.3.4:54321"}
{"level":"info","ts":"2025-01-XX","msg":"Handshake completed","user":"user1"}
{"level":"warn","ts":"2025-01-XX","msg":"Replay attempt detected","remote":"5.6.7.8:12345"}
{"level":"error","ts":"2025-01-XX","msg":"Decryption failed","reason":"auth_tag_mismatch"}
```

### 19.2 Логи клиента

```json
{"level":"info","ts":"2025-01-XX","msg":"SOCKS5 server started","addr":"127.0.0.1:1080"}
{"level":"info","ts":"2025-01-XX","msg":"Connecting to server","host":"your.server.com:443"}
{"level":"info","ts":"2025-01-XX","msg":"Handshake completed","profile":"chrome125"}
{"level":"warn","ts":"2025-01-XX","msg":"Honeypot detected","test":"timing"}
{"level":"error","ts":"2025-01-XX","msg":"Connection reset","action":"switching to Mode B"}
```

### 19.3 Запрещённые логи

```go
// ❌ НИКОГДА НЕ ДЕЛАТЬ:
log.Printf("PSK: %s", psk)
log.Printf("Payload: %x", payload)
log.Printf("Encryption key: %x", key)
log.Printf("Nonce: %x", nonce)

// ✅ Правильно:
log.Printf("Handshake completed", "user", userName)
log.Printf("Connection closed", "reason", "timeout")
```

---

## 20. CHECKLIST ЭТАПА 1

- [x] Архитектурная диаграмма
- [x] Модель угрозы с HTTP/2 анализом
- [x] Криптографические примитивы (stdlib only)
- [x] Handshake протокол с replay protection
- [x] Форматы сообщений (hex examples)
- [x] Key derivation spec
- [x] Packet size distribution formulas
- [x] Inter-packet delay formulas
- [x] HTTP/2 framing spec с sizes
- [x] TLS JA4 profiles (3 шт)
- [x] Marker switching logic
- [x] Encrypted packet format
- [x] Honeypot detection tests
- [x] Adaptive evasion state machine
- [x] Модульная структура кода
- [x] YAML config spec
- [x] Таблица параметров
- [x] Edge cases
- [x] Monitoring/logging spec
- [x] Security guarantees

---

## 21. СЛЕДУЮЩИЙ ЭТАП

**ЭТАП 2: Криптография + Handshake**

- `internal/crypto/{kdf.go, aead.go, x25519.go}`
- `internal/handshake/{client.go, server.go, replay_window.go}`
- Unit-тесты на 100% coverage
- **STOP** → Проверка security, timing-safety

---

**ВОПРОС:** Продолжать к ЭТАПУ 2?
