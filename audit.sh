#!/usr/bin/env bash
cd "$(dirname "$0")"

echo "===== 1. ServerHelloSize (должно быть 50) ====="
grep -rn "ServerHelloSize" internal/

echo; echo "===== 2. Constant-time PSK loop (ищем break внутри цикла) ====="
grep -B10 -A6 "ConstantTimeCompare" internal/handshake/protocol.go

echo; echo "===== 3. AEAD counter (как устроен) ====="
grep -n -i "counter" internal/crypto/aead.go

echo; echo "===== 4. TODO/FIXME/placeholder ====="
grep -rn -E "TODO|FIXME|XXX|placeholder" --include="*.go" . && echo "^^^ НАЙДЕНО" || echo "clean"

echo; echo "===== 5. ModeA: порядок dial → TLS handshake → phantom handshake ====="
grep -n "func DialModeA\|HandshakeContext\|ApplyPreset\|tlsConn.Write\|performHandshake\|ClientHello" internal/transport/mode_a.go

echo; echo "===== 6. Key wiring (aeadTx должен получить keyC2S) ====="
grep -n "DeriveKeys\|aeadTx\|aeadRx\|keyC2S\|keyS2C" internal/transport/mode_a.go internal/handshake/protocol.go

echo; echo "===== 7. Framing: рандомизация размеров ====="
grep -n -E "IntN|rand\." internal/framing/frames.go | head -20

echo; echo "===== 8. vet ====="
go vet ./... && echo "vet: clean"

echo; echo "===== 9. Coverage все пакеты ====="
go test -count=1 -cover ./internal/... 2>&1

echo; echo "===== 10. Race ====="
go test -race -count=1 ./internal/... 2>&1 | grep -E "FAIL|WARNING|ok "
