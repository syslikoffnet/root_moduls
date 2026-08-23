#!/system/bin/sh
# ==============================================================================
# geo-unblock — точечный обход гео-блокировок через ваш VLESS/SS прокси.
#
# Архитектура (без TUN-интерфейса):
#   приложения -> (iptables mangle, порты 80/443, не-root) пометка 0x40000002
#     * бит 0x40000000: nfqws2 (zapret2) эти пакеты НЕ трогает
#     * бит 0x2: policy routing -> local table -> TPROXY в sing-box:7893
#   sing-box по SNI: домен из domains.list -> VLESS/SS прокси (наружу с меткой
#     0x40000000, минуя nfqws2); всё остальное -> direct-исход (без метки,
#     nfqws2 применяет обход DPI как обычно).
#
# FAIL-OPEN: любая ошибка/сбой прокси -> правила снимаются МГНОВЕННО,
# весь трафик уходит напрямую; интернет не пропадает ни на секунду.
# ==============================================================================
umask 077

MODDIR="${0%/*}"
case "$MODDIR" in /*) ;; *) MODDIR="$(cd "$MODDIR" 2>/dev/null && pwd)" ;; esac
DATA_DIR=/data/adb/geo-unblock
BIN_CANDIDATES="$DATA_DIR/bin/sing-box $MODDIR/bin/sing-box"
DOMAINS="$DATA_DIR/domains.list"
PROXY_URI_FILE="$DATA_DIR/proxy.uri"
PROXY_JSON_FILE="$DATA_DIR/proxy.outbound.json"
DISABLE_FLAG="$DATA_DIR/disabled"
RUN="$MODDIR/run"
WORK="$RUN/singbox"
LOG_DIR="$MODDIR/logs"
LOG="$LOG_DIR/geo-unblock.log"
CORE_PID_FILE="$RUN/singbox.pid"
STATE_FILE="$RUN/state.env"

TPROXY_PORT=7893
REDIRECT_PORT=7894
MIXED_PORT=7890
MARK_SKIP=0x40000000
MARK_TPROXY=0x2
MARK_FULL=0x40000002
TABLE=2025
RULE_PREF=30000
HEALTH_INTERVAL=45
FAIL_THRESHOLD=2
TEST_URL="https://cp.cloudflare.com/generate_204"
Z2_CURL=/data/adb/modules/zapret2-android/bin/curl
Z2_CA=/data/adb/modules/zapret2-android/bin/curl-cacert.pem

mkdir -p "$RUN" "$LOG_DIR" "$WORK" 2>/dev/null
chmod 0700 "$RUN" "$LOG_DIR" "$WORK" 2>/dev/null || true
[ -f "$DOMAINS" ] || cp -f "$MODDIR/domains.list.default" "$DOMAINS" 2>/dev/null

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }
log_i(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" >> "$LOG"; }
log_w(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >> "$LOG"; }
log_e(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >> "$LOG"; }

IPT=$(command -v iptables 2>/dev/null); [ -n "$IPT" ] || IPT=/system/bin/iptables
IP6T=$(command -v ip6tables 2>/dev/null); [ -n "$IP6T" ] || IP6T=/system/bin/ip6tables
IP_BIN=$(command -v ip 2>/dev/null); [ -n "$IP_BIN" ] || IP_BIN=/system/bin/ip
ipt4(){ "$IPT" -w 5 "$@" >/dev/null 2>&1; }
ipt6(){ [ -x "$IP6T" ] && "$IP6T" -w 5 "$@" >/dev/null 2>&1; }

MODE=""        # tproxy | redirect
CORE_PID=""

write_state() {
  printf 'STATE=%s\nMODE=%s\nPID=%s\nUPDATED=%s\n' "${1:-unknown}" "${MODE:-none}" "${CORE_PID:-0}" "$(date +%s 2>/dev/null)" > "$STATE_FILE.tmp.$$" 2>/dev/null \
    && mv -f "$STATE_FILE.tmp.$$" "$STATE_FILE" 2>/dev/null
}

# ------------------------------------------------------------------------------
# Транспорт для проверки здоровья: curl из бандла zapret2 или busybox wget.
# ------------------------------------------------------------------------------
http_via_proxy() {
  if [ -x "$Z2_CURL" ]; then
    CURL_CA_BUNDLE="$Z2_CA" "$Z2_CURL" -s -m 8 -x "http://127.0.0.1:$MIXED_PORT" -o /dev/null -w '%{http_code}' "$TEST_URL" 2>/dev/null | grep -q '^2'
    return
  fi
  local b
  for b in "$(command -v busybox 2>/dev/null)" /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
    [ -x "$b" ] || continue
    https_proxy="http://127.0.0.1:$MIXED_PORT" "$b" wget -q -T 8 -O /dev/null "$TEST_URL" 2>/dev/null && return 0
    return 1
  done
  return 1
}

# ------------------------------------------------------------------------------
# JSON-помощники (значения проходят жёсткую валидацию по символам).
# ------------------------------------------------------------------------------
jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
valid_host() { case "$1" in ''|*[!A-Za-z0-9.-]*) return 1 ;; *) return 0 ;; esac; }
valid_port() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null; }
valid_uuid() { case "$1" in ''|*[!A-Za-z0-9-]*) return 1 ;; *) return 0 ;; esac; }

b64d() {
  local s="$1" pad
  s=$(printf '%s' "$s" | tr '_-' '/+')
  pad=$(( (4 - ${#s} % 4) % 4 ))
  [ "$pad" -ne 0 ] && s="$s$(printf '%*s' "$pad" '' | tr ' ' '=')"
  printf '%s' "$s" | base64 -d 2>/dev/null
}

urld() {
  # decode %XX портируемо (printf %b в dash не знает \xHH)
  printf '%s' "$1" | awk '
    BEGIN { for (i = 0; i < 256; i++) h[sprintf("%02x", i)] = i }
    {
      gsub(/\+/, " ")
      out = ""; s = $0
      while (match(s, /%[0-9a-fA-F][0-9a-fA-F]/)) {
        out = out substr(s, 1, RSTART - 1) sprintf("%c", h[tolower(substr(s, RSTART + 1, 2))])
        s = substr(s, RSTART + 3)
      }
      printf "%s", out s
    }'
}

qparam() {
  # регистронезависимо: в ссылках встречаются и sni=, и SNI=, и sID=
  printf '%s' "$QUERY" | tr '&' '\n' | awk -v k="$1" 'tolower(substr($0,1,length(k)+1)) == tolower(k)"=" {print substr($0,length(k)+2); exit}'
}

# Готовый outbound из строки URI. Пишет валидный JSON в $1.
build_outbound() {
  local out="$1" uri scheme rest cred host port
  if [ -s "$PROXY_JSON_FILE" ]; then
    grep -q '"server"' "$PROXY_JSON_FILE" 2>/dev/null || { log_e "proxy.outbound.json не содержит \"server\""; return 1; }
    cp -f "$PROXY_JSON_FILE" "$out"
    return 0
  fi
  [ -s "$PROXY_URI_FILE" ] || { log_e "нет $PROXY_URI_FILE и нет $PROXY_JSON_FILE — прокси не настроен"; return 1; }
  uri=$(head -n1 "$PROXY_URI_FILE" | tr -d '[:space:]')
  scheme=${uri%%://*}; rest=${uri#*://}
  case "$scheme" in
    ss)   build_ss "$out" "$rest" ;;
    vless) build_vless "$out" "$rest" ;;
    *) log_e "неподдерживаемая схема '$scheme' (нужен vless:// или ss://)"; return 1 ;;
  esac
}

build_ss() {
  local out="$1" rest="$2" body dec method pass hostport host port
  body=${rest%%#*}
  if printf '%s' "$body" | grep -q '@'; then
    hostport=${body##*@}
    dec=$(b64d "${body%%@*}")
  else
    dec=$(b64d "$body"); hostport=${dec##*@}; dec=${dec%%@*}
  fi
  method=${dec%%:*}; pass=${dec#*:}
  host=${hostport%%:*}; port=${hostport##*:}
  valid_host "$host" && valid_port "$port" || { log_e "ss:// некорректный host/port"; return 1; }
  case "$method" in ''|*[!A-Za-z0-9-]*) log_e "ss:// некорректный метод"; return 1 ;; esac
  [ -n "$pass" ] || { log_e "ss:// нет пароля"; return 1; }
  cat > "$out" <<EOJ
{"type":"shadowsocks","tag":"proxy","server":"$(jesc "$host")","server_port":$port,"method":"$(jesc "$method")","password":"$(jesc "$pass")","dialer":{"routing_mark":$((0x40000000))}}
EOJ
  return 0
}

build_vless() {
  local out="$1" rest="$2" uuid hostport host port security sni fp pbk sid trans thost tpath svc flow skipinv
  uuid=${rest%%@*}; hostport=$(printf '%s' "$rest" | sed -n 's/^[^@]*@\([^?]*\).*/\1/p')
  QUERY=$(printf '%s' "$rest" | sed -n 's/^[^?]*?//p' | sed 's/#.*//')
  host=${hostport%%:*}; port=${hostport##*:}
  valid_uuid "$uuid" && valid_host "$host" && valid_port "$port" || { log_e "vless:// некорректные uuid/host/port"; return 1; }
  security=$(qparam security); sni=$(qparam sni); fp=$(qparam fp)
  pbk=$(qparam pbk); sid=$(qparam sid)
  trans=$(qparam type); [ -n "$trans" ] || trans=tcp
  thost=$(qparam host); tpath=$(qparam path); svc=$(qparam serviceName)
  flow=$(qparam flow); skipinv=$(qparam allowInsecure)

  local j="{\"type\":\"vless\",\"tag\":\"proxy\",\"server\":\"$(jesc "$host")\",\"server_port\":$port,\"uuid\":\"$(jesc "$uuid")\""
  [ -n "$flow" ] && j="$j,\"flow\":\"$(jesc "$flow")\""
  case "$security" in
    tls|reality)
      j="$j,\"tls\":{\"enabled\":true"
      [ -n "$sni" ] && j="$j,\"server_name\":\"$(jesc "$sni")\""
      [ "$skipinv" = "1" ] && j="$j,\"insecure\":true"
      if [ -n "$fp" ]; then j="$j,\"utls\":{\"enabled\":true,\"fingerprint\":\"$(jesc "$fp")\"}"; fi
      if [ "$security" = "reality" ]; then
        [ -n "$pbk" ] || { log_e "vless reality без pbk (public key) — ссылка неполная"; return 1; }
        j="$j,\"reality\":{\"enabled\":true,\"public_key\":\"$(jesc "$pbk")\""
        [ -n "$sid" ] && j="$j,\"short_id\":\"$(jesc "$sid")\""
        j="$j}"
      fi
      j="$j}"
      ;;
    none|'') ;;
    *) log_w "vless: security=$security не распознан — TLS не включаю" ;;
  esac
  case "$trans" in
    ws)
      j="$j,\"transport\":{\"type\":\"ws\""
      [ -n "$tpath" ] && j="$j,\"path\":\"$(jesc "$(urld "$tpath")")\""
      [ -n "$thost" ] && j="$j,\"headers\":{\"Host\":\"$(jesc "$thost")\"}"
      j="$j}"
      ;;
    grpc)
      j="$j,\"transport\":{\"type\":\"grpc\""
      [ -n "$svc" ] && j="$j,\"service_name\":\"$(jesc "$svc")\""
      j="$j}"
      ;;
    tcp) ;;
    *) log_w "vless: transport $trans не поддерживается парсером — использую tcp (или proxy.outbound.json)" ;;
  esac
  j="$j,\"dialer\":{\"routing_mark\":$((0x40000000))}}"
  printf '%s\n' "$j" > "$out"
  return 0
}

# ------------------------------------------------------------------------------
# Сборка полного конфига sing-box.
# ------------------------------------------------------------------------------
gen_config() {
  local ob="$WORK/outbound.json" dom_json
  build_outbound "$ob" || return 1
  dom_json=$(grep -vE '^[[:space:]]*(#|$)' "$DOMAINS" 2>/dev/null | sed 's/[[:space:]]//g' | grep -E '^[A-Za-z0-9.-]+$' | sort -u | awk 'BEGIN{s=""} {s=s (s?",":"") "\"" $0 "\""} END{print s}')
  [ -n "$dom_json" ] || { log_e "domains.list пуст — нечего заворачивать в прокси"; return 1; }
  cat > "$WORK/config.json" <<EOJ
{
  "log": {"level": "warn", "output": "$WORK/singbox.log", "timestamp": true},
  "inbounds": [
    {"type": "tproxy",   "tag": "tproxy-in",   "listen": "::", "listen_port": $TPROXY_PORT, "network": "tcp"},
    {"type": "redirect", "tag": "redirect-in", "listen": "::", "listen_port": $REDIRECT_PORT, "network": "tcp"},
    {"type": "mixed",    "tag": "mixed-in",    "listen": "127.0.0.1", "listen_port": $MIXED_PORT}
  ],
  "outbounds": [
    $(cat "$ob"),
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [
      {"action": "sniff"},
      {"domain_suffix": [$dom_json], "outbound": "proxy"},
      {"ip_is_private": true, "outbound": "direct"}
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOJ
  return 0
}

# ------------------------------------------------------------------------------
# Ядро sing-box.
# ------------------------------------------------------------------------------
find_core() {
  local b
  for b in $BIN_CANDIDATES; do [ -x "$b" ] && { printf '%s' "$b"; return 0; }; done
  return 1
}

core_alive() {
  [ -n "$CORE_PID" ] && kill -0 "$CORE_PID" 2>/dev/null
}

start_core() {
  local core
  core=$(find_core) || { log_e "sing-box не найден ($DATA_DIR/bin/sing-box) — см. инструкцию в README"; return 1; }
  gen_config || return 1
  "$core" check -c "$WORK/config.json" >> "$LOG" 2>&1 || {
    log_e "sing-box check: конфиг невалиден (проверьте proxy.uri / domains.list); детали:"
    tail -n 5 "$WORK/singbox.log" >> "$LOG" 2>/dev/null
    "$core" check -c "$WORK/config.json" 2>&1 | tail -n 3 >> "$LOG"
    return 1
  }
  : > "$WORK/singbox.log" 2>/dev/null
  if command -v setsid >/dev/null 2>&1; then
    setsid "$core" run -D "$WORK" -c "$WORK/config.json" >> "$LOG" 2>&1 &
    CORE_PID=$!
  else
    "$core" run -D "$WORK" -c "$WORK/config.json" >> "$LOG" 2>&1 &
    CORE_PID=$!
  fi
  echo "$CORE_PID" > "$CORE_PID_FILE"
  # готовность: прокси-тест через mixed-порт, до 20 секунд
  local n=0
  while [ "$n" -lt 10 ]; do
    core_alive || { log_e "sing-box умер сразу; последние строки:"; tail -n 5 "$WORK/singbox.log" >> "$LOG"; return 1; }
    http_via_proxy && { log_i "sing-box запущен (PID $CORE_PID) и прокси отвечает"; return 0; }
    sleep 2; n=$((n + 1))
  done
  log_w "sing-box запущен, но прокси не ответил за 20с (проверьте сервер/ссылку)"
  return 0
}

stop_core() {
  if [ -n "$CORE_PID" ] && kill -0 "$CORE_PID" 2>/dev/null; then
    kill -TERM "$CORE_PID" 2>/dev/null
    local n=0
    while kill -0 "$CORE_PID" 2>/dev/null && [ "$n" -lt 20 ]; do sleep 0.1; n=$((n + 1)); done
    kill -0 "$CORE_PID" 2>/dev/null && kill -9 "$CORE_PID" 2>/dev/null
  fi
  CORE_PID=""
  rm -f "$CORE_PID_FILE" 2>/dev/null
}

# ------------------------------------------------------------------------------
# Правила. FAIL-OPEN: снимаются одной функцией, любые ошибки не фатальны.
# ------------------------------------------------------------------------------
GEO_OUT=GEO_OUT_CHAIN
GEO_TPR=GEO_TPROXY_CHAIN
GEO_RDR=GEO_REDIRECT_CHAIN

cleanup_rules() {
  ipt4 -t mangle -D OUTPUT -j "$GEO_OUT"
  ipt4 -t mangle -F "$GEO_OUT"; ipt4 -t mangle -X "$GEO_OUT"
  ipt4 -t mangle -D PREROUTING -j "$GEO_TPR"
  ipt4 -t mangle -F "$GEO_TPR"; ipt4 -t mangle -X "$GEO_TPR"
  ipt4 -t nat -D OUTPUT -j "$GEO_RDR"
  ipt4 -t nat -F "$GEO_RDR"; ipt4 -t nat -X "$GEO_RDR"
  ipt6 -t mangle -D OUTPUT -j "$GEO_OUT"
  ipt6 -t mangle -F "$GEO_OUT"; ipt6 -t mangle -X "$GEO_OUT"
  ipt6 -t mangle -D PREROUTING -j "$GEO_TPR"
  ipt6 -t mangle -F "$GEO_TPR"; ipt6 -t mangle -X "$GEO_TPR"
  ipt6 -t nat -D OUTPUT -j "$GEO_RDR"
  ipt6 -t nat -F "$GEO_RDR"; ipt6 -t nat -X "$GEO_RDR"
  "$IP_BIN" -4 rule del pref "$RULE_PREF" fwmark "$MARK_TPROXY/$MARK_TPROXY" 2>/dev/null
  "$IP_BIN" -6 rule del pref "$RULE_PREF" fwmark "$MARK_TPROXY/$MARK_TPROXY" 2>/dev/null
  "$IP_BIN" -4 route flush table "$TABLE" 2>/dev/null
  "$IP_BIN" -6 route flush table "$TABLE" 2>/dev/null
  return 0
}

apply_rules() {
  cleanup_rules
  # --- общая цепочка пометки: локальные/приватные и WARP не трогаем ---
  local mark="$MARK_FULL"
  [ "$1" = redirect ] && mark="$MARK_SKIP"
  ipt4 -t mangle -N "$GEO_OUT" || return 1
  ipt6 -t mangle -N "$GEO_OUT" 2>/dev/null
  for dst in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4 255.255.255.255/32; do
    ipt4 -t mangle -A "$GEO_OUT" -d "$dst" -j RETURN
  done
  ipt4 -t mangle -A "$GEO_OUT" -o "${WARP_DEV:-awg99}" -j RETURN
  ipt4 -t mangle -A "$GEO_OUT" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner 0 -m mark --mark 0 -j MARK --set-mark "$mark"
  ipt4 -t mangle -I OUTPUT 1 -j "$GEO_OUT"
  ipt6 -t mangle -A "$GEO_OUT" -d fc00::/7 -j RETURN 2>/dev/null
  ipt6 -t mangle -A "$GEO_OUT" -d fe80::/10 -j RETURN 2>/dev/null
  ipt6 -t mangle -A "$GEO_OUT" -o "${WARP_DEV:-awg99}" -j RETURN 2>/dev/null
  ipt6 -t mangle -A "$GEO_OUT" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner 0 -m mark --mark 0 -j MARK --set-mark "$mark" 2>/dev/null
  ipt6 -t mangle -I OUTPUT 1 -j "$GEO_OUT" 2>/dev/null

  if [ "$1" = redirect ]; then
    # --- режим REDIRECT (нет xt_TPROXY): только TCP, nat OUTPUT ---
    ipt4 -t nat -N "$GEO_RDR" || return 1
    ipt4 -t nat -A "$GEO_RDR" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner 0 -m mark --mark 0 -j REDIRECT --to-port "$REDIRECT_PORT"
    ipt4 -t nat -I OUTPUT 1 -j "$GEO_RDR"
    ipt6 -t nat -N "$GEO_RDR" 2>/dev/null
    ipt6 -t nat -A "$GEO_RDR" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner 0 -m mark --mark 0 -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null
    ipt6 -t nat -I OUTPUT 1 -j "$GEO_RDR" 2>/dev/null
    MODE=redirect
    log_i "правила применены: режим REDIRECT (TCP) — TPROXY в ядре недоступен"
    return 0
  fi

  # --- основной режим TPROXY ---
  ipt4 -t mangle -N "$GEO_TPR" || return 1
  if ipt4 -t mangle -A "$GEO_TPR" -i lo -p tcp -m multiport --dports 80,443 -m mark --mark "$MARK_TPROXY/$MARK_TPROXY" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_TPROXY/$MARK_TPROXY"; then
    ipt4 -t mangle -I PREROUTING 1 -j "$GEO_TPR"
    ipt6 -t mangle -N "$GEO_TPR" 2>/dev/null
    ipt6 -t mangle -A "$GEO_TPR" -i lo -p tcp -m multiport --dports 80,443 -m mark --mark "$MARK_TPROXY/$MARK_TPROXY" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_TPROXY/$MARK_TPROXY" 2>/dev/null
    ipt6 -t mangle -I PREROUTING 1 -j "$GEO_TPR" 2>/dev/null
    "$IP_BIN" -4 route add local default dev lo table "$TABLE" 2>/dev/null
    "$IP_BIN" -6 route add local default dev lo table "$TABLE" 2>/dev/null
    "$IP_BIN" -4 rule add pref "$RULE_PREF" fwmark "$MARK_TPROXY/$MARK_TPROXY" table "$TABLE" 2>/dev/null
    "$IP_BIN" -6 rule add pref "$RULE_PREF" fwmark "$MARK_TPROXY/$MARK_TPROXY" table "$TABLE" 2>/dev/null
    MODE=tproxy
    log_i "правила применены: режим TPROXY (TCP, v4+v6)"
    return 0
  fi
  # TPROXY не поддержан — откат на REDIRECT
  ipt4 -t mangle -F "$GEO_TPR" 2>/dev/null; ipt4 -t mangle -X "$GEO_TPR" 2>/dev/null
  log_w "xt_TPROXY недоступен — переключаюсь на REDIRECT"
  apply_rules redirect
}

rules_present() {
  ipt4 -t mangle -C OUTPUT -j "$GEO_OUT" 2>/dev/null || ipt4 -t nat -C OUTPUT -j "$GEO_RDR" 2>/dev/null
}

# ------------------------------------------------------------------------------
# Жизненный цикл.
# ------------------------------------------------------------------------------
stop_all() {
  local had_rules=0
  rules_present && had_rules=1
  cleanup_rules
  stop_core
  # не затираем диагностические состояния no-proxy/no-binary при пустом старте
  [ "$had_rules" = 1 ] && write_state stopped
  log_i "остановлен, правила сняты (трафик прямой)"
}

start_all() {
  [ -f "$DISABLE_FLAG" ] && { log_i "выключен флагом $DISABLE_FLAG"; exit 0; }
  local core
  core=$(find_core) || { log_e "sing-box не установлен — модуль в режиме ожидания (см. README)"; write_state "no-binary"; exit 0; }
  [ -s "$PROXY_URI_FILE" ] || [ -s "$PROXY_JSON_FILE" ] || {
    log_e "прокси не настроен: положите vless://… или ss://… в $PROXY_URI_FILE (одной строкой)"
    write_state "no-proxy"
    exit 0
  }
  start_core || { stop_core; write_state "config-error"; exit 1; }
  if ! rules_present; then
    apply_rules tproxy || apply_rules redirect || { cleanup_rules; write_state "rules-error"; log_e "не удалось применить правила — трафик прямой"; return 1; }
  fi
  write_state running
}

watchdog() {
  local failures=0 last_dom_sig="" dom_sig
  last_dom_sig=$(cksum "$DOMAINS" 2>/dev/null | awk '{print $1}')
  log_i "watchdog запущен (интервал ${HEALTH_INTERVAL}s, fail-open)"
  while :; do
    sleep "$HEALTH_INTERVAL"
    dom_sig=$(cksum "$DOMAINS" 2>/dev/null | awk '{print $1}')
    if [ -n "$dom_sig" ] && [ "$dom_sig" != "$last_dom_sig" ]; then
      last_dom_sig="$dom_sig"
      log_i "domains.list изменён — перечитываю и перезапускаю ядро (трафик на это время прямой)"
      cleanup_rules; stop_core
      start_core && { apply_rules tproxy || apply_rules redirect; }
      write_state running
      failures=0
      continue
    fi
    if ! core_alive; then
      failures=$((failures + 1))
      log_w "sing-box не отвечает (нет процесса), попытка $failures"
      if [ "$failures" -ge "$FAIL_THRESHOLD" ]; then
        rules_present && cleanup_rules
        stop_core; start_core && { apply_rules tproxy || apply_rules redirect; }
        write_state "${CORE_PID:+running}"
        failures=0
      fi
      continue
    fi
    if ! rules_present; then
      log_w "правила исчезли (внешнее вмешательство?) — восстанавливаю"
      apply_rules tproxy || apply_rules redirect
      write_state running
      continue
    fi
    if http_via_proxy; then
      failures=0
      write_state running
    else
      failures=$((failures + 1))
      log_w "прокси не проходит проверку ($failures/$FAIL_THRESHOLD)"
      if [ "$failures" -ge "$FAIL_THRESHOLD" ]; then
        # FAIL-OPEN: снимаем правила мгновенно — интернет (прямой) жив
        cleanup_rules
        log_w "fail-open: маршрутизация в прокси снята, весь трафик прямой; перезапускаю ядро"
        stop_core
        start_core && { apply_rules tproxy || apply_rules redirect; write_state running; }
        failures=0
        write_state "${CORE_PID:+degraded}"
      fi
    fi
  done
}

status() {
  echo "state=$(sed -n 's/^STATE=//p' "$STATE_FILE" 2>/dev/null | head -n1)"
  echo "mode=$(sed -n 's/^MODE=//p' "$STATE_FILE" 2>/dev/null | head -n1)"
  echo "core_pid=$(cat "$CORE_PID_FILE" 2>/dev/null)"
  echo "rules_v4=$(ipt4 -t mangle -C OUTPUT -j "$GEO_OUT" 2>/dev/null && echo yes || ipt4 -t nat -C OUTPUT -j "$GEO_RDR" 2>/dev/null && echo yes-redirect || echo no)"
  echo "domains=$(grep -cvE '^[[:space:]]*(#|$)' "$DOMAINS" 2>/dev/null)"
  echo "proxy=$([ -s "$PROXY_URI_FILE" ] && echo "uri" || { [ -s "$PROXY_JSON_FILE" ] && echo json || echo none; })"
  echo "binary=$(find_core || echo none)"
  echo "health_now=$(http_via_proxy >/dev/null 2>&1 && echo OK || echo FAIL)"
}

case "${1:-boot}" in
  boot)
    trap 'stop_all' TERM INT
    trap 'stop_all' EXIT
    n=0
    until [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] || [ "$n" -ge 150 ]; do sleep 2; n=$((n + 1)); done
    sleep 20   # дать zapret2 первым поставить свои цепочки
    start_all
    watchdog
    ;;
  start|restart)
    trap 'stop_all' TERM INT
    cleanup_rules; stop_core
    start_all
    watchdog
    ;;
  stop)
    stop_all
    ;;
  apply)
    apply_rules tproxy || apply_rules redirect
    ;;
  status) status ;;
  *) echo "Использование: $0 [start|stop|restart|status|apply]"; exit 2 ;;
esac
