#!/system/bin/sh
# ==============================================================================
# geo-unblock — точечный обход гео-блокировок через VLESS/SS/Hysteria2/Trojan.
#
# Два режима:
#   manual — своя ссылка в /data/adb/geo-unblock/proxy.uri (приоритет);
#   auto   — подписки из /data/adb/geo-unblock/subscriptions.list: модуль сам
#            скачивает списки нод, разделяет их по классу сети (wifi/mobile/all)
#            и собирает urltest-группу: sing-box сам меряет задержку каждой
#            ноды ЧЕРЕЗ ТЕКУЩУЮ сеть и переключается на лучшую. Сменили
#            WiFi на мобилку — тесты уйдут в новую сеть, выбор пересоберётся.
#
# Архитектура (без TUN):
#   приложения -> (iptables mangle, порты 80/443, не-root) метка 0x40000002
#     * бит 0x40000000: nfqws2 (zapret2) эти пакеты не трогает; в filter OUTPUT
#       помеченный трафик принимается раньше QUIC-REJECT zapret2 (нужно для
#       hysteria2 на UDP/443);
#     * бит 0x2: policy routing -> local table -> TPROXY в sing-box:7893.
#   sing-box по SNI: домен из domains.list -> urltest/лучшая нода; остальное ->
#   direct (без метки -> nfqws2 применяет DPI-обход как обычно).
#
# FAIL-OPEN: сбой прокси/нод -> правила снимаются мгновенно, весь трафик
# прямой. Интернет не пропадает ни на секунду.
# ==============================================================================
umask 077

MODDIR="${0%/*}"
case "$MODDIR" in /*) ;; *) MODDIR="$(cd "$MODDIR" 2>/dev/null && pwd)" ;; esac
DATA_DIR=/data/adb/geo-unblock
DOMAINS="$DATA_DIR/domains.list"
SUBS="$DATA_DIR/subscriptions.list"
PROXY_URI_FILE="$DATA_DIR/proxy.uri"
PROXY_JSON_FILE="$DATA_DIR/proxy.outbound.json"
DISABLE_FLAG="$DATA_DIR/disabled"
APPS_MODE_FILE="$DATA_DIR/apps.mode"
APPS_LIST_FILE="$DATA_DIR/apps.list"
MANUAL_NODES="$DATA_DIR/nodes-manual.list"
# Рантим и логи — ВНЕ каталога модуля (переживают обновление, и конфиг с
# паролями нод не хранится внутри module-dir, доступного на чтение шире).
RUN="$DATA_DIR/run"
WORK="$RUN/singbox"
LOG_DIR="$DATA_DIR/logs"
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
HEALTH_INTERVAL=90
FAIL_THRESHOLD=3
MAX_NODES=40
SUB_REFRESH_SEC=21600
TEST_URL="https://cp.cloudflare.com/generate_204"
Z2_CURL=/data/adb/modules/zapret2-android/bin/curl
Z2_CA=/data/adb/modules/zapret2-android/bin/curl-cacert.pem

mkdir -p "$RUN" "$LOG_DIR" "$WORK" 2>/dev/null
chmod 0700 "$DATA_DIR" "$RUN" "$LOG_DIR" "$WORK" 2>/dev/null || true
[ -f "$DOMAINS" ] || cp -f "$MODDIR/domains.list.default" "$DOMAINS" 2>/dev/null
[ -f "$SUBS" ] || cp -f "$MODDIR/subscriptions.list.default" "$SUBS" 2>/dev/null

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }
log_i(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" >> "$LOG"; }
log_w(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >> "$LOG"; }
log_e(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >> "$LOG"; }

IPT=$(command -v iptables 2>/dev/null); [ -n "$IPT" ] || IPT=/system/bin/iptables
IP6T=$(command -v ip6tables 2>/dev/null); [ -n "$IP6T" ] || IP6T=/system/bin/ip6tables
IP_BIN=$(command -v ip 2>/dev/null); [ -n "$IP_BIN" ] || IP_BIN=/system/bin/ip
ipt4(){ "$IPT" -w 5 "$@" >/dev/null 2>&1; }
ipt6(){ [ -x "$IP6T" ] && "$IP6T" -w 5 "$@" >/dev/null 2>&1; }

MODE=""          # tproxy | redirect (транспорт правил)
PROXY_MODE=""    # manual | auto
NETWORK_CLASS="" # wifi | mobile | all
NODES_COUNT=0
CORE_PID=""

write_state() {
  printf 'STATE=%s\nMODE=%s\nPROXY=%s\nCLASS=%s\nNODES=%s\nPID=%s\nUPDATED=%s\n' \
    "${1:-unknown}" "${MODE:-none}" "${PROXY_MODE:-none}" "${NETWORK_CLASS:-none}" \
    "${NODES_COUNT:-0}" "${CORE_PID:-0}" "$(date +%s 2>/dev/null)" > "$STATE_FILE.tmp.$$" 2>/dev/null \
    && mv -f "$STATE_FILE.tmp.$$" "$STATE_FILE" 2>/dev/null
}

now_epoch() { date +%s 2>/dev/null || echo 0; }

# ------------------------------------------------------------------------------
# Класс текущей сети: wifi / mobile / all.
# ------------------------------------------------------------------------------
network_class() {
  local dev
  dev=$("$IP_BIN" -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
  case "$dev" in
    wlan*|wifi*|swlan*) echo wifi ;;
    rmnet*|ccmni*|pdp*|wwan*|usb*|rndis*|ncm*) echo mobile ;;
    *) echo all ;;
  esac
}

# ------------------------------------------------------------------------------
# Скачивание и парсинг подписок.
# ------------------------------------------------------------------------------
fetch_url() {
  local t=${FETCH_TIMEOUT:-60}
  if [ -x "$Z2_CURL" ]; then
    CURL_CA_BUNDLE="$Z2_CA" "$Z2_CURL" -sSL --max-time "$t" "$1" 2>/dev/null
    return
  fi
  if command -v curl >/dev/null 2>&1; then
    curl -sSL --max-time "$t" "$1" 2>/dev/null
    return
  fi
  local b
  for b in "$(command -v busybox 2>/dev/null)" /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
    [ -x "$b" ] || continue
    "$b" wget -q -T "$t" -O - "$1" 2>/dev/null && return 0
    return 1
  done
  return 1
}

# Кандидаты источника одной подписки: оригинал -> jsdelivr-зеркало -> GitHub API.
# raw.githubusercontent.com у ряда российских провайдеров недоступен, поэтому
# каждый файл тянется по первому работающему каналу из трёх независимых.
sub_url_candidates() {
  printf '%s\n' "$1"
  case "$1" in
    https://raw.githubusercontent.com/*)
      local p owner repo rest br path
      p=${1#https://raw.githubusercontent.com/}
      owner=${p%%/*}; rest=${p#*/}; repo=${rest%%/*}; rest=${rest#*/}
      br=${rest%%/*}; path=${rest#*/}
      [ -n "$owner" ] && [ -n "$repo" ] && [ -n "$br" ] && [ -n "$path" ] && {
        printf 'https://cdn.jsdelivr.net/gh/%s/%s@%s/%s\n' "$owner" "$repo" "$br" "$path"
        printf 'API:%s|%s|%s|%s\n' "$owner" "$repo" "$br" "$path"
      }
      ;;
  esac
}

sub_fetch() { # $1=url -> содержимое файла в stdout (или rc=1)
  local u raw b64 owner repo br path
  while IFS= read -r u; do
    case "$u" in
      API:*)
        u=${u#API:}; owner=${u%%|*}; u=${u#*|}; repo=${u%%|*}; u=${u#*|}; br=${u%%|*}; path=${u#*|}
        raw=$(FETCH_TIMEOUT=15 fetch_url "https://api.github.com/repos/$owner/$repo/contents/$path?ref=$br")
        b64=$(printf '%s' "$raw" | sed -n 's/.*"content"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed 's/\\n//g')
        [ -n "$b64" ] && printf '%s' "$b64" | base64 -d 2>/dev/null && return 0
        ;;
      *)
        raw=$(FETCH_TIMEOUT=15 fetch_url "$u")
        [ -n "$raw" ] && { printf '%s' "$raw"; return 0; }
        ;;
    esac
  done <<EOC
$(sub_url_candidates "$1")
EOC
  return 1
}

extract_uris() {
  grep -aE '^(vless|ss|hysteria2|trojan)://' 2>/dev/null | tr -d '\r' | awk 'NF && !seen[$0]++'
}

# Скачивает все подписки и раскладывает ноды по классам в кэш DATA_DIR/nodes-*.list
refresh_nodes() {
  local line cls url tmp_all raw count
  [ -s "$SUBS" ] || { log_i "подписки не настроены ($SUBS)"; return 1; }
  date +%s > "$RUN/last-refresh.ts" 2>/dev/null
  tmp_all="$WORK/subs.$$"
  : > "$tmp_all" 2>/dev/null || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$line" in ''|'#'*) continue ;; esac
    cls=$(printf '%s' "$line" | awk '{print $1}')
    url=$(printf '%s' "$line" | awk '{print $2}')
    case "$cls" in wifi|mobile|all) ;; *) cls=all; url="$line" ;; esac
    case "$url" in http://*|https://*) ;; *) continue ;; esac
    murl=$(printf '%s' "$url" | sed 's/\?.*//')   # токены подписки не пишем в лог
    raw=$(sub_fetch "$url")
    if [ -n "$raw" ]; then
      uris=$(printf '%s' "$raw" | extract_uris)
      if [ -z "$uris" ]; then
        # формат подписки Happ/панелей: весь ответ — base64 от списка ссылок
        uris=$(printf '%s' "$raw" | tr -d '\n\r' | base64 -d 2>/dev/null | extract_uris)
      fi
      if [ -n "$uris" ]; then
        count=$(printf '%s' "$uris" | tee -a "$tmp_all.$cls" | wc -l)
        log_i "подписка [$cls] $murl: нод $count"
      else
        log_w "подписка [$cls] $murl: ссылок vless/ss/hysteria2/trojan не найдено"
      fi
    else
      log_w "подписка [$cls] $murl не скачалась (сохраняю старый кэш)"
    fi
  done < "$SUBS"
  local c total=0
  for c in wifi mobile all; do
    if [ -s "$tmp_all.$c" ]; then
      extract_uris < "$tmp_all.$c" > "$DATA_DIR/nodes-$c.list"
    fi
    [ -f "$DATA_DIR/nodes-$c.list" ] || : > "$DATA_DIR/nodes-$c.list"
    total=$((total + $(wc -l < "$DATA_DIR/nodes-$c.list" 2>/dev/null || echo 0)))
  done
  rm -f "$tmp_all" "$tmp_all.wifi" "$tmp_all.mobile" "$tmp_all.all" 2>/dev/null
  log_i "кэш нод обновлён: всего $total (wifi=$(wc -l < "$DATA_DIR/nodes-wifi.list" 2>/dev/null) mobile=$(wc -l < "$DATA_DIR/nodes-mobile.list" 2>/dev/null) all=$(wc -l < "$DATA_DIR/nodes-all.list" 2>/dev/null))"
  [ "$total" -gt 0 ]
}

nodes_for_class() {
  case "$1" in
    wifi) cat "$DATA_DIR/nodes-wifi.list" "$DATA_DIR/nodes-all.list" 2>/dev/null ;;
    mobile) cat "$DATA_DIR/nodes-mobile.list" "$DATA_DIR/nodes-all.list" 2>/dev/null ;;
    *) cat "$DATA_DIR/nodes-wifi.list" "$DATA_DIR/nodes-mobile.list" "$DATA_DIR/nodes-all.list" 2>/dev/null ;;
  esac | cat - "$MANUAL_NODES" 2>/dev/null | awk 'NF && !seen[$0]++' | head -n "$MAX_NODES"
}

# Режим отбора приложений: all | exclude | include. apps.list — UID'ы.
app_mode() {
  local m
  m=$(cat "$APPS_MODE_FILE" 2>/dev/null)
  case "$m" in all|exclude|include) printf '%s' "$m" ;; *) printf 'all' ;; esac
}
app_uids() {
  awk 'NF && !seen[$0]++' "$APPS_LIST_FILE" 2>/dev/null | while IFS= read -r u; do
    case "$u" in ''|*[!0-9]*) continue ;; esac
    [ "$u" -le 65535 ] 2>/dev/null && printf '%s\n' "$u"
  done
}

# ------------------------------------------------------------------------------
# Транспорт для проверки здоровья.
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
# JSON-помощники.
# ------------------------------------------------------------------------------
jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
valid_host() { case "$1" in ''|*[!A-Za-z0-9.-]*) return 1 ;; *) return 0 ;; esac; }
valid_port() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null; }
valid_token() { case "$1" in '') return 1 ;; *) return 0 ;; esac; }

b64d() {
  local s="$1" pad
  s=$(printf '%s' "$s" | tr '_-' '/+')
  pad=$(( (4 - ${#s} % 4) % 4 ))
  [ "$pad" -ne 0 ] && s="$s$(printf '%*s' "$pad" '' | tr ' ' '=')"
  printf '%s' "$s" | base64 -d 2>/dev/null
}

urld() {
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
  printf '%s' "$QUERY" | tr '&' '\n' | awk -v k="$1" 'tolower(substr($0,1,length(k)+1)) == tolower(k)"=" {print substr($0,length(k)+2); exit}'
}

# parse_uri <файл-результата> <tag> <uri>
parse_uri() {
  local out="$1" tag="$2" uri="$3" scheme rest
  scheme=${uri%%://*}; rest=${uri#*://}
  case "$scheme" in
    vless)      build_vless "$out" "$rest" "$tag" ;;
    ss)         build_ss "$out" "$rest" "$tag" ;;
    hysteria2)  build_hys2 "$out" "$rest" "$tag" ;;
    trojan)     build_trojan "$out" "$rest" "$tag" ;;
    vmess)      return 1 ;;
    *) return 1 ;;
  esac
}

split_hostport() {
  # $1=hostport -> HOST/PORT; срезает хвостовой '/' (hysteria2://host:443/?..)
  hostport=${hostport%/}
  host=${hostport%%:*}; port=${hostport##*:}
}

build_ss() {
  local out="$1" rest="$2" tag="$3" body dec method pass hostport host port
  body=${rest%%#*}
  if printf '%s' "$body" | grep -q '@'; then
    hostport=${body##*@}
    case "${body%%@*}" in
      *:*) dec=${body%%@*} ;;                       # SIP002 открытый: method:pass@host:port
      *) dec=$(b64d "${body%%@*}") ;;               # base64(method:pass)@host:port
    esac
  else
    dec=$(b64d "$body"); hostport=${dec##*@}; dec=${dec%%@*}
  fi
  method=${dec%%:*}; pass=${dec#*:}
  split_hostport
  valid_host "$host" && valid_port "$port" || return 1
  case "$method" in ''|*[!A-Za-z0-9-]*) return 1 ;; esac
  valid_token "$pass" || return 1
  cat > "$out" <<EOJ
{"type":"shadowsocks","tag":"$tag","server":"$(jesc "$host")","server_port":$port,"method":"$(jesc "$method")","password":"$(jesc "$pass")","dialer":{"routing_mark":1073741824}}
EOJ
  return 0
}

build_vless() {
  local out="$1" rest="$2" tag="$3" uuid hostport host port security sni fp pbk sid trans thost tpath svc flow skipinv
  uuid=${rest%%@*}; hostport=$(printf '%s' "$rest" | sed -n 's/^[^@]*@\([^?]*\).*/\1/p')
  QUERY=$(printf '%s' "$rest" | sed -n 's/^[^?]*?//p' | sed 's/#.*//')
  split_hostport
  case "$uuid" in ''|*[!A-Za-z0-9-]*) return 1 ;; esac
  valid_host "$host" && valid_port "$port" || return 1
  security=$(qparam security); sni=$(qparam sni); fp=$(qparam fp)
  pbk=$(qparam pbk); sid=$(qparam sid)
  trans=$(qparam type); [ -n "$trans" ] || trans=tcp
  case "$trans" in raw) trans=tcp ;; esac
  thost=$(qparam host); tpath=$(qparam path)
  svc=$(qparam serviceName); [ -n "$svc" ] || svc=$(qparam servicename)
  flow=$(qparam flow); skipinv=$(qparam allowInsecure)
  [ -z "$skipinv" ] && skipinv=$(qparam insecure)

  local j="{\"type\":\"vless\",\"tag\":\"$tag\",\"server\":\"$(jesc "$host")\",\"server_port\":$port,\"uuid\":\"$(jesc "$uuid")\""
  [ -n "$flow" ] && j="$j,\"flow\":\"$(jesc "$flow")\""
  case "$security" in
    tls|reality)
      j="$j,\"tls\":{\"enabled\":true"
      [ -n "$sni" ] && j="$j,\"server_name\":\"$(jesc "$sni")\""
      [ "$skipinv" = "1" ] && j="$j,\"insecure\":true"
      if [ -n "$fp" ]; then j="$j,\"utls\":{\"enabled\":true,\"fingerprint\":\"$(jesc "$fp")\"}"; fi
      if [ "$security" = "reality" ]; then
        [ -n "$pbk" ] || return 1
        j="$j,\"reality\":{\"enabled\":true,\"public_key\":\"$(jesc "$pbk")\""
        [ -n "$sid" ] && j="$j,\"short_id\":\"$(jesc "$sid")\""
        j="$j}"
      fi
      j="$j}"
      ;;
    none|false|"") ;;
    *) ;;
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
    *) return 1 ;;   # xhttp и прочее — Xray-only
  esac
  j="$j,\"dialer\":{\"routing_mark\":1073741824}}"
  printf '%s\n' "$j" > "$out"
  return 0
}

build_hys2() {
  local out="$1" rest="$2" tag="$3" pass hostport host port sni skipinv obfs obfspw j
  pass=${rest%%@*}; hostport=$(printf '%s' "$rest" | sed -n 's/^[^@]*@\([^?]*\).*/\1/p')
  QUERY=$(printf '%s' "$rest" | sed -n 's/^[^?]*?//p' | sed 's/#.*//')
  split_hostport
  valid_host "$host" && valid_port "$port" || return 1
  valid_token "$pass" || return 1
  sni=$(qparam sni); [ -n "$sni" ] || sni="$host"
  skipinv=$(qparam allowInsecure); [ -z "$skipinv" ] && skipinv=$(qparam insecure)
  obfs=$(qparam obfs); obfspw=$(qparam obfs-password)
  j="{\"type\":\"hysteria2\",\"tag\":\"$tag\",\"server\":\"$(jesc "$host")\",\"server_port\":$port,\"password\":\"$(jesc "$(urld "$pass")")\""
  j="$j,\"tls\":{\"enabled\":true,\"server_name\":\"$(jesc "$sni")\",\"alpn\":[\"h3\"]"
  [ "$skipinv" = "1" ] && j="$j,\"insecure\":true"
  j="$j}"
  if [ "$obfs" = "salamander" ] && [ -n "$obfspw" ]; then
    j="$j,\"obfs\":{\"type\":\"salamander\",\"password\":\"$(jesc "$obfspw")\"}"
  fi
  j="$j,\"dialer\":{\"routing_mark\":1073741824}}"
  printf '%s\n' "$j" > "$out"
  return 0
}

build_trojan() {
  local out="$1" rest="$2" tag="$3" pass hostport host port sni skipinv j trans thost tpath svc
  pass=$(urld "${rest%%@*}")
  hostport=$(printf '%s' "$rest" | sed -n 's/^[^@]*@\([^?]*\).*/\1/p')
  QUERY=$(printf '%s' "$rest" | sed -n 's/^[^?]*?//p' | sed 's/#.*//')
  split_hostport
  valid_host "$host" && valid_port "$port" || return 1
  valid_token "$pass" || return 1
  sni=$(qparam sni); [ -n "$sni" ] || sni="$host"
  skipinv=$(qparam allowInsecure); [ -z "$skipinv" ] && skipinv=$(qparam insecure)
  j="{\"type\":\"trojan\",\"tag\":\"$tag\",\"server\":\"$(jesc "$host")\",\"server_port\":$port,\"password\":\"$(jesc "$pass")\""
  j="$j,\"tls\":{\"enabled\":true,\"server_name\":\"$(jesc "$sni")\""
  [ "$skipinv" = "1" ] && j="$j,\"insecure\":true"
  j="$j}"
  trans=$(qparam type); case "$trans" in raw) trans=tcp ;; esac
  case "$trans" in
    ws)
      thost=$(qparam host); tpath=$(qparam path)
      j="$j,\"transport\":{\"type\":\"ws\""
      [ -n "$tpath" ] && j="$j,\"path\":\"$(jesc "$(urld "$tpath")")\""
      [ -n "$thost" ] && j="$j,\"headers\":{\"Host\":\"$(jesc "$thost")\"}"
      j="$j}"
      ;;
    grpc)
      svc=$(qparam serviceName); [ -n "$svc" ] || svc=$(qparam servicename)
      j="$j,\"transport\":{\"type\":\"grpc\""
      [ -n "$svc" ] && j="$j,\"service_name\":\"$(jesc "$svc")\""
      j="$j}"
      ;;
  esac
  j="$j,\"dialer\":{\"routing_mark\":1073741824}}"
  printf '%s\n' "$j" > "$out"
  return 0
}

# Секрет Clash-API (ручной пинг нод из WebUI). Один раз генерируется.
clash_secret() {
  local f="$RUN/clash.secret" sec
  if [ -s "$f" ]; then cat "$f" 2>/dev/null; return 0; fi
  sec=$(tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 24)
  [ "${#sec}" -ge 16 ] || sec="geo$RANDOM$RANDOM$RANDOM$RANDOM"
  printf '%s' "$sec" > "$f" 2>/dev/null && chmod 0600 "$f" 2>/dev/null
  printf '%s' "$sec"
}

# ------------------------------------------------------------------------------
# Сборка конфига sing-box: manual (одна нода) или auto (urltest-группа).
# ------------------------------------------------------------------------------
gen_config() {
  local dom_json outbounds="$WORK/outbounds.json" frag="$WORK/node.json" uri tag
  dom_json=$(grep -vE '^[[:space:]]*(#|$)' "$DOMAINS" 2>/dev/null | sed 's/[[:space:]]//g' | grep -E '^[A-Za-z0-9.-]+$' | sort -u | awk 'BEGIN{s=""} {s=s (s?",":"") "\"" $0 "\""} END{print s}')
  [ -n "$dom_json" ] || { log_e "domains.list пуст"; return 1; }

  rm -f "$outbounds"
  if [ -s "$PROXY_JSON_FILE" ] || [ -s "$PROXY_URI_FILE" ]; then
    PROXY_MODE=manual
    NODES_COUNT=1
    if [ -s "$PROXY_JSON_FILE" ]; then
      grep -q '"server"' "$PROXY_JSON_FILE" 2>/dev/null || { log_e "proxy.outbound.json без \"server\""; return 1; }
      { printf '{"tag":"proxy",'; sed 's/^{//' "$PROXY_JSON_FILE"; } > "$outbounds"
    else
      parse_uri "$frag" proxy "$(head -n1 "$PROXY_URI_FILE" | tr -d '[:space:]')" || { log_e "proxy.uri не разобралась"; return 1; }
      cat "$frag" > "$outbounds"
    fi
    printf ',\n{"type":"direct","tag":"direct"}\n' >> "$outbounds"
  else
    PROXY_MODE=auto
    NETWORK_CLASS=$(network_class)
    local nodes i=0 ok_cnt=0 skip_cnt=0 tags=""
    nodes=$(nodes_for_class "$NETWORK_CLASS")
    if [ -z "$nodes" ]; then
      lr=$(cat "$RUN/last-refresh.ts" 2>/dev/null)
      case "$lr" in ''|*[!0-9]*) lr=0 ;; esac
      if [ $(( $(now_epoch) - lr )) -ge 600 ] 2>/dev/null; then
        refresh_nodes || true
      else
        log_w "подписки качались менее 10 мин назад — не дёргаю чаще (см. run/last-refresh.ts)"
      fi
      nodes=$(nodes_for_class "$NETWORK_CLASS")
    fi
    [ -n "$nodes" ] || { log_e "нет нод для класса '$NETWORK_CLASS' (подписки не скачались?)"; return 1; }
    while IFS= read -r uri; do
      [ -n "$uri" ] || continue
      i=$((i + 1))
      tag="node_$i"
      if parse_uri "$frag" "$tag" "$uri"; then
        [ "$ok_cnt" -gt 0 ] && printf ',\n' >> "$outbounds"
        cat "$frag" >> "$outbounds"
        tags="$tags\"$tag\","
        ok_cnt=$((ok_cnt + 1))
      else
        skip_cnt=$((skip_cnt + 1))
      fi
    done <<EOU
$nodes
EOU
    [ "$ok_cnt" -gt 0 ] || { log_e "ни одна нода не разобралась ($skip_cnt пропущено)"; return 1; }
    NODES_COUNT=$ok_cnt
    [ "$skip_cnt" -gt 0 ] && log_i "нод разобрано $ok_cnt, пропущено $skip_cnt (vmess/xhttp/битые)"
    tags=${tags%,}
    {
      printf '{"type":"urltest","tag":"proxy","outbounds":[%s],"url":"%s","interval":"300s","tolerance":150,"idle_timeout":"2m"},\n' "$tags" "$TEST_URL"
      cat "$outbounds"
      printf ',\n{"type":"direct","tag":"direct"}\n'
    } > "$outbounds.new"
    mv -f "$outbounds.new" "$outbounds"
    log_i "режим auto: класс сети '$NETWORK_CLASS', нод в urltest: $ok_cnt"
  fi

  cat > "$WORK/config.json" <<EOJ
{
  "log": {"level": "warn", "output": "$WORK/singbox.log", "timestamp": true},
  "inbounds": [
    {"type": "tproxy",   "tag": "tproxy-in",   "listen": "::", "listen_port": $TPROXY_PORT, "network": "tcp"},
    {"type": "redirect", "tag": "redirect-in", "listen": "::", "listen_port": $REDIRECT_PORT, "network": "tcp"},
    {"type": "mixed",    "tag": "mixed-in",    "listen": "127.0.0.1", "listen_port": $MIXED_PORT}
  ],
  "outbounds": [
    $(cat "$outbounds")
  ],
  "route": {
    "rules": [
      {"action": "sniff"},
      {"domain_suffix": [$dom_json], "outbound": "proxy"},
      {"ip_is_private": true, "outbound": "direct"}
    ],
    "final": "direct",
    "auto_detect_interface": true
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "__CLASH_SECRET__",
      "default_mode": "rule"
    }
  }
}
EOJ
  local csec
  csec=$(clash_secret)
  sed -i "s/__CLASH_SECRET__/$csec/" "$WORK/config.json" 2>/dev/null
  return 0
}

# ------------------------------------------------------------------------------
# Ядро sing-box.
# ------------------------------------------------------------------------------
find_core() {
  local b
  for b in "$DATA_DIR/bin/sing-box" "$MODDIR/bin/sing-box"; do
    [ -x "$b" ] && { printf '%s' "$b"; return 0; }
  done
  return 1
}

core_alive() { [ -n "$CORE_PID" ] && kill -0 "$CORE_PID" 2>/dev/null; }

start_core() {
  local core
  core=$(find_core) || { log_e "sing-box не найден ($DATA_DIR/bin/sing-box)"; return 1; }
  gen_config || return 1
  "$core" check -c "$WORK/config.json" >> "$LOG" 2>&1 || {
    log_e "sing-box check: конфиг невалиден:"
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
  local n=0
  while [ "$n" -lt 10 ]; do
    core_alive || { log_e "sing-box умер сразу; последние строки:"; tail -n 5 "$WORK/singbox.log" >> "$LOG"; return 1; }
    http_via_proxy && { log_i "sing-box запущен (PID $CORE_PID), прокси отвечает"; return 0; }
    sleep 2; n=$((n + 1))
  done
  log_w "sing-box запущен, но тест через прокси не прошёл за 20с (подождите выбор ноды urltest'ом)"
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
  rm -f "$CORE_PID_FILE" "$RUN/geo-watchdog.pid" 2>/dev/null
}

# ------------------------------------------------------------------------------
# Правила. FAIL-OPEN.
# ------------------------------------------------------------------------------
GEO_OUT=GEO_OUT_CHAIN
GEO_TPR=GEO_TPROXY_CHAIN
GEO_RDR=GEO_REDIRECT_CHAIN
GEO_GRD=GEO_GUARD_CHAIN

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
  # разрешение помеченному трафику раньше QUIC-REJECT zapret2 (hysteria2/UDP443)
  ipt4 -t filter -D OUTPUT -m mark --mark "$MARK_SKIP/$MARK_SKIP" -j ACCEPT
  ipt6 -t filter -D OUTPUT -m mark --mark "$MARK_SKIP/$MARK_SKIP" -j ACCEPT
  ipt4 -t filter -D OUTPUT -j "$GEO_GRD"
  ipt4 -t filter -F "$GEO_GRD" 2>/dev/null; ipt4 -t filter -X "$GEO_GRD" 2>/dev/null
  "$IP_BIN" -4 rule del pref "$RULE_PREF" fwmark "$MARK_TPROXY/$MARK_TPROXY" 2>/dev/null
  "$IP_BIN" -6 rule del pref "$RULE_PREF" fwmark "$MARK_TPROXY/$MARK_TPROXY" 2>/dev/null
  "$IP_BIN" -4 route flush table "$TABLE" 2>/dev/null
  "$IP_BIN" -6 route flush table "$TABLE" 2>/dev/null
  return 0
}

apply_rules() {
  cleanup_rules
  # Пометленный (наш/прокси) трафик принимаем в filter OUTPUT раньше цепочек
  # zapret2: иначе QUIC-REJECT ронял бы hysteria2-ноды на UDP/443.
  ipt4 -t filter -I OUTPUT 1 -m mark --mark "$MARK_SKIP/$MARK_SKIP" -j ACCEPT
  ipt6 -t filter -I OUTPUT 1 -m mark --mark "$MARK_SKIP/$MARK_SKIP" -j ACCEPT
  # mixed-порт 127.0.0.1:7890 доступен только root-скриптам модуля:
  # без этого любое приложение могло бы пользоваться вашим прокси бесплатно.
  ipt4 -t filter -N "$GEO_GRD" 2>/dev/null
  ipt4 -t filter -A "$GEO_GRD" -p tcp -d 127.0.0.1 -m multiport --dports "$MIXED_PORT,9090" -m owner ! --uid-owner 0 -j REJECT
  ipt4 -t filter -I OUTPUT 1 -j "$GEO_GRD"

  local mark="$MARK_FULL"
  [ "$1" = redirect ] && mark="$MARK_SKIP"
  ipt4 -t mangle -N "$GEO_OUT" || return 1
  ipt6 -t mangle -N "$GEO_OUT" 2>/dev/null
  for dst in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4 255.255.255.255/32; do
    ipt4 -t mangle -A "$GEO_OUT" -d "$dst" -j RETURN
  done
  ipt4 -t mangle -A "$GEO_OUT" -o "${WARP_DEV:-awg99}" -j RETURN
  local amode uids u
  amode=$(app_mode)
  uids=$(app_uids)
  if [ "$amode" = exclude ]; then
    for u in $uids; do ipt4 -t mangle -A "$GEO_OUT" -m owner --uid-owner "$u" -j RETURN; done
  fi
  if [ "$amode" = include ]; then
    for u in $uids; do
      ipt4 -t mangle -A "$GEO_OUT" -p tcp -m multiport --dports 80,443 -m owner --uid-owner "$u" -m mark --mark 0 -j MARK --set-mark "$mark"
    done
    [ -n "$uids" ] || log_w "режим include с пустым списком: ни одно приложение не проксируется"
  else
    ipt4 -t mangle -A "$GEO_OUT" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner 0 -m mark --mark 0 -j MARK --set-mark "$mark"
  fi
  ipt4 -t mangle -I OUTPUT 1 -j "$GEO_OUT"
  ipt6 -t mangle -A "$GEO_OUT" -d fc00::/7 -j RETURN 2>/dev/null
  ipt6 -t mangle -A "$GEO_OUT" -d fe80::/10 -j RETURN 2>/dev/null
  ipt6 -t mangle -A "$GEO_OUT" -o "${WARP_DEV:-awg99}" -j RETURN 2>/dev/null
  if [ "$amode" = exclude ]; then
    for u in $uids; do ipt6 -t mangle -A "$GEO_OUT" -m owner --uid-owner "$u" -j RETURN 2>/dev/null; done
  fi
  if [ "$amode" = include ]; then
    for u in $uids; do
      ipt6 -t mangle -A "$GEO_OUT" -p tcp -m multiport --dports 80,443 -m owner --uid-owner "$u" -m mark --mark 0 -j MARK --set-mark "$mark" 2>/dev/null
    done
  else
    ipt6 -t mangle -A "$GEO_OUT" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner 0 -m mark --mark 0 -j MARK --set-mark "$mark" 2>/dev/null
  fi
  ipt6 -t mangle -I OUTPUT 1 -j "$GEO_OUT" 2>/dev/null

  if [ "$1" = redirect ]; then
    ipt4 -t nat -N "$GEO_RDR" || return 1
    ipt4 -t nat -A "$GEO_RDR" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner 0 -m mark --mark 0 -j REDIRECT --to-port "$REDIRECT_PORT"
    ipt4 -t nat -I OUTPUT 1 -j "$GEO_RDR"
    ipt6 -t nat -N "$GEO_RDR" 2>/dev/null
    ipt6 -t nat -A "$GEO_RDR" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner 0 -m mark --mark 0 -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null
    ipt6 -t nat -I OUTPUT 1 -j "$GEO_RDR" 2>/dev/null
    MODE=redirect
    log_i "правила применены: REDIRECT (TCP); TPROXY в ядре недоступен"
    return 0
  fi

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
    log_i "правила применены: TPROXY (TCP, v4+v6), режим=$PROXY_MODE класс=$NETWORK_CLASS нод=$NODES_COUNT"
    return 0
  fi
  ipt4 -t mangle -F "$GEO_TPR" 2>/dev/null; ipt4 -t mangle -X "$GEO_TPR" 2>/dev/null
  log_w "xt_TPROXY недоступен — REDIRECT"
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
  [ "$had_rules" = 1 ] && write_state stopped
  log_i "остановлен, правила сняты (трафик прямой)"
}

start_all() {
  [ -f "$DISABLE_FLAG" ] && { log_i "выключен флагом $DISABLE_FLAG"; exit 0; }
  find_core >/dev/null || { log_e "sing-box не установлен — модуль в режиме ожидания (README)"; write_state "no-binary"; exit 0; }
  [ -s "$PROXY_URI_FILE" ] || [ -s "$PROXY_JSON_FILE" ] || [ -s "$SUBS" ] || {
    log_e "прокси не настроен: proxy.uri, proxy.outbound.json или subscriptions.list"
    write_state "no-proxy"
    exit 0
  }
  start_core || { stop_core; write_state "config-error"; exit 1; }
  if ! rules_present; then
    apply_rules tproxy || apply_rules redirect || { cleanup_rules; write_state "rules-error"; log_e "правила не применились — трафик прямой"; return 1; }
  fi
  write_state running
}

watchdog() {
  echo $$ > "$RUN/geo-watchdog.pid" 2>/dev/null
  local failures=0 last_dom_sig="" dom_sig last_class="" cls last_sub=0 now restart_guard=0
  last_dom_sig=$(cksum "$DOMAINS" 2>/dev/null | awk '{print $1}')
  last_class=$(network_class)
  last_sub=$(now_epoch)
  restart_guard=$(now_epoch)
  log_i "watchdog: интервал ${HEALTH_INTERVAL}s, класс сети '$last_class', подписки каждые ${SUB_REFRESH_SEC}s"
  while :; do
    sleep "$HEALTH_INTERVAL"
    now=$(now_epoch)

    dom_sig=$(cksum "$DOMAINS" 2>/dev/null | awk '{print $1}')
    if [ -n "$dom_sig" ] && [ "$dom_sig" != "$last_dom_sig" ]; then
      last_dom_sig="$dom_sig"
      log_i "domains.list изменён — перечитываю (трафик на это время прямой)"
      cleanup_rules; stop_core
      start_core && { apply_rules tproxy || apply_rules redirect; }
      write_state running; failures=0; restart_guard=$now
      continue
    fi

    cls=$(network_class)
    if [ -n "$cls" ] && [ "$cls" != "$last_class" ]; then
      log_i "класс сети сменился '$last_class' -> '$cls': пересобираю набор нод"
      last_class="$cls"
      cleanup_rules; stop_core
      start_core && { apply_rules tproxy || apply_rules redirect; }
      write_state running; failures=0; restart_guard=$now
      continue
    fi

    if [ "$PROXY_MODE" = auto ] && [ $((now - last_sub)) -ge "$SUB_REFRESH_SEC" ]; then
      last_sub=$now
      log_i "плановое обновление подписок"
      refresh_nodes || true
    fi

    if ! core_alive; then
      failures=$((failures + 1))
      if [ "$failures" -ge "$FAIL_THRESHOLD" ] && [ $((now - restart_guard)) -ge 60 ]; then
        restart_guard=$now
        rules_present && cleanup_rules
        stop_core
        start_core && { apply_rules tproxy || apply_rules redirect; }
        write_state "${CORE_PID:+running}"
        failures=0
      fi
      continue
    fi

    if ! rules_present; then
      log_w "правила исчезли — восстанавливаю"
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
      if [ "$failures" -ge "$FAIL_THRESHOLD" ] && [ $((now - restart_guard)) -ge 60 ]; then
        restart_guard=$now
        cleanup_rules
        log_w "fail-open: правила сняты, трафик прямой; перезапускаю ядро"
        stop_core
        start_core && { apply_rules tproxy || apply_rules redirect; write_state running; }
        failures=0
        [ -n "$CORE_PID" ] || write_state degraded
      fi
    fi
  done
}

status() {
  echo "state=$(sed -n 's/^STATE=//p' "$STATE_FILE" 2>/dev/null | head -n1)"
  echo "mode=$(sed -n 's/^MODE=//p' "$STATE_FILE" 2>/dev/null | head -n1) proxy=$(sed -n 's/^PROXY=//p' "$STATE_FILE" 2>/dev/null | head -n1)"
  echo "network_class=$(network_class) (сохранён: $(sed -n 's/^CLASS=//p' "$STATE_FILE" 2>/dev/null | head -n1))"
  echo "nodes=$(sed -n 's/^NODES=//p' "$STATE_FILE" 2>/dev/null | head -n1) (кэш: wifi=$(wc -l < "$DATA_DIR/nodes-wifi.list" 2>/dev/null || echo 0) mobile=$(wc -l < "$DATA_DIR/nodes-mobile.list" 2>/dev/null || echo 0) all=$(wc -l < "$DATA_DIR/nodes-all.list" 2>/dev/null || echo 0))"
  echo "core_pid=$(cat "$CORE_PID_FILE" 2>/dev/null)"
  echo "rules_v4=$(ipt4 -t mangle -C OUTPUT -j "$GEO_OUT" 2>/dev/null && echo tproxy || { ipt4 -t nat -C OUTPUT -j "$GEO_RDR" 2>/dev/null && echo redirect || echo no; })"
  echo "domains=$(grep -cvE '^[[:space:]]*(#|$)' "$DOMAINS" 2>/dev/null)"
  echo "subscriptions=$([ -s "$SUBS" ] && echo "$(grep -cvE '^[[:space:]]*(#|$)' "$SUBS")" || echo 0)"
  echo "apps_mode=$(app_mode) apps_selected=$(wc -l < "$APPS_LIST_FILE" 2>/dev/null || echo 0)"
  echo "binary=$(find_core || echo none)"
  echo "health_now=$(http_via_proxy >/dev/null 2>&1 && echo OK || echo FAIL)"
}

case "${1:-boot}" in
  boot)
    trap 'stop_all' TERM INT
    trap 'stop_all' EXIT
    n=0
    until [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] || [ "$n" -ge 150 ]; do sleep 2; n=$((n + 1)); done
    sleep 20
    start_all
    watchdog
    ;;
  start-geo)
    # вызывается из service.sh основной службы при каждом её старте/reload:
    # ИДЕМПОТЕНТНО — не плодим вторые копии sing-box и watchdog.
    wp=$(cat "$RUN/geo-watchdog.pid" 2>/dev/null)
    case "$wp" in ''|*[!0-9]*) ;; *) kill -0 "$wp" 2>/dev/null && { log_i "гео-прокси уже работает (watchdog PID $wp) — старт пропущен"; exit 0; } ;; esac
    cp=$(cat "$CORE_PID_FILE" 2>/dev/null)
    case "$cp" in ''|*[!0-9]*) ;; *) kill -0 "$cp" 2>/dev/null && { log_i "sing-box уже работает (PID $cp) — старт пропущен"; exit 0; } ;; esac
    trap 'stop_all' TERM INT
    rm -f "$RUN/geo-watchdog.pid" 2>/dev/null
    start_all
    watchdog
    ;;
  start|restart)
    trap 'stop_all' TERM INT
    cleanup_rules; stop_core
    start_all
    watchdog
    ;;
  stop)    stop_all ;;
  update)
    refresh_nodes || true
    if core_alive || rules_present; then
      cleanup_rules; stop_core
      start_core && { apply_rules tproxy || apply_rules redirect; }
      write_state running
    fi
    echo "OK: ноды обновлены, движок пересобран"
    ;;
  # import-url <класс> <url>: добавить подписку (кнопка «Импорт из Happ»)
  import-url)
    cls="${2:-all}"; urlv="$3"
    case "$cls" in wifi|mobile|all) ;; *) echo "класс: wifi|mobile|all"; exit 2 ;; esac
    case "$urlv" in https://*|http://*) ;; *) echo "нужен URL http(s)://"; exit 2 ;; esac
    printf '%s' "$urlv" | grep -q ' ' && { echo "URL с пробелом"; exit 2; }
    printf '%s %s\n' "$cls" "$urlv" >> "$SUBS"
    refresh_nodes >/dev/null 2>&1
    echo "OK: подписка добавлена, ноды скачаны"
    ;;
  # import-raw <текст со ссылками>: вставка ссылок из Happ/подписки вручную
  import-raw)
    cnt=$(printf '%s\n' "$2" | extract_uris | tee -a "$MANUAL_NODES" | wc -l)
    [ "$cnt" -gt 0 ] || { echo "не найдено ссылок vless/ss/hysteria2/trojan"; exit 2; }
    awk 'NF && !seen[$0]++' "$MANUAL_NODES" > "$MANUAL_NODES.tmp" && mv -f "$MANUAL_NODES.tmp" "$MANUAL_NODES"
    echo "OK: добавлено ссылок $cnt (применятся после перезапуска)"
    ;;
  apply)   apply_rules tproxy || apply_rules redirect ;;
  status)  status ;;
  class)   network_class ;;
  nodes-of-class) nodes_for_class "$2" ;;
  *) echo "Использование: $0 [start|stop|restart|update|status|apply]"; exit 2 ;;
esac
