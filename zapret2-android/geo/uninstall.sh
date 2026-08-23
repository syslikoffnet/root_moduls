#!/system/bin/sh
# geo-unblock — удаление: снять правила, остановить ядро. Данные пользователя
# (/data/adb/geo-unblock: прокси-ссылка, домены, бинарник) сохраняются.
umask 077
MODDIR="${0%/*}"
RUN="/data/adb/geo-unblock/run"

IPT=$(command -v iptables 2>/dev/null); [ -n "$IPT" ] || IPT=/system/bin/iptables
IP6T=$(command -v ip6tables 2>/dev/null); [ -n "$IP6T" ] || IP6T=/system/bin/ip6tables
IP_BIN=$(command -v ip 2>/dev/null); [ -n "$IP_BIN" ] || IP_BIN=/system/bin/ip
del(){ "$1" -w 5 -t "$2" -D "$3" -j "$4" >/dev/null 2>&1; }

for t in mangle nat; do
  del "$IPT" "$t" OUTPUT   GEO_OUT_CHAIN
  del "$IPT" "$t" OUTPUT   GEO_TPROXY_CHAIN
  del "$IPT" "$t" OUTPUT   GEO_REDIRECT_CHAIN
  del "$IPT" "$t" PREROUTING GEO_TPROXY_CHAIN
  del "$IP6T" "$t" OUTPUT   GEO_OUT_CHAIN
  del "$IP6T" "$t" OUTPUT   GEO_TPROXY_CHAIN
  del "$IP6T" "$t" OUTPUT   GEO_REDIRECT_CHAIN
  del "$IP6T" "$t" PREROUTING GEO_TPROXY_CHAIN
done
for c in GEO_OUT_CHAIN GEO_TPROXY_CHAIN GEO_REDIRECT_CHAIN; do
  "$IPT" -w 2 -t mangle -F "$c" >/dev/null 2>&1; "$IPT" -w 2 -t mangle -X "$c" >/dev/null 2>&1
  "$IPT" -w 2 -t nat -F "$c" >/dev/null 2>&1; "$IPT" -w 2 -t nat -X "$c" >/dev/null 2>&1
  "$IP6T" -w 2 -t mangle -F "$c" >/dev/null 2>&1; "$IP6T" -w 2 -t mangle -X "$c" >/dev/null 2>&1
  "$IP6T" -w 2 -t nat -F "$c" >/dev/null 2>&1; "$IP6T" -w 2 -t nat -X "$c" >/dev/null 2>&1
done
"$IP_BIN" -4 rule del pref 30000 fwmark 0x2/0x2 2>/dev/null
"$IP_BIN" -6 rule del pref 30000 fwmark 0x2/0x2 2>/dev/null
"$IP_BIN" -4 route flush table 2025 2>/dev/null
"$IP_BIN" -6 route flush table 2025 2>/dev/null

pid=$(cat "$RUN/singbox.pid" 2>/dev/null)
case "$pid" in ''|*[!0-9]*) ;; *) kill -TERM "$pid" 2>/dev/null; sleep 1; kill -KILL "$pid" 2>/dev/null ;; esac
rm -f "$RUN/singbox.pid" "$RUN/state.env" 2>/dev/null
exit 0
