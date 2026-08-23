#!/system/bin/sh
# ==============================================================================
# smart-all.sh — «Умный подбор всего» одним запуском (кнопка WebUI / CLI).
#
# Что делает:
#   1. WARP: полный перезапуск туннеля со сбросом перебора профилей — поиск
#      рабочего профиля с нуля (при «чёрной дыре» сразу выйдет на SIP).
#      Интернет при этом НЕ рвётся: маршруты завёрнутых подсетей на время
#      поиска уходят в прямой канал, где продолжает работать DPI-обход,
#      а NFQUEUE-правила с --queue-bypass пропускают трафик при любом сбое.
#   2. Автоподбор стратегии под текущую сеть (auto-select force). При движке
#      SMART_NATIVE внешний подбор не нужен — auto-select сам это определит
#      и завершится мгновенно с записью в лог (без reload службы).
#
# Скрипт рассчитан на фоновый запуск: пишет только в логи модуля и ничего
# не ломает при принудительной остановке.
# ==============================================================================
umask 077
MODDIR="${0%/*}"
case "$MODDIR" in /*) ;; *) MODDIR="$(cd "$MODDIR" 2>/dev/null && pwd)" ;; esac
LOG_DIR="$MODDIR/logs"
DEBUG_LOG="$LOG_DIR/zapret2_debug.log"
AUTO_LOG="$LOG_DIR/zapret2_auto.log"

note() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] smart-all: $*" >> "$DEBUG_LOG"; }

[ -f "$MODDIR/zapret2.conf" ] && . "$MODDIR/zapret2.conf"

note "запущен полный подбор (кнопка «Умный подбор всего»)"

if [ "${ENABLE_WARP:-0}" = "1" ] && [ -x "$MODDIR/warp-tunnel.sh" ]; then
  note "шаг 1/2: перезапуск WARP и поиск рабочего профиля (интернет не рвётся: подсети временно идут напрямую)"
  sh "$MODDIR/warp-tunnel.sh" force-restart >> "$DEBUG_LOG" 2>&1 || true
else
  note "шаг 1/2: WARP выключен — пропуск"
fi

if [ -x "$MODDIR/auto-select.sh" ]; then
  note "шаг 2/2: автоподбор стратегии под сеть (при SMART_NATIVE завершится сразу)"
  sh "$MODDIR/auto-select.sh" force >> "$AUTO_LOG" 2>&1 || true
fi

note "полный подбор завершён; итоги: WebUI → статус/туннель, логи: logs/zapret2_debug.log + logs/zapret2_auto.log"
exit 0
