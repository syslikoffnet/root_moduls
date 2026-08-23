#!/system/bin/sh
# geo-unblock — установщик. Бинарник sing-box скачивается при установке
# (телефон имеет доступ к github); при неудаче модуль ставится всё равно,
# и service.sh будет ждать бинарник в /data/adb/geo-unblock/bin/sing-box.
umask 077
SKIPUNZIP=1

SINGBOX_VER="1.13.19"
DATA_DIR=/data/adb/geo-unblock

[ -n "$MODPATH" ] || { ui_print "! MODPATH не задан"; abort "! Окружение менеджера не распознано"; }
mkdir -p "$MODPATH" || abort "! Не удалось создать каталог модуля"

if [ -n "$ZIPFILE" ] && [ -f "$ZIPFILE" ]; then
  UNZIP_BIN="unzip"
  command -v unzip >/dev/null 2>&1 || {
    for b in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
      [ -x "$b" ] && UNZIP_BIN="$b unzip" && break
    done
    command -v busybox >/dev/null 2>&1 && UNZIP_BIN="busybox unzip"
  }
  $UNZIP_BIN -o "$ZIPFILE" -d "$MODPATH" >/dev/null 2>&1 || unzip -o "$ZIPFILE" -d "$MODPATH" >/dev/null 2>&1 || abort "! Ошибка распаковки"
fi
rm -rf "$MODPATH/META-INF" 2>/dev/null
[ -f "$MODPATH/module.prop" ] || abort "! module.prop отсутствует"

set_exec() { [ -f "$1" ] && { chown 0:0 "$1" 2>/dev/null; chmod 0755 "$1" 2>/dev/null; }; }
for f in "$MODPATH/service.sh" "$MODPATH/uninstall.sh"; do set_exec "$f"; done

# ---------- каталог данных пользователя (переживает обновления) ----------
mkdir -p "$DATA_DIR/bin" 2>/dev/null
if [ ! -f "$DATA_DIR/domains.list" ]; then
  cp -f "$MODPATH/domains.list.default" "$DATA_DIR/domains.list" 2>/dev/null
  chmod 0644 "$DATA_DIR/domains.list" 2>/dev/null
  ui_print "- Создан список доменов: $DATA_DIR/domains.list"
fi

if [ ! -f "$DATA_DIR/subscriptions.list" ]; then
  cp -f "$MODPATH/subscriptions.list.default" "$DATA_DIR/subscriptions.list" 2>/dev/null
  chmod 0644 "$DATA_DIR/subscriptions.list" 2>/dev/null
  ui_print "- Создан файл подписок: $DATA_DIR/subscriptions.list"
fi

# ---------- ABI ----------
ABI=$(getprop ro.product.cpu.abi 2>/dev/null); [ -n "$ABI" ] || ABI="$ARCH"
case "$ABI" in
  arm64-v8a|arm64|aarch64) SB_ARCH=android-arm64 ;;
  armeabi-v7a|armeabi|arm|armv7l) SB_ARCH=android-arm ;;
  x86_64|x64) SB_ARCH=android-amd64 ;;
  x86) SB_ARCH=android-386 ;;
  *) SB_ARCH="" ;;
esac

# ---------- sing-box: скачать/переиспользовать ----------
SB_DST="$DATA_DIR/bin/sing-box"
try_download() {
  [ -n "$SB_ARCH" ] || return 1
  local url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/sing-box-${SINGBOX_VER}-${SB_ARCH}.tar.gz"
  local tmp="/data/local/tmp/sing-box-$$.tar.gz"
  ui_print "- Скачиваю sing-box ${SINGBOX_VER} (${SB_ARCH})..."
  # curl из бандла zapret2 (ему нужен CA-бандл), затем системный curl/busybox wget
  local zc=/data/adb/modules/zapret2-android/bin/curl
  if [ -x "$zc" ]; then
    CURL_CA_BUNDLE=/data/adb/modules/zapret2-android/bin/curl-cacert.pem "$zc" -sSL --max-time 180 -o "$tmp" "$url" && [ -s "$tmp" ] && extract_it "$tmp" && return 0
  elif command -v curl >/dev/null 2>&1; then
    curl -sSL --max-time 180 -o "$tmp" "$url" && [ -s "$tmp" ] && extract_it "$tmp" && return 0
  else
    for b in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox "$(command -v busybox 2>/dev/null)"; do
      [ -x "$b" ] || continue
      "$b" wget -q -T 180 -O "$tmp" "$url" && [ -s "$tmp" ] && extract_it "$tmp" && return 0
    done
  fi
  return 1
}
extract_it() {
  local tmp="$1" dir="/data/local/tmp/sb-$$"
  mkdir -p "$dir" 2>/dev/null || return 1
  local ok=0
  for t in tar "busybox tar"; do
    $t -xzf "$tmp" -C "$dir" 2>/dev/null && { ok=1; break; }
  done
  [ "$ok" = 1 ] || { rm -rf "$dir" "$tmp"; return 1; }
  local found
  found=$(find "$dir" -type f -name sing-box 2>/dev/null | head -n1)
  [ -n "$found" ] && cp -f "$found" "$SB_DST" && chmod 0755 "$SB_DST"
  rm -rf "$dir" "$tmp"
  [ -x "$SB_DST" ]
}

if [ -x "$SB_DST" ]; then
  ui_print "- sing-box уже установлен в $SB_DST (переиспользуется)"
elif try_download; then
  ui_print "- sing-box установлен: $SB_DST"
else
  ui_print "- ! Не удалось скачать sing-box автоматически."
  ui_print "-  Положите бинарник вручную:"
  ui_print "-  adb push sing-box $SB_DST && adb shell su -c chmod 755 $SB_DST"
  ui_print "-  (брать: github.com/SagerNet/sing-box/releases -> android-arm64)"
fi

ui_print " "
ui_print "- Настройка прокси: положите ссылку VLESS/SS в"
ui_print "  $DATA_DIR/proxy.uri   (или готовый outbound JSON в proxy.outbound.json)"
ui_print "- Список доменов: $DATA_DIR/domains.list"
ui_print "- После настройки: перезагрузка или su -c 'sh $MODPATH/service.sh restart'"
ui_print "- Установка завершена."
