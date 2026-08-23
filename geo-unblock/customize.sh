#!/system/bin/sh
# geo-unblock — установщик. Бинарник sing-box скачивается при установке
# (телефон имеет доступ к github); при неудаче модуль ставится всё равно,
# и service.sh будет ждать бинарник в /data/adb/geo-unblock/bin/sing-box.
umask 077
SKIPUNZIP=1

SINGBOX_VER="1.13.19"
# SHA-256 официальных релизов sing-box ${SINGBOX_VER} (github.com/SagerNet/sing-box):
# защита от подмены/битой загрузки. При несовпадении установка бинаря отменяется.
case "$(getprop ro.product.cpu.abi 2>/dev/null || echo "$ARCH")" in
  arm64-v8a|aarch64)   SB_SHA256="e737ac40187563673e1fc282aebf1774e09f3b2057203872798968a2126fab53" ;;
  armeabi-v7a|armeabi|arm) SB_SHA256="0e2f8004279365a642992ee6a683efb9c1f12a8aa56bfcef98196e991bf72eee" ;;
  x86_64)             SB_SHA256="85e39a82576d222fef743e1c1435e0f3eb29c75fbe88837671efe1098fda5602" ;;
  x86)                SB_SHA256="d07fccc31c5426ab250f9f190f7092a7f777daa7de538e20bd7afe77c8b43eba" ;;
  *)                  SB_SHA256="" ;;
esac
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
for f in "$MODPATH/service.sh" "$MODPATH/uninstall.sh" "$MODPATH/bin/geo-control"; do set_exec "$f"; done
chmod 0755 "$MODPATH/webroot" 2>/dev/null
[ -f "$MODPATH/webroot/index.html" ] && ui_print "- WebUI: откройте модуль в менеджере (KernelSU/APatch) — вкладки Статус/Подписки/Приложения/Домены"

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
  local tmp="$1" dir="/data/local/tmp/sb-$$" sum=""
  # целостность: SHA-256 должен совпасть с официальным релизом
  if [ -n "$SB_SHA256" ]; then
    sum=$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')
    if [ -z "$sum" ]; then
      for bb in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
        [ -x "$bb" ] && { sum=$("$bb" sha256sum "$tmp" 2>/dev/null | awk '{print $1}'); break; }
      done
    fi
    [ "$sum" = "$SB_SHA256" ] || { ui_print "- ! SHA-256 не совпал ($sum)"; rm -f "$tmp"; return 1; }
  fi
  mkdir -p "$dir" 2>/dev/null || return 1
  local ok=0
  for t in tar "busybox tar"; do
    $t -xzf "$tmp" -C "$dir" 2>/dev/null && { ok=1; break; }
  done
  [ "$ok" = 1 ] || { rm -rf "$dir" "$tmp"; return 1; }
  local found
  found=$(find "$dir" -type f -name sing-box 2>/dev/null | head -n1)
  [ -n "$found" ] && cp -f "$found" "$SB_DST" && chmod 0755 "$SB_DST" 2>/dev/null
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
