# geo-unblock — точечный обход гео-блокировок (компаньон zapret2-android)

Проксирует **только** домены из вашего списка через ваш VLESS/Shadowsocks сервер
(например, из подписки Happ). Весь остальной трафик — рунет, банки, YouTube
(DPI-обход остаётся за zapret2) — идёт напрямую, без единого лишнего хопа.

**Без TUN-интерфейса**: sing-box работает в режиме TPROXY (fallback REDIRECT),
маршрутизация — по меткам iptables + policy routing.

## Установка
1. Установите zip через KernelSU/Magisk. При установке скачается sing-box
   (нужен интернет). Если не скачался — положите вручную:
   `adb push sing-box /data/adb/geo-unblock/bin/sing-box` + `chmod 755`.
2. Положите прокси (одной строкой, без пробелов):
   ```sh
   echo "vless://uuid@host:port?security=reality&sni=...&pbk=...&fp=chrome&sid=..." \
     > /data/adb/geo-unblock/proxy.uri
   ```
   Поддерживаются `vless://` (tls/reality, tcp/ws/grpc) и `ss://`.
   Ссылку можно скопировать в Happ (Поделиться → скопировать).
   Экспертам: вместо ссылки можно готовый outbound JSON в
   `/data/adb/geo-unblock/proxy.outbound.json` (полное покрытие всех опций).
3. Отредактируйте домены: `/data/adb/geo-unblock/domains.list`
   (изменения подхватываются сами за ~45 сек).
4. Перезагрузка — или сразу: `su -c "sh /data/adb/modules/geo-unblock/service.sh restart"`

## Проверка
```sh
su -c "sh /data/adb/modules/geo-unblock/service.sh status"
su -c "tail -20 /data/adb/modules/geo-unblock/logs/geo-unblock.log"
```

## Гарантии
- **Fail-open**: прокси умер/ссылка битая → правила снимаются мгновенно,
  весь интернет идёт напрямую. Ни секунды без сети.
- **Никаких конфликтов с zapret2**: исходящие к прокси помечены
  `routing_mark 0x40000000` — nfqws2 их не трогает; DPI-обход продолжает
  работать для всего остального трафика.
- Отметка `disabled`: `touch /data/adb/geo-unblock/disabled` + перезапуск.

## Источники
- sing-box (GPLv3): github.com/SagerNet/sing-box — версия фиксируется
  в customize.sh (SINGBOX_VER), бинарник кладётся в /data/adb/geo-unblock/bin.
