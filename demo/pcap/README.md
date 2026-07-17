# Демо-трейси (походження)

Кожен `.pcap` — це невелика вибірка з повного тестового трейсу CTU. DNS-пакети
навмисно **збережені** для контексту у Wireshark (детектор працює лише з TCP і DNS ігнорує).

| Файл | Джерело (з якого капчуру взято) | Фільтр вибірки (tshark `-Y`) | Пакетів | Очікувано |
|------|--------------------------------|------------------------------|--------:|-----------|
| `emotet.pcap`   | `pcap/ctu/emotet/114_2-Emotet.pcap`   | `(ip.addr==112.124.3.15 and frame.time_relative>=360000 and frame.time_relative<=375500) or dns` | 361 | 8 × `[ALERT]` |
| `trickbot.pcap` | `pcap/ctu/trickbot/324_1-TrickBot.pcap` | `(ip.addr==82.146.57.127 and frame.time_relative<1700) or ip.addr==107.22.255.106 or dns` | 82 | 7 × `[ALERT]` |
| `benign.pcap`   | `pcap/ctu/normal/32-normal.pcap`      | перші 1500 пакетів (`-c 1500`) | 1500 | 30 × `[OK]`, 0 алертів |
| `mixed.pcap`    | `emotet.pcap` + `trickbot.pcap` + `benign.pcap` (mergecap) | — | 1943 | 15 × `[ALERT]` + 30 × `[OK]` |

> `114_2`, `324_1` — це файли, на яких валідована e2e-модель (лежать і в
> `pcap/icsx-ctu-extended/test/`), тому детекція стабільна.

## Регенерація (за потреби)

```bash
# Emotet — C2-маячок на 112.124.3.15:8080 (містить успішне довантаження модуля ~180 КБ)
tshark -r pcap/ctu/emotet/114_2-Emotet.pcap \
  -Y '(ip.addr==112.124.3.15 and frame.time_relative>=360000 and frame.time_relative<=375500) or dns' \
  -w demo/pcap/emotet.pcap

# TrickBot — розвідка checkip.amazonaws.com + TLS C2-маячки на 82.146.57.127:443
tshark -r pcap/ctu/trickbot/324_1-TrickBot.pcap \
  -Y '(ip.addr==82.146.57.127 and frame.time_relative<1700) or ip.addr==107.22.255.106 or dns' \
  -w demo/pcap/trickbot.pcap

# Benign — звичайний веб-серфінг хоста 10.0.2.15
tshark -r pcap/ctu/normal/32-normal.pcap -c 1500 -w demo/pcap/benign.pcap

# Mixed — три трейси разом (для демонстрації змішаного трафіку)
mergecap -w demo/pcap/mixed.pcap demo/pcap/emotet.pcap demo/pcap/trickbot.pcap demo/pcap/benign.pcap
```
