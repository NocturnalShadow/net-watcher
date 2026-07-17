# NetWatcher — демо детектора загроз

Детектор читає PCAP → реконструює TCP-потоки → класифікує кожен потік навченою
DNN-моделлю.
Події пишуться у `demo\out\<pcap>.log`: `[ALERT]` — шкідливий потік, `[OK]` — нормальний.

**Виконувати з кореня репозиторію (`net-watcher\`). Оболонка — cmd. Кожен крок ~5 c.**
Трейси та їх походження — у [`demo\pcap\`](pcap/README.md); DNS збережено для контексту у Wireshark.

---

## 0. Підготовка (один раз)

<!-- Активуємо venv і ставимо/оновлюємо залежності. Далі всі команди — просто `python ...`. -->

```bat
venv\Scripts\activate.bat
pip install -r requirements.txt
```

> Журнал дописується при повторному запуску — очистити можна командою `rmdir /s /q demo\out`.

---

## 1. Emotet — C2-маячок

<!-- Вхід: demo\pcap\emotet.pcap (заражений хост 10.0.2.102). Вихід: demo\out\emotet.pcap.log ([ALERT]). -->

```bat
python src\run.py --role detector --input-path demo\pcap\emotet.pcap --output-path demo\out
type demo\out\emotet.pcap.log
```

Очікувано: **8 × `[ALERT]`** — `10.0.2.102 → 112.124.3.15:8080`.

Співставлення журнал ↔ Wireshark (`demo\pcap\emotet.pcap`):

| Потік у журналі | Wireshark-фільтр | Що це |
|-----------------|------------------|-------|
| `10.0.2.102:55492 → 112.124.3.15:8080` — **модель пропускає (`[OK]`)**, але подія ключова | `tcp.port==55492` | Успішний C2-чекін: `POST /83736aa6/806782973/` із зашифрованим тілом + **~180 КБ** зашифрованого модуля у відповідь (довантаження Emotet) |
| `10.0.2.102:55526 → 112.124.3.15:8080` **`[ALERT]`** (+ ще 7: порти 55538–55610) | `tcp.port==55526` | 3× `SYN` без відповіді — повторна спроба з'єднання з C2; саме цей патерн «стукоту» бота ловить детектор |
| усі спроби з'єднання з C2 | `ip.addr==112.124.3.15 && tcp.flags.syn==1 && tcp.flags.ack==0` | Огляд усіх маячків на один C2-сервер |

---

## 2. TrickBot — розвідка + C2 через TLS

<!-- Вхід: demo\pcap\trickbot.pcap (заражений хост 192.168.1.123). Вихід: demo\out\trickbot.pcap.log ([ALERT]). -->

```bat
python src\run.py --role detector --input-path demo\pcap\trickbot.pcap --output-path demo\out
type demo\out\trickbot.pcap.log
```

Очікувано: **7 × `[ALERT]`** — 1 потік розвідки + 6 C2-маячків.

Співставлення журнал ↔ Wireshark (`demo\pcap\trickbot.pcap`):

| Потік у журналі | Wireshark-фільтр | Що це |
|-----------------|------------------|-------|
| `192.168.1.123:49158 → 107.22.255.106:80` **`[ALERT]`** | `tcp.port==49158` | `GET checkip.amazonaws.com` — TrickBot з'ясовує зовнішній IP жертви (розвідка) |
| `192.168.1.123:49189 → 82.146.57.127:443` **`[ALERT]`** (+ ще 5: порти 49190–49194) | `tcp.port==49189` | TLS-маячок на C2 **без SNI** (самопідписаний сертифікат) — типовий канал C2 TrickBot |
| усі C2-маячки | `ip.addr==82.146.57.127` | Короткі TLS-сесії на один C2-сервер |

---

## 3. Benign — нормальний трафік (контроль)

<!-- Вхід: demo\pcap\benign.pcap (звичайний веб-серфінг 10.0.2.15). --output-filter all, бо [OK] типово приховані.
     Вихід: demo\out\benign.pcap.log — усі потоки [OK], жодного алерту. -->

```bat
python src\run.py --role detector --input-path demo\pcap\benign.pcap --output-path demo\out --output-filter all
type demo\out\benign.pcap.log
```

Очікувано: **30 × `[OK]`, 0 алертів** — звичайні HTTPS/HTTP-сесії (CloudFront, Google, CDN) не турбують аналітика.

---

## 4. Змішаний трафік

<!-- Вхід: demo\pcap\mixed.pcap (emotet + trickbot + benign разом). Вихід: demo\out\mixed.pcap.log ([ALERT]). -->

```bat
python src\run.py --role detector --input-path demo\pcap\mixed.pcap --output-path demo\out
type demo\out\mixed.pcap.log
```

Очікувано: **15 × `[ALERT]`** (8 Emotet + 7 TrickBot) серед нормального трафіку.
