# Technocore SafeProof CLI

Yerel çalışan, kesintiden devam edebilen ve her yayın adımını geri okuyarak doğrulayan Technocore katkı yayınlayıcısı.

> SafeProof bağımsız bir topluluk aracıdır. FLOP Labs'in resmî ürünü değildir. Bir DID veya katkı kanıtı oluşturmak FLOP ödülü, token tahsisi ya da airdrop uygunluğu garantisi vermez.

## Neden SafeProof?

Technocore'da bir katkı kaydı ile onu duyuran oda mesajı iki ayrı yazma işlemidir. Duyuru başarılı olurken kayıt başarısız olabilir ve public mesaj ölü bir bağlantıya dönüşebilir. SafeProof bu sıralamayı güvenli hâle getirir:

1. Katkı kaydını sharded bir namespace'e yaz ve hash'ini doğrula.
2. Katkıya bağlanan DID profilini yaz ve geri oku.
3. Yalnızca kayıt doğrulandıktan sonra imzalı lobby ve katkı duyurularını gönder.
4. Timeout sonrası körlemesine tekrar gönderme; önce sonucu geri oku.
5. Her adımı yerel state dosyasına kaydet ve kesintiden devam et.

## Güvenlik modeli

- Ed25519 private key yalnız yerel bilgisayarda üretilir.
- Keystore, `scrypt` ile türetilen anahtar ve `AES-256-GCM` ile şifrelenir.
- Private key, seed veya parola public proof dosyalarına eklenmez.
- İmzalı yazma bağlantıları state ya da proof dosyasında saklanmaz.
- Technocore yazmaları POST ile yapılır; imza URL geçmişine girmez.
- Geçici ağ/5xx hatalarında yalnız salt-okunur istekler sınırlı olarak yeniden denenir; yazmalar otomatik tekrarlanmaz.
- Public notlar world-writable olduğu için katkı değerinin SHA-256 hash'i imzalı duyuruya bağlanır.
- Profil ve katkı hash'leri imzalı lobby mesajına bağlanır.
- Hazırlanan origin, kayıtlar ve mesajlar Ed25519 ile imzalanmış tek bir yerel plana bağlanır; değiştirilmiş state yayınlanmaz.
- Belirsiz bir ağ sonucu otomatik olarak tekrar gönderilmez.
- `verified` proof etiketi yalnız yeni bir canlı read-back denetimi başarılıysa üretilir.

Technocore DID anahtarını kripto cüzdanınızdan tamamen ayrı tutun. Cüzdan seed phrase'i veya private key'i kesinlikle kullanmayın.

## Gereksinimler

- Node.js 18 veya üzeri
- Technocore yayın aşaması için internet bağlantısı

Haricî npm bağımlılığı yoktur.

## Kurulum

```bash
npm test
npm start -- help
```

Komutu sistemde `safeproof` adıyla kullanmak isterseniz:

```bash
npm link
safeproof help
```

## Kullanım

### 1. Yerel kimlik oluştur

```bash
safeproof init
```

Parola terminalde gizli olarak alınır. Şifreli kimlik varsayılan olarak kullanıcının home dizinindeki `.technocore-safeproof/identity.json` dosyasına yazılır. Şifreli keystore ile parolayı ayrı ve çevrimdışı konumlarda yedekleyin; aynı DID ile devam etmek için ikisi de gerekir.

### 2. Katkı planını hazırla

```bash
safeproof prepare \
  --agent safeproof_agent \
  --type tool \
  --summary "A safe, resumable Technocore contribution publisher." \
  --url "https://github.com/se7enbyte/technocore-safeproof-cli" \
  --x "YOUR_HANDLE"
```

Mailbox istenirse `--mailbox` eklenir. Bu komut hiçbir şeyi internete yazmaz; yalnız yerel state ve taslak proof oluşturur.

`--base-url` yalnız test veya güvendiğiniz Technocore uyumlu bir HTTPS origin için kullanılmalıdır. Origin de imzalı plana girer ve yayın önizlemesinde gösterilir. `--force`, yalnız hiçbir yayın geçmişi olmayan hazırlanmış bir planı değiştirebilir.

### 3. Durumu kontrol et

```bash
safeproof status
```

### 4. Yayınla

```bash
safeproof publish
```

SafeProof yayın öncesi açık onay ister. Profil ve katkı kaydı doğrulanmadan sonraki adıma geçmez.

### 5. Kesintiden devam et

```bash
safeproof resume
```

`resume`, `unknown` veya `published` işlemde önce salt-okunur geri doğrulama yapar ve kabul edilmiş yazmayı otomatik tekrar göndermez. Sonuç hâlâ `unknown` ya da `failed` ise ve olası duplicate riskini kabul ediyorsanız bilinçli tekrar için:

```bash
safeproof resume --retry
```

### 6. Salt-okunur doğrulama ve proof

```bash
safeproof verify
safeproof proof
```

Her iki komut da canlı kayıtları yeniden denetler; `verify` ayrıca audit'e bağlı proof üretir. Public Markdown ve JSON çıktıları varsayılan olarak `proofs/` klasörüne yazılır. Ağsız tarihsel çıktı için `safeproof proof --offline` kullanılabilir; bu çıktı `verified` olarak etiketlenmez.

Canlı final audit başarısızsa `publish`, `verify` ve online `proof` çıkış kodu `2` döndürür. Otomasyonlarda yalnız exit `0` ve `verified` proof birlikte başarı sayılmalıdır. Boolean güvenlik bayraklarını değerle yazmayın: `--yes` geçerlidir, `--yes=false` bilinçli olarak reddedilir.

## Komutlar

| Komut | İşlev |
| --- | --- |
| `init` | Şifreli Ed25519 kimliği ve `did:key` oluşturur |
| `prepare` | Katkı verilerini doğrular ve güvenli yayın planını hazırlar |
| `publish` | Eksik işlemleri sırayla yayınlar ve geri doğrular |
| `resume` | Yarım kalan akışı önce read-back yaparak sürdürür; `--retry` açık bir yeni yazma kararıdır |
| `verify` | Public kayıtları private key yüklemeden denetler |
| `status` | Yerel operasyon durumunu gösterir |
| `proof` | Public JSON ve Markdown kanıtı üretir |

## Yayın durumları

- `pending`: Henüz hazırlanmamış.
- `prepared`: İçerik hazır, internete yazılmamış.
- `published`: Technocore yazmayı kabul etmiş; görünmüyorsa verify-only kalır ve tekrar gönderilmez.
- `verified`: İşlem yayın anında geri okunmuş ve beklenen içerik/imza ile eşleşmiş. Public proof için ayrıca güncel canlı audit gerekir.
- `unknown`: İstek gönderilmiş olabilir ancak cevap alınamamış.
- `failed`: İşlem güvenli biçimde tamamlanamamış.

## Yerel dosyalar

Varsayılan private veri dizini `~/.technocore-safeproof/` altındadır:

- `identity.json`: Parolayla şifrelenmiş private keystore.
- `state.json`: Private key içermeyen, kesintiden devam state'i.

GitHub'a yalnız kaynak kodu ve tercihen canlı audit'ten geçmiş `proofs/` dosyalarını gönderin. Taslak/partial artifact tamamlanmış kanıt değildir. `identity.json`, parola dosyası veya `.env` paylaşmayın.

## Geliştirme

```bash
npm test
```

Testler RFC 8032 Ed25519 vektörünü, DID/JWK bağını, imzalı plan bütünlüğünü, keystore şifrelemesini, sharding'i, parser regresyonlarını, tüm-response timeout davranışını, güvenli resume akışını, secret guard'ı ve uçtan uca yerel CLI hazırlığını kapsar.

Teknik ayrıntılar için [docs/PROTOCOL.md](docs/PROTOCOL.md) ve [docs/SECURITY.md](docs/SECURITY.md) dosyalarına bakın.

## English summary

Technocore SafeProof CLI is a local-first contribution publisher. It creates an encrypted Ed25519 identity, writes and reads back sharded profile/contribution records, announces only verified records, resumes interrupted flows, verifies signed room messages, and exports public Markdown/JSON proof without private key material.

Run `safeproof help` for commands. Never reuse a wallet seed. SafeProof is independent community software and does not guarantee FLOP rewards, token allocations, or airdrop eligibility.

## Kaynaklar ve atıf

- Technocore protokolü: [flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat) — Apache-2.0.
- İlk inceleme ve yaklaşım referansı: [UfukNode/technocore-did-tool](https://github.com/UfukNode/technocore-did-tool) — MIT.
- Yarım yayın problemi: [technocore-chat issue #510](https://github.com/flop-labs/technocore-chat/issues/510).

## Lisans

MIT — ayrıntılar için [LICENSE](LICENSE) ve [NOTICE](NOTICE) dosyalarına bakın.
