# pfSense-Sysmon-Wazuh-Log-Toplama-ve-SIEM-Mimarisi
Bu proje, farklı işletim sistemlerinden gelen logların pfSense ile yönetilen izole bir ağ üzerinde toplanarak Wazuh SIEM platformunda analiz edilmesini amaçlayan uçtan uca bir güvenlik mimarisidir.

<img width="213" height="183" alt="image" src="https://github.com/user-attachments/assets/575b8634-24d0-497a-b668-bfb7e1dfe4df" />


🎯 Proje Amaçları

Gerçek bir SOC ortamında kullanılan log akışını simüle etmek
Sysmon ile gelişmiş Windows event logları toplamak
Ubuntu üzerinden Linux tabanlı logları Wazuh’a aktarmak
pfSense ile ağ segmentasyonu ve güvenli trafik yönetimi yapmak
SIEM üzerinde korelasyon, alerting ve temel tehdit avcılığı pratiği kazanmak

| Bileşen                 | Açıklama                                  |
| ----------------------- | ----------------------------------------- |
| **pfSense**             | Ağ segmentasyonu, Firewall / NAT yönetimi |
| **Sysmon**              | Windows davranışsal olay kayıt sistemi    |
| **Wazuh SIEM**          | Log toplama, analiz, MITRE ATT&CK eşleme  |
| **Windows 10/11**       | Sysmon agent testleri                     |
| **Ubuntu 22.04**        | Linux log agent                           |
| **VirtualBox / VMware** | Sanal ortam altyapısı                     |

⚙️ Kurulum Adımları
1️⃣ pfSense Yapılandırması
LAN ve WAN arayüzlerinin ayarlanması
DHCP sunucusunun etkinleştirilmesi
Wazuh server için statik IP atanması
Gerekli firewall kurallarının düzenlenmesi

2️⃣ Wazuh Server Kurulumu
Wazuh Manager + Dashboard kurulumu
API bağlantı testleri
Agent enrollment izinlerinin açılması

3️⃣ Windows Üzerinde Sysmon + Wazuh Agent
Sysmon kurulum
Olaf Hartong Sysmon config uygulanması
Wazuh agent kurulumu
Wazuh dashboard üzerinde agent doğrulama
Sysmon event ID’lerin Wazuh tarafından yakalanması

4️⃣ Ubuntu Agent Kurulumu
Agent kurulumu
Syslog, auth.log, sudo.log gibi kayıtların Wazuh’a gönderilmesi
Agent sağlık kontrolleri

5️⃣ Wazuh Dashboard İncelemeleri
Security Events
MITRE ATT&CK
PCI-DSS / CIS benchmark modülleri
Sysmon log incelemeleri
Rule set testleri

📝 Sonuç
Bu proje, bir SOC ortamındaki temel bileşenleri barındıran, hem ağ hem endpoint hem de SIEM düzeyinde pratik kazandıran bir yapıdır.
Genişletilebilirliği sayesinde ileride:
*Malware testleri
*Olay senaryoları
*Özel Wazuh kural yazımı
*Log korelasyon çalışmaları gibi eklemeler yapılabilir.

<img width="1057" height="611" alt="image" src="https://github.com/user-attachments/assets/6640aec0-e502-417a-a9ad-a7f811e2ed97" />    <img width="1473" height="888" alt="image" src="https://github.com/user-attachments/assets/46e9c61b-835a-4968-9291-8ea26c3c547e" />

<img width="1477" height="889" alt="image" src="https://github.com/user-attachments/assets/d3a168c4-2cd3-4d09-b637-6344b15b58f5" />


