<h1 align="center">「☣」 About kill-floor.exe</h1>

<p align="center"><img src="https://github.com/user-attachments/assets/d4dbe1f0-2cea-42b2-af30-141e14b7bed0"></p>

kill-floor.exe is a type of malware that exploits the legitimacy of a driver to abuse its functionality through a technique known as BYOVD (Bring Your Own Vulnerable Driver). This new campaign was discovered and published by researchers at [Trellix](https://www.trellix.com/blogs/research/when-guardians-become-predators-how-malware-corrupts-the-protectors/) on November 20, 2024. In their article, they describe the behavior of the malicious software and part of its code through reverse engineering.

When the malware starts, it drops a driver in the path `C:\Users\Default\AppData\Local\Microsoft\Windows\ntfs.bin`, posing as a legitimate file on the system. The driver is known as `aswArPot.sys`, a driver from the company Avast that is part of its defense software. Due to lack of control, malicious users ended up exploiting this flaw to abuse the process killing functionality, which allows attackers to kill any type of process, even system-level protection. The malware has a list of 142 processes on its blacklist, set to be killed after execution.

The same driver had been used in one of the AvosLocker ransomware group's campaigns in mid-May 2022, published by [Trend Micro](https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html). This driver has now been updated and defense solutions already have the driver on their blacklist.

**Note**: This is not the official code for the kill-floor.exe malware, it is just a recreation made by me while I was analyzing the binary.
This is the [original malware sample](https://bazaar.abuse.ch/sample/e882af8b945c92e5a7dd337378e6a8bffc2b93f1e2719e853d756123cc8ab947/)

## Demo

![image](https://github.com/user-attachments/assets/bbf1b851-6950-471e-b881-8b0e6c05f0b6)

## References

* https://www.trellix.com/blogs/research/when-guardians-become-predators-how-malware-corrupts-the-protectors/
* https://www.bleepingcomputer.com/news/security/hackers-abuse-avast-anti-rootkit-driver-to-disable-defenses/
* https://caveiratech.com/post/malware-burla-antivirus-6715616
* https://www.joesandbox.com/analysis/1562334/1/html
* https://bazaar.abuse.ch/sample/e882af8b945c92e5a7dd337378e6a8bffc2b93f1e2719e853d756123cc8ab947/
* https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html
