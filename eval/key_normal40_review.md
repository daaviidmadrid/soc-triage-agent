# Level 1 practice exam: normal-day answer key to review

The answers for the 40 alerts in `key_normal40_alerts.txt`, a random sample in about the severity mix of a normal day. Scores here show how the AI copes with ordinary traffic, and `key40_review.md` covers the hard cases.

**Status: draft, not yet reviewed by a person.** Four Claude helpers wrote it from the policy, runbooks and logs, without seeing any AI ticket. It is a judgement, not ground truth.

The key has 19 attacks, 3 authorised and 18 false positives. To change an answer, edit `labels.csv` and replace `claude-draft` with your name.

## Check these first (6)

### ALR-20261007-001150: Correo reportado como phishing por un usuario

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (medium confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** The reported mail passes SPF, DKIM and DMARC for Tarvia's own domain, the gateway rates it clean, its link stays on tarvia.example, and the user never clicked it or showed odd activity afterwards. It looks harmless, but no drill is on record in the change calendar, so it can't count as authorised.

**Worth checking:** Only the subject line says this is a phishing drill, and that text proves nothing. Ask Security or HR to confirm the drill exists: it isn't in the change calendar or the context files, yet 301 copies went out across the whole month. Reopen if nobody owns it.

### ALR-20261013-003419: Malware detectado por el antivirus

**Draft answer:** `true_positive`, low, close (medium confidence). Rule `UC-EDR-003`, product EDR, rule severity medium.

**Why:** The antivirus correctly caught a potentially unwanted program and quarantined it before it ran, the sandbox rates it suspicious (45/100) with no network behaviour, and the laptop shows nothing unusual afterwards. So the detection is real but was stopped: base medium on an Alta laptop, -1 for being blocked, which matches the runbook's close at low with a full scan.

**Worth checking:** This is unwanted software rather than proven malware, so a team that treats it as harmless would call it false_positive; either way it closes without escalation. Run the full scan the runbook asks for. The logs don't show how the file reached the laptop.

### ALR-20261014-003718: Correo reportado como phishing por un usuario

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (medium confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** The reported mail passes SPF, DKIM and DMARC for Tarvia's own domain, the gateway rates it clean, its link stays on tarvia.example, and the user never clicked it or showed odd activity afterwards. It looks harmless, but no drill is on record in the change calendar, so it can't count as authorised.

**Worth checking:** Only the subject line says this is a phishing drill, and that text proves nothing. Ask Security or HR to confirm the drill exists, since it isn't in the change calendar. The same question applies to ALR-20261007-001150.

### ALR-20261016-004912: Malware detectado por el antivirus

**Draft answer:** `true_positive`, low, close (medium confidence). Rule `UC-EDR-003`, product EDR, rule severity medium.

**Why:** The antivirus correctly caught an unsigned unwanted program (WebCompanion) in the user's Downloads folder and quarantined it before it ran, and the laptop shows only routine activity afterwards. The rule's medium on a medium-criticality laptop stays medium, and the block lowers it one level to low, matching the runbook.

**Worth checking:** Run the full scan the runbook asks for. This is unwanted software rather than clear malware (sandbox: suspicious, score 45, signature only), so calling it malicious is a judgement call. The same file was quarantined 59 times on 58 machines this month and the proxy shows no download source, so someone may want to find where people are getting it.

### ALR-20261011-002595: Correo reportado como phishing por un usuario

**Draft answer:** `true_positive`, low, close (medium confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** This 'you won an iPhone' mail is a prize scam: it fails DMARC, the gateway rates it spam, and threat intel tags the domain as a scam. Nobody in the company clicked any of its 317 copies or visited the domain, so a low rule on a medium-criticality user stays low.

**Worth checking:** Threat intel only rates the domain suspicious (60), so malicious scam versus plain spam is a judgement call. Purge and block, because the gateway delivered it to 272 mailboxes. The blocked Chinese sign-in two days later (SIGN-0026478) came from an IP that tried 12 accounts, so it looks like separate password spraying, though this account saw four such attempts this month.

### ALR-20261020-006153: Beaconing a dominio poco frecuente

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (medium confidence). Rule `UC-NET-001`, product PROXY, rule severity medium.

**Why:** The same ping to this domain, with identical tiny sizes, comes from 131 hosts across the whole four weeks, which contradicts the rule's 'fewer than 3 hosts'. The domain is over six years old, its address is labelled a monitoring agent, and the laptop shows no suspicious process. It looks like ordinary monitoring software, not command and control.

**Worth checking:** Nothing in the inventory, change calendar or TIP names this agent, and the EDR shows no process for it. Ask IT to confirm it is managed software before adding a rule exclusion. This is why confidence is medium.

## Attacks marked high confidence (16)

### ALR-20261009-001854: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet hosting IP sent a real SQL injection probe to the shop's products API, the WAF answered 403, and the IP appears nowhere else in the logs. It falls inside the pentest dates, but CHG-2026-1042 only covers 192.0.2.10-12, so it is an unauthorised attempt that was blocked: low rule on the critical shop gives medium, minus one for the block gives low.

**Worth checking:** The alert counts 13 hits but the WAF log holds one row for this IP, so the other 12 rest on the alert's own 'blocked' field. No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket for a blocked internet scan; the severity does not copy its two-level drop.

### ALR-20261030-010347: Correo reportado como phishing por un usuario

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** This is real phishing: the domain imitates Microsoft, fails SPF and DMARC, and internal threat intel rates it malicious (90) as phishing. The user reported it without clicking and nobody in the company ever clicked or visited the domain, so a low rule on a medium-criticality user stays low with no adjustment.

**Worth checking:** Purge the mail and block the sender. The gateway marked it spam but still delivered it, and 323 copies reached 282 mailboxes over the month, so check whether that counts as mass delivery under the runbook. The blocked Russian sign-in (SIGN-0075712) came three hours before this mail and that IP tried 12 accounts, so it looks like separate password spraying. Same campaign as ALR-20261014-003645.

### ALR-20261011-011807: Actividad de cuenta de cliente compatible con toma de control (ATO)

**Draft answer:** `true_positive`, critical, escalate (high confidence). Rule `UC-WEB-003`, product ECOM, rule severity high.

**Why:** From one residential proxy IP in Vietnam, an automated browser made 54 failed customer logins and one success, then within 17 minutes changed that customer's email to a throwaway address and bought a gift card with the saved card. This is account takeover and fraud, and the pentest on the calendar doesn't explain it: it ended at 18:00 on 10 Oct Madrid time and used other IPs; base high on the online shop (Crítica) gives critical.

**Worth checking:** Treat this as part of a wider attack and group it: that night 26 headless logins succeeded across the 198.51.100.x range, followed by 12 email changes and 12 gift card purchases in the logs I checked. The Fraud team should reset accounts and try to stop the gift cards. On this purchase the gift card value is 150 but the amount charged is 250, which someone should explain.

### ALR-20261014-003645: Correo reportado como phishing por un usuario

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** This is the same Microsoft look-alike phishing campaign: it fails SPF and DMARC, and internal threat intel rates the domain malicious (90). The user reported it with no click, visit or unusual sign-in afterwards, so a low rule on a medium-criticality user stays low.

**Worth checking:** Purge and block as part of the campaign shared with ALR-20261030-010347. Her title is systems administrator but her account isn't flagged privileged; if she does hold admin rights, severity would rise to medium. Ask her to confirm the new iPhone added as an MFA method from the office (AUD-0000231). It came about three hours before this mail and hours after a blocked Chinese sign-in (SIGN-0030191), so the mail didn't cause it, and no new device shows up afterwards.

### ALR-20261008-001763: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet hosting IP probed a known PHPUnit exploit path, the WAF answered 403, no vulnerability is recorded for that path, and the IP appears nowhere else in the logs. It falls inside the pentest dates, but CHG-2026-1042 only covers 192.0.2.10-12, so it is an unauthorised attempt that was blocked: medium from the matrix, minus one for the block gives low.

**Worth checking:** The alert counts 18 hits but the WAF log holds one row for this IP, so the other 17 rest on the alert's own 'blocked' field. No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket for a blocked internet scan.

### ALR-20261101-010911: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet hosting IP sent a scripted SQL injection probe to the shop's products API, the WAF answered 403, and the IP appears nowhere else in the logs. No change covers this date or source, so it is an unauthorised attempt that was blocked: medium from the matrix, minus one for the block gives low.

**Worth checking:** The alert counts 9 hits but the WAF log holds one row for this IP, so the other 8 rest on the alert's own 'blocked' field. No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket for a blocked internet scan.

### ALR-20261009-002214: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet scanner tried to read the shop's /.env secrets file, the WAF answered 403, and the IP appears nowhere else in the logs. By event time this is inside the pentest window, but CHG-2026-1042 only covers 192.0.2.10-12, so it is an unauthorised attempt that was blocked: medium from the matrix, minus one for the block gives low.

**Worth checking:** The alert counts 28 hits but the WAF log holds one row for this IP, so the other 27 rest on the alert's own 'blocked' field. No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket for a blocked internet scan.

### ALR-20261010-011796: Escaneo de puertos interno

**Draft answer:** `true_positive`, high, escalate (high confidence). Rule `UC-NET-003`, product NGFW, rule severity medium.

**Why:** This is a buyer's laptop, not the authorised scanner, scanning servers at 02:28 Madrid on a Saturday. The EDR shows why: a phishing attachment ran a loader the day before (domain rated malicious, Latrodectus), then came AD discovery and a dump of LSASS credentials. Right after the scan it used PsExec with adm.aortega to reach FS01 and deleted its shadow copies (medium base on a Media laptop, +1 for confirmed execution).

**Worth checking:** The matrix stops at high for this one alert, but the chain looks like ransomware preparation, so N2 should treat it as one incident and act urgently on FS01 (Alta) and the adm.aortega account, which was used outside JUMP01. Check whether FS01's data was encrypted or copied.

### ALR-20261013-011816: Inicio de sesión exitoso desde infraestructura anónima o de hosting

**Draft answer:** `true_positive`, critical, escalate (high confidence). Rule `UC-IDP-004`, product IDP, rule severity high.

**Why:** A Tor exit node tried 26 staff accounts on the VPN at 03:00 Madrid, all failing, then got in as svc_backup, which has no MFA and is privileged. Four minutes later it used RDP to reach BACKUP01 and ran discovery commands against admins, domain trusts, the Finance share and the backups (high base, +1 for confirmed access by a privileged account). The MFA exemption is an accepted risk, not permission for this login.

**Worth checking:** The account's inventory note allows VPN for supplier maintenance, but no change covers this time and a supplier would not come through Tor, so confirm with the backup owner. Logs stop at 01:22 UTC with no VPN disconnect, so check whether the session continued or data was copied. Warn the business before disabling the account because backups depend on it. FS01 also appears in ALR-20261010-011796, so N2 should consider whether they are linked.

### ALR-20261021-006524: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet scanner probed a router-style command execution path, the WAF answered 403, no vulnerability is recorded for that path, and the IP appears nowhere else in the logs. No change covers this source (the weekly scan comes from internal NESSUS01), so it is an unauthorised attempt that was blocked: medium from the matrix, minus one for the block gives low.

**Worth checking:** The alert counts 29 hits but the WAF log holds one row for this IP, so the other 28 rest on the alert's own 'blocked' field. No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket for a blocked internet scan.

### ALR-20261019-005729: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet scanner looked for a WordPress login page on the shop, the WAF answered 403, and the IP appears nowhere else in the logs. No change covers this date or source, so it is an unauthorised probe that was blocked: medium from the matrix, minus one for the block gives low.

**Worth checking:** WEB-ECOM03 has an open blog plugin flaw (VLN-2026-0412, detected 15 Oct) on a different path; the WAF log shows no requests to that path. The alert counts 25 hits but the WAF log holds one row for this IP. No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket.

### ALR-20261015-011818: Envío de datos personales a correo externo

**Draft answer:** `true_positive`, high, escalate (high confidence). Rule `UC-DLP-002`, product DLP, rule severity medium.

**Why:** An employee leaving for a competitor two days later dumped the whole customer, order and loyalty tables, zipped them into an encrypted archive, uploaded it to mega.nz, and the next morning emailed a file with about 41,200 customer emails and 39,800 phone numbers to her personal address. Nothing in the change calendar authorises this and the DLP only audited it, so the data left; base medium on her Media laptop, +1 for personal data.

**Worth checking:** N2 should bring in HR, Legal and the DPO, because the 72-hour notification clock may apply. Group with ALR-20261014-011817. Severity uses her workstation as the affected asset as docs/decisions.md says; counting the CRM database (Crítica) would make it critical. Her last day was 16 Oct but her account still shows activity up to 22 Oct, so check whether access was removed.

### ALR-20261012-002906: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet hosting IP using the Nuclei scanner tried to read the shop's /.env secrets file, the WAF answered 403, and the IP appears nowhere else in the logs. The pentest ended on 10 Oct and no other change covers it, so it is an unauthorised attempt that was blocked: medium from the matrix, minus one for the block gives low.

**Worth checking:** The alert counts 28 hits but the WAF log holds one row for this IP, so the other 27 rest on the alert's own 'blocked' field. No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket for a blocked internet scan.

### ALR-20261007-001332: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet scanner made a single request to a known PHPUnit exploit path, the WAF answered 403, no vulnerability is recorded for that path, and the IP appears nowhere else in the logs. The pentest had not started and no other change covers it, so it is an unauthorised attempt that was blocked: medium from the matrix, minus one for the block gives low.

**Worth checking:** No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket for a blocked internet scan.

### ALR-20261010-011828: Viaje imposible

**Draft answer:** `true_positive`, high, escalate (high confidence). Rule `UC-IDP-001`, product IDP, rule severity medium.

**Why:** This is not really about travel: late on a Saturday someone on a commercial VPN with an unknown device sent 26 rejected MFA pushes in about 8 minutes until one was approved (MFA fatigue). That session downloaded the store's payslips and contracts and registered a new Android MFA method, which means confirmed access, personal data and persistence (medium base on a Media laptop, +1).

**Worth checking:** Call Sergio by another channel to confirm he did not knowingly approve it. N2 should decide on revoking the session and removing the new MFA method, and the DPO should assess the payslips. The alert's own note that the rule only fired on the VPN's network, and the TIP note about legitimate VPN clients, do not explain the rejected pushes. No sign-in row backs the Zaragoza login the alert cites, and geoip for 198.18.2.58 (RU hosting) disagrees with the sign-in log (Bilbao).

### ALR-20261030-010300: Ataque de inyección contra aplicación web

**Draft answer:** `true_positive`, low, close (high confidence). Rule `UC-WEB-001`, product WAF, rule severity low.

**Why:** An internet hosting IP using the Nuclei scanner probed a known PHPUnit exploit path, the WAF answered 403, no vulnerability is recorded for that path, and the IP appears nowhere else in the logs. No change covers this date or source, so it is an unauthorised attempt that was blocked: medium from the matrix, minus one for the block gives low.

**Worth checking:** The alert counts 21 hits but the WAF log holds one row for this IP, so the other 20 rest on the alert's own 'blocked' field. No EDR rows exist for WEB-ECOM01-04, so 'no effect' rests on the WAF alone. The true_positive label follows the challenge's example ticket for a blocked internet scan.

## Authorised or false positives marked high confidence (18)

### ALR-20261014-004078: Posible túnel DNS

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-NET-006`, product DNS, rule severity medium.

**Why:** The long names look like file hashes and every answer is the loopback address 127.0.0.2, the same pattern seen with dnsbl.spamhaus.org, sophosxl.net and avqs.mcafee.com, which points to reputation lookups rather than a tunnel. The domain is about nine years old, the alert counts 296 clients using it, threat intel has nothing, and the laptop shows only normal processes.

**Worth checking:** The alert claims 276 queries in an hour, but the DNS log shows only 6 for this host, in one 35-second burst, so the count should be reconciled. The data can't confirm who owns e5.sk or which product on the laptop makes these lookups, and that should be verified before excluding it from the rule.

### ALR-20261026-008281: Consulta DNS a dominio con aspecto DGA

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-NET-005`, product DNS, rule severity low.

**Why:** This is one lookup of a random-looking name under Microsoft's blob storage domain, which the rule mistook for malware-generated. 93 workstations across Barcelona, Madrid and Martorell looked up the same name once or twice each over 26 days, threat intel has nothing on it, and this laptop shows no proxy traffic to it and only normal processes.

**Worth checking:** The data doesn't say which application uses this storage name. Someone could identify it and consider a rule exclusion.

### ALR-20261019-005538: Consulta DNS a dominio con aspecto DGA

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-NET-005`, product DNS, rule severity low.

**Why:** This is one lookup of a random-looking name under Microsoft's azureedge.net content network, not a malware-generated domain. 92 workstations across all offices looked it up once or twice each over 25 days, threat intel has nothing on it, and this laptop shows no proxy traffic to it and only normal processes.

**Worth checking:** The data doesn't say which application uses this name. Someone could identify it and consider a rule exclusion.

### ALR-20261025-008022: Correo reportado como phishing por un usuario

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** This is an ordinary DocuSign notification: it passes SPF, DKIM and DMARC, is rated clean, has no attachment and no threat intel hit, and the same sender regularly mails a purchasing manager like her. She didn't click this message and nothing unusual followed, so the report was a mistaken one.

**Worth checking:** The logs don't include the mail body, so she could confirm she expected this supply contract. Her later click (CLK-0013496) was on a different DocuSign message, also rated clean.

### ALR-20261028-009223: PowerShell con comando codificado

**Draft answer:** `benign_true_positive`, low, close (high confidence). Rule `UC-EDR-002`, product EDR, rule severity medium.

**Why:** The rule is right that encoded PowerShell ran, but it is the approved SCCM software inventory in change CHG-2026-1031: started by the SCCM agent, covering all workstations, at 09:57 Madrid time inside the daily 08:00-10:00 window. The script only lists installed software to a local file, and nothing unusual followed on the laptop.

**Worth checking:** The event is logged as NT AUTHORITY\SYSTEM while the change names svc_sccm; it is accepted because the parent, command and window all match. The logged command line stops after the first statement and decodes only that far, so the rest of the script is known only from the EDR's decoded field.

### ALR-20261005-000099: Correo reportado como phishing por un usuario

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** This is a routine marketing newsletter: it passes SPF, DKIM and DMARC, the gateway rates it bulk rather than harmful, threat intel has nothing on the domain, and it goes regularly to many staff. He didn't click this copy and nothing unusual followed.

### ALR-20261028-009418: Malware detectado por el antivirus

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-EDR-003`, product EDR, rule severity medium.

**Why:** The file is EICAR, a harmless standard file made to test antivirus: the sandbox rates it clean (0/100), it was quarantined without running, and nothing unusual followed. No antivirus test is on the change calendar, so it is harmless with no authorisation on record rather than authorised.

**Worth checking:** The same customer service supervisor, who isn't in IT, triggered the same file on 9 Oct, and a PUA on 10 Oct (EDR-0027715). Someone could ask why; if these were real tests they should be on the calendar.

### ALR-20261026-008370: Consulta DNS a dominio con aspecto DGA

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-NET-005`, product DNS, rule severity low.

**Why:** This is the same azureedge.net name seen across 92 workstations over 25 days, here as a single lookup from this laptop. Threat intel has nothing on it, and the laptop shows no proxy traffic to it and only normal processes in the days around it.

**Worth checking:** The data doesn't say which application uses this name. Someone could identify it and consider a rule exclusion.

### ALR-20261005-000059: Consulta DNS a dominio con aspecto DGA

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-NET-005`, product DNS, rule severity low.

**Why:** This is one lookup of a random-looking name under Amazon's API gateway domain. 97 workstations looked up the same name once or twice each over 26 days, threat intel has nothing on it, and this laptop shows no proxy traffic to it; its only unusual process is the routine SCCM inventory script, which is unrelated.

**Worth checking:** The alert falls on the first day of the data, so "no history" can't be checked before 5 Oct; the later weeks are what show wide use. Someone could confirm which application calls this API.

### ALR-20261006-000501: Beaconing a dominio poco frecuente

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-NET-001`, product PROXY, rule severity medium.

**Why:** The 'beacon' is four identical tiny pings to teams.microsoft.com, which the TIP rates known-good, sent to the same address as normal Teams traffic. At least 59 hosts send the same ping, which contradicts the rule's 'fewer than 3 hosts', and the laptop shows only normal signed software, including Teams that morning. No change or flow covers it, so it is a misfire.

**Worth checking:** Consider excluding this domain from the rule. The EDR does not link the 'agent' user agent to a specific process.

### ALR-20261023-007361: Correo reportado como phishing por un usuario

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** This is a routine marketing newsletter: it passes SPF, DKIM and DMARC, the gateway rates it bulk rather than harmful, threat intel has nothing on the domain, and she has received earlier editions. She didn't click this copy and nothing unusual followed.

### ALR-20261028-011864: Escaneo de puertos interno

**Draft answer:** `benign_true_positive`, low, close (high confidence). Rule `UC-NET-003`, product NGFW, rule severity medium.

**Why:** It really is a scan, but it is the approved weekly one: the source is NESSUS01, the traffic ran at 01:05 Madrid on Wednesday 28 October inside the 01:00-05:00 window of CHG-2026-1052, and it passed the scanner firewall rule. None of its destinations are in the OT range the change excludes.

**Worth checking:** The log has 300 rows and 298 distinct destinations against the alert's 319 hosts, a small gap worth noting. The calendar times carry no timezone and are read as Europe/Madrid, which is what makes the UTC time fit after the clock change.

### ALR-20261017-011876: Conexión a red OT desde origen no autorizado

**Draft answer:** `benign_true_positive`, low, close (high confidence). Rule `UC-OT-001`, product NGFW, rule severity high.

**Why:** Traffic from JUMP01 to the sorter PLCs would normally be forbidden, but it fits approved vendor maintenance CHG-2026-1063 exactly: via JUMP01, through firewall rule OT-MAINT-TEMP, to PLC-SORT01..06 only (10.40.16.21-26), at 09:10-09:15 Madrid inside the 08:00-14:00 window. That rule carried no other traffic in the data. Base would be high, but authorised activity is low.

**Worth checking:** The logs cannot show who was on JUMP01, because the EDR has no rows for it at all despite being listed as installed. Ask Logistics to confirm the vendor session and that OT-MAINT-TEMP was removed afterwards. Take no containment action on OT.

### ALR-20261017-005021: Correo reportado como phishing por un usuario

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** This is a routine marketing newsletter: it passes SPF, DKIM and DMARC, the gateway rates it bulk rather than harmful, threat intel has nothing on the domain, and she has received it before. She didn't click this copy and no unusual sign-in or process followed.

**Worth checking:** Not linked to this mail, but worth a separate look: the next day DLP logged, without blocking, a confidential budget file sent to a supplier from her laptop (DLP-0000494).

### ALR-20261023-007556: Viaje imposible

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-IDP-001`, product IDP, rule severity medium.

**Why:** The 'Paris' login is his own compliant corporate phone, already seen the day before, reusing an existing MFA session and leaving through a Microsoft mobile relay/VPN exit, so he did not actually travel. Nothing was changed or downloaded afterwards. No trip or change is on record, so this is a misfire rather than authorised activity.

**Worth checking:** Consider excluding this mobile relay network from the impossible-travel rule.

### ALR-20261029-009691: Viaje imposible

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-IDP-001`, product IDP, rule severity medium.

**Why:** The 'Dublin' login is her own compliant corporate phone, used the day before from Spain, reusing an existing MFA session and leaving through a Microsoft mobile relay/VPN exit. Her laptop stayed in normal use and nothing was changed afterwards. No trip or change is on record, so this is a misfire rather than authorised activity.

**Worth checking:** Consider excluding this mobile relay network from the impossible-travel rule.

### ALR-20261021-006372: Correo reportado como phishing por un usuario

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-EML-001`, product EMAIL_GW, rule severity low.

**Why:** The reported mail is a routine LinkedIn sign-in notice from the real linkedin.com domain: SPF, DKIM and DMARC all pass, the link stays on linkedin.com, and 310 identical clean mails went to other staff. She never clicked it and her laptop and sign-ins show nothing unusual afterwards.

### ALR-20261019-005625: Beaconing a dominio poco frecuente

**Draft answer:** `false_positive`, no severity (the policy gives false positives none), close (high confidence). Rule `UC-NET-001`, product PROXY, rule severity medium.

**Why:** The laptop pinged settings-win.data.microsoft.com every 5 minutes with tiny fixed-size requests, but internal threat intel rates the domain known-good and the proxy shows 1,044 machines using it, so the rule's 'fewer than 3 machines' premise is wrong. No suspicious process appears on the laptop that day and no change on record covers it, so this is harmless noise rather than a command-and-control channel.

**Worth checking:** EDR does not show which process made the calls (the user agent is just 'agent'), so the source process is inferred, not confirmed. Consider excluding this domain from the rule. Separately, adware was quarantined on this laptop on 9 Oct (EDR-0027172); nothing links it to this traffic.
