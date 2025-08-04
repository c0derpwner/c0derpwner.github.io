---
layout: page
title: About
---

[HTB-Account](https://app.hackthebox.com/profile/1086633)


## whoami

I'm an enthusiast researcher and Senior Pentester pretty almost dedicated to CTF. I have almost 10 years experience and i did almost then 300 Penetration Test and 20 researches, some of those are public like the `CVE-2022-24637` or the `Zend` Upload which brings a PHP heap exploit.

Freelancer who works with more than 20 leading Italian companies in the IT sector, first analysing various vulnerabilities and then securing the code. I'm pretty dedicated to Computer Science and to bring knowledge to anyone who visits this sort of Blogspot.
Very near to Omniscient on HTB platform as shown here: 

![](/assets/8th_c0der.png)


Got RCE troght oob read/write in the famous Sorting insertion bug presented in the `memcpy` if `msort_with_TMP` .
This memory corruption in the GNU C Library through the qsort function is invoked by an application passing a non-transitive comparison function, which is undefined according to POSIX and ISO C standards. As a result, we are of the opinion that the resulting CVE, if any, should be assigned to ny such calling applications and subsequently fixed by passing a valid comparison function to qsort and not to glibc. We however acknowledge that this is a  quality of implementation issue and we fixed this in a recent refactor of `qsort`. We would like to thank `Qualys` for sharing their findings and helping  us validate our recent changes to qsort.  