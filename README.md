# File Integrity Monitoring for Linux
Five Directions, Inc
March 2020

## Funding
This script was produced as part of a transition effort from the DARPA Transparent Computing (TC) program. This README provides a basic description of the script as well as an overall manifest and description of each file. The TC program web page can be found at https://www.darpa.mil/program/transparent-computing

DARPA is releasing these files in the public domain to stimulate further research. Their release implies no obligation or desire to support additional work in this space. The data is released as-is. DARPA makes no warranties as to the correctness, accuracy, or usefulness of the released data. In fact, since the data was produced by research prototypes, it is practically guaranteed to be imperfect. Nonetheless, as this data represents a very large repository of semantically rich and structured data, DARPA believes that it is in the best interests of the Department of Defense and the research community to make them freely available.

## Overview
Integrity is fundamental to the protection/security of a computer system. Without integrity, it is impossible to ensure confidentiality and availability as the mechanisms implementing them could be compromised.

Integrity monitoring for Linux has typically been provided by external packages such as Tripwire or AIDE since there was no built-in capability to monitor or report integrity on Linux. This changed in 2009 when Linux kernel version 2.6.36 was released with the Integrity Measurement Architecture (IMA). Unfortunately IMA and the related subsystems are poorly understood and documented.

Tripwire and AIDE monitor file integrity via an on-demand or scheduled basis. Thus, an intruder could modify a file without detection until the next on-demand or scheduled scan. IMA, however, when combined with the Linux audit subsystem enables the continuous integrity reporting of files accessed or executed along with the process that accessed or executed the file. Replacing Tripwire/AIDE would require local or back-end logic to determine when reported hashes have changed and is not covered in this document.

This document will provide a brief overview of IMA and describe how to enable continuous reporting of the cryptographic hashes for files executed or memory mapped for execution. Collecting hashes from files accessed is also possible. However, the sheer size of the telemetry from such monitoring may severly saturate network links.

## Integrity Measurement Architecture (IMA)
IMA was originally intended to implement the capabilities described by the Trusted Computing Group (TCG) which is a consortium of companies from the computer industry. The TCG designed the Trusted Platform module (TPM). The TPM is a hardware chip, virtual TPM (vTPM) also exist, residing on the motherboard of a computer. <span id="a3">[[3]](#f3)</span>

The TPM provides two hardware capabilities for the operating system:
**Sealed storage** – enables keeping secret values/keys within hardware
**Platform configuration registers** – a PCR is a memory location in the TPM. They are used to hold the result of a chained cryptographic hash in a secure fashion.

IMA provides three basic funtions:
-   **Collect**  – measure a file before it is accessed.
-   **Store**  – add the measurement to a kernel resident list and, if a hardware Trusted Platform Module (TPM) is present, extend an IMA PCR
-   **Attest**  – if present, use the TPM to sign the IMA PCR value, to allow a remote validation of the measurement list

*Store* and *Attest* enable the ability to implement a measured boot and securely attest that the state of machine is in a known good state after completing the boot sequence. Implementing a measured boot is out of scope.  The focus of this document is how to implement the collect/measurement capability on Linux (focusing on CentOS and RHEL) via the audit subsystem, *e.g.* integrity measurements are placed into ```/var/log/audit/audit.log```. Using ```rsyslog``` or another log forwarding
program is also out of scope.

### Enabling IMA Audit
There are two steps to enabling IMA audit. First, IMA must be compiled into the kernel. Second, IMA policy must be loaded at some point- ideally as early in the boot process as possible.

#### Configuring the Kernel
While IMA is included in Linux kernels after 2.6.36, it may not be enabled depending on the Linux distribution used. Fortunately, both CentOS and RHEL enable IMA in their default kernel. 

You can determine if IMA is enabled in your distribution in two ways. The first is to look at a running system and see if the directory ```/sys/kernel/security/integrity/ima``` exists. If it doesn’t, you can try and mount the security filesystem via 
```
mount -t securityfs security /sys/kernel/security
```
and check for the *ima* directory again. If it doesn’t exist, then you need to configure and recompile the kernel.

The following kernel config options need to be set and the kernel recompiled and installed:
-   ```CONFIG_INTEGRITY```
-   ```CONFIG_IMA```
-   ```CONFIG_AUDIT```
-   ```CONFIG_IMA_AUDIT```

Configuration options vary widely by kernel version. You MUST confirm the exact options needed for your specific kernel.

*Kernel configuration and recompilation is beyond the scope of this document.*

#### Loading Policy
Once the kernel supports Audit and IMA, the next step is loading a policy. This is ideally done as early in the boot process as possible via ```initramfs``` (IMA only not AUDIT)  if a trusted boot is desired, and/or via ```systemd``` after the audit subsystem has started for our purposes.

```systemd``` version 240 includes support for loading IMA policies. Unfortunately for us, CentOS/RHEL 8 ships with ```systemd``` 239. As a result, we need to install a ```systemd``` unit file and enable it. A bash script, ```Fd-IMA.sh``` to do so is included with this deliverable.

The bash script creates two files on the file system:
```/etc/ima/ima-policy.systemd```   NOTE: The directory ```/etc/ima``` is also created.
```/usr/lib/systemd/system/Fd-IMA.service```

This naming convention was used to mirror that of ```systemd``` v2.40 except that we use different files names to prevent collisions if an upgrade occurs at a later date. Additionally, the service is set to start after the *auditd* service has started.

#### System Files
IMA uses several files within the security file system located at ```/sys/kernel/security/ima```. The only file of importance to our effort is the ```policy``` file. Setting an IMA policy is by writing the policy to the ```policy``` file. Once written, the ```policy``` file disappears and the policy cannot be changed until the system is rebooted.

### Policies
The IMA subsystem ships with several builtin policies, but it is also capable of accepting custom policies. For this effort, we’re using a custom policy that is a subset of the default policy.

#### One Builtin Policy
One default IMA policy is named *ima_tcb*. The policy measures all files executed, all files memory mapped with the execute permission, and all files accessed by the root (uid=0) user.

The default (*may vary by distribution and kernel version*) policy is:
```
dont_measure fsmagic=PROC_SUPER_MAGIC
dont_measure fsmagic=SYSFS_MAGIC
dont_measure fsmagic=DEBUGFS_MAGIC
dont_measure fsmagic=TMPFS_MAGIC
dont_measure fsmagic=SECURITYFS_MAGIC
dont_measure fsmagic=SELINUX_MAGIC
measure func=BPRM_CHECK
measure func=FILE_MMAP mask=MAY_EXEC
measure func=PATH_CHECK mask=MAY_READ uid=0
```

One of the advantages of the default policy is that it can be set at boot time via modifications to the grub command line. A disadvantage of the default policy is that it measures all files by the root user which creates a significant number of events. An additional disadvantage is that the default policy only reports the measurements to the files in ```/sys/kernel/security/ima``` without correlating the measurements to the process or thread that opened or executed the file.

#### Custom Policies
We’re not concerned with simply measuring files as provided by the default policy. We want to measure the file and have the correlated results reported to the audit subsystem. To do so, we must define a custom policy.

As mentioned in the introduction, IMA is not documented well. The only syntax specification we could find for custom policies is a document from Mimi Zohar in 2008. <span id="a4">[[4]](#f4)</span> The specification is shown below:
```
		rule format: action [condition ...]

		action: measure | dont_measure | appraise | dont_appraise |
			audit | hash | dont_hash
		condition:= base | lsm  [option]
			base:	[[func=] [mask=] [fsmagic=] [fsuuid=] [uid=]
				[euid=] [fowner=] [fsname=]]
			lsm:	[[subj_user=] [subj_role=] [subj_type=]
				 [obj_user=] [obj_role=] [obj_type=]]
			option:	[[appraise_type=]] [template=] [permit_directio]
				[appraise_flag=] [keyrings=]
		base: 	func:= [BPRM_CHECK][MMAP_CHECK][CREDS_CHECK][FILE_CHECK][MODULE_CHECK]
				[FIRMWARE_CHECK]
				[KEXEC_KERNEL_CHECK] [KEXEC_INITRAMFS_CHECK]
				[KEXEC_CMDLINE] [KEY_CHECK]
			mask:= [[^]MAY_READ] [[^]MAY_WRITE] [[^]MAY_APPEND]
			       [[^]MAY_EXEC]
			fsmagic:= hex value
			fsuuid:= file system UUID (e.g 8bcbe394-4f13-4144-be8e-5aa9ea2ce2f6)
			uid:= decimal value
			euid:= decimal value
			fowner:= decimal value
		lsm:  	are LSM specific
		option:	appraise_type:= [imasig] [imasig|modsig]
			appraise_flag:= [check_blacklist]
			Currently, blacklist check is only for files signed with appended
			signature.
			keyrings:= list of keyrings
			(eg, .builtin_trusted_keys|.ima). Only valid
			when action is "measure" and func is KEY_CHECK.
			template:= name of a defined IMA template type
			(eg, ima-ng). Only valid when action is "measure".
			pcr:= decimal value
```

The effects from the various options in the syntax are not well defined, if at all. A FireEye blog post by Alek Rollyson in November 2016 showed how IMA audit could be enabled in Ubuntu 16.04.1. <span id="a5">[[5]](#f5) Additional work, however, was required to support CentOS/RHEL.

### Supported Versions
IMA was introduced in Linux kernel 2.6.36, and therefore IMA is only supported on CentOS/RHEL 7+. The kernel used in CentOS/RHEL version 7 is 3.10.0. CentOS/RHEL 6 used the 2.6.32 kernel and thus IMA is not supported on any version under CentOS/RHEL 7. The kernel used in CentOS/RHEL 8 is 4.18.X.

### Limitations of CentOS/RHEL 7.X
IMA only supported MD5 and SHA1 as cryptographic hashes from kernel 2.6.36 to 3.12.0 when SHA256 was added. The default hash is SHA1.

NOTE: We have not added SHA256 support on CentOS/RHEL 8 to ensure a unified install and backend analysis between OS versions.

## iVersion
Measuring every file either opened or executed *every* time would be very expensive <span id="a1">[[1]](#f1)</span>. As a result, a number of file systems have added the ability to keep track of when a file changes in the meta-data of the file. iVersion is an example of one such meta-data element.

Most UNIX based file systems use a data structure that holds meta-data for directories and files called an inode. One piece of meta-data in an inode in filesystems such as xfs, ext4, and btrfs is the *i_Version*. The *i_Version* field changes any time there is a change to any data or metadata associated with the inode <span id="a2">[[2]](#f2)</span>. IMA leverages *i_version* to avoid having to remeasure files that have already been measured. This does introduce the possibility that IMA maeasuring can be avoided by resetting the *i_version* field to its original value after a file modification. This would require the adversary to load a device driver to affect the changes. An adversary with the access level needed to load a device driver can already affect the security of the system greatly.

*i_version* is enabled by default on CentOS/RHEL 8. It must be enabled in CentOS/RHEL 7.


## Installation
Installation is straightforward on CentOS/RHEL 7 and 8 via the delivered bash and Ansible scripts. The bash script includes significant error checks that are sent to STDOUT.

## Appendix: Example Log Entries

Below are example log entries for file executes and mmap’d files.

### Upon start-up of IMA/Audit
```
type=INTEGRITY_RULE msg=audit(1585509232.084:289): action="audit" func="BPRM_CHECK" mask="MAY_EXEC" res=1
type=INTEGRITY_RULE msg=audit(1585509232.084:290): action="audit" func="MMAP_CHECK" mask="MAY_EXEC" res=1
```

### Example audit entry file execution 
```
type=INTEGRITY_RULE msg=audit(1585509232.075:292): file="/usr/bin/pkla-check-authorization" hash="533aab6a68d00e7e01611d31acb798c6fc843406" ppid=680 pid=12410 auid=4294967295 uid=999 gid=998 euid=999 suid=999 fsuid=999 egid=998 sgid=998 fsgid=998 tty=(none) ses=4294967295 comm="polkitd" exe="/usr/lib/polkit-1/polkitd" subj=system_u:system_r:policykit_t:s0
type=INTEGRITY_RULE msg=audit(1585509232.130:329): file="/usr/bin/mount" hash="28cf7810e3b4d891dba68f0ccd4f30c5736f2c5c" ppid=12301 pid=12417 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="Fd-IMA.sh" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
type=INTEGRITY_RULE msg=audit(1585509232.144:330): file="/usr/bin/cp" hash="3a5ac7aae41b2afb148210babf97f792ca6ed879" ppid=12301 pid=12420 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="Fd-IMA.sh" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
type=INTEGRITY_RULE msg=audit(1585509232.148:332): file="/usr/bin/awk" hash="47463d0a3f2764e11fee19dfb62211e2d757a1a5" ppid=12301 pid=12421 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="Fd-IMA.sh" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
type=INTEGRITY_RULE msg=audit(1585509232.151:333): file="/usr/bin/echo" hash="b18ade0de3f6af3ff9576b2757c89c4c0049d864" ppid=12301 pid=12423 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="Fd-IMA.sh" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
type=INTEGRITY_RULE msg=audit(1585509232.154:334): file="/usr/bin/sed" hash="6ecf9700205a1fde9b7605f2749c5001419c3d3f" ppid=12424 pid=12426 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
type=INTEGRITY_RULE msg=audit(1585509235.795:335): file="/usr/bin/ls" hash="3a8573bbffe368e88e6cf9f1a2f3b5ca76444c52" ppid=10186 pid=12432 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
type=INTEGRITY_RULE msg=audit(1585509238.755:336): file="/usr/bin/date" hash="976f3b2b8511cf5c4c95067b0a221a6952f5035a" ppid=10186 pid=12439 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
type=INTEGRITY_RULE msg=audit(1585509238.791:337): file="/usr/bin/pgrep" hash="03be728c30a053aa6ab6110c3786c36d33e479bf" ppid=12449 pid=12450 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="ksmtuned" exe="/usr/bin/bash" subj=system_u:system_r:ksmtuned_t:s0
```

### Example audit entry for mmap’d file with execute privileges
```
type=INTEGRITY_RULE msg=audit(1585509232.075:292): file="/usr/lib64/ld-2.17.so" hash="681bd8955812d5d452d4fea378051f9fe7e8007e" ppid=680 pid=12410 auid=4294967295 uid=999 gid=998 euid=999 suid=999 fsuid=999 egid=998 sgid=998 fsgid=998 tty=(none) ses=4294967295 comm="pkla-check-auth" exe="/usr/bin/pkla-check-authorization" subj=system_u:system_r:policykit_t:s0
type=INTEGRITY_RULE msg=audit(1585509232.085:293): file="/usr/lib64/libpolkit-gobject-1.so.0.0.0" hash="2fc79a6ca85828b56c4836622dab06045da3c6bc" ppid=680 pid=12410 auid=4294967295 uid=999 gid=998 euid=999 suid=999 fsuid=999 egid=998 sgid=998 fsgid=998 tty=(none) ses=4294967295 comm="pkla-check-auth" exe="/usr/bin/pkla-check-authorization" subj=system_u:system_r:policykit_auth_t:s0
type=INTEGRITY_RULE msg=audit(1585509232.085:294): file="/usr/lib64/libgio-2.0.so.0.5600.1" hash="7b13e13d7c6e42db02895e5a71f6fad616d1806f" ppid=680 pid=12410 auid=4294967295 uid=999 gid=998 euid=999 suid=999 fsuid=999 egid=998 sgid=998 fsgid=998 tty=(none) ses=4294967295 comm="pkla-check-auth" exe="/usr/bin/pkla-check-authorization" subj=system_u:system_r:policykit_auth_t:s0
type=INTEGRITY_RULE msg=audit(1585509232.087:295): file="/usr/lib64/libgobject-2.0.so.0.5600.1" hash="15e74ebcd59bdde0530a291f3a0f534687365bf7" ppid=680 pid=12410 auid=4294967295 uid=999 gid=998 euid=999 suid=999 fsuid=999 egid=998 sgid=998 fsgid=998 tty=(none) ses=4294967295 comm="pkla-check-auth" exe="/usr/bin/pkla-check-authorization" subj=system_u:system_r:policykit_auth_t:s0
type=INTEGRITY_RULE msg=audit(1585509232.146:331): file="/usr/lib64/libacl.so.1.1.0" hash="0b85bc89a27262a5de4f2db89a876169f907b3b3" ppid=12301 pid=12420 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="cp" exe="/usr/bin/cp" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

### Operational Use
The above audit entries are found in the file ```/var/log/audit/audit.log```. Our approach presumes an existing infrastructure, *e.g.* rsyslog, to forward contents of the file to a backend analysis system.

## References
1. <span id="f1"></span> L. van Doorn, G. Ballintijn, and W. Arbaugh. Signed Executables for Linux.  [*Technical report CS-TR-4259, University of Maryland, College Park June 2001.*](http://www.cs.umd.edu/~waa/pubs/cs4259.ps) [$\hookleftarrow$](#a1)
2. <span id="f2"></span> Jeff Layton. fs:rework and optimize i_version handling in filesystems. [*Email to fsdevel mailing list. 22 December 2017.*](https://lwn.net/Articles/742137/) [$\hookleftarrow$](#a2)
3. <span id="f3"></span> D. Safford et. al. [*Internet Measurement Architecture (IMA).*](https://sourceforge.net/p/linux-ima/wiki/Home/) [$\hookleftarrow$](#a3)
4. <span id="f4"></span> Mimi Zohar. [*security/ima/policy*](https://www.kernel.org/doc/Documentation/ABI/testing/ima_policy) [$\hookleftarrow$](#a4)
5. <span id="f5"></span> Alek Rollyson. Extending Linux Executable Logging with the Integrity Measurement Architecture, November 2016. [*FireEye Blog post*](https://www.fireeye.com/blog/threat-research/2016/11/extending_linux_exec.html)

## File Manifest and Descriptions
README.md - This file.
Fd-IMA.sh - A bash shell script to enable IMA audit on CentOS/RHEL 7 and 8.
Fd-IMA.ansible - An ansible script to run the Fd-IMA.sh file.

Jacob Tory<br/>
Program Manager<br/>
DARPA/I2O

Original release: 13 May 2020 DISTAR Case 32969

DISTRIBUTION A (Approved for Public Release, Distribution Unlimited)



