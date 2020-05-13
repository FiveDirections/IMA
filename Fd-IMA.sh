#!/bin/bash
#
###################################################################################################
#
# LICENSE: This code is provide to the United States Government with unlimited rights.
#
# This script was originally written for the DARPA Transparent Computing (TC) Program.
# The TC program web page can be found at https://www.darpa.mil/program/transparent-computing
#
# Original release: 13 May 2020 DISTAR Case 32969
#
# DISTRIBUTION A (Approved for Public Release, Distribution Unlimited)
#
#
# This script creates one directory and two files. The directory is /etc/ima.
# This is the default directory for IMA policy files in later versions of CentOS/RHEL.
# The two files are /etc/ima/ima-policy.systemd which contains the IMA policy for the
# machine, and $UNITFILE which contains the systemd unit
# specification. Each of these files are created with a 'here doc' via a function call
# to improve the readability of the code. Additionally, the file /etc/fstab is modified
# to include the iversion mount option for the root partition.
#
# NOTE: THIS ONLY WORKS FOR A DEFAULT INSTALL OF Centos/RHEL. Use on a custom install will
# require modification. 
#
# Once the files are created, permissions are set and the unit spec is associated with systemd.
#
# THIS FILE MUST BE RUN AS ROOT
#
###################################################################################################
#
# GLOBALS
#
###################################################################################################
#
PROGNAME=$(basename $0)
# Where the policy is kept
IMAFILE=/etc/ima/ima-policy.systemd
# The systemd unit file
UNITFILE=/usr/lib/systemd/system/Fd-IMA.service
# Version of CentOS/RHEL
OSVER="unknown"
#
####################################################################################################
#
# Functions
#
###################################################################################################
#
# Error and exit
#
# Takes one argument the string to print and returns 1 since there is an error.
#
###################################################################################################
error_exit () {
	/usr/bin/echo "${PROGNAME}: ${1}" 1>&2
    /usr/bin/echo "INSTALLATION FAILED"
	exit 1
}
###################################################################################################
#
# Check OS version
#
# Takes no arguments and returns the OSVER set to either the version or 'unknown'
#
function checkosver {
    OSVER=`/usr/bin/hostnamectl | /usr/bin/awk '$3~/CentOS/ {print $5}'`
    if [[ "$OSVER" == "" ]]; then
        OSVER=`/usr/bin/hostnamectl | /usr/bin/awk '$3~/Red/ {print $7}'`
        OSVER=${OSVER::1}
    fi
}
###################################################################################################
#
# Create the IMA Policy file
#
# Takes no arguments and returns non-zero if the file is not created
#
###################################################################################################
function ima-policy {
    cat << EOF > $IMAFILE
audit func=BPRM_CHECK mask=MAY_EXEC
audit func=MMAP_CHECK mask=MAY_EXEC
EOF
#
# If file wasn't created error and exit
#
    [ ! -f "$IMAFILE" ] && error_exit "$LINENO: IMA policy file not created! Aborting"
}
###################################################################################################
#
# Create the Unit specification file
#
# Takes no arguments and returns non-zero if the file is not created
#
###################################################################################################
function unit-spec {
    cat << EOF > $UNITFILE
[Unit]
Description=Set IMA policy at boot
After=auditd.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/bin/cat $IMAFILE > /sys/kernel/security/ima/policy'
RemainAfterExit=True

[Install]
WantedBy=basic.target
EOF
#
# If file wasn't created error and exit
#
    [ ! -f "$UNITFILE" ] && error_exit "$LINENO: UNIT file not created! Aborting"
}
###################################################################################################
#
# End of functions
#
###################################################################################################
#
# main body
#
###################################################################################################
#
# Check we're on the right/tested OS
#
checkosver
if [[ "$OSVER" != "8" && "$OSVER" != "7" ]]; then
    error_exit "This script only works on CentOS/RHEL 7 and 8! Aborting"
fi
#
# Make sure we're root
#
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root! Aborting"
fi
# 
# TODO: check if /etc/ima exists to prevent erroring out here
#
/usr/bin/mkdir /etc/ima || error_exit "$LINENO Cannot create /etc/ima! Aborting"
ima-policy
/usr/bin/chmod 600 $IMAFILE || error_exit "$LINENO Cannot chmod IMA file! Aborting"
unit-spec
/usr/bin/touch $UNITFILE || error_exit "$LINENO Cannot touch service file! Aborting"
/usr/bin/chmod 664 $UNITFILE || error_exit "$LINENO Cannot chmod service file! Aborting"
/usr/bin/systemctl link $UNITFILE || error_exit "$LINENO Cannot create service link! Aborting"
/usr/bin/systemctl daemon-reload || error_exit "$LINENO Cannot reload daemon! Aborting"
/usr/bin/systemctl enable Fd-IMA.service || error_exit "$LINENO Cannot enable service! Aborting"
/usr/bin/systemctl start Fd-IMA.service || error_exit "$LINENO Cannot start service! Aborting"
#
# THE BELOW IS ONLY FOR CentOS/RHEL 7.
# remount the root file system with iversion. NOTE: default install only uses / as the base
#                                             filesystem. This will have to be redone depending
#                                             on standard practice per location.
#
if [[ "$OSVER" == "7" ]]; then
    # XXXXX SPECIAL CASE WARNING XXXXX
    # The code below only works on a default install where the entire file system is placed in /.
    # If the install has a custom file system, this code MUST BE CHANGED.
    #
    /usr/bin/mount -o remount,iversion,defaults / || error_exit "$LINENO Unable to remount /! Aborting"
    #
    # Modify /etc/fstab so that / is always mounted with iversion
    #
    /usr/bin/cp /etc/fstab /etc/fstab.orig || error_exit "$LINENO Creating back-up of fstab failed!"
    #
    # This awk command looks for the root entry and then adds iversion before the current mount options.
    #
    /usr/bin/awk '$2~"^/$"{$4="iversion,"$4}1' OFS="\t" /etc/fstab > /etc/fstab.tmp || error_exit "$LINENO Modifying fstab failed!"
    /usr/bin/cp /etc/fstab.tmp /etc/fstab || error_exit "$LINENO Copying new fstab failed!"
fi
/usr/bin/echo "Installation completed successfully."
exit 0