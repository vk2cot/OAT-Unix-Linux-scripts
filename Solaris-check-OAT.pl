#!/bin/sh -- # Really perl
eval 'exec perl -S $0 ${1+"$@"} 2>/dev/null'
  if 0;
#
# @(#) $Id: Solaris-check-OAT.pl,v 1.10 2014/05/05 12:45:26 root Exp root $
#
# Description: Basic Operations Acceptance Testing for Solaris servers
#              Results are displayed on stdout or redirected to a file
#
# If you obtain this script via Web, convert it to Unix format:
# dos2unix Solaris-check-OAT.pl.txt ... 
#
# Usage:       Solaris-check-OAT.pl [-c] [-h] [-n] [-p] [-r] [-t conffile] \
#              [-v] [> `uname -n`-OAT-report.txt]
#              -c                  Enable check of SUID/SGID files
#              -f                  Enable NMAP scans
#              -h                  Print this help message
#              -n                  Enable SUID/SGID checks in NFS
#              -p                  Enable patch checks through SUNWinck
#              -r                  Server part of cluster or H/A server group
#              -t file             Read variables from a config file
#              -v                  Print version of this script
#
# Last Update:  20 May 2014
# Designed by:  Dusan U. Baljevic (dusan.baljevic@ieee.org)
# Coded by:     Dusan U. Baljevic (dusan.baljevic@ieee.org)
#
# Copyright 2006-2014 Dusan Baljevic
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Perl script Solaris-check-oat.pl is a modest attempt to automate basic
# tasks when running Operations Acceptance Testing (OAT) for a server
# that is about to be commissioned or checked.
#
# The script tries to capture most critical information about an Solaris
# server and highlights potential configuration or system problems.
#
# The script has been developed over several hectic days, so errors
# (although not planned) might exist. Please use with care.
#
# There are not many comments throught the script and that
# is not best practices for writing good code. However,
# I see this script as a learning tool for system administrators
# too so lack of comments is partially left as an exercise.
#
# My goals were:
#
# A) Simplicity to do basic Operations Acceptance Testing (OAT)
# on Solaris servers;
# B) Portability;
# C) Standard Perl interperter (very few modules - optional);
# D) Many new features;
# E) Support for SVM and VxVM;
# F) No temporary files;
# G) No repeated runs of similar commands;
# H) Not to replace more comprehensive debugging tools but
# provide a quick summary of server status;
# I) Usefullness of results, not their formatting on the screen;
#
# Like all scripts and programs, this one will continue to
# change as our needs change.

use strict;
no strict 'subs';
no strict 'refs';

# use diagnostics;
# use warnings;

use vars qw($CMD $pty $System $Hostname $Maj $Version $Major $Minor $Patch
  $opt_h $opt_f $fqdn $Hardware $u $Model %DKARRAY $MEM_MBYTE %OSARRAY $s
  $opt_c $opt_d $opt_n $opt_p $opt_r $opt_t $opt_v %ZKARRAY $dpcw %lines
  %shadarr);

my $SCRIPT_VERSION = "2014052001";
my $REC_VERSION    = '5.006';
my $CUR_VERSION    = "$]";

if ( "$CUR_VERSION" < $REC_VERSION ) {
    print "WARNING: This script has only been tested for use with
Perl version $REC_VERSION and above. 

The Perl on this server is version $CUR_VERSION.

Proper functionality with older Perl is unknown and unsupported.

It is recommended to:

a) Change the first line in this script

  #!/usr/bin/env perl

   to a full path of a newer version of Perl, for example:

  #!/usr/contrib/bin/perl
    or
  #!/opt/perl/bin/perl 

or

b) Change the environment variable PATH outside this script
   and put the better version of Perl first in the directory search.
\n";
    exit(1);
}

#
# Define important environment variables
#
my $Model = `uname -i`;
chomp($Model);

$ENV{'PATH'} = "/usr/bin:/usr/sbin:/sbin:/bin:/usr/ccs/bin:/etc";
$ENV{'PATH'} = "$ENV{PATH}:/usr/cluster/bin:/usr/lib/osa/bin:/usr/sbin/osa";
$ENV{'PATH'} = "$ENV{PATH}:/usr/local/sbin:/usr/aset:/opt/VRTS/bin:/opt/VRTSvmsa/bin";
$ENV{'PATH'} = "$ENV{PATH}:/etc/vx/bin:/opt/samba/bin:/usr/platform/${Model}/sbin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/VRTSvcs/vxfen/bin:/opt/VRTSvxfs/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/VRTSdbed/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/VRTSdb2ed/bin:/opt/VRTS/vxse/vxvm";
$ENV{'PATH'} = "$ENV{PATH}:/opt/VRTSsybed/bin:/opt/VRTSob/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/SUNWvts/bin:/opt/SUNWinck/bin:/opt/SUNWut/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/SUNWut/sbin:/opt/sfw/bin:/usr/sfw/bin:/etc/fw/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/SUNWssmu/bin:/opt/VRTSvcs/bin:/etc/opt/SUNWconn/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/SUNWssp/bin:/opt/SUNWSMS/bin:/opt/SUNWsrspx/bin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/symcli/bin:/opt/Navisphere/bin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/local/bin:/opt/CPQswsp/bin:/usr/opt/SUNWesm/sbin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/SUNWsan/bin:/opt/hpsmc/rcm/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/omni/bin:/opt/omni/lbin:/opt/omni/sbin";
$ENV{'PATH'} = "$ENV{PATH}:/var/opt/OV/bin/OpC/cmds:/opt/HPO/SMSPI";
$ENV{'PATH'} = "$ENV{PATH}:/HORCM/usr/bin:/opt/HORCM/usr/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/OV/bin:/opt/OV/bin/OpC:/opt/OV/contrib/OpC";
$ENV{'PATH'} = "$ENV{PATH}:/opt/erm/sbin:/opt/SUNWsneep/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/resmon/bin:/usr/lbin/sysadm:/opt/SUNWldm/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/tivoli/tsm/server/bin:/opt/tivoli/tsm/client/ba/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/adsmserv/bin:/opt/DynamicLinkManager/bin";
$ENV{'PATH'} = "$ENV{PATH}:/etc/init.d:/opt/FJSVmadm/sbin:/var/cfengine/bin";

$ENV{'SHELL'} = '/sbin/sh' if $ENV{'SHELL'} ne '';
$ENV{'IFS'}   = ''         if $ENV{'IFS'}   ne '';

#
# Global variables
#
my $ffs              = q{};
my $addr             = q{};
my $file_perms       = q{};
my $alldet           = q{};
my $tswap            = q{};
my $tswapUSED        = q{};
my $uptime           = q{};
my @Alldevs          = ();
my @alllocales       = ();
my $ngroupsmax       = q{};
my $ORATAB           = "/etc/oratab";
my $ORATAB2           = "/var/opt/oracle/oratab";
my @ORAARR           = ( "$ORATAB", "$ORATAB2", ) ;
my @CHECKARR         = ();
my @FSWARN           = ();
my $dssize           = q{};
my @NETARR           = ();
my @KERNARR          = ();
my @LANARR           = ();
my $LANmode          = q{};

my @VXERRARR         = ();
my $vxdiskls         = q{};
my @VXALLDISK        = ();
my $VXDEFATTRS       = q{};
my $VXDBFILE         = q{};
my $vxdgls           = q{};
my @CHECKVXVM        = ();

# Delay and count values for commands vmstat, iostat, mpstat, and sar...
#
my $ITERATIONS       = 10;
my $DELAY            = 2;

my $h                = q{};
my $Lsys             = q{};
my $host             = q{};
my $POOLCFG          = "/etc/pooladm.conf";
my @MAU              = ();
my @haddrs           = ();
my $psize            = q{};
my $puid             = q{};
my @hchk             = ();
my @heq              = ();
my $allocated        = q{};
my $avail            = q{};
my @bge_driver       = ();
my $c                = q{};
my $Bootpath         = q{};
my $displ            = q{};
my $passnofs         = q{};
my $pcused           = q{};
my $pgsize           = q{};
my $oct_perms        = q{};
my $offset           = q{};
my $used             = q{};
my $USED             = q{};
my $gid              = q{};
my $vxcom            = q{};
my $vxdisk           = q{};
my $vxe              = q{};
my @vxl              = ();
my $watche           = q{};
my $ctime            = q{};
my $ddriv            = q{};
my $dev              = q{};
my $when             = q{};
my $x                = q{};
my $Year             = q{};
my @addrs            = ();
my $atime            = q{};
my $FREESPACE        = q{};
my $fromhour         = q{};
my $fs               = q{};
my $fs_crash         = q{};
my $fsreal           = q{};
my @fss              = ();
my @Fstabed          = ();
my $poll             = q{};
my $port             = q{};
my $Portproto        = q{};
my $proto            = q{};
my $RAMsize          = q{};
my $reach            = q{};
my $realctrl         = q{};
my $realdsk          = q{};
my $refid            = q{};
my $remfs            = q{};
my $remote           = q{};
my $rstch            = q{};
my $snooping         = q{};
my $snoopint         = q{};
my $KMEMFLAGS        = q{};
#
# 50000000 microseconds = 50 seconds
#
my $SNOOPDEF         = 50000000;

# Hashing algorithms
#
my %PWHASHARR = ( "1",       "hashing-algorithm=BSD-MD5",
                 "2a",       "hashing-algorithm=BSD-Blowfish",
                 "md5",      "hashing-algorithm=SUN-MD5",
                 "5",        "hashing-algorithm=SHA-256",
                 "6",        "hashing-algorithm=SHA-512",
                 "__unix__", "hashing-algorithm=DES",
               );

my $CRYPTDEF = q{};

# String lengths for encrypted part of the pasword string
#
my %PWLEN     = ( "1",          "22",
                  "2a",         "53",
                  "md5",        "22",
                  "5",          "43",
                  "6",          "86",
                  "__unix__",   "13",
                );

my $Sec              = q{};
my $SGCNT            = q{};
my @Skipnomnt        = ();
my $st               = q{};
my $state            = q{};
my @bk               = ();
my $blksize          = q{};
my $blocks           = q{};
my $Lopkt            = q{};
my $tcpflag          = q{};
my $THRESHOLD        = q{};
my $tm               = q{};
my $tohour           = q{};
my $TOTAL_PAGES      = q{};
my $sockaddr         = q{};
my $Hour             = q{};
my @hourarr          = ();
my $hourrun          = q{};
my $ipcused          = q{};
my $IsDST            = q{};
my $iused            = q{};
my $rdev             = q{};
my $RELAY            = q{};
my $response         = q{};
my @RMC              = ();
my $lancardno        = q{};
my $LANdpa           = q{};
my $LANdps           = q{};
my $LANdpx           = q{};
my $lanint           = q{};
my $lant             = q{};
my $len_lline        = q{};
my $lfs              = q{};
my $mflagsvm         = q{};
my $Min              = q{};
my $mingood          = q{};
my $Month            = q{};
my $DayOfMonth       = q{};
my @Mounted          = ();
my @entry            = ();
my @ckarr            = ();
my $conflag          = q{};
my $crashconf        = q{};
my $i                = q{};
my $IDLE             = q{};
my $ifree            = q{};
my $impdisk          = q{};
my $DayOfWeek        = q{};
my $DayofYear        = q{};
my $deffs_size       = q{};
my $delay            = q{};
my @muarr            = ();
my $Lcoll            = q{};
my $Lierr            = q{};
my $nddflag          = q{};
my $fcpath           = q{};
my $fileux           = q{};
my $Lipkt            = q{};
my $Lmtu             = q{};
my $Lname            = q{};
my $Lnet             = q{};
my $Loerr            = q{};
my $HostIP           = q{};
my $tswap1           = q{};
my $ino              = q{};
my $instance         = q{};
my @KBars            = ();
my $Laddr            = q{};
my $Lqueu            = q{};
my $matime           = q{};
my $mblksize         = q{};
my $mblocks          = q{};
my $mctime           = q{};
my $nlink            = q{};
my $mdev             = q{};
#
# Recommended general guidelines for minimum swap configuration based on RAM
#
# System Type           Swap Space Size    Dedicated Dump Device Size 
# RAM <= 4GB                  1GB                1GB 
# 4GB < RAM <= 8GB            2GB                2GB 
# 8GB < RAM <= 128GB          4GB                4GB
# RAM > 128GB                 1/4 of RAM         1/4 of RAM
#
# Oracle's own recommendation at:
#
# http://docs.oracle.com/cd/E19253-01/817-5093/fsswap-31050/index.html
#
# Minimum swap size (as per Unix Standard Build)
#
my $minswap   = 1024;
my $MEMTHRES1 = 4096;
my $MEMTHRES2 = 8192;
my $MEMTHRES3 = 131072;
my %MEMARR    = ( "$MEMTHRES1", "1024",
                  "$MEMTHRES2", "2048",
                  "$MEMTHRES3", "4096",
                );

my $datestring       = q{};
my $Csec             = q{};
my $Cmin             = q{};
my $Chour            = q{};
my $Cmday            = q{};
my $Cmon             = q{};
my $Cyear            = q{};
my $Cwday            = q{};
my $Cyday            = q{};
my $Cisdst           = q{};

my $mgid             = q{};
my $mino             = q{};
my $mmode            = q{};
my $mmtime           = q{};
my $mnlink           = q{};
my $mode             = q{};
my $MPXopts          = q{};
my $mrdev            = q{};
my $msize            = q{};
my $mtime            = q{};
my $muid             = q{};
my $passln           = q{};
my @port             = ();
my $prdev            = q{};
my $sino             = q{};
my $size             = q{};
my $smode            = q{};
my $smtime           = q{};
my $satime           = q{};
my $sblksize         = q{};
my $sblocks          = q{};
my $scadm            = q{};
my $sctime           = q{};
my $sdev             = q{};
my $sfail            = q{};
my $sgid             = q{};
my $snlink           = q{};
my $srdev            = q{};
my $SrvHostIP        = q{};
my $ssize            = q{};
my $stop_time        = q{};
my $suid             = q{};
my $suln             = q{};
my $WARNING          = q{};
my $TZent            = q{};
my $Vxopts           = q{};
my $uid              = q{};
my $myfs             = q{};
my $MPxIO_conf1      = "/kernel/drv/scsi_vhci.conf";
my $aide_conf        = "/usr/local/etc/aide.conf";
my $lfdir            = "lost+found";
my $pam_conf         = "/etc/pam.conf";
my $bge_dr_maj       = q{};
my $bge_dr_min       = q{};
my $bge_old          = q{};
my $finalsa          = q{};
my $conln            = q{};
my @vxcheck          = ();
my $v1               = q{};
my $v2               = q{};
my $v3               = q{};
my $v4               = q{};
my $v5               = q{};
my $vfsck            = q{};
my $rdv              = q{};
my $vxblocksize      = q{};
my $tswapdef         = q{};
my $swappath         = q{};
my $swappathno       = 0;
my $swapdev          = q{};
my $swaplow          = q();
my $tswapused        = q{};
my $vxdisklayout     = q{};
my $MBOX_THRESHOLD   = 52428800;    # 50 MB
my $sulogln          = q{};
my $VXBOOT           = 0;
my $syslogln         = q{};
my @TBars            = ();
my @SGSCAN           = ();
my $SWname           = q{};
my $Swstatus         = q{};
my @CPUarray         = ();
my @nonrootcron      = ();
my @SWarray          = ();
my $vxdisksize       = q{};
my $Rootdir          = "/root";
my $Kerbconf         = "/etc/krb5/krb5.conf";
my $nisflag          = 0;
my $VXSWAP           = 0;
my $patime           = q{};
my $pblksize         = q{};
my $pblocks          = q{};
my $pctime           = q{};
my $pdev             = q{};
my $pgid             = q{};
my $pino             = q{};
my $pmode            = q{};
my $pmtime           = q{};
my $pnlink           = q{};
my $ldapcld_conf     = "/var/ldap/ldap_client_file";
my @initarr          = ();
my @Restmdb          = ();
my $sst              = q{};
my $Restmdb          = q{};
my $strongiss        = q{};
my @ftpDisArr        = ();
my $gwip             = q{};
my @GWlist           = ();
my @Badsw            = ();
my $HostIPsubnet     = q{};
my @HBars            = ();
my $SrvHostIPsubnet  = q{};
my @Grarr            = ();
my @SKIPlist         = ();
my @ALLDISKS         = ();
my @RSCsvrs          = ();
my $ACPS             = "/etc/security/policy.conf";
my $CRYPTCONF        = "/etc/security/crypt.conf";
my $nologinf         = "/etc/nologin";
my @RBars            = ();
my @PassWdarr        = ();
my $userattr         = "/etc/user_attr";
my @svcsarr          = ();
my $authattr         = "/etc/security/auth_attr";
my $profattr         = "/etc/security/prof_attr";
my $SERVICES         = "/etc/services";
my @kcmod            = ();
my $PROTOCOLS        = "/etc/protocols";
my $ETHERS           = "/etc/ethers";
#
# PowerBroker
#
my $POWERBROKERSRV_FLAG = 0;
my $POWERBROKERCL_FLAG  = 0;
my $PBCONF           = "/etc/pb.conf";
my $PBSET            = "/etc/pb.settings";
my $PBENC            = "/etc/pb.key";
my $PBSHELL          = "/etc/pbshells.conf";
#
my @Prtarr           = ();
my @grentry          = ();
my $volboot          = "/etc/vx/volboot";
my @EMC              = ();
my @SNMPARR          = ( "/etc/sma/snmp/snmpd.conf",
                         "/usr/etc/snmp/snmpd.conf",
                         "/etc/snmp/conf/snmpd.conf",
                       );
my $SNMPdm           = "/etc/dmi/conf/snmpXdmid.conf";
my $GDMFLAG          = 0;
my @GDMARR           = ();
my $esm              = "/esm/config/tcp_port.dat";
my $esmmgr           = "/esm/config/manager.dat";
my $esmrc            = "/esm/esmrc";
my $lhentry          = "127.0.0.1";
my $esmdirhost       = "/esm/system/$Hostname";
my $esmportdef       = 5600;
my @esmck            = ();
my @ESMarr           = ();
my @ESMfull          = ();
my $ESMport          = q{};
my @ESMportarr       = ();
my $esmid            = q{};
my $esmport          = q{};
my $SMTPD            = "/etc/mail/sendmail.cf";
my @POSTFIXARR       = ( '/etc/postfix/main.cf', '/etc/postfix/master.cf', );
my $noexeclog        = q{};
my $noexecusr        = q{};
my $rlimfdcur        = q{};
my $rlimfdmax        = q{};
my $RLIMCURPERF      = 65536;
my $RLIMMAXPERF      = 65536;
#
# UFS does not support SCSI UNMAP
# 1. Enable this feature by adding the following entries to the
# /etc/system file:
# set zfs:zfs_unmap_ignore_size=0x100000
# set zfs:zfs_log_unmap_ignore_size=0x100000
# 2. Reboot the system.
#
# A 1MB (0x100000) size is recommended so that smaller
# areas are not reclaimed.
#
# ZFS does it automaticaly: freeing blocks when the
# underlying device advertises the functionality but be aware
# of various bugs or performance issues, like Solaris 11.1 ZFS
# Write Performance Degradation on Storage Devices That Support
# the SCSI UNMAP Command (Doc ID 1503167.1)...
#
my $zfsunmaplogsize  = q{};
my $zfsunmapsize     = q{};

my $crashdir         = q{};
my $dumpdev          = q{};
my @DUMPARR          = ();
my @SWAPARR          = ();
my $ARRFLAG          = 0;
my @SPMGR            = ();
my @svcstmp          = ();
my @PRIVACY          = ();
my $NDPDCONF         = "/etc/inet/ndpd.conf";
my $INET6COUNT       = 0;
my $IPNODES_FLAG     = 0;
my @ALLZFS           = ();
my $ZFS_FLAG         = 0;
my @ZFSROOTARR       = ();
my $TSMCL_FLAG       = 0;
my $TSMSRV_FLAG      = 0;
my $outputvalue      = q{};
my $umaskln          = q{};
my @EEPROMarr        = ();
my $defroute         = "/etc/defaultrouter";
my $SRSconfig        = "/etc/opt/SUNWsrspx/srsproxyconfig.cfg";
my $diaglevel        = q{};
my $abonerror        = q{};
my $diagswitch       = q{};
my $inputvalue       = q{};
my $diagvalue        = q{};
my $bootdevice       = q{};
my $ftpacc           = "/etc/ftpd/ftpaccess";
my $ftpusers         = "/etc/ftpd/ftpusers";
my $ERMflag          = 0;
my @Stickyarr        = ( "/tmp", "/var/tmp", );
my @remaccarr        = ( ".netrc", ".rhosts", ".shosts", );
my @mailboxdir       = ( "/var/mail", "/var/spool/mail", "/var/share/mail", );
my $HBAWWN           = q{};
my @HBAARR           = ();
my $FMRI             = q{};
my @fcinfo           = ();
my @SVCARR           = ();
my @tapes            = ();
my $sysid_config     = q{};
my @SYSIDARR         = ();
my $POSTFIX_FLAG     = 0;
my $SRSPROXY_FLAG    = 0;
my $SENDMAIL_FLAG    = 0;
my $EXIM_FLAG        = 0;
my $DNSCONF          = '/etc/named.conf';
my $DNSCONF2         = '/etc/named.boot';
my @DNSarray         = ( $DNSCONF, $DNSCONF2, );
my $DHCPconf         = "/etc/inet/dhcpsvc.conf";
my $DHCPtab          = "/etc/dhcp/inittab";
my @ALLLAN           = ();
my $ccount          = q{};
my $reallancardno   = 0;
my $bings           = 0;
my $SVMDISK         = 0;
my $ZFSDISK         = 0;
my $ordlast         = q{};
my $ordlast2        = q{};
my $MOUNTORDER      = 1;
my $ORDMOUNTCNT     = 1;
my @MOUNTORD        = ();
my $RCM_FLAG        = 0;
my @OVget           = ();
my $syslog_conf     = "/etc/syslog.conf";
my @WARNSLOGARR     = ();
my $SYSLOG          = "/var/adm/messages";
my $CRASHCONF       = "/etc/dumpadm.conf";
my $MinBootSize     = 18;   # Boot disks should be 18 GB minimum
my $rdsklist        = "/dev/rdsk";
my $Exploconf1      = "/etc/opt/SUNWexplo/default/explorer";
my $Exploconf2      = "/etc/default/explorer";
my @EXplarr         = ( 
                      "$Exploconf1", "$Exploconf2",
                      );
my $sshconf1        = "/etc/ssh/sshd_config";
my $sshconf2        = "/usr/local/etc/sshd_config";
my $sshconf3        = "/usr/local/ssh/etc/sshd_config";
my $sshconf4        = "/etc/ssh2/sshd_config";
my @SSHarr          = ( 
                      "$sshconf1", "$sshconf2", "$sshconf3", "$sshconf4",
                      );
my @SSHARR          = ();
my $SSHRHOST        = q{};
my $SSHEMPTYPW      = q{};
my $SSHPRIVSEP      = q{};
my $SSHSTRICT       = q{};
my $SSHTCPFWD       = q{};
my $SSHTCPTUN       = q{};
my $PWPN            = q{};
my $PWYN            = q{};
my @SQUIDarray      = (
                      '/etc/squid.conf', '/etc/squid/squid.conf',
                      '/usr/local/squid/etc/squid.conf',
                      '/usr/local/etc/squid.conf',
                      '/opt/squid/etc/squid.conf',
                      );
my @Proftpdarray    = (
                     '/etc/proftpd.conf',
                      '/opt/express/proftpd/etc/proftpd.conf',
                      '/usr/local/etc/proftpd.conf',
                      '/opt/proftpd/etc/proftpd.conf',
                     );
my @VSftpdarray     = (
                      '/etc/vsftpd.conf',
                      '/etc/vsftpd.banned_emails',
                      '/etc/vsftpd.chroot_list',
                      '/etc/vsftpd.user_list',
                      );
my @SQUIDRUN        = ();
my $uidno           = 0;
my $Shadow          = "/etc/shadow";
my $shaduser        = q{};
my @SHADWARN         = ();
my $pwgrdconf        = "/etc/default/passwd";
my $logiconf         = "/etc/default/login";
my $inetinitconf     = "/etc/default/inetinit";
my $suconf           = "/etc/default/su";
my $MINPASSLENGTH    = 8;
my $btmplog          = "/var/adm/loginlog";
my @VXBOOTDISK       = ();
my @fwlic            = ();
my $MPxIO_conf2      = "/kernel/drv/fp.conf";
my $MPxIO_conf       = q{};
my @MAJMIN           = ();
my @FINDUP           = ();
my $NAMED            = "/etc/resolv.conf";
my $PFMERR           = q{};
my $DOMCOUNT         = 0;
my $SEARCHCOUNT      = 0;
my $MAXDNSSRV        = 3;
my $DNS_NO           = 0;
my $DNSdefdom        = q{};
my @MYDNSSRV         = ();
my $HOSTS            = "/etc/hosts";
my @HOSTWARN         = ();
my $IPNODES          = "/etc/inet/ipnodes";
my $NSSWITCH         = "/etc/nsswitch.conf";

my $glob_conf  = q{};

# Configuration management tools
#
my $PUPPETMASTER           = 0;
my $PUPPETCLIENT           = 0;
my $CFENGINEMASTER         = 0;
my $CFENGINECLIENT         = 0;

# Due to excessive tape backup times, some teams
# recommended maximum F/S size limit of 512 GB
#
my $MAXFSSIZE        = 512;
my $LUTAB            = "/etc/lutab";
my $LUSYNC           = "/etc/lu/synclist";
my $zoneid           = q{};
my $zonename         = q{};
my $zonestatus       = q{};
my $zonepath         = q{};
my $Autobootonerror  = q{};
my $Autoboot         = q{};
my @OSarray          = ( '/etc/release', '/var/sadm/system/admin/CLUSTER',
                         '/var/sadm/system/admin/INST_RELEASE',
                       );
my $OSUPGRADE        = "/var/sadm/upgrade";
my $snmpmod          = "Net::SNMP";
my $snmphostname     = shift || 'localhost';
my $snmpcommunity    = shift || 'public';
my $snmpport         = shift || 161;
my $oid              = shift || '1.3.6.1.4.1.42.3.1';
my $snmperror        = q{};
my $snmpsession      = q{};
my @Zonepkgarr       = ( 'SUNWzoner', 'SUNWzoneu' );
my $Utconf           = "/etc/opt/SUNWut/utadmin.conf";
my $tzfile           = "/etc/TIMEZONE";
my $UXSA             = "/var/adm/sa";
my $accnomb          = 0;
my @NDDarrs =        ( '/dev/tcp', '/dev/udp', '/dev/ip', '/dev/arp', 
                       '/dev/icmp',
                     );
my @nddskip          = ();
my @MDdisk           = ();
my $syst             = "/etc/system";
my $TMPCLEAN1        = "/etc/init.d/RMTMPFILES";
my $TMPCLEAN2        = "/etc/rc2.d/S05RMTMPFILES";
my $SWAP_THRESHOLD   = 15;
my $CPU_IDLE_THRESHOLD = 15;
my $CRON_DENY        = "/etc/cron.d/cron.deny";
my $CRON_ALLOW       = "/etc/cron.d/cron.allow";
my $AT_DENY          = "/etc/cron.d/at.deny";
my $AT_ALLOW         = "/etc/cron.d/at.allow";
my $BSMconf          = "/etc/security/audit_startup";
my $BSMevent         = "/etc/security/audit_event";
my $BSMclass         = "/etc/security/audit_class";
my @Dmust            = ( "inetd", "sshd", "syslogd", "cron", "auditd", );
my @Nott             = ( "automount", "snmpdm",   "in.routed", "gated",
                          "dtlogin",   "ypserv",   "nscd",     "ypbind",
                          "dmispd",    "in.rdisc", "xinit",
                       );
my $ssd              = "/etc/default/syslogd";
my $inetdd           = "/etc/default/inetd";
my $fswarnings       = 0;
my $FSTAB            = "/etc/vfstab";
my $MNTTAB           = "/etc/mnttab";
my @Skipnonfs        = ( "/proc", "/dev/fd", "/var/run", "/etc/mnttab", 
                         "/devices",
                       );

#
my @AUTOARR        = ( "/etc/auto_master", "/etc/auto_home",
                     );
my @AUTOEXTRA      = ();
my $AUTO_FLAG      = 0;

my $initt            = "/etc/inittab";
my $nfsconf          = "/etc/inet/nfs";
my $exportfs         = "/etc/dfs/dfstab";
my $autom            = "/etc/auto_master";
my $nfscount         = 0;
my $ntpconf          = "/etc/inet/ntp.conf";
my $sulog            = "/var/adm/sulog";
my $Superconf        = q{};
my $Superconf1       = "/opt/super/etc/super.tab";
my $Superconf2       = "/etc/super.tab";
my $Superconf3       = "/usr/local/etc/super.tab";
my $sudoconf         = q{};
my $sudoconf1        = "/etc/sudoers";
my $sudoconf2        = "/opt/sudo/etc/sudoers";
my $sudoconf3        = "/usr/local/etc/sudoers";
my $BEENV            = q{};
my $TCPSTRONGDEF     = 2;
#
my @PSARR           = ();
my @userid          = ();
my $psline          = q{};
my @pss             = ();
my @PSSLEEP         = ();
my @PSRUN           = ();
my @PSSTOP          = ();
my @PSPAGE          = ();
my @PSPROC          = ();
my @PSZOMBIE        = ();
my @PSREST          = ();
my @HEADLN          = ();
#
my $ipsecconf        = "/etc/inet/ipsecinit.conf";
my $ipsecpolicy      = "/etc/inet/ipsecpolicy.conf";
my $Combinedlic      = "/etc/opt/licenses/licenses_combined";
my $dpck             = "/etc/opt/omni/client/cell_server";
my $dpcw1            = "/etc/opt/omni/cell/lic.dat";
my $dpcw2           = "/etc/opt/omni/server/cell/lic.dat";
-s      "$dpcw1" ? $dpcw = $dpcw1
   : -s "$dpcw2" ? $dpcw = $dpcw2
   :               $dpcw = q{};
my $DPusers         = "/etc/opt/omni/server/users/UserList";
my $CSusers         = "/etc/opt/omni/server/users/ClassSpec";
my $dpcellinfo      = "/etc/opt/omni/server/cell/cell_info";
my $dpinstsrvs      = "/etc/opt/omni/server/cell/installation_servers";
my $dpoptions       = "/etc/opt/omni/server/options/global";

my $ovnnmlic         = "/var/opt/OV/HPOvLIC/LicFile.txt";
my $lvmconf          = "/etc/lvm/md.cf";
my $wanbootcfg       = '/etc/netboot/wanboot.conf';
my $instlcfg         = "/etc/sysidcfg";
my $bootparams       = "/etc/bootparams";
my $tftpboot         = "/tftpboot";
my $VXCONF           = "/etc/init.d/vxvm-sysboot";
my $ISSUE            = "/etc/issue";
my $ISSUENET         = "/etc/issue.net";
my $MOTD             = "/etc/motd";
my $secnets          = "/var/yp/securenets";
my $secservers       = "/var/yp/secureservers";
my $OPCinfo          = "/opt/OV/bin/OpC/install/opcinfo";
my $NODEinfo         = "/var/opt/OV/conf/OpC/nodeinfo";
my $MGRCONF          = "/var/opt/OV/conf/OpC/mgrconf";
my $opcflag          = q{};
my $INETD            = "/etc/inet/inetd.conf";
my $KINETD           = "/etc/inetsvcs.conf";
my $INETDSEC         = "/etc/hosts.allow";
my $hostequiv        = "/etc/hosts.equiv";
my $Shells           = "/etc/shells";
my $lanok            = 0;
my $CUPSDIR          = "/etc/cups";
my $NETBCKDIR        = q{};
my $NETBCKDIR1       = "/usr/openv";
my $NETBCKDIR2       = "/opt/openv";
my $DUMPDATES        = "/etc/dumpdates";
my @Passnumarr       = ();
my $Diskmgrcnt       = q{};
my @Grnumarr         = ();
my $MSGFILE          = "/var/adm/messages";
my $CRDIR            = "/var/spool/cron/crontabs";

# How many mailboxes in /var/spool/mail?
#
my $mboxcount        = 0;

my $CRFILE           = "$CRDIR/root";
my $WARNSTR          = "AUDIT-WARN";
my $ERRSTR           = "AUDIT-FAIL";
my $NOTESTR          = "AUDIT-NOTE";
my $INFOSTR          = "AUDIT-INFO";
my $PASSSTR          = "AUDIT-PASS";
my $REMOTECONF       = '/etc/remote';
my $UUCPSYS          = '/etc/uucp/Systems';
my $UUCPDIA          = '/etc/uucp/Dialers';
my $UUCPDEV          = '/etc/uucp/Devices';
my $PPPCONF          = '/etc/asppp.cf';
my $Secure_SYSLOGD   = 0;
my $INCK_FLAG        = 0;
my $Diskmgrno        = 0;
my $Diskmgr         = q{};
my $Diskmgr1         = q{};
my $Diskmgr2         = q{};
my $MPATHDconf       = "/etc/default/mpathd";
my @IPMParray        = `ls /etc/hostname.*`;
my $ESMD_FLAG        = 0;
my $CHECKPOINT_FLAG  = 0;
my $IPF_FLAG         = 0;
my $SCFno            = 0;
my $SUNSCREEN_FLAG   = 0;
my $EXPLO_FLAG       = 0;
my $VRTSCLUSTER_FLAG = 0;
my $SUNRAY_FLAG      = 0;
my $IPMP_FLAG        = 0;
my $DHCPD_FLAG       = 0;
my $ctrlcounter      = 0;
my $SECPATH_FLAG     = 0;
my $CDE_FLAG         = 0;
my $HIDS_FLAG        = 0;
my $VTS_FLAG         = 0;
my $UMASKDEF         = "022";
my $dumpmem          = 0;

#
# Where to start SUID/SGID file search
#
my @directories_to_search = ("/");

#
my $SVM_FLAG       = 0;
my @Metadbdb       = ();
my $shealth        = 0;
my $cpucount       = 0;
my $passno         = 0;
my $SECPATCH_FLAG  = 0;
my $NTP_REST_FLAG  = 0;
my $RBAC_FLAG      = 0;
my $IDS_FLAG       = 0;
my $LICENSE        = 0;
my @licdaemon      = ();
my $NISPLUS_FLAG   = 0;
my $LPSCHED        = 0;
my $ldap_conf      = "/etc/ldap.conf";
my $sldap_conf     = "/etc/openldap/slapd.conf";
my $ldap2_conf     = "/etc/openldap/ldap.conf";
my $LDAPCLIENT     = 0;
my $LDAPSERVER     = 0;
my @ldapdaemon     = ();
my $NSADMIN        = 0;
my $LPSTAND        = 0;
my $LOCALHOST_FLAG = 0;
my $SNMP_FLAG      = 0;
my $OMNI_FLAG      = 0;
my $MNT_FLAG       = 0;
my $VXCONFIG       = 0;
my $swapdeviceno   = 0;
my $Minswapdevno   = 1;
my $warnings       = 0;
my @FCarray        = ();
my @unc            = ();
my $NSCD_FLAG      = 0;
my @DNSRUN         = ();
my @allprocesses   = ();
my @ntpdaemon      = ();
my @nfsdaemon      = ();
my $secureshell    = 0;
my $autopath       = 0;
my $PASSFILE       = "/etc/passwd";
my $DefMTU         = 1500;
my $OS_Standard    = "Solaris Build Standard";

#
# In Australia, Daylight Savings Time normally changes
# between 0200 and 0300 hours respectively
#
my $DSTbegin = 2;
my $DSTend   = 3;

#
# Array of accounts that should be disabled for FTP access
#
my @FTPdisable = ( "root", "adm", "sys", "daemon" );

#
# Software packages that are most critical
#
my @SWmust = (
    "tcpd",       "Data Protector", "SSH Server",
    "SSH Client", "SUNWexplo",      "SUNWvts",
    "Tripwire",
);

if ( "$Minor" < 10 ) {
    push(@SWmust, "SUNWinck", "SUNWrsc", "SUNWast");
}

sub loginerror {
   #  print "$INFOSTR Could not connect with this login name or password\n";
   ;
}

sub Usage {
    if ( eval "require File::Basename" ) {
        import File::Basename;
        $CMD = basename( "$0", ".pl" );
    }
    else {
        $CMD = `basename $0`;
        chomp($CMD);
    }

    print <<MYMSG
  USAGE: $CMD [-c] [-f] [-h] [-n] [-p] [-r] [-t conffile] [-v]

  -c                  Enable check of SUID/SGID files
  -f                  Enable NMAP scans
  -h                  Print this help message
  -n                  Enable SUID/SGID checks in NFS (default is disable)
  -p                  Enable patch checks through SUNWinck
  -r                  Server part of cluster or H/A server group
  -t file             Read variables from a config file
  -v                  Print version of this script
MYMSG
      ;
    exit(0);
}

#
# Ensure that modules are loaded
#
BEGIN {
    $opt_n = 0;
    $opt_p = 0;
    $opt_r = 0;
    $opt_c = 0;
    $opt_f = 0;
    $opt_v = 0;

    $REC_VERSION = '5.006';
    $CUR_VERSION = "$]";

    if ( eval "require File::Find" ) {
        import File::Find;
    }
    else {
        warn "ERROR: Perl module File::Find not found\n";
    }

    if ( eval "require Socket" ) {
        import Socket;
    }
    else {
        warn "ERROR: Perl module Socket not found\n";
    }

    if ( eval "require Net::Ping" ) {
        import Net::Ping;
    }
    else {
        warn "ERROR: Perl module Net::Ping not found\n";
    }

    if ( eval "require Time::Local" ) {
        import Time::Local;
    }
    else {
        warn "ERROR: Perl module Time::Local not found\n";
    }

    if ( eval "require POSIX" ) {
        import POSIX 'uname';
        import POSIX qw(locale_h);
        ( $System, $Hostname, $Maj, $Version, $Hardware ) = uname();
        if ("$Maj") {
            ( $Major, $Minor, $Patch ) = split( /\./, $Maj );
        }
    }
    else {
        warn "ERROR: Perl module POSIX not found\n";
    }

    if ( eval "require Getopt::Std" ) {
        import Getopt::Std;
        ($::opt_s) = ();    #avoid warning message
        getopts('chfnprvt:');
        if ($opt_h) {
            &Usage;
        }
    }
    else {
        warn "ERROR: Perl module Getopt::Std not found\n";
    }

    if ( $CUR_VERSION > $REC_VERSION ) {
        if ( eval "require Net::Domain" ) {
            import Net::Domain qw(hostname hostfqdn hostdomain);
            $fqdn = hostfqdn();
        }
        else {
            print "INFO: Perl module Net::Domain not found\n";
            if ( "$Hostname" ) {
                $fqdn =
`nslookup $Hostname | nawk -F: '! /awk/ && /^Name:/ {print \$2}' 2>/dev/null`;
                if ("$fqdn") {
                    $fqdn =~ s/Name:\s+//g;
                    $fqdn =~ s/^\s+//g;
                }
                else {
                    $fqdn = "N/A";
                }
            }
        }
    }
}

if ( !"$Hostname" ) {
    my $VH = `uname -a 2>&1`;
    ( $System, $Hostname, $Maj, undef, $Hardware, undef ) =
      split( /\s+/, $VH );
    $Version = $Maj;
    ( $Major, $Minor, $Patch ) = split( /\./, $Maj );
}

if ( "$Minor" < 8 ) {
    print "$ERRSTR Operating system version getting old ($Maj)\n";
    print "$INFOSTR Recommended to upgrade to newer version\n";
    exit(1);
}

if ("fqdn") {
    chomp($fqdn);
    $fqdn =~ s/^\s+//g;
}
else {
    $fqdn = "N/A";
}

#
# Do not allow to run as unprivileged user
#
if ( $> != 0 ) {
    print "$ERRSTR The OAT should be run with root privileges\n";
    exit(1);
}

#
# Get current local time
#
(
    $Sec,  $Min,       $Hour,      $DayOfMonth, $Month,
    $Year, $DayOfWeek, $DayofYear, $IsDST
  )
  = localtime;

my $EPOCHTIME = timelocal( $Sec, $Min, $Hour, $DayOfMonth, $Month, $Year );

#
# Localtime returns January..December as 0..11
#
$Month++;
$Year           = $Year + 1900;

rawpscheck();

#
# Get system's pagesize
#
$pgsize = `pagesize 2>/dev/null | nawk NF`;
if ("$pgsize") {
    chomp($pgsize);
}
else {
    $pgsize = "Unknown";
}

if ( open( PRTCONF, "prtconf -pv |" ) ) {
    while (<PRTCONF>) {
        push( @Prtarr, $_ );
        if ( grep( /Memory size:/, $_ ) ) {
            $_ =~ s/Memory size://g;
            $_ =~ s/^\s+//g;
            $RAMsize = $_;
            chomp($RAMsize);
        }

        if ( grep( /bootpath/, $_ ) ) {
            $_ =~ s/^\s+bootpath://g;
            $_ =~ s/^\s+//g;
            $_ =~ s/'//g;
            $Bootpath = $_;
            chomp($Bootpath);
        }

        if ( grep( /auto-boot-on-error/, $_ ) ) {
            $_ =~ s/auto-boot-on-error://g;
            $_ =~ s/^\s+//g;
            $_ =~ s/'//g;
            $Autobootonerror = $_;
            chomp($Autobootonerror);
        }

        if ( grep( /auto-boot\?/, $_ ) ) {
            $_ =~ s/auto-boot?://g;
            $_ =~ s/^\s+//g;
            $_ =~ s/'//g;
            $Autoboot = $_;
            chomp($Autoboot);
        }
    }
    close(PRTCONF);
}
else {
    print "$WARNSTR Cannot run prtconf\n";
    push(@CHECKARR, "\n$WARNSTR Cannot run prtconf\n");
    $warnings++;
}

my $runlevel = `who -r | nawk '/run-level/ {print \$3}' 2>&1`;
chomp($runlevel);

if ( ! "$runlevel" ) {
    $runlevel = "Unknown (data corruption of utmpx suspected)";
}

my $LASTBOOT = `who -b | sed -e 's/^.*system boot //g'`;
$LASTBOOT =~ s/^\s+//g;
chomp($LASTBOOT);

if ( ! "$LASTBOOT" ) {
    $LASTBOOT = "Unknown (data corruption of utmpx suspected)";
}

$uptime = `uptime`;
$uptime =~ s/^\s+//g;
chomp($uptime);

my $wtmpfile = "/var/adm/wtmp";
my $etcutmp  = "/etc/utmp";

if ( !"$uptime" ) {
    print "$WARNSTR $wtmpfile or $etcutmp possibly corrupted\n";
    push(@CHECKARR, "\n$WARNSTR $wtmpfile or $etcutmp possibly corrupted\n");
    $warnings++;
    $uptime = "Unknown (check manually)";
}

my $ARCH = `isainfo -kv 2>/dev/null`;
chomp($ARCH);

my $KERNEL_BITS = `isainfo -b 2>/dev/null`;
chomp($KERNEL_BITS);

my $KSYMS = "/dev/ksyms";

#
# Get system's volume manager details
#
my @vxdctl0 = `vxdctl list 2>/dev/null`;

if ( open( QCK, "vxinfo 2>/dev/null |" ) ) {
    while (<QCK>) {
        push( @vxcheck, $_ );
    }
    close(QCK);
}
else {
    print "$INFOSTR Vxinfo not installed or not in PATH\n";
}

my @zfsmount = ();
my $zpoolH = q{};
my $zpoolboot = q{};
my $dffstyp = `df -n / 2>/dev/null | awk '{print \$3}'`;
$dffstyp =~ s/^\s+//g;
$dffstyp =~ s/\s+$//g;
chomp($dffstyp);

if ( "$Minor" >= 10 ) {
    @zfsmount = `zfs mount 2>/dev/null`;
    $zpoolH = `zpool list -H | awk '{print \$1}' 2>/dev/null`;
    chomp($zpoolH);
    $zpoolboot = `zpool list -Ho bootfs 2>/dev/null`;
}

if ( "@zfsmount" ) {
    $Diskmgr1 = "Zettabyte File System (ZFS)";
    $Diskmgrno++;
}

if ( "$SVM_FLAG" > 0 ) {
    $Diskmgr1 = "Solaris Volume Manager (SVM)";
    $Diskmgrno++;
}

if ( "@vxcheck" ) {
    $Diskmgr2 = "Veritas Volume Manager (VVM)";
    $Diskmgrno++;
}

$Diskmgr = "$Diskmgr1 $Diskmgr2";

if ( "$Diskmgrno" == 0 ) {
    $Diskmgr    = "None";
    $Diskmgrcnt = "No Volume Manager";
}
elsif ( "$Diskmgrno" == 1 ) {
    $Diskmgrcnt = "SINGLE Volume Manager Environment";
}
else {
    $Diskmgrcnt = "DUAL Volume Manager Environment";
}

sub print_header {
    my $lline = shift;
#    $len_lline = length($lline);
    print "\n$lline\n";
#    printf "_" x $len_lline;
    print "\n";
}

my $SNEEP1 = `sneep -a 2>/dev/null | egrep -v explorer`;
chomp($SNEEP1);
$SNEEP1 =~ s/\^s+//g;

my $SNEEP2 = `eeprom | egrep ChassisSerialNumber`;
chomp($SNEEP2);
$SNEEP2 =~ s/\^s+//g;

# This one comes from Fujitsu toolkit
#
my $SNEEP3 = `serialid 2>/dev/null`;
chomp($SNEEP3);
$SNEEP3 =~ s/\^s+//g;

my $SNEEP = $SNEEP1 || $SNEEP2 || $SNEEP3 || "Not Available";

# Run hostid(1) and it will give the hostid of the system
# Take off the first two digits of the hostid
# Take the remaining number (it is a hex #) and convert it into decimal
# This is the serial number of the NVRAM chip
#
my $hostid = `hostid 2>/dev/null`;
my $NVRAMSN = q{};
chomp($hostid);
$hostid =~ s/\^s+//g;

if ( ! "$hostid" ) {
    $hostid = "Not Available";
}
else {
    $NVRAMSN = substr($hostid, 2);
    $NVRAMSN = hex($NVRAMSN);
    chomp($NVRAMSN);
    if ( ! "$NVRAMSN" ) {
        $NVRAMSN = "Not Available";
    }
}

# Slurp - read a config file into a scalar or list
#
sub slurp {
    # the config file should have the following syntax:
    # $SSHD_CONF1      = '/etc/opt/ssh/sshd_config';
    # @VSHARR          = ();
    # $MCCLNAME        = q{};
    #
    # Variables which are not defined in the config file will be defined from
    # within this Perl script
    #
    my $file = shift;
    do "$file";
}

if ( eval "require Config" ) {
    import Config;
    use Config;
}
else {
    print "WARN: Perl Config not found\n";
}

my $endianess = "$Config{byteorder}";
my $Endian = q{};
my $ev2 = unpack("h*", pack("s", 1));
if ( "$endianess" == 4321 ) {
   $Endian = "Big-Endian ($endianess byte-order)";
}
elsif ( "$endianess" == 1234 ) {
   $Endian = "Little-Endian ($endianess byte-order)";
}
else {
    $Endian = "Mixed-Endian ($endianess byte-order)";
}

if ( ! "$endianess" ) {
   if ( $ev2 =~ /^1/ ) {
      $endianess = 1234;
      $Endian = "Little-Endian ($endianess byte-order)";
   }
   elsif ( $ev2 =~ /01/ ) {
      $endianess = 4321;
      $Endian = "Big-Endian ($endianess byte-order)";
   } else {
      $Endian = "Mixed-Endian";
   }
}

if ( ! "$Endian" ) {
   $Endian = "Unknown Endianness";
}

sub SYS_INFO {
    print "$INFOSTR Data collected by Perl script version $SCRIPT_VERSION

DATE                      $DayOfMonth/$Month/$Year $Hour:$Min
HOSTNAME                  $Hostname
FQDN                      $fqdn
MODEL                     $Model
HOSTID                    $hostid
NVRAM SERIAL NUMBER       $NVRAMSN
SERIAL NUMBER             $SNEEP
UNAME -A                  $System $Hostname $Maj $Version $Hardware
ARCH                      $ARCH
ENDIANNESS                $Endian
RUN LEVEL                 $runlevel
PHYSICAL MEMORY           $RAMsize
PAGESIZE                  $pgsize bytes
VOLUME MANAGER COUNT      $Diskmgrcnt
VOLUME MANAGER            $Diskmgr
UPTIME                    $uptime
LAST REBOOT               $LASTBOOT\n";
}

sub check_hostname_valid {
   datecheck();
   print_header("*** BEGIN CHECKING HOSTNAME CONTAINS VALID CHARACTERS $datestring ***");

    if ( "$Hostname" ) {
        if( ! ( $Hostname =~ /^[a-zA-Z0-9\.\-]+$/ ) ) {
            print "$WARNSTR Invalid characters in hostname $Hostname\n";
            print "RFCs define valid characters as 'a-zA-Z0-9.-'\n";
            push(@CHECKARR, "\n$WARNSTR Invalid characters in hostname $Hostname\n");
        }
        else {
            print "$PASSSTR Valid characters in hostname $Hostname\n";
            print "RFCs define valid characters as 'a-zA-Z0-9.-'\n";
        }

         if( $Hostname =~ /\p{IsUpper}/ ) {
            print "\n$INFOSTR Upper-case characters in hostname $Hostname\n";
            print "$INFOSTR Lower-case characters in hostnames are recommended\n";
        }
    }
    else {
        print "$WARNSTR Hostname string empty\n";
        push(@CHECKARR, "\n$WARNSTR Hostname string empty\n");
        $warnings++;
    }

    my @checkh = `check-hostname 2>/dev/null`;
    if ("@checkh") {
        print "\n$INFOSTR Check if Sendmail MTA can determine system's FQDN\n";
        print @checkh;
    }

   datecheck();
   print_header("*** END CHECKING HOSTNAME CONTAINS VALID CHARACTERS $datestring ***");
}

# Subroutine to test open TCP port
#
sub openport {
    use IO::Socket;
    my $REMOTE = $_[0];
    my $port = $_[1];
    my $proto = $_[2];
    my $sock = new IO::Socket::INET (
    PeerAddr => $REMOTE,
    PeerPort => $port,
    Proto => $proto,
    );

    if ( "$sock" ) {
        print "\n$INFOSTR Successful open socket on $proto port $port @ $REMOTE\n";
        close($sock);
    }
    else {
        print "\n$INFOSTR Failed open socket on $proto port $port @ $REMOTE\n";
    }
}

# Subroutine to check clustering
#
sub sgcheck {
    datecheck();
    print_header("*** BEGIN CHECKING CLUSTER CONFIGURATION $datestring ***");

    my @Sclver = `scinstall -pv 2>/dev/null`;
    if ("@Sclver") {
        $SGCNT++;
        print "$INFOSTR Sun Cluster version\n";
        print @Sclver;
    }

    my @clinfo = `clinfo -h 2>/dev/null`;
    if ("@clinfo") {
        $SGCNT++;
        print "$INFOSTR Sun Cluster info\n";
        print @clinfo;
    }

    if ( "$SGCNT" == 0 ) {
        print "$INFOSTR Sun Cluster not running or not installed\n";
    }
    else {
        my @clustername = `scha_cluster_get -O CLUSTERNAME`;

        print "\n$PASSSTR Sun Cluster running\n";
        $opt_r = 1;
        print @clustername;

        my @scstatq = `scstat -q 2>/dev/null`;
        if ("@scstatq") {
            print "$INFOSTR Sun Cluster device and node quorum\n";
            print @scstatq;
        }

        my @scstatg = `scstat -g 2>/dev/null`;
        if ("@scstatg") {
            print "$INFOSTR Sun Cluster resource groups\n";
            print @scstatg;
        }

        my @scstatpv = `scstat -pv 2>/dev/null`;
        if ("@scstatpv") {
            print "$INFOSTR Sun Cluster components\n";
            print @scstatpv;
        }

        my @scdpm = `scdpm -p 2>/dev/null`;
        if ("@scdpm") {
            print "$INFOSTR Sun Cluster disk path info\n";
            print @scdpm;
        }

        my @scnas = `scnas -p 2>/dev/null`;
        if ("@scnas") {
            print "$INFOSTR Sun Cluster NAS info\n";
            print @scnas;
        }

        my @scnasdir = `scnasdir -p 2>/dev/null`;
        if ("@scnasdir") {
            print "$INFOSTR Sun Cluster NAS directories info\n";
            print @scnasdir;
        }

        my @scrgadm = `scrgadm -p 2>/dev/null`;
        if ("@scrgadm") {
            print "$INFOSTR Sun Cluster registered resources\n";
            print @scrgadm;
        }

        if ( open( FROM, "scconf -pv |" ) ) {
            print "\n$INFOSTR Sun Cluster Scconf report\n";
            while (<FROM>) {
                print $_;
            }
            close(FROM);
        }
        else {
            print "\n$WARNSTR Cannot run scconf\n";
            $warnings++;
        }

        if ( open( FROM, "scdidadm -L |" ) ) {
            print "\n$INFOSTR Sun Cluster Scdidadm report\n";
            while (<FROM>) {
                print $_;
            }
            close(FROM);
        }
        else {
            print "\n$WARNSTR Cannot run scdidadm\n";
            $warnings++;
        }

        my @clust_nodenames = `scha_cluster_get -O ALL_NODENAMES`;

        foreach my $clusnode ( @clust_nodenames ) {
            chomp($clusnode);

            my @cl_state = `scha_cluster_get -O NODESTATE_NODE $clusnode`;
            if ( "@cl_state" ) {
                print "\n$INFOSTR Cluster node $clusnode status\n";
                print @cl_state;
            }
        }

        my @resource_groups = `scha_cluster_get -O ALL_RESOURCEGROUPS`;
        if ( "@resource_groups" ) {
            print "\n$INFOSTR Cluster resource groups\n";
            print @resource_groups;
        }
    }

    if ( "$VRTSCLUSTER_FLAG" > 0 ) {
        print "\n$INFOSTR Veritas Cluster package installed\n";

        my @Vart = (
            '/etc/gabtab',
            '/etc/llttab',
            '/etc/llthosts',
            '/etc/VRTSvcs/conf/config/main.cf',
            '/etc/VRTSvcs/conf/config/main.cmd',
            '/etc/VRTSvcs/conf/config/types.cf',
            '/etc/VRTSvcs/conf/sysname',
        );

        foreach my $vvva (@Vart) {
            my @GBar = ();
            if ( ( -s "$vvva" ) && ( -T "$vvva" ) ) {
                print
                  "\n$INFOSTR Veritas Cluster configuration file $vvva\n";
                @GBar = `cat $vvva`;
                print @GBar;
            }
            else {
                print
"\n$INFOSTR Veritas Cluster configuration file $vvva empty or non-existent\n";
            }
        }

        my @LLTd = `lltconfig -a list 2>/dev/null`;
        if ("@LLTd") {
            print "\n$INFOSTR Veritas Cluster lltconfig status\n";
            print @LLTd;
        }

        my @LLTs = `lltstat 2>/dev/null`;
        if ("@LLTs") {
            $opt_r = 1;
            print "\n$INFOSTR Veritas Cluster lltstat status\n";
            print @LLTs;
        }

        my @LLTc = `lltstat -c 2>/dev/null`;
        if ("@LLTc") {
            print "\n$INFOSTR Veritas Cluster lltstat extended status\n";
            print @LLTc;
        }

        my @GABc = `gabconfig -l 2>/dev/null`;
        if ("@GABc") {
            print "\n$INFOSTR Veritas Cluster gabconfig status\n";
            print @GABc;
        }

        my @HAGRPD = `hagrp -display 2>/dev/null`;
        if ("@HAGRPD") {
            print "\n$INFOSTR Veritas Cluster HA status\n";
            print @HAGRPD;
        }

        my @HAGRP = `hagrp -list 2>/dev/null`;
        if ("@HAGRP") {
            print "\n$INFOSTR Veritas Cluster HA configuration\n";
            print @HAGRP;
        }

        my @HAATTR = `haattr -display 2>/dev/null`;
        if ("@HAATTR") {
            print "\n$INFOSTR Veritas Cluster HA attributes\n";
            print @HAATTR;
        }

        my @HATYPE = `hatype -display 2>/dev/null`;
        if ("@HATYPE") {
            print "\n$INFOSTR Veritas Cluster HA types\n";
            print @HATYPE;
        }

        my @HAAGENT = `haagent -display 2>/dev/null`;
        if ("@HAAGENT") {
            print "\n$INFOSTR Veritas Cluster HA agents\n";
            print @HAAGENT;
        }

        my @HASYS = `hasys -display 2>/dev/null`;
        if ("@HASYS") {
            print "\n$INFOSTR Veritas Cluster HA sys display\n";
            print @HASYS;
        }

        my @HASTATUS = `hastatus -summary 2>/dev/null`;
        if ("@HASTATUS") {
            print "\n$INFOSTR Veritas Cluster HA summary\n";
            print @HASTATUS;
        }

        my @HAUSER = `hauser -display 2>/dev/null`;
        if ("@HAUSER") {
            print "\n$INFOSTR Veritas Cluster HA user summary\n";
            print @HAUSER;
        }
    }
    else {
        print "\n$INFOSTR Veritas Cluster package not installed\n";
    }

    my @SNDRadm = `sndradm -i 2>/dev/null`;
    if ("@SNDRadm") {
        $opt_r = 1;
        print "\n$INFOSTR Sun Network Data Replication (SNDR) seemingly installed\n";
        print @SNDRadm;

        my @SNDRadmp = `sndradm -P 2>/dev/null`;
        if ("@SNDRadmp") {
            print "\n";
            print @SNDRadmp;
        }
    }
    else {
        print "\n$INFOSTR Sun Network Data Replication (SNDR) not installed\n";
    }

    my @IIadm = `iiadm -i 2>/dev/null`;
    if ("@IIadm") {
        print "\n$INFOSTR Instant Image (II) seemingly installed\n";
        print @IIadm;
    }
    else {
        print "\n$INFOSTR Instant Image (II) not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING CLUSTER CONFIGURATION $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING CONTINENTALCLUSTER AND METROCLUSTER CONFIGURATION $datestring ***");

    my @horcmconf = `ls /etc/horcm*.conf 2>/dev/null`;
    foreach my $horcm ( @horcmconf ) {
        my @horcmarr = `egrep -v ^# $horcm`;
        if ( @horcmarr ) {
            print "$INFOSTR Configuration file $horcm\n";
            print @horcmarr;
            print "\n";
        }
    }

    my @ccmcclu = `raidqry -l 2>/dev/null`;
    if ( @ccmcclu ) {
        print "$INFOSTR Continentalcluster/Metrocluster seemingly running\n";
        print @ccmcclu;

        my @ccmccluf = `raidqry -l -f`;
        if ( @ccmccluf ) {
            print "\n$INFOSTR Floatable hosts\n";
            print @ccmcclu;
        }

        my @raidcvhkscan = `raidvchkscan -v jnl`;
        if ( @raidcvhkscan ) {
            print "\n$INFOSTR Journal Group summary\n";
            print @raidcvhkscan;
        }

        my @horcctl = `horcctl -D`;
        if ( @horcctl ) {
            print "\n$INFOSTR Horcctl summary\n";
            print @horcctl;
        }

        my @cmviewconcl = `cmviewconcl -v`;
        if ( @cmviewconcl ) {
            print "\n$INFOSTR Cmviewconcl summary\n";
            print @cmviewconcl;
        }

        my @cmquerycl = `cmquerycl -v`;
        if ( @cmquerycl ) {
            print "\n$INFOSTR Cmquerycl summary\n";
            print @cmquerycl;
        }
    }
    else {
        print "$INFOSTR Continentalcluster/Metrocluster seemingly not running\n";
    }

    datecheck();
    print_header("*** END CHECKING CONTINENTALCLUSTER AND METROCLUSTER CONFIGURATION $datestring ***");
}

#
# Subroutine to check SVM rc startup
#
sub svmsynccheck {
    datecheck();
    print_header("*** BEGIN CHECKING SYSTEM KERNEL CONFIGURATION $datestring ***");

    if ( ( -s "$syst" ) && ( -T "$syst") ) {
        if ( open( SYC, "nawk NF $syst 2>&1 |" ) ) {
            print "$INFOSTR Kernel startup file $syst\n";
            while (<SYC>) {
                next if ( grep( /^$/,  $_ ) );
                next if ( grep( /^\*/, $_ ) );

                if ( grep( /^rootdev:/, $_ ) ) {
                    ( undef, $rdv ) = split( /\s+/, $_ );
                }

                if ( "$Minor" < 11 ) {
                    if ( grep( /rstchown/, $_ ) ) {
                        ( undef, $rstch ) = split( /=/, $_ );
                        $rstch =~ s/^\s+//g;
                        chomp($rstch);
                        if ( "$rstch" == 0 ) {
                            push(@KERNARR,
"\n$PASSSTR POSIX_CHOWN_RESTRICTED enabled (parameter rstchown)\n");
                        }
                        elsif ( "$rstch" == 1 ) {
                            push(@KERNARR,
"\n$WARNSTR POSIX_CHOWN_RESTRICTED disabled (parameter rstchown)\n");
                            push(@CHECKARR, 
"\n$WARNSTR POSIX_CHOWN_RESTRICTED disabled (parameter rstchown)\n");
                            $warnings++;
                        }
                    }
                }

                if ( grep( /snooping/, $_ ) ) {
                    ( undef, $snooping ) = split( /=/, $_ );
                    $snooping =~ s/^\s+//g;
                    chomp($snooping);
                    if ( "$snooping" == 1 ) {
                        push(@KERNARR,
"\n$PASSSTR Deadman timer enabled (parameter snooping)\n");
                    }
                    elsif ( "$snooping" == 0 ) {
                        push(@KERNARR,
"\n$WARNSTR Deadman timer disabled (parameter snooping)\n");
                        push(@CHECKARR, 
"\n$WARNSTR Deadman timer disabled (parameter snooping)\n");
                        $warnings++;
                    }
                }

                if ( "$snooping" == 1 ) {
                    if ( grep( /snoop_interval/, $_ ) ) {
                        ( undef, $snoopint ) = split( /=/, $_ );
                        $snoopint =~ s/^\s+//g;
                        chomp($snoopint);
                        if ( "$snoopint" ) {
                            push(@KERNARR,
"\n$PASSSTR Deadman timer panic introduced after $snoopint seconds\n");
                        }
                    } else {
                            push(@KERNARR,
"\n$INFOSTR Deadman timer panic introduced after default period of $SNOOPDEF microseconds\n");
                    }

                    if ( "$snoopint" < $SNOOPDEF ) {
                        push(@KERNARR,
"\n$WARNSTR Deadman timer panic interval $snoopint smaller than default value of $SNOOPDEF\n");
                        push(@CHECKARR,
"\n$WARNSTR Deadman timer panic interval $snoopint smaller than default value of $SNOOPDEF\n");
                        $warnings++;
                    }
                }

                if ( grep( /kmem_flags/, $_ ) ) {
                    ( undef, $KMEMFLAGS ) = split( /=/, $_ );
                    $KMEMFLAGS =~ s/^\s+//g;
                    $KMEMFLAGS =~ s/\s+$//g;
                    chomp($KMEMFLAGS);
                    if ( "$KMEMFLAGS" eq "0x1" ) {
                        push(@KERNARR,
"\n$INFOSTR Kernel memory auditing for detection of high kernel memory allocation and leaks is enabled (parameter kmem_flags)\n");
                        push(@KERNARR,
"$NOTESTR Performance degradation and large memory overhead possible\n");
                    }
                }

                if ( grep( /ngroups_max/, $_ ) ) {
                    ( undef, $ngroupsmax ) = split( /=/, $_ );
                    $ngroupsmax =~ s/^\s+//g;
                    chomp($ngroupsmax);
                    if ( "$ngroupsmax" >16 ) {
                        push(@KERNARR,
"\n$WARNSTR ngroups_max larger than 16\n");
                        push(@KERNARR,
"$NOTESTR RFC 1057 RPC Remote Procedure Call Protocol Specification Version 2 (services like NFS are affected)\n");
                        push(@KERNARR,
"$NOTESTR Workaround: use ACLs to do access control instead of multiple Unix groups\n");
                    }
                    else {
                        push(@KERNARR,
"\n$PASSSTR ngroups_max less than 16\n");
                        push(@CHECKARR, 
"\n$PASSSTR ngroups_max less than 16\n");
                        $warnings++;
                    }
                }

                if ( grep( /rlim_fd_cur/, $_ ) ) {
                    ( undef, $rlimfdcur ) = split( /=/, $_ );
                    $rlimfdcur =~ s/^\s+//g;
                    chomp($rlimfdcur);
                    if ( "$rlimfdcur" != $RLIMCURPERF ) {
                        push(@KERNARR,
"\n$INFOSTR Open file descriptors soft limit set to $rlimfdcur (parameter rlim_fd_cur)\n");
                        push(@KERNARR,
"$NOTESTR Recommended setting for performance benchmarking and scalability is $RLIMCURPERF\n");
                    }
                }

                if ( grep( /rlim_fd_max/, $_ ) ) {
                    ( undef, $rlimfdmax ) = split( /=/, $_ );
                    $rlimfdmax =~ s/^\s+//g;
                    chomp($rlimfdmax);
                    if ( "$rlimfdmax" != $RLIMMAXPERF ) {
                        push(@KERNARR,
"\n$INFOSTR Open file descriptors soft limit set to $rlimfdmax (parameter rlim_fd_max)\n");
                        push(@KERNARR,
"$NOTESTR Recommended setting for performance benchmarking and scalability is $RLIMMAXPERF\n");
                    }
                }

                if ( grep( /zfs_unmap_ignore_size/, $_ ) ) {
                    ( undef, $zfsunmapsize ) = split( /=/, $_ );
                    $zfsunmapsize =~ s/^\s+//g;
                    chomp($zfsunmapsize);
                    if ( "$zfsunmapsize" != 0 ) {
                        push(@KERNARR,
"\n$INFOSTR ZFS SCSI UNMAP ignore size set to $zfsunmapsize (parameter zfs_unmap_ignore_size for thin volume space reclamation)\n");
                    }
                }

                if ( grep( /zfs_log_unmap_ignore_size/, $_ ) ) {
                    ( undef, $zfsunmaplogsize ) = split( /=/, $_ );
                    $zfsunmaplogsize =~ s/^\s+//g;
                    chomp($zfsunmaplogsize);
                    if ( "$zfsunmaplogsize" != 0 ) {
                        push(@KERNARR,
"\n$INFOSTR ZFS SCSI UNMAP log ignore size set to $zfsunmaplogsize (parameter zfs_log_unmap_ignore_size for thin volume space reclamation)\n");
                    }
                }

                if ( grep( /noexec_user_stack_log/, $_ ) ) {
                    ( undef, $noexeclog ) = split( /=/, $_ );
                    $noexeclog =~ s/^\s+//g;
                    chomp($noexeclog);
                    if ( "$noexeclog" == 0 ) {
                        push(@KERNARR,
"\n$WARNSTR Safe user stack execution logging disabled (parameter noexec_user_stack_log)\n");
                        push(@CHECKARR, 
"\n$WARNSTR Safe user stack execution logging disabled (parameter noexec_user_stack_log)\n");
                        $warnings++;
                    }
                    elsif ( "$noexeclog" == 1 ) {
                        push(@KERNARR, 
"\n$PASSSTR Safe user stack execution logging enabled (parameter noexec_user_stack_log)\n");
                    }
                }

                if ( $KERNEL_BITS == 32 ) { 
                    if ( grep( /noexec_user_stack=|noexec_user_stack /, $_ ) ) {
                        ( undef, $noexecusr ) = split( /=/, $_ );
                        $noexecusr =~ s/^\s+//g;
                        chomp($noexecusr);
                        if ( "$noexecusr" == 0 ) {
                            push(@KERNARR,
"\n$WARNSTR Safe user stack execution disabled (parameter noexec_user_stack)\n");
                            push(@CHECKARR, 
"\n$WARNSTR Safe user stack execution disabled (parameter noexec_user_stack)\n");
                            $warnings++;
                        }
                        elsif ( "$noexecusr" == 1 ) {
                            push(@KERNARR,
"\n$PASSSTR Safe user stack execution enabled (parameter noexec_user_stack)\n");
                        }
                    }
                } else {
                    if ( grep( /noexec_user_stack=|noexec_user_stack /, $_ ) ) {
                        ( undef, $noexecusr ) = split( /=/, $_ );
                        $noexecusr =~ s/^\s+//g;
                        chomp($noexecusr);
                        if ( "$noexecusr" == 0 ) {
                            push(@KERNARR,
"\n$WARNSTR Safe user stack execution disabled (parameter noexec_user_stack)\n");
                            push(@CHECKARR, 
"\n$WARNSTR Safe user stack execution disabled (parameter noexec_user_stack)\n");
                            $warnings++;
                        }
                        elsif ( "$noexecusr" == 1 ) {
                            push(@KERNARR,
"\n$PASSSTR Safe user stack execution enabled (parameter noexec_user_stack)\n");
                        }
                    } else {
                        push(@KERNARR,
"\n$PASSSTR Safe user stack execution enabled by default on ${KERNEL_BITS}-bit systems (parameter noexec_user_stack)\n");
                    }
                }

                if ( grep( /mirrored_root_flag/, $_ ) ) {
                    ( undef, $mflagsvm ) = split( /=/, $_ );
                    $mflagsvm =~ s/^\s+//g;
                    chomp($mflagsvm);
                    if ( "$mflagsvm" == 1 ) {
                        push(@KERNARR,
"\n$PASSSTR SVM override the 50%+1 rule enabled (parameter mirrored_root_flag should be 1 for two-disk boot environment)\n");
                    }
                    elsif ( "$mflagsvm" == 0 ) {
                        push(@KERNARR,
"\n$WARNSTR SVM override the 50%+1 rule disabled (parameter mirrored_root_flag should be 1 for two-disk boot environment)\n");
                        push(@CHECKARR, 
"\n$WARNSTR SVM override the 50%+1 rule disabled (parameter mirrored_root_flag)\n");
                        $warnings++;
                    }
                    else {
                        push(@KERNARR,
"\n$WARNSTR SVM override the 50%+1 rule not defined (parameter mirrored_root_flag should be 1 for two-disk boot environment)\n");
                        push(@CHECKARR, 
"\n$WARNSTR SVM override the 50%+1 rule not defined (parameter mirrored_root_flag)\n");
                        $warnings++;
                    }
                }

                if ( grep( /^watchdog_enable/, $_ ) ) {
                    ( undef, $watche ) = split( /=/, $_ );
                    $watche =~ s/^\s+//g;
                    chomp($watche);
                    if ( "$watche" == 1 ) {
                        push(@KERNARR,
"\n$PASSSTR Watchdog enabled (parameter watchdog_enable)\n");
                    }
                    else {
                        push(@KERNARR,
"\n$WARNSTR Watchdog disabled (parameter watchdog_enable)\n");
                        push(@CHECKARR, 
"\n$WARNSTR Watchdog disabled (parameter watchdog_enable)\n");
                        $warnings++;
                    }
                }
                print $_;
            }
            close(SYC);

            if ( !"$rstch" ) {
                push(@KERNARR, "\n$PASSSTR POSIX_CHOWN_RESTRICTED enabled\n");
            }
        }
        else {
            print "$WARNSTR Cannot open $syst\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $syst\n");
            $warnings++;
        }
    }

    if ( "$snooping" == 1 ) {
        push(@KERNARR,
"\n$PASSSTR Deadman timer enabled (parameter snooping)\n");
    }
    else {
        if ( "$snooping" == 0 ) {
            push(@KERNARR,
"\n$WARNSTR Deadman timer disabled (parameter snooping)\n");
            push(@CHECKARR, 
"\n$WARNSTR Deadman timer disabled (parameter snooping)\n");
            $warnings++;
        }
    }

    if ( "@KERNARR" ) {
        print @KERNARR;
    }

    if ( open( GETC, "getconf -a |" ) ) {
        print "\n$INFOSTR List kernel configuration\n";
        while (<GETC>) {
            print $_;
        }
        close(GETC);
    }
    else {
        print "\n$WARNSTR Cannot run getconf\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run getconf\n");
        $warnings++;
    }

    my @auditstat = `auditstat -T -d 2>/dev/null`;
    if ("@auditstat") {
        print "\n$INFOSTR Kernel auditing statistics\n";
        print @auditstat;
    }

    my @NMKSYS = ();
    my @NMARR  = ();
    if ( open( KMSYS, "nm $KSYMS | grep OBJ 2>/dev/null |" ) ) {
        print "\n$INFOSTR Kernel parameters and objects from kernel symbols file $KSYMS\n";
        while (<KMSYS>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            chomp($_);
            my @nmkarr = split( /\|/, $_ );
            $nmkarr[2] =~ s/^\s+//g;
            $nmkarr[2] =~ s/\s+$//g;
            $nmkarr[$#nmkarr] =~ s/^\s+//g;
            $nmkarr[$#nmkarr] =~ s/\s+$//g;
            push(@NMKSYS, "$nmkarr[$#nmkarr] = $nmkarr[2]\n");
        }
        close(KMSYS);
    }
    else {
        print "\n$WARNSTR Cannot check objects and kernel parameters from kernel symbols file $KSYMS \n";
    }

    if ( "@NMKSYS" ) {
        print "\n$INFOSTR Formatted objects and kernel parameters from kernel symbols file $KSYMS\n";
        print @NMKSYS;
    }

    datecheck();
    print_header("*** END CHECKING SYSTEM KERNEL CONFIGURATION $datestring ***");

    if ( grep( /SVM/, "$Diskmgr" ) ) {
        datecheck();
        print_header("*** BEGIN CHECKING SVM SYNCHRONISATION $datestring ***");

        if ( ( -s "$lvmconf" ) && ( -T "$lvmconf" ) ) {
            if ( open( SVMSYNC, "egrep -v ^# $lvmconf 2>&1 |" ) ) {
                print "$INFOSTR SVM startup file $lvmconf\n";
                while (<SVMSYNC>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(SVMSYNC);
            }
            else {
                print "$WARNSTR Cannot open $lvmconf\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open $lvmconf\n");
                $warnings++;
            }
        }

        if ( open( METADB, "metadb | nawk NF |" ) ) {
            my $metadbav = q{};
            print "\n$INFOSTR SVM replicas status\n";
            while (<METADB>) {
                next if grep( /flags/, $_ );
                $_ =~ s/^\s+//g;

                ( $metadbav, @Restmdb ) = split( /\s+/, $_ );
                if ( !grep( /\ba\b/, $metadbav ) ) {
                    print "\n$WARNSTR Metadb replica not available\n";
                    push(@CHECKARR, "\n$WARNSTR Metadb replica not available\n");
                    $warnings++;
                }

                print $_;

                my $marrent = $Restmdb[ $Restmdb - 1 ];
                chomp($marrent);
                if ( !grep( /\Q$marrent\E/, @Metadbdb ) ) {
                    push( @Metadbdb, $marrent );
                }
            }
            close(METADB);

            if ( $#Metadbdb == 0 ) {
                print "\n$ERRSTR Only one disk defined for metadb replicas\n";
                push(@CHECKARR, "\n$ERRSTR Only one disk defined for metadb replicas\n");
                $warnings++;
            }
            elsif ( $#Metadbdb >= 1 ) {
                print
"\n$PASSSTR Metadb replicas defined accross different disks\n";
            }
            else {
                print "\n$ERRSTR No metadb replicas!\n";
                push(@CHECKARR, "\n$ERRSTR No metadb replicas!\n");
            }
        }
        else {
            print "\n$WARNSTR Cannot run metadb\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run metadb\n");
            $warnings++;
        }

        if ( open( METAS, "metastat | nawk NF |" ) ) {
            print "\n$INFOSTR SVM status\n";
            while (<METAS>) {
                if ( grep( /maint/i, $_ ) ) {
                    print "\n$WARNSTR Metadevice problem\n";
                    print $_;
                    push(@CHECKARR, "\n$WARNSTR Metadevice problem\n");
                    push(@CHECKARR, $_);
                    $warnings++;
                }
                else {
                    print $_;
                }

                if ( grep( /^c[0-9]/, $_ ) ) {
                    ( $realdsk, undef ) = split( /\s+/, $_ );
                    chomp($realdsk);
                    $realctrl = $realdsk;
                    $realctrl =~ s/t.*$//g;
                    $DKARRAY{$realctrl}++;
                    print "\n$INFOSTR Disk $realdsk on controller $realctrl\n";
                    $SVMDISK++;
                }
            }
            close(METAS);
        }
        else {
            print "\n$WARNSTR Cannot run metastat\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run metastat\n");
            $warnings++;
        }

        my @lppm = keys(%DKARRAY);

        foreach my $aaa (@lppm) {
            print
"\n$WARNSTR Multiple disks ($DKARRAY{$aaa}) on same controller $aaa\n";
            push(@CHECKARR,
"\n$WARNSTR Multiple disks ($DKARRAY{$aaa}) on same controller $aaa\n");
            $warnings++;
            $bings++;
        }

        my @metadb = `metastat -i 2>/dev/null`;
        if ("@metadb") {
            print "\n$INFOSTR SVM meta database status\n";
            print @metadb;
        }

        my @metaset = `metaset 2>/dev/null`;
        if ("@metaset") {
            print "\n$INFOSTR SVM metaset\n";
            print @metaset;
        }

        datecheck();
        print_header("*** END CHECKING SVM SYNCHRONISATION $datestring ***");
    }
}

#
# Subroutine to check boot devices
#
sub bootdev {
    datecheck();
    print_header("*** BEGIN CHECKING CURRENT BOOT DEVICE $datestring ***");

    if ( "$Bootpath" ) {
        print "Boot path:     $Bootpath\n";
        print "               $Autobootonerror\n";
        print "               $Autoboot\n";
    }
    elsif ( "$zpoolboot" ) {
        print "\nZFS Boot path: $zpoolboot\n";
    }
    else {
        my $BOOTDEV = `devnm / 2>/dev/null`;
        if ( "$BOOTDEV" ) {
            print "Boot path:     $BOOTDEV\n";
        }
    }

    if ( "@vxcheck" ) {
        if ( open( VXI, "vxinfo |" ) ) {
            print "$INFOSTR VxFS volume status\n";
            while (<VXI>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /^Unstartable/, $_ ) ) {
                    print "$ERRSTR VxFS volume not started correctly\n";
                    print $_;
                    push(@CHECKARR, "\n$ERRSTR VxFS volume not started correctly\n");
                    push(@CHECKARR, $_);
                    $warnings++;
                }
                else {
                    print $_;
                }
            }
        }
        close(VXI);

        if ( open( BMX, "vxdg list rootdg |" ) ) {
            while (<BMX>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /^config disk/, $_ ) ) {
                    if ( grep( /state=clean online/, $_ ) ) {
                        print
                          "\n$PASSSTR VxVM boot volume in healthy state\n";
                    }
                    else {
                        print
"\n$WARNSTR VxVM boot volume not in healthy state\n";
                        push(@CHECKARR,
"\n$WARNSTR VxVM boot volume not in healthy state\n");
                        push(@CHECKARR, $_);
                        $warnings++;
                    }
                }
                print $_;
            }
            close(BMX);
        }
        else {
            print "\n$WARNSTR Cannot run vxdg\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run vxdg\n");
            $warnings++;
        }

        if ( open( MP, "vxprint -g rootdg -vp |" ) ) {
            print "\n$INFOSTR VxVM rootdg\n";
            while (<MP>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /^dm/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    (
                        undef, undef, $vxdisk, $vxdisklayout, $vxblocksize,
                        $vxdisksize
                      )
                      = split( /\s+/, $_ );
                    if ("$vxdisk") {
                        push( @VXBOOTDISK, $vxdisk );
                    }
                }
                if ( grep( /rootvol/, $_ ) ) {
                    if ( grep( /^pl/, $_ ) ) {
                        $VXBOOT++;
                    }
                }
                elsif ( grep( /swapvol/, $_ ) ) {
                    if ( grep( /^pl/, $_ ) ) {
                        $VXSWAP++;
                    }
                }
                print $_;
            }
            close(MP);
        }

        if ( "$VXBOOT" == 0 ) {
            print "$WARNSTR Boot volumes not in VxVM\n";
            push(@CHECKARR, "\n$WARNSTR Boot volumes not in VxVM\n");
            $warnings++;
        }
        elsif ( "$VXBOOT" == 1 ) {
            print "$WARNSTR Single boot volume in VxVM\n";
            push(@CHECKARR, "\n$WARNSTR Single boot volume in VxVM\n");
            $warnings++;
        }
        else {
            print "$PASSSTR Multiple boot volumes in VxVM\n";
        }

        if ( "$VXSWAP" == 0 ) {
            print "$WARNSTR Swap volumes not in VxVM\n";
            push(@CHECKARR, "\n$WARNSTR Swap volumes not in VxVM\n");
            $warnings++;
        }
        elsif ( "$VXSWAP" == 1 ) {
            print "$WARNSTR Single swap volume in VxVM\n";
            $warnings++;
        }
        else {
            print "$PASSSTR Multiple swap volumes in VxVM\n";
        }

        if ( -f "$volboot" && -s "$volboot" ) {
            print "$PASSSTR VxVM $volboot exists\n";
            if ( open( VB, "nawk '! /^#/ && ! /awk/ {print}' $volboot |" ) ) {
                while (<VB>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
            }
            close(VB);
        }
        else {
            print "$WARNSTR $volboot corrupt or missing\n";
            push(@CHECKARR, "\n$WARNSTR $volboot corrupt or missing\n");
            $warnings++;
        }

        my @vxdmpadm = `vxdmpadm listctlr all  2>/dev/null | nawk NF`;
        if ("@vxdmpadm") {
            print "\n$INFOSTR VX DMP setup\n";
            print @vxdmpadm;
        }
    }

    my @bootadm = `bootadm list-archive`;
    if ( "@bootadm" ) {
        print "\n$INFOSTR Boot status of GRUB-enabled operating system\n";
        print @bootadm;

        my @bootadmlst = `bootadm list-menu`;
        if ( "@bootadmlst" ) {
            print "\n$INFOSTR Boot list menu of GRUB-enabled operating system\n";
            print @bootadmlst;
        }
    }

    datecheck();
    print_header("*** END CHECKING CURRENT BOOT DEVICE $datestring ***");
}

#
# Subroutine to check boot volumes
#
sub bootcheck {
    datecheck();
    print_header "*** BEGIN CHECKING DISKS $datestring ***";

    if ( open( FF, "ls $rdsklist/*s2 $rdsklist/*s0 |" ) ) {
        while (<FF>) {
            chomp($_);
            $impdisk = "$_";
            push(@ALLDISKS, $impdisk);
            if (
                open( FQ,
"devinfo -p $impdisk 2>/dev/null | nawk '! /No such device/ && ! /awk/ {print}' |"
                )
              )
            {
                print "$PASSSTR Disk $impdisk has valid VTOC\n";
                while (<FQ>) {
                    ( undef, undef, undef, undef, $dssize, undef ) =
                      split( /\s+/, $_ );
                    if ( open( FZ, "prtvtoc $impdisk |" ) ) {
                        @muarr = ();
                        while (<FZ>) {
                            next if grep( /Unable/, $_ );
                            next if grep( /^$/,     $_ );
                            push( @muarr, $_ );
                        }
                        close(FZ);
                    }
                    else {
                        print "$INFOSTR Cannot list VTOC for device $impdisk\n";
                    }

                    my $disksizeGB = int( $dssize / ( 1028 * 2048 ) );
                    if ( $disksizeGB < $MinBootSize ) {
                        print "$WARNSTR $impdisk is less than ";
                        print "recommended in $OS_Standard\n";
                        print
"($disksizeGB GB while minimum is $MinBootSize GB)\n\n";
                        push(@CHECKARR, "\n$WARNSTR $impdisk is less than ");
                        push(@CHECKARR, "recommended in $OS_Standard\n");
                        push(@CHECKARR,
"($disksizeGB GB while minimum is $MinBootSize GB)\n");
                    }
                    else {
                        print "$PASSSTR $impdisk is larger than ";
                        print "recommended in $OS_Standard\n";
                        print
"($disksizeGB GB while minimum is $MinBootSize GB)\n\n";
                    }
                }
                close(FQ);
                if ("@muarr") {
                    print "@muarr\n";
                }
                else {
                    print "$INFOSTR Device $impdisk has no partitions\n";
                    print "\n";
                }
            }
            else {
                print "$INFOSTR VTOC on disk $impdisk cannot be found\n";
            }
        }
        close(FF);
    }
    else {
        print "$ERRSTR Cannot list directory $rdsklist\n";
        push(@CHECKARR, "\n$ERRSTR Cannot list directory $rdsklist\n");
        $warnings++;
    }

    my @DISKINFO = `diskinfo 2>/dev/nulli | nawk NF`;
    if ( "@DISKINFO" ) {
        print "\n$INFOSTR Diskinfo summary\n";
        print @DISKINFO;
    }
    
    datecheck();
    print_header "*** END CHECKING DISKS $datestring ***";
}

#
# Subroutine to check savecrash
#
sub crashcheck {
    datecheck();
    print_header "*** BEGIN CHECKING CRASH CONFIGURATION $datestring ***";

    if ( open( FROM, "egrep -v ^# $CRASHCONF |" ) ) {
        print "$INFOSTR $CRASHCONF configuration\n";
        while (<FROM>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            chomp;
            if ( grep( /^DUMPADM_ENABLE/, $_ ) ) {
                ( undef, $crashconf ) = split( /=/, $_ );
            }
            if ( grep( /^DUMPADM_SAVDIR/, $_ ) ) {
                ( undef, $crashdir ) = split( /=/, $_ );
            }
            if ( grep( /^DUMPADM_DEVICE/, $_ ) ) {
                ( undef, $dumpdev ) = split( /=/, $_ );
                $dumpdev =~ s/^\s+//g;
                $dumpdev =~ s/\s+$//g;
                push(@DUMPARR, $dumpdev);
            }
        }
        close(FROM);
    }
    else {
        print "$WARNSTR Cannot open $CRASHCONF\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $CRASHCONF\n");
        $warnings++;
    }

    if ( ( $crashconf eq "yes" ) || ( $crashconf eq "YES" ) ) {
        print "\n$INFOSTR Crash dump enabled in $CRASHCONF\n";
        print "$NOTESTR Best practice is to disable it and use dedicated dump devices that are not shared with swap\n";
        print "$NOTESTR In that case, manual savecore can be initiated after reboot without fear that swap will overwrite crash dump\n";
    }
    else {
        print "\n$INFOSTR Crash dump not enabled in $CRASHCONF\n";
        print "$NOTESTR Best practice is to disable it and use dedicated dump devices that are not shared with swap\n";
        print "$NOTESTR In that case, manual savecore can be initiated after reboot without fear that swap will overwrite crash dump\n";
    }

    if ( open( CC, "dumpadm |" ) ) {
        print "\n$PASSSTR Dumpadm status\n";
        while (<CC>) {
            $_ =~ s/^\s+//g;
            next if ( grep( /^$/, $_ ) );
            print $_;
            if ( grep( /Dump content:/, $_ ) ) {
                $_ =~ s/Dump content:\s+//g;
                $TOTAL_PAGES = $_;
                chomp($TOTAL_PAGES);
            }
        }
        close(CC);
    }
    else {
        print "\n$WARNSTR Cannot run dumpadm\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run dumpadm\n");
        $warnings++;
    }

    if ( $TOTAL_PAGES eq "all pages" ) {
        print "\n$PASSSTR Full crash dump specified ";
        print "($TOTAL_PAGES)\n";
    }
    else {
        print "\n$WARNSTR Full crash dump not specified ";
        print "($TOTAL_PAGES only)\n";
        push(@CHECKARR, "\n$WARNSTR Full crash dump not specified ");
        push(@CHECKARR, "($TOTAL_PAGES only)\n");
        $warnings++;
    }

    datecheck();
    print_header "*** END CHECKING CRASH CONFIGURATION $datestring ***";

    datecheck();
    print_header "*** BEGIN CHECKING CORE CONFIGURATION $datestring ***";

    if ( open( CADM, "coreadm |" ) ) {
        print "$PASSSTR Coreadm status\n";
        while (<CADM>) {
            $_ =~ s/^\s+//g;
            next if ( grep( /^$/, $_ ) );
            print $_;
        }
        close(CADM);
    }
    else {
        print "$WARNSTR Cannot run coreadm\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run coreadm\n");
        $warnings++;
    }

    datecheck();
    print_header "*** END CHECKING CORE CONFIGURATION $datestring ***";
}

#
# Subroutine to check file system free disk space and inodes
#
sub space {
    datecheck();
    print_header "*** BEGIN CHECKING FILE SYSTEMS SPACE AND INODES MINIMUM 10% FREE $datestring ***";

    $THRESHOLD = 10;
    $mingood   = 100 - $THRESHOLD;

    if ("$MEM_MBYTE") {
        $fs_crash = $MEM_MBYTE / 2;
    }
    else {
        $fs_crash = 1024;
    }

    #
    # Associative array of minimum file system sizing in MBytes
    # (as set in the Solaris Standard Build)
    # 
    my %OSARRAY1 = (
        "/",               "8192",  "/export/home",  "1024",
        "/usr",            "8192",  "/var",          "$fs_crash",
        "/opt",            "8192",
    );

    # If boot partition uses ZFS, /opt  and /usr file systems are not 
    # separate from root file system
    # 
    if ( "$dffstyp" eq "zfs" ) {
        delete $OSARRAY1{"/opt"}; 
        delete $OSARRAY1{"/usr"}; 
    }

    %OSARRAY = %OSARRAY1;

    my @MYFSTYPE = ( "ufs", "vxfs", "zfs", );

    foreach $myfs ( sort @MYFSTYPE ) {
        if ( open( CC, "df -k -F $myfs |" )) {
            my $fscnt   = 0;
            my @MYFSARR = ();
            my @MYFSCOM = ();
            print "$INFOSTR $myfs file systems:\n\n";
            while (<CC>) {
                push(@MYFSARR, $_);
                chomp;
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /Mounted on/, $_ ) );
                @ckarr = split( /\s+/, $_ );
                my $zzz = scalar @ckarr;
                next if ( $zzz == 1 );
                ( $fs, $allocated, $used, $avail, $pcused, $ffs ) =
                  split( /\s+/, $_ );
                $fscnt++;

                # Check each file system for lost+found
                #
                @Skipnomnt = ( '/dev/fd', '/proc', '/var/run', '/etc/mnttab' );

                if ( "$myfs" ne "zfs" ) {
                    if ( !-d "$ffs/$lfdir" ) {
                        push(@MYFSCOM,
                          "\n$WARNSTR File system missing or corrupt $ffs/$lfdir\n");
                        push(@CHECKARR,
                          "\n$WARNSTR File system missing or corrupt $ffs/$lfdir\n");
                        $warnings++;
                    }
                    else {
                        push(@MYFSCOM,
                          "\n$PASSSTR File system has valid $ffs/$lfdir\n");
                    }
                }
                
                push( @MAU, $ffs );
               
                if ( $OSARRAY{$ffs} ) {
                    $deffs_size = $OSARRAY{$ffs};
                    my $allocMB = int( $allocated / 1024 );
                    my $allocGB = int( $allocMB / 1024 );
                    if ( "$allocMB" < "$deffs_size" ) {
                        push(@MYFSCOM, "\n$WARNSTR F/S size for $ffs is less than ");
                        push(@MYFSCOM, "recommended in $OS_Standard\n");
                        push(@MYFSCOM, "($allocMB MB while minimum is $deffs_size MB)\n");
                        push(@CHECKARR, "\n$WARNSTR F/S size for $ffs is less than ");
                        push(@CHECKARR, "recommended in $OS_Standard\n");
                        push(@CHECKARR, "($allocMB MB while minimum is $deffs_size MB)\n");
                        $warnings++;
                    }
                    elsif ( "$allocGB" >= "$MAXFSSIZE" ) {
                    push(@MYFSCOM, "\n$INFOSTR F/S size for $ffs is larger than ");
                    push(@MYFSCOM, "recommended for efficient backups\n");
                    push(@MYFSCOM,  "($allocGB GB while maximum is $MAXFSSIZE GB)\n");
                    }
                    else {
                        push(@MYFSCOM, "\n$PASSSTR F/S size for $ffs as ");
                        push(@MYFSCOM, "recommended in $OS_Standard\n");
                        push(@MYFSCOM, "($allocMB MB while minimum is $deffs_size MB)\n");
                    }
                }

                $pcused =~ s/%//g;
                if ( !grep( /\Q$ffs\E/, @Skipnomnt ) ) {
                    if ( ( 100 - $pcused ) >= $THRESHOLD ) {
                        push(@MYFSCOM, 
                          "\n$PASSSTR File system $ffs has more than $mingood% ");
                        push(@MYFSCOM, "free disk space ($pcused% used)\n");
                    }
                    else {
                        push(@MYFSCOM,
                          "\n$WARNSTR File system $ffs has less than $mingood% ");
                        push(@MYFSCOM, "free disk space ($pcused% used)\n");
                        push(@CHECKARR,
                          "\n$WARNSTR File system $ffs has less than $mingood% ");
                        push(@CHECKARR, "free disk space ($pcused% used)\n");
                        $warnings++;
                    }
                }
                print "\n";
            }
            close(CC);

            if ( $fscnt == 0 ) {
                print "$INFOSTR No $myfs on the system\n";
            }
            else {
                print @MYFSARR;
            }

            if ( "@MYFSCOM" ) {
                print @MYFSCOM;
            }
        } else {
            print "$WARNSTR Cannot run df\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run df\n");
            $warnings++;
        }

        if ( "$myfs" ne "zfs" ) {
            if ( open( CCM, "df -F $myfs -o i |" ) ) { 
                while (<CCM>) {
                    chomp;
                    next if ( grep( /^$/,         $_ ) );
                    next if ( grep( /Mounted on/, $_ ) );
                    @ckarr = split( /\s+/, $_ );
                    my $zzz = scalar @ckarr;
                    next if ( $zzz == 1 );
                    ( $fs, $iused, $ifree, $ipcused, $ffs ) = split( /\s+/, $_ );
                    push( @MAU, $ffs );
                    $ipcused =~ s/%//g;

                    if ( $ipcused > $mingood ) {
                        print "$WARNSTR File system $ffs has less than $mingood% ";
                        print "free inodes ($ipcused% used)\n\n";
                        push(@CHECKARR, "\n$WARNSTR File system $ffs has less than $mingood% ");
                        push(@CHECKARR, "free inodes ($ipcused% used)\n");
                        $warnings++;
                    }
                    else {
                        print "$PASSSTR File system $ffs has more than $mingood% ";
                        print "free inodes ($ipcused% used)\n\n";
                    }
                }
                close(CCM);
            }
            else {
                print "$WARNSTR Cannot run df\n";
                $warnings++;
            }
        }
    }

    my @DFI = `df -o -i 2>/dev/null`;
    if (@DFI) {
        print "\n$INFOSTR File system inode status\n";
        print @DFI;
    }

    my @LOCKFS = `lockfs 2>/dev/null`;
    if (@LOCKFS) {
        print "\n$INFOSTR File system locks\n";
        print @LOCKFS;
    }

    my @CACHESTAT = `cachefsstat 2>/dev/null`;
    if (@CACHESTAT) {
        print "\n$INFOSTR Cache file system statistics\n";
        print @CACHESTAT;
    }

    datecheck();
    print_header "*** END CHECKING FILE SYSTEMS SPACE AND INODES MINIMUM 10% FREE $datestring ***";

    datecheck();
    print_header "*** BEGIN CHECKING FILE SYSTEMS NAMING STRUCTURE AS PER STANDARDS $datestring ***";

    my @VVM = keys(%OSARRAY);
    if ("@VVM") {
        foreach $i ( sort @VVM ) {
            if ( ! grep( /^$i$/, @MAU) ) {
                if ( "$dffstyp" ne "zfs" ) {
                    print
"$WARNSTR File system $i does not exist as per $OS_Standard\n";
                    push(@CHECKARR,
"\n$WARNSTR File system $i does not exist as per $OS_Standard\n");
                    $warnings++;
                }
                else {
                    print "$PASSSTR File system $i exists as per $OS_Standard\n";
                }
            }
            else {
                print "$PASSSTR File system $i exists as per $OS_Standard\n";
            }
        }
    }

    datecheck();
    print_header "*** END CHECKING FILE SYSTEMS NAMING STRUCTURE AS PER STANDARDS $datestring ***";
}

sub netcalc {
    my $laninst = shift;
    push(@NETARR, "$WARNSTR Interface $laninst running half-duplex\n");
    push(@CHECKARR, "\n$WARNSTR Interface $laninst running half-duplex\n");
}

#
# Subroutine to check LAN cards
#
sub lan {
    datecheck();
    print_header("*** BEGIN CHECKING LAN STATUS $datestring ***");

    if ( "$Minor" < 11 ) {
        if ( open( CC, "ifconfig -a |" ) ) {
            while (<CC>) {
                push(@ALLLAN, $_);
                chomp;

                next if ( grep( /^$/, $_ ) );

                if ( grep( /\binet6\b/, $_ ) ) {
                    $INET6COUNT++;
                }

                if ( grep( /flags=/, $_ ) ) {
                    $lancardno++;
                    ( $lanint, undef ) = split( /\s+/, $_ );
                    $lanint =~ s/:$//g;
                    if ( ! grep(/:|lo0/, $lanint) ) {
                        $reallancardno++;
                    }

                    next if grep( /^lo0/, $lanint );
                    if ( grep( /^bge/, $lanint ) ) {
                        next if grep( /:/, $lanint );
                        print "\n$INFOSTR Interface $lanint\n";
                        $LANdpx = `ndd -get /dev/$lanint link_duplex`;
                        chomp($LANdpx);
                        $bge_old = "37";

                        push(@NETARR, 
"$INFOSTR BGE driver version $bge_dr_maj.$bge_dr_min\n");

                        if ( $bge_dr_maj == 0 ) {
                            if ( $bge_dr_min <= $bge_old ) {
                                push(@NETARR, 
"$WARNSTR BGE driver older than minimum recommended 0.$bge_old\n");
                                push(@CHECKARR, 
"\n$WARNSTR BGE driver older than minimum recommended 0.$bge_old\n");
                                "$LANdpx" == 0
                                  ? netcalc($lanint) 
                                  : "$LANdpx" == 1
                                  ? push(@NETARR, 
"$PASSSTR Interface $lanint running full-duplex\n")
                                  : "$LANdpx" == -1
                                  ? push(@NETARR, 
"$INFOSTR Interface $lanint running undefined duplex\n")
                                  : push(@NETARR, 
"$INFOSTR Interface $lanint running undefined duplex\n");
                            }
                            else {
                                "$LANdpx" == 0
                                  ? push(@NETARR, 
"$INFOSTR Interface $lanint running undefined duplex\n")
                                  : "$LANdpx" == 1
                                  ? netcalc($lanint) 
                                  : "$LANdpx" == 2
                                  ? push(@NETARR, 
"$PASSSTR Interface $lanint running full-duplex\n")
                                  : push(@NETARR, 
"$PASSSTR Interface $lanint running full-duplex\n");
                            }
                        }
                        else {
                            "$LANdpx" == 0
                              ? push(@NETARR, 
"$INFOSTR Interface $lanint running undefined duplex\n")
                              : "$LANdpx" == 1
                              ? netcalc($lanint)
                              : "$LANdpx" == 2
                              ? push(@NETARR, 
                          "$PASSSTR Interface $lanint running full-duplex\n")
                              : push(@NETARR, 
"$INFOSTR Interface $lanint running undefined duplex\n");
                        }

                        $LANdps = `ndd -get /dev/$lanint link_speed`;
                        chomp($LANdps);
                        push(@NETARR, 
                      "$INFOSTR Interface $lanint running at $LANdps Mbs\n");
                    }
                    elsif ( grep( /^dmfe/, $lanint ) ) {
                        print "$INFOSTR Interface $lanint\n";
                        $LANdpx = `ndd -get /dev/$lanint link_mode`;
                        chomp($LANdpx);
                        "$LANdpx" == 0
                          ? netcalc($lanint)
                          : "$LANdpx" == 1
                          ? push(@NETARR, 
                      "$WARNSTR Interface $lanint running full-duplex\n")
                          : push(@NETARR, 
"$WARNSTR Interface $lanint running undefined duplex\n");

                        $LANdps = `ndd -get /dev/$lanint link_speed`;
                        chomp($LANdps);
                        push(@NETARR, 
                      "$INFOSTR Interface $lanint running at $LANdps Mbs\n");

                        $LANdpa = `ndd -get /dev/$lanint lp_autoneg_cap`;
                        chomp($LANdpa);
                        push(@NETARR, 
"$INFOSTR Interface $lanint has auto-negotiate capability $LANdpa\n");
                    }
                    elsif ( grep( /^eri/, $lanint ) ) {
                        print "\n$INFOSTR Interface $lanint\n";
                        $lant = $lanint;
                        $lant =~ s/[0-9]*//g;
                        $LANdpa = `ndd -get /dev/$lant lp_autoneg_cap`;
                        chomp($LANdpa);
                        push(@NETARR, 
"$INFOSTR Interface $lant has auto-negotiate capability $LANdpa\n");
                        if ( open( ERILN, "kstat -n $lanint |" ) ) {
                            while (<ERILN>) {
                                print $_;
                                $_ =~ s/^\s+//g;
                                if ( grep( /link_duplex/, $_ ) ) {
                                    ( undef, $LANdpx ) = split( /\s+/, $_ );
                                    chomp($LANdpx);
                                    "$LANdpx" == 1
                                      ? netcalc($lanint)
                                      : "$LANdpx" == 2
                                      ? push(@NETARR, 
"$PASSSTR Interface $lanint running full-duplex\n")
                                      : "$LANdpx" == 0
                                      ? push(@NETARR, 
                                      "$INFOSTR Interface $lanint down\n")
                                      : push(@NETARR, 
"$WARNSTR Interface $lanint running undefined duplex\n");
                                }

                                if ( grep( /ifspeed/, $_ ) ) {
                                    ( undef, $LANdps ) = split( /\s+/, $_ );
                                    chomp($LANdps);
                                    if ( $LANdps > 0 ) {
                                        $LANdps = int( $LANdps / 1000000 );
                                        push(@NETARR, 
"$INFOSTR Interface $lanint running at $LANdps Mbs\n");
                                    }
                                }
                            }
                        }
                        close(ERILN);
                    }
                    elsif ( grep( /^e1000/, $lanint ) ) {
                        print "\n$INFOSTR Interface $lanint\n";
                        $lant = $lanint;
                        $lant =~ s/[0-9]*//g;
                        $LANdpa = `ndd -get /dev/$lanint lp_autoneg_cap`;
                        chomp($LANdpa);
                        push(@NETARR, 
"$INFOSTR Interface $lant has auto-negotiate capability $LANdpa\n");

                        my $LANdps = `ndd -get /dev/$lanint link_speed`;
                        chomp($LANdps);
                        push(@NETARR, 
                      "$INFOSTR Interface $lanint running at $LANdps Mbs\n");

                        my $LANdup = `ndd -get /dev/$lanint link_duplex`;
                        chomp($LANdup);
                        "$LANdup" == 1
                                  ? netcalc($lanint)
                                  : "$LANdup" == 2
                                  ?  $LANmode = "full-duplex"
                                  : "$LANdup" == 3
                                  ? netcalc($lanint)
                                  : "$LANdup" == 4
                                  ?  $LANmode = "full-duplex"
                                  : push(@NETARR, 
"$WARNSTR Interface $lanint running undefined duplex\n");
                        if ( "$LANmode" ) {
                            push(@NETARR, 
                          "$INFOSTR Interface $lanint running $LANmode\n");
                        }
                    }
                    elsif ( grep( /^nxge/, $lanint ) ) {
                        print "\n$INFOSTR Interface $lanint\n";
                        $lant = $lanint;
                        $lant =~ s/[0-9]*//g;
                        $LANdpa = `ndd -get /dev/$lant adv_autoneg_cap`;
                        chomp($LANdpa);
                        push(@NETARR, 
"$INFOSTR Interface $lant has auto-negotiate capability $LANdpa\n");

                        my $LANdps = `ndd -get /dev/$lanint link_speed`;
                        chomp($LANdps);
                        push(@NETARR, 
                      "$INFOSTR Interface $lanint running at $LANdps Mbs\n");

                        my $LANpm = `ndd -get /dev/$lanint port_mode | nawk NF`;
                        chomp($LANpm);
                        push(@NETARR, "$INFOSTR $LANpm\n");
                    }
                    elsif ( grep( /^ce/, $lanint ) ) {
                        next if grep( /:/, $lanint );
                        print "\n$INFOSTR Interface $lanint\n";
                        $lant = $lanint;
                        $lant =~ s/[0-9]*//g;
                        if ( open( ERICE, "kstat -n $lanint |" ) ) {
                            while (<ERICE>) {
                                print $_;
                                $_ =~ s/^\s+//g;
                                if ( grep( /link_duplex/, $_ ) ) {
                                    ( undef, $LANdpx ) = split( /\s+/, $_ );
                                    chomp($LANdpx);
                                    "$LANdpx" == 1
                                      ? netcalc($lanint) 
                                      : "$LANdpx" == 2
                                      ? push(@NETARR, 
"$PASSSTR Interface $lanint running full-duplex\n")
                                      : "$LANdpx" == 0
                                      ? push(@NETARR, 
                                      "$INFOSTR Interface $lanint down\n")
                                      : push(@NETARR, 
"$INFOSTR Interface $lanint running undefined duplex\n");
                                }

                                if ( grep( /link_speed/, $_ ) ) {
                                    ( undef, $LANdps ) = split( /\s+/, $_ );
                                    chomp($LANdps);
                                    if ( $LANdps > 1000 ) {
                                        $LANdps = int( $LANdps / 1000000 );
                                    }
                                    push(@NETARR, 
"$INFOSTR Interface $lanint running at $LANdps Mbs\n");
                                }
                            }
                        }
                        close(ERICE);
                    }
                    elsif ( grep( /^ipge/, $lanint ) ) {
                        next if grep( /:/, $lanint );
                        print "\n$INFOSTR Interface $lanint\n";
                        $lant = $lanint;
                        $lant =~ s/[0-9]*//g;
                        if ( open( ERICE, "kstat -n $lanint |" ) ) {
                            while (<ERICE>) {
                                print $_;
                                $_ =~ s/^\s+//g;
                                if ( grep( /link_duplex/, $_ ) ) {
                                    ( undef, $LANdpx ) = split( /\s+/, $_ );
                                    chomp($LANdpx);
                                    "$LANdpx" == 1
                                      ? netcalc($lanint) 
                                      : "$LANdpx" == 2
                                      ? push(@NETARR, 
"$PASSSTR Interface $lanint running full-duplex\n")
                                      : "$LANdpx" == 0
                                      ? push(@NETARR, 
                                      "$INFOSTR Interface $lanint down\n")
                                      : push(@NETARR, 
"$INFOSTR Interface $lanint running undefined duplex\n");
                                }

                                if ( grep( /link_speed/, $_ ) ) {
                                    ( undef, $LANdps ) = split( /\s+/, $_ );
                                    chomp($LANdps);
                                    if ( $LANdps > 1000 ) {
                                        $LANdps = int( $LANdps / 1000000 );
                                    }
                                    push(@NETARR, 
"$INFOSTR Interface $lanint running at $LANdps Mbs\n");
                                }
                            }
                        }
                        close(ERICE);
                    }
                    else {
                        print "\n$INFOSTR Interface $lanint\n";
                        $LANdpx = `ndd -get /dev/$lanint link_mode`;
                        chomp($LANdpx);
                        "$LANdpx" == 0
                          ? netcalc($lanint) 
                          : "$LANdpx" == 1
                          ? push(@NETARR, 
                          "$PASSSTR Interface $lanint running full-duplex\n")
                          : push(@NETARR, 
"$WARNSTR Interface $lanint running undefined duplex\n");

                        $LANdps = `ndd -get /dev/$lanint link_speed`;
                        chomp($LANdps);
                        push(@NETARR, 
                          "$INFOSTR Interface $lanint running at $LANdps Mbs\n");

                        $LANdpa = `ndd -get /dev/$lanint lp_autoneg_cap`;
                        chomp($LANdpa);
                        push(@NETARR, 
"$INFOSTR Interface $lanint has auto-negotiate capability $LANdpa\n");
                    }
                }
            }
            close(CC);
        }
        else {
            print "$WARNSTR Cannot run ifconfig\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run ifconfig\n");
            $warnings++;
        }
    }
    else {
        if ( open( ZCC, "ifconfig -a |" ) ) {
            while (<ZCC>) {
                push(@ALLLAN, $_);
                chomp;

                next if ( grep( /^$/, $_ ) );

                if ( grep( /\binet6\b/, $_ ) ) {
                    $INET6COUNT++;
                }

                if ( grep( /flags=.*IPv4/, $_ ) ) {
                    $lancardno++;
                    ( $lanint, undef ) = split( /\s+/, $_ );
                    $lanint =~ s/:$//g;
                    if ( ! grep(/:|lo0/, $lanint) ) {
                        $reallancardno++;
                    }
      
                    if ( open( ZRICE, "kstat -n $lanint |" ) ) {
                        while (<ZRICE>) {
                            print $_;
                            $_ =~ s/^\s+//g;
                            if ( grep( /link_duplex/, $_ ) ) {
                                ( undef, $LANdpx ) = split( /\s+/, $_ );
                                chomp($LANdpx);
                                "$LANdpx" == 1
                                  ? netcalc($lanint) 
                                  : "$LANdpx" == 2
                                  ? push(@NETARR, 
"$PASSSTR Interface $lanint running full-duplex\n")
                                  : "$LANdpx" == 0
                                  ? push(@NETARR, 
"$INFOSTR Interface $lanint down or not applicable\n")
                                  : push(@NETARR, 
"$INFOSTR Interface $lanint running undefined duplex\n");
                            }

                            if ( grep( /link_speed/, $_ ) ) {
                                ( undef, $LANdps ) = split( /\s+/, $_ );
                                chomp($LANdps);
                                if ( $LANdps > 1000 ) {
                                    $LANdps = int( $LANdps / 1000000 );
                                }
                                push(@NETARR, 
"$INFOSTR Interface $lanint running at $LANdps Mbs\n");
                            }
                        }
                        close(ZRICE);
                    }
                }
            }
            close(ZCC);
        }
        else {
            print "$WARNSTR Cannot run ifconfig\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run ifconfig\n");
            $warnings++;
        }
    }

    if ( "@NETARR" ) {
        print @NETARR;
    }

    if ( $lancardno <= 2 ) {
        print "\n$WARNSTR Only one network interface configured\n";
        push(@CHECKARR, "\n$WARNSTR Only one network interface configured\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR There are $lancardno network interfaces configured\n";
    }

    if ( "@ALLLAN" ) {
        print "\n$INFOSTR Ifconfig summary\n"; 
        print @ALLLAN;
    }

    my @IPADMIF = `ipadm show-if 2>/dev/null`;
    if ( "@IPADMIF" ) {
        print "\n$INFOSTR Ipadm interface summary\n"; 
        print @IPADMIF;

        my @IPADMA = `ipadm show-addrprop 2>/dev/null`;
        if ( "@IPADMA" ) {
            print "\n$INFOSTR Ipadm address object properties\n"; 
            print @IPADMA;
        }

        my @IPADMIP = `ipadm show-ifprop 2>/dev/null`;
        if ( "@IPADMIP" ) {
            print "\n$INFOSTR Ipadm physical and virtual datalink properties\n"; 
            print @IPADMIP;
        }
    }

    if ( -s "$defroute" && -T "$defroute" ) {
        print "\n$PASSSTR File $defroute\n";
        my @rdf = `nawk NF $defroute`;
        print @rdf;
    }

    my $defmask = "/etc/netmasks";
    if ( -s "$defmask" && -T "$defmask" ) {
        print "\n$PASSSTR File $defmask\n";
        my @rnt = `nawk NF $defmask`;
        print @rnt;
    }

    my $defnwk = "/etc/networks";
    if ( -s "$defnwk" && -T "$defnwk" ) {
        print "\n$PASSSTR File $defnwk exists\n";
        my @rnw = `nawk NF $defnwk`;
        print @rnw;
    }

    my $defncfg = "/etc/netconfig";
    if ( -s "$defncfg" && -T "$defncfg" ) {
        print "\n$PASSSTR File $defncfg exists\n";
        my @rnc = `nawk NF $defncfg`;
        print @rnc;
    }

    datecheck();
    print_header("*** END CHECKING LAN STATUS $datestring ***");
}

#
# Subroutine to check given ports
#
sub checkActivePorts {
    my @sshp = shift;

    foreach my $n (@sshp) {
        my $p = Net::Ping->new("tcp");
        $Portproto = getservbyport( $n, 'tcp' );
        $p->{port_num} = $n if $n;
        &openport( $Hostname, $n, 'tcp' );
    }
}

sub esmcalc {
    $ESMD_FLAG++;
    $HIDS_FLAG = 1;
    $IDS_FLAG++;
}

#
# Subroutine to check installed software packages
#
sub swcheck {
    datecheck();
    print_header("*** BEGIN CHECKING INSTALLED SOFTWARE $datestring ***");

    print "$NOTESTR Some applications might be installed without pkgadd\n";
    print "$NOTESTR Please check them manually\n";

    #
    # Get Solaris Product Registry Database
    #
    if ( "$Minor" >= '8' ) {
        my @bundle = `prodreg browse 2>&1`;

        if ( !"@bundle" ) {
            @bundle = "Unknown";
        }
        else {
            print "$INFOSTR Solaris Product Registry Database\n";
            print @bundle;
        }

        print "\n";
    }

    @SWarray = `pkginfo 2>/dev/null`;

    if ("@SWarray") {
        print "$INFOSTR Solaris SVR4 package status\n";
        print @SWarray;
    }
    else {
        print "$ERRSTR Solaris SVR4 package list is empty or corrupt\n";
        push(@CHECKARR, "\n$ERRSTR Solaris SVR4 package list is empty or corrupt\n");
        $warnings++;
    }

    print "\n";

    my @SWarray2 = `pkg list 2>/dev/null`;
    if ("@SWarray2") {
        print "$INFOSTR Solaris IPS package status\n";
        print "@SWarray2\n";
    }

    foreach $a (@SWmust) {
        if ( grep( /$a/i, @SWarray ) ) {
            print "\n$PASSSTR $a installed\n";
                $a eq "OmniBack"       ? $OMNI_FLAG  = 1
              : $a eq "Data Protector" ? $OMNI_FLAG  = 1
              : $a eq "SUNWvts"        ? $VTS_FLAG   = 1
              : $a eq "SUNWexplo"      ? $EXPLO_FLAG = 1
              : $a eq "SUNWinck"       ? $INCK_FLAG  = 1
              : $a eq "SMCaide"        ? $HIDS_FLAG  = 1
              : grep( /esmd|esmnetd|esmcifd/, $_ ) ? esmcalc()
              : $a eq "Tripwire" ? $HIDS_FLAG = 1
              : $a eq "Security Patch Check Tool" ? $SECPATCH_FLAG = 1
              : ( $a eq "SSH Client" )
              || ( $a eq "SSH Server" ) ? $secureshell++
              : 1;
        }
        else {
            if ( $a eq "OmniBack" ) {
                next;
            }
            elsif ( $a eq "Data Protector" ) {
                next;
            }
            elsif ( ( $a eq "SSH Client" ) || ( $a eq "SSH Server" ) ) {
                $warnings++;
            }
            else {
                print "\n$INFOSTR $a not installed\n";
            }
        }
    }

    if ( grep( /\bSUNWut\b/, @SWarray ) ) {
        $SUNRAY_FLAG++;
    }

    if ( grep( /\bCPfw1\b/, @SWarray ) ) {
        $CHECKPOINT_FLAG++;
    }

    if ( grep( /\bCKPfw\b/, @SWarray ) ) {
        $CHECKPOINT_FLAG++;
    }

    if ( grep( /\bCKPfwgui\b/, @SWarray ) ) {
        $CHECKPOINT_FLAG++;
    }

    if ( grep( /\bCKPagent\b/, @SWarray ) ) {
        $CHECKPOINT_FLAG++;
    }

    if ( grep( /\bCKPfwmap\b/, @SWarray ) ) {
        $CHECKPOINT_FLAG++;
    }

    if ( grep( /\bSUNWicgSS\b/, @SWarray ) ) {
        $SUNSCREEN_FLAG++;
    }

    if ( grep( /\bSUNWicgSA\b/, @SWarray ) ) {
        $SUNSCREEN_FLAG++;
    }

    if ( grep( /\bVRTSvcs\b/, @SWarray ) ) {
        $VRTSCLUSTER_FLAG++;
    }

    if ( grep( /\bCPQswsp\b/, @SWarray ) ) {
        $SECPATH_FLAG++;
    }

    datecheck();
    print_header("*** END CHECKING INSTALLED SOFTWARE $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING STATUS OF INSTALLED PACKAGES $datestring ***");

    if ( open( CC, "pkgchk -l |" ) ) {
        while (<CC>) {
            print "$INFOSTR SVR4 package command pkgchk\n";
            print $_;
            ( $SWname, $Swstatus ) = split( /\s+/, $_ );
            if ( grep( /ERROR:/, $_ ) ) {
                push( @Badsw, $_ );
                $warnings++;
            }
            print "\n";
        }
        close(CC);
    }
    else {
        print "$ERRSTR Cannot run SVR4 pkgchk\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run SVR4 pkgchk\n");
    }

    if (@Badsw) {
        print "$ERRSTR Software packages not installed correctly\n";
        print "@Badsw\n";
        push(@CHECKARR, "\n$ERRSTR Software packages not installed correctly\n");
        push(@CHECKARR, "@Badsw\n");
    }
    else {
        print "$PASSSTR All software packages installed correctly\n";
    }

    my @pkgv = `pkg verify 2>/dev/null`;
    if ("@pkgv") {
        print "\n$INFOSTR Solaris 11 IPS package status\n";
        print @pkgv;
    }

    my @PKGHIST = `pkg history 2>/dev/null`;
    if ("@PKGHIST") {
        print "\n$INFOSTR Solaris 11 update history\n";
        print @PKGHIST;
    }

    datecheck();
    print_header("*** END CHECKING STATUS OF INSTALLED PACKAGES $datestring ***");
}

#
# Subroutine to check firewall
#
sub checkfirewall {
    datecheck();
    print_header("*** BEGIN CHECKING FIREWALL SETUP $datestring ***");

    if ( "$SUNSCREEN_FLAG" > 0 ) {
        print "$INFOSTR SunScreen Secure Net seemingly installed\n";

        my @SUNSCarr = ( '/etc/sunscreen', '/etc/opt/SUNWicg/SunScreen' );

        foreach my $SCf (@SUNSCarr) {
            if ( -f "$SCf" ) {
                my $SCstart = "$SCf/.active";
                print
"$INFOSTR SunScreen Secure Net startup file $SCstart exists\n";
                $SCFno++;
            }
        }

        if ( "$SCFno" == 0 ) {
            print "$INFOSTR SunScreen Secure Net not started at boot\n";
        }
        else {
            my @ssadmpolicy = `ssadm policy -l -v 2>dev/null`;
            if ("@ssadmpolicy") {
                print "$INFOSTR SunScreen Secure Net policies\n";
                print @ssadmpolicy;
            }

            my @ssadmact = `ssadm active 2>dev/null`;
            if ("@ssadmact") {
                print "\n$INFOSTR SunScreen Secure Net activity status\n";
                print @ssadmact;
            }

            my @ssadmha = `ssadm ha status 2>dev/null`;
            if ("@ssadmha") {
                print "$INFOSTR SunScreen Secure Net HA status\n";
                print @ssadmha;
            }

            my @ssadmsys = `ssadm sys_info 2>dev/null`;
            if ("@ssadmsys") {
                print
                  "$INFOSTR SunScreen Secure Net software description\n";
                print @ssadmsys;
            }
        }
    }
    else {
        print "$INFOSTR SunScreen Secure Net seemingly not installed\n";
    }

    my @IPFrules = (
        '/etc/ipf.rules', '/usr/local/etc/ipf.rules', '/etc/opt/ipf/ipf.rules'
    );

    foreach my $ipftest (@IPFrules) {
        if ( -s "$ipftest" && -T "$ipftest" ) {
            my $IPFdir = `dirname $ipftest`;
            chomp($IPFdir);
            if ("@$IPFdir") {
                print "\n$INFOSTR IP Filter seemingly installed\n";
                print "$INFOSTR IP Filter base config directory $IPFdir\n";
                $IPF_FLAG++;

                my @IPFfiles = ( 'ipf.conf', 'ipf.rules', 'ipnat.rules' );

                foreach my $ipfls (@IPFfiles) {
                    $ipfls = "$IPFdir/$ipfls";
                    my @IPFcat = ();
                    if ( -s "$ipfls" && -T "$ipfls" ) {
                        @IPFcat = `nawk '! /^#/ && ! /awk/ {print}' $ipfls`;
                        if ("@IPFcat") {
                            print
"$INFOSTR IP Filter configuration file $ipfls\n";
                            print @IPFcat;
                        }
                    }
                }
            }
        }
    }

    my @IPNAT = `ipnat -l -s -v 2>/dev/null`;
    if ("@IPNAT") {
        print "\n$INFOSTR IP NAT status\n";
        print @IPNAT;
    }

    if ( "$IPF_FLAG" == 0 ) {
        print "\n$INFOSTR IP Filter seemingly not installed\n";
    }

    if ( "$CHECKPOINT_FLAG" > 0 ) {
        print "\n$INFOSTR CheckPoint Firewall-1 seemingly installed\n";

        my @fwv = `fw ver 2>/dev/null`;
        if ("@fwv") {
            print "\n$INFOSTR CheckPoint Firewall-1 version\n";
            print @fwv;
        }

        @fwlic = `fw printlic 2>/dev/null`;
        if ("@fwlic") {
            print "\n$INFOSTR CheckPoint Firewall-1 licensing\n";
            print @fwlic;
        }

        my @fwtab = `fw tab -all -u 2>/dev/null`;
        if ("@fwtab") {
            print "\n$INFOSTR CheckPoint Firewall-1 tables\n";
            print @fwtab;
        }

        my @fwlichosts = `fw lichosts 2>/dev/null`;
        if ("@fwlichosts") {
            print "\n$INFOSTR CheckPoint Firewall-1 licensed hosts\n";
            print @fwlichosts;
        }

        my @fwm = `fwm -p 2>/dev/null`;
        if ("@fwm") {
            print "\n$INFOSTR CheckPoint Firewall-1 administrators\n";
            print @fwm;
        }
    }
    else {
        print "\n$INFOSTR CheckPoint Firewall-1 seemingly not installed\n";
    }

    my @TCPDV = `tcpdchk -v 2>/dev/null`;
    if ("@TCPDV") {
        print "\n$INFOSTR Tcpd wrappers config\n";
        print @TCPDV;
    }

    my @TCPDA = `tcpdchk -v 2>/dev/null`;
    if ("@TCPDA") {
        print "\n$INFOSTR Tcpd warnings\n";
        print @TCPDA;
    }

    my @CRYPTADM = `cryptoadm list 2>/dev/null`;
    if ("@CRYPTADM") {
        print "\n$INFOSTR Cryptographic framework\n";
        print @CRYPTADM;
    }
    datecheck();
    print_header("*** END CHECKING FIREWALL SETUP $datestring ***");
}

#
# Subroutine to check installed patch packages
#
sub patch {
    datecheck();
    print_header("*** BEGIN CHECKING SUN UPDATE CONNECTION $datestring ***");

    my @patchsvr = `patchsvr setup -l 2>/dev/null`;
    if ("@patchsvr") {
         print @patchsvr;
    }
    else {
        print "$INFOSTR Sun Update Connection not configured or applicable on this system\n";
    }

    my @PKGPUBL = `pkg publisher 2>/dev/null`;
    if ("@PKGPUBL") {
        print "\n$INFOSTR Default package publisher repositories\n";
        print @PKGPUBL;
    }

    datecheck();
    print_header("*** END CHECKING SUN UPDATE CONNECTION $datestring ***");

    my @ASRADM = `asradm list 2>/dev/null`;
    if ("@ASRADM") {
        datecheck();
        print_header("*** BEGIN CHECKING AUTO SERVICE REQUEST (ASR) $datestring ***");

        print @ASRADM;

        datecheck();
        print_header("*** END CHECKING AUTO SERVICE REQUEST (ASR) $datestring ***");
    }

    if ( "$Minor" < 11 ) { 
        datecheck();
        print_header("*** BEGIN CHECKING SUN PATCH MANAGER $datestring ***");

        my @smpatch = `smpatch get 2>/dev/null`;
        if ("@smpatch") {
             print @smpatch;
        }
        else {
            print "$INFOSTR Sun Patch Manager not configured\n";
        }

        datecheck();
        print_header("*** END CHECKING SUN PATCH MANAGER $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING INSTALLED PATCHES $datestring ***");

    my @lsbundle = ();

    if ( "$Minor" < 10 ) {
        @lsbundle = `showrev -p 2>/dev/null`;
    }

    my @pkgpl = `pkg list -u 2>/dev/null`;

    if ("@lsbundle") {
        print @lsbundle;
    }
    else {
        if ("@pkgpl") {
            print @pkgpl;
        }
    }

    if (!"@lsbundle" && !"@pkgpl") {
        print "\n$INFOSTR Patches seemingly not installed on this system\n";
    }

    if ( "$opt_p" == 1 ) {
        my @INCKarr = ();
        my $incklock = "/var/opt/SUNWinck/sunic.lck";

        if ( "$INCK_FLAG" == 1 ) {
            if ( -f $incklock ) {
                print "\n$WARNSTR Lock file $incklock exists. Please check it\n";
                push(@CHECKARR, "\n$WARNSTR Lock file $incklock exists.\n");
                $warnings++;
            }
            else {
                if ( open( FH, "| sunic -i cli" ) ) {
                    select(FH);
                    $| = 1;
                    print "1\n";
                    print "\n";
                    print "5\n";
                    $| = 0;
                }
                close(FH);
            }
        }
    }

    datecheck();
    print_header("*** END CHECKING INSTALLED PATCHES $datestring ***");
}

#
# Subroutine to check privileged account
#
sub rootacc {
    datecheck();
    print_header("*** BEGIN CHECKING PRIVILEGED ACCOUNT $datestring ***");

    my $umsk    = sprintf "%lo", umask;

    if ( $umsk == "$UMASKDEF" ) {
        print "$PASSSTR Umask for root set to $UMASKDEF\n";
    }
    else {
        print "$INFOSTR Umask set to $umsk not $UMASKDEF\n";
        $warnings++;
    }

    my $roothome = `nawk -F: '/^root:/ && ! /awk/ {print \$6}' $PASSFILE`;
    chomp($roothome);
    if ( "$roothome" ne "$Rootdir" ) {
        print "$WARNSTR Root home directory $roothome, not $Rootdir\n";
        push(@CHECKARR, "\n$WARNSTR Root home directory $roothome, not $Rootdir\n");
        $warnings++;
    }
    else {
        print "$PASSSTR Root home directory correct ($Rootdir)\n";
    }

    if ( !stat $Rootdir || !-d $Rootdir ) {
        print "$WARNSTR $Rootdir directory not valid\n";
        push(@CHECKARR, "\n$WARNSTR $Rootdir directory not valid\n");
        $warnings++;
    }

    $file_perms = ( stat $roothome )[2] & 0777;
    $oct_perms = sprintf "%lo", $file_perms;
    if ( $oct_perms != "700" ) {
        print
          "$WARNSTR Root home directory permissions not 700 ($oct_perms)\n";
        push(@CHECKARR,
          "\n$WARNSTR Root home directory permissions not 700 ($oct_perms)\n");
        $warnings++;
    }
    else {
        print
          "$PASSSTR Root home directory permissions correct ($oct_perms)\n";
    }

    my $rho = "$roothome/.rhosts";
    if ( -s "$rho" && -T "$rho" ) {
        print "\n$WARNSTR File $rho exists\n";
        my @rhosts = `cat $rho`;
        print @rhosts;
        push(@CHECKARR, "\n$WARNSTR File $rho exists\n");
    }

    my $rauth = "$roothome/.ssh/authorized_keys";
    if ( -s "$rauth" && -T "$rauth" ) {
        print "\n$INFOSTR File $rauth exists\n";
        my @rauhosts = `cat $rauth`;
        print @rauhosts;
    }

    -s "$Superconf1" ? $Superconf = $Superconf1
    : -s "$Superconf2" ? $Superconf = $Superconf2
    : -s "$Superconf3" ? $Superconf = $Superconf3
    : $Superconf = "";

    if ( -s "$Superconf" && -T "$Superconf" ) {
        print "\n$INFOSTR $Superconf exists\n";
        if ( open( SCF, "nawk '! /^#/ && ! /awk/ {print}' $Superconf |" ) ) {
            while (<SCF>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
        else {
            print "\n$INFOSTR Cannot open $Superconf\n";
        }
        close(SCF);
    }
    else {
        print "\n$PASSSTR Super seemingly not used for privileged access\n";
    }

    -s "$sudoconf1" ? $sudoconf = $sudoconf1
    : -s "$sudoconf2" ? $sudoconf = $sudoconf2
    : -s "$sudoconf3" ? $sudoconf = $sudoconf3
    : $sudoconf = "";

    if ( -s "$sudoconf" ) {
        print "\n$INFOSTR $sudoconf exists\n";
        if ( open( SUF, "nawk '! /^#/ && ! /awk/ {print}' $sudoconf |" ) ) {
            while (<SUF>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
        else {
            print "\n$INFOSTR Cannot open $sudoconf\n";
        }
        close(SUF);
    }
    else {
        print "\n$PASSSTR SUDO seemingly not used for privileged access\n";
    }

    if ( -s "$sulog" && -T "$sulog" ) {
        my @SUent = `egrep -i root $sulog`;
        if ("@SUent") {
            print "\n$INFOSTR Recent su(1) entries in $sulog\n";
            print @SUent;
        }
    }

    datecheck();
    print_header("*** END CHECKING PRIVILEGED ACCOUNT $datestring ***");
}

#
# Subroutine to check NTP
#
sub ntp_check {
    datecheck();
    print_header("*** BEGIN CHECKING NTP SERVICES $datestring ***");

    if ("@ntpdaemon") {
        print "$PASSSTR Network Time Protocol daemon running\n";
        if ( open( CC, "ntpq -n -c peers |" ) ) {
            while (<CC>) {
                next if ( grep( /^$/,     $_ ) );
                next if ( grep( /offset/, $_ ) );
                next if ( grep( /===/,    $_ ) );
                $_ =~ s/^\s+//g;
                (
                    $remote, $refid, $st,    $tm,     $when,
                    $poll,   $reach, $delay, $offset, $displ
                  )
                  = split( /\s+/, $_ );
                $reach  =~ s/^\s+//g;
                $remote =~ s/\*//g;
                $remote =~ s/\+//g;

                if ( $reach == 0 ) {
                    print "$ERRSTR NTP server $remote not reachable\n";
                    push(@CHECKARR, "\n$ERRSTR NTP server $remote not reachable\n");
                }
                elsif ( $reach == 377 ) {
                    print
                  "$PASSSTR NTP server $remote reachable and synchronised ";
                    print "(stratum $st, status $reach)\n";
                }
                else {
                    print
                      "$PASSSTR NTP server $remote reachable but not fully ";
                    print "synchronised (stratum $st, status $reach)\n";
                }
            }
            close(CC);

            my @NTPqas = `ntpq -c as 2>/dev/null`;
            if ( "@NTPqas" ) {
                print "\n$INFOSTR NTP associations\n";
                print @NTPqas;
            }
 
            my @NTPqrv = `ntpq -c rv 2>/dev/null`;
            if ( "@NTPqrv" ) {
                print "\n$INFOSTR NTP variables\n";
                print @NTPqrv;
            }
        }
        else {
            print "$WARNSTR Cannot run ntpq\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run ntpq\n");
        }

        if ( -s "$ntpconf" && -T "$ntpconf" ) {
            print "\n$PASSSTR $ntpconf exists\n";
            if ( open( NTPC, "nawk '! /^#/ && ! /awk/ {print}' $ntpconf |" ) )
            {
                while (<NTPC>) {
                    $_ =~ s/^\s+//g;
                    print $_;
                    if ( grep( /restrict/, $_ ) ) {
                        $NTP_REST_FLAG++;
                    }
                }
            }
            close(NTPC);

            if ( $NTP_REST_FLAG == 0 ) {
                print
"\n$WARNSTR Network Time Protocol not restricted in $ntpconf\n";
                push(@CHECKARR,
"\n$WARNSTR Network Time Protocol not restricted in $ntpconf\n");
                $warnings++;
            }
            else {
                print
"\n$PASSSTR Network Time Protocol restricted in $ntpconf\n";
            }
        }
        else {
            print "\n$ERRSTR Cannot open $ntpconf\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $ntpconf\n");
            $warnings++;
        }
    }
    else {
        print "$ERRSTR Network Time Protocol not running\n";
        push(@CHECKARR, "\n$ERRSTR Network Time Protocol not running\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING NTP SERVICES $datestring ***");
}

#
# Subroutine to check NFS
#
sub nfs_check {
    datecheck();
    print_header("*** BEGIN CHECKING SHARED FILE SYSTEMS (NFS AND ZFS) $datestring ***");

    if ( "$Minor" >= 10 ) {
        my @sharemgr = `sharemgr show -vp 2>/dev/null`;
        if ( @sharemgr != 0 ) {
            print "$INFOSTR File sharing setup\n";
            print @sharemgr;
            print "\n";
        }
    }

    if ("@nfsdaemon") {
        if ( "$MNT_FLAG" == 0 ) {
            if ( open( CC, "mount | egrep -i nfs |" ) ) {
                while (<CC>) {
                    next if ( grep( /^$/, $_ ) );
                    ( $lfs, undef, $remfs, $state, undef ) =
                      split( /\s+/, $_ );
                    $nfscount++;
                    if ( grep( /soft/, $state ) ) {
                        print
"$WARNSTR There are NFS mounts that are not soft mounted\n";
                        print "$_\n";
                        push(@CHECKARR,
"\n$WARNSTR There are NFS mounts that are not soft mounted\n");
                    }
                }
            }
            else {
                print "$WARNSTR Cannot run mount command\n";
                push(@CHECKARR, "\n$WARNSTR Cannot run mount command\n");
                $warnings++;
            }
            close(CC);
        }
    }

    if ( $nfscount > 0 ) {
        print "$WARNSTR There are NFS mounts\n";
    }
    else {
        print "$PASSSTR There are no NFS mounts\n";
    }

    my @nfsc = `nfsstat -c 2>/dev/null`;
    if ( @nfsc != 0 ) {
        print "\n$INFOSTR NFS client statistics\n";
        print @nfsc;
    }

    my @nfss = `nfsstat -s 2>/dev/null`;
    if ( @nfss != 0 ) {
        print "\n$INFOSTR NFS server statistics\n";
        print @nfss;
    }

    if ( -x "$nfsconf" && -s "$nfsconf" ) {
        print "\n$PASSSTR $nfsconf exists\n";
        if ( open( CC, "nawk '! /^#/ && ! /awk/ {print}' $nfsconf |" ) ) {
            while (<CC>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/\s+//g;
                print $_;
            }
            close(CC);
        }
        else {
            print "$WARNSTR Cannot open $nfsconf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $nfsconf\n");
        }
    }

    print "\n$NOTESTR Refer to mount_nfs regarding Hard/Soft mounts\n";

    if ( -s "$exportfs" && -T "$exportfs" ) {
        my @efs = `nawk '! /^#/ && ! /awk/ {print}' $exportfs | nawk NF`;
        if ("@efs") {
            print "\n$NOTESTR $exportfs exists\n";
            print @efs;
        }
        else {
            print "\n$NOTESTR $exportfs exists and empty\n";
        }
    }
    else {
        print "\n$NOTESTR $exportfs not set up\n";
    }

    my @DFSHARES = `dfshares 2>/dev/null`;
    if ( @DFSHARES != 0 ) {
        print "\n$INFOSTR Available resources from remote or local systems\n";
        print @DFSHARES;
    }

    if ( -s "$autom" ) {
        my @automst = `nawk '! /^#/ && ! /awk/ {print}' $autom | nawk NF`;
        if ("@automst") {
            print "\n$NOTESTR $autom exists\n";
            print @automst;
        }
        else {
            print "\n$NOTESTR $autom exists and empty\n";
        }
    }
    else {
        print "\n$NOTESTR $autom not set up\n";
    }

    my $NFSSEC = "/etc/nfssec.conf";
    my @sharesec = `nawk NF $NFSSEC 2>/dev/null`;
    if ( @sharesec != 0 ) {
        print "\n$INFOSTR Supported NFS security modes\n";
        print @sharesec;
    }

    my @DFMOUNTS = `dfmounts 2>/dev/null`;
    if ( @DFMOUNTS != 0 ) {
        print "\n$INFOSTR Mounted resource information without NFSv4 clients\n";
        print @DFMOUNTS;
    }

    my @fsmadm = `fsmadm status 2>/dev/null`;
    if ( @fsmadm != 0 ) {
        print "$INFOSTR Sun SAMFS/QFS status\n";
        print @fsmadm;
    }

    datecheck();
    print_header("*** END CHECKING SHARED FILE SYSTEMS (NFS AND ZFS) $datestring ***");
}

#
# Subroutine to check mounted file systems
#
sub CHECK_MOUNTED_FILESYSTEMS {

    if ( open( ZK, "nawk NF $initt |" ) ) {
        while (<ZK>) {
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /^#/, $_ ) );
            $_ =~ s/#.*$//g;
            $_ =~ s/^\s+//g;
            if ( grep( /vxenablef/, $_ ) ) {
                ( undef, undef, undef, $vxe ) = split( /:/, $_ );
                if ("$vxe") {
                    chomp($vxe);
                    $vxe =~ s/^\s+//g;
                    ( $vxcom, undef ) = split( /\s+/, $vxe );
                    @vxl = `$vxcom`;
                }
            }
            push( @initarr, $_ );
        }
        close(ZK);
    }
    else {
        print "$WARNSTR Cannot open $initt\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $initt\n");
        $warnings++;
    }

    if ("@initarr") {
        datecheck(); 
        print_header("*** BEGIN CHECKING INITTAB $datestring ***");

        print @initarr;

        datecheck(); 
        print_header("*** END CHECKING INITTAB $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING ALL VFSTAB FILE SYSTEMS MOUNTED AND VALID $datestring ***");

    if ( !-s "$MNTTAB" ) {
        print "$ERRSTR File $MNTTAB empty\n";
        push(@CHECKARR, "\n$ERRSTR File $MNTTAB empty\n");
        $MNT_FLAG = 1;
        $warnings++;
    }
    else {
        if ( open( MM, "mount | nawk '{print $1}' | sort |" ) ) {
            while (<MM>) {
                next if ( grep( /^$/, $_ ) );
                ( $fsreal, undef ) = split( /\s+/, $_ );
                push( @Mounted, $_ );
                push( @fss,     $fsreal );
            }
            close(MM);
        }
        else {
            print "$ERRSTR Cannot run mount command\n";
            push(@CHECKARR, "\n$ERRSTR Cannot run mount command\n");
            $warnings++;
        }
    }

    if ( open( VV, "nawk '! /awk/ && ! /^#/ {print}' $FSTAB |" ) ) {
        print "$NOTESTR $FSTAB contents\n";
        print "\n";
        while (<VV>) {
            print $_;
            next if ( grep( /^$/,  $_ ) );
            next if ( grep( /nfs/, $_ ) );
            chomp($_);

            my @KFSARR = split( /\s+/, $_ );
            if ( $#KFSARR != 6 ) {
                push(@FSWARN,
"$WARNSTR Line \"$_\" contains extra white-space seperated fields in $FSTAB (should be six)\n");
                push(@CHECKARR,
"\n$WARNSTR Line \"$_\" contains extra white-space seperated fields in $FSTAB (should be six)\n");
               $warnings++;
            }

            ( $v1, $vfsck, $v2, $v3, $passnofs, $v4, $v5 ) = split( /\s+/, $_ );

            $ORDMOUNTCNT = sprintf("%d%s", $MOUNTORDER, ordinalize($MOUNTORDER));
            if ( "$v2" ne "-" ) {
                push(@MOUNTORD, "$ORDMOUNTCNT... $v2\n");
                $MOUNTORDER++;
            }

            if ( grep( /swap/, $v3 ) ) {
                $swapdeviceno++;
                next;
            }

            push( @Fstabed, $v2 );

            if ( "$v2" eq "/tmp" ) {
                if ( grep( /tmpfs/, $v3 ) ) {
                    push(@FSWARN, "$PASSSTR File system $v2 mounted as \"tmpfs\"\n");
                }
                else {
                    push(@FSWARN, "$WARNSTR File system $v2 not mounted as \"tmpfs\"\n");
                    push(@CHECKARR, "\n$WARNSTR File system $v2 not mounted as \"tmpfs\"\n");
                    $warnings++;
                }

                if ( grep( /size=/, $v5 ) ) {
                    push(@FSWARN, "$PASSSTR File system $v2 limited through \"size=\" in $FSTAB\n");
                }
                else {
                    push(@FSWARN, "$WARNSTR File system $v2 not limited through \"size=\" in $FSTAB\n");
                    push(@CHECKARR, "\n$WARNSTR File system $v2 not limited through \"size=\" in $FSTAB\n");
                    $warnings++;
                }
            }

            if ( grep( /ufs|vxfs/, $v3 ) ) {
                if ( !grep( /$v2/, @Mounted ) ) {
                    push(@FSWARN, "$INFOSTR File system $v2 listed in $FSTAB but not mounted\n");
                    $warnings++;
                    $fswarnings++;
                }

                if ( grep( /\bro\b/, $v5 ) ) {
                    push(@FSWARN,
"$INFOSTR File system $v2 set to be mounted read-only\n");
                }

                if ( !grep( /\Q$v2\E/, @Skipnonfs ) ) {
                    if ( grep( /logging/, $v5 ) ) {
                        push(@FSWARN, "$PASSSTR File system $v2 mounted with logging\n");
                    }
                    else {
                        push(@FSWARN, "$WARNSTR File system $v2 not mounted with logging\n");
                        push(@CHECKARR, "\n$WARNSTR File system $v2 not mounted with logging\n");
                        $warnings++;
                    }
                }

                if( ! ( $passnofs =~ /^[0-9]+$/ ) ) {
                    push(@FSWARN,
"$ERRSTR File system $v2 check pass number $passnofs is not numeric\n");
                    push(@CHECKARR,
"\n$ERRSTR File system $v2 check pass number $passnofs is not numeric\n");
                    $warnings++;
                }
                else {
                    if ( "$passnofs" == 0 ) {
                        if ( grep( /\Q$v2\E/, @Skipnonfs ) ) {
                            next;
                        }
                        next if ( ( "$v2" eq "/tmp" ) && ( grep( /tmpfs/, $v3 ) ) );
                        push(@FSWARN, "$ERRSTR File system $v2 check pass number set to zero\n");
                        push(@CHECKARR, "\n$ERRSTR File system $v2 check pass number set to zero\n");
                        $warnings++;
                    }
                    else {
                        push(@FSWARN, "$PASSSTR File system $v2 check pass number not set to zero\n");
                    }
                }
            }
        }
        close(VV);
    }
    else {
        print "$ERRSTR Cannot check $FSTAB\n";
        push(@CHECKARR, "\n$ERRSTR Cannot check $FSTAB\n");
    }

    if ( $swapdeviceno < $Minswapdevno ) {
        print
"\n$WARNSTR Less than minimum recommended number of swap devices in $FSTAB (minimum $Minswapdevno)\n";
        push(@CHECKARR,
"\n$WARNSTR Less than minimum recommended number of swap devices in $FSTAB (minimum $Minswapdevno)\n");
        $warnings++;
    }
    else {
        print
"\n$PASSSTR Recommended minimum number of swap devices satisfied in $FSTAB (minimum $Minswapdevno)\n";
    }

    foreach $c (@fss) {
        if ( !grep( /$c/, @Skipnonfs ) ) {
            if ( !grep( /$c/, @Fstabed ) ) {
                push(@FSWARN, "$INFOSTR File system $c mounted but not listed in $FSTAB\n");
                $warnings++;
                $fswarnings++;
            }
        }
    }

    if ( "@FSWARN" ) {
        print @FSWARN;
    }

    if ( $fswarnings > 0 ) {
        print "\n$WARNSTR Some file systems might not be mounted correctly\n";
    }
    else {
        print "\n$PASSSTR All file systems mounted correctly\n";
    }

    print "$NOTESTR Non fstab mounts may be cluster/automount related\n";

    datecheck();
    print_header("*** END CHECKING ALL VFSTAB FILE SYSTEMS MOUNTED AND VALID $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING AUTOMOUNT $datestring ***");

    if ( "$Minor" >= 10 ) {
        my @AUARR = `svcs -H autofs`;
        if ( grep(/online|enabled/, $AUARR[0]) ) {
            $AUTO_FLAG++;
        }
    }

    if ( $AUTO_FLAG > 0 ) {
        print "$INFOSTR Automount is enabled\n";
    }
    else {
        print "$INFOSTR Automount is disabled\n";
    }

    foreach my $autocm ( @AUTOARR ) {
        if ( "$autocm" eq "/etc/auto_master" ) {
            if ( open( YA, "nawk NF $autocm 2>/dev/null | grep -v ^# | " ) ) {
                print "\n$INFOSTR Configuration file $autocm\n";
                while (<YA>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                    my @AUTOLS = split(/\s+/, $_ );

                    $AUTOLS[0] =~ s/^\s+//g;
                    $AUTOLS[0] =~ s/\s+$//g;

                    chomp($AUTOLS[1]);
                    $AUTOLS[1] =~ s/^\s+//g;
                    $AUTOLS[1] =~ s/\s+$//g;

                    if ( $AUTOLS[0] eq "/-" ) {
                        if (! grep(/\//, $AUTOLS[1] ) ) {
                            $AUTOLS[1] = "/etc/$AUTOLS[1]";
                        }
                    }

                    if ( (! grep(/:/, $AUTOLS[1])) && (! grep(/&/, $AUTOLS[1])) ) {
                        if ( grep(/\//, $AUTOLS[1] ) ) {
                            if (! grep(/\Q$AUTOLS[1]\E/, @AUTOARR) ) {
                                if (! grep(/\Q$AUTOLS[1]\E/, @AUTOEXTRA) ) {
                                    push(@AUTOEXTRA, $AUTOLS[1]);
                                }
                            }
                        }
                    }
                }
                close(YA);
            }
            else {
                print "$WARNSTR System auditing not configured\n";
                push(@CHECKARR, "\n$WARNSTR System auditing not configured\n");
            }
        }
        else {
            if ( -s "$autocm" ) {
                my @autocmarr = `egrep -v ^# $autocm | nawk NF`;
                if ( @autocmarr ) {
                    print "\n$INFOSTR Configuration file $autocm\n";
                    print @autocmarr;
                }
            }
            else {
                print "\n$INFOSTR Configuration file $autocm empty or does not exist\n";
            }
        }
    }
    
    foreach my $autocm2 ( @AUTOEXTRA ) {
        if ( -s "$autocm2" ) {
            my @autocmarr2 = `egrep -v ^# $autocm2 | nawk NF`;
            if ( @autocmarr2 ) {
                print "\n$INFOSTR Configuration file $autocm2\n";
                print @autocmarr2;
            }
        }
        else {
            print "\n$INFOSTR Configuration file $autocm2 empty or does not exist\n";
        }
    }

    datecheck();
    print_header("*** END CHECKING AUTOMOUNT $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING VXFS $datestring ***");

    if ( open( KK, "vxlicense -p |" ) ) {
        while (<KK>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
        }
        close(KK);
    }
    else {
        print "$INFOSTR Cannot run vxlicense\n";
    }

    datecheck();
    print_header("*** END CHECKING VXFS $datestring ***");
}

#
# Is /dev/null a special device?
#
sub checknull {
    datecheck();
    print_header("*** BEGIN CHECKING DEVICE FILES $datestring ***");

    my $DEVDIR = "/dev";
    my @Devarray = `ls -alL $DEVDIR`;

    if ( "@Devarray" ) {
        print "$INFOSTR Device tree in $DEVDIR\n";
        print @Devarray;
    }
    else {
        print "$WARNSTR Device tree in $DEVDIR seemingly empty\n";
        push(@CHECKARR, "\n$WARNSTR Device tree in $DEVDIR seemingly empty\n");
        $warnings++;
    }

    if ( -c "/dev/null" ) {
        print "\n$PASSSTR /dev/null is character device file\n";
    }
    else {
        print "\n$ERRSTR /dev/null is not character device file\n";
        push(@CHECKARR, "\n$ERRSTR /dev/null is not character device file\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING DEVICE FILES $datestring ***");
}

#
# Subroutine to check kernel parameters
#
sub checkkernel {
    datecheck();
    print_header("*** BEGIN CHECKING KERNEL MODULES $datestring ***");

    if ( open( KCM, "modinfo |" ) ) {
        while (<KCM>) {
            push( @kcmod, $_ );
            if ( grep( /\bbge\b/, $_ ) ) {
                @bge_driver = split( /\s+/, $_ );
                my $bge_drive_version = $bge_driver[$#bge_driver];
                $bge_drive_version =~ s/\)$//g;
                $bge_drive_version =~ s/^v//g;
                chomp($bge_drive_version);
                ( $bge_dr_maj, $bge_dr_min ) =
                  split( /\./, $bge_drive_version );
            }
        }
        close(KCM);
    }

    if ("@kcmod") {
        print @kcmod;
    }
    else {
        print "$WARNSTR Kernel modules cannot be listed\n";
        push(@CHECKARR, "\n$WARNSTR Kernel modules cannot be listed\n");
    }

    my @KSTATARR = `kstat -p -T d 2>/dev/null`;
    if ( @KSTATARR ) {
        print "\n$INFOSTR Kstat summary in parseable format\n";
        print @KSTATARR;
    }

    datecheck();
    print_header("*** END CHECKING KERNEL MODULES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING KERNEL DRIVER CONFIGS $datestring ***");

    my @kernconf = `ls /kernel/drv/*.conf 2>/dev/null`;
    foreach my $kercm ( @kernconf ) {
        chomp($kercm);
        if ( -s $kercm && -T $kercm ) {
            my @kernarr = `nawk NF $kercm`;
            if ( @kernarr ) {
                print "$INFOSTR Configuration file $kercm\n";
                print @kernarr;
                print "\n";
            }
        }
    }

    datecheck();
    print_header("*** END CHECKING KERNEL DRIVER CONFIGS $datestring ***");
}

#
# Subroutine to check various daemons
#
sub basic_daemons {
    datecheck();
    print_header("*** BEGIN CHECKING CRITICAL DAEMONS $datestring ***");

    if ( grep( /VxVM/, "$Diskmgr" ) ) {
        push( @Dmust, "vxconfigd", "vxfsd", "vxiod", "vxnotify" );
    }

    foreach my $x (@Nott) {
        my $ckd = grep( /\b$x\b/i, @allprocesses );
        if ("$ckd") {
            print "$WARNSTR Daemon $x running (recommendation is to ";
            print "disable it)\n";
            push(@CHECKARR, "\n$WARNSTR Daemon $x running\n");
            $warnings++;
        }
        else {
            print "$PASSSTR Daemon $x not running\n";
        }
    }

    foreach $a (@Dmust) {
        my @cky = grep( /$a/, @allprocesses );
        if ("@cky") {
            print "$PASSSTR Daemon $a running\n";
            if ( "$a" eq "syslogd" ) {
                if ( -s "$ssd" ) {
                    open( LSYSD, "nawk '! /^#/ && ! /awk/ {print}' $ssd |" )
                      || warn "$WARNSTR Cannot open $ssd\n";
                    while (<LSYSD>) {
                        next if ( grep( /^$/, $_ ) );
                        if ( grep( /^LOG_FROM_REMOTE/, $_ ) ) {
                            ( undef, $Lsys ) = split( /=/, $_ );
                            $Lsys =~ s/^\s+//g;
                            chomp($Lsys);
                            if ( "$Lsys" eq "NO" ) {
                                print "$PASSSTR Daemon flag for $a set up ";
                                print
"correctly in $ssd (LOG_FROM_REMOTE=$Lsys)\n";
                                $Secure_SYSLOGD = 1;
                            }
                            else {
                                print
                                  "$WARNSTR Daemon flag for $a not set up ";
                                print
"correctly in $ssd (LOG_FROM_REMOTE=$Lsys)\n";
                                push(@CHECKARR,
                                  "\n$WARNSTR Daemon flag for $a not set up ");
                                push(@CHECKARR,
"correctly in $ssd (LOG_FROM_REMOTE=$Lsys)\n");
                                $warnings++;
                            }
                        }
                    }
                    close(LSYSD);
                }
                else {
                    print "$WARNSTR Configuration file missing ($ssd)\n";
                    push(@CHECKARR, "\n$WARNSTR Configuration file missing ($ssd)\n");
                }

                if ( grep( /\-T/, @cky ) ) {
                    print
"$PASSSTR Daemon $a running without remote connections ";
                    print "(flag -T)\n";
                    $warnings++;
                }
                else {
                    print
"$INFOSTR Daemon $a might be allowing remote connections ";
                    print "(flag -T missing)\n";
                }
            }
            elsif ( "$a" eq "auditd" ) {
                if ( -s "$BSMconf" ) {
                    print
"$INFOSTR Basic Security Module (BSM) startup script $BSMconf\n";
                    my @BSM1 =
                      `nawk '! /^#/ && ! /awk/ {print}' $BSMconf | nawk NF`;
                    print @BSM1;
                }

                if ( -s "$BSMevent" ) {
                    print
"\n$INFOSTR Basic Security Module (BSM) events $BSMevent\n";
                    my @BSM2 =
                      `nawk '! /^#/ && ! /awk/ {print}' $BSMevent | nawk NF`;
                    print @BSM2;
                }

                if ( -s "$BSMclass" ) {
                    print
"\n$INFOSTR Basic Security Module (BSM) classes $BSMclass\n";
                    my @BSM3 =
                      `nawk '! /^#/ && ! /awk/ {print}' $BSMclass | nawk NF`;
                    print @BSM3;
                }
            }
            elsif ( "$a" eq "inetd" ) {
                if ( -s "$inetdd" ) {
                    if ( open( FROM, "nawk '! /^#/ && ! /awk/ {print}' $inetdd |") ) {
                        while (<FROM>) {
                            next if ( grep( /^$/, $_ ) );
                            if ( grep( /^ENABLE_CONNECTION_LOGGING/, $_ ) ) {
                                ( undef, $conflag ) = split( /=/, $_ );
                                $conflag =~ s/^\s+//g;
                                if ( "$conflag" eq "YES" ) {
                                    print
"$PASSSTR Daemon flag for $a set up correctly ";
                                    print
                              "in $inetdd (ENABLE_CONNECTION_LOGGING=YES)\n";
                                }
                                else {
                                    print "$WARNSTR Daemon flag for $a not set up ";
                                    print
"correctly in $inetdd (ENABLE_CONNECTION_LOGGING=NO)\n";
                                    push(@CHECKARR, "\n$WARNSTR Daemon flag for $a not set up ");
                                    push(@CHECKARR,
"correctly in $inetdd (ENABLE_CONNECTION_LOGGING=NO)\n");
                                    $warnings++;
                                }

                                if ( grep( /^ENABLE_TCPWRAPPERS/, $_ ) ) {
                                    ( undef, $tcpflag ) = split( /=/, $_ );
                                    $tcpflag =~ s/^\s+//g;
                                    if ( "$tcpflag" eq "YES" ) {
                                        print
"$PASSSTR Daemon flag for $a set up correctly ";
                                        print "in $inetdd (ENABLE_TCPWRAPPERS=YES)\n";
                                    }
                                    else {
                                        print "$WARNSTR Daemon flag for $a not set up ";
                                        print
"correctly in $inetdd (ENABLE_TCPWRAPPERS=NO)\n";
                                        push(@CHECKARR, "\n$WARNSTR Daemon flag for $a not set up ");
                                        push(@CHECKARR,
"correctly in $inetdd (ENABLE_TCPWRAPPERS=NO)\n");
                                        $warnings++;
                                    }
                                }
                            }
                        }
                    }
                    else {
                        print "\n$WARNSTR Cannot open $inetdd\n";
                        push(@CHECKARR, "\n$WARNSTR Cannot open $inetdd\n");
                        $warnings++;
                    }
                    close(FROM);
                
                    if ( !"$conflag" ) {
                        print "$WARNSTR Daemon flag for $a not set up ";
                        print "correctly in $inetdd (ENABLE_TCPWRAPPERS=NO)\n";
                        push(@CHECKARR, "\n$WARNSTR Daemon flag for $a not set up ");
                        push(@CHECKARR, "correctly in $inetdd (ENABLE_TCPWRAPPERS=NO)\n");
                        $warnings++;
                    }

                    if ( !"$tcpflag" ) {
                        print "$WARNSTR Daemon flag for $a not set up ";
                        print
                      "correctly in $inetdd (ENABLE_CONNECTION_LOGGING=NO)\n";
                        push(@CHECKARR, "\n$WARNSTR Daemon flag for $a not set up ");
                        push(@CHECKARR,
                      "correctly in $inetdd (ENABLE_CONNECTION_LOGGING=NO)\n");
                        $warnings++;
                    }
                }

                if ( grep( /\-t/, @cky ) ) {
                    print "$PASSSTR Daemon $a running with logging ";
                    print "(flag -t)\n";
                }
                else {
                    print "$WARNSTR Daemon $a not running with logging ";
                    print "(flag -t missing)\n";
                    push(@CHECKARR, "\n$WARNSTR Daemon $a not running with logging ");
                    push(@CHECKARR, "(flag \"-t\" missing)\n");
                    $warnings++;
                }
            }
        }
        else {
            print "$WARNSTR Daemon $a not running\n";
            $warnings++;
        }
    }

    datecheck();
    print_header("*** END CHECKING CRITICAL DAEMONS $datestring ***");
}

#
# Subroutine to check root's crontab
#
sub ROOT_CRON {
    datecheck();
    print_header("*** BEGIN CHECKING ROOT CRON TASKS $datestring ***");

    my @CRarr = `crontab -l | nawk '! /^#/ && ! /nawk/ {print}'`;
    if ("@CRarr") {
        print "$PASSSTR Crontab for root exists\n";
        print @CRarr;
        if ( -s "$CRFILE" ) {
            print "\n$INFOSTR Crontab file $CRFILE exists\n";
        }
        else {
            print "\n$INFOSTR Crontab file $CRFILE does not exist\n";
        }
    }
    else {
        print "$INFOSTR Crontab for root does not exist\n";
    }

    print
      "\n$INFOSTR In Australia, Daylight Savings Time normally changes ";
    print "at 0200 and 0300 hours respectively\n";
    print
"$INFOSTR Change variables \$DSTbegin and \$DSTend for other regions\n";

    foreach my $cronjob (@CRarr) {
        ( undef, $hourrun, undef ) = split( /\s+/, $cronjob );

        if ( $hourrun eq "*" ) {
            print
"\n$INFOSTR Following task might be affected by Daylight Savings Time changes\n";
            print $cronjob;
        }

        if ( grep( /,/, $hourrun ) ) {
            @hourarr = split( /,/, $hourrun );
            foreach my $finhour (@hourarr) {
                if (   ( int($finhour) == $DSTbegin )
                    || ( int($finhour) == $DSTend ) )
                {
                    print
"\n$INFOSTR Following task might be affected by Daylight Savings Time changes\n";
                    print $cronjob;
                }
            }
        }

        if ( grep( /-/, $hourrun ) ) {
            ( $fromhour, $tohour ) = split( /-/, $hourrun );
            if (   ( int($fromhour) <= $DSTbegin )
                && ( int($tohour) >= $DSTend ) )
            {
                print
"\n$INFOSTR Following task might be affected by Daylight Savings Time changes\n";
                print $cronjob;
            }
        }
    }

    datecheck();
    print_header("*** END CHECKING ROOT CRON TASKS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING NON-ROOT CRON TASKS $datestring ***");

    @nonrootcron = `ls $CRDIR/* | grep -v root 2>/dev/null`;
    my $nonroot = q{};

    if ( "@nonrootcron" ) {
        foreach $nonroot (@nonrootcron) {
            chomp($nonroot);
            my @nrcron = `cat $nonroot`;
            if ( "@nrcron" ) {
                print "$INFOSTR Cron tasks for $nonroot\n";
                print @nrcron;
                print "\n";
            }
        }
    }
    else {
        print "$INFOSTR Cron tasks for non-root accounts not defined\n";
    }

    datecheck();
    print_header("*** END CHECKING NON-ROOT CRON TASKS $datestring ***");
}

#
# Subroutine to check cron ACLs
#
sub cron_access {
    datecheck();
    print_header("*** BEGIN CHECKING CRON ACCESS LIST $datestring ***");

    if ( open( CD, "cat $CRON_DENY 2>/dev/null |" ) ) {
        my $crond = 0;
        print "$INFOSTR $CRON_DENY:\n";
        while (<CD>) {
            print $_;
            $crond++;
        }
        close(CD);
        
        if ( $crond == 0 ) {
            print "$INFOSTR No entries in $CRON_DENY\n";
        }
    }
    else {
        print "$ERRSTR Cannot open $CRON_DENY\n";
        push(@CHECKARR, "\n$ERRSTR Cannot open $CRON_DENY\n");
        $warnings++;
    }

    if ( open( CA, "cat $CRON_ALLOW 2>/dev/null |" ) ) {
        my $crona = 0;
        print "\n$INFOSTR $CRON_ALLOW:\n";
        while (<CA>) {
            print $_;
            $crona++;
        }
        close(CA);
        
        if ( $crona == 0 ) {
            print "$INFOSTR No entries in $CRON_ALLOW\n";
        }
    }
    else {
        print "\n$ERRSTR Cannot open $CRON_ALLOW\n";
        push(@CHECKARR, "\n$ERRSTR Cannot open $CRON_ALLOW\n");
        $warnings++;
    }

    if ( open( AD, "cat $AT_DENY 2>/dev/null |" ) ) {
        my $atd = 0;
        print "\n$INFOSTR $AT_DENY:\n";
        while (<AD>) {
            print $_;
            $atd++;
        }
        close(AD);

        if ( $atd == 0 ) {
            print "$INFOSTR No entries in $AT_DENY\n";
        }

    }
    else {
        print "\n$ERRSTR Cannot open $AT_DENY\n";
        push(@CHECKARR, "\n$ERRSTR Cannot open $AT_DENY\n");
        $warnings++;
    }

    if ( open( AA, "cat $AT_ALLOW 2>/dev/null |" ) ) {
        my $ata = 0;
        print "\n$INFOSTR $AT_ALLOW:\n";
        while (<AA>) {
            print $_;
            $ata++;
        }
        close(AA);

        if ( $ata == 0 ) {
            print "$INFOSTR No entries in $AT_ALLOW\n";
        }
    }
    else {
        print "\n$ERRSTR Cannot open $AT_ALLOW\n";
        push(@CHECKARR, "\n$ERRSTR Cannot open $AT_ALLOW\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING CRON ACCESS LIST $datestring ***");
}

#
# Subroutine to check scan
#
sub SCAN_HW {
    datecheck();
    print_header("*** BEGIN CHECKING DEVICES $datestring ***");

    my $prdefdg = "/usr/platform/$Model/sbin/prtdiag";
    if ( ! -x $prdefdg ) {
        $prdefdg = "/usr/sbin/prtdiag";
    }

    if ( open( IS, "$prdefdg -v |" ) ) {
        while (<IS>) {
            if ( grep( /failed/, $_ ) ) {
                push( @unc, $_ );
            }
            push( @Alldevs, $_ );
        }
        close(IS);

        if ("@Alldevs") {
            print @Alldevs;
        }
        else {
            print "$ERRSTR Prtdiag scan failed\n";
            push(@CHECKARR, "\n$ERRSTR Prtdiag scan failed\n");
            $warnings++;
        }

        if ("@unc") {
            print "$ERRSTR Hardware scan found FAILED devices\n";
            print @unc;
            push(@CHECKARR, "\n$ERRSTR Hardware scan found FAILED devices\n");
            push(@CHECKARR, @unc);
            $warnings++;
        }
    }
    else {
        print "$ERRSTR Cannot run prtdiag\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run prtdiag\n");
    }

    datecheck();
    print_header("*** END CHECKING DEVICES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING IOSTAT AND DEVICE RESERVATIONS $datestring ***");

    if ( open( IOEN, "iostat -En |" ) ) {
        while (<IOEN>) {
            if ( grep(/^rmt\//, $_ ) ) {
                push(@tapes, $_);
            }
            print $_;
        }
        close(IOEN);
    }
    else {
        print "\n$WARNSTR Iostat failed\n";
        push(@CHECKARR, "\n$WARNSTR Iostat failed\n");
        $warnings++;
    }

    if ( "$Minor" >= 10 ) {
        my @devreserv = `devreserv`;

        if ( "@devreserv" ) {
            print "\n$INFOSTR Currently reserved devices\n";
            print @devreserv;
        }
    }

    my @LSHAL = `lshal 2>/dev/null`;

    if ("@LSHAL") {
        print "\n$INFOSTR HAL device status\n";
        print @LSHAL;
    }

    my @BIOSDEV = `lshal 2>/dev/null`;

    if ("@BIOSDEV") {
        print "\n$INFOSTR BIOS device status\n";
        print @BIOSDEV;
    }

    my @SMBIOS = `smbios 2>/dev/null`;

    if ("@SMBIOS") {
        print "\n$INFOSTR System Management BIOS image\n";
        print @SMBIOS;
    }

    my @rmformat = `rmformat -l 2>/dev/null`;

    if ("@rmformat") {
        print "\n$INFOSTR Removable rewritable media status\n";
        print @rmformat;
    }

    datecheck();
    print_header("*** END CHECKING IOSTAT AND DEVICE RESERVATIONS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING PLATFORM INFORMATION AND CONTROL LIBRARY $datestring ***");

    if ( open( PICL, "prtpicl -v |" ) ) {
        while (<PICL>) {
            print $_;
        }
        close(PICL);
    }
    else {
        print "$ERRSTR Prtpicl scan failed\n";
        push(@CHECKARR, "\n$ERRSTR Prtpicl scan failed\n");
        $warnings++;
    }

    if ("@Prtarr") {
        print "\n$INFOSTR System configuration prtconf\n";
        print @Prtarr;
    }

    my @SYSDEF = `sysdef 2>/dev/null`;
    if ("@SYSDEF") {
        print "\n$INFOSTR System definition sysdef\n";
        print @SYSDEF;
    }

    my @GETDEVPOL = `getdevpolicy 2>/dev/null`;
    if ("@GETDEVPOL") {
        print "\n$INFOSTR System device policy\n";
        print @GETDEVPOL;
    }

    my @hrdconfl = `hrdconf -l 2>/dev/null`;
    if ("@hrdconfl") {
        print "\n$INFOSTR Fujitsu native command for SPARC servers\n";
        print @hrdconfl;
    }

    if ( "$Minor" >= 10 ) {
        my @fwflash = `fwflash -l 2>/dev/null | egrep -v "List of available"`;

        if ("@fwflash") {
            print "\n$INFOSTR Firmware query\n";
            print @fwflash;
        }
    }

    datecheck();
    print_header("*** END CHECKING PLATFORM INFORMATION AND CONTROL LIBRARY $datestring ***");
}

#
# Subroutine to check basic performance
#
sub PERFORMANCE_BASICS {
    my @Priolist = `priocntl -l 2>/dev/null | nawk NF`;

    if ("@Priolist") {
        datecheck();
        print_header("*** BEGIN CHECKING SCHEDULING PARAMETERS $datestring ***");

        print @Priolist;

        datecheck();
        print_header("*** END CHECKING SCHEDULING PARAMETERS $datestring ***");
    }

    my @lgrpinfo = `lgrpinfo -Ta 2>/dev/null`;

    if ("@lgrpinfo") {
        datecheck();
        print_header("*** BEGIN CHECKING LOCALITY GROUPS $datestring ***");

        print @lgrpinfo;

        datecheck();
        print_header("*** END CHECKING LOCALITY GROUPS $datestring ***");
    }

    my @rcapstat = `rcapstat -g 2>/dev/null`;

    if ("@rcapstat") {
        datecheck();
        print_header("*** BEGIN CHECKING RESOURCE CAP ENFORCEMENT STATISTICS $datestring ***");

        print @rcapstat;

        datecheck();
        print_header("*** END CHECKING RESOURCE CAP ENFORCEMENT STATISTICS $datestring ***");
    }

    my @rctladm = `rctladm -l 2>/dev/null`;

    if ("@rctladm") {
        datecheck();
        print_header("*** BEGIN CHECKING GLOBAL STATE OF SYSTEM RESOURCE CONTROLS $datestring ***");

        print @rctladm;

        datecheck();
        print_header("*** END CHECKING GLOBAL STATE OF SYSTEM RESOURCE CONTROLS $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING BASIC PERFORMANCE $datestring ***");

    $USED = int( ( ( $tswap - $tswapUSED ) / $tswap ) * 100 );
    chomp($USED);
    $FREESPACE = 100 - $USED;
    if ( "$FREESPACE" < "$SWAP_THRESHOLD" ) {
        print
"$WARNSTR Swap free below $SWAP_THRESHOLD% (current usage $USED%)\n";
        push(@CHECKARR,
"\n$WARNSTR Swap free below $SWAP_THRESHOLD% (current usage $USED%)\n");
        $warnings++;
    }
    else {
        print
"$PASSSTR Swap free over $SWAP_THRESHOLD% (current usage $USED%)\n";
    }

    my @LOCKSTAT = `lockstat sleep 10 2>/dev/null`;
    if ( "@LOCKSTAT" ) {
        print "\n$INFOSTR Kernel lock and profiling statistics\n";
        print @LOCKSTAT;
    }

    my @DISPADM = `dispadmin -l 2>/dev/null | nawk NF`;
    if ( "@DISPADM" ) {
        print "\n$INFOSTR Process scheduler\n";
        print @DISPADM;
    }

    my @RCTLADM = `rctladm -l 2>/dev/null | nawk NF`;
    if ( "@RCTLADM" ) {
        print "\n$INFOSTR Global state of system resource controls\n";
        print @RCTLADM;
    }

    my @VMSTATS = `vmstat -s 2>/dev/null`;
    if ( "@VMSTATS" ) {
        print "\n$INFOSTR Virtual memory counters\n";
        print @VMSTATS;
    }

    my @VMSTAT = `vmstat $DELAY $ITERATIONS 2>/dev/null`;
    if ( "@VMSTAT" ) {
        print "\n$INFOSTR Virtual memory statistics\n";
        print "$NOTESTR If runqueue \"r\" number exceeds the number of CPUs on
           server (or available threads on multi-threaded CPUs), CPU bottleneck
           might exist\n";
        print "$NOTESTR Number of blocked \"b\" processes/threads sleeping
           (usually waiting for I/O)\n";
        print "$NOTESTR Page In \"pi\" occurs when server is experiencing RAM shortage\n";
        print @VMSTAT;

        my @IDLEVALS = split( /\s+/, $VMSTAT[$#VMSTAT] );
        my $IDLE = $IDLEVALS[$#IDLEVALS];
        chomp($IDLE);

        if ( "$IDLE" < "$CPU_IDLE_THRESHOLD" ) {
            print
"\n$WARNSTR CPU idle below $CPU_IDLE_THRESHOLD% (current idle $IDLE%)\n";
            push(@CHECKARR,
"\n$WARNSTR CPU idle below $CPU_IDLE_THRESHOLD% (current idle $IDLE%)\n");
            $warnings++;
        }
        else {
            print
"\n$PASSSTR CPU idle over $CPU_IDLE_THRESHOLD% (current idle $IDLE%)\n";
        }
    }

    my @Kstatlist = `kstat 2>/dev/null`;

    if ("@Kstatlist") {
        print "\n$INFOSTR Kstat report\n";
        print @Kstatlist;
    }

    if ( "$Minor" >= 9 ) {
        my @memstat = `echo "::memstat" | mdb -k`;

        if ("@memstat") {
            print "\n$INFOSTR Kstat report\n";
            print @memstat;
        }
    }

    my @SARD = `sar -d $DELAY $ITERATIONS 2>/dev/null`;
    if ( "@SARD" ) {
        print "\n$INFOSTR Disk activity\n";
        print @SARD;
    }

    my @MPSTAT = `mpstat $DELAY $ITERATIONS 2>/dev/null`;
    if ( "@MPSTAT" ) {
        print "\n$INFOSTR Mpstat processor statistics\n";
        print "$NOTESTR Important columns to be analysed if values in them are significantly
           large over period of time:\n";
        print "$NOTESTR Monor Faults \"minf\" - when memory subsystem doesn't
           find a mapping in the hash page table, but knows that
           a page with the same content is on the list of free pages\n";
        print "$NOTESTR Major Faults \"mjf\" - when there is no mapping to a
           physical page in the hash page table and the content of the page was 
           migrated to swap space\n";
        print "$NOTESTR Interrupts \"intr\" - preempts the current work on the
           processor and forces it to execute the code needed to handle the interrupt\n";  
        print "$NOTESTR Context Switches \"csw\" - currently running thread
           doesn't have anything to compute on the processor (example: due to I/O waits)\n";
        print "$NOTESTR Involuntary Context Switches \"icsw\" - when processor
           consumed its time slice or higher priority process is ready for execution,
           involuntary context switch occurs (forces the process off the CPU)\n";
        print "$NOTESTR Migrations \"migr\" - thread migrations when a process
           is scheduled on a different processor than last time it ran\n";
        print "$NOTESTR Spins on Mutexes \"smtx\" - code flow on the processor
           not able to gather a mutex lock\n";
        print "$NOTESTR \"sys\" constantly higher that \"usr\"\n"; 
        print @MPSTAT;
    }

    my $iostatflag = q{};
    if ( "$Minor" >= 10 ) {
        $iostatflag = "CTdrzY";
    }

    my @iostatY = `iostat -xcn${iostatflag} $DELAY $ITERATIONS 2>/dev/null`;
    if ( "@iostatY" ) {
        print "\n$INFOSTR Iostat summary\n";
        print "$NOTESTR If a disk shows consistently high reads/writes along
           with: the percentage busy \"%b\" of the disks is greater than 5-10%, and
           the average service time \"asvc_t\" is greater than around 20-30ms,
           thorough checks are recommended\n"; 
        print @iostatY;
    }

    my @TRAPSTAT = `trapstat $DELAY $ITERATIONS 2>/dev/null`;

    if ("@TRAPSTAT") {
        print "\n$INFOSTR Trap statistics\n";
        print @TRAPSTAT;
    }

    my @TRAPSTATT = `trapstat -t $DELAY $ITERATIONS 2>/dev/null `;

    if ("@TRAPSTATT") {
        print
"\n$INFOSTR Trap statistics with translation lookaside buffer (TLB)\n";
        print @TRAPSTATT;
    }

    if ( "@vxdctl0" ) {
        my @vxmemstat = `vxmemstat 2>/dev/null`;
        if ( "@vxmemstat" ) {
            print "\n$INFOSTR VxVM memory status\n";
            print @vxmemstat;
        }
    }

    my @TOPLOAD = `ps -elf | sort -nr | head -25 2>/dev/null`;

    if ("@TOPLOAD") {
        print "\n$INFOSTR Top load processes\n";
        print @TOPLOAD;
    }

    my @TOPMEM = `prstat -S rss -c 1 1 2>/dev/null | head -25` ;

    if ("@TOPMEM") {
        print "\n$INFOSTR Top memory-consuming processes\n";
        print @TOPMEM;
    }

    my @TOPCPU = `prstat -S cpu -c 1 1 2>/dev/null | head -25`;

    if ("@TOPCPU") {
        print "\n$INFOSTR Top CPU-consuming processes\n";
        print @TOPCPU;
    }

    my @TOPPRI = `prstat -S pri -c 1 1 2>/dev/null | head -25`;

    if ("@TOPPRI") {
        print "\n$INFOSTR Top priority-consuming processes\n";
        print @TOPPRI;
    }

    datecheck();
    print_header("*** END CHECKING BASIC PERFORMANCE $datestring ***");

    my @psrset = `psrset`;
    if ("@psrset") {
        datecheck();
        print_header("*** BEGIN CHECKING STATUS OF PROCESSOR SETS $datestring ***");

        print @psrset;

        datecheck();
        print_header("*** END CHECKING STATUS OF PROCESSOR SETS $datestring ***");
    }
}

#
# Subroutine to check syslog
#
sub SYSLOG_LOGGING {
    datecheck();
    print_header("*** BEGIN CHECKING SYSLOG OPERATIONAL $datestring ***");

    my $DDate       = rand();
    my $LOGSTR      = "AUTOMATED TEST MESSAGE $DDate FOR OAT. PLEASE IGNORE";
    print "$INFOSTR Expected logging in $SYSLOG\n";

    my $RSYSLOG = q{};

    if ( -s "$syslog_conf" ) {
        if ( open( SYSD, "egrep -v ^# $syslog_conf |" ) ) {
            print "\n$INFOSTR File $syslog_conf\n";
            while (<SYSD>) {
                next if ( grep( /^$/, $_ ) );

                ($s) = /^([^#]\S+\s+)/ and
                $s =~ s/ /<SPACE>/g and
                do { $s =~ s/\t/<TAB>/g ;
                    if ( ! grep(/ifdef|LOGHOST/i, $s) ) {
                        push(@CHECKARR,
"\n$ERRSTR Syslog file $syslog_conf: Line $. contains SPACES instead of TABS \"$s ...\"\n");
                        push(@WARNSLOGARR,
"$ERRSTR Syslog file $syslog_conf: Line $. contains SPACES instead of TABS \"$s ...\"\n"); 
                        $warnings++;
                    }
                };

                grep( /info/, $_ ) ? ( undef, $RSYSLOG ) =
                  split( /\s+/, $_ )
                  : grep( /debug/, $_ ) ? ( undef, $RSYSLOG ) =
                  split( /\s+/, $_ )
                  : 1;

                print $_;
            }
            close(SYSD);
        }
        else {
            print "\n$WARNSTR Cannot open $syslog_conf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $syslog_conf\n");
            $warnings++;
        }
    }

    if ( "@WARNSLOGARR" ) {
        print "\n";
        print @WARNSLOGARR;
    }
    else {
        print "\n$PASSSTR Syslog file $syslog_conf contains TABS as separator\n";
    }

    if ( "$Secure_SYSLOGD" == 1 ) {
        system("logger -p daemon.notice $LOGSTR");
    }
    else {
        #if ( eval "require Sys::Syslog" ) {
        #    import Sys::Syslog;
        #    use Sys::Syslog qw(:DEFAULT setlogsock);
        #    setlogsock("inet") || warn "\n$WARNSTR Cannot open setlogsock\n";
        #    openlog( "$SYSLOG", "ndelay,nowait", "daemon" );
        #    syslog( "notice", "$LOGSTR" );
        #    closelog();
        #}
        #else {
            system("logger -p daemon.notice $LOGSTR");
        #}
    }

    if ( -s "$RSYSLOG" ) {
        $SYSLOG = $RSYSLOG;
    }

    sleep(60);

    my $See = `egrep "$LOGSTR" $SYSLOG 2>/dev/null`;
    if ("$See") {
        print "\n$PASSSTR System logger messages successful in $SYSLOG\n";
        print "Message $LOGSTR logged\n";
    }
    else {
        print "\n$ERRSTR System logger messages failed in $SYSLOG\n";
        print "Message $LOGSTR not logged\n";
        $warnings++;
    }

    my @logfind = `nawk '/error|fail|warn|crit/ && ! /awk/ {print}' $SYSLOG`;
    if (@logfind) {
        print "\n$INFOSTR Recent syslog entries of interest\n";
        print @logfind;
    }

    my @dmesglog = `dmesg | egrep -i "error|fail|warn|crit"`;
    if (@dmesglog) {
        print "\n$INFOSTR Recent dmesg entries of interest\n";
        print @dmesglog;
    }

    if ( -s "$btmplog" ) {
        my @btmp = `cat $btmplog 2>/dev/null | nawk NF`;
        if (@btmp) {
            print "\n$INFOSTR Recent unsuccessful login attempts\n";
            print @btmp;
        }
    }
    else {
        print "\n$WARNSTR Bad login attempts not logged in $btmplog\n";
        push(@CHECKARR, "\n$WARNSTR Bad login attempts not logged in $btmplog\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING SYSLOG OPERATIONAL $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SYSTEM LOG ROTATION STATUS $datestring ***");

    if ( "$Minor" >= 8 ) {
        my @logadm = `logadm -V 2>/dev/null`;
        if ("@logadm") {
            print "\n$INFOSTR Logadm configuration status\n";
            print @logadm;
        }
    }

    datecheck();
    print_header("*** END CHECKING SYSTEM LOG ROTATION STATUS $datestring ***");
}

#
# Subroutine to check Unix password and group databases
#
sub pwdbcheck {
    datecheck();
    print_header("*** BEGIN CHECKING UNIX PASSWORD AND GROUP DATABASES $datestring ***");

    if ( -s "$pwgrdconf" ) {
        if (
            open( PWGRT,
"nawk '! /^#/ && ! /awk/ {print}' $pwgrdconf 2>/dev/null | nawk NF |"
            )
          )
        {
            print "$INFOSTR File $pwgrdconf\n";
            while (<PWGRT>) {
                next if grep( /^$/, $_ );
                next if grep( /^#/, $_ );
                print $_;
                if ( grep( /^PASSLENGTH/, $_ ) ) {
                    ( undef, $passln ) = split( /=/, $_ );
                    chomp($passln);
                }
            }
            close(PWGRT);
            if ( "$passln" < $MINPASSLENGTH ) {
                print "\n$WARNSTR Weak password length in $pwgrdconf ";
                print "($passln is below threshold $MINPASSLENGTH)\n";
                push(@CHECKARR, "\n$WARNSTR Weak password length in $pwgrdconf ");
                push(@CHECKARR, "($passln is below threshold $MINPASSLENGTH)\n");
                $warnings++;
            }
            else {
                print
"\n$PASSSTR Password length above threshold in $pwgrdconf ";
                print "($passln >= $MINPASSLENGTH)\n";
            }
        }
        else {
            print "$WARNSTR Cannot open $pwgrdconf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $pwgrdconf\n");
            $warnings++;
        }
    }
    else {
        print "$WARNSTR File $pwgrdconf missing or empty\n";
        push(@CHECKARR, "\n$WARNSTR File $pwgrdconf missing or empty\n");
        $warnings++;
    }

    if ( -s "$inetinitconf" ) {
        if (
            open( IGRT,
"nawk '! /^#/ && ! /awk/ {print}' $inetinitconf 2>/dev/null | nawk NF |"
            )
          )
        {
            print "\n$INFOSTR File $inetinitconf\n";
            while (<IGRT>) {
                next if grep( /^$/, $_ );
                next if grep( /^#/, $_ );
                print $_;
                if ( grep( /^TCP_STRONG_ISS/, $_ ) ) {
                    ( undef, $strongiss ) = split( /=/, $_ );
                    chomp($strongiss);
                }
            }
            close(IGRT);

            if ( "$strongiss" != $TCPSTRONGDEF ) {
                print
"\n$WARNSTR Weak TCP initial sequence number generation in $inetinitconf ";
                print "($strongiss is not $TCPSTRONGDEF)\n";
                push(@CHECKARR,
"\n$WARNSTR Weak TCP initial sequence number generation in $inetinitconf ");
                push(@CHECKARR, "($strongiss is not $TCPSTRONGDEF)\n");
                $warnings++;
            }
            else {
                print
"\n$PASSSTR Strong TCP initial sequence number generation in $inetinitconf ";
                print "($strongiss)\n";
            }
        }
        else {
            print "$WARNSTR Cannot open $inetinitconf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $inetinitconf\n");
            $warnings++;
        }
    }
    else {
        print "$WARNSTR File $inetinitconf missing or empty\n";
        push(@CHECKARR, "\n$WARNSTR File $inetinitconf missing or empty\n");
        $warnings++;
    }

    if ( -s "$logiconf" ) {
        if (
            open( LGRT,
"nawk '! /^#/ && ! /awk/ {print}' $logiconf 2>/dev/null | nawk NF |"
            )
          )
        {
            print "\n$INFOSTR File $logiconf\n";
            while (<LGRT>) {
                next if grep( /^$/, $_ );
                next if grep( /^#/, $_ );
                print $_;

                if ( grep( /^CONSOLE/, $_ ) ) {
                    ( undef, $conln ) = split( /=/, $_ );
                    chomp($conln);
                }

                if ( grep( /^UMASK/, $_ ) ) {
                    ( undef, $umaskln ) = split( /=/, $_ );
                    chomp($umaskln);
                }

                if ( grep( /^SYSLOG=/, $_ ) ) {
                    ( undef, $syslogln ) = split( /=/, $_ );
                    chomp($syslogln);
                }

                if ( grep( /^SYSLOG_FAILED_LOGINS/, $_ ) ) {
                    ( undef, $sfail ) = split( /=/, $_ );
                    chomp($sfail);
                }
                else {
                    $sfail = 5;
                }
            }
            close(LGRT);

            if ( "$conln" ne "/dev/console" ) {
                print
"\n$WARNSTR Remote privileged access allowed in $logiconf ";
                print "($conln not defined)\n";
                push(@CHECKARR,
"\n$WARNSTR Remote privileged access allowed in $logiconf ");
                push(@CHECKARR, "($conln not defined)\n");
                $warnings++;
            }
            else {
                print
"\n$PASSSTR Remote privileged access disabled in $logiconf\n";
            }

            if ( ! "$umaskln" ) {
                $umaskln = "022";
            }

            if ( $umaskln eq "$UMASKDEF" ) {
                print "\n$PASSSTR Umask $umaskln in $logiconf meets minimum recommendation $UMASKDEF\n";
            }
            else {
                print "\n$INFOSTR Umask $umaskln in $logiconf differs from recommended minimum requirement $UMASKDEF\n";
            }

            if ( "$syslogln" ne "YES" ) {
                print
"\n$WARNSTR Syslog logging disabled ($syslogln) in $logiconf\n";
                push(@CHECKARR,
"\n$WARNSTR Syslog logging disabled ($syslogln) in $logiconf\n");
                $warnings++;
            }
            else {
                print
"\n$PASSSTR Syslog logging enabled ($syslogln) in $logiconf\n";
            }

            if ( "$sfail" != '0' ) {
                print
"\n$WARNSTR Not all failed login attempts logged in $logiconf ($sfail not 0)\n";
                push(@CHECKARR,
"\n$WARNSTR Not all failed login attempts logged in $logiconf ($sfail not 0)\n");
                $warnings++;
            }
            else {
                print
"\n$PASSSTR All failed login attempts logged in $logiconf ($sfail is 0)\n";
            }
        }
        else {
            print "$WARNSTR Cannot open $logiconf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $logiconf\n");
            $warnings++;
        }
    }
    else {
        print "$WARNSTR File $logiconf missing or empty\n";
        push(@CHECKARR, "\n$WARNSTR File $logiconf missing or empty\n");
        $warnings++;
    }

    if ( -s "$suconf" ) {
        if (
            open( SGRT,
"nawk '! /^#/ && ! /awk/ {print}' $suconf 2>/dev/null | nawk NF |"
            )
          )
        {
            print "\n$INFOSTR File $suconf\n";
            while (<SGRT>) {
                next if grep( /^$/, $_ );
                next if grep( /^#/, $_ );
                print $_;
                if ( grep( /^SULOG/, $_ ) ) {
                    ( undef, $suln ) = split( /=/, $_ );
                    chomp($suln);
                }

                if ( grep( /^SYSLOG=/, $_ ) ) {
                    ( undef, $sulogln ) = split( /=/, $_ );
                    chomp($sulogln);
                }
            }
            close(SGRT);
            if ( -s "$suln" ) {
                print "\n$PASSSTR SU login file $suln exists\n";
            }
            else {
                print
"\n$WARNSTR SU login file $suln does not exist or empty\n";
                push(@CHECKARR,
"\n$WARNSTR SU login file $suln does not exist or empty\n");
                $warnings++;
            }

            if ( "$sulogln" ne "YES" ) {
                print
"\n$WARNSTR SU logging disabled ($sulogln) in $logiconf\n";
                push(@CHECKARR,
"\n$WARNSTR SU logging disabled ($sulogln) in $logiconf\n");
                $warnings++;
            }
            else {
                print
                  "\n$PASSSTR SU logging enabled ($sulogln) in $logiconf\n";
            }
        }
        else {
            print "$WARNSTR Cannot open $suconf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $suconf\n");
            $warnings++;
        }
    }
    else {
        print "$WARNSTR File $suconf missing or empty\n";
        push(@CHECKARR, "\n$WARNSTR File $suconf missing or empty\n");
        $warnings++;
    }

    (
        $pdev,   $pino,     $pmode, $pnlink, $puid,
        $pgid,   $prdev,    $psize, $patime, $pmtime,
        $pctime, $pblksize, $pblocks
      )
      = stat($PASSFILE);

    if ( "$pnlink" > 1 ) {
        print "\n$WARNSTR $PASSFILE has $pnlink hard links\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE has $pnlink hard links\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR $PASSFILE has one hard link only\n";
    }

    my $pfile_perms = $pmode & 0777;

    my $poct_perms  = sprintf "%lo", $pfile_perms;

    if ( "$pblocks" == 0 ) {
        print "\n$WARNSTR $PASSFILE empty\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE empty\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR $PASSFILE not empty\n";
    }

    if ( "$puid" == 0 ) {
        print "\n$PASSSTR $PASSFILE owned by UID $puid\n";
    }
    else {
        print "\n$WARNSTR $PASSFILE not owned by UID 0 ($puid)\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE not owned by UID 0\n");
        $warnings++;
    }

    if ( ( "$pgid" == 0 ) || ( "$pgid" == 3) ) {
        print "\n$PASSSTR $PASSFILE owned by GID $pgid\n";
    }
    else {
        print "\n$WARNSTR $PASSFILE not owned by GID 0 or 3 ($pgid)\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE not owned by GID 0 or 3\n");
        $warnings++;
    }

    if ( ( $poct_perms != "444" ) && ( $poct_perms != "644" ) ) {
        print 
"\n$WARNSTR $PASSFILE permissions not 644 or 444 ($poct_perms)\n";
        push(@CHECKARR, 
"\n$WARNSTR $PASSFILE permissions not 644 or 444\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR $PASSFILE permissions correct ($poct_perms)\n";
    }

    if ( -T "$PASSFILE" ) {
        print "\n$PASSSTR $PASSFILE is plain ASCII file\n";
    }
    else {
        print "\n$WARNSTR $PASSFILE not plain ASCII file\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE not plain ASCII file\n");
        $warnings++;
    }

    if ( !-s "$Shadow" ) {
        print "\n$ERRSTR Shadow password database not used\n";
        push(@CHECKARR, "\n$ERRSTR Shadow password database not used\n");
        $warnings++;
        print "\n$WARNSTR Standard password database used\n\n";
        push(@CHECKARR, "\n$WARNSTR Standard password database used (no shadow support)\n");
    }
    else {
        print "\n$PASSSTR Shadow password database used\n\n";
        if ( open( Shad, "cat $Shadow |" ) ) {
            print "$INFOSTR File $Shadow\n";
            while (<Shad>) {
                print $_;
                ($shaduser, undef) = split(/:/, $_);
                chomp($shaduser);
                if ( $shadarr{$shaduser}) {
                   push(@SHADWARN, "\n$INFOSTR Username $shaduser exists more than once in $Shadow\n");
                   push(@CHECKARR, "\n$INFOSTR Username $shaduser exists more than once in $Shadow\n");
                }
                else {
                   $shadarr{$shaduser} = 1;
                }
            }
            close(Shad);

            if ( "@SHADWARN" ) {
                print @SHADWARN;
            }
            else {
                 print "\n$PASSSTR All usernames in $Shadow are unique\n";
            }
        }
        else {
            print "$WARNSTR Cannot open $Shadow\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $Shadow\n");
            $warnings++;
        }
    }

    my @passck   = `pwck 2>&1 | nawk NF`;
    my @grpck    = `grpck 2>&1 | nawk NF`;
    my @loginsnp = `logins -p 2>&1 | nawk NF`;
    my @passexp = `passwd -sa 2>&1`;

    print "\n$INFOSTR Pwck(1) verification\n";
    if (@passck) {
        print @passck;
    }
    else {
        print "$PASSSTR Pwck clean\n\n";
    }

    print "\n$INFOSTR Grpck(1) verification\n";
    if (@grpck) {
        print @grpck;
    }
    else {
        print "$PASSSTR Grpck clean\n";
    }

    if (@passexp) {
        print "\n$INFOSTR Password expiration check\n";
        print @passexp;
    }

    if (@loginsnp) {
        print "\n$INFOSTR Logins with empty passwords\n";
        print @loginsnp;
    }
    else {
        print "\n$PASSSTR No logins with empty passwords\n";
    }

    while ( @entry = getpwent ) {
        $passno++;
        push( @Passnumarr, $entry[2] );
        if ( $entry[2] == 0 ) {
            print "\n$INFOSTR Username $entry[0] has UID 0\n";
            $uidno++;
        }

        foreach my $raccess ( @remaccarr ) {
            my $racent = "$entry[7]/$raccess";
            if ( -s "$racent" && -T "$racent" ) {
                print "\n$WARNSTR Username $entry[0] has $raccess\n";
                my @aent = `cat $racent`;
                print @aent;
                push(@CHECKARR, "\n$WARNSTR Username $entry[0] has $raccess\n");
            }
        }

        my $epmode = (stat($entry[7]))[2];

        if ( $epmode & 0020 ) {
            print "\n$WARNSTR Home directory for $entry[0] ($entry[7]) group-writable!\n";
            push(@CHECKARR, "\n$WARNSTR Home directory for $entry[0] ($entry[7]) group-writable\n");
        }

        if ( $epmode & 0002 ) {
            print "\n$WARNSTR Home directory for $entry[0] ($entry[7]) world-writable!\n";
            push(@CHECKARR, "\n$WARNSTR Home directory for $entry[0] ($entry[7]) world-writable\n");
        }

        if ( grep(/^\$/, $entry[1]) ) {
            my @passwdarr = split(/\$/, $entry[1]);
            if ( $#passwdarr eq 3 ) {
                print
"\n$INFOSTR Username $entry[0]: $PWHASHARR{$passwdarr[1]}, salt=$passwdarr[2], hashed-password-and-salt=$passwdarr[3]\n";
            } elsif ( $#passwdarr eq 4 ) {
                if ( $passwdarr[2] =~ /rounds=/ ) {
                    print
"\n$INFOSTR Username $entry[0]: $PWHASHARR{$passwdarr[1]}, $passwdarr[2], salt=$passwdarr[3], hashed-password-and-salt=$passwdarr[4]\n";
                }
                elsif ( "$passwdarr[3]" eq "" ) {
                    print
"\n$INFOSTR Username $entry[0]: $PWHASHARR{$passwdarr[1]}, salt=$passwdarr[2], hashed-password-and-salt=$passwdarr[4]\n";
               }
               else {
                    print
"\n$INFOSTR Username $entry[0]: $PWHASHARR{$passwdarr[1]}, salt=$passwdarr[2], hashed-password-and-salt=$passwdarr[4]\n";
                }
            } else {
                print "\n$INFOSTR Username $entry[0]: ";
                foreach my $passent ( @passwdarr) {
                    print "$passent ";
                }
                print "\n";
            }

            if ( length($passwdarr[$#passwdarr]) ne $PWLEN{$passwdarr[1]} ) {
                print "ERROR: Incorrect length of encrypted password string for user $entry[0] (length($passwdarr[$#passwdarr] versus $PWLEN{$passwdarr[1]})\n";
            } else {
                print "PASS: Correct length of encrypted password string for user $entry[0] ($PWLEN{$passwdarr[1]} for $PWHASHARR{$passwdarr[1]})\n";
            }
        } else {
            if ( ! grep(/!|\*|^NP$/, $entry[1]) ) {
               print "\n$entry[0]: hashing-algorithm=DES (\"__unix__\")\n";

               my $DESLEN = length($entry[1]);
               if ( $DESLEN ne $PWLEN{"__unix__"} ) {
                   print "ERROR: Incorrect length of encrypted password string for user $entry[0] ($DESLEN versus $PWLEN{\"__unix__\"})\n";
               }
               else {
                   print "PASS: Correct length of encrypted password string for user $entry[0] ($PWLEN{\"__unix__\"})\n";
               }
            }
        }

        if ( $entry[0] eq "ermclnt" ) {
            $ERMflag++;
        }

        if ( grep( /^\+/, @entry ) ) {
            $nisflag++;
        }
        push( @PassWdarr, "@entry\n" );
    }

    while ( @grentry = getgrent ) {
        push( @Grarr,    "@grentry\n" );
        push( @Grnumarr, $grentry[2] );
    }

    if ( $nisflag > 0 ) {
        print "\n$WARNSTR There are \"+:\" entries in password file\n\n";
        push(@CHECKARR, "\n$WARNSTR There are \"+:\" entries in password file\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR No \"+:\" entries in password file\n\n";
    }

    if ( $uidno > 1 ) {
        print "$WARNSTR Multiple usernames with UID 0\n\n";
        push(@CHECKARR, "\n$WARNSTR Multiple usernames with UID 0\n");
        $warnings++;
    }
    else {
        print "$PASSSTR No multiple usernames with UID 0\n\n";
    }

    if ("@PassWdarr") {
        print "$INFOSTR Entries in Unix password file\n";
        print @PassWdarr;
    }

    if ("@Grarr") {
        print "\n$INFOSTR Entries in Unix group file\n";
        print @Grarr;
    }

    if ( -f "$nologinf" ) {
        print "\n$INFOSTR File \"$nologinf\" exists\n";
        print "$NOTESTR Non-root logins are affected by the \"$nologinf\" file\n";
    }
    else {
        print "\n$INFOSTR File \"$nologinf\" does not exist\n";
    }

    datecheck();
    print_header("*** END CHECKING UNIX PASSWORD AND GROUP DATABASES $datestring ***");
}

sub CODchk {
    datecheck();
    print_header("*** BEGIN CHECKING CAPACITY ON DEMAND $datestring ***");

    my @CODlic = `showcodlicense -r -v 2>/dev/null`;
    if ("@CODlic") {
        print "$INFOSTR Capacity on Demand (COD) licensing\n";
        print @CODlic;

        my @CODusage = `showcodusage -v 2>/dev/null`;
        if ("@CODusage") {
            print "$INFOSTR Capacity on Demand (COD) usage\n";
            print @CODusage;
        }
    }
    else {
        print "$INFOSTR Capacity on Demand (COD) not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING CAPACITY ON DEMAND $datestring ***");
}

#
# Subroutine to check codewords
#
sub codewrd {
    datecheck();
    print_header("*** BEGIN CHECKING LICENSE KEYS $datestring ***");

    my @CODarr = `showcodlicense -v`;
    if ("@CODarr") {
        print "$INFOSTR Capacity on Demand (COD) license\n";
        print @CODarr;
    }

    if ( $OMNI_FLAG == 1 ) {
        if ( -s "$dpck" ) {
            my @is_cellmgr = `egrep ^$Hostname $dpck | cut -d. -f1`;
            if ("@is_cellmgr") {
                if ( -s "$dpcw" ) {
                    print "\n$INFOSTR Data Protector codewords file $dpcw exist\n";
                    my @DPCW = `cat $dpcw`;
                    print @DPCW;
                }
            }
        }
    }

    my @DPCW = `omnicc -check_licenses -detail 2>/dev/null`;
    if ( "@DPCW" ) {
        print "\n$INFOSTR Data Protector licenses\n";
        print @DPCW;
    }

    if ( (-s "$ovnnmlic" ) && ( -T "$ovnnmlic" ) ) {
        print "\n$INFOSTR network Node Manager file $ovnnmlic exists\n";
        my @NNMLIC = `cat $ovnnmlic`;
        print @NNMLIC;
    }
    else {
        print "\n$INFOSTR Network Node Manager $ovnnmlic does not exist\n";
    }

    if ("$NETBCKDIR") {
        my $NETBCKLIC2 = "$NETBCKDIR/netbackup/bin/admincmd/get_license_key";

        $ENV{'PATH'} = "$ENV{PATH}:$NETBCKDIR/netbackup/bin/admincmd";
        $ENV{'PATH'} = "$ENV{PATH}:$NETBCKDIR/netbackup/bin/goodies";

        if ( open( VV, "bpminlicense -list_keys | nawk NF |" ) ) {
            print "\n$INFOSTR NetBackup licenses\n";
            while (<VV>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(VV);
        }
        else {
            if ( open( VVC, "get_license_key -L keys |" ) ) {
                print "\n$INFOSTR NetBackup licenses\n";
                while (<VVC>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(VVC);
            }
        }
    }

    if ( -s "$Combinedlic" ) {
        print "\n$INFOSTR Combined license file $Combinedlic exist\n";
        my @ACCW = `cat $Combinedlic`;
        print @ACCW;
    }
    else {
        print
          "\n$INFOSTR Combined license file $Combinedlic does not exist\n";
    }

    if ("@fwlic") {
        print "\n$INFOSTR CheckPoint Firewall-1 licensing\n";
        print @fwlic;
    }

    my @POWERMT = `powermt check_registration 2>/dev/null`;
    if ("@POWERMT") {
        print "\n$INFOSTR PowerPath licensing\n";
        print @POWERMT;
    }

    print "\n$INFOSTR Other applications might have their license keys ";
    print "in other files\n";

    datecheck();
    print_header("*** END CHECKING LICENSE KEYS $datestring ***");
}

#
# Subroutine to check superdaemon inetd setup
#
sub inetdchk {
    datecheck();
    print_header("*** BEGIN CHECKING INTERNET SERVICES $datestring ***");

    foreach my $proftpfile (@Proftpdarray) {
        if ( -s "$proftpfile" ) {
            my @pflist = `egrep -v ^# $proftpfile | nawk NF`;
            if ( @pflist ) {
                print "\n";
                print "$INFOSTR ProFTPD configuration in $proftpfile\n";
                print @pflist;
            }
        }
    }

    foreach my $vsftpfile (@VSftpdarray) {
        if ( -s "$vsftpfile" ) {
            my @vslist = `egrep -v ^# $vsftpfile | nawk NF`;
            if ( @vslist ) {
                print "\n";
                print "$INFOSTR VsFTP configuration in $vsftpfile\n";
                print @vslist;
            }
        }
    }

    if ( -s "$INETD" ) {
        my $inetcnt = 0;
        if ( open( I, "cat $INETD |" ) ) {
            print "\n$INFOSTR Active services in $INETD\n";
            while (<I>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
                $inetcnt++;
                chomp;
                if ( grep( /^ftp/, $_ ) ) {
                    if ( !-s "$ftpacc" ) {
                        print
"$ERRSTR FTP configuration file $ftpacc missing\n";
                        $warnings++;
                    }

                    if ( !-s "$ftpusers" ) {
                        print
"$ERRSTR FTP configuration file $ftpusers missing\n";
                        $warnings++;
                    }
                    else {
                        if ( open( FTPU, "egrep -v ^# $ftpusers |" ) ) {
                            print "$INFOSTR Users in $ftpusers\n";
                            while (<FTPU>) {
                                next if ( grep( /^$/, $_ ) );
                                print $_;
                                push( @ftpDisArr, $_ );
                            }
                            close(FTPU);

                            print "\n";
                            foreach my $ftpusr (@FTPdisable) {
                                if ( grep( /\b$ftpusr\b/, @ftpDisArr ) ) {
                                    print
"$PASSSTR FTP access disabled for $ftpusr in $ftpusers\n";
                                }
                                else {
                                    print
"$ERRSTR FTP access allowed for $ftpusr in $ftpusers\n";
                                    push(@CHECKARR,
"\n$ERRSTR FTP access allowed for $ftpusr in $ftpusers\n");
                                    $warnings++;
                                }
                            }
                        }
                        else {
                            print "$ERRSTR Cannot open $ftpusers\n";
                            $warnings++;
                        }
                    }
                }
            }
        }
        close(I);

        if ( $inetcnt == 0 ) {
            print "$INFOSTR No active services in $INETD\n";
        }
    }
    else {
        print "$ERRSTR Cannot open $INETD\n";
        push(@CHECKARR, "\n$ERRSTR Cannot open $INETD\n");
        $warnings++;
    }

    if ( -s "$KINETD" ) {
        my $kinetcnt = 0;
        if ( open( KI, "cat $KINETD |" ) ) {
            print "\n$INFOSTR Configuration file $KINETD\n";
            while (<KI>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
                $kinetcnt++;
            }
        }
        close(KI);

        if ( $kinetcnt == 0 ) {
            print "$INFOSTR No active services in $KINETD\n";
        }
    }

    if ( !-f "$INETDSEC" && !-s "$INETDSEC" ) {
        print
          "\n$WARNSTR Inetd not managed through ACLs ($INETDSEC not used)\n";
        push(@CHECKARR,
          "\n$WARNSTR Inetd not managed through ACLs ($INETDSEC not used)\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR Inetd managed through ACLs ($INETDSEC used)\n";
        my $vinetcnt = 0;
        if ( open( V, "cat $INETDSEC |" ) ) {
            print "\n$INFOSTR Active services in $INETDSEC\n";
            while (<V>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
                $vinetcnt++;
            }
            close(V);
            
            if ( $vinetcnt == 0 ) {
                print "$INFOSTR No active services in $INETDSEC\n";
            }
        }
        else {
            print "$WARNSTR Cannot open $INETDSEC\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $INETDSEC\n");
        }
    }

    if ( "$Minor" >= 10 ) {
        my @inetadm = `inetadm -p 2>/dev/null`;
        if ("@inetadm") {
            print "\n$INFOSTR Inetadm configuration status\n";
            print @inetadm;
        }
    }

    if ( -s "$hostequiv" && -T "$hostequiv" ) {
        @heq = `cat $hostequiv | nawk NF 2>/dev/null`;
        if ("@heq") {
            print "\n$WARNSTR $hostequiv enabled\n";
            print @heq;
            push(@CHECKARR, "\n$WARNSTR $hostequiv enabled\n");
        }
        else {
            print "\n$PASSSTR $hostequiv disabled\n";
        }
    }
    else {
        print "\n$PASSSTR $hostequiv does not exist or is empty\n";
    }

    if ( -s "$Shells" && -T "$Shells" ) {
        my $sinetcnt = 0;
        if ( open( SHL, "cat $Shells 2>/dev/null |" ) ) {
            print "\n$INFOSTR Active Shells in $Shells\n";
            while (<SHL>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;
                $sinetcnt++;
                chomp($_);
                if ( -e $_ && -x $_ && -s $_ ) {
                    print "$PASSSTR Valid Shell $_\n";
                }
                else {
                    print "$INFOSTR Invalid Shell $_\n";
                }
            }
            close(SHL);

            if ( $sinetcnt == 0 ) {
                print "$INFOSTR No entries in $Shells\n";
            }
        }
        else {
            print "\n$INFOSTR $Shells not in use\n";
            $warnings++;
        }
    }

    datecheck();
    print_header("*** END CHECKING INTERNET SERVICES $datestring ***");

    if ( "$Minor" >= 10 ) {
        datecheck();
        print_header("*** BEGIN CHECKING SERVICE INSTANCES $datestring ***");
        if ( open( SVCS, "svcs -a |" ) ) {
            while (<SVCS>) {
                push(@svcsarr, $_);
                next if ( grep( /FMRI/, $_ ) );
                next if ( grep( /legacy_run/, $_ ) );
                if ( grep( /gdm|gdm2-login/, $_ ) ) {
                    $GDMFLAG++;
                    push(@GDMARR, $_);
                } 
                $_ =~ s/^\s+//g;
                ( undef, undef, $FMRI ) = split( /\s+/, $_ );
                my @FULLSVCNAME = split( /\//, $FMRI );
                push (@SVCARR, $FULLSVCNAME[$#FULLSVCNAME]);
            }
            close(SVCS);
        }

        if ("@svcsarr") {
            print @svcsarr;

            if ("@SVCARR") {
                foreach my $svcent (@SVCARR) {
                    my @svccheck = `svcprop $svcent 2>/dev/null`;
                    if ( @svccheck != 0 ) {
                        print "\n$INFOSTR Service $svcent configuration summary\n";
                        print "@svccheck";
                    }
                }
            }
        }
        else {
            print "$INFOSTR Empty service instance listing\n";
        }

        my @svcx = `svcs -x 2>/dev/null`;
        if ("@svcx") {
            print "\n$INFOSTR Status with explanations for service states\n";
            print @svcx;
        }

        my @SVCCFGL = `svccfg listnotify problem-diagnosed,problem-updated 2>/dev/null`;
        if ("@SVCCFGL") {
            print "\n$INFOSTR Svccfg service notification status\n";
            print @SVCCFGL;
        }

        datecheck();
        print_header("*** END CHECKING SERVICE INSTANCES $datestring ***");
    }
}

#
# Subroutine to check defined protocols and services
#
sub protchk {
    datecheck();
    print_header("*** BEGIN CHECKING DEFINED SERVICES AND PROTOCOLS $datestring ***");

    if ( -s "$SERVICES" && -T "$SERVICES" ) {
        if ( open( SE, "egrep -v ^# $SERVICES |" ) ) {
            print "$INFOSTR Active services in $SERVICES\n";
            while (<SE>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;
            }
            close(SE);
        }
        else {
            print "$ERRSTR Cannot open $SERVICES\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $SERVICES\n");
            $warnings++;
        }
    }
    else {
        print "$INFOSTR File $SERVICES missing\n";
    }

    if ( -s "$PROTOCOLS" && -T "$PROTOCOLS" ) {
        if ( open( PR, "egrep -v ^# $PROTOCOLS |" ) ) {
            print "\n$INFOSTR Active services in $PROTOCOLS\n";
            while (<PR>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;
            }
            close(PR);
        }
        else {
            print "\n$ERRSTR Cannot open $PROTOCOLS\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $PROTOCOLS\n");
            $warnings++;
        }
    }
    else {
        print "\n$INFOSTR File $PROTOCOLS missing\n";
    }

    if ( -s "$ETHERS" && -T "$ETHERS" ) {
        if ( open( ET, "egrep -v ^# $ETHERS |" ) ) {
            print "\n$INFOSTR Active hosts in $ETHERS\n";
            while (<ET>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;
            }
            close(ET);
        }
        else {
            print "\n$INFOSTR $ETHERS not in use\n";
        }
    }
    else {
        print "\n$INFOSTR File $ETHERS missing\n";
    }

    datecheck();
    print_header("*** END CHECKING DEFINED SERVICES AND PROTOCOLS $datestring ***");
}

#
# Subroutine to check SMTP setup
#
sub smtpchk {
    datecheck();
    print_header("*** BEGIN CHECKING EMAIL SERVICES $datestring ***");

    @port  = (25);

    if ( $POSTFIX_FLAG > 0 ) {
        print "\n$INFOSTR Mail Transfer Agent is seemingly Postfix\n";
        my @postcheck = `postconf -n 2>/dev/null`;
        if ( @postcheck != 0 ) {
            print "$INFOSTR Postfix configuration summary\n";
            print "@postcheck\n";
        }

        foreach my $postfixconf ( @POSTFIXARR ) {
            if ( ( -s "$postfixconf" ) && ( -T "$postfixconf" ) ) {
                $POSTFIX_FLAG++;
                print "$INFOSTR Postfix configuration file $postfixconf\n";
                my @postcat = `egrep -v ^# $postfixconf 2>/dev/null`;
                if ( @postcat != 0 ) {
                    print "@postcat\n";
                }
            }
        }

        my @postq = `mailq -n 2>/dev/null`;
        if ( @postq != 0 ) {
            print "$INFOSTR Postfix mail queue\n";
            print "@postq\n";
        }

        my @postqs = `qshape 2>/dev/null`;
        if ( @postqs != 0 ) {
            print "$INFOSTR Postfix queue shape\n";
            print "@postqs\n";
        }
    }

    if ( $EXIM_FLAG > 0 ) {
        print "\n$INFOSTR Mail Transfer Agent is seemingly Exim\n";
        my @eximcfg = `exim -bP 2>/dev/null`;
        if ( @eximcfg != 0 ) {
            print "\n$INFOSTR Exim configuration settings\n";
            print "@eximcfg\n";
        }

        my @exiwhat = `exiwhat 2>/dev/null`;
        if ( @exiwhat != 0 ) {
            print "\n$INFOSTR Exim current status\n";
            print "@exiwhat\n";
        }

        my @exiq = `exim -bp 2>/dev/null`;
           if ( @exiq != 0 ) {
               print "\n$INFOSTR Mail queue\n";
               print "@exiq\n";
        }
    }

    if ( $SENDMAIL_FLAG > 0 ) {
        print "\n$INFOSTR Mail Transfer Agent is seemingly Sendmail\n";
    }

    if ( -s "$SMTPD" && -T "$SMTPD" ) {
        if ( open( ALS, "egrep -v ^# $SMTPD |" ) ) {
            print "\n$INFOSTR $SMTPD contents\n";
            while (<ALS>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;

                if ( grep(/^DS/, $_ ) ) {
                    $RELAY = $_;
                    chomp($RELAY);
                    $RELAY =~ s/^DS//g;
                    $RELAY =~ s/DS//g;
                }

                if ( grep(/PrivacyOptions/, $_ ) ) {
                    @PRIVACY = $_;
                }
            }
            close(ALS);
        }
        else {
            print "\n$ERRSTR Cannot open $SMTPD\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $SMTPD\n");
            $warnings++;
        }
    }

    if ("@PRIVACY") {
        if (   ( grep( /noexpn/, @PRIVACY ) )
            && ( grep( /novrfy/, @PRIVACY ) ) )
        {
            print "\n$INFOSTR SMTPD privacy options defined\n";
        }
        else {
            print "\n$WARNSTR SMTPD privacy options not fully defined\n";
            push(@CHECKARR, "\n$WARNSTR Sendmail SMTP privacy options not fully defined\n");
        }
        print @PRIVACY;
    }

    if ("$RELAY") {
        $RELAY =~ s/\s+//g;
        $RELAY =~ s/\[//g;
        $RELAY =~ s/\]//g;
        print "\n$INFOSTR SMTP Smarthost defined ($RELAY)\n";
        my @machines = split( /:/, $RELAY );
        foreach $host (@machines) {
            my $PING = 0;
            ( undef, undef, undef, undef, @addrs ) = gethostbyname($host);
            foreach my $a (@addrs) {
                $HostIP = join( '.', unpack( 'C4', $a ) );
            }

            if ( !defined($HostIP) ) {
                print
"$WARNSTR Check hostname resolution for server \"$host\"\n";
            }

            # First check if the server is responding to ICMP...
            #
            $h = Net::Ping->new();
            if ( !$h->ping($host) ) {
                print "$WARNSTR $host is NOT reachable (first type ICMP)\n";
                $PING++;
            }
            else {
                print "$PASSSTR $host is reachable (first type ICMP)\n";
            }
            $h->close();

            # Second type of ping test.
            #
            $h = Net::Ping->new("icmp");
            if ( !$h->ping( $host, 2 ) ) {
                print
                  "$WARNSTR $host is NOT reachable (second type ICMP)\n";
                $PING++;
            }
            else {
                print "$PASSSTR $host is reachable (second type ICMP)\n";
            }
            $h->close();

            # Third type of ping test.
            #
            $h = Net::Ping->new( "tcp", 2 );
            while ( $stop_time > time() ) {
                print "$WARNSTR $host is NOT not reachable (TCP ping)",
                  scalar( localtime() ), "\n"
                  unless $h->ping($host);
                $PING++;
            }
            undef($h);

            # Now, check the ports.
            #
            if ( $PING < 3 ) {
                foreach my $n (@port) {
                    my $p = Net::Ping->new("tcp");
                    $Portproto = getservbyport( $n, 'tcp' );
                    $p->{port_num} = $n if $n;
                    &openport( $host, $n, 'tcp' );
                }
            }
        }
    }
    else {
        print "$ERRSTR SMTP Smart Host not defined\n";
        push(@CHECKARR, "\n$ERRSTR Sendmail SMTP smarthost not defined\n");
        $warnings++;
    }

    my @mailqcheck = `mailq | egrep "Total requests: 0"`;
    if ("@mailqcheck") {
        print "\n$PASSSTR Mail queue empty\n";
    }
    else {
        print "\n$WARNSTR Mail queue not empty\n";
        print "$INFOSTR Mail queue status\n";
        print @mailqcheck;
        push(@CHECKARR, "\n$WARNSTR Mail queue not empty\n");
    }

    my @mailstat = `mailstats 2>&1`;
    if ( grep( /No such/, @mailstat ) ) {
        print "\n$WARNSTR Email statistics not defined\n";
        print @mailstat;
        $warnings++;
        push(@CHECKARR, "\n$WARNSTR Sendmail email statistics not defined\n");
    }
    else {
        print "\n$INFOSTR Email statistics\n";
        print @mailstat;
    }

    my $alis = "/etc/mail/aliases";
    if ( open( ALI, "egrep -v ^# $alis |" ) ) {
        print "\n$INFOSTR Active email aliases in $alis\n";
        while (<ALI>) {
            next if ( grep( /^$/, $_ ) );
            $_ =~ s/^\s+//g;
            print $_;
        }
        close(ALI);
    }
    else {
        print "\n$ERRSTR Cannot open $alis\n";
        push(@CHECKARR, "\n$ERRSTR Cannot open $alis\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING EMAIL SERVICES $datestring ***");
}

#
# Subroutine to check RPC
#
sub rpcchk {
    datecheck();
    print_header("*** BEGIN CHECKING REMOTE PROCEDURE CALLS $datestring ***");

    my @rpcinfo = `rpcinfo -s 2>/dev/null`;
    if ("@rpcinfo") {
        print "$INFOSTR RPC status\n";
        print @rpcinfo;
    }
    else {
        print "$INFOSTR RPC seemingly not used\n";
    }

    datecheck();
    print_header("*** END CHECKING REMOTE PROCEDURE CALLS $datestring ***");
}

#
# Subroutine to check Solaris Fault Manager - fmd
#
sub fmdchk {
    datecheck();
    print_header("*** BEGIN CHECKING SOLARIS FAULT MANAGER STATUS $datestring ***");

    my @fmdinfo = `fmadm config 2>/dev/null`;
    if ("@fmdinfo") {
        print "$INFOSTR FMD status\n";
        print @fmdinfo;

        my @fmderr = `fmadm faulty 2>/dev/null`;
        if ("@fmderr") {
            print "\n$INFOSTR FMD fault report\n";
            print @fmderr;
        }

        my @fmdump = `fmdump -eV`;
        if ("@fmdump") {
            print "\n$INFOSTR FMD dump report\n";
            print @fmdump;
        }

        my @fmstat = `fmstat 2>/dev/null`;
        if ("@fmstat") {
            print "\n$INFOSTR FMD fault statistics\n";
            print @fmstat;
        }
    }
    else {
        print "$INFOSTR FMD seemingly not used or installed\n";
    }

    datecheck();
    print_header("*** END CHECKING SOLARIS FAULT MANAGER STATUS $datestring ***");
}

#
# Subroutine to check DNS
#
sub dnschk {
    datecheck();
    print_header("*** BEGIN CHECKING DOMAIN NAME SERVICES $datestring ***");

    if ( !"@DNSRUN" ) {
        print "$INFOSTR DNS server (named) not running\n";
    }
    else {
        print "$INFOSTR DNS server (named) running\n";
        foreach my $dnsfile (@DNSarray) {
            print "\n$INFOSTR Checking $dnsfile\n";
            if ( open( XY, "egrep -v ^# $dnsfile | nawk NF |" ) ) {
                while (<XY>) {
                    print $_;
                }
                close(XY);
            }
            else {
               print "\n$INFOSTR Cannot open $dnsfile or is in non-standard location\n";
            }
        }
    }

    if ( open( I, "nawk NF $NAMED |" ) ) {
        print "\n$INFOSTR DNS resolver configuration ($NAMED):\n";
        while (<I>) {
            print $_;
            $_ =~ s/^\s+//g;

            if ( grep( /^search/, $_ ) ) {
                $SEARCHCOUNT++;
                if ( grep( /\s+$/, $_ ) ) {
                    $PFMERR++;
                }
            }

            if ( grep( /^domain/, $_ ) ) {
                (undef, $DNSdefdom) = split( /\s+/, $_ );
                $DOMCOUNT++;
            }

            if ( grep( /^nameserver/, $_ ) ) {
                my (undef, $DNSsrv) = split( /\s+/, $_ );
                if ( "$DNSsrv" ) {
                    push(@MYDNSSRV, "$DNSsrv");
                    $DNS_NO++;
                }
            }
        }
        close(I);

        if ( "$DNSdefdom" ) {
            print "\n$INFOSTR Default domain is $DNSdefdom\n";
        }
        else {
            print "\n$WARNSTR Default domain entry missing in $NAMED\n";
            push(@CHECKARR, "\n$WARNSTR Default domain entry missing in $NAMED\n");
            $warnings++;
        }

        if ( "$SEARCHCOUNT" > 1 ) {
            print "\n$WARNSTR Multiple \"search\" keywords found in $NAMED\n";
            print "$INFOSTR When more than one instance of the keyword is present, the last instance overrides\n";
            push(@CHECKARR, "\n$WARNSTR Multiple \"search\" keywords found in $NAMED\n");
            $warnings++;
        }
        elsif ( "$SEARCHCOUNT" == 1 ) {
            print "\n$PASSSTR One \"search\" keyword found in $NAMED\n";
        }
        else {
            print "\n$INFOSTR No \"search\" keyword found in $NAMED\n";
        }

        if ( "$DOMCOUNT" > 1 ) {
            print "\n$WARNSTR Multiple \"domain\" keywords found in $NAMED\n";
            print "$INFOSTR When more than one instance of the keyword is present, the last instance overrides\n";
            push(@CHECKARR, "\n$WARNSTR Multiple \"domain\" keywords found in $NAMED\n");
            $warnings++;
        }
        elsif ( "$DOMCOUNT" == 1 ) {
            print "\n$PASSSTR One \"domain\" keyword found in $NAMED\n";
        }
        else {
            print "\n$INFOSTR No \"domain\" keyword found in $NAMED\n";
        }

        if ( "@MYDNSSRV" ) {
            foreach my $ztm (@MYDNSSRV) {
                &openport($ztm, '53', 'udp');
                &openport($ztm, '53', 'tcp');
            }
        }

        print "\n$INFOSTR Found $DNS_NO \"nameserver\" entries in $NAMED\n";
        if ( $DNS_NO > $MAXDNSSRV ) {
            print "$INFOSTR Normally, resolver library is limited to $MAXDNSSRV entires\n";
        }

        if ( $PFMERR > 0 ) {
            print
"\n$WARNSTR Search command contains empty spaces at the end of line in $NAMED\n";
            print
"$INFOSTR This been known to generate the \"PFMERRR 10\" error message\n";
            push(@CHECKARR,
"\n$WARNSTR Search command contains empty spaces at the end of line in $NAMED\n");
            $warnings++;
        }

        my $stperm = (stat($NAMED))[2] & 07777;
        my $rootow = (stat($NAMED))[4];
        my $octp = sprintf "%lo", $stperm;

        if ( "$rootow" == 0 ) {
            print "\n$PASSSTR $NAMED owned by UID $rootow\n";
        }
        else {
            print "\n$WARNSTR $NAMED not owned by UID 0 ($rootow)\n";
            push(@CHECKARR, "\n$WARNSTR $NAMED not owned by UID 0 ($rootow)\n");
            $warnings++;
        }

        if ( ($octp != 444) && ($octp != 644) ) {
           print "\n$WARNSTR Permissions for $NAMED incorrect ($octp)\n";
           push(@CHECKARR, "\n$WARNSTR Permissions for $NAMED incorrect ($octp)\n");
           $warnings++;
           print "$NOTESTR Permissions for $NAMED should be 444 or 644\n";
        }
        else {
           print "\n$PASSSTR Permissions for $NAMED correct ($octp)\n";
           print "$NOTESTR Permissions for $NAMED should be 444 or 644\n";
        }
    }
    else {
        print "\n$WARNSTR $NAMED is empty or does not exist\n";
        push(@CHECKARR, "\n$WARNSTR $NAMED is empty or does not exist\n");
        $warnings++;
    }

    print "\n$INFOSTR Checking hostname resolution order\n";
    if ( ( -s "$NSSWITCH" ) && ( -T "$NSSWITCH") ) {
        print "$INFOSTR Configuration file $NSSWITCH exists\n";
        while (<NPAD>) {
            next if grep( /^$/, $_ );
            if ( grep( /^ipnodes:/, $_ ) ) {
                $IPNODES_FLAG++;
            }
            print $_;
        }
        close(NPAD);

        if ( ( $INET6COUNT > 0 ) && ( $IPNODES_FLAG == 0 ) ) {
            print "\n$WARNSTR Missing entry for ipnodes in $NSSWITCH\n";
            print "$INFOSTR Ipnodes is important for IPv4 and IPv6\n";
            push(@CHECKARR, "\n$WARNSTR Missing entry for ipnodes in $NSSWITCH\n");
            $warnings++;
        }
        else {
            print "\n$PASSSTR Entry for ipnodes in $NSSWITCH is defined\n";
        }

        my $stperm = (stat($NSSWITCH))[2] & 07777;
        my $rootow = (stat($NSSWITCH))[4];
        my $octp = sprintf "%lo", $stperm;

        if ( "$rootow" == 0 ) {
            print "\n$PASSSTR $NSSWITCH owned by UID $rootow\n";
        }
        else {
            print "\n$WARNSTR $NSSWITCH not owned by UID 0 ($rootow)\n";
            push(@CHECKARR, "\n$WARNSTR $NSSWITCH not owned by UID 0 ($rootow)\n");
            $warnings++;
        }

        if ( ($octp != 444) && ($octp != 644) ) {
           print "\n$WARNSTR Permissions for $NSSWITCH incorrect ($octp)\n";
           push(@CHECKARR, "\n$WARNSTR Permissions for $NSSWITCH incorrect ($octp)\n");
           $warnings++;
           print "$NOTESTR Permissions for $NSSWITCH should be 444 or 644\n";
        }
        else {
           print "\n$PASSSTR Permissions for $NSSWITCH correct ($octp)\n";
           print "$NOTESTR Permissions for $NSSWITCH should be 444 or 644\n";
        }
    }
    else {
        print "\n$WARNSTR Cannot open $NSSWITCH\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $NSSWITCH\n");
        $warnings++;
    }

    print "\n$INFOSTR Checking hosts file\n";
    if ( -s "$HOSTS" ) {
        print "$INFOSTR Configuration file $HOSTS exists\n";
        if ( open( HO, "cat $HOSTS | nawk NF |" ) ) {
            while (<HO>) {
                next if ( grep( /^#/, $_ ) );
                print $_;
                if ( grep( /\$lhentry/, $_ ) ) {
                    $LOCALHOST_FLAG++;
                }

                chomp($_);
                $_ =~ s/^\s+//g;
                $_ =~ s/\s+$//g;
                $_ =~ s/#.*$//g;

                my @HARR = split(/\s+/, $_);
                foreach my $hentry (@HARR) {
                    if ( $lines{$hentry}) {
                        push(@HOSTWARN, "\n$WARNSTR Entry $hentry exists more than once in $HOSTS\n");
                        push(@CHECKARR, "\n$WARNSTR Entry $hentry exists more than once in $HOSTS\n");
                        $warnings++;
                    }
                    else {
                        $lines{$hentry} = 1;
                    }
                }
            }
            close(HO);

            if ( "@HOSTWARN" ) {
                print @HOSTWARN;
            }
            else {
                 print "\n$PASSSTR All entries in $HOSTS are unique\n";
            }
        }
        else {
            print "$ERRSTR Cannot open $HOSTS\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $HOSTS\n");
        }
        close(HO);
    }
    else {
        print "$ERRSTR Configuration file $HOSTS does not exist\n";
        push(@CHECKARR, "\n$ERRSTR Configuration file $HOSTS does not exist\n");
        $warnings++;
    }

    if ( -s "$IPNODES" ) {
        my @ipnodes = `egrep -v ^# $IPNODES 2>/dev/null`;
        if ( "@ipnodes" ) {
            print "\n$INFOSTR Configuration file $IPNODES exists\n";
            print @ipnodes;
        }
    }

    if ( $LOCALHOST_FLAG == 0 ) {
        print "\n$PASSSTR Valid entry for localhost ($lhentry) in $HOSTS\n";
    }
    else {
        print "\n$ERRSTR No entry for localhost ($lhentry) in $HOSTS\n";
        push(@CHECKARR, "\n$ERRSTR No entry for localhost ($lhentry) in $HOSTS\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING DOMAIN NAME SERVICES $datestring ***");

    if ( $NSCD_FLAG > 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING SUN NAME SERVICE CACHE SERVICES $datestring ***");

        my $NSCDCONF = '/etc/nscd.conf';
        my @nscdls = `nawk '! /^#/ && ! /awk/ {print}' $NSCDCONF | nawk NF`;
        if (@nscdls) {
            print "$INFOSTR Configuration file $NSCDCONF\n";
            print @nscdls;
        }
        else {
            print "$INFOSTR $NSCDCONF not configured\n";
        }

        datecheck();
        print_header("*** END CHECKING SUN NAME SERVICE CACHE SERVICES $datestring ***");
    }
}

#
# Subroutine to check Kerberos
#
sub Kerberoschk {
    datecheck();
    print_header("*** BEGIN CHECKING KERBEROS $datestring ***");

    if ( -s "$Kerbconf" ) {
        if ( open( KBROM, "nawk '! /^#/ && ! /awk/ {print}' $Kerbconf |" ) ) {
            while (<KBROM>) {
                next if ( grep( /^$/, $_ ) );
                push( @KBars, $_ );
            }
            close(KBROM);
        }

        if ("@KBars") {
            print "$INFOSTR Kerberos configuration file $Kerbconf\n";
            print @KBars;

            my @kblist = `klist | nawk NF`;
            if ("@kblist") {
                print "$INFOSTR Kerberos tickets\n";
                print @kblist;
            }
        }
        else {
            print "$INFOSTR Kerberos configuration file $Kerbconf empty\n";
        }
    }
    else {
        print
"$INFOSTR Kerberos configuration file $Kerbconf empty or non-existent\n";
    }

    datecheck();
    print_header("*** END CHECKING KERBEROS $datestring ***");
}

#
# Subroutine to check DHCP
#
sub DHCPchk {
    datecheck();
    print_header("*** BEGIN CHECKING DHCP $datestring ***");

    if ( "$DHCPD_FLAG" > 0 ) {
        print "$INFOSTR DHCP server running\n";

        if ( -s "$DHCPconf" ) {
            if (
                open( DBROM, "nawk '! /^#/ && ! /awk/ {print}' $DHCPconf |" ) )
            {
                while (<DBROM>) {
                    next if ( grep( /^$/, $_ ) );
                    push( @HBars, $_ );
                }
                close(DBROM);
            }

            if ("@HBars") {
                print "\n$INFOSTR DHCP configuration file $DHCPconf\n";
                print @HBars;
            }
        }

        if ( -s "$DHCPtab" ) {
            if ( open( TBROM, "nawk '! /^#/ && ! /awk/ {print}' $DHCPtab |" ) )
            {
                while (<TBROM>) {
                    next if ( grep( /^$/, $_ ) );
                    push( @TBars, $_ );
                }
                close(TBROM);
            }

            if ("@TBars") {
                print "\n$INFOSTR DHCP configuration file $DHCPtab\n";
                print @TBars;
            }

            my @pntadm = `pntadm -L 2>/dev/null`;

            if ( "@pntadm" ) {
                print "\n$INFOSTR Existing DHCP tables\n";
                print @pntadm;
            }
        }
    }
    else {
        print "$INFOSTR DHCP server not running\n";
    }

    datecheck();
    print_header("*** END CHECKING DHCP $datestring ***");
}

#
# Subroutine to check NIS/YP
#
sub nischk {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK INFORMATION SERVICES (NIS/YP) $datestring ***");

    my $domname = `domainname | nawk NF`;

    if ("$domname") {
        my $ypwhich = `ypwhich 2>/dev/null`;

        my @nisdefs = `nisdefaults 2>/dev/null`;
        if ("@nisdefs") {
            print "$INFOSTR NIS+ default values\n";
            print @nisdefs;
            my @nisls = `nisls 2>/dev/null`;
            if ("@nisls") {
                print "\n$INFOSTR NIS+ listing\n";
                print @nisls;
            }
        }

        if ("$ypwhich") {
            print
              "$INFOSTR NIS domain $domname (bound to server $ypwhich)\n";

            if ( -s "$secnets" ) {
                my @sn = `egrep -v ^# $secnets 2>/dev/null`;
                if ("@sn") {
                    print "\n$INFOSTR File $secnets\n";
                    print @sn;
                }
                else {
                    print "\n$INFOSTR File $secnets not set\n";
                    $warnings++;
                }
            }
            else {
                print "\n$INFOSTR File $secnets does not exist";
                $warnings++;
            }

            if ( -s "$secservers" ) {
                my @sn1 = `egrep -v ^# $secservers 2>/dev/null`;
                if ("@sn1") {
                    print "\n$INFOSTR File $secservers\n";
                    print @sn1;
                }
                else {
                    print "\n$INFOSTR File $secservers not set\n";
                    $warnings++;
                }
            }
            else {
                print "\n$INFOSTR File $secservers does not exist\n";
                $warnings++;
            }
        }
        else {
            print "\n$INFOSTR NIS not active\n";
        }
    }
    else {
        print "$INFOSTR NIS not set\n";
    }

    datecheck();
    print_header("*** END CHECKING NETWORK INFORMATION SERVICES (NIS/YP) $datestring ***");
}

#
# Subroutine to check RAM and swap
#
sub swapcheck {
    datecheck(); 
    print_header("*** BEGIN CHECKING MEMORY AND SWAP $datestring ***");

    ( $MEM_MBYTE, undef ) = split( /\s+/, $RAMsize );

    if ( open( MX, "swap -l | nawk '! /swapfile/ && ! /awk/ {print}' |" ) ) {
        print "$INFOSTR \"swap -l\" command\n";
        while (<MX>) {
            print $_;
            chomp;
            ( $swappath, $swapdev, $swaplow, $tswapdef, $tswapused ) = split( /\s+/, $_ );
            $tswap1    += $tswapdef;
            $tswapUSED += $tswapused;
            $swappathno++;
            push(@SWAPARR, $swappath);
        }
        close(MX);
    }
    else {
        print "$WARNSTR Cannot run swap\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run swap\n");
    }

    $tswap     = int( $tswap1 /    ( 2 * 1024 ) );
    $tswapUSED = int( $tswapused / ( 2 * 1024 ) );

    print "\n$INFOSTR Total disk-based swap space is $tswap MB (physical paging devices, and file-systems)\n";
    print "\n$INFOSTR Physical memory is $MEM_MBYTE MB\n";

    my @SWAPSARR = ();
    my $SWAPUA   = q{};
    if ( open( MX3, "swap -s|" ) ) {
        print "\n$INFOSTR \"swap -s\" command\n";
        while (<MX3>) {
            print $_;
            chomp;
            @SWAPSARR = split( /\s+/, $_ );
            $SWAPSARR[1] =~ s/^\s+//g;
            $SWAPSARR[1] =~ s/\s+$//g;
            $SWAPSARR[1] =~ s/k$//g;
            $SWAPSARR[$#SWAPSARR - 1] =~ s/^\s+//g;
            $SWAPSARR[$#SWAPSARR - 1] =~ s/\s+$//g;
            $SWAPSARR[$#SWAPSARR - 1] =~ s/k$//g;
            #
            # Swap used plus available
            $SWAPUA = int(( $SWAPSARR[1] / 1024) + ( $SWAPSARR[$#SWAPSARR - 1] / 1024));
        }
        close(MX3);
    }

    print "\n$INFOSTR Swap used plus available is $SWAPUA MB, of which $tswap MB is disk-based\n";

    if ( $MEM_MBYTE <= $MEMTHRES1 ) {
        if ( $tswap < $minswap ) {
            print "\n$WARNSTR Swap space is less than minimum for RAM <= $MEMTHRES1 MB ";
            print "(Swap=$tswap MB, minumum=$minswap MB)\n";
            push(@CHECKARR, "\n$WARNSTR Swap space is less than minimum for RAM <= $MEMTHRES1 MB ");
            push(@CHECKARR, "(Swap=$tswap MB, minumum=$minswap MB)\n");
            $warnings++;
        }
        else 
        {
            print "\n$PASSSTR Swap space satisfies minimum general recommendations for RAM <= $MEMTHRES1 ";
            print "(Swap=$tswap MB, minumum=$minswap MB)\n";
        }
    } elsif ( $MEM_MBYTE <= $MEMTHRES2 ) {
        if ( $tswap < $MEMARR{$MEMTHRES2} ) {
            print "$WARNSTR Swap space is less than minimum for RAM <= $MEMTHRES2 MB ";
            print "(Swap=$tswap MB, minumum=$MEMARR{$MEMTHRES2} MB)\n";
            push(@CHECKARR, "\n$WARNSTR Swap space is less than minimum for RAM <= $MEMTHRES2 MB ");
            push(@CHECKARR, "(Swap=$tswap MB, minumum=$MEMARR{$MEMTHRES2} MB)\n");
            $warnings++;
        } else
        {
            print "\n$PASSSTR Swap space satisfies minimum general recommendations for RAM <= $MEMTHRES2 MB ";
            print "(Swap=$tswap MB, minumum=$MEMARR{$MEMTHRES2} MB)\n";
        }
    } elsif ( $MEM_MBYTE <= $MEMTHRES3 ) {
        if ( $tswap < $MEMARR{$MEMTHRES3} ) {
            print "$WARNSTR Swap space is less than minimum for RAM <= $MEMTHRES3 MB ";
            print "(Swap=$tswap MB, minumum=$MEMARR{$MEMTHRES3} MB)\n";
            push(@CHECKARR, "\n$WARNSTR Swap space is less than minimum for RAM <= $MEMTHRES3 MB ");
            push(@CHECKARR, "(Swap=$tswap MB, minumum=$MEMARR{$MEMTHRES3} MB)\n");
            $warnings++;
        } else
        {
            print "\n$PASSSTR Swap space satisfies minimum general recommendations for RAM <= $MEMTHRES3 MB ";
            print "(Swap=$tswap MB, minumum=$MEMARR{$MEMTHRES3} MB)\n";
        }
    } else
    {
        $minswap = sprintf("%.2f", ($MEM_MBYTE / 4));
        if ( $tswap < $minswap ) {
            print "\n$WARNSTR Swap space is less than minimum for RAM > $MEMTHRES3 MB ";
            print "(Swap=$tswap MB, minumum=$minswap MB)\n";
            push(@CHECKARR, "\n$WARNSTR Swap space is less than minimum ");
            push(@CHECKARR, "(Swap=$tswap MB, minumum=$minswap MB)\n");
            $warnings++;
        }
        else 
        {
            print "\n$PASSSTR Swap space satisfies minimum general recommendations for RAM > $MEMTHRES3 MB ";
            print "(Swap=$tswap MB, minumum=$minswap MB)\n";
        }
    }

    if ( $swappathno < $Minswapdevno ) {
        print
"\n$WARNSTR Less than recommended minimum number of online swap devices (minimum $Minswapdevno)\n";
        push(@CHECKARR,
"\n$WARNSTR Less than recommended minimum number of online swap devices (minimum $Minswapdevno)\n");
        $warnings++;
    }
    else {
        print
"\n$PASSSTR Recommended minimum number of online swap devices satisfied (minimum $Minswapdevno)\n";
    }

    if ( $swappathno > 0 ) {
        my @union = my @intersection = my @difference = ();
        my %count = ();
        my $element = q{};
        foreach $element ( @DUMPARR, @SWAPARR ) { $count{$element}++; }
        foreach $element ( keys %count ) {
            push @union, $element;
            push @{ $count{$element} > 1 ? \@intersection : \@difference },
              $element;
        }

        print "\n$INFOSTR Dump device listing: @DUMPARR\n";
        print "\n$INFOSTR Swap device listing: @SWAPARR\n";

        if (@difference) {
            print "\n$PASSSTR Dump and swap devices are on different volumes\n";
        }
        else {
            print "\n$WARNSTR Dump and swap devices are on same volumes\n";
            push(@CHECKARR,
"\n$WARNSTR Dump and swap devices are on same volumes)\n");
            $warnings++;
       }
    }

    datecheck(); 
    print_header("*** END CHECKING MEMORY AND SWAP $datestring ***");
}

#
# Subroutine to check login banners
#
sub motd {
    datecheck();
    print_header("*** BEGIN CHECKING LOGIN BANNERS $datestring ***");

    if ( -s "$ISSUE" ) {
        print "$PASSSTR Login banner $ISSUE exists\n";
        $sst = `egrep "Release|Sun|Solaris" $ISSUE`;
        if ("$sst") {
            print "$WARNSTR Login banner $ISSUE possibly not customised ";
            print "(please check it)\n";
            push(@CHECKARR, "\n$WARNSTR Login banner $ISSUE possibly not customised\n");
            $warnings++;
        }
    }
    else {
        print "$WARNSTR Login banner $ISSUE does not exist\n";
        push(@CHECKARR, "\n$WARNSTR Login banner $ISSUE does not exist\n");
        $warnings++;
    }

    if ( -s "$ISSUENET" ) {
        print "\n$PASSSTR Login banner $ISSUENET exists\n";
        $sst = `egrep "Release|Sun/Solaris" $ISSUENET`;
        if ("$sst") {
            print
              "\n$WARNSTR Login banner $ISSUENET possibly not customised ";
            print "(please check it)\n";
            push(@CHECKARR,
              "\n$WARNSTR Login banner $ISSUENET possibly not customised\n");
            $warnings++;
        }
    }
    else {
        print "\n$WARNSTR Login banner $ISSUENET does not exist\n";
        push(@CHECKARR, "\n$WARNSTR Login banner $ISSUENET does not exist\n");
        $warnings++;
    }

    if ( -s "$MOTD" ) {
        print "\n$PASSSTR Login banner $MOTD exists\n";
        my $ssm = `egrep "Release|Sun|Solaris" $MOTD`;
        if ("$ssm") {
            print "\n$WARNSTR Login banner $MOTD possibly not customised ";
            print "(please check it)\n";
            push(@CHECKARR, "\n$WARNSTR Login banner $MOTD possibly not customised\n");
            $warnings++;
        }
    }
    else {
        print "\n$WARNSTR Login banner $MOTD does not exist\n";
        push(@CHECKARR, "\n$WARNSTR Login banner $MOTD does not exist\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING LOGIN BANNERS $datestring ***");
}

#
# Subroutine to check SAN configuration
#
sub SANchk {
    datecheck();
    print_header("*** BEGIN CHECKING SAN CONFIGURATION $datestring ***");

    my $rmparams = "/etc/osa/rmparams";

    if ( -s "$rmparams" ) {
        if ( open( RMROM, "nawk '! /^#/ && ! /awk/ {print}' $rmparams |" ) ) {
            while (<RMROM>) {
                next if ( grep( /^$/, $_ ) );
                push( @RBars, $_ );
            }
            close(RMROM);
        }

        if ("@RBars") {
            print "$INFOSTR RAID Manager configuration file $rmparams\n";
            print @RBars;
        }
        else {
            print
              "$INFOSTR RAID Manager configuration file $rmparams empty\n";
        }
    }
    else {
        print
"$INFOSTR RAID Manager configuration file $rmparams empty or non-existent\n";
    }

    if ( open( HCK, "healthck -a 2>/dev/null |" ) ) {
        while (<HCK>) {
            push( @hchk, $_ );
        }
        close(HCK);
    }

    if ("@hchk") {
        print "$INFOSTR Health check\n";
        print @hchk;
    }

    if ( "$SECPATH_FLAG" > 0 ) {
        print "\n$INFOSTR Secure Path seemingly installed\n";
        @SPMGR = `spmgr display 2>/dev/null`;
        if ("@SPMGR") {
            print "\n$INFOSTR EVA SAN seemingly connected\n";
            print @SPMGR;
            $ARRFLAG++;
        }
    }

    if ( "$Minor" >= 10 ) { 
        my @stmsboot = `stmsboot -L 2>/dev/null`;
        if ("@stmsboot") {
            print 
"\n$INFOSTR Solaris I/O Multipathing (also known as STMS and MPxIO)\n";
            print @stmsboot;
        }
    }

    my @MPXarr = ( "$MPxIO_conf1", "$MPxIO_conf2" ); 

    foreach $MPxIO_conf ( @MPXarr ) {
        if ( -s "$MPxIO_conf" ) {
            if ( open( MPX, "egrep -v ^# $MPxIO_conf |" ) ) {
                print "\n$INFOSTR Configuration file $MPxIO_conf\n";
                while (<MPX>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                    if ( grep( /^mpxio-disable/, $_ ) ) {
                        ( undef, $MPXopts ) = split( /=/, $_ );
                        $MPXopts =~ s/^\s+//g;
                        $MPXopts =~ s/\"//g;
                        $MPXopts =~ s/;//g;
                        chomp($MPXopts);
                        if ( "$MPXopts" eq 'yes' ) {
                            print "$INFOSTR MPxIO disabled globally\n";
                        }
                        else {
                            print "$INFOSTR MPxIO enabled globally\n";
                        }
                    }
                }
                close(MPX);
            }
        }
    }

    my @XPINFO = `xpinfo 2>/dev/null| egrep -v "Scanning|No disk"| nawk NF`;
    my @INQRAID = `inqraid 2>/dev/null | nawk NF`;
    my @ISCSIADM = `iscsiadm list target -v 2>/dev/null | nawk NF`;
    my @ISCSINODE = `iscsiadm list initiator-node 2>/dev/null | nawk NF`;
    my @ISCSISTATIC = `iscsiadm list static-config 2>/dev/null | nawk NF`;
    my @ISCSIDISC = `iscsiadm list discovery 2>/dev/null | nawk NF`;
    my @ISCSITARGET = `iscsiadm list target -v 2>/dev/null | nawk NF`;
    my @ISCSIISNS = `iscsiadm list isns-server -v 2>/dev/null | nawk NF`;
    my $DRIVERALIAS = "/etc/driver_aliases";
    my @mpathadm = `mpathadm list initiator-port 2>/dev/null`;
    my @sbdadmlu = `sbdadm list-lu 2>/dev/null`;
    my @stfmadmlu = `stmfadm list-lu -v 2>/dev/null`;
    my @evainfo = `evainfo -a -l 2>/dev/null`;
    my @evadiscovery = `evadiscovery -l 2>/dev/null`;
    my @HP3PARINFOI = `HP3PARInfo -i 2>/dev/null`;
    my @HP3PARINFOF = `HP3PARInfo -f 2>/dev/null`;

    if ("@mpathadm") {
        print "\n$INFOSTR Solaris multipathing discovery\n";
        print @mpathadm;

        my @mpathadmlu = `mpathadm list lu 2>/dev/null`;
        print @mpathadmlu;
        foreach my $hbaentlu ( grep(/rdsk/, @mpathadmlu) ) {
            chomp($hbaentlu);
            my @hchklu = `mpathadm show lu $hbaentlu 2>/dev/null`;
            if ("@hchklu") {
                print "\n$INFOSTR $hbaentlu multipath status\n";
                print @hchklu;
            }
        }
    }
    
    if ( -s "$DRIVERALIAS" ) {
        my @DRALS = `nawk NF $DRIVERALIAS`;
        if ( "@DRALS" ) {
            print "\n$INFOSTR Configuration file $DRIVERALIAS\n";
            print @DRALS;
        }
    }

    if ("@XPINFO") {
        print "\n$INFOSTR XP SAN check\n";
        print @XPINFO;

        my @XPINFOI = `xpinfo -d 2>/dev/null | nawk NF`;
        if ("@XPINFOI") {
            print "\n$INFOSTR XP SAN path checks\n";
            print @XPINFOI;
        }
    }

    if ("@evainfo") {
        print "\n$INFOSTR EVA SAN status\n";
        print @evainfo;
    }

    if ("@evadiscovery") {
        print "\n$INFOSTR EVA SAN discovery\n";
        print @evadiscovery;
    }

    if ("@HP3PARINFOI") {
        print "\n$INFOSTR HP 3PAR SAN status\n";
        print @HP3PARINFOI;
    }

    if ("@HP3PARINFOF") {
        print "\n$INFOSTR HP 3PAR SAN LUNs\n";
        print @HP3PARINFOF;
    }

    if ("@INQRAID") {
        print "\n$INFOSTR Hitachi/XP SAN status\n";
        print @INQRAID;
    }

    if ("@ISCSIADM") {
        print "\n$INFOSTR iSCSI check\n";
        print @ISCSIADM;
        print "\n$INFOSTR iSCSI initiator-node check\n";
        print @ISCSINODE;
        print "\n$INFOSTR iSCSI static config\n";
        print @ISCSISTATIC;
        print "\n$INFOSTR iSCSI discovery\n";
        print @ISCSIDISC;
        print "\n$INFOSTR iSCSI targets\n";
        print @ISCSITARGET;
        print "\n$INFOSTR iSCSI isns server\n";
        print @ISCSIISNS;
    }
    else {
        print "\n$INFOSTR iSCSI seemingly not configured\n";
    }

    my @raidctl = `raidctl 2>/dev/null`;
    if ("@raidctl") {
        print "\n$INFOSTR Hardware RAID check\n";
        print @raidctl;
    }

    if ( "$Minor" >= 10 ) {
        if ( open( FCINFO, "fcinfo hba-port -l 2>/dev/null |" ) ) {
            while (<FCINFO>) {
                push(@fcinfo, $_);
                if ( grep( /HBA Port WWN|Port WWN/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    ( undef, $HBAWWN ) = split( /:/, $_ );
                    $HBAWWN =~ s/^\s+//g;
                    push (@HBAARR, $HBAWWN);
                }
            }
            close(FCINFO);
        }

        if ("@fcinfo") {
            print "\n$INFOSTR Fcinfo check\n";
            print @fcinfo;
        }

        if ( @HBAARR ) {
            foreach my $hbaent ( @HBAARR ) {
                chomp($hbaent);
                my @hchk = `fcinfo remote-port -slp $hbaent 2>/dev/null`;
                if ("@hchk") {
                    print "\n$INFOSTR HBA WWN $hbaent remote port scan\n";
                    print @hchk;
                }
            }
        }
    }

    my @lchk     = `luxadm probe 2>/dev/null`;
    my @lportc   = `luxadm -e port 2>/dev/null | nawk NF`;
    my @luxfcode = `luxadm -v fcode_download -p 2>/dev/null | nawk NF`;
    my @luxdmp   = `luxadm -e dump_map 2>/dev/null | nawk NF`;

    if ("@lchk") {
        print "\n$INFOSTR Luxadm scan\n";
        print @lchk;
    }

    if ("@lportc") {
        print "\n$INFOSTR Luxadm port status\n";
        print @lportc;
    }

    if ("@luxfcode") {
        print "\n$INFOSTR Luxadm fcode status\n";
        print @luxfcode;
    }

    if ("@luxdmp") {
        print "\n$INFOSTR Luxadm dump map\n";
        print @luxdmp;
    }

    foreach my $actdisk ( @ALLDISKS ) {
        chomp($actdisk);
        my @mydisk = `luxadm -v display $actdisk 2>/dev/null | nawk NF`;
        if ("@mydisk") {
            print "\n$INFOSTR Luxadm status for disk $actdisk\n";
            print @mydisk;
        }
    }

    my @prtpicl = `prtpicl -v -c scsi-fcp 2>/dev/null | nawk NF`;
    if ("@prtpicl") {
        print "\n$INFOSTR Checking Qlogic and Emulex cards\n";
        print @prtpicl;
    }

    my @prtpicl2 = `prtpicl -v -c scsi 2>/dev/null | nawk NF`;
    if ("@prtpicl2") {
        print "\n$INFOSTR Checking JNI cards\n";
        print @prtpicl2;
    }

    if ("@sbdadmlu") {
        print "\n$INFOSTR Sbdadm SCSI block disk logical unit summary\n";
        print @sbdadmlu;
    }

    if ("@stfmadmlu") {
        print "\n$INFOSTR Stfmadm logical unit summary\n";
        print @stfmadmlu;
    }

    if ( "$VTS_FLAG" == 1 ) {
        my @vchk = `vtsprobe 2>/dev/null`;
        if ("@vchk") {
            print "\n$INFOSTR SUNWvts check\n";
            print @vchk;
        }
    }

    my @dlnkmgr = `dlnkmgr view -sys`;
    if ("@dlnkmgr") {
        print "\n$INFOSTR Hitachi Dynamic Link Manager seemingly installed\n";
        print @dlnkmgr;

        my @dlnkmgrpath = `dlnkmgr view -path`;
        if ("@dlnkmgrpath") {
            print
"\n$INFOSTR Hitachi Dynamic Link Manager path status\n";
            print @dlnkmgrpath;
        }
    }
    else {
        print "\n$INFOSTR Hitachi Dynamic Link Manager not installed\n";
    }

    if ( open( RCK, "ls /dev/rdsk | raidscan -find" ) ) {
        while (<RCK>) {
            push( @RMC, $_ );
        }
        close(RCK);
    }

    if ("@RMC") {
        print "\n$INFOSTR Raidscan report\n";
        print @RMC;
        $ARRFLAG++;
    }

    if ( open( ECK, "syminq 2>/dev/null |" ) ) {
        while (<ECK>) {
            push( @EMC, $_ );
        }
        close(ECK);
    }

    if ("@EMC") {
        print "\n$INFOSTR EMC Symmetrix seemingly connected\n";
        print @EMC;
        $ARRFLAG++;

        my @EMCL = `symcfg list -v`;
        if ("@EMCL") {
            print "\n$INFOSTR EMC Symmetrix configuration\n";
            print @EMCL;
        }

        my @EMCC = `symcfg -connections list`;
        if ("@EMCC") {
            print "\n$INFOSTR EMC Symmetrix connections\n";
            print @EMCC;
        }

        my @Clararr = `navicli getagent`;
        if ("@Clararr") {
            $ARRFLAG++;
            print "\n$INFOSTR EMC Clariion seemingly connected\n";
            print @Clararr;

            my @CLARdisk = `navicli getdisk`;
            if ("@CLARdisk") {
                print "\n$INFOSTR EMC Clariion disk status\n";
                print @CLARdisk;
            }

            my @CLARstor = `navicli storagegroup -list`;
            if ("@CLARstor") {
                print "\n$INFOSTR EMC Clariion storage group status\n";
                print @CLARstor;
            }

            my @CLARlun = `navicli getlun`;
            if ("@CLARlun") {
                print "\n$INFOSTR EMC Clariion LUN status\n";
                print @CLARlun;
            }

            my @CLARport = `navicli port -list`;
            if ("@CLARport") {
                print "\n$INFOSTR EMC Clariion port status\n";
                print @CLARport;
            }

            my @CLARatf = `navicli getatf`;
            if ("@CLARatf") {
                print "\n$INFOSTR EMC Clariion atf status\n";
                print @CLARatf;
            }
        }
    }

    if ( open( SCK, "sgscan 2>/dev/null |" ) ) {
        while (<SCK>) {
            push( @SGSCAN, $_ );
        }
        close(SCK);
    }

    if ("@SGSCAN") {
        print "\n$INFOSTR Sgscan check\n";
        print @SGSCAN;
        $ARRFLAG++;
    }

    my @CFGADM = `cfgadm -la 2>/dev/null`;

    if ("@CFGADM") {
        print "\n$INFOSTR Cfgadm check\n";
        print @CFGADM;
        $ARRFLAG++;
    }

    my @SSMAA = `ssmadmin -view 2>/dev/null`;

    if ("@SSMAA") {
        print "\n$INFOSTR Ssmadmin check\n";
        print @SSMAA;
        $ARRFLAG++;
    }

    my @fcinfolu = `fcinfo logical-unit -v 2>/dev/null`;

    if ("@fcinfolu") {
        print "\n$INFOSTR FC logical units\n";
        print @fcinfolu;
        $ARRFLAG++;
    }

    if ( $ARRFLAG == 0 ) {
        print
"\n$INFOSTR It seems no SAN connected or their support toolkits not installed correctly\n";
    }

    if ("@FCarray") {
        print "\n$INFOSTR Fcmsutil status\n";
        foreach my $fa (@FCarray) {
            chomp($fa);
            $fa =~ s/^\s+//g;
            $fa =~ s/CLAIMED.*//g;
            $fa =~ s/\s+$//g;
            ( undef, $instance, $fcpath, $ddriv, undef ) =
              split( /\s+/, $fa );
            my $fulfcpath = "/dev/${ddriv}${instance}";
            print "\n$INFOSTR fcmsutil $fulfcpath\n";
            my @printfc = `fcmsutil $fulfcpath 2>&1`;
            print "@printfc";
        }
    }

    if ( "$autopath" == 1 ) {
        print "\n$INFOSTR AutoPath seemingly installed\n";
        my @autop = `autopath display all | nawk NF`;
        print @autop;
    }

    datecheck();
    print_header("*** END CHECKING SAN CONFIGURATION $datestring ***");
}

# Subroutine to check VxVM
#
sub VXVM_CHECK {
    if ( "@vxcheck" ) {
        datecheck();
        print_header("*** BEGIN CHECKING VXVM STATUS $datestring ***");

        my @vxiod = `vxiod 2>/dev/null`;
        if ( "@vxiod" ) {
            print "\n$INFOSTR VxVM kernel daemons\n";
            print @vxiod;
        }

        if ( -s "$VXCONF" ) {
            if ( open( VXC, "egrep -v ^# $VXCONF | awk '/^opts=/ {print}' |" ) ) {
                print "\n$INFOSTR Configuration file $VXCONF\n";
                while (<VXC>) {
                    print $_;
                    next if ( grep( /^$/, $_ ) );
                    $_ =~ s/#.*$//g;
                    ( undef, $Vxopts ) = split( /=/, $_ );
                    $Vxopts =~ s/\"//g;
                }
                close(VXC);

                if ("$Vxopts") {
                    print "\n$PASSSTR VxVM logging defined in $VXCONF ($Vxopts)\n";
                }
                else {
                    print "\n$WARNSTR VxVM logging not defined in $VXCONF\n";
                    push(@CHECKARR, "\n$WARNSTR VxVM logging not defined in $VXCONF\n");
                    $warnings++;
                }
            }
            else {
                print "$WARNSTR Cannot open $VXCONF\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open $VXCONF\n");
                $warnings++;
            }
        }
        else {
            print "$WARNSTR $VXCONF empty or does not exist\n";
            push(@CHECKARR, "\n$WARNSTR $VXCONF empty or does not exist\n");
        }

        if ( open( VXD, "vxdisk -o alldgs list |" ) ) {
            print "\n$INFOSTR Vxdisk status\n";
            while (<VXD>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
    
                if ( grep( /offline|fail|error|invalid/i, $_ ) ) {
                    push(@VXERRARR, $_);
                }

                if ( grep( /online/i, $_ ) ) {
                    ($vxdiskls, undef) = split(/\s+/, $_);
                    chomp($vxdiskls);
                    if ( "$vxdiskls" ) {
                        push(@VXALLDISK, $vxdiskls);
                    }
                }
            }
            close(VXD);

            if ( "@VXERRARR" ) {
                print "\n$WARNSTR Non-VxVM or faulty physical volume(s)\n";
                print @VXERRARR;
                push(@CHECKARR, "\n$WARNSTR Non-VxVM or faulty physical volume(s)\n");
                push(@CHECKARR, "@VXERRARR\n");
                $warnings++;
            }
        }
        else {
            print "\n$WARNSTR Cannot run vxdisk\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run vxdisk\n");
            $warnings++;
        }

        my @vxcmdlog = `vxcmdlog -l 2>/dev/null`;
        if ( "@vxcmdlog" ) {
            print "\n$INFOSTR Current settings for command logging\n";
            print @vxcmdlog;
        }

        my @vxtranslog = `vxtranslog -l 2>/dev/null`;
        if ( "@vxtranslog" ) {
            print "\n$INFOSTR Current settings for transaction logging\n";
            print @vxtranslog;
        }

        my @vxdiskpath = `vxdisk path 2>/dev/null`;
        if ( "@vxdiskpath" ) {
            print "\n$INFOSTR Vxdisk path status\n";
            print @vxdiskpath;
        }

        my @vxdmpadm1 = `vxdmpadm listenclosure all 2>/dev/null`;
        if ( "@vxdmpadm1" ) {
            print "\n$INFOSTR Disk enclosure status\n";
            print @vxdmpadm1;
        }

        my @vxdmpadm2 = `vxdmpadm listctlr all 2>/dev/null`;
        if ( "@vxdmpadm2" ) {
            print "\n$INFOSTR Disk controller status\n";
            print @vxdmpadm2;
        }

        my @vxdmpadm3 = `vxdmpadm listapm all 2>/dev/null`;
        if ( "@vxdmpadm3" ) {
            print "\n$INFOSTR Array Policy Modules (APM) status\n";
            print @vxdmpadm3;
        }

        my @vxassist = `vxassist help showattrs 2>/dev/null`;
        if ( "@vxassist" ) {
            print "\n$INFOSTR Default attributes in $VXDEFATTRS\n";
            print @vxassist;
        }

        if ( -f "$VXDBFILE" ) {
            print "\n$INFOSTR File $VXDBFILE exists (VxVM initialized)\n";
        }

        my @vxddladm0 = `vxddladm listsupport all 2>/dev/null`;
        if ( "@vxddladm0" ) {
            print "\n$INFOSTR Supported array status\n";
            print @vxddladm0;
        }

        my @vxddladm = `vxddladm listjbod 2>/dev/null`;
        if ( "@vxddladm" ) {
            print "\n$INFOSTR Supported JBOD status\n";
            print @vxddladm;
        }

        if ( open( VXDG, "vxdg list |" ) ) {
            my @VXALLDG = ();
            print "\n$INFOSTR Disk group status\n";
            while (<VXDG>) {
                next if ( grep( /^$/, $_ ) );
                print $_;

                if ( grep( /online|enabled/i, $_ ) ) {
                    ($vxdgls, undef) = split(/\s+/, $_);
                    chomp($vxdgls);
                    if ( "$vxdgls" ) {
                        push(@VXALLDG, $vxdgls);
                    }
                }
            }
            close(VXDG);

            if ( "@VXALLDG" ) {
                foreach my $ndg (@VXALLDG) {
                    my @NDy = `dgcfgrestore -n $ndg -l 2>/dev/null`;
                    if ( "@NDy" ) {
                        print "\n$INFOSTR Disk group $ndg dgcfgrestore config\n";
                        print "@NDy";
                    }
                    else {
                        print "\n$WARNSTR Disk group $ndg missing dgcfgrestore config\n";
                    }

                    my @vxsplit = `vxsplitlines -g $ndg 2>/dev/null`;
                    if ( "@vxsplit" ) {
                        print "\n$INFOSTR Conflicting configuration status for $ndg\n";
                        print "@vxsplit";
                    }

                    my @VXINFOARR = ();
                    if ( open( VXI, "vxinfo -g $ndg |" ) ) {
                        print "\n$INFOSTR Disk group $ndg status\n";
                        while (<VXI>) {
                            next if ( grep( /^$/, $_ ) );
                            if ( grep( /^Unstartable/, $_ ) ) {
                                print "$ERRSTR VxFS volume not started correctly\n";
                                push(@VXINFOARR, "\n$ERRSTR VxFS volume not started correctly\n");
                                push(@VXINFOARR, "$_");
                                push(@CHECKARR, "\n$ERRSTR VxFS volume not started correctly\n");
                                push(@CHECKARR, "$_");
                                $warnings++;
                            }
                            print $_;
                        }
                        close(VXI);
                    }

                    if ( "@VXINFOARR" ) {
                        print @VXINFOARR;
                    }
                }
            }
        }
        else {
            print "\n$WARNSTR Cannot run vxdg\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run vxdg\n");
            $warnings++;
        }

        my @vxdgf = `vxdg free 2>/dev/null`;
        if ( "@vxdgf" ) {
            print "\n$INFOSTR Free disk status\n";
            print @vxdgf;
        }

        my @vxdgs = `vxdg spare 2>/dev/null`;
        if ( "@vxdgs" ) {
            print "\n$INFOSTR Spare disk status\n";
            print @vxdgs;
        }

        my @vxsehost = `vxse_host 2>/dev/null`;
        if ( "@vxsehost" ) {
            print "\n$INFOSTR VxVM hostname check\n";
            print @vxsehost;
        }

        my @vxseraid5 = `vxse_raid5 2>/dev/null`;
        if ( "@vxseraid5" ) {
            print "\n$INFOSTR VxVM RAID5 healthcheck\n";
            print @vxseraid5;
        }

        my @vxsestripes1 = `vxse_stripes1 2>/dev/null`;
        if ( "@vxsestripes1" ) {
            print "\n$INFOSTR VxVM Striped volumes first healthcheck\n";
            print @vxsestripes1;
        }

        my @vxsestripes2 = `vxse_stripes2 2>/dev/null`;
        if ( "@vxsestripes2" ) {
            print "\n$INFOSTR VxVM Striped volumes second healthcheck\n";
            print @vxsestripes2;
        }

        my @vxsevolplex = `vxse_volplex 2>/dev/null`;
        if ( "@vxsevolplex" ) {
            print "\n$INFOSTR VxVM Volumes and plexes healthcheck\n";
            print @vxsevolplex;
        }

        my @vxsedcfail = `vxse_dc_failures 2>/dev/null`;
        if ( "@vxsedcfail" ) {
            print "\n$INFOSTR VxVM Controller and disk healthcheck\n";
            print @vxsedcfail;
        }

        my @vxserootmir = `vxse_rootmir check 2>/dev/null`;
        if ( "@vxserootmir" ) {
            print "\n$INFOSTR VxVM Root mirror configuration healthcheck\n";
            print @vxserootmir;
        }

        my @vxsespare = `vxse_spares 2>/dev/null`;
        if ( "@vxsespare" ) {
            print "\n$INFOSTR VxVM Spare disk configuration healthcheck\n";
            print @vxsespare;
        }

        my @vxseredundancy = `vxse_redundancy 2>/dev/null`;
        if ( "@vxseredundancy" ) {
            print "\n$INFOSTR VxVM Redundancy configuration healthcheck\n";
            print @vxseredundancy;
        }

        if ( open( MP, "vxprint -htvq |" ) ) {
            print "\n$INFOSTR Vxprint status\n";
            while (<MP>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                if ( grep( /MAINT|ERR|OFF/i, $_ ) ) {
                    push(@CHECKVXVM, "\n$WARNSTR Check VxVM error\n");
                    push(@CHECKVXVM, $_);
                    push(@CHECKARR, "\n$WARNSTR Check VxVM error\n");
                    push(@CHECKARR, $_);
                    $warnings++;
                }
            }
            close(MP);

            if ( "@CHECKVXVM" ) {
                print @CHECKVXVM;
            }
        }
        else {
            print "\n$WARNSTR Cannot run vxprint\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run vxprint\n");
            $warnings++;
        }

        my @vxtask = `vxtask -h list`;
        if ( @vxtask != 0 ) {
            print "\n$INFOSTR VxVM running task status\n";
            print @vxtask;
        }

        my @vxtaskp = `vxtask -p list`;
        if ( @vxtaskp != 0 ) {
            print "\n$INFOSTR VxVM paused task status\n";
            print @vxtaskp;
        }

        datecheck();
        print_header("*** END CHECKING VXVM STATUS $datestring ***");
    }
}

# Subroutine to check Jumpstart setup
#
sub Jumpstartchk {
    datecheck();
    print_header("*** BEGIN CHECKING JUMPSTART SERVICES $datestring ***");

    if ( -s "$bootparams" ) {
        if ( open( BOOTPAR, "egrep -v ^# $bootparams |" )) {
            print "$INFOSTR File $bootparams\n";
            while (<BOOTPAR>) {
                next if grep( /^$/, $_ );
                print $_;
                $sysid_config = $_;
                $sysid_config =~ s/^.*sysid_config=//g;
                $sysid_config =~ s/ .*//g;
                $sysid_config =~ s/^.*://g;
                chomp($sysid_config);
                push(@SYSIDARR, $sysid_config);
            }
            close(BOOTPAR);
        }
        else {
            print "$WARNSTR Cannot open $bootparams\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $bootparams\n");
            $warnings++;
        }
    }
    else {
        print "$INFOSTR File $bootparams empty or missing\n";
    }

    foreach my $sysiddir ( @SYSIDARR ) {
        my @privsysid = `ls $sysiddir`;
        if ( "@privsysid" ) {
            foreach my $sysidsam ( @privsysid ) {
                chomp($sysidsam);
                if ( -s "$sysiddir/$sysidsam" ) {
                    if ( open( SYSID, "egrep -v ^# $sysiddir/$sysidsam |" )) {
                        print
"\n$INFOSTR Configuration file $sysiddir/$sysidsam\n";
                        while (<SYSID>) {
                            next if grep(/^$/, $_ );
                            print $_;
                        }
                        close(SYSID);
                    }
                }
            }
        }
    }

    if ( !-d "$tftpboot" ) {
        print "\n$INFOSTR Directory $tftpboot missing\n";
    }
    else {
        print "\n$INFOSTR Directory $tftpboot exists\n";
        my @lstftp = `ls -als $tftpboot`;
        if (@lstftp) {
            print @lstftp;
        }
        else {
            print "$INFOSTR Directory $tftpboot empty\n";
        }
    }

    if ( -s "$instlcfg" ) {
        print "\n$INFOSTR Jumpstart install parameters in $instlcfg\n";
        my @zk = `egrep -v ^# $instlcfg`;
        print @zk;
    }
    else {
        print "\n$INFOSTR Server not set for Jumpstart install\n";
    }

    datecheck();
    print_header("*** END CHECKING JUMPSTART SERVICES $datestring ***");

    if ( "$Minor" >= 11 ) {
        datecheck();
        print_header("*** BEGIN CHECKING AUTOMATED INSTALLATION SERVICES $datestring ***");

        my @iai = `installadm list -m 2>/dev/null | nawk NF`;
        if (@iai) {
            print "$INFOSTR Automated installation services status\n";
            print @iai;
        }

        my @iaip = `installadm list -p 2>/dev/null | nawk NF`;
        if (@iaip) {
            print "\n$INFOSTR Automated installation services profile status\n";
            print @iaip;
        }

        my @iaic = `installadm list -c 2>/dev/null | nawk NF`;
        if (@iaic) {
            print "\n$INFOSTR Automated installation services client status\n";
            print @iaic;
        }

        datecheck();
        print_header("*** END CHECKING AUTOMATED INSTALLATION SERVICES $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING WANBOOT SERVICES $datestring ***");

    if ( -s "$wanbootcfg" ) {
        my @wanb = `cat $wanbootcfg 2>/dev/null`;
        if (@wanb) {
            print "$INFOSTR WAN boot configuration file $wanbootcfg\n";
            my @bootconfchk = `bootconfchk $wanbootcfg`;
            if (@bootconfchk) {
                print "\n$INFOSTR WAN boot configuration check\n";
                print @bootconfchk;
            }
        }
        else {
            print "$INFOSTR $wanbootcfg not configured\n";
        }
    }
    else {
        print "$INFOSTR WAN boot not in use\n";
    }

    datecheck();
    print_header("*** END CHECKING WANBOOT SERVICES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING LIVE UPGRADE STATUS $datestring ***");

    if ( -s "$LUTAB" ) { 
        my @lutab = `egrep -v ^# $LUTAB`;
        if (@lutab) {
            print "$INFOSTR Live Upgrade configuration file $LUTAB\n";
            print @lutab;

            if ( open( LUCK, "lustatus 2>/dev/null |" )) {
                print "\n$INFOSTR Live Upgrade configured\n";
                while (<LUCK>) {
                    $_ =~ s/^\s+//g;
                    print "\n$_";
                    next if grep( /^Boot Environment/,  $_ );
                    next if grep( /^Name/,  $_ );
                    next if grep( /^----/,  $_ );
                    ( $BEENV, undef) = split(/\s+/, $_);
                    if ( "$BEENV" ) {
                        my @luflist = `lufslist $BEENV`;
                        if (@luflist) {
                            print 
"\n$INFOSTR Live Upgrade boot environment $BEENV\n";
                            print @luflist;
                        }
                    }
                }
                close(LUCK);
            }
            else {
                print "\n$INFOSTR Live Upgrade not configured\n";
            }
        }
        else {
            print "$INFOSTR Live Upgrade configuration file $LUTAB empty\n";
        }

        if ( -s "$LUSYNC" ) { 
            my @lusync = `egrep -v ^# $LUSYNC`;
            if (@lusync) {
                print "$INFOSTR File $LUSYNC (list of files to be synchronized when changing from one boot environment to another)\n";
                print @lusync;
            }
        }
    }
    else {
        print "$INFOSTR Live Upgrade configuration file $LUTAB missing\n";
    }

    my @beadml = `beadm list -a 2>/dev/null`;
    if ("@beadml") {
        print "\n$INFOSTR ZFS boot environments\n";
        print @beadml;
    }

    datecheck();
    print_header("*** END CHECKING LIVE UPGRADE STATUS $datestring ***");
}

#
# Subroutine to check LAN
#
sub lancheck {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK SETUP $datestring ***");

    if ( open( LAN, "netstat -rnv |" ) ) {
        while (<LAN>) {
            print $_;
            $_ =~ s/^\s+//g;
            if ( grep( /default/i, $_ ) ) {
                ( undef, undef, $gwip, undef, undef, undef, undef ) =
                  split( /\s+/, $_ );
                chomp($gwip);
                push( @GWlist, $gwip );
                $lanok++;
            }
        }
        close(LAN);
    }
    else {
        print "$WARNSTR Cannot run netstat\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run netstat\n");
    }

    if ( $lanok == 0 ) {
        print "\n$WARNSTR Default static route missing\n";
        push(@CHECKARR, "\n$WARNSTR Default static route missing\n");
        $warnings++;
    }
    elsif ( $lanok == 1 ) {
        print "\n$PASSSTR Default static route defined\n";
        foreach $host (@GWlist) {
            my $PING = 0;
            ( undef, undef, undef, undef, @addrs ) = gethostbyname($host);
            foreach my $a (@addrs) {
                $HostIP = join( '.', unpack( 'C4', $a ) );
            }

            if ( !defined($HostIP) ) {
                print
"$WARNSTR Check hostname resolution for server \"$host\"\n";
            }

            # First check if the server is responding to ICMP...
            #
            $h = Net::Ping->new();
            if ( !$h->ping($host) ) {
                print
"$WARNSTR Default route $host is NOT reachable (first type ICMP)\n";
                $PING++;
            }
            else {
                print
"$PASSSTR Default route $host is reachable (first type ICMP)\n";
            }
            $h->close();

            # Second type of ping test.
            #
            $h = Net::Ping->new("icmp");
            if ( !$h->ping( $host, 2 ) ) {
                print
"$WARNSTR Default route $host is NOT reachable (second type ICMP)\n";
                $PING++;
            }
            else {
                print
"$PASSSTR Default route $host is reachable (second type ICMP)\n";
            }
            $h->close();

            # Third type of ping test.
            #
            $h = Net::Ping->new( "tcp", 2 );
            while ( $stop_time > time() ) {
                print
"$WARNSTR Default route $host is NOT not reachable (TCP ping)",
                  scalar( localtime() ), "\n"
                  unless $h->ping($host);
                $PING++;
            }
            undef($h);

            # Now, check the ports.
            #
            if ( $PING >= 2 ) {
                print "$WARNSTR Default gateway not reachable or ";
                print "ICMP blocked\n";
            }
        }
    }

    foreach my $IPl (@IPMParray) {
        chomp($IPl);
        if ( -s "$IPl" ) {
            print "\n$INFOSTR Configuration file $IPl\n";
            my @IPcat = `cat $IPl`;
            if ("@IPcat") {
                print @IPcat;
            }
        }
        else {
            print "\n$WARNSTR Configuration file $IPl empty\n";
            $warnings++;
        }
    }

    if ( -s "$NDPDCONF" ) {
        if ( open( RNZ, "egrep -v ^# $NDPDCONF |" ) ) {
            print "\n$INFOSTR IPv6 neighbour discovery protocol setup in $NDPDCONF\n";
            while (<RNZ>) {
                next if grep( /^$/, $_ );
                print $_;
            }
            close(RNZ);
        }
    }
    else {
        print "\n$INFOSTR IPv6 neighbour discovery protocol $NDPDCONF empty\n";
    }

    my @AParray = `apconfig -v`;
    if ("@AParray") {
        print "\n$INFOSTR Alternate Pathing (AP) is active\n";
        print @AParray;

        my @APDarray = `apconfig -D`;
        if ("@APDarray") {
            print "\n$INFOSTR Alternate Pathing database layout\n";
            print @APDarray;
        }

        my @APSarray = `apconfig -S`;
        if ("@APSarray") {
            print "\n$INFOSTR Alternate Pathing for disks\n";
            print @APSarray;
        }

        my @APNarray = `apconfig -N`;
        if ("@APNarray") {
            print "\n$INFOSTR Alternate Pathing for networks\n";
            print @APNarray;
        }
    }

    my @Trunkarray = `nettr -conf`;
    my $trunkcf    = '/etc/opt/SUNWconn/bin/nettr.sh';
    if ("@Trunkarray") {
        print "\n$INFOSTR Sun Trunking configuration\n";
        print @Trunkarray;
        if ( -s "$trunkcf" ) {
            print "\n$INFOSTR Sun Trunking configuration file $trunkcf\n";
            my @nettrst = `cat $trunkcf`;
            print @nettrst;
        }
        else {
            print "\n$INFOSTR Sun Trunking configuration file $trunkcf empty
or non-existent\n";
        }
    }
    else {
        print "\n$INFOSTR Sun Trunking is not configured\n";
    }

    if ( "$IPMP_FLAG" > 0 ) {
        print "\n$INFOSTR IP Multi Pathing (IPMP) is active\n";

        if ( -s "$MPATHDconf" ) {
            print "\n$INFOSTR Configuration file $MPATHDconf\n";
            my @MPcat = `nawk '! /^#/ && ! /awk/ {print}' $MPATHDconf | nawk NF`;
            if ("@MPcat") {
                print @MPcat;
            }
        }
        else {
            print "\n$WARNSTR Configuration file $MPATHDconf empty\n";
            push(@CHECKARR, "\n$WARNSTR Configuration file $MPATHDconf empty\n");
            $warnings++;
        }
    }
    else {
        my @IPMPS = `ipmpstat -nt 2>/dev/null`;
        if ( "@IPMPS" ) {
            print "\n$INFOSTR IP Multi Pathing (IPMP) is active\n";
            print @IPMPS;
        } 
        else {
            print "\n$WARNSTR IP Multi Pathing (IPMP) is not configured\n";
            push(@CHECKARR, "\n$WARNSTR IP Multi Pathing (IPMP) is not configured\n");
            $warnings++;
        }
    }

    my @hippis = `hippi status 2>/dev/null`;
    if ( "@hippis" ) {
        print "\n$INFOSTR High Performance Parallel Interface (HIPPI) status\n";
        print @hippis;

        my @hippic = `hippistat 2>/dev/null`;
        if ( "@hippic" ) {
            print "\n$INFOSTR High Performance Parallel Interface (HIPPI) statistics\n";
            print @hippic;
        }

        my @hippia = `hippiarp -a 2>/dev/null`;
        if ( "@hippia" ) {
            print "\n$INFOSTR High Performance Parallel Interface (HIPPI) network status\n";
            print @hippia;
        }
    }

    foreach my $myndd (@NDDarrs) {
        my @NDset = ();
        my @NDy   = ();
        if ( open( NC, "ndd $myndd \? 2>/dev/null |" ) ) {
            while (<NC>) {
                next if grep( /\?/,       $_ );
                next if grep( /^$/,       $_ );
                next if grep( /obsolete/, $_ );
                ( $nddflag, undef ) = split( /\s+/, $_ );
                chomp($nddflag);
                $nddflag =~ s/^\s+//g;
                $nddflag =~ s/\(*//g;
                push( @NDset, $nddflag );
            }
            close(NC);
        }
        else {
            print "\n$WARNSTR Cannot list $myndd network parameters\n";
            $warnings++;
        }

        if ("@NDset") {
            print "\n$INFOSTR $myndd network parameters\n";
            foreach my $ndz (@NDset) {
                @NDy = `ndd $myndd $ndz 2>/dev/null`;
                print "$myndd $ndz: @NDy";
            }
        }
    }

    my @IPADMP = `ipadm show-prop 2>/dev/null`;
    if ("@IPADMP") {
        print "\n$INFOSTR Ipadm tunables\n";
        print @IPADMP;
    }

    my @neti = `netstat -an 2>/dev/null`;
    if ("@neti") {
        print "\n$INFOSTR Active connections\n";
        print @neti;
    }

    my @nets = `netstat -s 2>/dev/null`;
    if ("@nets") {
        print "\n$INFOSTR Summary statistics for each protocol\n";
        print @nets;
    }

    my @TCPSTAT = `tcpstat -c 1 2>/dev/null`;
    if ("@TCPSTAT") {
        print "\n$INFOSTR Tcpstat statistics\n";
        print @TCPSTAT;
    }

    my @IPSTAT = `ipstat -c 1 2>/dev/null`;
    if ("@IPSTAT") {
        print "\n$INFOSTR Ipstat statistics\n";
        print @IPSTAT;
    }

    my @ARPA = `arp -a 2>/dev/null`;
    if ("@ARPA") {
        print "\n$INFOSTR ARP table\n";
        print @ARPA;
    }

    if ( open( NETN, "netstat -in |" ) ) {
        print "\n$INFOSTR Network errors and collisions\n";
        while (<NETN>) {
            $_ =~ s/^\s+//g;
            next if grep( /^$/, $_ );
            print $_;
            next if ( grep( /Mtu/, $_ ) );
            (
                $Lname, $Lmtu,  $Lnet,  $Laddr, $Lipkt,
                $Lierr, $Lopkt, $Loerr, $Lcoll, $Lqueu
              )
              = split( /\s+/, $_ );

            if ( grep( /lan/, $Lname ) ) {
                if ( "$Lmtu" == $DefMTU ) {
                    push(@LANARR,
"$PASSSTR Interface $Lname has default MTU ($DefMTU)\n");
                }
                else {
                    push(@LANARR,
"$WARNSTR Interface $Lname has non-default MTU ($Lmtu instead of $DefMTU)\n");
                    push(@CHECKARR,
"\n$WARNSTR Interface $Lname has non-default MTU ($Lmtu instead of $DefMTU)\n");
                    $warnings++;
                }
            }

            if ( "$Lcoll" > 0 ) {
                push(@LANARR, "$WARNSTR Collisions on interface $Lname\n");
                push(@CHECKARR, "\n$WARNSTR Collisions on interface $Lname\n");
                $warnings++;
            }
            else {
                push(@LANARR, "$PASSSTR No collisions on interface $Lname\n");
            }

            if ( "$Lierr" > 0 ) {
                push(@LANARR, "$WARNSTR Input errors on interface $Lname\n");
                push(@CHECKARR, "\n$WARNSTR Input errors on interface $Lname\n");
                $warnings++;
            }
            else {
                push(@LANARR, "$PASSSTR No input errors on interface $Lname\n");
            }

            if ( "$Loerr" > 0 ) {
                push(@LANARR, "$WARNSTR Output errors on interface $Lname\n\n");
                push(@CHECKARR, "\n$WARNSTR Output errors on interface $Lname\n");
                $warnings++;
            }
            else {
                push(@LANARR, "$PASSSTR No output errors on interface $Lname\n\n");
            }
        }
        close(NETN);
    }

    if ( "@LANARR" ) {
        print "\n@LANARR";
    }

    my @dlnet = `dladm show-link 2>/dev/null`;
    if ("@dlnet") {
        print "\n$INFOSTR Data-Link link status\n";
        print @dlnet;
    }

    my @dladm = `dladm show-dev 2>/dev/null`;
    if ("@dladm") {
        print "\n$INFOSTR Data-Link device status\n";
        print @dladm;
    }

    my @dladmp = `dladm show-phys 2>/dev/null`;
    if ("@dladmp") {
        print "\n$INFOSTR Data-Link physical device status\n";
        print @dladmp;
    }

    my @dlstat = `dlstat -a 2>/dev/null`;
    if ("@dlstat") {
        print "\n$INFOSTR Data-Link statistics\n";
        print @dlstat;
    }

    my @dladmib = `dladm show-part 2>/dev/null`;
    if ("@dladmib") {
        print "\n$INFOSTR Data-Link Infiniband device status\n";
        print @dladmib;

        my @ibs = `ibstatus 2>/dev/null`;
        if ("@ibs") {
            print "\n$INFOSTR Infiniband query basic status\n";
            print @ibs;
        }

        my @iblnk = `iblinkinfo 2>/dev/null`;
        if ("@iblnk") {
            print "\n$INFOSTR Infiniband link information\n";
            print @iblnk;
        }

        my @ibchks = `ibcheckstate 2>/dev/null`;
        if ("@ibchks") {
            print "\n$INFOSTR Infiniband check state\n";
            print @ibchks;
        }
    }

    my @dladmiv = `dladm show-vlan 2>/dev/null`;
    if ("@dladmiv") {
        print "\n$INFOSTR Data-Link VLAN device status\n";
        print @dladmiv;
    }

    datecheck();
    print_header("*** END CHECKING NETWORK SETUP $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING DIALUP CONFIGURATION $datestring ***");

    my @Remoteconf = `nawk NF $REMOTECONF`;
    if ("@Remoteconf") {
        print "$INFOSTR Configuration file $REMOTECONF\n";
        print @Remoteconf;
    }
    else {
        print "$INFOSTR $REMOTECONF not configured\n";
    }

    my @uucpsys = `nawk '! /^#/ && ! /awk/ {print}' $UUCPSYS | nawk NF`;
    if ("@uucpsys") {
        print "\n$INFOSTR Configuration file $UUCPSYS\n";
        print @uucpsys;
    }
    else {
        print "\n$INFOSTR $UUCPSYS not configured\n";
    }

    my @uucpdia = `nawk '! /^#/ && ! /awk/ {print}' $UUCPDIA | nawk NF`;
    if ("@uucpdia") {
        print "\n$INFOSTR Configuration file $UUCPDIA\n";
        print @uucpdia;
    }
    else {
        print "\n$INFOSTR $UUCPDIA not configured\n";
    }

    my @uucpdev = `nawk '! /^#/ && ! /awk/ {print}' $UUCPDEV | nawk NF`;
    if ("@uucpdev") {
        print "\n$INFOSTR Configuration file $UUCPDEV\n";
        print @uucpdev;
    }
    else {
        print "\n$INFOSTR $UUCPDEV not configured\n";
    }

    my @pppconf = `nawk '! /^#/ && ! /awk/ {print}' $PPPCONF | nawk NF`;
    if ("@pppconf") {
        print "\n$INFOSTR Configuration file $PPPCONF\n";
        print @pppconf;
    }
    else {
        print "\n$INFOSTR $PPPCONF not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING DIALUP CONFIGURATION $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING IP FORWARDING CONFIGURATION $datestring ***");

    my @routeadmconf = `routeadm -p 2>/dev/null`;
    if ("@routeadmconf") {
        print @routeadmconf;
    }
    else {
        print "$INFOSTR IP forwarding and routing not defined\n";
    }

    datecheck();
    print_header("*** END CHECKING IP FORWARDING CONFIGURATION $datestring ***");
}

#
# Subroutine to check Unix systems accounting
#
sub sachk {
    datecheck();
    print_header("*** BEGIN CHECKING UNIX SYSTEM ACCOUNTING $datestring ***");

    if ( !-d "$UXSA" ) {
        print "$WARNSTR System accounting directory $UXSA missing\n";
        push(@CHECKARR, "\n$WARNSTR System accounting directory $UXSA missing\n");
        $warnings++;
    }
    else {
        print "$PASSSTR System accounting directory $UXSA exists\n";
        if ( opendir( SSDIR, "$UXSA" ) ) {
            while ( $fileux = readdir(SSDIR) ) {
                next if ( $fileux eq ".." || $fileux eq "." );
                $accnomb++;
                (
                    $dev,   $ino,     $mode, $nlink, $uid,
                    $gid,   $rdev,    $size, $atime, $mtime,
                    $ctime, $blksize, $blocks
                  )
                  = stat($fileux);
            }
            closedir(SSDIR);
        }
        else {
            print "$WARNSTR Cannot open directory $UXSA\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open directory $UXSA\n");
        }
    }

    if ( $accnomb == 0 ) {
        print "$WARNSTR System accounting not running\n";
        push(@CHECKARR, "\n$WARNSTR System accounting not running\n");
        $warnings++;
    }
    else {
        print "$PASSSTR System accounting seemingly running\n";
        $accnomb = 0;

        if ( opendir( SSDIR, "$UXSA" ) ) {
            while ( $fileux = readdir(SSDIR) ) {
                next if ( $fileux eq ".." || $fileux eq "." );
                $accnomb++;
                $finalsa = $fileux;
            }
            closedir(SSDIR);
        }
        else {
            print "$WARNSTR Cannot open directory $UXSA\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open directory $UXSA\n");
        }

        (
            $dev,   $ino,     $mode, $nlink, $uid,
            $gid,   $rdev,    $size, $atime, $mtime,
            $ctime, $blksize, $blocks
        )
        = stat("$UXSA/$finalsa");

        my $DAYCK  = 7;
        my $HOWOLD = 24 * 3600 * $DAYCK;    # 24 hours x 3600 minutes x 7 days
        if ( ( $EPOCHTIME - $mtime ) > $HOWOLD ) {
            print "$WARNSTR System accounting last ran more than $DAYCK ";
            print "days ago\n";
            push(@CHECKARR, "\n$WARNSTR System accounting last ran more than $DAYCK ");
            push(@CHECKARR, "days ago\n");
            $warnings++;
        }
    }

    if ( "$Minor" >= 10 ) {
        my @acctadm = `acctadm 2>/dev/null`;

        if ("@acctadm") {
            print "\n$INFOSTR Extended accounting facility\n";
            print @acctadm;
        }
    }

    datecheck();
    print_header("*** END CHECKING UNIX SYSTEM ACCOUNTING $datestring ***");
}

#
# Subroutine to check timezone
#
sub timezone_info {
    datecheck();
    print_header("*** BEGIN CHECKING TIMEZONE $datestring ***");

    if ( "$IsDST" == 1 ) {
        print
"$INFOSTR Daylight Savings Time set to $IsDST (currently active)\n";
    }
    elsif ( "$IsDST" == 0 ) {
        print
"$INFOSTR Daylight Savings Time set to $IsDST (currently not active)\n";
    }
    else {
        print "$INFOSTR Daylight Savings Time undefined\n";
    }

    my $tzcur  = $ENV{'TZ'};
    if ("$tzcur") {
        print "$INFOSTR Server is in timezone $tzcur\n";
    }

    if ( -s "$tzfile" ) {
        if ( open( TZZ, "nawk NF $tzfile |" ) ) {
            print "\n$INFOSTR Timezone configuration file $tzfile\n";
            while (<TZZ>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                if ( grep( /^TZ/, $_ ) ) {
                    ( undef, $TZent ) = split( /=/, $_ );
                    $TZent =~ s/^\s+//g;
                    chomp($TZent);
                }
                print $_;
            }
        }
        close(TZZ);
    }

    datecheck();
    print_header("*** END CHECKING TIMEZONE $datestring ***");
}

#
# Subroutine to check Samba
#
sub samba_info {
    datecheck();
    print_header("*** BEGIN CHECKING SAMBA $datestring ***");

    my @SAMBAarr = `testparm -s`;

    if ("@SAMBAarr") {
        print "$INFOSTR Samba seemingly installed\n";
        print @SAMBAarr;
        my @SAMBAconf = `smbstatus | nawk NF`;
        if ("@SAMBAconf") {
            print @SAMBAconf;
        }
    }
    else {
        print "$INFOSTR Samba seemingly not active\n";
    }

    datecheck();
    print_header("*** END CHECKING SAMBA $datestring ***");
}

#
# Subroutine to check standard Unix printing
#
sub lp_info {
    datecheck();
    print_header("*** BEGIN CHECKING UNIX PRINTING $datestring ***");

    my @CUPSlp  = `lpinfo -v`;
    my @LPRnglp = `checkpc -V`;

    if ("@CUPSlp") {
        print "\n$INFOSTR CUPS printing seemingly installed\n";
        print @CUPSlp;
        $LPSTAND++;

        my @cupsls = `ls $CUPSDIR/* 2>/dev/null`;
        foreach my $cupsf (@cupsls) {
            chomp($cupsf);
            if ( -s $cupsf ) {
                print "\n$INFOSTR Configuration file $cupsf\n";
                my @csfg = `nawk NF $cupsf`;
                print @csfg;
            }
        }
    }

    if ("@LPRnglp") {
        print "\n$INFOSTR LPRng printing seemingly installed\n";
        print @LPRnglp;
        $LPSTAND++;
    }

    if ( "$LPSTAND" == 0 ) {
        print "\n$INFOSTR Standard LP printing seemingly installed\n";
    }

    if ( "$LPSCHED" > 0 ) {
        my @LParr = `lpstat -a 2>/dev/null`;
        if ("@LParr") {
            print "\n$INFOSTR Printing seemingly active\n";
            print @LParr;
        }
        else {
            print "\n$INFOSTR Printing enabled but queues not defined\n";
        }
    }
    else {
        print "\n$INFOSTR Printing seemingly not active\n";
    }

    my @LPQ = `lpq -a -l 2>/dev/null`;
    if ("@LPQ") {
        print "\n$INFOSTR Printer job queue status\n";
        print @LPQ;
    }

    my @CUPSCTL = `cupsctl 2>/dev/null`;
    if ("@CUPSCTL") {
        print "\n$INFOSTR CUPS settings\n";
        print @CUPSCTL;
    }
    datecheck();
    print_header("*** END CHECKING UNIX PRINTING $datestring ***");
}

#
# Subroutine to check OpenView-based monitoring
#
sub OVchk {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK NODE MANAGER $datestring ***");

    if ( grep( /NNM|Network Node Manager/, @SWarray ) ) {
        print "\n$INFOSTR Network Node Manager bundles seemingly installed\n";

        my @OVtopodump = `ovtopodump -s -l 2>/dev/null`;
        if ( @OVtopodump != 0 ) {
            print "\n$INFOSTR OV Network Node Manager server topology\n";
            print @OVtopodump;
        }

        my @OVtopodump2 = `ovtopodump -s 2>/dev/null`;
        if ( @OVtopodump2 != 0 ) {
            print "\n$INFOSTR OV Network Node Manager whole topology\n";
            print @OVtopodump2;
        }

        my @rnetstat = `rnetstat -n 2>/dev/null`;
        if ( @rnetstat != 0 ) {
            print "\n$INFOSTR OV Network Node Manager network status\n";
            print @rnetstat;
        }

        my @rlist = `request_list schedule 2>/dev/null`;
        if ( @rlist != 0 ) {
            print "\n$INFOSTR OV Network Node Manager schedule status\n";
            print @rlist;
        }

        my @OVobjprint = `ovobjprint -S 2>/dev/null`;
        if ( @OVobjprint != 0 ) {
            print "\n$INFOSTR OV Network Node Manager objects\n";
            print @OVobjprint;
        }

        my @OVfilter = `ovfiltercheck -v 2>/dev/null`;
        if ( @OVfilter != 0 ) {
            print "\n$INFOSTR OV Network Node Manager filter check\n";
            print @OVfilter;
        }

        my @OVwls = `owvls 2>/dev/null`;
        if ( @OVwls != 0 ) {
            print "\n$INFOSTR OV Network Node Manager maps\n";
            print @OVwls;
        }
    }
    else {
        print "\n$INFOSTR Network Node Manager seemingly not running (software bundles missing)\n";
    }
    
    datecheck();
    print_header("*** END CHECKING NETWORK NODE MANAGER $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING OPENVIEW MONITORING $datestring ***");

    if ( -s $OPCinfo ) {
        if ( open( OPCI, "cat $OPCinfo 2>/dev/null |" ) ) {
            print "$INFOSTR Configuration file $OPCinfo\n";
            while (<OPCI>) {
                next if ( grep( /^#/, $_ ) );
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(OPCI);
        }
        else {
            print "\n$WARNSTR Configuration file $OPCinfo missing\n";
            $warnings++;
        }
    }
    else {
        print "\n$INFOSTR Configuration file $OPCinfo missing or empty\n";
    }

    if ( -s $NODEinfo ) { 
        if ( open( NODEI, "cat $NODEinfo 2>/dev/null |" ) ) {
            print "\n$INFOSTR Configuration file $NODEinfo\n";
            while (<NODEI>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close(NODEI);
        }
        else {
            print "\n$WARNSTR Configuration file $NODEinfo missing\n";
            $warnings++;
        }
    }
    else {
        print "\n$WARNSTR Configuration file $NODEinfo missing or empty\n";
    }

    if ( -s $MGRCONF ) { 
        if ( open( MGRC, "egrep -v ^# $MGRCONF 2>/dev/null |" ) ) {
            print
"\n$INFOSTR Configuration file $MGRCONF for NAT Management Server\n";
            while (<MGRC>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(MGRC);
        }
        else {
            print "\n$INFOSTR Configuration file $MGRCONF missing\n";
        }
    }
    else {
        print "\n$INFOSTR Configuration file $MGRCONF missing or empty\n";
    }

    my @OVver = `opcctla -type -verbose 2>/dev/null`;
    if ( @OVver != 0 ) {
        print "\n$INFOSTR OV Toolkit version\n";
        print @OVver;
    }

    @OVget = `opcagt -status 2>&1`;
    if ("@OVget") {
        print "\n$PASSSTR OV Toolkit installed\n";
        print @OVget;
    }
    else {
        print "\n$WARNSTR OV Toolkit installed but not running\n";
        $warnings++;
    }

    my $ITOres = "/tmp/ito_rpt_agt/ITO.rpt";

    my @tocheck1 = `echo 1 | itochecker_agt 2>/dev/null`;

    if ( @tocheck1 ) {
        if ( -s "$ITOres" ) {
            my @prITOres = `nawk NF $ITOres`;
            if ( "@prITOres" ) {
                print "\n$INFOSTR OV Toolkit system environment check\n";
                print @prITOres;
            }
        }
    }

    if ( -s "$ITOres" ) {
        unlink $ITOres;
    }

    my @tocheck2 = `echo 2 | itochecker_agt 2>/dev/null`;

    if ( @tocheck2 ) {
        if ( -s "$ITOres" ) {
            my @prITOres = `nawk NF $ITOres`;
            if ( "@prITOres" ) {
                print "\n$INFOSTR OV Toolkit log and configuration check\n";
                print @prITOres;
            }
        }
    }

    datecheck();
    print_header("*** END CHECKING OPENVIEW MONITORING $datestring ***");

    if ( @OVget != 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING OPENVIEW AND SMSPI TEST ALERTS $datestring ***");

        my @ovalert = `poptestticket 2>/dev/null`;
        my @smspialert = `smspi -test 2>/dev/null`;
        print
"$INFOSTR Verify the Cases were raised on the back-end monitoring server\n";

        datecheck();
        print_header("*** END CHECKING OPENVIEW AND SMSPI TEST ALERTS $datestring ***");
    }
}

#
# Subroutine to check cleanup of /tmp at boot
#
sub tmpcleanupcheck {
    datecheck();
    print_header("*** BEGIN CHECKING /tmp CLEANUP AT BOOT $datestring ***");

    if ( "$Minor" >= 10 ) {
        @svcstmp = `svcs rmtmpfiles | egrep online 2>/dev/null`;
        if ( "@svcstmp" ) {
            print "$INFOSTR File system /tmp cleanup scheduled at boot\n";
            print @svcstmp;
        }
        else {
            print
"$INFOSTR File system /tmp cleanup seemingly not scheduled at boot\n";
        }
    }
    else {
        if ( ( -x "$TMPCLEAN1" ) && ( -x "$TMPCLEAN2" ) ) {
            print "$INFOSTR File system /tmp cleanup scheduled at boot\n";
        }
        else {
            print
"$INFOSTR File system /tmp cleaning seemingly not scheduled at boot\n";
        }
    }

    datecheck();
    print_header("*** END CHECKING /tmp CLEANUP AT BOOT $datestring ***");
}

#
# Subroutine to check vendor backup configuration
#
sub vendorbck {
    datecheck();
    print_header("*** BEGIN CHECKING VENDOR-BASED BACKUPS $datestring ***");

    if ( !-s "$DUMPDATES" ) {
        print "$INFOSTR Ufsdumps of file systems seemingly not running\n";
    }
    else {
        print "$INFOSTR Ufsdumps of file systems seemingly running\n";
        my @DDT = `cat $DUMPDATES`;
        print @DDT;
    }

    if ( -d "$NETBCKDIR1" ) {
        $NETBCKDIR = $NETBCKDIR1;
    }
    elsif ( -d "$NETBCKDIR2" ) {
        $NETBCKDIR = $NETBCKDIR2;
    }
    else {
        print "\n$INFOSTR NetBackup seemingly not installed\n";
    }

    if ("$NETBCKDIR") {
        my $NETBCKVER  = "$NETBCKDIR/netbackup/version";
        my $NETBCKCONF = "$NETBCKDIR/netbackup/bp.conf";

        if ( -s "$NETBCKCONF" ) {
            if ( open( CRM, "nawk NF $NETBCKCONF |" ) ) {
                print "\n$INFOSTR NetBackup seemingly installed\n";
                print "$INFOSTR NetBackup configuration file $NETBCKCONF\n";
                while (<CRM>) {
                    next if ( grep( /^$/, $_ ) );
                    next if ( grep( /^#/, $_ ) );
                    print $_;
                }
            }
            close(CRM);
        }

        if ( -s "$NETBCKVER" ) {
            if ( open( BRM, "nawk NF $NETBCKVER |" ) ) {
                print "\n$INFOSTR NetBackup version\n";
                while (<BRM>) {
                    next if ( grep( /^$/, $_ ) );
                    next if ( grep( /^#/, $_ ) );
                    print $_;
                }
            }
            close(BRM);
        }
        else {
            $ENV{'PATH'} = "$ENV{PATH}:$NETBCKDIR/volmgr/bin";

            my @bpps = `bpps -a 2>/dev/null`;
            if (@bpps) {
                print "\n$INFOSTR NetBackup seemingly running\n";
                print @bpps;

                my @vmoprcmd = `vmoprcmd -d 2>/dev/null`;
                if (@vmoprcmd) {
                    print "\n$INFOSTR NetBackup vmoprcmd\n";
                    print @vmoprcmd;
                }

                my @tpconfig = `tpconfig -d 2>/dev/null`;
                if (@tpconfig) {
                    print "\n$INFOSTR NetBackup tpconfig\n";
                    print @tpconfig;
                }

                my @mmck = `mmcrawl 2>&1 | awk NF`;
                if (@mmck) {
                    print "\n$INFOSTR NetBackup consistency check\n";
                    print @mmck;
                }

                my @bpcllist = `bpcllist -L -allpolicies 2>/dev/null`;
                if (@bpcllist) {
                    print "\n$INFOSTR NetBackup policies\n";
                    print @bpcllist;
                }

                my @bpstulist = `bpstulist -L 2>/dev/null`;
                if (@bpstulist) {
                    print "\n$INFOSTR NetBackup media managers\n";
                    print @bpstulist;
                }

                my @bpclclients = `bpclclients -U -allunique 2>/dev/null`;
                if (@bpclclients) {
                    print "\n$INFOSTR NetBackup clients\n";
                    print @bpclclients;
                }

                my @tpclean = `tpclean -l 2>/dev/null`;
                if (@tpclean) {
                    print "\n$INFOSTR NetBackup tape cleaning status\n";
                    print @tpclean;
                }

                my @bpdbjobs = `bpdbjobs -summary 2>/dev/null`;
                if (@bpdbjobs) {
                    print "\n$INFOSTR NetBackup recent backups\n";
                    print @bpdbjobs;
                }

                my @bpsyncinfo = `bpsyncinfo 2>/dev/null`;
                if (@bpsyncinfo) {
                    print "\n$INFOSTR NetBackup DB Index backups\n";
                    print @bpsyncinfo;
                }

                my @checkcov = `check_coverage 2>/dev/null`;
                if (@checkcov) {
                    print "\n$INFOSTR NetBackup check coverage\n";
                    print @checkcov;
                }

                my @availm = `available_media 2>/dev/null`;
                if (@availm) {
                    print "\n$INFOSTR NetBackup check coverage\n";
                    print @availm;
                }

                my @bperror = `bperror -problems -hoursago 24 2>/dev/null`;
                if (@bperror) {
                    print "\n$INFOSTR NetBackup errors for the last 24 hours\n";
                    print @bperror;
                }

                my @bpmedia = `bpmedialist -summary 2>/dev/null`;
                if (@bpmedia) {
                    print "\n$INFOSTR NetBackup media list\n";
                    print @bpmedia;
                }
            }
            else {
                print "\n$INFOSTR NetBackup seemingly not running\n";
            }
        }
    }

    if ( "$TSMSRV_FLAG" > 0 ) {
        print "\n$INFOSTR Tivoli Storage Manager (TSM) server\n";

        my @tsmstatus = `query status 2>/dev/null`;
        if (@tsmstatus) {
            print @tsmstatus;
        }

        my @tsmdb = `query db format=detailed 2>/dev/null`;
        if (@tsmdb) {
            print "\n$INFOSTR TSM database status\n";
            print @tsmdb;
        }

        my @tsmdom = `query domain \* 2>/dev/null`;
        if (@tsmdom) {
            print "\n$INFOSTR TSM domain status\n";
            print @tsmdom;
        }

        my @tsmpool = `query stgpool format=detailed 2>/dev/null`;
        if (@tsmpool) {
            print "\n$INFOSTR TSM storage pool status\n";
            print @tsmpool;
        }

        my @tsmdrive = `query drive 2>/dev/null`;
        if (@tsmdrive) {
            print "\n$INFOSTR TSM drive status\n";
            print @tsmdrive;
        }
    }
    else {
        print
"\n$INFOSTR Tivoli Storage Manager (TSM) server seemingly not installed\n";
    }

    if ( "$TSMCL_FLAG" > 0 ) {
        print "\n$INFOSTR Tivoli Storage Manager (TSM) client installed\n";
    }
    else {
        print
"\n$INFOSTR Tivoli Storage Manager (TSM) client seemingly not installed\n";
    }

    my $NETWKCONF = "/etc/init.d/networker";
    if ( -s "$NETWKCONF" ) {
        print "\n$INFOSTR NetWorker startup script $NETWKCONF exists\n";

        if (
            open( NSR, "echo \"show\nprint type:NSR client\" | nsradmin -i - 2>/dev/null |"
            )
          )
        {
            print "$INFOSTR NetWorker seemingly installed\n";
            while (<NSR>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(NSR);

            my @mminfo = `mminfo -m 2>/dev/null | awk NF`;
            if (@mminfo) {
                print "\n$INFOSTR NetWorker media status\n";
                print @mminfo;
            }

            my @nsrall = `echo \"show\nprint type:nsr\" | nsradmin -i - 2>/dev/null`;
            if (@nsrall) {
                print "\n$INFOSTR NetWorker status for NSR\n";
                print @nsrall;
            }

            my @nsrsch = `echo \"show\nprint type:nsr schedule\" | nsradmin -i - 2>/dev/null`;
            if (@nsrsch) {
                print "\n$INFOSTR NetWorker status for NSR schedule\n";
                print @nsrsch;
            }

            my @nsrpol = `echo \"show\nprint type:nsr policy\" | nsradmin -i - 2>/dev/null`;
            if (@nsrpol) {
                print "\n$INFOSTR NetWorker status for NSR policy\n";
                print @nsrpol;
            }

            my @nsrpool = `echo \"show\nprint type:nsr pool\" | nsradmin -i - 2>/dev/null`;
            if (@nsrpool) {
                print "\n$INFOSTR NetWorker status for NSR pool\n";
                print @nsrpool;
            }

            my @nsrstage = `echo \"show\nprint type:nsr stage\" | nsradmin -i - 2>/dev/null`;
            if (@nsrstage) {
                print "\n$INFOSTR NetWorker status for NSR stage\n";
                print @nsrstage;
            }

            my @nsrdir = `echo \"show\nprint type:nsr directive\" | nsradmin -i - 2>/dev/null`;
            if (@nsrdir) {
                print "\n$INFOSTR NetWorker status for NSR directive\n";
                print @nsrdir;
            }
        }
    }
    else {
        print "\n$INFOSTR NetWorker seemingly not installed\n";
    }

    if ( $OMNI_FLAG == 1 ) {
        print "\n$INFOSTR Data Protector seemingly installed\n";

        if ( -s "$dpck" ) {
            my @is_cellmgr = `egrep ^$Hostname $dpck | cut -d. -f1`;
            if ( @is_cellmgr != 0 ) {
                if ( "$dpcw" ) {
                    print "\n$INFOSTR Data Protector file $dpcw exists\n";
                    my @DPCW = `cat $dpcw`;
                    print @DPCW;
                }
            }
        }

        if ( -s "$dpoptions" ) {
            my @dpopt = `awk NF $dpoptions 2>/dev/null`;
            if ( @dpopt != 0 ) {
                print "\n$INFOSTR Data Protector file $dpoptions\n";
                print @dpopt;
            }
        }

        if ( -s "$DPusers" ) {
            my @dpusr = `awk NF $DPusers 2>/dev/null`;
            if ( @dpusr != 0 ) {
                print "\n$INFOSTR Data Protector file $DPusers\n";
                print @dpusr;
            }
        }

        if ( -s "$CSusers" ) {
            my @csusr = `awk NF $CSusers 2>/dev/null`;
            if ( @csusr != 0 ) {
                print "\n$INFOSTR Data Protector file $CSusers\n";
                print @csusr;
            }
        }

        if ( -s "$dpcellinfo" ) {
            my @dpcl1 = `awk NF $dpcellinfo 2>/dev/null`;
            if ( @dpcl1 != 0 ) {
                print "\n$INFOSTR Data Protector file $dpcellinfo\n";
                print @dpcl1;
            }
        }

        if ( -s "$dpinstsrvs" ) {
            my @dpcl2 = `awk NF $dpinstsrvs 2>/dev/null`;
            if ( @dpcl2 != 0 ) {
                print "\n$INFOSTR Data Protector file $dpinstsrvs\n";
                print @dpcl2;
            }
        }

        my @dpck = `omnicellinfo -cell 2>&1 | nawk NF`;
        if (@dpck) {
            print "\n$INFOSTR Data Protector configuration status\n";
            print @dpck;
        }

        my @omnidbutil = `omnidbutil -show_cell_name 2>/dev/null`;
        if (@omnidbutil) {
            print "\n$INFOSTR Data Protector Cell Manager\n";
            print @omnidbutil;
        }

        my @omnisv = `omnisv status 2>/dev/null`;
        if ( "@omnisv" ) {
            print "\n$INFOSTR Data Protector Cell Manager services\n";
            print @omnisv;
        }

        my @dpck1 = `omnicc 2>&1 | nawk NF`;
        if (@dpck1) {
            print "\n$INFOSTR Data Protector client configuration status\n";
            print @dpck1;
        }

        my @dptapeck = `devbra -dev 2>&1 | nawk NF`;
        if (@dptapeck) {
            print "\n$INFOSTR Data Protector tape configuration status\n";
            print @dptapeck;
        }

        my @omnirpts = `omnirpt -report dl_sched 2>/dev/null`;
        if (@omnirpts) {
            print "\n$INFOSTR Data Protector schedules\n";
            print @omnirpts;
        }

        my @omnirpti = `omnirpt -report dl_info 2>/dev/null`;
        if (@omnirpti) {
            print "\n$INFOSTR Data Protector specifications\n";
            print @omnirpti;
        }

        my @omnitrig = `omnitrig -run_checks 2>/dev/null`;
        if (@omnitrig) {
            print "\n$INFOSTR Data Protector trigger scheduled backup status\n";
            print @omnitrig;
        }

        my @omnirptd = `omnirpt -report db_size 2>/dev/null`;
        if (@omnirptd) {
            print "\n$INFOSTR Data Protector internal DB status\n";
            print @omnirptd;
        }

        my @omnimm = `omnimm -list_pools 2>/dev/null`;
        if (@omnimm) {
            print "\n$INFOSTR Data Protector pools\n";
            print @omnimm;
        }

        my @omnidownload = `omnidownload -list_devices -detail 2>/dev/null`;
        if (@omnidownload) {
            print "\n$INFOSTR Data Protector omnidownload device status\n";
            print @omnidownload;
        }

        my @omnidownloadd = `omnidownload -dev_info 2>/dev/null`;
        if (@omnidownloadd) {
            print "\n$INFOSTR Data Protector omnidownload device info status\n";
            print @omnidownloadd;
        }

        my @omnidownloadl = `omnidownload -list_libraries -detail 2>/dev/null`;
        if (@omnidownloadl) {
            print "\n$INFOSTR Data Protector omnidownload library status\n";
            print @omnidownloadl;
        }

        my @sanconf = `sanconf -list_devices -hosts $Hostname 2>/dev/null`;
        if (@sanconf) {
            print "\n$INFOSTR Data Protector sanconf status\n";
            print @sanconf;
        }

        my @omnidbutilsl = `omnidbutil -show_locked_devs 2>/dev/null`;
        if (@omnidbutilsl) {
            print "\n$INFOSTR Data Protector locked devices\n";
            print @omnidbutilsl;
        }
    }
    else {
        print "\n$INFOSTR Data Protector seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING VENDOR-BASED BACKUPS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING FILE SYSTEM SNAPS $datestring ***");

    my @fssnap = `fssnap -i 2>/dev/null`;
    if ("@fssnap") {
        print "$INFOSTR File system snapshots\n";
        print @fssnap;
    }
    else {
        print "$INFOSTR No file system snapshots currently defined\n";
    }

    my @zfssnap = `zfs list -t snapshot 2>/dev/null`;
    if ("@zfssnap") {
        print "\n$INFOSTR ZFS snapshots\n";
        print @zfssnap;
    }
    else {
        print "$INFOSTR No ZFS snapshots currently defined\n";
    }

    datecheck();
    print_header("*** END CHECKING FILE SYSTEM SNAPS $datestring ***");
}

#
# Subroutine for port monitor
#
sub portcheck {
    datecheck();
    print_header("*** BEGIN CHECKING PORT MONITOR $datestring ***");

    my @listpath = `pmadm -l`;
    if ("@listpath") {
        print @listpath;
    }
    else {
        print "$INFOSTR No ports to monitor\n";
    }

    datecheck();
    print_header("*** END CHECKING PORT MONITOR $datestring ***");
}

#
# Subroutine to check FRU power status
#
sub frucheck {
    datecheck();
    print_header("*** BEGIN CHECKING FRU STATUS $datestring ***");

    my @fruce = `prtfru`;

    if ("@fruce") {
        print @fruce;
    }
    else {
        print "$INFOSTR This platform does not provide FRU ID data\n";
    }

    datecheck();
    print_header("*** END CHECKING FRU STATUS $datestring ***");
}

#
# Subroutine to check LOCALE
#
sub localecheck {
    datecheck();
    print_header("*** BEGIN CHECKING LOCALES $datestring ***");

    if ( "$Minor" >= 10 ) {
        my @localelock = `ls /var/run/localeadm.lock* 2>/dev/null`;
        if ( "@localelock" ) {
            print "$WARNSTR Localeadm lock file(s) exist\n";
            print "$INFOSTR Recommended to remove them\n";
            print @localelock;
        }
        else {
            @alllocales = `localeadm -lc`;
        }
    }
    else {
        @alllocales = `locale -a`;
    }

    if ("@alllocales") {
        print "$INFOSTR Available locales\n";
        print @alllocales;
    }

    my @loccur = `locale`;

    if ("@loccur") {
        print "\n$INFOSTR Current system-wide LOCALE\n";
        print @loccur;
    }

    datecheck();
    print_header("*** END CHECKING LOCALES $datestring ***");
}

# Is the IP address valid
# For example, 300.201.33.12 is INVALID
#
sub CheckIP {
    my $ip = shift;
    my ( $addrs, $rev_ip );
    ( $addrs = inet_aton($ip) ) and ( $rev_ip = inet_ntoa($addrs) );
    return ( defined($addrs) and defined($rev_ip) and $ip eq $rev_ip );
}

#
# Subroutine to check RSC (MP) status
#
sub RSCcheck {
    my $RSCCK = `/usr/platform/${Model}/rsc/rscadm shownetwork 2>/dev/null`;

    datecheck();
    print_header("*** BEGIN CHECKING RSC CONSOLE $datestring ***");

    if ( open( EEP, "eeprom |" ) ) {
        while (<EEP>) {
            push( @EEPROMarr, $_ );

            if ( grep( /^input-device/, $_ ) ) {
                ( undef, $inputvalue ) = split( /=/, $_ );
                $inputvalue =~ s/^\s+//g;
                chomp($inputvalue);
                if ( "$inputvalue" ne 'rsc-console' ) {
                    print
"\n$WARNSTR Eeprom flag input-device incorrect for RSC (\"$inputvalue\" instead of \"rsc-console\")\n";
                    $warnings++;
                }
            }

            if ( grep( /^auto-boot-on-error/, $_ ) ) {
                ( undef, $abonerror ) = split( /=/, $_ );
                $abonerror =~ s/^\s+//g;
                chomp($abonerror);
                if ( "$abonerror" ne 'false' ) {
                    print
"\n$WARNSTR Eeprom auto-boot-on-error incorrect (\"$abonerror\" instead of \"false\")\n";
                    push(@CHECKARR,
"\n$WARNSTR Eeprom auto-boot-on-error incorrect (\"$abonerror\" instead of \"false\")\n");
                    $warnings++;
                }
                else {
                    print
"\n$PASSSTR Eeprom auto-boot-on-error correct (\"$abonerror\")\n";
                }
            }

            if ( grep( /^diag-switch/, $_ ) ) {
                ( undef, $diagswitch ) = split( /=/, $_ );
                $diagswitch =~ s/^\s+//g;
                chomp($diagswitch);
                if ( "$diagswitch" ne 'false' ) {
                    print
"\n$WARNSTR Eeprom diag-switch incorrect (\"$diagswitch\" instead of \"false\")\n";
                    push(@CHECKARR,
"\n$WARNSTR Eeprom diag-switch incorrect (\"$diagswitch\" instead of \"false\")\n");
                    $warnings++;
                }
                else {
                    print
"\n$PASSSTR Eeprom diag-switch correct (\"$diagswitch\")\n";
                }
            }

            if ( grep( /^boot-device/, $_ ) ) {
                ( undef, $bootdevice ) = split( /=/, $_ );
                $bootdevice =~ s/^\s+//g;
                chomp($bootdevice);
                if ( ! "$bootdevice" ) {
                    print
"\n$WARNSTR Eeprom boot-device string is empty\n";
                    push(@CHECKARR,
"\n$WARNSTR Eeprom boot-device string is empty\n");
                    $warnings++;
                }
                else {
                    print
"\n$PASSSTR Eeprom boot-device string not empty\n";
                    print "$bootdevice\n";
                }
            }

            if ( grep( /^diag-level/, $_ ) ) {
                ( undef, $diaglevel ) = split( /=/, $_ );
                $diaglevel =~ s/^\s+//g;
                chomp($diaglevel);
                if ( "$diaglevel" eq 'max' ) {
                    print
"\n$INFOSTR Eeprom diag-level is \"$diaglevel\" (boot process can be slow)\n";
                    $warnings++;
                }
                else {
                    print
"\n$PASSSTR Eeprom diag-level is \"$diaglevel\"\n";
                }
            }

            if ( grep( /^output-device/, $_ ) ) {
                ( undef, $outputvalue ) = split( /=/, $_ );
                $outputvalue =~ s/^\s+//g;
                chomp($outputvalue);
                if ( "$outputvalue" ne 'rsc-console' ) {
                    print
"\n$WARNSTR Eeprom flag output-device incorrect for RSC (\"$outputvalue\" instead of \"rsc-console\")\n";
                    $warnings++;
                }
            }

            if ( grep( /^diag-out-console/, $_ ) ) {
                ( undef, $diagvalue ) = split( /=/, $_ );
                $diagvalue =~ s/^\s+//g;
                chomp($diagvalue);
                if ( "$diagvalue" ne 'true' ) {
                    print
"\n$WARNSTR Eeprom diag-out-console incorrect (\"$diagvalue\" instead of \"true\")\n";
                    push(@CHECKARR,
"\n$WARNSTR Eeprom diag-out-console incorrect (\"$diagvalue\" instead of \"true\")\n");
                    $warnings++;
                }
                else {
                    print
"\n$PASSSTR Eeprom diag-out-console correct (\"$diagvalue\")\n";
                }
            }
        }
        close(EEP);
    }

    ( undef, undef, undef, undef, @haddrs ) = gethostbyname($Hostname);
    foreach my $ma (@haddrs) {
        $SrvHostIP       = join( '.', unpack( 'C4', $ma ) );
        $SrvHostIPsubnet = join( '.', unpack( 'C3', $ma ) );
    }

    foreach $host (@RSCsvrs) {
        my $PING = 0;
        ( undef, undef, undef, undef, @addrs ) = gethostbyname($host);

        foreach my $a (@addrs) {
            $HostIP       = join( '.', unpack( 'C4', $a ) );
            $HostIPsubnet = join( '.', unpack( 'C3', $a ) );
        }

        if ( !CheckIP($HostIP) ) {
            print "$WARNSTR Invalid or incomplete subnet for RSC\n";
        }
        else {
            if ( "$SrvHostIPsubnet" && "$HostIPsubnet" ) {
                if ( "$SrvHostIPsubnet" eq "$HostIPsubnet" ) {
                    print "$WARNSTR Server $Hostname ($SrvHostIP) ";
                    print
"and its RSC $host on the same subnet $SrvHostIPsubnet\n";
                    $warnings++;
                }
                else {
                    print "$PASSSTR Server $Hostname ($SrvHostIP) and ";
                    print "its RSC $host on different subnet\n";
                }
            }

            if ( !defined($HostIP) ) {
                print
"$WARNSTR Check hostname resolution for server \"$host\"\n";
            }

            # First check if the server is responding to ICMP...
            #
            $h = Net::Ping->new();
            if ( !$h->ping($host) ) {
                print "$WARNSTR $host is NOT reachable (first type ICMP)\n";
                $PING++;
            }
            else {
                print "$PASSSTR $host is reachable (first type ICMP)\n";
            }
            $h->close();

            # Second type of ping test
            #
            $h = Net::Ping->new("icmp");
            if ( !$h->ping( $host, 2 ) ) {
                print
                  "$WARNSTR $host is NOT reachable (second type ICMP)\n";
                $PING++;
            }
            else {
                print "$PASSSTR $host is reachable (second type ICMP)\n";
            }
            $h->close();

            # Third type of ping test
            #
            $h = Net::Ping->new( "tcp", 2 );
            while ( $stop_time > time() ) {
                print "$WARNSTR $host is NOT not reachable (TCP ping)",
                  scalar( localtime() ), "\n"
                  unless $h->ping($host);
                $PING++;
            }
            undef($h);

            # Now, check the ports
            #
            if ( $PING < 3 ) {
                @port = "23";

                foreach my $n (@port) {
                    my $p = Net::Ping->new("tcp");
                    $Portproto = getservbyport( $n, 'tcp' );
                    $p->{port_num} = $n if $n;
                    if ( $p->ping($host) ) {
                        print "$PASSSTR Port $n\@$host is ACTIVE\n";
                        print "$INFOSTR Factory-default RSC account ";
                        print "should always be changed\n";
                    }
                    else {
                        print "$ERRSTR Port $n\@$host is INACTIVE ";
                        print "or FILTERED\n";
                        print "$INFOSTR It is recommended to check ";
                        print "the RSC manually\n";
                    }
                }
            }
        }
    }

    $scadm = "/usr/platform/$Model/sbin/scadm";

    if ( -x "$scadm" ) {
        print "\n$INFOSTR SCadm $scadm exists for this model\n";
        my @SCnet     = `$scadm shownetwork`;
        my @SCustat   = `$scadm usershow`;
        my @SCshow    = `$scadm show`;
        my @SChistory = `$scadm loghistory`;

        if ("@SCnet") {
            print "\n$INFOSTR RSC network\n";
            print @SCnet;
        }

        if ("@SCustat") {
            print "\n$INFOSTR RSC user status\n";
            print @SCustat;
        }

        if ("@SCshow") {
            print "\n$INFOSTR RSC show\n";
            print @SCshow;
        }

        if ("@SChistory") {
            print "\n$INFOSTR RSC log history\n";
            print @SChistory;
        }
    }

    my $RSCexe = "/usr/platform/$Model/rsc/rscadm";

    if ( -s "$RSCexe" ) {
        print "\n$WARNSTR RSCadm $RSCexe exists for this model\n";
        my @RSCnet  = `$RSCexe shownetwork`;
        my @RSCstat = `$RSCexe status`;
        my @RSCshow = `$RSCexe show`;

        if ("@RSCnet") {
            print "$INFOSTR RSC network\n";
            print @RSCnet;
        }

        if ("@RSCstat") {
            print "\n$INFOSTR RSC status\n";
            print @RSCstat;
        }

        if ("@RSCshow") {
            print "\n$INFOSTR RSC show\n";
            print @RSCshow;
        }
    }

    if (! "$RSCCK" ) {
        print "$INFOSTR RSC seemingly not applicable to this platform\n";
    }

    datecheck();
    print_header("*** END CHECKING RSC CONSOLE $datestring ***");

    if ( @EEPROMarr ) {
        datecheck();
        print_header("*** BEGIN CHECKING EEPROM SETTINGS $datestring ***");

        print @EEPROMarr;

        datecheck();
        print_header("*** END CHECKING EEPROM SETTINGS $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING LOM STATUS $datestring ***");

    my @LOMconf = `lom -c`;
    if ("@LOMconf") {
        print "$INFOSTR LOM configuration\n";
        print @LOMconf;

        my @LOMa = `lom -a`;
        if ("@LOMa") {
            print "$INFOSTR LOM status\n";
            print @LOMa;
        }
    }
    else {
        print "$INFOSTR LOM not configured\n";
    }

    my @ILOMconf = `ilomconfig 2>/dev/null | nawk NF`;
    if ("@ILOMconf") {
        print "\n$INFOSTR ILOM configuration\n";
        print @ILOMconf;
    }

    datecheck();
    print_header("*** END CHECKING LOM STATUS $datestring ***");

    if ( "$Minor" < 11 ) {
        datecheck();
        print_header("*** BEGIN CHECKING SUN WEB CONSOLE STATUS $datestring ***");

        my @smreg = `smreg list 2>/dev/null | nawk NF`;
        if ("@smreg") {
            print @smreg;
        }

        my @smcweb = `smcwebserver status 2>/dev/null | nawk NF`;
        if ("@smcweb") {
            print "\n";
            print @smcweb;
        }

        my @wcadmin = `wcadmin list -a 2>/dev/null`;
        if ("@wcadmin") {
            print "\n";
            print @wcadmin;
        }

        datecheck();
        print_header("*** END CHECKING SUN WEB CONSOLE STATUS $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING AUXILIARY CONSOLE STATUS $datestring ***");

    my @consadmlist = `consadm list 2>/dev/null`;
    if ( ! "@consadmlist") {
        @consadmlist = `consadm -p 2>/dev/null`;
    }

    if ( "@consadmlist") {
        print "$INFOSTR Aux console configuration\n";
        print @consadmlist;
    } 
    else {
        print "$INFOSTR Aux console not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING AUXILIARY CONSOLE STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING IPMI $datestring ***");

    my @ipmi = `ipmitool lan print 2>/dev/null`;
    if ("@ipmi") {
        print "$INFOSTR IPMI configuration\n";
        print @ipmi;
    }
    else {
        print "$INFOSTR IPMI not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING IPMI $datestring ***");
}

#
# Subroutine to check IPSec
#
sub IPseccheck {
    datecheck();
    print_header("*** BEGIN CHECKING IPSEC $datestring ***");

    if ( -s "$ipsecconf" ) {
        print "$PASSSTR IPSec configuration file $ipsecconf exists\n";
        my @cna = `nawk '! /^#/ && ! /awk/ {print}' $ipsecconf | nawk NF`;
        print @cna;
    }
    else {
        print
          "$INFOSTR IPSec configuration file $ipsecconf does not exists\n";
    }

    if ( -s "$ipsecpolicy" ) {
        print "\n$PASSSTR IPSec policy file $ipsecpolicy exists\n";
        my @cnb = `nawk '! /^#/ && ! /awk/ {print}' $ipsecpolicy | nawk NF`;
        print @cnb;
    }
    else {
        print "\n$INFOSTR IPSec policy file $ipsecpolicy does not exists\n";
    }

    if ( open( VCK, "skiplocal -l 2>/dev/null |" ) ) {
        while (<VCK>) {
            push( @SKIPlist, $_ );
        }
        close(VCK);
    }

    if ("@SKIPlist") {
        print "\n$INFOSTR IPSec Skey keys\n";
        print @SKIPlist;
    }

    datecheck();
    print_header("*** END CHECKING IPSEC $datestring ***");
}

#
# Subroutine to check third-party licensing software
#
sub liccheck {
    if ( "$LICENSE" > 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING THIRD-PARTY LICENSE MANAGERS $datestring ***");

        print
"$INFOSTR Third-party license manager might be running (please check it manually)\n";
        print @licdaemon;

        datecheck();
        print_header("*** END CHECKING THIRD-PARTY LICENSE MANAGERS $datestring ***");
    }

    my @vxlicrep = `vxlicrep 2>/dev/null`;
    if ("@vxlicrep") {
        datecheck();
        print_header("*** BEGIN CHECKING VERITAS LICENSES $datestring ***");

        print @vxlicrep;

        datecheck();
        print_header("*** END CHECKING VERITAS LICENSES $datestring ***");
    }

    my @tsmlic = `query license 2>/dev/null`;
    if (@tsmlic) {
        datecheck();
        print_header("*** BEGIN CHECKING TIVOLI STORAGE MANAGER LICENSES $datestring ***");

        print @tsmlic;

        datecheck();
        print_header("*** END CHECKING TIVOLI STORAGE MANAGER LICENSES $datestring ***");
    }

    my @db2licm = `db2licm -l 2>/dev/null`;

    if ("@db2licm") {
        datecheck();
        print_header("*** BEGIN CHECKING IBM DB2 LICENSES $datestring ***");

        print @db2licm;

        datecheck();
        print_header("*** END CHECKING IBM DB2 LICENSES $datestring ***");
    }

}

#
# Subroutine to check LDAP client
#
sub LDAPclientcheck {
    datecheck();
    print_header("*** BEGIN CHECKING LDAP CLIENT $datestring ***");

    if ( -s "$ldapcld_conf" && -T "$ldapcld_conf" ) {
        if ( open( LDP, "cat $ldapcld_conf | nawk NF |" ) ) {
            print "$INFOSTR LDAP client is running\n";
            print "$INFOSTR LDAP client daemon config file $ldapcld_conf\n";
            while (<LDP>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
        }
        close(LDP);

        my @ldaplist = `ldaplist 2>/dev/null`;
        if ("@ldaplist") {
            print "$INFOSTR LDAP search\n";
            print @ldaplist;
        }

        my @ldapclient = `ldapclient list 2>/dev/null`;
        if ("@ldapclient") {
            print "$INFOSTR LDAP client status\n";
            print @ldapclient;
        }
    }
    else {
        print
"$INFOSTR Cannot open LDAP client daemon config file $ldapcld_conf\n";
    }

    datecheck();
    print_header("*** END CHECKING LDAP CLIENT $datestring ***");
}

#
# Subroutine to check LDAP server
#
sub LDAPservercheck {
    if ( "$LDAPSERVER" > 0 ) {
        if ( $NSADMIN > 0 ) {
            datecheck();
            print_header("*** BEGIN CHECKING NETSPACE LDAP SERVER $datestring ***");

            print "$INFOSTR Netscape LDAP server seemingly running\n";
            print @ldapdaemon;

            datecheck();
            print_header("*** END CHECKING NETSPACE LDAP SERVER $datestring ***");
        } else 
        { 
            datecheck();
            print_header("*** BEGIN CHECKING OPENLDAP SERVER $datestring ***");

            if ( ( -s "$sldap_conf" ) && ( -T "$sldap_conf" ) ) {
                if ( open( SLDP, "nawk NF $sldap_conf |" ) ) {
                    print "$INFOSTR LDAP config file $sldap_conf\n";
                    while (<SLDP>) {
                        print $_;
                    }
                }
                close(SLDP);
            }
            else {
                print
"$INFOSTR Cannot open SLDAP daemon config file $sldap_conf\n";
            }

            if ( ( -s "$ldap2_conf" ) && ( -T "$ldap2_conf" ) ) {
                if ( open( LDP, "nawk NF $ldap2_conf |" ) ) {
                    print "$INFOSTR LDAP config file $ldap2_conf\n";
                    while (<LDP>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                    }
                }
                close(LDP);
            }
            else {
                print
"$INFOSTR Cannot open LDAP daemon config file $ldap2_conf\n";
            }

            datecheck();
            print_header("*** END CHECKING OPENLDAP SERVER $datestring ***");
        }
    }

    datecheck();
    print_header("*** BEGIN CHECKING LDAP CONFIG $ldap_conf $datestring ***");

    if ( ( -s "$ldap_conf" ) && ( -T "$ldap_conf" ) ) {
        if ( open( LDP, "nawk NF $ldap_conf |" ) ) {
            print "$INFOSTR LDAP config file $ldap_conf\n";
            while (<LDP>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
        close(LDP);
    }
    else {
        print "$INFOSTR Cannot open LDAP config file $ldap_conf\n";
    }

    datecheck();
    print_header("*** END CHECKING LDAP CONFIG $ldap_conf $datestring ***");
}

#
# Subroutine to check shared memory and semaphores
#
sub IPCScheck {
    my @ipcsstat = `ipcs -a 2>/dev/null`;

    if ("@ipcsstat") {
        datecheck();
        print_header("*** BEGIN CHECKING INTERPROCESS COMMUNICATION FACILITIES $datestring ***");

        print @ipcsstat;

        datecheck();
        print_header("*** END CHECKING INTERPROCESS COMMUNICATION FACILITIES $datestring ***");
    }
}

#
# Subroutine to check disk quotas
#
sub QUOTAcheck {
    datecheck();
    print_header("*** BEGIN CHECKING FILE SYSTEM QUOTAS $datestring ***");

    my @quotastat = `quotacheck -a -v 2>/dev/null`;

    if ("@quotastat") {
        print "$INFOSTR Quotas seemingly active\n";
        print @quotastat;
    }
    else {
        print "$INFOSTR Quotas not active\n";
    }

    datecheck();
    print_header("*** END CHECKING FILE SYSTEM QUOTAS $datestring ***");
}

#
# Subroutine to check ulimits
#
sub ULIMITcheck {
    datecheck();
    print_header("*** BEGIN CHECKING ULIMIT $datestring ***");

    my @ulimitstat = `ulimit -a 2>/dev/null`;

    if ("@ulimitstat") {
        print @ulimitstat;
    }
    else {
        print "$INFOSTR Cannot check ulimits\n";
    }

    datecheck();
    print_header("*** END CHECKING ULIMIT $datestring ***");
}

#
# Get system's CPU number
#
sub CPUcheck {
    datecheck();
    print_header("*** BEGIN CHECKING CPU STATUS $datestring ***");

    if ( open( PSR, " psrinfo -v 2>&1 |" ) ) {
        while (<PSR>) {
            next if ( grep( /^$/, $_ ) );
            push( @CPUarray, $_ );
            if ( grep( /on-line/, $_ ) ) {
                $cpucount++;
            }
        }
        close(PSR);

        print "Active CPUs: $cpucount\n";
        print @CPUarray;
    }
    else {
        print "$WARNSTR Cannot run psrinfo\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run psrinfo\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING CPU STATUS $datestring ***");
}

#
# Check sticky bit on common directories
#
sub STICKYcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SKICKY BIT ON SHARED DIRECTORIES $datestring ***");

    foreach my $commdir (@Stickyarr) {
        if ( -k $commdir ) {
            print "$PASSSTR Directory $commdir has sticky bit\n";
        }
        else {
            print "$WARNSTR Directory $commdir does not have sticky bit\n";
            push(@CHECKARR, "\n$WARNSTR Directory $commdir does not have sticky bit\n");
            $warnings++;
        }
    }

    datecheck();
    print_header("*** END CHECKING SKICKY BIT ON SHARED DIRECTORIES $datestring ***");
}

#
# Subroutine to check PAM
#
sub PAMcheck {
    datecheck(); 
    print_header("*** BEGIN CHECKING PAM CONFIGURATION $datestring ***");

    if ( -s "$pam_conf" ) {
        if ( open( PAM, "cat $pam_conf |" ) ) {
            print "$INFOSTR PAM config file $pam_conf\n";
            while (<PAM>) {
                print $_;
            }
        }
        close(PAM);
    }
    else {
        print
"$WARNSTR PAM config file $pam_conf empty, missing or in different directory\n";
        push(@CHECKARR,
"\n$WARNSTR PAM config file $pam_conf empty, missing or in different directory\n");
    }

    my @pamls = `ls /etc/pam.d/* 2>/dev/null`;
    foreach my $pcfg (@pamls) {
        chomp($pcfg);
        if ( -s $pcfg ) {
            print "\n$INFOSTR Configuration file $pcfg\n";
            my @psfg = `nawk NF $pcfg`;
            print @psfg;
        }
    }

    datecheck(); 
    print_header("*** END CHECKING PAM CONFIGURATION $datestring ***");
}

#
# Subroutine to check Security Containment
#
sub SCRBACcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SECURITY CONTAINMENT (RBAC) $datestring ***");

    if ( -s "$ACPS" ) {
        if ( open( ACP, "nawk NF $ACPS |" ) ) {
            print "$INFOSTR Security policy configuration file $ACPS\n";
            while (<ACP>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                if ( grep( /^CRYPT_DEFAULT/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    ( undef, $CRYPTDEF ) = split(/=/, $_);
                    chomp($CRYPTDEF);
                }
                print $_;
            }
            close(ACP);
        }
        else {
            print
              "$INFOSTR Policy configuration file $ACPS does not exist\n";
        }

        if ( "$CRYPTDEF" ) {
           if ( "$PWHASHARR{$CRYPTDEF}" ) {
               print "\n$INFOSTR Default $PWHASHARR{$CRYPTDEF} in configuration file $ACPS\n";
           }
           else {
               print "\n$INFOSTR Default hashing-algorithm=$CRYPTDEF} in configuration file $ACPS\n";
           }
        }
    }

    my @cryptcat = `cat $CRYPTCONF 2>/dev/null`;
    if ("@cryptcat") {
        print "\n$INFOSTR Configuration file $CRYPTCONF\n";
        print @cryptcat;
    }

    if ( -s "$userattr" ) {
        if ( open( ACP1, "nawk NF $userattr |" ) ) {
            print "\n$INFOSTR User attribute file $userattr\n";
            while (<ACP1>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close(ACP1);
        }
        else {
            print
              "\n$INFOSTR User attribute file $userattr does not exist\n";
        }
    }

    if ( -s "$authattr" ) {
        if ( open( ACP2, "nawk NF $authattr |" ) ) {
            print "\n$INFOSTR Authorisation attribute file $authattr\n";
            while (<ACP2>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close(ACP2);
        }
        else {
            print
"\n$INFOSTR Authorisation attribute file $authattr does not exist\n";
        }
    }

    if ( -s "$profattr" ) {
        if ( open( ACP3, "nawk NF $profattr |" ) ) {
            print "\n$INFOSTR Profile attribute file $profattr\n";
            while (<ACP3>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close(ACP3);
        }
        else {
            print
"\n$INFOSTR Profile attribute file $profattr does not exist\n";
        }
    }

    my @rbaclist = `roles 2>/dev/null`;
    if ("@rbaclist") {
        print "\n$INFOSTR RBAC roles\n";
        print @rbaclist;
    }

    my @profiles = `profiles 2>/dev/null`;
    if ("@profiles") {
        print "\n$INFOSTR Rights profiles\n";
        print @profiles;
    }

    my @projects = `projects 2>/dev/null`;
    if ("@projects") {
        print "\n$INFOSTR Projects\n";
        print @projects;
    }

    datecheck();
    print_header("*** END CHECKING SECURITY CONTAINMENT (RBAC) $datestring ***");

    if ( "$Minor" >= 10 ) {
        datecheck();
        print_header("*** BEGIN CHECKING PRIVILEGE SETS $datestring ***");

        my @pprivlist = `ppriv -lv 2>/dev/null`;
        if ("@pprivlist") {
            print @pprivlist;
        }
        else {
            print "$INFOSTR No privilege sets defined\n";
        }

        datecheck();
        print_header("*** END CHECKING PRIVILEGE SETS $datestring ***");
    }

    if ( "$Minor" >= 11 ) {
        datecheck();
        print_header("*** BEGIN CHECKING SECURITY EXTENSIONS CONFIGURATION $datestring ***");

        my @SXADMARR = `sxadm info 2>/dev/null`;
        if ("@SXADMARR") {
            print @SXADMARR;
        }

        datecheck();
        print_header("*** END CHECKING SECURITY EXTENSIONS CONFIGURATION $datestring ***");
    }
}

#
# Subroutine to check Host Intrusion Detection System (HIDS)
#
sub HIDScheck {
    datecheck();
    print_header("*** BEGIN CHECKING HOST INTRUSION DETECTION SYSTEM $datestring ***");

    if ( -s "$esmmgr" ) {
        if ( open( ESMAY, "egrep -v ^# $esmmgr | nawk NF |" ) ) {
            while (<ESMAY>) {
                next if ( grep( /^$/, $_ ) );
                push( @ESMfull, $_ );
                $_ =~ s/^\s+//g;
                ( $esmid, undef ) = split( /\s+/, $_ );
                chomp($esmid);
                push( @ESMarr, $esmid );
            }
            close(ESMAY);
            $HIDS_FLAG++;
        }
    }

    if ( -s "$esm" ) {
        if ( open( ESP, "egrep -v ^# $esm | nawk NF |" ) ) {
            while (<ESP>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                push( @ESMportarr, $_ );
                if ( grep( /^PORT_MANAGER/, $_ ) ) {
                    ( undef, $ESMport ) = split( /=/, $_ );
                    chomp($ESMport);
                }
            }
            close(ESP);
            $HIDS_FLAG++;
        }
    }

    $esmport = $ESMport || $esmportdef;

    if ( "$HIDS_FLAG" > 0 ) {
        if ( -s "$aide_conf" ) {
            my @aidecheck =
              `nawk '! /^#/ && ! /awk/ {print}' $aide_conf`;
            if ("@aidecheck") {
                print "$INFOSTR AIDE seemingly configured\n";
                print @aidecheck;

                my @aidev = `aide -v 2>&1 | egrep -v "command not found"`;
                if ("@aidev") {
                    print "\n$INFOSTR AIDE seemingly configured\n";
                    print @aidev;
                }
            }
        }

        my @twcheck = `twadmin --print-cfgfile 2>/dev/null`;
        if ("@twcheck") {
            print "\n$INFOSTR Tripwire seemingly configured\n";
            print @twcheck;
        }
        else {
            print "\n$INFOSTR Tripwire seemingly not configured\n";
        }

        my @auck =
`auditconfig -getpolicy | nawk '! /failed|Invalid argument/ && ! /awk/ {print}'`;
        if ("@auck") {
            print
"\n$INFOSTR Basic Security Module auditing seemingly configured\n";
            print @auck;
        }
        else {
            print
"\n$INFOSTR Basic Security Module auditing seemingly not configured\n";
        }

        if ( "$ESMD_FLAG" > 0 ) {
            print
"\n$INFOSTR Symantec Enterprise Security Manager seemingly configured\n";
        }
        else {
            print
"\n$INFOSTR Symantec Enterprise Security Manager seemingly configured\n";
        }

        if ("@ESMfull") {
            print "\n$INFOSTR ESM manager config file $esmmgr\n";
            print @ESMfull;
        }

        if ("@ESMportarr") {
            print
"\n$INFOSTR Symantec Enterprise Security Manager Agent seemingly configured\n";
            print @ESMportarr;
            foreach my $ESM_server (@ESMarr) {
                &openport( $ESM_server, $esmport, 'tcp' );
            }
        }
        else {
            print
"\n$INFOSTR Symantec Enterprise Security Manager Agent seemingly not configured\n";
        }

        if ( -d "$esmdirhost" ) {
            print
"\n$INFOSTR Symantec ESM client directory $esmdirhost exists\n";
        }
        else {
            print
"\n$INFOSTR Symantec ESM client directory $esmdirhost does not exist\n";
        }

        if ( -s "$esmrc" ) {
            my @esmstart = `nawk NF $esmrc`;
            print "\n$INFOSTR Symantec ESM startup file $esmrc\n";
            print @esmstart;
        }
    }
    else {
        print "$INFOSTR HIDS tools seemingly not in use\n";
    }

    datecheck();
    print_header("*** BEND CHECKING HOST INTRUSION DETECTION SYSTEM $datestring ***");
}

# Subroutine to check current time
#
sub datecheck {
    ($Csec,$Cmin,$Chour,$Cmday,$Cmon,$Cyear,$Cwday,$Cyday,$Cisdst) = localtime(time);
    $datestring = sprintf("%02d-%02d-%04d-%02d:%02d:%02d",$Cmday, ($Cmon+1), ($Cyear + 1900), $Chour, $Cmin, $Csec);
}

#
# Subroutine to check active processes
#
my $PSFLAG = q{};

if ( "$Minor" >= 10 ) {
   $PSFLAG="Z";
}

sub rawpscheck {
    if ( open( KM, "ps -efl${PSFLAG} |" ) ) {
        while (<KM>) {
            push( @allprocesses, $_ );

            $_ =~ s/\s+$//g;
            $psline = $_;
            chomp $psline;

            if ( $psline =~ /TIME.*CMD/ ) {
                @HEADLN = $psline;
            }
            else {
                @userid = split(/\s+/, $psline);
            }

            if ( $userid[2] =~ /^S/ ) {
               push(@PSSLEEP, "@userid\n");
            }
            elsif ( $userid[2] =~ /^R/ ) {
               push(@PSRUN, "@userid\n");
            }
            elsif ( $userid[2] =~ /^T/ ) {
               push(@PSSTOP, "@userid\n");
            }
            elsif ( $userid[2] =~ /^W/ ) {
               push(@PSPAGE, "@userid\n");
            }
            elsif ( $userid[2] =~ /^O/ ) {
               push(@PSPROC, "@userid\n");
            }
            elsif ( $userid[2] =~ /^Z/ ) {
               push(@PSZOMBIE, "@userid\n");
            }
            else {
               if ( "@userid" != 0 ) {
                  push(@PSREST, "@userid\n");
               }
            }

            if ( "$Minor" >= 10 ) {
                if( $userid[4] =~ /^[0-9]+$/ ) {
                    push(@PSARR,
"$ERRSTR Process \"$psline\" without owner defined in password database (\"$userid[4]\")\n");
                    push(@CHECKARR,
"$ERRSTR Process \"$psline\" without owner defined in password database (\"$userid[4]\")\n");
                    $warnings++;
                }
            }
            else {
                if( $userid[3] =~ /^[0-9]+$/ ) {
                    push(@PSARR,
"$ERRSTR Process \"$psline\" without owner defined in password database (\"$userid[3]\")\n");
                    push(@CHECKARR,
"$ERRSTR Process \"$psline\" without owner defined in password database (\"$userid[3]\")\n");
                    $warnings++;
                }
            }

            grep( /nscd/,                         $_ ) ? $NSCD_FLAG++
            : grep( /rpc.metad/,                  $_ ) ? $SVM_FLAG++
            : grep( /mdmonitord/,                 $_ ) ? $SVM_FLAG++
            : grep( /ldapclientd/,                $_ ) ? $LDAPCLIENT++
            : grep( /dtlogin|dmispd/,             $_ ) ? $CDE_FLAG++
            : grep( /automountd/,                 $_ ) ? $AUTO_FLAG++
            : grep( /idsagent/,                   $_ ) ? $IDS_FLAG++
            : grep( /slapd/,                      $_ ) ? ldapcalc()
            : grep( /ns-admin/,                   $_ ) ? nsadmcalc()
            : grep( /lmgrd|netlsd|i4lmd|license/, $_ ) ? liccalc()
            : grep( /lpsched/,                    $_ ) ? $LPSCHED++
            : grep( /in.dhcpd|dhcpd/,             $_ ) ? $DHCPD_FLAG++
            : grep( /in.ipmpd/,                   $_ ) ? $IPMP_FLAG++
            : grep( /named/,                      $_ ) ? push( @DNSRUN, $_ )
            : grep( /squid/,                      $_ ) ? push( @SQUIDRUN, $_ )
            : grep( /ntpd/,                       $_ ) ? push( @ntpdaemon, $_ )
            : grep( /nfsd/,                       $_ ) ? push( @nfsdaemon, $_ )
            : grep( /sendmail/,                   $_ ) ? $SENDMAIL_FLAG++
            : grep( /exim/,                       $_ ) ? $EXIM_FLAG++
            : grep( /postfix/,                    $_ ) ? $POSTFIX_FLAG++
            : grep( /puppetmasterd/,              $_ ) ? $PUPPETMASTER++
            : grep( /puppetd/,                    $_ ) ? $PUPPETCLIENT++
            : grep( /cfservd|cf-serverd/,         $_ ) ? $CFENGINEMASTER++
            : grep( /cfagent|cf-agent/,           $_ ) ? $CFENGINECLIENT++
            : grep( /srsproxy/,                   $_ ) ? $SRSPROXY_FLAG++
            : grep( /pbmasterd/,                  $_ ) ? $POWERBROKERSRV_FLAG++
            : grep( /pblogd|pblocald/,            $_ ) ? $POWERBROKERCL_FLAG++
            : grep( /dsmc/,                       $_ ) ? $TSMCL_FLAG++
            : grep( /dsmserv/,                    $_ ) ? $TSMSRV_FLAG++
            : 1;
        }
    }
    else {
        print "$ERRSTR Cannot run ps (process list)\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run ps (process list)\n");
    }
    close(KM);
}

#
# Subroutine to check active processes
#
sub pscheck {
    datecheck();
    print_header("*** BEGIN CHECKING UNIX PROCESSES $datestring ***");

   if ( @PSSLEEP ) {
       print "$INFOSTR Processes in interruptible sleep\n";
       print "@HEADLN\n";
       print @PSSLEEP;
       print "\n";
   }

   if ( @PSSTOP ) {
       print "$INFOSTR Stopped processes (job control or tracing)\n";
       print "@HEADLN\n";
       print @PSSTOP;
       print "\n";
   }

   if ( @PSPAGE ) {
       print "$INFOSTR Processes waiting for CPU usage to drop to CPU-caps enforced limits\n";
       print "@HEADLN\n";
       print @PSPAGE;
       print "\n";
   }

   if ( @PSPROC ) {
       print "$INFOSTR Processes running on a processor\n";
       print "@HEADLN\n";
       print @PSPROC;
       print "\n";
   }

   if ( @PSZOMBIE ) {
       print "$INFOSTR Defunct (\"zombie\") processes\n";
       print "@HEADLN\n";
       print @PSZOMBIE;
       print "\n";
   }

   if ( @PSRUN ) {
       print "$INFOSTR Runable processes (on run queue)\n";
       print "@HEADLN\n";
       print @PSRUN;
   }

   if ( "@PSREST" ) {
       print "\n$INFOSTR Processes in non-standard states\n";
       print "@HEADLN\n";
       print @PSREST;
   }

#    if ("@allprocesses") {
#        print @allprocesses;
#    }

     my $PTREECON = "c";
     if ( "$Minor" < 10 ) {
         $PTREECON = "";
     }

     my @PTREE = `ptree -a${PTREECON} 2>/dev/null`;
     if ("@PTREE") {
         print "\n$INFOSTR Process tree\n";
         print @PTREE;
     }

     my @CTSTAT = `ctstat -v -a 2>/dev/null`;
     if ("@CTSTAT") {
         print "\n$INFOSTR System contracts\n";
         print @CTSTAT;
     }

    datecheck();
    print_header("*** END CHECKING UNIX PROCESSES $datestring ***");
}

#
# Subroutine to check SSH
#
sub SSHcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SECURE SHELL (SSH) $datestring ***");

    if ( "$secureshell" == 0 ) {
        print "$ERRSTR Secure Shell (SSH) seemingly not installed\n";
        push(@CHECKARR, "\n$ERRSTR Secure Shell (SSH) seemingly not installed\n");
    }
    else {
        foreach my $sxva (@SSHarr) {
            if ( -s "$sxva" ) {
                if ( open( SSHCD, "nawk NF $sxva |" ) ) {
                    print "\n$INFOSTR SSH configuration file $sxva\n";
                    while (<SSHCD>) {
                        print $_;
                        next if ( grep( /^$/, $_ ) );

                        if ( grep( /PermitRootLogin/, $_ ) ) {
                            $_ =~ s/\s+$//g;
                            next if ( grep( /^#/, $_ ) );
                            next if ( grep( /,/,  $_ ) );
                            ( undef, $PWPN ) = split( /\s+/, $_ );
                            chomp($PWPN);
                            if ( lc($PWPN) eq 'yes' ) {
                                push(@SSHARR, "$WARNSTR SSH allows direct Root access\n");
                                push(@SSHARR, "$INFOSTR It is strongly recommended to disable it\n");
                                push(@CHECKARR, "\n$WARNSTR SSH allows direct Root access\n");
                            }

                            if ( lc($PWPN) eq 'no' ) {
                                push(@SSHARR, "$PASSSTR SSH does not allow direct Root access\n");
                            }
                        }

                        if ( grep( /StrictModes/, $_ ) ) {
                            $_ =~ s/\s+$//g;
                            next if ( grep( /^#/, $_ ) );
                            next if ( grep( /,/,  $_ ) );
                            ( undef, $SSHSTRICT ) = split( /\s+/, $_ );
                            chomp($SSHSTRICT);
                            if ( lc($SSHSTRICT) eq 'no' ) {
                                push(@SSHARR, "$WARNSTR StrictModes set to \"no\"\n");
                                push(@SSHARR, "$INFOSTR It is strongly recommended to disable it\n");
                                push(@CHECKARR, "\n$WARNSTR SSH StrictModes set to \"no\"\n");
                            }

                            if ( lc($SSHSTRICT) eq 'yes' ) {
                                push(@SSHARR, "$PASSSTR StrictModes set to \"yes\"\n");
                            }
                        }

                        if ( grep( /IgnoreRhosts/, $_ ) ) {
                            $_ =~ s/\s+$//g;
                            next if ( grep( /^#/, $_ ) );
                            next if ( grep( /,/,  $_ ) );
                            ( undef, $SSHRHOST ) = split( /\s+/, $_ );
                            chomp($SSHRHOST);
                            if ( lc($SSHRHOST) eq 'no' ) {
                                push(@SSHARR, "$WARNSTR IgnoreRhosts set to \"no\"\n");
                                push(@SSHARR, "$INFOSTR It is strongly recommended to disable it\n");
                                push(@CHECKARR, "$WARNSTR SSH IgnoreRhosts set to \"no\"\n");
                            }

                            if ( lc($SSHRHOST) eq 'yes' ) {
                                push(@SSHARR, "$PASSSTR IgnoreRhosts set to \"yes\"\n");
                            }
                        }

                        if ( grep( /PermitEmptyPasswords/, $_ ) ) {
                            $_ =~ s/\s+$//g;
                            next if ( grep( /^#/, $_ ) );
                            next if ( grep( /,/,  $_ ) );
                            ( undef, $SSHEMPTYPW ) = split( /\s+/, $_ );
                            chomp($SSHEMPTYPW);
                            if ( lc($SSHEMPTYPW) eq 'yes' ) {
                                push(@SSHARR, "$WARNSTR PermitEmptyPasswords set to \"yes\"\n");
                                push(@SSHARR, "$INFOSTR It is strongly recommended to disable it\n");
                                push(@CHECKARR, "\n$WARNSTR SSH PermitEmptyPasswords set to \"yes\"\n");
                            }

                            if ( lc($SSHEMPTYPW) eq 'no' ) {
                                push(@SSHARR, "$PASSSTR PermitEmptyPasswords set to \"no\"\n");
                            }
                        }

                        if ( grep( /PasswordAuthentication/, $_ ) ) {
                            $_ =~ s/\s+$//g;
                            next if ( grep( /^#/, $_ ) );
                            next if ( grep( /,/,  $_ ) );
                            ( undef, $PWYN ) = split( /\s+/, $_ );
                            chomp($PWYN);
                            if ( lc($PWYN) eq 'yes' ) {
                                push(@SSHARR, "$WARNSTR SSH allows password authentication\n");
                                push(@SSHARR, "$INFOSTR It is strongly recommended to use ");
                                push(@SSHARR, "public key client/user credentials only\n");
                                push(@CHECKARR, "\n$WARNSTR SSH allows password authentication\n");
                            }

                            if ( lc($PWYN) eq 'no' ) {
                                push(@SSHARR, "$PASSSTR SSH allows public key client/user authentication only\n");
                            }
                        }

                        if ( grep( /UsePrivilegeSeparation/, $_ ) ) {
                            $_ =~ s/\s+$//g;
                            my $SSHPRIVSEP = q{};
                            next if ( grep( /^#/, $_ ) );
                            next if ( grep( /,/,  $_ ) );
                            ( undef, $SSHPRIVSEP ) = split( /\s+/, $_ );
                            chomp($SSHPRIVSEP);
                            if ( lc($SSHPRIVSEP) eq 'no' ) {
                                push(@SSHARR, "$WARNSTR UsePrivilegeSeparation set to \"no\"\n");
                                push(@SSHARR, "$INFOSTR It is strongly recommended to disable it\n");
                                push(@CHECKARR, "\n$WARNSTR SSH UsePrivilegeSeparation set to \"no\"\n");
                            }

                            if ( lc($SSHPRIVSEP) eq 'yes' ) {
                                push(@SSHARR, "$PASSSTR UsePrivilegeSeparation set to \"yes\"\n");
                            }
                        }

                        if ( grep( /AllowTcpForwarding/, $_ ) ) {
                            $_ =~ s/\s+$//g;
                            next if ( grep( /^#/, $_ ) );
                            next if ( grep( /,/,  $_ ) );
                            ( undef, $SSHTCPFWD ) = split( /\s+/, $_ );
                            chomp($SSHTCPFWD);
                            if ( lc($SSHTCPFWD) eq 'yes' ) {
                                push(@SSHARR, "$WARNSTR AllowTcpForwarding set to \"yes\"\n");
                                push(@SSHARR, "$INFOSTR It is strongly recommended to disable it\n");
                                push(@CHECKARR, "\n$WARNSTR SSH AllowTcpForwarding set to \"yes\"\n");
                            }

                            if ( lc($SSHTCPFWD) eq 'no' ) {
                                push(@SSHARR, "$PASSSTR AllowTcpForwarding set to \"no\"\n");
                            }
                        }

                        if ( grep( /PermitTunnel/, $_ ) ) {
                            $_ =~ s/\s+$//g;
                            next if ( grep( /^#/, $_ ) );
                            next if ( grep( /,/,  $_ ) );
                            ( undef, $SSHTCPTUN ) = split( /\s+/, $_ );
                            chomp($SSHTCPTUN);
                            if ( lc($SSHTCPTUN) eq 'yes' ) {
                                push(@SSHARR, "$WARNSTR PermitTunnel set to \"yes\"\n");
                                push(@SSHARR, "$NOTESTR It is strongly recommended to disable it\n");
                                push(@CHECKARR, "\n$WARNSTR SSH PermitTunnel set to \"yes\"\n");
                            }

                            if ( lc($SSHTCPTUN) eq 'no' ) {
                                push(@SSHARR, "$PASSSTR PermitTunnel set to \"no\"\n");
                            }
                        }
                    }
                    close(SSHCD);

                    if ( ! "$PWPN" ) {
                        push(@SSHARR, "$WARNSTR SSH allows direct Root access by default configuration\n");
                        push(@CHECKARR, "\n$WARNSTR SSH allows direct Root access by default configuration\n");
                    }

                    if ( ! "$SSHSTRICT" ) {
                        push(@SSHARR, "$PASSSTR StrictModes set to \"yes\" by default configuration\n");
                    }
            
                    if ( ! "$SSHRHOST" ) {
                        push(@SSHARR, "$PASSSTR IgnoreRhosts set to \"yes\" by default configuration\n");
                    }

                    if ( ! "$SSHEMPTYPW" ) {
                        push(@SSHARR, "$PASSSTR PermitEmptyPasswords set to \"no\" by default configuration\n");
                    }

                    if ( ! "$PWYN" ) {
                        push(@SSHARR, "$WARNSTR SSH allows password authentication by default configuration\n");
                        push(@CHECKARR, "\n$WARNSTR SSH allows password authentication by default configuration\n");
                    }

                    if ( ! "$SSHPRIVSEP" ) {
                        push(@SSHARR, "$PASSSTR UsePrivilegeSeparation set to \"yes\" by default configuration\n");
                    }

                    if ( ! "$SSHTCPFWD" ) {
                        push(@SSHARR, "$PASSSTR AllowTcpForwarding set to \"no\" by default configuration\n");
                    }
                }
                else {
                    print "\n$WARNSTR Cannot open $sxva\n";
                    push(@CHECKARR, "\n$WARNSTR Cannot open $sxva\n");
                    $warnings++;
                }
            }
        }
    }

    print "\n";

    if ( @SSHARR ) {
        print @SSHARR;
    }

    print "\n";

    checkActivePorts(22);

    datecheck();
    print_header("*** END CHECKING SECURE SHELL (SSH) $datestring ***");
}

#
# Subroutine to check Sun Explorer
#
sub SunExplorercheck {
    datecheck();
    print_header("*** BEGIN CHECKING SUN EXPLORER $datestring ***");

    if ( "$EXPLO_FLAG" > 0 ) {
        foreach my $exva (@EXplarr) {
            if ( -s "$exva" ) {
                my @Excat = `nawk '! /^#/ && ! /awk/ {print}' $exva`;
                if ("@Excat") {
                    print
                      "$INFOSTR Sun Explorer configuration file $exva\n";
                    print @Excat;
                }
                else {
                    print
"$INFOSTR Empty Sun Explorer configuration file $exva\n";
                }
            }
            else {
                print
"$WARNSTR Empty or non-existent Sun Explorer configuration file $exva\n";
                push(@CHECKARR,
"\n$WARNSTR Empty or non-existent Sun Explorer configuration file $exva\n");
                $warnings++;
            }
            print "\n";
        }
    }
    else {
        print "$WARNSTR Sun Explorer not installed\n";
        push(@CHECKARR, "\n$WARNSTR Sun Explorer not installed\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING SUN EXPLORER $datestring ***");
}

#
# Subroutine to check Sun Ray devices
#
sub SunRaycheck {

    if ( "$SUNRAY_FLAG" > 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING SUN RAY SERVERS $datestring ***");

        my @Utgstat = `utgstatus`;
        if ("@Utgstat") {
            print "$INFOSTR Sun Ray server status\n";
            print @Utgstat;
        }

        if ( -s "$Utconf" ) {
            my @utcheck = `nawk '! /^#/ && ! /awk/ {print}' $Utconf`;
            if ("@utcheck") {
                print "\n$INFOSTR Sun Ray configuration file $Utconf\n";
                print @utcheck;
            }
            else {
                print
"\n$WARNSTR Sun Ray configuration file $Utconf empty or non-existent\n";
                print "$WARNSTR Sun Ray utconfig should be run\n";
            }
        }

        datecheck();
        print_header("*** END CHECKING SUN RAY SERVERS $datestring ***");
    }
}

#
# Subroutine to check Zones
#
sub Zonecheck {

    my @domain_status = `domain_status -m 2>/dev/null`;
    if ("@domain_status") {
        datecheck();
        print_header("*** BEGIN CHECKING ENTERPRISE 10000 DOMAIN STATUS $datestring ***");

        print @domain_status;

        datecheck();
        print_header("*** END CHECKING ENTERPRISE 10000 DOMAIN STATUS $datestring ***");
    }

    my @get_hostinfo = `ndd -get /dev/dman man_get_hostinfo 2>/dev/null`;
    if ("@get_hostinfo") {
        datecheck();
        print_header("*** BEGIN CHECKING DOMAIN NETWORKS (HIGH-END SERVERS) $datestring ***");

        print @get_hostinfo;

        datecheck();
        print_header("*** END CHECKING DOMAIN NETWORKS (HIGH-END SERVERS) $datestring ***");
    }

    my @showdatasync = `showdatasync 2>/dev/null`;
    if ("@showdatasync") {
        datecheck();
        print_header("***BEGIN CHECKING DATASYNC ON SYSTEM CONTROLLERS (HIGH-END SERVERS) $datestring ***");

        print @showdatasync;

        datecheck();
        print_header("***END CHECKING DATASYNC ON SYSTEM CONTROLLERS (HIGH-END SERVERS) $datestring ***");
    }

    my @showfailover = `showfailover 2>/dev/null`;
    if ("@showfailover") {
        datecheck();
        print_header("*** BEGIN CHECKING FAILOVER ON SYSTEM CONTROLLER (HIGH-END SERVERS) $datestring ***");

        print @showfailover;

        datecheck();
        print_header("*** END CHECKING FAILOVER ON SYSTEM CONTROLLER (HIGH-END SERVERS) $datestring ***");
    }

    my @smsconfig = `smsconfig -v 2>/dev/null`;
    if ("@smsconfig") {
        datecheck();
        print_header("*** BEGIN CHECKING SMS NETWORK SETUP (HIGH-END SERVERS) $datestring ***");

        print @smsconfig;

        datecheck();
        print_header("*** END CHECKING SMS NETWORK SETUP (HIGH-END SERVERS) $datestring ***");
    }

    my @showenvironment = `showenvironment 2>/dev/null`;
    if ("@showenvironment") {
        datecheck();
        print_header("*** BEGIN CHECKING ENVIRONMENTAL DATA (HIGH-END SERVERS) $datestring ***");

        print @showenvironment;

        datecheck();
        print_header("*** END CHECKING ENVIRONMENTAL DATA (HIGH-END SERVERS) $datestring ***");
    }

    my @showplatform = `showplatform 2>/dev/null`;
    if ("@showplatform") {
        datecheck();
        print_header("*** BEGIN CHECKING PLATFORM (HIGH-END SERVERS) $datestring ***");

        print @showplatform;

        datecheck();
        print_header("*** END CHECKING PLATFORM (HIGH-END SERVERS) $datestring ***");
    }

    my @showcomponent = `showcomponent -v 2>/dev/null`;
    if ("@showcomponent") {
        datecheck();
        print_header("*** BEGIN CHECKING BLACKLIST STATUS OF COMPONENTS (HIGH-END SERVERS) $datestring ***");

        print @showcomponent;

        datecheck();
        print_header("*** END CHECKING BLACKLIST STATUS OF COMPONENTS (HIGH-END SERVERS) $datestring ***");
    }

    if ( "$Minor" >= 10 ) {
        datecheck();
        print_header("*** BEGIN CHECKING CONTAINERS (VIRTUAL ZONES) $datestring ***");

        foreach my $zp (@Zonepkgarr) {
            if ( grep( /\b$zp\b/, @SWarray ) ) {
                print "$PASSSTR Zone package $zp installed\n";
            }
            else {
                print "$INFOSTR Zone package $zp not installed\n";
            }
            print "\n";
        }

        my @Zstat = `zonename 2>/dev/null`;
        if ("@Zstat") {
            print "$INFOSTR Zonename status\n";
            print @Zstat;

            my @pooladm = `pooladm`;
            if ("@pooladm") {
                print "\n$INFOSTR Resource pool status\n";
                print @pooladm;
            }

            my @poolcfg = `poolcfg -c 'info' $POOLCFG`;
            if ("@poolcfg") {
                print
"\n$INFOSTR Current Resource pool configuration ($POOLCFG)\n";
                print @poolcfg;
            }

            my @poolstat = `poolstat -r all`;
            if ("@poolstat") {
                print "\n$INFOSTR Pool status for all resources\n";
                print @poolstat;
            }

            if ( open( ZOOP, "zoneadm list -cv |" ) ) {
                print "\n$INFOSTR Configured zones\n";
                while (<ZOOP>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                    chomp($_);
                    next if grep( /STATUS/, $_ );
                    $_ =~ s/^\s+//g;
                    ( $zoneid, $zonename, $zonestatus, $zonepath ) =
                      split( /\s+/, $_ );
                    if ("$zonename") {
                        next if ( "$zonename" eq "global" );
                        my @Znstat = `zonecfg -z $zonename info`;
                        if ("@Znstat") {
                            print "\n$INFOSTR $zonename info\n";
                            print "@Znstat";
                        }

                        my @Znexp = `zonecfg -z $zonename export`;
                        if ("@Znexp") {
                            print "\n$INFOSTR $zonename export\n";
                            print "@Znexp";
                        }
                    }
                }
                close(ZOOP);
            }
            else {
                print "$INFOSTR No zones configured\n";
            }
        }

#        my @zostat = `zonestat 5 5 2>/dev/null`;
        
        eval {
        # zonestat hangs from scripts, so we need to
        # manage how long it runs
        #
            local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - zonestat command interrupted\n"};
            alarm 80;
            my @zostat = `zonestat -q -r summary -z 5 -T i -R high 5 5 2>/dev/null`;
            if ("@zostat") {
                print "\n$INFOSTR Active zone statistics\n";
                print @zostat;
            }
            alarm 0;
        };

        if ($@) {
            warn "\n$WARNSTR Command \"zonestat\" timed out\n";
        }

        my @zonep2v = `zonep2vchk 2>/dev/null`;
        if ("@zonep2v") {
            print "\n$INFOSTR Check global zone's configuration for physical to virtual migration into non-global zone\n";
            print @zonep2v;
        }

        datecheck();
        print_header("*** END CHECKING CONTAINERS (VIRTUAL ZONES) $datestring ***");
    }

    if ( "$Minor" >= 10 ) {
        my @ldomv = `ldm -V 2>/dev/null`;

        if ( @ldomv) {
            datecheck();
            print_header("*** BEGIN CHECKING LOGICAL DOMAINS (LDOM) $datestring ***");
      
            print @ldomv;

            my @ldomlist = `ldm list-domain 2>/dev/null`;
            if ( @ldomlist ) {
                print "\n$INFOSTR LDom domain listing\n";
                print @ldomlist;
            }

            my @ldomlc = `ldm list-config 2>/dev/null`;
            if ( @ldomlc ) {
                print "\n$INFOSTR LDom configuration\n";
                print @ldomlc;
            }

            my @ldomll = `ldm ls -l 2>/dev/null`;
            if ( @ldomll ) {
                print "\n$INFOSTR LDom long listing of domains\n";
                print @ldomll;
            }

            my @ldomlp = `ldm list-services 2>/dev/null`;
            if ( @ldomlp ) {
                print "\n$INFOSTR LDom services\n";
                print @ldomlp;
            }

            my @ldomlb = `ldm list-bindings 2>/dev/null`;
            if ( @ldomlb ) {
                print "\n$INFOSTR LDom bindings\n";
                print @ldomlb;
            }

            my @ldomld = `ldm list-devices -a 2>/dev/null`;
            if ( @ldomld ) {
                print "\n$INFOSTR LDom devices\n";
                print @ldomld;
            }

            my @ldomlo = `ldm list-constraints 2>/dev/null`;
            if ( @ldomlo ) {
                print "\n$INFOSTR LDom constraints\n";
                print @ldomlo;
            }

            datecheck();
            print_header("*** END CHECKING LOGICAL DOMAINS (LDOM) $datestring ***");
        }
    }
}

#
# Subroutine to list RC scripts
#
sub RCcheck {
    datecheck();
    print_header("*** BEGIN CHECKING RC SCRIPTS $datestring ***");

    my @RCarray = (
        '/etc/rc0.d', '/etc/rc1.d', '/etc/rc2.d', '/etc/rc3.d',
        '/etc/rcS.d', '/etc/init.d',
    );

    foreach my $RCdir (@RCarray) {
        if ( -d "$RCdir" ) {
            my @RClist = `ls -1 $RCdir | egrep -v README`;

            if ("@RClist") {
                print "$INFOSTR $RCdir listing\n";
                print @RClist;
            }
            else {
                print "$INFOSTR $RCdir empty\n";
            }
        }
        else {
            print "$WARNSTR Directory $RCdir does not exist\n";
            push(@CHECKARR, "\n$WARNSTR Directory $RCdir does not exist\n");
            $warnings++;
        }
        print "\n";
    }

    datecheck();
    print_header("*** END CHECKING RC SCRIPTS $datestring ***");
}

#
# Subroutine to list OS build (cluster) information
#
sub OScheck {
    datecheck();
    print_header("*** BEGIN CHECKING OPERATING SYSTEM BUILD INFORMATION $datestring ***");

    foreach my $Odir (@OSarray) {
        if ( -s "$Odir" ) {
            my @Olist = `nawk NF $Odir`;

            if ("@Olist") {
                print "$INFOSTR $Odir listing\n";
                print "@Olist\n";
            }
        }
        else {
            print "\n$INFOSTR File $Odir empty or non-existent\n";
        }
    }

    if (! -d "$OSUPGRADE" ) {
        print "\n$INFOSTR System was seemingly build through clean install (directory $OSUPGRADE missing)\n";
    }
    else {
        print "\n$INFOSTR System was seemingly build through upgrade (directory $OSUPGRADE exists)\n";
    }
  
    if ( "$Minor" < 10 ) {
        my @altver = `pkginfo -l SUNWsolnm | grep VERSION`;
        if ("@altver") {
            print "\n$INFOSTR Solaris OE release\n";
            print @altver;
        }
    }
    else {
        print "\n$INFOSTR O/S $System $Maj $Version\n";
    }

    datecheck();
    print_header("*** END CHECKING OPERATING SYSTEM BUILD INFORMATION $datestring ***");
}

#
# Subroutine to check SNMP
#
sub SNMPcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SNMP $datestring ***");

    eval "require $snmpmod";
    if ( !"$@" ) {
        import $snmpmod;
        $SNMP_FLAG++;
    }
    elsif ( grep( /Can't locate/, "$@" ) ) {
        print "$INFOSTR Cannot find Perl module $snmpmod\n";
        &openport( $snmphostname, $snmpport, 'udp' );
    }
    else {
        print "$INFOSTR Cannot load $snmpmod: $@\n";
    }

    if ( "$Minor" >= 10 ) {
        $SNMPdm   = "/etc/dmi/conf/snmpXdmid.conf";
    }

    foreach my $SNMPconf (@SNMPARR) {
        if ( -s "$SNMPconf" ) {
            if ( open( LA, "egrep -v ^# $SNMPconf |" ) ) {
                my @NWX = ();
                while (<LA>) {
                    next if ( grep( /^$/, $_ ) );
                    push( @NWX, $_ );
                }
                close(LA);
                if ("@NWX") {
                    print "\n$INFOSTR SNMP Master file $SNMPconf\n";
                    print @NWX;
                }
                else {
                    print "\n$INFOSTR SNMP Master file $SNMPconf empty\n";
                }
            }
        }
        else {
            print "\n$INFOSTR SNMP Master file $SNMPconf not defined\n";
        }
    }

    if ( -s "$SNMPdm" ) {
        if ( open( LAB, "egrep -v ^# $SNMPdm |" ) ) {
            my @NWY = ();
            while (<LAB>) {
                next if ( grep( /^$/, $_ ) );
                push( @NWY, $_ );
            }
            close(LAB);
            if ("@NWY") {
                print "\n$INFOSTR SNMP Xdmid file $SNMPdm\n";
                print @NWY;
            }
            else {
                print "\n$INFOSTR SNMP Xdmid file $SNMPdm empty\n";
            }
        }
    }
    else {
        print "\n$INFOSTR SNMP Xdmid file $SNMPdm not defined\n";
    }

    if ( $SNMP_FLAG == 1 ) {
        ( $snmpsession, $snmperror ) = Net::SNMP->session(
            Hostname  => $snmphostname,
            Community => $snmpcommunity,
            Port      => $snmpport
        );

        if ( !defined($snmpsession) ) {
            printf( "$INFOSTR %s\n", $snmperror );
        }
        else {
            if ( !defined( $response = $snmpsession->get_request($oid) ) ) {
                print
"\n$PASSSTR Default SNMP public community password not active\n";
                printf( "$INFOSTR %s\n", $snmpsession->error );
            }
            else {
                print
"\n$WARNSTR Default SNMP public community password used\n";
                printf( "$oid for host '%s' is %s\n",
                    $snmphostname, $response->{$oid} );
            }
        }
        $snmpsession->close;
    }

    datecheck();
    print_header("*** END CHECKING SNMP $datestring ***");
}

#
# Check interesting files
#
sub BasSeccheck {
    datecheck();
    print_header("*** BEGIN CHECKING MAILBOX STATUS $datestring ***");

    foreach my $mmentry (@mailboxdir) {
        my @mailfile = `ls -alsb $mmentry 2>/dev/null`;
        if ( "@mailfile" ) {
            print "$INFOSTR Mailbox directory $mmentry\n";
            print "@mailfile\n";
        }
    }

    find( \&mailboxsearch, @mailboxdir );

    if ( $mboxcount > 0 ) {
        print "\n$INFOSTR Number of mailboxes is $mboxcount\n";
    }
    else {
        print "\n$INFOSTR There are no mailboxes on this server\n";
    }

    datecheck();
    print_header("*** END CHECKING MAILBOX STATUS $datestring ***");

    if ( "$opt_c" == 1 ) {
        datecheck();
        print_header("*** BEGIN CHECKING BASIC FILE SECURITY $datestring ***");

        find( \&dirsearch, @directories_to_search );

        datecheck();
        print_header("*** END CHECKING BASIC FILE SECURITY $datestring ***");
    }
}

#
# Check device file conflicts
#
sub DevFilecheck {
    datecheck();
    print_header("*** BEGIN CHECKING DEVICE MAJOR AND MINOR NUMBER STATUS $datestring ***");
    find( \&devsearch, "/devices" );

    if ( "@FINDUP") {
        print "$INFOSTR Multiple devices with identical major/minor numbers\n";
        print " @FINDUP";
    }
    else {
        print "$INFOSTR No multiple devices with identical major/minor numbers\n";
    }
}

sub devsearch {
    (
        $sdev,   $sino,     $smode, $snlink, $suid,
        $sgid,   $srdev,    $ssize, $satime, $smtime,
        $sctime, $sblksize, $sblocks
    ) = stat($File::Find::name);

    -l && next;

    if ( (-b "$File::Find::name") || (-c "$File::Find::name") ) {
        use integer;
        (my $major, my $minor) = ( $srdev / 256 , $srdev % 256 );
        no integer;
        my @DEVARRDUP = grep(/\b$major $minor\b/, @MAJMIN);
        if ( ! "@DEVARRDUP" ) {
            push(@MAJMIN, "$major $minor $File::Find::name\n");
        }
        else {
            push(@FINDUP, @DEVARRDUP);
            push(@FINDUP, "$major $minor $File::Find::name\n");
        }
    }
}

sub mailboxsearch {
    my (
        $mdev,   $mino,     $mmode, $mnlink, $muid,
        $mgid,   $mrdev,    $msize, $matime, $mmtime,
        $mctime, $mblksize, $mblocks,
    )
    = stat($File::Find::name);

    my @userent = getpwuid($muid);
    my @mailboxfile = split(/\//, $File::Find::name);
    my $mboxowner = $mailboxfile[$#mailboxfile];
    chomp($mboxowner);

    if ( $_ ne "." ) {
        next if ( grep(/:saved/, $File::Find::name) );
        if ( -d $File::Find::name ) {
            print "$INFOSTR Mailbox $File::Find::name is a directory\n";
#            push(@CHECKARR, "\n$WARNSTR Mailbox $File::Find::name is a directory\n");
#            $warnings++;
        } else {
            $mboxcount++;

            if ( ! "$userent[0]" ) {
                print "$WARNSTR Username $mboxowner missing for mailbox $File::Find::name\n";
                push(@CHECKARR, "\n$WARNSTR Username $mboxowner missing for mailbox $File::Find::name\n");
                print "$NOTESTR Mailbox $File::Find::name possibly obsolete\n";
                $warnings++;
            }
            else {
                print "$PASSSTR Username $userent[0] valid for mailbox $File::Find::name\n";
                if ( "$userent[0]" ne "$mboxowner" ) {
                    print "$WARNSTR Mailbox $File::Find::name owned by username $userent[0]\n";
                    push(@CHECKARR, "\n$WARNSTR Mailbox $File::Find::name owned by username $userent[0]\n");
                    $warnings++;
                }
                else {
                    print "$PASSSTR Mailbox $File::Find::name owned by username $mboxowner\n";
                }
            }

            if ( ! -T $File::Find::name ) {
                print "$WARNSTR Mailbox $File::Find::name not text (ASCII) file\n";
                push(@CHECKARR, "\n$WARNSTR Mailbox $File::Find::name not text (ASCII) file\n");
                $warnings++;
            }

            if ( -z $File::Find::name ) {
                print "$INFOSTR Zero-size file: $File::Find::name\n";
                push(@CHECKARR, "\n$INFOSTR Zero-size file: $File::Find::name\n");
                $warnings++;
            }

            if ( (-l $File::Find::name) && (! -e $File::Find::name) ) {
                print "$WARNSTR Invalid symbolic link: $File::Find::name\n";
                push(@CHECKARR, "\n$WARNSTR Invalid symbolic link: $File::Find::name\n");
                $warnings++;
            }

            my $DAYCK  = 365;
            my $HOWOLD = 24 * 3600 * $DAYCK; # 24 hours x 3600 minutes x 365 days
            if ( ( $EPOCHTIME - $mmtime ) > $HOWOLD ) {
                print "$WARNSTR $File::Find::name last modified more than $DAYCK ";
                print "days ago\n";
                push(@CHECKARR, "\n$WARNSTR $File::Find::name last modified more than $DAYCK days ago\n");
                $warnings++;
            }

            if ( $msize >= $MBOX_THRESHOLD ) {
                print
                "$WARNSTR Mailbox $File::Find::name large (threshold is 50 MB)\n";
                if ( $msize > 0 ) {
                    print "$INFOSTR Mailbox $File::Find::name is ", int($msize/1024), " KB\n";
                }
                push(@CHECKARR,
                "\n$WARNSTR Mailbox $File::Find::name large (threshold is 50 MB)\n");
                $warnings++;
                print "\n";
            }
            else {
                print
                "$PASSSTR Mailbox $File::Find::name smaller than threshold 50 MB\n";
                if ( $msize > 0 ) {
                    print "$INFOSTR Mailbox $File::Find::name is ", int($msize/1024), " KB\n";
                }
                print "\n";
            }
        }
    }
}

sub dirsearch {
    (
        $sdev,   $sino,     $smode, $snlink, $suid,
        $sgid,   $srdev,    $ssize, $satime, $smtime,
        $sctime, $sblksize, $sblocks
      )
      = stat($File::Find::name);

    if ( "$opt_n" != 1 ) {
        if ( $sdev < 0 ) {
            $File::Find::prune = 1;
        }
    }

    if ( grep(/^\/proc/, $File::Find::name) ) {
        $File::Find::prune = 1;
    }

    if ( (-f $File::Find::name) && ($_ eq 'core') ) {
        print "$INFOSTR Possibly a core file $File::Find::name\n";
    }

    -u && print "$INFOSTR SUID file: $File::Find::name\n";
    -g && print "$INFOSTR SGID file: $File::Find::name\n";
    -z && print "$INFOSTR Zero-size file: $File::Find::name\n";
    -l && !-e && print
      "$WARNSTR Invalid symbolic link: $File::Find::name\n";

    if ( !( grep( /\b$sgid\b/, @Grnumarr ) ) ) {
        print "$WARNSTR Missing group ownership: $File::Find::name\n";
        push(@CHECKARR, "\n$WARNSTR Missing group ownership: $File::Find::name\n");
    }

    if ( !( grep( /\b$suid\b/, @Passnumarr ) ) ) {
        print "$WARNSTR Missing user ownership: $File::Find::name\n";
        push(@CHECKARR, "\n$WARNSTR Missing user ownership: $File::Find::name\n");
    }

    datecheck();
    print_header("*** END CHECKING DEVICE MAJOR AND MINOR NUMBER STATUS $datestring ***");
}

#
# Subroutine to check file system free disk space and inodes
#
sub zfslist {
    if ( "$Minor" >= 10 ) {
        datecheck();
        print_header "*** BEGIN CHECKING ZFS $datestring ***";

        if ( open( ZFSC, "zfs list -o name,type,sharenfs,mountpoint,reservation,setuid,used,volsize,zoned 2>/dev/null |" ) ) {
            while (<ZFSC>) {
                print "$INFOSTR ZFS status\n";
                print $_;
                next if (grep(/no datasets available/, $_));
                next if (grep(/NAME/, $_));
                my $ZFSname = {};
                $ZFS_FLAG++;
                $_ =~ s/^\s+//g;
                ($ZFSname, undef) = split(/\s+/, $_);
                chomp($ZFSname);
                push(@ALLZFS, $ZFSname);
            }
            close(ZFSC);
        }
        else {
            print "\n$INFOSTR ZFS datasets do not exist\n";
        }

        foreach my $zs ( @ALLZFS ) {
            my @zfspool = `zfs get all $zs 2>/dev/null`;
            if ("@zfspool") {
                print "\n$INFOSTR ZFS dataset $zs\n";
                print @zfspool;
            }
        }

        if ( $ZFS_FLAG > 0 ) {
            my @zpools = `zpool status 2>/dev/null`;
            if ("@zpools") {
                print "\n$INFOSTR ZFS pool status\n";
                print @zpools;

                my @zpoolstat = `zpool status -vx 2>/dev/null`;
                if ("@zpoolstat") {
                    print "\n$INFOSTR ZFS pool health status\n";
                    print @zpoolstat;
                }

                my @zpoolupg = `zpool upgrade -v 2>/dev/null`;
                if ("@zpoolupg") {
                    print "\n$INFOSTR ZFS upgrade status\n";
                    print @zpoolupg;
                }

                my @zpoolvdevs = `zpool vdevs 2>/dev/null`;
                if ("@zpoolvdevs") {
                    print "\n$INFOSTR ZFS current mirror/pool device properties\n";
                    print @zpoolvdevs;
                }

                my @zpoolhistory = `zpool history 2>/dev/null`;
                if ("@zpoolhistory") {
                    print "\n$INFOSTR ZFS pool history\n";
                    print @zpoolhistory;
                }

                my @zpooliostat = `zpool iostat -v 2>/dev/null`;
                if ("@zpooliostat") {
                    print "\n$INFOSTR ZFS zpool iostat\n";
                    print @zpooliostat;
                }

                my @fsstatzfs = `fsstat zfs 2>/dev/null`;
                if ("@fsstatzfs") {
                    print "\n$INFOSTR ZFS fsstat\n";
                    print @fsstatzfs;
                }
            }
            else {
                print "\n$INFOSTR ZFS pools not defined\n";
            }

            if ("@zfsmount") {
                my $zfsmount2 = `zfs mount 2>/dev/null`;
                print "\n$INFOSTR ZFS mounted file systems\n";
                print "$zfsmount2\n";

                my @ALLRDISKS = `ls /dev/rdsk/c*s0 2>/dev/null`;
                if ( "$zpoolH" ) {
                    foreach my $actdisk ( @ALLRDISKS ) {
                        chomp($actdisk);
                        if ( open( VXI, "zdb -l $actdisk |" ) ) {
                            print "\n$INFOSTR ZFS debugger (zdb) status for disk $actdisk\n";
                            while (<VXI>) {
                                next if ( grep( /^$/, $_ ) );
                                print $_;
                                $_ =~ s/^\s+//g;
                                if ( grep( /^name=.*$zpoolH/, $_ ) ) {
                                    if ( ! grep(/\b$zpoolH\b/, @ZFSROOTARR )) {
                                        push(@ZFSROOTARR ,
"$INFOSTR Disk $actdisk belongs to root pool $zpoolH\n");
                                        $bings++; 
                                        $ZFSDISK++;
                                    } 
                                }
                            }
                            close(VXI);
            
                            ( undef, undef, $realdsk ) = split( /\//, $actdisk );
                            if ( grep( /^c[0-9]/, $realdsk ) ) {
                                chomp($realdsk);
                                my $realctrl = $realdsk;
                                $realctrl =~ s/t.*$//g;
                                $ZKARRAY{$realctrl}++;
                            }
                        }
                    }
                }

                if ( "@ZFSROOTARR" ) {
                    print @ZFSROOTARR;
                }

                my @lppm = keys(%ZKARRAY);

                foreach my $aaa (@lppm) {
                    print
"\n$WARNSTR Multiple disks ($ZKARRAY{$aaa}) on same controller $aaa\n";
                    push(@CHECKARR,
"\n$WARNSTR Multiple disks ($ZKARRAY{$aaa}) on same controller $aaa\n");
                    $warnings++;
                    $bings++;
                }

                my @zfschk = `zfs get checksum 2>/dev/null`;
                if ("@zfschk") {
                    print "\n$INFOSTR ZFS checksum summary\n";
                    print @zfschk;
                }
            }
            else {
                print "\n$INFOSTR No ZFS mounted file systems currently\n";
            }
        }
        else {
            print "\n$INFOSTR ZFS not configured\n";
        }

        datecheck();
        print_header "*** END CHECKING ZFS $datestring ***";
    }
}

sub ldapcalc {
    $LDAPSERVER++;
    push( @ldapdaemon, $_ );
}

sub liccalc {
    $LICENSE++;
    push( @licdaemon, $_ );
}

sub nsadmcalc {
    $NSADMIN++;
    push( @ldapdaemon, $_ );
}

#
# Check Xwindows/CDE
#
sub Xcheck {
    datecheck();
    print_header("*** BEGIN CHECKING XWINDOWS AND CDE STATUS $datestring ***");

    if ( "$GDMFLAG" > 0 ) {
        print "$INFOSTR GDM service status\n";
        print @GDMARR;
    }

    if ( "$CDE_FLAG" > 0 ) {
        print "$WARNSTR CDE/X Windows server seemingly running\n";
        push(@CHECKARR, "\n$WARNSTR CDE/X Windows server seemingly running\n");
        $warnings++;
    }

    if ( "$ENV{'DISPLAY'}" ne '' ) {
        print "\n$INFOSTR Environment variable DISPLAY set\n";
        print "$ENV{'DISPLAY'}\n";
    }

    checkActivePorts(6000);
    checkActivePorts(6112);
    checkActivePorts(7100);

    datecheck();
    print_header("*** END CHECKING XWINDOWS AND CDE STATUS $datestring ***");

    if ( "$opt_f" == 1 ) {
        datecheck();
        print_header("*** BEGIN NMAP PORT SCAN $datestring ***");

        my @TCPSCANTEST = `nmap -O -sS -p1-65535 $Hostname 2>/dev/null | nawk NF`;
        my @UDPSCANTEST = `nmap -sU -p1-65535 $Hostname 2>/dev/null | nawk NF`;

        if ("@TCPSCANTEST") {
            print "$INFOSTR TCP port scan on interface $Hostname\n";
            print @TCPSCANTEST;
        }
        else {
            print "$INFOSTR Nmap not installed or TCP scan empty\n";
        }

        if ("@UDPSCANTEST") {
            print "\n$INFOSTR UDP port scan on interface $Hostname\n";
            print @UDPSCANTEST;
        }
        else {
            print "$INFOSTR Nmap not installed or TCP scan empty\n";
        }

        datecheck();
        print_header("*** END NMAP PORT SCAN $datestring ***");
    }
}

#
# Subroutine to check Revision and Configuration Management (RCM)
#
sub RCMcheck {
    datecheck();
    print_header("*** BEGIN CHECKING REVISION AND CONFIGURATION MANAGEMENT $datestring ***");

    my @RCMVER = `rcmcollect -version 2>/dev/null`;
    if ("@RCMVER") {
        print "$INFOSTR RCM seemingly installed\n";
            print @RCMVER;
    }
    else {
        print "$INFOSTR RCM seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING REVISION AND CONFIGURATION MANAGEMENT $datestring ***");
}

#
# Subroutine to check runtime linking environment 
#
sub CRLEcheck {
    datecheck();
    print_header("*** BEGIN CHECKING RUNTIME LINKING ENVIRONMENT $datestring ***");

    my @crle = `crle 2>/dev/null`;
    if ( "@crle" ) {
        print @crle;
    }

    if ( $ENV{'LD_LIBRARY_PATH'} ne '' ) {
        print "\n$INFOSTR LD_LIBRARY_PATH defined\n";
        print "$ENV{'LD_LIBRARY_PATH'}\n";
    }

    datecheck();
    print_header("*** END CHECKING RUNTIME LINKING ENVIRONMENT $datestring ***");
}

#
# Subroutine to check ERM 
#
sub ERMcheck {
    datecheck();
    print_header("*** BEGIN CHECKING ENTERPRISE ROOT MODEL $datestring ***");

    if ( $ERMflag > 0 ) {
        print "$INFOSTR ERM client seemingly installed (username ermclnt exists)\n";
    }
    else {
        print "$INFOSTR ERM client not installed (username ermclnt missing)\n";
    }

    my @ermarr = `update_client -V 2>&1 | grep Version`;

    if ( @ermarr ) {
        print "\n$INFOSTR ERM client version\n";
        print @ermarr;
        my @ermcfg = `update_client -t 2>/dev/null`;
        print "\n$INFOSTR ERM client configuration\n";
        print @ermcfg;
    }

    datecheck();
    print_header("*** END CHECKING ENTERPRISE ROOT MODEL $datestring ***");
}

#
# Subroutine to check file system mount order in /etc/vfstab
#
sub checkmountorder {
    datecheck();
    print_header("*** BEGIN CHECKING LOCAL FILE SYSTEMS MOUNT ORDER AT BOOT $datestring ***");

    if ( "@zfsmount" ) {
        print "$INFOSTR ZFS mount order\n";
        my $MOUNTORDER = 1;
        foreach my $VZFS (@zfsmount) {
            next if ( grep( /^$/,  $VZFS ) );
            chomp($VZFS);

            my $v1 = my $v2 = q{}; 
            ( $v1, $v2 ) = split( /\s+/, $VZFS );
            $ORDMOUNTCNT = sprintf("%d%s", $MOUNTORDER, ordinalize($MOUNTORDER));
            if ( "$v2" ne "-" ) {
                print "$ORDMOUNTCNT... $v2\n";
                $MOUNTORDER++;
            }
        }
        print "\n";
    }

    if ( @MOUNTORD != 0 ) {
        print "$INFOSTR File system mount order in $FSTAB\n";
        print @MOUNTORD;
    }
    else {
        print "$ERRSTR Cannot define file system mount order in $FSTAB\n";
        push(@CHECKARR, "\n$ERRSTR Cannot define file system mount order in $FSTAB\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING LOCAL FILE SYSTEMS MOUNT ORDER AT BOOT $datestring ***");
}

# Subroutine to check SRS Netconnect 
#
sub checkSRS {
    datecheck();
    print_header("*** BEGIN CHECKING SRS NETCONNECT $datestring ***");

    if ( $SRSPROXY_FLAG > 0 ) {
        print "$PASSSTR SRS seemingly running\n";

        if ( -s "$SRSconfig" ) {
            my @srscat = `egrep -v ^# $SRSconfig 2>/dev/null | nawk NF`;
            if ( @srscat ) {
                print "\n$PASSSTR SRS configuration\n";
                print @srscat;
            }
        }

        my @srspxstat = `srspxstat 2>/dev/null`;
        if ( @srspxstat ) {
            print "\n$PASSSTR SRS status\n";
            print @srspxstat;
        }
    }
    else {
        print "$INFOSTR SRS seemingly not running or not applicable to current system\n";
   }

    datecheck();
    print_header("*** END CHECKING SRS NETCONNECT $datestring ***");
}

# PowerBroker
#
sub checkPowerBroker {
    datecheck();
    print_header("*** BEGIN CHECKING POWERBROKER $datestring ***");

    if ( $POWERBROKERSRV_FLAG > 0 ) {
        print "$PASSSTR PowerBroker Master host seemingly running\n";

        my @pbcheck = `pbcheck -c -s 2>/dev/null`;
        if ( @pbcheck != 0 ) {
            print "\n$INFOSTR PowerBroker client licensing check\n";
            print @pbcheck;
        }

        my @pbbench = `pbbench -v`;
        if ( @pbbench != 0 ) {
            print "\n$INFOSTR PowerBroker pbbench check\n";
            print @pbbench;
        }
    }
    else {
        print "$INFOSTR PowerBroker Master host seemingly not running\n";
    }

    if ( $POWERBROKERCL_FLAG > 0 ) {
        print "\n$PASSSTR PowerBroker Run and/or Log host seemingly running\n";
        my @pbcheck = `pbcheck 2>/dev/null`;
        if ( @pbcheck != 0 ) {
            print "\n$INFOSTR PowerBroker configuration check\n";
            print @pbcheck;
        }
    }
    else {
        print "\n$INFOSTR PowerBroker Run and/or Log host seemingly not running\n";
    }

    my @pbconf = `nawk NF $PBCONF 2>/dev/null`;
    if ( @pbconf != 0 ) {
        print "\n$INFOSTR PowerBroker Master configuration file $PBCONF\n";
        print @pbconf;
    }

    my @pbset = `nawk NF $PBSET 2>/dev/null`;
    if ( @pbset != 0 ) {
        print "\n$INFOSTR PowerBroker network and port configuration file $PBSET\n";
        print @pbset;
    }

    my @pbenc = `nawk NF $PBENC 2>/dev/null`;
    if ( @pbenc != 0 ) {
        print "\n$INFOSTR PowerBroker encryption key file $PBENC\n";
        print @pbenc;
    }

    my @pbshell = `nawk NF $PBSHELL 2>/dev/null`;
    if ( @pbshell != 0 ) {
        print "\n$INFOSTR PowerBroker Shells file $PBSHELL\n";
        print @pbshell;
    }

    datecheck();
    print_header("*** END CHECKING POWERBROKER $datestring ***");
}

#
# Subroutine to check / 
#
sub checkTLDIR {
   datecheck();
   print_header("*** BEGIN CHECKING TOP LEVEL DIRECTORY / $datestring ***");

   my $TLDIR = "/";

   my (
        $tdev,   $tino,   $tmode,  $tnlink,
        $tuid,   $tgid,   $trdev,  $tsize,
        $tatime, $tmtime, $tctime, $tblksize,
        $tblocks,
    ) = stat($TLDIR);

    if ( "$tuid" == 0 ) {
        print "$PASSSTR Top-level directory \"$TLDIR\" owned by UID $tuid\n";
    }
    else {
        print "$WARNSTR Top-level directory \"$TLDIR\" not owned by UID 0 ($tuid)\n";
        push(@CHECKARR, "\n$WARNSTR Top-level directory \"$TLDIR\" not owned by UID 0\n");
        $warnings++;
    }

    if ( "$tgid" == 0 ) {
        print "\n$PASSSTR Top-level directory \"$TLDIR\" owned by GID $tgid\n";
    }
    else {
        print "\n$WARNSTR Top-level directory \"$TLDIR\" not owned by GID 0 ($tgid)\n";
        push(@CHECKARR, "\n$WARNSTR Top-level directory \"$TLDIR\" not owned by GID 0\n");
        $warnings++;
    }

    my @tldlist = `ls -alsb $TLDIR 2>/dev/null`;
    if ( @tldlist ) {
        print "\n$INFOSTR Top-level directory \"$TLDIR\" listing\n";
        print @tldlist;
    }

   datecheck();
   print_header("*** END CHECKING TOP LEVEL DIRECTORY / $datestring ***");
}

# Subroutine to check Squid proxy
#
sub checkSquid {
   datecheck();
   print_header("*** BEGIN CHECKING SQUID PROXY $datestring ***");

   if ( !"@SQUIDRUN" ) {
       print "$INFOSTR Proxy server (squid) not running\n";
   }
   else {
      print "$INFOSTR Proxy server (squid) seemingly running\n";

      foreach my $squidfile (@SQUIDarray) {
          if ( -s "$squidfile" ) {
              my @sqlist = `egrep -v ^# $squidfile`;
              if ( @sqlist ) {
                  print "\n";
                  print "$INFOSTR Squid configuration in $squidfile\n";
                  print @sqlist;
              }
          }
      }
   }

   datecheck();
   print_header("*** END CHECKING SQUID PROXY $datestring ***");
}

#
sub ordinalize {
    $ccount = shift;

    my $ordlast2 = $ccount % 100;
    my $ordlast = $ccount % 10;

    if ($ordlast2 < 10 || $ordlast2 > 13) {
        return "st" if $ordlast == 1;
        return "nd" if $ordlast == 2;
        return "rd" if $ordlast == 3;
    }
    return "th";
}

# Subroutine to check Chef
#
sub check_chef {
    datecheck();
    print_header("*** BEGIN CHECKING CONFIGURATION MANAGEMENT TOOL CHEF $datestring ***");

    my @chefsrv = `chef-server-ctl test 2>/dev/null`;
    if ( "@chefsrv" ) {
        print "$INFOSTR Chef server is seemingly installed - full status\n";
        print @chefsrv;

        my @knifeall = `knife list -R / 2>/dev/null`;
        if ( "@knifeall" ) {
            print "$INFOSTR Chef full status\n";
            print @knifeall;
    
            my @knifeenv = `knife environment list -w 2>/dev/null`;
            if ( "@knifeenv" ) {
                print "\n$INFOSTR Chef list of environments\n";
                print @knifeenv;
            }
        }

        my @knifecl = `knife client list 2>/dev/null`;
        if ( "@knifecl" ) {
            print "\n$INFOSTR Chef list of registered API clients\n";
            print @knifecl;

            foreach my $chefcl ( @knifecl ) {
                chomp($chefcl);
                my @kchefcl = `knife client show $chefcl 2>/dev/null`;
                if ( "@kchefcl" ) {
                    print "\n$INFOSTR Chef detailed list for client \"chefcl\"\n";
                    print @kchefcl;
                }
            }
        }

        my @knifeco = `knife cookbook list 2>/dev/null`;
        if ( "@knifeco" ) {
            print "\n$INFOSTR Chef list of registered cookbooks\n";
            print @knifeco;

            foreach my $chefco ( @knifeco ) {
                chomp($chefco);
                my @kchefco = `knife cookbook show $chefco 2>/dev/null`;
                if ( "@kchefco" ) {
                    print "\n$INFOSTR Chef detailed list for cookbook \"chefco\"\n";
                    print @kchefco;
                }
            }
        }

        my @knifedb = `knife data bag list 2>/dev/null`;
        if ( "@knifedb" ) {
            print "\n$INFOSTR Chef list of data bags\n";
            print @knifedb;

            foreach my $chefdb ( @knifedb ) {
                chomp($chefdb);
                my @kchefdb = `knife data bag list $chefdb 2>/dev/null`;
                if ( "@kchefdb" ) {
                    print "\n$INFOSTR Chef detailed list for data bag \"chefdb\"\n";
                    print @kchefdb;
                }
            }
        }

        my @knifediff = `knife diff 2>/dev/null`;
        if ( "@knifediff" ) {
            print "\n$INFOSTR Chef differences between the local chef-repo and the files on the server\n";
            print @knifediff;
        }
    }
    else {
        print "$INFOSTR Chef server is seemingly not installed\n";
    }

    my @chefcc = `chef-client -v 2>/dev/null`;
    if ( "@chefcc" ) {
        print "\n$INFOSTR Chef client is seemingly installed\n";
        print @chefcc;
    }
    else {
        print "\n$INFOSTR Chef client is seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING CONFIGURATION MANAGEMENT TOOL CHEF $datestring ***");
}

# Subroutine to check CFEngine
#
sub check_cfengine {
   datecheck();
   print_header("*** BEGIN CHECKING CONFIGURATION MANAGEMENT TOOL CFENGINE $datestring ***");

   if ( "$CFENGINEMASTER" > 0 ) {
      print "$INFOSTR This server is seemingly an active CFEngine Server\n";
   }
   else {
      print "$INFOSTR This server is seemingly not an active CFEngine Server\n";
   }

   if ( "$CFENGINECLIENT" > 0 ) {
      print "\n$INFOSTR This server is seemingly an active CFEngine Agent\n";
   }
   else {
      print "\n$INFOSTR This server is seemingly not an active CFEngine Agent\n";
   }

   my @cfsrvv = `cf-serverd --version 2>/dev/null`;
   if ( "@cfsrvv" ) {
       print "\n$INFOSTR CFEngine v3 Server version\n";
       print @cfsrvv;
   }

   my @cfagentv = `cf-agent --version 2>/dev/null`;
   if ( "@cfagentv" ) {
       print "\n$INFOSTR CFEngine v3 Agent version\n";
       print @cfagentv;
   }

   my @cfpromise = `cf-report -q --show promises 2>/dev/null`;
   if ( "@cfpromise" ) {
       print "\n$INFOSTR CFEngine v3 promises\n";
       print @cfpromise;
   }

   my @cfval = `cf-promises -v 2>/dev/null 2>/dev/null`;
   if ( "@cfval" ) {
       print "\n$INFOSTR CFEngine v3 validation of policy code\n";
       print @cfval;
   }

   my @cfap = `cfagent -p -v 2>/dev/null`;
   if ( "@cfap" ) {
       print "\n$INFOSTR Cfengine v2 classes on the client\n";
       print @cfap;
   }

   my @cfagck = `cfagent --no-lock --verbose --no-splay 2>/dev/null`;
   if ( "@cfagck" ) {
       print "\n$INFOSTR Cfengine v2 managed client status\n";
       print @cfagck;
   }

   my @cfagd1 = `cfagent -n 2>/dev/null`;
   my @cfagd2 = `cf-agent -n 2>/dev/null`;
   my @cfagd = @cfagd1 || @cfagd2;
   if ( "@cfagd" ) {
       print "\n$INFOSTR Cfengine pending actions for managed client (dry-run)\n";
       print @cfagd;
   }
   else {
       print "\n$INFOSTR No cfengine pending actions for managed client found\n";
   }

   my @cfshowa = `cfshow --active 2>/dev/null`;
   if ( "@cfshowa" ) {
       print "\n$INFOSTR Cfengine v2 dump of active database\n";
       print @cfshowa;
   }

   my @cfshowc = `cfshow --classes 2>/dev/null`;
   if ( "@cfshowc" ) {
       print "\n$INFOSTR Cfengine v2 dump of classes database\n";
       print @cfshowc;
   }

   datecheck();
   print_header("*** END CHECKING CONFIGURATION MANAGEMENT TOOL CFENGINE $datestring ***");
}

# Subroutine to check Puppet
#
sub check_puppet {
   datecheck();
   print_header("*** BEGIN CHECKING CONFIGURATION MANAGEMENT TOOL PUPPET $datestring ***");

   if ( "$PUPPETMASTER" > 0 ) {
      print "$INFOSTR This server is seemingly an active Puppet Master\n";
   }
   else {
      print "$INFOSTR This server is seemingly not an active Puppet Master\n";
   }

   if ( "$PUPPETCLIENT" > 0 ) {
      print "\n$INFOSTR This server is seemingly an active Puppet Client\n";
   }
   else {
      print "\n$INFOSTR This server is seemingly not an active Puppet Client\n";
   }

   my @puppetd = `puppetd -v 2>/dev/null`;
   if ( "@puppetd" ) {
       print "\n$INFOSTR Puppet Client agent version\n";
       print @puppetd;
   }
   
   my @puppetcfg = `puppet config print all 2>/dev/null`;
   if ( "@puppetcfg" ) {
       print "\n$INFOSTR Puppet configuration\n";
       print @puppetcfg;
   }

   my @puppetcfgm = `puppet config print modulepath 2>/dev/null`;
   if ( "@puppetcfgm" ) {
       print "\n$INFOSTR Puppet configuration module paths\n";
       print @puppetcfgm;
   }

   my @puppetca = `puppetca -l -a 2>/dev/null`;
   if ( "@puppetca" ) {
       print "\n$INFOSTR Puppet certificates\n";
       print @puppetd;
   }

   my @facter = `facter 2>/dev/null`;
   if ( "@facter" ) {
       print "\n$INFOSTR Puppet facter about local server\n";
       print @facter;
   }

   my @puppetru = `puppet resource user 2>/dev/null`;
   if ( "@puppetru" ) {
       print "\n$INFOSTR Users in Puppet Resource Abstraction Layer (RAL)\n";
       print @puppetru;
   }

   my @puppetrp = `puppet resource package 2>/dev/null`;
   if ( "@puppetrp" ) {
       print "\n$INFOSTR Packages in Puppet Resource Abstraction Layer (RAL)\n";
       print @puppetrp;
   }

   my @puppetrs = `puppet resource service 2>/dev/null`;
   if ( "@puppetrs" ) {
       print "\n$INFOSTR Services in Puppet Resource Abstraction Layer (RAL)\n";
       print @puppetrs;
   }

   datecheck();
   print_header("*** END CHECKING CONFIGURATION MANAGEMENT TOOL PUPPET $datestring ***");
}

# Check Oracle instances
#
sub checkOracle {
    datecheck();
    print_header("*** BEGIN CHECKING ORACLE $datestring ***");

    foreach my $oracfg (@ORAARR) {
        if ( -s "$oracfg" ) {
            print "$INFOSTR $oracfg installed\n";
            my @oracat = `nawk NF $oracfg`;
            if (@oracat) {
                print @oracat;
            }
        }
        else {
            print "$INFOSTR $oracfg not installed\n";
        }
    }

    my @oracleasm = `oracleasm listdisks 2>/dev/null`;
    if (@oracleasm) {
        print "\n$INFOSTR Oracle Automatic Storage Management (ASM) status\n";
        print @oracleasm;
    }

    my @olsnodes = `olsnodes -v 2>/dev/null`;
    if (@olsnodes) {
        print "\n$INFOSTR Oracle Cluster status\n";
        print @olsnodes;
    }

    datecheck();
    print_header("*** END CHECKING ORACLE $datestring ***");
}

# Read in file with variables
#
if ( "$opt_t" ) {
    $glob_conf = $opt_t;

    if ( -s "$glob_conf" ) {
        slurp($glob_conf);
    }
    else {
        print "$ERRSTR Configuration file $glob_conf does not exist or is not readable\n";
        exit(1);
    }
}

if ($opt_v) {
     print "$INFOSTR OAT script version $SCRIPT_VERSION\n";
     exit(0);
}

SYS_INFO();
check_hostname_valid();
OScheck();
SCAN_HW();
CODchk();
swcheck();
sgcheck();
crashcheck();
svmsynccheck();
frucheck();
pscheck();

if ( grep( /SVM/, "$Diskmgr" ) ) {
    bootcheck();
    if ( "$Diskmgrno" == 2 ) {
        VXVM_CHECK();
    }
}
else {
    if ( "$Diskmgrno" != 0 ) {
        VXVM_CHECK();
    }
}

Jumpstartchk();
bootdev();
checkTLDIR();
DevFilecheck();
basic_daemons();
CHECK_MOUNTED_FILESYSTEMS();
checkmountorder();
zfslist();
space();
portcheck();
cron_access();
ROOT_CRON();
checkkernel();
lan();
lancheck();
IPseccheck();
swapcheck();
PERFORMANCE_BASICS();
CPUcheck();
SYSLOG_LOGGING();
ERMcheck();
CRLEcheck();
rootacc();
SCRBACcheck();
pwdbcheck();
checkPowerBroker();
inetdchk();
checkfirewall();
dnschk();
protchk();
ntp_check();
nfs_check();
smtpchk();
rpcchk();
checknull();
motd();
timezone_info();
SSHcheck();
SunExplorercheck();
RCMcheck();
fmdchk();
sachk();
OVchk();
PAMcheck();
nischk();
vendorbck();
lp_info();
samba_info();
localecheck();
STICKYcheck();
QUOTAcheck();
ULIMITcheck();
liccheck();
RCcheck();
tmpcleanupcheck();
BasSeccheck();
SANchk();
codewrd();
checkSRS();
IPCScheck();
HIDScheck();
LDAPclientcheck();
LDAPservercheck();
Kerberoschk();
DHCPchk();
SNMPcheck();
check_cfengine();
check_puppet();
check_chef();
Xcheck();
SunRaycheck();
Zonecheck();
checkSquid();
RSCcheck();
checkOracle();
patch();

# Tier 1 Basic
# Hardware must have 24x7x8 support at least
# Minimum RAM = 1024 MB
# Minimum CPUs = 1
# Minimum O/S disks (mirrored) = 2
# Minimum LAN cards = 2
# Minimum O/S disk controllers = 1
# Minimum power supplies = 1
# Minimum tape drives = 1
# Tape drives must be on separate controller!
#
my $TIERK = "Tier 1 Basic";
my $TIER1MEMMIN      = 1024;
my $TIER1CPUMIN      = 1;
my $TIER1OSDISKMIN   = 2;
my $TIER1LANMIN      = 2;
my $TIER1OSDISKCNTRL = 1;

# Tier 2 Standard
# Hardware must have 24x7x8 support at least
# Minimum RAM = 2048 MB
# Minimum CPUs = 1
# Minimum O/S disks (mirrored) = 2
# Minimum LAN cards = 2
# Minimum O/S disk controllers = 2
# Minimum power supplies = 2
# Minimum tape drives = 1
# Tape drives must be on separate controller!
#
my $TIER2MEMMIN      = 2048;
my $TIER2CPUMIN      = 1;
my $TIER2OSDISKMIN   = 2;
my $TIER2LANMIN      = 2;
my $TIER2OSDISKCNTRL = 2;

# Tier 3 High Availability
# Hardware must have 24x7x24 support
# Minimum RAM = 3072 MB
# Minimum CPUs = 2
# Minimum O/S disks (mirrored) = 2
# Minimum LAN cards = 2
# Minimum O/S disk controllers = 2
# O/S disks must be on separate controllers!
# Full cabinet power redundancy
# Minimum tape drives = 1
# Tape drives must be on separate controller!
#
my $TIER3MEMMIN      = 3072;
my $TIER3CPUMIN      = 2;
my $TIER3OSDISKMIN   = 2;
my $TIER3LANMIN      = 2;
my $TIER3OSDISKCNTRL = 2;

# Tier 4 Mission Critical
# Hardware must have 24x7x24 support
# Minimum RAM = 4096 MB
# Minimum CPUs = 2
# Minimum O/S disks (mirrored) = 2
# Minimum LAN cards = 4
# Minimum O/S disk controllers = 2
# O/S disks must be on separate controllers!
# Full cabinet power redundancy and UPS
# Minimum tape drives = 1
# Tape drives must be on separate controller!
#
my $TIER4MEMMIN      = 4096;
my $TIER4CPUMIN      = 2;
my $TIER4OSDISKMIN   = 2;
my $TIER4LANMIN      = 4;
my $TIER4OSDISKCNTRL = 2;

my $TIERL = ( $reallancardno >= $TIER4LANMIN ) ? "Tier 4 Mission Critical"
            : ( $reallancardno >= $TIER3LANMIN ) ? "Tier 3 High Availability"
            : ( $reallancardno >= $TIER2LANMIN ) ? "Tier 2 Standard"
            : ( $reallancardno >= $TIER1LANMIN ) ? "Tier 1 Basic"
            : "Tier 1 Basic";

my $TIERM = ( $MEM_MBYTE >= $TIER4MEMMIN ) ? "Tier 4 Mission Critical"
            : ( $MEM_MBYTE >= $TIER3MEMMIN ) ? "Tier 3 High Availability"
            : ( $MEM_MBYTE >= $TIER2MEMMIN ) ? "Tier 2 Standard"
            : ( $MEM_MBYTE >= $TIER1MEMMIN ) ? "Tier 1 Basic"
            : "Tier 1 Basic";

my $TIERP = ( $cpucount >= $TIER4CPUMIN ) ? "Tier 4 Mission Critical"
            : ( $cpucount >= $TIER3CPUMIN ) ? "Tier 3 High Availability"
            : ( $cpucount >= $TIER2CPUMIN ) ? "Tier 2 Standard"
            : ( $cpucount >= $TIER1CPUMIN ) ? "Tier 1 Basic"
            : "Tier 1 Basic";

my $TIERC = q{};

if ( "$SVM_FLAG" > 0 ) {
    if ( $SVMDISK < $TIER1OSDISKMIN ) {
        $TIERC = "Tier 1 Basic";
    }
    elsif ( $SVMDISK >= $TIER4OSDISKMIN ) {
        $TIERC = "Tier 4 Mission Critical";
    }
    elsif ( $SVMDISK >= $TIER3OSDISKMIN ) {
        $TIERC = "Tier 3 High Availability";
    }
    elsif ( $SVMDISK >= $TIER2OSDISKMIN ) {
        $TIERC = "Tier 2 Standard";
    }
    else {
        $TIERC = "Tier 1 Basic";
    }

    if ( $bings == 0 ) {
        $TIERK = "Tier 4 Mission Critical";
    }
    else {
        $TIERK = "Tier 1 Basic";
    }
}
elsif ( "$ZFS_FLAG" > 0 ) {
    if ( $ZFSDISK < $TIER1OSDISKMIN ) {
        $TIERC = "Tier 1 Basic";
    }
    elsif ( $ZFSDISK >= $TIER4OSDISKMIN ) {
        $TIERC = "Tier 4 Mission Critical";
    }
    elsif ( $ZFSDISK >= $TIER3OSDISKMIN ) {
        $TIERC = "Tier 3 High Availability";
    }
    elsif ( $ZFSDISK >= $TIER2OSDISKMIN ) {
        $TIERC = "Tier 2 Standard";
    }
    else {
        $TIERC = "Tier 1 Basic";
    }
}
else {
    $TIERC = "Tier X (please verify manually)";
}

my $TIERT = "Tier 1 Basic";

my @tapelst = `ls /dev/rmt | egrep -v "n|u|h|c|b|m|l"`;
foreach my $sintape ( @tapelst ) {
    chomp($sintape);
    my @tapestat = `mt -f /dev/rmt/$sintape config 2>&1 | egrep -v "No such"`;
    if ( "@tapestat" ) {
        push(@tapes, $_);
    }
}

if (@tapes) {
    $TIERT = "Tier 4 Mission Critical";
}

print "\nSUMMARY:
Operations Acceptance Testing (OAT) assessment reported $warnings warnings\n";

if ( "@CHECKARR" ) {
    print @CHECKARR;
    print "\n";
}

print
"Estimate (based on highest Tier level that satisfied test conditions):

   LAN redundancy            ... $TIERL
   CPU redundancy            ... $TIERP
   Minimum RAM               ... $TIERM
   Tape drive(s) available   ... $TIERT
";

if ( ( "$SVM_FLAG" > 0 ) || ( "$ZFS_FLAG" > 0 ) ) {
    print "   O/S disk redundancy       ... $TIERC
   O/S controller redundancy ... $TIERK
";
}

my $TTIERC = my $TTIERM = my $TTIERK = my $TTIERP = my $TTIERL = q{};
my @ACCESSTIER = ();

(undef, $TTIERC, undef) = split(/\s+/, $TIERC);
push(@ACCESSTIER, $TTIERC);
my $OVERALLTIER = $TTIERC;
(undef, $TTIERK, undef) = split(/\s+/, $TIERK);
push(@ACCESSTIER, $TTIERK);
(undef, $TTIERL, undef) = split(/\s+/, $TIERL);
push(@ACCESSTIER, $TTIERL);
(undef, $TTIERP, undef) = split(/\s+/, $TIERP);
push(@ACCESSTIER, $TTIERP);
(undef, $TTIERM, undef) = split(/\s+/, $TIERM);
push(@ACCESSTIER, $TTIERM);

foreach my $TESTTIER (@ACCESSTIER) {
    if ($TESTTIER < $OVERALLTIER) {
        $OVERALLTIER = $TESTTIER;
    }
}

print "
Overall Tier (reviewed for this server as stand-alone) is $OVERALLTIER.
";

if ( "$opt_r" == 1 ) {
    print "Since the server is part of a cluster or H/A group,
please assess the overall Tier by checking the whole environment\n";
}

print "It is strongly recommended to evaluate all warnings.";

exit(0);
