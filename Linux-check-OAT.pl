#!/usr/bin/env perl

# @(#) $Id: Linux-check-OAT.pl,v 6.10 2014/11/06 18:38:58 root Exp root $

# Description: Basic Operations Acceptance Testing for Linux servers
#              Results are displayed on stdout or redirected to a file
#
# If you obtain this script via Web, convert it to Unix format. For example:
# dos2unix -n Linux-check-OAT.pl.txt Linux-check-OAT.pl
#
# Usage:       Linux-check-OAT.pl [-c] [-h] [-f] [-n] [-o] [-r] [-t conffile] [-v] [-z] 
#              [> `uname -n`-OAT-report.txt]
#
#              -c        Enable check of SUID/SGID files
#              -f        Enable NMAP scans
#              -h        Print this help message
#              -n        Enable SUID/SGID checks in NFS
#              -o        OpenView monitoring used (default is OVO not used)
#              -r        Server part of cluster or H/A server group
#              -t file   Read variables from a config file
#              -v        Print version of this script 
#              -z        Enable SMART checks (smartctl)
#
# Last Update:  6 November 2014
# Designed by:  Dusan U. Baljevic (dusan.baljevic@ieee.org)
# Coded by:     Dusan U. Baljevic (dusan.baljevic@ieee.org)
# 
# I acknowledge kind corrections by Ralph Roth of cfg2html fame.
# His contribution is also recognised for numerous suggestions
# for additional tests.
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
# Perl script Linux-check-oat.pl is a modest attempt to automate basic
# tasks when running Operations Acceptance Testing (OAT) for a server
# that is about to be commissioned or checked.
#
# The script tries to capture most critical information about a Linux
# server and highlights potential configuration or system problems.
#
# The script has been developed over several hectic days, so errors
# (although not planned) might exist. Please use with care.
# 
# There are not many comments throught the script and that
# is not best practices for writing good code. However,
# I view this script as a learning tool for system administrators
# too so lack of comments is partially left as an exercise.
#
# My goals were:
#
# A) Simplicity to do basic Operations Acceptance Testing (OAT)
# on Linux servers;
# B) Portability;
# C) Standard Perl interpreter (very few modules - optional);
# D) Many new features;
# E) Support for LVM and VxVM;
# F) No temporary files;
# G) No repeated runs of similar commands;
# H) Not to replace more comprehensive debugging tools but
# provide a quick summary of server status;
# I) Usefulness of results, not their formatting on the screen;
#
# Like all scripts and programs, this one will continue to
# change as our needs change.

#
# Define important environment variables
#
$ENV{'PATH'} = "/bin:/usr/sbin:/sbin:/usr/bin:/usr/local/bin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/local/sbin:/opt/hp/hp_fibreutils";
$ENV{'PATH'} = "$ENV{PATH}:/HORCM/usr/bin:/opt/HORCM/usr/bin:/opt/hpcfs/lib";
$ENV{'PATH'} = "$ENV{PATH}:/opt/polyserve/sbin:/opt/polyserve/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/polyserve/tools";
$ENV{'PATH'} = "$ENV{PATH}:/opt/compaq/utils:/opt/compaq/storage/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/ids/bin:/var/opt/OV/bin/OpC/cmds";
$ENV{'PATH'} = "$ENV{PATH}:/opt/OV/bin:/opt/OV/contrib/OpC";
$ENV{'PATH'} = "$ENV{PATH}:/opt/omni/bin:/opt/omni/lbin:/opt/omni/sbin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/OV/bin/OpC:/opt/HPO/SMSPI:/opt/erm/sbin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/lib/rpm:/opt/resmon/bin:/usr/lbin/sysadm";
$ENV{'PATH'} = "$ENV{PATH}:/opt/tivoli/tsm/server/bin:/var/cfengine/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/tivoli/tsm/client/ba/bin:/opt/adsmserv/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/Zimbra/bin:/opt/zimbra/bin:/opt/Zimbra/contrib";
$ENV{'PATH'} = "$ENV{PATH}:/opt/quest/sbin:/opt/quest/bin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/local/qs/bin:/opt/qs/bin:/etc/init.d";

#
# Define Shell
#
$ENV{'SHELL'} = '/bin/sh' if $ENV{'SHELL'} ne '';
$ENV{'IFS'}   = ''        if $ENV{'IFS'}   ne '';

no strict 'refs';
use strict;

#use diagnostics;
#use warnings;
#
# List all variables on purpose
#
use vars qw($CMD $pty $PTYcur $System $Hostname $Maj $Version
  $Major $Minor $Patch $opt_h $opt_f %opts $fqdn $Hardware $u $Hostname1
  %disklist $ARCH %MAXPV $opt_w %OSARRAY %VGfpe %VGpes $opt_c $opt_f
  $SCRIPT_VERSION $REC_VERSION $BEST_VERSION $CUR_VERSION $OLDER_PERL_FLAG
  $s $opt_n $opt_o $opt_r $opt_s $opt_t $opt_z $opt_v $dpcw %shadarr %lines
  %ZKARRAY);

if ( $CUR_VERSION < $REC_VERSION ) {
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
elsif ( $CUR_VERSION < $BEST_VERSION ) {
    $OLDER_PERL_FLAG++;
    print "NOTE: For best results (and to avoid bugs in older versions)
it is highly recommended to upgrade Perl to $BEST_VERSION or higher.
\n";
}

#
# Global variables
#
my @TMPFSARR        = ();
my @SSHARR          = ();
my $maxpv           = q{};
my @PSARR           = ();
my @userid          = ();
my $psline          = q{};
my @pss             = ();
my @PSSLEEP         = ();
my @PSUNINTSLEEP    = ();
my @PSRUN           = ();
my $MPATHCFG        = "/etc/multipath.conf";
my @PSSTOP          = ();
my @PSPAGE          = ();
my @PSDEAD          = ();
my @PSZOMBIE        = ();
my @PSREST          = ();
my @CRarr           = ();
my $DEBIFCFG        = "/etc/network/interfaces"; 
my @droutes         = ();
my $ORATAB          = "/etc/oratab";
my @INITARR         = ();
my @PVARRAY         = ();
my @TAINTARR        = ();
my @MODARR          = ();
my $Modname         = ();
my $MCCLLOCKVG      = q{};
my $MCCLLOCKDISK    = q{};
my $MCCLNAME        = q{};
my @MYVGS           = ();
my $PVGconf         = "/etc/lvm/lvm.conf";
my $cmdline         = "/proc/cmdline";
my $proctaint       = "/proc/sys/kernel/tainted";
my @kcmod           = ();
my $ESXCONF         = "/etc/vmware/esx.conf";
my $VXPACFG         = "/etc/vmware/vxpa.cfg";
my @VSHARR          = ();
my @LDEFARR         = ();
my $SSHD_CONF       = '';
my $SSHD_CONF1      = '/etc/opt/ssh/sshd_config';
my $SSHD_CONF2      = '/opt/ssh/etc/sshd_config';
my $SSHD_CONF3      = '/usr/local/etc/sshd_config';
my $SSHD_CONF4      = '/usr/local/ssh/etc/sshd_config';
my $SSHD_CONF5      = '/etc/ssh/sshd_config';
my $dpck            = "/etc/opt/omni/client/cell_server";
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
my $SSHRHOST        = q{};
my $SSHEMPTYPW      = q{};
my $SSHPRIVSEP      = q{};
my $SSHSTRICT       = q{};
my $SSHTCPFWD       = q{};
my $SSHTCPTUN       = q{};
my @FSTABINFO       = ();
my @PSINFO          = ();
my $ccount          = q{};
my $mine            = q{};
my $mingood         = q{};
my $oct_perms       = q{};
my $offset          = q{};
my $VH              = q{};
my $VV              = q{};
my $ok              = q{};
my @olack           = ();
my $used            = q{};
my $Crd             = q{};
my $curpv           = q{};
my $Auto            = q{};
my $avail           = q{};
my $c               = q{};
my @Swap            = ();
my $tm              = q{};
my $tohour          = q{};
my $USED            = q{};
my $FREESPACE       = q{};
my $fromhour        = q{};
my $fs              = q{};
my $ALTLINK         = q{};
my $fs_crash        = q{};
my $fsreal          = q{};
my @fss             = ();
my @Fstabed         = ();
my $freepe          = q{};
my $Active          = q{};
my $alength         = q{};
my $allct           = q{};
my $alldet          = q{};
my $allocated       = q{};
my $swappriority    = q{};
my $Lmet            = q{};
my $rxok            = q{};
my $opcflag         = q{};
my $vgname          = q{};
my $iflg            = q{};
my $pcused          = q{};
my $pesize          = q{};
my $pgsize          = q{};
my $poll            = q{};
my $MS              = q{};
my $lastrx          = q{};
my $lastsample      = q{};
my $Portproto       = q{};
my $buf             = q{};
my $buf1            = q{};
my $ctime           = q{};
my $ddriv           = q{};
my $dev             = q{};
my $iallocated      = q{};
my $iused           = q{};
my $iavail          = q{};
my $Lname           = q{};
my $Lmtu            = q{};
my $swapreserve     = q{};
my $swapstart       = q{};
my $swapused        = q{};
my $uid             = q{};
my $username        = q{};
my $Vxopts          = q{};
my $y               = q{};
my $SYSLOGD_FLAG    = 0;
my $SYSINIT_FLAG    = 0;
#
my $KICKSTART       = "/root/anaconda-ks.cfg";
#
#
# Hashing algorithms
#
my %PWHASHARR = ( "1", "hashing-algorithm=MD5",
                 "2",  "hashing-algorithm=Blowfish",
                 "2a", "hashing-algorithm=Blowfish-system-specific-handling-8bit-chars",
                 "2y", "hashing-algorithm=Blowfish-with-correct-handling-8bit-chars",
                 "5",  "hashing-algorithm=SHA-256",
                 "6",  "hashing-algorithm=SHA-512",
               );

my $DESLENGTH = 13;

# String lengths for encrypted part of the pasword string
#
my %PWLEN     = ( "1",  "22",
                  "2a", "53",
                  "2y", "53",
                  "5",  "43",
                  "6",  "86",
                );

my $Csec            = q{};
my $Cmin            = q{};
my $Chour           = q{};
my $Cmday           = q{};
my $Cmon            = q{};
my $Cyear           = q{};
my $Cwday           = q{};
my $Cyday           = q{};
my $Cisdst          = q{};
my $datestring      = q{};

#
# PolyServe
my $MXINITCONF      = "/etc/var/polyserve/mxinit.conf";
my $PCITABLE        = "/etc/opt/polyserve/fc_pcitable";
my $PSLICFILE       = "/etc/opt/polyserve/licenses/license";
#
my @VXERRARR        = ();
my $TSMCL_FLAG      = 0;
my $TSMSRV_FLAG     = 0;
my $acst            = q{};
my $acst2           = q{};
my @CLARR           = ();
my $impdisk         = q{};
my $impdisk3        = q{};
my @initarr         = ();
my @lvlist          = ();
my $initt           = "/etc/inittab";
my $inodefree       = q{};
my $inodepcused     = q{};
my $inodeused       = q{};
my $iotout          = q{};
my $IsDST           = q{};
my $lancardno       = q{};
my $lancount        = q{};
my $lvmresync       = q{};
my $lvolid          = q{};
my $lvsize          = q{};
my $Mactype         = q{};
my @ALLMounted      = ();
my $mydisk          = q{};
my $Netif           = q{};
my $ftpusr          = q{};
my $fulfcpath       = q{};
my $gid             = q{};
my @entry           = ();
my @SWarray         = ();
my $patime          = q{};
my $pblksize        = q{};
my $pblocks         = q{};
my $pctime          = q{};
my $pdev            = q{};
my $pfile_perms     = q{};
my $pgid            = q{};
my $pino            = q{};
my $pmode           = q{};
my $pmtime          = q{};
my $pnlink          = q{};
my $poct_perms      = q{};
my @port            = ();
my $prdev           = ();
my @privent         = q{};
my $psize           = q{};
my $sino            = q{};
my $size            = q{};
my $smode           = q{};
my $smtime          = q{};
my $pstreeflag      = q{};
my $puid            = q{};
my @rbacck          = ();
my @rbaclist        = ();
my $rdev            = q{};
my $RELAY           = q{};
my $response        = q{};
my $satime          = q{};
my $sblksize        = q{};
my $sblocks         = q{};
my $scrflag         = q{};
my $sctime          = q{};
my $sdev            = q{};
my $sgid            = q{};
my $snlink          = q{};
my $tswap           = q{};
my $i               = q{};
my $IDLE            = q{};
my $len_lline       = q{};
my $lfs             = q{};
my $lvdisk          = q{};
my $srdev           = q{};
my $SrvHostIP       = q{};
my $SrvHostIPsubnet = q{};
my $ssize           = q{};
my $ssm             = q{};
my $sst             = q{};
my $stop_time       = q{};
my $suid            = q{};
my $swapdev         = q{};
my $swapfree        = q{};
my $swappctused     = q{};
my $DDate           = q{};
my $RSYSLOG         = q{};
my $LOGSTR          = q{};
my @LVarr           = ();
my $servdsk         = q{};
my $Ttype           = q{};
my @cmget           = ();
my @cmview          = ();
my $displ           = q{};
my $dpath           = q{};
my $dstatus         = q{};
my $dstflag         = q{};
my $disk            = q{};
my $Diskmgrcnt      = q{};
my $Diskmgrno       = q{};
my $disksize        = q{};
my $disksizeGB      = q{};
my $ffs             = q{};
my $file_perms      = q{};
my $ino             = q{};
my $instance        = q{};
my $alldet2         = q{};
my $alldet3         = q{};
my $ldapcld_conf    = q{};
my $ldap_conf       = "/etc/ldap.conf";
my $sldap_conf      = "/etc/openldap/slapd.conf";
my $ldap2_conf      = "/etc/openldap/ldap.conf";
my $ldap3_conf      = "/etc/ldap/ldap.conf";
my $SLAPDDEF        = "/etc/default/slapd";
my $IPsecversion    = q{};
my $KERN            = q{};
my $KMEM            = q{};
my $when            = q{};
my @addrs           = ();
my $alis            = q{};
my $armline         = q{};
my $atime           = q{};
my $blk             = q{};
my $blk1            = q{};
my $blksize         = q{};
my $blocks          = q{};
my $esmid           = q{};
my $esmport         = q{};
my $ESMport         = q{};
my $ESM_server      = q{};
my @esmstart        = ();
my $f               = q{};
my $fcpath          = q{};
my $fileux          = q{};
my $finalsa         = q{};
my $NISPLUSslave    = q{};
my $nlink           = q{};
my $np              = q{};
my $Laddr           = q{};
my $lanok           = q{};
my @lastpv          = ();
my $Lcoll           = q{};
my $gwip            = q{};
my $h               = q{};
my $host            = q{};
my $HostIP          = q{};
my $HostIPsubnet    = q{};
my $mode            = q{};
my $mrdev           = q{};
my $msize           = q{};
my $mtime           = q{};
my $muid            = q{};
my $myndd           = q{};
my $nddflag         = q{};
my $ndz             = q{};
my $NISclient       = q{};
my $nisflag         = q{};
my $NISPLUSclient   = q{};
my $NISPLUSserver   = q{};
my $Lipkt           = q{};
my @listpath        = ();
my $Lnet            = q{};
my @loccur          = ();
my $Loerr           = q{};
my $Lopkt           = q{};
my $mblocks         = q{};
my $mctime          = q{};
my $mdev            = q{};
my $mgid            = q{};
my $matime          = q{};
my $mblksize        = q{};
my $pathf           = q{};
my $mino            = q{};
my $minswap         = q{};
my $mmode           = q{};
my $mmtime          = q{};
my $mnlink          = q{};
my $lhentry         = "127.0.0.1";
my $Rootdir         = "/root";
my $hourrun         = q{};
my $LZVALUE         = q{};
my $SMTPD           = "/etc/mail/sendmail.cf";
my @PPanarray       = ();
my $vxe             = q{};
my @pvlist          = ();
my $PPA             = q{};
my $ppanic          = q{};
my $pvdisk          = q{};
my $reach           = q{};
my $refid           = q{};
my $remfs           = q{};
my $remote          = q{};
my $REMOTE          = q{};
my $rgval           = q{};
my @Root            = ();
my $rootacc         = q{};
my $Rootarray       = q{};
my $sockaddr        = q{};
my $st              = q{};
my $rootgecos       = q{};
my $rootgid         = q{};
my $roothome        = q{};
my $rootpasswd      = q{};
my $rootshell       = q{};
my $rootuid         = q{};
my $SG              = q{};
my $SGCNT           = q{};
my $sgval           = q{};
my $slength         = q{};
my $vxcom           = q{};
my $vxda            = q{};
my $MEM_MBYTE       = q{};
my $vxfscount       = 0;
my $vgformat        = q{};
my $SERVICES        = "/etc/services";
my $PROTOCOLS       = "/etc/protocols";
my $ETHERS          = "/etc/ethers";
my @ARMDSP          = ();
my $Rclog           = "/var/log/boot.log";
my $BOOTCHARTCONF   = "/etc/init/bootchart.conf";
my $ARRFLAG         = 0;
my @PassWdarr       = ();
my @ESMportarr      = ();
# PowerBroker
#
my $POWERBROKERSRV_FLAG = 0;
my $POWERBROKERCL_FLAG  = 0;
my $PBCONF              = "/etc/pb.conf";
my $PBSET               = "/etc/pb.settings";
my $PBENC               = "/etc/pb.key";
my $PBSHELL             = "/etc/pbshells.conf";
#
my $CUPSCONF            = "/etc/cups/cupsd.conf";
my $CUPSPR              = "/etc/cups/printers.conf";
#
my $nfsconf         = "/etc/sysconfig/nfs";
my $lkcddump        = "/etc/sysconfig/dump";
my @OVset           = ();
my $nfscount        = 0;
#
my $btmplog         = "/var/log/btmp";
my $faillog         = "/var/log/faillog";
#
# How many mailboxes in /var/spool/mail or /var/mail?
#
my $mboxcount       = 0;
#
my @MAU             = ();
my @ftpDisArr       = ();
my @grentry         = ();
my @GWlist          = ();
my @Grarr           = ();
my $ntpconf         = "/etc/ntp.conf";
my $chronyconf      = "/etc/chrony.conf";

#
my @CRONARR         = ( "/etc/cron.deny", "/etc/cron.allow",
                        "/etc/at.deny",   "/etc/at.allow",
                      );

# How long to wait for commands to complete (enable alarms)
#
my $ALARM_TIMEOUT = 40;

my @SPMGR           = ();
my $state           = q{};
my @ESMfull         = ();
my $ssd             = "/etc/sysconfig/syslog";
my $rssd            = "/etc/sysconfig/rsyslog";
my $secnets         = "/var/yp/securenets";
my $secservers      = "/var/yp/secureservers";
my $delay           = q{};
my $sudoconf        = q{};
my $exportfs        = "/etc/exports";
my $sectty          = "/etc/securetty";
my $sudoconf1       = "/etc/sudoers";
my $sudoconf2       = "/opt/sudo/etc/sudoers";
my $sudoconf3       = "/usr/local/etc/sudoers";
my $sulog           = "/var/log/sulog";
my $Superconf       = q{};
my $execstackflag   = q{};
my $kerndmesgflag   = q{};
my $swappiness      = q{};
my @SYSCTLARR       = ();
my $Superconf1      = "/opt/super/etc/super.tab";
my $Superconf2      = "/etc/super.tab";
my $Superconf3      = "/usr/local/etc/super.tab";
my $UXSA            = "/var/log/sa";
my $XWIN_FLAG       = 0;
my @alllocales      = ();
my $accnomb         = 0;
my $MBOX_THRESHOLD  = 52428800;    # 50 MB
my @mailboxdir      = ("/var/spool/mail", "/var/mail");
my $ERMflag         = 0;
my $RPMDIR          = "/var/lib/rpm";
my $syslog_conf     = "/etc/syslog.conf";
my @WARNSLOGARR     = ();
my $rsyslog_conf    = "/etc/rsyslog.conf";
my $rsyslogdir      = "/etc/rsyslog.d";
my $syslogng_conf   = "/etc/syslog-ng/syslog-ng.conf";
my $SYSLOG          = "/var/log/messages";
my $BOOTDIR         = "/boot";
my @HEADLN          = ();
my $EFIDIR          = "/sys/firmware/efi";
my $LILOCONF        = "/etc/lilo.conf";
my $IBMESERVZSERIES = "/etc/zipl.conf";
my $IBMESERVPSERIES = "/etc/aboot.conf";
my $Diskmgr         = q{};
my $Diskmgr1        = q{};
my $Diskmgr2        = q{};
my $Diskmgr3        = q{};
my $Diskmgr4        = q{};
my $initconf        = '/etc/rc.d/init.d/functions';
my $POSTFIX_FLAG    = 0;
my $alis1           = "/etc/mail/aliases";
my $alis2           = "/etc/aliases";
my $secdev          = q{};
my $AUDIT_FLAG      = 0;
my $SCSIDEV         = q{};
my @SCSIARR         = ();
my $PWYN            = q{};
my $PWPN            = q{};
my $SENDMAIL_FLAG   = 0;
my $EXIM_FLAG       = 0;
my $cpucount        = 0;
my $reallancardno   = 0;
my $ordlast         = q{};
my $ordlast2        = q{};
my $MOUNTORDER      = 1;
my $ORDMOUNTCNT     = 1;
my @MOUNTORD        = ();
my @OVget         = ();
my $NETWKCONF     = "/etc/init.d/networker";
my $ZEROCONF_FLAG = q{};
my @NETCONFARR    = ();
my @NETSTATARR    = ();
my @RCarray       = (
                    '/etc/rc0.d', '/etc/rc1.d', '/etc/rc2.d', '/etc/rc3.d',
                    '/etc/rc4.d', '/etc/rc5.d', '/etc/rc6.d',
                     );
my @YUMarray       = (
                     '/etc/yum.conf', '/etc/yumex.conf',
                     '/etc/yumex.profiles.conf',
                     );
my $YUMDIR         = '/etc/yum.repos.d'; 
my @SQUIDarray     = (
                     '/etc/squid.conf', '/etc/squid/squid.conf',
                     '/usr/local/squid/etc/squid.conf',
                     '/usr/local/etc/squid.conf',
                     '/opt/squid/etc/squid.conf',
                     '/etc/squid3/squid.conf',
                     );
my @Proftpdarray   = (
                     '/etc/proftpd.conf',
                     '/opt/express/proftpd/etc/proftpd.conf',
                     '/usr/local/etc/proftpd.conf',
                     '/opt/proftpd/etc/proftpd.conf',
                     );
my @VSftpdarray    = (
                     '/etc/vsftpd.conf',
                     '/etc/vsftpd.banned_emails',
                     '/etc/vsftpd.chroot_list',
                     '/etc/vsftpd.user_list',
                     );
#
# Due to excessive tape backup times, some teams
# recommended maximum F/S size limit of 512 GB
#
my $MAXFSSIZE      = 512;
my $Sec            = q{};
my $Min            = q{};
my $Hour           = q{};
my $DayOfMonth     = q{};
my $Month          = q{};
my $Year           = q{};
my $DayOfWeek      = q{};
my $DayofYear      = q{};
my $OVCONF         = "/etc/init.d/opcagt";
my $OPCinfo        = "/opt/OV/bin/OpC/install/opcinfo";
my $NODEinfo       = "/var/opt/OV/conf/OpC/nodeinfo";
my $mgrconf        = "/var/opt/OV/conf/OpC/mgrconf";
my $NETBCKDIR      = q{};
my $NETBCKDIR1     = "/usr/openv";
my $NETBCKDIR2     = "/opt/openv";
my @Passnumarr     = ();
my @MAJMIN         = ();
my @FINDUP         = ();
my @Grnumarr       = ();
my $LOGINDEFS      = '/etc/login.defs';
my $SUSEDEFPASSWD   = '/etc/default/passwd';
my $UBUNTUDEFPASSWD = '/etc/pam.d/common-password';
my $SELINUXCONF    = '/etc/selinux/config';
my $SESTATUSCONF   = '/etc/sestatus.conf';
my $MSGFILE        = '/var/log/messages';
my $CRFILE         = '/var/spool/cron/root';
my $CRFILE2         = '/etc/crontab';
my @CHECKARR       = ();
my $WARNSTR        = 'AUDIT-WARN';
my $ERRSTR         = 'AUDIT-FAIL';
my $NOTESTR        = 'AUDIT-NOTE';
my $INFOSTR        = 'AUDIT-INFO';
my $PASSSTR        = 'AUDIT-PASS';
my $Secure_SYSLOGD = 0;
my $EMCP_FLAG      = 0;
my $PASSMIN_FLAG   = 0;
my $PASSMAXDAYS_FLAG = 0;
my $PAMCRACKLIB_FLAG = 0;;
my $PASSMINTHRESH  = 8;
my $PASSMAXTHRESH  = 120;
my $OPENVPN_FLAG   = 1;
my $LVS_FLAG       = 0;
my $SVA_FLAG       = 0;
my $defrootshell   = '/sbin/sh';
my $CSTM_FLAG      = 0;
my @SWAPARRAY      = ();
my $SECDIR         = "/etc/security";
my $pam_conf       = "$SECDIR/pam_env.conf";
my $pam_auth       = "/etc/pam.d/system-auth";
my $FSTAB          = '/etc/fstab';
my $CRYPTTAB       = '/etc/crypttab';
my $MNTTAB         = '/etc/mtab';
my $svaconf        = '/opt/sva/etc/sva.conf';

#
my @AUTOARR        = ( "/etc/auto.master", "/etc/auto.misc",
                       "/etc/auto.net",    "/etc/auto.smb",
                     );
my @AUTOEXTRA      = ();
my $AUTO_FLAG      = 0;

#
my $UDEVCONF       = "/etc/udev/udev.conf";
my $UDEVDIR        = "/etc/udev/rules.d";

# Delay and count values for commands vmstat, ioscan, and sar...
#
my $ITERATIONS = 10;
my $DELAY      = 2;

#
# LVM
my $VG00ALLOCCONT    = "strict/contiguous";
my $VG00ALLOCNONCONT = "strict";
my $THRESHOLD_MAX_PE = 16000;
my $THRESHOLD_MAX_PV = 16;
my $THRESHOLD_MAX_LV = 255;
my $THRESHOLD_MAX_VG = 50;
my $lvsizedef        = 4096;

#
# Host Intrusion Detection System
my $esm        = "/esm/config/tcp_port.dat";
my $esmmgr     = "/esm/config/manager.dat";
my $esmrc      = "/esm/esmrc";
my $esmportdef = 5600;

#
my $SWAP_DEV_NO        = 0;
my $SWAP_NETWORK_NO    = 0;
my $SWAP_LOCALFS_NO    = 0;
my $tswapall           = 0;
my $SWAP_THRESHOLD     = 15;
my $THRESHOLD          = 90;
my $CPU_IDLE_THRESHOLD = 15;

# VXVM
my $VXCONF             = '/sbin/init.d/vxvm-sysboot';
my $VXCONFIG           = 0;

# SNMP configs
my $SNMPAconf          = '/etc/snmp/snmpd.conf';
my $SNMP_FLAG          = 0;
my $snmpmod            = "Net::SNMP";
my $snmphostname       = shift || 'localhost';
my $snmpcommunity      = shift || 'public';
my $snmpport           = shift || 161;
my $oid                = shift || '1.3.6.1.2.1.1.3.0';
my $snmperror          = q{};
my $snmpsession        = q{};

my $IPCHAINS  = '/etc/sysconfig/ipchains';

my $ITOres    = "/tmp/ito_rpt_agt/ITO.rpt";

my $DUMPDATES = '/etc/dumpdates';

# HIDS configs
my $aide_conf = "/etc/aide.conf";
my $ids_conf  = "/etc/tripwire/twcfg.txt";

# Check directories sticky-bit
my @Stickyarr = ( "/tmp", "/var/tmp", );

my @remaccarr = ( ".netrc", ".rhosts", ".shosts", );

# LVM defaults
my $LVBOOT      = 0;
my $LVROOT      = 0;
my $LVSWAP      = 0;
my $LVDUMP      = 0;
my $LVBDISK     = 0;
my $MinBootSize = 18;    # Boot disks should be 18 GB minimum
my $bings       = 0;
my $Seen        = q{};
my @bootara     = ();

# Password checks
my $uidno       = 0;
my $Shadow      = '/etc/shadow';
my $shaduser    = q{};
my @SHADWARN    = ();

my $MISSING_FS_FLAG = 0;

# Login messages
my $ISSUE     = '/etc/issue';
my $MOTD      = '/etc/motd';

# Inetd configs
my $INETD     = "/etc/xinetd.conf";
my $INETDSEC  = "/etc/hosts.allow";
my $hostequiv = "/etc/hosts.equiv";
my $Shells    = "/etc/shells";

# Network
my $NETCONF   = "/etc/sysconfig/network";
my @NDset     = ();
my $NSCDCONF  = "/etc/nscd.conf";

my $XINIT     = '/etc/sysconfig/init';
my $XORGCONF  = '/etc/X11/xorg.conf';
my $XWMDEF    = '/etc/X11/default-display-manager';

my $TLDIR     = "/";

my $NAMED     = '/etc/resolv.conf';
my $PFMERR    = q{};
my $DOMCOUNT  = 0;
my $SEARCHCOUNT = 0;
my $MAXDNSSRV = 3;
my $DNS_NO    = 0;
my $DNSdefdom = q{};
my @MYDNSSRV  = ();
my $DNSCONF1   = '/etc/named.conf';
my $DNSCONF2   = '/var/named/chroot/etc/named.conf';
my $HOSTS     = '/etc/hosts';
my @HOSTWARN  = ();
my $NSSWITCH  = '/etc/nsswitch.conf';
my $NAMEDCONF = '/etc/host.conf';

my $SMB_CONF  = '/etc/samba/smb.conf';
my $SMB_PASS  = '/etc/samba/smbpasswd';
my $SMB_USR   = '/etc/samba/smbusers';

my $FTP_FLAG        = 0;
my $ftpacc          = '/etc/ftpaccess';
my $ftpusers        = '/etc/ftpusers';
my $ftphosts        = '/etc/ftphosts';
my $rv              = 0;
my $FOREGROUND_FLAG = 0;
my @Alllanscan      = ();
my @CPUarray        = ();
my $GRAPHval        = q{};
my $ESMD_FLAG       = 0;
my @NFSarr          = ();

# Where to start SUID/SGID file search
#
my @directories_to_search = ("/");

my $LVM_FLAG               = 0;
my $shealth                = 0;
my $passno                 = 0;
my $SECPATCH_FLAG          = 0;
my $STAND_FLAG             = 0;
my $NTP_REST_FLAG          = 0;
my $IDS_FLAG               = 0;
my $DNSMASQ_FLAG           = 0;
my $LICENSE                = 0;
my @licdaemon              = ();
my $ovnnmlic               = "/var/opt/OV/HPOvLIC/LicFile.txt";
my $NISPLUS_FLAG           = 0;
my $THRESHOLD_MAXUPRC_FLAG = 256;
my $LPSCHED                = 0;
my $LDAPCLIENT             = 0;
my $LDAPSERVER             = 0;
my @ldapdaemon             = ();
my $NSADMIN                = 0;
my $LPSTAND                = 0;
my @klu                    = ();
my @Alldevs                = ();
my @VVM                    = ();
my @unc                    = ();
my @quotastat              = ();
my $LOCALHOST_FLAG         = 0;
my $OMNI_FLAG              = 0;
my $MNT_FLAG               = 0;
my $ONLINEDIAG_FLAG        = 0;
my $swapdeviceno           = 0;
my $Minswapdevno           = 1;
my $SECPATHAG              = 0;
my $PUPPETMASTER           = 0;
my $PUPPETCLIENT           = 0;
my $CFENGINEMASTER         = 0;
my $CFENGINECLIENT         = 0;
my $warnings               = 0;
my @FCarray                = ();
my @tapes                  = ();
my $SGRUN                  = 0;
my $DIAGMOND               = 0;
my @DNSRUN                 = ();
my @SQUIDRUN               = ();
my @HTTPDRUN               = ();
my $HTTPDD                 = "/etc/httpd/conf.d";
my $HTTPDCONF              = "/etc/httpd/conf/httpd.conf";
my $TOMCAT_FLAG            = 0;
my $NGINX_FLAG             = 0;
my $webcomm                = "httpd";
my @allprocesses           = ();
my @ntpdaemon              = ();
my @chronydaemon           = (); 
my @nfsdaemon              = ();
my $securepath             = 0;
my $secureshell            = 0;
my $autopath               = 0;
my $apacount               = 0;
my $parset                 = 0;
my $PASSFILE               = "/etc/passwd";
my $CMNODEFILE             = q{};
my $CMNODEFILE1            = "/etc/cmcluster/cmclnodelist";
my $CMNODEFILE2            = "/usr/local/qs/conf/cmclnodelist";
my $CMNODEFILE3            = "/opt/qs/conf/cmclnodelist";
my $CMAUTHFILE             = q{};
my $CMAUTHFILE1            = "/etc/cmcluster/qs_authfile";
my $CMAUTHFILE2            = "/usr/local/qs/conf/qs_authfile";
my $CMAUTHFILE3            = "/opt/qs/conf/qs_authfile";

# ServiceGuard clustering
#
my $HACLCFG                = '/etc/xinet.d/hacl-cfg';
my $HACLUDP                = '/etc/xinet.d/hacl-cfgudp';
my $CMCLUSTCONF            = "/etc/cmcluster.conf";

# Oracle clustering
#
my $OCFSF1                 = '/etc/ocfs.conf';
my $OCFSF2                 = '/etc/ocfs2/cluster.conf';

my $DefMTU                 = 1500;
my $DefMTUlo               = 16436;
my $OS_Standard            = 'Dusan Standard Build';

# ZFS stuff
#
my @zfsmount   = ();
my $zfspoolH   = q{};
my @zpools     = ();
my $zpoolboot  = q{};
my $ZFS_FLAG   = q{};
my @ALLZFS     = ();
my @ZFSROOTARR = ();
my $ZFSDISK    = q{};
my $realdsk    = q{};
my @zdfsmount  = ();
my $zpoolH     = q{};
my $poolname   = q{};
my @ZFSPOOLARR = ();

my $glob_conf  = q{};

# Array of accounts that should be disabled for FTP access
#
my @FTPdisable = ( "root", "adm", "sys", "daemon", );

# Bundles that are most critical
#
my @SWmust = (
# These were from the tims when I worked on special projects
# Most probably not required for general sites:
#    "DP_",        "openssh",  "Bastille",  "iptables", "HPSIM", "postgres",
#    "aide",      "dpkg",     "chkconfig", "chkrootkit", "shadow-utils",
#    "openvpn",   "Bastille",
#
    "openssh",  "iptables",   "openssl", "tripwire",
    "aide",     "chkrootkit", "sudo", "net-tools",
);

sub loginerror {

   #  print "$INFOSTR Could not connect with this login name or password\n";
    ;
}

sub Usage {
    if ( eval "require File::Basename" ) {
        import File::Basename;
        $CMD = basename( "$0", ".pl" );
        Prusage();
    }
    else {
        $CMD = `basename $0`;
        chomp($CMD);
        Prusage();
    }
}

sub Prusage {

    print <<MYMSG
    USAGE: $CMD [-c] [-f] [-h] [-n] [-o] [-r] [-t conffile] [-v] [-z]

    -c           Enable check of SUID/SGID files
    -f           Enable NMAP scans
    -h           Print this help message
    -n           Enable SUID/SGID checks in NFS (default is disable)
    -o           OpenView monitoring used (default is OVO not used)
    -r           Server part of cluster or H/A server group
    -t file      Read variables from a config file
    -v           Print version of this script 
    -z           Enable SMART checks (smartctl) (default is disable)
MYMSG
      ;
    exit(0);
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

# Ensure that modules are loaded
#
BEGIN {
    $SCRIPT_VERSION  = "2014110601";
    $REC_VERSION     = '5.006';
    $BEST_VERSION    = '5.008';
    $CUR_VERSION     = "$]";
    $OLDER_PERL_FLAG = 0;

    $opt_n = 0;
    $opt_f = 0;
    $opt_r = 0;
    $opt_t = q{};
    $opt_c = 0;
    $opt_o = 0;
    $opt_v = 0;
    $opt_z = 0;

    if ( eval "require IO::Pty" ) {
        import IO::Pty;
        $pty    = new IO::Pty;
        $PTYcur = $pty->ttyname();
    }
    else {
        $PTYcur = `tty`;
        chomp($PTYcur);
    }

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
        use POSIX qw/getpgrp tcgetpgrp/;
        ( $System, $Hostname1, $Maj, $Version, $Hardware ) = uname();
        if ( defined $Maj ) {
            ( $Major, $Minor, $Patch ) = split( /\./, $Maj );
        }
    }
    else {
        warn "ERROR: Perl module POSIX not found\n";
    }

    if ( eval "require Getopt::Std" ) {
        import Getopt::Std;
        ($::opt_s) = ();    #avoid warning message
        getopts('cfhnort:vz');
        if ( $opt_h ) {
            &Usage;
        }
    }
    else {
        warn "ERROR: Perl module Getopt::Std not found\n";
    }

    if ( eval "require Net::Domain" ) {
        import Net::Domain qw(hostname hostfqdn hostdomain);
        $fqdn = hostfqdn();
    }
    else {
        print "INFO: Perl module Net::Domain not found\n";
        if ( "$Hostname1" ) {
            $fqdn =
`nslookup $Hostname1 | awk -F: '! /awk/ && /^Name:/ {print $2}' 2>/dev/null`;
            $fqdn =~ s/Name:\s+//g;
            $fqdn =~ s/^\s+//g;
        } else 
        {
            $fqdn = `hostname -f 2>/dev/null`;
        }
    }
}

my $Hostname2 = `hostname -s 2>/dev/null`;
chomp($Hostname2);

my $Hostname3 = q{};

if ( !"$Hostname1" ) {
    $VH = `uname -a 2>&1`;
    ( $System, $Hostname3, $Maj, undef, $Hardware, undef ) =
    split( /\s+/, $VH );
    $Version = $Maj;
    ( $Major, $Minor, $Patch ) = split( /\./, $Maj );
}

$Hostname = $Hostname2 || $Hostname3 || $Hostname1;

if ("$fqdn") {
    chomp($fqdn);
    $fqdn =~ s/^\s+//g;
}
else {
    $fqdn = "N/A";
}

# Do not allow to run as unprivileged user
#
if ( $> != 0 ) {
    print "$ERRSTR The OAT should be run with root privileges\n";
    exit(1);
}

# Get current local time
#
(
    $Sec,  $Min,       $Hour,      $DayOfMonth, $Month,
    $Year, $DayOfWeek, $DayofYear, $IsDST
  )
  = localtime;

my $EPOCHTIME = timelocal( $Sec, $Min, $Hour, $DayOfMonth, $Month, $Year );

# Localtime returns January..December as 0..11
#
$Year = $Year + 1900;
$Month++;

rawpscheck();

# Get system's pagesize
#
$pgsize = `getconf PAGE_SIZE 2>/dev/null | awk NF`;
if ("$pgsize") {
    chomp($pgsize);
}
else {
    $pgsize = "Unknown";
}

my $KERNEL_BITS = `getconf LONG_BIT 2>/dev/null | awk NF`;
if ("$KERNEL_BITS") {
    chomp($KERNEL_BITS);
}
else {
    $KERNEL_BITS = "Unknown";
}

my $runlevel = `who -r | awk '/run-level/ {print \$2}' 2>&1`;
if ( ! "$runlevel" ) {
    $runlevel = `runlevel | awk '{print \$2}' 2>&1`;
}
chomp($runlevel);

my $uptime = `uptime`;
$uptime =~ s/^\s+//g;
chomp($uptime);

my $wtmpfile = '/var/log/wtmp';
my $etcutmp  = '/etc/utmp';

if ( !"$uptime" ) {
    print "$WARNSTR $wtmpfile or $etcutmp possibly corrupted\n";
    push(@CHECKARR, "\n$WARNSTR $wtmpfile or $etcutmp possibly corrupted\n");
    $warnings++;
    $uptime = "Unknown (check manually)";
}

my $UNAME = `uname -ms 2>/dev/null`;
chomp($UNAME);

my $MACHARCH =
  $UNAME =~ /ia64/i  ? 'Itanium IA64'
  : $UNAME =~ /amd64/i ? 'AMD64'
  : $UNAME =~ /x86_64/i ? 'AMD64/EM64T'
  : $UNAME =~ /ppc64p/i ? 'IBM PPC64 pSeries'
  : $UNAME =~ /ppc64i/i ? 'IBM PPC64 iSeries'
  : $UNAME =~ /i383|i486|i586|i686/i ? 'X86'
  : $UNAME =~ /s390x/i ? 'IBM S390 zSeries'
  : $UNAME =~ /s390/i ? 'IBM S/390'
  : "Unknown";

my $HOSTID2 = `hostid 2>/dev/null`;
chomp($HOSTID2);
my $HOSTID =
       $HOSTID2 ? $HOSTID2
       : "Unknown";

# Get system's volume manager details
#
my $vxcheck = `vxinfo 2>&1 | egrep -v "ERROR|not found"`;
my $lvcheck = `vgs 2>/dev/null`;
my @mdcheck = `cat /proc/mdstat 2>/dev/null | egrep -v "^Personalities|^unused devices"`;
my @mdcheck2 = `mdadm --examine 2>&1 |egrep -v "No devices"`;

if ("$vxcheck") {
    $Diskmgr2 = "Veritas Volume Manager (VVM)";
    $Diskmgrno++;
}

if ("$lvcheck") {
    $Diskmgr1 = "Linux Volume Manager (LVM)";
    $Diskmgrno++;
}

@zfsmount = `zfs mount 2>/dev/null`;
if ( "@zfsmount" ) {
    $zpoolH = `zpool list -H 2>/dev/null | awk '{print \$1}' 2>/dev/null`;
    chomp($zpoolH);
    $zpoolboot = `zpool list -Ho bootfs 2>/dev/null`;
    $Diskmgr3 = "Zettabyte File System (ZFS)";
    $Diskmgrno++;
}

if ("@mdcheck" && "@mdcheck2") {
    $Diskmgr4 = "Linux Software RAID (LSR)";
    $Diskmgrno++;
}

if ( (! "$Diskmgr1") && (! "$Diskmgr2") && (! "$Diskmgr3") && (! "$Diskmgr4")) {
    $Diskmgr = "Not Applicable";
}
else {
   $Diskmgr = "$Diskmgr1 $Diskmgr2 $Diskmgr3 $Diskmgr4";
}

$Diskmgr =~ s/^\s+//g;

if ( $Diskmgrno > 1 ) {
    $Diskmgrcnt = "Multiple-Volume-Manager Environment";
}
elsif ( $Diskmgrno == 0 ) {
    $Diskmgrcnt = "No-Volume-Manager Environment";
}
else {
    $Diskmgrcnt = "Single-Volume-Manager Environment";
}

sub print_header {
    my $lline = shift;
#    $len_lline = length($lline);
    print "\n$lline\n";
#    printf "_" x $len_lline;
    print "\n";
}

$ARCH = `arch 2>/dev/null`;
chomp($ARCH);

my $LSB = `lsb_release -a 2>/dev/null`;
chomp($LSB);

my $PKGDB = "RPM";

my $LARCH = `cat /proc/version 2>/dev/null`;
chomp($LARCH);

my @HPASMCLI =
`hpasmcli -s "show server; show ipl; show ht; show pxe; show uid" 2>/dev/null`;

my $REDHATREL    = '/etc/redhat-release';
my $FEDORAREL    = '/etc/fedora-release';
my $SUSEREL      = '/etc/SuSE-release';
my $MANDRAKEREL  = '/etc/mandrake-release';
my $UNITEDREL    = '/etc/UnitedLinux-release';
my $DEBIANREL    = '/etc/debian_version';
my $GENTOOREL    = '/etc/gentoo-release';
my $SLACKWAREREL = '/etc/slackware-version';
my $UBUNTUREL    = '/etc/lsb-release';
my $ORACLEREL1   = '/etc/enterprise-release';
my $ORACLEREL2   = '/etc/oracle-release';

my $REL    = '/etc/lsb-release';

my $DIST =
    -f $REDHATREL    ? 'RedHat'
  : -f $SUSEREL      ? 'SuSE'
  : -f $MANDRAKEREL  ? 'Mandrake'
  : -f $UNITEDREL    ? 'UnitedLinux'
  : -f $DEBIANREL    ? 'Debian'
  : -f $GENTOOREL    ? 'Gentoo'
  : -f $SLACKWAREREL ? 'Slackware'
  : -f $FEDORAREL    ? 'Fedora'
  : -f $UBUNTUREL    ? 'Ubuntu'
  : -f $ORACLEREL1   ? 'Oracle'
  : -f $ORACLEREL2   ? 'Oracle'
  : "$LARCH";

my $nologinf  = "/etc/nologin.txt";

my $AUDCONF   = '/etc/auditd.conf';
my $AUDCONF2  = '/etc/audit/auditd.conf';
if ( ! -s "$AUDCONF" ) {
    $AUDCONF = $AUDCONF2;
}

if ( $DIST eq 'Debian' ) {
    $PKGDB     = "DPKG";
    $nologinf  = "/etc/nologin";
    $HTTPDD    = "/etc/apache2/conf.d";
    $HTTPDCONF = "/etc/apache2/apache2.conf";
}

#$LCOMM = -f $REDHATREL ? "yum list"
my $LCOMM =
    -f $REDHATREL   ? "rpm -qa"
  : -f $SUSEREL     ? "rpm -qa"
  : -f $MANDRAKEREL ? "rpm -qa"
  : -f $UNITEDREL   ? 'UnitedLinux'
  : -f $DEBIANREL   ? "dpkg -l"
  : -f $UBUNTUREL    ? "dpkg -l"
  : -f $GENTOOREL   ? "equery list"
  : "rpm -qa";

if ( ( $DIST ne 'RedHat' ) && ( $DIST ne 'SuSE' ) && ( $DIST ne 'Debian' ) && ($DIST ne 'Oracle') ) {
    print "$INFOSTR Red Hat, Oracle, SUSE, and Debian distributions supported currently ($DIST)\n";
    print "$NOTESTR Other distributions are not supported commercially\n";
}

if ( !"$ARCH" ) {
    $ARCH = "Unknown";
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
UNAME -A                  $System $Hostname $Maj $Version $Hardware
DISTRIBUTION              $DIST
ARCHITECTURE              $ARCH
MACHINE ARCHITECTURE      $MACHARCH
ENDIANNESS                $Endian
HOSTID                    $HOSTID
RUN LEVEL                 $runlevel
KERNEL MODE               $KERNEL_BITS-bits
PAGESIZE                  $pgsize bytes
VOLUME MANAGER COUNT      $Diskmgrcnt
VOLUME MANAGER            $Diskmgr
UPTIME                    $uptime\n";

    datecheck();
    print_header("*** BEGIN CHECKING LINUX STANDARD BASE $datestring ***");
    if ( "$LSB" ) {
        print "$LSB\n";
    }
    else {
        print "$INFOSTR LSB not configured\n";
    }

    if ( "@HPASMCLI" ) {
        print "@HPASMCLI\n";
    }

    my @hpbmc = `hpbmc 2>/dev/null`;
    if ( "@hpbmc" ) {
        print "\n@hpbmc";
    }

    datecheck();
    print_header("*** END CHECKING LINUX STANDARD BASE $datestring ***");

    if ( $DIST eq 'RedHat' ) {
        my @rhsuppcheck = `redhat-support-check -t 2>/dev/null`;
        if ( "@rhsuppcheck" ) {
            datecheck(); 
            print_header("*** BEGIN CHECKING RED HAT MINIMUM CONFIGURATION $datestring ***");

            print @rhsuppcheck;
            datecheck(); 
            print_header("*** END CHECKING RED HAT MINIMUM CONFIGURATION $datestring ***");
        }
    }
}

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

   my $cfagd1 = `cfagent -n 2>/dev/null`;
   my $cfagd2 = `cf-agent -n 2>/dev/null`;
   my $cfagd = $cfagd1 || $cfagd2;
   if ( "$cfagd" ) {
       print "\n$INFOSTR Cfengine pending actions for managed client (dry-run)\n";
       print $cfagd;
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

   my @puppets = `puppet status master 2>/dev/null`;

   if ( "@puppets" ) {
       print "\n$INFOSTR Puppet Server status\n";
       print @puppets;
   }

   my $puppetd1 = `puppet agent -V 2>/dev/null`;
   my $puppetd2 = `puppet -V 2>/dev/null`;
   my $puppetd3 = `puppetd -V 2>/dev/null`;
   my $puppetd = $puppetd1 || $puppetd2 || $puppetd3;

   if ( "$puppetd" ) {
       print "\n$INFOSTR Puppet Client agent version\n";
       print "$puppetd";
   }
  
   my @COMMTEST = `puppet help 2>/dev/null | awk '\$1 == \"config\" {print}' 2>/dev/null`;
   if ( "@COMMTEST" ) { 
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
   }

   my $puppetca1 = `puppet ca list --all 2>/dev/null`;
   my $puppetca2 = `puppetca -l -a 2>/dev/null`;
   my $puppetca = $puppetca1 || $puppetca2;

   if ( "$puppetca" ) {
       print "\n$INFOSTR Puppet Certificate Authority status\n";
       print $puppetca;
   }

   my $puppetdtest1 = `puppetd --test --noop 2>/dev/null`;
   my $puppetdtest2 = `puppet agent --noop --test 2>/dev/null`;
   my $puppetdtest = $puppetdtest1 || $puppetdtest2;

   if ( "$puppetdtest" ) {
       print "\n$INFOSTR Puppet Client dry-ryn\n";
       print $puppetdtest;
   }

   my @puppetcl = `puppet cert list --all 2>/dev/null`;
   if ( "@puppetcl" ) {
       print "\n$INFOSTR Puppet certificate details\n";
       print @puppetcl;
   }

   my @puppetlocnode = `puppet node find $Hostname 2>/dev/null`;
   if ( "@puppetlocnode" ) {
       print "\n$INFOSTR Puppet local node status\n";
       print @puppetlocnode;
   }

   my @facter = `facter 2>/dev/null`;
   if ( "@facter" ) {
       print "\n$INFOSTR Puppet facter about local server\n";
       print @facter;
   }

   my @PRARR = ( "package", "service", "user", ) ; 
   my @puppetrt = `puppet resource -t 2>/dev/null | awk '/package|service|user/ && ! /nagios/ {print}'`;
  
   foreach my $prelem ( @PRARR ) {
       if ( grep(/\b$prelem\b/i, @puppetrt) ) {
           my @puppetru = `puppet resource $prelem 2>/dev/null`;
           if ( "@puppetru" ) {
               print "\n$INFOSTR Puppet $prelem in Resource Abstraction Layer (RAL)\n";
               print @puppetru;
           }
        }
    }

   datecheck();
   print_header("*** END CHECKING CONFIGURATION MANAGEMENT TOOL PUPPET $datestring ***");
}

sub check_hostname_valid {
   datecheck();
   print_header("*** BEGIN CHECKING HOSTNAME CONTAINS VALID CHARACTERS $datestring ***");

    if ( "$Hostname" ) {
        if( ! ( $Hostname =~ /^[a-zA-Z0-9\.\-]+$/ ) ) {
            print "$WARNSTR Invalid characters in hostname $Hostname\n";
            push(@CHECKARR, "\n$WARNSTR Invalid characters in hostname $Hostname\n");
            print "RFCs define valid characters as 'a-zA-Z0-9.-'\n";
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

    my @HOSTNAMECTL = `hostnamectl 2>/dev/null`;
    if ( "@HOSTNAMECTL" ) {
        print "\n$INFOSTR Hostname settings\n";
        print @HOSTNAMECTL;
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
        print "\nINFOSTR Failed open socket on $proto port $port @ $REMOTE\n";
    }
}

# Subroutine to check ServiceGuard
#
sub sgcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SERVICEGUARD CONFIGURATION $datestring ***");

    if ( -s "$HACLCFG" ) {
        if ( open( FROM, "awk NF $HACLCFG 2>/dev/null |" ) ) {
            $SGCNT++;
            print "$INFOSTR Configuration file $HACLCFG\n";
            while (<FROM>) {
                next if ( grep( /#/, $_ ) );
                print $_;
            }
            close(FROM);
        }
        else {
            print "$INFOSTR Cannot check $HACLCFG\n";
        }
    }
    else {
        print "$INFOSTR $HACLCFG empty or does not exist\n";
    }

    if ( -s "$HACLUDP" ) {
        if ( open( FROM, "awk NF $HACLUDP 2>/dev/null |" ) ) {
            print "\n$INFOSTR Configuration file $HACLUDP\n";
            $SGCNT++;
            while (<FROM>) {
                next if ( grep( /#/, $_ ) );
                print $_;
            }
            close(FROM);
        }
        else {
            print "\n$INFOSTR Cannot check $HACLUDP\n";
        }
    }
    else {
        print "$INFOSTR $HACLUDP empty or does not exist\n";
    }

    if ( "$SGCNT" == 0 ) {
        print "$INFOSTR ServiceGuard not installed\n";
    }
    elsif ( "$SGCNT" > 0 ) {
        if ( "$SGRUN" == 0 ) {
            print "\n$WARNSTR ServiceGuard installed and not running\n";
            push(@CHECKARR, "\n$WARNSTR ServiceGuard installed and not running\n");
            $warnings++;
        }
        elsif ( "$SGRUN" > 0 ) {
            print "\n$PASSSTR ServiceGuard installed and running\n";

            $opt_r = 1;

            my $SGVER = `what /usr/lbin/cmcld 2 >/dev/null | awk '/Date:/ {print \$1}`;

            if ( open( CMGET, "cmgetconf -v 2>&1 |" ) ) {
                print "\n$INFOSTR CMgetconf\n";
                while (<CMGET>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                    $_ =~ s/^\s+//g;
                    $_ =~ s/\s+$//g;
                    if ( grep( /^CLUSTER_NAME/, $_ ) ) {
                        ( undef, $MCCLNAME ) = split( /\s+/, $_ );
                        chomp($MCCLNAME);
                        $MCCLNAME =~ s/^\s+//g;
                        $MCCLNAME =~ s/\s+$//g;
                    }

                    if ( grep( /^FIRST_CLUSTER_LOCK_PV/, $_ ) ) {
                        ( undef, $MCCLLOCKDISK ) = split( /\s+/, $_ );
                        chomp($MCCLLOCKDISK);
                        $MCCLLOCKDISK =~ s/^\s+//g;
                        $MCCLLOCKDISK =~ s/\s+$//g;
                    }

                    if ( grep( /^FIRST_CLUSTER_LOCK_VG/, $_ ) ) {
                        ( undef, $MCCLLOCKVG ) = split( /\s+/, $_ );
                        chomp($MCCLLOCKVG);
                        $MCCLLOCKVG =~ s/^\s+//g;
                        $MCCLLOCKVG =~ s/\s+$//g;
                    }
                }
                close(CMGET);

                if ( "$MCCLLOCKDISK" ) {
                    print
"\n$PASSSTR Cluster lock disk defined as $MCCLLOCKDISK\n";
                }
                else {
                    print
"\n$WARNSTR ServiceGuard cluster lock disk not defined\n";
                    push(@CHECKARR, "\n$WARNSTR ServiceGuard cluster lock disk not defined\n");
                    $warnings++;
                }

                if ( "$MCCLLOCKVG" ) {
                    print
"\n$PASSSTR Cluster lock VG defined as $MCCLLOCKVG\n";
                }
                else {
                    print
"\n$WARNSTR ServiceGuard cluster lock VG not defined\n";
                    push(@CHECKARR, "\n$WARNSTR ServiceGuard cluster lock VG not defined\n");
                    $warnings++;
                }

                print "\n";
            }
            else {
                print "\n$INFOSTR Cannot run cmgetconf\n";
            }

            my @cmview = `cmviewcl -v`;
            if ( @cmview ) {
                print "\n$INFOSTR CMviewcl summary\n";
                print @cmview;
            }

            $SGVER =~ s/\.//g;
            $SGVER =~ s/^[A-Z]//g;
            if ( $SGVER >= 111600 ) {
                my @cmviewf = `cmviewcl -f line -v`;
                if ( @cmviewf ) {
                    print "\n$INFOSTR CMviewcl formatted summary\n";
                    print @cmviewf;
                }
            }

            my @cmviewl = `cmviewcl -l group -v`;
            if ( @cmviewl ) {
                print "\n$INFOSTR CMviewcl group summary\n";
                print @cmviewl;
            }

            my @cmviewv = `cmviewcl -l package -v`;
            if ( @cmviewv ) {
                print "\n$INFOSTR CMviewcl package summary\n";
                print @cmviewv;
            }

            my @cmquerycl = `cmquerycl -v`;
            if ( @cmquerycl ) {
                print "\n$INFOSTR Cmquerycl summary\n";
                print @cmquerycl;
            }

            my @cmqueryloc = `cmquerycl -v -c $MCCLNAME`;
            if ( @cmqueryloc ) {
                print "\n$INFOSTR Cmquerycl full cluster summary\n";
                print @cmqueryloc;
            }

            my @cmscancl = `cmscancl -s`;
            if ( @cmscancl ) {
                print "\n$INFOSTR CMscancl summary\n";
                print @cmscancl;
            }

            if ( $DIST eq 'RedHat' ) {
                $CMNODEFILE = $CMNODEFILE2;
            } elsif ( $DIST eq 'SuSE' ) {
                $CMNODEFILE = $CMNODEFILE3;
            } else {
                $CMNODEFILE = $CMNODEFILE1;
            }

            if ( -s "$CMNODEFILE" ) {
                if ( open( CMAC, "egrep -v ^# $CMNODEFILE 2>&1 |" ) ) {
                    print "\n$INFOSTR Configuration file $CMNODEFILE\n";
                    while (<CMAC>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                    }
                    close(CMAC);
                    print "\n";
                }
                else {
                    print
"\n$INFOSTR Cannot open configuration file $CMNODEFILE\n";
                }
            }

            if ( $DIST eq 'RedHat' ) {
                $CMAUTHFILE = $CMAUTHFILE2;
            } elsif ( $DIST eq 'SuSE' ) {
                $CMAUTHFILE = $CMAUTHFILE3;
            } else {
                $CMAUTHFILE = $CMAUTHFILE1;
            }

            if ( -s "$CMAUTHFILE" ) {
                if ( open( CMAF, "egrep -v ^# $CMAUTHFILE 2>&1 |" ) ) {
                    print "\n$INFOSTR Configuration file $CMAUTHFILE for Quorum Server\n";
                    while (<CMAF>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                    }
                    close(CMAF);
                    print "\n";
                }
                else {
                    print
"\n$INFOSTR Cannot open configuration file $CMAUTHFILE for Quorum Server\n";
                }
            }

            if ( $SGVER >= 111800 ) {
                if ( -s "$CMCLUSTCONF" ) {
                    if ( open( CMAK, "egrep -v ^# $CMCLUSTCONF 2>&1 |" ) ) {
                        print "\n$INFOSTR Configuration file $CMCLUSTCONF\n";
                        while (<CMAK>) {
                            next if ( grep( /^$/, $_ ) );
                            print $_;
                        }
                        close(CMAK);
                        print "\n";
                    }
                    else {
                        print
"\n$INFOSTR Cannot open configuration file $CMCLUSTCONF\n";
                    }
                }
            }
        }
        else {
            print "\n$WARNSTR Possibly corrupt ServiceGuard installation\n";
            push(@CHECKARR, "\n$WARNSTR Possibly corrupt ServiceGuard installation\n");
        }
    }
    else {
        print "\n$PASSSTR Ambiguous ServiceGuard installation\n";
    }

    datecheck();
    print_header("*** END CHECKING SERVICEGUARD CONFIGURATION $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING CLUSTERING $datestring ***");

    my $RACLCFG = '/etc/cluster/cluster.conf';

    my @CMANA   = ();
    my @MYCLUST = ();
    my @cmanarr = ();
    my @mkqdisk = ();
    my @qdsk    = ();
    my $NODECNT = q{};
    my $TOTVOTES = q{};
    my @DNAMEARR = ();
    my @LVMCFGARR = ();
    my $LOCKTYPE = q{};
    my $LOCKLIB  = q{};
    my $WAITLOCK = q{};
    my $LOCKDIR  = q{};
    my $THRESHOLD = q{};
    my %LVMLOCKARR = ();
    my @cmannode = ();

###############
    if ( -s $PVGconf ) {
       if ( open( PVGC, "awk NF $PVGconf 2>/dev/null |" ) ) {
          print "\n$INFOSTR LVM configuration file $PVGconf\n";
          while (<PVGC>) {
             next if ( grep( /#/, $_ ) );
             print $_;
             $_ =~ s/^\s+//g;
             $_ =~ s/\s+$//g;

             if ( grep(/locking_type/i, $_ ) ) { 
                ( undef, $LOCKTYPE ) = split( /=/, $_ );
                $LOCKTYPE =~ s/^\s+//g;
                $LOCKTYPE =~ s/\s+$//g;
                push(@LVMCFGARR, "\n$INFOSTR LVM \"locking_type\" is $LOCKTYPE ($LVMLOCKARR{$LOCKTYPE})\n");
             }

             if ( grep(/wait_for_locks/i, $_ ) ) { 
                ( undef, $WAITLOCK ) = split( /=/, $_ );
                $WAITLOCK =~ s/^\s+//g;
                $WAITLOCK =~ s/\s+$//g;
                if ( "$WAITLOCK" eq 1 ) {
                   push(@LVMCFGARR, "\n$INFOSTR LVM tools wait if a lock request cannot be satisifed immediately (\"wait_for_locks\" set to $WAITLOCK)\n");
                }
                else {
                   if ( "$WAITLOCK" eq 0 ) {
                      push(@LVMCFGARR, "\n$INFOSTR LVM tools abort operation if a lock request cannot be satisifed immediately (\"wait_for_locks\" set to $WAITLOCK)\n");
                   }
                }
             }

             if ( grep(/locking_library/i, $_ ) ) { 
                ( undef, $LOCKLIB ) = split( /=/, $_ );
                $LOCKLIB =~ s/^\s+//g;
                $LOCKLIB =~ s/\s+$//g;
                $LOCKLIB =~ s/"//g;
                if ( "$LOCKTYPE" eq 2 ) {
                   if ( "$LOCKLIB" ) {
                      push(@LVMCFGARR, "\n$INFOSTR LVM \"locking_library\" set to $LOCKTYPE\n");
                   }
                }
             }

             if ( "$LOCKTYPE" eq 1 ) {
                if ( grep(/locking_dir/i, $_ ) ) { 
                   ( undef, $LOCKDIR ) = split( /=/, $_ );
                   $LOCKDIR =~ s/^\s+//g;
                   $LOCKDIR =~ s/\s+$//g;
                   $LOCKDIR =~ s/"//g;
                   if ( -d "$LOCKDIR" ) {
                      push(@LVMCFGARR, "\n$INFOSTR LVM \"lock_dir\" $LOCKDIR exists\n");
                   }
                   else {
                      push(@LVMCFGARR, "\n$WARNSTR LVM \"lock_dir\" $LOCKDIR does not exist\n");
                   }
                }
             }
          }
          close(PVGC);
       }
       else {
          print "\n$INFOSTR $PVGconf cannot be opened\n";
       }
    }

    if ( @LVMCFGARR ) {
       print @LVMCFGARR;
    }

    if ( -s $RACLCFG ) {
       if ( open( FROM, "awk NF $RACLCFG 2>/dev/null |" ) ) {
          print "\n$INFOSTR Cluster configuration file $RACLCFG\n";
          while (<FROM>) {
             next if ( grep( /#/, $_ ) );
             print $_;
          }
          close(FROM);
       }
       else {
          print "\n$INFOSTR $RACLCFG cannot be opened\n";
       }
    }
    else {
       print "\n$INFOSTR $RACLCFG does not exist or empty\n";
    }

    my @clustat = `clustat 2>/dev/null | awk NF`;
    if ( @clustat ) {
       print "\n$INFOSTR Linux Cluster status\n";
       print @clustat;
    }

    my @clusval = `ccs_config_validate 2>/dev/null`;
    if ( @clusval ) {
       print "\n$INFOSTR Linux Cluster configuration validation\n";
       print @clusval;
    }

    my @FENCECAP = `ccs -h localhost --lsfenceopts 2>/dev/null`;
    if ( @FENCECAP ) {
       print "\n$INFOSTR Linux Cluster fence device options on local node\n";
       print @FENCECAP;
    }

    if ( open( CMANC, "cman_tool status 2>/dev/null |" ) ) {
       while (<CMANC>) {
          next if ( grep( /#/, $_ ) );
          push(@MYCLUST, $_);
          $_ =~ s/^\s+//g;
          $_ =~ s/\s+$//g;
          if ( grep(/^Nodes:/i, $_ ) ) { 
             ( undef, $NODECNT ) = split( /:/, $_ );
             $NODECNT =~ s/^\s+//g;
             $NODECNT =~ s/\s+$//g;
          }

          if ( grep(/^Total votes:/i, $_ ) ) { 
             ( undef, $TOTVOTES ) = split( /:/, $_ );
             $TOTVOTES =~ s/^\s+//g;
             $TOTVOTES =~ s/\s+$//g;
          }
       }
       close(CMANC);
    }

    if ( "@MYCLUST" ) {
       print "\n$INFOSTR Linux Cluster vote status\n";
       print @MYCLUST;
    }

    if ( "$NODECNT" eq 1 ) {
        printf "\n$ERRSTR Linux Cluster has 1 node (there is no redundancy in services)\n";
    }

    if ( "$NODECNT" eq 2 ) {
       printf "\n$INFOSTR Linux Cluster has %s node%s (recommended to set up Quorum Disk in addition to fencing)\n", $NODECNT, $NODECNT == 1 ? "" : "s";
    }

    if ( "$TOTVOTES" lt "$NODECNT" ) {
       print "\n$WARNSTR Linux Cluster has less votes that number of nodes ($TOTVOTES and $NODECNT respectively)\n";
       print "$INFOSTR Best practice recommends at least one vote for each node\n";
    }

    if ( open( CMANC, "mkqdisk -L 2>/dev/null | awk NF |" ) ) {
       while (<CMANC>) {
          push(@mkqdisk, $_);
          $_ =~ s/^\s+//g;
          $_ =~ s/\s+$//g;
          if ( grep(/^\//, $_ ) ) { 
             chomp($_);
             $_ =~ s/://g;
             @qdsk = split( /\//, $_ );
             my @DNAME = `lsblk -io KNAME,TYPE,SCHED,ROTA,DISC-GRAN,DISC-MAX | grep "^$qdsk[$#qdsk]"`;
             if ( "@DNAME" ) {
                push(@DNAMEARR, @DNAME);
             }
          }
       }
    }

    if ( @mkqdisk ) {
       print "\n$INFOSTR Linux Cluster lock disk status\n";
       print @mkqdisk;

       if ( @DNAMEARR ) {
          print "\n$INFOSTR Linux Cluster lock disk IO elevator\n";
          print "\n$INFOSTR Recommended to use \"deadline\" scheduler or \cfq\" scheduler with realtime priority (ionice -c 1 -n 0 -p \`pidof qdiskd\`)\n";
          print @DNAMEARR;
       }
    }

    my @ccstooll = `ccs_tool lsnode 2>/dev/null | awk NF`;
    if ( @ccstooll ) {
       print "\n$INFOSTR Linux Cluster node status\n";
       print @ccstooll;
    }

    my @ccstoolf = `ccs_tool lsfence 2>/dev/null`;
    if ( @ccstoolf ) {
       print "\n$INFOSTR Linux Cluster fence device status\n";
       print @ccstoolf;

       my @fencearr = grep { !(/Name.*Agent/) } @ccstoolf;
       if ( ! @fencearr ) {
          print "\n$ERRSTR Linux Cluster has no fence devices\n";
       }
    }

    my @grouptool = `group_tool ls 2>/dev/null | awk NF`;
    if ( @grouptool ) {
       print "\n$INFOSTR Linux Cluster fence group status\n";
       print @grouptool;
    }

    my @victim = grep(/victim/, @grouptool);
    if ( @victim ) {
       print "\n$INFOSTR Linux Cluster victim status\n";
       print @victim;
    }

    my @wait = grep(/wait state|change/, @grouptool);
    if ( @wait ) {
       print "\n$INFOSTR Linux Cluster wait and change summary\n";
       print @wait;
    }

    if ( open( CMANC, "cman_tool nodes 2>/dev/null |" ) ) {
       while (<CMANC>) {
          push(@cmannode, $_);
          chomp($_);
          $_ =~ s/^\s+//g;
          $_ =~ s/\s+$//g;
          @cmanarr = split( /\s+/, $_ );
          if ( $cmanarr[1] eq "X" ) {
             push(@CMANA, "$WARNSTR Node $cmanarr[$#cmanarr] is not a member of the cluster\n");
          }
          elsif ( $cmanarr[1] eq "d" ) {
             push(@CMANA, "$WARNSTR Node $cmanarr[$#cmanarr] is a member of the cluster but access to it is disallowed\n");
          }
          else {
             if ( $cmanarr[1] eq "M" ) {
                push(@CMANA, "$PASSSTR Node $cmanarr[$#cmanarr] is an active member of the cluster\n");
             }
          }
       }
    }

    if ( @cmannode ) {
       print "\n$INFOSTR Linux Cluster nodes and last time each was fenced\n";
       print @cmannode;
    }

    my @clusvcadm = `clusvcadm -S 2>/dev/null`;
    if ( @clusvcadm ) {
       print "\n$INFOSTR Linux Cluster lock state\n";
       print @clusvcadm;
    }

    if ( @CMANA ) {
       print "\n$INFOSTR Linux Cluster nodes membership status\n";
       print @CMANA;
    }

###############

    my @mpdump = `mpdump -v 2>/dev/null`;
    if ( @mpdump ) {
        print "\n$INFOSTR PolyServe Clustered Gateway status\n";
        print @mpdump;

        if ( -s $PSLICFILE ) {
            my @pslic = `egrep -v ^# $PSLICFILE 2>/dev/null | awk NF`;
            if ( "@pslic" ) {
                print "\n$INFOSTR Configuration file $PSLICFILE\n";
                print @pslic;
            }
        }

        if ( -s $MXINITCONF ) {
            my @mxi = `egrep -v ^# $MXINITCONF 2>/dev/null | awk NF`;
            if ( "@mxi" ) {
                print "\n$INFOSTR Configuration file $MXINITCONF\n";
                print @mxi;
            }
        }

        if ( -s $PCITABLE ) {
            my @pcitab = `egrep -v ^# $PCITABLE 2>/dev/null | awk NF`;
            if ( "@pcitab" ) {
                print "\n$INFOSTR Configuration file $PCITABLE\n";
                print @pcitab;
            }
        }

        my @mxmpios = `mxmpio status 2>/dev/null`;
        if ( @mxmpios ) {
            print "\n$INFOSTR PolyServe Clustered Gateway multipath I/O status\n";
            print @mxmpios;
        }

        my @mxmpioi = `mxmpio iostat -u 2>/dev/null`;
        if ( @mxmpioi ) {
            print "\n$INFOSTR PolyServe Clustered Gateway iostatus\n";
            print @mxmpioi;
        }

        my @sandiskinfo = `sandiskinfo -ial 2>/dev/null`;
        if ( @sandiskinfo ) {
            print "\n$INFOSTR PolyServe Clustered Gateway imported SAN LUNs\n";
            print @sandiskinfo;
        }

        my @sandiskinfou = `sandiskinfo -ual 2>/dev/null`;
        if ( @sandiskinfou ) {
            print "\n$INFOSTR PolyServe Clustered Gateway unimported SAN LUNs\n";
            print @sandiskinfou;
        }

        my @sandiskinfor = `sandiskinfo -iar 2>/dev/null`;
        if ( @sandiskinfor ) {
            print "\n$INFOSTR PolyServe Clustered Gateway paths to LUNs\n";
            print @sandiskinfor;
        }

        my @mxsanlk = `mxsanlk 2>/dev/null`;
        if ( @mxsanlk ) {
            print "\n$INFOSTR PolyServe Clustered Gateway SANlock status\n";
            print @mxsanlk;
        }
    }

    datecheck();
    print_header("*** END CHECKING CLUSTERING $datestring ***");

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
        $opt_r = 1;
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

    datecheck();
    print_header("*** BEGIN CHECKING ORACLE CLUSTER FILE SYSTEM (OCFS) $datestring ***");

    my $OCFSF = $OCFSF1;
    if ( -s $OCFSF2 ) {
        $OCFSF = $OCFSF2;
    }

    if ( -s $OCFSF ) {
        if ( open( FROM, "awk NF $OCFSF 2>/dev/null |" ) ) {
            print "$INFOSTR Cluster configuration file $OCFSF\n";
            while (<FROM>) {
                next if ( grep( /#/, $_ ) );
                print $_;
            }
            close(FROM);

            ocfs2chk();
        }
    }
    else {
        print "$INFOSTR OCFS seemingly not running\n";
    }

    datecheck();
    print_header("*** END CHECKING ORACLE CLUSTER FILE SYSTEM (OCFS) $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING LINUX VIRTUAL SERVER $datestring ***");

    my $LVSCFG    = '/etc/sysconfig/ha/lvs.cf';
    my $LVSWEBCFG = '/etc/sysconfig/ha/conf/httpd.conf';
    my $LVSWEBSEC = '/etc/sysconfig/ha/web/secure/.htaccess';

    if ( -s $LVSCFG ) {
        if ( open( FROM, "awk NF $LVSCFG 2>/dev/null |" ) ) {
            $LVS_FLAG++;
            print "$INFOSTR LVS configuration file $LVSCFG\n";
            while (<FROM>) {
                next if ( grep( /#/, $_ ) );
                print $_;
            }
            close(FROM);
        }

        if ( open( FROM, "awk NF $LVSWEBCFG 2>/dev/null |" ) ) {
            print "\n$INFOSTR LVS Web configuration file $LVSWEBCFG\n";
            while (<FROM>) {
                next if ( grep( /#/, $_ ) );
                print $_;
            }
            close(FROM);
        }
        else {
            print
              "\n$INFOSTR $LVSWEBCFG does not exist or not configured\n";
        }

        if ( open( FROM, "awk NF $LVSWEBSEC 2>/dev/null |" ) ) {
            print
"\n$INFOSTR LVS Web secure access configuration file $LVSWEBCFG\n";
            while (<FROM>) {
                next if ( grep( /#/, $_ ) );
                print $_;
            }
            close(FROM);
        }
        else {
            print
              "\n$INFOSTR $LVSWEBSEC does not exist or not configured\n";
        }
    }
    else {
        print "$INFOSTR $LVSCFG does not exist or not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING LINUX VIRTUAL SERVER $datestring ***");
}

#
# Subroutine to check boot volumes
#
sub bootcheck {
    datecheck();
    print_header "*** BEGIN CHECKING DISKS $datestring ***";

    if ( open( FF, "fdisk -c -l 2>/dev/null |" ) ) {
        while (<FF>) {
            print $_;
        }
        close(FF);
    }
    else {
        print "$ERRSTR Cannot run fdisk\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run fdisk\n");
        $warnings++;
    }

    my @sfdisk = `sfdisk -d 2>/dev/null`;
    if ( "@sfdisk" ) {
        print "\n$INFOSTR Checking partition alignment\n";
        print "$INFOSTR Information on how to restore disks (sfdisk --force /dev/device ...)\n";
        print @sfdisk;
    }

    my @blockdev = `blockdev --report 2>/dev/null`;
    if ( "@blockdev" ) {
        print "\n$INFOSTR Checking block device IOCTLs\n";
        print @blockdev;
    }

    my @mydisks = `ls /dev/sd* /dev/hd* 2>/dev/null |grep -v [0-9]`;
    foreach my $mdisk (@mydisks) {
        chomp($mdisk);
        my @sfg = `hdparm -i -t -T $mdisk 2>/dev/null`;
        if ( "@sfg" ) {
            print "\n$INFOSTR Device parameters (hdparm) for disk $mdisk\n";
            print @sfg;
        }
    }

    my @IOelevator = `grep . /sys/block/*/queue/scheduler 2>/dev/null`;
    if ( "@IOelevator" ) {
        print "\n$INFOSTR I/O Elevator setup\n";
        print "$NOTESTR Recommended NOOP for VMware and SAN, DEADLINE for most other workloads\n";
        print @IOelevator;
    }

    my @tree = `tree /dev/disk 2>/dev/null`;
    if ( "@tree" ) {
        print "\n$INFOSTR Device tree for disks\n";
        print @tree;
    }

    datecheck();
    print_header "*** END CHECKING DISKS $datestring ***";
}

#
# Subroutine to check boot paths
#
sub bootpath {
    datecheck();
    print_header "*** BEGIN CHECKING BOOT LOADER $datestring ***";

    my $BOOTMODE = "BIOS";

    if ( -d "$EFIDIR" ) {
        $BOOTMODE = "EFI";
        print "$INFOSTR Linux boot mode is seemingly $BOOTMODE\n";

        my @efibootmgr = `efibootmgr -v 2>/dev/null`;
        if ( @efibootmgr ) {
            print "\n$INFOSTR EFI Boot Manager status\n";
            print @efibootmgr;
        }

        print "\n";
    }
    else {
        print "$INFOSTR Linux boot mode is seemingly $BOOTMODE\n";
    }

    my $BOOTTYPE = q{};

    if ( $UNAME =~ /s390x/i ) {
        $BOOTTYPE = "IBM z/IPL";
    }
    elsif ( $UNAME =~ /ppc64p/i ) {
        $BOOTTYPE = "IBM YABOOT";
    }
    elsif ( $UNAME =~ /ia64/i ) {
        $BOOTTYPE = "ITANIUM 64";
    }
    else {
        $BOOTTYPE = "";
    }

    my @BOOTCONF = `find $BOOTDIR -name "*.conf" -o -name "*.cfg" 2>/dev/null`;
    foreach my $bcfg (@BOOTCONF) {
        chomp($bcfg);
        if ( -s $bcfg ) {
            my @ssfg = `awk NF $bcfg 2>/dev/null`;
            if ( "@ssfg" ) {
                print "$INFOSTR Boot loader configured ($bcfg)\n";
                print @ssfg;
                print "\n";
            }
        }
    }

    if ( -s "$IBMESERVZSERIES" ) {
        if ( open( FROM, "cat $IBMESERVZSERIES 2>/dev/null |" ) ) {
            print
"$INFOSTR $BOOTTYPE boot loader configured ($IBMESERVZSERIES)\n";
            while (<FROM>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close(FROM);
        }
        else {
            print "$INFOSTR IBM z/IPL boot loader not configured\n";
        }
    }

    if ( -s "$IBMESERVPSERIES" ) {
        if ( open( FROM, "cat $IBMESERVPSERIES 2>/dev/null |" ) ) {
            print
"$INFOSTR $BOOTTYPE boot loader configured ($IBMESERVPSERIES)\n";
            while (<FROM>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close(FROM);
        }
        else {
            print "$INFOSTR IBM YABOOT boot loader not configured\n";
        }
    }
    
    if ( -s "$LILOCONF" ) {
        if ( open( LFROM, "cat $LILOCONF 2>/dev/null |" ) ) {
            print "\n$INFOSTR LILO boot loader configured ($LILOCONF)\n";
            while (<LFROM>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close(LFROM);
        }
    }

    my @BOOTCTL = `bootctl status 2>/dev/null | awk NF`;
    if ( "@BOOTCTL" ) {
        print "$INFOSTR Firmware and boot manager settings\n";
        print @BOOTCTL;
    }

    datecheck();
    print_header "*** END CHECKING BOOT LOADER $datestring ***";
}

#
# Subroutine to check savecrash
#
sub crashcheck {
    if ( $DIST ne "Debian" ) {
        datecheck();
        print_header "*** BEGIN CHECKING SYSCONFIG DIRECTORY $datestring ***";

        my @syscfgls = `find /etc/sysconfig -type f 2>/dev/null`;
        foreach my $scfg (@syscfgls) {
            chomp($scfg);
            next if ( -d $scfg );
            if ( -s $scfg ) {
                my @ssfg = `egrep -v ^# $scfg | awk NF`;
                if ( "@ssfg" ) {
                    print "$INFOSTR Configuration file $scfg\n";
                    print @ssfg;
                    print "\n";
                }
                else {
                    print "$INFOSTR Configuration file $scfg exist but no configuration lines set up\n";
                    print "\n";
                }
            }
            else {
                print "$INFOSTR Configuration file $scfg empty or does not exist\n";
                print "\n";
            }
        }

        datecheck();
        print_header "*** END CHECKING SYSCONFIG DIRECTORY $datestring ***";
    }

    if ( ( $DIST eq 'RedHat' ) || ( $DIST eq 'Fedora' ) ) {
        datecheck();
        print_header "*** BEGIN CHECKING NETDUMP $datestring ***";

        if ( open( FROM, "/etc/init.d/netdump status 2>&1 |" ) ) {
            while (<FROM>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(FROM);
        }
        else {
            print "$INFOSTR Netdump not configured\n";
        }

        datecheck();
        print_header "*** END CHECKING NETDUMP $datestring ***";

        datecheck();
        print_header "*** BEGIN CHECKING DISKDUMP $datestring ***";

        if ( open( FROM, "/etc/init.d/diskdump status 2>&1 |" ) ) {
            while (<FROM>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(FROM);

            my $diskdump = "/proc/diskdump";
            my @diskdumpval = `cat $diskdump 2>/dev/null`;
            if ("@diskdumpval") {
                print "$INFOSTR Diskdump status\n";
                print @diskdumpval;
            }
            else {
                print "\n$INFOSTR Diskdump $diskdump does not exist)\n";
            }
        }
        else {
            print "$INFOSTR Diskdump not configured\n";
        }

        datecheck();
        print_header "*** END CHECKING DISKDUMP $datestring ***";
    }

    datecheck();
    print_header "*** BEGIN CHECKING KDUMP $datestring ***";

    my @kdumpctl = `kdumpctl status 2>/dev/null`;
    if ("@kdumpctl") {
        print "$INFOSTR Kdump status\n";
        print @kdumpctl;
    }
    else {
        print "$INFOSTR Kdump not available on this architecture or not installed\n";
    }

    datecheck();
    print_header "*** END CHECKING KDUMP $datestring ***";

    if ( $DIST eq 'SuSE' ) {
        datecheck();
        print_header "*** BEGIN CHECKING LINUX KERNEL CRASH DUMP (SuSE LKCD) $datestring ***";

        if ( -s "$lkcddump" ) {
            my @sysdump = `cat $lkcddump 2>/dev/null`;
            if ( @sysdump != 0 ) {
                print "$INFOSTR $lkcddump configuration\n";
                print @sysdump;
            }
        }
        else {
            print "$INFOSTR $lkcddump missing or empty\n";
        }

        my @lkcd = `lkcd -q 2>/dev/null`;
        if ("@lkcd") {
            print "\n$INFOSTR LKCD status\n";
            print @lkcd;
        }

        datecheck();
        print_header "*** END CHECKING LINUX KERNEL CRASH DUMP (SuSE LKCD) $datestring ***";
    }
}

#
# Subroutine to check file system free disk space and inodes
#
sub space {
    datecheck();
    print_header "*** BEGIN CHECKING FILE SYSTEMS SPACE AND INODES MINIMUM 10% FREE $datestring ***";

    $mingood = 100 - $THRESHOLD;

    # Hash of minimum file system sizing in MBytes
    # (as set in my Linux Standard Build)
    #
    my $BOOTFS2 = q{};
    if ($UNAME =~ /ia64|x86_64/i ) {
        $BOOTFS2 = "/boot/efi";
    }

    my %OVOARRAY = ( "/var/opt/perf",   "1024",
                     "/var/opt/OV",     "1024",
                   );

    my %OSARRAY1 = (
        "/",        "1024", "/tmp",     "1024",
        "/home",    "512",  "/usr",     "10240",
        "/var",     "4096", "/var/tmp", "1024",
        "/var/log", "4096", "/opt",     "4096",
        "/boot",    "1024",
    );

    # Add new key to the hash
    #    
    if ( "$BOOTFS2" ) {
        $OSARRAY1{$BOOTFS2} .= '1024';
    }

    # If OpenView used for monitoring, append the hash
    # with OVO file systems
    #
    if ( "$opt_o" == 1 ) {
        for my $what (keys %OVOARRAY) {
            $OSARRAY1{$what} = $OVOARRAY{$what};
        }
    }

    %OSARRAY = %OSARRAY1;

    if ( open( CC, "df -P -T | " )) {
        while (<CC>) {
            chomp;
            next if ( grep( /^$/,         $_ ) );
            next if ( grep( /Mounted on/, $_ ) );
            ( $fs, $Ttype, $allocated, $used, $avail, $pcused, $ffs ) =
              split( /\s+/, $_ );
            if ( $fs eq "tmpfs" ) {
                push( @TMPFSARR, $ffs );
                next;
            }
            push( @MAU, $ffs );
            $pcused =~ s/%//g;

            # Check each file system for lost+found
            #
            my $lfdir = "lost+found";
            if ( grep(/^ext/, $Ttype ) ) {
                if ( !-d "$ffs/$lfdir" ) {
                    print
                      "$WARNSTR File system missing or corrupt $ffs/$lfdir\n";
                    push(@CHECKARR,
                      "\n$WARNSTR File system missing or corrupt $ffs/$lfdir\n");
                    $warnings++;
                }
                else {
                    print "$PASSSTR File system has valid $ffs/$lfdir\n";
                }
            }

            if ( $OSARRAY{$ffs} ) {
                my $deffs_size = $OSARRAY{$ffs};
                my $allocMB = int( $allocated / 1024 );
                my $allocGB = int( $allocMB / 1024 );
                if ( "$allocMB" < "$deffs_size" ) {
                    print "$WARNSTR F/S size for $ffs is less than ";
                    print "recommended in $OS_Standard\n";
                    print "($allocMB MB while minimum is $deffs_size MB)\n";
                    push(@CHECKARR, "\n$WARNSTR F/S size for $ffs is less than ");
                    push(@CHECKARR, "recommended $OS_Standard\n");
                    push(@CHECKARR, "($allocMB MB while minimum is $deffs_size MB)\n");
                    $warnings++;
                }
                elsif ( "$allocGB" >= "$MAXFSSIZE" ) {
                    print "$INFOSTR F/S size for $ffs is larger than ";
                    print "recommended for efficient backups\n";
                    print "($allocGB GB while maximum is $MAXFSSIZE GB)\n";
                }
                else {
                    print "$PASSSTR F/S size for $ffs as ";
                    print "recommended in $OS_Standard\n";
                    print "($allocMB MB while minimum is $deffs_size MB)\n";
                }
            }

            if ( $pcused > $THRESHOLD ) {
                print "$WARNSTR File system $ffs has less than $mingood% ";
                print "free disk space ($pcused% used)\n\n";
                push(@CHECKARR, "\n$WARNSTR File system $ffs has less than $mingood% ");
                push(@CHECKARR, "free disk space ($pcused% used)\n");
                $warnings++;
            }
            else {
                print "$PASSSTR File system $ffs has more than $mingood% ";
                print "free disk space ($pcused% used)\n\n";
            }
        }
        close(CC);
    }
    else {
        print "$WARNSTR Cannot run df\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run df\n");
        $warnings++;
    }

    if ( open( CC, "df -P -i| egrep -iv ^none |" )) {
        while (<CC>) {
            chomp;
            next if ( grep( /^$/,         $_ ) );
            next if ( grep( /Mounted on/, $_ ) );
            next if ( grep( /^tmpfs\s+/, $_ ) );
            ( $fs, $iallocated, $iused, $iavail, $inodepcused, $ffs ) =
              split( /\s+/, $_ );
            $inodepcused =~ s/%//g;
            next if ( $inodepcused eq '-' );
            if ( $inodepcused > $THRESHOLD ) {
                print "$WARNSTR File system $ffs has less than $mingood% ";
                print "free inodes ($inodepcused% used)\n\n";
                push(@CHECKARR, "\n$WARNSTR File system $ffs has less than $mingood% ");
                push(@CHECKARR, "free inodes ($inodepcused% used)\n\n");
                $warnings++;
            }
            else {
                print "$PASSSTR File system $ffs has more than $mingood% ";
                print "free inodes ($inodepcused% used)\n\n";
            }
        }
        close(CC);
    }
    else {
        print "$WARNSTR Cannot run df\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run df\n");
        $warnings++;
    }

    datecheck();
    print_header "*** END CHECKING FILE SYSTEMS SPACE AND INODES MINIMUM 10% FREE $datestring ***";

    datecheck();
    print_header "*** BEGIN CHECKING FILE SYSTEMS NAMING STRUCTURE AS PER STANDARDS $datestring ***";

    if ( "@TMPFSARR" ) {
        print "$INFOSTR The following file systems are of tmpfs type\n";
        print "@TMPFSARR\n\n";
    }

    @VVM = keys(%OSARRAY);

    if ( @VVM != 0 ) {
        print
"$INFOSTR In some environments, following file systems might exist\n";
        foreach $i ( sort @VVM ) {
            if ( !( grep( /^$i$/, @MAU ) ) ) {
                if ( !( grep( /^$i$/, @TMPFSARR ) ) ) {
                    print "\n$INFOSTR File system $i does not exist\n";
                    $MISSING_FS_FLAG++;
                }
            }
        }
    }

    if ( $MISSING_FS_FLAG == 0 ) {
        print "$PASSSTR All O/S file system defined as per $OS_Standard\n";
    }

    datecheck();
    print_header "*** END CHECKING FILE SYSTEMS NAMING STRUCTURE AS PER STANDARDS $datestring ***";
}

#
# Subroutine to check LAN cards
#
sub lan {
    datecheck();
    print_header("*** BEGIN CHECKING LAN CARD STATUS $datestring ***");

    if ( open( CC, "cat /proc/net/dev |" ) ) {
        while (<CC>) {
            $alldet = q{};
            chomp;
            next if ( grep( /^$/,         $_ ) );
            next if ( grep( /Receive/,    $_ ) );
            next if ( grep( /compressed/, $_ ) );
            push( @Alllanscan, "$_\n" );

            $lancardno++;

            $_ =~ s/^\s+//g;

            if (! grep(/^sit0:|^lo:|^virbr/, $_) ) {
                $reallancardno++;
            }

            ( $Crd, undef ) = split( /:/, $_ );
            if ( open( ZZ, "ethtool $Crd 2>/dev/null |" ) ) {
                while (<ZZ>) {
                    $Active = q{};
                    chomp;
                    $VV = $_;
                    next if ( grep( /^$/,      $VV ) );
                    next if ( grep( /NO LINK/, $VV ) );
                    $VV =~ s/^\s+//g;
                    if ( grep( /Link detected:/, $VV ) ) {
                        ( undef, $alldet ) = split( /:/, $VV );
                        $alldet =~ s/^\s+//g;
                        if ( lc($alldet) eq 'yes' ) {
                            print "$PASSSTR Interface $Crd up\n";
                        }
                        else {
                            print "$INFOSTR Interface $Crd down\n";
                        }
                    }

                    if ( grep( /Speed:/, $VV ) ) {
                        ( undef, $alldet2 ) = split( /:/, $VV );
                        $alldet2 =~ s/^\s+//g;
                        print
                          "$INFOSTR Interface $Crd running at $alldet2\n";

                        if ( grep(/Unknown/, $alldet2 ) ) {
                            $reallancardno = $reallancardno - 1;
                        }
                    }

                    if ( grep( /Duplex:/, $VV ) ) {
                        ( undef, $alldet3 ) = split( /:/, $VV );
                        $alldet3 =~ s/^\s+//g;
                        print
"$INFOSTR Interface $Crd running at $alldet3 duplex\n";
                    }

                    if ( grep( /^Auto-negotiation:/, $VV ) ) {
                        ( undef, $Auto ) = split( /:/, $VV );
                        $Auto =~ s/^\s+//g;
                        print
"$INFOSTR Interface $Crd autonegotiation set to $Auto\n";
                    }
                }
                close(ZZ);
            }
            else {
                print "$WARNSTR Cannot run ethtool for interface $Crd\n";
                push(@CHECKARR, "\n$WARNSTR Cannot run ethtool for interface $Crd\n");
            }

            if ( open( ZZ, "ifconfig $Crd 2>/dev/null |" ) ) {
                print "\n$INFOSTR Ifconfig Interface $Crd\n";
                my @IARR = ();
                while (<ZZ>) {
                    print $_;
                    if ( grep( /PROMISC/, $_ ) ) {
                        push (@IARR, "$ERRSTR Interface $Crd running in PROMISCUOUS mode\n");
                        push(@CHECKARR, "\n$ERRSTR Interface $Crd running in PROMISCUOUS mode\n");
                        $warnings++;
                    }

                    if ( grep( /MULTICAST/, $_ ) ) {
                        push (@IARR, "$INFOSTR Interface $Crd supports MULTICASTING\n");
                    }
                }
                close(ZZ);

                if ( "@IARR" ) {
                    print "\n@IARR";
                }

                my @ethtoolk = `ethtool -k $Crd 2>/dev/null`;
                if ( @ethtoolk != 0 ) {
                    print "\n$INFOSTR Offload information for interface $Crd\n";
                    print "@ethtoolk\n";
                }

                my @ethtooli = `ethtool -i $Crd 2>/dev/null`;
                if ( @ethtooli != 0 ) {
                    print "\n$INFOSTR Driver information for interface $Crd\n";
                    print "@ethtooli\n";
                }

                my @ethtoolc = `ethtool -c $Crd 2>/dev/null`;
                if ( @ethtoolc != 0 ) {
                    print "\n$INFOSTR Interrupt coalescing information for interface $Crd\n";
                    print "@ethtoolc\n";
                }

                my @ethtoolg = `ethtool -g $Crd 2>/dev/null`;
                if ( @ethtoolg != 0 ) {
                    print "\n$INFOSTR Ring buffer information for interface $Crd\n";
                    print "@ethtoolg\n";
                }

                my @ethtoolS = `ethtool -S $Crd 2>/dev/null`;
                if ( @ethtoolS != 0 ) {
                    print "\n$INFOSTR HW level statistics for interface $Crd\n";
                    print "@ethtoolS\n";
                }
            }
            else {
                print "$WARNSTR Cannot run ifconfig for interface $Crd\n";
                push(@CHECKARR, "\n$WARNSTR Cannot run ifconfig for interface $Crd\n");
            }

        }
        close(CC);
    }
    else {
        print "$WARNSTR Cannot check /proc/net/dev\n";
        push(@CHECKARR, "\n$WARNSTR Cannot check /proc/net/dev\n");
        $warnings++;
    }

    if ( @Alllanscan != 0 ) {
        print "\n$INFOSTR Network status\n";
        print @Alllanscan;
    }

    if ( $lancardno <= 2 ) {
        print "\n$WARNSTR Only one network interface configured\n";
        push(@CHECKARR, "\n$WARNSTR Only one network interface configured\n");
        $warnings++;
    }
    else {
        if ( $reallancardno <= 2 ) {
            print
"\n$WARNSTR There is $reallancardno network interface configured (out of $lancardno interfaces in total)\n";
            push(@CHECKARR, "\n$WARNSTR There is $reallancardno network interface configured (out of $lancardno interfaces in total)\n");
        }
        else {
            print "\n$INFOSTR There are $reallancardno network interfaces configured (out of $lancardno interfaces in total)\n";
        }
    }

    datecheck();
    print_header("*** END CHECKING LAN CARD STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING CHANNEL BONDING $datestring ***");

    my @netcard = `ls /etc/sysconfig/network-scripts/ifcfg-bond* 2>/dev/null`;
    my @netcard2 = `ls /etc/sysconfig/network/ifcfg-bond* 2>/dev/null`;
    my @droutes2 = `awk '! /^#/ && /bond/ {print}' $DEBIFCFG 2>/dev/null`;

    my @BONDARR = `netstat -s | awk '/^bond/ {print \$1}' 2>/dev/null`;
    foreach my $bondent ( @BONDARR ) {
        chomp($bondent);
        my @BONDSTAT = `cat /proc/net/bonding/$bondent 2>/dev/null`;
        if ( @BONDSTAT ) {
             print "$INFOSTR Channel Bonding status for $bondent\n";
             print "@BONDSTAT\n";
        }
    }

    if ( @netcard != 0 ) {
        foreach $i (@netcard) {
            chomp($i);
            print "$INFOSTR Channel bonding setup for $i\n";
            my @netif = `egrep -v ^# $i | awk NF`;
            print "@netif\n";
        }
    }
    elsif ( @netcard2 != 0 ) {
        foreach $i (@netcard2) {
            chomp($i);
            print "$INFOSTR Channel bonding setup for $i\n";
            my @netif = `egrep -v ^# $i | awk NF`;
            print "@netif\n";
        }
    }
    elsif ( @droutes2 != 0 ) {
        print "\n$INFOSTR Channel bonding setup in $DEBIFCFG\n";
        print @droutes;
    }
    else {
        print "$INFOSTR Channel Bonding not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING CHANNEL BONDING $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING ETHERNET BRIDGE STATUS $datestring ***");

    my @brctls = `brctl show 2>/dev/null`;
    if ( @brctls != 0 ) {
        print "$INFOSTR Ethernet bridges\n";
        print @brctls;
    }
    else {
        print "$INFOSTR Ethernet bridges not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING ETHERNET BRIDGE STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING DIALUP INTERFACES $datestring ***");

    my @netcardp = `ls /etc/sysconfig/network-scripts/ifcfg-ppp* 2>/dev/null`;
    if ( @netcardp != 0 ) {
        foreach $i (@netcardp) {
            chomp($i);
            print "\n$INFOSTR Dialup setup for $i\n";
            my @netif = `egrep -v ^# $i | awk NF`;
            print @netif;
        }
    }
    else {
        print "$INFOSTR Dialup not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING DIALUP INTERFACES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING WIRELESS STATUS $datestring ***");

    my @iwconf = `iwconfig 2>&1`;
    if ( @iwconf != 0 ) {
        print "$INFOSTR Wireless configuration\n\n";
        print @iwconf;
    }
    else {
        print "$INFOSTR Wireless not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING WIRELESS STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING STATIC ROUTES PER INTERFACE $datestring ***");

    if ( $DIST eq 'SuSE' ) {
        my @suseroute = `egrep -v ^# /etc/sysconfig/network/routes 2>/dev/null`;
        if ( @suseroute != 0 ) {
            print @suseroute;
            print "\n";
        }
    }

    my @netcards = `ls /etc/sysconfig/network-scripts/route-* 2>/dev/null`;
    if ( @netcards != 0 ) {
        foreach $i (@netcards) {
            chomp($i);
            print "\n$INFOSTR Static route setup for $i\n";
            my @netif = `egrep -v ^# $i | awk NF`;
            print @netif;
        }
    } elsif ( $DIST eq 'Debian' ) {
        @droutes = `grep -v ^# $DEBIFCFG 2>/dev/null`;
        if ( @droutes != 0 ) {
            print @droutes;
            print "\n";
        }
    } else {
        print "$INFOSTR Static routes per interfaces not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING STATIC ROUTES PER INTERFACE $datestring ***");
}

#
# Subroutine to check shutdown and boot logs
#
sub start_shutdown_log {
    datecheck();
    print_header("*** BEGIN CHECKING LOG FILES FOR STARTUP ERRORS $datestring ***");

    if ( open( CC, "egrep -i 'warn|error|fail' $Rclog |" ) ) {
        while (<CC>) {
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /Failsafe/i, $_ ) );
            push( @PPanarray, $_ );
            $ppanic++;
        }
        close(CC);
    }
    else {
        print "$WARNSTR Cannot open $Rclog\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $Rclog\n");
        $warnings++;
    }

    if ( $ppanic > 0 ) {
        print "$WARNSTR $Rclog not clear of system errors\n";
        print "@PPanarray";
        push(@CHECKARR, "\n$WARNSTR $Rclog not clear of system errors\n");
        push(@CHECKARR, "@PPanarray");
        $warnings++;
    }
    else {
        print "$PASSSTR $Rclog clear of system errors\n";
    }

    datecheck();
    print_header("*** END CHECKING LOG FILES FOR STARTUP ERRORS $datestring ***");
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

#
# Subroutine to check installed software bundles
#
sub swcheck {
    if ( $DIST ne "Debian" ) {
        datecheck();
        print_header("*** BEGIN CHECKING SUPPORT NETWORK LICENSING $datestring ***");

        if ( $DIST eq 'RedHat' ) {
            my @RHARS = (
                '/etc/sysconfig/rhn/up2date',
                '/etc/sysconfig/rhn/rhn-applet',
                '/etc/sysconfig/rhn/up2date-uuid',
                '/etc/sysconfig/rhn/systemid',
            );

            foreach my $zla (@RHARS) {
                my @RHNarray = `egrep -v ^# $zla 2>/dev/null | awk NF`;

                if ("@RHNarray") {
                    print "$INFOSTR Configuration file $zla\n";
                    print @RHNarray;
                }
                else {
                    print "$WARNSTR Configuration file $zla is empty or corrupt\n";
                    push(@CHECKARR, "\n$WARNSTR Configuration file $zla is empty or corrupt\n");
                    $warnings++;
                }
                print "\n";
            }

            my @rhncheck = `rhn_check 2>/dev/null`;
            if ( "@rhncheck" ) {
                print "$WARNSTR RHN check\n";
                print @rhncheck;
            }
            else {
                print "$PASSSTR rhn_check does not report any problems\n";
            }
        }

        if ( $PKGDB eq "RPM" ) {
            foreach my $yumdir (@YUMarray) {
                if ( -s "$yumdir" ) {
                    my @yumlist = `egrep -v ^# $yumdir | awk NF`;
                    if ("\@yumlist") {
                        print "\n$INFOSTR $yumdir listing\n";
                        print @yumlist;
                    }
                }
            }

            my @YUMLIST = `ls $YUMDIR/*.repo 2>/dev/null`;
            my @GPGARR  = ();
            my $gpgstat = q{};
            foreach my $yumfile (@YUMLIST) {
                chomp($yumfile);
                if ( -s "$yumfile" ) {
                    if ( open( YC, "egrep -v ^# $yumfile 2>/dev/null |" ) ) {
                        print "\n$INFOSTR Contents of $yumfile:\n";
                        while (<YC>) {
                            next if grep( /^$/, $_ );
                            print $_;
                            if ( grep(/^baseurl|^gpgcheck/, $_) ) {
                                push(@GPGARR, $_);
                            }
                        }
                        close(YC);
                    }
                }
            }

            if ( @GPGARR ) {
                print "\n$INFOSTR YUM repository status of GPG cryptographic signatures before package installations (potentially dangerous if gpgcheck=0)\n";
                print @GPGARR;

                my @yumrepo = `yum repolist 2>/dev/null`;
                if ("\@yumrepo") {
                    print "\n$INFOSTR YUM installation repositories\n";
                    print @yumrepo;
                }

                my @yumhist = `yum history 2>/dev/null`;
                if ("\@yumhist") {
                    print "\n$INFOSTR YUM repo history\n";
                    print @yumhist;
                }
            }
        }

#        my @ulncheck = `uln-channel --list 2>/dev/null 2>/dev/null`;
#        if ( "@ulncheck" ) {
#            print "\n$INFOSTR Unbreakable Linux Network (ULN) check\n";
#            print @ulncheck;

#            my @ulnchan = `uln-channel --available-channels 2>/dev/null`;
#            if ( "@ulnchan" ) {
#                print "\n$INFOSTR Unbreakable Linux Network (ULN) channels\n";
#                print @ulnchan;
#            }
#        }

        if ( $DIST eq 'SuSE' ) {
            my @ZYPPERREPO = `zypper -n repos --uri 2>/dev/null| awk NF`;
            if ("\@ZYPPERREPO") {
                print "\n$INFOSTR Zypper installation repositories\n";
                print @ZYPPERREPO;
            }

            my @ZYPPERPU = `zypper -n lu 2>/dev/null | awk NF`;
            if ("\@ZYPPERPU") {
                print "\n$INFOSTR Zypper pending updates\n";
                print @ZYPPERPU;
            }

            my @ZYPPERPEND = `zypper -n lp 2>/dev/null | awk NF`;
            if ("\@ZYPPERPEND") {
                print "\n$INFOSTR Zypper pending patches\n";
                print @ZYPPERPEND;
            }

            my @ZYPPERPS = `zypper -n ps 2>/dev/null | awk NF`;
            if ("\@ZYPPERPS") {
                print "\n$INFOSTR Zypper processes that need restart after update\n";
                print @ZYPPERPS;
            }

            my @yast = `yast -l | awk NF`;
            if ("\@yast") {
                print "\n$INFOSTR YAST status\n";
                print @yast;
            }

            my $YASTDIR = '/etc/YaST2';
            my @yastarray = `ls $YASTDIR/* 2>/dev/null`;

            foreach my $ydev (@yastarray) {
                chomp($ydev);
                if ( -s "$ydev" ) {
                    my @YL = `egrep -v ^# $ydev | awk NF` ;
                    if ( @YL ) {
                        print "\n$INFOSTR YAST configuration file $ydev\n";
                        print @YL;
                    }
                }
            }
        }

        datecheck();
        print_header("*** END CHECKING SUPPORT NETWORK LICENSING $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING INSTALLED SOFTWARE PACKAGES $datestring ***");

    print
      "$NOTESTR Some applications might be installed without packages\n";
    print "$NOTESTR Please check them manually\n\n";

    if ( $DIST eq "Debian" ) {
        my @RPMtest = `debsums -a 2>&1`;
        @SWarray = `$LCOMM`;
        if ( ! "@SWarray" ) {
           print "$ERRSTR $PKGDB package database possibly corrupt\n";
           push(@CHECKARR, "\n$ERRSTR $PKGDB package database possibly corrupt\n");
        } else {
           print "$PASSSTR $PKGDB package database seemingly valid\n";
        }

        if ( "@RPMtest" ) {
           print "\n$INFOSTR $PKGDB package database status\n";
           print @RPMtest;
        }

        print "\n";
    } else {
        my @RPMtest = `rpm --verifydb`;
        my @RPMtest2 = `rpmdb_verify $RPMDIR/Packages`;

        if ( @RPMtest || @RPMtest2 ) {
           print "$ERRSTR $PKGDB package database possibly corrupt\n";
           push(@CHECKARR, "\n$ERRSTR $PKGDB package database possibly corrupt\n");
        }
        else {
           print "$PASSSTR $PKGDB package database seemingly valid\n";
        }

        @SWarray = `$LCOMM --last`;

        if ( "@SWarray" != 0 ) {
            print "\n$ERRSTR Package is empty or corrupt\n";
            push(@CHECKARR, "\n$ERRSTR Package is empty or corrupt\n");
            $warnings++;
        }
        else {
            my @PKGI1 = ();

           foreach my $acst (@SWarray) {
               my @realpkg = split(/\s+/, $acst);
               my @pkgi = `rpm -qi $realpkg[0] 2>/dev/null`;
               if ( "@pkgi") {
                   push(@PKGI1, "@pkgi\n");
               }
           }

           if ( "@PKGI1" ) {
               print "\n$INFOSTR Package build environment\n";
               print @PKGI1;
           }

           print "\n";
        }
    }

    foreach my $acst (@SWmust) {
        if ( grep( /$acst/i, @SWarray ) ) {
            print "$PASSSTR $acst installed\n";
            eval(
              ( $acst =~ /Bastille/ ) ? $IDS_FLAG = 1
            : ( $acst =~ /DP_/ ) ? $OMNI_FLAG = 1
            : ( $acst =~ /openvpn/ ) ? $OPENVPN_FLAG = 1
            : ( $acst =~ /openssh/ ) ? $secureshell++
            : ""
            );
        }
        else {
          eval(
              ( $acst =~ /SecurePath/ ) ? $warnings++
            : ( $acst =~ /DP_/ )      ? ""
            : ( $acst =~ /emcpower/ ) ? ""
            : ( $acst =~ /openssh/ )  ? $warnings++
            : swcalc($acst)
            );
        }
    }

    datecheck();
    print_header("*** END CHECKING INSTALLED SOFTWARE PACKAGES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SECURE SHELL STATUS $datestring ***");

    if ( "$secureshell" == 0 ) {
        print "$ERRSTR Secure Shell (SSH) not installed\n";
        push(@CHECKARR, "\n$ERRSTR Secure Shell (SSH) not installed\n");
    }

        -s "$SSHD_CONF1" ? $SSHD_CONF = $SSHD_CONF1
      : -s "$SSHD_CONF2" ? $SSHD_CONF = $SSHD_CONF2
      : -s "$SSHD_CONF3" ? $SSHD_CONF = $SSHD_CONF3
      : -s "$SSHD_CONF4" ? $SSHD_CONF = $SSHD_CONF4
      : -s "$SSHD_CONF5" ? $SSHD_CONF = $SSHD_CONF5
      : print "$INFOSTR SSH daemon configuration file not installed\n\n";

    if ( -s "$SSHD_CONF") {
        if ( open( SSHCD, "awk NF $SSHD_CONF |" ) ) {
            print "$INFOSTR File $SSHD_CONF\n";
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
                        push(@CHECKARR, "\n$WARNSTR StrictModes set to \"no\"\n");
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
                        push(@CHECKARR, "\n$WARNSTR IgnoreRhosts set to \"no\"\n");
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
                        push(@CHECKARR, "\n$WARNSTR PermitEmptyPasswords set to \"yes\"\n");
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
                    next if ( grep( /^#/, $_ ) );
                    next if ( grep( /,/,  $_ ) );
                    ( undef, $SSHPRIVSEP ) = split( /\s+/, $_ );
                    chomp($SSHPRIVSEP);
                    if ( lc($SSHPRIVSEP) eq 'no' ) {
                        push(@SSHARR, "$WARNSTR UsePrivilegeSeparation set to \"no\"\n");
                        push(@SSHARR, "$INFOSTR It is strongly recommended to disable it\n");
                        push(@CHECKARR, "\n$WARNSTR UsePrivilegeSeparation set to \"no\"\n");
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
                        push(@CHECKARR, "\n$WARNSTR AllowTcpForwarding set to \"yes\"\n");
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
            print "\n$WARNSTR Cannot open $SSHD_CONF\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $SSHD_CONF\n");
            $warnings++;
        }
    }

    print "\n";

    if ( @SSHARR ) {
        print @SSHARR;
    }

    checkActivePorts(22);

    datecheck();
    print_header("*** END CHECKING SECURE SHELL STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING STATUS OF INSTALLED PACKAGES AND PATCH DATES $datestring ***");

    print @SWarray;

    datecheck();
    print_header("*** END CHECKING STATUS OF INSTALLED PACKAGES AND PATCH DATES $datestring ***");
}

#
# Subroutine to check privileged account
#
sub rootacc { 
    datecheck();
    print_header("*** BEGIN CHECKING PRIVILEGED ACCOUNT $datestring ***");

    my $umsk = sprintf "%lo", umask;

    if ( $umsk == "022" ) {
        print "$PASSSTR Umask for root set to 022\n";
    }
    else {
        print "$INFOSTR Umask set to $umsk (minimum recommended is 022)\n";
        $warnings++;
    }

    $Rootarray = `awk '/^root:/ && ! /awk/ {print}' $PASSFILE`;
    chomp($Rootarray);

    (
        $rootacc,   $rootpasswd, $rootuid, $rootgid,
        $rootgecos, $roothome,   $rootshell
      )
      = split( /:/, $Rootarray );

    print "$INFOSTR Root Shell is $rootshell\n";

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
    if ( -s "$rho" ) {
        print "\n$WARNSTR File $rho exists\n";
        my @rhosts = `cat $rho`;
        push(@CHECKARR, "\n$WARNSTR File $rho exists\n");
        push(@CHECKARR, @rhosts);
    }

    my $rauth = "$roothome/.ssh/authorized_keys";
    if ( -s "$rauth" ) {
        print "\n$INFOSTR File $rauth exists\n";
        my @rauhosts = `cat $rauth`;
        print @rauhosts;
    }

    if ( -f "$sectty" && -s "$sectty" ) {
        print "\n$PASSSTR $sectty exists\n";
        if ( open( CC, "awk '! /^#/ && ! /awk/ {print}' $sectty |" ) ) {
            while (<CC>) {
                next if grep( /^$/, $_ );
                print $_;
            }
            close(CC);
        }
        else {
            print "$ERRSTR Cannot open $sectty\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $sectty\n");
            $warnings++;
        }
    }
    else {
        print "\n$WARNSTR $sectty not installed\n";
        push(@CHECKARR, "\n$WARNSTR $sectty not installed\n");
        $warnings++;
    }

    my @Secarray = `ls $SECDIR/*.conf 2>/dev/null`;

    foreach $secdev (@Secarray) {
        chomp($secdev);
        if ( -s "$secdev" ) {
            if ( open( CC, "cat $secdev |" ) ) {
                print "\n$INFOSTR $secdev exists\n";
                while (<CC>) {
                    next if grep( /^$/, $_ );
                    print $_;
                }
                close(CC);
            }
             else {
                print "\n$INFOSTR $secdev exists but not configured\n";
            }
        }
        else {
            print "\n$INFOSTR $secdev empty or does not exist\n";
        }
    }

    if ( -s "$Superconf1" ) {
        $Superconf = $Superconf1;
    }
    elsif ( -s "$Superconf2" ) {
        $Superconf = $Superconf2;
    }
    elsif ( -s "$Superconf3" ) {
        $Superconf = $Superconf3;
    }

    if ( -s "$Superconf" ) {
        print "\n$INFOSTR $Superconf exists\n";
        if ( open( SCF, "awk '! /^#/ && ! /awk/ {print}' $Superconf |" ) ) {
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

    if ( -s "$sudoconf1" ) {
        $sudoconf = $sudoconf1;
    }
    elsif ( -s "$sudoconf2" ) {
        $sudoconf = $sudoconf2;
    }
    elsif ( -s "$sudoconf3" ) {
        $sudoconf = $sudoconf3;
    }

    if ( -s "$sudoconf" ) {
        print "\n$INFOSTR $sudoconf exists\n";
        if ( open( SUF, "awk '! /^#/ && ! /awk/ {print}' $sudoconf |" ) ) {
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

    if ( -s "$sulog" ) {
        my @SUent = `egrep -i root $sulog`;
        if ( @SUent != 0 ) {
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

    if ( @ntpdaemon != 0 ) {
        my @NTPARR = ();

        print "$PASSSTR Standard Network Time Protocol daemon running\n";
        if ( open( CC, "ntpq -n -c peers |" ) ) {
            while (<CC>) {
                push(@NTPARR, $_);
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

            if ( "@NTPARR" ) {
                print "\n$INFOSTR NTP sources\n";
                print @NTPARR;
            }

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
            print "$WARNSTR Cannot run ntpq";
            push(@CHECKARR, "\n$WARNSTR Cannot run ntpq");
        }

        if ( -s "$ntpconf" ) {
            print "\n$PASSSTR $ntpconf exists\n";
            if ( open( NTPC, "awk '! /^#/ && ! /awk/ {print}' $ntpconf |" ) )
            {
                while (<NTPC>) {
                    $_ =~ s/^\s+//g;
                    print $_;
                    next if ( grep( /^#/, $_ ) );
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
            my @NTPtrace = `ps -lC ntpd 2>/dev/null`;
            if ( "@NTPtrace" ) {
                print "$NOTESTR NTP configuration possibly located elsewhere\n";
                print @NTPtrace;
            }
            $warnings++;
        }
    }
    elsif ( @chronydaemon != 0 ) {
        my @NTPARR = ();

        print "$PASSSTR Chrony Standard Network Time Protocol daemon running\n";

        if ( open( CC, "chronyc -n sources 2>/dev/null |" ) ) {
            while (<CC>) {
                push(@NTPARR, $_);
                next if ( grep( /^$/,     $_ ) );
                next if ( grep( /Stratum/, $_ ) );
                next if ( grep( /Number of/, $_ ) );
                next if ( grep( /===/,    $_ ) );
                $_ =~ s/^\s+//g;
                (
                    $MS, $remote, $st, $poll, $reach, $lastrx, $lastsample
                  )
                  = split( /\s+/, $_ );
                $reach  =~ s/^\s+//g;
                $remote =~ s/\*//g;

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

            if ( @NTPARR) {
                print "\n$INFOSTR NTP sources\n";
                print @NTPARR;
            }

            my @chronystat = `chronyc -n sourcestats 2>/dev/null`;
            if ( "@chronystat" ) {
                print "\n$INFOSTR NTP source statistics\n";
                print @chronystat;
            }

            my @chronyact = `chronyc -n activity 2>/dev/null`;
            if ( "@chronyact" ) {
                print "\n$INFOSTR NTP activity\n";
                print @chronyact;
            }

            my @chronytrack = `chronyc -n tracking 2>/dev/null`;
            if ( "@chronytrack" ) {
                print "\n$INFOSTR NTP tracking\n";
                print @chronytrack;
            }
        }
        else {
            print "$WARNSTR Cannot run chronyc";
            push(@CHECKARR, "\n$WARNSTR Cannot run chronyc");
        }

        if ( -s "$chronyconf" ) {
            print "\n$PASSSTR $chronyconf exists\n";
            if ( open( NTPC, "awk '! /^#/ && ! /awk/ {print}' $chronyconf |" ) )
            {
                while (<NTPC>) {
                    $_ =~ s/^\s+//g;
                    print $_;
                    next if ( grep( /^#/, $_ ) );
                    if ( grep( /allow/, $_ ) ) {
                        $NTP_REST_FLAG++;
                    }
                }
            }
            close(NTPC);

            if ( $NTP_REST_FLAG == 0 ) {
                print
"\n$WARNSTR Network Time Protocol not restricted in $chronyconf\n";
                push(@CHECKARR,
"\n$WARNSTR Network Time Protocol not restricted in $chronyconf\n");
                $warnings++;
            }
            else {
                print
"\n$PASSSTR Network Time Protocol restricted in $chronyconf\n";
            }
        }
        else {
            print "\n$ERRSTR Cannot open $chronyconf\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $chronyconf\n");
            my @chronyd = `ps -lC chronyd 2>/dev/null`;
            if ( "@chronyd" ) {
                print "$NOTESTR NTP configuration possibly located elsewhere\n";
                print @chronyd;
            }
            $warnings++;
        }
    }
    else {
        print "$WARNSTR Standard or Chrony Network Time Protocol not running\n";
        push(@CHECKARR, "\n$WARNSTR Standard or Chrony Network Time Protocol not running\n");
        $warnings++;

    }

    my @TIMEDATE = `timedatectl status 2>/dev/null`;
    if ( "@TIMEDATE" ) {
        print "\n$INFOSTR System time and date status\n";
        print @TIMEDATE;
    }

    datecheck();
    print_header("*** END CHECKING NTP SERVICES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING DHCP SERVICES $datestring ***");

    my @dhcpstat = `/etc/init.d/dhcpd status 2>/dev/null`;

    if ( @dhcpstat != 0 ) {
        print "$INFOSTR DHCP server seemingly running\n";
        print @dhcpstat;

        my $DHCPCONF = '/etc/dhcpd.conf';
        if ( -s "$DHCPCONF" ) {
            my @DHCPCAT = `egrep -v ^# $DHCPCONF | awk NF`;
            print "\n$INFOSTR DHCP server configuration file\n";
            print @DHCPCAT;
        }
        else {
            print
"\n$INFOSTR DHCP server configuration file empty or does not exist\n";
        }
    }
    else {
        print "$INFOSTR DHCP server seemingly not running\n";
    }

    datecheck();
    print_header("*** END CHECKING DHCP SERVICES $datestring ***");
}

#
# Subroutine to check NFS
#
sub raw_check { 
    datecheck();
    print_header("*** BEGIN CHECKING BINDINGS FOR RAW DEVICES $datestring ***");

    my @rawfs = `raw -qa 2>/dev/null`;
    if ( @rawfs != 0 ) {
        print @rawfs;
    }
    else {
        print "$INFOSTR Seemingly no raw devices in use, or raw(8) command does not exist\n";
    }

    datecheck();
    print_header("*** END CHECKING BINDINGS FOR RAW DEVICES $datestring ***");
}

#
# Subroutine to check NFS
#
sub nfs_check { 
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK FILE SYSTEM (NFS) $datestring ***");

    if ( @nfsdaemon != 0 ) {
        if ( "$MNT_FLAG" == 0 ) {
            if ( open( CC, "mount | egrep -i nfs |" ) ) {
                while (<CC>) {
                    next if ( grep( /^$|^sunrpc |^nfsd /, $_ ) );
                    ( $lfs, undef, $remfs, $state, undef ) =
                      split( /\s+/, $_ );
                    chomp($lfs);
                    push( @NFSarr, $lfs );
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
        print "$INFOSTR There are NFS mounts\n";
        print "@NFSarr\n";
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

    if ( -T "$nfsconf" && -s "$nfsconf" ) {
        print "\n$PASSSTR $nfsconf exists\n";
        if ( open( CC, "awk '! /^#/ && ! /awk/ {print}' $nfsconf |" ) ) {
            while (<CC>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/\s+//g;
                if ( grep( /^NFS_SERVER=/, $_ ) ) {
                    if ( grep( /1/, $_ ) ) {
                        print
"$WARNSTR NFS server enabled in $nfsconf (flag NFS_SERVER)\n";
                        push(@CHECKARR,
"\n$WARNSTR NFS server enabled in $nfsconf (flag NFS_SERVER)\n");
                        $warnings++;
                    }
                    else {
                        print "$PASSSTR NFS server disabled in $nfsconf ";
                        print "(flag NFS_SERVER)\n";
                    }
                }

                if ( grep( /^NFS_CLIENT=/, $_ ) ) {
                    if ( grep( /1/, $_ ) ) {
                        print "$WARNSTR NFS client enabled in $nfsconf ";
                        print "(flag NFS_CLIENT)\n";
                        push(@CHECKARR, "\n$WARNSTR NFS client enabled in $nfsconf ");
                        push(@CHECKARR, "(flag NFS_CLIENT)\n");
                        $warnings++;
                    }
                    else {
                        print "$PASSSTR NFS client disabled in $nfsconf ";
                        print "(flag NFS_CLIENT)\n";
                    }
                }

                if ( grep( /^AUTOMOUNT=/, $_ ) ) {
                    if ( grep( /1/, $_ ) ) {
                        print "$INFOSTR Automount enabled in $nfsconf ";
                        print "(flag AUTOMOUNT)\n";
                        $AUTO_FLAG++;
                    }
                    else {
                        print "$PASSSTR Automount client disabled in ";
                        print "$nfsconf (flag AUTOMOUNT)\n";
                    }
                }

                if ( grep( /^AUTOFS=/, $_ ) ) {
                    if ( grep( /1/, $_ ) ) {
                        print "$INFOSTR Autofs client enabled in $nfsconf ";
                        print "(flag AUTOFS)\n";
                        $AUTO_FLAG++;
                    }
                    else {
                        print "$PASSSTR Autofs client disabled in $nfsconf ";
                        print "(flag AUTOFS)\n";
                    }
                }
            }
        }
        close(CC);
    }
    else {
        print "\n$INFOSTR Cannot open $nfsconf or it is empty\n";
    }

    print "\n$NOTESTR Refer to mount_nfs regarding Hard/Soft mounts\n";

    if ( -s "$exportfs" ) {
        print "\n$NOTESTR $exportfs exists\n";
        my @efs = `awk '! /^#/ && ! /awk/ {print}' $exportfs`;
        print @efs;
    }
    else {
        print "\n$NOTESTR $exportfs not set up\n";
    }

    datecheck();
    print_header("*** END CHECKING NETWORK FILE SYSTEM (NFS) $datestring ***");
}

#
# Subroutine to check mounted file systems
#
sub CHECK_MOUNTED_FILESYSTEMS {
    if ( open( ZK, "awk NF $initt 2>/dev/null |" ) ) {
        while (<ZK>) {
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /^#/, $_ ) );
            $_ =~ s/#.*$//g;
            $_ =~ s/^\s+//g;
            push( @initarr, $_ );

            if ( grep( /vxenablef/, $_ ) ) {
                ( undef, undef, undef, $vxe ) = split( /:/, $_ );
                if ("$vxe") {
                    chomp($vxe);
                    $vxe =~ s/^\s+//g;
                    ( $vxcom, undef ) = split( /\s+/, $vxe );
                    my @vxl = `$vxcom`;
                }
            }

            if ( grep( /:initdefault:/, $_ ) ) {
                chomp($_);
                my @deflev = split(/:/, $_);
                if( ! "$deflev[1]" ) {
                    push(@CHECKARR, "\n$WARNSTR Line \"$_\" contains undefined default runlevel in $initt\n");
                    push(@INITARR, "\n$WARNSTR Line \"$_\" contains undefined default runlevel in $initt\n");
                    $warnings++;
                }
                else {
                    if( ! ( $deflev[1] =~ /^[0-6]$/ ) ) {
                        push(@CHECKARR, "\n$INFOSTR Line \"$_\" contains additional value in default runlevel $deflev[1] in $initt\n");
                        push(@INITARR, "\n$INFOSTR Line \"$_\" contains additional value in default runlevel $deflev[1] in $initt\n");
                    }

                    if ( $deflev[1] != $runlevel ) {
                        push(@CHECKARR, "\n$WARNSTR Default runlevel $deflev[1] in $initt differs from runlevel(1)\n");
                        push(@INITARR, "\n$WARNSTR Default runlevel $deflev[1] in $initt differs from runlevel(1)\n");
                        $warnings++;
                    }
                }
            }

            if ( grep( /:wait:/, $_ ) ) {
                chomp($_);
                my @deflev = split(/:/, $_);
                my @lastfig = split(/\s+/, $deflev[$#deflev]);
                if ( $deflev[1] != $lastfig[1] ) {
                    push(@CHECKARR, "\n$WARNSTR Corrupt line \"$_\" in $initt\n");
                    push(@INITARR, "\n$WARNSTR Corrupt line \"$_\" in $initt\n");
                    $warnings++;
                }
            }

            if ( grep( /:respawn:/, $_ ) ) {
                chomp($_);
                my @deflev = split(/:/, $_);
                
                if( $deflev[0] =~ /^~~$/ ) { 
                    if ( ! ( $deflev[1] =~ /^S$|^1$/i ) ) {
                        push(@CHECKARR, "\n$WARNSTR Line \"$_\" contains invalid value for runlevel $deflev[0] in $initt\n");
                        push(@INITARR, "\n$WARNSTR Line \"$_\" contains invalid value for runlevel $deflev[0] in $initt\n");
                        $warnings++;
                    }
                }
                else {
                    if( $deflev[0] ne 'x' ) {
                        if( ! ( $deflev[0] =~ /^[0-6]$/ ) ) {
                            push(@CHECKARR, "\n$WARNSTR Line \"$_\" contains invalid value for runlevel $deflev[0] in $initt\n");
                            push(@INITARR, "\n$WARNSTR Line \"$_\" contains invalid value for runlevel $deflev[0] in $initt\n");
                            $warnings++;
                        }
                    }
                }
            }

            if ( grep( /:sysinit:/, $_ ) ) {
               $SYSINIT_FLAG++;
            }
        }
        close(ZK);
    }
    else {
        print "$WARNSTR Cannot open $initt\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $initt\n");
        $warnings++;
    }

    if ( @initarr != 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING SYSTEM V INIT $datestring ***");

        print "$INFOSTR Configuration file $initt\n";
        print @initarr;

        if ( $SYSINIT_FLAG == 0 ) {
            push(@INITARR, "\n$INFOSTR $initt missing rc.sysinit (not critical if Upstart Init in use)\n");
            push(@CHECKARR, "\n$INFOSTR $initt missing rc.sysinit (not critical if Upstart Init in use)\n");
        }

        if ( "@INITARR" ) {
            print @INITARR;

            if ( ! grep(/WARN/, "@INITARR") ) {
                print "\n$PASSSTR $initt passed basic syntax health check\n";
            }
        }
        else {
            print "\n$PASSSTR $initt passed basic syntax health check\n";
        }

        datecheck();
        print_header("*** END CHECKING SYSTEM V INIT $datestring ***");
    }

    my $INITDIR = "/etc/init";
    if ( -d "$INITDIR" ) {
        datecheck();
        print_header("*** BEGIN CHECKING UPSTART INIT $datestring ***");

        my @Initarray = `ls $INITDIR 2>/dev/null`;

        foreach my $initfile (@Initarray) {
            chomp($initfile);
            if ( -f "$INITDIR/$initfile" ) {
                print "\n$INFOSTR $INITDIR/$initfile is a plain file\n";
                my $initcat = `cat $INITDIR/$initfile 2>/dev/null`;
                if ("$initcat") {
                    print $initcat;
                }
            }
        }

        datecheck();
        print_header("*** END CHECKING UPSTART INIT $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING ALL FSTAB FILE SYSTEMS MOUNTED AND VALID $datestring ***");

    my $fswarnings;

    my @RESBLKARR   = ();
    my @BLKARR      = ();
    my @PROCARR     = ();
    my @EXT4ARR     = (); 
    my @XFSARR      = (); 
    my @BTRFSARR    = ();
    my @DUMPE2FSARR = ();
    my @ext4defrag  = ();

    my @MNTTABARR = `cat $MNTTAB 2>/dev/null`;
    if ( ! "@MNTTABARR" ) {
        print "$ERRSTR File $MNTTAB empty\n";
        push(@CHECKARR, "\n$ERRSTR File $MNTTAB empty\n");
        $MNT_FLAG = 1;
        $warnings++;
    }
    else {
        my @rbc        = ();
        my @mline      = ();
        my $fsdev      = q{};
        my $fstype     = q{};
        my $Resblkcnt  = 0; 
        my @bc         = ();
        my $Blkcnt     = 0; 

        if ( open( MM, "mount | sort |" ) ) {
            while (<MM>) {
                next if ( grep( /^$/, $_ ) );
                push( @ALLMounted, $_ );
                chomp($_);
                @mline = split(/\s+/, $_);
                $fsreal = $mline[2];
                $fsdev = $mline[0];
                $fstype = $mline[4];

                if ( ($fstype eq "proc") && ( grep(/^proc/, $fsdev)) ) {
                    if ( grep(/hidepid=1|hidepid=2/, $_) ) {
                        push(@PROCARR, "\n$_");
                    }
                }

                next if ( grep(/^none |^sunrpc |^usbfs |^sysfs |^devpts |^proc |binfmt_misc|^nfsd |^gvfs-|^fusectl |^rpc_pipefs | vfat | type none |^tmpfs /, $_ ) );
                if ( "$fsreal" ) {
                    push( @fss, $fsreal );
                }
                
                if ( ($fstype eq "ext2") || ($fstype eq "ext3") || ($fstype eq "ext4") ) {
                    push(@DUMPE2FSARR, "\n$INFOSTR Dump of file system $fsdev information\n");
                    if ( open( DUMP2, "dumpe2fs $fsdev 2>/dev/null |" ) ) {
                        while (<DUMP2>) {
                            push(@DUMPE2FSARR, $_);

                            if ( grep(/Filesystem volume name:/, $_) ) {
                                push(@BLKARR, "\n$_");
                            } else {
                                push(@BLKARR, $_);
                            }
                            chomp($_);
                            if ( grep(/^Reserved block count:/, $_ ) ) {
                                @rbc = split(/:/, $_);
                                $Resblkcnt = $rbc[1];
                            }

                            if ( grep(/^Block count:/, $_ ) ) {
                                @bc = split(/:/, $_);
                                $Blkcnt = $bc[1];
                            }
                        }
                        close(DUMP2);
           
                        if ( ("$Resblkcnt") && ("$Blkcnt") ) {
                            my $Resblkpct = sprintf("%.0f", (($Resblkcnt / $Blkcnt) * 100));
                            if ( $Resblkpct > 1 ) {
                                push(@RESBLKARR,
"\n$WARNSTR File system \"$fsdev\" allocated $Resblkpct% for reserved blocks (recommended to allocate 1%)");
                                push(@CHECKARR,
"\n$WARNSTR File system \"$fsdev\" allocated $Resblkpct% for reserved blocks (recommended to allocate 1%)\n");
                                $warnings++;
                            }
                        }
                    }
                }

                if ( $fstype eq "xfs" ) {
                    my @xfsinfo = `xfs_info $fsreal 2>/dev/null`;
                    if ( "@xfsinfo" ) {
                        push(@XFSARR, "\n$INFOSTR Defragmentation status for file system $fsdev\n");
                        push(@XFSARR, @xfsinfo);
                    }
                }

                if ( $fstype eq "btrfs" ) {
                    my @btrfssup = `btrfs-show-super $fsdev 2>/dev/null`;
                    if ( "@btrfssup" ) {
                        push(@BTRFSARR, "\n$INFOSTR BTRFS file system device $fsdev superblock status\n");
                        push(@BTRFSARR, @btrfssup);
                    }

                    my @btrfssub = `btrfs subvolume list $fsdev 2>/dev/null`;
                    if ( "@btrfssub" ) {
                        push(@BTRFSARR, "\n$INFOSTR BTRFS file system device $fsdev subvolumes\n");
                        push(@BTRFSARR, @btrfssub);
                    }
                }

                if ( $fstype eq "ext4" ) {
                    @ext4defrag = `e4defrag -c $fsdev 2>/dev/null`;
                    if ( "@ext4defrag" ) {
                        push(@EXT4ARR, "\n$INFOSTR Defragmentation status for file system $fsdev\n");
                        push(@EXT4ARR, @ext4defrag);
                    }
                }
            }
            close(MM);
        }
        else {
            print "$ERRSTR Cannot run mount command\n\n";
            push(@CHECKARR, "\n$ERRSTR Cannot run mount command\n");
            $warnings++;
        }
    }

    if ( "@ALLMounted" ) {
        print "$INFOSTR List of mounted file systems\n";
        print @ALLMounted;
    }

    if ( "@PROCARR") {
        print "\n$PASSSTR /proc/PID directories restricted";
        print "@PROCARR\n";
    }

    if ( "@BLKARR") {
        print "\n$INFOSTR EXT file system superblock and blocks group information";
        print "@BLKARR";
    }

    if ( "@DUMPE2FSARR") {
        print "\n$INFOSTR EXT file system dump information";
        print "@DUMPE2FSARR";
    }

    if ( "@EXT4ARR") {
        print "\n$INFOSTR EXT4 file system defragmentation status";
        print "@EXT4ARR";
    }

    if ( "@XFSARR") {
        print "\n$INFOSTR XFS file system status";
        print "@XFSARR";
    }

    if ( "@BTRFSARR") {
        print "\n$INFOSTR BTRFS file system superblock information";
        print "@BTRFSARR";
    }

    my @glustervollist = `gluster volume list 2>/dev/null`;
    if ( "@glustervollist") {
        print "\n$INFOSTR GlusterFS volumes";
        print "@glustervollist";

        my @glustervolinfo = `gluster volume info 2>/dev/null`;
        if ( "@glustervolinfo") {
            print "\n$INFOSTR GlusterFS volume details";
            print "@glustervolinfo";
        }

        my @glustervolstat = `gluster volume status all 2>/dev/null`;
        if ( "@glustervolstat") {
            print "\n$INFOSTR GlusterFS volume status";
            print "@glustervolstat";
        }

        my @glusterpeers = `gluster peer status 2>/dev/null`;
        if ( "@glusterpeers") {
            print "\n$INFOSTR GlusterFS peer status";
            print "@glusterpeers";
        }
    }

    if ( "@RESBLKARR") {
        print "@RESBLKARR\n";
    }

    my @Skipnomnt = (
        '/sys',     '/proc', '/dev/shm', '/media/floppy',
        '/dev/pts', '/media/cdrecorder', "/proc/fs/nfsd",
    );

    my @isencrypted = ();
    my @ENCINFO     = ();

    if ( open( VV, "awk '! /awk/ && ! /^#/ {print}' $FSTAB |" )) {
        print "\n$NOTESTR $FSTAB contents\n";

        while (<VV>) {
            next if ( grep( /^$/, $_ ) );

            print $_;
            chomp($_);

            my @KFSARR = split( /\s+/, $_ );
            if ( $#KFSARR != 5 ) {
                push(@FSTABINFO,
"\n$WARNSTR Line \"$_\" contains extra white-space seperated fields in $FSTAB (should be six)\n");
                push(@CHECKARR,
"\n$WARNSTR Line \"$_\" contains extra white-space seperated fields in $FSTAB (should be six)\n");
               $warnings++;
            }

            next if ( grep( /noauto/, $_ ) );

            if ( grep( /swap/, $_ ) ) {
                $swapdeviceno++;
            }

            if ( grep( /\/boot\/efi/, $_ ) ) {
                if ( !grep( /umask=077/, $_ ) ) {
                    push(@FSTABINFO,
                    "\n$WARNSTR File system \"$KFSARR[1]\" in $FSTAB without umask=077 (to ensure only administrators are able to access the data)\n");
                    push(@CHECKARR,
                    "\n$WARNSTR File system \"$KFSARR[1]\" in $FSTAB without umask=077 (to ensure only administrators are able to access the data)\n");
                }
            }

            if ( ! grep(/tmpfs|proc|vfat|nfs|devpts|sysfs/, $KFSARR[2]) ) {
                @isencrypted = `cryptsetup status $KFSARR[0] 2>/dev/null`;
                if ( "@isencrypted" ) {
                    push(@ENCINFO, "@isencrypted\n");
                }
            }
 
            $ORDMOUNTCNT = sprintf("%d%s", $MOUNTORDER, ordinalize($MOUNTORDER));
            push(@MOUNTORD, "$ORDMOUNTCNT... $KFSARR[1]\n");
            $MOUNTORDER++;

            if ( !grep( /$KFSARR[1]/, @ALLMounted ) ) {
                if ( "$KFSARR[2]" ne "swap" ) {
                    push(@FSTABINFO,
"\n$WARNSTR File system \"$KFSARR[1]\" listed in $FSTAB but not mounted\n");
                    push(@CHECKARR,
"\n$WARNSTR File system \"$KFSARR[1]\" listed in $FSTAB but not mounted\n");
                    $warnings++;
                    $fswarnings++;
                }
            }

             if ( grep( /\bro\b/, $KFSARR[3] ) ) {
                if ( ! grep( /\berrors=remount -ro\b|\berrors=remount-ro\b/, $KFSARR[3] ) ) {
                   push(@FSTABINFO,
"\n$INFOSTR File system \"$KFSARR[1]\" set to be mounted read-only\n");
                }
            }

            if ( ( "$KFSARR[1]" eq "/tmp" ) || ( "$KFSARR[1]" eq "/var/tmp" ) ) {
                if ( grep( /tmpfs/, $KFSARR[2] ) ) {
                    push(@FSTABINFO,
"\n$PASSSTR File system \"$KFSARR[1]\" mounted with \"tmpfs\"\n");
                }
            }

            if ( "$KFSARR[2]" eq "gfs" ) {
                push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" is GFS-type\n");
                my @gfsstat = `gfs_tool stat $KFSARR[1] 2>/dev/null`;
                if (@gfsstat) {
                    push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" stats\n");
                    push(@FSTABINFO, @gfsstat);
                }

                my @gfstoolext = `gfs_tool gettune $KFSARR[1] 2>/dev/null`;
                if (@gfstoolext) {
                    push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" tunables\n");
                    push(@FSTABINFO, @gfstoolext);
                }

                my @gfstoolcnt = `gfs_tool counters $KFSARR[1] 2>/dev/null`;
                if (@gfstoolcnt) {
                    push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" counters\n");
                    push(@FSTABINFO, @gfstoolcnt);
                }
            }
            else {
                if ( "$KFSARR[2]" eq "gfs2" ) {
                    push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" is GFS2-type\n");
                    my @gfsstat2 = `gfs2_tool stat $KFSARR[1] 2>/dev/null`;
                    if (@gfsstat2) {
                        push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" stats\n");
                        push(@FSTABINFO, @gfsstat2);
                    }

                    my @gfstoolext2 = `gfs2_tool gettune $KFSARR[1] 2>/dev/null`;
                    if (@gfstoolext2) {
                        push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" tunables\n");
                        push(@FSTABINFO, @gfstoolext2);
                    }

                    my @gfstoolcnt2 = `gfs2_tool counters $KFSARR[1] 2>/dev/null`;
                    if (@gfstoolcnt2) {
                        push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" counters\n");
                        push(@FSTABINFO, @gfstoolcnt2);
                    }
                }
            }

            if ( "$KFSARR[2]" eq "ocfs" ) {
                push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" is OCFS-type\n");
                my @mocfs = `mounted.ocfs $KFSARR[0] 2>/dev/null`;
                if (@mocfs) {
                    push(@FSTABINFO, @mocfs);
                }
            }

            if ( "$KFSARR[2]" eq "ocfs2" ) {
                push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" is OCFS2-type\n");
                my @mocfs2 = `mounted.ocfs2 $KFSARR[0] 2>/dev/null`;
                if (@mocfs2) {
                    push(@FSTABINFO, @mocfs2);
                }
            }

            if ( grep(/^ext/, "$KFSARR[2]" ) ) {
                if( ! ( $KFSARR[5] =~ /^[0-9]+$/ ) ) {
                    push(@FSTABINFO,
"\n$ERRSTR File system \"$KFSARR[1]\" FSCK pass number $KFSARR[5] is not numeric\n");
                    push(@CHECKARR,
"\n$ERRSTR File system \"$KFSARR[1]\" FSCK pass number $KFSARR[5] is not numeric\n");
                    $warnings++;
                }
                else {
                    if ( "$KFSARR[5]" == 0 ) {
                        push(@FSTABINFO,
"\n$ERRSTR File System \"$KFSARR[1]\" FSCK pass number set to zero\n");
                        push(@CHECKARR,
"\n$ERRSTR File System \"$KFSARR[1]\" FSCK pass number set to zero\n");
                        $warnings++;
                    }
                    else {
                        push(@FSTABINFO,
"\n$PASSSTR File system \"$KFSARR[1]\" FSCK pass number set to non-zero\n");
                    }
                }
            }

            push( @Fstabed, $KFSARR[1] );

            if ( !grep( /\Q$KFSARR[1]\E/, @Skipnomnt ) ) {
                if ( ($KFSARR[2] ne "ext2") && ($KFSARR[2] ne "ext3") && ($KFSARR[2] ne "ext4") ) {
                    push(@FSTABINFO, "\n$INFOSTR File system \"$KFSARR[1]\" not EXT-type ($KFSARR[2])\n");
                    $vxfscount++;
                }
            }
        }
        close(VV);

        if ( "@FSTABINFO" ) {
            print "@FSTABINFO";
        }

        my @gfstool1 = `gfs_tool list 2>/dev/null`;
        my @gfstool2 = `gfs2_tool list 2>/dev/null`;

        if (@gfstool1) {
            print "\n$INFOSTR GFS file system listing\n";
            print @gfstool1;

            my @gfstooldf  = `gfs_tool df 2>/dev/null`;
            if (@gfstooldf) {
                print "\n$INFOSTR GFS file system status\n";
                print @gfstooldf;
            }
        }

        if (@gfstool2) {
            print "\n$INFOSTR GFS2 file system listing\n";
            print @gfstool2;

            my @gfstooldf2  = `gfs2_tool df 2>/dev/null`;
            if (@gfstooldf2) {
                print "\n$INFOSTR GFS2 file system status\n";
                print @gfstooldf2;
            }
        }

        ocfs2chk();
    }
    else {
        print "\n$WARNSTR Cannot open $FSTAB\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $FSTAB\n");
    }

    if ( $swapdeviceno < $Minswapdevno ) {
        print
"\n$INFOSTR Less than recommended number of swap devices (minimum $Minswapdevno)\n";
    }
    else {
        print
"\n$PASSSTR Recommended number of swap devices (minimum $Minswapdevno)\n";
    }

    if ( -s $CRYPTTAB ) {
        if ( open( CRTAB, "awk '! /awk/ && ! /^#/ {print}' $CRYPTTAB |" )) {
            print "\n$INFOSTR $CRYPTTAB contents\n";
            while (<CRTAB>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(CRTAB);
        }
    }

    my @dmsetups = `dmsetup status 2>/dev/null`;
    if ( "@dmsetups" ) {
        print "\n$INFOSTR dmsetup LVM status (including encrypted volumes)\n";
        print "@dmsetups";
    }

    if ( "@ENCINFO" ) {
        print "\n$INFOSTR Cryptsetup status\n";
        print "@ENCINFO";
    }

    foreach $c (@fss) {
        if ( !grep( /^\Q$c\E$/, @Skipnomnt ) ) {
            if ( !grep( /\Q$c\E/, @Fstabed ) ) {
                next if ( grep( /\Qchroot\E|^proc /, $c ) );
                print
"\n$INFOSTR File system $c mounted but not listed in $FSTAB (check if using \"noauto\" option or file system is ZFS)\n";
                push(@CHECKARR,
"\n$INFOSTR File system $c mounted but not listed in $FSTAB (check if using \"noauto\" option or file system is ZFS)\n");
                $warnings++;
                $fswarnings++;
            }
            else {
                print
"\n$PASSSTR File system $c mounted and listed in $FSTAB\n";
            }
        } 
        else {
            print
"\n$INFOSTR File system $c mounted but skipped checking in $FSTAB\n";
        }
    }

    if ( "$fswarnings" == 0 ) {
        print "\n$PASSSTR All file systems mounted correctly\n";
    }

    datecheck();
    print_header("*** END CHECKING ALL FSTAB FILE SYSTEMS MOUNTED AND VALID $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING AUTOMOUNT $datestring ***");

    my $autofsrun = `chkconfig --list autofs 2>/dev/null`;
    chomp($autofsrun);
    my @runlvauto = split(/\s+/, $autofsrun);

    if ( grep(/on/, $runlvauto[$runlevel + 1] ) ) {
        $AUTO_FLAG++;
    }

    if ( $AUTO_FLAG > 0 ) {
        print "$INFOSTR Automount is enabled\n";
    }
    else {
        print "$INFOSTR Automount is disabled\n";
    }

    foreach my $autocm ( @AUTOARR ) {
        if ( "$autocm" eq "/etc/auto.master" ) {
            if ( open( YA, "awk NF $autocm 2>/dev/null | grep -v ^# | " ) ) {
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
                print "$WARNSTR Automount config $autocm not configured\n";
                push(@CHECKARR, "\n$WARNSTR Automount config $autocm not configured\n");
            }
        }
        else {
            if ( -s "$autocm" ) {
                my @autocmarr = `egrep -v ^# $autocm | awk NF`;
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
            my @autocmarr2 = `egrep -v ^# $autocm2 | awk NF`;
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
}

#
# Subroutine to check system auditing
#
sub audsys {
    datecheck();
    print_header("*** BEGIN CHECKING AUDITD SYSTEM AUDITING $datestring ***");

    if ( $AUDIT_FLAG > 0 ) {

        if ( -s $AUDCONF ) {
            if ( open( FROM, "awk NF $AUDCONF 2>/dev/null | grep -v ^# | " ) ) {
                while (<FROM>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(FROM);
            }
            else {
                print "$WARNSTR System auditing config $AUDCONF not configured or missing\n";
                push(@CHECKARR, "\n$WARNSTR System auditing config $AUDCONF not configured or missing\n");
            }

            my @auctl = `auditctl -l 2>/dev/null | awk NF`;
            if ( "@auctl" ) {
                print "\n$INFOSTR Audit rules\n";
                print @auctl;
            }

            my @aurep = `aureport 2>/dev/null | awk NF`;
            if ( "@aurep" ) {
                print "\n$INFOSTR Audit daemon logs\n";
                print @aurep;
            }
        }
        else {
            print "$WARNSTR System auditing seemingly not configured\n";
            push(@CHECKARR, "\n$WARNSTR System auditing seemingly not configured\n");
            $warnings++;
        }
    }
    else {
        print "$WARNSTR System auditing seemingly not running\n";
        push(@CHECKARR, "\n$WARNSTR System auditing seemingly not running\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING AUDITD SYSTEM AUDITING $datestring ***");
}

#
# Is /dev/null a special device?
#
sub checknull {
    datecheck();
    print_header("*** BEGIN CHECKING DEVICE FILES $datestring ***");

    my $DEVDIR = "/dev";
    my @Devarray = `ls $DEVDIR`;

    foreach my $Confdev (@Devarray) {
        chomp($Confdev);
        next if ( -d "$DEVDIR/$Confdev" );
        next if ( -l "$DEVDIR/$Confdev" );
        if ( -c "$DEVDIR/$Confdev" ) {
            print "$PASSSTR $DEVDIR/$Confdev is a character device file\n";
        }
        elsif ( -b "$DEVDIR/$Confdev" ) {
            print "$PASSSTR $DEVDIR/$Confdev is a block device file\n";
        }
        elsif ( -p "$DEVDIR/$Confdev" ) {
            print "$PASSSTR $DEVDIR/$Confdev is a pipe\n";
        }
        elsif ( -S "$DEVDIR/$Confdev" ) {
            print "$PASSSTR $DEVDIR/$Confdev is a socket\n";
        }
        else {
            print "$WARNSTR $DEVDIR/$Confdev is not a special device\n";
            push(@CHECKARR, "\n$WARNSTR $DEVDIR/$Confdev is not a special device\n");
            $warnings++;
        }
    }

    datecheck();
    print_header("*** END CHECKING DEVICE FILES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING DYNAMIC DEVICE MANAGEMENT $datestring ***");

    my @udevv = `udevadm --version 2>/dev/null`;
    if ( @udevv ) {
        print "$INFOSTR Udevadm version string\n";
        print @udevv;
        print "\n";
    }

    if ( -s "$UDEVCONF" ) {
        my @udevarr = `egrep -v ^# $UDEVCONF | awk NF`;
        if ( @udevarr ) {
            print "$INFOSTR Configuration file $UDEVCONF\n";
            print @udevarr;
            print "\n";
        }
        else {
            print "$INFOSTR Configuration file $UDEVCONF empty\n";
            print "\n";
        }
    }
    else {
        print "$INFOSTR Configuration file $UDEVCONF empty or does not exist\n";
        print "\n";
    }

    my @udevls = `find $UDEVDIR -type f 2>/dev/null`;
    foreach my $ucfg (@udevls) {
        chomp($ucfg);
        next if ( -d $ucfg );
        if ( -s $ucfg ) {
            my @usfg = `egrep -v ^# $ucfg | awk NF`;
            if ( "@usfg" ) {
                print "$INFOSTR Configuration file $ucfg\n";
                print @usfg;
                print "\n";
            }
            else {
                print "$INFOSTR Configuration file $ucfg exist but no configuration lines set up\n";
                print "\n";
            }
        }
        else {
            print "$INFOSTR Configuration file $ucfg empty or does not exist\n";
            print "\n";
        }
    }

    datecheck();
    print_header("*** END CHECKING DYNAMIC DEVICE MANAGEMENT $datestring ***");
}

#
# Subroutine to check kernel parameters
#
sub checkkernel {
    datecheck();
    print_header("*** BEGIN CHECKING KERNEL PARAMETERS $datestring ***");

    print "$INFOSTR Sequence of steps required to lock down messages file:

    1 Use \"chattr +a /var/log/messages\" to protect the messages file
    2 Edit /etc/sysctl.conf to include \"kernel.cap-bound = -4195073\"
    3 Use \"chattr +i /etc/sysctl.conf\" to protect the sysctl configuration
       settings
    4 Either reboot the system, or use \"echo 0xFFBFFCFF > /proc/sys/kernel/cap-bound\" to enforce the protections\n\n";

    my $sysctlconf = "/etc/sysctl.conf";
    my @sysctlc = `egrep -v ^# $sysctlconf 2>/dev/null | awk NF`;
    if ("@sysctlc") {
        print "$INFOSTR Kernel configuration file $sysctlconf\n";
        print @sysctlc;
    }
    print "\n";

    my $capbound = "/proc/sys/kernel/cap-bound";
    my $capboundval = `cat $capbound 2>/dev/null`;
    if ("$capboundval") {
        chomp($capboundval);
        if ( "$capboundval" ne "-769" ) {
            print
"$WARNSTR Capability setting in $capbound not safe ($capboundval)\n";
            push(@CHECKARR,
"\n$WARNSTR Capability setting in $capbound not safe ($capboundval)\n");
            $warnings++;
        }
        else {
            print
"$INFOSTR Capability setting in $capbound is safe ($capboundval)\n";
        }
    }

    open( FROM, "sysctl -a 2>/dev/null |" ) || warn "Cannot run sysctl\n";
    print "\n$INFOSTR Kernel parameter status\n";
    while (<FROM>) {
        $_ =~ s/^\s+//g;
        print $_;
        chomp($_);

        if ( grep( /exec-shield-randomize/, $_ ) ) {
            ( undef, $execstackflag ) = split( /=/, $_ );
            $execstackflag =~ s/^\s+//g;
            chomp($execstackflag);
            if ( $execstackflag == 0 ) {
                print "$ERRSTR Kernel parameter exec-shield-randomize set";
                print "to $execstackflag\n";
                print "$INFOSTR Randomized VM mapping is disabled\n";
                push(@CHECKARR, "\n$ERRSTR Kernel parameter exec-shield-randomize set");
                push(@CHECKARR, " to $execstackflag\n");
                $warnings++;
            }
            elsif ( $execstackflag == 1 ) {
                print
                  "$PASSSTR Kernel parameter exec-shield-randomize set";
                print "to $execstackflag\n";
                print "$INFOSTR Randomized VM mapping is enabled\n";
            }
            else {
                print
"$WARNSTR Kernel parameter exec-shield-randomize not set to 1\n";
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter exec-shield-randomize not set to 1\n");
                $warnings++;
            }
        }

        if ( grep( /kernel.dmesg_restrict/, $_ ) ) {
            ( undef, $kerndmesgflag ) = split( /=/, $_ );
            $kerndmesgflag =~ s/^\s+//g;
            chomp($kerndmesgflag);
            if ( $kerndmesgflag == 0 ) {
                push(@SYSCTLARR, "$ERRSTR Kernel parameter kernel.dmesg_restrict set");
                push(@SYSCTLARR, " to $kerndmesgflag (dmesg not restricted to non-root users)\n");
                push(@CHECKARR, "\n$ERRSTR Kernel parameter kernel.dmesg_restrict set");
                push(@CHECKARR, " to $kerndmesgflag\n");
                $warnings++;
            }
            elsif ( $kerndmesgflag == 1 ) {
                push(@SYSCTLARR, "$PASSSTR Kernel parameter kernel.dmesg_restrict set");
                push(@SYSCTLARR, " to $kerndmesgflag dmesg restricted to root users only)\n");
            }
            else {
                push(@SYSCTLARR, "$WARNSTR Kernel parameter kernel.dmesg_restrict not set to 1");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter kernel.dmesg_restrict not set to 1\n");
                $warnings++;
            }
        }

        if ( grep( /vm.swappiness/, $_ ) ) {
            ( undef, $swappiness ) = split( /=/, $_ );
            $swappiness =~ s/^\s+//g;
            chomp($swappiness);
            push(@SYSCTLARR, "$INFOSTR Kernel parameter vm.swappiness set");
            push(@SYSCTLARR, "to $swappiness\n");
            push(@SYSCTLARR, "$INFOSTR If swap is not in use at all, recommended value is 0\n");
        }

        my @FWlistarr = (
            'net.ipv4.conf.default.accept_redirects',
            'net.ipv4.conf.default.secure_redirect',
            'net.ipv4.conf.all.secure_redirects',
            'net.ipv4.conf.all.accept_redirects',
            'net.ipv4.conf.default.accept_redirects',
            'net.ipv4.conf.all.send_redirects',
            'net.ipv4.conf.default.send_redirects',
            'net.ipv4.ip_forward',
            'net.ipv4.conf.default.accept_source_route',
            'net.ipv4.conf.all.accept_source_route',
        );

        my @FWlistopp = (
            'net.ipv4.tcp_syncookies',
            'net.ipv4.icmp_echo_ignore_broadcasts',
            'net.ipv4.conf.all.rp_filter',
            'net.ipv4.conf.default.rp_filter',
            'net.ipv4.conf.all.log_martians',
            'net.ipv4.conf.default.log_martians',
            'net.ipv4.icmp_ignore_bogus_error_responses',
        );

#        print "\n";

        foreach my $kernfw (@FWlistarr) {
            if ( $kernfw eq 'net.ipv4.ip_forward' ) {
                if ( $LVS_FLAG > 0 ) {
                    if ( grep( /$kernfw/, $_ ) ) {
                        ( undef, $execstackflag ) = split( /=/, $_ );
                        $execstackflag =~ s/^\s+//g;
                        chomp($execstackflag);
                        if ( $execstackflag == 1 ) {
                            push(@SYSCTLARR, "$PASSSTR Kernel parameter $kernfw set");
                            push(@SYSCTLARR,
" to $execstackflag (required for Linux Virtual Server)\n");
                        }
                        elsif ( $execstackflag == 0 ) {
                            push(@SYSCTLARR, "$WARNSTR Kernel parameter $kernfw set");
                            push(@SYSCTLARR,
" to $execstackflag (required for Linux Virtual Server\n");
                            push(@CHECKARR, "\n$WARNSTR Kernel parameter $kernfw set");
                            push(@CHECKARR,
" to $execstackflag (required for Linux Virtual Server\n");
                            $warnings++;
                        }
                        else {
                            push(@SYSCTLARR,
"$WARNSTR Kernel parameter $kernfw not defined\n");
                            $warnings++;
                        }
                    }
                }
                else {
                    if ( grep( /$kernfw/, $_ ) ) {
                        ( undef, $execstackflag ) = split( /=/, $_ );
                        $execstackflag =~ s/^\s+//g;
                        chomp($execstackflag);
                        if ( $execstackflag == 1 ) {
                            push(@SYSCTLARR, "$WARNSTR Kernel parameter $kernfw set");
                            push(@SYSCTLARR, " to $execstackflag\n");
                            push(@CHECKARR, "\n$WARNSTR Kernel parameter $kernfw set");
                            push(@CHECKARR, " to $execstackflag\n");
                            $warnings++;
                        }
                        elsif ( $execstackflag == 0 ) {
                            push(@SYSCTLARR, "$PASSSTR Kernel parameter $kernfw set");
                            push(@SYSCTLARR, "to $execstackflag\n");
                        }
                        else {
                            push(@SYSCTLARR,
"$WARNSTR Kernel parameter $kernfw not defined\n");
                            $warnings++;
                        }
                    }
                }
            }
            else {
                if ( grep( /$kernfw/, $_ ) ) {
                    ( undef, $execstackflag ) = split( /=/, $_ );
                    $execstackflag =~ s/^\s+//g;
                    chomp($execstackflag);
                    if ( $execstackflag == 1 ) {
                        push(@SYSCTLARR, "$WARNSTR Kernel parameter $kernfw set");
                        push(@SYSCTLARR, "to $execstackflag\n");
                        push(@CHECKARR, "\n$WARNSTR Kernel parameter $kernfw set");
                        push(@CHECKARR, " to $execstackflag\n");
                        $warnings++;
                    }
                    elsif ( $execstackflag == 0 ) {
                        push(@SYSCTLARR, "$PASSSTR Kernel parameter $kernfw set");
                        push(@SYSCTLARR, "to $execstackflag\n");
                    }
                    else {
                        push(@SYSCTLARR,
                          "$WARNSTR Kernel parameter $kernfw not defined\n");
                        $warnings++;
                    }
                }
            }
        }

        foreach my $kernfw (@FWlistopp) {
            if ( grep( /$kernfw/, $_ ) ) {
                ( undef, $execstackflag ) = split( /=/, $_ );
                $execstackflag =~ s/^\s+//g;
                chomp($execstackflag);
                if ( $execstackflag == 1 ) {
                    push(@SYSCTLARR, "$PASSSTR Kernel parameter $kernfw set");
                    push(@SYSCTLARR, "to $execstackflag\n");
                }
                elsif ( $execstackflag == 0 ) {
                    push(@SYSCTLARR, "$WARNSTR Kernel parameter $kernfw set");
                    push(@SYSCTLARR, "to $execstackflag\n");
                    push(@CHECKARR, "\n$WARNSTR Kernel parameter $kernfw set");
                    push(@CHECKARR, " to $execstackflag\n");
                    $warnings++;
                }
                else {
                    push(@SYSCTLARR, "$WARNSTR Kernel parameter $kernfw not defined\n");
                    $warnings++;
                }
            }
        }

        if ( grep( /exec-shield /, $_ ) ) {
            ( undef, $execstackflag ) = split( /=/, $_ );
            $execstackflag =~ s/^\s+//g;
            chomp($execstackflag);
            if ( $execstackflag == 0 ) {
                push(@SYSCTLARR, "$ERRSTR Kernel parameter exec-shield set");
                push(@SYSCTLARR, "to $execstackflag (recommended to set to 1)\n");
                push(@CHECKARR, "\n$ERRSTR Kernel parameter exec-shield set");
                push(@CHECKARR, " to $execstackflag\n");
                $warnings++;
            }
            elsif ( $execstackflag == 1 ) {
                push(@SYSCTLARR, "$PASSSTR Kernel parameter exec-shield set");
                push(@SYSCTLARR, "to $execstackflag\n");
            }
            else {
                push(@SYSCTLARR, "$PASSSTR Kernel parameter exec-shield set to");
                push(@SYSCTLARR, "$execstackflag\n");
            }
        }

        if ( grep( /net.ipv4.tcp_max_syn_backlog/, $_ ) ) {
            ( undef, $execstackflag ) = split( /=/, $_ );
            $execstackflag =~ s/^\s+//g;
            chomp($execstackflag);
            if ( $execstackflag < 4096 ) {
                push(@SYSCTLARR,
"$ERRSTR Kernel parameter net.ipv4.tcp_max_syn_backlog set to $execstackflag (recommended to increase above 4096)\n");
                push(@CHECKARR,
"\n$ERRSTR Kernel parameter net.ipv4.tcp_max_syn_backlog set to $execstackflag\n");
                $warnings++;
            }
            elsif ( $execstackflag >= 4096 ) {
                push(@SYSCTLARR,
"$PASSSTR Kernel parameter net.ipv4.tcp_max_syn_backlog set");
                push(@SYSCTLARR, "to $execstackflag\n");
            }
            else {
                push(@SYSCTLARR,
"$WARNSTR Kernel parameter net.ipv4.tcp_max_syn_backlog not defined\n");
            }
        }
    }
    close(FROM);

    if ( "@SYSCTLARR" ) {
        print "\n";
        print "@SYSCTLARR\n";
    }

    datecheck();
    print_header("*** END CHECKING KERNEL PARAMETERS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING KERNEL BOOT ARGUMENTS $datestring ***");

    my @bootkern = `cat $cmdline 2>/dev/null`;

    if ( "@bootkern" ) {
        print @bootkern;
    }
    else {
        print "$WARNSTR $cmdline corrupt or missing\n";
    }

    datecheck();
    print_header("*** END CHECKING KERNEL BOOT ARGUMENTS $datestring ***");

    datecheck();
    print_header("*** BEGIN BOOT TIMINGS $datestring ***");

    my @sysana = `systemd-analyze 2>/dev/null`;
    if ( "@sysana" ) {

        print "$INFOSTR Boot timings with systemd-analyze\n";
        print @sysana;

        my @sysanb = `systemd-analyze blame 2>/dev/null`;
        if ( "@sysanb" ) {
            print "\n$INFOSTR Services affecting boot timings\n";
            print @sysanb;
        }
        print "\n";
    }

    my @bchartc = `awk NF $BOOTCHARTCONF 2>/dev/null`;
    if ( "@bchartc" ) {
        print "$INFOSTR Boot timing configuration with bootchart\n";
        print "$NOTESTR Boot timing results are in /var/log/bootchart directory\n";
        print @bchartc;
    }

    datecheck();
    print_header("*** END BOOT TIMINGS $datestring ***");

    my @SORTKERNEL = `rpm -qa kernel\* |sort -V 2>/dev/null`;
    if ( @SORTKERNEL ) {
        datecheck();
        print_header("*** BEGIN CHECKING INSTALLED KERNEL VERSIONS $datestring ***");
  
        print @SORTKERNEL;

        datecheck();
        print_header("*** END CHECKING INSTALLED KERNEL VERSIONS $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING KERNEL MODULES $datestring ***");

    my $RELVER = `uname -r 2>/dev/null`;
    chomp($RELVER);
    my $MODDEP = "/lib/modules/${RELVER}/modules.dep";
    if ( ! -s "$MODDEP" ) {
        print "$WARNSTR Listing of module dependencies in $MODDEP does not exist or the file has been removed\n";
        print "$NOTESTR It is suggested to run \"depmod -a\" or use  method to restore contents of the file\n";
    }
    else {
        my @catdep = `cat $MODDEP 2>/dev/null`;
        if ( @catdep ) {
            print "$PASSSTR File $MODDEP not empty\n";
            print "\n$INFOSTR Listing of module dependencies in $MODDEP\n";
            print "@catdep\n";
        }
    }

    if ( open( LSMOD, "lsmod |" ) ) {
        while (<LSMOD>) {
            print $_;

            next if ( grep( /Used by/, $_ ) );

            if ( grep( /Tainted:/, $_ ) ) {
                push(@TAINTARR, $_);
            }

            $_ =~ s/^\s+//g;

            ( $Modname , undef ) = split( /\s+/, $_ );
            chomp($Modname);
            if ( ! grep(/$Modname/, @MODARR)) {
                push(@MODARR, $Modname);
            }
        }
    }
    else {
        print "$WARNSTR Kernel modules cannot be listed\n";
        push(@CHECKARR, "\n$WARNSTR Kernel modules cannot be listed\n");
    }

    my $moddir = "/lib/modules";
    my @moduledir = `ls $moddir 2>/dev/null`;
    if ( "@moduledir" ) {
        print "\n$INFOSTR Available modules trees in $moddir\n";
        print @moduledir;
    }

    datecheck();
    print_header("*** END CHECKING KERNEL MODULES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING IF KERNEL TAINTED $datestring ***");

    my $istainted = `cat $proctaint 2>/dev/null`;

    if ( "$istainted" == 0 ) {
        print "$INFOSTR Kernel not tainted (no modules with Proprietary license have been loaded)\n";
    }
    elsif ( "$istainted" == 1 ) {
        print "$WARNSTR Kernel tainted (modules with Proprietary license have been loaded)\n";
        push(@CHECKARR, "\n$WARNSTR Kernel tainted (modules with Proprietary license have been loaded)\n");

        if ( "@TAINTARR" ) {
            print "\n$WARNSTR Modules with Proprietary license\n";
            print @TAINTARR;
            push(@CHECKARR, "\n$WARNSTR Modules with Proprietary license\n");
            push(@CHECKARR, @TAINTARR);
        }

        foreach my $modls ( @MODARR ) {
            my $licval  = q{};
            my $licname = q{};
            if ( open( TAINT, "modinfo $modls 2>/dev/null |" ) ) {
                while (<TAINT>) {
                    if ( grep( /^filename:/, $_ ) ) {
                        ( undef, $licname ) = split( /:/, $_ );
                        chomp($licname);
                        $licname =~ s/^\s+//g;
                        $licname =~ s/\s+$//g;
                    }

                    if ( grep( /^license:/, $_ ) ) {
                        ( undef, $licval ) = split( /:/, $_ );
                        chomp($licval);
                        $licval =~ s/^\s+//g;
                        $licval =~ s/\s+$//g;
                    }
                }
                close(TAINT);
                if ( ( "$licval" ) && ( "$licval" ne "GPL" ) ) {
                    print
"\n$WARNSTR Module $modls with Proprietary license $licval\n";
                    push(@CHECKARR, "\n$WARNSTR Module $modls with Proprietary license $licval\n");
                    $warnings++;
                }
            }
        }
    }
    else {
        print "$WARNSTR $proctaint corrupt or missing\n";
    }

    datecheck();
    print_header("*** END CHECKING IF KERNEL TAINTED $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING BUFFER PAGES ALLOCATION $datestring ***");

    my @BUFFS = `free`;
    print @BUFFS;

    datecheck();
    print_header("*** END CHECKING BUFFER PAGES ALLOCATION $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING GETCONF $datestring ***");

    my @getconf = `getconf -a 2>/dev/null`;
    if ( @getconf != 0 ) {
        print @getconf;
    }

    datecheck();
    print_header("*** END CHECKING GETCONF $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING MODULES CONFIGURATION $datestring ***");

    my @kcusage = `modprobe -c 2>/dev/null`;
    if ( @kcusage != 0 ) {
        print @kcusage;
    }

    my @kcconf = `awk NF /etc/modprobe.conf 2>/dev/null`;
    if ( @kcconf != 0 ) {
        print "\n$INFOSTR Configuration file /etc/modprobe.conf\n";
        print @kcconf;
    }

    my @moddir = `ls /etc/modprobe.d/*.conf 2>/dev/null`;
    foreach my $mmod ( @moddir ) {
        my @msysarr = `awk NF $mmod`;
        if ( @msysarr ) {
            print "\n$INFOSTR Modprobe configuration file $mmod\n";
            print @msysarr;
            print "\n";
        }
    }

    datecheck();
    print_header("*** END CHECKING MODULES CONFIGURATION $datestring ***");
}

#
# Subroutine to check various daemons
#
sub basic_daemons {
    datecheck();
    print_header("*** BEGIN CHECKING CRITICAL DAEMONS $datestring ***");

#   my @Dmust = ( "sshd", "syslogd", "rsyslogd", "crond", );
    my @Dmust = ( "sshd", "syslogd", "rsyslogd", );

    if ( grep( /VxVM/, "$Diskmgr" ) ) {
        push( @Dmust, "vxconfigd", "vxfsd", "vxiod", "vxnotify", );
    }

    my @Nott = (
        "automount", "routed", "gated",
        "xinetd",    "dtlogin", "ypserv", "ypbind",
        "dtrc",      "xfs",     "xinit",  "scrdaemon",
    );

    foreach my $x (@Nott) {
        my $ckd = grep( /\b$x\b/i, @allprocesses );
        if ("$ckd") {
            print "$WARNSTR Daemon $x running (recommendation is to ";
            print "disable it)\n";
            push(@CHECKARR, "\n$WARNSTR Daemon $x running (recommendation is to ");
            push(@CHECKARR, "disable it)\n");
            $warnings++;
        }
        else {
            print "$PASSSTR Daemon $x not running\n";
        }
    }

    my $sysval = q{};

    foreach $a (@Dmust) {
        my @cky = grep( /\b$a\b/, @allprocesses );
        if ( @cky != 0 ) {
            if ( "$a" eq "syslogd" ) {
                if ( open( FROM, "egrep -v ^# $ssd 2>/dev/null |" ) ) {
                    $SYSLOGD_FLAG++;
                    while (<FROM>) {
                        chomp;
                        next if ( grep( /^$/, $_ ) );
                        if ( grep( /SYSLOGD_OPTIONS/, $_ ) ) {
                            ( undef, $sysval ) = split( /=/, $_ );
                            $sysval =~ s/"//g;
                            if ( grep( /-r/, $sysval ) ) {
                                print
"$WARNSTR Daemon flags for $a not set up ";
                                print "correctly in $ssd (flag -r enabled)\n";
                                push(@CHECKARR,
"\n$WARNSTR Daemon flags for $a not set up ");
                                push(@CHECKARR, "correctly in $ssd (flag \"-r\" enabled)\n");
                                $warnings++;
                            }
                            else {
                                print
                                  "$PASSSTR Daemon flags for $a set up ";
                                print
                                  "correctly in $ssd (flag -r disabled)\n";
                                $Secure_SYSLOGD = 1;
                            }
                        }
                    }
                    close(FROM);
                }
                else {
                    print "$WARNSTR Configuration file missing ($ssd)\n";
                    push(@CHECKARR, "\n$WARNSTR Configuration file missing ($ssd)\n");
                }

                if ( grep( /\-r/, @cky ) ) {
                    print "$WARNSTR Daemon $a not running without socket ";
                    print "(flag -r missing)\n";
                    push(@CHECKARR, "\n$WARNSTR Daemon $a not running without socket ");
                    push(@CHECKARR, "(flag \"-r\" missing)\n");
                    $warnings++;
                }
                else {
                    print "$PASSSTR Daemon $a running without socket ";
                    print "(flag -r)\n";
                }
            }

            if ( "$a" eq "rsyslogd" ) {
                if ( open( FROM, "egrep -v ^# $rssd 2>/dev/null |" ) ) {
                    $SYSLOGD_FLAG++;
                    while (<FROM>) {
                        chomp;
                    }
                    close(FROM);
                }
                else {
                    print "$WARNSTR Configuration file missing ($rssd)\n";
                    push(@CHECKARR, "\n$WARNSTR Configuration file missing ($rssd)\n");
                }
            }

            if ( "$a" eq "xinetd" ) {
                if (
                    open( FROM, "awk '! /^#/ && ! /awk/ {print}' $INETD |" ) )
                {
                    print "\n$INFOSTR Configuration file $INETD";
                    while (<FROM>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                    }
                    close(FROM);
                }
                else {
                    print "\n$INFOSTR Cannot open $INETD\n";
                }
            }
        }
        else {
            if ( ! ( ( "$a" eq "rsyslogd" ) || ( "$a" eq "syslogd" ) ) ) {
                print "$WARNSTR Daemon $a not running\n";
                push(@CHECKARR, "\n$WARNSTR Daemon $a not running\n");
                $warnings++;
            }
        }
    }

    if ( $SYSLOGD_FLAG < 2 ) {
        print "$WARNSTR Daemon syslogd/rsyslogd not running\n";
        push(@CHECKARR, "\n$WARNSTR Daemon syslogd/rsyslogd not running\n");
        $warnings++;
    }
    else {
        print "$PASSSTR Daemon syslogd/rsyslogd running\n";
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

    my @CXarray = (
        '/etc/cron.d',     '/etc/cron.hourly',
        '/etc/cron.daily', '/etc/cron.weekly',
        '/etc/cron.monthly',
    );

    foreach my $RXdir (@CXarray) {
        if ( -d "$RXdir" ) {
            chomp($RXdir);
            my @RXlist = `ls -1 $RXdir`;
            if ( "@RXlist" ) {
                print "$INFOSTR $RXdir listing\n";
                print @RXlist;

                foreach my $posao (@RXlist) {
                    chomp($posao);
                    my @possee = `cat $RXdir/$posao`;
                    if ( "@possee" ) {
                        print "\n$INFOSTR $RXdir/$posao listing\n";
                        print @possee;
                    }
                }
            }
            else {
                print "$INFOSTR $RXdir empty\n";
            }
        }
        else {
            print "$WARNSTR Directory $RXdir does not exist\n";
            push(@CHECKARR, "\n$WARNSTR Directory $RXdir does not exist\n");
            $warnings++;
        }
        print "\n";
    }

    if ( -s $CRFILE ) {
        @CRarr = `awk NF $CRFILE 2>/dev/null | egrep -v ^#`;
        if ( @CRarr != 0 ) {
            print "$PASSSTR Crontab $CRFILE exists\n";
            print @CRarr;
        }
    }

    if ( -s $CRFILE2 ) {
        my @CRarr2 = `awk NF $CRFILE2 2>/dev/null | egrep -v ^#`;
        if ( @CRarr2 != 0 ) {
            print "$PASSSTR Crontab $CRFILE2 exists\n";
            print @CRarr2;
        }
    }

    datecheck();
    print_header("*** END CHECKING ROOT CRON TASKS $datestring ***");
}

#
# Subroutine to check cron ACLs
#
sub cron_access {
    datecheck();
    print_header("*** BEGIN CHECKING CRON ACCESS LIST $datestring ***");

    foreach my $croncm ( @CRONARR ) {
        if ( -s "$croncm" ) {
            my @croncmarr = `egrep -v ^# $croncm`;
            if ( @croncmarr ) {
                print "\n$INFOSTR Configuration file $croncm\n";
                print @croncmarr;
            }
        }
        else {
            print "\n$WARNSTR Configuration file $croncm empty or does not exist\n";
            push(@CHECKARR, "\n$ERRSTR Configuration file $croncm empty or does not exist\n");
            $warnings++;
        }
    }

    datecheck();
    print_header("*** END CHECKING CRON ACCESS LIST $datestring ***");
}

#
# Subroutine to check syslogging
#
sub DMESG_IN_CRON {
    datecheck();
    print_header("*** BEGIN CHECKING DMESG LOGGING TO MESSAGES IN CRON $datestring ***");

    print "$INFOSTR Crontab entry should be \"10 * * * * /usr/sbin/dmesg ";
    print "- >> $MSGFILE\"\n";
    my $zz = `awk '! /^#/ && ! /awk/ && /dmesg/ && /messages/ {print}' $CRFILE 2>/dev/null`;
    if ("$zz") {
        print "$PASSSTR Crontab entry for dmesg to write to $MSGFILE\n";
    }

    datecheck();
    print_header("*** END CHECKING DMESG LOGGING TO MESSAGES IN CRON $datestring ***");
}

#
# Subroutine to check ioscan
#
sub IOSCAN_NO_HW {
    datecheck();
    print_header("*** BEGIN CHECKING DEVICES $datestring ***");

    if ( open( IS, "lsdev |" ) ) {
        print "$INFOSTR Lsdev report\n";
        while (<IS>) {
            print $_;
        }
        close(IS);
    }
    else {
        print "$INFOSTR Cannot run lsdev\n";
    }

    if ( open( IS, "lshal 2>&1 |" ) ) {
        print "\n$INFOSTR Lshal report\n";
        while (<IS>) {
            print $_;
        }
        close(IS);
    }
    else {
        print "\n$INFOSTR Cannot run lshal\n";
    }

    # Warning: lshw can generate "*** stack smashing detected *** errors
    # If so, disable this test or recompile the code yourself
    #
    if ( open( IS, "lshw -short |" ) ) {
        print "\n$INFOSTR Lshw report\n";
        while (<IS>) {
            print $_;
        }
        close(IS);
    }
    else {
        print "\n$INFOSTR Cannot run lshw\n";
    }

    my @systool = `systool 2>/dev/null`;
    if ( @systool != 0 ) {
        print "\n$INFOSTR System device information by bus, class, and topology\n";
        print @systool;
    }

    my @BIOSDEC = `biosdecode 2>/dev/null`;
    if ( @BIOSDEC != 0 ) {
        print "\n$INFOSTR BIOS information decoder status\n";
        print @BIOSDEC;
    }

    my @proclist = `procinfo -a 2>/dev/null`;
    if ( @proclist != 0 ) {
        print "\n$INFOSTR System status gathered from /proc\n";
        print @proclist;
    }

    my @lspci = `lspci 2>/dev/null`;
    if ( @lspci != 0 ) {
        print "\n$INFOSTR Listing of PCI devices\n";
        print @lspci;
    }

    my @lsusb = `lsusb 2>/dev/null`;
    if ( @lsusb != 0 ) {
        print "\n$INFOSTR Listing of USB devices\n";
        print @lsusb;
    }

    my @lsscsi = `lsscsi -l -v 2>/dev/null | egrep -vi "not found"`;
    if ( @lsscsi != 0 ) {
        print "\n$INFOSTR Listing of SCSI devices\n";
        print @lsscsi;
    }

    my @iscsiadm = `iscsiadm -m session 2>/dev/null`;
    if ( @iscsiadm != 0 ) {
        print "\n$INFOSTR Listing of iSCSI active sessions\n";
        print @iscsiadm;
    }

    my @wodim = `wodim -scanbus 2>/dev/null`;
    if ( @wodim != 0 ) {
        print "\n$INFOSTR Listing of optical devices\n";
        print @wodim;
    }

    my @tree = `tree /dev/disk 2>/dev/null`;
    if ( @tree != 0 ) {
        print "\n$INFOSTR Enumerated disks under /dev/disk\n";
        print @tree;
    }

    if ( $DIST eq "SuSE" ) {
        my @hwinfo = `hwinfo`;
        if ( @hwinfo != 0 ) {
            print "\n$INFOSTR $DIST-based hardware status\n";
            print @hwinfo;
        }
    }

    datecheck();
    print_header("*** END CHECKING DEVICES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING DEVICE-MAPPER MULTIPATHING $datestring ***");

    my @MPATHCAT = `awk NF $MPATHCFG 2>/dev/null`;
    if ( @MPATHCAT != 0 ) {
        print "$INFOSTR Multipathing configuration file $MPATHCFG\n";
        print "@MPATHCAT\n";
    }

    my @mpathinfo = `multipath -ll -v 3 2>/dev/null`;
    if ( @mpathinfo != 0 ) {
        print "$INFOSTR Current multipath configuration\n";
        print @mpathinfo;

        my @MPATHK = `echo "show paths" | multipathd -k 2>/dev/null`;
        if ( @MPATHK != 0 ) {
            print "\n$INFOSTR Multipathing path checker\n";
            print @MPATHK;
        }

        my @dmsetup = `dmsetup ls --target=multipath 2>/dev/null`;
        if ( @dmsetup != 0 ) {
            print "\n$INFOSTR Multipath device assignment\n";
            print @dmsetup;
        }
        else {
            print "$INFOSTR Multipathing not actively used\n";
        }
    }
    else {
        print "$INFOSTR Multipathing not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING DEVICE-MAPPER MULTIPATHING $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING DMI DECODE $datestring ***");

    if ( open( DMI, "dmidecode |" ) ) {
        while (<DMI>) {
            print $_;
            if ( grep(/Central Processor/, $_ ) ) {
                $cpucount++;
            }
        }
        close(DMI);
    }
    else {
        print "$ERRSTR Cannot run dmidecode\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run dmidecode\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING DMI DECODE $datestring ***");
}

#
# Subroutine to check LVM setup
#
sub LVM_PARAM_CHECK {
    datecheck();
    print_header("*** BEGIN CHECKING PHYSICAL, LOGICAL, AND VOLUME AVAILABILITY $datestring ***");

    if ( -s "$PVGconf" ) {
        my @PVGlist = `awk NF $PVGconf`;
        if ( @PVGlist != 0 ) {
            print "$INFOSTR LVM configured\n";
            print @PVGlist;
        }
    }

    my @lvscanv = `lvscan --version 2>/dev/null`;
    if ( @lvscanv != 0 ) {
        print "\n";
        print @lvscanv;
    }

    my @VGCK = `vgck 2>/dev/null`;
    if ( @VGCK != 0 ) {
        print "\n$WARNSTR LVM volume group metadata check\n";
        push(@CHECKARR, "\n$WARNSTR LVM volume group metadata check\n");
        push(@CHECKARR, @VGCK);
    }
    else {
        print "\n$PASSSTR LVM volume group metadata check successful\n";
    }

    my @LVMDUMP = `lvm dumpconfig 2>/dev/null`;
    if ( @LVMDUMP != 0 ) {
        print "\n$INFOSTR LVM dumpconfig\n";
        print @LVMDUMP;
    }

    if ( $lvcheck ) {
        print "\n$INFOSTR LVM volume group status\n";
        print $lvcheck;
    }

    my @VGSCAN = `vgscan | egrep -v "Finding|Found|Reading"`;
    if ( @VGSCAN != 0 ) {
        print "\n$INFOSTR LVM volume group scan\n";
        print @VGSCAN;
    }

    my @PVSCAN = `pvscan 2>/dev/null`;
    if ( @PVSCAN != 0 ) {
        print "\n$INFOSTR LVM physical volume status\n";
        print @PVSCAN;
    }

    my @LVSCANALL = `lvs -o+seg_all 2>/dev/null`;
    if ( @LVSCANALL != 0 ) {
        print "\n$INFOSTR LVM logical volume status\n";
        print @LVSCANALL;
    }
    else {
        my @LVSCANALL = `lvs 2>/dev/null`;
        print "\n$INFOSTR LVM logical volume status\n";
        print @LVSCANALL;
    }

    my @LVMDSCAN = `lvmdiskscan 2>/dev/null`;
    if ( @LVMDSCAN != 0 ) {
        print "\n$INFOSTR LVM disk scan\n";
        print @LVMDSCAN;
    }

    if ( open( NN, "vgdisplay -vv --partial 2>/dev/null |" ) ) {
        print "\n$INFOSTR Volume group scan\n";
        while (<NN>) {
            print $_;
            chomp;
            if ( grep( /VG Name/, $_ ) ) {
                $_ =~ s/^\s+//g;
                ( undef, undef, $vgname ) = split( /\s+/, $_ );
                chomp($vgname);
                if ( ! grep(/\Q$vgname\E/, @MYVGS ) ) {
                    push(@MYVGS, $vgname);
                }
                undef $VGfpe{$vgname};
                undef $VGpes{$vgname};
            }

            if ( grep( /Format/, $_ ) ) {
                $_ =~ s/^\s+//g;
                ( undef, $vgformat ) = split( /\s+/, $_ );
                chomp($vgformat);
            }

            if ( grep( /Max PV/, $_ ) ) {
                $_ =~ s/^\s+//g;
                ( undef, undef, $maxpv ) = split( /\s+/, $_ );
                chomp($maxpv);
                $MAXPV{$vgname} = $maxpv;
                if ( $vgformat eq "lvm2" ) {
                    if ( $maxpv == 0 ) {
                        print
"$PASSSTR Max PV not limited for lvm2 volume group $vgname\n";
                    }
                }
                else {
                    if ( $maxpv < $THRESHOLD_MAX_PV ) {
                        print
                          "$WARNSTR Max PV ($maxpv) below the threshold ";
                        print
                          "($THRESHOLD_MAX_PV) for volume group $vgname\n";
                        push(@CHECKARR,
                          "\n$WARNSTR Max PV ($maxpv) below the threshold ");
                        push(@CHECKARR,
                          "($THRESHOLD_MAX_PV) for volume group $vgname\n");
                        $warnings++;
                    }
                    else {
                        print
"$PASSSTR Max PV ($maxpv) satisfies the threshold ";
                        print
"(minimum $THRESHOLD_MAX_PV) for volume group $vgname\n";
                    }
                }
            }

            if ( grep( /Cur PV/, $_ ) ) {
                $_ =~ s/^\s+//g;
                ( undef, undef, $curpv ) = split( /\s+/, $_ );
                chomp($curpv);

                if ( $vgformat ne "lvm2" ) {
                    my $pvthresh = int( $curpv / $maxpv ) * 100;
                    if ( $curpv == $maxpv ) {
                        print
"$ERRSTR Current PV ($curpv) reached Max PV threshold ";
                        print "in volume group $vgname\n";
                        push(@CHECKARR,
"\n$ERRSTR Current PV ($curpv) reached Max PV threshold ");
                        push(@CHECKARR, "in volume group $vgname\n");
                        $warnings++;
                    }
                    elsif ( $pvthresh == $THRESHOLD ) {
                        print
"$WARNSTR Current PV ($curpv) reached 90% of Max PV ";
                        print "($maxpv) in volume group $vgname\n";
                        push(@CHECKARR,
"\n$WARNSTR Current PV ($curpv) reached 90% of Max PV ");
                        push(@CHECKARR, "($maxpv) in volume group $vgname\n");
                        $warnings++;
                    }
                    elsif ( $pvthresh > $THRESHOLD ) {
                        print
"$WARNSTR Current PV ($curpv) exceeds 90% of Max PV ";
                        print "($maxpv) in volume group $vgname\n";
                        push(@CHECKARR,
"\n$WARNSTR Current PV ($curpv) exceeds 90% of Max PV ");
                        push(@CHECKARR, "($maxpv) in volume group $vgname\n");
                        $warnings++;
                    }
                    else {
                        print
"$PASSSTR Current PV ($curpv) below 90% of Max PV ";
                        print "($maxpv) in volume group $vgname\n";
                    }
                }
            }

            if ( grep( /VG Status/, $_ ) ) {
                $_ =~ s/^\s+//g;
                ( undef, undef, my $vgstat ) = split( /\s+/, $_ );
                chomp($vgstat);
                if ( $vgstat eq "resizable" ) {
                    print "$PASSSTR Volume group $vgname is resizable\n";
                }
                else {
                    print "$WARNSTR Volume group is not resizable\n";
                    push(@CHECKARR, "\n$WARNSTR Volume group is not resizable\n");
                    $warnings++;
                }
            }

            if ( grep( /^Free  PE/, $_ ) ) {
                $_ =~ s/^\s+//g;
                ( undef, undef, my $freepe2 ) = split( /\//, $_ );
                $freepe2 =~ s/^\s+//g;
                $freepe2 =~ s/\s+$//g;
                ( undef, my $freepe ) = split( /\s+/, $_ );
                chomp($freepe);
                if ( $freepe == 0 ) {
                    print
"$ERRSTR No free PEs available in volume group $vgname\n";
                    push(@CHECKARR,
"\n$ERRSTR No free PEs available in volume group $vgname\n");
                    $warnings++;
                }
                else {
                    print
"$PASSSTR $freepe free PEs available in volume group $vgname\n";
                    $warnings++;
                }
                $VGfpe{$vgname} = $freepe;
            }

            if ( grep( /^PE Size/, $_ ) ) {
                $_ =~ s/^\s+//g;
                ( undef, undef, $pesize, undef ) = split( /\s+/, $_ );
                chomp($pesize);
                $VGpes{$vgname} = $pesize;
            }

            if ( grep( /PV Name/, $_ ) ) {
                $_ =~ s/^\s+//g;
                ( undef, undef, $pvdisk ) = split( /\s+/, $_ );
                if ( !grep( /\Q$pvdisk\E/, @pvlist ) ) {
                    push( @pvlist, $pvdisk );
                }
            }

            if ( grep( /LV Name/, $_ ) ) {
                $_ =~ s/^\s+//g;
                push( @LVarr, "$_\n" );
                ( undef, undef, $lvdisk ) = split( /\s+/, $_ );
                push( @lvlist, $lvdisk );
            }

            if ( grep( /LV Status/, $_ ) ) {
                $_ =~ s/^\s+//g;
                push( @LVarr, "$_\n" );
            }

            if ( grep( /LV Size/, $_ ) ) {
                $_ =~ s/^\s+//g;
                push( @LVarr, "$_\n" );
            }

            if ( grep( /Current LE/, $_ ) ) {
                $_ =~ s/^\s+//g;
                push( @LVarr, "$_\n" );
            }

            if ( grep( /Allocated PE/, $_ ) ) {
                $_ =~ s/^\s+//g;
                push( @LVarr, "$_\n" );
            }

            if ( grep( /Used PV/, $_ ) ) {
                $_ =~ s/^\s+//g;
                push( @LVarr, "$_\n" );
            }
        }
        close(NN);

        foreach my $vgnn ( @MYVGS ) {
            my @vgcfgr = `vgcfgrestore -l $vgnn 2>/dev/null`;
            if ( "@vgcfgr" ) {
                print "\n$INFOSTR vgcfgrestore status for volume group $vgnn\n";
                print @vgcfgr;
            }
            else {
                print "\n$WARNSTR Unknown vgcfgrestore status for volume group $vgnn\n";
            }
        }
    }
    else {
        print "$WARNSTR Cannot run vgdisplay\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run vgdisplay\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING PHYSICAL, LOGICAL, AND VOLUME AVAILABILITY $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING PHYSICAL VOLUMES $datestring ***");

    if ( $DIST eq 'RedHat' ) {
        my @blkid = `blkid 2>/dev/null`;
        if ( "@blkid" ) {
            print "$INFOSTR Disk partition labels\n";
            print @blkid;
            print "\n";
        }
    }

    my @lsblk = `lsblk -f 2>/dev/null`;
    if ( "@lsblk" ) {
        print "\n$INFOSTR File systems and raids\n";
        print @lsblk;
    }

    my @lsblkdet = `lsblk -t 2>/dev/null`;
    if ( "@lsblkdet" ) {
        print "\n$INFOSTR Block devices\n";
        print @lsblkdet;
    }

    my $DISKTYPE = q{};
    my $DISCARD = q{};
    my @PVCKARR = ();

    if ( open( LSBK, "lsblk -io KNAME,TYPE,SCHED,ROTA,DISC-GRAN,DISC-MAX |" ) ) {
        print "\n$INFOSTR I/O elevator (scheduler) and discard support summary\n";
        while (<LSBK>) {
            next if ( grep( /^$/, $_ ) );
            chomp($_);
            my @LSLN = split( /\s+/, $_ );
            my $DTYPE = $LSLN[1];
            if ( "$DTYPE" eq "disk" ) {
                my $DISCMAX = $LSLN[$#LSLN];
                my $DISCGRAN = $LSLN[$#LSLN - 1];
                my $ROTATION = $LSLN[$#LSLN - 2];
                my $DNAME = $LSLN[0];
                my $DNAMECNF = "/sys/block/${DNAME}/queue/scheduler";
                my $SCHED = $LSLN[$#LSLN - 3];
                my $SCHED2 = q{};

                if ( "$ROTATION" == 0 ) {
                    $DISKTYPE = "SSD";
                }
                else {
                    $DISKTYPE = "Hard Disk";
                }

                if ( ("$DISCMAX" > 0) && ("$DISCGRAN" > 0) ) {
                    $DISCARD = "supports discard operation";
                }
                else {
                    $DISCARD = q{};
                }

               if ( "$SCHED" eq "disk" ) {
                   $SCHED = "UNDEFINED";
                   $SCHED2 = `cat $DNAMECNF 2>/dev/null`;
                   chomp($SCHED2);
               }

               print "$INFOSTR $DISKTYPE $DNAME configured with I/O scheduler \"$SCHED\" $DISCARD\n";
               if ( "$SCHED2" ) {
                   print "INFO: $DNAMECNF contents: \"$SCHED2\"\n";
               }
            }
        }
        close(LSBK);
    }

    foreach $a (@pvlist) {
        print "\n";
        if ( open( VTB, "pvdisplay $a |" ) ) {
            while (<VTB>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /Physical volume/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;
                if ( grep( /Free PE/, $_ ) ) {
                    undef $LZVALUE;
                    ( undef, undef, my $LZVALUE ) = split( /\s+/, $_ );
                    chomp($LZVALUE);
                    $LZVALUE =~ s/^\s+//g;
                    $LZVALUE =~ s/\s+$//g;
                    if ( $LZVALUE == 0 ) {
                        push(@PVARRAY,
"\n$WARNSTR PV $a has no PEs available ($LZVALUE)\n");
                        push(@CHECKARR,
"\n$WARNSTR PV $a has no PEs available ($LZVALUE)\n");
                        $warnings++;
                    }
                    else {
                        push(@PVARRAY, "\n$PASSSTR PV $a has free PEs ($LZVALUE)\n");
                    }
                }

                if ( grep( /Alternate Link/, $_ ) ) {
                    ( undef, undef, $ALTLINK, undef, undef ) =
                      split( /\s+/, $_ );
                    chomp($ALTLINK);
                    if ("$ALTLINK") {
                        push(@PVARRAY,
                          "\n$PASSSTR PV $a has alternate link $ALTLINK\n");
                    }
                    else {
                        push(@PVARRAY,
                          "\n$INFOSTR PV $a does not have alternate link\n");
                        $warnings++;
                    }
                }
            }
            close(VTB);
        }
        else {
            print
"\n$WARNSTR PV $a seems not initialised in LVM or unavailable\n";
            push(@CHECKARR,
"\n$WARNSTR PV $a seems not initialised in LVM or unavailable\n");
            $warnings++;
        }
    
        my @PVCK = `pvck -v $a 2>/dev/null`;
        if ( @PVCK != 0 ) {
            push(@PVCKARR, "\n$INFOSTR PV $a metadata check\n");
            push(@PVCKARR, @PVCK);
        }
    }

    if ( "@PVARRAY" ) {
        print @PVARRAY;
    }

    if ( "@PVCKARR" ) {
        print @PVCKARR;
    }

    datecheck();
    print_header("*** END CHECKING PHYSICAL VOLUMES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING LOGICAL VOLUMES $datestring ***");

    if ( @LVarr != 0 ) {
        print "$INFOSTR Logical volumes defined\n";
        print @LVarr;
    }
    else {
        print "$INFOSTR No logical volumes defined\n";
    }

    foreach $servdsk ( sort keys %disklist ) {
        print
"\n$INFOSTR Physical volume $servdsk contains logical volumes @{$disklist{$servdsk}}\n";
    }

    datecheck();
    print_header("*** END CHECKING LOGICAL VOLUMES $datestring ***");
}

#
# Subroutine to check basic performance
#
sub PERFORMANCE_BASICS {
    datecheck();
    print_header("*** BEGIN CHECKING BASIC PERFORMANCE $datestring ***");

    print "$NOTESTR The most impotant step in any performance analysis is\n";
    print "$NOTESTR to establish baseline of what is considered to be\n";
    print "$NOTESTR \"normal\" state of the server\n\n";

    my @USED = `free -t`;
    print @USED;

    my @pcpu = `ps -e -o pcpu,cpu,nice,state,cputime,args --sort -pcpu 2>/dev/null`;
    if ( "@pcpu" ) {
        print "\n$INFOSTR List processes by CPU activity\n";
        print @pcpu;
    }

    my @cpupoweri = `cpupower idle-info 2>/dev/null`;
    if ( "@cpupoweri" ) {
        print "\n$INFOSTR CPU idle kernel information\n";
        print @cpupoweri;
    }

    my @pmem = `ps -e -o rss,args --sort -rss | pr -TW\$COLUMNS 2>/dev/null`;
    if ( "@pmem" ) {
        print "\n$INFOSTR List processes by memory usage\n";
        print @pmem;
    }
    else {
        @pmem = `ps aux --sort pmem 2>/dev/null`;
        if ( "@pmem" ) {
            print "\n$INFOSTR List processes by memory usage\n";
            print @pmem;
        }
    }

    my @TOP = `top -n 1 2>/dev/null`;
    if ( "@TOP" ) {
        print "\n$INFOSTR Top activity\n";
        print @TOP;
    }

    my @VMSTATS = `vmstat -s 2>/dev/null`;
    if ( "@VMSTATS" ) {
        print "\n$INFOSTR Virtual memory counters\n";
        print @VMSTATS;
    }

    my @AASTAT = `aa-status 2>/dev/null`;
    if ( "@AASTAT" ) {
        print "\n$INFOSTR Programs confined to limited set of resources in AppArmor\n";
        print @AASTAT;
    }

    my @VMSTAT = `vmstat $DELAY $ITERATIONS 2>/dev/null`;
    if ( "@VMSTAT" ) {
        print "\n$INFOSTR Virtual memory statistics to review\n";
        print "$NOTESTR Runnable processes queue \"r\" exceeds the number of CPUs on
           server (or available threads on multi-threaded CPUs)\n";
        print "$NOTESTR High number of blocked \"b\" processes/threads in uniterruptible sleep
           (usually waiting for I/O)\n";
        print "$NOTESTR Swap In \"si\" occurs when server is experiencing RAM shortage
           and memory is swapped in from disk\n";
        print "$NOTESTR CPU \"sy\" constantly higher than \"us\"\n"; 

        print @VMSTAT;

        my @IDLEVALS = split( /\s+/, $VMSTAT[$#VMSTAT] );
        my $IDLE = $IDLEVALS[$#IDLEVALS - 2];
        chomp($IDLE);

        if ( "$IDLE" > "$CPU_IDLE_THRESHOLD" ) {
            print
"\n$PASSSTR CPU idle over $CPU_IDLE_THRESHOLD% (current idle $IDLE%)\n";
        }
        else {
            print
"\n$WARNSTR CPU idle below $CPU_IDLE_THRESHOLD% (current idle $IDLE%)\n";
            push(@CHECKARR,
"\n$WARNSTR CPU idle below $CPU_IDLE_THRESHOLD% (current idle $IDLE%)\n");
            $warnings++;
        }
    }

    my @SARD = `sar -d $DELAY $ITERATIONS 2>/dev/null`;
    if ( "@SARD" ) {
        print "\n$INFOSTR SA Disk activity\n";
        print @SARD;
    }

    my @IOSTATD = `iostat -dxNhtz $DELAY $ITERATIONS 2>/dev/null`;
    if ( "@IOSTATD" ) {
        print "\n$INFOSTR Iostat disk activity to review\n";
        print "$NOTESTR Disk shows consistently high reads/writes (\"rrqm/s\" 
           and \"wrqm/s\") along with: significant average wait \"%await\",
           and the utilisation \"%util\" close to 100%\n";
 
        print @IOSTATD;
    }

    my @MPSTAT = `mpstat -P ALL $DELAY $ITERATIONS 2>/dev/null`;
    if ( "@MPSTAT" ) {
        print "\n$INFOSTR Mpstat processor activity to review\n";
        print "$NOTESTR \"%iowait\" - percentage of time spent waiting on I/O\n";  
        print "$NOTESTR \"%irq\" - percentage of time spent servicing hardware interrupts\n";  
        print "$NOTESTR \"%soft\" - percentage of time spent servicing software interrupts\n";  
        print "$NOTESTR \"%steal\" - percentage of time spent in involuntary waits while
           hypervisor services another virtual processor\n";  
        print "$NOTESTR \"sys\" constantly higher that \"usr\"\n"; 

        print @MPSTAT;
    }

    my @TUNEDADM = `tuned-adm list 2>/dev/null`;
    if ( "@TUNEDADM" ) {
        print "\n$INFOSTR Tuning profiles\n";
        print @TUNEDADM;

        my @TUNEDADMACT = `tuned-adm active 2>/dev/null`;
        if ( "@TUNEDADMACT" ) {
            print "\n$INFOSTR Tuning profile active status\n";
            print @TUNEDADMACT;
        }
    }

    datecheck();
    print_header("*** END CHECKING BASIC PERFORMANCE $datestring ***");
}

#
# Subroutine to check syslog
#
sub SYSLOG_LOGGING {
    datecheck();
    print_header("*** BEGIN CHECKING SYSLOG OPERATIONAL $datestring ***");

    $DDate       = rand();
    $LOGSTR      = "AUTOMATED TEST MESSAGE $DDate FOR OAT. PLEASE IGNORE";
    print "$INFOSTR Expected logging in $SYSLOG\n";

    if ( -s "$syslog_conf" ) {
        if ( open( SYSD, "egrep -v ^# $syslog_conf |" ) ) {
            print "\n$INFOSTR File $syslog_conf\n";
            while (<SYSD>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /info/, $_ ) ) {
                    ( undef, $RSYSLOG ) = split( /\s+/, $_ );
                }

                ($s) = /^([^#]\S+\s+)/ and
                $s =~ s/ /<SPACE>/g and
                do { $s =~ s/\t/<TAB>/g ;
                push(@CHECKARR,
"\n$ERRSTR Syslog file $syslog_conf: Line $. contains SPACES instead of TABS \"$s ...\"\n");
                push(@WARNSLOGARR,
"$ERRSTR Syslog file $syslog_conf: Line $. contains SPACES instead of TABS \"$s ...\"\n"); };

                $warnings++;

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
    elsif ( -s "$rsyslog_conf" ) {
        if ( open( SYSD, "egrep -v ^# $rsyslog_conf |" ) ) {
            print "\n$INFOSTR File $rsyslog_conf\n";
            while (<SYSD>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /info/, $_ ) ) {
                    ( undef, $RSYSLOG ) = split( /\s+/, $_ );
                }
                print $_;
            }
            close(SYSD);
        }
        else {
            print "\n$WARNSTR Cannot open $rsyslog_conf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $rsyslog_conf\n");
            $warnings++;
        }

        my @rsyscfg = `ls $rsyslogdir/*.conf 2>/dev/null`;
        foreach my $rsc ( @rsyscfg ) {
            my @rsysarr = `egrep -v ^# $rsc`;
            if ( @rsysarr ) {
                print "\n$INFOSTR Configuration file $rsc\n";
                print @rsysarr;
                print "\n";
            }
        }
    }
    else {
        if ( -s "$syslogng_conf" ) {
            if ( open( SYSD, "egrep -v ^# $syslogng_conf |" ) ) {
                print "\n$INFOSTR File $syslogng_conf\n";
                while (<SYSD>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
            }
            else {
                print "\n$WARNSTR Cannot open $syslogng_conf\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open $syslogng_conf\n");
                $warnings++;
            }
            close(SYSD);
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
        #use Sys::Syslog qw(:DEFAULT setlogsock);
        #setlogsock("stream") || die "Error: Cannot open setlogsock\n";
        system("logger $LOGSTR");
    }
    else {
        if ( eval "require Sys::Syslog" ) {
            import File::Find;
            use Sys::Syslog;
            openlog( '$SYSLOG', 'ndelay', 'daemon' );
            syslog( 'info', "$LOGSTR" );
            closelog();
        }
        else {
            system("logger $LOGSTR");
        }
    }

    if ( -s "$RSYSLOG" ) {
        $SYSLOG = $RSYSLOG;
    }

    my $See = `egrep "$LOGSTR" $SYSLOG 2>&1`;
    if ("$See") {
        print "\n$PASSSTR System logger messages successful\n";
    }
    else {
        print "\n$ERRSTR System logger messages failed\n";
        push(@CHECKARR, "\n$ERRSTR System logger messages failed\n");
        $warnings++;
    }

    my @logfind = `awk '/error|fail|warn|crit/ && ! /awk/ {print}' $SYSLOG 2>/dev/null`;
    if (@logfind) {
        print "\n$INFOSTR Recent syslog entries of interest\n";
        print @logfind;
    }

    if ( $STAND_FLAG > 0 ) {
        my @dmesglog = `dmesg | egrep -i "error|fail|warn|crit"`;
        if (@dmesglog) {
            print "\n$INFOSTR Recent dmesg entries of interest\n";
            print @dmesglog;
        }
    }
    else {
        print "\n$INFOSTR Dmesg check reports no errors\n";
    }

    if ( -s "$btmplog" ) {
        my @btmp = `lastb 2>/dev/null | awk NF`;
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

    if ( -s "$faillog" ) {
        my @faill = `faillog -a 2>/dev/null | awk NF`;
        if (@faill) {
            print "\n$INFOSTR Recent failed login attempts\n";
            print @faill;
        }

        my @pam_tally = `pam_tally 2>/dev/null | awk NF`;
        if (@pam_tally) {
            print "\n$INFOSTR PAM tally of failed logins\n";
            print @pam_tally;
        }
    }
    else {
        print "\n$WARNSTR Failed login attempts not logged in $faillog\n";
        push(@CHECKARR, "\n$WARNSTR Failed login attempts not logged in $faillog\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING SYSLOG OPERATIONAL $datestring ***");
}

#
# Subroutine to check Unix password and group databases
#
sub pwdbcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SYSTEM AUTHENTICATION RESOURCES $datestring ***");

    my $pwdhash = q{};

    if ( -s $SUSEDEFPASSWD ) {
        if ( open( SAUTHC, "awk NF $SUSEDEFPASSWD 2>/dev/null |" ) ) {
            print "\n$INFOSTR Enabled features in configuration file $SUSEDEFPASSWD\n";
            while (<SAUTHC>) {
                print $_;
                chomp($_);
                if ( grep( /^CRYPT=/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    $_ =~ s/\s+$//g;
                    my @pwdhash = split(/=/, $_);
                    $pwdhash = $pwdhash[1];
                }
            }
            close(SAUTHC);
        }
    }

    if ( -s $UBUNTUDEFPASSWD ) {
        if ( open( UAUTHC, "awk NF $UBUNTUDEFPASSWD 2>/dev/null |" ) ) {
            print "\n$INFOSTR Enabled features in configuration file $UBUNTUDEFPASSWD\n";
            while (<UAUTHC>) {
                print $_;
                chomp($_);
            }
            close(UAUTHC);
        }
    }

    if ( -s $LOGINDEFS ) {
        if ( open( LAUTHC, "awk NF $LOGINDEFS 2>/dev/null |" ) ) {
            print "\n$INFOSTR Enabled features in configuration file $LOGINDEFS\n";
            while (<LAUTHC>) {
                print $_;
                chomp($_);
                if ( grep( /^ENCRYPT_METHOD/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    $_ =~ s/\s+$//g;
                    my @pwdhash = split(/\s+/, $_);
                    $pwdhash = $pwdhash[1];
                }
            }
            close(LAUTHC);
        }
    }

    if ( open( AUTHC, "authconfig --test 2>/dev/null |" ) ) {
        print "\n$INFOSTR Global system authentication resources\n";
        while (<AUTHC>) {
            print $_;
            if ( grep( /hashing/, $_ ) ) {
                $_ =~ s/^\s+//g;
                $pwdhash = $_;
            }
        }
        close(AUTHC);
    }
    else {
        print "\n$WARNSTR System authentication resources status unknown or command \"authconfig\" missing in this distribution\n";
    }

    if ( "$pwdhash" ) {
        print "\n$INFOSTR Default password hashing\n";
        print "$NOTESTR $pwdhash\n";
        print "$NOTESTR Minimum recommended password hashing is SHA512\n";
        print "$NOTESTR For different Linux distributions, following methods are used to modify it:
Run \"authconfig --passalgo=sha512 --update\"\n";
        print "Set \"CRYPT=SHA512\" in \"$SUSEDEFPASSWD\"\n";
        print "Modify \"password\" in \"$UBUNTUDEFPASSWD\" 
Set \"ENCRYPT_METHOD SHA512\" in \"$LOGINDEFS\"\n";
    }

    datecheck();
    print_header("*** END CHECKING SYSTEM AUTHENTICATION RESOURCES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING UNIX PASSWORD AND GROUP DATABASES $datestring ***");

    (
        $pdev,   $pino,     $pmode, $pnlink, $puid,
        $pgid,   $prdev,    $psize, $patime, $pmtime,
        $pctime, $pblksize, $pblocks
      )
      = stat($PASSFILE);

    if ( "$pnlink" > 1 ) {
        print "$WARNSTR $PASSFILE has $pnlink hard links\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE has $pnlink hard links\n");
        $warnings++;
    }
    else {
        print "$PASSSTR $PASSFILE has one hard link only\n";
    }

    $pfile_perms = $pmode & 0777;
    $poct_perms  = sprintf "%lo", $pfile_perms;

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
        push(@CHECKARR, "\n$WARNSTR $PASSFILE not owned by UID 0 ($puid)\n");
        $warnings++;
    }

    if ( "$pgid" == 0 ) {
        print "\n$PASSSTR $PASSFILE owned by GID $pgid\n";
    }
    else {
        print "\n$WARNSTR $PASSFILE not owned by GID 0 ($pgid)\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE not owned by GID 0 ($pgid)\n");
        $warnings++;
    }

    if ( !( ( $poct_perms != "444" ) || ( $poct_perms != "644" ) ) ) {
        print
          "\n$WARNSTR $PASSFILE permissions not 444 or 644 ($poct_perms)\n";
        push(@CHECKARR,
          "\n$WARNSTR $PASSFILE permissions not 444 or 644 ($poct_perms)\n");
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
                   push(@SHADWARN, "\n$WARNSTR Username $shaduser exists more than once in $Shadow\n");
                   push(@CHECKARR, "\n$WARNSTR Username $shaduser exists more than once in $Shadow\n");
                   $warnings++;
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

    my @passck = `pwck -r 2>&1 | awk NF`;
    my @grpck  = `grpck -r 2>&1 | awk NF`;

    print "\n$INFOSTR Pwck(1) verification\n";
    if (@passck) {
        print @passck;
        print "\n";
    }
    else {
        print "$PASSSTR Pwck clean\n\n";
    }

    print "$INFOSTR Grpck(1) verification\n";
    if (@grpck) {
        print @grpck;
        print "\n";
    }
    else {
        print "$PASSSTR Grpck clean\n\n";
    }

    $nisflag = 0;

    while ( @entry = getpwent ) {
        $passno++;
        push( @Passnumarr, $entry[2] );
        if ( $entry[2] == 0 ) {
            print "$INFOSTR Username \"$entry[0]\" has UID 0\n";
            $uidno++;
        }

        foreach my $raccess ( @remaccarr ) {
            my $racent = "$entry[7]/$raccess";
            if ( -s "$racent" && -T "$racent" ) {
                print "\n$WARNSTR Username \"$entry[0]\" has $raccess\n";
                my @aent = `cat $racent`;
                print @aent;
                push(@CHECKARR, "\n$WARNSTR Username \"$entry[0]\" has $raccess\n");
                push(@CHECKARR, @aent);
            }
        }

        my $epmode = (stat($entry[7]))[2];

        if ( $epmode & 0020 ) {
            print "\n$WARNSTR Home directory for \"$entry[0]\" ($entry[7]) group-writable!\n";
            push(@CHECKARR, "\n$WARNSTR Home directory for \"$entry[0]\" ($entry[7]) group-writable\n");
        }

        if ( $epmode & 0002 ) {
            print "\n$WARNSTR Home directory for \"$entry[0]\" ($entry[7]) world-writable!\n";
            push(@CHECKARR, "\n$WARNSTR Home directory for \"$entry[0]\" ($entry[7]) world-writable\n");
        }

        if ( grep(/^\$/, $entry[1]) ) { 
            my @passwdarr = split(/\$/, $entry[1]);
            if ( $#passwdarr eq 3 ) {
                print
"\n$INFOSTR Username \"$entry[0]\": $PWHASHARR{$passwdarr[1]}, salt=$passwdarr[2], hashed-password-and-salt=$passwdarr[3]\n";
            } elsif ( $#passwdarr eq 4 ) {
                if ( $passwdarr[2] =~ /rounds=/ ) {
                    print
"\n$INFOSTR Username \"$entry[0]\": $PWHASHARR{$passwdarr[1]}, $passwdarr[2], salt=$passwdarr[3], hashed-password-and-salt=$passwdarr[4]\n";
                }
                elsif ( "$passwdarr[3]" eq "" ) {
                    print
"\n$INFOSTR Username \"$entry[0]\": $PWHASHARR{$passwdarr[1]}, salt=$passwdarr[2], hashed-password-and-salt=$passwdarr[4]\n";
               }
               else {
                    print
"\n$INFOSTR Username \"$entry[0]\": $PWHASHARR{$passwdarr[1]}, salt=$passwdarr[2], hashed-password-and-salt=$passwdarr[4]\n";
                }
            } else {
                print "\n$INFOSTR Username \"$entry[0]\": ";
                foreach my $passent ( @passwdarr) {
                    print "$passent ";
                }
                print "\n";
            }

            if ( length($passwdarr[$#passwdarr]) ne $PWLEN{$passwdarr[1]} ) {
                print "$ERRSTR Incorrect length of encrypted password string for user \"$entry[0]\" (length($passwdarr[$#passwdarr] versus $PWLEN{$passwdarr[1]})\n";
            } else {
                print "$PASSSTR Correct length of encrypted password string for user \"$entry[0]\" ($PWLEN{$passwdarr[1]} for $PWHASHARR{$passwdarr[1]})\n";
            }
        } else {
            if ( $entry[1] eq "x" ) {
               print "\n\"$entry[0]\": hashing-algorithm=UNDEFINED\n";
               my @pw2 = `passwd -S "$entry[0]" 2>&1 | awk NF`;
               if ( "@pw2" ) {
                   print
"$INFOSTR Full password entry status for \"$entry[0]\" via \"passwd -S\" command \n";
                   print @pw2;
               }
            }
            else {
                if ( ! grep(/!|\*/, $entry[1]) ) {
                   print "\n\"$entry[0]\": hashing-algorithm=DES\n";

                   if ( length($entry[1]) ne $DESLENGTH ) {
                       print "$ERRSTR Incorrect length of encrypted password string for user \"$entry[0]\" (length($entry[1]) versus $DESLENGTH)\n";
                   } else {
                       print "$PASSSTR Correct length of encrypted password string for user \"$entry[0]\" ($DESLENGTH)\n";
                   }
                }
            }
        }

        # adduser and addgroup enforce conformity to IEEE Std
        # 1003.1-2001, which allows only the following characters to
        # appear in group and user names: letters, digits, underscores,
        # periods, at signs (@), dollar sign ($), and dashes. The name
        # may no start with # a dash.
        # The "$" sign is allowed at the end of usernames (to
        # conform with Samba).
        #
        # IEEE Std 1003.1-2001 is one of the POSIX standards.
        # To be portable across systems conforming to
        # IEEE Std 1003.1-2001, the value is composed of
        # characters from the portable filename character set.
        #
        # POSIX compliance.and compatibility with other *NIX
        # variants is one reason that adduser limits the characters
        # in user names.
        # 
        # But the default NAME REGEX is even more restrictive than
        # POSIX portable filename character set.
        #
        # ^[a-z][-a-z0-9]*$
        # 
        if ( ! grep(/^[a-zA-Z0-9\.\-\$\_]+$/, "$entry[0]") ) { 
            print
"\n$WARNSTR Username \"$entry[0]\" contains characters non-conforming with IEEE Std 1003.1-2001\n";
        }

        my @chage = `chage -l "$entry[0]" 2>/dev/null`;
        if ( @chage != 0 ) {
            print "\n$INFOSTR Password expiry status for \"$entry[0]\"\n";
            print @chage;
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
        print "\n$WARNSTR There are \"+:\" entries in password file\n";
        push(@CHECKARR, "\n$WARNSTR There are \"+:\" entries in password file\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR No \"+:\" entries in password file\n";
    }

    if ( $uidno > 1 ) {
        print "\n$WARNSTR Multiple usernames with UID 0\n";
        push(@CHECKARR, "\n$WARNSTR Multiple usernames with UID 0\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR No multiple usernames with UID 0\n";
    }

    if ( @PassWdarr != 0 ) {
        print "\n$INFOSTR Entries in Unix password file\n";
        print @PassWdarr;
    }

    if ( @Grarr != 0 ) {
        print "\n$INFOSTR Entries in Unix group file\n";
        print @Grarr;
    }

    if ( -s "$LOGINDEFS" ) {
        if ( open( I, "egrep -v ^# $LOGINDEFS |" ) ) {
            print "\n$INFOSTR Login defaults in $LOGINDEFS\n";
            while (<I>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                chomp;
                $_ =~ s/^\s+//g;
                $_ =~ s/\s+$//g;
                if ( grep( /^PASS_MIN_LEN/, $_ ) ) {
                    $PASSMIN_FLAG++;
                    ( undef, my $passlenmin ) = split(/\s+/, $_);
                    if ( $passlenmin < $PASSMINTHRESH ) {
                        push(@LDEFARR,
"$WARNSTR Minimum password length below threshold ($passlenmin instead of $PASSMINTHRESH)\n");
                        push(@CHECKARR,
"\n$WARNSTR Minimum password length below threshold ($passlenmin instead of $PASSMINTHRESH)\n");
                        $warnings++;
                    }
                    else {
                        push(@LDEFARR,
"$PASSSTR Minimum password length above threshold ($passlenmin)\n");
                    }
               }

               if ( grep( /^PASS_MAX_DAYS/, $_ ) ) {
                   $PASSMAXDAYS_FLAG++;
                   ( undef, my $passmaxdays ) = split(/\s+/, $_);
                   if ( $passmaxdays > $PASSMAXTHRESH ) {
                       push(@LDEFARR,
"$WARNSTR Maximum password age above threshold ($passmaxdays instead of $PASSMAXTHRESH)\n");
                       push(@CHECKARR,
"\n$WARNSTR Maximum password age above threshold ($passmaxdays instead of $PASSMAXTHRESH)\n");
                       $warnings++;
                   }
                   else {
                       push(@LDEFARR,
"$PASSSTR Maximum password age below threshold ($passmaxdays)\n");
                   }
               }

               if ( grep( /^SHA_CRYPT_MIN_ROUNDS/, $_ ) ) {
                   ( undef, my $shaminround ) = split(/\s+/, $_);
                   if ( "$shaminround" ) {
                       push(@LDEFARR,
"$INFOSTR Minimum number of rounds used by SHA algorithms is $shaminround\n");
                   }
               }

               if ( grep( /^SHA_CRYPT_MAX_ROUNDS/, $_ ) ) {
                   ( undef, my $shamaxround ) = split(/\s+/, $_);
                   if ( "$shamaxround" ) {
                       push(@LDEFARR,
"$INFOSTR Maximum number of rounds used by SHA algorithms is $shamaxround\n");
                   }
               }
            }
            close(I);

            if ( $PASSMIN_FLAG == 0 ) {
                push(@LDEFARR,
"$WARNSTR Minimum password length below threshold (using default)\n");
                push(@CHECKARR,
"\n$WARNSTR Minimum password length below threshold (using default)\n");
                $warnings++;
            }

            if ( $PASSMAXDAYS_FLAG == 0 ) {
                push(@LDEFARR,
"$WARNSTR Maximum password age using default (no ageing)\n");
                push(@CHECKARR,
"\n$WARNSTR Maximum password age using default (no ageing)\n");
                $warnings++;
            }
        }
    }
    else {
        print "\n$WARNSTR $LOGINDEFS does not exist or empty\n";
        push(@CHECKARR, "\n$WARNSTR $LOGINDEFS does not exist or empty\n");
        $warnings++;
    }

    if ( "@LDEFARR" ) {
        print "\n";
        print @LDEFARR;
    }

    my @chsh = `chsh -list 2>/dev/null`;
    if ( @chsh != 0 ) {
        print "\n$INFOSTR Valid login Shells\n";
        print @chsh;
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

#
# Subroutine to check superdaemon xinetd setup
#
sub inetdchk {
    datecheck();
    print_header("*** BEGIN CHECKING INTERNET SERVICES $datestring ***");

    my @SIS = ();
    eval {
    # On certain occasions (wireless services), this command hangs, so we need to
    # manage how long it runs
    #
    local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
    alarm $ALARM_TIMEOUT;
    @SIS = `service --status-all 2>/dev/null`;
    alarm 0;
};

    if ($@) {
        print "$WARNSTR Command \"service --status-all\" timed out\n";
        push(@CHECKARR,
"\n$WARNSTR Command \"service --status-all\" timed out\n");
        $warnings++;
    } else {
        if ( @SIS != 0 ) {
            print "$INFOSTR Status of services\n";
            print @SIS;
        }
    }

    my @SIS2 = `chkconfig --list 2>/dev/null`;
    if ( @SIS2 != 0 ) {
        print "\n$INFOSTR Configuration of services\n";
        print @SIS2;
    }

    foreach my $proftpfile (@Proftpdarray) {
        if ( -s "$proftpfile" ) {
            my @pflist = `egrep -v ^# $proftpfile | awk NF`;
            if ( @pflist ) {
                print "\n";
                print "$INFOSTR ProFTPD configuration in $proftpfile\n";
                print @pflist;
            }
        }
    }

    foreach my $vsftpfile (@VSftpdarray) {
        if ( -s "$vsftpfile" ) {
            my @vslist = `egrep -v ^# $vsftpfile | awk NF`;
            if ( @vslist ) {
                print "\n";
                print "$INFOSTR VsFTP configuration in $vsftpfile\n";
                print @vslist;
            }
        }
    }

    if ( -s "$INETD" ) {
        if ( open( I, "egrep -v ^# $INETD |" ) ) {
            print "\n$INFOSTR Active services in $INETD\n";
            while (<I>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                chomp;
                if ( grep( /^ftp/, $_ ) ) {
                    $FTP_FLAG++;
                }
            }

            print "\n";

            if ( $FTP_FLAG > 0 ) {
                if ( !-s "$ftpusers" ) {
                    print
"\n$ERRSTR FTP configuration file $ftpusers missing\n";
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
                        foreach $ftpusr (@FTPdisable) {
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

                if ( !-s "$ftpacc" ) {
                    print
                      "\n$ERRSTR FTP configuration file $ftpacc missing\n";
                    $warnings++;
                }
                else {
                    if ( open( FTPA, "egrep -v ^# $ftpacc |" ) ) {
                        print "\n$INFOSTR Configuration file $ftpacc\n";
                        while (<FTPA>) {
                            next if ( grep( /^$/, $_ ) );
                            print $_;
                        }
                        close(FTPA);
                    }
                    else {
                        print "\n$WARNSTR Cannot open $ftpacc\n";
                        push(@CHECKARR, "\n$WARNSTR Cannot open $ftpacc\n");
                        $warnings++;
                    }
                }

                if ( !-s "$ftphosts" ) {
                    print
"\n$ERRSTR FTP configuration file $ftphosts missing\n";
                    $warnings++;
                }
                else {
                    if ( open( FTPH, "egrep -v ^# $ftphosts |" ) ) {
                        print "\n$INFOSTR Configuration file $ftphosts\n";
                        while (<FTPH>) {
                            next if ( grep( /^$/, $_ ) );
                            print $_;
                        }
                        close(FTPH);
                    }
                    else {
                        print "\n$WARNSTR Cannot open $ftphosts\n";
                        $warnings++;
                    }
                }
            }
        }
        close(I);
    }
    else {
        print "\n$INFOSTR Cannot open $INETD\n";
    }

    if ( !-f "$INETDSEC" && !-s "$INETDSEC" ) {
        print
          "\n$ERRSTR Inetd not managed through ACLs ($INETDSEC not used)\n";
        push(@CHECKARR,
          "\n$ERRSTR Inetd not managed through ACLs ($INETDSEC not used)\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR Inetd managed through ACLs ($INETDSEC used)\n";
        if ( open( V, "egrep -v ^# $INETDSEC | awk NF |" ) ) {
            print "\n$INFOSTR Active services in $INETDSEC\n";
            while (<V>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(V);
        }
        else {
            print "\n$WARNSTR Cannot open $INETDSEC\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $INETDSEC\n");
        }
    }

    if ( -s "$hostequiv" ) {
        my @heq = `egrep -v ^# $hostequiv | awk NF 2>/dev/null`;
        if ( @heq != 0 ) {
            print "\n$WARNSTR $hostequiv enabled\n";
            push(@CHECKARR, "\n$WARNSTR $hostequiv enabled\n");
            print @heq;
        }
        else {
            print "\n$PASSSTR $hostequiv disabled\n";
        }
    }
    else {
        print "\n$PASSSTR $hostequiv does not exist or is empty\n";
    }

    if ( -s "$Shells" ) {
        if ( open( SHL, "egrep -v ^# $Shells 2>/dev/null |" ) ) {
            print "\n$INFOSTR Defined Shells in $Shells\n";
            while (<SHL>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                chomp($_);
                if ( -e $_ && -x $_ && -s $_ ) {
                    push(@VSHARR, "$PASSSTR Valid Shell $_\n");
                }
                else {
                    push(@VSHARR, "$INFOSTR Invalid Shell $_\n");
                }
            }
            close(SHL);

            if ( "@VSHARR" ) {
                print @VSHARR;
            }
        }
        else {
            print "\n$INFOSTR $Shells not in use\n";
            $warnings++;
        }
    }

    datecheck();
    print_header("*** END CHECKING INTERNET SERVICES $datestring ***");
}

#
# Subroutine to check defined protocols and services
#
sub protchk {
    datecheck();
    print_header("*** BEGIN CHECKING DEFINED SERVICES AND PROTOCOLS $datestring ***");

    if ( -s "$SERVICES" ) {
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

    if ( -s "$PROTOCOLS" ) {
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

    if ( -s "$ETHERS" ) {
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

    my @alternatives = `alternatives --display mta 2>/dev/null | awk NF`;
    if ( "@alternatives" ) {
        print @alternatives;
    }

    @port  = (25);


    my @POSTFIXARR = `ls /etc/postfix/* 2>/dev/null`;

    my @postr = `postfix status 2>/dev/null`;

    if ( $POSTFIX_FLAG > 0 ) {
        print "\n$INFOSTR Mail Transfer Agent is seemingly Postfix\n";
        print @postr;
        my @postcheck = `postconf -n 2>/dev/null | awk NF`;
        if ( @postcheck != 0 ) {
            print "\n$INFOSTR Postfix configuration summary\n";
            print "@postcheck";
        }

        foreach my $postfixconf ( @POSTFIXARR ) {
            chomp($postfixconf);
            if ( ( -s "$postfixconf" ) && ( -T "$postfixconf" ) ) {
                $POSTFIX_FLAG++;
                my @postcat = `cat $postfixconf 2>/dev/null`;
                if ( @postcat != 0 ) {
                    print "\n$INFOSTR Postfix configuration file $postfixconf\n";
                    print "@postcat";
                }
            }
        }

        my @postck = `postfix check 2>&1`;
        if ( @postck != 0 ) {
            print "\n$INFOSTR Postfix check\n";
            print "@postck";
        }

        my @postq = `postqueue -p 2>/dev/null`;
        if ( @postq != 0 ) {
            print "\n$INFOSTR Postfix queue status\n";
            print "@postq";
        }

        my @posta = `postalias -s $alis2 2>/dev/null`;
        if ( @posta != 0 ) {
            print "\n$INFOSTR Postfix aliases in default location ($alis2)\n";
            print "@posta";
        }
    }
    else {
        print "\n$INFOSTR Mail Transfer Agent Postfix seemingly not running\n";
    }

    if ( $EXIM_FLAG > 0 ) {
        print "\n$INFOSTR Mail Transfer Agent is seemingly Exim\n";
        my @exiwhat = `exiwhat 2>/dev/null`;
        if ( @exiwhat != 0 ) {
            print "@exiwhat\n";
        }
    }
    else {
        print "\n$INFOSTR Mail Transfer Agent Exim seemingly not running\n";
    }

    if ( $SENDMAIL_FLAG > 0 ) {
        print "\n$INFOSTR Mail Transfer Agent is seemingly Sendmail\n";
    }
    else {
        print "\n$INFOSTR Mail Transfer Agent Sendmail seemingly not running\n";
    }

    my @zms = `zmcontrol status 2>/dev/null`;
    if ( @zms ) {
        if ( grep(/not running/i, @zms) ) {
            print "\n$INFOSTR Mail Transfer Agent Zimbra seemingly not running\n";
        }
        else {
            print "\n$INFOSTR Mail Transfer Agent is seemingly Zimbra\n";
            print @zms;

            my @ZMP = `postconf 2>/dev/null`;
            if ( @ZMP ) {
                print "\n$INFOSTR Zimbra configuration\n";
                print @ZMP;
            }

            my @ZMQUEUE = `qshape 2>/dev/null`;
            if ( @ZMQUEUE ) {
                print "\n$INFOSTR Zimbra queue status\n";
                print @ZMQUEUE;
            }

            my @ZMACC = `zmprov sa -v objectClass="zimbraAccount" 2>/dev/null`;
            if ( @ZMACC ) {
                print "\n$INFOSTR Zimbra email accounts\n";
                print @ZMACC;
            }

            my @ZMLDAP = `ldap status 2>/dev/null`;
            if ( @ZMLDAP ) {
                print "\n$INFOSTR Zimbra LDAP service status\n";
                print @ZMLDAP;
            }

            my @ZMAPACHE = `zmapachectl status 2>/dev/null`;
            if ( @ZMAPACHE ) {
                print "\n$INFOSTR Zimbra Apache service status\n";
                print @ZMAPACHE;
            }

            my @ZMST = `zmauditswatchctl status 2>/dev/null`;
            if ( @ZMST ) {
                print "\n$INFOSTR Zimbra auditswatch service status\n";
                print @ZMST;
            }

            my @ZMAMAV = `zmamavisdctl status 2>/dev/null`;
            if ( @ZMAMAV ) {
                print "\n$INFOSTR Zimbra Amavis-D New service status\n";
                print @ZMAMAV;
            }

            my @ZMAVIRUS = `zmantivirusctl status 2>/dev/null`;
            if ( @ZMAVIRUS ) {
                print "\n$INFOSTR Zimbra anti-virus service status\n";
                print @ZMAVIRUS;
            }

            my @ZMCLAM = `zmclamdctl status 2>/dev/null`;
            if ( @ZMCLAM ) {
                print "\n$INFOSTR Zimbra Clam AV service status\n";
                print @ZMCLAM;
            }

            my @ZMSPAM = `zmantispamctl status 2>/dev/null`;
            if ( @ZMSPAM ) {
                print "\n$INFOSTR Zimbra anti-spam service status\n";
                print @ZMSPAM;
            }
        }
    }

    my @PRIVACY = ();

    if ( -s "$SMTPD" && -T "$SMTPD" ) {
        if ( open( ALS, "egrep -v ^# $SMTPD |" ) ) {
            print "\n$INFOSTR Found $SMTPD contents\n";
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
            $warnings++;
        }
    }

    if ( $SENDMAIL_FLAG > 0 ) {
        if ( @PRIVACY != 0 ) {
            if (   ( grep( /noexpn/, @PRIVACY ) )
                && ( grep( /novrfy/, @PRIVACY ) ) )
            {
                print "$INFOSTR SMTPD privacy options defined\n";
            }
            else {
                print "$WARNSTR SMTPD privacy options not fully defined\n";
                push(@CHECKARR, "\n$WARNSTR SMTPD privacy options not fully defined in Sendmail\n");
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
            print "\n$WARNSTR SMTP Smarthost not defined\n";
            push(@CHECKARR, "\n$WARNSTR Sendmail SMTP Smarthost not defined\n");
            $warnings++;
        }
    }

    my @mailqcheck = `mailq 2>/dev/null | egrep -vi "is empty|Total requests: 0"`;
    if ( @mailqcheck != 0 ) {
        print "\n$WARNSTR Mail queue not empty\n";
        print "$INFOSTR Mail queue status\n";
        print @mailqcheck;
        push(@CHECKARR, "\n$WARNSTR Mail queue not empty\n");
    }
    else {
        print "\n$PASSSTR Mail queue empty\n";
    }

    my @mailstat = `mailstats 2>&1`;
    if ( grep( /No such/, @mailstat ) ) {
        print "\n$WARNSTR Email statistics not defined\n";
        print @mailstat;
        push(@CHECKARR, "\n$WARNSTR Sendmail email statistics not defined\n");
        $warnings++;
    }
    else {
        if ( "@mailstat" ) {
            print "\n$INFOSTR Email statistics\n";
            print @mailstat;
        }
    }

    $alis = q{};

    -s $alis1     ? $alis = $alis1
      : -s $alis2 ? $alis = $alis2
      : print "$INFOSTR Aliases file not installed\n";

    if ("$alis") {
        if ( open( ALI, "egrep -v ^# $alis 2>/dev/null |" ) ) {
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

    my @rpcinfo = `rpcinfo -p 2>/dev/null`;
    if ( @rpcinfo != 0 ) {
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

        my @rndcc = `rndc -s 127.0.0.1 -y rndc-key status 2>/dev/null`;
        if ( "@rndcc" ) {
            print "\n$INFOSTR BIND rndc status\n";
            print @rndcc;
        }

        my $DNSCONF = q{};
        -s "$DNSCONF1" ? $DNSCONF = $DNSCONF1
        : -s "$DNSCONF2" ? $DNSCONF = $DNSCONF2
        : print "\n$INFOSTR DNS configuration file named.conf not installed\n";

        if ( -s "$DNSCONF" ) {
            if ( open( XY, "egrep -v ^# $DNSCONF | awk NF |" ) ) {
                print "\n$INFOSTR Checking $DNSCONF\n";
                while (<XY>) {
                    print $_;
                }
                close(XY);
            }
            else {
                print "\n$INFOSTR Cannot open $DNSCONF\n";
            }
        }
        else {
            print "\n$INFOSTR $DNSCONF empty or does not exist\n";
        }

        my @ncheckconf = `named-checkconf 2>/dev/null`;
        if ( "@ncheckconf" ) {
            print "\n$INFOSTR BIND named-checkconf results\n";
            print @ncheckconf;
        }
    }

    if ( open( YX, "egrep -v ^# $NAMEDCONF 2>/dev/null | awk NF |" ) ) {
        print "\n$INFOSTR Checking $NAMEDCONF\n";
        while (<YX>) {
            print $_;
        }
        close(YX);
    }
    else {
        print "\n$INFOSTR Cannot open $NAMEDCONF\n";
    }

    if ( open( I, "awk NF $NAMED 2>/dev/null |" ) ) {
        print "\n$INFOSTR DNS resolver configuration $NAMED\n";
        while (<I>) {
            print $_;
            chomp($_);
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
        print "\n$WARNSTR Cannot open $NAMED\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $NAMED\n");
    }

    print "\n$INFOSTR Checking hostname resolution order in $NSSWITCH\n";
    if ( -s "$NSSWITCH" ) {
        my @nssl = `awk '! /^#/ && ! /awk/ {print}' $NSSWITCH | awk NF`;
        print @nssl;

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
        print "$WARNSTR Configuration file $NSSWITCH does not exist\n";
        push(@CHECKARR, "\n$WARNSTR Configuration file $NSSWITCH does not exist\n");
        $warnings++;
    }

    if ( "$DNSMASQ_FLAG" > 0 ) {
        print "\n$INFOSTR Lightweight DHCP and caching DNS server seemingly running (dnsmasq)\n";
    }

    if ( -s "$HOSTS" ) {
        print "\n$INFOSTR Configuration file $HOSTS exists\n";
        if ( open( HO, "egrep -v ^# $HOSTS | awk NF |" ) ) {
            while (<HO>) {
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
            print "\n$ERRSTR Cannot open $HOSTS\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $HOSTS\n");
        }
        close(HO);
    }
    else {
        print "\n$ERRSTR Configuration file $HOSTS does not exist\n";
        push(@CHECKARR, "\n$ERRSTR Configuration file $HOSTS does not exist\n");
        $warnings++;
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
    print_header("*** END DOMAIN NAME SERVICES $datestring ***");

    my $DKIMDIR = "/etc/opendkim";
    my $DKIMCONF = "/etc/opendkim.conf";

    if ( -d "$DKIMDIR" && -s "$DKIMCONF" ) { 
       datecheck();
       print_header("*** BEGIN CHECKING DOMAINKEYS IDENTIFIED MAIL (DKIM) $datestring ***");

      my @DKIMCF = `grep -v ^# $DKIMCONF 2>/dev/null | awk NF`;
      if ( @DKIMCF ) {
           print "$INFOSTR DKIM configuration file $DKIMCONF\n";
           print @DKIMCF;
      }

      my @DKIMARR = `ls $DKIMDIR 2>/dev/null`;
      foreach my $dkiment (@DKIMARR) {
          next if ( -d $dkiment );
          chomp($dkiment);
          my @DKIMCAT = `grep -v ^# $dkiment 2>/dev/null | awk NF`;
          if ( @DKIMCAT ) {
              print "\n$INFOSTR DKIM file $dkiment\n";
              print @DKIMCAT;
          }
      }

      datecheck();
      print_header("*** END CHECKING DOMAINKEYS IDENTIFIED MAIL (DKIM) $datestring ***");
    }
}

#
# Subroutine to check NIS/YP
#
sub nischk {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK INFORMATION SERVICES (NIS/YP) $datestring ***");

    my $domname = `domainname | awk NF`;

    if ("$domname") {
        my $ypwhich = `ypwhich 2>/dev/null`;

        if ( $NISPLUS_FLAG > 0 ) {
            my @nisdefs = `nisdefaults`;
            if ( @nisdefs != 0 ) {
                print "$INFOSTR NIS+ default values\n";
                print @nisdefs;
            }
        }

        if ("$ypwhich") {
            print "$INFOSTR NIS domain $domname (bound to server $ypwhich)";

            if ( -s "$secnets" ) {
                my @sn = `egrep -v ^# $secnets 2>/dev/null`;
                if ( @sn != 0 ) {
                    print "$INFOSTR File $secnets";
                    print @sn;
                }
                else {
                    print "$INFOSTR File $secnets not set";
                    $warnings++;
                }
            }
            else {
                print "$INFOSTR File $secnets does not exist";
                $warnings++;
            }

            if ( -s "$secservers" ) {
                my @sn1 = `egrep -v ^# $secservers 2>/dev/null`;
                if ( @sn1 != 0 ) {
                    print "$INFOSTR File $secservers";
                    print @sn1;
                }
                else {
                    print "$INFOSTR File $secservers not set";
                    $warnings++;
                }
            }
            else {
                print "$INFOSTR File $secservers does not exist";
                $warnings++;
            }
        }
        else {
            print "$INFOSTR NIS not active\n";
        }
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

    my @MEMINFO = `cat /proc/meminfo 2>/dev/null`;
    if ( @MEMINFO ) {
        print "$INFOSTR Detailed memory usage status\n";
        print @MEMINFO;
    }

    my @BUDDYINFO = `cat /proc/buddyinfo 2>/dev/null`;
    if ( @BUDDYINFO ) {
        print "\n$NOTESTR /proc/buddyinfo shows how many free pages of given order are\n";
        print "$NOTESTR on the system. Interpret it in such a way that the bigger number\n";
        print "$NOTESTR of the low order pages the bigger fragmentation of physical memory.\n";
        print "$NOTESTR With no fragmentation, one gets only the highest order\n";
	print "$NOTESTR pages and at most one page for each lower order.\n";
	print "$NOTESTR DMA zone is the first 16 MB of memory\n";
	print "$NOTESTR DMA64 zone is the first 4 GB of memory on 64-bit Linux\n";
	print "$NOTESTR Normal zone is between DMA and HighMem\n";
	print "$NOTESTR HighMem zone is above 4 GB of memory\n";
        print "$INFOSTR Zoned buddy allocator/memory fragmentation and zones status\n";
        print @BUDDYINFO;
        foreach my $bi ( @BUDDYINFO ) {
            my @biarr = split(/\s+/, $bi);
            $biarr[1] =~ s/,$//g;
            print "$INFOSTR $biarr[0]$biarr[1]: Zone $biarr[3] has\n";
            my $cntb = 1;
            my @who = splice @biarr, 4;
            for my $p (0 .. $#who) {
                print $who[$p], " free ", 2*(2**$cntb), "KB pages\n";
                $cntb++;
            }
            print "\n";
        }
    }

    my @PAGETYPEINFO = `cat /proc/pagetypeinfo 2>/dev/null`;
    if ( @PAGETYPEINFO ) {
        print "\n$INFOSTR Additional page allocator information\n";
        print @PAGETYPEINFO;
    }

    my @ZONEINFO = `cat /proc/zoneinfo 2>/dev/null`;
    if ( @ZONEINFO ) {
        print "\n$INFOSTR Per-zone page allocator\n";
        print @ZONEINFO;
    }

    my @VMSTAT = `cat /proc/vmstat 2>/dev/null`;
    if ( @VMSTAT ) {
        print "\n$INFOSTR Detailed virtual memory statistics\n";
        print @VMSTAT;
    }

    my @HUGEPAGES = grep(/Huge/, @MEMINFO);
    if ( @HUGEPAGES ) {
        print "\n$INFOSTR Huge Pages overview\n";
        print @HUGEPAGES;
    }

    my @HPID    = ();
    my $KBAM    = q{};
    my $CMDLINE = q{};
    my $hall    = 0;
    my @HUGEPG  = ();
    my @HPG     = ();
    my $Flinbe  = q();
    my @HUGEARR = `ls /proc/*/smaps 2>/dev/null`;
    foreach my $harr (@HUGEARR) {
        chomp($harr);
        if ( -f $harr ) {
            @HPID = split(/\//, $harr);
            $KBAM = `grep AnonHugePages $harr | awk '{ sum += \$2; } END { if (sum > 0) {printf ("%d", sum+0)\;} }'`;
            chomp ($KBAM);

            # maybe /proc/$PID/numa_maps is useful for further details??
            if ( "$KBAM" ) {
                my $CMDLINE = `cat /proc/$HPID[2]/cmdline 2>/dev/null`;
                $Flinbe = sprintf("%6d  (%d)  %s", $KBAM, ($HPID[2]), $CMDLINE);
                push(@HUGEPG, "$Flinbe\n");
                $hall += $KBAM;
                $KBAM = q{};
            }
        }
    }
    push(@HPG, "$hall");

    if ( "@HUGEPG" ) {
        print "\n$INFOSTR Processes that use anon huge pages\n";
        print "KBytes   (PID)  Program_and_command_line\n";
        print sort { $b <=> $a } @HUGEPG;
        print @HPG, " KBytes total anon huge pages\n";
    } else {
        print "\n$INFOSTR There are no processes that use anon huge pages\n";
    }

    my @SLABTOP = `slabtop --once 2>/dev/null`;
    if ( @SLABTOP ) {
        print "\n$INFOSTR Detailed kernel slab top cache information\n";
        print @SLABTOP;
    }

    my $MEM_BLOCK =
      `cat /proc/meminfo | awk '/^MemTotal/ && ! /awk/ {print \$2}'`;
    $MEM_MBYTE = int( $MEM_BLOCK / 1024 );

    my $SWAP_TOTAL =
      `cat /proc/meminfo | awk '/^SwapTotal/ && ! /awk/ {print \$2}'`;
    my $SWAP_MBYTE = int( $SWAP_TOTAL / 1024 );

    if ( open( MX, "cat /proc/swaps |" ) ) {
        print "\n$INFOSTR Swap space\n";
        while (<MX>) {
            print $_;
            chomp;
            next if ( grep(/Priority/, $_) );
            ( undef, $swapdev, $tswap, $swapused, $swappriority ) =
            split( /\s+/, $_ );
            if ( $swapdev eq 'partition' ) {
                $tswapall += $tswap;
                $SWAP_DEV_NO++;
                push( @SWAPARRAY, $swapdev );
            }
            elsif ( $swapdev eq 'file' ) {
                $tswapall += $tswap;
                $SWAP_LOCALFS_NO++;
            }
            elsif ( $swapdev eq 'network' ) {
                $tswapall += $tswap;
                $SWAP_NETWORK_NO++;
            }
        }
        close(MX);
    }
    else {
        print "$ERRSTR Cannot check swap\n";
        push(@CHECKARR, "\n$ERRSTR Cannot check swap\n");
        $warnings++;
    }

    if ( $tswapall > 0 ) {
        $tswapall = int( $tswapall / 1024 );

        foreach $servdsk ( sort keys %disklist ) {
            my $swpcnt = 0;
            foreach my $itm (@SWAPARRAY) {
                if ( grep( /\Q$itm\E/, @{ $disklist{$servdsk} } ) ) {
                    $swpcnt++;
                }
            }

            $swpcnt == 0
              ? print
"\n$INFOSTR Physical volume $servdsk contains no device-based paging spaces\n"
              : $swpcnt > 1
              ? print
"\n$WARNSTR Physical volume $servdsk contains multiple device-based paging spaces\n"
              : print
"\n$PASSSTR Physical volume $servdsk contains 1 (single) device-based paging space\n";
        }

        print "\n";

        printf
"$INFOSTR Server has %d paging space%s on mass storage (device-based)\n\n",
          $SWAP_DEV_NO, $SWAP_DEV_NO == 1 ? "" : "s";

        printf
"$INFOSTR Server has %d paging space%s in local file system storage (file system based)\n\n",
          $SWAP_LOCALFS_NO, $SWAP_LOCALFS_NO == 1 ? "" : "s";

        printf
"$INFOSTR Server has %d paging space%s in remote file system storage (network file system based)\n",
          $SWAP_NETWORK_NO, $SWAP_NETWORK_NO == 1 ? "" : "s";


        print "\n";

        # Minimum swap size (as per Unix Standard Build)
        #
        if ( "$opt_w" == 1 ) {
            $minswap = 4096;
        }
        else {
            $minswap = 4096;
        }

        if ( $tswapall < $minswap ) {
            print "$WARNSTR Swap space is less than minimum ";
            print "(Swap=$tswapall MB, minimum=$minswap MB)\n";
            push(@CHECKARR, "\n$WARNSTR Swap space is less than minimum ");
            push(@CHECKARR, "(Swap=$tswapall MB, minimum=$minswap MB)\n");
            $warnings++;
        }
    }
    else {
        print "$ERRSTR Cannot check swap\n";
        $warnings++;
    }

    my @memrss = `ps -efyl 2>/dev/null |sort  -n -r -k 8`;
    if ( "@memrss") {
        print "\n$INFOSTR Processes sorted by Resident Memory (RSS) Usage\n";
        print @memrss;
    }

    # Memory and crashkernel recommended sizing:
    # 0 - 12 GB     128 MB (*)
    # 13 - 48 GB    256 MB
    # 49 - 128 GB   512 MB
    # 129 - 256 GB    1 GB
    #
    # Crashkernel no longer needs the offset of 16M on SLES 11
    # for x86 and x86_64 architecture.
    # (*) Note: For SLES11 SP2 double the values for crashkernel.
    #     The minimum need is 256M.
    # For the PPC64 architecture: crashkernel=128M@64M

    my $MEM_GBYTE = int( $MEM_MBYTE / 1024 );

    if ( $UNAME =~ /ppc64p/i ) {
        print "\n$INFOSTR RAM size is $MEM_GBYTE GB: Recommended crashkernel size is 128 MB @ 64 MB offset on PPC64 architecture\n";
    }
    else {
        if ( $MEM_GBYTE <= 12 ) {
            print "\n$INFOSTR RAM size is $MEM_GBYTE GB: RAM <= 12 GB, recommended crashkernel size is 128 MB (256 MB on SLES11 SP2)\n";
        }
        elsif ( $MEM_GBYTE <= 48 ) {
            print "\n$INFOSTR RAM size is $MEM_GBYTE GB: 12 GB <= RAM <= 48 GB, recommended crashkernel size is 256 MB (512 MB on SLES11 SP2)\n";
        }
        elsif ( $MEM_GBYTE <= 128 ) {
            print "\n$INFOSTR RAM size is $MEM_GBYTE GB: 48 GB <= RAM <= 128 GB, recommended crashkernel size is 512 MB (1 GB on SLES11 SP2)\n";
        }
        else {
            print "\n$INFOSTR RAM size is $MEM_GBYTE GB: RAM > 128 GB, recommended crashkernel size is 1 GB (2 GB on SLES11 SP2)\n";
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
        my @CATISSUE = `cat $ISSUE 2>/dev/null`;
        print @CATISSUE;
        $sst = `egrep -i "Release|Kernel" $ISSUE`;
        if ("$sst") {
            print "\n$WARNSTR Login banner $ISSUE possibly not customised ";
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

    if ( -s "$MOTD" ) {
        print "\n$PASSSTR Login banner $MOTD exists\n";
        my @CATMOTD = `cat $MOTD 2>/dev/null`;
        print @CATMOTD;
        $ssm = `egrep -i "Release|Kernel" $MOTD`;
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

    if ( $SECPATHAG > 0 ) {
        print "$INFOSTR Secure Path Agent running\n";
        @SPMGR = `spmgr display 2>/dev/null`;
    }
    else {
        print "$INFOSTR Secure Path Agent seemingly not running\n";
    }

    my @XPINFO = `xpinfo 2>/dev/null| egrep -v "Scanning|No disk"| awk NF`;

    my @ARRAYDSP = `arraydsp -i 2>/dev/null`;

    my @EMC = `syminq 2>/dev/null`;

    my @LSSG = `lssg 2>/dev/null`;

    my @probeluns = `probe-luns -a 2>/dev/null`;

    my @adapterinfo = `adapter_info 2>/dev/null`;

    my @EVAINFO = `evainfo -a -l 2>/dev/null`;

    my @HP3PARINFOI = `HP3PARInfo -i 2>/dev/null`;

    my @HP3PARINFOF = `HP3PARInfo -f 2>/dev/null`;

    my @NETAPPSANLUN = `sanlun lun show all 2>/dev/null`;

    my @partss = `cat /proc/partitions`;

    my @INTRAID =
      `irconcheck 2>/dev/null | egrep -vi "No Internal RAID adapters found"`;

    @ARMDSP = `armdsp -i 2>/dev/null | awk NF`;

    if (@LSSG) {
        print "\n$INFOSTR HP fibreutils lssg status\n";
        print @LSSG;
        $ARRFLAG++;
    }

    if (@probeluns) {
        print "\n$INFOSTR HP fibreutils probe-luns status\n";
        print @probeluns;
        $ARRFLAG++;
    }

    if (@adapterinfo) {
        print "\n$INFOSTR HP fibreutils adapter_info status\n";
        print @adapterinfo;
        $ARRFLAG++;
    }

    if (@partss) {
        print "\n$INFOSTR /proc/partitions status\n";
        print @partss;
        $ARRFLAG++;
    }

    if ( @SPMGR != 0 ) {
        print "\n$INFOSTR EVA SAN seemingly connected\n";
        print @SPMGR;
        $ARRFLAG++;
    }

    if ( @EVAINFO != 0 ) {
        print "\n$INFOSTR EVA SAN seemingly connected\n";
        print @EVAINFO;
        $ARRFLAG++;
    }

    if ( @XPINFO != 0 ) {
        print "\n$INFOSTR XP SAN seemingly connected\n";
        print @XPINFO;
        $ARRFLAG++;
    }

    if ( @HP3PARINFOI != 0 ) {
        print "\n$INFOSTR 3PAR SAN seemingly connected (short summary)\n";
        print @HP3PARINFOI;
        $ARRFLAG++;

        if ( @HP3PARINFOF != 0 ) {
            print "\n$INFOSTR 3PAR LUN information\n";
            print @HP3PARINFOF;
        } 
    }

    if ( @NETAPPSANLUN != 0 ) {
        print "\n$INFOSTR NetApp sanlun status\n";
        print @NETAPPSANLUN;
        $ARRFLAG++;
    }

    if ( @ARRAYDSP != 0 ) {
        print "\n$INFOSTR AutoRAID seemingly connected\n";
        print @ARRAYDSP;
        $ARRFLAG++;
    }

    if ( @EMC != 0 ) {
        print "\n$INFOSTR EMC Symmetrix seemingly connected\n";
        print @EMC;
        $ARRFLAG++;
    }

    if ( @INTRAID != 0 ) {
        print "\n$INFOSTR Internal RAID adapters seemingly connected\n";
        print @INTRAID;
    }

    if ( @ARMDSP != 0 ) {
        print "\n\n$INFOSTR Virtual Array seemingly connected\n";
        print @ARMDSP;

        foreach $armline (@ARMDSP) {
            chomp($armline);
            if ( grep( /Alias Name:/, $armline ) ) {
                ( undef, my $ARMALIAS ) = split( /:/, $armline );
                if ("$ARMALIAS") {
                    my @FULLARM = `armdsp -L $ARMALIAS 2>/dev/null`;
                    if ( @FULLARM != 0 ) {
                        print "$INFOSTR Virtual Array configuration\n";
                        print @FULLARM;
                    }
                }
            }
        }
    }

    if ( $ARRFLAG == 0 ) {
        print
"$INFOSTR It seems no SAN connected or their support toolkits not installed correctly\n";
    }

    if ( @FCarray != 0 ) {
        print "\n$INFOSTR Fcmsutil status\n";
        foreach my $fa (@FCarray) {
            chomp($fa);
            $fa =~ s/^\s+//g;
            $fa =~ s/CLAIMED.*//g;
            $fa =~ s/\s+$//g;
            ( undef, $instance, $fcpath, $ddriv, undef ) =
              split( /\s+/, $fa );
            $fulfcpath = "/dev/${ddriv}${instance}";
            print "$INFOSTR fcmsutil $fulfcpath\n";
            my @printfc = `fcmsutil $fulfcpath 2>&1`;
            print "@printfc";
        }
    }

    if ( "$autopath" == 1 ) {
        print "\n$INFOSTR AutoPath seemingly installed\n";
        my @autop = `autopath display all | awk NF`;
        print @autop;
    }

    if ( "$EMCP_FLAG" > 0 ) {
        print "\n$INFOSTR EMS PowerPath seemingly installed\n";
        my @powermt = `powermt display`;
        print @powermt;
        my @powermtc = `powermt check`;
        print @powermtc;
    }

    datecheck();
    print_header("*** END CHECKING SAN CONFIGURATION $datestring ***");
}

#
# Subroutine to check VxVM
#
sub VXVM_CHECK {
    datecheck();
    print_header("*** BEGIN CHECKING VXVM STATUS $datestring ***");

    if ( -s "$VXCONF" ) {
        if ( open( VXC, "egrep -v ^# $VXCONF | awk '/^opts=/ {print}' |" ) ) {
            print "$INFOSTR Configuration file $VXCONF\n";
            while (<VXC>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
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
        $warnings++;
    }

    if ( open( VXD, "vxdisk list 2>/dev/null |" ) ) {
        print "\n$INFOSTR Vxdisk list\n";
        while (<VXD>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            if ( grep( /offline|fail|error/i, $_ ) ) {
                push(@VXERRARR, $_);
            }
        }
        close(VXD);

        if ( "@VXERRARR" ) {
            print "\n$WARNSTR Non-VxVM or faulty physical volume(s)\n";
            print @VXERRARR;
            push(@CHECKARR, "\n$WARNSTR Non-VxVM or faulty physical volume(s)\n");
            push(@CHECKARR, @VXERRARR);
            $warnings++;
        }
    }
    else {
        print "\n$WARNSTR Cannot run vxdisk\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run vxdisk\n");
        $warnings++;
    }

    my @vxdiskpath = `vxdisk path 2>/dev/null`;
    if ( "@vxdiskpath" ) {
        print "\n$INFOSTR Vxdisk path status\n";
        print @vxdiskpath;
    }

    my @vxdiske = `vxdisk -e list 2>/dev/null`;
    if ( "@vxdiske" ) {
        print "\n$INFOSTR Vxdisk status with WWNs\n";
        print @vxdiske;
    }

    if ( open( DUB, "vxdg free |" ) ) {
        print "$INFOSTR Vxdg free\n";
        while (<DUB>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
        }
        close(DUB);
    }
    else {
        print "$WARNSTR Cannot run vxdg\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run vxdg\n");
        $warnings++;
    }

    if ( open( MP, "vxprint -htvq |" ) ) {
        print "$INFOSTR Vxprint status\n";
        while (<MP>) {
            next if ( grep( /^$/, $_ ) );
            if ( grep( /MAINT|ERR|OFF/i, $_ ) ) {
                print "$WARNSTR Check VxVM error\n";
                print $_;
                push(@CHECKARR, "\n$WARNSTR Check VxVM error\n");
                push(@CHECKARR, $_);
                $warnings++;
            } else {
                print $_;
            }
        }
        close(MP);
    }
    else {
        print "$WARNSTR Cannot run vxprint\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run vxprint\n");
        $warnings++;
    }

    my @vxtask = `vxtask list`;
    if ( @vxtask != 0 ) {
        print "$INFOSTR VxVM task status\n";
        print @vxtask;
    }

    datecheck();
    print_header("*** END CHECKING VXVM STATUS $datestring ***");
}

#
# Subroutine to check LAN
#
sub lancheck {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK SETUP $datestring ***");

    $lanok = 0;
    if ( open( LAN, "netstat -rnv 2>/dev/null |" )) {
        while (<LAN>) {
            $_ =~ s/^\s+//g;
            if ( grep( /^0.0.0.0/i, $_ ) ) {
                print "\n$PASSSTR Default static route defined\n";
                ( undef, $gwip, undef, undef, undef, undef ) = split( /\s+/, $_ );
                chomp($gwip);
                push( @GWlist, $gwip );
                $lanok++;
            }

            if ( grep( /^169.254.0.0/i, $_ ) ) {
                push( @NETSTATARR, "\n$INFOSTR ZEROCONF route 169.254.0.0/16 exists\n" );
                push( @NETSTATARR, "$_\n" );
            }

            if ( grep( /^224.0/, $_ ) ) {
                push( @NETSTATARR, "\n$INFOSTR Multicast routing is enabled (subnet 224.0.0.0)\n" );
                push( @NETSTATARR, "$_\n" );
            }
            print $_;
        }
        close(LAN);
    }
    else {
        print "\n$WARNSTR Cannot run netstat\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run netstat\n");
    }

    if ( "@NETSTATARR" ) {
        print @NETSTATARR;
    }

    if ( $lanok == 0 ) {
        print "\n$WARNSTR Default static route missing\n";
        push(@CHECKARR, "\n$WARNSTR Default static route missing\n");
        $warnings++;
    }
    elsif ( $lanok == 1 ) {
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
"\n$WARNSTR Default route $host is NOT reachable (first type ICMP)\n";
                $PING++;
            }
            else {
                print
"\n$PASSSTR Default route $host is reachable (first type ICMP)\n";
            }
            $h->close();

            # Second type of ping test.
            #
            $h = Net::Ping->new("icmp");
            if ( !$h->ping( $host, 2 ) ) {
                print
"\n$WARNSTR Default route $host is NOT reachable (second type ICMP)\n";
                $PING++;
            }
            else {
                print
"\n$PASSSTR Default route $host is reachable (second type ICMP)\n";
            }
            $h->close();

            # Third type of ping test.
            #
            $h = Net::Ping->new( "tcp", 2 );
            while ( $stop_time > time() ) {
                print
"\n$WARNSTR Default route $host is NOT not reachable (TCP ping)",
                  scalar( localtime() ), "\n"
                  unless $h->ping($host);
                $PING++;
            }
            undef($h);
        }
    }

    if ( $DIST ne "Debian" ) {
        if ( (-s "$NETCONF") && (-f "$NETCONF") ) {
            if ( open( NZ, "egrep -v ^# $NETCONF |" ) ) {
                print "\n$INFOSTR Customised network setup in $NETCONF\n";
                while (<NZ>) {
                    next if grep( /^$/, $_ );
                    print $_;
                    if ( grep( /^NOZEROCONF/i, $_ ) ) {
                        $_ =~ s/^\s+//g;
                        $_ =~ s/\s+$//g;
                        ( undef, $ZEROCONF_FLAG ) = split( /=/, $_ );
                        chomp($ZEROCONF_FLAG);
                        push( @NETCONFARR, "\n$INFOSTR ZEROCONF route 169.254.0.0/16 disabled in $NETCONF\n" );
                        push( @NETCONFARR, "$_\n" );
                    }
                }

                close(NZ);
            }
            else {
                print "\n$WARNSTR Cannot open $NETCONF\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open $NETCONF\n");
            }
        }
        else {
            print "\n$INFOSTR $NETCONF empty\n";
        }
    }

    if ( "@NETCONFARR" ) {
        print @NETCONFARR;
    }

    my @ipv6addr = `ip -6 addr show 2>/dev/null`;
    if ( @ipv6addr != 0 ) {
        print "\n$INFOSTR IPv6 address status\n";
        print @ipv6addr;
    }

    my @ipv4route = `ip route 2>/dev/null`;
    if ( @ipv4route != 0 ) {
        print "\n$INFOSTR IPv4 route status\n";
        print @ipv4route;
    }

    my @ipv6route = `ip -6 route 2>/dev/null`;
    if ( @ipv6route != 0 ) {
        print "\n$INFOSTR IPv6 route status\n";
        print @ipv6route;
    }

    my @neti = `netstat -atup 2>/dev/null`;
    if ( @neti != 0 ) {
        print "\n$INFOSTR Active connections\n";
        print @neti;
    }

    my @NMCLICONN = `nmcli connection show 2>/dev/null`;
    if ( "@NMCLICONN" ) {
        print "\n$INFOSTR NetworkManager connections\n";
        print @NMCLICONN;
    }

    my @ARPA = `arp -a`;
    if ("@ARPA") {
        print "\n$INFOSTR ARP table\n";
        print @ARPA;
    }

    my @netstatg = `netstat -g 2>/dev/null`;
    if ( @netstatg != 0 ) {
        print "\n$INFOSTR IPv4/IPv6 group status\n";
        print @netstatg;
    }

    my @ssall = `ss -a 2>/dev/null`;
    if ( @ssall != 0 ) {
        print "\n$INFOSTR Socket statistics\n";
        print @ssall;
    }

    my $rxerr = q{};
    my $rxdrp = q{};
    my $rxovr = q{};
    my $txok  = q{};
    my $txerr = q{};
    my $txdrp = q{};
    my $txovr = q{};

    if ( open( NETN, "netstat -in |" ) ) {
        print "\n$INFOSTR Network errors and collisions\n";
        while (<NETN>) {
            $_ =~ s/^\s+//g;
            print $_;
            next if ( grep( /MTU/, $_ ) );

            next if ( grep( /Kernel Interface/, $_ ) );
            (
                $Lname, $Lmtu, $Lmet,  $rxok,  $rxerr, $rxdrp,
                $rxovr, $txok, $txerr, $txdrp, $txovr, $iflg
              )
              = split( /\s+/, $_ );

            if ( $Lname eq 'lo' ) {
                $DefMTU = $DefMTUlo;
            }
            else {
                $DefMTU = 1500;
            }

            if ( "$Lmtu" == $DefMTU ) {
                print
                  "$PASSSTR Interface $Lname has default MTU ($DefMTU)\n";
            }
            else {
                print
"$INFOSTR Interface $Lname has non-default MTU ($Lmtu instead of $DefMTU)\n";
            }

            if ( "$rxerr" > 0 ) {
                print "$WARNSTR Input errors on interface $Lname\n";
                push(@CHECKARR, "\n$WARNSTR Input errors on interface $Lname\n");
                $warnings++;
            }
            else {
                print "$PASSSTR No input errors on interface $Lname\n";
            }

            if ( "$txerr" > 0 ) {
                print "$WARNSTR Output errors on interface $Lname\n\n";
                push(@CHECKARR, "\n$WARNSTR Output errors on interface $Lname\n");
                $warnings++;
            }
            else {
                print "$PASSSTR No output errors on interface $Lname\n\n";
            }
        }
        close(NETN);
    }

    my @NMCLI = `nmcli nm status 2>/dev/null`;
    if ( "@NMCLI" ) {
        print "\n$INFOSTR NetworkManager status\n";
        print @NMCLI;
    }

    my @NDDarrs = `mii-tool 2>/dev/null`;
    if ( "@NDDarrs" ) {
        print "\n$INFOSTR Network interface brief status\n";
        print @NDDarrs;
    }

    my @netcardi =
`ls /etc/sysconfig/network-scripts/ifcfg-* 2>/dev/null |egrep -v "bond|ppp"`;
    if ( @netcardi != 0 ) {
        foreach $i (@netcardi) {
            chomp($i);
            print "\n$INFOSTR Network interface card $i setup\n";
            my @netif = `egrep -v ^# $i | awk NF`;
            print @netif;
        }
    }

    datecheck();
    print_header("*** END CHECKING NETWORK SETUP $datestring ***");
}

#
# Subroutine to check Unix systems accounting
#
sub sachk {
    datecheck();
    print_header("*** BEGIN CHECKING UNIX SYSTEM ACCOUNTING $datestring ***");

    if ( open( AC, "sar -A 2>/dev/null |" ) ) {
        while (<AC>) {
            print $_;
        }
        close(AC);
    }
    else {
        print "$WARNSTR Cannot run sar\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run sar\n");
    }

    if ( !-d "$UXSA" ) {
        print "\n$WARNSTR System accounting directory $UXSA missing\n";
        push(@CHECKARR, "\n$WARNSTR System accounting directory $UXSA missing\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR System accounting directory $UXSA exists\n";
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
            print "\n$WARNSTR Cannot open directory $UXSA\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open directory $UXSA\n");
        }
    }

    if ( $accnomb == 0 ) {
        print "\n$WARNSTR System accounting not running\n";
        push(@CHECKARR, "\n$WARNSTR System accounting not running\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR System accounting seemingly running\n";
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
            print "\n$WARNSTR Cannot open directory $UXSA\n";
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
            print "\n$WARNSTR System accounting last ran more than $DAYCK ";
            print "days ago\n";
            push(@CHECKARR, "\n$WARNSTR System accounting last ran more than $DAYCK ");
            push(@CHECKARR, "days ago\n");
            $warnings++;
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

    "$IsDST" == 1
      ? print
      "$INFOSTR Daylight Savings Time set to $IsDST (currently active)\n"
      : "$IsDST" == 0
      ? print
"$INFOSTR Daylight Savings Time set to $IsDST (currently not active)\n"
      : print "$INFOSTR Daylight Savings Time undefined\n";

    my $tzcur = $ENV{'TZ'};
    if ("$tzcur") {
        print "\n$INFOSTR Environment variable TZ defined\n";
        print $tzcur;
    }
    else {
        print "\n$INFOSTR Environment variable TZ not defined\n";
    }

    my $TZZ = `date '+%Z'`;
    if ("$TZZ") {
        print "\n$INFOSTR Timezone defined in $TZZ\n";
    }
    else {
        print "\n$WARNSTR Timezone not defined\n";
        push(@CHECKARR, "\n$WARNSTR Timezone not defined\n");
        $warnings++;
    }

    my $HWCLOCK = `hwclock --show`;
    if ("$HWCLOCK") {
        print "$INFOSTR Hardware clock (RTC)\n";
        print $HWCLOCK;
    }
    else {
        print "\n$WARNSTR Cannot check hardware clock (RTC)\n";
        push(@CHECKARR, "\n$WARNSTR Cannot check hardware clock (RTC)\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING TIMEZONE $datestring ***");
}

#
# Subroutine to check dynamic linker run-time bindings
#
sub ldconfig_info {
    datecheck();
    print_header("*** BEGIN CHECKING DYNAMIC LINKER RUN-TIME BINDINGS $datestring ***");

    my @ldconfig = `ldconfig -vN 2>/dev/null`;
    if ( @ldconfig != 0 ) {
        print @ldconfig;
    }
    else {
        print "$INFOSTR ldconfig status not available\n";
    }

    datecheck();
    print_header("*** END CHECKING DYNAMIC LINKER RUN-TIME BINDINGS $datestring ***");
}

#
# Subroutine to check SIM
#
sub sim_info {
    datecheck();
    print_header("*** BEGIN CHECKING SYSTEMS INSIGHT MANAGER (SIM) $datestring ***");

    my @SIMarr = `mxnode -ld 2>/dev/null`;
    if ( @SIMarr != 0 ) {
        print "$INFOSTR SIM seemingly installed\n";
        print @SIMarr;

        my @SIMuser = `mxuser -lt 2>/dev/null`;
        if ( @SIMuser != 0 ) {
            print "\n$INFOSTR Users in Service Control Manager\n";
            print @SIMuser;

            my @mxauth = `mxauth -l 2>/dev/null`;
            if ( @mxauth != 0 ) {
                print "\n$INFOSTR Trusted users in Service Control Manager\n";
                print @mxauth;
            }
        }

        my @mxagentconfig = `mxagentconfig -l 2>/dev/null`;
        if ( @mxagentconfig != 0 ) {
            print "\n$INFOSTR Command Management Server agents\n";
            print @mxagentconfig;
        }

        my @mxagentconfigc = `mxagentconfig -c 2>/dev/null`;
        if ( @mxagentconfigc != 0 ) {
            print "\n$INFOSTR Command Management Server access\n";
            print @mxagentconfigc;
        }

        my @mxcert = `mxcert -ld 2>/dev/null`;
        if ( @mxcert != 0 ) {
            print "\n$INFOSTR Trusted certificates\n";
            print @mxcert;
        }

        my @mxcollection = `mxcollection -ln 2>/dev/null`;
        if ( @mxcollection != 0 ) {
            print "\n$INFOSTR Collections listed in a hierarchical tree\n";
            print @mxcollection;
        }

        my @mxgetdbinfo = `mxgetdbinfo 2>/dev/null`;
        if ( @mxgetdbinfo != 0 ) {
            print "\n$INFOSTR Database information\n";
            print @mxgetdbinfo;
        }

        my @mxglobalp = `mxglobalprotocolsettings -ld 2>/dev/null`;
        if ( @mxglobalp != 0 ) {
            print "\n$INFOSTR Global protocol settings\n";
            print @mxglobalp;
        }

        my @mxglobals = `mxglobalsettings -ld 2>/dev/null`;
        if ( @mxglobals != 0 ) {
            print "\n$INFOSTR Global settings\n";
            print @mxglobals;
        }

        my @mxinitconfig = `mxinitconfig -l 2>/dev/null`;
        if ( @mxinitconfig != 0 ) {
            print "\n$INFOSTR Current configuration status\n";
            print @mxinitconfig;
        }

        my @mxmib = `mxmib -l 2>/dev/null`;
        if ( @mxmib != 0 ) {
            print "\n$INFOSTR Registered MIBs\n";
            print @mxmib;
        }

        my @mxngroup = `mxngroup -lm 2>/dev/null`;
        if ( @mxngroup != 0 ) {
            print "\n$INFOSTR Member systems\n";
            print @mxngroup;
        }

        my @mxnodesecurity = `mxnodesecurity -l 2>/dev/null`;
        if ( @mxnodesecurity != 0 ) {
            print "\n$INFOSTR Command Management Server credentials\n";
            print @mxnodesecurity;
        }

        my @mxpassword = `mxpassword -l 2>/dev/null`;
        if ( @mxpassword != 0 ) {
            print "\n$INFOSTR Passwords stored by SIM\n";
            print @mxpassword;
        }

        my @mxreport = `mxreport -l -x report 2>/dev/null`;
        if ( @mxreport != 0 ) {
            print "\n$INFOSTR Listing of all reports\n";
            print @mxreport;
        }

        my @mxstm = `mxstm -l 2>/dev/null`;
        if ( @mxstm != 0 ) {
            print "\n$INFOSTR Listing of system type manager rules\n";
            print @mxstm;
        }

        my @mxtask = `mxtask -lt 2>/dev/null`;
        if ( @mxtask != 0 ) {
            print "\n$INFOSTR Tasks currently registered\n";
            print @mxtask;
        }

        my @mxtool = `mxtool -ld 2>/dev/null`;
        if ( @mxtool != 0 ) {
            print "\n$INFOSTR Listing of tools\n";
            print @mxtool;
        }

        my @mxtoolbox = `mxtoolbox -lt 2>/dev/null`;
        if ( @mxtoolbox != 0 ) {
            print "\n$INFOSTR Listing of toolboxes\n";
            print @mxtoolbox;
        }

        my @mxwbemsub = `mxwbemsub -l 2>/dev/null`;
        if ( @mxwbemsub != 0 ) {
            print "\n$INFOSTR Listing of WBEM subscriptions\n";
            print @mxwbemsub;
        }
    }
    else {
        print "$INFOSTR SIM seemingly not active\n";
    }

    datecheck();
    print_header("*** END CHECKING SYSTEMS INSIGHT MANAGER (SIM) $datestring ***");
}

#
# Subroutine to check Samba
#
sub samba_info {
    datecheck();
    print_header("*** BEGIN CHECKING SAMBA $datestring ***");

    my @SAMBAarr = `smbstatus 2>/dev/null |awk NF`;

    if ( @SAMBAarr != 0 ) {
        print "$INFOSTR Samba seemingly installed\n";
        print @SAMBAarr;
        my @SAMBAconf = `testparm -s 2>/dev/null |awk NF`;
        if ( @SAMBAconf != 0 ) {
            print @SAMBAconf;
        }
    }
    else {
        print "$INFOSTR Samba seemingly not active\n";
    }

    my @findsmb = `findsmb 2>/dev/null`;

    if ( @findsmb != 0 ) {
        print "\n$INFOSTR Listing of machines that respond to SMB name queries\n";
        print @findsmb;
    }

    my @SAMBAconf = `testparm -s 2>/dev/null |awk NF`;
    if ( @SAMBAconf != 0 ) {
        print "\n$INFOSTR Samba configuration check (testparm)\n";
        print @SAMBAconf;
    }

    my @samls = `ls /etc/samba/* 2>/dev/null`;
    foreach my $samcfg (@samls) {
        chomp($samcfg);
        if ( -s $samcfg ) {
            my @ssfg = `awk NF $samcfg 2>/dev/null`;
            if ( @ssfg ) {
                print "\n$INFOSTR Configuration file $samcfg\n";
                print @ssfg;
            }
        }
    }

    my @pdbe = `pdbedit -w -L 2>/dev/null`;
    if ( @pdbe ) {
        print "\n$INFOSTR Samba database of users (pdbedit)\n";
        print @pdbe;
    }

    datecheck();
    print_header("*** END CHECKING SAMBA $datestring ***");
}

#
# Subroutine to check standard Unix printing
#
sub lp_info {
    datecheck();
    print_header("*** BEGIN CHECKING STANDARD UNIX PRINTING $datestring ***");

    my @CUPSlp   = `lpinfo -v 2>&1 | egrep -vi "not found"`;
    my @LPRnglp  = `checkpc -V 2>&1 | egrep -vi "not found"`;

    if ( @CUPSlp != 0 ) {
        print "$INFOSTR CUPS printing seemingly installed\n";
        print @CUPSlp;
        $LPSTAND++;

        if ( -s "$CUPSCONF" ) {
            my @cupscat = `egrep -v ^# $CUPSCONF 2>/dev/null`;
            if ( "@cupscat") {
              print "\n$INFOSTR Configuration file $CUPSCONF\n";
               print @cupscat;
            }
        }

        if ( -s "$CUPSPR" ) {
            my @cupspr = `egrep -v ^# $CUPSPR 2>/dev/null`;
            if ( "@cupspr") {
              print "\n$INFOSTR Configuration file $CUPSPR\n";
               print @cupspr;
            }
        }
    }

    if ( @LPRnglp != 0 ) {
        print "$INFOSTR LPRng printing seemingly installed\n";
        print @LPRnglp;
        $LPSTAND++;
    }

    if ( "$LPSTAND" == 0 ) {
        print "$INFOSTR Standard LP printing seemingly installed\n";
    }

    my @hpinfo = `echo q|hp-info -i 2>/dev/null | col`;
    if ( @hpinfo ) {
        print "\n$INFOSTR HP Linux Imaging and Printing System status\n";
        print @hpinfo;
    }

    if ( "$LPSCHED" > 0 ) {
        my @LParr = `lpstat -a 2>/dev/null | egrep -vi "no entries"`;
        if ( @LParr ) {
            print "\n$INFOSTR Printing seemingly active\n";
            print @LParr;
        }
        else {
            print "\n$INFOSTR Printing enabled but queues not defined\n";

            if ( "$LPSTAND" == 0 ) {
                my $lpanalyser = "/var/adm/lp/lpana.log";
                if ( -s "$lpanalyser" ) {
                    my @lpana = `lpana | awk NF`;
                    if ( @lpana != 0 ) {
                        print
"$INFOSTR Standard LP spooler performance analysis\n";
                        print @lpana;
                    }
                }
            }
        }
    }
    else {
        print "\n$INFOSTR Printing seemingly not active\n";
    }

    datecheck();
    print_header("*** END CHECKING STANDARD UNIX PRINTING $datestring ***");
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

    if ( "$opt_o" == 1 ) {
        datecheck();
        print_header("*** BEGIN CHECKING OPENVIEW MONITORING $datestring ***");

        $opcflag = q{};

        if ( -s "$OVCONF" ) {
            if ( open( OV, "egrep -v ^# $OVCONF 2>/dev/null |" ) ) {
                print "$WARNSTR Configuration file $OVCONF\n";
                while (<OV>) {
                    chomp;
                    next if ( grep( /^$/, $_ ) );
                    if ( grep( /^OPCAGT=/, $_ ) ) {
                        ( undef, $opcflag ) = split( /=/, $_ );
                    }
                    push( @OVset, "$_\n" );
                }
                close(OV);
            }
            else {
                print "$WARNSTR Cannot open configuration file $OVCONF\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open configuration file $OVCONF\n");
                $warnings++;
            }
        }
        else {
            print "$WARNSTR Configuration file $OVCONF missing or empty\n";
            push(@CHECKARR, "\n$WARNSTR Configuration file $OVCONF missing or empty\n");
            $warnings++;
        }

        if ( -s "$OPCinfo" ) {
            if ( open( OPCI, "egrep -v ^# $OPCinfo 2>/dev/null |" ) ) {
                print "$INFOSTR Configuration file $OPCinfo\n";
                while (<OPCI>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(OPCI);
            }
            else {
                print "\n$WARNSTR Cannot open configuration file $OPCinfo\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open configuration file $OPCinfo\n");
                $warnings++;
            }
        }
        else {
            print "\n$WARNSTR Configuration file $OPCinfo missing or empty\n";
            push(@CHECKARR, "\n$WARNSTR Configuration file $OPCinfo missing or empty\n");
            $warnings++;
        }

        if ( -s "$NODEinfo" ) {
            if ( open( NODEI, "egrep -v ^# $NODEinfo 2>/dev/null |" ) ) {
                print "\n$INFOSTR Configuration file $NODEinfo\n";
                while (<NODEI>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(NODEI);
            }
            else {
                print "\n$WARNSTR Cannot open configuration file $NODEinfo\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open configuration file $NODEinfo\n");
                $warnings++;
            }
        }
        else {
            print "\n$WARNSTR Configuration file $NODEinfo missing or empty\n";
            push(@CHECKARR, "\n$WARNSTR Configuration file $NODEinfo missing or empty\n");
            $warnings++;
        }

        if ( -s "$mgrconf" ) {
            if ( open( NODEM, "egrep -v ^# $mgrconf 2>/dev/null |" ) ) {
                print "\n$INFOSTR Configuration file $mgrconf for NAT Management Server\n";
                while (<NODEM>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(NODEM);
            }
            else {
                print "\n$WARNSTR Cannot open configuration file $mgrconf\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open configuration file $mgrconf\n");
                $warnings++;
            }
        }
        else {
            print "\n$INFOSTR Configuration file $mgrconf missing or empty\n";
            push(@CHECKARR, "\n$WARNSTR Configuration file $mgrconf missing or empty\n");
            $warnings++;
        }

        my @OVver = `opcctla -type -verbose 2>/dev/null`;
        if ( @OVver != 0 ) {
            print "\n$INFOSTR OV Toolkit version\n";
            print @OVver;
        }

        @OVget = `opcagt -status 2>&1`;
        if ( @OVget != 0 ) {
            print "\n$PASSSTR OV Toolkit installed\n";
            print @OVget;
        }
        else {
            print "\n$WARNSTR OV Toolkit missing, or installed but not running\n";
            $warnings++;
        }

        if ( "$opcflag" == 1 ) {
            print "\n$PASSSTR OV startup defined in $OVCONF\n";
        }
        else {
            print "\n$WARNSTR OV startup not defined in $OVCONF\n";
            $warnings++;
        }
        print @OVset;

        my @tocheck1 = `itochecker_agt -1 2>/dev/null`;

        if ( @tocheck1 ) {
            if ( -s "$ITOres" ) {
                my @prITOres = `awk NF $ITOres`;
                if ( "@prITOres" ) {
                    print "\n$INFOSTR OV Toolkit system environment check\n";
                    print @prITOres;
                }
            }
        }

       if ( -s "$ITOres" ) {
            unlink $ITOres;
        }

        my @tocheck2 = `itochecker_agt -2 2>/dev/null`;

        if ( @tocheck2 ) {
            if ( -s "$ITOres" ) {
                my @prITOres = `awk NF $ITOres`;
                if ( "@prITOres" ) {
                    print "\n$INFOSTR OV Toolkit log and configuration check\n";
                    print @prITOres;
                }
            }
        }

        my @ovcluster = `ovclusterinfo -a 2>/dev/null`;
        if ( @ovcluster ) {
            print "\n$INFOSTR OVclusterinfo summary\n";
            print @ovcluster;
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
}

#
# Subroutine to check vendor backup configuration
#
sub vendorbck {
    datecheck();
    print_header("*** BEGIN CHECKING VENDOR-BASED BACKUPS $datestring ***");

    -d "$NETBCKDIR1"     ? $NETBCKDIR = $NETBCKDIR1
      : -d "$NETBCKDIR2" ? $NETBCKDIR = $NETBCKDIR2
      : print "$INFOSTR NetBackup seemingly not installed\n";

    if ("$NETBCKDIR") {
        my $NETBCKVER  = "$NETBCKDIR/netbackup/version";
        my $NETBCKCONF = "$NETBCKDIR/netbackup/bp.conf";

        if ( -s "$NETBCKCONF" ) {
            if ( open( CRM, "awk NF $NETBCKCONF |" ) ) {
                print "$INFOSTR NetBackup seemingly installed\n";
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
            if ( open( BRM, "awk NF $NETBCKVER |" ) ) {
                print "$INFOSTR NetBackup version\n";
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

    if ( -x "$NETWKCONF" ) {
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

        my @dpck = `omnicellinfo -cell 2>&1 | awk NF`;
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

        my @dpck1 = `omnicc 2>&1 | awk NF`;
        if (@dpck1) {
            print "\n$INFOSTR Data Protector client configuration status\n";
            print @dpck1;
        }

        my @dptapeck = `devbra -dev 2>&1 | awk NF`;
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

    if ( -s "$DUMPDATES" ) {
        my @ddck = `cat $DUMPDATES`;
        if (@ddck) {
            print "\n$INFOSTR DUMP-based backups status\n";
            print @ddck;
        }
    }
    else {
        print "\n$INFOSTR DUMP-based backups seemingly not running\n";
    }

    datecheck();
    print_header("*** END CHECKING VENDOR-BASED BACKUPS $datestring ***");
}

#
# Subroutine to check global PATH
#
sub pathcheck {
    if ( $DIST ne 'Debian' ) {
        datecheck();
        print_header("*** BEGIN CHECKING GLOBAL ENVIRONMENT VARIABLES $datestring ***");

        if ( $DIST eq 'SuSE' ) {
            $initconf = '/etc/sysconfig/hardware/scripts/functions';
        }

        if ( open( XV, "awk NF $initconf 2>/dev/null |" ) ) {
            print "$INFOSTR Configuration file $initconf\n";
            while (<XV>) {
                next if ( grep( /^#/, $_ ) );
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(XV);
        }
        else {
            print "$WARNSTR Configuration file $initconf missing\n";
            push(@CHECKARR, "\n$WARNSTR Configuration file $initconf missing\n");
        }

        datecheck();
        print_header("*** END CHECKING GLOBAL ENVIRONMENT VARIABLES $datestring ***");
    }
}

#
# Subroutine to check LOCALE
#
sub localecheck {
    datecheck();
    print_header("*** BEGIN CHECKING LOCALES $datestring ***");

    @alllocales = `locale -a`;

    if ( @alllocales != 0 ) {
        print "$INFOSTR Available locales\n";
        print @alllocales;
    }

    @loccur = `locale`;

    if ( @loccur != 0 ) {
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
# Subroutine to check IPSec
#
sub IPseccheck {
    datecheck();
    print_header("*** BEGIN CHECKING IPSEC $datestring ***");
    if ( open( IG, "ipsec verify 2>/dev/null | awk NF |" ) ) {
        while (<IG>) {
            print $_;
        }
        close(IG);

        if ("$IPsecversion") {
            print "$INFOSTR IPSec version $IPsecversion installed\n";
        }
        else {
            print "$INFOSTR IPSec seemingly not installed\n";
        }

        my @ipsec_conf   = `ipsec showdefaults 2>/dev/null`;
        my @ipsec_report = `ipsec setup status 2>/dev/null`;

        if ( @ipsec_conf != 0 ) {
            print "$INFOSTR IPSec configuration\n";
            print @ipsec_conf;
        }

        if ( @ipsec_report != 0 ) {
            print "$INFOSTR IPSec report\n";
            print @ipsec_report;
        }
    }
    else {
        print "$INFOSTR IPSec seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING IPSEC $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING NSA SECURITY-ENHANCED LINUX (SELINUX) $datestring ***");

    if ( "@pss") {
        print "$INFOSTR Processes with security data\n";
        print "@HEADLN[ 1 .. $#HEADLN ]\n";
        print @pss;
    }
    else {
        print "$INFOSTR There are no processes with security data\n";
    }

    my @sestatus = `sestatus -v 2>/dev/null`;
    if ( @sestatus != 0 ) {
        print "\n$INFOSTR SELinux sestatus for files\n";
        print @sestatus;
    }

    my @sestatusb = `sestatus -b 2>/dev/null`;
    if ( @sestatusb != 0 ) {
        print "\n$INFOSTR SELinux sestatus for Booleans\n";
        print @sestatusb;
    }

    my @getenforce = `getenforce 2>/dev/null`;
    if ( @getenforce != 0 ) {
        print "\n$INFOSTR SELinux getenforce\n";
        print @getenforce;
    }

    my @semodule = `semodule -l 2>/dev/null`;

    if ( @semodule != 0 ) {
        print "\n$INFOSTR SELinux policy modules\n";
        print @sestatus;
    }

    my @semanagef = `semanage fcontext -l 2>/dev/null`;

    if ( @semanagef != 0 ) {
        print "\n$INFOSTR SELinux file types\n";
        print @semanagef;
    }

    my @getsebool = `getsebool -a 2>/dev/null`;

    if ( @getsebool != 0 ) {
        print "$INFOSTR SELinux boolean values\n";
        print @getsebool;
    }

    my @avcstat = `avcstat 2>/dev/null`;

    if ( @avcstat != 0 ) {
        print "$INFOSTR SELinux AVC statistics\n";
        print @avcstat;
    }

    if ( ( -s "$SESTATUSCONF" ) && ( -T "$SESTATUSCONF" ) ) {
        if ( open( SIG, "egrep -v ^# $SESTATUSCONF  | awk NF |" ) ) {
            print "\n$INFOSTR Configuration file $SESTATUSCONF\n";
            while (<SIG>) {
                print $_;
            }
            close(SIG);
        }
        else {
            print "\n$INFOSTR Configuration file $SESTATUSCONF missing or empty\n";
        }
    }

    if ( ( -s "$SELINUXCONF" ) && ( -T "$SELINUXCONF" ) ) {
        if ( open( IG, "egrep -v ^# $SELINUXCONF  | awk NF |" ) ) {
            print "\n$INFOSTR Configuration file $SELINUXCONF\n";
            while (<IG>) {
                print $_;
            }
            close(IG);
        }
        else {
            print "$INFOSTR Configuration file $SELINUXCONF missing or empty\n";
        }
    }

    datecheck();
    print_header("*** END CHECKING NSA SECURITY-ENHANCED LINUX (SELINUX) $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING IPTABLES AND FIREWALL $datestring ***");

    if ( open( IG, "iptables -L -v --line-numbers 2>&1 | awk NF |" ) ) {
        while (<IG>) {
            print $_;
        }
        close(IG);
    }
    else {
        print "$INFOSTR Iptables seemingly not installed\n";
    }

    my @UFWS = `ufw status 2>/dev/null`;

    if ( @UFWS != 0 ) {
        print "\n$INFOSTR Netfilter firewall status\n";
        print @UFWS;

        my @UFWA = `ufw app list 2>/dev/null`;

        if ( @UFWA != 0 ) {
            print "\n$INFOSTR Applications available in Netfilter\n";
            print @UFWA;
        }
    }
    else {
        print "\n$INFOSTR Netfilter firewall seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING IPTABLES AND FIREWALL $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING IPCHAINS $datestring ***");

    if ( -s "$IPCHAINS" ) {
        if (
            open( IG, "/etc/init.d/ipchains status 2>/dev/null | awk NF |" ) )
        {
            while (<IG>) {
                print $_;
            }
            close(IG);
        }
        else {
            print "$INFOSTR Ipchains seemingly not installed\n";
        }
    }
    else {
        print "$INFOSTR Ipchains seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING IPCHAINS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING OPENVPN $datestring ***");

    if ( $OPENVPN_FLAG > 0 ) {
        my @openvpnstat = `/etc/init.d/openvpn status 2>/dev/null`;
        if ( "@openvpnstat" ) {
            print "$INFOSTR OpenVPN seemingly installed\n";
            print @openvpnstat;
        }
        else {
            print "$INFOSTR OpenVPN seemingly installed but not active\n";
        }
    }
    else {
            print "$INFOSTR OpenVPN seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING OPENVPN $datestring ***");
}

#
# Subroutine to check drivers
#
sub lsdevcheck {
    datecheck();
    print_header("*** BEGIN CHECKING LSDEV (DRIVERS) $datestring ***");

    my @lsdevls = `lsdev`;

    if ( @lsdevls != 0 ) {
        print @lsdevls;
    }
    else {
        print "$INFOSTR Lsdev not applicable\n";
    }

    datecheck();
    print_header("*** END CHECKING LSDEV (DRIVERS) $datestring ***");
}

#
# Subroutine to check third-party licensing software
#
sub liccheck {
    datecheck();
    print_header("*** BEGIN CHECKING THIRD-PARTY LICENSE MANAGERS $datestring ***");

    if ( "$LICENSE" > 0 ) {
        print
"$INFOSTR Third-party license manager might be running (please check it manually)\n";
        print @licdaemon;
    }

    if ( (-s "$ovnnmlic" ) && ( -T "$ovnnmlic" ) ) {
        print "\n$INFOSTR network Node Manager file $ovnnmlic exists\n";
        my @NNMLIC = `cat $ovnnmlic`;
        print @NNMLIC;
    }
    else {
        print "\n$INFOSTR Network Node Manager $ovnnmlic does not exist\n";
    }

    datecheck();
    print_header("*** END CHECKING THIRD-PARTY LICENSE MANAGERS $datestring ***");

    my @vxlicrep = `vxlicrep 2>/dev/null`;

    if ("@vxlicrep") {
        datecheck();
        print_header("*** BEGIN CHECKING VERITAS LICENSES $datestring ***");

        print @vxlicrep;

        datecheck();
        print_header("*** END CHECKING VERITAS LICENSES $datestring ***");
    }

    if ("$NETBCKDIR") {
        $ENV{'PATH'} = "$ENV{PATH}:$NETBCKDIR/netbackup/bin/admincmd";
        $ENV{'PATH'} = "$ENV{PATH}:$NETBCKDIR/netbackup/bin/goodies";

        datecheck();
        print_header("*** BEGIN CHECKING NETBACKUP LICENSES $datestring ***");
        if ( open( VV, "bpminlicense -list_keys |" ) ) {
            while (<VV>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(VV);
        }
        else {
            if ( open( VVC, "get_license_key -L keys |" ) ) {
                print "\n$INFOSTR NetBackup get_license_key\n";
                while (<VVC>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(VVC);
            }
        }

        datecheck();
        print_header("*** END CHECKING NETBACKUP LICENSES $datestring ***");
    }

    my @tsmlic = `query license 2>/dev/null`;
    if (@tsmlic) {
        datecheck();
        print_header("*** BEGIN CHECKING TIVOLI STORAGE MANAGER LICENSES $datestring ***");

        print @tsmlic;

        datecheck();
        print_header("*** END CHECKING TIVOLI STORAGE MANAGER LICENSES $datestring ***");
    }

    my @DPCW = `omnicc -check_licenses -detail 2>/dev/null`;
    if ( "@DPCW" ) {
        datecheck();
        print_header("*** BEGIN CHECKING DATA PROTECTOR LICENSES $datestring ***");

        print @DPCW;

        datecheck();
        print_header("*** END CHECKING DATA PROTECTOR LICENSES $datestring ***");
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
sub LDAPcheck {
    if ( "$LDAPSERVER" > 0 ) {
        if ( $NSADMIN > 0 ) {
            datecheck();
            print_header("*** BEGIN CHECKING NETSPACE LDAP $datestring ***");

            print "$INFOSTR Netscape LDAP server seemingly running\n";
            print @ldapdaemon;

            datecheck();
            print_header("*** END CHECKING NETSPACE LDAP $datestring ***");
        } else
        {
            datecheck();
            print_header("*** BEGIN CHECKING OPENLDAP $datestring ***");

            my @slapddef = `cat $SLAPDDEF 2>/dev/null`;

            if ( "\@slapddef" ) {
                print "\n$INFOSTR SLAPD config file $SLAPDDEF\n";
                print @slapddef;
                print "\n";
            }

            if ( ( -s "$sldap_conf" ) && ( -T "$sldap_conf" ) ) {
                if ( open( SLDP, "awk NF $sldap_conf |" ) ) {
                    print "$INFOSTR LDAP server config file $sldap_conf\n";
                    while (<SLDP>) {
                        print $_;
                    }
                }
                close(SLDP);
            }
            else {
                print
"$INFOSTR Cannot open LDAP server client config file $sldap_conf\n";
            }

            my @slaptest = `slaptest -v -d 3 2>/dev/null`;

            if ( "\@slaptest" ) {
                print "\n$INFOSTR Slaptest results\n";
                print @slaptest;
            }

            my @slapcat = `slapcat 2>/dev/null`;

            if ( "\@slapcat" ) {
                print "\n$INFOSTR SLAPD database to LDIF export (slapcat)\n";
                print @slapcat;
                print "\n";
            }

            my @ldapsearch = `ldapsearch -x -Z 2>/dev/null`;

            if ( "\@ldapsearch" ) {
                print "\n$INFOSTR LDAP search\n";
                print @ldapsearch;
            }

            my @ldapsearch2 = `ldapsearch -x -s base -b "" supportedSASLMechanisms 2>/dev/null`;

            if ( "\@ldapsearch2" ) {
                print "\n$INFOSTR LDAP supported SASL mechanisms\n";
                print @ldapsearch2;
            }

            my @sasldbusers2 = `sasldblistusers2 2>/dev/null`;

            if ( "\@sasldbusers2" ) {
                print "\n$INFOSTR SASL DB users\n";
                print @sasldbusers2;
            }

            datecheck();
            print_header("*** END CHECKING OPENLDAP $datestring ***");
        }
    }

    datecheck();
    print_header("*** BEGIN CHECKING LDAP CLIENT $datestring ***");

    if ( ( -s "$ldap2_conf" ) && ( -T "$ldap2_conf" ) ) {
        if ( open( LDP, "awk NF $ldap2_conf |" ) ) {
            print "\n$INFOSTR LDAP client config file $ldap2_conf\n";
            while (<LDP>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
        close(LDP);
    }
    else {
        print
"\n$INFOSTR Cannot open LDAP client config file $ldap2_conf\n";
    }

    if ( ( -s "$ldap3_conf" ) && ( -T "$ldap3_conf" ) ) {
        if ( open( LDP, "awk NF $ldap3_conf |" ) ) {
            print "\n$INFOSTR LDAP client config file $ldap3_conf\n";
            while (<LDP>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
        close(LDP);
    }
    else {
        print
"\n$INFOSTR Cannot open LDAP client config file $ldap3_conf\n";
    }

    if ( ( -s "$ldap_conf" ) && ( -T "$ldap_conf" ) ) {
        if ( open( LDP, "awk NF $ldap_conf |" ) ) {
            print "\n$INFOSTR LDAP config file $ldap_conf\n";
            while (<LDP>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
        close(LDP);
    }
    else {
        print "\n$INFOSTR Cannot open LDAP config file $ldap_conf\n";
    }

    datecheck();
    print_header("*** END CHECKING LDAP CLIENT $datestring ***");
}

#
# Subroutine to check shared memory and semaphores
#
sub IPCScheck {
    datecheck();
    print_header("*** BEGIN CHECKING INTERPROCESS COMMUNICATION FACILITIES $datestring ***");

    my @ipcsstat = `ipcs -a 2>/dev/null`;
    if ( "@ipcsstat" ) {
        print @ipcsstat;
    }

    my @ipcslim = `ipcs -ls 2>/dev/null`;
    if ( "@ipcslim" ) {
        print "\n$INFOSTR IPCS limits\n";
        print @ipcslim;
    }

    my @ipcst = `ipcs -t 2>/dev/null`;
    if ( "@ipcst" ) {
        print "\n$INFOSTR IPCS last accessed times\n";
        print @ipcst;
    }

    my @ipcsu = `ipcs -u 2>/dev/null`;
    if ( "@ipcsu" ) {
        print "\n$INFOSTR IPCS current usage\n";
        print @ipcsu;
    }

    datecheck();
    print_header("*** END CHECKING INTERPROCESS COMMUNICATION FACILITIES $datestring ***");

    my @numactl = `numactl --show 2>/dev/null`;

    if ( "@numactl" ) {
        datecheck();
        print_header("*** BEGIN CHECKING NUMA POLICY $datestring ***");

        print @numactl;

        my @numactlhw = `numactl --hardware 2>/dev/null`;
        if ( "@numactlhw" ) {
            print "\n$INFOSTR Inventory of available NUMA nodes on the system\n";
            print @numactlhw;
        }

        datecheck();
        print_header("*** END CHECKING NUMA POLICY $datestring ***");
    }
}

#
# Subroutine to check disk quotas
#
sub QUOTAcheck {
    datecheck();
    print_header("*** BEGIN CHECKING FILE SYSTEM QUOTAS $datestring ***");

    @quotastat = `quotacheck -a 2>/dev/null`;

    if ( @quotastat != 0 ) {
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

    if ("\@ulimitstat") {
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

    my @CPU_no = `awk NF /proc/cpuinfo`;

    print "@CPU_no\n";
    print @CPUarray;

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
        if ( !-d "$commdir" ) {
            print "$ERRSTR Directory $commdir does not exist\n";
            push(@CHECKARR, "\n$ERRSTR Directory $commdir does not exist\n");
            $warnings++;

            if ( "$commdir" eq "/var/tmp" ) {
                print
"$WARNSTR Without $commdir, tools like vi(1) and swinstall(1) will fail\n";
                push(@CHECKARR,
"\n$WARNSTR Without $commdir, tools like vi(1) and swinstall(1) will fail\n");
            }
        }
        else {
            if ( -k $commdir ) {
                print "$PASSSTR Directory $commdir has sticky bit\n";
            }
            else {
                print
                  "$WARNSTR Directory $commdir does not have sticky bit\n";
                push(@CHECKARR,
                  "\n$WARNSTR Directory $commdir does not have sticky bit\n");
                $warnings++;
            }
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

    my @pamls = `ls /etc/pam.d/* 2>/dev/null`;
    foreach my $pcfg (@pamls) {
        chomp($pcfg);
        if ( -s $pcfg ) {
            print "$INFOSTR Configuration file $pcfg\n";
            my @psfg = `egrep -v ^# $pcfg | awk NF`;
            print @psfg;
            print "\n";
        }
    }

    if ( -s "$pam_auth" ) {
        if ( open( I, "egrep -v ^# $pam_auth | awk NF |" ) ) {
            print "\n$INFOSTR PAM defaults in $pam_auth\n";
            while (<I>) {
                print $_;
                chomp;
                $_ =~ s/^\s+//g;
                $_ =~ s/\s+$//g;
                if ( grep( /pam_cracklib/, $_ ) ) {
                    $PAMCRACKLIB_FLAG++;
print "$PASSSTR PAM password checks enabled (pam_cracklib)\n";
                }
            }
            close(I);

            if ( $PAMCRACKLIB_FLAG == 0 ) {
                print
"$WARNSTR PAM password checks disabled (pam_cracklib missing)\n";
                push(@CHECKARR,
"\n$WARNSTR PAM password checks disabled (pam_cracklib missing)\n");
                $warnings++;
            }
        }
    }
    else {
         print "\n$WARNSTR Configuration file $pam_auth missing or empty\n";
         push(@CHECKARR, "\n$WARNSTR Configuration file $pam_auth missing or empty\n");
         $warnings++;
    }

     if ( $DIST ne 'Debian' ) {
        if ( -s "$pam_conf" ) {
            my @PAMST = `awk NF $pam_conf`;
            if ("@PAMST") {
                print "\n$INFOSTR PAM config file $pam_conf\n";
                print @PAMST;
            }
            else {
                print "\n$WARNSTR PAM config file $pam_conf empty or missing\n";
                push(@CHECKARR, "\n$WARNSTR PAM config file $pam_conf empty or missing\n");
                $warnings++;
            }
        }
    }
    else {
        print "$WARNSTR PAM config file $pam_conf empty or missing\n";
        push(@CHECKARR, "\n$WARNSTR PAM config file $pam_conf empty or missing\n");
        $warnings++;
    }

    my @pamcfg = `pam-config --list-modules 2>/dev/null`;
    if ( "@pamcfg" ) {
        print "\n$INFOSTR List of supported PAM modules\n";
        print @pamcfg;
    }

    datecheck();
    print_header("*** END CHECKING PAM CONFIGURATION $datestring ***");
}

#
# Subroutine to check Host Intrusion Detection System (HIDS)
#
sub HIDScheck {
    datecheck();
    print_header("*** BEGIN CHECKING HOST INTRUSION DETECTION SYSTEM $datestring ***");

    my $esmdirhost = "/esm/system/$Hostname";
    my @ESMarr     = ();

    if ( -s "$esmmgr" ) {
        if ( open( ESMAY, "egrep -v ^# $esmmgr | awk NF |" ) ) {
            while (<ESMAY>) {
                next if ( grep( /^$/, $_ ) );
                push( @ESMfull, $_ );
                $_ =~ s/^\s+//g;
                ( $esmid, undef ) = split( /\s+/, $_ );
                chomp($esmid);
                push( @ESMarr, $esmid );
            }
            close(ESMAY);
            $IDS_FLAG++;
        }
    }

    if ( -s "$esm" ) {
        if ( open( ESP, "egrep -v ^# $esm | awk NF |" ) ) {
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
            $IDS_FLAG++;
        }
    }

    $esmport = $ESMport || $esmportdef;

    if ( -s "$aide_conf" ) {
        my @aidecheck = `awk '! /^#/ && ! /awk/ {print}' $aide_conf | awk NF`;
        if ("@aidecheck") {
            print "\n$INFOSTR AIDE seemingly configured ($aide_conf)\n";
            print @aidecheck;

            my @aidev = `aide -v 2>&1 | egrep -v "command not found" | awk NF`;
            if ( @aidev != 0 ) {
                print "\n$INFOSTR AIDE status\n";
                print @aidev;
            }
        }
    }

    my @twcheck = `twadmin --print-cfgfile 2>/dev/null`;
    if ( @twcheck != 0 ) {
        print "\n$INFOSTR Tripwire seemingly configured\n";
        print @twcheck;
    }
    else {
        print "\n$INFOSTR Tripwire seemingly not configured\n";
    }

    if ( "$ESMD_FLAG" == "0" ) {
        print
"\n$INFOSTR Symantec Enterprise Security Manager seemingly not configured\n";
    }
    else {
        print
"\n$INFOSTR Symantec Enterprise Security Manager seemingly configured\n";
    }

    if ( @ESMfull != 0 ) {
        print "\n$INFOSTR ESM manager config file $esmmgr\n";
        print @ESMfull;
    }

    if ( @ESMportarr != 0 ) {
        print
"\n$INFOSTR Symantec Enterprise Security Manager Agent seemingly configured\n";
        print @ESMportarr;
        foreach $ESM_server (@ESMarr) {
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
        @esmstart = `cat $esmrc| awk NF`;
        print "\n$INFOSTR Symantec ESM startup file $esmrc\n";
        print @esmstart;
    }

    datecheck();
    print_header("*** END CHECKING HOST INTRUSION DETECTION SYSTEM $datestring ***");
}

sub liccalc {
    $LICENSE++;
    push( @licdaemon, "$_\n" );
}

sub swcalc {
    my $acst2 = shift;
    print "$INFOSTR $acst2 not installed\n";
#    push(@CHECKARR, "\n$WARNSTR $acst2 not installed\n");
#    $warnings++;
}

sub ldapcalc {
    $LDAPSERVER++;
    push( @ldapdaemon, "$_\n" );
}

sub nsadmcalc {
    $NSADMIN++;
    push( @ldapdaemon, "$_\n" );
}

sub esmcalc {
    $ESMD_FLAG++;
    $IDS_FLAG++;
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
sub rawpscheck {
    # Under XPG4 (Unix95), "-H" flag option gives pstree-line results
    #
    if ( "$ENV{'UNIX95'}" == 1 ) {
        $pstreeflag = "H";
    }
    else {
        $pstreeflag = q{};
    }

    if ( open( KM, "ps auxwZ$pstreeflag |" ) ) {
        while (<KM>) {
            push( @allprocesses, $_);
            $_ =~ s/\s+$//g;
            $psline = $_;
            chomp $psline;

            if ( $psline =~ /TIME.*COMMAND/ ) {
                @HEADLN = $psline;
            }
            else {
                @userid = split(/\s+/, $psline);
            }

            if( ($userid[0] ne "-" ) && !($psline =~ /TIME.*COMMAND/) ) {
               push(@pss, "@userid[ 1 .. $#userid ]\n");
            }

            if ( $userid[8] =~ /^S/ ) {
               push(@PSSLEEP, "@userid\n");
            }
            elsif ( $userid[8] =~ /^D/ ) {
               push(@PSUNINTSLEEP, "@userid\n");
            }
            elsif ( $userid[8] =~ /^R/ ) {
               push(@PSRUN, "@userid\n");
            }
            elsif ( $userid[8] =~ /^T/ ) {
               push(@PSSTOP, "@userid\n");
            }
            elsif ( $userid[8] =~ /^W/ ) {
               push(@PSPAGE, "@userid\n");
            }
            elsif ( $userid[8] =~ /^X/ ) {
               push(@PSDEAD, "@userid\n");
            }
            elsif ( $userid[8] =~ /^Z/ ) {
               push(@PSZOMBIE, "@userid\n");
            }
            else {
               if ( "@userid" ) {
                   push(@PSREST, "@userid\n");
               }
            }

            if( $userid[1] =~ /^[0-9]+$/ ) {
                push(@PSARR,
"$WARNSTR Process \"$psline\" owned by numeric UID or not defined in password database (\"$userid[1]\")\n");
                push(@CHECKARR,
"$WARNSTR Process \"$psline\" owned by numeric UID or not defined in password database (\"$userid[1]\")\n");
                $warnings++;
            }

            grep( /cmcld/,                            $_ ) ? $SGRUN++
              : grep(
                /emcpdaemon|emcpProcd|emspd|emcpstratd|emcpwdd|emcpdfd/i,
                                                      $_ ) ? $EMCP_FLAG++
              : grep( /auditd/,                       $_ ) ? $AUDIT_FLAG++
              : grep( /xfs|xinit/,                    $_ ) ? $XWIN_FLAG++
              : grep( /ldapclientd/,                  $_ ) ? $LDAPCLIENT++
              : grep( /idsagent/,                     $_ ) ? $IDS_FLAG++
              : grep( /automount/,                    $_ ) ? $AUTO_FLAG++
              : grep( /dnsmasq/,                      $_ ) ? $DNSMASQ_FLAG++
              : grep( /cmclconfd|cmlogd/,             $_ ) ? $SGRUN++
              : grep( /cmlockund|cmomd|cmsrvassistd/, $_ ) ? $SGRUN++
              : grep( /cmresmond/,                    $_ ) ? $SGRUN++
              : grep( /slapd|slurpd/,                 $_ ) ? ldapcalc()
              : grep( /ns-admin/,                     $_ ) ? nsadmcalc()
              : grep( /lmgrd|netlsd|i4lmd/,           $_ ) ? liccalc()
              : grep( /esmd|esmnetd|esmcifd/,         $_ ) ? esmcalc()
              : grep( /spagent/,                      $_ ) ? $SECPATHAG++
              : grep( /puppetmasterd|puppet master/,  $_ ) ? $PUPPETMASTER++
              : grep( /puppetd|puppet agent/,         $_ ) ? $PUPPETCLIENT++
              : grep( /cfservd|cf-serverd/,           $_ ) ? $CFENGINEMASTER++
              : grep( /cfagent|cf-agent/,             $_ ) ? $CFENGINECLIENT++
              : grep( /lpsched|lpd/,                  $_ ) ? $LPSCHED++
              : grep( /cupsd/,                        $_ ) ? $LPSCHED++
              : grep( /dsmc/,                         $_ ) ? $TSMCL_FLAG++
              : grep( /dsmserv/,                      $_ ) ? $TSMSRV_FLAG++
              : grep( /syslogd|rsyslogd/,             $_ ) ? $SYSLOGD_FLAG++
              : grep( /named/,                        $_ ) ? push( @DNSRUN, "$_\n" )
              : grep( /squid/,                        $_ ) ? push( @SQUIDRUN, "$_\n" )
              : grep( /httpd/,                        $_ ) ? push( @HTTPDRUN, "$_\n" )
              : grep( /apache|apache2/,               $_ ) ? push( @HTTPDRUN, "$_\n" )
              : grep( /tomcat/,                       $_ ) ? $TOMCAT_FLAG++
              : grep( /nginx.*master|nginx.*worker/,  $_ ) ? $NGINX_FLAG++
              : grep( /ntpd/,                         $_ ) ? push( @ntpdaemon, "$_\n" )
              : grep( /chronyd/,                      $_ ) ? push( @chronydaemon, "$_\n" )
              : grep( /nfsd/,                         $_ ) ? push( @nfsdaemon, "$_\n" )
              : grep( /sendmail/,                     $_ ) ? $SENDMAIL_FLAG++
              : grep( /exim/,                         $_ ) ? $EXIM_FLAG++
              : grep( /postfix/,                      $_ ) ? $POSTFIX_FLAG++
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
# Subroutine to check Kickstart config
#
sub kickstart {
    if ( ( $DIST eq 'RedHat' ) || ( $DIST eq 'Fedora' )  || ( $DIST eq 'Oracle' )) {
        datecheck();
        print_header("*** BEGIN CHECKING KICKSTART $datestring ***");

        if ( -s "$KICKSTART" ) {
            my @ks = `cat $KICKSTART 2>/dev/null`;
            if ( "@ks" ) {
                print "$INFOSTR Kickstart config $KICKSTART\n";
                print @ks;
            }
        }
        else {
            print "$INFOSTR Kickstart config $KICKSTART does not exist, empty or not applicable to this Linux distribution\n";
        }

        datecheck();
        print_header("*** END CHECKING KICKSTART $datestring ***");
    }

    if ( $DIST eq 'SuSE' ) {
        datecheck();
        print_header("*** BEGIN CHECKING YAST $datestring ***");

        my @YASTCFGARR = ( "/etc/sysconfig/yast", "/etc/sysconfig/yast2", );
        foreach my $yastfile (@YASTCFGARR) {
            if ( -s "$yastfile" ) {
                my @ylist = `cat $yastfile`;
                if ( @ylist ) {
                    print "$INFOSTR YAST configuration in $yastfile\n";
                    print @ylist;
                }
            }
        }

        datecheck();
        print_header("*** END CHECKING YAST $datestring ***");
    }
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

   if ( @PSUNINTSLEEP ) {
       print "$INFOSTR Processes in uninterruptible sleep (usually I/O issue)\n";
       print "@HEADLN\n";
       print @PSUNINTSLEEP;
       push(@CHECKARR, "\n$WARNSTR There are processes in uninterruptible sleep (usually I/O issue)\n");
       $warnings++;
       print "\n";
   }
 
   if ( @PSSTOP ) {
       print "$INFOSTR Stopped processes (job control or tracing)\n";
       print "@HEADLN\n";
       print @PSSTOP;
       print "\n";
   }
 
   if ( @PSPAGE ) {
       print "$INFOSTR Paging processes (should not be seen since the 2.6.xx kernel)\n";
       print "@HEADLN\n";
       print @PSPAGE;
       print "\n";
   }
 
   if ( @PSDEAD ) {
       print "$INFOSTR Dead processes (should never be seen)\n";
       print "@HEADLN\n";
       print @PSDEAD;
       push(@CHECKARR, "\n$WARNSTR There are dead processes (should never be seen)\n");
       $warnings++;
       print "\n";
   }
 
   if ( @PSZOMBIE ) {
       print "$INFOSTR Defunct (\"zombie\") processes\n";
       print "@HEADLN\n";
       print @PSZOMBIE;
       print "\n";
   }
 
   if ( @PSRUN ) {
       print "$INFOSTR Running or runable processes\n";
       print "@HEADLN\n";
       print @PSRUN;
   }

   if ( "@PSREST" ) {
       print "\n$INFOSTR Processes in non-standard states\n";
       print "@HEADLN\n";
       print @PSREST;
   }

#    if ( "@allprocesses" ) {
#        print @allprocesses;
#        print "\n";
#        print @PSARR;
#        print "\n";
#    }

    my @pidstat = `pidstat -lrud 2>/dev/null`;
    if ( "@pidstat" ) {
        print "\n$INFOSTR Statistics for tasks currently managed by Linux kernel\n";
        print @pidstat;
    }

    my @ptree = `pstree 2>/dev/null`;
    if ( "@ptree" ) {
        print "\n$INFOSTR Process tree hierarchy\n";
        print @ptree;
    }

    my @STATUSS = `status 2>/dev/null`;
    if ( @STATUSS ) {
        print "$INFOSTR Profiles\n";
        print "@STATUSS\n";
    }

    datecheck();
    print_header("*** END CHECKING UNIX PROCESSES $datestring ***");
}

#
# Subroutine to list RC scripts
#
sub RCcheck {
    datecheck();
    print_header("*** BEGIN CHECKING RC SCRIPTS $datestring ***");

    if ( $DIST eq 'SuSE' ) {
        @RCarray = ( '/etc/rc.d', );
    }

    foreach my $RCdir (@RCarray) {
        if ( -d "$RCdir" ) {
            my @RClist = `ls -1 $RCdir`;
            if ("\@RClist") {
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

    my @SYSTEMD = `systemctl status 2>/dev/null`;
   
    if ( "@SYSTEMD" ) { 
        datecheck();
        print_header("*** BEGIN CHECKING SYSTEMD $datestring ***");
 
        print "$INFOSTR Systemd current service status\n";
        print @SYSTEMD;

        my @SYSTEMB = `systemctl list-unit-files 2>/dev/null`;
        if ( "@SYSTEMB" ) { 
            print "\n$INFOSTR Systemd brief service status\n";
            print @SYSTEMB;
        }

        datecheck();
        print_header("*** END CHECKING SYSTEMD $datestring ***");
    }
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

    if ( -s "$SNMPAconf" ) {
        if ( open( SN, "egrep -v ^# $SNMPAconf | awk NF |" ) ) {
            print
              "\n$INFOSTR Active services in SNMP Agent file $SNMPAconf\n";
            while (<SN>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
    }
    else {
        print "\n$INFOSTR SNMP Agent file $SNMPAconf not defined\n";
    }
    close(SN);

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

        if ( ! -l $mmentry ) {
            find( \&mailboxsearch, $mmentry );
        }
    }

    if ( $mboxcount > 0 ) {
        print "$INFOSTR Number of mailboxes is $mboxcount\n";
    }
    else {
        print "$INFOSTR There are no mailboxes on this server\n";
    }

    datecheck();
    print_header("*** END CHECKING MAILBOX STATUS $datestring ***");

    if ( "$opt_c" == 1 ) {
        datecheck();
        print_header("*** BEGIN CHECKING BASIC FILE SECURITY $datestring ***");

        find( \&dirsearch, @directories_to_search );

        datecheck();
        print_header("*** BEGIN CHECKING BASIC FILE SECURITY $datestring ***");
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
        if ( (-d $File::Find::name) && (! -l $File::Find::name) ) {
            print "$WARNSTR Mailbox $File::Find::name is a directory\n";
            push(@CHECKARR, "\n$WARNSTR Mailbox $File::Find::name is a directory\n");
            $warnings++;
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
                    print "$INFOSTR Mailbox $File::Find::name size is ", int($msize/1024), " KB\n";
                }
                print "\n";
            }
        }
    }
}

#
# Check device file conflicts
#
sub DevFilecheck {
    datecheck();
    print_header("*** BEGIN CHECKING DEVICE MAJOR AND MINOR NUMBER STATUS $datestring ***");
    find( \&devsearch, "/dev" );

    if ( "@FINDUP") {
        print "$INFOSTR Multiple devices with identical major/minor numbers\n";
        print " @FINDUP";
    }

    datecheck();
    print_header("*** END CHECKING DEVICE MAJOR AND MINOR NUMBER STATUS $datestring ***");
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

    next if grep(/^\/proc/, "$File::Find::dir" );

    if ( (-f $File::Find::name) && ($_ eq 'core') ) {
        print "$INFOSTR Possibly a core file $File::Find::name\n";
    }

    -u && print "$INFOSTR SUID file: $File::Find::name\n";
    -g && print "$INFOSTR SGID file: $File::Find::name\n";
    if ( ! -d $File::Find::name ) {
        -z && print "$INFOSTR Zero-size file: $File::Find::name\n";
    }
    -l && !-e && print
      "$WARNSTR Invalid symbolic link: $File::Find::name\n";

    if ( ! -l $File::Find::name ) {
        if ( !( grep( /\b$sgid\b/, @Grnumarr ) ) ) {
            print "$WARNSTR Missing group ownership: $File::Find::name\n";
            push(@CHECKARR, "\n$WARNSTR Missing group ownership: $File::Find::name\n");
        }

        if ( !( grep( /\b$suid\b/, @Passnumarr ) ) ) {
            print "$WARNSTR Missing user ownership: $File::Find::name\n";
            push(@CHECKARR, "\n$WARNSTR Missing user ownership: $File::Find::name\n");
        }
    }
}

#
# Check Xwindows/CDE
#
sub Xcheck {
    datecheck();
    print_header("*** BEGIN CHECKING XWINDOWS AND CDE STATUS $datestring ***");

    if ( -s $XWMDEF ) {
        my @xwmd = `cat $XWMDEF 2>/dev/null`;
        if ("@xwmd") {
            print "\n$INFOSTR Default Window Manager\n";
            print "@xwmd\n";
        }
    }

    if ( -s "$XORGCONF" ) {
        if ( open( XORG, "egrep -v ^# $XORGCONF 2>/dev/null |" ) ) {
            print "$INFOSTR Checking $XORGCONF\n";
            while (<XORG>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(XORG);
            print "\n";
         }
    }

    if ( -s "$XINIT" ) {
        if ( open( XINT, "egrep -v ^# $XINIT 2>/dev/null |" ) ) {
            print
"$INFOSTR Checking if graphical interface enabled at boot in $XINIT\n";
            while (<XINT>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                chomp($_);
                $_ =~ s/^\s+//g;
                $_ =~ s/\s+$//g;
                if ( grep( /^GRAPHICAL/, $_ ) ) {
                    (undef, $GRAPHval) = split ( /=/, $_ );
                    $GRAPHval =~ s/^\s+//g;
                    lc($GRAPHval) eq 'yes' ?
                    push(@CHECKARR, "\n$WARNSTR Graphical interface enabled at boot\n")
                    : lc($GRAPHval) eq 'no' ?  print
"$PASSSTR Graphical interface disabled at boot\n"
                    : 1;
                }
            }
            close(XINT);
        }
        if ( ! "$GRAPHval" ) {
            print "$WARNSTR GRAPHICAL entry missing in $XINIT\n";
        }
    }

    if ( $XWIN_FLAG > 0 ) {
        if ( open( XFS, "/etc/init.d/xfs status 2>/dev/null |" ) ) {
            while (<XFS>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(XFS);
        }
    }

    my @glxinfo = `glxinfo 2>/dev/null`;
    if ("@glxinfo") {
        print "\n$INFOSTR GLX status (glxinfo)\n";
        print @glxinfo;
    }

    my @fcc = `fc-list 2>/dev/null`;
    if ("@fcc") {
        print "\n$INFOSTR Available fonts via Fontconfig\n";
        print "@fcc\n";
    }

    my @xlsfonts = `xlsfonts 2>/dev/null`;
    if ("@xlsfonts") {
        print "\n$INFOSTR X Server font listing\n";
        print "@xlsfonts\n";
    }

    if ( "$ENV{'DISPLAY'}" ne '' ) {
        print "\n$INFOSTR Environment variable DISPLAY set\n";
        print "$ENV{'DISPLAY'}\n";

        my @xhost = `xhost 2>/dev/null`;
        if ("@xhost") {
            print "\n$INFOSTR Host-based ACLs (xhost) for X Server\n";
            print "@xhost\n";
        }

        my @xauth = `xauth list 2>/dev/null`;
        if ("@xauth") {
            print "\n$INFOSTR Token-based ACLs (xauth) for X Server\n";
            print "@xauth\n";
        }
    }

    print "\n";
    checkActivePorts(6000);
    checkActivePorts(7000);

    datecheck();
    print_header("*** END CHECKING XWINDOWS AND CDE STATUS $datestring ***");

    if ( "$opt_f" == 1 ) {
        datecheck();
        print_header("*** BEGIN CHECKING NMAP PORT SCAN $datestring ***");

        my @TCPSCANTEST = `nmap -O -sS -p1-65535 $Hostname 2>/dev/null | awk NF`;
        my @UDPSCANTEST = `nmap -sU -p1-65535 $Hostname 2>/dev/null | awk NF`;

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
        print_header("*** END CHECKING NMAP PORT SCAN $datestring ***");
    }
}

sub SRAIDcheck {
    datecheck();
    print_header("*** BEGIN RAID CHECKS $datestring ***");

    my @mdscan = `mdadm --examine --brief --scan --config=partitions`;
    my @mdpart = `mdadm -Ebsc partitions`;
    my @dmraid = `dmraid -r 2>/dev/null |egrep -vi "no software"`;
    my @raidtab = `egrep -v ^# /etc/raidtab 2>/dev/null | awk NF`;

    if ("@mdcheck") {
        print "\n$INFOSTR Software RAID status\n";
        print @mdcheck;

        if ("@raidtab") {
            print "\n$INFOSTR RAID configuration file /etc/raidtab\n";
            print @raidtab;
        }

        if ("@mdscan") {
            print "\n$INFOSTR Software RAID scan\n";
            print @mdscan;
        }

        if ("@mdpart") {
            print "\n$INFOSTR Software RAID brief listing\n";
            print @mdpart;
        }

        my @mdlist = `find /dev -name 'md*' 2>/dev/null`;
        foreach my $mdentry (@mdlist) {
            chomp($mdentry);
            my @mdaa = `mdadm --misc --detail $mdentry 2>/dev/null`;
            if ( @mdaa != 0 ) {
                print "$INFOSTR Software RAID detailed status\n";
                print @mdaa;
            }
        }
    }

    if ("@dmraid") {
        print "\n$INFOSTR Software ATA RAID status\n";
        print @dmraid;
    }

    datecheck();
    print_header("*** END RAID CHECKS $datestring ***");
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

#
# Subroutine to check file system mount order in /etc/fstab
#
sub checkmountorder {
    datecheck();
    print_header("*** BEGIN CHECKING LOCAL FILE SYSTEMS MOUNT ORDER AT BOOT $datestring ***");

    if ( @MOUNTORD != 0 ) {
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

#
# Subroutine to check SCSI
#
sub SCSIcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SCSI ATTACHED DEVICES $datestring ***");

    if ( open( SCSICHK, "cat /proc/scsi/scsi 2>/dev/null |" ) ) {
        while (<SCSICHK>) {
            print $_;
            if ( grep(/^Host:/, $_ ) ) {
               chomp($_);
               (undef, $SCSIDEV, undef) = split(/\s+/, $_);
               if ( ! grep(/\Q$SCSIDEV\E/, @SCSIARR ) ) {
                   push(@SCSIARR, $SCSIDEV);
               }
            }

            if ( grep(/Sequential-Access/, $_ ) ) {
               push(@tapes, $_);
            }
        }
        close(SCSICHK);
    }
    else {
        print "$INFOSTR Cannot check SCSI devices\n";
    }

    datecheck();
    print_header("*** END CHECKING SCSI ATTACHED DEVICES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING HP SMART ARRAY DEVICES $datestring ***");

    my @ccissarr = `ls /proc/driver/cciss/cciss* 2>/dev/null`;

    if ( "@ccissarr" ) {
        foreach my $ccss (@ccissarr) {
            chomp($ccss);
            my @ccssa = `cat $ccss 2>/dev/null`;
            if ( @ccssa != 0 ) {
                print "$INFOSTR Smart Array Controller $ccss\n";
                print @ccssa;
            }
        }

        if ( open( CCISS, "ls /dev/cciss/* 2>/dev/null | grep -v p |" ) ) {
            while (<CCISS>) {
                chomp($_);
                my $CCISSDEV = $_;
                next if (grep(/p[0-9].*/, $CCISSDEV));

                if ( ! grep(/\Q$CCISSDEV\E/, @CLARR ) ) {
                    push(@CLARR, $CCISSDEV);
                }

                $CCISSDEV =~ s/d[0-9].*//g;
                if ( ! grep(/\Q$CCISSDEV\E/, @SCSIARR ) ) {
                    push(@SCSIARR, $CCISSDEV);
                }
            }
            close(CCISS);
        }

#       if ( open( HPACU, "hpacucli ctrl all show | egrep Slot | sed -e 's/^.*Slot //g' -e 's/ .*$//g' |" ) ) {
        if ( open( HPACU, "hpacucli ctrl all show | egrep Slot | sed -e 's/^.*Slot //g' | awk '{print \$1}' |" ) ) {
            while (<HPACU>) {
                chomp($_);
                my $hpctrl = $_;
                my @h0 = `hpacucli ctrl slot=$hpctrl show 2>/dev/null | awk NF`;
                my @h1 = `hpacucli ctrl slot=$hpctrl ld all show 2>/dev/null | awk NF`;
                my @h2 = `hpacucli ctrl slot=$hpctrl pd all show 2>/dev/null | awk NF`;
                print "\n";
                print @h0;
                print @h1;
                print @h2;
            }
            close(HPACU);
        }

        # SMART commands can easily hung servers. Use at risk.
        #
        if ( "$opt_z" == 1 ) {
            foreach my $ccar (@CLARR) {
#               my @zwy = `smartctl -a -d cciss,0 $ccar 2>/dev/null`;
                my @zwy = `smartctl -a -d scsi $ccar 2>/dev/null`;
                if ( "@zwy" ) {
                    print "\n$INFOSTR Smart Array Controller $ccar health status\n";
                    print @zwy;
                }
            }
        }
    }
    else {
        print "$INFOSTR There are no CCISS devices\n";
    }

    my @sdarr = `ls /dev/sd* 2>/dev/null`;

    if ( "@sdarr" ) {
        foreach my $ccsd (@sdarr) {
            chomp($ccsd);
            my @zwy1 = `smartctl -a $ccsd 2>/dev/null`;
            if ( "@zwy1" ) {
                print "\n$INFOSTR Smart Array Controller $ccsd health status\n";
                print @zwy1;
            }
        }
    }
    else {
        print "\n$INFOSTR There are no SD devices\n";
    }

    my @hdarr = `ls /dev/hd* 2>/dev/null`;

    if ( "@hdarr" ) {
        foreach my $cchd (@hdarr) {
            chomp($cchd);
            my @zwy1 = `smartctl -a $cchd 2>/dev/null`;
            if ( "@zwy1" ) {
                print "\n$INFOSTR Smart Array Controller $cchd health status\n";
                print @zwy1;
            }
        }
    }
    else {
        print "\n$INFOSTR There are no HD devices\n";
    }

    datecheck();
    print_header("*** END CHECKING HP SMART ARRAY DEVICES $datestring ***");
}

#
# Subroutine to local locks
#
sub locallocks {
    datecheck();
    print_header("*** BEGIN CHECKING LOCAL LOCKS $datestring ***");

    my @locallocks = `lslk 2>/dev/null`;
    if ( @locallocks != 0 ) {
        print @locallocks;
    }
    else {
        print "$INFOSTR No locks seemingly defined\n";
    }

    datecheck();
    print_header("*** END CHECKING LOCAL LOCKS $datestring ***");
}

#
# Subroutine to check OCFS2
#
sub ocfs2chk {
    my @mocfs2d = `mounted.ocfs2 -d 2>/dev/null`;

    if (@mocfs2d) {
        print "\n$INFOSTR OCFS2 device mapping\n";
        print @mocfs2d;
    }

    my @mocfs2f = `mounted.ocfs2 -f 2>/dev/null`;

    if (@mocfs2f) {
        print "\n$INFOSTR OCFS2 node mapping\n";
        print @mocfs2f;
    }
}

# Subroutine to check ERM
#
sub ERMcheck {
    datecheck();
    print_header("*** BEGIN CHECKING ENTERPRISE ROOT MODEL $datestring ***");

    if ( $ERMflag > 0 ) {
        print "$INFOSTR ERM client seemingly installed (username ermclnt exist
s)\n";
    }
    else {
        print "$WARNSTR ERM client not installed (username ermclnt missing)\n";
        push(@CHECKARR, "\n$WARNSTR ERM client not installed (username ermclnt missing)\n");
    }

    my @ermarr = `update_client -V 2>&1 | grep Version`;

    if ( @ermarr ) {
        print "\n$INFOSTR ERM client version\n";
        print @ermarr;
        my @ermcfg = `update_client -t 2>/dev/null`;
        print "\n$INFOSTR ERM client configuration\n";
        print @ermcfg;
    }
    else {
        print "\n$WARNSTR ERM client seemingly not installed\n";
        push(@CHECKARR, "\n$WARNSTR ERM client seemingly not installed\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING ENTERPRISE ROOT MODEL $datestring ***");
}

#
# Subroutine to check Xen
#
sub checkXen {
    datecheck();
    print_header("*** BEGIN CHECKING XEN VIRTUALIZATION $datestring ***");

    my @xen = `xm list 2>/dev/null`;
    if ( @xen != 0 ) {
        print "$INFOSTR Xen listing (short info)\n";
        print @xen;

        my @xenl = `xm list -l 2>/dev/null`;
        if ( @xenl != 0 ) {
            print "\n$INFOSTR Xen listing (long info)\n";
            print @xenl;
        }

        my @xenlab = `xm list --label 2>/dev/null`;
        if ( @xenlab != 0 ) {
            print "\n$INFOSTR Xen label listing\n";
            print @xenlab;
        }

        my @xeninfo = `xm info 2>/dev/null`;
        if ( @xeninfo != 0 ) {
            print "\n$INFOSTR Xen host info\n";
            print @xeninfo;
        }

        my @xenuptime = `xm uptime 2>/dev/null`;
        if ( @xenuptime != 0 ) {
            print "\n$INFOSTR Xen uptime\n";
            print @xenuptime;
        }
    }
    else {
        print "$INFOSTR Xen seemingly not configured\n";
    }

    datecheck();
    print_header("*** END CHECKING XEN VIRTUALIZATION $datestring ***");
}

#
# Subroutine to check if running in virtual machine 
#
sub checkVIRT {
    datecheck();
    print_header("*** BEGIN CHECKING RUNNING IN VIRTUAL MACHINE $datestring ***");

    my @VIRTWHAT = `virt-what 2>/dev/null`;
    if ( "@VIRTWHAT" ) {
        print "$INFOSTR System running in virtualisation\n";
        print @VIRTWHAT;
    }
    else {
        print "$INFOSTR System not running in virtual machine or type of virtualisation not recognised\n";
    }

    datecheck();
    print_header("*** END CHECKING RUNNING IN VIRTUAL MACHINE $datestring ***");
}

#
# Subroutine to check KVM
#
sub checkKVM {
    datecheck();
    print_header("*** BEGIN CHECKING KVM VIRTUALIZATION $datestring ***");

    my @cpukvm = `egrep '(vmx|svm)' /proc/cpuinfo 2>/dev/null`;
    if ( "@cpukvm" ) {
        print "$INFOSTR CPU seemingly supports hardware virtualisation\n";
        print @cpukvm;

        my @virshv = `virsh version 2>/dev/null`;
        if ( @virshv != 0 ) {
            print "\n$INFOSTR Virsh version\n";
            print @virshv;
        }

        my @virshsys = `virsh sysinfo 2>/dev/null`;
        if ( @virshsys != 0 ) {
            print "\n$INFOSTR Virtualisation hypervisor sysinfo\n";
            print @virshsys;
        }

        my @virsh = ();
        my @virshe = ();
        my $domid = q{};
        my $domname = q{};
        my $domstate = q{};
        if ( open( VIR, "virsh list 2>/dev/null |" ) ) {
            while (<VIR>) {
                push(@virsh, $_);
                chomp($_);
                next if ( grep( /^Id|State|---/, $_ ) );
                ( $domid, $domname, $domstate ) = split( /\s+/, $_);
                if ( "$domname" ) {
                    $domname =~ s/^\s+//g;
                    $domname =~ s/\s+$//g;
                    push(@virshe, $domname);
                }
            }
        }

        if ( @virsh != 0 ) {
            print "\n$INFOSTR KVM listing\n";
            print @virsh;
        }

        foreach my $virshs (@virshe) {
            if ( "$virshs" ) {
                my @vircat = `virsh dominfo $virshs 2>/dev/null`;
                if ( "@vircat" ) {
                    print "\n";
                    print "$INFOSTR KVM domain info for $virshs\n";
                    print @vircat;
                }

                my @virxml = `virsh dumpxml $virshs 2>/dev/null`;
                if ( "@virxml" ) {
                    print "\n";
                    print "$INFOSTR KVM XML domain info for $virshs\n";
                    print @virxml;
                }
            }
        }
    }
    else {
        print "$INFOSTR CPU seemingly does not support hardware virtualisation\n";
    }

    datecheck();
    print_header("*** END CHECKING KVM VIRTUALIZATION $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SYSTEMD VIRTUALIZATION $datestring ***");

    my @machinectlv = `machinectl --version 2>/dev/null`;
    if ( "@machinectlv" ) {
        print "$INFOSTR Systemd Virtual Machine and Container version\n";
        print @machinectlv;

        my @machinectll = `machinectl list 2>/dev/null`;
        if ( "@machinectll" ) {
            print "\n$INFOSTR Systemd Virtual Machine and Container status\n";
            print @machinectll;
        }
    }
    else {
        print "$INFOSTR Systemd Virtual Machine and Container seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING SYSTEMD VIRTUALIZATION $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING VIRTUALBOX VIRTUALIZATION $datestring ***");

    my @vboxv = `VBoxManage -v 2>/dev/null`;
    if ( "@vboxv" ) {
        print "$INFOSTR VirtualBox version\n";
        print @vboxv;

        my @vboxprop = `VBoxManage list systemproperties 2>/dev/null`;
        if ( "@vboxprop" ) {
            print "\n$INFOSTR VirtualBox properties\n";
            print @vboxprop;
        }

        my @vboxvms = `VBoxManage list vms 2>/dev/null`;
        if ( "@vboxvms" ) {
            print "\n$INFOSTR VirtualBox VMS\n";
            print @vboxvms;
        }
    }
    else {
        print "$INFOSTR Systemd Virtual Machine and Container seemingly not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING VIRTUALBOX VIRTUALIZATION $datestring ***");
}

#
# Subroutine to check PowerBroker
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

    my @pbconf = `awk NF $PBCONF 2>/dev/null | egrep -v ^#`;
    if ( @pbconf != 0 ) {
        print "\n$INFOSTR PowerBroker Master configuration file $PBCONF\n";
        print @pbconf;
    }

    my @pbset = `awk NF $PBSET 2>/dev/null | egrep -v ^#`;
    if ( @pbset != 0 ) {
        print "\n$INFOSTR PowerBroker network and port configuration file $PBSET\n";
        print @pbset;
    }

    my @pbenc = `awk NF $PBENC 2>/dev/null | egrep -v ^#`;
    if ( @pbenc != 0 ) {
        print "\n$INFOSTR PowerBroker encryption key file $PBENC\n";
        print @pbenc;
    }

    my @pbshell = `awk NF $PBSHELL 2>/dev/null | egrep -v ^#`;
    if ( @pbshell != 0 ) {
        print "\n$INFOSTR PowerBroker Shells file $PBSHELL\n";
        print @pbshell;
    }

    datecheck();
    print_header("*** END CHECKING POWERBROKER $datestring ***");
}

#
# Subroutine to check PowerBroker
#
sub checkUPMQuestPrivilegeManager {
    datecheck();
    print_header("*** BEGIN CHECKING UPM QUEST PRIVILEGE MANAGER $datestring ***");

    my @pminfo = `pminfo -s 2>/dev/null`;
    if ( @pminfo != 0 ) {
        print "$INFOSTR Status of UPM Privilege Manager installation\n";
        print @pminfo;
    }
    else {
        print "$INFOSTR UPM Privilege Manager seemingly not installed or configured\n";
    }

    my @pmclientinfo = `pmclientinfo 2>/dev/null`;
    if ( @pmclientinfo != 0 ) {
        print "\n$INFOSTR UPM Privilege Manager client status\n";
        print @pmclientinfo;
    }

    my @pmloadcheck = `pmloadcheck 2>/dev/null`;
    if ( @pmloadcheck != 0 ) {
        print "\n$INFOSTR UPM Privilege Manager client registration status\n";
        print @pmloadcheck;
    }

    my @pmsrvinfo = `pmsrvinfo 2>/dev/null`;
    if ( @pmsrvinfo != 0 ) {
        print "\n$INFOSTR UPM Privilege Manager policy server configuration\n";
        print @pmsrvinfo;
    }

    my @pmpolicy = `pmpolicy masterstatus 2>/dev/null`;
    if ( @pmpolicy != 0 ) {
        print "\n$INFOSTR UPM Privilege Manager policy status across masters\n";
        print @pmpolicy;
    }

    my @pmserviced = `pmserviced -s 2>/dev/null`;
    if ( @pmserviced != 0 ) {
        print "\n$INFOSTR UPM Privilege Manager service daemons\n";
        print @pmserviced;
    }

    datecheck();
    print_header("*** END CHECKING UPM QUEST PRIVILEGE MANAGER $datestring ***");
}

#
# Subroutine to check /
#
sub checkTLDIR {
   datecheck();
   print_header("*** BEGIN CHECKING TOP LEVEL DIRECTORY / $datestring ***");

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
        push(@CHECKARR, "\n$WARNSTR Top-level directory \"$TLDIR\" not owned by UID 0 ($tuid)\n");
        $warnings++;
    }

    if ( "$tgid" == 0 ) {
        print "\n$PASSSTR Top-level directory \"$TLDIR\" owned by GID $tgid\n";
    }
    else {
        print "\n$WARNSTR Top-level directory \"$TLDIR\" not owned by GID 0 ($tgid)\n";
        push(@CHECKARR, "\n$WARNSTR Top-level directory \"$TLDIR\" not owned by GID 0 ($tgid)\n");
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

#
# Subroutine to check VMware
#
sub checkVMware {
   datecheck();
   print_header("*** BEGIN CHECKING VMWARE ESX $datestring ***");

   if ( -s "$ESXCONF" ) {
       my @vmwarelist = `egrep -v ^# $ESXCONF | awk NF`;
       if ( @vmwarelist ) {
           print "$INFOSTR VMware configuration $ESXCONF\n";
           print @vmwarelist;
       }

       if ( -s "$VXPACFG" ) {
           my @vxpalist = `egrep -v ^# $VXPACFG | awk NF`;
           if ( @vxpalist ) {
               print "\n$INFOSTR VMware configuration $VXPACFG\n";
               print @vxpalist;
           }
       }

       my @vmware = `vmware -v 2>/dev/null`;
       if ( @vmware ) {
           print "\n$INFOSTR VMware server\n";
           print @vmware;
       }

       my @vmwaretools = `vmware-toolbox --version 2>/dev/null`;
       if ( @vmwaretools ) {
           print "\n$INFOSTR VMware Tools\n";
           print @vmwaretools;
       }

       my @esxcfginfo = `esxcfg-info -a 2>/dev/null`;
       if ( @esxcfginfo ) {
           print "\n$INFOSTR VMware esxcfg-info\n";
           print @esxcfginfo;
       }

       my @esxcfgmod = `esxcfg-module -l 2>/dev/null`;
       if ( @esxcfgmod ) {
           print "\n$INFOSTR VMware esxcfg-module in the service console\n";
           print @esxcfgmod;
       }

       my @esxcfgvsw = `esxcfg-vswitch -l 2>/dev/null`;
       if ( @esxcfgvsw ) {
           print "\n$INFOSTR VMware esxcfg-vswitch status\n";
           print @esxcfgvsw;
       }

       my @esxcfgnics = `esxcfg-nics -l 2>/dev/null`;
       if ( @esxcfgnics ) {
           print "\n$INFOSTR VMware esxcfg-nics status\n";
           print @esxcfgnics;
       }

       my @esxcfgvmknic = `esxcfg-vmknic -l 2>/dev/null`;
       if ( @esxcfgvmknic ) {
           print "\n$INFOSTR VMware esxcfg-vmknic status\n";
           print @esxcfgvmknic;
       }

       my @esxcfgfw = `esxcfg-firewall -q 2>/dev/null`;
       if ( @esxcfgfw ) {
           print "\n$INFOSTR VMware esxcfg-firewall status\n";
           print @esxcfgfw;
       }

       my @esxcfgmpath = `esxcfg-mpath -l 2>/dev/null`;
       if ( @esxcfgmpath ) {
           print "\n$INFOSTR VMware esxcfg-mpath status\n";
           print @esxcfgmpath;
       }

       my @esxcfgswiscsi = `esxcfg-swiscsi -q 2>/dev/null`;
       if ( @esxcfgswiscsi ) {
           print "\n$INFOSTR VMware esxcfg-swiscsi status\n";
           print @esxcfgswiscsi;
       }
       my @esxcfgvmhbadevs = `esxcfg-vmhbadevs 2>/dev/null`;
       if ( @esxcfgvmhbadevs ) {
           print "\n$INFOSTR VMware esxcfg-vmhbadevs status\n";
           print @esxcfgvmhbadevs;
       }

       my @esxcfgvmhbadevsm = `esxcfg-vmhbadevs -m 2>/dev/null`;
       if ( @esxcfgvmhbadevsm ) {
           print "\n$INFOSTR VMware esxcfg-vmhbadevs VMFS status\n";
           print @esxcfgvmhbadevsm;
       }

       my @esxcfgroute = `esxcfg-route 2>/dev/null`;
       if ( @esxcfgroute ) {
           print "\n$INFOSTR VMware esxcfg-route status\n";
           print @esxcfgroute;
       }

       my @esxcfgdumppart = `esxcfg-dumppart -l 2>/dev/null`;
       if ( @esxcfgdumppart ) {
           print "\n$INFOSTR VMware esxcfg-dumppart status\n";
           print @esxcfgdumppart;
       }

       my @esxcfgnas = `esxcfg-nas -l 2>/dev/null`;
       if ( @esxcfgnas ) {
           print "\n$INFOSTR VMware esxcfg-nas NFS status\n";
           print @esxcfgnas;
       }

       my @vdf = `vdf 2>/dev/null`;
       if ( @vdf ) {
           print "\n$INFOSTR VMware VMFS status\n";
           print @vdf;
       }

       my @esxcfgcmd = `esxcfg-cmd -l 2>/dev/null`;
       if ( @esxcfgcmd ) {
           print "\n$INFOSTR VMware esxcfg-cmd status\n";
           print @esxcfgcmd;
       }

       my @vmkpcidivy = `vmkpcidivy -q vmhba_devs 2>/dev/null`;
       if ( @vmkpcidivy ) {
           print "\n$INFOSTR VMware HBA status\n";
           print @vmkpcidivy;
       }

       my @esxclihw = `esxcli hardware get 2>/dev/null`;
       if ( @esxclihw ) {
           print "\n$INFOSTR VMware platform information\n";
           print @esxclihw;
       }

       my @esxclihwboot = `esxcli hardware bootdevice list 2>/dev/null`;
       if ( @esxclihwboot ) {
           print "\n$INFOSTR VMware boot device order\n";
           print @esxclihwboot;
       }

       my @esxclifence = `esxcli network fence list 2>/dev/null`;
       if ( @esxclifence ) {
           print "\n$INFOSTR VMware fence switch information\n";
           print @esxclifence;
       }

       my @esxclifw = `esxcli network firewall get 2>/dev/null`;
       if ( @esxclifw ) {
           print "\n$INFOSTR VMware firewall status\n";
           print @esxclifw;
       }

       my @esxcliipget = `esxcli network ip get 2>/dev/null`;
       if ( @esxcliipget ) {
           print "\n$INFOSTR VMware global network settings\n";
           print @esxcliipget;
       }

       my @esxclivsw = `esxcli network vswitch standard list 2>/dev/null`;
       if ( @esxclivsw ) {
           print "\n$INFOSTR VMware virtual network switches\n";
           print @esxclivsw;
       }

       my @esxcliiplist = `esxcli network ip interface list 2>/dev/null`;
       if ( @esxcliiplist ) {
           print "\n$INFOSTR VMware VMkernel network interfaces\n";
           print @esxcliiplist;
       }

       my @esxclipci = `esxcli pci list 2>/dev/null`;
       if ( @esxclipci ) {
           print "\n$INFOSTR VMware PCI information\n";
           print @esxclipci;
       }

       my @esxclicpu = `esxcli cpu list 2>/dev/null`;
       if ( @esxclicpu ) {
           print "\n$INFOSTR VMware CPU information\n";
           print @esxclicpu;
       }

       my @esxcliram = `esxcli memory get 2>/dev/null`;
       if ( @esxcliram ) {
           print "\n$INFOSTR VMware memory information\n";
           print @esxcliram;
       }

       my @esxclinmp = `esxcli storage nmp device list 2>/dev/null`;
       if ( @esxclinmp ) {
           print "\n$INFOSTR VMware datastores and SATP/PSP plugins\n";
           print @esxclinmp;
       }

       my @esxclisan = `esxcli storage san fc list 2>/dev/null`;
       if ( @esxclisan ) {
           print "\n$INFOSTR VMware FC list\n";
           print @esxclisan;
       }

       my @esxclisanstats = `esxcli storage core path stats get 2>/dev/null`;
       if ( @esxclisanstats ) {
           print "\n$INFOSTR VMware path I/O stats\n";
           print @esxclisanstats;
       }

       my @esxclisanev = `esxcli storage san fc events get 2>/dev/null`;
       if ( @esxclisanev ) {
           print "\n$INFOSTR VMware FC events\n";
           print @esxclisanev;
       }

       my @esxclivm = `esxcli vm process list 2>/dev/null`;
       if ( @esxclivm ) {
           print "\n$INFOSTR VMware virtual machines\n";
           print @esxclivm;
       }

   }
   else {
       print "$INFOSTR VMware configuration $ESXCONF missing or empty\n";
   }

   datecheck();
   print_header("*** END CHECKING VMWARE ESX $datestring ***");
}

#
# Subroutine to check Squid proxy
#
sub checkNSCD {
   datecheck();
   print_header("*** BEGIN CHECKING NAME SERVICE CACHING DAEMON $datestring ***");

   my @nscd = `nscd -g 2>/dev/null`;
   if ( @nscd ) {
       print @nscd;

       if ( -s "$NSCDCONF" ) {
           my @nscdc = `egrep -v ^# $NSCDCONF | awk NF 2>/dev/null`;
           if ( @nscdc ) {
               print "\n$INFOSTR Configuration file $NSCDCONF\n";
               print @nscdc;
           }
           else {
               print "\n$INFOSTR $NSCDCONF empty\n";
           }
       }
       else {
           print "\n$INFOSTR $NSCDCONF missing or empty\n";
       }
   }
   else {
       print "$INFOSTR nscd not running\n";
   }

   datecheck();
   print_header("*** END CHECKING NAME SERVICE CACHING DAEMON $datestring ***");
}

#
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
              my @sqlist = `egrep -v ^# $squidfile | awk NF`;
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
# Subroutine to check Apache
#
sub checkHTTPD {
   datecheck();
   print_header("*** BEGIN CHECKING WEB SERVICES $datestring ***");

   if ( !"@HTTPDRUN" ) {
       print "$INFOSTR Apache web server or its derivative not running\n";
   }
   else {
      print "$INFOSTR Apache web server or its derivative seemingly running\n";

      if ( -s "$HTTPDCONF" ) {
          my @hdc = `awk NF $HTTPDCONF 2>/dev/null`;
          if ( @hdc ) {
              print "\n$INFOSTR HTTPD configuration $HTTPDCONF\n";
              print @hdc;
          }
      }

      my @hdlist = `find $HTTPDD -type f 2>/dev/null`;
      foreach my $httpdfile (@hdlist) {
          chomp($httpdfile);
          if ( -s "$httpdfile" ) {
              my @hdcat = `cat $httpdfile 2>/dev/null`;
              if ( @hdcat ) {
                  print "\n$INFOSTR HTTPD configuration $httpdfile\n";
                  print @hdcat;
              }
          }
      }

      if ( $DIST eq 'Debian' ) {
         $webcomm = "apache2";
      }

      my @hdv = `$webcomm -V 2>/dev/null`;
      if ( @hdv ) {
          print "\n$INFOSTR HTTPD status\n";
          print @hdv;
      }

      my @hdl = `$webcomm -l 2>/dev/null`;
      if ( @hdl ) {
          print "\n$INFOSTR HTTPD build-in modules\n";
          print @hdl;
      }

      my @hdvh = `$webcomm -t -D DUMP_VHOST 2>/dev/null`;
      if ( @hdvh ) {
          print "\n$INFOSTR HTTPD VHOST check\n";
          print @hdvh;
      }

      my @hdvm = `$webcomm -t -D DUMP_MODULES 2>/dev/null`;
      if ( @hdvm ) {
          print "\n$INFOSTR HTTPD MODULES check\n";
          print @hdvm;
      }
   }

   my @nginx     = `nginx -V 2>&1 |grep -v "not found"`;
   my @nginxconf = ();
   my @ngconf    = ();

   if ( ($NGINX_FLAG > 0) || (@nginx) ) {
       print "\n$INFOSTR Nginx seemingly running\n";
       print @nginx;
       if ( open( ZI, "nginx -t 2>&1 |" ) ) {
           print "\n$INFOSTR Nginx configuration verification\n";
           while (<ZI>) {
               print $_;
               chomp($_);
               if ( grep( /the configuration file/, $_ ) ) {
                   @nginxconf = split( /\s+/, $_);
                   @ngconf = `awk NF $nginxconf[4] 2>/dev/null`;
               }
           }
       }
       close(ZI);

       if ( "@ngconf" ) {
           print "\n$INFOSTR Nginx configuration $nginxconf[4]\n";
           print @ngconf;
       }
   }

   my @tomcatck = `/etc/init.d/\*tomcat\* status 2>/dev/null`;

   if ( ($TOMCAT_FLAG > 0) || (@tomcatck) ) {
       print "\n$INFOSTR Tomcat seemingly installed\n";
       print @tomcatck;
   }

   datecheck();
   print_header("*** END CHECKING WEB SERVICES $datestring ***");
}

sub zfslist {
    datecheck();
    print_header "*** BEGIN CHECKING ZFS FILE SYSTEMS $datestring ***";

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
        if ( open( ZXI, "zpool status 2>/dev/null |" ) ) {
            while (<ZXI>) {
                push(@zpools, $_);
                chomp($_);
                if ( grep( /pool:/, $_ ) ) {
                    ( undef, $poolname ) = split( /:/, $_);
                    if ( "$poolname" ) {
                        $poolname =~ s/^\s+//g;
                        $poolname =~ s/\s+$//g;
                        push(@ZFSPOOLARR, $poolname);
                    }
                }
            }
        }
        close (ZXI);

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

            foreach my $zpl (@ZFSPOOLARR) {
                my @zdb = `zdb $zpl 2>/dev/null`;
                if ("@zdb") {
                    print "\n$INFOSTR ZFS debugger (zdb) status for pool $zpl\n";
                    print @zdb;
                }
            }
        }
        else {
            print "\n$INFOSTR ZFS pools not defined\n";
        }

        if ("@zfsmount") {
            print "\n$INFOSTR ZFS mounted file systems\n";
            print "@zfsmount\n";
        }
        else {
            print "\n$INFOSTR No ZFS mounted file systems currently\n";
        }
    }
    else {
        print "\n$INFOSTR ZFS not configured\n";
    }

    datecheck();
    print_header "*** END CHECKING ZFS FILE SYSTEMS $datestring ***";
}

# Check Oracle instances
#
sub checkOracle {
    datecheck();
    print_header("*** BEGIN CHECKING ORACLE $datestring ***");

    if ( -s "$ORATAB" ) {
        print "$INFOSTR $ORATAB installed\n";

        my @oratab = `awk NF $ORATAB`;
        if (@oratab) {
            print @oratab;
        }
    }
    else {
        print "$INFOSTR $ORATAB not installed\n";
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

# Check last reboots 
#
sub checkreboots {
    my @reboots = `last reboot 2>/dev/null`;
    if (@reboots) {
        datecheck();
        print_header("*** BEGIN CHECKING FREQUENCY OF REBOOTS $datestring ***");
        print @reboots;
        datecheck();
        print_header("*** END CHECKING FREQUENCY OF REBOOTS $datestring ***");
    }
}

sub coreadm {
    datecheck();
    print_header("*** BEGIN CHECKING CORE PATTERN ADMINISTRATION $datestring ***");

    my $coreconf = "/proc/sys/kernel/core_pattern";
    my @coreadm = `cat $coreconf 2>/dev/null | awk NF`;
    if ( @coreadm ) {
         print @coreadm;
    }
    else {
        print "$INFOSTR Core administration config $coreconf missing\n";
    }

    my @corekadm = `sysctl kernel.core_pattern 2>/dev/null`;
    if ( @corekadm ) {
        print "\n$INFOSTR Core pattern config in kernel (sysctl)\n";
        print @corekadm;
    }

    datecheck();
    print_header("*** END CHECKING CORE PATTERN ADMINISTRATION $datestring ***");
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

if ( $opt_v ) {
    print "$INFOSTR OAT script version $SCRIPT_VERSION\n";
    exit(0);
}

SYS_INFO();
kickstart();
check_hostname_valid();
sgcheck();
crashcheck();
IOSCAN_NO_HW();
DevFilecheck();
swcheck();
pscheck();
bootpath();
coreadm();
bootcheck();

if ( grep( /LVM/, "$Diskmgr" ) ) {
    LVM_PARAM_CHECK();
}

if ("$vxcheck") {
    VXVM_CHECK();
}

if ("@mdcheck") {
    SRAIDcheck();
}

if ("@zfsmount") {
    zfslist();
}

SCSIcheck();
ldconfig_info();
pathcheck();
checkTLDIR();
basic_daemons();
lancheck();
audsys();
lan();
start_shutdown_log();
pwdbcheck();
checkPowerBroker();
checkUPMQuestPrivilegeManager();
swapcheck();
space();
rootacc();
ntp_check();
CHECK_MOUNTED_FILESYSTEMS();
checkmountorder();
CPUcheck();
nfs_check();
raw_check();
checknull();
inetdchk();
protchk();
smtpchk();
dnschk();
nischk();
OVchk();
cron_access();
ROOT_CRON();
PERFORMANCE_BASICS();
SYSLOG_LOGGING();
RCcheck();
motd();
timezone_info();
vendorbck();
SANchk();
ERMcheck();
sachk();
localecheck();
sim_info();
lp_info();
samba_info();
checkXen();
checkKVM();
checkVIRT(); 
IPseccheck();
checkkernel();
lsdevcheck();
rpcchk();
SNMPcheck();
liccheck();
locallocks();
STICKYcheck();
ULIMITcheck();
PAMcheck();
IPCScheck();
QUOTAcheck();
LDAPcheck();
HIDScheck();
checkHTTPD();
checkNSCD();
checkSquid();
check_cfengine();
check_puppet();
check_chef();
checkVMware();
BasSeccheck();
checkOracle();
checkreboots();
Xcheck();

# Tier 1 Basic
# Hardware must have 24x7x8 support at least
# Minimum RAM = 1024 MB
# Minimum CPUs = 1
# Minimum O/S disks (mirrored) = 2
# Minimum LAN cards = 2
# Minimum O/S disk controllers = 1
# Ignite backups
# Minimum power supplies = 1
# Minimum tape drives = 1
# Tape drives must be on separate controller!
#
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
# Ignite backups
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
# Ignite backups
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
# Ignite backups
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

my $TIERC = "Tier 1 Basic";

my $TIERT = "Tier 1 Basic";

if (@tapes) {
    $TIERT = "Tier 4 Mission Critical";
}

print "\n\nSUMMARY:

The Operations Acceptance Testing (OAT) assessment
reported $warnings warnings.\n
";

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

my $TTIERC = my $TTIERM = my $TTIERK = my $TTIERP = my $TTIERL = q{};
my @ACCESSTIER = ();

$TTIERK = @SCSIARR;

my $TIERK = ( $TTIERK >= $TIER4OSDISKCNTRL ) ? "Tier 4 Mission Critical"
            : ( $TTIERK >= $TIER3OSDISKCNTRL ) ? "Tier 3 High Availability"
            : ( $TTIERK >= $TIER2OSDISKCNTRL ) ? "Tier 2 Standard"
            : ( $TTIERK >= $TIER1OSDISKCNTRL ) ? "Tier 1 Basic"
            : "Tier 1 Basic";

if ( "$TIERK" ) {
    print "   O/S controller redundancy ... $TIERK
";
}

(undef, $TTIERK, undef) = split(/\s+/, $TIERK);
push(@ACCESSTIER, $TTIERK);
my $OVERALLTIER = $TTIERK;
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

print "It is strongly recommended to evaluate all warnings.\n";

exit(0);
