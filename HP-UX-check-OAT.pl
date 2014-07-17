#!/usr/bin/env perl
# @(#) $Id: HP-UX-check-OAT.pl,v 1.5 2014/04/24 06:41:48 root Exp root $
#
# Description: Basic Operations Acceptance Testing for HP-UX servers
#              Results are displayed on stdout or redirected to a file
#
# If you obtain this script via Web, convert it to Unix format. For example:
# dos2ux HP-UX-check-OAT.pl.txt > HP-UX-check-OAT.pl
#
# Usage: HP-UX-check-OAT.pl [-b] [-c] [-e] [-f] [-h] [-l] [-n] \
#        [-s GSP_server] [-S XP|EVA|EMC|OTHER] \
#        [-u GSP_login -p GSP_pass] [-o] [-r] \
#        [-t conffile] [-V ALL|NONVG0|NONE] [-v] [-w] [> `uname -n`-OAT-report.txt]
#
#        -b                  Brief summary of server setup
#        -c                  Enable check of SUID/SGID files
#        -e                  Enable EFI disk scan on Itanium servers 
#                            This test crashed HP-UX 11.23 once! Watch out.
#        -f                  Force running this script even if RAM usage high
#        -h                  Print this help message
#        -l                  Enable NMAP scans
#        -n                  Enable SUID/SGID checks in NFS
#        -s GSP_server       IP address or FQDN of GSP (telnet to MP)
#        -S XP|EVA|EMC|OTHER Type of SAN
#        -u GSP_login        GSP login name
#        -o                  OpenView monitoring used (default is OVO not used)
#        -p GSP_pass         GSP password
#        -r                  Server part of cluster or H/A server group
#        -t                  Read variables from a config file 
#        -V ALL|NONVG0|NONE  Volume groups on SAN or local disks
#        -v                  Print version of this script
#        -w                  Use CMSG WorldWide Standard for O/S
#                            file system sizing (default is to
#                            use my own Build Standard)
#
# Normally, OLA/R check is advisable to run in single-user mode.
#
# Last Update: 24 March 2014
# Designed by: Dusan U. Baljevic (dusan.baljevic@ieee.org)
# Coded by:    Dusan U. Baljevic (dusan.baljevic@ieee.org)
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
# Perl script HP-UX-check-oat.pl is a modest attempt to automate basic
# tasks when running Operations Acceptance Testing (OAT) for a server
# that is about to be commissioned or checked.
#
# The script tries to capture most critical information about an HP-UX
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
# on HP-UX servers;
# B) Portability;
# C) Standard Perl interpreter;
# D) Many new features;
# E) Support for LVM and VxVM;
# F) No temporary files;
# G) No repeated runs of similar commands;
# H) Not to replace more comprehensive debugging tools but
# provide a quick summary of server status;
# I) Usefulness of results, not their formatting on the screen;
#
# Like all scripts and programs, this one will continue to
# change as my needs change.
#
# I must admit the documentation of the code needs to improve!

# Define important environment variables
#
$ENV{'PATH'} = "/usr/bin:/usr/sbin:/sbin:/opt/ignite/bin:/opt/ignite/lbin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/local/bin:/usr/lbin:/usr/local/sbin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/contrib/bin:/opt/hparray/bin:/opt/fcms/bin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/sbin/diag/contrib:/usr/symcli/bin";
$ENV{'PATH'} = "$ENV{PATH}:/etc:/usr/sbin/acct:/opt/rdma/bin";
$ENV{'PATH'} = "$ENV{PATH}:/HORCM/usr/bin:/opt/HORCM/usr/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/hpvm/bin:/opt/hpvm/lbin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/guid/bin:/opt/guid/sbin:/opt/guid/util";
$ENV{'PATH'} = "$ENV{PATH}:/opt/perf/bin:/opt/mx/bin:/opt/mx/lbin:/opt/VRTS/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/VRTSvxfs/bin:/opt/VRTSdbed/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/VRTSdb2ed/bin:/opt/VRTS/vxse/vxvm";
$ENV{'PATH'} = "$ENV{PATH}:/opt/VRTSsybed/bin:/opt/VRTSob/bin";
$ENV{'PATH'} = "$ENV{PATH}:/etc/vx/bin:/opt/VRTSvcs/bin:/sbin/fs/vxfs";
$ENV{'PATH'} = "$ENV{PATH}:/opt/hpsmh/bin:/opt/ots/bin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/lib/vxvm/diag.d:/etc/vx/type/static";
$ENV{'PATH'} = "$ENV{PATH}:/opt/hpsmh/data/htdocs/comppage";
$ENV{'PATH'} = "$ENV{PATH}:/opt/VRTSvcs/vxfen/bin:/opt/samba/bin";
$ENV{'PATH'} = "$ENV{PATH}:/usr/lib/nis:/opt/sec_mgmt/spc/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/wbem/bin:/opt/wbem/sbin:/opt/wbem/lbin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/sec_mgmt/bastille/bin:/opt/iscsi/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/raid4si/bin:/usr/sam/lbin:/usr/sam/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/ibm/ESScli:/opt/iscsi/tools";
$ENV{'PATH'} = "$ENV{PATH}:/opt/clusterpath/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/sanmgr/commandview/client/sbin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/lprng/sbin:/opt/hpsmc/shc/bin:/opt/swa/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/hpsmc/rcm/bin:/opt/ids/bin:/opt/wlm/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/gwlm/bin:/opt/prm/bin:/opt/mpt/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/raidsa/bin:/opt/networker/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/OV/bin:/opt/OV/bin/OpC:/opt/OV/contrib/OpC";
$ENV{'PATH'} = "$ENV{PATH}:/opt/OV/support:/opt/omni/bin:/opt/omni/lbin:/opt/omni/sbin";
$ENV{'PATH'} = "$ENV{PATH}:/var/opt/OV/bin/OpC/cmds:/opt/HPO/SMSPI";
$ENV{'PATH'} = "$ENV{PATH}:/opt/erm/sbin:/opt/resmon/bin:/usr/lbin/sysadm";
$ENV{'PATH'} = "$ENV{PATH}:/etc/opt/resmon/lbin:/opt/lpfc/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/sas/bin:/usr/lib/netsvc/yp:/opt/sfm/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/tivoli/tsm/server/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/tivoli/tsm/client/ba/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/adsmserv/bin:/opt/hpservices/RemoteSupport/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/HP/CM/ConfigurationServer/bin";
$ENV{'PATH'} = "$ENV{PATH}:/app/Novadigm/ConfigurationServer/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/omnistorage/bin:/opt/netapp/santools";
$ENV{'PATH'} = "$ENV{PATH}:/opt/netapp/santools/bin:/opt/Ontap/santools/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/drd/bin:/etc/init.d:/opt/hpsrp/bin";
$ENV{'PATH'} = "$ENV{PATH}:/local/flexlm/bin:/opt/flexlm/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/ifor/bin:/opt/ifor/ls/bin:/opt/clic/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/ldapux/config:/opt/ldapux/bin:/opt/ldapux/sbin:/opt/vse/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/dirsrv/bin:/opt/sna/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/ipqos/bin:/opt/ipf/bin:/opt/meter/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/amgr/bin:/opt/HPO/SMSPIv2/bin:/oracle/crs/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/graphics/common/bin:/opt/upgrade/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/dt/bin:/opt/CIS:/opt/propplus/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/dsau/sbin:/opt/dsau/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/fusionio/bin";
$ENV{'PATH'} = "$ENV{PATH}:/opt/tuneserver/bin:/opt/caliper/bin:/sbin/init.d";

# Define Shell
#
$ENV{'SHELL'} = '/usr/bin/sh' if $ENV{'SHELL'} ne '';
$ENV{'IFS'}   = ''        if $ENV{'IFS'}   ne '';

# Enforce strictness
#
if ( eval "require strict" ) {
    import strict;
    use strict;
    no strict 'refs';
}
else {
    print "WARN: Perl strict not found\n";
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

# Check Perl code
#
# use diagnostics;
# use warnings;

# Make sure strictness is enforced
#
use vars qw($CMD $pty $PTYcur %opts $fqdn $Hardware %ctrllist %disklist
  $PROCNO2 $PROCNO %Freevg $i $len_lline $ARCH $GSP_login $GSP_pass
  $SANtype %VGfpe %MAXLV %MAXPV $Min $VGSAN %OSARRAY %OSARRAY1 %OSARRAY2
  %PEPV %VGpes $GSP_server $h $REC_VERSION $BEST_VERSION $CUR_VERSION
  $OLDER_PERL_FLAG $SCRIPT_VERSION %swcount %SLMMEM %CLMMEM %ILMMEM
  %GOODMEM $dpcw $balanceIP %balanceIP %lines %shadarr %patharr %bines
  %iines $s %tcpcount %CMLCKARR %PVcount $CONFFILE %VGpeact %VGcurLV
  %VGstatus %VGverc %VGpetot %PVGN %PVAL %PVFREE %PVSIZE %PVALOC
  %LVSSTAT %LVMIRR %LVSTRIPE %LVALOC %LVSZ %LVPERMIS
);

# START OF VARIABLES THAT CAN BE READ FROM CONFIG FILE
# VIA "-t CONFFILE" OPTION
#
# Check RAM usage - if too high (above 85%), abort running this script
# and give chance to admins to check it.
#
my $HIGHMEMUSAGE = 85;

# Due to excessive tape backup times (sigh, tape backups should
# be obsolete by now!), some support teams recommend maximum
# file system size limit of 512 GB
#
use constant MAXFSSIZE  => 512;

# Number of seconds in current time()
#
my $Sec             = q{};

# Delay and count values for commands vmstat, ioscan, and sar...
#
my $ITERATIONS = 10;
my $DELAY      = 2;
my $READFLAG   = q{};

my $GUIDCONF   = "/opt/guid/etc/guid.conf";
my $GUID_WARN  = 0;
my @guidmgmt   = (); 

# iCAP variables.
#
my @realexcept = ();
my @realemail  = ();
my @realcap    = ();
my @ICAPARR    = (); 

# Configuration management tools
#
my $PUPPETMASTER           = 0;
my $PUPPETCLIENT           = 0;
my $CFENGINEMASTER         = 0;
my $CFENGINECLIENT         = 0;

# HP-UX 11.23 and above support flag "-v" for vgcfgrestore
#
$VGCFGFLAG = "";

# Default size of crash space in MBytes
#
my $fs_crash        = 4096;

# Device name in bdf command
#
my $fs              = q{};

# Minimum space in /var/tmp to keep temporary LIF volume
# during make_tape_recovery (/var/tmp/uxinstlf.recovery).
# On-line manuals state:
# 	120 MB for HP-UX 11v1
# 	32 MB for HP-UX 11v2
#
my $LIFtemp         = 120;

#
my @SSHARR          = ();
my @BADPV           = ();
my $badVG           = q{};
my @BADVG           = ();
my $VGSCAN_FLAG     = q{};

# File with DRD sync preview results 
#
my $DRDSYNCP        = "/var/opt/drd/sync/files_to_be_copied_by_drd_sync";

# Automount
#
my @AUTOARR         = ( "/etc/auto_master", );
my @AUTOEXTRA       = ( );
my $AUTO_FLAG       = 0;

# If /var/adm/ps_data is corrupt, command ps(1) might give
# strange results!
# Here is a test on HP-UX 11.31:
# cp /etc/motd /var/adm/ps_data
# ps -ef
# ps: not enough memory for tables
#
my $PSDATA         = "/var/adm/ps_data";

# Userdb database
#
my $USERDB          = "/var/adm/userdb";
my $SECURITYDSC     = "/etc/security.dsc";
my $DISABLEUSERDB   = "${USERDB}/USERDB.DISABLED";

# Does /etc/resolv.conf contain empty spaces at the end of "search" line?
# This been known to generate the "PFMERRR 10" error message
#
my $PFMERR          = 0;

# EFI disk check
#
my $eficptest       = "/tmp/eficptest"; 

# Does server have mpt devices in ioscan?
#
my @MPTARR          = ();

# Does server have Fusion-IO devices in ioscan?
#
my @FUSIONIOARR     = ();
my $FUSIONIO_FLAG   = 0;

# How many mailboxes in /var/mail?
#
my $mboxcount       = 0;

my $envconf         = "/etc/envd.conf";

# Primary and alternate boot disks
#
my $ckpriboot       = q{};
my $ckaltboot       = q{};

# Are there any striped volumes in LVM?
#
my @STRIPEDVOLS     = ();

my @VOLMGRTYPE      = ();
my @VOLMGRTYPE2     = ();
my @VOLMGRTYPE3     = ();

# Array of LANs
#
my @LANSTAT         = ();

# Array of ATMs
#
my @ATMLANS         = ();
my @ATMarray        = ();

# Infiniband array
#
my @IBarray         = ();

my $TDFLAG          = q{};
my $FCDFLAG         = q{};
my $NUMUSRGRP_FLAG  = 0;
my $CAPADV_FLAG     = 0;
my $CISSEC_FLAG     = 0;
my $DSAU_FLAG       = 0;
my $ISOIMAGE_FLAG   = 0;
my $CCCLUSTER_FLAG  = 0;
my $HORCMD_FLAG     = 0; 
my @PAMARR          = ();
my @FINDARR         = ();
my @COMPARR         = ();
my $COMPID          = q{}; 
my @BDFARR          = ();
my @PASSTHRUARR     = ();
my $PTDIR           = "/dev/pt";
my $BDFARGS         = q{};
my @ALLAPAARR       = (); 
my @APAmon          = ();
my @APAst           = ();
my @ALLAPAARR2      = (); 
my @NAMARR          = ();
my $dev             = q{};

my $CMPTDIR         = "/etc/cmpt";
my $CMPTHARDCFG     = "$CMPTDIR/hardlinks/hardlinks.config";

# HP-UX asyncdsk pseudo driver - used to speed up I/O operations for databases
#
# minor number 0x000000 (default)
# minor number 0x000001 enable immediate reporting 
# minor number 0x000002 flush the CPU cache after reads
# minor number 0x000004 allow I/O timeout
# minor number 0x000005 combination of 1 and 4
# minor number 0x000007 combination of 1, 2 and 4
#
my $ASYNCDRV        = "/dev/async";

my @Boot            = ();
my @CRASHARR        = ();
my @MYDMPARR        = ();
my $dumpmatch       = q{};
my $DUMPCALC        = q{};
my $DUMPNO          = 0;
my @ALLDISKINFO     = ();
my @ALLVGS          = ();
my @LVTOT           = ();
my $lvreal          = q{};
my @VGPATH          = ();
my @ALLVGG          = ();
my @FSTABINFO       = ();
my @MKFSARR         = ();
my @FSARR           = ();
my @FSLF            = ();
my @SPMGR           = ();
my @AUTOPATH        = ();
my @stale           = ();
my @vxlicrep        = ();
my @vxlicarr        = ();
my $ADB_FLAG        = q{};
my $HA_ALTFLAG      = 0;
my $ORACLE_FLAG     = 0; 
my $BADDIR_FLAG     = 0;
my @ORAERRARR       = ();
my @ORACRS          = ();
my @GOODORA         = ();

# Is default umask set in /etc/profile?
#
my $DEFPROFILE      = "/etc/profile";
my $DEFCPROFILE     = "/etc/csh.login";
my $defumsk         = q{};
my $UMASKREAL       = q{};
my $UMASKDEF        = "0022";
my @UMASKARR        = ();

# /stand has to be HFS in HP-UX <= 11.23
#
my $Standhfs        = q{};
my $used            = q{};
my $f               = q{};
my @HFSARR          = ();
my @HFSCLEAN        = ();
my $HFSVOL          = q{};

# Default kernel
#
my $KERN            = "/stand/vmunix";
my $KMEM            = "/dev/kmem";
my $DEFSYSTEM       = "/stand/system";

# Value to pass to adb to find RAM on various HP-UX versions
# 
my $SYMBOL          = q{};

# Character device major number for VG group files in LVM
#
my $GRMAJ           = 64;
my $GRMAJL2         = 128;

my $disk            = q{};
my $mode            = q{};
my $vxe             = q{};
my $uid             = q{};
my $gid             = q{};
my $avail           = q{};
my @VMcheck         = ();  

# Bad Block Relocation policy in HP-UX < 11.31
#
my $BBR             = q{};

my $impdisk         = q{};
my $rimpdk          = q{};
my $impdisk3        = q{};
my $Diskmgrcnt      = q{};
my $Diskmgr         = q{};
my $rdev            = q{};

# Array of swap devices
#
my @Swap            = ();
my $realswappv      = q{};

my $tel             = q{};
my $z               = q{};

# Inode
#
my $ino             = q{};

# RC script configuration directory
#
my $RCCONFDIR       = "/etc/rc.config.d";

# Array of RC configs that contain valid "dots" and "dashes" in names.
# All other files with such characters in names should be moved from
# /etc/rc.config.d directory.
#
my @RCVALARR = ( "netconf-ipv6",
                 "syslog-ng",
                 "HATOOLS.parm",
                 "Nds-adm7",
                 "Nds-ds7",
                 "evfs.priv",
                 "ip6addrpool.conf",
                 "pctl.default",);

# IPFilter configs
#
my $IPFCONF         = "/etc/opt/ipf/ipf.conf";
my $IPFNAT          = "/etc/opt/ipf/ipnat.conf";
my $IPFRCCONF       = "$RCCONFDIR/ipfconf";
my $IPFRPCCONF      = "$RCCONFDIR/rpc_ipfconf";

# IpQoS
#
my $IPQOSCONF       = "$RCCONFDIR/ipqos";

# Mobile IPv4
#
my $MIPDCONF        = "$RCCONFDIR/mipdconf";
my $AAAEYCONF       = "/var/adm/mip/AAAKeyTypes.conf";

# Mobile IPv6
#
my $MIP6CONF        = "$RCCONFDIR/mip6";
my $MIP6MOD         = "/etc/mip6.conf";

# OpenView
#
my $OVBIN           = "/opt/OV/bin";
my $OVOPTCNF        = "/var/opt/OV/conf";
my $OVCONF          = "$RCCONFDIR/opcagt";
my $OPCinfo         = "$OVBIN/OpC/install/opcinfo";
my $ITOres          = "/tmp/ito_rpt_agt/ITO.rpt";
my $ITOdir          = "/opt/OV/contrib/OpC";
my @OVget           = ();
my $NODEinfo        = "$OVOPTCNF/OpC/nodeinfo";
my $MGRCONF         = "$OVOPTCNF/OpC/mgrconf";
my $SMSPIconf       = "/opt/HPO/SMSPI/smspi.cfg";
my $NNMVer          = "/var/opt/OV/NNMVersionInfo";
my $opcflag         = q{};
#
# For NNM version 8 nnmtopodump.ovpl requires authentication:
#
my $NNM8USER        = "system";
my $NNM8PASS        = "NNMpass";

my $Min             = q{};
my @INTWARN         = ();
my @CHECKARR        = ();
my $atime           = q{};
my $maxpv           = q{};
my $bgval           = q{};
my $sgval           = q{};
my $rgval           = q{};
my $lfs             = q{};
my $curpv           = q{};
my $actpv           = q{};
my $alldet          = q{};
my @vxl             = ();
my $allct           = q{};
my $Netif           = q{};
my $freepe          = q{};
my $stop_time       = q{};
my $Auto            = q{};
my $priboot         = q{};
my $altboot         = q{};
my $HAaltboot       = q{};
my $HAaltbootv3     = q{};
my $blk1            = q{};
my $blk             = q{};
my $CIFSCLFILE      = "/etc/opt/cifsclient/cifsclient.cfg";
my $ffs             = q{};
my $blksize         = q{};
my $DUPLICATE_GRNO  = 0;
my $ipstrong        = q{};
my @IPSTRONG        = ();
my @IPARR           = ();
my @IPV4NET         = ();
my $CODAWARN        = 0;
my $IPV4count       = 0;
my $REALMASK        = q{};
my $IPaddr2         = q{};
my $IPmask          = q{};
my $IPsubnet        = q{};
my $NETCALC         = q{};
my @IPSUMARR        = ();
my @NETARR          = ();
my $LANIP           = q{};
my $LANMASK         = q{};
my $LANBROAD        = q{};
my $lvsize          = q{};
my $Stand           = q{};
my $servdsk         = q{};
my $lvolid          = q{};
my $HWPATH          = q{};
my $CLASS           = q{};
my $DRVNAME         = q{};
my $Bootbuff        = q{};
my $CARDCELL        = q{};
my $CPUID           = q{};
my $CPUCELL         = q{};
my $INTRTYPE        = q{};
my $INTRID          = q{};
my $CARDDESC        = q{};
my $bblock          = q{};
my $pepv            = q{};
my $REMOTE          = q{};
my $idev            = q{};
my $iino            = q{};
my $inlink          = q{};
my $igid            = q{};
my $irdev           = q{};
my $isize           = q{};
my $iatime          = q{};
my $imtime          = q{};
my $ictime          = q{};
my $iblksize        = q{};
my $iblocks         = q{};

# PowerBroker
#
my $POWERBROKERSRV_FLAG = 0;
my $POWERBROKERCL_FLAG  = 0;
my $PBCONF              = "/etc/pb.conf";
my $PBSET               = "/etc/pb.settings";
my $PBENC               = "/etc/pb.key";
my $PBSHELL             = "/etc/pbshells.conf";

my $host            = q{};
my @Mounted         = ();
my @ALLSRVPV        = ();
my $pvcnt           = 0;
my @PVARR           = ();
my @LVMARR          = (); 
my @LVALLFSTYP      = ();
my @lvfstyp         = ();
my $pvdisk          = q{};
my $altpvdisk       = q{};
my $sblksize        = q{};
my $MEM_MBYTE       = q{};
my $MEM_BLOCK       = q{};

# The sum of physical memory and swap space must be at least 32 MB
# to ensure that a VxFS file system with 16384K intent log can be cleaned
#
my $INTLOGMIN       = 32;

# Maximum and recommended intent VxFS log size as this allows the largest
# number of requests to be pending in the log file before any intent log
# maintenance is required by the kernel
#
# In VxVM 4.1, with disk layout 6, the maximum intent log size 
# has been increased to 256 MB
#
my $RECINTLOG       = 16384;
my $vxlogsize       = q{};
my $vxdskver        = q{};

my @INTARR          = ();

my $patime          = q{};
my $Laddr           = q{};
my $LPFCCONF        = "/opt/lpfc/conf/lpfc.conf";
my $suid            = q{};
my $username        = q{};
my $allocated       = q{};
my $LanHW           = q{};
my $LanSA           = q{};
my $pcused          = q{};
my $xvfb            = q{};
my $Crd             = q{};
my $Lipkt           = q{};
my $element         = q{};
my $Lmtu            = q{};
my $Lname           = q{};
my $Lnet            = q{};
my $pctime          = q{};
my $swapdev         = q{};
my $swapfree        = q{};
my $fsreal          = q{};
my $swappctused     = q{};
my $swappriority    = q{};
my $tswap           = q{};
my $swapreserve     = q{};
my $swapstart       = q{};
my $swapused        = q{};
my $maxlv           = q{};
my $vgstat          = q{};
my $curlvs          = q{};
my $tswap2          = q{};
my $ctime           = q{};
my $mino            = q{};
my $response        = q{};
my $VMbootdisk      = q{};
my $VMtype          = q{};
my $mmode           = q{};
my @CRarr           = ();
my @CRarr2          = ();
my @CRarr3          = ();
my $state           = q{};
my $State           = q{};
my @Root            = ();
my $mmtime          = q{};
my $mnlink          = q{};
my $sblocks         = q{};
my $blocks          = q{};
my $matime          = q{};
my $satime          = q{};
my $sctime          = q{};
my $Vxopts          = q{};
my $pdev            = q{};
my $Hour            = q{};
my $pgid            = q{};
my $pino            = q{};
my $ssize           = q{};
my $pmode           = q{};
my $pmtime          = q{};
my $pnlink          = q{};
my $sdev            = q{};
my $VV              = q{};
my $sgid            = q{};
my $snlink          = q{};
my $srdev           = q{};
my $sino            = q{};
my $size            = q{};
my $smode           = q{};
my $smtime          = q{};
my $mrdev           = q{};
my $msize           = q{};
my $mtime           = q{};
my $muid            = q{};
my $smtrw           = q{};
my $sockaddr        = q{};
my $vgname          = q{};
my $VGVER           = q{};
my @lifcp           = ();
my $mirrno          = 0;
my @lifls           = ();
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
my $DayOfMonth      = q{};
my $Month           = q{};
my $Year            = q{};
my $DayOfWeek       = q{};
my $DayofYear       = q{};
my $IsDST           = q{};
my $disc1           = q{};
my $alength         = 0;
my $mblocks         = q{};
my $mctime          = q{};
my $mdev            = q{};
my  $mgid           = q{};
my $HostIP          = q{};
my $lfdir           = "lost+found";
my @BADDISK         = ();
my $gwip            = q{};
my $prdev           = q{};
my $psize           = q{};
my $puid            = q{};
my @PrimSwap        = ();
my $passnofs        = q{};
my $Lcoll           = 0;
my $Lopkt           = 0;
my $finalsa         = q{};
my @initarr         = ();
my $hourrun         = q{};
my $nlink           = q{};
my $AnsiCcw         = "/opt/softbench/lib/softbench.cwd";
my $AnsiCpluscw     = "/opt/aCC/newconfig/aCC.cwd";
my @Barr            = ();
my @Barr2           = ();
my $fstflag         = q{};
my $remfs           = q{};
my $buf             = q{};
my $buf1            = q{};
my $accnomb         = 0;
my $xfsval          = q{};
my $xdmcpdef        = q{};
my $iddsflag        = q{};
my @gspstat         = ();
my $vxcom           = q{};
my $vxcom2         = q{};
my $v1              = q{};
my $minswap         = 4096;
my $PPA             = q{};
my $Mactype         = q{};
my $prodid          = q{};
my $ok              = q{};
my $v2              = q{};
my $v3              = q{};
my $v4              = q{};
my $v5              = q{};
my $nddflag         = q{};
my $esmid           = q{};
my $dstflag         = q{};
my @entry           = ();
my $esmport         = q{};
my $doittmp         = q{};
my $mblksize        = q{};
my @Grarr           = ();
my @goodsir         = ();
my $Visible         = q{};
my @addrs           = ();
my $fcpath          = q{};
my $fcdriver        = q{};
my $HostIPsubnet    = q{};
my $Portproto       = q{};
my $fromhour        = q{};
my $tohour          = q{};
my $fileux          = q{};
my $SWname          = q{};
my $pesize          = q{};
my $totpe           = q{};
my $PESIZE          = q{};
my $FREEPE          = q{};
my $ALLOCPE         = q{};
my $PVGNAME         = q{};
my @DEACTTARR       = ();
my $STALEPE         = q{};
my $acctval         = q{};
my @Dump            = ();
my $pgsize          = q{};
my $vxdisk          = q{};
my $ALTLINK         = q{};
my @grentry         = ();
my @Fstabed         = ();
my $ORATAB          = "/etc/oratab";
my $Swstatus        = q{};
my @Badsv           = ();
my $autovg          = 0;
my $lvmresync       = q{};
my $lvmpathnb       = q{};
my @GWlist          = ();
my @haddrs          = ();
my $panic           = 0;
my $slength         = 0;
my $swapmemflag     = q{};
my $vxblocksize     = q{};
my @GSPsvrs         = ();
my $vxdisklayout    = q{};
my $vxdisksize      = q{};
my $lancount        = 0;
my @lvlist          = ();
my $vxfscount       = 0;
my $mcarecovery     = q{};
my $pblksize        = q{};
my $pblocks         = q{};
my $vxninodeflag    = 0;
my $IPsecversion    = q{};
my $sbtab           = "/var/adm/sbtab";
my $Active          = q{};
my $ppanic          = 0;
my $Min_Ign_ver     = "B.2.6";
my $inodefree       = 0;
my $TOTAL_PAGES     = 0;
my $inodepcused     = 0;
my $inodeused       = 0;
my $iotout          = "default";
my @APA             = ();
my @MAU             = ();
my $lanok           = 0;
my $Diskmgrno       = 0;
my @Bootconfdsk     = ();

# YP/NIS
#
my $NISPLUS_FLAG    = 0;
my $NISserver       = 0;
my $NISslave        = 0;
my $NISclient       = 0;
my $NISLDAP_FLAG    = 0;
my $secnets         = "/var/yp/securenets";
my $secservers      = "/var/yp/secureservers";
my $NISLDAPRC       = "/etc/rc.config.d/ypldapd";
my $NISPLUSclient   = 0;
my $NISPLUSserver   = 0;
my $NISPLUSslave    = 0;
my $NISLDAPDIR      = "/opt/ldapux";
my $NISLDAPCONTXT   = "${NISLDAPDIR}/yplpdapd/etc/namingcontexts.conf";
my $NISLDAPCONF1    = "${NISLDAPDIR}/yplpdapd/etc/ypldapd.conf";
my $NISLDAPCONF2    = "${NISLDAPDIR}/yplpdapd/ypldapd.conf";
-s      "$NISLDAPCONF1" ? $NISLDAPCONF = $NISLDAPCONF1
   : -s "$NISLDAPCONF2" ? $NISLDAPCONF = $NISLDAPCONF2
   :               $NISLDAPCONF = q{};

my $vxfsbcbufhwm    = q{};
my $BASTILLE_FLAG   = 0;
my $BASTILLELOCK    = "/var/opt/sec_mgmt/bastille/bastille_lock";
my $BASTILLECONF    = "/etc/opt/sec_mgmt/bastille/config";
my $BASTILLEREP     = "/var/opt/sec_mgmt/bastille/log/Assessment/assessment-report.txt";
my $BASTILLBASE     = "/var/opt/sec_mgmt/bastille/baselines/default_baseline";
my $CLIC_FLAG       = 0;
my $CLIC_CONF       = "$RCCONFDIR/clic_global_conf";
my $FWTMP_FLAG      = q{}; 
my $LOG_SIZE_FLAG   = 0;
my $INTCTL_FLAG     = 0;

#  nPars
#
my $DYNPAR_FLAG     = 0;
my $goodmem         = 0;
my $CLMmem          = 0;
my $SLMmem          = 0;
my $ILMmem          = 0;
my $partnum         = q{};
my @NPARARR         = ();
my @DYPARARR        = ();

my $MOUNT_CNT       = 0;
my @ALLMOUNT        = ();
my @ALLSWAPINFO     = ();
my @ALLSWPDSP       = ();
my @LVBOOTAR        = ();

# vPars
#my $VPAR_FLAG       = 0;
my $VPARCOUNT       = 0;
my $MAX_VPAR_PER_NPAR = 8; 

my $VARTMP_FLAG     = 0;
my $VGMODIFY_FLAG   = 0;
my $GETRULES_FLAG   = q{};
my $TSMCL_FLAG      = 0;
my $TSMSRV_FLAG     = 0;
my @SHELLARR        = ();
my @KERNARR         = ();
my @KERNARR2        = ();
my $HPVM_FLAG       = 0;
my $HPVMVERSION     = q{};
my $HPVMVERSION2    = q{};
my $iSCSIFLAG       = 0;
my $pstreeflag      = q{};
my $pribootv3       = q{};
my $USERPASS        = q{};
my $altbootv3       = q{};
my $SASFLAG         = q{};
my $snmperror       = q{};
my $snmpsession     = q{};
my $SrvHostIP       = q{};

# Crashdump
my $TOTAL_DUMP_PAGES = 0;
my $DUMPCOMPRESS    = q{};
#
# The following requirements must be met to achieve multiple dump units,
# and hence parallelism:
#
# Multiple CPUs:
#    One CPU per dump unit for an uncompressed dump. For example,
#    to achieve 4-way parallelism (4 dump units) in an uncompressed dump,
#    the system must have at least 4 CPUs.
#
#    Five CPUs per dump unit for a compressed dump (4 CPUs compressing data
#    and one CPU writing the data to the disks).
#
my $PARDUMPCPU      = 5;

my $UXSA            = "/var/adm/sa";
my $SSHD_CONF       = '';
my $SSHD_CONF1      = '/etc/opt/ssh/sshd_config';
my $SSHD_CONF2      = '/opt/ssh/etc/sshd_config';
my $SSHD_CONF3      = '/usr/local/etc/sshd_config';
my $SSHD_CONF4      = '/usr/local/ssh/etc/sshd_config';
my $SrvHostIPsubnet = q{};
my $exphflag        = q{};
my $eoverflag       = q{};
my $IPNODES_FLAG    = 0;
my $HOSTS_FLAG      = 0;
my $nisflag         = 0;
my $rootacc         = q{};
my $rootpasswd      = q{};
my $rootuid         = q{};
my $rootgid         = q{};
my $rootgecos       = q{};
my $roothome        = q{};
my $rootshell       = q{};
my $ACTUAL_VALUE    = q{};
my $NETBCKCONF      = q{};
my $NETBCKVER       = q{};
my $dumpdates       = "/etc/dumpdates";
my $vxdumpdates     = "/etc/dumpdates";
my $fbackupdates    = "/var/adm/fbackupfiles/dates";
my @Dumplvol        = ();
my @PPP             = ();
my $PPP             = q{};
my $ESMport         = q{};
my $PWGR_FLAG       = 0;
my @ESMportarr      = ();
my $execstackflag   = 1;
my $dinst           = q{};
my $y               = q{};
my @es              = ();
my $dpath           = q{};
my $disc2           = q{};
my $dstatus         = q{};
my $disc3           = q{};
my $disc4           = q{};
my $ddesc           = q{};
my $domname         = q{};
my $remote          = q{};
my $refid           = q{};
my $st              = q{};
my $tm              = q{};
my $when            = q{};
my $poll            = q{};
my $reach           = q{};
my $delay           = q{};
my $offset          = q{};
my $displ           = q{};
my $ERMflag         = 0;
my $PWYN            = q{};
my $SANbootdisk     = 0;
my $PWPN            = q{};
my $SSHRHOST        = q{};
my $SSHEMPTYPW      = q{};
my $SSHPRIVSEP      = q{};
my $SSHSTRICT       = q{};
my $SSHTCPFWD       = q{};
my $tcpstate        = q{};
my $tcptot          = 0;
#
# 12 Kbytes of memory for each TCP connection that is not in
# TIME_WAIT state
#
my $tcpmemutl       = 12;
my @TCPARRSTAT      = ();
my $SSHTCPTUN       = q{}; 
my @ESMfull         = ();
my $PROCNO5         = q{};
my @CPU_no          = ();
my $PVID            = q{};
my $PVID1           = q{};
my $PVID2           = q{};
my $VGID            = q{};
my $VGID1           = q{};
my $VGID2           = q{};
my @tpint           = ();
my @tpdiff          = ();
my %tpc             = ();
my $firsttapeent    = q{};
my $tapecont        = q{};
my @tapecontrollers = ();
my $ccount          = q{};
my $vconspid        = q{};
my @vconsmpsched    = ();
my $reallancardno   = 0;
my $lancardno       = 0;
my $ordlast         = q{};
my $ordlast2        = q{};
my $CPUHINTS        = '/usr/include/sys/unistd.h';
my $impdk           = q{};
my $groupfile       = q{};
my $MOUNTORDER      = 1;
my $ORDMOUNTCNT     = 1;
my @MOUNTORD        = ();
my @ALLVGARRAY      = ();
my @ACTIVEVGARRAY   = ();
my @ALLVGLVMTAB     = ();
my @ALLVGLVMTABL2   = ();
my $LVMLOCK         = "/etc/lvmconf/lvm_lock";
my $PVLOCK          = "/etc/lvmconf/pv_lock";
my $VGNAMEALL       = q{};
my $CPUDESC         = q{};
my @IMPDISK         = ();
my $ACTIVECPUNO     = q{};
my $bufpagesflag    = q{};
my @LVarr           = ();
my $DBC_MAX_PCT     = 8;
my $scrflag         = 0;
my $bunset          = q{};
my @PPanarray       = ();
my @Panarray        = ();
my $System          = q{};
my $Hostname        = q{};
my $RCHOSTNAME      = q{};
my $RCNODENAME      = q{};
my $SHostname       = q{};
my $Maj             = q{};
my $Version         = q{};
my $Major           = q{};
my $Minor           = q{};
my $Patch           = q{};
my $buset           = q{};
my $scsi_max_qdepth = q{};
my $nbufflag        = q{};
my $dbcmaxflag      = q{};
my $dbcminflag      = q{};
my $maxvgsflag      = q{};
my $maxuprcflag     = q{};
my @olack           = ();
my $NETWKCONF       = "/sbin/init.d/networker";
my $SDUXpush        = "/var/adm/sw/.sdkey";
my $swsave          = "/var/adm/sw/save";
my $swsec           = "/var/adm/sw/security/secrets";
my $Kmemdev         = "/dev/kmem";
my $diskcont        = q{};
my @Allcontrollers  = ();
my $svctrl          = q{};
my $lhentry         = "127.0.0.1";
my $tcbdef          = "/tcb/files/auth/system/default";
my $tcbttys         = "/tcb/files/ttys";
my $snmpmod         = "Net::SNMP";
my $snmphostname    = shift || 'localhost';
my $snmpcommunity   = shift || 'public';
my $snmpport        = shift || 161;
my $oid             = shift || '1.3.6.1.4.1.11.3.0';
my $TMPCLEAN        = "$RCCONFDIR/clean_tmps";
my $VLANCONF        = "$RCCONFDIR/vlanconf";
my @SWarray         = ();
my $jfs             = q{};

# NFS sharing and exports
#
my $exportfs        = "/etc/exports";
my $sharetab        = q{};
my $DEFNFS          = "/etc/default/nfs";
my $NFSMAPID        = q{};
my $initt           = "/etc/inittab";
my $nfsconf         = "$RCCONFDIR/nfsconf";
my $nfssec          = "/etc/nfssec.conf";
my $RCMCONF         = "$RCCONFDIR/rcmconfig";
my $nfscount        = 0;
my $nfsavoid        = q{};
my $maxthreadproc   = q{};
my $nfs2maxthreads  = q{};
my $nfs3maxthreads  = q{};
my $nfs4maxthreads  = q{};
my $nfsfinegrain    = q{};
my $nfsnewlock      = q{};
my $nfsnewrnode     = q{};
my $nfswakeup       = q{};
my $nfsnewacache    = q{};
my $nfsexportfs     = q{};

# System Management Homepage
#
my $SMHXML          = "/opt/hpsmh/conf.common/smhpd.xml";
my $SMHDIR          = "/opt/hpsmh";
my $SMHCONFDIR      = "${SMHDIR}/conf";
my $SMHASSISTFLAG   = q{};

# MINPASSDEF should define 8 characters as minimum for passwords
# PASSDEPTH should define 8 characters as minimum for password history
#
my $defsec          = "/etc/default/security";
my $MINPASS         = q{};
my $MINPASSDEF      = 8;
my $PASSDEPTH       = q{};
my $PASSDEPTHDEF    = 8;
my $AUDITFLAG       = q{};
my $LOGINSTRICT     = q{};
my $PASSSTRICT      = q{};
my $AUDNAMES        = "/etc/audit/audnames";
my $AUDSITE         = "/etc/audit/audit_site.conf";
my $AUDFILTER       = "/etc/audit/filter.conf";
my $AUDRC           = "/etc/rc.config.d/auditing";
my @AUDARR          = ();
my @PASSARR         = ();
my $LOGINALLOW      = q{};
my $ABORTHOME       = q{};

# HP-UX 11.31 support for Shadow passwords with up
# to 255 characters
#
my $LONGPASS        = q{};
my $CRYPTDEF        = q{};
my $CRYPTVAL        = 6;
my $CRYPTALG        = q{};
my $CRYPTSTR        = "__unix__";
my $LONGPASS_FLAG   = 0;
my @LPASSARR        = ();

my $ALLOWNPASS      = q{};
my $NOLOGIN         = q{};
my $nologinf        = "/etc/nologin";
my $BOOTAUTH        = q{};
my $BYPASSSEC       = "/etc/default/I_ACCEPT_RESPONSIBILITY_FOR_BYPASSING_SECURITY_CHECKS";

my $suroot          = 0;
my $sectty          = "/etc/securetty";
my $Rootdir         = "/root";
my @lsbundle        = ();
my $SWdir           = "/var/adm/sw/products";
my $SWINSTALLLOCK   = "$SWdir/swlock";
my $SWINDEX         = "$SWdir/INDEX";
my $SWINFO          = "$SWdir/ifiles/INFO";
my $TCB             = q{};
my $TCB2            = q{};
my $DEFPS           = "/etc/default/ps";

#
# If ugconf exists, tsconvert will fail on HP-UX 11.31 (sysconf _SC_EXTENDED_LOGIN_NAME returns 1)
#
my $UGCONF          = "/etc/default/ugconf";

$TCB                = `/usr/lbin/getprdef -r 2>&1 | egrep "not trusted"`;
$TCB2               = `/usr/sbin/getprdev 2>&1 | egrep "not trusted"`;
my $defckhfile      = "/tmp/check_patches.report";
my @PassWdarr       = ();
my $envdconf        = "/etc/envd.conf";
my @envd            = ();
my @VPARARRAY       = (
                      '/dev/vcn', '/dev/vpmon', '/dev/vcs',
                      );
my @SQUIDarray      = (
                      '/etc/squid.conf', '/etc/squid/squid.conf',
                      '/usr/local/squid/etc/squid.conf',
                      '/usr/local/etc/squid.conf',
                      '/opt/squid/etc/squid.conf',
                      );
my @APACHEarray     = (
                      '/etc/httpd.conf', '/opt/hpws/apache/conf/httpd.conf',
                      '/usr/local/apache/conf/httpd.conf',
                      '/usr/local/etc/httpd.conf',
                      '/etc/httpd/conf/httpd.conf',
                      '/usr/local/apache2/conf/squid.conf',
                      );
my @Proftpdarray    = (
                      '/etc/proftpd.conf',
                      '/opt/iexpress/proftpd/etc/proftpd.conf',
                      '/usr/local/etc/proftpd.conf',
                      '/opt/proftpd/etc/proftpd.conf',
                      );
my @VSftpdarray     = (
                      '/etc/vsftpd.conf',
                      '/etc/vsftpd.banned_emails',
                      '/etc/vsftpd.chroot_list',
                      '/etc/vsftpd.user_list',
                      );
my @mailboxdir      = ("/var/mail",);
my @PRIVACY         = ();
my $RELAY           = q{};
my @port            = ();
my $SMTPD           = "/etc/mail/sendmail.cf";
my @ftpDisArr       = ();
my @lastpv          = ();
my $svalic          = "/opt/sva/etc/license/SVA.lic";
my $Vrtslicdir      = "/etc/vx/elm";
my $SoftBenchcw     = "/etc/update.lib/codeword";
my $alis            = "/etc/mail/aliases";
my $SERVICES        = "/etc/services";
my $PROTOCOLS       = "/etc/protocols";
my $ETHERS          = "/etc/ethers";
my $Igniteversion   = `cat /opt/ignite/Version 2>/dev/null`;
chomp($Igniteversion);
my $ARRFLAG         = 0;
my $SASDFLAG        = 0;
my @SASDINFO        = ();
my @SASDLUN         = ();
my @IRDIAGARR       = ();
my $DIAGVER         = 1;
my $CSTMCOMM        = "selall;info;vers;wait;infolog;Done;quit;OK";
my $ACCTCONF        = "$RCCONFDIR/acct";
my $accholidays     = "/etc/acct/holidays";
my $RSYSLOG         = q{};
my $dpck            = "/etc/opt/omni/client/cell_server";
my $OMNIRC          = "/opt/omni/.omnirc";
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
my $TIMEOUT         = 180;
my $MINPVTIMEOUT    = 30;
my $crashconf       = 1;
my $MAXVGS          = 256;
my $MAXVGSC         = q{};
my $MAXVGSVX        = 256;
my $lpanalyser      = "/var/adm/lp/lpana.log";
my @OVset           = ();
my @EMC             = ();
my @EMCCFG          = ();
my @EMCGATE         = ();
my @SYMPD           = ();
my @SYMRDF          = ();
my @SYMDG           = ();
my @MAJMIN          = ();
my @FINDUP          = ();
my @CISS            = ();
my @INTRAID         = ();
my $GNO             = q{};
my $RAIDgroup       = q{};
my $RAIDtype        = q{};
my $IVH             = q{};
my $IVM             = q{};
my $MUNH            = q{};
my $MUNM            = q{};
my @RAIDARRAY       = ();
my @ARRAYDSP        = ();
my @XPINFO          = ();
my $RSMHACFG        = "/opt/Hewlett-Packard/RSMHostSW/RSMHA/hprsmha.cfg";
my @SANLUN          = ();
my @EMULEX          = ();
my @EVADISC         = ();
my @EVAINFO         = ();
my @EVAINFOWWN      = ();
my @TDLIST          = ();
my @FCDLIST         = ();
my @LANCOREarray    = ();
my @Lanshow         = ();
my @Dmust           = ( "inetd", "sshd", "syslogd", "syslog-ng", "cron", );
my @Nott            = (
                      "automount", "snmpdm", "routed", "gated",
                      "dtlogin",   "ypserv", "ypbind", "dtrc",
                      "pwgrd",     "Xhp",    "xinit",  "scrdaemon",
                      );
my $NETBCKDIR       = q{};
my $NETBCKDIR1      = "/usr/openv";
my $NETBCKDIR2      = "/opt/openv";
my @Badsw           = ();
my @SUarray         = ();
my @SUent           = ();
my $sudoconf        = q{};
my $sudoconf1       = "/etc/sudoers";
my $sudoconf2       = "/opt/sudo/etc/sudoers";
my $sudoconf3       = "/usr/local/etc/sudoers";
my $sulog           = "/var/adm/sulog";
my $Superconf       = q{};
my $Superconf1      = "/opt/super/etc/super.tab";
my $Superconf2      = "/etc/super.tab";
my $Superconf3      = "/usr/local/etc/super.tab";
my $SPC_CONF        = "/etc/opt/sec_mgmt/spc/spc_config";
my $SWA_CONF        = "/etc/opt/swa/swa.conf";
my $SWAIGNORE       = "$ENV{'HOME'}/.swa/ignore";
my $ssd             = "$RCCONFDIR/syslogd";
my $inetd           = "$RCCONFDIR/netdaemons";

# Array of SAN LUNs in ioscan
#
my @SANdiskarray    = ();

# Array of CD-ROM and DVD devices in ioscan
#
my @CDDVDarray      = ();

# Mailbox threshold, warning reported if larger than threshold
#
my $MBOX_THRESHOLD  = 51200 ; # 50 MB = 51200 KB

# WTMP, BTMP threshold, warning reported if larger than threshold
#
my $WTMP_THRESHOLD  = 51200 ; # 50 MB = 51200 KB

my @pvlist          = ();
my $kernrem         = 0;
my @Lanlinkloop     = ();
my $kernval         = 0;
my $FINALKERN       = 0;
my $KERNSTART       = 0;
my $KERNEND         = 0;
my $KERNSIZE        = 0;
my $dsknohwcnt      = 0;
my $dsklvmcnt       = 0;
my $dskunclaimedcnt = 0;
my $nondskunclaimedcnt = 0;
my $dsksuspendedcnt = 0;
my $dskerrorcnt     = 0;
my $dskdiffhwcnt    = 0;
my $dskscancnt      = 0;
my $dskunusablecnt  = 0;
my $dsknotlvmcnt    = 0;
my $cdisk           = q{};
my $rdisk           = q{};
my @InclDisks       = ();
my @InclDisksS2     = ();
my @corelan         = ();
my $RAM_THRESHOLD   = 8192;
my @Passnumarr      = ();
my $st_ats          = q{};
my $ssidscript      = q{};
my $eoverflow       = q{};

#
# Maximum value for percentage of physical memory that can be used by audit sybsystem
# (default is 5%)
#
my $audmem          = q{};
my $MAXAUDMEMPC     = 20;

my $numapolicy      = q{};
my $timeslice       = q{};
my $numamode        = q{};
my $dumpconc        = 1;
my $dumpcprs        = 1;
my $lcpuattr        = 0;
my @Grnumarr        = ();
my @ARMLICENSE      = ();
my $MSGFILE         = '/var/adm/messages';
my $CRDIR           = "/var/spool/cron/crontabs";
my $CRFILE          = "$CRDIR/root";
my $WARNSTR         = 'AUDIT-WARN:';
my $ERRSTR          = 'AUDIT-FAIL:';
my $NOTESTR         = 'AUDIT-NOTE:';
my $INFOSTR         = 'AUDIT-INFO:';
my $PASSSTR         = 'AUDIT-PASS:';
my $Secure_SYSLOGD  = 0;
my $IGNITE_FLAG     = 0;
my $BOOTSYS_BLOCK   = "/.bootsys_block"; 
my $AAA_FLAG        = 0;
my $PPU_FLAG        = 0;
my $POSTFIX_FLAG    = 0;
my $SENDMAIL_FLAG   = 0;
my $EXIM_FLAG       = 0;
my $VRTSVCS_FLAG    = 0;
my $LVMTAB_FLAG     = 0;
my $LVMTABL2_FLAG   = 0;
my $exphostflag     = 0;
my $WLMD_FLAG       = 0;
my $GWLMCMSPROP     = "/etc/opt/gwlm/conf/gwlmcms.properties";
my $GWLMPROP        = "/etc/opt/gwlm/properties";
my $GWLMAGTPROP     = "/etc/opt/gwlm/conf/gwlmagent.properties";
my $ADPROP          = "/var/opt/amgr/agent.properties";
my $MXPATHPROP      = "/etc/opt/mx/config/path.properties";
my $SIMPROP         = "/etc/opt/mx/config/globalsettings.props";
my $CIM_FLAG        = 0;
my $BDF_FLAG        = 0;
my $SFM_FLAG        = 0;
my $PRM_FLAG        = 0;
my $RCM_FLAG        = 0;
my $WLMCONF         = "$RCCONFDIR/wlm";
my $PRMCONF         = "$RCCONFDIR/prm";
my $PRMRUNCONF      = '/etc/prmconf';
my $PRMRUNCONF2     = '/var/opt/prm/PRM.prmconf';
my $IOSCANADD       = q{};
my @BADIOHEALTH     = ();
my @GOODIOHEALTH     = ();
my $IOSCAN_FLAG     = 0;
my $VCONSD_FLAG     = 0;
my $NODENAME_LEN    = 8;
my $SVA_FLAG        = 0;
my $defrootshell    = '/sbin/sh';
my $CSTM_FLAG       = 0;
my @SWAPARRAY       = ();
my @ALLSWAPVAL      = ();
my @BADSWAPARR      = ();
my $lvmconf         = '/etc/lvmrc';
my $LVMCONFDIR      = '/etc/lvmconf';
my $pam_conf        = "/etc/pam.conf";
my $pamuser_conf    = "/etc/pam_user.conf";
my $PAMREG          = "/var/sam/ts/pam_mod.reg";
my $FSTAB           = '/etc/fstab';
my $RAMDISKTAB      = "/etc/ramdsktab";
my @RAMdiskarray    = ();
my $RMTAB           = '/etc/rmtab';
my $USETAB          = '/var/sam/fs/usetab';

# EVFS
#
my $EVFSDEVDIR      = '/dev/evfs';
my $ETCEVFSDIR      = '/etc/evfs';
my $EVFSTAB         = "${ETCEVFSDIR}/evfstab";
my $EVFSCONF        = "${ETCEVFSDIR}/evfs.conf";
my $EVFSCRYPTX      = "${ETCEVFSDIR}/evfs_cryptx.conf";
my $EVFSRC          = "${RCCONFDIR}/evfs";
my $EVFSPKEY        = "${ETCEVFSDIR}/pkey";
my $EVFS_FLAG       = 0;

my $UPSTAB          = '/etc/ups_conf';
my $DHCPTAB         = '/etc/dhcptab';
my $DHCPDENY        = '/etc/dhcpdeny';
my $DHCPV6TAB       = '/etc/dhcpv6tab';
my $dhcpcl          = "/etc/dhcpclient.data";
my $dhcpv6cl        = "/etc/dhcpv6client.data";
my $ISCDHCPTAB      = '/etc/dhcpd.conf';
my $BOOTPTAB        = '/etc/bootptab';
my $TUNEFSTAB       = '/etc/vx/tunefstab';
my $MNTTAB          = '/etc/mnttab';
my $tvs             = '/var/tombstones/ts99';
my $samcrash        = '/dev/dsk/disk_query';
my $samcrash2       = '/dev/rdsk/disk_query';
my $svaconf         = '/opt/sva/etc/sva.conf';

# LVM
my $VG00BBR              = "off";
my $VG00ALLOCCONT        = "strict/contiguous";
my $VG00ALLOCNONCONT     = "strict";
my $THRESHOLD_MAX_PE     = 16000;
my $THRESHOLD_MAX_PV     = 16;
my $THRESHOLD_MAX_LV     = 255;
my $THRESHOLD_MAX_VG     = 50;
my $lvsizedef            = 4096;

# Lvmtab for L1 and L2 disk layout
# (L2 is part of HP-UX 11.31 from March 2008) 
#
my $LVMTAB               = "/etc/lvmtab";
my $LVMTABL2             = "/etc/lvmtab_p";

my $THRESHOLD_MIN_QDEPTH = 8;

# Host Intrusion Detection System
my $esm        = "/esm/config/tcp_port.dat";
my $esmmgr     = "/esm/config/manager.dat";
my $esmrc      = "/esm/esmrc";
my $esmportdef = 5600;
my @ESMarr     = ();

# System Information Reporter
my $sircfg     = '/opt/sir/sir.cfg';
my $goodsir    = 0;
my @SIRjobs    = ("send.sh");
my $goodserial = 0;

my $SWAP_DEV_NO        = 0;
my $SWAP_NETWORK_NO    = 0;
my $SWAP_FS_NO         = 0;
my $SWAP_LOCALFS_NO    = 0;
my $tswapall           = 0;
my $tswapall2          = 0;
my $SWAP_THRESHOLD     = 15;
my $THRESHOLD          = 90;
my $mingood            = 100 - $THRESHOLD;
my $CPU_IDLE_THRESHOLD = 15;

my $SAVECRASH    = "$RCCONFDIR/savecrash";
my $CRASHCONF    = "$RCCONFDIR/crashconf";
my $dumpmem      = 0;
my $savecrash    = 1;
my $foregrd      = 1;
my $savecrashdir = q{};
my $savecrashdef = "/var/adm/crash";

my $UMETERCONF   = "/etc/opt/meter/meter.xml";

# VXVM
#
my $VXCONF       = "/sbin/init.d/vxvm-sysboot";
my $VXCONFS      = "/sbin/init.d/vxvm-startup";
my $VXFSFLAG     = "-F vxfs -t 20";
my $VXFSNOREORG  = "/etc/fs/vxfs/vxfs_noreorg_config";
my $VXCONFIG     = 0;
my $VXSWAP       = 0;
my $vxmaxflag    = q{};
my $VXDEFATTRS   = "/etc/default/vxassist";
my $VXDBFILE     = "/etc/vx/reconfig.d/state.d/install-db";
my $VXBOOT       = 0;
my $volboot      = "/etc/vx/volboot";
my @VXBOOTDISK   = ();
my @VXERRARR     = ();
my @NOTVXARR     = ();
my @NOTLVMARR    = ();
my @VXINFOARR    = ();
my @VXALLDISK    = ();
my @VXALLDG      = ();
my $VXFENTAB     = "/etc/vxfentab";
my @CHECKVXVM    = ();
my $vxdiskls     = q{};
my $DEFBOOTDG    = "nodg";
my $rootdg       = "rootdg";

# Ignite
#
my $igndir    = "/var/opt/ignite";
my $etcigndir = "/etc/opt/ignite";
my $bootigndir= "/opt/ignite/boot";
my $instlcfg  = "${etcigndir}/instl_boottab";
my $hostinfo  = "${igndir}/local/host.info";
my $confinfo  = "${igndir}/local/config";
my $confrec   = "${igndir}/local/config.recovery";
my $preview   = "${igndir}/recovery/previews";
my $rpreview  = "${igndir}/clients/$Hostname/recovery/client_status";
my $IGNINDEX  = "${igndir}/INDEX";

# SNMP configs
#
my $SNMPconf   = '/etc/SnmpAgent.d/snmpd.conf';
my $SNMPmaster = "$RCCONFDIR/SnmpMaster";
my $SNMPHpunix = "$RCCONFDIR/SnmpHpunix";
my $SNMPMib2   = "$RCCONFDIR/SnmpMib2";
my $SNMPTrpDst = "$RCCONFDIR/SnmpTrpDst";
my $SNMP_FLAG  = 0;
my @SNMPINFO   = ();

# HIDS configs
#
my $aide_conf = "/usr/local/etc/aide.conf";
my $ids_conf  = "/etc/opt/ids/ids.cf";

# Check directories sticky-bit
#
my @Stickyarr   = ( "/tmp", "/var/tmp", "/var/spool/sockets",
                  "/var/preserve", "/var/X11/Xserver/log",
                  "/var/spool/sockets/common", );
my @remaccarr   = ( ".netrc", ".rhosts", ".shosts", );

# LVM defaults
#
my $LVBOOT      = 0;
my $LVROOT      = 0;
my $LVSWAP      = 0;
my $LVDUMP      = 0;
my $LVBDISK     = 0;
my $DefMinBootSize = 18;   # Boot disks should be 18 GB minimum for HP-UX 11i v1
my $MinBootSize = q{};
my $bings       = 0;
my $Seen        = q{};
my @bootara     = ();
my $standboot   = '/stand/bootconf';
my $standroot   = '/stand/rootconf';
my @ROOTARR     = ();
my $STANDFLAG   = 0;
my @STBOOTARR   = ();
my @BOOTCARR    = ();
my @rootchead   = ();
my $rootsizeKB  = q{};
my $hexroots    = q{};
my $decroots    = q{};
my $bdfroots    = q{};

# Password checks
#
my $uidno            = 0;
my $Shadow           = '/etc/shadow';
#
# If patch PHCO_36426 or later is installed on HP-UX 11.23,
# then for systems using shadow passwords the rounding of password
# aging arguments can be suppressed by creating the file
# /etc/default/DO_NOT_ROUND_PW_AGING.
# If the file exists, then the password command does not round
# the "-x", "-n", and "-w" values to a multiple of a week.
# The use of this file is specific to this release. New releases
# will change the password command to never round aging values
# for systems that are using shadow passwords.
#
my $SHADOWROUND      = "/etc/default/DO_NOT_ROUND_PW_AGING";
my $shaduser         = q{};
my @SHADWARN         = ();
my $pwgrdconf        = "$RCCONFDIR/pwgr";
my $PASSWD_THRESHOLD = 200;
my $pwgrdir          = '/var/spool/sockets/pwgr';
my $privgrp          = '/etc/privgroup';

my $MISSING_FS_FLAG = 0;

# Login messages
#
my $ISSUE = '/etc/issue';
my $MOTD  = '/etc/motd';

# Inetd configs
#
my $INETD      = "/etc/inetd.conf";
my $GATED      = "/etc/gated.conf";
my $GATEDNEW   = "/etc/gated.conf+";
my $GATED_FLAG = 0;
my $KINETD     = "/etc/inetsvcs.conf";
my $INETDSEC   = "/var/adm/inetd.sec";
my $hostequiv  = "/etc/hosts.equiv";
my $hostallow  = "/etc/hosts.allow";
my $hostdeny   = "/etc/hosts.deny";
my $ntpconf    = "/etc/ntp.conf";
my $Shells     = "/etc/shells";
my $Shutlog    = "/etc/shutdownlog";
my $Rclog      = "/etc/rc.log";
my $CRONDIR    = "/var/adm/cron";
my $CRON_DENY  = "$CRONDIR/cron.deny";
my $CRON_ALLOW = "$CRONDIR/cron.allow";
my $AT_DENY    = "$CRONDIR/at.deny";
my $AT_ALLOW   = "$CRONDIR/at.allow";
my $QUEDEFS    = "$CRONDIR/queuedefs";
my $CRONLOG    = "$CRONDIR/log";
my $GLANCECF   = "/var/opt/perf/parm";

# Network
#
my $NDDCONF   = "$RCCONFDIR/nddconf";
my $NETCONF   = "$RCCONFDIR/netconf";
my $NETCONFV6 = "$RCCONFDIR/netconf-ipv6";
my $IPv6dev   = "/dev/ip6";
my $RTRADVD   =  "/etc/rtradvd.conf";
my @rtradvdC  = ();
my @NDset     = ();
my $APAconf   = "$RCCONFDIR/hp_apaconf";
my $APAport   = "$RCCONFDIR/hp_apaportconf";
my $APAasc    = "/etc/lanmon/lanconfig.ascii";

# SAM configs
#
my $RESTRSAM  = "/etc/sam/custom/username.cf";
my $SAMEXUSR  = "/etc/sam/rmuser.excl";
my $SAMEXFILE = "/etc/sam/rmfiles.excl";
my $SAMEXGRP  = "/etc/sam/rmgroup.excl";
my $CUSTSAM   = "/etc/sam/custom.cu";

# System Configuration Daemon
#
my $SCRCONF = "$RCCONFDIR/scrdaemon";

# Codeword files
#
my $cw        = "/var/adm/sw/.codewords";
my $glancecw  = "/var/opt/perf/gkey";
my $mwakey    = "/var/opt/perf/mwakey";
my $pvkey     = "/var/opt/perf/pvkey";
my $glancecw1 = "/opt/perf/newconfig/gkey";
my $ovnnmlic  = "/var/opt/OV/HPOvLIC/LicFile.txt";
my $ovnnmlic2 = "/etc/opt/OV/HPOvLIC/.license";
my $NSDIRSVR_FLAG = 0;
my $RHDIRSVR_FLAG = 0;
my $LDAPDIR   = "/etc/opt/ldapux";
my $LDAPDIR2  = "/etc/opt/dirsrv";
my $ldaplic   = "${LDAPDIR}/licenses/libxml2-license.txt";
my $LDAPAUTHZ  = "${LDAPDIR}/pam_authz.policy";
my $wlmlic1   = "/opt/wlm/lib/mongui/LGPL.txt";
my $wlmlic2   = "/opt/wlm/lib/README.libxml2";

# Cell-based systems (rx7640, rx8640 and Superdome) are non-uniform
# memory access capable (NUMA), and even then only in multi-cell
# partitions.
#
# To see if a given system is NUMA or not, run:
#
# mpsched -s
#
# If the locality domain count is > 1, your system is NUMA.
#
my $NUMACOUNT = 1;

# Hostname resolution
#
my $NAMED     = '/etc/resolv.conf';
my $DOMCOUNT  = 0;
my $SEARCHCOUNT = 0;
my $MAXDNSSRV = 3;
my $DNS_NO    = 0;
my $DNSdefdom = q{};
my @MYDNSSRV  = ();
my $DNSCONF   = '/etc/named.conf';
my $DNSCONF2  = '/etc/named.boot';
my @DNSarray  = ( $DNSCONF, $DNSCONF2, );
my $HOSTS     = '/etc/hosts';
my @HOSTWARN  = ();
my $NSSWITCH  = '/etc/nsswitch.conf';
my $NAMEDCONF = "$RCCONFDIR/namesvrs";

my @SECARR    = ();
my @INETSWARN = ();

# GSP (MP) prompts (change them if required)
#
my $GSPprompt   = "MP>";
my $GSPCMprompt = "MP:CM>";
my $GSPppr      = "MP password:";
my $GSPlpr      = "MP login:";

my $DBC_MIN_PCT     = 5;
my $FTP_FLAG        = 0;
my $ftpacc          = '/etc/ftpd/ftpaccess';
my $ftpusers        = '/etc/ftpd/ftpusers';
my $ftphosts        = '/etc/ftpd/ftphosts';
my $Vparcontrol     = q{};
my $rv              = 0;
my $FOREGROUND_FLAG = 0;
my @LANarray        = ();
my @Alllanscan      = ();
my @Alllanscan2     = ();
my @CPUarray        = ();
my $ESMD_FLAG       = 0;
my $ESMDM_FLAG      = 0;
my @NFSarr          = ();
my $STATMON         = "/var/statmon/sm";
my @Depotarr        = ();

# Npar and Vpar configs
#
my $vpdb     = '/stand/vpdb';
my $vpard    = "$RCCONFDIR/vpard";
my $vparhb   = "$RCCONFDIR/vparhb";
my $vparinit = "$RCCONFDIR/vparinit";

# Where to start SUID/SGID file search
#
my @directories_to_search = ("/");

my $LVM_FLAG               = 0;
my $SETBOOTARG             = "-v";
my $KERNEL_BITS            = 32;
my $CPU_HW_SUPPORT         = 32;
my $syslog_conf            = "/etc/syslog.conf";
my @WARNSLOGARR            = ();
my $SYSLOG_FLAG            = 0;
my $syslogng_conf          = q{};
my $syslogng_conf1         = "/etc/syslog-ng.conf";
my $syslogng_conf2         = "/etc/syslog-ng/syslog-ng.conf";
my $SYSLOG                 = "/var/adm/syslog/syslog.log";
my $SYSINIT_FLAG           = 0;
my @INITARR                = ();
my $shealth                = 0;
my $cpucount               = 0;
my $passno                 = 0;
my $SECPATCH_FLAG          = 0;
my $STAND_FLAG             = 0;
my $NTP_REST_FLAG          = 0;
my $RBAC_FLAG              = 0;
my $keystroke              = 0;
my $keybanner              = 0;
my $keylimit               = q{};
my $RBACDIR                = "/etc/rbac";
my $RBACCONF               = "${RBACDIR}/rbac.conf";
my $IDS_FLAG               = 0;
my $LICENSE                = 0;
my @licdaemon              = ();
my $THRESHOLD_MAXUPRC_FLAG = 256;
my $LPSCHED                = 0;
my $ldap_conf              = "/etc/ldap.conf";
my $sldap_conf             = "/etc/openldap/slapd.conf";
my $ldap2_conf             = "/etc/openldap/ldap.conf";
my $LDAPCLIENT             = 0;
my $LDAPSERVER             = 0;
my @ldapdaemon             = ();
my $NSADMIN                = 0;
my $LPSTAND                = 0;
my @klu                    = ();
my @Alldevs                = ();
my @VVM                    = ();
my @unc                    = ();
my @suspended              = ();
my @errorhw                = ();
my @scanhw                 = ();
my @diffhw                 = ();
my @unusablehw             = ();
my @quotastat              = ();
my $LOCALHOST_FLAG         = 0;
my $OMNI_FLAG              = 0;
my $OMNIDIR                = q{};
my $OMNIDIR1               = "/usr/omni";
my $OMNIDIR2               = "/opt/omni";
my $MNT_FLAG               = 0;
my $ONLINEDIAG_FLAG        = 0;
my $DYNROOT_FLAG           = 0;
my $ISEE_FLAG              = 0;
my $ISEEDEVINFO            = "/opt/hpservices/RemoteSupport/config/deviceinfo";
my $swapdeviceno           = 0;
my $Minswapdevno           = 1;
my $SECPATHAG              = 0;
my $warnings               = 0;
my @FCarray                = ();
my @tapes                  = ();

# Serviceguard variables
#
my $SG                     = q{};
my $SGRUN                  = 0;
my @SGARR                  = ();
my @SGPROTS                = ( "hacl-probe", "hacl-cfg", "ident", );
my $SGCNT                  = 0;
my $SGSAFETYTIMERDEV       = "/dev/kepd";
my $SGSAFETYCNT            = 0;
my @SGCONFARR              = ();
my $MCCLNAME               = q{};
my $FMCCLLOCKDISK          = q{};
my $FMCCLLOCKVG            = q{};
my $SMCCLLOCKDISK          = q{};
my $SMCCLLOCKVG            = q{};
my $MAXPKG                 = 0;
my @CLARRAY                = ();
my @CLPKGARRAY             = ();
my @CLLOCKARRAY            = ();
my $CLNODE                 = q{};
my $CLLOCK                 = q{};
my $CLPACKAGE              = q{};

my $DIAGMOND               = 0;
my @DNSRUN                 = ();
my @SQUIDRUN               = ();
my @HTTPDRUN               = ();
my @allprocesses           = ();
my @ntpdaemon              = ();
my @nfsdaemon              = ();
my $secureshell            = 0;
my $autopath               = 0;
my $apacount               = 0;
my $parset                 = 0;
my $PASSFILE               = "/etc/passwd";

# Serviceguard
my $CMNODEFILE             = "/etc/cmcluster/cmclnodelist";
my $CMKNOWCMDS             = "/etc/cmcluster/cmknowncmds";
my @CMARR                  = ();
my $CMAUTHFILE             = "/etc/cmcluster/qs_authfile";
my $CMHELMD_FLAG           = 0;
my $CMHELMCONF             = "/etc/opt/helm/helm.conf";

# For Serviceguard 11.18 and later
#
my $CMCLUSTCONF            = "/etc/cmcluster.conf";

my $METROSITE              = q{};
my @METROARR               = ();

my $LMRC                   = "/etc/lmrc";
my $SLVMVGCONF             = "/dev/slvmvg";
my $DefMTU                 = 1500;
my $OS_Standard            = "Dusan HP-UX Build Standard";
my $XFONTCONF              = "$RCCONFDIR/xfs";
my $XCONF                  = "/etc/dt/config/Xconfig";
my $CDEDESKTOP             = "$RCCONFDIR/desktop";
my $XVFBCONF               = "$RCCONFDIR/xvfb";

# Timezone 
#
my $TZFILE   = '/etc/TIMEZONE';
my $TZTAB    = '/usr/lib/tztab';
my $TZDEF    = '/etc/default/tz';
my $TZHOME   = q{};
my $TZHOME2  = q{};

# Array of accounts that should be disabled for FTP access
#
my @FTPdisable = ( "root", "adm", "sys", "daemon", );

# Bundles that are most critical
#
my @SWmust = (
    "GlancePlus",         "ISEE",
    "OnlineDiag",         "Mirror",
    "Secure Shell",       "SSH",
    "Bastille",           "Host IDS",
    "System Healthcheck", "MCPS-COLLECT",
    "VRTSvcsvr",          "SwAssistant",
    "Ignite",             "Data Protector",
    "MCPS-COMMON",
);

# Systems that support vPartitioning
#
my @Models_with_vpar = (
    "SD16",   "SD32",   "SD64", "S16K",
    "Superdome2", "BL860c", "BL870c", "BL890c", "rx2800",
    "rx6600", "rx7620", "rx7640",
    "rx8420",
    "rx8620", "rx8640", "rx9610",
    "rp5405", "rp5470",
    "rp7400", "rp7405", "rp7410", "rp7420", "rp7440",
    "rp8400", "rp8420", "rp8440",
    "N4000",
);

# Subroutine for decimal to binary conversion
#
sub dec2bin {
    my $str = unpack( "B32", pack( "N", shift ) );
    $str =~ s/^0+(?=\d)//;    # otherwise you'll get leading zeros
    return $str;
}

sub loginerror {
    # print "$INFOSTR Could not connect with this login name or password\n";
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

# Display usage if "-h" option is used
#
sub Prusage {
    print <<MYMSG
    USAGE: $CMD [-b] [-c] [-e] [-f] [-h] [-l] [-n] [-s GSP_server] 
    [-S XP|EVA|EMC|OTHER] [-u GSP_login -p GSP_pass] [-o] 
    [-r] [-t conffile] [-V ALL|NONVG00|NONE] [-v] [-w]

    -b                  Brief summary of server setup
    -c                  Enable check of SUID/SGID files
    -e                  Enable EFI disk scan on Itanium servers 
                        (This test crashed HP-UX 11.23 once! Watch out)
    -f                  Force running this script even if RAM usage high
    -h                  Print this help message
    -l                  Enable NMAP scans
    -n                  Enable SUID/SGID checks in NFS (default is disable)
    -s GSP_server       IP address or FQDN of GSP (telnet to MP)
    -S XP|EVA|EMC|OTHER Type of SAN
    -u GSP_login        GSP login name
    -o                  OpenView monitoring used (default is OVO not used)
    -p GSP_pass         GSP password 
    -r                  Server part of cluster or H/A server group
    -t file             Read variables from a config file 
    -V ALL|NONVG0|NONE  VGs on SAN or local disks (default is NONE - no SAN)
    -v                  Print version of this script
    -w                  Use CMSG WorldWide Standard for O/S
                        file system sizing (default is Dusan Standard)
MYMSG
      ;
    exit(0);
}

# Ensure that modules are loaded
#
BEGIN {
    # Avoid zombies
    #
    # $SIG{CHLD} = 'IGNORE';
    #
    # On HP-UX 11.31 with latest ITRC patches (Dec 2007) this
    # creates problem when setboot(1) command is run in the
    # Perl script:
    #
    # "setboot: waitpid() failed"

    $REC_VERSION     = '5.006';
    $BEST_VERSION    = '5.008';
    $CUR_VERSION     = "$]";
    $OLDER_PERL_FLAG = 0;
    $SCRIPT_VERSION  = "2014032401";

    $opts{b} = 0;
    $opts{c} = 0;
    $opts{o} = 0;
    $opts{e} = 0;
    $opts{f} = 0;
    $opts{v} = 0;

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
        print "AUDIT-NOTE: For best results (and to avoid bugs in older versions)\n";
        print "AUDIT-NOTE: it is highly recommended to run Perl $BEST_VERSION or higher.\n";
    }

    if ( eval "require IO::Pty" ) {
        import IO::Pty;
        $pty    = new IO::Pty;
        $PTYcur = $pty->ttyname();
    }
    else {
        $PTYcur = `tty`;
        chomp($PTYcur);
    }

    my $ModuleValid = `perl -MNetAddr::IP -e 'print 1' 2>/dev/null`;

    # Both methods methods work fine on Linux but fail on HP-UX
    # if the module is not installed (I cannot get rid of the annoying
    # error that it cannot find the module...
    #
    # if ( "$ModuleValid" ) {
    #     import NetAddr::IP;
    #     use NetAddr::IP;
    # }

    # if ( eval "require import NetAddr::IP" ) {
    #     import NetAddr::IP;
    #     use NetAddr::IP;
    # }

    if ( eval "require File::Find" ) {
        import File::Find;
    }
    else {
        warn "WARN: Perl module File::Find not found\n";
    }

    if ( eval "require Socket" ) {
        import Socket;
    }
    else {
        warn "WARN: Perl module Socket not found\n";
    }

    if ( eval "require Net::Ping" ) {
        import Net::Ping;
    }
    else {
        warn "WARN: Perl module Net::Ping not found\n";
    }

    if ( eval "require Time::Local" ) {
        import Time::Local;
    }
    else {
        warn "WARN: Perl module Time::Local not found\n";
    }

    if ( eval "require Unix::Processors" ) {
        import Unix::Processors;
        $PROCNO2 = join"\t", $_->id, $_->state, $_->type, $_->clock for @{Unix::Processors->new()->processors};
    }

    if ( eval "require POSIX" ) {
        import POSIX 'uname';
        import POSIX qw(locale_h);
        use POSIX qw/getpgrp tcgetpgrp/;
        ( $System, $Hostname, $Maj, $Version, $Hardware ) = uname();
        if ( defined $Maj ) {
            ( $Major, $Minor, $Patch ) = split( /\./, $Maj );
        }
    }
    else {
        warn "WARN: Perl module POSIX not found\n";
    }

    if ( eval "require Getopt::Std" ) {
        import Getopt::Std;
        getopts( 'bcefhlnworvu:V:p:s:S:t:', \%opts );
        if ( $opts{h} ) {
            &Usage;
        }

        $GSP_login  = $opts{u} || q{};
        $GSP_pass   = $opts{p} || q{};
        $GSP_server = $opts{s} || q{};
        $SANtype    = $opts{S} || q{};
        $CONFFILE   = $opts{t} || q{};
        $VGSAN      = $opts{V} || q{};
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
        if ( "$Hostname" ) {
            $fqdn =
`nslookup $Hostname | awk -F: '! /awk/ && /^Name:/ {print $2}' 2>/dev/null`;
            $fqdn =~ s/Name:\s+//g;
            # 
            # Old style to get rid of leading empty spaces
            #
            # $fqdn =~ s/^\s+//g;
            #
            # Better method to get rid of leading and trailing empty spaces
            #
            $fqdn =~ s{\A \s* | \s* \z}{}gxm;
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

if ("$fqdn") {
    chomp($fqdn);
    #
    # Get rid of leading and trailing empty spaces
    #
    $fqdn =~ s{\A \s* | \s* \z}{}gxm;
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

my $BINPATH = "/bin";

# Very important symbolic link check: /bin -> /usr/bin
# if it does not exist, lot of things break
# 
if ( ! -e $BINPATH ) {
    print "\n$WARNSTR Directory $BINPATH is invalid symbolic link\n";
    print "$INFOSTR Directory $BINPATH should be a symbolic link to \"/usr/bin\"\n";
    exit(1);
}

my $LIBPATH = "/lib";
# Very important symbolic link check: /lib -> /usr/lib
# 
if ( ! -e $LIBPATH ) {
    print "\n$WARNSTR Directory $LIBPATH is invalid symbolic link\n";
    print "$INFOSTR Directory $LIBPATH should be a symbolic link to \"/usr/lib\"\n";
    exit(1);
}

# The EMS log files in /etc/opt/resmon/log are limited to 500 KB
# in size and are then moved to <logfile>.old. The previous *.old
# gets lost. The limit of 500 KB per logfile can be removed by creating
# the file /etc/opt/resmon/unlimited_log.
# Be careful with creating this file. Growing EMS log files
# can easily fill up root file system.
#
my $EMS_ULIMIT      = "/etc/opt/resmon/unlimited_log";
my $EMSP_FLAG       = 0;
my $EMS_FLAG        = 0;
my $EVWEBCONF       = "/opt/sfm/conf/evweb.conf";
if ( "$Minor$Patch" >= 1131 ) {
    $EVWEBCONF = "/var/opt/sfm/conf/evweb.conf";
}

# XPG4 variables
#
my $XPG4VAR="UNIX95=";    
if ( "$Minor$Patch" >= 1131 ) {
    $XPG4VAR="UNIX_STD=2003";    
}

# Maximum usable swap space
#
# Swap space in the kernel is managed using 'chunks' of
# physical device space. These chunks contain one or more
# (usually more) pages of memory, but provide another layer
# of indexing (similar to inodes in file systems) to keep the
# global swap table relatively small, as opposed to a large
# table indexed by swap page.
#
# swchunk controls the size in physical disk blocks (which
# are defined as 1 KB) for each chunk.
#
# The total bytes of swap space manageable by the system on
# HP-UX 11.23 is:
#
# swchunk x 1KB x 16384
#
# 16384 is the system maximum number of swap chunks in the swap table,
# as defined by kernel parameter maxswapchunks.
#
# The total bytes of swap space manageable by the system on
# HP-UX 11.31 is:
#
# swchunk x 1KB x 2147483648
#
# What Are the Side Effects of Raising the Value of swchunk?
# The second level of the swap table (used to track pages within
# a chunk) will increase, resulting in more memory used by the kernel.
# If swchunk is being increased to allow for mapping of a larger
# swap space, increased memory usage by the kernel to track the swap
# space is unavoidable. This means that more swap is allocated to
# each device (or file system) using the round-robin interleaving
# scheme when all priorities are equal. Increasing swchunk when the
# number of chunks needed to represent the system swap space is
# less than 16384 could hinder system performance by creating unneeded
# I/O bottlenecks. For example, two pages that were in different chunks
# using the smaller value which were previously on different swap devices
# and thus accessible independently of one another (with no read head
# or controller issues) are now on the same device and can not be read
# concurrently, resulting in a longer access time for the second page.
#
# When Should the Value of swchunk Be Lowered?
# If the amount of swap space mappable by the system is much larger
# than the total amount of swap space which is attached (or going to
# be attached) to the system, which is calculable by multiplying
# "16384 * swchunk* 1KB", then kernel memory usage can be reduced
# by lowering swchunk to fit the actual swap space.
#
# What Are the Side Effects of Lowering the Value of swchunk?
# It may have to be raised back if more swap is added to the system
# and there is not enough room in the swap table to allow for the
# increased space. If this is not the case, then there is a finer
# grain of interleaving on the system (assuming there is more than
# one swap device) that can provide a performance gain under heavy
# swap usage.
#
my $swchunk         = q{};
my $maxswapchunks   = q{};
my $maxswchunk      = 16384;
if ( "$Minor$Patch" >= 1131 ) {
   $maxswchunk      = 2147483648;
}
my $maxuswap        = q{};

# Array of test results for SSH
# Limitations for entries in /etc/passwd file
#
# HP-UX 11.11 and 11.23 (possibly older releases too)
# The following fields have size limitations:
#
# 1 Login name field can be no longer than 8 characters
#
# 2 Initial working directory field can be no longer than 63 characters
#
# 3 Program field can be no longer than 44 characters
#
# Results are unpredictable if these fields are longer than the
# limits specified above.
#
# The following fields have numerical limitations:
#
# 1 The user ID is an integer value between 0 and UID_MAX-1
# inclusive. As a special case, -2 may be present
#
# 2 The group ID is an integer value between 0 and UID_MAX-1
# inclusive. As a special case -2 may be present
#
# 3 If either of these values are out of range, the getpwent(3C)
# functions reset the ID value to (UID_MAX)
#
# HP-UX 11.31
# The following fields have size limitations:
#
# 1 Login name field can be no longer than 8 characters, or 255 characters
# if the support of long user and group names is enabled on the system
#
# 2 Initial working directory field can be no longer than 1023 characters
#
# 3 Program field can be no longer than 44 characters
#
# Results are unpredictable if these fields are longer than the limits
# specified above.
#
# The following fields have numerical limitations:
#
# 1 The user ID is an integer value between 0 and UID_MAX-1 inclusive.
# As a special case, -2 may be present
#
# 2 The group ID is an integer value between 0 and UID_MAX-1 inclusive.
# As a special case -2 may be present
#
# 3 If either of these values are out of range, the getpwent(3C) functions
# reset the ID value to (UID_MAX)
#
# HP-UX 11i Version 3 is the last release to support trusted systems
# functionality.
#
my $PASS_SHELL_LENGTH = 44;
my $PASS_HOMEDIR_LENGTH = 63; 
if ( "$Minor$Patch" < 1131 ) {
    $PASS_HOMEDIR_LENGTH = 1023; 
}

# Starting with HP-UX 11 Version 3, there are two ioconfig files,
# /etc/ioconfig which is the same as in prior releases and
# /etc/ext_ioconfig which contains additional agile entries
#
my $ioconfig        = "/etc/ioconfig";
my $ioconfiga       = "/etc/ext_ioconfig";
my @IOCONFIGARR     = ( $ioconfig );
if ( "$Minor$Patch" >= 1131 ) {
    push(@IOCONFIGARR, $ioconfiga );

    $exportfs = "/etc/dfs/dfstab";
    $sharetab = "/etc/dfs/sharetab";

    $NAMEDCONF = "$RCCONFDIR/namesvrs_dns";
}

if ( "$Minor$Patch" < 1100 ) {
    print
"$ERRSTR Operating system version $Minor.$Patch too old and unsupported\n";
    push(@CHECKARR,
"\n$ERRSTR Operating system version $Minor.$Patch old and unsupported\n");
    $warnings++;
    exit(1);
}
else {
    if ( "$Minor$Patch" == 1100 ) {
        print
"$WARNSTR Operating system version $Minor.$Patch unsupported but still in widespread use\n";
        push(@CHECKARR,
"\n$WARNSTR Operating system version $Minor.$Patch unsupported but still in widespread use\n");
        $warnings++;
    } else {
        print "$INFOSTR Operating system version $Minor.$Patch is supported\n";
    }
}

# Associative array of dump driver capabilities
# These are based on documentation I could find
# Sadly, I have not yet been able to figure out
# how to poll the card directly
#
# QXCR1000772840 delivers the concurrent dump functionality to the fclp driver
#
my %DUMPARRAY = (
    "fcd", "Concurrent",
    "td", "Reentrant",
    "mpt", "Reentrant",
    "c8xx", "Reentrant",
    "ciss", "Reentrant",
    "sasd", "Reentrant",
    "fclp", "Reentrant",
);

# Associative array of default GSP accounts
# It is bad if they succeed - factory-default logins should be changed
#
my %GSPPASSARRAY = (
    "Admin", "Admin",
    "Admin", "",
    "Oper",  "Oper",
    "Oper",  "",
    "hp",    "hp",
    "",      "",
);

my %OVOARRAY = ( "/var/opt/perf",   "1024",
                 "/var/opt/OV",     "1024",
               );

# Associative array of minimum file system sizing in MBytes
#
if ( "$Minor$Patch" >= 1131 ) {
     %OSARRAY1 = (
        "/",                       "2048",
        "/stand",                  "2048",
        "/tmp",                    "2048",
        "/home",                   "512",
        "/usr",                    "8192",
        "/var",                    "10240",
        "/var/tmp",                "1024",
        "/var/adm/crash",          "$fs_crash",
        "/opt",                    "10240",
    );
}
elsif ( "$Minor$Patch" >= 1120 ) {
    %OSARRAY1 = (
        "/",                       "512",
        "/stand",                  "1024",
        "/tmp",                    "1024",
        "/home",                   "512",
        "/usr",                    "5120",
        "/var",                    "6156",
        "/var/tmp",                "512",
        "/var/adm/crash",          "$fs_crash",
        "/opt",                    "6156",
    );
}
else {
    %OSARRAY1 = (
        "/",                       "512",
        "/stand",                  "512",
        "/tmp",                    "1024",
        "/home",                   "512",
        "/usr",                    "1200",
        "/var",                    "2048",
        "/var/tmp",                "512",
        "/var/adm/crash",          "$fs_crash",
        "/opt",                    "2048",
    );
}

# HP-UX whitelisting (WLI)
#
my $WLIDIR         = "/etc/wli";
my @WLICONFARR     = ( "wlisys.conf", "wlisyspolicy.conf", "wlicert.conf", );
my $WLICERTDIR     = "${WLIDIR}/certificates";
my $WLIKEYDIR      = "${WLIDIR}/keys";
my $WHITELIST_FLAG = 0;

# END OF VARIABLES THAT CAN BE READ FROM CONFIG FILE
# VIA "-t CONFFILE" OPTION

if ("$GSP_login") {
    if ("$GSP_pass") {
        $GSPPASSARRAY{$GSP_login} = $GSP_pass;
    }
    else {
        print "$ERRSTR GSP login defined but not its password\n";
    }
}

# Get current local time
#
(
    $Sec,
    $Min,
    $Hour,
    $DayOfMonth,
    $Month,
    $Year,
    $DayOfWeek,
    $DayofYear,
    $IsDST
) = localtime;

my $EPOCHTIME = timelocal( $Sec, $Min, $Hour, $DayOfMonth, $Month, $Year );

# Localtime returns January..December as 0..11
#
$Month++;
$Year = $Year + 1900;

my $Model1 = `model 2>/dev/null`;
chomp($Model1);

my $Model2 = `getconf MACHINE_MODEL 2>/dev/null`;
chomp($Model2);

my $Model = $Model1 || $Model2 || "Unknown";

my @machinfo = ();

if ( "$Hardware" eq "ia64" ) {
    if ( "$Minor$Patch" >= 1131 ) {
        @machinfo = `machinfo -v -m 2>/dev/null`;
        if ( ! @machinfo  ) {
            @machinfo = `machinfo -v 2>/dev/null`;
        }
    }
    elsif ( "$Minor$Patch" >= 1123 ) {
        @machinfo = `machinfo -v 2>/dev/null`;
    }
    else {
        @machinfo = `machinfo 2>/dev/null`;
    }
}

rawpscheck();

# Get system's serial number
#
my $serial1 = q{};
eval {
    # On certain occasions, getconf CS_MACHINE_SERIAL hangs, so we need to
    # manage how long it runs
    #
    local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
    alarm 15;
    $serial1 = `getconf CS_MACHINE_SERIAL 2>/dev/null | awk NF`;
    chomp($serial1);
    alarm 0;
};

if ($@) {
    warn "\n$WARNSTR Command \"getconf CS_MACHINE_SERIAL\" timed out\n";
}

my $serial2 = `getsn 2>/dev/null | awk -F: '{print \$2}'`;
if ("$serial2") {
    # Old method to get rid of leading and trailing blank spaces
    #
    # $serial2 =~ s/^\s+//g;
    # $serial2 =~ s/\s+$//g;
    #
    # Get rid of leading and trailing empty spaces
    #
    $serial2 =~ s{\A \s* | \s* \z}{}gxm;
    chomp($serial2);
}

my $Manifest = "$igndir/local/manifest/manifest";
my $serial3 = q{};
if ( ( -s "$Manifest" ) && ( -T "$Manifest" ) ) {
    $serial3 = `egrep "Serial number:" $Manifest 2>/dev/null | awk -F: '{print \$2}'`;
    #
    # Get rid of leading and trailing empty spaces
    #
    $serial3 =~ s{\A \s* | \s* \z}{}gxm;
    chomp($serial3);
}

my $serial4 = `getconf MACHINE_SERIAL 2>/dev/null | awk NF`;
chomp($serial4);

my $serial5 = `echo "map; sel dev 1;info;il" | cstm 2>/dev/null | awk -F: '! /awk/ && /System Serial Number/ {print \$3}'`;
chomp($serial5);

my $serial = $serial1 || $serial2 || $serial3 || $serial4 || $serial5 || "Unknown";

# Get system's pagesize
#
my $pgsize1 = `getconf PAGE_SIZE 2>/dev/null | awk NF`;
my $pgsize2 = `getconf _SC_PAGE_SIZE 2>/dev/null | awk NF`;
chomp($pgsize1);
chomp($pgsize2);
$pgsize = $pgsize1 || $pgsize2 || "4096";

# Get systems HP-UX bundle
#
my $bundle1 =
`swlist | awk '/-OE-/ || /-OE/ || /COE/ || /BOE/ && ! /awk/ {print}' 2>&1`;

# Get rid of leading and trailing empty spaces
#
$bundle1 =~ s{\A \s* | \s* \z}{}gxm;
$bundle1 =~ s/\s+/ /g;
chomp($bundle1);

my $bundle2 = `swlist | awk '/General Release|Quality Pack Bundle|Quality Pack Depot/ && ! /awk/ {print}' 2>&1`;

# Get rid of leading and trailing empty spaces
#
$bundle2 =~ s{\A \s* | \s* \z}{}gxm;
$bundle2 =~ s/\s+/ /g;
chomp($bundle2);

my $bundle3 =
`swlist -l fileset -a os_release | awk '/OS-Core.CORE2-KRN/ && ! /awk/ {print \$2}' 2>&1`;

# Get rid of leading and trailing empty spaces
#
$bundle3 =~ s{\A \s* | \s* \z}{}gxm;
$bundle3 =~ s/\s+/ /g;
chomp($bundle3);

my $bundle4 = `swlist -l product OS-Core 2>&1`;

# Get rid of leading and trailing empty spaces
#
$bundle4 =~ s{\A \s* | \s* \z}{}gxm;
chomp($bundle4);

my $bundle = $bundle1 || $bundle2 || $bundle3 || $bundle4 || "Unknown";

my $runlevel = `who -r | awk '/run-level/ {print \$3}' 2>&1`;
chomp($runlevel);

if ( ! "$runlevel" ) {
   $runlevel = `getrunlvl 2>/dev/null`;
   chomp($runlevel);
}

my $uptime = `uptime`;

# Get rid of leading and trailing empty spaces
#
$uptime =~ s{\A \s* | \s* \z}{}gxm;
chomp($uptime);

# User Accounting databases in HP-UX 11.11 and older
#
my $wtmpfile    = "/var/adm/wtmp";
my $etcutmp     = "/etc/utmp";
my $etcutmpold  = "/etc/utmp";
my $btmplog     = "/var/adm/btmp";

# User Accounting databases in HP-UX 11.23 and newer
#
if ( "$Minor$Patch" >= 1123 ) {
    $wtmpfile = "/var/adm/wtmps";
    $etcutmp  = "/etc/utmps";
    $btmplog  = "/var/adm/btmps";
}

if ( !"$uptime" ) {
    print "$WARNSTR $wtmpfile or $etcutmp possibly corrupted\n";
    push(@CHECKARR, "\n$WARNSTR $wtmpfile or $etcutmp possibly corrupted\n");
    $warnings++;
    $uptime = "Unknown (check manually)";
}

# Maximum number of device-based swaps 
#
my $MAXNSWAPDEV = q{};
if ( "$Minor$Patch" >= 1131 ) {
    $MAXNSWAPDEV = 1024;
}
elsif ( "$Minor$Patch" >= 1120 ) {
    $MAXNSWAPDEV = 25;
}
else {
    $MAXNSWAPDEV = 25;
}

if ( "$Minor$Patch" >= 1100 ) {
    $KERNEL_BITS = `getconf KERNEL_BITS`;
    chomp($KERNEL_BITS);
    $CPU_HW_SUPPORT = `getconf HW_CPU_SUPP_BITS`;
    chomp($CPU_HW_SUPPORT);
}

# Get system's volume manager details
#
#$vxcheck = `vxinfo 2>&1 | egrep "ERROR|not found"`;
my @vxdctl0 = `vxdctl list 2>/dev/null`;
my @vgdisp = `vgdisplay 2>/dev/null`;
if ( @vgdisp ) {
    $LVM_FLAG++;
}

if ( ! @vxdctl0 ) {
    $Diskmgr    = "HP Logical Volume Manager (LVM)";
    $Diskmgrcnt = "SINGLE Volume Manager Environment";
    $Diskmgrno  = 1;
}
else {
    if ( "$LVM_FLAG" > 0 ) {
        $Diskmgr =
          "Veritas Volume Manager (VxVM) and Logical Volume Manager (LVM)";
        $Diskmgrcnt = "DUAL Volume Manager Environment";
        $Diskmgrno  = 2;
    }
    else {
        $Diskmgr    = "Veritas Volume Manager (VxVM)";
        $Diskmgrcnt = "SINGLE Volume Manager Environment";
        $Diskmgrno  = 1;
    }
}

sub print_header {
    my $lline = shift;
#    $len_lline = length($lline);
#    printf "_" x $len_lline;
    print "\n$lline\n";
    print "\n";
}

sub print_trailer {
    my $lline = shift;
#    $len_lline = length($lline);
    print "\n$lline\n";
#    printf "_" x $len_lline;
#    print "\n\n";
    print "\n";
}

sub aries_check {
    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING AUTOMATIC RECOMPILATION AND INTEGRATED ENVIRONMENT SIMULATION $datestring ***");
        my @ARRIES = (
            "/usr/lib/hpux32/pa_boot32.so", "/usr/lib/hpux32/aries32.so",
            "/usr/lib/hpux64/pa_boot64.so", "/usr/lib/hpux64/aries64.so",
        );
        foreach my $myarries (@ARRIES) {
            if ( -s "$myarries" ) {
                print
"$INFOSTR ARIES shared library $myarries exists (PA-RISC emulation)\n";
            }
            else {
                print
"$INFOSTR ARIES shared library $myarries (PA-RISC emulation) does not exist\n";
            }
        }

        datecheck();
        print_header("*** END CHECKING AUTOMATIC RECOMPILATION AND INTEGRATED ENVIRONMENT SIMULATION $datestring ***");
    }
}

sub check_usergroup_length {
    datecheck();
    print_header("*** BEGIN CHECKING LONG USER AND GROUP NAME LENGTH $datestring ***");

    if ( "$Minor$Patch" >= 1131 ) {
        my $lugadmin = `lugadmin -l 2>/dev/null`;
        chomp($lugadmin);
        if ( "$lugadmin" == 64 ) {
            print
"$INFOSTR Server is restricted to short (8-byte) user and group names (lugadmin is 64)\n";
        }

        if ( "$lugadmin" == 256 ) {
            print
"$INFOSTR Server is enabled for long (255-byte) user and group names (lugadmin is 256)\n";
        }
    }
    else {
        print
"$INFOSTR HP-UX ignores user names beyond eight characters\n";
        if ( -f "$BYPASSSEC" ) {
            print "\n$INFOSTR File $BYPASSSEC exists\n";
            print
"$NOTESTR Longer user names possibly supported (check patches)\n";
        }
        else {
            print "\n$INFOSTR File $BYPASSSEC does not exist\n";
            print "$NOTESTR Longer user names not supported\n";
        }
    }

    datecheck();
    print_header("*** END CHECKING LONG USER AND GROUP NAME LENGTH $datestring ***");

    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING NUMERIC USER GROUP FEATURE $datestring ***");

        if ( $NUMUSRGRP_FLAG > 0 ) {
            print
"$INFOSTR Software product \"Numeric User Group Name\" installed\n";
        }
        else {
            print
"$INFOSTR Software product \"Numeric User Group Name\" not installed\n";
        }

        datecheck();
        print_header("*** END CHECKING NUMERIC USER GROUP FEATURE $datestring ***");
    }
}

sub check_hostname_length {
    datecheck();
    print_header("*** BEGIN CHECKING NODENAME LENGTH $datestring ***");

    if ("$Hostname") {
        my $nname = length($Hostname);
        if ( "$Minor$Patch" >= 1131 ) {
            if ( "$nname" <= $NODENAME_LEN ) {
                print
"$PASSSTR Nodename length ($nname for $Hostname) satisfies recommended limit of $NODENAME_LEN characters\n";
            }
            else {
                print
"$WARNSTR Nodename length ($nname for $Hostname) exceeds recommended limit of $NODENAME_LEN characters\n";
                push(@CHECKARR,
"\n$WARNSTR Nodename length ($nname for $Hostname) exceeds recommended limit of $NODENAME_LEN character\n");
                $warnings++;
            }
            print
"$INFOSTR Dynamic kernel parameter expanded_node_host_names is available\n";
        }
        else {
            if ( "$nname" > $NODENAME_LEN ) {
                print
"$WARNSTR Nodename length ($nname for $Hostname) exceeds recommended limit of $NODENAME_LEN characters\n";
                print "$INFOSTR Nodename length might affect SAM GUI\n";
                push(@CHECKARR,
"\n$WARNSTR Nodename length ($nname for $Hostname) exceeds recommended limit of $NODENAME_LEN character\n");
                $warnings++;
            }
            else {
                print
"$PASSSTR Nodename length ($nname for $Hostname) satisfies recommended limit of $NODENAME_LEN characters\n";
            }
        }
    }
    else {
        print "$WARNSTR Cannot check nodename\n";
        push(@CHECKARR, "\n$WARNSTR Cannot check nodename\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING NODENAME LENGTH $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING HOSTNAME CONTAINS VALID CHARACTERS $datestring ***");

    if ( "$Hostname" ) {
        if( ! ( $Hostname =~ /^[a-zA-Z0-9\.\-]+$/ ) ) {
            print "$WARNSTR Invalid characters in hostname $Hostname\n";
            push(@CHECKARR, "\n$WARNSTR Invalid characters in hostname $Hostname\n");
            print "$NOTESTR RFCs define valid characters as 'a-zA-Z0-9.-'\n";
        }
        else {
            print "$PASSSTR Valid characters in hostname $Hostname\n";
            print "$NOTESTR RFCs define valid characters as 'a-zA-Z0-9.-'\n";
        }

        ( $SHostname, undef ) = split(/\./, $Hostname); 
        if( ( $SHostname =~ /^\pL+$/ ) ) {
            print
"\n$INFOSTR Hostname $SHostname contains alphabetic characters only\n";
        }
        else {
            if( $SHostname =~ /^[a-zA-Z0-9]+$/ ) {
                print
"\n$INFOSTR Hostname $SHostname contains alphabetic characters only\n";
            }
        }

        if ( $CUR_VERSION >= $BEST_VERSION ) {
            if( $SHostname =~ /\p{IsUpper}/ ) {
                print "\n$INFOSTR Upper-case characters in hostname $SHostname\n";
                print "$NOTESTR Lower-case characters in hostnames are recommended\n";
            }
        }
    }
    else {
        print "$WARNSTR Hostname string is zero-length\n";
        push(@CHECKARR, "\n$WARNSTR Hostname string is zero-length\n");
        $warnings++;
    }

    datecheck();
    print_header("*** END CHECKING HOSTNAME CONTAINS VALID CHARACTERS $datestring ***");
}

if ( "$Minor$Patch" < 1123 ) {
    $Stand = `kmpath 2>/dev/null`;
}
else {
    $Stand = `kcpath -x 2>/dev/null`;
}
chomp($Stand);

if ("$Stand") {
    $ARCH = `file $Stand | sed -e 's/^.* - //g'`;
    chomp($ARCH);
}

if ( !"$ARCH" ) {
    $ARCH =
        "$Hardware" eq "ia64" ? "Itanium"
      : grep( /9000/, "$Hardware" ) ? "PA-RISC"
      :                               "Unknown";
}

my $HOSTID2 = `hostid 2>/dev/null`;
chomp($HOSTID2);
my $HOSTID3 = `getconf MACHINE_IDENT 2>/dev/null`;
chomp($HOSTID3);
my $HOSTID = 
       $HOSTID2 ? $HOSTID2
       : $HOSTID3 ? $HOSTID3
       : "Unknown";

my $PROCNO3 = `echo "sc product cpu;il" | cstm 2>/dev/null | grep 'CPU Module'`;
chomp($PROCNO3);

my $PROCNO4 = `echo "sc product cpu;il" | cstm 2>/dev/null | grep 'CPU Present' | wc -l`;
chomp($PROCNO4);

if ( open( MPSCH, "mpsched -s 2>&1 | " ) ) {
    while (<MPSCH>) {
        next if grep( /not found/, $_ );
        push(@CPU_no, $_);
        chomp($_);
        if ( grep( /^Processor Count:/, $_ ) ) {
            ( undef, $PROCNO5 ) = split( /:/, $_ );
            #
            # Get rid of leading and trailing empty spaces
            #
            $PROCNO5 =~ s{\A \s* | \s* \z}{}gxm;
        }
        if ( grep( /^Locality Domain Count:/, $_ ) ) {
            ( undef, $NUMACOUNT ) = split( /:/, $_ );
            $NUMACOUNT =~ s/^\s+//g;
            $NUMACOUNT =~ s/\s+$//g;
        }
    }
    close(MPSCH);
}

ramswapcheck();

$PROCNO = 
       $ACTIVECPUNO ? $ACTIVECPUNO
       : $PROCNO2 ? $PROCNO2
       : $PROCNO4 ? $PROCNO4
       : $PROCNO5 ? $PROCNO5
       : $cpucount ? $cpucount
       : $PROCNO3 ? $PROCNO3
       : "Unknown";

# Get rid of leading and trailing empty spaces
#
$PROCNO =~ s{\A \s* | \s* \z}{}gxm;

my $CSPARTNO2 = `getconf CS_PARTITION_IDENT 2>/dev/null | awk NF`;
chomp ($CSPARTNO2);

my $CSPARTNO = 
       $CSPARTNO2 ? $CSPARTNO2
       : "Unknown";
         
my $CPUVERSION2 = `getconf CPU_VERSION 2>/dev/null | awk NF`;
chomp ($CPUVERSION2);
if ( "$CPUVERSION2" ) {
    my $CPUHEX = `printf '0x%x' $CPUVERSION2`;
    $CPUDESC = `egrep -i "CPU_.*$CPUHEX" $CPUHINTS | awk '{print \$3}'`;
    chomp($CPUDESC);
}

my $CPUCHIP = q{};
my $CPUCHIPTYPE = q{};
my $CPUCC = q{};
if ( "$Hardware" eq "ia64" ) {
    $CPUCHIP = `getconf CPU_CHIP_TYPE 2>/dev/null`;
    chomp ($CPUCHIP);
    if ( "$CPUCHIP" ) {
        $CPUCC = substr($CPUCHIP,0,4);
        $CPUCHIPTYPE =
            "$CPUCC" eq "" ? "Merced"
          : "$CPUCC" eq "5200" ? "McKinley"
          : "$CPUCC" eq "5201" ? "Madison, Deerfield, Hondo"
          : "$CPUCC" eq "5202" ? "Madison 9M, Fanwood"
          : "$CPUCC" eq "5368" ? "Montecito, Millington"
          : "$CPUCC" eq "5369" ? "Montvale"
          : "$CPUCC" eq "5370" ? "Tukwila"
          : "$CPUCC" eq "5536" ? "Poulson"
          : "Unknown";
    }
    else {
        $CPUCHIPTYPE = "Merced";
    }
}
else {
    $CPUCHIPTYPE = `getconf CPU_CHIP_TYPE 2>/dev/null`;
    chomp ($CPUCHIPTYPE);
}

my $CPUVERSION = $CPUVERSION2 || "Unknown";

if ( $System ne "HP-UX" ) {
    print "\n$ERRSTR Uname -s string not \"HP-UX\"\n";
    print "$INFOSTR Commands like swlist and swinstall will fail\n";
    print "$NOTESTR Recommended to run command \"setuname -s HP-UX\"\n";
    push(@CHECKARR, "\n$ERRSTR Uname -s string not \"HP-UX\"\n");
    $warnings++;
}

my @Pararr = ();
eval {
    # On certain occasions, parstatus hangs, so we need to
    # manage how long it runs
    #
    local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
    alarm 30;
    my @Pararr   = `parstatus -w 2>/dev/null | egrep -v CIM_ERR`;
    alarm 0;
};

if ($@) {
    warn "\n$WARNSTR Command \"parstatus\" timed out\n";
}

my $LBPOLICY = q{};
my @LBARR    = ();

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

sub SYS_INFO {
    print "$INFOSTR Data collected by Perl script version $SCRIPT_VERSION

DATE                      $DayOfMonth/$Month/$Year $Hour:$Min
HOSTNAME                  $Hostname
FQDN                      $fqdn
MODEL                     $Model
UNAME -A                  $System $Hostname $Maj $Version $Hardware
ARCH                      $ARCH
HOSTID                    $HOSTID
PHYSICAL MEMORY           $MEM_MBYTE MB
SWAP                      $tswapall2 MB
NUMBER OF PROCESSORS      $PROCNO
PROCESSOR VERSION         $CPUVERSION $CPUDESC
PROCESSOR TYPE            $CPUCHIPTYPE
RUN LEVEL                 $runlevel
O/S BUNDLE                $bundle
SERIAL NUMBER             $serial
SOFTWARE ID               $CSPARTNO
CPU HARDWARE SUPPORT      ${CPU_HW_SUPPORT}-bit
ENDIANESS                 $Endian
KERNEL MODE               ${KERNEL_BITS}-bit
PAGESIZE                  $pgsize
VOLUME MANAGER COUNT      $Diskmgrcnt
VOLUME MANAGER            $Diskmgr
UPTIME                    $uptime\n";

    if ( "$Hardware" eq "ia64" ) {
        print "\nITANIUM MACHINFO\n@machinfo";
        print "\n";
    }
    else {
        print "\n";
    }

    datecheck();
    print_header("*** BEGIN CHECKING XPG4 ENVIRONMENT VARIABLES $datestring ***");
    if ( "$ENV{'UNIX95'}" == 1 ) {
        print "$WARNSTR UNIX95 variable set\n";
        print "$INFOSTR It is strongly recommended to unset it as number of utilities like SD commands can fail when this variable is set\n";
        push(@CHECKARR, "\n$WARNSTR UNIX95 variable set (it is strongly recommended to unset it as number of utilities like SD commands can fail when this variable is set)\n");
        $warnings++;
    }
    else {
        print "$PASSSTR UNIX95 variable not set\n";
    }

    if ( "$ENV{'UNIX_STD'}" == 1 ) {
        print "\n$WARNSTR UNIX_STD variable set\n";
        print "$INFOSTR It is strongly recommended to unset it as number of utilities like SD commands can fail when this variable is set\n";
        push(@CHECKARR, "\n$WARNSTR UNIX_STD variable set (it is strongly recommended to unset it as number of utilities like SD commands can fail when this variable is set)\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR UNIX_STD variable not set\n";
    }

    datecheck();
    print_trailer("*** END CHECKING XPG4 ENVIRONMENT VARIABLES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SERVER-WIDE VOLUME MANAGER STATUS VIA VXVM COMMANDS $datestring ***");

    my @vxlvmvglist = `vxlvmvglist 2>/dev/null`;
    if ( @vxlvmvglist ) {
        print @vxlvmvglist;
    }
    else {
        print "$INFOSTR vxlvmvglist not supported on this server\n";
    }

    my @vxgetrootdisk = `vxgetrootdisk 2>/dev/null`;
    if ( @vxgetrootdisk ) {
        print "\n$INFOSTR Root disk device\n";
        print @vxgetrootdisk;
    }
    else {
        print "\n$INFOSTR vxgetrootdisk not supported on this server\n";
    }

    my @vxdevlist = `vxdevlist 2>/dev/null`;
    if ( @vxdevlist && (grep(/dsk|disk/, @vxdevlist)) ) {
        print "\n$INFOSTR vxdevlist status\n";
        print @vxdevlist;
    }
    else {
        print "\n$INFOSTR vxdevlist not supported or no devices found on this server\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SERVER-WIDE VOLUME MANAGER STATUS VIA VXVM COMMANDS $datestring ***");
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
        print
"\n$INFOSTR Successful open socket on $proto port $port @ $REMOTE\n";
        close($sock);
    }
    else {
        print "\n$INFOSTR Failed open socket on $proto port $port @ $REMOTE\n";
    }
}

# Subroutine to check Serviceguard
#
sub sgcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SERVICEGUARD CONFIGURATION $datestring ***");

    if ( open( FROM, "swlist -l product ServiceGuard 2>&1 |" ) ) {
        while (<FROM>) {
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /#/,  $_ ) );
            #
            # Get rid of leading and trailing empty spaces
            #
            $_ =~ s{\A \s* | \s* \z}{}gxm;
            chomp($_);
            ( $SG, undef ) = split( /\s+/, $_ );
            if ( "$SG" eq "ServiceGuard" ) {
                $SGCNT++;
            }
        }
        close(FROM);
    }
    else {
        print "$WARNSTR Cannot run swlist\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run swlist\n");
        $warnings++;
        print "\n";
    }

    if ( "$SGCNT" == 0 ) {
        print "$INFOSTR Serviceguard not installed\n";
    }
    elsif ( "$SGCNT" == 1 ) {
        if ( "$SGRUN" == 0 ) {
            print "$INFOSTR Serviceguard installed and not running\n";
        }
        elsif ( "$SGRUN" >= 1 ) {
            print "$PASSSTR Serviceguard installed and running\n";
            
            my @hainfo = `get_ha_info -c 2>/dev/null`; 
            if ( "@hainfo" ) {
                print "\n$INFOSTR Cluster information in concise format\n";
                print @hainfo;
            }

            my @multicmcld = grep {/cmclconfd.*-p/i} @allprocesses; 
            my $counta = @multicmcld;

            if ( "$counta" > 1 ) {
                print "\n$INFOSTR Multiple \"cmclconfd -p\" detected\n";
                print "$NOTESTR Indication that many Serviceguard commands might be running\n";
            }

            $opts{r} = 1;

            my $SGVER = `what /usr/lbin/cmcld 2>/dev/null | awk '/Date:/ {print \$1}`;
            my $SGVER1 = `cmversion 2 >/dev/null`;

            if ( "$SGVER1" ) {
                chomp($SGVER1);
                print "\n$INFOSTR Serviceguard version is $SGVER1\n";
                $SGVER = $SGVER1;
            }
            else {
                if ( "$SGVER" ) {
                    chomp($SGVER);
                    print "\n$INFOSTR Serviceguard version is $SGVER\n";
                }
            }

            if ( -f $SGSAFETYTIMERDEV ) {
                print
"\n$INFOSTR Serviceguard Safety Timer device $SGSAFETYTIMERDEV exists\n";
                $SGSAFETYCNT++;
            }
            else {
                print
"\n$ERRSTR Serviceguard Safety Timer device $SGSAFETYTIMERDEV does not exist\n";
                push(@CHECKARR,
"\n$WARNSTR Serviceguard Safety Timer device $SGSAFETYTIMERDEV does not exist\n");
                $warnings++;
            }

            if ( open( CMGET, "cmgetconf -v 2>&1 |" ) ) {
                print "\n$INFOSTR CMgetconf\n";
                while (<CMGET>) {
                    next if ( grep( /^$/, $_ ) );

                    if ( grep( /Warning/, $_ ) ) {
                        push(@CHECKARR, "$WARNSTR Serviceguard $_\n");
                        push(@SGCONFARR, "$WARNSTR Serviceguard $_\n");
                        $warnings++;
                    }

                    print $_;

                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s/^\s+//g;
                    $_ =~ s/\s+$//g;

                    if ( grep( /^CLUSTER_NAME/, $_ ) ) {
                        ( undef, $MCCLNAME ) = split( /\s+/, $_ );
                        chomp($MCCLNAME);
                        #
                        # Get rid of leading and trailing empty spaces
                        #
                        $MCCLNAME =~ s/^\s+//g;
                        $MCCLNAME =~ s/\s+$//g;
                    }

                    if ( grep( /^SITE_NAME/, $_ ) ) {
                        $METROSITE = q{};
                        ( undef, $METROSITE ) = split( /\s+/, $_ );
                        push(@METROARR, "$METROSITE ");
                    }

                    if ( grep( /^FIRST_CLUSTER_LOCK_PV/, $_ ) ) {
                        ( undef, $FMCCLLOCKDISK ) = split( /\s+/, $_ );
                        chomp($FMCCLLOCKDISK);
                        #
                        # Get rid of leading and trailing empty spaces
                        #
                        $FMCCLLOCKDISK =~ s/^\s+//g;
                        $FMCCLLOCKDISK =~ s/\s+$//g;
                    }

                    if ( grep( /^SECOND_CLUSTER_LOCK_PV/, $_ ) ) {
                        ( undef, $SMCCLLOCKDISK ) = split( /\s+/, $_ );
                        chomp($SMCCLLOCKDISK);
                        #
                        # Get rid of leading and trailing empty spaces
                        #
                        $SMCCLLOCKDISK =~ s/^\s+//g;
                        $SMCCLLOCKDISK =~ s/\s+$//g;
                    }

                    if ( grep( /^FIRST_CLUSTER_LOCK_VG/, $_ ) ) {
                        ( undef, $FMCCLLOCKVG ) = split( /\s+/, $_ );
                        chomp($FMCCLLOCKVG);
                        #
                        # Get rid of leading and trailing empty spaces
                        #
                        $FMCCLLOCKVG =~ s/^\s+//g;
                        $FMCCLLOCKVG =~ s/\s+$//g;
                    }

                    if ( grep( /^SECOND_CLUSTER_LOCK_VG/, $_ ) ) {
                        ( undef, $SMCCLLOCKVG ) = split( /\s+/, $_ );
                        chomp($SMCCLLOCKVG);
                        #
                        # Get rid of leading and trailing empty spaces
                        #
                        $SMCCLLOCKVG =~ s/^\s+//g;
                        $SMCCLLOCKVG =~ s/\s+$//g;
                    }

                    if ( grep( /^MAX_CONFIGURED_PACKAGES/, $_ ) ) {
                        ( undef, $MAXPKG ) = split( /\s+/, $_ );
                        chomp($MAXPKG);
                        #
                        # Get rid of leading and trailing empty spaces
                        #
                        $MAXPKG =~ s/^\s+//g;
                        $MAXPKG =~ s/\s+$//g;
                    }

                    if ( "$FMCCLLOCKDISK" && "$FMCCLLOCKVG" ) {
                        $CMLCKARR{$FMCCLLOCKDISK} = $FMCCLLOCKVG; 
                    }

                    if ( "$SMCCLLOCKDISK" && "$SMCCLLOCKVG" ) {
                        $CMLCKARR{$SMCCLLOCKDISK} = $SMCCLLOCKVG; 
                    }
                }
                close(CMGET);

                foreach my $lckdsk (sort keys %CMLCKARR) {
                    if ( "$lckdsk" ) {
                        print "\n$PASSSTR Cluster lock disk defined as $lckdsk\n";
                        if ( grep( /\Q$lckdsk\E/, @BADDISK ) ) {
                            push(@SGCONFARR,
"\n$WARNSTR Serviceguard lock disk $lckdsk seemingly unavailable\n");
                            push(@CHECKARR,
"\n$WARNSTR Serviceguard cluster lock disk $lckdsk seemingly unavailable\n");
                            $warnings++;
                        }
                        else {
                            my $CheckCLLOCK = `echo '0x2084?4D' | adb $lckdsk 2>/dev/null | awk '{print \$2}' 2>/dev/null`;
                            chomp($CheckCLLOCK);
                            if ( "$CheckCLLOCK" == 1 ) {
                                print
"\n$PASSSTR Serviceguard cluster lock structure loaded on disk $lckdsk\n";
                            }
                            else {
                                push(@SGCONFARR,
"\n$WARNSTR Serviceguard cluster lock structure not loaded on disk $lckdsk\n");
                                push(@CHECKARR,
"\n$WARNSTR Serviceguard cluster lock structure not loaded on disk $lckdsk\n");
                                $warnings++;
                            }

                            if ( "$CMLCKARR{$lckdsk}" ) {
                                print
"\n$PASSSTR Cluster lock VG defined as $CMLCKARR{$lckdsk}\n";
                                my @cminitlock = `cminitlock -v -t $CMLCKARR{$lckdsk} $lckdsk 2>/dev/null`;
                                if ( @cminitlock ) {
                                    print
"\n$INFOSTR Serviceguard cminitlock check on disk $lckdsk in VG $CMLCKARR{$lckdsk}\n";
                                    print @cminitlock;
                                }
                            }
                            else {
                                push(@SGCONFARR,
"\n$WARNSTR Serviceguard cluster lock VG not defined\n");
                                push(@CHECKARR,
"\n$WARNSTR Serviceguard cluster lock VG not defined\n");
                               $warnings++;
                            }
                        }
                    }
                    else {
                        push(@SGCONFARR,
"\n$WARNSTR Serviceguard cluster lock disk not defined\n");
                        push(@CHECKARR,
"\n$WARNSTR Serviceguard cluster lock disk not defined\n");
                        $warnings++;
                    }
                }

                if ( "$MAXPKG" == 0 ) {
                    push(@SGCONFARR,
"\n$WARNSTR Serviceguard parameter \"MAX_CONFIGURED_PACKAGES\" set to $MAXPKG\n");
                    push(@CHECKARR,
"\n$WARNSTR Serviceguard parameter \"MAX_CONFIGURED_PACKAGES\" set to $MAXPKG\n");
                    $warnings++;
                }
                else {
                    print 
"\n$PASSSTR Serviceguard parameter \"MAX_CONFIGURED_PACKAGES\" set to $MAXPKG\n";
                }

                print "\n";
            }
            else {
                print "\n$INFOSTR Cannot run cmgetconf\n";
            }

            if ( @SGCONFARR ) {
                print "\n$INFOSTR Serviceguard cmgetconf warnings\n";
                print @SGCONFARR;
            }

            my @cmview = `cmviewcl -v 2>/dev/null`;
            if ( @cmview ) {
                print "\n$INFOSTR CMviewcl summary\n";
                print @cmview;
            }

            my @cmcheckconf = `cmcheckconf -v 2>/dev/null`;
            if ( @cmcheckconf ) {
                print "\n$INFOSTR CMcheckconf summary\n";
                print @cmcheckconf;
            }

            my @cmdo1 = `cmdo uptime 2>/dev/null`;
            if ( @cmdo1 ) {
                print "\n$INFOSTR Serviceguard uptime summary on each node\n";
                print @cmdo1;
            }

            my @cmdo2 = `cmdo dmesg 2>/dev/null`;
            if ( @cmdo2 ) {
                print "\n$INFOSTR Serviceguard dmesg summary on each node\n";
                print @cmdo2;
            }

            my @cmsetdsfgroup = `cmsetdsfgroup -v -q 2>/dev/null`;
            if ( @cmsetdsfgroup ) {
                print "\n$INFOSTR cmsetdsfgroup Cluster Device Special File (cDSF) summary\n";
                print @cmsetdsfgroup;
            }

            my @iosdsf = `ioscan -m cluster_dsf 2>/dev/null`;
            if ( @iosdsf ) {
                print "$INFOSTR Ioscan cluster_dsf mapping\n";
                print @iosdsf;
                print "\n";
            }

            my @iocdsf = `io_cdsf_config -q 2>/dev/null`;
            if ( @iocdsf ) {
                print "\n$INFOSTR io_cdsf_config Cluster Device Special File (cDSF) summary\n";
                print @iocdsf;
            }

            if ( $SGVER <= 111900 ) {
                # Command cmviewconf is deprecated as of Serviceguard A.11.19
                # This command will be obsolete in future releases
                #
                my @cmviewconf = `cmviewconf 2>/dev/null`;
                if ( @cmviewconf ) {
                    print "\n$INFOSTR CMviewconf summary\n";
                    print @cmviewconf;
                }
            }

            $SGVER =~ s/\.//g;
            $SGVER =~ s/^[A-Z]//g;

            if ( $SGVER >= 111600 ) {
                if ( open( CMFORM, "cmviewcl -f line -v 2>/dev/null |" ) ) {
                    print "\n$INFOSTR CMviewcl formatted summary\n";
                    while (<CMFORM>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                        if ( grep( /^node:/, $_ ) ) {
                            ( undef, $CLNODE, undef ) = split( /:/, $_ );
                            chomp($CLNODE);
                            $CLNODE =~ s/\|.*//g;
                            if ( "$CLNODE" ) {
                                if ( ! grep(/$CLNODE/, @CLARRAY ) ) {
                                    push(@CLARRAY, $CLNODE);
                                }
                            }
                        }

                        if ( grep( /^package:/, $_ ) ) {
                            ( undef, $CLPACKAGE, undef ) = split( /:/, $_ );
                            chomp($CLPACKAGE);
                            $CLPACKAGE =~ s/\|.*//g;
                            if ( "$CLPACKAGE" ) {
                                if ( ! grep(/$CLPACKAGE/, @CLPKGARRAY ) ) {
                                    push(@CLPKGARRAY, $CLPACKAGE);
                                }
                            }
                        }

                        if ( grep( /cluster_lock:/, $_ ) ) {
                            ( undef, $CLLOCK ) = split( /:/, $_ );
                            chomp($CLLOCK);
                            $CLLOCK =~ s/.*physical_volume=//g;
                            if ( "$CLLOCK" ) {
                                if ( ! grep(/$CLLOCK/, @CLLOCKARRAY ) ) {
                                    push(@CLLOCKARRAY, $CLLOCK);
                                }
                            }
                        }
                    }
                }
                close(CMFORM);
            }

            if ( @CLARRAY ) {
                my $FIRSTCLNODE = pop @CLARRAY;
                if ( "$FIRSTCLNODE" ) {
                    my @cmquerystg = `cmquerystg -f line -n $FIRSTCLNODE 2>/dev/null`;
                    if ( @cmquerystg ) {
                        print "\n$INFOSTR Serviceguard DSF summary on node $FIRSTCLNODE\n";
                        print @cmquerystg;
                    }

                    foreach my $othnode (@CLARRAY) {
                        my @patchdiff = `sysdiff -v $FIRSTCLNODE $othnode 2>/dev/null`;
                        if ( @patchdiff ) {
                            print
"\n$INFOSTR Patch comparison on nodes $FIRSTCLNODE and $othnode\n";
                            print @patchdiff;
                        }
                        else {
                            print
"\n$INFOSTR Patch comparison between nodes $FIRSTCLNODE and $othnode shows no differences\n";
                        }
                    }
                }
            }

            if ( @CLPKGARRAY ) {
                foreach my $myclpkg (@CLPKGARRAY) {
                    my @cmgetpkg = `cmgetpkgenv $myclpkg 2>/dev/null`;
                    if ( @cmgetpkg ) {
                        print "\n$INFOSTR CMgetpkgenv for package $myclpkg\n";
                        print @cmgetpkg;
                    }

                    my @cmcheckpkg = `cmcheckonf -P $myclpkg 2>/dev/null`;
                    if ( @cmcheckpkg ) {
                        print "\n$INFOSTR CMcheckconf for package $myclpkg\n";
                        print @cmcheckpkg;
                    }
                }
            }

            if ( @CLLOCKARRAY ) {
                foreach my $mycllck (@CLLOCKARRAY) {
                    my @cmgetlck = `cmdisklock check $mycllck 2>/dev/null`;
                    if ( @cmgetlck ) {
                        print "\n$INFOSTR CMdisklock for disk $mycllck\n";
                        print @cmgetlck;
                    }
                }
            }

            my @cmviewl = `cmviewcl -l group -v 2>/dev/null`;
            if ( @cmviewl ) {
                print "\n$INFOSTR CMviewcl group summary\n";
                print @cmviewl;
            }

            my @cmviewv = `cmviewcl -l package -v 2>/dev/null`;
            if ( @cmviewv ) {
                print "\n$INFOSTR CMviewcl package summary\n";
                print @cmviewv;
            }

            my @cmquerycl = `cmquerycl -v 2>/dev/null`;
            if ( @cmquerycl ) {
                print "\n$INFOSTR Cmquerycl summary\n";
                print @cmquerycl;
            }

            my @cmqueryloc = `cmquerycl -v -w full -c $MCCLNAME 2>/dev/null`;
            if ( @cmqueryloc ) {
                print "\n$INFOSTR Cmquerycl full cluster summary\n";
                print @cmqueryloc;
            }

            my @cmscancl = `cmscancl -s 2>/dev/null`;
            if ( @cmscancl ) {
                print "\n$INFOSTR CMscancl summary\n";
                print @cmscancl;
            }

            my @ovcluster = `ovclusterinfo -a 2>/dev/null`;
            if ( @ovcluster ) {
                print "\n$INFOSTR OVclusterinfo summary\n";
                print @ovcluster;
            }

            if ( $CMHELMD_FLAG < 1 ) { 
                 print
"\n$INFOSTR CM Heartbeat Exchange Latency Measurement (HELM) cmhelmd not running\n";
            }
            else {
                if ( grep( /HELM/, @SWarray ) ) {
                    print
"\n$PASSSTR CM Heartbeat Exchange Latency Measurement (HELM) bundle installed\n";
               
                    if ( -s "$CMHELMCONF" ) {
                        my @cmhelmcat = `egrep -v ^# $CMHELMCONF 2>/dev/null`;
                        if ( @cmhelmcat ) {
                            print
"\n$INFOSTR CM HELM configuration file $CMHELMCONF\n";
                            print @cmhelmcat;
                            print "\n";
                        }

                        my @cmrunhelm = `cmrunhelm 2>/dev/null`;
                        sleep(240);

                        my @cmrephelm = `cmreporthelm 2>/dev/null`;
                        if ( @cmrephelm ) {
                            print
"\n$INFOSTR CM HELM summary for 240 seconds measurement\n";
                            print @cmrephelm;
                        }

                        my @cmhalthelm = `cmhalthelm >/dev/null 2>&1`;
                    }
                }
                else {
                    print
"\n$INFOSTR CM Heartbeat Exchange Latency Measurement bundle not installed\n";
                } 
            }

            if ( -s "$CMNODEFILE" ) {
                if ( open( CMAC, "egrep -v ^# $CMNODEFILE 2>&1 |" ) ) {
                    print
"\n$INFOSTR Configuration file $CMNODEFILE for enabling remote access to nodes in the cluster\n";
                    while (<CMAC>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                    }
                    close(CMAC);
                    print "\n";
                }
                else {
                    print "\n$INFOSTR Cannot open configuration file $CMNODEFILE\n";
                }
            }
            else {
                print
"\n$INFOSTR Configuration file $CMNODEFILE is zero-length or does not exist on this node\n";
            }

            if ( -s "$CMAUTHFILE" ) {
                if ( open( CMAF, "egrep -v ^# $CMAUTHFILE 2>&1 |" ) ) {
                    print
"\n$INFOSTR Configuration file $CMAUTHFILE for Quorum Server\n";
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
            else {
                print
"\n$INFOSTR Configuration file $CMAUTHFILE is zero-length or does not exist on this node\n";
            }

            if ( $SGVER >= 111600 ) {
                if ( -f "$CMKNOWCMDS" ) {
                    print
"\n$INFOSTR Configuration file $CMKNOWCMDS exists (used internally by Serviceguard 11.16 and above)\n";
                }
                else {
                    print
"\n$INFOSTR Configuration file $CMKNOWCMDS missing (used internally by Serviceguard 11.16 and above)\n";
                }
            }

            if ( -s "$LMRC" ) {
                if ( open( LMAC, "cat $LMRC 2>&1 |" ) ) {
                    print
"\n$INFOSTR Configuration file $LMRC for volume groups at startup time\n";
                    while (<LMAC>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                    }
                    close(LMAC);
                    print "\n";
                }
                else {
                    print "\n$INFOSTR Cannot open configuration file $LMRC\n";
                }
            }
            else {
                    print
"\n$INFOSTR Configuration file $LMRC is zero-length or does not exist on this node\n";
            }

            if ( $SGVER >= 111800 ) {
                if ( -s "$CMCLUSTCONF" ) {
                    if ( open( CMAK, "egrep -v ^# $CMCLUSTCONF 2>&1 |" ) ) {
                        print "\n$INFOSTR Configuration file $CMCLUSTCONF\n";
                        while (<CMAK>) {
                            next if ( grep( /^$/, $_ ) );
                            next if ( grep( /^#/, $_ ) );
                            print $_;
                            if ( ! grep( /=/, $_ ) ) {
                                push(@CHECKARR,
"\n$WARNSTR Possibly corrupt Serviceguard configuration file $CMCLUSTCONF\n");
                                push(@CHECKARR,
"\n$WARNSTR Missing (\"=\" on line \"$_\"\n");
                                push(@CMARR,
"\n$WARNSTR Possibly corrupt Serviceguard configuration file $CMCLUSTCONF\n");
                                push(@CMARR,
"\n$WARNSTR Missing (\"=\" on line \"$_\"\n");
                                $warnings++;
                            }
                        }
                        close(CMAK);
                        print "\n";
                    }
                    else {
                        print
"\n$INFOSTR Cannot open configuration file $CMCLUSTCONF\n";
                    }
                }
                if ( @CMARR ) {
                    print @CMARR;
                }
            }

            my @cmclusterll = `ll -R /etc/cmcluster 2>/dev/null`;
            if ( @cmclusterll != 0 ) {
                print "\n$INFOSTR Recursive listing of /etc/cmcluster\n";
                print @cmclusterll;
            }

            if ( "$Minor$Patch" >= 1131 ) {
                my @olradC = `olrad -C 2>/dev/null`;
                if ( @olradC ) {
                    print
"\n$INFOSTR Network interface cards that are part of the Serviceguard cluster\n";
                    print @olradC;
                }
            }
        }
        else {
            print "\n$WARNSTR Possibly corrupt Serviceguard installation\n";
            push(@CHECKARR,
"\n$WARNSTR Possibly corrupt Serviceguard installation\n");
            $warnings++;
        }

        print "\n";
        Veritasop(); 
    }
    else {
        print "$PASSSTR Ambiguous Serviceguard installation\n";
    }

    if ( ( "$SGCNT" == 0 ) || ( "$SGRUN" == 0 ) ) {
        if ( -c "$SLVMVGCONF" ) {
            print
"\n$WARNSTR $SLVMVGCONF exists (should be removed when Serviceguard not used)\n";
            push(@CHECKARR,
"\n$WARNSTR $SLVMVGCONF exists (should be removed when Serviceguard not used)\n");
            $warnings++;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING SERVICEGUARD CONFIGURATION $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING CLUSTERPACK $datestring ***");

    my @fconfig = `finalize_config 2>/dev/null`;
    if ( @fconfig ) {
        $opts{r} = 1;

        print "$INFOSTR ClusterPack seemingly installed\n";
        print @fconfig;

        my $checklist = "/etc/checklist";
        if ( -s "$checklist" ) {
            my @chklist = `awk NF $checklist`;
            if ( @chklist ) {
                print "$INFOSTR ClusterPack file $checklist\n";
                print @chklist;
            }
        }
    }
    else {
        print "$INFOSTR ClusterPack seemingly not running or installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING CLUSTERPACK $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SCALABLE VIRTUALIZATION ARRAY $datestring ***");

    if ( -s "$svaconf" ) {
        if ( open( SVAC, "egrep -v ^# $svaconf 2>&1 |" ) ) {
            print "$INFOSTR Configuration file $svaconf\n";
            while (<SVAC>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /#/,  $_ ) );
                print $_;
            }
            close(SVAC);
            print "\n";
        }
        else {
            print "$WARNSTR Cannot open configuration file $svaconf\n\n";
            push(@CHECKARR,
"\n$WARNSTR Cannot open configuration file $svaconf\n\n");
        }
    }
    else {
        print
"$INFOSTR Configuration file $svaconf does not exist or is zero-length\n\n";
    }

    if ( open( SVAA, "svaverify -V |" ) ) {
        print "$INFOSTR SVA seemingly running\n";
        $SVA_FLAG++;
        while (<SVAA>) {
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /#/,  $_ ) );
            print $_;
        }
        close(SVAA);
    }
    else {
        print "$INFOSTR SVA seemingly not running\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SCALABLE VIRTUALIZATION ARRAY $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING CONTINENTALCLUSTER AND METROCLUSTER CONFIGURATION $datestring ***");

    if ( "$HORCMD_FLAG" > 0 ) {
        print "\n$INFOSTR Raid Manager seemingly running\n";
    }
    else {
        print "\n$INFOSTR Raid Manager seemingly not running\n";
    }

    my @horcmconf = `ls /etc/horcm*.conf 2>/dev/null`;
    foreach my $horcm ( @horcmconf ) {
        chomp($horcm);
        my @horcmarr = `awk NF $horcm`;
        if ( @horcmarr ) {
            print "$INFOSTR Configuration file $horcm\n";
            print @horcmarr;
            print "\n";
        }
    }

    my @smispasswd = `smispasswd -l 2>/dev/null`;
    if ( @smispasswd ) {
        print "\n$INFOSTR Management servers\n";
        print @smispasswd;
    }

    my @xpdisc = `xpinfo -i 2>/dev/null | awk NF`;
    if ( @xpdisc ) {
        print "\n$INFOSTR XP storage devices\n";
        print @xpdisc;
    }

    @EVADISC = `evadiscovery -l 2>/dev/null`;
    if ( @EVADISC ) {
        print "\n$INFOSTR EVA discovery\n";
        print @EVADISC;
    }

    @EVAINFO = `evainfo -a -l 2>/dev/null | awk NF`;
    if ( @EVAINFO ) {
        print "\n$INFOSTR EVA storage devices\n";
        print @EVAINFO;
    }

    @EVAINFOWWN = `evainfo -P -W 2>/dev/null | awk NF`;
    if ( @EVAINFOWWN ) {
        print "\n$INFOSTR EVA storage devices with agile view\n";
        print @EVAINFOWWN;
    }

    @EMC = `syminq 2>/dev/null`;
    if ( @EMC ) {
        print "\n$INFOSTR EMC storage devices\n";
        print @EMC;
    }

    @EMCCFG = `symcfg list -v 2>/dev/null`;
    if ( "@EMCCFG" ) {
        print "\n$INFOSTR EMC storage devices full listing\n";
        print @EMCCFG;
    }

    @EMCGATE = `symgate list 2>/dev/null`;
    if ( "@EMCGATE" ) {
        print "\n$INFOSTR EMC Symmetrix gatekeepers\n";
        print @EMCGATE;
    }

    @SYMRDF = `symrdf list -rdfa 2>/dev/null`;
    if ( "@SYMRDF" ) {
        print "\n$INFOSTR EMC Symmetrix SRDF/async capabilities\n";
        print @SYMRDF;
    }

    @SYMPD = `sympd list 2>/dev/null`;
    if ( "@SYMPD" ) {
        print "\n$INFOSTR EMC Symmetrix devices\n";
        print @SYMPD;
    }

    @SYMDG = `symdg list 2>/dev/null`;
    if ( "@SYMDG" ) {
        print "\n$INFOSTR EMC Symmetrix symdb capabilities\n";
        print @SYMDG;
    }

    my @ccmcclu = `raidqry -l 2>/dev/null`;
    if ( @ccmcclu ) {
        print "\n$INFOSTR Software status of Raid Manager\n";
        print @ccmcclu;
    
        if ( open( RAIDQRY, "raidqry -g 2>/dev/null |" ) ) {
            print "\n$INFOSTR RAID query status\n";
            while (<RAIDQRY>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /#/,  $_ ) );
                print $_;
                next if ( grep( /RAID_type/, $_ ) );
                $autovg =~ s/^\s+//g;
                ( $GNO, $RAIDgroup, $RAIDtype, $IVH, $IVM, $MUNH, $MUNM ) = split( /\s+/, $_ );
                $RAIDgroup =~ s/^\s+//g;
                $RAIDgroup =~ s/\s+$//g;
                push(@RAIDARRAY, $RAIDgroup);
            }
        }

        my @ccmccluf = `raidqry -l -f 2>/dev/null`;
        if ( @ccmccluf ) {
            print "\n$INFOSTR Floatable hosts status via Raid Manager\n";
            print @ccmcclu;
        }

        my @raidscan = `ls /dev/rdsk/* /dev/rdisk/* | raidscan -find 2>/dev/null`;
        if ( @raidscan ) {
            print "\n$INFOSTR RAID Manager Raidcsan summary\n";
            print @raidscan;
        }

        my @raidscanf = `ls /dev/rdsk/* /dev/rdisk/* | raidscan -find verify -fd 2>/dev/null`;
        if ( @raidscanf ) {
            print "\n$INFOSTR RAID Manager Raidcsan verification summary\n";
            print @raidscanf;
        }
    }

    if ( @RAIDARRAY ) {
        foreach my $raent ( @RAIDARRAY ) {
            my @raidres = `pairdisplay -g $raent -m all 2>/dev/null`;
            if ( @raidres ) {
                print "\n$INFOSTR RAID Manager group $raent pairdisplay\n";
                print @raidres;
            }

            my @raidvol = `pairvolchk -g $raent 2>/dev/null`;
            if ( @raidvol ) {
                print "\n$INFOSTR RAID Manager group $raent pairvolchk\n";
                print @raidvol;
            }
        }
    }

    my @pairmon = `pairmon -allsnd -nowait 2>/dev/null`;
    if ( @pairmon ) {
        print "\n$INFOSTR RAID Manager monitor status\n";
        print @pairmon;
    }

    my @raidcvhkscan = `raidvchkscan -v jnl 2>/dev/null`;
    if ( @raidcvhkscan ) {
        print "\n$INFOSTR Raid Manager Journal Group summary\n";
        print @raidcvhkscan;
    }

    my @horcctl = `horcctl -DI 2>/dev/null`;
    if ( @horcctl ) {
        print "\n$INFOSTR RAID Manager control device summary\n";
        print @horcctl;
    }

    if ( @METROARR ) {
        print "\n$INFOSTR Metrocluster with Site Controller seemingly installed\n";
        print "$INFOSTR Metrocluster \"SITE_NAME\" status\n";
        print @METROARR;
        print "\n"; 
    }
    else {
        print "\n$INFOSTR Metrocluster with Site Controller seemingly not installed\n";
    }

    my @cmviewsc = `cmviewsc -v 2>/dev/null`;
    if ( @cmviewsc ) {
        print "\n$INFOSTR Metrocluster Site Aware Disaster Tolerant Architecture (SADTA) status\n";
        print @cmviewsc;
    }

    if ( "$CCCLUSTER_FLAG" > 0 ) {
        print "\n$INFOSTR Continentalcluster seemingly running\n";

        my @cmviewconcl  = `cmviewconcl -v 2>/dev/null`;
        my @cmqueryconcl = `cmqueryconcl -v 2>/dev/null`;

        $opts{r} = 1;

        if ( @cmviewconcl ) {
            print "\n$INFOSTR Cmviewconcl summary\n";
            print @cmviewconcl;
        }

        if ( @cmqueryconcl ) {
            print "\n$INFOSTR Cmqueryconcl summary\n";
            print @cmqueryconcl;
        }

        my @cmjar = `/opt/cmconcl/jar/what.sh configcl.jar -v 2>/dev/null`;
        if ( @cmjar ) {
            print "\n$INFOSTR Continentalcluster Java .jar version summary\n";
            print @cmjar;
        }
    }
    else {
        print "\n$INFOSTR Continentalcluster seemingly not configured or running\n";
    }

    datecheck();
    print_trailer("*** END CHECKING CONTINENTALCLUSTER AND METROCLUSTER CONFIGURATION $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING VERITAS CLUSTER CONFIGURATION $datestring ***");

    if ( @vxdctl0 ) {
        if ( $VRTSVCS_FLAG > 0 ) {
            print "$INFOSTR Veritas Cluster package installed\n";
          
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
                if ( (-s "$vvva" ) && ( -T "$vvva" ) ) {
                    print
                  "\n$INFOSTR Veritas Cluster configuration file $vvva\n";
                    @GBar = `cat $vvva`;
                    print @GBar;
                }
                else {
                    print
"\n$INFOSTR Veritas Cluster configuration file $vvva is zero-length or non-existent\n";
                }
            }

            if ( -s "$VXFENTAB" ) {
                print
                "\n$INFOSTR Veritas Cluster configuration file $VXFENTAB\n";
                my @FENARR = `egrep -v ^# $VXFENTAB`;
                print @FENARR;
                my @vxfenconfig = `vxfenconfig -V`;
                if ( @vxfenconfig ) {
                    print "\n";
                    print @vxfenconfig;
                }
            }
            else {
                print
"\n$INFOSTR Veritas fencing configuration file $VXFENTAB is zero-length or non-existent\n";
            }

            print "\n";
            Veritasop(); 

            my @cfscluster = `cfscluster status 2>/dev/null`;
            if (@cfscluster) {
                print
"\n$INFOSTR Veritas Cluster Volume Manager and multi-node package status\n";
                print @cfscluster;
            }

            my @cfsdgadm = `cfsdgadm display 2>/dev/null`;
            if (@cfsdgadm) {
                print
"\n$INFOSTR Veritas Cluster Volume Manager and disk group package status\n";
                print @cfsdgadm;
            }

            my @cfsmntadm = `cfsmntadm display 2>/dev/null`;
            if (@cfsmntadm) {
                print
"\n$INFOSTR Veritas Cluster Volume Manager and mount status\n";
                print @cfsmntadm;
            }

            my @LLTd = `lltconfig -a list 2>/dev/null`;
            if (@LLTd) {
                print "\n$INFOSTR Veritas Cluster lltconfig status\n";
                print @LLTd;
            }

            my @LLTs = `lltstat 2>/dev/null`;
            if (@LLTs) {
                $opts{r} = 1;
                print "\n$INFOSTR Veritas Cluster lltstat status\n";
                print @LLTs;
            }

            my @LLTc = `lltstat -c 2>/dev/null`;
            if (@LLTc) {
                print "\n$INFOSTR Veritas Cluster lltstat extended status\n";
                print @LLTc;
            }

            my @GABc = `gabconfig -l 2>/dev/null`;
            if (@GABc) {
                print "\n$INFOSTR Veritas Cluster gabconfig status\n";
                print @GABc;
            }

            my @HAGRPD = `hagrp -display 2>/dev/null`;
            if (@HAGRPD) {
                print "\n$INFOSTR Veritas Cluster HA status\n";
                print @HAGRPD;
            }

            my @HAGRPS = `hagrp -state 2>/dev/null`;
            if (@HAGRPS) {
                print "\n$INFOSTR Veritas Cluster HA state\n";
                print @HAGRPS;
            }

            my @HAGRP = `hagrp -list 2>/dev/null`;
            if (@HAGRP) {
                print "\n$INFOSTR Veritas Cluster HA configuration\n";
                print @HAGRP;
            }

            my @HAATTR = `haattr -display 2>/dev/null`;
            if (@HAATTR) {
                print "\n$INFOSTR Veritas Cluster HA attributes\n";
                print @HAATTR;
            }

            my @HATYPE = `hatype -display 2>/dev/null`;
            if (@HATYPE) {
                print "\n$INFOSTR Veritas Cluster HA types\n";
                print @HATYPE;
            }

            my @HAAGENT = `haagent -display 2>/dev/null`;
            if (@HAAGENT) {
                print "\n$INFOSTR Veritas Cluster HA agents\n";
                print @HAAGENT;
            }

            my @HASYS = `hasys -display 2>/dev/null`;
            if (@HASYS) {
                print "\n$INFOSTR Veritas Cluster HA sys display\n";
                print @HASYS;
            }

            my @HASTATUS = `hastatus -summary 2>/dev/null`;
            if (@HASTATUS) {
                print "\n$INFOSTR Veritas Cluster HA summary\n";
                print @HASTATUS;
            }

            my @HAUSER = `hauser -display 2>/dev/null`;
            if (@HAUSER) {
                print "\n$INFOSTR Veritas Cluster HA user summary\n";
                print @HAUSER;
            }

            my @vxclustadmnid = `vxclustadm nidmap 2>/dev/null`;
            if (@vxclustadmnid) {
                print "\n$INFOSTR Veritas Cluster node ID status\n";
                print @vxclustadmnid;
            }
        }
        else {
            print "$INFOSTR Veritas Cluster package not installed\n";
        }
    }
    else {
        print "$INFOSTR Veritas Cluster package not installed\n";
    }

    datecheck();
    print_header("*** END CHECKING VERITAS CLUSTER CONFIGURATION $datestring ***");
}

# Subroutine to check Veritas VxVM 
#
sub Veritasop {
    if (@vxdctl0) {
        print "$INFOSTR VxVM status\n";
        print @vxdctl0;
    }
    else {
        print "$INFOSTR VxVM not in use\n";
    }

    my @vxdctll  = `vxdctl license 2>/dev/null`;
    if (@vxdctll) {
        print "\n$INFOSTR VxVM licensed features\n";
        print @vxdctll;
    }

    my @vxdctlm  = `vxdctl -c mode 2>/dev/null`;
    if (@vxdctlm) {
        print "\n$INFOSTR VxVM current operating mode of vxconfigd\n";
        print @vxdctlm;
    }

    my @vxdctlp  = `vxdctl protocolversion 2>/dev/null`;
    if (@vxdctlp) {
        print "\n$INFOSTR VxVM protocol version\n";
        print @vxdctlp;
    }

    my @vxdctls  = `vxdctl support 2>/dev/null`;
    if (@vxdctls) {
        print "\n$INFOSTR VxVM supported cluster protocol version range\n";
        print @vxdctls;
    }
}

# Subroutine to check HyperFabric 
#
sub HyperFabriccheck {
    datecheck();
    print_header("*** BEGIN CHECKING HYPERFABRIC $datestring ***");

    if ( $CLIC_FLAG > 0 ) {
        print "$INFOSTR HyperFabric subsystem seemingly installed and running\n";
     
        if ( -s "$CLIC_CONF") {
            if ( open( CLD, "awk NF $CLIC_CONF |" ) ) {
                print "\n$INFOSTR File $CLIC_CONF\n";
                while (<CLD>) {
                    print $_;
                }
                close(CLD);
            }

            my @clica = `clic_stat -dALL 2>/dev/null`;
            if ( @clica ) {
                print "\n$INFOSTR General configuration and statistics\n";
                print @clica;
            }

            my @clicstat = `clic_stat -d CFG 2>/dev/null`;
            if ( @clicstat ) {
                print
"\n$INFOSTR Management daemon (clic_mgmtd) configuration and statistics\n";
                print @clicstat;
            }

            my @clicvrid = `clic_stat -d VRID 2>/dev/null`;
            if ( @clicvrid ) {
                print "\n$INFOSTR VRID configuration and statistics\n";
                print @clicvrid;
            }
        }
        else {
            print "\n$INFOSTR File $CLIC_CONF is zero-length or does not exist\n";
        }
    }
    else {
        print "$INFOSTR HyperFabric subsystem seemingly not running\n";
    }

    datecheck();
    print_trailer("*** END CHECKING HYPERFABRIC $datestring ***");
}

# Subroutine to check LVM rc startup
#
sub lvmsynccheck {
    datecheck();
    print_header("*** BEGIN CHECKING LVM SYNCHRONISATION $datestring ***");

    if ( -s "$lvmconf" ) {
        if ( open( LVMSYNC, "egrep -v ^# $lvmconf 2>&1 | awk NF |" ) ) {
            print "$INFOSTR LVM startup file $lvmconf\n";
            while (<LVMSYNC>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /#/,  $_ ) );

                if ( grep( /^AUTO_VG_ACTIVATE/, $_ ) ) {
                    ( undef, $autovg ) = split( /=/, $_ );
                    $autovg =~ s/^\s+//g;
                    $autovg =~ s/\s+$//g;
                    chomp($autovg);
                }

                if ( grep( /^RESYNC/, $_ ) ) {
                    ( undef, $lvmresync ) = split( /=/, $_ );
                    $lvmresync =~ s/^\s+//g;
                    $lvmresync =~ s/\s+$//g;
                }

                if ( grep( /^LVMP_CONF_PATH_NON_BOOT/, $_ ) ) {
                    ( undef, $lvmpathnb ) = split( /=/, $_ );
                    $lvmpathnb =~ s/^\s+//g;
                    $lvmpathnb =~ s/\s+$//g;
                    $lvmpathnb =~ s/"//g;
                    chomp($lvmpathnb);
                }

                print $_;
            }
        }
        else {
            print "$WARNSTR Cannot open $lvmconf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $lvmconf\n");
            $warnings++;
        }
        close(LVMSYNC);
    }

    if ( "$lvmpathnb" ne "" ) {
        print "\n$INFOSTR Default path to store non-bootable VG configuration backup file is $lvmpathnb\n";
    }

    if ( "$autovg" == 0 ) {
        if ( "$SGRUN" >= 1 ) {
            print
"\n$PASSSTR Automatic VG activation set to $autovg for Serviceguard servers\n";
        }
        else {
            print
"\n$WARNSTR Automatic VG activation should be set to 1 for ";
            print
"non-Serviceguard servers (currently $autovg in $lvmconf)\n";
            push(@CHECKARR,
"\n$WARNSTR Automatic VG activation should be set to 1 for ");
            push(@CHECKARR,
"non-Serviceguard servers (currently $autovg in $lvmconf)\n");
            $warnings++;
        }
    }
    elsif ( "$autovg" == 1 ) {
        if ( "$SGRUN" >= 1 ) {
            print
"\n$WARNSTR Automatic VG activation set to $autovg (should be disabled for Serviceguard servers)\n";
            push(@CHECKARR,
"\n$WARNSTR Automatic VG activation set to $autovg (should be disabled for Serviceguard servers)\n");
            $warnings++;
        }
        else {
            print
"\n$PASSSTR Automatic VG activation set to $autovg for non-Serviceguard servers\n";
        }
    }
    else {
        print "\n$ERRSTR Automatic VG activation not defined in $lvmconf\n";
        push(@CHECKARR,
"\n$ERRSTR Automatic VG activation not defined in $lvmconf\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING LVM SYNCHRONISATION $datestring ***");
}

# Subroutine to check live dumps on HP-UX v3 and above
#
sub livedump {
    if ( "$Hardware" eq "ia64" ) {
        if ( "$Minor$Patch" >= 1131 ) {
            datecheck();
            print_header("*** BEGIN CHECKING LIVE DUMP $datestring ***");

            my $LDUMPCONF = "${RCCONFDIR}/livedump";
            if ( ( -s "$LDUMPCONF" ) && ( -T "$LDUMPCONF" ) ) {
                my @ldumpcat = `egrep -v ^# $LDUMPCONF | awk NF`;
                if ( @ldumpcat ) {
                    print "$INFOSTR $LDUMPCONF configuration file\n";
                    print @ldumpcat;
                }
            }
            else {
                print "$INFOSTR $LDUMPCONF is zero-length or missing\n";
            }

            datecheck();
            print_trailer("*** END CHECKING LIVE DUMP $datestring ***");
        }
    }
}

# Subroutine to check core file administration on HP-UX v3 and above
#
sub coreadm {
    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING CORE FILE ADMINISTRATION $datestring ***");

        my @coreadm = `coreadm | awk NF`;
        if ( @coreadm ) {
            print @coreadm;
        }
        else {
            print "$INFOSTR Core file administration missing\n";
        }

        datecheck();
        print_trailer("*** END CHECKING CORE FILE ADMINISTRATION $datestring ***");
    }
}

# Subroutine to check boot devices
#
sub bootdev {
    datecheck();
    print_header("*** BEGIN CHECKING CURRENT BOOT DEVICE $datestring ***");

    if ( !"$Stand" ) {
        $Stand = "/stand/vmunix";
    }

    if ( "$Minor$Patch" >= 1123 ) {
        $ADB_FLAG = "-o";
    }

    if ( ! @vxdctl0 ) {
        @Barr = `echo "boot_string/s" | adb $ADB_FLAG $Stand $Kmemdev | egrep "\/"`;
        @Barr2 = `echo "bootdev/X" | adb $ADB_FLAG $Stand $Kmemdev | tail -1 | awk '{print \$NF}'`;

        if ( @Barr2 ) {
            chomp(@Barr2);
            foreach my $bd1 (@Barr2) {
                chomp($bd1);
                $bd1 =~ s/^\s+//g;
                $bd1 =~ s/\s+$//g;
                if ( "$bd1" ) {
                    if ( grep( /^0x/, $bd1 ) ) {
                        $bd1 =~ s/^0x//g;
                    }

                    my $classno = my $ctrlno = my $targetno = q{};
                    my $diskno = my $bflags = q{} ;
                    if ( "$Minor$Patch" >= 1131 ) {
                        ($classno, $dev_t ) = unpack("A1 A*", $bd1);
                        if ( "$dev_t" ) {
                            my @rbdisk = `ll /dev/disk | grep $dev_t`;
                            if ( @rbdisk ) {
                                chomp($rbdisk[$#rbdisk]);
                                print
"$INFOSTR Boot device $dev_t translates to disk\n$rbdisk[$#rbdisk]\n";
                            }
                        }
                    }
                    else {
                        ($classno, $ctrlno, $targetno, $diskno, $bflags) = unpack("A2 A2 A1 A1 A*", $bd1);
                        my $CX1 = hex($ctrlno);
                        my $CX2 = hex($targetno);
                        my $CX3 = hex($diskno);
                        my $C1 = sprintf("%d", $CX1);
                        my $C2 = sprintf("%d", $CX2);
                        my $C3 = sprintf("%d", $CX3);
                        print
"$INFOSTR Boot device $bd1 translates to disk c${C1}t${C2}d${C3}\n";
                    }
                }
            }
        
            if ( @Barr != 0 ) {
                print "\n$INFOSTR Boot string\n";
                print "@Barr";
            }
        }
        else {
            print
"$ERRSTR Cannot find boot device in $Stand and $Kmemdev\n";
            push(@CHECKARR,
"\n$ERRSTR Cannot find boot device in $Stand and $Kmemdev\n");
            $warnings++;
        }

        datecheck();
        print_trailer("*** END CHECKING CURRENT BOOT DEVICE $datestring ***");

        if ( -s "$sbtab" ) {
            my @sblist = `awk NF $sbtab`;
            if ( @sblist != 0 ) {
                datecheck();
                print_header("*** BEGIN CHECKING BOOT DEVICE SUPER-BLOCKS");
                print @sblist;
                datecheck();
                print_trailer("*** END CHECKING BOOT DEVICE SUPER-BLOCKS");
            }
        } 

        datecheck();
        print_header("*** BEGIN CHECKING SHUTDOWN STATUS OF HFS FILE SYSTEMS $datestring ***");

        if ( open( FSCLEAN, "fsclean -v 2>/dev/null |" ) ) {
            while (<FSCLEAN>) {
                next if ( grep( /^$/, $_ ) );
                push(@HFSCLEAN, $_);
                chomp($_);
                if ( grep(/:/, $_) ) {
                    ( undef, $HFSVOL, undef ) = split( /\s+/, $_ );
                    if ( grep(/^\/dev\//, $HFSVOL ) ) {
                        push(@HFSARR, $HFSVOL);
                    }
                }
            }
            close(FSCLEAN);

            if ( @HFSCLEAN ) {
                print "$INFOSTR HFS status\n";
                print @HFSCLEAN;
            }
            else {
                print "$INFOSTR No HFS detected on the system\n";
            }
        }

        datecheck();
        print_trailer("*** END CHECKING SHUTDOWN STATUS OF HFS FILE SYSTEMS $datestring ***");
    }
    else {
        my $bootdg = `vxdg bootdg 2>/dev/null`;
        chomp($bootdg);
        if ( "$bootdg" ne "$DEFBOOTDG" ) { 
            $rootdg = "$bootdg";
        }

        my @Barrvx = `ll /dev/vx/dmp | grep 0x000000`;
        if ( @Barrvx != 0 ) {
            print "@Barrvx\n\n";
        }

        if ( open( BMX, "vxdg list $rootdg |" ) ) {
            while (<BMX>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /^config disk/, $_ ) ) {
                    if ( grep( /state=clean online/, $_ ) ) {
                        print
"\n$PASSSTR VxVM boot disk group in healthy state\n";
                    }
                    else {
                        push(@VXINFOARR,
"\n$WARNSTR VxVM boot disk group not in healthy state\n");
                        push(@VXINFOARR, "$_");
                        push(@CHECKARR,
"\n$WARNSTR VxVM boot disk group not in healthy state\n");
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

        if ( @VXINFOARR ) {
            print @VXINFOARR;
        }

        if ( open( MP, "vxprint -g $rootdg |" ) ) {
            print "\n$INFOSTR VxVM boot disk group $rootdg\n";
            while (<MP>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /^dm/, $_ ) ) {
                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s{\A \s* | \s* \z}{}gxm;
                    (
                        undef, undef, $vxdisk, $vxdisklayout, $vxblocksize,
                        $vxdisksize,
                    ) = split( /\s+/, $_ );
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

        foreach my $vxdck (@VXBOOTDISK) {
            my $vxda = "/dev/rdsk/$vxdck";

            if ( grep(/_p/, $vxdck) ) {
                $vxda =~ s/\/rdsk\//\/rdisk\//g;
            }

            my @vxvmboot  = `vxvmboot -v $vxda 2>&1| awk NF`;
            my @vxvmlifls = `lifls -l $vxda 2>&1| awk NF`;
            my @vxvmlifcp = `lifcp $vxda:AUTO - 2>/dev/null`;

            if ( @vxvmboot != 0 ) {
                print "\n$INFOSTR VxVM boot LIF and label status\n";
                print @vxvmboot;
            }

            if ( @vxvmlifls != 0 ) {
                print "\n$INFOSTR VxVM boot LIF details\n";
                print @vxvmlifls;
            }

            if ( @vxvmlifcp != 0 ) {
                if ( !grep( /vpmon/, @vxvmlifcp ) ) {
                    if ( !grep( /-lq/, @vxvmlifcp ) ) {
                        print
"\n$WARNSTR Boot disk $vxda does not have low-quorum set\n";
                        push(@CHECKARR,
"\n$WARNSTR Boot disk $vxda does not have low-quorum set\n\n");
                    }
                    else {
                        print "\n$PASSSTR Boot disk $vxda has low-quorum set\n";
                    }
                    print @vxvmlifcp;
                }
            }
        }

        if ( "$VXBOOT" == 0 ) {
            print "\n$WARNSTR Boot volumes not in VxVM\n";
            push(@CHECKARR, "\n$WARNSTR Boot volumes not in VxVM\n");
            $warnings++;
        }
        elsif ( "$VXBOOT" == 1 ) {
            print "\n$WARNSTR Single boot volume in VxVM\n";
            push(@CHECKARR, "\n$WARNSTR Single boot volume in VxVM\n");
            $warnings++;
        }
        else {
            print "\n$PASSSTR Multiple boot volumes in VxVM\n";
        }

        if ( "$VXSWAP" == 0 ) {
            print "\n$WARNSTR Swap volumes not in VxVM\n";
            push(@CHECKARR, "\n$WARNSTR Swap volumes not in VxVM\n");
            $warnings++;
        }
        elsif ( "$VXSWAP" == 1 ) {
            print "\n$WARNSTR Single swap volume in VxVM\n";
            push(@CHECKARR, "\n$WARNSTR Single swap volume in VxVM\n");
            $warnings++;
        }
        else {
            print "\n$PASSSTR Multiple swap volumes in VxVM\n";
        }

        if ( -f "$volboot" && -s "$volboot" ) {
            print "\n$PASSSTR VxVM $volboot exists\n";
            if ( open( VB, "awk '! /^#/ && ! /awk/ {print}' $volboot |" ) ) {
                while (<VB>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
            }
            close(VB);
        }
        else {
            print "\n$WARNSTR $volboot corrupt or missing\n";
            push(@CHECKARR, "\n$WARNSTR $volboot corrupt or missing\n");
            $warnings++;
        }

        datecheck();
        print_trailer("*** END CHECKING CURRENT BOOT DEVICE $datestring ***");
    }
}

# Subroutine to check boot volumes
#
sub standbootck {
    if ( open( FF, "awk '! /^#/ && ! /awk/ {print}' $standboot |" ) ) {
        print "$INFOSTR Configuration file $standboot\n";
        while (<FF>) {
            print $_;
            chomp($_);
            if ( grep( /\s+$/, $_ ) ) {
                push(@STBOOTARR,
"\n$WARNSTR Empty spaces at the end of line \"$_\" in $standboot\n");
                push(@STBOOTARR,
"$INFOSTR This been known to generate the error message with DRD mount\n");
                push(@CHECKARR, 
"\n$WARNSTR Empty spaces at the end of line \"$_\" in $standboot\n");
                $warnings++;
            }

            ( $VMtype, $VMbootdisk ) = split( /\s+/, $_ );

            if ( ! grep(/disk|dsk/, $VMbootdisk) ) {
                push(@STBOOTARR,
                "\n$WARNSTR Corrupt entry in $standboot: disk $VMbootdisk does not exist\n");
                push(@CHECKARR,
                "\n$WARNSTR Corrupt entry in $standboot: disk $VMbootdisk does not exist\n");
                $warnings++;
            }
            else {
                if ( grep(/$VMbootdisk/, @BOOTCARR) ) {
                    push(@STBOOTARR,
                    "\n$WARNSTR Multiple entries in $standboot: disk $VMbootdisk\n");
                    push(@CHECKARR,
                    "\n$WARNSTR Multiple entries in $standboot: disk $VMbootdisk\n");
                    $warnings++;
                }

                push(@BOOTCARR, $VMbootdisk);
            }

            "$VMtype" eq "l"
              ? push(@STBOOTARR,
              "\n$INFOSTR Boot disk $VMbootdisk managed by LVM or VxVM\n")
              : "$VMtype" eq "p"
              ? push(@STBOOTARR,
"\n$INFOSTR Boot disk $VMbootdisk has Series 800-style hard partitions and boot volume is section 6\n")
              : "$VMtype" eq "w"
              ? push(@STBOOTARR,
"\n$INFOSTR Boot disk $VMbootdisk in \"whole disk\" format with no partitions\n")
              : push(@STBOOTARR, "\n$INFOSTR Boot disk $VMbootdisk under unknown management\n");

            if ("$VMbootdisk") {
                push( @Bootconfdsk, $VMbootdisk );
            }
            else {
                print "\n$WARNSTR $standboot entries corrupted\n";
                push(@CHECKARR, "\n$WARNSTR $standboot entries corrupted\n");
                $warnings++;
            }
        }
        close(FF);

        if ( @STBOOTARR ) {
            print @STBOOTARR;
        }

        my @cksumssb = `cksum $standboot 2>/dev/null`;
        if ( @cksumssb != 0 ) {
            print "\n$INFOSTR Checksum of $standboot\n";
            print @cksumssb;
        }
    }
    else {
        print "\n$ERRSTR Cannot open $standboot\n";
        push(@CHECKARR, "\n$ERRSTR Cannot open $standboot\n");
        $warnings++;
    }
}

sub standck {
    datecheck();
    print_header("*** BEGIN CHECKING CONTENTS OF /STAND $datestring ***");

    my @standlist = `ls -als /stand 2>/dev/null`;

    if ( @standlist != 0 ) {
        print @standlist;
    }
    else {
        print "$ERRSTR Cannot list /stand\n";
        push(@CHECKARR, "\n$ERRSTR Cannot list /stand\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING CONTENTS OF /STAND $datestring ***");
}

sub standrt {
    if ( -s $standroot ) {
        print "$PASSSTR $standroot non-empty\n";

        my $srootuid = (stat($standroot))[4];

        if ( "$srootuid" == 0 ) {
            print "\n$PASSSTR $standroot owned by UID $srootuid\n";
        }
        else {
            print "\n$WARNSTR $standroot not owned by UID 0 ($srootuid)\n";
            push(@CHECKARR,
"\n$WARNSTR $standroot not owned by UID 0 ($srootuid)\n");
            $warnings++;
        }

        if ( open( STR, "xd $standroot 2>/dev/null |" ) ) {
            print "\n$INFOSTR Hex dump of $standroot\n";
            while (<STR>) {
                print $_;
                if ( grep( /0000000 dead beef/, $_ ) ) {
                    $STANDFLAG++;
                    @rootchead = split(/\s+/, $_);
                    $rootsizeKB = "$rootchead[5]$rootchead[6]";
                    $hexroots = hex($rootsizeKB);
                    $decroots = sprintf("%d", $hexroots);
                    chomp($decroots);
                    $bdfroots = `bdf / | awk '! /^Filesystem/ {if (/^\\/dev/) {print \$2} else {print \$1}}'`;
                    $bdfroots =~ s/\n//g;
                    $bdfroots =~ s/\^s+//g;
                    chomp($bdfroots);
                    if ( "$bdfroots" && "$decroots" ) {
                        if ( $decroots == $bdfroots ) {
                            push(@ROOTARR,
"\n$PASSSTR Size of file system \"/\" in $standroot ($decroots KB) matches the size as reported by bdf\n");
                        }
                        else {
                            push(@ROOTARR,
"\n$WARNSTR Size of file system \"/\" in $standroot ($decroots KB) does not match the size as reported by bdf ($bdfroots KB)\n");
                            push(@CHECKARR,
"\n$WARNSTR Size of file system \"/\" in $standroot ($decroots KB) does not match the size as reported by bdf ($bdfroots KB)\n");
                           $warnings++;
                        }
                    }
                }
            }
            close(STR);

            if ( @ROOTARR ) {
                print @ROOTARR;
            }

            if ( $STANDFLAG > 0 ) {
                print
"\n$INFOSTR $standroot seemingly valid (\"dead beef\" magic label present)\n";
                print "$INFOSTR Possible to boot with volume manager\n";
            }
            else {
                print
"\n$ERRSTR $standroot seemingly corrupt (\"dead beef\" magic label missing)\n";
                print "$INFOSTR Difficult to boot with volume manager\n";
                push(@CHECKARR,
"\n$ERRSTR $standroot seemingly corrupt (\"dead beef\" magic label missing)\n");
                $warnings++;
            }
        }
        else {
            print "$ERRSTR Cannot open $standroot\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $standroot\n");
            $warnings++;
        }
    }
    else {
        print "$ERRSTR $standroot is zero-length or does not exist\n";
        push(@CHECKARR, "\n$ERRSTR $standroot is zero-length or does not exist\n");
        $warnings++;
    }
}

# Subroutine to check boot volumes
#
sub bootcheck {
    standck();

    datecheck();
    print_header("*** BEGIN CHECKING /STAND/ROOTCONF $datestring ***");
    standrt();
    datecheck();
    print_header("*** END CHECKING /STAND/ROOTCONF $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING BOOT DISKS AND VOLUMES $datestring ***");

    standbootck();

    if ( open( UUU, "lvlnboot -v 2>/dev/null |" )) {
        print "\n$INFOSTR lvlnboot status\n";
        while (<UUU>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            chomp;
            next if ( grep( /Boot Definitions|Physical Volumes|Current/, $_ ) );

            if ( grep( /Boot Disk/, $_ ) ) {
                #
                # Get rid of leading and trailing empty spaces
                #
                $_ =~ s{\A \s* | \s* \z}{}gxm;
                $impdisk = $impdisk3 = q{};
                ( $impdisk, undef ) = split( /\s+/, $_ );
                $LVBDISK++;

                foreach my $bentry (@Bootconfdsk) {
                    if ( ${impdisk} eq ${bentry} ) {
                        push(@LVBOOTAR, 
"\n$PASSSTR Boot disk $impdisk listed in $standboot\n");
                        $bines{$impdisk} = 1;
                    }
                    else {
                        if ( $bines{$impdisk} != 1 ) {
                            $bines{$impdisk} = 0;
                        }
                    }
                }

                foreach my $bdisklst (sort keys %bines) {
                    if ( $bines{$bdisklst} == 0 ) {
                        push(@LVBOOTAR, 
"\n$ERRSTR Boot disk $bdisklst not listed in $standboot\n");
                        push(@CHECKARR,
"\n$ERRSTR Boot disk $bdisklst not listed in $standboot\n");
                        $warnings++;
                    }
                }

                ( undef, undef, undef, $impdisk3 ) = split( /\//, $impdisk );

                if ( "$impdisk3" ) {
                   push(@IMPDISK, $impdisk3);
                }
            }

            if ( grep( /\/dev\/drd/, $_ ) ) {
                push(@LVBOOTAR, "\n$INFOSTR Dynamic Root Disk configured\n");
            }

            if ( grep( /Boot:/, $_ ) ) {
                ( $Seen, $lvolid, undef, $disk ) = split( /\s+/, $_ );
                push( @Boot, "$lvolid on" );
                push( @Boot, $disk );
                $LVBOOT++;
            }

            if ( grep( /Root:/, $_ ) ) {
                ( $Seen, $lvolid, undef, $disk ) = split( /\s+/, $_ );
                push( @Root, "$lvolid on" );
                push( @Root, $disk );
                $LVROOT++;
            }

            if ( grep( /Swap:/, $_ ) ) {
                ( $Seen, $lvolid, undef, $disk ) = split( /\s+/, $_ );
                push( @Swap, "$lvolid on" );
                push( @Swap, $disk );
                push( @PrimSwap, $lvolid );
                $LVSWAP++;
            }

            if ( grep( /Dump:/, $_ ) ) {
                ( $Seen, $lvolid, undef, $disk ) = split( /\s+/, $_ );
                push( @Dump, "$lvolid on" );
                push( @Dumplvol, $lvolid );
                $disk =~ s/,$//g;
                push( @Dump, $disk );
                $LVDUMP++;
            }

            if ( $Seen eq "Boot:" ) {
                if ( !grep( /:/, $_ ) ) {
                    $LVBOOT++;
                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s{\A \s* | \s* \z}{}gxm;
                    push( @Boot, $_ );
                }
            }

            if ( $Seen eq "Root:" ) {
                if ( !grep( /:/, $_ ) ) {
                    $LVROOT++;
                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s{\A \s* | \s* \z}{}gxm;
                    push( @Root, $_ );
                }
            }

            if ( $Seen eq "Swap:" ) {
                if ( !grep( /:/, $_ ) ) {
                    $LVSWAP++;
                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s{\A \s* | \s* \z}{}gxm;
                    push( @Swap, $_ );
                }
            }

            if ( $Seen eq "Dump:" ) {
                if ( !grep( /:/, $_ ) ) {
                    $LVDUMP++;
                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s{\A \s* | \s* \z}{}gxm;
                    $_ =~ s/,$//g;
                    push( @Dump, $_ );
                }
            }
        }
        close(UUU);
    }
    else {
        print "\n$WARNSTR Cannot run lvlnboot\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run lvlnboot\n");
        $warnings++;
    }

    if ( @LVBOOTAR ) {
        print "\n";
        print @LVBOOTAR;
    }

    if ( @IMPDISK ) {
        foreach my $impdk (@IMPDISK) {
            if ( "$Minor$Patch" >= 1131 ) {
                $rimpdk = $impdk;
                $rimpdk =~ s/\/disk\//\/rdisk\//g;
                if ( ! grep(/\//, $rimpdk ) ) {
                    $rimpdk = "/dev/rdisk/$impdk";
                }
            }
            else {
                $rimpdk = $impdk;
                $rimpdk =~ s/\/dsk\//\/rdsk\//g;
                if ( ! grep(/\//, $rimpdk ) ) {
                    $rimpdk = "/dev/rdsk/$impdk";
                }
            }

            if ( open( BDI, "diskinfo -v $rimpdk 2>/dev/null |" ) ) {
                push( @ALLDISKINFO, "\n");
                while (<BDI>) {
                    push( @ALLDISKINFO, $_ );
                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s{\A \s* | \s* \z}{}gxm;
                    chomp($_);

                    if ( grep( /product id:/, $_ ) ) {
                        ( undef, $prodid ) = split( /:/, $_ );
                        if ( grep( /OPEN-|HSV|HSG|MSA|IBM DMV|NEXSAN|OPENstorage|EMC|DGC|SYMMETRIX|IR Volume|HITACHI|LOGICAL VOLUME|CX2|CX3|CX4/, $prodid ) ) {
                            print "\n$WARNSTR $impdk seemingly SAN or hardware-RAID based\n";
                            push(@CHECKARR,
"\n$WARNSTR $impdk seemingly SAN or hardware RAID-based\n");
                            print
"$NOTESTR Verify the benefits and disadvantages of SAN boot very carefully\n";
                            $SANbootdisk++;
                        }
                        elsif ( grep( /NETAPP/, $prodid ) ) {
                            print "\n$WARNSTR $impdk seemingly NAS-based\n";
                            push(@CHECKARR,
"\n$WARNSTR $impdk seemingly NAS-based\n");
                        }
                        else {
                            print
"\n$PASSSTR $impdisk is not SAN or hardware-RAID based\n";
                        }
                    }

                     if ( grep( /size:/, $_ ) ) {
                         my $disksize = 0;
                         ( undef, $disksize, undef ) = split( /:/, $_ );
                         my $disksizeGB = int( $disksize / ( 1024 * 1024 ) );
                         if ( "$Minor$Patch" >= 1131 ) {
                             # Boot disks for v3 requires 22.7 GB minimum
                             # Refer to page 25 in "HP-UX 11i v3 Installation
                             # and Update Guide, Sep 2007, Edition 2"
                             #
                             # Let's make it safe by adding overhead
                             # (especially if crash/dump vols are added
                             #
                             $MinBootSize = 60;
                         }
                         elsif ( "$Minor$Patch" >= 1120 ) {
                             $MinBootSize = 36;
                         }
                         else {
                             $MinBootSize = $DefMinBootSize;
                         }

                         if ( $disksizeGB < $MinBootSize ) {
                             print "$WARNSTR $impdk is less than ";
                             print "recommended in $OS_Standard ";
                             print
"($disksizeGB GB while minimum is $MinBootSize GB)\n";
                             push(@CHECKARR, "\n$WARNSTR $impdk is less than ");
                             push(@CHECKARR, "recommended in $OS_Standard ");
                             push(@CHECKARR,
"($disksizeGB GB while minimum is $MinBootSize GB)\n");
                         }
                         else {
                             print "$PASSSTR $impdk is larger than ";
                             print "recommended in $OS_Standard ";
                             print
"($disksizeGB GB while minimum is $MinBootSize GB)\n";
                        }
                    }
                }
                close(BDI);
            }
        }
    }

    if ( @ALLDISKINFO ) {
        print "\n$INFOSTR Diskinfo for all boot physical volumes\n";
        print @ALLDISKINFO;
    }

    foreach my $mine (@Boot) {
        if ( grep( /dsk\//, $mine )) { 
            my $XX = `lssf $mine | awk '{print \$2\$3\$4}'`;
            chomp($XX);
            print "\n$INFOSTR Boot disk $mine on controller $XX\n";
            if ( grep( /\b$XX\b/, @bootara ) ) {
                print
              "\n$ERRSTR Multiple boot disks on same controller $XX\n";
                push(@CHECKARR,
              "\n$ERRSTR Multiple boot disks on same controller $XX\n");
                $warnings++;
                $bings++;
            }
            else {
                push( @bootara, $XX );
            }
        }

        if ( grep( /\/disk\//, $mine )) { 
            my $dsfdev = `ioscan -F -m dsf $mine | awk -F: '{print \$2}'`;
            chomp($dsfdev);

            my $XX = `lssf $dsfdev | awk '{print \$2\$3\$4}'`;
            chomp($XX);
            print "\n$INFOSTR Boot disk $mine on controller $XX\n";
            if ( grep( /\b$XX\b/, @bootara ) ) {
                print
              "\n$ERRSTR Multiple boot disks on same controller $XX\n";
                push(@CHECKARR,
              "\n$ERRSTR Multiple boot disks on same controller $XX\n");
                $warnings++;
                $bings++;
            }
            else {
                push( @bootara, $XX );
            }
        }

    }

    if ( "$LVBDISK" == 0 ) {
        print "\n$ERRSTR No boot disks defined in lvlnboot\n";
        push(@CHECKARR, "\n$ERRSTR No boot disks defined in lvlnboot\n");
        $warnings++;
    }
    elsif ( "$LVBDISK" == 1 ) {
        print "\n$WARNSTR Only one boot disk defined in lvlnboot\n";
        push(@CHECKARR, "\n$WARNSTR Only one boot disk defined in lvlnboot\n");
        if ( $SANbootdisk == 0 ) {
            print "$WARNSTR Boot disk is seemingly not SAN or hardware-RAID based\n";
            push(@CHECKARR, "\n$WARNSTR Boot disk is seemingly not SAN or hardware-RAID based\n");
            print
"$NOTESTR Unless there is hardware RAID-1 or RAID-5, boot disk is not protected against single-disk failures\n";
            $warnings++;
        }
        else {
            print "$INFOSTR Boot disk is SAN or hardware-RAID based\n";
            $bings++;
        }
    }
    else {
        print "\n$PASSSTR Multiple boot disks defined in lvlnboot\n";
        if ( "$LVBOOT" > 1 ) {
            if ( $bings == 0 ) {
                print "\n$PASSSTR Boot disks on different controllers\n";
            }
        }
    }

    if ( "$LVBOOT" == 0 ) {
        print "\n$WARNSTR Boot lvol not in lvlnboot\n";
        push(@CHECKARR, "\n$WARNSTR Boot lvol not in lvlnboot\n");
        $warnings++;
    }
    elsif ( "$LVBOOT" == 1 ) {
        if ( $SANbootdisk == 0 ) {
            print "\n$WARNSTR Single boot lvol in lvlnboot\n";
            push(@CHECKARR, "\n$WARNSTR Single boot lvol in lvlnboot\n");
            print "@Boot\n";
            $warnings++;
        }
        else {
            print "\n$INFOSTR Single boot lvol in lvlnboot (possibly SAN or hardsware RAID)\n";
            print "@Boot\n";
        }
    }
    else {
        print "\n$PASSSTR Multiple boot lvols defined\n";
        print "@Boot\n";
    }

    if ( "$LVROOT" == 0 ) {
        print "\n$WARNSTR Root lvol not in lvlnboot\n";
        push(@CHECKARR, "\n$WARNSTR Root lvol not in lvlnboot\n");
        $warnings++;
    }
    elsif ( "$LVROOT" == 1 ) {
        if ( $SANbootdisk == 0 ) {
            print "\n$WARNSTR Single root lvol in lvlnboot\n";
            push(@CHECKARR, "\n$WARNSTR Single root lvol in lvlnboot\n");
            $warnings++;
            print "@Root\n";
        }
        else {
            print "\n$INFOSTR Single root lvol in lvlnboot (possibly SAN or hardsware RAID)\n";
            print "@Root\n";
        }
    }
    else {
        print "\n$PASSSTR Multiple root lvols defined\n";
        print "@Root\n";
    }

    if ( "$LVSWAP" == 0 ) {
        print "\n$WARNSTR Swap lvol not configured in lvlnboot\n";
        push(@CHECKARR, "\n$WARNSTR Swap lvol not configured in lvlnboot\n");
        $warnings++;
    }
    elsif ( "$LVSWAP" == 1 ) {
        if ( $SANbootdisk == 0 ) {
            print "\n$WARNSTR Single primary swap lvol in lvlnboot\n";
            push(@CHECKARR, "\n$WARNSTR Single primary swap lvol in lvlnboot\n");
            $warnings++;
            print "@Swap\n";
        }
        else {
            print "\n$INFOSTR Single primary swap lvol in lvlnboot (possibly SAN or hardsware RAID)\n";
            print "@Swap\n";
        }
    }
    else {
        print "\n$PASSSTR Multiple primary swap lvols defined\n";
        print "@Swap\n";
    }

    if ( "$LVDUMP" == 0 ) {
        print "\n$WARNSTR Dump lvol not defined in lvlnboot\n";
        push(@CHECKARR, "\n$WARNSTR Dump lvol not defined in lvlnboot\n");
        $warnings++;
    }
    elsif ( "$LVDUMP" == 1 ) {
        print "\n$PASSSTR Single dump lvol defined\n";
        print "@Dump\n";
    }
    else {
        print "\n$INFOSTR Multiple dump lvols defined\n";
        print "@Dump\n";
    }

    if ( "$LVSWAP" > 0 ) {
        my @union = my @intersection = my @difference = ();
        my %count = ();
        foreach $element ( @Boot, @Swap ) { $count{$element}++; }
        foreach $element ( keys %count ) {
            next if ( grep( /lvol/, $element ) );
            push @union, $element;
            push @{ $count{$element} > 1 ? \@intersection : \@difference },
              $element;
        }

        if (@difference) {
            print
"\n$WARNSTR Some boot and primary swap LVs are on different PVs (or not fully RAID-1)\n";
            push(@CHECKARR,
"\n$WARNSTR Some boot and primary swap LVs are on different PVs (or not fully RAID-1)\n");
        }
        else {
            print "\n$PASSSTR All boot and primary swap LVs are on same PVs\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING BOOT DISKS AND VOLUMES $datestring ***");
}

# Subroutine to check boot paths
#
sub lvmtabck {
    datecheck();
    print_header("*** BEGIN CHECKING LVMTAB FILES $datestring ***");

    if ( -s "$LVMTAB" ) {
        print "$PASSSTR $LVMTAB exists and not zero-length\n";
    }
    else {
        print "$ERRSTR $LVMTAB does not exist or is zero-length\n";
        push(@CHECKARR, "\n$ERRSTR $LVMTAB does not exist or is zero-length\n");
        $warnings++;
        $LVMTAB_FLAG++;
    }

    if ( "$Minor$Patch" >= 1131 ) {
        if ( -s "$LVMTABL2" ) {
            print "\n$PASSSTR $LVMTABL2 (disk layout L2) exists and not zero-length\n";
            $LVMTABL2_FLAG++;
        }
        else {
            print "\n$INFOSTR $LVMTABL2 (disk layout L2) does not exist or is zero-length\n";
        }
    }

    my @lvmtabt = `lvmadm -l 2>/dev/null`;
    if ( @lvmtabt != 0 ) {
        print "\n";
        print @lvmtabt;
    }
    
    my @lvmtabls = `strings $LVMTAB 2>/dev/null`;
    if ( @lvmtabls != 0 ) {
        print "\n$INFOSTR $LVMTAB file\n";
        print @lvmtabls;
    }

    my @lvmtabls2 = `strings $LVMTABL2 2>/dev/null`;
    if ( @lvmtabls2 != 0 ) {
        print "\n$INFOSTR $LVMTABL2 file\n";
        print @lvmtabls2;
    }

    datecheck();
    print_trailer("*** END CHECKING LVMTAB FILES $datestring ***");
}

# Subroutine to check boot paths
#
sub bootpath {
    datecheck();
    print_header("*** BEGIN CHECKING PRIMARY AND ALTERNATE BOOT PATHS $datestring ***");

    if ( "$Minor$Patch" <= 1100 ) {
        $SETBOOTARG = q{};
    }

    my @bootpath = `bootpath 2>/dev/null`;
    if ( @bootpath ) {
        print "$INFOSTR Current boot device as given by bootpath(1M)\n";
        print @bootpath;
        print "\n";
    }

    if ( open( SFROM, "setboot $SETBOOTARG 2>&1 | " ) ) {
        while (<SFROM>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            chomp;

            if ( grep( /^Primary bootpath/, $_ ) ) {
                ( undef, $priboot ) = split( /:/, $_ );
                #
                # Get rid of leading and trailing empty spaces
                #
                $priboot =~ s{\A \s* | \s* \z}{}gxm;
                if ( "$Minor$Patch" >= 1131 ) {
                    ( undef, $pribootv3 ) = split( /\s+/, $priboot );
                    $pribootv3 =~ s/\(//g ;
                    $pribootv3 =~ s/\)//g ;
                    $pribootv3 =~ s/\/rdisk\//\/disk\//g;
                    $priboot = $pribootv3;
                }
            }

            if ( grep( /^HA Alternate bootpath/, $_ ) ) {
                $HA_ALTFLAG++;
                ( undef, $HAaltboot ) = split( /:/, $_ );
                #
                # Get rid of leading and trailing empty spaces
                #
                $HAaltboot =~ s{\A \s* | \s* \z}{}gxm;
                if ( "$Minor$Patch" >= 1131 ) {
                    ( undef, $HAaltbootv3 ) = split( /\s+/, $HAaltboot );
                    $HAaltbootv3 =~ s/\(//g ;
                    $HAaltbootv3 =~ s/\)//g ;
                    $HAaltbootv3 =~ s/\/rdisk\//\/disk\//g;
                    $HAaltboot = $HAaltbootv3;
                }
            }

            if ( grep( /^Alternate bootpath/, $_ ) ) {
                ( undef, $altboot ) = split( /:/, $_ );
                #
                # Get rid of leading and trailing empty spaces
                #
                $altboot =~ s{\A \s* | \s* \z}{}gxm;
                if ( "$Minor$Patch" >= 1131 ) {
                    ( undef, $altbootv3 ) = split( /\s+/, $altboot );
                    $altbootv3 =~ s/\(//g ;
                    $altbootv3 =~ s/\)//g ;
                    $altbootv3 =~ s/\/rdisk\//\/disk\//g;
                    $altboot = $altbootv3;
                }
            }
        }
        close(SFROM);

        chomp($priboot);
        chomp($altboot);
        chomp($HAaltboot);

        print "\n";

        if ( open( UUV, "lvlnboot -v 2>/dev/null |" )) {
            while (<UUV>) {
                chomp;
                next if ( grep( /Boot Definitions|Physical Volumes|Current/, $_ ) );
                next if ( grep( /^$/, $_ ) );

                if ( grep( /Boot Disk/, $_ ) ) {
                    if ( grep( /$priboot/, $_ ) ) {
                        $ckpriboot = $_;
                    }

                    if ( grep( /$altboot/, $_ ) ) {
                        $ckaltboot = $_;
                    }

                    if ( grep( /$HAaltboot/, $_ ) ) {
                        $HAckaltboot = $_;
                    }
                }
            }
            close(UUV);
        }

        if ( "$priboot" ) {
            if ( !"$ckpriboot" ) {
                print "$ERRSTR Primary Bootpath $priboot not in bootpath\n";
                push(@CHECKARR,
"\n$ERRSTR Primary Bootpath $priboot not in bootpath\n");
                $warnings++;
            }
            else {
                print "$PASSSTR Primary Bootpath $priboot in bootpath\n";
            }
        }
        else {
            print "$WARNSTR Primary Bootpath not defined\n";
            push(@CHECKARR, "\n$WARNSTR Primary Bootpath not defined\n");
        }

        if ( $HA_ALTFLAG > 0 ) {
            if ( "$HAaltboot" ) {
                if ( !"$HAckaltboot" ) {
                    if ( $SANbootdisk == 0 ) {
                        print
"$WARNSTR HA Alternate Bootpath $HAaltboot not in bootpath\n";
                        push(@CHECKARR,
"\n$WARNSTR HA Alternate Bootpath $HAaltboot not in bootpath\n");
                        $warnings++;
                    }
                    else {
                        print
"$INFOSTR HA Alternate Bootpath $HAaltboot not in bootpath (not critical when hardware-based RAID is used)\n";
                        push(@CHECKARR,
"\n$INFOSTR HA Alternate Bootpath $HAaltboot not in bootpath (not critical when hardware-based RAID is used)\n");
                    }
                }
                elsif ( grep( /<none>/, "$HAckaltboot" ) ) {
                    if ( $SANbootdisk == 0 ) {
                        print "$WARNSTR HA Alternate Bootpath not defined\n";
                        push(@CHECKARR,
"\n$WARNSTR HA Alternate Bootpath not defined\n");
                        $warnings++;
                    }
                    else {
                        print "$INFOSTR HA Alternate Bootpath not defined (not critical when hardware-based RAID is used)\n";
                        push(@CHECKARR,
"\n$INFOSTR HA Alternate Bootpath not defined (not critical when hardware-based RAID is used)\n");
                    }
                }
                else {
                    print "$PASSSTR HA Alternate Bootpath $HAaltboot in bootpath\n";
                }
            }
            else {
                print "$WARNSTR HA Alternate Bootpath not defined\n";
                push(@CHECKARR, "\n$WARNSTR HA Alternate Bootpath not defined\n");
            }
        }
        else {
            print "$INFOSTR HA Alternate Bootpath not defined on this platform\n";
        }

        if ( "$altboot" ) {
            if ( !"$ckaltboot" ) {
                if ( grep(/LAN/, "$altboot" ) ) {
                    print
"$INFOSTR Alternate Bootpath is LAN-based\n";
                }
                else {
                    if ( $SANbootdisk == 0 ) {
                        print
"$WARNSTR Alternate Bootpath $altboot not in bootpath\n";
                        push(@CHECKARR,
"\n$WARNSTR Alternate Bootpath disk $altboot not in bootpath\n");
                        $warnings++;
                    }
                    else {
                        print
"$INFOSTR Alternate Bootpath $altboot not in bootpath (not critical when hardware-based RAID is used)\n";
                        push(@CHECKARR,
"\n$INFOSTR Alternate Bootpath disk $altboot not in bootpath (not critical when hardware-based RAID is used)\n");
                    }
                }
            }
            elsif ( grep( /<none>/, "$ckaltboot" ) ) {
                if ( $SANbootdisk == 0 ) {
                    print "$WARNSTR Alternate Bootpath disk not defined (not applicable to hardware RAID PVs)\n";
                    push(@CHECKARR, "\n$WARNSTR Alternate Bootpath disk not defined (not applicable to hardware RAID PVs)\n");
                    $warnings++;
                }
                else {
                    print "$INFOSTR Alternate Bootpath disk not defined (not critical when hardware-based RAID is used)\n";
                    push(@CHECKARR, "\n$INFOSTR Alternate Bootpath disk not defined (not critical when hardware-based RAID is used)\n");
                }
            }
            else {
                print "$PASSSTR Alternate Bootpath $altboot in bootpath\n";
            }
        }
        else {
            print "$WARNSTR Alternate Bootpath not defined\n";
            push(@CHECKARR, "\n$WARNSTR Alternate Bootpath not defined\n");
        }
    }
    else {
        print "$WARNSTR Cannot run setboot\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run setboot\n");
        $warnings++;
    }

    if ( "$priboot" eq "$altboot" ) {
        print "$WARNSTR Primary and alternate boot paths IDENTICAL\n";
        push(@CHECKARR, "\n$WARNSTR Primary and alternate boot paths IDENTICAL\n");
        $warnings++;
    }

    if ( "$Hardware" eq "ia64" ) {
        if ( "$Minor$Patch" >= 1131 ) {
            my $htcap = `getconf _SC_HT_CAPABLE 2>/dev/null`;
            my $htena = `getconf _SC_HT_ENABLED 2>/dev/null`;
            chomp($htcap);
            chomp($htena);

            if ( "$htcap" == 1 ) {
                print
"\n$INFOSTR Server firmware threading (hyperthreading) capable (\"_SC_HT_CAPABLE\" is 1)\n";
            }
            elsif ( "$htcap" == 0 ) {
                print
"\n$INFOSTR Server not firmware threading (hyperthreading) capable (\"_SC_HT_CAPABLE\" is 0)\n";
            }
            else {
                print
"\n$INFOSTR Server not firmware threading (hyperthreading) capability undefined\n";
            }

            if ( "$htena" == 1 ) {
                print
"\n$INFOSTR Server firmware threading (hyperthreading) enabled (\"_SC_HT_ENABLED\" is 1)\n";
                print
"\n$NOTESTR Integrity VM software cannot be started when hyperthreading is enabled on older versions\n";
                print
"\n$NOTESTR Use \"setboot -m off\" and reboot to enable this server as an Integrity VM host\n";
            }
            elsif ( "$htena" == 0 ) {
                print
"\n$INFOSTR Server firmware threading (hyperthreading) disabled (\"_SC_HT_ENABLED\" is 0)\n";
            }
            else {
                print
"\n$INFOSTR Server not firmware threading (hyperthreading) enablement undefined\n";
            }
        }
    }

    datecheck();
    print_trailer("*** END CHECKING PRIMARY AND ALTERNATE BOOT PATHS $datestring ***");
}

# Subroutine to check savecrash
#
sub crashcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SAVECRASH AND CRASHCONF $datestring ***");

    if ( open( FROM, "awk NF $SAVECRASH |" ) ) {
        print "$INFOSTR Configuration file $SAVECRASH\n";
        while (<FROM>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            chomp;
            if ( grep( /^SAVECRASH=/, $_ ) ) {
                ( undef, $savecrash ) = split( /=/, $_ );
            }

            if ( grep( /^FOREGRD=/, $_ ) ) {
                ( undef, $foregrd ) = split( /=/, $_ );
            }

            if ( grep( /^SAVECRASH_DIR/, $_ ) ) {
                ( undef, $savecrashdir ) = split( /=/, $_ );
            }
        }
        close(FROM);
    }
    else {
        print "$WARNSTR Cannot open $SAVECRASH\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $SAVECRASH\n");
        $warnings++;
    }

    if ( open( FROM, "awk NF $CRASHCONF |" ) ) {
        print "\n$INFOSTR Configuration file $CRASHCONF\n";
        while (<FROM>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            chomp;
            if ( grep( /^CRASHCONF_ENABLED/, $_ ) ) {
                ( undef, $crashconf ) = split( /=/, $_ );
            }
        }
        close(FROM);
    }
    else {
        print "\n$WARNSTR Cannot open $CRASHCONF\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $CRASHCONF\n");
        $warnings++;
    }

    if ( open( CC, "crashconf -v 2>/dev/null |" ) ) {
        print "\n$INFOSTR Crash configuration status\n";
        while (<CC>) {
            print $_;
            chomp;
            next if ( grep( /^$/, $_ ) );

            if ( grep( /^USTACK/, $_ ) ) {
                my @ustack = split(/\s+/, $_);
                my $USTACKON = $ustack[2];
                $USTACKON =~ s/,//g;
                chomp($USTACKON);
                if ( "$USTACKON" ne "yes" ) {
                    push(@CRASHARR, "\n$WARNSTR USTACK class is not included in the minimal dump config\n");
                    push(@CHECKARR, "\n$WARNSTR USTACK class is not included in the minimal dump config\n");
                    $warnings++;
                }
                else {
                    push(@CRASHARR, "\n$PASSSTR USTACK class is included in the minimal dump config\n");
                }
            }

            if ( grep( /^FSDATA/, $_ ) ) {
                my @fsdata = split(/\s+/, $_);
                my $FSDATAON = $fsdata[2];
                $FSDATAON =~ s/,//g;
                chomp($FSDATAON);
                if ( "$FSDATAON" ne "yes" ) {
                    push(@CRASHARR, "\n$WARNSTR FSDATA class is not included in the minimal dump config\n");
                    push(@CHECKARR, "\n$WARNSTR FSDATA class is not included in the minimal dump config\n");
                    $warnings++;
                }
                else {
                    push(@CRASHARR, "\n$PASSSTR FSDATA class is included in the minimal dump config\n");
                }
            }

            if ( grep( /^KDDATA/, $_ ) ) {
                my @kddata = split(/\s+/, $_);
                my $KDDATAON = $kddata[2];
                $KDDATAON =~ s/,//g;
                chomp($KDDATAON);
                if ( "$KDDATAON" ne "yes" ) {
                    push(@CRASHARR, "\n$WARNSTR KDDATA class is not included in the minimal dump config\n");
                    push(@CHECKARR, "\n$WARNSTR KDDATA class is not included in the minimal dump config\n");
                    $warnings++;
                }
                else {
                    push(@CRASHARR, "\n$PASSSTR KDDATA class is included in the minimal dump config\n");
                }
            }

            if ( grep( /^KSDATA/, $_ ) ) {
                my @ksdata = split(/\s+/, $_);
                my $KSDATAON = $ksdata[2];
                $KSDATAON =~ s/,//g;
                chomp($KSDATAON);
                if ( "$KSDATAON" ne "yes" ) {
                    push(@CRASHARR, "\n$WARNSTR KSDATA class is not included in the minimal dump config\n");
                    push(@CHECKARR, "\n$WARNSTR KSDATA class is not included in the minimal dump config\n");
                    $warnings++;
                }
                else {
                    push(@CRASHARR, "\n$PASSSTR KSDATA class is included in the minimal dump config\n");
                }
            }

            if ( grep( /^Total pages on system/, $_ ) ) {
                $_ =~ s/^Total pages on system:\s+//g;
                $TOTAL_PAGES = $_;
            }

            if ( grep( /^Total pages included in dump/, $_ ) ) {
                $_ =~ s/^Total pages included in dump:\s+//g;
                $TOTAL_DUMP_PAGES = $_;
            }

            if ( grep( /^Dump compressed:/, $_ ) ) {
                $_ =~ s/^Dump compressed:\s+//g;
                $DUMPCOMPRESS = $_;
            }

            if ( grep( /offline/, $_ ) ) {
                push(@CRASHARR, "$WARNSTR Offline device\n");
                push(@CRASHARR, "$_\n");
                push(@CHECKARR, "\n$WARNSTR Offline device\n");
                push(@CHECKARR, "$_\n");
                $warnings++;
            }

            $_ =~ s/^\s+//g;
            $_ =~ s/\s+$//g;

            next if ( grep(/^Use crashconf/, $_ ) ) ;
            next if ( grep(/^Dump device configuration mode/, $_ ) ) ;

            my @dumparr = split(/\s+/, $_);
            my $dumpz = @dumparr;

            if ( ($dumpz > 1) && grep(/\/dev/, $_) ) {
                $DUMPNO++;
            } 

            # if ( $_ =~ /^[0-9]+$/ ) {
            #
            if ( $dumpz == 1 ) {
                if ( $_ =~ /^\d+$/ ) {
                    $dumpmem = int($_ / 1024);
                }
            }
        }
        close(CC);

        printf "\n$INFOSTR Server has %s dump device%s\n", $DUMPNO, $dumpmatch,
        $dumpmatch == 1 ? "" : "s";

        if ( "$DUMPCOMPRESS" eq "ON" ) {
            if ( "$DUMPNO" > 0 ) {
                 $DUMPCALC = $PARDUMPCPU * $DUMPNO;
            }
            else {
                 $DUMPCALC = $PARDUMPCPU;
            }

            if ( "$PROCNO" >= $DUMPCALC ) {
                print "\n$INFOSTR Compressed dump enabled\n";
                printf
"$INFOSTR Server has %s CPU%s and satisfies rule of minimum %s CPUs per dump unit\n", $PROCNO, $PROCNO == 1 ? "" : "s", $PARDUMPCPU;
            }
            else {
                print "\n$INFOSTR Compressed dump enabled but not possible\n";
                printf
"$INFOSTR Server has %s CPU%s and does not satisfy rule of minimum %s CPUs per dump unit\n", $PROCNO, $PROCNO == 1 ? "" : "s", $PARDUMPCPU;
            }
        }

        if ( "$Minor$Patch" >= 1131 ) {
            if ( open( CCONF, "crashconf -l 2>/dev/null |" )) {
                print "\n$INFOSTR Crashconf with LUN paths\n";
                while (<CCONF>) {
                    print $_;
                    chomp($_);
                    if ( grep( /dev/, $_ ) ) {
                        my @ccarr = split( /\s+/, $_ );
                        my $DDEV = $ccarr[$#ccarr];
                        my @dfinal = split(/\./, $DDEV);
                        my $ddriver = `ioscan -fk | grep "$dfinal[0] " | awk '{print \$4}'`;
                        chomp($ddriver);
                        if ("$ddriver") {
                            push(@MYDMPARR,
                            "\n$INFOSTR External Bus $dfinal[0] is $ddriver with capability $DUMPARRAY{$ddriver}\n");
                        }
                    }
                }
            }
            close(CCONF);
        }

        if ( @CRASHARR ) {
            print @CRASHARR;
        }

        if ( @MYDMPARR ) {
            print @MYDMPARR;
        }

        print "\n$INFOSTR Total dump size is $dumpmem MB\n";

        if ( $dumpmem < int((3 * $MEM_MBYTE) / 4)) {
            print
"\n$WARNSTR Total dump size is less than 3/4 of RAM (Memory=$MEM_MBYTE MB, Dump=$dumpmem MB)\n";
            print "$INFOSTR Full dump might not be possible\n";
            print "$INFOSTR Ideally, total dump size should match RAM\n";
            push(@CHECKARR,
"\n$WARNSTR Total dump size is less than 3/4 of RAM (Memory=$MEM_MBYTE MB, Dump=$dumpmem MB)\n");
            $warnings++;
        }
        else {
            if ( $dumpmem >= $MEM_MBYTE ) {
                print
"\n$PASSSTR Dump space sufficient (Memory=$MEM_MBYTE MB, Dump=$dumpmem MB)\n";
                print "$INFOSTR Full dump possible\n";
            }
        }

        if ( $savecrash == 1 ) {
            if ("$savecrashdir") {
                print "\n$PASSSTR Savecrash enabled and saved in $savecrashdir\n";
            }
            else {
                print
"\n$WARNSTR Savecrash enabled but SAVECRASH_DIR undefined (using default $savecrashdef)\n";
                push(@CHECKARR,
"\n$WARNSTR Savecrash enabled but SAVECRASH_DIR undefined (using default $savecrashdef)\n");
                $savecrashdir = $savecrashdef;
            }
        }
        else {
            print "\n$NOTESTR Savecrash not enabled\n";
        }

        if ( -d "$savecrashdir" ) {
            my $sdirsize = `bdf $savecrashdir | awk '! /^Filesystem/ {print \$2 / 1024}'`;
            chomp($sdirsize);
            if ( int($sdirsize) < int((3 * $MEM_MBYTE) / 4)) {
                print "\n$WARNSTR $savecrashdir size is less than 3/4 of RAM\n";
                print "$INFOSTR Full crash dump might not be possible\n";
                print "$INFOSTR Ideally, $savecrashdir size should match RAM\n";
                push(@CHECKARR,
"\n$WARNSTR $savecrashdir size is less than 3/4 of RAM\n");
                $warnings++;
            }
            else {
                if ( int($sdirsize) >= $MEM_MBYTE ) {
                    print
"\n$PASSSTR $savecrashdir size is sufficient for crash dump\n";
                }
            }

            my @llsdir = `ll $savecrashdir | egrep -v "total 0" 2>/dev/null`;
            if ( @llsdir ) {
                print "\n$INFOSTR $savecrashdir directory not empty\n";
                print "@llsdir";
            }
            else {
                print "\n$INFOSTR $savecrashdir directory is empty\n";
            }
        }
        else {
            print "\n$WARNSTR $savecrashdir does not exist\n";
            push(@CHECKARR, "\n$WARNSTR $savecrashdir does not exist\n");
            $warnings++;
        }
    }
    else {
        print "\n$WARNSTR Cannot run crashconf\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run crashconf\n");
        $warnings++;
    }

    if ( $crashconf == 1 ) {
        print "\n$PASSSTR Crashconf enabled\n";
    }
    else {
        print "\n$WARNSTR Crashconf not enabled\n";
        push(@CHECKARR, "\n$WARNSTR Crashconf not enabled\n");
        $warnings++;
    }

    if ( $foregrd == 1 ) {
        print "\n$INFOSTR Savecrash runs as foreground process\n";
    }

    if ( $foregrd == 0 ) {
        print "\n$PASSSTR Savecrash runs as background process\n";
    }

    if ( $TOTAL_DUMP_PAGES == $TOTAL_PAGES ) {
        print "\n$PASSSTR Full crash dump specified ";
        print
          "(Total Dump = $TOTAL_DUMP_PAGES, Total Pages = $TOTAL_PAGES)\n";
    }
    else {
        print "\n$INFOSTR Full crash dump not specified ";
        print "(Only $TOTAL_DUMP_PAGES out of $TOTAL_PAGES pages)\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SAVECRASH AND CRASHCONF $datestring ***");
}

# Subroutine to check file system free disk space and inodes
#
sub space {
    datecheck();
    print_header("*** BEGIN CHECKING FILE SYSTEMS SPACE AND INODES MINIMUM 10% FREE $datestring ***");

    if ("$MEM_MBYTE") {
        if ( "$Minor$Patch" >= 1120 ) {
            $fs_crash = int( $MEM_MBYTE / 4 );
        }
        else {
            $fs_crash = int( $MEM_MBYTE / 2 );
        }
    }

    # Associative array of minimum file system sizing in MBytes
    # (as set in the CMSG HP-UX WorldWide Standard for HP-UX 11.11)
    #
    if ( "$Minor$Patch" >= 1131 ) {
        %OSARRAY2 = (
            "/",                       "1024",
            "/stand",                  "2048",
            "/tmp",                    "512",
            "/home",                   "256",
            "/usr",                    "5008",
            "/var",                    "8704",
            "/var/opt/perf",           "256",
            "/var/opt/OV",             "600",
            "/var/tmp",                "512",
            "/var/adm/crash",          "$fs_crash",
            "/opt",                    "6144",
        );
    }
    elsif ( "$Minor$Patch" >= 1120 ) {
        %OSARRAY2 = (
            "/",                       "1024",
            "/stand",                  "400",
            "/tmp",                    "1024",
            "/home",                   "512",
            "/usr",                    "2048",
            "/var",                    "1024",
            "/var/tmp",                "400",
            "/var/opt/perf",           "1024",
            "/var/opt/OV",             "600",
            "/var/adm/crash",          "4096",
            "/opt",                    "1500",
        );
    }
    else {
        %OSARRAY2 = (
            "/",                       "512",
            "/stand",                  "512",
            "/tmp",                    "1024",
            "/home",                   "512",
            "/usr",                    "1200",
            "/var",                    "1024",
            "/var/tmp",                "512",
            "/var/opt/perf",           "1024",
            "/var/opt/OV",             "600",
            "/var/adm/crash",          "4096",
            "/opt",                    "1500",
        );
    }

    #
    # Which standard to use?
    #
    if ( "$opts{w}" == 1 ) {
        %OSARRAY     = %OSARRAY2;
        $OS_Standard = "CMSG HP-UX WW Build Standard";
    }
    else {
        %OSARRAY = %OSARRAY1;

        # If OpenView used for monitoring, append the hash
        # with OVO file systems
        #
        if ( "$opts{o}" == 1 ) {
            for my $what (keys %OVOARRAY) {
                $OSARRAY1{$what} = $OVOARRAY{$what};
            }
        }
    }

    my @FSinfo = `fslist -p 2>/dev/null`;
    if ( @FSinfo ) {
        print "\n$INFOSTR Fslist\n";
        print @FSinfo;
        print "\n";
    }

    if ( $BDF_FLAG > 0 ) {
        # If there is a seemingly hung bdf(1M) in ps(1M),
        # maybe some NFS problem is causing it.
        # So, try to use special flags for bdf(1)
        # "-sl" to not sync, and list local file systems only.
        #
        $BDFARGS = "-sl";
    }

    if ( open( CC, "bdf -i $BDFARGS 2>/dev/null |" )) {
        while (<CC>) {
            push(@BDFARR, $_);
            chomp;
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /Mounted on/, $_ ) );
            my @ckarr = split( /\s+/, $_ );
            my $zzz = scalar @ckarr;
            next if ( $zzz == 1 );
            if ( $zzz == 9 ) {
                ( $fs,          $allocated,   $used,
                  $avail,       $pcused,      $inodeused,
                  $inodefree,   $inodepcused, $ffs,
                ) = split( /\s+/, $_ );
            }
            else {
                ( $allocated,   $used,        $avail,
                  $pcused,      $inodeused,   $inodefree,
                  $inodepcused, $ffs,
                ) = split( /\s+/, $_ );
            }

            push( @MAU, $ffs );

            if ( "$ffs" eq "/stand" ) {
                $STAND_FLAG++;
            }

            # Check each file system for lost+found
            #

            next if (grep( /^\/dev\/deviceFileSystem/, $ffs ) );

            if ( !-d "$ffs/$lfdir" ) {
                push(@FSLF, $ffs);
                push(@FSARR,
"$WARNSTR File system missing or corrupt $ffs/$lfdir\n");
                push(@CHECKARR,
"\n$WARNSTR File system missing or corrupt $ffs/$lfdir\n");
                $warnings++;
            }
            else {
                push(@FSARR, "$PASSSTR File system has valid $ffs/$lfdir\n");

                my @listlost = `ls -Als $ffs/$lfdir | grep -vi "total 0"`;
                if ( @listlost ) {
                    push(@FSARR, "$INFOSTR $ffs/$lfdir is not zero-length\n");
                    push(@FSARR, @listlost);
                }
                else {
                    push(@FSARR, "$PASSSTR $ffs/$lfdir is zero-length\n");
                }
            }

            if ( $OSARRAY{$ffs} ) {
                my $deffs_size = $OSARRAY{$ffs};
                my $allocMB = int( $allocated / 1024 );
                my $allocGB = int( $allocMB / 1024 );
                if ( "$allocMB" < "$deffs_size" ) {
                    push(@FSARR, "$WARNSTR F/S size for $ffs is less than ");
                    push(@FSARR, "recommended in $OS_Standard ");
                    push(@FSARR, "($allocMB MB while minimum is $deffs_size MB)\n");
                    push(@CHECKARR, "\n$WARNSTR F/S size for $ffs is less than ");
                    push(@CHECKARR, "recommended in $OS_Standard ");
                    push(@CHECKARR,
"($allocMB MB while minimum is $deffs_size MB)\n");
                    $warnings++;
                }
                elsif ( "$allocGB" >= "@{[MAXFSSIZE]}" ) {
                    push(@FSARR, "$INFOSTR F/S size for $ffs is larger than ");
                    push(@FSARR, "recommended for efficient tape backups ");
                    push(@FSARR,
"($allocGB GB while maximum is @{[MAXFSSIZE]} GB)\n");
                }
                else {
                    push(@FSARR, "$PASSSTR F/S size for $ffs as ");
                    push(@FSARR, "recommended in $OS_Standard ");
                    push(@FSARR, "($allocMB MB while minimum is $deffs_size MB)\n");
                }
            }
            else {
                my $allocMB = int( $allocated / 1024 );
                my $allocGB = int( $allocMB / 1024 );
                if ( "$allocGB" >= "@{[MAXFSSIZE]}" ) {
                    push(@FSARR, "$WARNSTR F/S size for $ffs is larger than ");
                    push(@FSARR, "recommended for efficient tape backups ");
                    push(@FSARR,
"($allocGB GB while maximum is @{[MAXFSSIZE]} GB)\n");
                    push(@CHECKARR, "\n$WARNSTR F/S size for $ffs is larger than ");
                    push(@CHECKARR, "recommended for efficient tape backups ");
                    push(@CHECKARR,
"($allocGB GB while maximum is @{[MAXFSSIZE]} GB)\n");
                }
            }

            $pcused      =~ s/%//g;
            $inodepcused =~ s/%//g;
            if ( $pcused > $THRESHOLD ) {
                push(@FSARR, "$WARNSTR File system $ffs has less than $mingood% ");
                push(@FSARR, "free disk space ($pcused% used)\n");
                push(@CHECKARR,
"\n$WARNSTR File system $ffs has less than $mingood% ");
                push(@CHECKARR, "free disk space ($pcused% used)\n");
                $warnings++;
            }
            else {
                push(@FSARR, "$PASSSTR File system $ffs has more than $mingood% ");
                push(@FSARR, "free disk space ($pcused% used)\n");
            }

            if ( $inodepcused > $THRESHOLD ) {
                push(@FSARR, "$INFOSTR File system $ffs has less than $mingood% ");
                push(@FSARR, "free inodes ($inodepcused% used)\n");
                 push(@FSARR, "$NOTESTR Not critical for VxFS since inodes get allocated as needed\n\n");
            }
            else {
                push(@FSARR, "$INFOSTR File system $ffs has more than $mingood% ");
                push(@FSARR, "free inodes ($inodepcused% used)\n");
                 push(@FSARR, "$NOTESTR Not critical for VxFS since inodes get allocated as needed\n\n");
            }

            if ( "$Minor$Patch" >= 1123 ) {
                $LIFtemp = 32;
            }

            if ( "$ffs" eq "/var/tmp" ) {
                my $availMB = int( $avail / 1024 );
                if ( "$availMB" < "$LIFtemp" ) {
                    push(@FSARR,
"\n$WARNSTR F/S $ffs has less than $LIFtemp MB free ");
                    push(@FSARR,
"($availMB MB) - more is needed for temporary make_tape_recovery LIF volume assembly)\n\n");
                    push(@CHECKARR,
"\n$WARNSTR F/S $ffs has less than $LIFtemp MB free ");
                    push(@CHECKARR,
"($availMB MB) - more is needed for temporary make_tape_recovery LIF volume assembly)\n");
                    $VARTMP_FLAG++;
                }
                else {
                    push(@FSARR,
"$PASSSTR F/S $ffs has more than $LIFtemp MB free ");
                    push(@FSARR,
"($availMB MB) - needed for temporary make_tape_recovery LIF volume assembly)\n\n");
                }
            }
        }
        close(CC);
    }
    else {
        print "\n$WARNSTR Cannot run bdf\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run bdf\n");
        $warnings++;
    }

    if ( @BDFARR ) {
        print @BDFARR;
        print "\n";
    }

    if ( @FSARR ) {
        print @FSARR;
    }

    datecheck();
    print_trailer("*** END CHECKING FILE SYSTEMS SPACE AND INODES MINIMUM 10% FREE $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING FILE SYSTEMS NAMING STRUCTURE AS PER STANDARDS $datestring ***");

    @VVM = keys(%OSARRAY);
    if ( @VVM != 0 ) {
        foreach $i ( sort @VVM ) {
            if ( !( grep( /^$i$/, @MAU ) ) ) {
                print
"$WARNSTR File system $i does not exist as per $OS_Standard\n";
                push(@CHECKARR,
"\n$WARNSTR File system $i does not exist as per $OS_Standard\n");
                $MISSING_FS_FLAG++;
                $warnings++;
            }
        }
    }

    if ( $MISSING_FS_FLAG == 0 ) {
        print "$PASSSTR All O/S file system defined as per $OS_Standard\n";
    }

    datecheck();
    print_trailer("*** END CHECKING FILE SYSTEMS NAMING STRUCTURE AS PER STANDARDS $datestring ***");
}

# Subroutine to check LAN cards
#
sub lan {
    datecheck();
    print_header("*** BEGIN CHECKING LAN CARD STATUS $datestring ***");

    if ( open( CC, "lanscan 2>/dev/null |" ) ) {
        while (<CC>) {
            $alldet = q{};
            next if ( grep( /^$/,       $_ ) );
            next if ( grep( /Hardware/, $_ ) );
            next if ( grep( /Address/,  $_ ) );
            push( @Alllanscan, "$_" );
            chomp;
            if ( grep( /^LinkAgg/, $_ ) ) {
                push( @APA, "$_\n" );
                if ( grep( /UP/, $_ ) ) {
                    $apacount++;
                }
            }
            else {
                $lancardno++;
            }

            (
                $LanHW, $LanSA,   $Crd,     $State, $Netif,
                $PPA,   my $NMid, $Mactype, undef
            ) = split( /\s+/, $_ );

            if ( (! grep(/:/, $Netif)) && ("$State" eq "UP") ) {
                my @IPv4up = `ifconfig $Netif 2>/dev/null`;
                my @IPv6up = `ifconfig $Netif inet6 2>/dev/null`;
                if ( @IPv4up || @IPv6up ) {
                    $reallancardno++;
                }
            }

            if ( open( IFCONF, "ifconfig $Netif 2>/dev/null |" ) ) {
                while (<IFCONF>) {
                    print $_;
                    if ( grep(/netmask/, $_ ) ) {
                        $_ =~ s/^\s+//g;
                        $_ =~ s/\s+$//g;
                        @NETARR = split( /\s+/, $_ );
                        $LANIP = $NETARR[1];
                        $LANMASK = $NETARR[3];
                        $LANBROAD = $NETARR[5];

                        if (! grep(/^[0-9A-Fa-f]{1,8}$/, $LANMASK) ) {
                            push(@CHECKARR,
"\n$ERRSTR: Invalid IPv4 subnet mask $LANMASK for interface $Netif\n");
                            push(@IPSUMARR,
"\n$ERRSTR: Invalid IPv4 subnet mask $LANMASK for interface $Netif\n");
                            $warnings++;
                        }

                        $REALMASK = join ('.', unpack ('C4', pack ('H8', substr ("0" x 8 . $LANMASK, -8))));
                        $IPaddr2 = inet_aton($LANIP);
                        $IPmask = inet_aton($REALMASK);
                        $IPsubnet = unpack("L", $IPaddr2) & unpack("L", $IPmask);
                        $NETCALC = inet_ntoa(pack("L", $IPsubnet));
                        push(@IPSUMARR,
"\n$INFOSTR LAN interface $LANIP: IPv4 subnet mask $REALMASK (0x${LANMASK}), IPv4 network $NETCALC\n");
                        $balanceIP{$LANIP} = $REALMASK;

                        if ( ! grep(/\Q$NETCALC\E/, @IPV4NET)) {
                            push(@IPV4NET, $NETCALC);
                        } else {
                            $IPV4count++;
                            push(@IPSUMARR,
"\n$INFOSTR Multiple LAN interfaces on IPv4 network $NETCALC\n");
                        }
                    }
                }
                close(IFCONF);
            }

            if ( open( IFCONF6, "ifconfig $Netif inet6 2>/dev/null |" ) ) {
                while (<IFCONF6>) {
                    print $_;
                    if ( grep(/inet6/, $_ ) ) {
                        @NETARR = split( /\s+/, $_ );
                        $LANIP = $NETARR[1];
                        $LANMASK = $NETARR[3];

                        push(@IPSUMARR,
"\n$INFOSTR LAN interface $LANIP: IPv6 subnet mask/prefix ${LANMASK}\n");

                        # if ( "$ModuleValid" ) {
                        #     my $quad = "$LANIP/$LANMASK";
                        #     my $addr2 = NetAddr::IP -> new6 ($quad);
                        #     if ( defined($addr2) ) {
                        #         push(@IPSUMARR, "\n$INFOSTR IPv6 address is ", $addr2->addr, " with mask ", $addr2->mask, "\n");
                        #     }
                        #     else {
                        #         push(@IPSUMARR, "\n$ERRSTR Invalid IPv6 address $quad for interface $Netif\n");
                        #         push(@CHECKARR, "\n$ERRSTR Invalid IPv6 address $quad for interface $Netif\n");
                        #        $warnings++;
                        #     }
                        # }
                    }
                }
                close(IFCONF6);
            }

            if ( grep(/^LinkAgg/, $_ ) ) {
                @APAst = `lanadmin -x -v $PPA 2>/dev/null`;
                if ( @APAst ) {
                    push(@ALLAPAARR, @APAst);
                }

                if ( "$Minor$Patch" >= 1131 ) {
                    @APAmon = `nwmgr --stats monitor -q counter=p -q value=d -I $PPA -S apa 2>/dev/null`;
                    if ( @APAmon ) {
                        push(@ALLAPAARR2, @APAmon);
                    }
                }
            }

            if ( open( ZZ, "lanadmin -x $Crd 2>/dev/null |" ) ) {
                while (<ZZ>) {
                    $Active = q{};
                    chomp;
                    $VV = $_;
                    next if ( grep( /^$/,      $VV ) );
                    next if ( grep( /down/i,   $VV ) );
                    next if ( grep( /NO LINK/, $VV ) );

                    @Lanlinkloop = `linkloop -i $Crd $LanSA 2>/dev/null`;
                    @Lanshow = `lanshow -i $PPA 2>/dev/null | awk NF`;

                    # Get rid of leading and trailing empty spaces
                    #
                    $VV =~ s/^\s+//g;
                    $VV =~ s/\s+$//g;
                    if ( "$Minor$Patch" > 1100 ) {
                        $Active =
                          `lanadmin -p $Crd 2>/dev/null |grep ifconfig`;
                        if ("$Active") {
                            if ( grep( /^Current config|^Current Config|^Current Speed|^Speed/, $VV ) ) {
                                my $ap2 = my $ap3 = q{};
                                ( undef, $alldet ) = split( /=/, $VV );
                                chomp($alldet);
                                $alldet =~ s/\.$//g;
                                #
                                # Get rid of leading and trailing empty spaces
                                #
                                $alldet =~ s/^\s+//g;
                                $alldet =~ s/\s+$//g;
                                ( $ap2, $ap3 ) =
                                  split( /\s+/, $alldet );
                                $alldet = "$ap2 Mbps $ap3";
                            }

                            if ( grep( /^Autonegotiation/, $VV ) ) {
                                ( undef, $Auto ) = split( /=/, $VV );
                                chomp($Auto);
                                $Auto =~ s/\.$//g;
                                #
                                # Get rid of leading and trailing empty spaces
                                #
                                $Auto =~ s{\A \s* | \s* \z}{}gxm;
                            }

                            if ("$Auto") {
                                $smtrw = "autonegotiation $Auto";
                            }
                            else {
                                $smtrw = q{};
                            }
                        }
                        else {
                            if ( grep( /^Current Config|^Current Config|^Speed|^Current Speed/, $VV ) ) {
                                ( undef, $alldet ) = split( /=/, $VV );
                                chomp($alldet);
                                $alldet =~ s/\.$//g;
                                #
                                # Get rid of leading and trailing empty spaces
                                #
                                $alldet =~ s/^\s+//g;
                                $alldet =~ s/\s+$//g;
                            }
                        }
                    }
                    else {
                        if ( grep( /^Current Speed|^Current Config|^Speed/, $VV ) ) {
                            ( undef, $smtrw ) = split( /=/, $VV );
                            #
                            # Get rid of leading and trailing empty spaces
                            #
                            $smtrw =~ s/^\s+//g;
                            $smtrw =~ s/\s+$//g;
                            chomp($smtrw);
                        }

                        if ( grep( /^Autonegotiation/, $VV ) ) {
                            my $autonn = q{};
                            ( undef, $autonn ) = split( /=/, $VV );
                            #
                            # Get rid of leading and trailing empty spaces
                            #
                            $autonn =~ s/^\s+//g;
                            $autonn =~ s/\s+$//g;
                            $autonn =~ s/\.$//g;
                            chomp($autonn);
                            $smtrw = "$smtrw autonegotiation $autonn";
                        }
                    }
                }
                close(ZZ);

                if ("$alldet") {
                    push(@Alllanscan2,
"\n$INFOSTR PPA $Crd set at $alldet $smtrw\n");
                }
                elsif ("$smtrw") {
                    push(@Alllanscan2, "\n$INFOSTR PPA $Crd set at $smtrw\n");
                }
                else {
                    push(@Alllanscan2, "\n$INFOSTR PPA $Crd installed\n");
                }

                if (@Lanlinkloop) {
                    push(@Alllanscan2,
"$INFOSTR Linkloop test for $LanSA via PPA $Crd\n");
                    push(@Alllanscan2, @Lanlinkloop);
                }
            }
            else {
                push( @Alllanscan2, "\n$WARNSTR Cannot run lanadmin on PPA $Crd\n");
                push(@CHECKARR, "\n$WARNSTR Cannot run lanadmin on PPA $Crd\n");
                $warnings++;
            }
        }
        close(CC);
    }
    else {
        print "$WARNSTR Cannot run lanscan\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run lanscan\n");
        $warnings++;
    }

    if ( @IPSUMARR != 0 ) {
        print @IPSUMARR;
    }

    if ( ($IPV4count > 0) && ( $apacount == 0) ) {
        print
"\n$WARNSTR Multiple LAN interfaces on IPv4 network $NETCALC but Auto Port Aggregation not used\n";
        print "$INFOSTR Verify if it is correct to use them\n";
        push(@CHECKARR,
"\n$WARNSTR Multiple LAN interfaces on IPv4 network $NETCALC but Auto Port Aggregation not used\n");
    }
    else {
        print "\n$PASSSTR No multiple LAN interfaces on same IPv4 networks\n";
        print "$NOTESTR Auto Port Aggregation does not apply to this rule\n";
    }

    if ( @Alllanscan != 0 ) {
        print "\n$INFOSTR LAN card status\n";
        print @Alllanscan;
        print "\n";
        print @Alllanscan2;
    }

    if ( @Lanshow != 0 ) {
        print "\n$INFOSTR LANshow status\n";
        print @Lanshow;
    }

    my @APAinfo = `apa_get_info -l 2>/dev/null`;
    if ( @APAinfo != 0 ) {
        print "\n$INFOSTR Auto Port Aggregation apa_get_info status\n";
        print @APAinfo;
        print "\n";
    }

    my @APAinfop = `apa_get_info -p 2>/dev/null`;
    if ( @APAinfop != 0 ) {
        print "\n$INFOSTR Parameters for network ports that support APA Link Aggregates\n";
        print @APAinfop;
        print "\n";
    }

    if ( $apacount > 0 ) {
        print "\n$INFOSTR Auto Port Aggregation seemingly running\n";
        print @APA;

        if ( @ALLAPAARR ) {
            print @ALLAPAARR;
        }

        my @lancheckconf = `lancheckconf 2>/dev/null`;
        if ( @lancheckconf != 0 ) {
            print "\n$INFOSTR Auto Port Aggregation config check\n";
            print @lancheckconf;
        }

        my @lanqueryconf = `lanqueryconf -s -v 2>&1`;
        if ( @lanqueryconf != 0 ) {
            print "\n$INFOSTR Auto Port Aggregation config query\n";
            print @lanqueryconf;
        }

        if ( -s "$APAconf" ) {
            print "\n$INFOSTR $APAconf exists\n";
            if ( open( APC, "awk '! /^#/ && ! /awk/ {print}' $APAconf |" ) ) {
                while (<APC>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(APC);
            }
            else {
                print "\n$WARNSTR Cannot open $APAconf\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open $APAconf\n");
            }
        }
        else {
            print "\n$INFOSTR $APAconf does not exists\n";
        }

        if ( -s "$APAport" ) {
            print "\n$INFOSTR $APAport exists\n";
            if ( open( APP, "awk '! /^#/ && ! /awk/ {print}' $APAport |" ) ) {
                while (<APP>) {
                    next if ( grep( /^$/, $_ ) );
                    if ( grep( /^HP_APAPORT_INTERFACE_NAME/, $_ ) ) {
                        $reallancardno++;
                    } 
                    print $_;
                }
                close(APP);
            }
            else {
                print "\n$WARNSTR Cannot open $APAport\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open $APAport\n");
            }
        }
        else {
            print "\n$INFOSTR $APAport does not exists\n";
        }

        if ( -s "$APAasc" ) {
            print "\n$INFOSTR $APAasc exists\n";
            if ( open( AAPP, "awk '! /^#/ && ! /awk/ {print}' $APAasc |" ) ) {
                while (<AAPP>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(AAPP);
            }
            else {
                print "\n$WARNSTR Cannot open $APAasc\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open $APAasc\n");
            }
        }
        else {
            print "\n$INFOSTR $APAasc does not exists\n";
        }

        if ( "$Minor$Patch" >= 1131 ) {
            my @nwmgr = `nwmgr -S apa 2>/dev/null`;
            if ( @nwmgr ) {
                print "\n$INFOSTR nwmgr APA status\n";
                print @nwmgr;
            }

            if ( @ALLAPAARR2 ) {
                print @ALLAPAARR2;
            }
        }
    }
    else {
        print "\n$INFOSTR Auto Port Aggregation not running\n";
    }

    my @linkinfo = `linkinfo all 2>/dev/null`;
    if ( "@linkinfo" ) {
        print "\n$INFOSTR Linkinfo status\n";
        print @linkinfo;
    }

    my @xportshow = `xportshow -f 2>/dev/null`;
    if ( "@xportshow" ) {
        print "\n$INFOSTR Xportshow status\n";
        print @xportshow;
    }

    my $nettlog = "/var/adm/nettl.LOG000";
    if ( -s "$nettlog" ) {
        my @netlog = `netfmt $nettlog 2>/dev/null | awk NF`;
        if ( @netlog ) {
            print "\n$INFOSTR Netfmt binary trace and log data gathered from $nettlog\n";
            print @netlog;
        }
    }

    if ( $reallancardno < 2 ) {
        print "\n$WARNSTR Only one LAN interface configured\n";
        push(@CHECKARR, "\n$WARNSTR Only one LAN interface configured\n");
        $warnings++;
    }
    else {
        if ( $reallancardno == 0 )  {
            print "\n$WARNSTR Seemingly $reallancardno LAN interfaces configured\n";
            push(@CHECKARR,
"\n$WARNSTR Seemingly $reallancardno LAN interfaces configured\n");
            print "$INFOSTR Check if some corruption is creating false results\n";
            $reallancardno = $apacount;
        }
    }

    if ( "$reallancardno" > 0 ) {
        printf "\n$INFOSTR There %s %s active physical LAN%s in ioscan\n",
        $reallancardno == 1 ? "is" : "are", $reallancardno, $reallancardno == 1 ? "" : "s";
    }
    
    if ( "$lancardno" > 0 ) {
        printf
"\n$INFOSTR There %s total of %s physical LAN%s in ioscan (excluding APA)\n",
        $lancardno == 1 ? "is" : "are", $lancardno, $lancardno == 1 ? "" : "s";
    }

    datecheck();
    print_trailer("*** END CHECKING LAN CARD STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING VLAN STATUS $datestring ***");

    my @VLANarray = `lanadmin -V scan 2>/dev/null`;
    my @VLANppa = `lanadmin -V basevppa 2>/dev/null`;

    if ( @VLANarray ) {
        print @VLANarray;
        print @VLANppa;

        my @vlanstart = `grep -v ^# $VLANCONF 2>/dev/null | awk NF`; 
        if ( @vlanstart ) {
            print "\n$INFOSTR $VLANCONF exists\n";
            print @vlanstart;
        }
    }
    else {
        print "$INFOSTR VLANs not configured\n";
    }

    datecheck();
    print_trailer("*** END CHECKING VLAN STATUS $datestring ***");
}

# Subroutine to check shutdown and boot logs
#
sub start_shutdown_log {
    datecheck();
    print_header("*** BEGIN CHECKING LOG FILES FOR STARTUP/SHUTDOWN ERRORS $datestring ***");

    if ( -s "$Shutlog" ) {
        my @shutlogarr = `strings $Shutlog | awk NF`;
        if ( @shutlogarr ) {
            print "$INFOSTR File $Shutlog\n";
            print @shutlogarr;
            if ( grep(/panic/i, @shutlogarr) ) {
                push( @Panarray, $_ );
                $panic++;
            }
        }
    }
    else {
        print "$INFOSTR $Shutlog is zero-length or does not exist\n";
    }

    if ( $panic > 0 ) {
        print "\n$WARNSTR $Shutlog not clear of system panics (check those events)\n";
        push(@CHECKARR, "\n$WARNSTR $Shutlog not clear of system panics (check those events\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR $Shutlog clear of system panics\n";
    }

    my @BOOTARRAY = ();
    if ( -s "$Rclog" ) {
       if ( open( RCLOG, "awk NF $Rclog |" ) ) {
           my $SPECFLG = 0;
           print "\n$INFOSTR File $Rclog\n";
           while (<RCLOG>) {
               print $_;
               if ( grep(/^WARNING:|ERROR:|FAILED/, $_) ) {
                  push( @PPanarray, $_ );
                  $ppanic++;
               }

               if ( grep(/HP-UX Start-up in progress/, $_) ) {
                  push( @BOOTARRAY, $_ );
                  $SPECFLG++;
               }

               if ( grep(/HP-UX run-level transition completed/, $_) ) {
                  push( @BOOTARRAY, $_ );
                  $SPECFLG++;
               }

               if ( $SPECFLG == 1 ) {
                   if ( grep(/^Mon|^Tue|^Wed|^Thu|^Fri|^Sat|^Sun/, $_) ) {
                      push( @BOOTARRAY, $_ );
                      $SPECFLG = 0;
                   }
               }
            }
        }
        close(RCLOG);
    }
    else {
        print "\n$WARNSTR $Rclog is zero-length or does not exist\n";
    }

    if ( $ppanic > 0 ) {
        print "\n$WARNSTR $Rclog might not be clear of system errors\n";
        print "@PPanarray";
        push(@CHECKARR, "\n$WARNSTR $Rclog might not be clear of system errors\n");
        push(@CHECKARR, "@PPanarray");
        $warnings++;
    }
    else {
        print "\n$PASSSTR $Rclog clear of system errors\n";
    }

    datecheck();
    print_trailer("*** END CHECKING LOG FILES FOR STARTUP/SHUTDOWN ERRORS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING BOOT PROCESS TIMINGS $datestring ***");

    if ( @BOOTARRAY ) {
        print "$INFOSTR Boot timings as recorded in current $Rclog\n";
        print @BOOTARRAY;
    }

    datecheck();
    print_header("*** END CHECKING BOOT PROCESS TIMINGS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING BOOT PROCESSES EXECUTION TIMINGS $datestring ***");

    if ( -s "$etcutmp" ) {
        # "-X" flag should be used for reading wtmps-like records.
        # If "-X" is not used, utmp-like structure is read.
        #
        if ( "$Minor$Patch" >= 1123 ) {
            $FWTMP_FLAG = "-X"; 
        }

        my @fwtmp = `fwtmp $FWTMP_FLAG < $etcutmp 2>/dev/null`; 
        my @fwtmp3 = `fwtmp < $etcutmpold 2>/dev/null`; 
        my @fwtmp2 = `fwtmp < $etcutmp 2>/dev/null`; 
    
        if ( @fwtmp3 ) {
            print @fwtmp3;
        }
        elsif ( @fwtmp2 ) {
            print @fwtmp2;
        }
        elsif ( @fwtmp ) {
            print @fwtmp;
        }
        else {
            my @fwtmp = `fwtmp < $etcutmp 2>/dev/null`; 
            if ( @fwtmp ) {
                print @fwtmp;
            }
            else {
                print "$WARNSTR $etcutmp is zero-length or possibly corrupted\n";
                push(@CHECKARR, "\n$WARNSTR $etcutmp is zero-length or possibly corrupted\n");
                $warnings++;
            }
        }
    }
    else {
        print "$WARNSTR $etcutmp is zero-length or possibly corrupted\n";
        push(@CHECKARR, "\n$WARNSTR $etcutmp is zero-length or possibly corrupted\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING BOOT PROCESSES EXECUTION TIMINGS $datestring ***");
}

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

# Subroutine to check installed software bundles
#
sub swcheck {
    datecheck();
    print_header("*** BEGIN CHECKING INSTALLED SOFTWARE BUNDLES $datestring ***");

    print "$NOTESTR Some applications might be installed without bundles\n";
    print "$NOTESTR Please check them manually\n";

    # Run swlist(1m) but get rid of empty spaces at the beginning of lines
    #
    @SWarray = `swlist | sed 's/^[ \t]*//'`;

    if ( ! @SWarray ) {
        print "\n$ERRSTR Swlist is zero-length or corrupt\n";
        push(@CHECKARR, "\n$ERRSTR Swlist is zero-length or corrupt\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR Swlist is not zero-length\n";
        print @SWarray;
        print "\n";

        if ( grep( /Numeric User Group Name/, @SWarray ) ) {
            $NUMUSRGRP_FLAG++;
        }

        if ( grep( /WhiteListInf/, @SWarray ) ) {
            $WHITELIST_FLAG++;
        }

        if ( grep( /Center for Internet Security/, @SWarray ) ) {
            $CISSEC_FLAG++;
        }

        if ( grep( /LongPass11i3/, @SWarray ) ) {
            $LONGPASS_FLAG++;
        }

        if ( grep( /PHI11i3/, @SWarray ) ) {
            $LONGPASS_FLAG++;
        }

        if ( grep( /Fusion-io|iomemory-vsl/, @SWarray ) ) {
            $FUSIONIO_FLAG++;
        }

        if ( grep( /NSDirSvr/, @SWarray ) ) {
            $NSDIRSVR_FLAG++;
        }

        if ( grep( /RHDirSvr/, @SWarray ) ) {
            $RHDIRSVR_FLAG++;
        }

        if ( grep( /Distributed Systems Administration Utilities|DSAUtil/, @SWarray ) ) {
            $DSAU_FLAG++;
        }

        if ( grep( /ISOIMAGE-ENH|ISO Image mount Enhancement/, @SWarray ) ) {
            $ISOIMAGE_FLAG++;
        }
    }

    if ( "$Minor$Patch" <= 1123 ) {
        push( @SWmust, "Medusa" );
        push( @SWmust, "AutoPath" );
        push( @SWmust, "OmniBack" );
        push( @SWmust, "SecurePath" );
        push( @SWmust, "Secure Path" );
    }

    if ( "$Minor$Patch" >= 1131 ) {
        push( @SWmust, "SysFaultMgmt" );
        push( @SWmust, "Tune-N-Tools" );
    }

    if ( "$Minor$Patch" >= 1123 ) {
        push( @SWmust, "RBAC" );
        push( @SWmust, "AccessControl" );
        push( @SWmust, "DynRootDisk" );

        if ( $WLMD_FLAG > 0 ) {
            push( @SWmust, "NodeHostNameXpnd" );
        }
    }

    if ( grep( /Capacity Advisor/, @SWarray ) ) {
        $CAPADV_FLAG++;
    }

    foreach my $acst (@SWmust) {
        if ( grep( /$acst/i, @SWarray ) ) {
            print "$PASSSTR $acst installed\n";
            eval(
                  ( $acst eq "Ignite" )          ? $IGNITE_FLAG = 1
                : ( $acst eq "OmniBack" )        ? $OMNI_FLAG   = 1
                : ( $acst eq "Bastille" )        ? $BASTILLE_FLAG = 1
                : ( $acst eq "RBAC" )            ? $RBAC_FLAG = 1
                : ( $acst eq "AccessControl" )   ? $RBAC_FLAG = 1
                : ( $acst eq "Data Protector" )  ? $OMNI_FLAG     = 1
                : ( $acst eq "SwAssistant" )     ? $SECPATCH_FLAG = 1
                : ( $acst eq "DynRootDisk" )     ? $DYNROOT_FLAG = 1
                : ( $acst eq "ISEE" )            ? $ISEE_FLAG = 1
                : ( $acst eq "SSH" )
                  || ( $acst eq "Secure Shell" ) ? $secureshell++
                : ( $acst eq "AutoPath" )           ? $autopath++
                : ( $acst eq "System Healthcheck" ) ? $shealth++
                : ( $acst eq "OnlineDiag" )         ? $ONLINEDIAG_FLAG = 1
                : ( $acst eq "MCPS-COMMON" )     ? $RCM_FLAG++
                : ( $acst eq "VRTSvcsvr" )       ? $VRTSVCS_FLAG++
                : ( $acst eq "MCPS-COLLECT" )    ? $RCM_FLAG++
                : ""
            );
        }
        else {
            if ( $acst eq "Mirror" ) {
                if ( grep( /Mission Critical|Enterprise|VSE-OE|DC-OE/, $bundle ) ) {
                    ( $bunset, undef ) = split( /\s+/, $bundle );
                    print "$PASSSTR $acst installed and licensed through ";
                    print "$bunset Operating Environment\n";
                }
            }
            elsif ( $acst eq "GlancePlus" ) {
                if ( grep( /Mission Critical|Enterprise|HA-OE|VSE-OE|DC-OE/, $bundle ) ) {
                    ( $bunset, undef ) = split( /\s+/, $bundle );
                    print "$PASSSTR $acst installed and licensed through ";
                    print "$bunset Operating Environment\n";
                }
            }
            else {
                eval(
                      ( $acst eq "SecurePath" )   ? ""
                    : ( $acst eq "OmniBack" )     ? ""
                    : ( $acst eq "Data Protector" ) ? ""
                    : ( $acst eq "OmniBack" )     ? ""
                    : ( $acst eq "AutoPath" )     ? ""
                    : ( $acst eq "emcpower" )     ? ""
                    : ( $acst eq "DynRootDisk" )  ? ""
                    : ( $acst eq "MCPS-COMMON" )  ? ""
                    : ( $acst eq "MCPS-COLLECT" ) ? ""
                    : ( $acst eq "VRTSvcsvr" )    ? ""
                    : ( $acst eq "RBAC" )         ? ""
                    : ( $acst eq "Secure Path" )  ? "" 
                    : ( $acst eq "ISEE" )         ? "" 
                    : ( $acst eq "System Healthcheck" ) ? "" 
                    : ( $acst eq "SSH" )
                      || ( $acst eq "Secure Shell" ) ? $warnings++
                    : swcalc($acst)
                );
            }
        }
    }

    datecheck();
    print_trailer("*** END CHECKING INSTALLED SOFTWARE BUNDLES $datestring ***");

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
    : print "$INFOSTR SSH daemon configuration file not installed\n";

    if ( -s "$SSHD_CONF") {
        if ( open( SSHCD, "awk NF $SSHD_CONF |" ) ) {
            print "$INFOSTR File $SSHD_CONF\n";
            while (<SSHCD>) {
                next if ( grep( /^$/, $_ ) );
                print $_;

                if ( grep( /PermitRootLogin/, $_ ) ) {
                    $_ =~ s/\s+$//g;
                    next if ( grep( /^#/, $_ ) );
                    next if ( grep( /,/,  $_ ) );
                    ( undef, $PWPN ) = split( /\s+/, $_ );
                    chomp($PWPN);
                    if ( lc($PWPN) eq 'yes' ) {
                        push(@SSHARR, "$WARNSTR SSH allows direct Root access\n");
                        push(@SSHARR,
"$NOTESTR It is strongly recommended to disable it\n");
                        push(@CHECKARR, "\n$WARNSTR SSH allows direct Root access\n");
                    }

                    if ( lc($PWPN) eq 'no' ) {
                        push(@SSHARR,
"$PASSSTR SSH does not allow direct Root access\n");
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
                        push(@CHECKARR, "\n$WARNSTR SSH StrictModes set to \"no\"\n");
                        push(@SSHARR,
"$NOTESTR It is strongly recommended to disable it\n");
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
                        push(@SSHARR,
"$NOTESTR It is strongly recommended to disable it\n");
                        push(@CHECKARR, "\n$WARNSTR SSH IgnoreRhosts set to \"no\"\n");
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
                        push(@SSHARR,
"$NOTESTR It is strongly recommended to disable it\n");
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
                        push(@SSHARR, "$NOTESTR It is strongly recommended to use ");
                        push(@SSHARR, "public key client/user credentials only\n");
                        push(@CHECKARR,
"\n$WARNSTR SSH allows password authentication\n");
                    }

                    if ( lc($PWYN) eq 'no' ) {
                        push(@SSHARR,
"$PASSSTR SSH allows public key client/user authentication only\n");
                    }
                }

                if ( grep( /UsePrivilegeSeparation/, $_ ) ) {
                    $_ =~ s/\s+$//g;
                    next if ( grep( /^#/, $_ ) );
                    next if ( grep( /,/,  $_ ) );
                    ( undef, $SSHPRIVSEP ) = split( /\s+/, $_ );
                    chomp($SSHPRIVSEP);
                    if ( lc($SSHPRIVSEP) eq 'no' ) {
                        push(@SSHARR,
"$WARNSTR UsePrivilegeSeparation set to \"no\"\n");
                        push(@SSHARR,
"$NOTESTR It is strongly recommended to disable it\n");
                        push(@CHECKARR,
"\n$WARNSTR SSH UsePrivilegeSeparation set to \"no\"\n");
                    }

                    if ( lc($SSHPRIVSEP) eq 'yes' ) {
                        push(@SSHARR,
"$PASSSTR UsePrivilegeSeparation set to \"yes\"\n");
                    }
                }

                if ( grep( /AllowTcpForwarding/, $_ ) ) {
                    $_ =~ s/\s+$//g;
                    next if ( grep( /^#/, $_ ) );
                    next if ( grep( /,/,  $_ ) );
                    ( undef, $SSHTCPFWD ) = split( /\s+/, $_ );
                    chomp($SSHTCPFWD);
                    if ( lc($SSHTCPFWD) eq 'yes' ) {
                        push(@SSHARR,
"$WARNSTR AllowTcpForwarding set to \"yes\"\n");
                        push(@SSHARR,
"$NOTESTR It is strongly recommended to disable it\n");
                        push(@CHECKARR,
"\n$WARNSTR SSH AllowTcpForwarding set to \"yes\"\n");
                    }

                    if ( lc($SSHTCPFWD) eq 'no' ) {
                        push(@SSHARR,
"$PASSSTR AllowTcpForwarding set to \"no\"\n");
                    }
                }

                if ( grep( /PermitTunnel/, $_ ) ) {
                    $_ =~ s/\s+$//g;
                    next if ( grep( /^#/, $_ ) );
                    next if ( grep( /,/,  $_ ) );
                    ( undef, $SSHTCPTUN ) = split( /\s+/, $_ );
                    chomp($SSHTCPTUN);
                    if ( lc($SSHTCPTUN) eq 'yes' ) {
                        push(@SSHARR,
"$WARNSTR PermitTunnel set to \"yes\"\n");
                        push(@SSHARR,
"$NOTESTR It is strongly recommended to disable it\n");
                        push(@CHECKARR,
"\n$WARNSTR SSH PermitTunnel set to \"yes\"\n");
                    }

                    if ( lc($SSHTCPTUN) eq 'no' ) {
                        push(@SSHARR, "$PASSSTR PermitTunnel set to \"no\"\n");
                    }
                }
            }
            close(SSHCD);
          
            if ( ! "$PWPN" ) {
                push(@SSHARR,
"$WARNSTR SSH allows direct Root access by default configuration\n");
                push(@CHECKARR,
"\n$WARNSTR SSH allows direct Root access by default configuration\n");
            }

            if ( ! "$SSHSTRICT" ) {
                push(@SSHARR,
"$PASSSTR StrictModes set to \"yes\" by default configuration\n");
            }
            
            if ( ! "$SSHRHOST" ) {
                push(@SSHARR,
"$PASSSTR IgnoreRhosts set to \"yes\" by default configuration\n");
            }

            if ( ! "$SSHEMPTYPW" ) {
                push(@SSHARR,
"$PASSSTR PermitEmptyPasswords set to \"no\" by default configuration\n");
            }

            if ( ! "$PWYN" ) {
                push(@SSHARR,
"$WARNSTR SSH allows password authentication by default configuration\n");
                push(@CHECKARR,
"\n$WARNSTR SSH allows password authentication by default configuration\n");
            }

            if ( ! "$SSHPRIVSEP" ) {
                push(@SSHARR,
"$PASSSTR UsePrivilegeSeparation set to \"yes\" by default configuration\n");
            }

            if ( ! "$SSHTCPFWD" ) {
                push(@SSHARR,
"$PASSSTR AllowTcpForwarding set to \"no\" by default configuration\n");
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
    print_trailer("*** END CHECKING SECURE SHELL STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING STATUS OF INSTALLED SOFTWARE FILESETS $datestring ***");

    if ( open( CC, "swlist -l fileset -a state |" ) ) {
        while (<CC>) {
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /^#/, $_ ) );
            #
            # Get rid of leading and trailing empty spaces
            #
            $_ =~ s{\A \s* | \s* \z}{}gxm;
            ( $SWname, $Swstatus ) = split( /\s+/, $_ );
            next if ( grep( /configured/, $Swstatus ) );
            next if ( grep( /installed/i, $Swstatus ) );
            push( @Badsw, $_ );
            $warnings++;
        }
    }
    else {
        print "$ERRSTR Cannot run swlist\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run swlist\n");
    }
    close(CC);

    if (@Badsw) {
        print "$ERRSTR Software filesets not installed correctly\n";
        print "@Badsw\n";
        push(@CHECKARR, "\n$ERRSTR Software filesets not installed correctly\n");
        push(@CHECKARR, "@Badsw\n");
    }
    else {
        print "$PASSSTR All software filesets installed correctly\n";
    }

    my @tllist = `tllist -v 2>/dev/null`;

    if ( @tllist ) {
        print "\n$INFOSTR Transitioning links on the system\n";
        print @tllist;
    }

    datecheck();
    print_trailer("*** END CHECKING STATUS OF INSTALLED SOFTWARE FILESETS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SOFTWARE DEPOTS $datestring ***");

    if ( open( SWD, "swlist -l depot 2>/dev/null | egrep -v ^# |" ) ) {
        while (<SWD>) {
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /^#/, $_ ) );
            $_ =~ s/^\s+//g; 
            if ("$_") {
                push( @Depotarr, $_ );
            }
        }
        close(SWD);
    }

    if ( @Depotarr != 0 ) {
        print "$INFOSTR Software depots installed\n";
        print @Depotarr;
        if ( -f "$SDUXpush" ) {
            print "\n$INFOSTR SD-UX push method set up ($SDUXpush exists)\n";
        }
        else {
            print
              "\n$INFOSTR SD-UX push method not set up ($SDUXpush missing)\n";
        }
    }
    else {
        print "$INFOSTR No software depots installed\n";
    }

    my $wpmodeg = (stat($swsave))[2];

    if ( $wpmodeg & 0002 ) {
        print "\n$WARNSTR Patch backup directory $swsave is world-writable\n";
        push(@CHECKARR, "\n$WARNSTR Patch backup directory $swsave is world-writable\n");
        $warnings++;
    }

    if ( -s "$swsec" ) {
        my @swsecarr = `cat $swsec 2>/dev/null`;
        if ( @swsecarr ) {
            print "\n$INFOSTR Software Distributor shared secrets file $swsec\n";
            print @swsecarr;
        }
    }

    my @SWconf = ( "/usr/lib/sw/sys.defaults", "/var/adm/sw/defaults", );
    foreach my $mycwcnf (@SWconf) {
        if ( -s "$mycwcnf" ) {
            my @cwcf = `egrep -v ^# $mycwcnf | awk NF`;
            if ( @cwcf ) {
                print "\n$INFOSTR Software Distributor configuration file $mycwcnf\n";
                print @cwcf;
            }
            else {
                print
"\n$INFOSTR Software Distributor configuration file $mycwcnf is not customised\n";
            }
        }
    }

    my @swaacl = `swacl -l root 2>/dev/null`;
    if ( @swaacl ) {
        print "\n$INFOSTR SD-UX (IPD) ACLs for root\n";
        print @swaacl;
        print 
"\n$NOTESTR Consider removing the \"any_other\" ACL to ensure that only root can access the IPD\n";
        print 
"$NOTESTR Run command \"swacl -l root -D any_other\"\n";
    }

    my @swaclhost = `swacl -l host 2>/dev/null`;
    if ( @swaclhost ) {
        print "\n$INFOSTR SD-UX ACLs for host\n";
        print @swaclhost;
    }

    my @SWacll = `ls /var/adm/sw/security/*_ACL ${SWdir}/ifiles/*_ACL 2>/dev/null`;
    foreach my $myacll (@SWacll) {
        chomp($myacll);
        if ( (-s "$myacll") && (-T "$myacll") ) {
            my @cwacll = `awk NF $myacll`;
            if ( @cwacll ) {
                print "\n$INFOSTR Software Distributor ACL file $myacll\n";
                print @cwacll;
            }
        }
    }

    datecheck();
    print_trailer("*** END CHECKING SOFTWARE DEPOTS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SOFTWARE PRODUCTS VERIFICATION $datestring ***");

    if ( -f "$SWINSTALLLOCK" ) {
        print "$INFOSTR $SWINSTALLLOCK exists - verify if required\n";
        print "$NOTESTR Swinstall sets fcntl(2) read locks on source\n";
        print "$NOTESTR depots using the swlock file mentioned above.\n";
        print "$NOTESTR When a read lock is set, it prevents all SD commands from\n";
        print "$NOTESTR performing modifications (for example, setting write locks).\n"; 
        print "\n";
    }

    if ( ! -s $SWINDEX ) {
        print "$ERRSTR $SWINDEX is zero-length or missing\n";
        print "\n";
        push(@CHECKARR, "\n$ERRSTR $SWINDEX is zero-length or missing\n");
        $warnings++;
    }
    else {
        print "$PASSSTR $SWINDEX is not zero-length\n";
        print "\n";
    }

    if ( ! -s $SWINFO ) {
        print "$ERRSTR $SWINFO is zero-length or missing\n";
        print "\n";
        push(@CHECKARR, "\n$ERRSTR $SWINFO is zero-length or missing\n");
        $warnings++;
    }
    else {
        print "$PASSSTR $SWINFO is not zero-length\n";
        print "\n";
    }

    if ( chdir $SWdir ) {
        if ( open( SV, "swverify \* 2>&1 |" ) ) {
            while (<SV>) {
                next if ( grep( /^$/,                 $_ ) );
                next if ( grep( /^#/,                 $_ ) );
                next if ( grep( /refers to a bundle/, $_ ) );
                next if ( grep( /Could not apply/,    $_ ) );
                if ( grep( /WARNING:|ERROR:|NOTE:|command/, $_ ) ) {
                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s/^\s+//g;
                    $_ =~ s/\s+$//g;
                    push( @Badsv, $_ );
                }
            }
        }
        else {
            print "$ERRSTR Cannot run swverify\n";
            push(@CHECKARR, "\n$ERRSTR Cannot run swverify\n");
            $warnings++;
        }
        close(SV);

        if ( @Badsv != 0 ) {
            print
"$ERRSTR Some software products seemingly not installed correctly\n";
            print "@Badsv\n";
            push(@CHECKARR,
"\n$ERRSTR Some software products seemingly not installed correctly\n");
            push(@CHECKARR, "@Badsv\n");
            $warnings++;
        }
        else {
            print "$PASSSTR All software products installed correctly\n\n";
        }
    }
    else {
        print "$ERRSTR Cannot cd to $SWdir (IPD possibly corrupt)\n";
        push(@CHECKARR, "\n$ERRSTR Cannot cd to $SWdir ((IPD possibly corrupt)\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING SOFTWARE PRODUCTS VERIFICATION $datestring ***");
}

# Subroutine to check installed patch bundles
#
sub patch {
    datecheck();
    print_header("*** BEGIN CHECKING INSTALLED PATCH BUNDLES $datestring ***");

    @lsbundle = `swlist -l bundle | egrep -i patch`;
    if ( @lsbundle != 0 ) {
        print @lsbundle;
    }

    datecheck();
    print_trailer("*** END CHECKING INSTALLED PATCH BUNDLES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING INSTALLED PATCHES $datestring ***");

    my @lsp = `show_patches -a 2>/dev/null | awk NF`;

    if ( @lsp != 0 ) {
        print "$INFOSTR Active patches\n";
        print @lsp;

        my @lspold = `show_patches -s 2>/dev/null | awk NF`;

        if ( @lspold != 0 ) {
            print "\n$INFOSTR Superseeded patches\n";
            print @lspold;
        }
    }
    else {
        print
          "$INFOSTR HP-UX Patch Tool show_patches possibly not installed\n";

        if ( "$Hardware" eq "ia64" ) {
            print
"$NOTESTR For Itanium platform, patch PHCO_32220 or higher is recommended\n";
        }

        @lsp = `swlist -l patch -a revision -a title -a install_date | awk NF`;
        if ( @lsp != 0 ) {
            print "\n$INFOSTR Patch listing with installation dates\n";
            print @lsp;
        }
    }

    if ( @lsp != 0 ) {
        if ( "$Minor$Patch" == 1123 ) {
            if ( grep( /PHCO_35524|PHCO_38717|PHCO_40920/, @lsp ) ) {
                print
"\n$PASSSTR Patch PHCO_35524, or PHCO_38717, or PHCO_40920 installed for HP-UX 11v2 LVM vgmodify\n";
                $VGMODIFY_FLAG++;
            }
        }
    }

    my @lpat = `ls -ltd $SWdir | awk 'NR>1 {exit}; { print \$6, \$7, \$8}'`;
    if ( @lpat != 0 ) {
        print "\n$INFOSTR Patch with seemingly most recent installation date\n";
        print @lpat;
    }

    datecheck();
    print_trailer("*** END CHECKING INSTALLED PATCHES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING PATCH SUMMARY STATUS $datestring ***");

    my @ckpatch = `check_patches >/dev/null 2>&1`;
    if ( (-s "$defckhfile" ) && ( -T "$defckhfile" ) ) {
        my @ckpsumm = `cat $defckhfile`;
        print @ckpsumm;
    }
    else {
        print
"$INFOSTR HP-UX Patch Tool check_patches possibly not installed\n";

        if ( "$Hardware" eq "ia64" ) {
            print
"$NOTESTR For Itanium platform, patch PHCO_32220 is recommended\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING PATCH SUMMARY STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING PATCH CLEANUP STATUS $datestring ***");

    my @lspcl = `cleanup -p -s 2>/dev/null |awk NF`;
    if ( @lspcl != 0 ) {
        print @lspcl;
    }
    else {
        print "$INFOSTR HP-UX Patch Tool cleanup possibly not installed\n";

        if ( "$Hardware" eq "ia64" ) {
            print
"$NOTESTR For Itanium platform, patch PHCO_32220 is recommended\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING PATCH CLEANUP STATUS $datestring ***");

    if ( $SECPATCH_FLAG > 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING HP RECOMMENDED PATCH STATUS $datestring ***");

        if ( -s "$SPC_CONF" ) {
            print "$INFOSTR Configuration file $SPC_CONF\n";
            my @seccf = `awk NF $SPC_CONF`;
            print @seccf;
        }
        else {
            print "$INFOSTR Configuration file $SPC_CONF does not exist\n";
        }

        if ( -s "$SWA_CONF" ) {
            print "\n$INFOSTR Configuration file $SWA_CONF\n";
            my @secsw = `awk '! /^#|^\$/ {print}' $SWA_CONF`;
            print @secsw;
        }
        else {
            print "\n$INFOSTR Configuration file $SWA_CONF does not exist\n";
        }

        print "\n$INFOSTR Attempting to run patch audit\n";

        # After November 1, 2008 only the use of the "-m" option will
        # be supported for security_patch_check. Use of the "-f" or
        # "-h" options will result in an error. All other valid
        # security_patch_check options will be ignored. For more
        # information, see the swa-report(1M) man page.
        # 
        # my @secck = `/opt/sec_mgmt/spc/bin/security_patch_check -m 2>&1`;
        # if ( @secck ) {
        #     print @secck;
        #     print "\n";
        # }

        if ( -s "$SWAIGNORE" ) {
            print "\n$INFOSTR Configuration file $SWAIGNORE exists\n";
            my @swaign = `awk NF $SWAIGNORE`;
            print @swaign;
        }
        else {
            print "\n$PASSSTR Configuration file $SWAIGNORE does not exist\n";
        }

        if ( @secsw ) {
            if (grep(/^hp_id/, @secsw) && grep(/^hp_pw/, @secsw)) {
                my @swack = `swa report 2>&1`;
                if ( @swack ) {
                    print @swack;
                }
            }
        }
        else {
            print "\n$INFOSTR Configuration options for ITRC login and password in file $SWA_CONF seemingly do not exist\n";
        }

        datecheck();
        print_trailer("*** END CHECKING HP RECOMMENDED PATCH STATUS $datestring ***");
    }
}

# Subroutine to check privileged account
#
sub defumask {
    datecheck();
    print_header("*** BEGIN CHECKING DEFAULT UMASK $datestring ***");

    if ( -s "$DEFPROFILE" ) {
        my $defumsk = `awk '! /^#/ && /umask/ {print \$2}' $DEFPROFILE 2>/dev/null`;
        chomp($defumsk);
        if ( ( $defumsk == "022" ) || ( $defumsk == "0022" ) ) {
            print
"$PASSSTR Default umask set to moderately restrictive \"022\" $DEFPROFILE\n";
        }

        if ( ( $defumsk == "027" ) || ( $defumsk == "0027" ) ) {
            print
"$PASSSTR Default umask set to very restrictive \"027\" $DEFPROFILE\n";
        }

        if ( ! "$defumsk" ) {
            print "$WARNSTR Default umask not set in $DEFPROFILE\n";
        }
    }

    if ( -s "$DEFCPROFILE" ) {
        my $defumsk = `awk '! /^#/ && /umask/ {print \$2}' $DEFCPROFILE 2>/dev/null`;
        chomp($defumsk);
        if ( ( $defumsk == "022" ) || ( $defumsk == "0022" ) ) {
            print
"\n$PASSSTR Default umask set to moderately restrictive \"022\" $DEFCPROFILE\n";
        }

        if ( ( $defumsk == "027" ) || ( $defumsk == "0027" ) ) {
            print
"\n$PASSSTR Default umask set to very restrictive \"027\" $DEFCPROFILE\n";
        }

        if ( ! "$defumsk" ) {
            print "\n$WARNSTR Default umask not set in $DEFCPROFILE\n";
        }
    }

    if ( @UMASKARR ) {
        print @UMASKARR;
    }

    datecheck();
    print_trailer("*** END CHECKING DEFAULT UMASK $datestring ***");
}

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

    my $Rootarray = `awk '/^root:/ && ! /awk/ {print}' $PASSFILE`;
    chomp($Rootarray);

    (
        $rootacc,   $rootpasswd, $rootuid, $rootgid,
        $rootgecos, $roothome,   $rootshell,
    ) = split( /:/, $Rootarray );

    if ( "$rootshell" ne "$defrootshell" ) {
        print "\n$WARNSTR Root Shell is $rootshell (not $defrootshell)\n";
        push(@CHECKARR, "\n$WARNSTR Root Shell is $rootshell (not $defrootshell)\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR Root Shell is $rootshell\n";
    }

    if ( "$Minor$Patch" > 1131 ) {
        $Rootdir = "/homeroot";
    }
 
    if ( "$roothome" ne "$Rootdir" ) {
        print "\n$WARNSTR Root home directory $roothome, not $Rootdir\n";
        push(@CHECKARR, "\n$WARNSTR Root home directory $roothome, not $Rootdir\n");
        $warnings++;
    }
    else {
        print "$PASSSTR Root home directory correct ($Rootdir)\n";
    }

    if ( !stat $Rootdir || !-d $Rootdir ) {
        print "$WARNSTR $Rootdir directory does not exist or not valid\n";
        push(@CHECKARR, "\n$WARNSTR $Rootdir directory does not exist or not valid\n");
        $warnings++;
    }

    my $file_perms = ( stat $roothome )[2] & 0777;
    my $oct_perms = sprintf "%lo", $file_perms;
    if ( $oct_perms != "700" ) {
        print
"\n$WARNSTR Root home directory $roothome permissions not 700 ($oct_perms)\n";
        push(@CHECKARR,
"\n$WARNSTR Root home directory $roothome permissions not 700 ($oct_perms)\n");
        $warnings++;
    }
    else {
        print
"\n$PASSSTR Root home directory $roothome permissions correct ($oct_perms)\n";
    }

    my $rho = "$roothome/.rhosts";
    if ( (-s "$rho" ) && ( -T "$rho" ) ) {
        print "\n$WARNSTR File $rho exists\n";
        push(@CHECKARR, "\n$WARNSTR File $rho exists\n");
        my @rhosts = `cat $rho`;
        print @rhosts;
    }

    my $rauth = "$roothome/.ssh/authorized_keys";
    if ( (-s "$rauth" ) && ( -T "$rauth" ) ) {
        print "\n$INFOSTR File $rauth exists\n";
        my @rauhosts = `cat $rauth`;
        print @rauhosts;
    }

    if ( -f "$sectty" && -s "$sectty" ) {
        print "\n$PASSSTR $sectty exists\n";
        if ( open( CC, "awk '! /^#/ && ! /awk/ {print}' $sectty |" ) ) {
            while (<CC>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                if ( grep( /^console/, $_ ) ) {
                    if ( "$SGRUN" >= 1 ) {
                        print
"\n$WARNSTR Root access via console in $sectty affects Serviceguard\n";
                        push(@CHECKARR,
"\n$WARNSTR Root access via console in $sectty affects Serviceguard\n");
                    }
                    else {
                        print
"\n$PASSSTR Root access via console configured in $sectty\n";
                    }
                }
                else {
                    print
"\n$ERRSTR Root access via non-console device configured in $sectty\n";
                    push(@CHECKARR,
"\n$ERRSTR Root access via non-console device configured in $sectty\n");
                    $warnings++;
                }
            }
        }
        else {
            print "$ERRSTR Cannot open $sectty\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $sectty\n");
            $warnings++;
        }
        close(CC);
    }
    else {
        print "\n$WARNSTR $sectty not installed\n";
        push(@CHECKARR, "\n$WARNSTR $sectty not installed\n");
        $warnings++;
    }

    if ( -f "$defsec" && -s "$defsec" ) {
        print "\n$PASSSTR $defsec exists\n";
        if ( open( CC, "awk '! /^#/ && ! /awk/ {print}' $defsec |" ) ) {
            while (<CC>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /^SU_ROOT_GROUP/, $_ ) ) {
                    $suroot = 1;
                    push( @SUarray, $_ );
                }

                if ( grep( /^MIN_PASSWORD_LENGTH/, $_ ) ) {
                    ( undef, $MINPASS ) = split( /=/, $_ );
                    chomp($MINPASS);
                    if ( "$MINPASS" < $MINPASSDEF ) {
                        push(@CHECKARR,
"\n$WARNSTR MIN_PASSWORD_LENGTH below recommended threshold in $defsec ($MINPASS versus $MINPASSDEF)\n");
                        push(@PASSARR,
"\n$WARNSTR MIN_PASSWORD_LENGTH below recommended threshold in $defsec ($MINPASS versus $MINPASSDEF)\n");
                        $warnings++;
                    }
                    else {
                        push(@PASSARR,
"\n$PASSSTR MIN_PASSWORD_LENGTH satisfies recommended threshold of $MINPASSDEF characters in $defsec\n");
                    }
                }

                if ( grep( /^ABORT_LOGIN_ON_MISSING_HOMEDIR/, $_ ) ) {
                    ( undef, $ABORTHOME ) = split( /=/, $_ );
                    chomp($ABORTHOME);
                    if ( "$ABORTHOME" != 1 ) {
                        push(@CHECKARR,
"\n$WARNSTR ABORT_LOGIN_ON_MISSING_HOMEDIR not set to 1 in $defsec (to disable login if home directory missing)\n");
                        push(@PASSARR,
"\n$WARNSTR ABORT_LOGIN_ON_MISSING_HOMEDIR not set to 1 in $defsec (to disable login if home directory missing)\n");
                        $warnings++;
                    }
                    else {
                        push(@PASSARR,
"\n$PASSSTR ABORT_LOGIN_ON_MISSING_HOMEDIR set to 1 in $defsec (to disable login if home directory missing)\n");
                    }
                }

                if ( "$Minor$Patch" >= 1131 ) {
                    if ( grep( /^CRYPT_DEFAULT/, $_ ) ) {
                        ( undef, $CRYPTDEF ) = split( /=/, $_ );
                        chomp($CRYPTDEF);
                        if ( "$CRYPTDEF" != "$CRYPTVAL" ) {
                            push(@CHECKARR,
"\n$WARNSTR CRYPT_DEFAULT not set to $CRYPTVAL in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@LPASSARR,
"\n$WARNSTR CRYPT_DEFAULT not set to $CRYPTVAL in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@PASSARR,
"\n$WARNSTR CRYPT_DEFAULT not set to $CRYPTVAL in $defsec (to support Shadow passwords up to 255 characters)\n");
                            $warnings++;
                        }
                        else {
                            push(@PASSARR,
"\n$PASSSTR CRYPT_DEFAULT set to $CRYPTVAL in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@LPASSARR,
"\n$PASSSTR CRYPT_DEFAULT set to $CRYPTVAL in $defsec (to support Shadow passwords up to 255 characters)\n");
                        }
                    }

                    if ( grep( /^CRYPT_ALGORITHMS_DEPRECATE/, $_ ) ) {
                        ( undef, $CRYPTALG ) = split( /=/, $_ );
                        chomp($CRYPTALG);
                        if ( "$CRYPTALG" ne "$CRYPTSTR" ) {
                            push(@CHECKARR,
"\n$WARNSTR CRYPT_ALGORITHMS_DEPRECATE not set to \"$CRYPTSTR\" in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@LPASSARR,
"\n$WARNSTR CRYPT_ALGORITHMS_DEPRECATE not set to \"$CRYPTSTR\" in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@PASSARR,
"\n$WARNSTR CRYPT_ALGORITHMS_DEPRECATE not set to \"$CRYPTSTR\" in $defsec (to support Shadow passwords up to 255 characters)\n");
                            $warnings++;
                        }
                        else {
                            push(@PASSARR,
"\n$PASSSTR CRYPT_ALGORITHMS_DEPRECATE set to \"$CRYPTSTR\" in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@LPASSARR,
"\n$PASSSTR CRYPT_ALGORITHMS_DEPRECATE set to \"$CRYPTSTR\" in $defsec (to support Shadow passwords up to 255 characters)\n");
                        }
                    }

                    if ( grep( /^LONG_PASSWORD/, $_ ) ) {
                        ( undef, $LONGPASS ) = split( /=/, $_ );
                        chomp($LONGPASS);
                        if ( "$LONGPASS" != 1 ) {
                            push(@CHECKARR,
"\n$WARNSTR LONG_PASSWORD not set to 1 in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@LPASSARR,
"\n$WARNSTR LONG_PASSWORD not set to 1 in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@PASSARR,
"\n$WARNSTR LONG_PASSWORD not set to 1 in $defsec (to support Shadow passwords up to 255 characters)\n");
                            $warnings++;
                        }
                        else {
                            push(@PASSARR,
"\n$PASSSTR LONG_PASSWORD set to 1 in $defsec (to support Shadow passwords up to 255 characters)\n");
                            push(@LPASSARR,
"\n$PASSSTR LONG_PASSWORD set to 1 in $defsec (to support Shadow passwords up to 255 characters)\n");
                        }
                    }
                }

                if ( grep( /^ALLOW_NULL_PASSWORD/, $_ ) ) {
                    ( undef, $ALLOWNPASS ) = split( /=/, $_ );
                    chomp($ALLOWNPASS);
                    if ( "$ALLOWNPASS" != 0 ) {
                        push(@CHECKARR,
"\n$WARNSTR ALLOW_NULL_PASSWORD not set to 0 in $defsec (to disable login with null password)\n");
                        push(@PASSARR,
"\n$WARNSTR ALLOW_NULL_PASSWORD not set to 0 in $defsec (to disable login with null password)\n");
                        $warnings++;
                    }
                    else {
                        push(@PASSARR,
"\n$PASSSTR ALLOW_NULL_PASSWORD set to 0 in $defsec (to disable login with null password)\n");
                    }
                }

                if ( grep( /^BOOT_AUTH/, $_ ) ) {
                    ( undef, $BOOTAUTH ) = split( /=/, $_ );
                    chomp($BOOTAUTH);
                    if ( "$BOOTAUTH" == 1 ) {
                        push(@CHECKARR,
"\n$INFOSTR BOOT_AUTH set to 1 in $defsec (root password required for single-user mode; if root password is lost it becomes more difficult to reset it)\n");
                        push(@PASSARR,
"\n$INFOSTR BOOT_AUTH set to 1 in $defsec (root password required for single-user mode; if root password is lost it becomes more difficult to reset it)\n");
                    }
                    else {
                        push(@PASSARR,
"\n$INFOSTR BOOT_AUTH not set to 1 in $defsec (root password not required for single-user mode)\n");
                    }
                }

                if ( grep( /^NOLOGIN/, $_ ) ) {
                    ( undef, $NOLOGIN ) = split( /=/, $_ );
                    chomp($NOLOGIN);
                    if ( "$NOLOGIN" == 1 ) {
                        push(@PASSARR,
"\n$INFOSTR NOLOGIN set to 1 in $defsec (non-root login is disabled by the \"$nologinf\" file)\n");
                    }
                    else {
                        push(@PASSARR,
"\n$INFOSTR NOLOGIN not set to 1 in $defsec (\"$nologinf\" file ignored for non-root logins)\n");
                    }
                }

                if ( grep( /^NUMBER_OF_LOGINS_ALLOWED/, $_ ) ) {
                    ( undef, $LOGINALLOW ) = split( /=/, $_ );
                    chomp($LOGINALLOW);
                    if ( "$LOGINALLOW" == 0 ) {
                        push(@CHECKARR,
"\n$WARNSTR NUMBER_OF_LOGINS_ALLOWED set to 0 in $defsec (number of concurrent logins not limited)\n");
                        push(@PASSARR,
"\n$WARNSTR NUMBER_OF_LOGINS_ALLOWED set to 0 in $defsec (number of concurrent logins not limited)\n");
                        $warnings++;
                    }
                    else {
                        push(@PASSARR,
"\n$PASSSTR NUMBER_OF_LOGINS_ALLOWED set to $LOGINALLOW in $defsec (number of concurrent logins is limited)\n");
                    }
                }

                if ( grep( /^PASSWORD_HISTORY_DEPTH/, $_ ) ) {
                    ( undef, $PASSDEPTH ) = split( /=/, $_ );
                    chomp($PASSDEPTH);
                    if ( "$PASSDEPTH" < $PASSDEPTHDEF ) {
                        push(@CHECKARR,
"\n$WARNSTR PASSWORD_HISTORY_DEPTH below recommended threshold in $defsec ($PASSDEPTH versus $PASSDEPTHDEF)\n");
                        push(@PASSARR,
"\n$WARNSTR PASSWORD_HISTORY_DEPTH below recommended threshold in $defsec ($PASSDEPTH versus $PASSDEPTHDEF)\n");
                        $warnings++;
                    }
                    else {
                        push(@PASSARR,
"\n$PASSSTR PASSWORD_HISTORY_DEPTH satisfies recommended threshold of $PASSDEPTHDEF in $defsec \n");
                    }
                }

                if ( grep( /^PASSWORD_POLICY_STRICT/, $_ ) ) {
                    ( undef, $PASSSTRICT ) = split( /=/, $_ );
                    chomp($PASSSTRICT);
                    if ( "$PASSSTRICT" == 0 ) {
                        push(@CHECKARR,
"\n$INFOSTR LOGIN_POLICY_STRICT set to 0 in $defsec (does not impose restrictions when root is changing passwords)\n");
                        push(@PASSARR,
"\n$INFOSTR LOGIN_POLICY_STRICT set to 0 in $defsec (does not impose restrictions when root is changing passwords)\n");
                    }
                    else {
                        push(@PASSARR,
"\n$PASSSTR LOGIN_POLICY_STRICT set to 1 in $defsec (imposes restrictions when root is changing passwords)\n");
                    }
                }

                if ( grep( /^LOGIN_POLICY_STRICT/, $_ ) ) {
                    ( undef, $LOGINSTRICT ) = split( /=/, $_ );
                    chomp($LOGINSTRICT);
                    if ( "$LOGINSTRICT" == 0 ) {
                        push(@CHECKARR,
"\n$INFOSTR PASSWORD_POLICY_STRICT set to 0 in $defsec (does not impose restrictions on root login and authentication)\n");
                        push(@PASSARR,
"\n$INFOSTR PASSWORD_POLICY_STRICT set to 0 in $defsec (does not impose restrictions on root login and authentication)\n");
                    }
                    else {
                        push(@PASSARR,
"\n$PASSSTR PASSWORD_POLICY_STRICT set to 1 in $defsec (imposes restrictions on root login and authentication)\n");
                    }
                }

                if ( grep( /^AUDIT_FLAG/, $_ ) ) {
                    ( undef, $AUDITFLAG ) = split( /=/, $_ );
                    chomp($AUDITFLAG);
                    if ( "$AUDITFLAG" != 1 ) {
                        push(@CHECKARR, "\n$WARNSTR AUDIT_FLAG not set to 1 in $defsec\n");
                        push(@PASSARR, "\n$WARNSTR AUDIT_FLAG not set to 1 in $defsec\n");
                        $warnings++;
                    }
                    else {
                        push(@PASSARR, "\n$PASSSTR AUDIT_FLAG set to 1 in $defsec\n");
                    }
                }

                if ( grep( /^AUTH_MAXTRIES/, $_ ) ) {
                    ( undef, $AUTHMAXTRIES ) = split( /=/, $_ );
                    chomp($AUTHMAXTRIES);
                    if ( ! "$AUTHMAXTRIES" ) {
                        push(@PASSARR, "\n$WARNSTR AUTH_MAXTRIES not set in $defsec\n");
                        push(@CHECKARR, "\n$WARNSTR AUTH_MAXTRIES not set in $defsec\n");
                        $warnings++;
                    }
                    else {
                        push(@PASSARR,
"\n$PASSSTR AUTH_MAXTRIES set to $AUTHMAXTRIES in $defsec\n");
                    }
                }

                if ( grep( /^UMASK/, $_ ) ) {
                    ( undef, $UMASKREAL ) = split( /=/, $_ );
                    chomp($UMASKREAL);
                    my $ztperm = $UMASKREAL & 0777;
                    if ( $ztperm & 022 ) {
                        push(@PASSARR,
"\n$PASSSTR UMASK satisfies recommended value in $defsec (\"$UMASKREAL\" versus recommended minimum \"$UMASKDEF\")\n");
                        push(@UMASKARR,
"\n$PASSSTR UMASK satisfies recommended value in $defsec (\"$UMASKREAL\" in $defsec versus recommended minimum \"$UMASKDEF\")\n");
                    }
                    else {
                        push(@PASSARR,
"\n$WARNSTR UMASK \"$UMASKREAL\" does not satisfy recommended value of \"$UMASKDEF\" in $defsec \n");
                        push(@UMASKARR,
"\n$WARNSTR UMASK \"$UMASKREAL\" does not satisfy recommended value of \"$UMASKDEF\" in $defsec\n");
                        $warnings++;
                    }
                }

                print $_;
            }
            close(CC);
        }
        else {
            print "$WARNSTR Cannot open $defsec\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $defsec\n");
            $warnings++;
        }

        if ( $suroot > 0 ) {
            print "\n$PASSSTR Root su(1) access restricted in $defsec ";
            print "(flag \"SU_ROOT_GROUP\")\n";
        }
        else {
            print "\n$ERRSTR Root su(1) access not restricted in ";
            print "$defsec (flag \"SU_ROOT_GROUP\")\n";
            push(@CHECKARR, "\n$ERRSTR Root su(1) access not restricted in ");
            push(@CHECKARR, "$defsec (flag \"SU_ROOT_GROUP\")\n");
            $warnings++;
        }

        if ( @PASSARR ) {
           print @PASSARR;
        }
    }
    else {
        print "\n$WARNSTR $defsec not installed\n";
        push(@CHECKARR, "\n$WARNSTR $defsec not installed\n");
        $warnings++;
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
        if ( open( SUF, "egrep -v ^# $sudoconf |" ) ) {
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
        @SUent = `egrep -i root $sulog`;
        if ( @SUent != 0 ) {
            print "\n$INFOSTR Recent su(1) entries in $sulog\n";
            print @SUent;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING PRIVILEGED ACCOUNT $datestring ***");
}

# Subroutine to check NTP
#
sub ntp_check {
    datecheck();
    print_header("*** BEGIN CHECKING NTP SERVICES $datestring ***");

    if ( @ntpdaemon != 0 ) {
        print "$PASSSTR Network Time Protocol daemon running\n";
        if ( open( NTPQ, "ntpq -n -c peers 2>/dev/null |" ) ) {
            while (<NTPQ>) {
                next if ( grep( /^$/,     $_ ) );
                next if ( grep( /offset/, $_ ) );
                next if ( grep( /===/,    $_ ) );
                #
                # Get rid of leading and trailing empty spaces
                #
                $_ =~ s{\A \s* | \s* \z}{}gxm;
                (
                    $remote, $refid, $st,    $tm,     $when,
                    $poll,   $reach, $delay, $offset, $displ
                ) = split( /\s+/, $_ );
                $reach  =~ s/^\s+//g;
                $remote =~ s/\*//g;
                $remote =~ s/\+//g;
                $remote =~ s/^#//g;

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
            close(NTPQ);

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
            print "$INFOSTR Cannot run ntpq\n";
        }

        my @xntpdcl = `xntpdc -c loopinfo 2>/dev/null`;
        if ( @xntpdcl ) {
            print "\n$NOTESTR NTP loopinfo\n";
            print @xntpdcl;
        }

        my @xntpdcs = `xntpdc -c sysinfo 2>/dev/null`;
        if ( @xntpdcs ) {
            print "\n$NOTESTR NTP sysinfo\n";
            print @xntpdcs;
        }

        if ( -s "$ntpconf" ) {
            print "\n$PASSSTR $ntpconf exists\n";
            if ( open( NTPC, "awk NF $ntpconf |" ) ) {
                while (<NTPC>) {
                    next if ( grep( /^$/, $_ ) );
                    $_ =~ s/^\s+//g;
                    print $_;
                    next if ( grep( /^#/, $_ ) );

                    if ( grep( /restrict 127.0.0.1/, $_ ) ) {
                        $NTP_REST_FLAG++;
                    }

                    if ( grep( /restrict default ignore/, $_ ) ) {
                        $NTP_REST_FLAG++;
                    }
                }
                close(NTPC);
            }

            if ( $NTP_REST_FLAG == 0 ) {
                print "\n$WARNSTR Network Time Protocol not restricted in $ntpconf\n";
                push(@CHECKARR,
"\n$WARNSTR Network Time Protocol not restricted in $ntpconf\n");
                $warnings++;
            }
            else {
                print "\n$PASSSTR Network Time Protocol restricted in $ntpconf\n";
            }
        }
        else {
            print "\n$ERRSTR Cannot open $ntpconf\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $ntpconf\n");
            my @NTPtrace = `$XPG4VAR ps -xC xntpd 2>/dev/null`;
            if ( @NTPtrace ) {
                print "$NOTESTR NTP configuration possibly located elsewhere\n";
                print @NTPtrace;
            }
            $warnings++;
        }
    }
    else {
        print "$ERRSTR Network Time Protocol not running\n";
        push(@CHECKARR, "\n$ERRSTR Network Time Protocol not running\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING NTP SERVICES $datestring ***");
}

# Subroutine to check iSCSI Initiator
#
sub checkiSCSI {
    datecheck();
    print_header("*** BEGIN CHECKING iSCSI $datestring ***");

    # The output of command /usr/sam/lbin/iscsi_check has return values:
    #  0 : iscsi is installed.
    #  1 : iscsi is not installed.
    #
    my $iscsiret = system "iscsi_check 2>/dev/null";
    my $IRCVALUE = ( $iscsiret >> 8 ) && 0xff;
    chomp($IRCVALUE);
    
    if ( ($iSCSIFLAG > 0) || ($IRCVALUE == 0) ) {
        print "$INFOSTR iSCSI installed\n";

        my @islpd = `islpd -g 2>&1`;
        if ( @islpd ) {
            print
"\n$INFOSTR iSCSI Service Location Protocol Daemon start on boot\n";
            print @islpd;
        }

        my @iSCSIc = `iscsiutil -l 2>&1`;
        if ( @iSCSIc ) {
            print "\n$INFOSTR iSCSI status\n";
            print @iSCSIc;

            my @iSCSIp = `iscsiutil -p -D 2>&1`;
            if ( @iSCSIp ) {
                print "\n$INFOSTR iSCSI keys for Discovery targets\n";
                print @iSCSIp;
            }

            my @iSCSIo = `iscsiutil -p -O 2>&1`;
            if ( @iSCSIo ) {
                print "\n$INFOSTR iSCSI keys for Operational targets\n";
                print @iSCSIo;
            }

            my @iSCSIS = `iscsiutil -p -S 2>&1`;
            if ( @iSCSIS ) {
                print "\n$INFOSTR iSCSI keys for all sessions\n";
                print @iSCSIS;
            }

            my @iSCSIs = `iscsiutil -sG 2>&1`;
            if ( @iSCSIs ) {
                print "\n$INFOSTR iSCSI software initiator\n";
                print @iSCSIs;
            }
        }
     }
     else {
        print "$INFOSTR iSCSI not installed\n";
     }

    datecheck();
    print_trailer("*** END CHECKING iSCSI $datestring ***");
}

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
    print_trailer("*** END CHECKING POWERBROKER $datestring ***");
}

# Subroutine to check NFS
#
sub nfs_check {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK FILE SYSTEM (NFS) $datestring ***");

    if ( "$Minor$Patch" >= 1123 ) {
        my @setoncenv = `setoncenv -lv 2>&1`;
        if ( @setoncenv != 0 ) {
            print "\n$INFOSTR NFS configuration variables\n";
            print @setoncenv;
            print "\n";
        }
    }

    my @MOUNTFS = `mount 2>/dev/null`;
    if ( @MOUNTFS ) {
        foreach my $c (@MOUNTFS) {
            chomp($c);
            if ( ( grep( /NFS/, $c ) ) && ( grep( /rsize/, $c ) ) ) {
                ( $lfs, undef, $remfs, $state, undef ) = split( /\s+/, $c );
                chomp($lfs);
                push( @NFSarr, $lfs );
                $nfscount++;
                if ( grep( /soft/, $state ) ) {
                    print
"$WARNSTR There are NFS mounts that are not soft mounted\n";
                    push(@CHECKARR,
"\n$WARNSTR There are NFS mounts that are not soft mounted\n");
                    print "$c\n";
                }
            }
        }
    }
    else {
        print "\n$WARNSTR Cannot run mount command\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run mount command\n");
        $warnings++;
    }

    if ( $nfscount > 0 ) {
        print "\n$INFOSTR There are NFS mounts on the local server\n";
    }
    else {
        print "$PASSSTR There are no NFS mounts on the local server\n";
    }

    my @nfsm = `nfsstat -m 2>/dev/null`;
    if ( @nfsm != 0 ) {
        print "\n$INFOSTR NFS statistics for NFS-mounted file systems\n";
        print @nfsm;
    }

    my @nfsc = `nfsstat -c 2>/dev/null`;
    if ( @nfsc != 0 ) {
        print "\n$INFOSTR NFS client-side statistics\n";
        print @nfsc;
    }

    my @nfss = `nfsstat -s 2>/dev/null`;
    if ( @nfss != 0 ) {
        print "\n$INFOSTR NFS server-side statistics\n";
        print @nfss;
    }

    if ( -T "$nfsconf" && -s "$nfsconf" ) {
        print "\n$PASSSTR $nfsconf exists\n";
        if ( open( CC, "awk '! /^#/ && ! /awk/ {print}' $nfsconf |" ) ) {
            while (<CC>) {
                next if ( grep( /^$/, $_ ) );
                #
                # Get rid of leading and trailing empty spaces
                #
                $_ =~ s{\A \s* | \s* \z}{}gxm;
                $_ =~ s/\s+//g;
                if ( grep( /^NFS_SERVER=/, $_ ) ) {
                    if ( grep( /1/, $_ ) ) {
                        print
"$INFOSTR NFS server enabled in $nfsconf (flag \"NFS_SERVER\")\n";
                       $nfscount++;
                    }
                    else {
                        print "$PASSSTR NFS server disabled in $nfsconf ";
                        print "(flag \"NFS_SERVER\")\n";
                    }
                }

                if ( grep( /^NFS_CLIENT=/, $_ ) ) {
                    if ( grep( /1/, $_ ) ) {
                        print "$INFOSTR NFS client enabled in $nfsconf ";
                        print "(flag \"NFS_CLIENT\")\n";
                        $nfscount++;
                    }
                    else {
                        print "$PASSSTR NFS client disabled in $nfsconf ";
                        print "(flag \"NFS_CLIENT\")\n";
                    }
                }

                if ( grep( /^AUTOMOUNT=/, $_ ) ) {
                    if ( grep( /1/, $_ ) ) {
                        print "$WARNSTR Automount enabled in $nfsconf ";
                        print "(flag \"AUTOMOUNT\")\n";
                        push(@CHECKARR, "\n$WARNSTR Automount enabled in $nfsconf ");
                        push(@CHECKARR, "(flag \"AUTOMOUNT\")\n");
                        $AUTO_FLAG++;
                        $warnings++;
                    }
                    else {
                        print "$PASSSTR Automount client disabled in ";
                        print "$nfsconf (flag \"AUTOMOUNT\")\n";
                    }
                }

                if ( grep( /^AUTOFS=/, $_ ) ) {
                    if ( grep( /1/, $_ ) ) {
                        print "$WARNSTR Autofs enabled in $nfsconf ";
                        print "(flag \"AUTOFS\")\n";
                        push(@CHECKARR, "\n$WARNSTR Autofs enabled in $nfsconf ");
                        push(@CHECKARR, "(flag \"AUTOFS\")\n");
                        $AUTO_FLAG++;
                        $warnings++;
                    }
                    else {
                        print "$PASSSTR Autofs client disabled in $nfsconf ";
                        print "(flag \"AUTOFS\")\n";
                    }
                }
            }
            close(CC);
        }
        else {
            print "$INFOSTR Cannot open $nfsconf\n";
        }

        if ( -T "$nfssec" && -s "$nfssec" ) {
            my @nfsss = `egrep -v ^# $nfssec | awk NF`;
            if ( @nfsss ) {
                print "\n$INFOSTR Configuration file $nfssec\n";
                print @nfsss;
            }
        }
        else {
            print "\n$INFOSTR Configuration file $nfssec is zero-length or missing\n";
        }

        my @statmon = `ls -als $STATMON 2>/dev/null`;
        if ( @statmon ) {
            print "\n$INFOSTR NFS file locks in $STATMON\n";
            print @statmon;
        }
    }
    else {
        print "\n$INFOSTR $nfsconf does not exist or zero-length\n";
    }

    print "$NOTESTR Refer to mount_nfs regarding Hard/Soft mounts\n";

    if ( "$Minor$Patch" >= 1131 ) {
        if ( -s "$sharetab" ) {
            my @sht = `awk '! /^#/ && ! /awk/ {print}' $sharetab`;
            if ( @sht ) { 
                print "\n$INFOSTR $sharetab contents\n";
                print @sht;
                $nfscount++;
            }
            else {
                print "\n$INFOSTR $sharetab not set up or zero-length\n";
            }
        }
        else {
            print "\n$INFOSTR $sharetab not set up or zero-length\n";
        }

        my @NFSARR = ( '/etc/default/autofs',
                       '/etc/default/nfslogd',
                     );

        foreach my $nfsent (@NFSARR) {
            if ( -s "$nfsent" ) {
                my @nfssee = `awk NF $nfsent`;
                if ( @nfssee ) { 
                    print "\n$INFOSTR $nfsent contents\n";
                    print @nfssee;
                }
            }
        }

        if ( -s "$DEFNFS" ) {
            if ( open( TMV, "awk NF $DEFNFS |" ) ) {
                print "\n$INFOSTR $DEFNFS contents\n";
                while (<TMV>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                    chomp($_);
                    if ( grep( /^NFSMAPID_DOMAIN/, $_ ) ) {
                        ( undef, $NFSMAPID ) = split( /=/, $_ );
                    }
                }
                close(TMV);
            }
        }

        if ( "$NFSMAPID" && "$DNSdefdom" ) {
            if ( "$DNSdefdom" ne "$DNSdefdom" ) {
                print "\n$INFOSTR Default domain name in $NAMED is $DNSdefdom\n";
                print
"\n$INFOSTR Domain name in $DEFNFS (parameter NFSMAPID_DOMAIN) is $NFSMAPID\n";
            }
        }
    }

    if ( -s "$exportfs" ) {
        my @efs = `awk '! /^#/ && ! /awk/ {print}' $exportfs`;
        if ( @efs ) { 
            print "\n$INFOSTR $exportfs contents\n";
            print @efs;
            $nfscount++;
        }
    }
    else {
        print "\n$INFOSTR $exportfs not set up\n";
    }

    my @showmnt = `showmount -e 2>/dev/null`;
    if ( @showmnt ) {
        print "\n$INFOSTR Listing of exported file systems (remote mounts)\n";
        print @showmnt;
    }

    if ( -T "$RMTAB" && -s "$RMTAB" ) {
        my @rmtab = `awk NF $RMTAB`;
        if ( @rmtab ) {
            print "\n$INFOSTR Logs of recent NFS mnounts in $RMTAB\n";
            print @rmtab;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING NETWORK FILE SYSTEM (NFS) $datestring ***");
}

# Subroutine to check mounted file systems
#
sub CHECK_INITTAB {
    datecheck();
    print_header("*** BEGIN CHECKING INITTAB $datestring ***");

    if ( open( ZK, "awk NF $initt |" ) ) {
        while (<ZK>) {
            push( @initarr, $_ );
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
                    @vxcom2 = `$vxcom 2>/dev/null`;
                }
            }

            if ( grep( /:initdefault:/, $_ ) ) {
                chomp($_);
                my @deflev = split(/:/, $_);
                if( ! "$deflev[1]" ) {
                    push(@CHECKARR,
"\n$WARNSTR Line \"$_\" contains undefined default runlevel in $initt\n");
                    push(@INITARR,
"\n$WARNSTR Line \"$_\" contains undefined default runlevel in $initt\n");
                    $warnings++;
                }
                else {
                    if( ! ( $deflev[1] =~ /^[0-6]$/ ) ) {
                        push(@CHECKARR,
"\n$WARNSTR Line \"$_\" contains invalid value in default runlevel $deflev[1] in $initt\n");
                        push(@INITARR,
"\n$WARNSTR Line \"$_\" contains invalid value in default runlevel $deflev[1] in $initt\n");
                        $warnings++;
                    }

                    if ( $deflev[1] != $runlevel ) {
                        push(@CHECKARR,
"\n$WARNSTR Default runlevel $deflev[1] in $initt differs from current runlevel\n");
                        push(@INITARR,
"\n$WARNSTR Default runlevel $deflev[1] in $initt differs from current runlevel\n");
                        $warnings++;
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
        print @initarr;

        if ( $SYSINIT_FLAG == 0 ) {
            push(@INITARR, "\n$WARNSTR $initt missing sysinit\n");
            push(@CHECKARR, "\n$WARNSTR $initt missing sysinit\n");
            $warnings++;
        }

        if ( @INITARR ) {
            print "\n";
            print @INITARR;
        }
        else {
            print "\n$PASSSTR $initt passed basic syntax health check\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING INITTAB $datestring ***");

    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING FILE SYSTEM STACK TEMPLATES $datestring ***");

        my @fstadm = `fstadm list`;
        if ( @fstadm ) {
            print @fstadm;
        }
        else {
            print "$INFOSTR fstadm list is zero-length or undefined\n";
        }

        datecheck();
        print_trailer("*** END CHECKING FILE SYSTEM STACK TEMPLATES $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING ALL FSTAB FILE SYSTEMS MOUNTED AND VALID $datestring ***");

    print 
"$NOTESTR Maximum intent log size should be used for VxFS, as this allows the largest number of requests\n";
    print 
"$NOTESTR to be pending in the log file before any intent log maintenance is required by the kernel\n\n";

    my $fswarnings;

    if ( !-s "$MNTTAB" ) {
        print "$ERRSTR File $MNTTAB is zero-length\n\n";
        push(@CHECKARR, "\n$ERRSTR File $MNTTAB is zero-length\n\n");
        $MNT_FLAG = 1;
        $warnings++;
    }
    else {
        my @MOUNTFS = `mount 2>/dev/null`;
        if ( @MOUNTFS ) {
            foreach my $c (@MOUNTFS) {
                push (@ALLMOUNT, "$c");
                chomp($c);
                #
                # Get rid of leading and trailing empty spaces
                #
                $c =~ s{\A \s* | \s* \z}{}gxm;
                $MOUNT_CNT++;

                my @ALLMARR = split( /\s+/, $c );
                $fsreal = $ALLMARR[0];
                push( @Mounted, $fsreal );
               
                my $mkfsck = $ALLMARR[2];
                my $mkfsorig = `mkfs -m $mkfsck 2>/dev/null`;

                # In VxVM 4.1, with disk layout 6, the maximum intent log size 
                # has been increased to 256 MB
                #
                my $vxvmver = `swlist | awk '/Base-VXVM|Base-VxVM/ {print \$2}'`;
                my @mm = split(/\./, $vxvmver);

                if ( int($mm[1]) >= 5 ) {
                    $RECINTLOG = 262144;
                }
                elsif ( int($mm[1]) >= 4 ) {
                    $RECINTLOG = 16384;
                }
                else {
                    $RECINTLOG = 16384;
                }

                if ( ! grep(/\bhfs\b/, $mkfsorig ) ) {
                    if ( "$mkfsorig" ) {
                        push(@MKFSARR, $mkfsorig);
                        chomp($mkfsorig);
                        my @ffmk = split(/,/, $mkfsorig);
                        foreach my $rr ( @ffmk ) {
                            if (grep/version=/, $rr) {
                                my @pp = split(/=/, $rr);
                                $vxdskver = $pp[1];
                                if ( ( int($mm[1]) >= 4 ) && ( $vxdskver >= 6) ) {
                                    if ( "$Minor$Patch" >= 1131 ) {
                                       # Maximum intent log size is 2 GB
                                       # but we will leave recommended value
                                       # at 256 MB
                                       # $RECINTLOG = 2097152;
                                       #
                                       $RECINTLOG = 262144;
                                    }
                                    else {
                                        $RECINTLOG = 262144;
                                    }
                                }

                            }

                            if (grep/logsize=/, $rr) {
                                my @oo = split(/=/, $rr);
                                $vxlogsize = $oo[1];
                            }
                        }

                        if ( "$vxlogsize" ) {
                            if ( "$vxlogsize" < $RECINTLOG ) {
                                push(@CHECKARR,
"\n$WARNSTR The intent log size for $mkfsck ($vxlogsize KB) is smaller than the recommended size of $RECINTLOG KB\n");
                                push(@INTARR,
"$WARNSTR The intent log size for $mkfsck ($vxlogsize KB) is smaller than the recommended size of $RECINTLOG KB\n");
                            }
                            else {
                                push(@INTARR,
"$PASSSTR The intent log size for $mkfsck ($vxlogsize KB) matches the recommended size\n");
                            }
                        }
                    }
                }
            }

            if ( @ALLMOUNT ) {
                print "$INFOSTR There are $MOUNT_CNT file systems mounted\n\n";
                print @ALLMOUNT;
            }

            if ( @MKFSARR ) {
                print "\n$INFOSTR File systems originally created by:\n";
                print @MKFSARR;
            }

            if ( @INTARR ) {
                print "\n";
                print @INTARR;
            }

            if ( ( -s $VXFSNOREORG ) && ( -T $VXFSNOREORG ) ) {
                my @vxnoreorg = `egrep -v ^# $VXFSNOREORG | awk NF`;
                if ( @vxnoreorg ) {
                    print
"\n$INFOSTR File systems disabled to run extent and log reorganization\n";
                    print "$INFOSTR (as defined in $VXFSNOREORG)\n";
                    print @vxnoreorg;
                }
            }
        }
        else {
            print "$ERRSTR Cannot run mount command\n\n";
            push(@CHECKARR, "\n$ERRSTR Cannot run mount command\n\n");
            $warnings++;
        }
    }

    if ( !-s "$TUNEFSTAB" ) {
        print "\n$INFOSTR File $TUNEFSTAB is zero-length or does not exist\n";
    }
    else {
        if ( open( TMM, "awk NF $TUNEFSTAB |" ) ) {
            print "\n$INFOSTR File $TUNEFSTAB\n";
            while (<TMM>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(TMM);
        }
    }

    if ( open( VV, "awk '! /awk/ && ! /^#/ {print}' $FSTAB |" ) ) {
        print "\n$INFOSTR $FSTAB contents\n";
        while (<VV>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            chomp($_);

            my @KFSARR = split( /\s+/, $_ );
            if ( $#KFSARR != 5 ) {
                push(@FSTABINFO,
"\n$ERRSTR Line \"$_\" contains extra white-space seperated fields in $FSTAB (should be six)\n");
                push(@CHECKARR,
"\n$ERRSTR Line \"$_\" contains extra white-space seperated fields in $FSTAB (should be six)\n");
               $warnings++;
            }

            if ( grep( /swap/, $_ ) ) {
                $swapdeviceno++;
                next;
            }

            next if ( grep( /nfs/, $_ ) );

            ( $v1, $v2, $v3, $v4, $v5, $passnofs ) = split( /\s+/, $_ );

            $ORDMOUNTCNT = sprintf("%d%s", $MOUNTORDER, ordinalize($MOUNTORDER));
            push(@MOUNTORD, "$ORDMOUNTCNT... $v2\n");
            $MOUNTORDER++;

            if ( "$v1" ) {
                chomp($v1);
                $v1 =~ s/^\s+//g;
                $v1 =~ s/\s+$//g;
                if ( "$v1" eq "/dev/odm" ) {
                    push(@FSTABINFO,
"\n$INFOSTR File system $v2 used by Oracle Disk Manager\n");
                }
            }

            if ( "$v2" ) {
                if ( !grep( /$v2/, @Mounted ) ) {
                    push(@FSTABINFO,
"\n$WARNSTR File system $v2 listed in $FSTAB but not mounted\n");
                    push(@CHECKARR,
"\n$WARNSTR File system $v2 listed in $FSTAB but not mounted\n");
                    $warnings++;
                    $fswarnings++;
                }

                if ( grep( /\bro\b/, $v4 ) ) {
                    push(@FSTABINFO,
"\n$INFOSTR File system $v2 set to be mounted \"read-only\"\n");
                }

                if ( grep( /\bnosuid\b/, $v4 ) ) {
                    push(@FSTABINFO,
"\n$PASSSTR File system $v2 disallows SUID execution (\"nosuid\" option enabled)\n");
                }
                else {
                    push(@FSTABINFO,
"\n$INFOSTR File system $v2 allows SUID execution (\"suid\" option enabled)\n");
                }

                if ( grep( /\bnolargefiles\b/, $v4 ) ) {
                    push(@FSTABINFO,
"\n$INFOSTR File system $v2 set to be mounted \"nolargefiles\"\n");
                }

                if ( grep( /\bblkclear\b/, $v4 ) ) {
                    push(@FSTABINFO,
"\n$INFOSTR File system $v2 set to be mounted \"blkclear\" (clears all data extents before allocating them to a file)\n");
                }

                if ( "$v2" eq "/tmp" ) {
                    if ( grep( /tmplog/, $v4 ) ) {
                        push(@FSTABINFO,
"\n$PASSSTR File system $v2 mounted with \"tmplog\"\n");
                    }
                    else {
                        push(@FSTABINFO,
"\n$WARNSTR File system $v2 not mounted with \"tmplog\"\n");
                        push(@CHECKARR,
"\n$WARNSTR File system $v2 not mounted with \"tmplog\"\n");
                        $warnings++;
                    }
                }

                if( ! ( $passnofs =~ /^[0-9]+$/ ) ) {
                    push(@FSTABINFO,
"$ERRSTR File system $v2 check pass number $passnofs is not numeric\n");
                    push(@CHECKARR,
"\n$ERRSTR File system $v2 check pass number $passnofs is not numeric\n");
                    $warnings++;
                }
                else {
                    if ( "$passnofs" == 0 ) {
                        push(@FSTABINFO,
"\n$ERRSTR File system $v2 check pass number set to zero\n");
                        push(@CHECKARR,
"\n$ERRSTR File system $v2 check pass number set to zero\n");
                        $warnings++;
                    }
                    else {
                        push(@FSTABINFO,
"\n$PASSSTR File system $v2 check pass number not set to zero\n");
                    }
                }

                push( @Fstabed, $v2 );
            }

            if ( $v3 ne "vxfs" ) {
                next if ( grep( /^\/stand/, $v2 ) );
                next if ( $v3 eq "dump" );
                push(@FSTABINFO, "\n$INFOSTR File system $v2 not VxFS\n");
                $vxfscount++;
            }
            else {
                push(@FSTABINFO,
"\n$INFOSTR Checking defragmentation of file system $v2\n");
                my @defrag = `fsadm -F vxfs -D -t 20 $v2 2>/dev/null | awk NF`;
                if ( @defrag != 0 ) {
                    push(@FSTABINFO, "@defrag\n");
                }

                push(@FSTABINFO,
"\n$INFOSTR Checking VxFS tuning parameters for file system $v2\n");
                my @vxfstunelist = `vxtunefs -p $v2 2>/dev/null | awk NF`;
                if ( @vxfstunelist != 0 ) {
                    push(@FSTABINFO, "@vxfstunelist\n");
                }
            }
        }
        close(VV);

        if ( @FSTABINFO ) {
            print "@FSTABINFO"; 
            print "\n"; 
        }
    }
    else {
        print "$WARNSTR Cannot check $FSTAB\n";
        push(@CHECKARR, "\n$WARNSTR Cannot check $FSTAB\n");
        $warnings++;
    }

    foreach my $c (@Mounted) {
        if ( !grep( /$c/, @Fstabed ) ) {
            next if (grep( /^\/dev\/deviceFileSystem|^\/net/, $c ) );
            print "$WARNSTR File system $c mounted but not listed in $FSTAB\n";
            push(@CHECKARR,
"\n$WARNSTR File system $c mounted but not listed in $FSTAB\n");
            $warnings++;
            $fswarnings++;
        }
    }

    if ( "$fswarnings" > 0 ) {
        print "\n$WARNSTR Some file systems not mounted correctly\n";
        push(@CHECKARR, "\n$WARNSTR Some file systems not mounted correctly\n");
    }
    else {
        print "\n$PASSSTR All file systems mounted correctly\n";
    }

    datecheck();
    print_trailer("*** END CHECKING ALL FSTAB FILE SYSTEMS MOUNTED AND VALID $datestring ***");

    if ( ( -s $RAMDISKTAB ) && ( -T $RAMDISKTAB ) ) {
        my @ramdisk = `egrep -v ^# $RAMDISKTAB | awk NF`;
        if ( @ramdisk ) {
            datecheck();
            print_header("*** BEGIN CHECKING RAMDISK SETUP $datestring ***");

            print "$INFOSTR Configuration file $RAMDISKTAB\n";
            print @ramdisk;

            if ( @RAMdiskarray ) {
                print "\n$INFOSTR Ioscan status for on-line ramdisks\n";
                print @RAMdiskarray;
            }

            my @ramarr = `ls /dev/rdsk/ram* /dev/rdisk/ram* 2>/dev/null`;
            if ( @ramarr != 0 ) {
                foreach my $ramdev (@ramarr) {
                    chomp($ramdev);
                    my @raminfo = `diskinfo $ramdev 2>/dev/null`;
                    if ( @raminfo ) {
                        print "\n$INFOSTR Diskinfo for $ramdev\n";
                        print @raminfo;
                    }
                }
            }

            datecheck();
            print_trailer("*** END CHECKING RAMDISK SETUP $datestring ***");
        }
    }

    datecheck();
    print_header("*** BEGIN CHECKING AUTOMOUNT $datestring ***");

    if ( $AUTO_FLAG > 0 ) {
        print "$INFOSTR Automount is enabled\n";
    }
    else {
        print "$INFOSTR Automount is disabled\n";
    }

    foreach my $autocm ( @AUTOARR ) {
        if ( "$autocm" eq "/etc/auto_master" ) {
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
                print "$WARNSTR System auditing (AUDSYS) not configured\n";
                push(@CHECKARR, "\n$WARNSTR System auditing (AUDSYS) not configured\n");
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
                print
"\n$INFOSTR Configuration file $autocm is zero-length or does not exist\n";
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
            print
"\n$INFOSTR Configuration file $autocm2 is zero-length or does not exist\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING AUTOMOUNT $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING ENCRYPTED FILE SYSTEMS (EVFS) $datestring ***");

    my @evfsls = `find $EVFSDEVDIR -exec ll {} \\; 2>/dev/null`;

    my @EVFSARR = `find $EVFSPKEY -name '*.priv' -print 2>/dev/null`;

    my @evfsst = `ll /etc/evfs/.status 2>/dev/null`;

    if ( @evfsst ) {
        print "$INFOSTR Listing of /etc/evfs/.status directory\n";
        print @evfsst;
        $EVFS_FLAG++;
    }

    if ( @evfsls ) {
        print "$INFOSTR Encrypted File System special devices in $EVFSDEVDIR\n";
        print @evfsls;
        $EVFS_FLAG++;
    }

    if ( @EVFSARR ) {
        print "\n$INFOSTR Encrypted File System key pairs\n";
        print @EVFSARR;
        $EVFS_FLAG++;
        my $evfsowner = q{};
        my $evfskey = q{};
        foreach my $evfspkey (@EVFSARR) {
            chomp($evfspkey);
            $evfspkey =~ s/\/etc\/evfs\/pkey\///g;
            $evfspkey =~ s/\.priv//g;
            ($evfsowner, $evfskey) = split(/\//, $evfspkey);
            my @evfslup = `evfspkey lookup -u $evfsowner -k $evfskey 2>/dev/null`;
            if ( @evfslup ) {
                print "\n$INFOSTR Encrypted File System key pairs lookup for user $evfsowner\n";
                print @evfslup;
            }
        }
    }

    my @evfslupr = `evfspkey lookup -r 2>/dev/null`;

    if ( @evfslupr ) {
        print "\n$INFOSTR Encrypted File System recovery key lookup\n";
        print @evfslupr;
    }

    my @evfsvol = `evfsvol display -a 2>/dev/null`;

    if ( @evfsvol ) {
        print "\n$INFOSTR Encrypted File System volumes\n";
        print @evfsvol;
        $EVFS_FLAG++;
    }

    my @evfsvolck = `evfsvol check -a 2>/dev/null`;

    if ( @evfsvolck ) {
        print "\n$INFOSTR Encrypted File System integrity of the EMD areas\n";
        print @evfsvolck;
        $EVFS_FLAG++;
    }

    my @evfsstat = `evfsadm stat -a 2>/dev/null`;

    if ( @evfsstat ) {
        print "\n$INFOSTR Encrypted File System statistics\n";
        print @evfsstat;
        $EVFS_FLAG++;
    }

    my @evfsstats = `evfsadm stat -s 2>/dev/null`;

    if ( @evfsstats ) {
        print "\n";
        print @evfsstats;
    }

    if ( ( -s $EVFSRC ) && ( -T $EVFSRC ) ) {
        if ( open( EVR, "awk NF $EVFSRC |" ) ) {
            print "\n$INFOSTR Encrypted File System $EVFSRC contents\n";
            while (<EVR>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close (EVR);
            $EVFS_FLAG++;
        }
        else {
            print "\n$WARNSTR Cannot open $EVFSRC\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $EVFSRC\n");
            $warnings++;
        }
    }
    else {
        print "\n$INFOSTR $EVFSRC is zero-length or does not exist\n";
    }

    if ( ( -s $EVFSTAB ) && ( -T $EVFSTAB ) ) {
        if ( open( EVV, "awk NF $EVFSTAB |" ) ) {
            print "\n$INFOSTR Encrypted File System $EVFSTAB contents\n";
            while (<EVV>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close (EVV);
            $EVFS_FLAG++;
        }
        else {
            print "\n$WARNSTR Cannot open $EVFSTAB\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $EVFSTAB\n");
            $warnings++;
        }
    }
    else {
        print "\n$INFOSTR $EVFSTAB is zero-length or does not exist\n";
    }

    if ( ( -s $EVFSCONF ) && ( -T $EVFSCONF ) ) {
        if ( open( EVS, "awk NF $EVFSCONF |" ) ) {
            print "\n$INFOSTR Encrypted File System $EVFSCONF contents\n";
            while (<EVS>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
            }
            close (EVS);
            $EVFS_FLAG++;
        }
        else {
            print "\n$WARNSTR Cannot open $EVFSCONF\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $EVFSCONF\n");
            $warnings++;
        }
    }
    else {
        print "\n$INFOSTR $EVFSCONF is zero-length or does not exist\n";
    }

    if ( ( -s $EVFSCRYPTX ) && ( -T $EVFSCRYPTX ) ) {
        if ( open( EVC, "awk '! /awk/ && ! /^#/ {print}' $EVFSCRYPTX |" ) ) {
            print
"\n$INFOSTR Encrypted File System cryptographic algorithms $EVFSCRYPTX\n";
            while (<EVC>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close (EVC);
            $EVFS_FLAG++;
        }
        else {
            print "\n$WARNSTR Cannot open $EVFSCRYPTX\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $EVFSCRYPTX\n");
            $warnings++;
        }
    }
    else {
        print "\n$INFOSTR $EVFSCRYPTX is zero-length or does not exist\n";
    }

    if ( $EVFS_FLAG > 0 ) {
        print "\n$INFOSTR EVFS installed and configured\n";
    }
    else {
        print "\n$INFOSTR EVFS seemingly not installed or configured\n";
    }

    datecheck();
    print_trailer("*** END CHECKING ENCRYPTED FILE SYSTEMS (EVFS) $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING NON-VXFS FILE SYSTEMS $datestring ***");

    if ( "$Minor$Patch" <= 1123 ) {
        $Standhfs = "(/stand has to be HFS)";
    }

    if ( "$vxfscount" > 0 ) {
        print "$INFOSTR Some file systems not vxfs $Standhfs\n";
        push(@CHECKARR, "\n$INFOSTR Some file systems not vxfs $Standhfs\n");
    }
    else {
        print "$INFOSTR All file systems vxfs $Standhfs\n";
    }

    print "$NOTESTR Non-fstab mounts may be cluster/automount related\n";

    datecheck();
    print_trailer("*** END CHECKING NON-VXFS FILE SYSTEMS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING ONLINE JFS $datestring ***");

    if ( @SWarray ) {
        $jfs = grep(/Advanced VxFS|MirrorDisk/, @SWarray);
    }

    @vxlicarr = `vxlicense -p 2>/dev/null | awk NF`;
    @vxlicrep = `vxlicrep -e 2>/dev/null`;
    my @vxenablef = `vxenablef 2>/dev/null`;

    if ( grep( /Mission Critical|Enterprise|HA-OE|VSE-OE|DC-OE/, $bundle ) ) {
        ( $bunset, undef ) = split( /\s+/, $bundle );
        print "$PASSSTR ADVANCED VxFS licensed through $bunset ";
        print "Operating Environment\n";
    }

    if ( @vxlicarr ) {
        if ( grep( /Feature name:.*OnlineJFS/, "@vxlicarr" ) ) {
            print "\n$INFOSTR Vxlicense status\n";
        }
        else {
            print "\n$WARNSTR According to vxlicense(1M) - OnlineJFS seemingly not installed or licensed)\n";
            $warnings++;
        }
        print "@vxlicarr";
    }

    if ( @vxlicrep ) {
        if ( grep( /OnlineJFS.*Enabled/, "@vxlicrep" ) ) {
            print "\n$INFOSTR Vxlicrep status\n";
        }
        else {
            print "\n$WARNSTR According to vxlicrep(1M) - OnlineJFS seemingly not installed or licensed)\n";
            $warnings++;
        }
        print "@vxlicrep";
    }

    if ( @vxenablef ) {
        print "\n$INFOSTR Vxenablef status\n";
        print "@vxenablef";
        print "\n";
    }

    if ( "$jfs" ) {
        if ( grep( /System is not licensed/, @vxl ) ) {
            print "\n$WARNSTR ADVANCED VxFS not licensed\n";
            push(@CHECKARR, "\n$WARNSTR ADVANCED VxFS not licensed\n");
        }
        elsif ( @vxl != 0 ) {
            print "\n$PASSSTR ADVANCED VxFS licensed\n";
            print @vxl;
        }
        else {
            print "\n$PASSSTR ADVANCED VxFS licensed\n";
            print $jfs;
        }
    }
    else {
        print "$WARNSTR ADVANCED VxFS not installed\n";
        push(@CHECKARR, "\n$WARNSTR ADVANCED VxFS not installed\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING ONLINE JFS $datestring ***");
}

# Subroutine to check system auditing
#
sub audsys {
    datecheck();
    print_header("*** BEGIN CHECKING SYSTEM AUDITING (AUDSYS) $datestring ***");

    if ( open( FROM, "audsys 2>&1 |" ) ) {
        while (<FROM>) {
            next if ( grep( /^$/, $_ ) );
            #
            # Get rid of leading and trailing empty spaces
            #
            $_ =~ s{\A \s* | \s* \z}{}gxm;
            print $_;
            if ( grep( /currently off|cannot open and lock/, $_ ) ) {
                push(@AUDARR, print "\n$WARNSTR System auditing not configured\n");
                push(@CHECKARR, "\n$WARNSTR System auditing not configured\n");
                $warnings++;
            }
        }
        close(FROM);

        if ( @AUDARR ) {
            print @AUDARR;
            print "\n";
        }

	if ( -f "$AUDNAMES" ) {
            print "\n$INFOSTR File $AUDNAMES exist (some changes to auditing RC config are ignored when this file exists!)\n";
        }

        if ( -s $AUDSITE ) { 
            my @audsite = `egrep -v ^# $AUDSITE 2>/dev/null`;
            if ( @audsite ) {
                print "\n$INFOSTR Auditing requirements in file $AUDSITE\n";
                print @audsite;
            }
        }

        if ( -s $AUDFILTER ) { 
            my @audfilter = `egrep -v ^# $AUDFILTER 2>/dev/null`;
            if ( @audfilter ) {
                print "\n$INFOSTR Auditing filters in file $AUDFILTER\n";
                print @audfilter;
            }
        }
        my @audevent = `audevent -l 2>/dev/null`;
        if ( @audevent ) {
            print "\n$INFOSTR Listing auditable events and system calls\n";
            print @audevent;
        }

        my @audrc = `egrep -v ^# $AUDRC 2>/dev/null`;
        if ( @audrc ) {
            print "\n$INFOSTR Auditing RC file $AUDRC\n";
            print @audrc;
        }
    }
    else {
        print "$INFOSTR Cannot run audsys\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SYSTEM AUDITING (AUDSYS) $datestring ***");
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
    print_trailer("*** END CHECKING DEVICE FILES $datestring ***");
}

sub diskscrub {
    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING DISK SCRUBBING (DOD 5220.22-M COMPLIANT) $datestring ***");

        my @diskscrub = `mediainit 2>&1 | grep scrub`;

        if ( @diskscrub ) {
            print "$INFOSTR Secure disk scrubbing supported\n";
            print @diskscrub;
        }
        else {
            print "$INFOSTR Secure disk scrubbing not supported\n";
        }

        datecheck();
        print_trailer("*** END CHECKING DISK SCRUBBING (DOD 5220.22-M COMPLIANT) $datestring ***");
    }
}

#
# Check initial boot RC scripts 
#
sub initboot {
    datecheck();
    print_header("*** BEGIN CHECKING INITIAL STARTUP SCRIPTS $datestring ***");

    my @Initarray  = ( '/etc/bcheckrc', '/etc/pre_init_rc', '/etc/rc.config', );

    foreach my $Confdev (@Initarray) {
        if ( -s "$Confdev" ) {
            print "$PASSSTR $Confdev exists\n";
            my @CRarrx = `awk NF $Confdev | egrep -v ^#`;
            if ( @CRarrx != 0 ) {
                print @CRarrx;
            }
        }
        else {
            print "$ERRSTR $Confdev does not exist or is zero-length\n";
            push(@CHECKARR, "\n$ERRSTR $Confdev does not exist or is zero-length\n");
            $warnings++;
        }
        print "\n";
    }

    datecheck();
    print_trailer("*** END CHECKING INITIAL STARTUP SCRIPTS $datestring ***");
}

# Subroutine to check kernel parameters
#
sub checkkernel {
    datecheck();
    print_header("*** BEGIN CHECKING KERNEL SIZE $datestring ***");

    if ( open( KFROM, "nm $KERN 2>/dev/null |" ) ) {
        while (<KFROM>) {
            next if ( grep( /^$/, $_ ) );
            if ( grep( /ABS\|_end/, $_ ) ) {
                ( undef, $KERNEND, undef ) = split( /\|/, $_ );
                #
                # Get rid of leading and trailing empty spaces
                #
                $KERNEND =~ s{\A \s* | \s* \z}{}gxm;
                chomp($KERNEND);
            }
            if ( grep( /__text_start$/, $_ ) ) {
                ( undef, $KERNSTART, undef ) = split( /\|/, $_ );
                #
                # Get rid of leading and trailing empty spaces
                #
                $KERNSTART =~ s{\A \s* | \s* \z}{}gxm;
                chomp($KERNSTART);
            }
        }
        close(KFROM);
    }
    else {
        print "$WARNSTR Cannot check kernel size\n";
        push(@CHECKARR, "\n$WARNSTR Cannot check kernel size\n");
    }

    if ( ( $KERNSTART > 0 ) && ( $KERNEND > 0 ) ) {
        $FINALKERN =
          sprintf( "%.2f", ( $KERNEND - $KERNSTART ) / ( 1024 * 1024 )  + 1 );
    }

    if ( $FINALKERN == 0 ) {
        my $KERNSIZE2 = `size $KERN 2>/dev/null | awk '{print \$NF}'`;
        chomp($KERNSIZE2);
        $FINALKERN = sprintf( "%.2f", ( $KERNSIZE2 ) / ( 1024 * 1024 ) );
    }

    if ( $FINALKERN > 0 ) {
        $kernrem = $FINALKERN % 64;
        $kernval = int( $FINALKERN / 64 );

        if ( $kernrem > 0 ) {
            $KERNSIZE = ( $kernval * 64 ) + 64;
        }
        else {
            $KERNSIZE = ( $kernval * 64 );
        }
    }

    print "$INFOSTR Actual kernel size is $FINALKERN MB\n";
    print "$INFOSTR Rounded-up kernel size is $KERNSIZE MB\n";

    print "\n$NOTESTR Although the actual size of the kernel may be smaller,\n";
    print "$NOTESTR minimum granularity for assigned memory to a partitioned\n";
    print "$NOTESTR server is multiple of 64 MB\n";

    my @footprints = `footprints $KERN 2>/dev/null`;
    if ( @footprints ) {
        print "\n$INFOSTR Compiler footprint summary for kernel $KERN\n";
        print @footprints;
    }

    my @whatkern = `what $KERN 2>/dev/null`;
    if ( @whatkern ) {
        print "\n$INFOSTR Module status for kernel $KERN\n";
        print @whatkern;
    }

    datecheck();
    print_trailer("*** END CHECKING KERNEL SIZE $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING KERNEL PARAMETERS $datestring ***");

    my @sysdef = `sysdef 2>/dev/null`;
    if ( @sysdef ) {
        print "$INFOSTR System definitions\n";
        print @sysdef;
        print "\n";
    }

    #
    # Usually, dbc_max_pct should be a percentage of RAM
    # that equals between 450 and 800 MB on HP-UX 11 v1
    # For HP-UX v2 and v3, some performance tests suggest to use
    # very high values so that all application data is
    # read once at boot and then reads become logical reads...
    #

    if ("$MEM_MBYTE") {
        $DBC_MAX_PCT = int( ( 100 * 600 ) / $MEM_MBYTE );
    }
    else {
        $DBC_MAX_PCT = 8;
    }

    if ( "$Minor$Patch" >= 1120 ) {
        open( FROM, "kctune 2>/dev/null |" ) || warn "Cannot run kctune\n";
    }
    else {
        open( FROM, "kmtune 2>/dev/null |" ) || warn "Cannot run kmtune\n";
    }

    while (<FROM>) {
        $_ =~ s/^\s+//g;
        next if ( grep( /^Tun/, $_ ) );
        print $_;

        if ( @tapes ) {
            if ( "$Minor$Patch" < 1131 ) {
                #
                # Kernel parameter st_san_safe is obsolete in HP-UX 11.31;
                # It was replaced by estape driver attribute
                # norewind_close_disabled
                #
                if ( grep( /^st_san_safe/, $_ ) ) {
                    ( undef, $fstflag, undef ) = split( /\s+/, $_ );
                    if ( $ARRFLAG > 0 ) {
                        if ( $fstflag == 0 ) {
                            push(@KERNARR,
"$WARNSTR Kernel parameter \"st_san_safe\" set to ");
                            push(@KERNARR,
"$fstflag (recommended value is 1 when SAN connected)\n");
                            push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"st_san_safe\" set to ");
                            push(@CHECKARR,
"$fstflag (recommended value is 1 when SAN connected)\n");
                            $warnings++;
                        }
                        else {
                            push(@KERNARR,
"$PASSSTR Kernel parameter \"st_san_safe\" set ");
                            push(@KERNARR,
"to $fstflag (recommended value when SAN connected)\n");
                        }
                    }
                    else {
                        if ( $fstflag == 0 ) {
                            push(@KERNARR,
"$PASSSTR Kernel parameter \"st_san_safe\" set ");
                            push(@KERNARR,
"to $fstflag (recommended value when SAN not connected)\n");
                        }
                        else {
                            push(@KERNARR,
"$WARNSTR Kernel parameter \"st_san_safe\" set to ");
                            push(@KERNARR,
"$fstflag (recommended value is 0 when SAN not connected)\n");
                            push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"st_san_safe\" set to ");
                            push(@CHECKARR,
"$fstflag (recommended value is 0 when SAN not connected)\n");
                            $warnings++;
                        }
                    }
                }
            }
            else {
                my @estapev = `scsimgr -d estape get_attr 2>/dev/null`;
                if ( @estapev ) {
                    print "\n$INFOSTR estape driver attributes\n";
                    print @estapev;
                }
            }
        }

        if ( grep( /^secure_sid_scripts/, $_ ) ) {
            ( undef, $ssidscript, undef ) = split( /\s+/, $_ );
            if ( $ssidscript == 0 ) {
                push(@KERNARR,
"$PASSSTR Kernel parameter \"secure_sid_scripts\" set to $ssidscript ");
                push(@KERNARR,
"(disables SETUID and SETGID bits on scripts)\n");
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"secure_sid_scripts\" set to $ssidscript ");
                push(@KERNARR,
"(enables SETUID and SETGID bits on scripts)\n");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"secure_sid_scripts\" set to $ssidscript ");
                push(@CHECKARR,
"(enables SETUID and SETGID bits on scripts)\n");
            }
        }

        if ( grep( /^uname_eoverflow/, $_ ) ) {
            ( undef, $eoverflow, undef ) = split( /\s+/, $_ );
            if ( $eoverflow == 1 ) {
                push(@KERNARR,
"$PASSSTR Kernel parameter \"uname_eoverflow\" set to $eoverflow ");
                push(@KERNARR, "(returns an error if hostname long)\n");
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"uname_eoverflow\" set to $eoverflow ");
                push(@KERNARR, "(long hostnames silently truncated)\n");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"uname_eoverflow\" set to $eoverflow ");
                push(@KERNARR, "(long hostnames silently truncated)\n");
            }
        }

        if ( grep( /^timeslice/, $_ ) ) {
            ( undef, $timeslice, undef ) = split( /\s+/, $_ );
            if ( $timeslice == 10 ) {
                push(@KERNARR,
"$PASSSTR Kernel parameter \"timeslice\" set to $timeslice\n");
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"timeslice\" set to $timeslice ");
                push(@KERNARR, "(if not set to 10, it can cause significant context switching)\n");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"timeslice\" set to $timeslice ");
                push(@KERNARR, "(if not set to 10, it can cause significant context switching)\n");
            }
        }

        if ( grep( /^audit_memory_usage/, $_ ) ) {
            ( undef, $audmem, undef ) = split( /\s+/, $_ );
            if ( $audmem > $MAXAUDMEMPC ) {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"audit_memory_usage\" set to $audmem ");
                push(@KERNARR,
"(above threshold of $MAXAUDMEMPC%% for audit subsystem)\n");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"audit_memory_usage\" set to $audmem ");
                push(@KERNARR,
"(above threshold of $MAXAUDMEMPC%% for audit subsystem)\n");
            }
            else {
                push(@KERNARR,
"$PASSSTR Kernel parameter \"audit_memory_usage\" set to $audmem ");
                push(@KERNARR,
"(below threshold of $MAXAUDMEMPC%% for audit subsystem)\n");
            }
        }

        if ( grep( /^st_ats_enabled/, $_ ) ) {
            ( undef, $st_ats, undef ) = split( /\s+/, $_ );
            if ( $ARRFLAG > 0 ) {
                if ( $st_ats == 0 ) {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"st_ats_enabled\" set to $st_ats ");
                    push(@KERNARR,
"(recommended value when SAN connected or Data Protector, NetBackup, and similar backups are used)\n");
                }
                else {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"st_ats_enabled\" set to $st_ats ");
                    push(@KERNARR,
"(recommended value is 0 when SAN connected or Data Protector, NetBackup, and similar backups are used)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"st_ats_enabled\" set to $st_ats ");
                    push(@CHECKARR,
"(recommended value is 0 when SAN connected or Data Protector, NetBackup, and similar backups are used)\n");
                }
            }
            else {
                if ( $st_ats == 0 ) {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"st_ats_enabled\" set to $st_ats ");
                    push(@KERNARR,
"(recommended value when not SAN connected)\n");
                }
                else {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"st_ats_enabled\" set to $st_ats ");
                    push(@KERNARR,
"(recommended value is 0 when not SAN connected)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"st_ats_enabled\" set to $st_ats ");
                    push(@CHECKARR,
"(recommended value is 0 when not SAN connected)\n");
                }
            }
        }

        if ( grep( /^numa_policy/, $_ ) ) {
            ( undef, $numapolicy, undef ) = split( /\s+/, $_ );
            chomp($numapolicy);
            if ( $numapolicy == 0 ) {
                push(@KERNARR,
"$INFOSTR Kernel parameter \"numa_policy\" set to $numapolicy (auto sense) ");
                push(@KERNARR,
"(recommended to set to 2 - Mixed mode for workloads with global references to shared data, ");
                push(@KERNARR,
"(or, set to 1 - LORA mode for vPars, SAP, Java)\n");
            }
            elsif ( $numapolicy == 1 ) {
                push(@KERNARR,
"$INFOSTR Kernel parameter \"numa_policy\" set to LORA mode $numapolicy ");
                push(@KERNARR,
"(recommended value for vPars, SAP, Java)\n");
            }
            else {
                push(@KERNARR,
"$INFOSTR Kernel parameter \"numa_policy\" set to Mixed mode $numapolicy ");
                push(@KERNARR,
"(recommended value for workloads with global references to shared data)\n");
            }
        }

        if ( grep( /^numa_mode/, $_ ) ) {
            ( undef, $numamode, undef ) = split( /\s+/, $_ );
            chomp($numamode);
            if ( $numamode == 1 ) {
                push(@KERNARR,
"$INFOSTR Kernel parameter \"numa_mode\" set to $numamode (LORA enabled)\n");
            }
            else {
                push(@KERNARR,
"$INFOSTR Kernel parameter \"numa_mode\" set to $numamode (LORA disabled)\n");
            }
        }

        if ( "$Minor$Patch" >= 1131 ) {
            if ( grep( /^dump_concurrent_on/, $_ ) ) {
                ( undef, $dumpconc, undef ) = split( /\s+/, $_ );
                if ( $dumpconc == 0 ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"dump_concurrent_on\" set to ");
                    push(@KERNARR,
"$dumpconc (recommended value is 1 to enable concurrent dumps)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"dump_concurrent_on\" set to ");
                    push(@CHECKARR,
"$dumpconc (recommended value is 1 to enable concurrent dumps)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"dump_concurrent_on\" set ");
                    push(@KERNARR,
"to $dumpconc (enable concurrent dumps)\n");
                }
            }

            if ( grep( /^dump_compress_on/, $_ ) ) {
                ( undef, $dumpcprs, undef ) = split( /\s+/, $_ );
                if ( $dumpcprs == 0 ) {
                    push(@KERNARR,
"$INFOSTR Kernel parameter \"dump_compress_on\" set to ");
                    push(@KERNARR,
"$dumpcprs (recommended value is 1 to enable compressed dumps (sometimes uncompressed dumps are needed for specific types of crashes)\n");
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"dump_compress_on\" set ");
                    push(@KERNARR,
"to $dumpcprs (enable compressed dumps)\n");
                }
            }

            if ( grep( /^lcpu_attr/, $_ ) ) {
                ( undef, $lcpuattr, undef ) = split( /\s+/, $_ );
                push(@KERNARR, "$INFOSTR Kernel parameter \"lcpu_attr\" set to ");
                if ( $lcpuattr == 0 ) {
                    push(@KERNARR, "$lcpuattr (logical CPI disabled)\n");
                }
                elsif ( $lcpuattr == 1 ) {
                    push(@KERNARR, "$lcpuattr (logical CPI enabled)\n");
                }
                else {
                    push(@KERNARR, "$lcpuattr (logical CPI disabled)\n");
                }
            }
        }

        if ( grep( /^uname_eoverflow/, $_ ) ) {
            ( undef, $eoverflag, undef ) = split( /\s+/, $_ );
            if ( $eoverflag == 0 ) {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"uname_eoverflow\" set to ");
                push(@KERNARR, "$eoverflag (recommended value is 1)\n");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"uname_eoverflow\" set to ");
                push(@CHECKARR, "$eoverflag (recommended value is 1)\n");
                $warnings++;
            }
            else {
                push(@KERNARR,
"$PASSSTR Kernel parameter \"uname_eoverflow\" set ");
                push(@KERNARR, "to $eoverflag\n");
            }
        }

        if ( grep( /^vx_maxlink/, $_ ) ) {
            ( undef, $vxmaxflag, undef ) = split( /\s+/, $_ );
        }

        if ( "$Minor$Patch" < 1131 ) {
            if ( grep( /^bufpages/, $_ ) ) {
                ( undef, $bufpagesflag, undef ) = split( /\s+/, $_ );
            }

            if ( grep( /^nbuf/, $_ ) ) {
                ( undef, $nbufflag, undef ) = split( /\s+/, $_ );
            }

            if ( grep( /^dbc_max_pct/, $_ ) ) {
                ( undef, $dbcmaxflag, undef ) = split( /\s+/, $_ );
            }

            if ( grep( /^dbc_min_pct/, $_ ) ) {
                ( undef, $dbcminflag, undef ) = split( /\s+/, $_ );
            }
        }
        else {
            if ( grep( /^filecache_max/, $_ ) ) {
                ( undef, $dbcmaxflag, undef ) = split( /\s+/, $_ );
            }

            if ( grep( /^filecache_min/, $_ ) ) {
                ( undef, $dbcminflag, undef ) = split( /\s+/, $_ );
            }
        }

        if ( grep( /^maxvgs/, $_ ) ) {
            ( undef, $maxvgsflag, undef ) = split( /\s+/, $_ );
            if ( $maxvgsflag < $THRESHOLD_MAX_VG ) {
                push(@KERNARR, "$WARNSTR Kernel parameter \"maxvgs\" set to ");
                push(@KERNARR,
"$maxvgsflag (recommended minimum is $THRESHOLD_MAX_VG)\n");
                push(@CHECKARR, "\n$WARNSTR Kernel parameter \"maxvgs\" set to ");
                push(@CHECKARR,
"$maxvgsflag (recommended minimum is $THRESHOLD_MAX_VG)\n");
                $warnings++;
            }
            else {
                push(@KERNARR, "$PASSSTR Kernel parameter \"maxvgs\" set ");
                push(@KERNARR,
"to $maxvgsflag (recommended minimum is $THRESHOLD_MAX_VG)\n");
            }
        }

        if ( "$Minor$Patch" < 1131 ) {
            if ( grep( /^scsi_max_qdepth/, $_ ) ) {
                ( undef, $scsi_max_qdepth, undef ) = split( /\s+/, $_ );
                if ( $scsi_max_qdepth < $THRESHOLD_MIN_QDEPTH ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"scsi_max_qdepth\" set to ");
                    push(@KERNARR,
"$scsi_max_qdepth (recommended minimum is $THRESHOLD_MIN_QDEPTH)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"scsi_max_qdepth\" set to ");
                    push(@CHECKARR,
"$scsi_max_qdepth (recommended minimum is $THRESHOLD_MIN_QDEPTH)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"scsi_max_qdepth\" set ");
                    push(@KERNARR,
"to $scsi_max_qdepth (recommended minimum is $THRESHOLD_MIN_QDEPTH)\n");
                }
            }
        }

        if ( grep( /^maxuprc/, $_ ) ) {
            ( undef, $maxuprcflag, undef ) = split( /\s+/, $_ );
            if ( $maxuprcflag >= $THRESHOLD_MAXUPRC_FLAG ) {
                push(@KERNARR, "$PASSSTR Kernel parameter \"maxuprc\" set ");
                push(@KERNARR,
"to $maxuprcflag (recommended minimum value is $THRESHOLD_MAXUPRC_FLAG)\n");
            }
            else {
                push(@KERNARR, "$WARNSTR Kernel parameter \"maxuprc\" set to ");
                push(@KERNARR,
"$maxuprcflag (recommended minimum value is $THRESHOLD_MAXUPRC_FLAG)\n");
                push(@CHECKARR, "\n$WARNSTR Kernel parameter \"maxuprc\" set to ");
                push(@CHECKARR,
"$maxuprcflag (recommended minimum value is $THRESHOLD_MAXUPRC_FLAG)\n");
                $warnings++;
            }
        }

        if ( grep( /^executable_stack/, $_ ) ) {
            ( undef, $execstackflag, undef ) = split( /\s+/, $_ );
            chomp($execstackflag);
            if ( $execstackflag == 0 ) {
                push(@KERNARR,
"$PASSSTR Kernel parameter \"executable_stack\" set ");
                push(@KERNARR, "to $execstackflag\n");
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"executable_stack\" set to ");
                push(@KERNARR, "$execstackflag (not 0) ");
                push(@KERNARR,
"(recommended to set to 0 (best mode) or 2 (trial mode))\n");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"executable_stack\" set to ");
                push(@CHECKARR, "$execstackflag (not 0)\n");
                $warnings++;
            }
        }

        if ( grep( /^vx_ninode/, $_ ) ) {
            ( undef, $vxninodeflag, undef ) = split( /\s+/, $_ );
            chomp($vxninodeflag);
            push(@KERNARR, "$INFOSTR Kernel parameter \"vx_ninode\" set to ");
            if ( $vxninodeflag == 0 ) {
                push(@KERNARR, "$vxninodeflag (dynamic allocation of inodes)\n");
            }
            else {
                push(@KERNARR, "$vxninodeflag\n");
            }
        }

        if ( grep( /^vxfs_bc_bufhwm/, $_ ) ) {
            ( undef, $vxfsbcbufhwm, undef ) = split( /\s+/, $_ );
            chomp($vxfsbcbufhwm);
            if ( $vxfsbcbufhwm == 0 ) {
                push(@KERNARR,
"$INFOSTR Kernel parameter \"vxfs_bc_bufhwm\" set to ");
                push(@KERNARR, "$vxfsbcbufhwm (dynamic allocation of inodes)\n");
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"vxfs_bc_bufhwm\" set to ");
                push(@KERNARR,
"$vxfsbcbufhwm (dynamic allocation not auto-tuned)\n");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"vxfs_bc_bufhwm\" set to ");
                push(@CHECKARR,
"$vxfsbcbufhwm (dynamic allocation not auto-tuned)\n");
                $warnings++;
            }
        }

        if ( "$Minor$Patch" >= 1131 ) {
            if ( grep( /^base_pagesize/, $_ ) ) {
                ( undef, $basepagesize, undef ) = split( /\s+/, $_ );
                chomp($basepagesize);
                if ( ( @VMcheck ) && ( $HPVM_FLAG > 0 ) ) {
                    if ( $basepagesize == 64 ) {
                        push(@KERNARR,
"$PASSSTR Kernel parameter \"base_pagesize\" set to ");
                        push(@KERNARR,
"$basepagesize (recommended value when VMs are configured)\n");
                    }
                    else {
                        push(@KERNARR,
"$WARNSTR Kernel parameter \"base_pagesize\" set to ");
                        push(@KERNARR,
"$basepagesize (recommended value is 64 KB when VMs are configured)\n");
                        push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"base_pagesize\" set to ");
                        push(@CHECKARR,
"$basepagesize (recommended value is 64 KB when VMs are configured)\n");
                        $warnings++;
                    }
                }
                else {
                    if ( $basepagesize != 4 ) {
                        push(@KERNARR,
"$INFOSTR Kernel parameter \"base_pagesize\" set to ");
                        push(@KERNARR,
"$basepagesize (default recommended value is 4 KB)\n");
                    }
                }
            }

            if ( grep( /^mca_recovery_on/, $_ ) ) {
                ( undef, $mcarecovery, undef ) = split( /\s+/, $_ );
                chomp($mcarecovery);
                if ( $mcarecovery == 1 ) {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"mca_recovery_on\" set to ");
                    push(@KERNARR,
"$mcarecovery (machine check aborts (MCA) enabled)\n");
                }

                if ( $mcarecovery == 0 ) {
                    push(@KERNARR,
"$INFOSTR Kernel parameter \"mca_recovery_on\" set to ");
                    push(@KERNARR,
"$mcarecovery (machine check aborts (MCA) disabled)\n");
                    push(@CHECKARR,
"\n$INFOSTR Kernel parameter \"mca_recovery_on\" set to ");
                    push(@CHECKARR,
"$mcarecovery (machine check aborts (MCA) disabled)\n");
                }
            }
        }

        if ( "$Minor$Patch" < 1131 ) {
            if ( grep( /^swapmem_on/, $_ ) ) {
                ( undef, $swapmemflag, undef ) = split( /\s+/, $_ );
                if ( $swapmemflag == 0 ) {
                    if ( ( @VMcheck ) && ( $HPVM_FLAG > 0 ) ) {
                        push(@KERNARR,
"$PASSSTR Kernel parameter \"swapmem_on\" set to ");
                        push(@KERNARR,
"$swapmemflag (0 for HP Integrity Virtual Machines and 1 for all other servers)\n");
                    }
                    else {
                        if ( $MEM_MBYTE < $tswapall ) {
                            push(@KERNARR,
"$PASSSTR Kernel parameter \"swapmem_on\" set to ");
                            push(@KERNARR,
"$swapmemflag (0 is recommended when physical memory is smaller than swap)\n");
                        } else {
                            push(@KERNARR,
"$WARNSTR Kernel parameter \"swapmem_on\" set to ");
                            push(@KERNARR, "$swapmemflag (not 1)\n");
                            push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"swapmem_on\" set to ");
                            push(@CHECKARR, "$swapmemflag (not 1)\n");
                            $warnings++;
                        }
                    }
                }
                else {
                    if ( ( @VMcheck ) && ( $HPVM_FLAG > 0 ) ) {
                        push(@KERNARR,
"$WARNSTR Kernel parameter \"swapmem_on\" set to ");
                        push(@KERNARR,
"$swapmemflag (should be 0 for HP Integrity Virtual Machines and 1 for all other servers)\n");
                        push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"swapmem_on\" set to ");
                        push(@CHECKARR,
"$swapmemflag (should be 0 for HP Integrity Virtual Machines and 1 for all other servers)\n");
                        $warnings++;
                    }
                    else {
                        if ( $MEM_MBYTE < $tswapall ) {
                            push(@KERNARR,
"$WARNSTR Kernel parameter \"swapmem_on\" set to ");
                            push(@KERNARR,
"$swapmemflag (0 is recommended when physical memory is smaller than swap)\n");
                            push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"swapmem_on\" set to ");
                            push(@CHECKARR,
"$swapmemflag (0 is recommended when physical memory is smaller than swap)\n");
                        } else {
                            push(@KERNARR,
"$PASSSTR Kernel parameter \"swapmem_on\" set ");
                            push(@KERNARR, "to $swapmemflag\n");
                        }
                    }
                }
            }
        }

        if ( grep( /^dst/, $_ ) ) {
            ( undef, $dstflag, undef ) = split( /\s+/, $_ );
            if ( $dstflag == 0 ) {
                push(@KERNARR, "$INFOSTR Kernel parameter \"dst\" set to ");
                push(@KERNARR, "$dstflag (Daylight Saving Time not enabled)\n");
                push(@CHECKARR, "\n$INFOSTR Kernel parameter \"dst\" set to ");
                push(@CHECKARR, "$dstflag (Daylight Saving Time not enabled)\n");
            }
            elsif ( $dstflag == 1 ) {
                push(@KERNARR, "$INFOSTR Kernel parameter \"dst\" set to ");
                push(@KERNARR, "$dstflag (Daylight Saving Time set to USA style)\n");
            }
            elsif ( $dstflag == 2 ) {
                push(@KERNARR, "$INFOSTR Kernel parameter \"dst\" set to ");
                push(@KERNARR,
"$dstflag (Daylight Saving Time set to Australian style)\n");
            }
            elsif ( $dstflag == 3 ) {
                push(@KERNARR, "$INFOSTR Kernel parameter \"dst\" set to ");
                push(@KERNARR,
"$dstflag (Daylight Saving Time set to Western European style)\n");
            }
            elsif ( $dstflag == 4 ) {
                push(@KERNARR, "$INFOSTR Kernel parameter \"dst\" set to ");
                push(@KERNARR,
"$dstflag (Daylight Saving Time set to Middle European style)\n");
            }
            elsif ( $dstflag == 5 ) {
                push(@KERNARR, "$INFOSTR Kernel parameter \"dst\" set to ");
                push(@KERNARR,
"$dstflag (Daylight Saving Time set to East European style)\n");
            }
            else {
                push(@KERNARR, "$WARNSTR Kernel parameter \"dst\" set ");
                push(@KERNARR, "to invalid value $dstflag\n");
                push(@CHECKARR, "\n$WARNSTR Kernel parameter \"dst\" set ");
                push(@CHECKARR, "to invalid value $dstflag\n");
            }
        }

        if ( grep( /^expanded_node_host_names/, $_ ) ) {
            ( undef, $exphostflag, undef ) = split( /\s+/, $_ );
            if ( $exphostflag == 0 ) {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"expanded_node_host_names\" set to ");
                push(@KERNARR,
"$exphostflag (recommended value is 1 for WorkLoad Manager)\n");
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"expanded_node_host_names\" set to ");
                push(@CHECKARR,
"$exphostflag (recommended value is 1 for WorkLoad Manager)\n");
                $warnings++;
            }
            else {
                push(@KERNARR,
"$PASSSTR Kernel parameter \"expanded_node_host_names\" set ");
                push(@KERNARR,
"to $exphostflag (important for WorkLoad Manager)\n");
            }
        }

        if ( grep( /^numa_policy/, $_ ) ) {
            ( undef, $numa_policy, undef ) = split( /\s+/, $_ );
            if ( $numa_policy == 0 ) {
                push(@KERNARR, "$INFOSTR Kernel parameter \"numa_policy\" set to ");
                push(@KERNARR,
"$numa_policy (recommended value is 1 for systems with lot Cell Local Memory)\n");
            }
            elsif ( $numa_policy == 1 ) {
                push(@KERNARR, "$INFOSTR Kernel parameter \"numa_policy\" set to ");
                push(@KERNARR,
"$numa_policy (recommended value for systems with lot Cell Local Memory)\n");
            }
            else {
                push(@KERNARR, "$PASSSTR Kernel parameter \"numa_policy\" set ");
                push(@KERNARR, "to $numa_policy\n");
            }
        }

        if ( grep( /^max_thread_proc/, $_ ) ) {
            ( undef, $maxthreadproc, undef ) = split( /\s+/, $_ );
            push(@KERNARR, "$INFOSTR Kernel parameter \"max_thread_proc\" set to ");
            push(@KERNARR, "$maxthreadproc\n");
        }

        if ( grep( /^nfs2_max_threads/, $_ ) ) {
            ( undef, $nfs2maxthreads, undef ) = split( /\s+/, $_ );
            push(@KERNARR, "$INFOSTR Kernel parameter \"nfs2_max_threads\" set to ");
            push(@KERNARR, "$nfs2maxthreads\n");
        }

        if ( grep( /^nfs3_max_threads/, $_ ) ) {
            ( undef, $nfs3maxthreads, undef ) = split( /\s+/, $_ );
            push(@KERNARR, "$INFOSTR Kernel parameter \"nfs3_max_threads\" set to ");
            push(@KERNARR, "$nfs3maxthreads\n");
        }

        if ( grep( /^nfs4_max_threads/, $_ ) ) {
            ( undef, $nfs4maxthreads, undef ) = split( /\s+/, $_ );
            push(@KERNARR, "$INFOSTR Kernel parameter \"nfs4_max_threads\" set to ");
            push(@KERNARR, "$nfs4maxthreads\n");
        }

        if ( grep( /^swchunk/, $_ ) ) {
            ( undef, $swchunk, undef ) = split( /\s+/, $_ );
            push(@KERNARR, "$INFOSTR Kernel parameter \"swchunk\" set to ");
            push(@KERNARR, "$swchunk\n");
        }

        if ( grep( /^maxswapchunks/, $_ ) ) {
            ( undef, $maxswapchunks, undef ) = split( /\s+/, $_ );
            push(@KERNARR, "$INFOSTR Kernel parameter \"maxswapchunks\" set to ");
            push(@KERNARR, "$maxswapchunks\n");
        }

        if ( "$Minor$Patch" >= 1131 ) {
            if ( grep( /^audit_track_paths/, $_ ) ) {
                ( undef, $iddsflag, undef ) = split( /\s+/, $_ );
                chomp($iddsflag);
                if ( $iddsflag == 1 ) {
                    push(@KERNARR,
"$PASSSTR Intrusion detection data source enabled\n");
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"audit_track_paths\" set to ");
                    push(@KERNARR, "$iddsflag\n");
                }
                else {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"audit_track_paths\" set to ");
                    push(@KERNARR, "$iddsflag (not 1)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"audit_track_paths\" set to ");
                    push(@CHECKARR, "$iddsflag (not 1)\n");
                    $warnings++;
                }
            }
        }
        else {
            if ( grep( /^enable_idds/, $_ ) ) {
                ( undef, $iddsflag, undef ) = split( /\s+/, $_ );
                chomp($iddsflag);
                if ( $iddsflag == 1 ) {
                    push(@KERNARR,
"$PASSSTR Intrusion detection data source enabled\n");
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"enable_idds\" set to ");
                    push(@KERNARR, "$iddsflag\n");
                }
                else {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"enable_idds\" set to ");
                    push(@KERNARR, "$iddsflag (not 1)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"enable_idds\" set to ");
                    push(@CHECKARR, "$iddsflag (not 1)\n");
                    $warnings++;
                }
            }
        }
    }
    close(FROM);

    if ( "$Minor$Patch" >= 1131 ) {
        my $NFILE = `kctune nfile 2>/dev/null | awk '/^nfile/ {print \$2}'`;
        chomp($NFILE);
        if ( "$NFILE" ) {
            if ( "$NFILE" != 0 ) { 
                print
"\n$INFOSTR Kernel parameter \"nfile\" parameter is private in HP-UX 11.31 and above\n";
                print "$WARNSTR Kernel parameter \"nfile\" current value is $NFILE\n";
                push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"nfile\" current value is $NFILE\n");
                push(@KERNARR,
"$WARNSTR Kernel parameter \"nfile\" current value is $NFILE (recommended to set it to \"default\")\n");
                $warnings++;
                print "$INFOSTR Recommended to set it to value \"default\"\n";
            }
        }
    }
  
    if ( "$maxswapchunks" ) { 
        $maxuswap = int(($swchunk * $maxswapchunks ) / 1024); 
    }
    else {
        $maxuswap = int(($swchunk * $maxswchunk ) / 1024); 
    }

    push(@KERNARR, "$INFOSTR Maximum usable swap is $maxuswap MB\n");

    # HP released patch PHNE_38254 for 11i v2 systems.
    # This patch automatically configures several ONC/NFS kernel
    # tunable parameters to their optimal values
    #
    # These recommendations are documented in the current copy of the
    # "Managing NFS and KRPC Kernel Configurations in HP-UX 11i v2"
    # white paper:
    #
    # http://docs.hp.com/en/10101/NFSTunablesWP.pdf
    #
    if ( ("$Minor$Patch" < 1131) && ("$Minor$Patch" >= 1120) ) {
        if ( $nfscount > 0 ) {
            $nfsavoid = `kctune nfs_async_read_avoidance_enabled 2>/dev/null | awk '! /Value/ {print \$2}'`;
            chomp($nfsavoid);
            if ( "$nfsavoid" ) {
                if ( $nfsavoid != 0 ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_async_read_avoidance_enabled\" set to ");
                    push(@KERNARR,
"$nfsavoid (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"nfs_async_read_avoidance_enabled\" set to ");
                    push(@CHECKARR,
"$nfsavoid (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"nfs_async_read_avoidance_enabled\" set ");
                    push(@KERNARR,
"to $nfsavoid (recommended value for NFS on HP-UX 11i v2 servers)\n");
                }
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_async_read_avoidance_enabled\" does not exist ");
                push(@KERNARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                push(@CHECKARR,
"$WARNSTR Kernel parameter \"nfs_async_read_avoidance_enabled\" does not exist ");
                push(@CHECKARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                $warnings++;
            }

            $nfsfinegrain = `kctune nfs_fine_grain_fs_lock 2>/dev/null | awk '! /Value/ {print \$2}'`;
            chomp($nfsfinegrain);
            if ( "$nfsfinegrain" ) {
                if ( $nfsfinegrain != 2 ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_fine_grain_fs_lock\" set to ");
                    push(@KERNARR,
"$nfsfinegrain (recommended value is 2 for NFS on HP-UX 11i v2 servers)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"nfs_fine_grain_fs_lock\" set to ");
                    push(@CHECKARR,
"$nfsfinegrain (recommended value is 2 for NFS on HP-UX 11i v2 servers)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"nfs_fine_grain_fs_lock\" set ");
                    push(@KERNARR,
"to $nfsfinegrain (recommended value for NFS on HP-UX 11i v2 servers)\n");
                }
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_fine_grain_fs_lock\" does not exist ");
                push(@KERNARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                push(@CHECKARR,
"$WARNSTR Kernel parameter \"nfs_fine_grain_fs_lock\" does not exist ");
                push(@CHECKARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                $warnings++;
            }

            $nfsnewlock = `kctune nfs_new_lock_code 2>/dev/null | awk '! /Value/ {print \$2}'`;
            chomp($nfsnewlock);
            if ( "$nfsnewlock" ) {
                if ( $nfsnewlock != 1 ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_new_lock_code\" set to ");
                    push(@KERNARR,
"$nfsnewlock (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"nfs_new_lock_code\" set to ");
                    push(@CHECKARR,
"$nfsnewlock (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"nfs_new_lock_code\" set ");
                    push(@KERNARR,
"to $nfsnewlock (recommended value for NFS on HP-UX 11i v2 servers)\n");
                }
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_new_lock_code\" does not exist ");
                push(@KERNARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                push(@CHECKARR,
"$WARNSTR Kernel parameter \"nfs_new_lock_code\" does not exist ");
                push(@CHECKARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                $warnings++;
            }

            $nfsnewrnode = `kctune nfs_new_rnode_lock_code 2>/dev/null | awk '! /Value/ {print \$2}'`;
            chomp($nfsnewrnode);
            if ( "$nfsnewrnode" ) {
                if ( $nfsnewrnode != 1 ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_new_rnode_lock_code\" set to ");
                    push(@KERNARR,
"$nfsnewrnode (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"nfs_new_rnode_lock_code\" set to ");
                    push(@CHECKARR,
"$nfsnewrnode (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"nfs_new_rnode_lock_code\" set ");
                    push(@KERNARR,
"to $nfsnewrnode (recommended value for NFS on HP-UX 11i v2 servers)\n");
                }
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_new_rnode_lock_code\" does not exist ");
                push(@KERNARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                push(@CHECKARR,
"$WARNSTR Kernel parameter \"nfs_new_rnode_lock_code\" does not exist ");
                push(@CHECKARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                $warnings++;
            }

            $nfswakeup = `kctune nfs_wakeup_one 2>/dev/null | awk '! /Value/ {print \$2}'`;
            chomp($nfswakeup);
            if ( "$nfswakeup" ) {
                if ( $nfswakeup != 2 ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_wakeup_one\" set to ");
                    push(@KERNARR,
"$nfswakeup (recommended value is 2 for NFS on HP-UX 11i v2 servers)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"nfs_wakeup_one\" set to ");
                    push(@CHECKARR,
"$nfswakeup (recommended value is 2 for NFS on HP-UX 11i v2 servers)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"nfs_wakeup_one\" set ");
                    push(@KERNARR,
"to $nfswakeup (recommended value for NFS on HP-UX 11i v2 servers)\n");
                }
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_wakeup_one\" does not exist ");
                push(@KERNARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                push(@CHECKARR,
"$WARNSTR Kernel parameter \"nfs_wakeup_one\" does not exist ");
                push(@CHECKARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                $warnings++;
            }

            $nfsnewacache = `kctune nfs3_new_acache 2>/dev/null | awk '! /Value/ {print \$2}'`;
            chomp($nfsnewacache);
            if ( "$nfsnewacache" ) {
                if ( $nfsnewacache != 1 ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs3_new_acache\" set to ");
                    push(@KERNARR,
"$nfsnewacache (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"nfs3_new_acache\" set to ");
                    push(@CHECKARR,
"$nfsnewacache (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"nfs3_new_acache\" set ");
                    push(@KERNARR,
"to $nfsnewacache (recommended value for NFS on HP-UX 11i v2 servers)\n");
                }
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs3_new_acache\" does not exist ");
                push(@KERNARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                push(@CHECKARR,
"$WARNSTR Kernel parameter \"nfs3_new_acache\" does not exist ");
                push(@CHECKARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                $warnings++;
            }

            $nfsexportfs = `kctune nfs_exportfs_rwlock 2>/dev/null | awk '! /Value/ {print \$2}'`;
            chomp($nfsexportfs);
            if ( "$nfsexportfs" ) {
                if ( $nfsexportfs != 1 ) {
                    push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_exportfs_rwlock\" set to ");
                    push(@KERNARR,
"$nfsexportfs (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"nfs_exportfs_rwlock\" set to ");
                    push(@CHECKARR,
"$nfsexportfs (recommended value is 1 for NFS on HP-UX 11i v2 servers)\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR,
"$PASSSTR Kernel parameter \"nfs_exportfs_rwlock\" set ");
                    push(@KERNARR,
"to $nfsexportfs (recommended value for NFS on HP-UX 11i v2 servers)\n");
                }
            }
            else {
                push(@KERNARR,
"$WARNSTR Kernel parameter \"nfs_exportfs_rwlock\" does not exist ");
                push(@KERNARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                push(@CHECKARR,
"$WARNSTR Kernel parameter \"nfs_exportfs_rwlock\" does not exist ");
                push(@CHECKARR,
"(recommended for NFS on HP-UX 11i v2 servers)\n");
                $warnings++;
            }
        }
    }

    if ( $maxthreadproc > 0 ) {
        if ( $nfs2maxthreads > 0 ) {
            my $nfs2maxfs = int($maxthreadproc / $nfs2maxthreads);
            if ( $nfs2maxfs > 0 ) {
                push(@KERNARR,
"$INFOSTR Maximum number of NFS v2 file systems that can be mounted is $nfs2maxfs (ratio betweeen \"max_thread_proc\" and \"nfs2_max_threads\" kernel parameters)\n");
            }
        }

        if ( $nfs3maxthreads > 0 ) {
            my $nfs3maxfs = int($maxthreadproc / $nfs3maxthreads);
            if ( $nfs3maxfs > 0 ) {
                push(@KERNARR,
"$INFOSTR Maximum number of NFS v3 file systems that can be mounted is $nfs3maxfs (ratio betweeen \"max_thread_proc\" and \"nfs3_max_threads\" kernel parameters)\n");
            }
        }

        if ( $nfs4maxthreads > 0 ) {
            my $nfs4maxfs = int($maxthreadproc / $nfs4maxthreads);
            if ( $nfs4maxfs > 0 ) {
                push(@KERNARR,
"$INFOSTR Maximum number of NFS v4 file systems that can be mounted is $nfs4maxfs (ratio betweeen \"max_thread_proc\" and \"nfs4_max_threads\" kernel parameters)\n");
            }
        }
    }

    if ( @KERNARR ) {
        print "\n";
        print @KERNARR;
    }

    datecheck();
    print_trailer("*** END CHECKING KERNEL PARAMETERS $datestring ***");

    if ( "$Minor$Patch" < 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING RECOMENDED KERNEL AND BUFFER PAGES ALLOCATION $datestring ***");

        if ( "$bufpagesflag" == 0 ) {
            if ( "$nbufflag" == 0 ) {
                push(@KERNARR2, "$INFOSTR Dynamic buffer cache enabled\n");
                if ( $dbcmaxflag < $DBC_MAX_PCT ) {
                    push(@KERNARR2,
"$WARNSTR Kernel parameter \"dbx_max_pct\" set to $dbcmaxflag");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"dbx_max_pct\" set to $dbcmaxflag");
                    $warnings++;
                }
                else {
                    push(@KERNARR2,
"$PASSSTR Kernel parameter \"dbc_max_pct\" set to $dbcmaxflag\n");
                }

                if ( $dbcminflag < $DBC_MIN_PCT ) {
                    push(@KERNARR2,
"$WARNSTR Kernel parameter \"dbc_min_pct\" set to $dbcminflag\n");
                    push(@CHECKARR,
"\n$WARNSTR Kernel parameter \"dbc_min_pct\" set to $dbcminflag\n");
                    $warnings++;
                }
                else {
                    push(@KERNARR2,
"$PASSSTR Kernel parameter \"dbc_min_pct\" set to $dbcminflag\n");
                }
            }
            else {
                $Bootbuff = $nbufflag * 2;
                push(@KERNARR2,
"$INFOSTR Allocated $Bootbuff pages of buffer pool and $nbufflag buffer headers at boot time\n");
            }
        }
        else {
            push(@KERNARR2,
"$INFOSTR $bufpagesflag set to non-zero value (\"dbc_min_pct\" and \"dbc_mac_pct\" parameters are ignored)\n");
            if ( "$nbufflag" == 0 ) {
                $Bootbuff  = $bufpagesflag / 2;
                my $Bootnbuff = $bufpagesflag * 4;
                push(@KERNARR2,
"$INFOSTR Allocated $Bootbuff pages of buffer pool and $Bootnbuff buffer headers at boot time\n");
            }
            else {
                push(@KERNARR2,
"$INFOSTR Allocated $bufpagesflag pages of buffer pool and $nbufflag buffer headers at boot time\n");
            }
        }

        if ( "$nbufflag" != 0 ) {
            push(@KERNARR2,
"$INFOSTR $nbufflag set to non-zero value (\"dbc_min_pct\" and \"dbc_mac_pct\" parameters are ignored)\n");
        }

        if ( @KERNARR2 ) {
            print @KERNARR2;
        }

        datecheck();
        print_trailer("*** END CHECKING RECOMENDED KERNEL AND BUFFER PAGES ALLOCATION $datestring ***");
    }

    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING MACHINE CHECK ABORTS (MCA) $datestring ***");

        if ( $mcarecovery == 1 ) {
            print "$PASSSTR Kernel parameter \"mca_recovery_on\" set to ";
            print "$mcarecovery (MCA enabled)\n";
        } 
        elsif ( $mcarecovery == 0 ) {
            print "$INFOSTR Kernel parameter \"mca_recovery_on\" set to ";
            print "$mcarecovery (MCA disabled)\n";
        }
        else {
            print "$INFOSTR Kernel parameter \"mca_recovery_on\" not defined\n";
        }

        datecheck();
        print_trailer("*** END CHECKING MACHINE CHECK ABORTS (MCA) $datestring ***");
    }

    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING TUNE-N-TOOL OPTIMIZATION STATUS $datestring ***");

        my @tuneserver = `tuneserver -l 2>/dev/null`;
        if ( @tuneserver ) {
            print @tuneserver;
        }
        else {
            print "$INFOSTR Tune-N-Tool seemingly not installed\n";
        }

        datecheck();
        print_trailer("*** END CHECKING TUNE-N-TOOL OPTIMIZATION STATUS $datestring ***");

        datecheck();
        print_header("*** BEGIN CHECKING SHADOW PASSWORD LENGTH LIMITS $datestring ***");

        if ( "$LONGPASS_FLAG" > 1 ) {
            print "$INFOSTR LongPass11i3 and PHI11i3 seemingly installed\n";
            print @LPASSARR;
        }
        elsif ( "$LONGPASS_FLAG" > 0 ) {
            print "$INFOSTR LongPass11i3 or PHI11i3 seemingly not installed\n";
            if ( ("$TCB") || ("$TCB2") ) {
               print "$NOTESTR Without TCB, only the first 8 characters are significant\n";
               print "$INFOSTR Long passwords not supported\n";
            }
        }
        else {
            print "$INFOSTR LongPass11i3 and PHI11i3 seemingly not installed\n";
            if ( ("$TCB") || ("$TCB2") ) {
               print "$NOTESTR Without TCB, only the first 8 characters are significant\n";
               print "$INFOSTR Long passwords not supported\n";
            }
        }

        datecheck();
        print_trailer("*** END CHECKING SHADOW PASSWORD LENGTH LIMITS $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING KERNEL MODULES $datestring ***");

    if ( -s "$DEFSYSTEM" ) {
        my @ksystem = `cat $DEFSYSTEM 2>/dev/null`;
        if ( @ksystem ) {
            print "$INFOSTR Kernel config file $DEFSYSTEM\n";
            print @ksystem;
            print "\n";
        }
    }

    if ( "$Minor$Patch" >= 1123 ) {
        my @kcmod = `kcmodule 2>/dev/null`;
        if ( @kcmod != 0 ) {
            print @kcmod;
        }
        else {
            print "$WARNSTR Kernel modules cannot be listed\n";
            push(@CHECKARR, "\n$WARNSTR Kernel modules cannot be listed\n");
            $warnings++;
        }

        my @kconfigs = `kconfig -S 2>/dev/null`;
        if ( @kconfigs ) {
            print
"\n$INFOSTR Non-default settings for running kernel configuration\n";
            print @kconfigs;
        }

        my @kconfigd = `kconfig -D 2>/dev/null`;
        if ( @kconfigd ) {
            print "\n$INFOSTR Pending kernel changes\n";
            print @kconfigd;
        }

        my @kcmoduled = `kcmodule -D 2>/dev/null`;
        if ( @kcmoduled ) {
            print "\n$INFOSTR Pending module changes in the nextboot kernel\n";
            print @kcmoduled;
        }

        my @kctuned = `kctune -D 2>/dev/null`;
        if ( @kctuned ) {
            print "\n$INFOSTR Pending tunable changes in the nextboot kernel\n";
            print @kctuned;
        }

        my @kctuneg = `kctune -g 2>/dev/null`;
        if ( @kctuneg ) {
            print "\n$INFOSTR Group related kernel tunables\n";
            print @kctuneg;
        }
    }
    else {
        my @Kmodarr = `kmsystem 2>/dev/null`;
        if ( @Kmodarr != 0 ) {
            print @Kmodarr;
        }
        else {
            print "$WARNSTR Kernel modules cannot be listed\n";
            push(@CHECKARR, "\n$WARNSTR Kernel modules cannot be listed\n");
        }
    }

    my @kcalarm = `kcalarm -m status 2>/dev/null`;
    if ( @kcalarm ) {
        print "\n$INFOSTR Kernel parameters alarm setup\n";
        print @kcalarm;
    
        my @kcalarm2 = `kcalarm 2>/dev/null`;
        if ( @kcalarm2 ) {
            print "\n$INFOSTR Kernel parameters alarm thresholds\n";
            print @kcalarm2;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING KERNEL MODULES $datestring ***");

    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING KERNEL USAGE $datestring ***");

        my @kcusage = `kcusage -d 2>/dev/null`;
        print @kcusage;

        datecheck();
        print_trailer("*** END CHECKING KERNEL USAGE $datestring ***");
    }
}

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
            push(@CHECKARR, "\n$WARNSTR Daemon $x running (recommendation is to ");
            push(@CHECKARR, "disable it)\n");
            $warnings++;
        }
        else {
            print "$PASSSTR Daemon $x not running\n";
        }
    }

    foreach $a (@Dmust) {
        my @cky = grep( /$a/, @allprocesses );
        if ( @cky != 0 ) {
            print "$PASSSTR Daemon $a running\n";
            if ( "$a" eq "syslogd" ) {
                if ( open( FROM, "egrep -v ^# $ssd 2>/dev/null |" ) ) {
                    while (<FROM>) {
                        chomp;

                        next if ( grep( /^$/, $_ ) );

                        if ( grep( /^SYSLOGD_OPTS/, $_ ) ) {
                            if ( grep( /-N/, $_ ) ) {
                                print "$PASSSTR Daemon flags for $a set up ";
                                print
"correctly in $ssd (flag \"-N\" - do not listen to socket)\n";
                                $Secure_SYSLOGD = 1;
                            }
                            else {
                                print
"$WARNSTR Daemon flags for $a not set up ";
                                print
"correctly in $ssd (flag \"-N\" missing for not to listen to socket)\n";
                                push(@CHECKARR,
"\n$WARNSTR Daemon flag \"-N\" for $a not set up in $ssd\n");
                                $warnings++;
                            }
                        }

                        if ( "$Minor$Patch" >= 1123 ) {
                            if ( grep( /^LOG_SIZE/, $_ ) ) {
                                print "$PASSSTR $a set up ";
                                print
"correctly in $ssd (option \"LOG_SIZE\" for syslogd file size grow limit)\n";
                                $LOG_SIZE_FLAG++;
                            }
                        }
                    }
                    close(FROM);
                }
                else {
                    print "$WARNSTR Configuration file missing ($ssd)\n";
                    push(@CHECKARR, "\n$WARNSTR Configuration file missing ($ssd)\n");
                }

                if ( "$Minor$Patch" >= 1123 ) {
                    if ( $LOG_SIZE_FLAG == 0 ) {
                        print "$WARNSTR $a not set up ";
                        print
"correctly in $ssd (option \"LOG_SIZE\" missing for syslogd file size grow limit)\n";
                        push(@CHECKARR,
"\n$WARNSTR Option \"LOG_SIZE\" missing for syslogd file size grow limit $a not set up in $ssd\n");
                        $warnings++;
                    }
                }

                if ( grep( /\-N/, @cky ) ) {
                    print "$PASSSTR Daemon $a running without socket ";
                    print "(flag \"-N\")\n";
                }
                else {
                    print "$WARNSTR Daemon $a not running without socket ";
                    print "(flag \"-N\" missing)\n";
                    push(@CHECKARR,
"\n$WARNSTR Daemon $a not running without socket ");
                    push(@CHECKARR, "(flag \"-N\" missing)\n");
                    $warnings++;
                }

                if ( grep( /\-r/, @cky ) ) {
                    print
"$WARNSTR Daemon $a does not suppress duplicate messages ";
                    print "(flag \"-r\" exists)\n";
                    push(@CHECKARR,
"\n$WARNSTR Daemon $a does not suppress duplicate messages ");
                    push(@CHECKARR, "(flag \"-r\" exists)\n");
                    $warnings++;
                }
                else {
                    print "$PASSSTR Daemon $a suppresses duplicate messages ";
                    print "(flag \"-r\" missing)\n";
                }
            }

            if ( "$a" eq "inetd" ) {
                if ( ( -s "$inetd" ) && ( -T "$inetd" ) ) {
                    if ( open( FROM,
                        "awk '! /^#/ && ! /awk/ && /INETD_ARGS/ {print}' $inetd |" ) ) {
                        while (<FROM>) {
                            chomp;
                            next if ( grep( /^$/, $_ ) );
                            if ( "$Minor$Patch" >= 1131 ) {
                                if ( grep( /-p/, $_ ) ) {
                                    print
"$PASSSTR Daemon flags for $a set up correctly ";
                                    print
"in $inetd (flag \"-p\" to limit number of processes)\n";
                                }
                                else {
                                    print
"$WARNSTR Daemon flags for $a not set up ";
                                    print
"correctly in $inetd (flag \"-p\" missing to limit number of processes)\n";
                                    push(@CHECKARR,
"\n$WARNSTR Daemon flags for $a not set up ");
                                    push(@CHECKARR,
"correctly in $inetd (flag \"-p\" missing to limit number of processes)\n");
                                    $warnings++;
                                }
                            } 

                            if ( "$Minor$Patch" >= 1131 ) {
                                if ( grep( /-a/, $_ ) ) {
                                    print
"$PASSSTR Daemon flags for $a set up correctly ";
                                    print
"in $inetd (flag \"-a\" to enable user-level auditing of processes)\n";
                                }
                                else {
                                    print
"$WARNSTR Daemon flags for $a not set up ";
                                    print
"correctly in $inetd (flag \"-a\" missing to enable user-level auditing of processes)\n";
                                    push(@CHECKARR,
"\n$WARNSTR Daemon flags for $a not set up ");
                                    push(@CHECKARR,
"correctly in $inetd (flag \"-a\" missing to enable user-level auditing of processes)\n");
                                    $warnings++;
                                }
                            }

                            if ( grep( /-l/, $_ ) ) {
                                print
"$PASSSTR Daemon flags for $a set up correctly ";
                                print
"in $inetd (flag \"-l\" to enable logging)\n";
                            }
                            else {
                                print "$WARNSTR Daemon flags for $a not set up ";
                                print
"correctly in $inetd (flag \"-l\" missing to enable logging)\n";
                                push(@CHECKARR,
"\n$WARNSTR Daemon flags for $a not set up ");
                                push(@CHECKARR,
"correctly in $inetd (flag \"-l\" missing to enable logging)\n");
                                $warnings++;
                            }
                        }
                        close(FROM);
                    }
                    else {
                        print "$WARNSTR Cannot open $inetd\n";
                        push(@CHECKARR, "\n$WARNSTR Cannot open $inetd\n");
                        $warnings++;
                    }
                }
                else {
                    print "$WARNSTR $inetd does not exist or is zero-length\n";
                    push(@CHECKARR, "\n$WARNSTR $inetd does not exist or is zero-length\n");
                    $warnings++;
                }

                if ( grep( /\-l/, @cky ) ) {
                    print "$PASSSTR Daemon $a running with logging ";
                    print "(flag \"-l\")\n";
                }
                else {
                    print "$WARNSTR Daemon $a not running with logging ";
                    print "(flag \"-l\" missing)\n";
                    push(@CHECKARR,
"\n$WARNSTR Daemon $a not running with logging ");
                    push(@CHECKARR, "(flag \"-l\" missing)\n");
                    $warnings++;
                }
            }
        }
        else {
            if ( "$a" ne "syslog-ng" ) {
                print "$WARNSTR Daemon $a not running\n";
                push(@CHECKARR, "\n$WARNSTR Daemon $a not running\n");
                $warnings++;
            }
        }
    }

    datecheck();
    print_trailer("*** END CHECKING CRITICAL DAEMONS $datestring ***");
}

# Subroutine to check root's crontab
#
sub ROOT_CRON {
    datecheck();
    print_header("*** BEGIN CHECKING ROOT CRON TASKS $datestring ***");

    if ( ( -s "$CRFILE" ) && ( -T "$CRFILE" ) ) {
        @CRarr2 = `awk NF $CRFILE 2>/dev/null`;
        print "$PASSSTR Crontab $CRFILE exists and in ASCII format\n";
    }
    else {
        print "$INFOSTR Crontab $CRFILE does not exist or is zero-length, or not in ASCII format\n";
    }

    @CRarr3 = `crontab -l 2>/dev/null`;

    if ( @CRarr2 ) {
        @CRarr = @CRarr2;
    }
    else {
        if ( @CRarr3 ) {
            @CRarr = @CRarr3;
        }
    }

    if ( @CRarr != 0 ) {
        print "\n$PASSSTR Crontab for root exists\n\n";
        print @CRarr;
    }
    else {
        print "\n$INFOSTR Crontab for root does not exist or is zero-length\n";
    }

    datecheck();
    print_trailer("*** END CHECKING ROOT CRON TASKS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING NON-ROOT CRON TASKS $datestring ***");

    my @nonrootcron = `ls $CRDIR | egrep -v root 2>/dev/null`;
    my $nonroot = q{}; 
    if ( @nonrootcron ) {
        foreach $nonroot (@nonrootcron) {
            chomp($nonroot);
            if ( ( -s "$CRDIR/$nonroot" ) && ( -T "$CRDIR/$nonroot" ) ) { 
                my @nrcron = `awk NF $CRDIR/$nonroot`;
                if ( @nrcron ) {
                    print "$INFOSTR Cron tasks for $nonroot\n";
                    print @nrcron;
                    print "\n";
                }
            }
        }
    }
    else {
        print "$INFOSTR Cron tasks for non-root accounts not defined\n";
    }

    datecheck();
    print_trailer("*** END CHECKING NON-ROOT CRON TASKS $datestring ***");
}

# Subroutine to check cron ACLs
#
sub cron_access {
    datecheck();
    print_header("*** BEGIN CHECKING CRON ACCESS LIST $datestring ***");

    if ( -s $CRON_DENY ) {
        if ( open( CD, "egrep -v ^# $CRON_DENY 2>/dev/null |" ) ) {
            print "$INFOSTR $CRON_DENY:\n";
            while (<CD>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;
            }
            close(CD);
        }
        else {
            print "$ERRSTR Cannot open $CRON_DENY\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $CRON_DENY\n");
            $warnings++;
        }
    }
    else {
        print "$ERRSTR $CRON_DENY is zero-length or missing\n";
        push(@CHECKARR, "\n$ERRSTR $CRON_DENY is zero-length or missing\n");
        $warnings++;
    }

    if ( -s $CRON_ALLOW ) {
        if ( open( CA, "egrep -v ^# $CRON_ALLOW 2>/dev/null |" ) ) {
            print "\n$INFOSTR $CRON_ALLOW:\n";
            while (<CA>) {
                next if ( grep( /^$/, $_ ) );
                #
                # Get rid of leading and trailing empty spaces
                #
                $_ =~ s/^\s+//g;
                print $_;
            }
            close(CA);
        }
        else {
            print "\n$ERRSTR Cannot open $CRON_ALLOW\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $CRON_ALLOW\n");
            $warnings++;
        }
    }
    else {
        print "\n$ERRSTR $CRON_ALLOW is zero-length or missing\n";
        push(@CHECKARR, "\n$ERRSTR $CRON_ALLOW is zero-length or missing\n");
        $warnings++;
    }

    if ( -s $AT_DENY ) {
        if ( open( AD, "egrep -v ^# $AT_DENY 2>/dev/null |" ) ) {
            print "\n$INFOSTR $AT_DENY:\n";
            while (<AA>) {
                next if ( grep( /^$/, $_ ) );
                #
                # Get rid of leading and trailing empty spaces
                #
                $_ =~ s/^\s+//g;
                print $_;
            }
            close(AD);
        }
        else {
            print "\n$ERRSTR Cannot open $AT_DENY\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $AT_DENY\n");
            $warnings++;
        }
    }
    else {
        print "\n$ERRSTR $AT_DENY is zero-length or missing\n";
        push(@CHECKARR, "\n$ERRSTR $AT_DENY is zero-length or missing\n");
        $warnings++;
    }

    if ( -s $AT_ALLOW ) {
        if ( open( AA, "egrep -v ^# $AT_ALLOW 2>/dev/null |" ) ) {
            print "\n$INFOSTR $AT_ALLOW:\n";
            while (<AA>) {
                next if ( grep( /^$/, $_ ) );
                #
                # Get rid of leading and trailing empty spaces
                #
                $_ =~ s/^\s+//g;
                print $_;
            }
            close(AA);
        }
        else {
            print "\n$ERRSTR Cannot open $AT_ALLOW\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $AT_ALLOW\n");
            $warnings++;
        }
    }
    else {
        print "\n$ERRSTR $AT_ALLOW is zero-length or missing\n";
        push(@CHECKARR, "\n$ERRSTR $AT_ALLOW is zero-length or missing\n");
        $warnings++;
    }

    if ( ( -s @QDCAT ) && ( -T @QDCAT ) ) {
        my @QDCAT = `cat $QUEDEFS 2>/dev/null`; 
        if ( @QDCAT ) {
            print "$INFOSTR $QUEDEFS:\n";
            print @QDCAT;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING CRON ACCESS LIST $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING CRON LOG $datestring ***");

    if ( -s "$CRONLOG" ) {
        print "$INFOSTR $CRONLOG not zero-length (listing 500 most recent entries)\n";
        my @crlog = `tail -500 $CRONLOG 2>/dev/null`;
        if ( @crlog ) {
            print @crlog;
        }
    }
    else {
        print "$INFOSTR $CRONLOG is zero-length or does not exist\n";
    }

    datecheck();
    print_trailer("*** END CHECKING CRON LOG $datestring ***");
}

# Subroutine to check syslogging
#
sub DMESG_IN_CRON {
    datecheck();
    print_header("*** BEGIN CHECKING DMESG LOGGING TO MESSAGES IN CRON $datestring ***");

    print "$INFOSTR Crontab entry should be \"10 * * * * /usr/sbin/dmesg ";
    print "- >> $MSGFILE\"\n";
    print "or \"0,10,20,30,40,50 * * * * /usr/sbin/dmesg - >> $MSGFILE\"\n";

    my $zz = q{};
    if ( ( -s "$CRFILE" ) && ( -T "$CRFILE" ) ) {
        $zz =
`awk '! /^#/ && ! /awk/ && /dmesg/ && /messages/ {print}' $CRFILE`;
    }
    else {
        $zz =
`crontab -l | awk '! /^#/ && ! /awk/ && /dmesg/ && /messages/ {print}'`;
    }

    if ("$zz") {
        print "\n$PASSSTR Crontab entry for dmesg to write to $MSGFILE\n";
        if ( grep(/>>/, $zz ) ) {
            print
"\n$PASSSTR Crontab entry for dmesg does not overwrite $MSGFILE (\">>\" used to redirect log entries)\n";
        }
        else {
            print
"\n$ERRSTR Crontab entry for dmesg overwrites $MSGFILE (\">\" used to redirect log entries, instead of \">>\")\n";
            push(@CHECKARR,
"\n$ERRSTR Crontab entry for dmesg overwrites $MSGFILE (\">\" used to redirect log entries, instead of \">>\")\n");
        }
    }
    else {
        print
"\n$WARNSTR Crontab entry for dmesg to write to $MSGFILE not set\n";
        push(@CHECKARR,
"\n$WARNSTR Crontab entry for dmesg to write to $MSGFILE not set\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING DMESG LOGGING TO MESSAGES IN CRON $datestring ***");
}

# Subroutine to check interrupts 
#
sub INTCTL_SCAN {
    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING INTERRUPT CONFIGURATION $datestring ***");

        if ( open( INTC, "intctl | awk NF |" ) ) {
            while (<INTC>) {
                if ( grep(/Interrupt migration feature not supported/, $_) ) {
                    push (@INTWARN, "$WARNSTR $_\n");
                } else {
                    print $_;
                    $INTCTL_FLAG++;
                    chomp($_);
                }

                (
                    $HWPATH, $CLASS, $DRVNAME, $CARDCELL, $CPUID,
                    $CPUCELL, $INTRTYPE, $INTRID, $CARDDESC
                ) = split( /\s+/, $_ );

                if ( "$CARDCELL" != "$CPUCELL" ) {
                    push (@INTWARN,
"$WARNSTR $DRVNAME in class $CLASS (hardware path $HWPATH) belongs to ");
                    push (@INTWARN,
"different Card and CPU cells ($CARDCELL and $CPUCELL respectively)\n");
                    push (@INTWARN,
"$NOTESTR For best performance, it is always best to\n");
                    push (@INTWARN,
"$NOTESTR allocate resources within the same cell!\n\n");
                    push(@CHECKARR,
"\n$WARNSTR $DRVNAME in class $CLASS (hardware path $HWPATH) belongs to ");
                    push(@CHECKARR,
"different Card and CPU cells ($CARDCELL and $CPUCELL respectively)\n");
                }
            }
            close(INTC);

            if ( @INTWARN ) {
                print "\n";
                print @INTWARN;
            } 
        }
        else {
            print "$WARNSTR Cannot run command intctl\n";
            push(@CHECKARR, "\n$WARNSTR Cannot run command intctl\n");
        }

        if ( $INTCTL_FLAG == 0 ) {
            print "$WARNSTR Interrupt migration feature not supported\n";
        } 

        datecheck();
        print_trailer("*** END CHECKING INTERRUPT CONFIGURATION $datestring ***");
    }
}

# Subroutine to check ioscan
#
sub IOSCAN_NO_HW {
    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING STALE DEVICES $datestring ***");

        @stale = `ioscan -s 2>/dev/null`;
        if ( @stale ) {
            print "$WARNSTR Ioscan stale devices found\n";
            print @stale;
        }
        else {
            print "$PASSSTR No ioscan stale devices found\n";
        }

        my @lssfstale = `lssf -s 2>/dev/null | awk NF`;
        if ( @lssfstale ) {
            print "\n$WARNSTR Lssf stale devices found\n";
            print @lssfstale;
        }
        else {
            print "\n$PASSSTR No lssf stale devices found\n";
        }

        datecheck();
        print_trailer("*** END CHECKING STALE DEVICES $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING IOSCAN $datestring ***");

    if ( $IOSCAN_FLAG > 0 ) {
        print "$INFOSTR Hardware ioscan already initiated by some other process\n";
        print "$NOTESTR Multiple ioscans typically relate to faulty devices\n\n";
        $IOSCANADD = "-k";
    }

    foreach my $iodev ( @IOCONFIGARR ) {
        chomp($iodev);
        ( $idev,   $iino,     $imode, $inlink, $iuid,
          $igid,   $irdev,    $isize, $iatime, $imtime,
          $ictime, $iblksize, $iblocks,
        ) = stat($iodev);

        my $ifile_perms = $imode & 0777;
        my $ioct_perms = sprintf "%lo", $ifile_perms;

        if ( $ioct_perms != "644" ) {
            print
"$WARNSTR Security risk: $iodev permissions not 644 ($ioct_perms)\n";
            push(@CHECKARR,
"\n$WARNSTR Security risk: $iodev permissions not 644 ($ioct_perms)\n");
            $warnings++;
        }
        else {
            print "$PASSSTR $iodev permissions are 644\n";
        }

        if ( "$iuid" == 0 ) {
            print "\n$PASSSTR $iodev owned by UID $iuid\n";
        }
        else {
            print "\n$WARNSTR $iodev not owned by UID 0 ($iuid)\n";
            push(@CHECKARR, "\n$WARNSTR $iodev not owned by UID 0 ($iuid)\n");
            $warnings++;
        }
    }

    my @ioscant = `ioscan -t 2>/dev/null`;
    if ( @ioscant ) {
        print "\n$INFOSTR Time of last hardware scan\n";
        print @ioscant;
    }

    my @ioscanFA = `ioscan -${IOSCANADD}FA 2>/dev/null`;
    if ( @ioscanFA ) {
        print "\n$INFOSTR Ioscan with alias path\n";
        print @ioscanFA;
    }

    my @ioscanB = `ioscan -B 2>/dev/null`;
    if ( @ioscanB ) {
        print "\n$INFOSTR Ioscan with pending deferred bindings\n";
        print @ioscanB;
    }

    my @ioscana = `ioscan -a 2>/dev/null`;
    if ( @ioscana ) {
        print "\n$INFOSTR Ioscan information about thread 0 of a processor with HyperThreading feature\n";
        print @ioscana;
    }

    #
    # For PA-RISC Superdomes vcn and vcs devices are OK to be NO_HW
    #
    if ( open( IS, "ioscan -fn${IOSCANADD} |" ) ) {
        while (<IS>) {
            push( @Alldevs, $_ );

            if ( grep( /NO_HW/, $_ ) ) {
                if ( grep( /SD/, "$Model" ) ) {
                    if ( "$Hardware" ne "ia64" ) {
                        next if ( grep( /\bvcs\b|\bvcn\b/, $_ ) );
                    }
                }

                push( @klu, $_ );

                if ( grep( /dsk|disk/, $_ ) ) {
                    $dsknohwcnt++;
                }
            }
            elsif ( grep( /UNCLAIMED/, $_ ) ) {
                push( @unc, $_ );
                if ( grep( /dsk|disk/, $_ ) ) {
                    $dskunclaimedcnt++;
                }
                else {
                    $nondskunclaimedcnt++;
                }
            }
            elsif ( grep( /SUSPENDED/, $_ ) ) {
                push( @suspended, $_ );
                $dsksuspendedcnt++;
            }
            elsif ( grep( /DIFF_HW/, $_ ) ) {
                push( @diffhw, $_ );
                $dskdiffhwcnt++;
            }
            elsif ( grep( /UNUSABLE/, $_ ) ) {
                push( @unusablehw, $_ );
                $dskunusablecnt++;
            }
            elsif ( grep( /ERROR/, $_ ) ) {
                push( @errorhw, $_ );
                $dskerrorcnt++;
            }
            elsif ( grep( /SCAN/, $_ ) ) {
                push( @scanhw, $_ );
                $dskscancnt++;
            }
            elsif ( grep( /\/dev\/ciss/, $_ ) ) {
                $_ =~ s/^\s+//;
                $_ =~ s/\s+$//;
                chomp($_);
                push( @CISS, $_ );
            }
            elsif ( grep( /\/dev\/mpt/, $_ ) ) {
                $_ =~ s/^\s+//;
                $_ =~ s/\s+$//;
                chomp($_);
                push( @MPTARR, $_ );
            }
            elsif ( grep( /iomemory_vsl|MassStore/, $_ ) ) {
                $_ =~ s/^\s+//;
                $_ =~ s/\s+$//;
                chomp($_);
                push( @FUSIONIOARR, $_ );
            }
            elsif ( grep( /^fc\s+/, $_ ) ) {
                my $fcdesc = q{};
                my $fcinst = q{};
                my $fcpath = q{};
                ( $fcdesc, $fcinst, $fcpath, $fcdriver, undef ) = split( /\s+/, $_ );
                chomp($fcpath);
                if ( "$fcpath" ) {
                    push( @FCarray, $fcpath );
                    push( @FCarray2, "/dev/${fcdriver}${fcinst}" );
                }
            }
            elsif ( grep( / sasd /, $_ ) ) {
                $SASDFLAG++;
            }
            elsif ( grep( /^iscsi/, $_ ) ) {
                $iSCSIFLAG++;
            }
            elsif ( grep( /^atm\s+/, $_ ) ) {
                push( @ATMarray, $_ );
            }
            elsif ( grep( /^ib\s+/, $_ ) ) {
                push( @IBarray, $_ );
            }
            elsif ( grep( /^disk/, $_ ) ) {
                if ( grep( /DVD|DV-|CD-ROM/, $_ ) ) {
                    push( @CDDVDarray, $_ );
                }

                next if ( grep( /DVD/,     $_ ) );
                next if ( grep( /DVD+/,     $_ ) );
                next if ( grep( /DV-/,     $_ ) );
                next if ( grep( /CD-ROM/,  $_ ) );
                next if ( grep( /SEAGATE/,  $_ ) );
                next if ( grep( /QUANTUM ATLAS/,  $_ ) );
                next if ( grep( /COMPAQ  BF/,  $_ ) );

                if ( grep( /ramdisc|Ramdisk/, $_ ) ) {
                    push( @RAMdiskarray, $_ );
                }

                my $mydisk = $_;

                (
                    $disc1,   $dinst, $dpath, $disc2,
                    $dstatus, $disc3, $disc4, $ddesc
                ) = split( /\s+/, $_ );

                $mydisk =~ s/^disk.*DEVICE//g;
                $mydisk =~ s/^\s+//g;
                $mydisk =~ s/^HP\s+//g;

                my $diskpath = "$dpath\t$mydisk";

                if ( ! ( grep( /^[0-9]/, $ddesc ) ) ) {
                    if ( ! ( grep( /\Q$diskpath\E/, @SANdiskarray ) ) ) {
                        push( @SANdiskarray, "$diskpath" );
                    }
                }

                if ( grep( /OPEN-|HSV|HSG|MSA|IBM DMV|NEXSAN|OPENstorage|EMC|DGC|SYMMETRIX|IR Volume|LOGICAL VOLUME|HITACHI|OPEN-V|IBM|P2000|CX2|CX3|CX4/, $ddesc ) ) {
                    if ( ! ( grep( /\Q$diskpath\E/, @SANdiskarray ) ) ) {
                        push( @SANdiskarray, "$diskpath" );
                    }
                }
            }
            elsif ( grep( /^processor/, $_ ) ) {
                $cpucount++;
                push( @CPUarray, $_ );
            }
            elsif ( grep( /^clic/, $_ ) ) {
                $CLIC_FLAG++;
            }
            elsif ( grep( /^lan/, $_ ) ) {
                $lancount++;
                push( @LANarray, $_ );
                #
                # Get rid of leading and trailing empty spaces
                #
                $_ =~ s{\A \s* | \s* \z}{}gxm;
                chomp($_);
                @corelan = split( /\s+/, $_ );
                if ( $corelan[$#corelan] eq 'Core' ) {
                    push( @LANCOREarray,
                        $corelan[0], $corelan[1], $corelan[2], "\n" );
                }
            }
            elsif ( grep( /^tape/, $_ ) ) {
                push( @tapes, $_ );
            }
            elsif ( grep( /\/rmt\/|\/rtape\//, $_ ) ) {
                $_ =~ s/\^s+//g;
                ( undef, $firsttapeent, undef) = split(/\s+/, $_);
                if ( "$firsttapeent" ) {
                    $tapecont = `lssf $firsttapeent | awk '{print \$2\$3\$4}'`;
                    chomp($tapecont);
                    if ( !grep( /\b$tapecont\b/, @tapecontrollers ) ) {
                        push( @tapecontrollers, $tapecont );
                    }
                }
            }
            elsif ( grep( /dsk/, $_ ) ) {
                #
                # Get rid of leading and trailing empty spaces
                #
                $_ =~ s{\A \s* | \s* \z}{}gxm;
                chomp($_);
                ( $cdisk, $rdisk ) = split( /\s+/, $_ );
                if ("$rdisk") {
                    if ( !grep( /\Q$cdisk\E/, @InclDisks ) ) {
                        push( @InclDisks, $cdisk );
                    }

                    if ( grep( /s2$/, $cdisk ) ) {
                        if ( !grep( /\Q$cdisk\E/, @InclDisksS2 ) ) {
                            push( @InclDisksS2, $cdisk );
                        }
                    }
                }
            }
            else {
                 # not interested in anything else
            }
        }
        close(IS);

        if ( @klu ) {
            print "\n$ERRSTR Hardware ioscan found devices in NO_HW state\n";
            print @klu;
            push(@CHECKARR,
"\n$ERRSTR Hardware ioscan found devices in NO_HW state\n");
            push(@CHECKARR, @klu);
            $warnings++;
        }
        else {
            print "\n$PASSSTR Hardware ioscan found no devices in NO_HW state\n";
        }

        my $ulength = scalar(@unc);
        if ( $ulength != 0 ) {
            print "\n$ERRSTR Hardware ioscan found devices in UNCLAIMED state\n";
            print @unc;
            push(@CHECKARR,
"\n$ERRSTR Hardware ioscan found devices in UNCLAIMED state\n");
            push(@CHECKARR, @unc);
            $warnings++;
        }
        else {
            print
"\n$PASSSTR Hardware ioscan found no devices in UNCLAIMED state\n";
        }

        my $suslength = scalar(@suspended);
        if ( $suslength != 0 ) {
            print "\n$ERRSTR Hardware ioscan found devices in SUSPENDED state\n";
            print @suspended;
            push(@CHECKARR,
"\n$ERRSTR Hardware ioscan found devices in SUSPENDED state\n");
            push(@CHECKARR, @suspended);
            $warnings++;
        }
        else {
            print
"\n$PASSSTR Hardware ioscan found no devices in SUSPENDED state\n";
        }

        my $difflength = scalar(@diffhw);
        if ( $difflength != 0 ) {
            print
"\n$ERRSTR Hardware ioscan found devices in DIFF_HW state (software found does not match the associated software)\n";
            print @diffhw;
            push(@CHECKARR,
"\n$ERRSTR Hardware ioscan found devices in DIFF_HW state (software found does not match the associated software)\n");
            push(@CHECKARR, @diffhw);
            $warnings++;
        }
        else {
            print "\n$PASSSTR Hardware ioscan found no devices in DIFF_HW state\n";
        }

        my $unlength = scalar(@unusablehw);
        if ( $unlength != 0 ) {
            print "\n$ERRSTR Hardware ioscan found devices in UNUSABLE state\n";
            print @unusablehw;
            push(@CHECKARR,
"\n$ERRSTR Hardware ioscan found devices in UNUSABLE state\n");
            push(@CHECKARR, @unusablehw);
            $warnings++;
        }
        else {
            print "\n$PASSSTR Hardware ioscan found no devices in UNUSABLE state\n";
        }

        my $elength = scalar(@errorhw);
        if ( $elength != 0 ) {
            print
"\n$ERRSTR Hardware ioscan found devices in ERROR state (hardware is respoinding but is in error)\n";
            print @errorhw;
            push(@CHECKARR,
"\n$ERRSTR Hardware ioscan found devices in ERROR state (hardware is respoinding but is in error)\n");
            push(@CHECKARR, @errorhw);
            $warnings++;
        }
        else {
            print "\n$PASSSTR Hardware ioscan found no devices in ERROR state\n";
        }

        my $scanlength = scalar(@scanhw);
        if ( $scanlength != 0 ) {
            print
"\n$ERRSTR Hardware ioscan found devices in SCAN state (node locked)\n";
            print @scanhw;
            push(@CHECKARR,
"\n$ERRSTR Hardware ioscan found devices in SCAN state (node locked)\n");
            push(@CHECKARR, @scanhw);
            $warnings++;
        }
        else {
            print "\n$PASSSTR Hardware ioscan found no devices in SCAN state\n";
        }

    my @escsidiag = `escsi_diag 2>/dev/null`;
    # If you want to exclude interface driver diagnostics (fcddiag, fclpdiag,
    # and tddiag) add flag "-X"
    #
    # my @escsidiag = `escsi_diag -X 2>/dev/null`;
    #
    if ( @escsidiag ) {
        print "\n$INFOSTR SCSI stack diagnostics status(escsi_diag debugging)\n";
        print @escsidiag;
    }

    datecheck();
    print_header("*** END CHECKING IOSCAN $datestring ***");

        datecheck();
        print_header("*** BEGIN CHECKING IODEBUG $datestring ***");

        my @iodebugtree = `iodebug -iotree 2>/dev/null`;
        if ( @iodebugtree ) {
            print "$INFOSTR WTEC iodebug iotree status\n";
            print @iodebugtree;
            print "\n";

            my @iodebugscsi = `iodebug -scsi 2>/dev/null`;
            if ( @iodebugscsi ) {
                print "$INFOSTR WTEC iodebug scsi status\n";
                print @iodebugscsi;
                print "\n";
            }

            my @iodebugmpt = `iodebug -mpt 2>/dev/null`;
            if ( @iodebugmpt ) {
                print "$INFOSTR WTEC iodebug mpt status\n";
                print @iodebugmpt;
                print "\n";
            }

            my @iodebugsasd = `iodebug -sasd 2>/dev/null`;
            if ( @iodebugsasd ) {
                print "$INFOSTR WTEC iodebug sasd status\n";
                print @iodebugsasd;
                print "\n";
            }

            my @iodebugciss = `iodebug -ciss 2>/dev/null`;
            if ( @iodebugciss ) {
                print "$INFOSTR WTEC iodebug ciss status\n";
                print @iodebugciss;
                print "\n";
            }

            my @iodebugstape = `iodebug -stape 2>/dev/null`;
            if ( @iodebugstape ) {
                print "$INFOSTR WTEC iodebug stape status\n";
                print @iodebugstape;
                print "\n";
            }

            my @iodebugusb = `iodebug -usb 2>/dev/null`;
            if ( @iodebugusb ) {
                print "$INFOSTR WTEC iodebug usb status\n";
                print @iodebugusb;
                print "\n";
            }
        }
        else {
            print "$INFOSTR WTEC iodebug not installed\n";
        }

        datecheck();
        print_trailer("*** END CHECKING IODEBUG $datestring ***");

        datecheck();
        print_header("*** BEGIN CHECKING SAN LUNS, VDISKS, USB DRIVES AND HW RAID $datestring ***");

        $slength = scalar(@SANdiskarray);
        if ( $slength != 0 ) {
            print @SANdiskarray;
            $ARRFLAG++;
            datecheck();
            print_trailer("*** END CHECKING SAN LUNS, VDISKS, USB DRIVES AND HW RAID $datestring ***");

            if ( @FCarray != 0 ) {
                datecheck();
                print_header("*** BEGIN CHECKING LUNS PER HBA $datestring ***");

                foreach my $fccard (@FCarray) {
                    my $fcmatch = scalar(grep(/$fccard\.|$fccard\//, @SANdiskarray));
                    printf
"$INFOSTR HBA %s has %d LUN%s attached\n", $fccard, $fcmatch,
                    $fcmatch == 1 ? "" : "s";
                }
                
                print "\n";
                datecheck();
                print_trailer("*** END CHECKING LUNS PER HBA $datestring ***");
            }
        }
        else {
            print "$INFOSTR No external SAN or disk arrays attached\n";
            datecheck();
            print_trailer("*** END CHECKING SAN LUNS, VDISKS AND HW RAID $datestring ***");
        }

        datecheck();
        print_header("*** BEGIN CHECKING HARDWARE IOSCAN SUMMARY $datestring ***");

        $alength = scalar(@Alldevs);
        if ( $alength != 0 ) {
            print @Alldevs;
    
            if ( "$Minor$Patch" >= 1123 ) {
                # WARNING! WARNING!
                # This test crashed RX7620 server on HP-UX 11.23 several times
                # Maybe a bug in ioscan(1)
                #
                if ( "$opts{e}" == 1 ) {
                    my @ioscanefi = `ioscan -eC disk 2>/dev/null`;
                    if ( @ioscanefi ) {
                        print "\n$INFOSTR Ioscan for disks with EFI addresses\n";
                        print @ioscanefi;
                    }
                }
            }
        }
        else {
            print "$ERRSTR Hardware ioscan failed\n";
            push(@CHECKARR, "\n$ERRSTR Hardware ioscan failed\n");
            $warnings++;
        }
    }
    else {
        print "$ERRSTR Cannot run ioscan\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run ioscan\n");
    }

    if ( ! @MPTARR ) {
         @MPTARR = `ls /dev/mpt* 2>/dev/null`;
    }

    foreach my $mptdev ( @MPTARR ) {
        if ( -c "$mptdev" ) {
            chomp($mptdev);
            my @mptconfig = `mptconfig $mptdev 2>/dev/null | awk NF`;
            if ( @mptconfig ) {
                print "\n$INFOSTR Mptconfig status for $mptdev\n";
                print @mptconfig;
            }

            my @mptutil = `mptutil $mptdev 2>/dev/null | awk NF`;
            if ( @mptutil ) {
                print "\n$INFOSTR Mptutil status for $mptdev\n";
                print @mptutil;
            }
        }
    }

    if ( "$Minor$Patch" >= 1131 ) {
        my @insftest = `insf -v -L`;
        if ( @insftest ) {
            print "\n$INFOSTR Checking Legacy mode\n";
            print @insftest;
        }

        my @ioscandsf = `ioscan -F -m dsf`;
        if ( @ioscandsf ) {
            print
"\n$INFOSTR Ioscan mapping of Legacy to Agile Naming Model for HP-UX 11v3 and above\n";
            print @ioscandsf;
        }

        if ( open( IOHEA, "ioscan -P health 2>/dev/null |" )) { 
            while (<IOHEA>) {
                if ( grep( /offline|unusable|limited|disabled/, $_ ) ) {
                    push(@BADIOHEALTH, $_);
                }
                else {
                    push(@GOODIOHEALTH, $_);
                }
            }
            close(IOHEA);
        }

        if ( @GOODIOHEALTH ) {
            print
"\n$INFOSTR Ioscan summary for healthy devices (HP-UX 11v3 and above)\n";
            print @GOODIOHEALTH;
        }

        if ( @BADIOHEALTH ) {
            print
"\n$INFOSTR Ioscan health reports non-online devices\n";
            print @BADIOHEALTH;
            push(@CHECKARR,
"\n$WARNSTR Ioscan health reports non-online devices\n");
            $warnings++;
        }

        my @ioscandesc = `ioscan -P description 2>/dev/null`;
        if ( @ioscandesc ) {
            print "\n$INFOSTR Ioscan descriptions for HP-UX 11v3 and above\n";
            print @ioscandesc;
        }

        my @ioscanerr = `ioscan -P error_recovery 2>/dev/null`;
        if ( @ioscanerr ) {
            print "\n$INFOSTR Ioscan error recovery for HP-UX 11v3 and above\n";
            print @ioscanerr;
        }

        my @ioscansc = `ioscan -P ms_scan_time 2>/dev/null`;
        if ( @ioscansc ) {
            print "\n$INFOSTR Storage subsystem I/O scan times\n";
            print @ioscansc;
        }

        my @ioscansp = `ioscan -P physical_location 2>/dev/null`;
        if ( @ioscansp ) {
            print "\n$INFOSTR Ioscan physical location\n";
            print @ioscansp;
        }

        my @scsimglun = `scsimgr lun_map 2>/dev/null`;
        if ( @scsimglun ) {
            print "\n$INFOSTR Scsimgr lun_map\n";
            print @scsimglun;
        }

        my @scsimgrsh = `scsimgr get_info 2>/dev/null`;
        if ( @scsimgrsh ) {
            print "\n$INFOSTR Scsimgr get_info\n";
            print @scsimgrsh;
        }

        my @scsimgrd = `scsimgr ddr_list 2>/dev/null`;
        if ( @scsimgrd ) {
            print "\n$INFOSTR Scsimgr settable attribute scopes\n";
            print @scsimgrd;
        }

        my @scsimgrdn = `scsimgr dump_node 2>/dev/null`;
        if ( @scsimgrdn ) {
            print "\n$INFOSTR Scsimgr persistent information\n";
            print @scsimgrdn;
        }

        my @scsimgrhp = `scsimgr get_attr hp 2>/dev/null`;
        if ( @scsimgrhp ) {
            print "\n$INFOSTR Scsimgr global attributes\n";
            print @scsimgrhp;
        }

        my @scsimgrss = `scsimgr -p get_attr all_lun -a device_file -a wwid -a vid -a pid -a encl_alias -a firmware_rev -a serial_number -a total_path_cnt -a load_bal_policy -a max_q_depth -a capacity 2>/dev/null`;
        if ( @scsimgrss ) {
            print "\n$INFOSTR Scsimgr formatted major global attributes\n";
            print @scsimgrss;
        }

        my @scsimgrinfo = `scsimgr -v get_info all_lun 2>/dev/null`;
        if ( @scsimgrinfo ) {
            # Superdome2 is not cell-based but Blade-based
            #
            if ( ! grep(/Superdome2/, $Model )) {
                if ( @Pararr ) {
                    print "\n$INFOSTR This is a cell-based system\n";
                    print "\n$NOTESTR It is strongly recommended to\n";
                    print "$NOTESTR set policy to \"cell-local round-robin\"\n";
                }
            }
            print "\n$INFOSTR Scsimgr get_info for all LUNs\n";
            print @scsimgrinfo;

            my @scsimgrarr = `scsimgr -p get_attr all_lun -a hw_path -a device_file -a wwid -a serial_number 2>/dev/null`;
            if ( @scsimgrarr ) {
                print "\n$INFOSTR Scsimgr get_attr status\n";
                print @scsimgrarr;
            }

            my @scsiarr = `ls /dev/rdisk/* | grep -v "_p" 2>/dev/null`;
            if ( @scsiarr != 0 ) {
                foreach my $ssr (@scsiarr) {
                    chomp($ssr);
                    next if ( grep(/\Q$ssr\E/, @stale ));
                    my $ssrcount = 0;
                    if ( open( SSRR, "scsimgr get_info -D $ssr 2>/dev/null |" ) ) {
                        print "\n$INFOSTR Scsimgr get_info status for $ssr\n";
                        while (<SSRR>) {
                            print $_;
                            $ssrcount++;
                            chomp($_);
                            if ( grep(/^I\/O load balance policy/, $_) ) {
                                (undef, $LBPOLICY) = split(/=/, $_ );
                                $LBPOLICY =~ s/^\s+//g ;
                                $LBPOLICY =~ s/\s+$//g ;
                                if ( @Pararr ) {
                                    if ( "$LBPOLICY" ) {
                                        if ( ! grep(/Superdome2/, $Model )) {
                                            if ( "$LBPOLICY" ne "cl_round_robin" ) {
                                                push(@CHECKARR,
"\n$WARNSTR $ssr has load balance policy \"$LBPOLICY\" (for cell-based servers \"cl_round_robin\" is recommended)\n");
                                                push(@LBARR,
"\n$WARNSTR $ssr has load balance policy \"$LBPOLICY\" (for cell-based servers \"cl_round_robin\" is recommended)\n");
                                                $warnings++;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        close(SSRR);
                    }
                    else {
                        print
"\n$WARNSTR Scsimgr get_info status for $ssr cannot be obtained (maybe obsolete device?)\n";
                    }
                }
            }
        }

        if ( @LBARR ) {
            print @LBARR;
        }

        datecheck();
        print_header("*** END CHECKING HARDWARE IOSCAN SUMMARY $datestring ***");

        datecheck();
        print_header("*** BEGIN CHECKING FUSION IO $datestring ***");

        if ( $FUSIONIO_FLAG > 0 ) {
            print "$INFOSTR Fusion-io depot seemingly installed\n";
        }
        else {
            print "$INFOSTR Fusion-io depot seemingly not installed\n";
        }
 
        if ( "@FUSIONIOARR" ) {
            print "$INFOSTR Fusion-IO devices seemingly enabled\n";
            
            my @FIOSTAT = `fio-status -a 2>/dev/null`;

            if ( @FIOSTAT ) {
                print "$INFOSTR Fusion-IO status\n";
                print @FIOSTAT;
            }

            my @FIOSTATE = `fio-status -e 2>/dev/null`;

            if ( @FIOSTATE ) {
                print "$INFOSTR Fusion-IO error status\n";
                print @FIOSTATE;
            }

            my @FIOSTATU = `fio-status -U 2>/dev/null`;

            if ( @FIOSTATU ) {
                print "$INFOSTR Fusion-IO unavailable fields status\n";
                print @FIOSTATU;
            }
        }
        else {
            print "$INFOSTR FusionIO devices not configured or not valid on this platform\n";
        }

        datecheck();
        print_header("*** END CHECKING FUSION IO $datestring ***");
    }

    if ( "$Minor$Patch" >= 1131 ) {
        print "\n";
        datecheck();
        print_header("*** BEGIN CHECKING SYSTEM STATUS VIA CPROP $datestring ***");

        my @cpropl = `cprop -list 2>/dev/null`;
    
        if ( @cpropl ) {
            print @cpropl;
            print "\n";

            my @cpropd = `cprop -detail -a 2>/dev/null`;
            if ( @cpropd ) {
                print @cpropd;
                print "\n";
            }

            my @cpropv = `cprop -viewtest -a 2>/dev/null`;
            if ( @cpropv ) {
                print @cpropv;
            }
        }
        else {
            print "$INFOSTR Command cprop(1M) missing or disabled\n";
        } 

        datecheck();
        print_trailer("*** END CHECKING SYSTEM STATUS VIA CPROP $datestring ***");
    }
}

# Subroutine to check LVM setup
#
sub ALLDISK_CHECK {
    datecheck();
    print_header("*** BEGIN CHECKING BOOT HEADERS ON PHYSICAL VOLUMES $datestring ***");

    # This is LVM:
    # xd -j8192 -N8 -tc disk | grep "L   V   M   R   E   C   0   1"
    #
    # This is LVM:
    # xd -j(128*1024) -N8 -tc disk | grep "H   P   L   V   M   B   D   R"
    #
    # This is VxVM:
    # xd -j(128*1024) -N8 -tc disk | grep "P   R   I   V   H   E   A   D"
    #
    # This is EFI GUID Partition Table Header:
    # xd -j512 -N8 -tc disk | grep -e "T   R   A   P       I   F   E" -e "E   F   I       P   A   R   T"
    #
    # xd -An -j(512+56) -N16 -tuL disk |read guid1 guid2 guid3 guid4
    # EFI GUID-PARTITION-HEADER $guid1-$guid2-$guid3-$guid4 
    #
    # This is EFI FAT32 Partition:
    # xd -j71 -N8 -tc disk | grep -e "I   A   6   4   _   E   F   I"
    #

    # xd may fail to read from raw disks if UNIX95 is set
    #
    if ( "$ENV{'UNIX95'}" == 1 ) {
        $ENV{'UNIX95'} = '';
    }

    foreach my $a ( @InclDisks ) {
        # Interesting problem when xd(1) was hung on HP-UX 11.31
        # lvdisplay looked fine, but vgdisplay(1) showed missing
        # SAN LUNs.
        # The trick I decided to implement involves
        # diskinfo(1)...
        # 
        my $rawa = $a;
        $rawa =~ s/\/dsk\//\/rdsk\//g;
        $rawa =~ s/\/disk\//\/rdisk\//g;
        my @DSKCKAGN = `diskinfo $rawa 2>&1`;

        if ( ! grep(/No such device/, "@DSKCKAGN") ) {
             eval {
                 # On certain occasions, xd hangs, so we need to
                 # manage how long it runs
                 #
                 local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
                 alarm 40;
                 @VOLMGRTYPE = `xd -j131072 -N8 -tc $a 2>/dev/null`;
                 alarm 0;
             };

             if ($@) {
                 warn "\n$WARNSTR Command \"xd -j131072 -N8 -tc $a\" timed out (could be Snap or Read-Only LUN?)\n";
             }

            eval {
                # On certain occasions, xd hangs, so we need to
                # manage how long it runs
                #
                local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
                alarm 40;
                @VOLMGRTYPE2 = `xd -j512 -N8 -tc $a 2>/dev/null`;
                alarm 0;
            };

            if ($@) {
                warn "\n$WARNSTR Command \"xd -j512 -N8 -tc $a\" timed out (could be Snap or Read-Only LUN?)\n";
            }

            eval {
                # On certain occasions, xd hangs, so we need to
                # manage how long it runs
                #
                local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
                alarm 40;
                @VOLMGRTYPE3 = `xd -j71 -N8 -tc $a 2>/dev/null`;
                alarm 0;
            };

            if ($@) {
                warn "\n$WARNSTR Command \"xd -j71 -N8 -tc $a\" timed out (could be Snap or Read-Only LUN?)\n";
            }

            if ( grep( /H   P   L   V   M   B   D   R/, @VOLMGRTYPE ) ) {
                print "$INFOSTR PV $a has LVM header\n";
            }

            if ( grep( /P   R   I   V   H   E   A   D/, @VOLMGRTYPE ) ) {
                print "$INFOSTR PV $a has VxVM header\n";
            }

            if ( grep( /T   R   A   P       I   F   E|E   F   I       P   A   R   T/, @VOLMGRTYPE2 ) ) {
                print "$INFOSTR PV $a has EFI GUID partition table header\n";
            }
              
            if ( grep( /I   A   6   4   _   E   F   I/, @VOLMGRTYPE3 ) ) {
                print "$INFOSTR PV $a has EFI FAT32 header\n";
            }
        }
    }

    my @dskinfo = `dskinfo 2>/dev/null`;
    
    if ( @dskinfo ) {
        print "\n$INFOSTR Dskinfo report status\n";
        print @dskinfo;
    }

    datecheck();
    print_trailer("*** END CHECKING BOOT HEADERS ON PHYSICAL VOLUMES $datestring ***");
}

# Subroutine to check LVM setup
#
sub LVM_PARAM_CHECK {
    datecheck();
    print_header("*** BEGIN CHECKING PHYSICAL VOLUME LVM CONFIGURATION $datestring ***");

    my @ioscm = ();
    if ( "$Minor$Patch" >= 1131 ) {
        print "$INFOSTR Ioscan lun status\n";
        @ioscm = `ioscan -m lun 2>/dev/null`;
    
        if ( @ioscm ) {
            print @ioscm;
            print "\n";
        }

        my @iosch = `ioscan -m hwpath 2>/dev/null`;
        if ( @iosch ) {
            print "$INFOSTR Lun Hardware Path to Legacy Hardware Path mapping\n";
            print @iosch;
            print "\n";
        }

        my @ioscr = `ioscan -m resourcepath 2>/dev/null`;
        if ( @ioscr ) {
            print "$INFOSTR Ioscan resourcepaths\n";
            print @ioscr;
            print "\n";
        }
    }

    foreach $a ( reverse @InclDisks) {
        next if ( grep( /cdrom|DVD/, $a ) );

        if ( "$Hardware" eq "ia64" ) {
            next if ( grep( /s1$/, $a ) );
            next if ( grep( /s3$/, $a ) );
            if ( ! grep( /s2$/, $a ) ) {
                next if ( grep( /\Q$a\E/, @InclDisksS2 ) );
            }
        }

        my $rawb = $a;
        $rawb =~ s/\/dsk\//\/rdsk\//g;
        $rawb =~ s/\/disk\//\/rdisk\//g;

        if ( "$Minor$Patch" >= 1131 ) {
            my @PVLVMcheckV3 = `pvdisplay -l $a 2>/dev/null`;

            if ( @PVLVMcheckV3 != 0 ) {
                print "$PASSSTR Physical volume $a configured in LVM\n";
                print "@PVLVMcheckV3\n";
                $dsklvmcnt++;
            }
            else {
                print "$INFOSTR Physical volume $a not configured in LVM\n";
                push(@NOTLVMARR, $a);
                push(@CHECKARR,
"\n$WARNSTR Physical volume $a not configured in LVM\n");
                $dsknotlvmcnt++;
            }

            my @PVcheckV3b = `diskowner -FA $rawb 2>&1 | egrep -v "not found"`;
            if ( @PVcheckV3b != 0 ) {
                print "$INFOSTR $rawb status as per command diskowner\n";
                print "@PVcheckV3b\n";
            }

            my @PVcheck2 = `rdvgid $rawb 2>/dev/null`;
            if ( @PVcheck2 != 0 ) {
                print "\n$INFOSTR $rawb status as per HA Tools command rdvgid\n";
                print "@PVcheck2\n";
            }

            # Under certain circumstances, this command simply hangs,
            # so setting TERM variable helps
            #
            my $dsfdev = `ioscan -F -m dsf $a | awk -F: '{print \$2}'`;
            chomp($dsfdev);
            my $comm1 = `TERM=100; export TERM; lssf $dsfdev`;

            my @lssfarr = split( /\s+/, $comm1 );
            my $lssfdev = $lssfarr[ $#lssfarr - 1 ];
            $diskcont = "$lssfarr[1] $lssfarr[2] $lssfarr[3]";
            push( @{ $ctrllist{$diskcont} }, $dsfdev );
            if ( !grep( /\b$diskcont\b/, @Allcontrollers ) ) {
                push( @Allcontrollers, $diskcont );
            }
        }
        else {
            # Under certain circumstances, this command simply hangs,
            # so setting TERM variable helps
            #
            my $comm1 = `TERM=100; export TERM; lssf $a`;

            my @lssfarr = split( /\s+/, $comm1 );
            my $lssfdev = $lssfarr[ $#lssfarr - 1 ];
            $diskcont = "$lssfarr[1] $lssfarr[2] $lssfarr[3]";
            push( @{ $ctrllist{$diskcont} }, $a );
            if ( !grep( /\b$diskcont\b/, @Allcontrollers ) ) {
                push( @Allcontrollers, $diskcont );
            }

            chomp($lssfdev);
            next if ( grep( /\Q$lssfdev\E/, @CDDVDarray ) );
            my @PVLVMcheck = `pvdisplay $a 2>/dev/null`;
            if ( @PVLVMcheck != 0 ) {
                print "$PASSSTR Physical volume $a configured in LVM\n";
                $dsklvmcnt++;
            }
            else {
                print "$WARNSTR Physical volume $a not configured in LVM\n";
                push(@NOTLVMARR, $a);
                push(@CHECKARR,
"\n$WARNSTR Physical volume $a not configured in LVM\n");
                $dsknotlvmcnt++;
            }
        }
    }

    print
"\n$INFOSTR Number of disk physical volumes in state UNCLAIMED: $dskunclaimedcnt\n";
    print
"\n$INFOSTR Number of other devices in state UNCLAIMED:         $nondskunclaimedcnt\n";
    print
"\n$INFOSTR Number of physical volumes in state NO_HW:          $dsknohwcnt\n";
    print
"\n$INFOSTR Number of physical volumes in state SUSPENDED:      $dsksuspendedcnt\n";
    print
"\n$INFOSTR Number of physical volumes in state ERROR:          $dskerrorcnt\n";
    print
"\n$INFOSTR Number of physical volumes in state DIFF_HW:        $dskdiffhwcnt\n";
    print
"\n$INFOSTR Number of physical volumes in state SCAN:           $dskscancnt\n";
    print
"\n$INFOSTR Number of physical volumes in state UNUSABLE:       $dskunusablecnt\n";
    print
"\n$INFOSTR Number of physical volumes not under LVM:           $dsknotlvmcnt\n";
    print
"\n$INFOSTR Number of physical volumes under LVM:               $dsklvmcnt\n";

    datecheck();
    print_trailer("*** END CHECKING PHYSICAL VOLUME LVM CONFIGURATION $datestring ***");

    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING LVM LIMITS $datestring ***");

        my @lvmadm = `lvmadm -t 2>/dev/null`;
        if ( @lvmadm ) {
            print @lvmadm;
        }
        else {
            print
"$INFOSTR Lvmadm not supported, or patches are too old, or \"lvmp\" driver is not loaded\n";
        }

        datecheck();
        print_trailer("*** END CHECKING LVM LIMITS $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING PHYSICAL, LOGICAL, AND VOLUME AVAILABILITY $datestring ***");

    my $PVGconf = "/etc/lvmpvg";
    if ( (-s "$PVGconf" ) && ( -T "$PVGconf" ) ) {
        my @PVGlist = `cat $PVGconf`;
        if ( @PVGlist != 0 ) {
            print
"$INFOSTR Physical volume group (PVG) distributed LVs configured\n";
            print @PVGlist;
            print "\n";
        }
    }
    else {
        print
"$INFOSTR Physical volume group (PVG) distributed LVs not configured\n";
        print "\n";
    }

    if ( -f "$LVMLOCK" ) {
        print "$INFOSTR $LVMLOCK exists (some LVM action is underway)\n";
        print "\n";
    }
    else {
        print "$INFOSTR $LVMLOCK does not exist (no LVM action is underway)\n";
        print "\n";
    }

    if ( -f "$PVLOCK" ) {
        print "$INFOSTR $PVLOCK exists (some PV action is underway)\n";
        print "\n";
    }
    else {
        print "$INFOSTR $PVLOCK does not exist (no PV action is underway)\n";
        print "\n";
    }

    # Try to guess SAN type if not defined on the command-line
    #
    if ( ! "$SANtype" ) {
        $SANtype =
            @SPMGR != 0 ? "EVA"
            : @EVAINFO != 0 ? "EVA"
            : @EVADISC != 0 ? "EVA"
            : grep( /HSV-|HSG/, @SANdiskarray ) ? "EVA"
            : @XPINFO != 0 ? "XP"
            : grep( /IBM/, @SANdiskarray ) ? "IBM"
            : grep( /OPEN-/, @SANdiskarray ) ? "XP"
            : grep( /EMC|DGC|CX2|CX3|CX4|SYMMETRIX/, @SANdiskarray ) ? "EMC"
            : @EMC != 0 ? "EMC"
            : q{};
    }

    if ( "$VGSAN" eq "ALL" ) {
        if ( "$SANtype" eq "XP" ) {
            $TIMEOUT = 60;
        }
        elsif ( "$SANtype" eq "EVA" ) {
            $TIMEOUT = 180;
        }
        elsif ( "$SANtype" eq "EMC" ) {
            # EMC document emc58837 outlines the time out parameters needed for HP-UX
            #
            $TIMEOUT = 180;
        }
        else {
            $TIMEOUT = 180;
        }

        $BBR = "NONE";
    }
    elsif ( "$VGSAN" eq "NONVG0" ) {
        if ( "$SANtype" eq "XP" ) {
            $TIMEOUT = 60;
        }
        elsif ( "$SANtype" eq "EVA" ) {
            $TIMEOUT = 180;
        }
        elsif ( "$SANtype" eq "EMC" ) {
            $TIMEOUT = 180;
        }
        else {
            $TIMEOUT = 180;
        }
        $BBR = "NONE";
    }
    elsif ( "$VGSAN" eq "NONE" ) {
        $TIMEOUT = 180;
        $BBR     = "on";
    }
    else {
        $TIMEOUT = 180;
        $BBR     = "on";
    }

    @ALLVGARRAY  = `find /dev -name 'group' -print 2>/dev/null`;
    if ( $LVMTAB_FLAG == 0 ) {
        @ALLVGLVMTAB = `strings $LVMTAB | egrep -v "\/dsk\/|\/disk\/" | egrep dev`;
        if ( @ALLVGLVMTAB != 0 ) {
            print "$INFOSTR Volume groups defined in LVM ($LVMTAB)\n";
            print @ALLVGLVMTAB;
            print "\n";
        }
        else {
            print "$WARNSTR Volume groups seemingly not defined in ";
            print "LVM ($LVMTAB)\n";
            push(@CHECKARR, "\n$WARNSTR Volume groups seemingly not defined in ");
            push(@CHECKARR, "LVM ($LVMTAB)\n");
            $warnings++;
        }
    }

    if ( $LVMTABL2_FLAG > 0 ) {
        @ALLVGLVMTABL2 = `strings $LVMTABL2 | egrep -v "\/dsk\/|\/disk\/" | egrep dev`;
        if ( @ALLVGLVMTABL2 != 0 ) {
            print "$INFOSTR Volume groups defined in LVM ($LVMTABL2)\n";
            print @ALLVGLVMTABL2;
        }
    }

    if ( @ALLVGARRAY ) {
        my @ALLGRP = `ls -als /dev/*/group 2>/dev/null`;
        if ( @ALLGRP ) {
            print "\n$INFOSTR LVM VG group file status\n";
            print @ALLGRP;
        }
    }

    if ( -T "$USETAB" && -s "$USETAB" ) {
        my @usetab = `cat $USETAB 2>/dev/null`;
        if ( @usetab ) {
            print "\n$INFOSTR Use description for PVs in $USETAB\n";
            print @usetab;
        }
    } else
    {
        print "\n$INFOSTR Use description for PVs not set up in $USETAB\n";
    }

    foreach $groupfile (@ALLVGARRAY) {
        chomp($groupfile);
        #
        # Get rid of leading and trailing empty spaces
        #
        $groupfile =~ s{\A \s* | \s* \z}{}gxm;
        if ( -c "$groupfile" ) {
            print "\n$PASSSTR $groupfile is character device file\n";
            
            my $epmodeg = (stat($groupfile))[2];

            if ( $epmodeg & 0020 ) {
                print "\n$WARNSTR $groupfile is group-writable!\n";
                push(@CHECKARR, "\n$WARNSTR $groupfile is group-writable!\n");
                $warnings++;
            }

            if ( $epmodeg & 0002 ) {
                print "\n$WARNSTR $groupfile is world-writable!\n";
                push(@CHECKARR, "\n$WARNSTR $groupfile is world-writable!\n");
                $warnings++;
            }

            my $st = `ls -als $groupfile | awk '{print \$6, \$7}'`;
            chomp($st);
            my ($grmajor, $mingr) = split(/\s+/, $st );
            my $grminor = hex($mingr);

            if ( "$grminor" ) {
                if ( grep(/\b$grminor\b/, @ALLVGG) ) {
                    print
"\n$WARNSTR Non-unique minor number for character device $groupfile\n";
                    push(@CHECKARR,
"\n$WARNSTR Non-unique minor number for character device $groupfile\n");
                    $DUPLICATE_GRNO++;
                }
            }

            push(@ALLVGG, "$grminor");

            if ( "$grmajor" ) {
                if ( ("$grmajor" != $GRMAJ) && ("$grmajor" != $GRMAJL2) ) {
                    print
"\n$WARNSTR Character device $groupfile has major number $grmajor (should be $GRMAJ or $GRMAJL2)\n";
                    push(@CHECKARR,
"\n$WARNSTR Character device $groupfile has major number $grmajor (should be $GRMAJ or $GRMAJL2)\n");
                    $warnings++;
                }
                else {
                    print
"\n$PASSSTR Character device $groupfile has major number $grmajor\n";
                }
            }

            (undef, undef, $VGNAMEALL, undef) = split(/\//, $groupfile);
            if ( grep(/\Q$VGNAMEALL\E/, @ALLVGLVMTAB ) ) {
                print
"\n$PASSSTR Volume group $VGNAMEALL defined in LVM ($LVMTAB)\n";

                if ( ( "$Minor$Patch" >= 1131 ) || ( $VGMODIFY_FLAG > 0 ) ) {
                    my @vgmod = `vgmodify -t -n -v $VGNAMEALL 2>/dev/null`;
                    if ( @vgmod ) {
                        print
"\n$INFOSTR Volume group $VGNAMEALL dynamic LUN expansion (vgmodify) settings\n";
                        print @vgmod;
                    }
                }
            }
            elsif ( grep(/\Q$VGNAMEALL\E/, @ALLVGLVMTABL2 ) ) {
                print
"\n$PASSSTR Volume group $VGNAMEALL defined in LVM ($LVMTABL2)\n";
            }
            else {
                print
"\n$INFOSTR Volume group $VGNAMEALL not defined in LVM ($LVMTAB)\n";
                push(@CHECKARR,
"\n$INFOSTR Volume group $VGNAMEALL not defined in LVM ($LVMTAB)\n");

                if ( "$Minor$Patch" >= 1131 ) {
                    if ( $LVMTABL2_FLAG == 0 ) {
                        print
"\n$INFOSTR Volume group $VGNAMEALL not defined in LVM ($LVMTABL2)\n";
                        push(@CHECKARR,
"\n$INFOSTR Volume group $VGNAMEALL not defined in LVM ($LVMTABL2)\n");
                    }
                }
            }

            if ( -s "$LVMCONFDIR/$VGNAMEALL.conf" ) {
                print
"\n$PASSSTR Volume group $VGNAMEALL configuration $VGNAMEALL.conf file exists in default location in $LVMCONFDIR\n";
            }
            else {
                print
"\n$WARNSTR Volume group $VGNAMEALL configuration file $VGNAMEALL.conf missing in default location in $LVMCONFDIR\n";
                push(@CHECKARR,
"\n$WARNSTR Volume group $VGNAMEALL configuration file $VGNAMEALL.conf missing in default location\n");
                $warnings++;
            }

            if ( "$lvmpathnb" ne "" ) {
                print
"\n$INFOSTR Volume group backup configuration directory $lvmpathnb defined in $lvmconf\n";
                my @LVMALTB = `ls $lvmpathnb 2>/dev/null`;
                if ( @LVMALTB != 0 ) {
                    print @LVMALTB;
                }
            }

            if ( "$Minor$Patch" >= 1123 ) {
                $VGCFGFLAG = "v";
            }

            my @vgcfgrest = `vgcfgrestore -n $VGNAMEALL -l${VGCFGFLAG} 2>/dev/null`;
            if ( @vgcfgrest ) {
                print "\n$INFOSTR Volume group $VGNAMEALL vgcfgrestore status\n";
                print @vgcfgrest;
            }

            my $VGmapfile = "$LVMCONFDIR/$VGNAMEALL.mapfile";

            if ( (-s "$VGmapfile" ) && ( -T "$VGmapfile" ) ) {
                my @mapcat = `cat $VGmapfile 2>/dev/null`;
                print
"\n$PASSSTR Volume group $VGNAMEALL mapfile $VGmapfile exists in default location in $LVMCONFDIR\n";
                if ( @mapcat != 0 ) {
                    print @mapcat;
                }
            }
            else {
                print
"\n$WARNSTR Volume group $VGNAMEALL mapfile $VGmapfile missing in default location in $LVMCONFDIR\n";
                push(@CHECKARR,
"\n$WARNSTR Volume group $VGNAMEALL mapfile $VGmapfile missing in default location in $LVMCONFDIR\n");
                $warnings++;
            }
        }
        else {
            print "\n$ERRSTR $groupfile is not a character device\n";
            push(@CHECKARR, "\n$ERRSTR $groupfile is not a character device\n");
            $warnings++;
        }
    }

    print "\n";

    open( NN, "vgdisplay -v 2>/dev/null |" ) || warn "$WARNSTR Cannot run vgdisplay\n";
    while (<NN>) {
        push(@ALLVGS, $_);
        chomp;
        next if ( grep( /^$/, $_ ) );
        if ( grep( /VG Name/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $vgname ) = split( /\s+/, $_ );
            chomp($vgname);
	    $pvcnt = 0;
            undef $VGfpe{$vgname};
            undef $VGpes{$vgname};
            undef $VGpeact{$vgname};
            undef $VGcurLV{$vgname};
            undef $VGstatus{$vgname};
            undef $VGverc{$vgname};
            undef $VGpetot{$vgname};
            push(@ACTIVEVGARRAY, "$vgname\n");
        }

        if ( grep( /VG Write Access/, $_ ) ) {
            $_ =~ s/^\s+//g;
            if ( grep( /read-only/i, $_ ) ) {
                print "$INFOSTR Volume group $vgname is quiesced\n";
            }
        }

        if ( grep( /VG Status/, $_ ) ) {
            $_ =~ s/VG Status//g;
            $vgstat = $_;
            chomp($vgstat);
            $vgstat =~ s/^\s+//g;
            $vgstat =~ s/\s+$//g;
            $vgstat =~ s/\s+//g;
            $VGstatus{$vgname} = $vgstat;
        }

        if ( grep( /Cur LV/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $curlvs ) = split( /\s+/, $_ );
            chomp($curlvs);
            $VGcurLV{$vgname} = $curlvs;
        }

        if ( grep( /Max LV/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $maxlv ) = split( /\s+/, $_ );
            chomp($maxlv);
            $MAXLV{$vgname} = $maxlv;
            if ( $maxlv < $THRESHOLD_MAX_LV ) {
                print "$WARNSTR Max LV ($maxlv) below the threshold ";
                print "($THRESHOLD_MAX_LV) for volume group $vgname\n";
                push(@CHECKARR, "\n$WARNSTR Max LV ($maxlv) below the threshold ");
                push(@CHECKARR, "($THRESHOLD_MAX_LV) for volume group $vgname\n");
                $warnings++;
            }
            else {
                print "$PASSSTR Max LV ($maxlv) satisfies the threshold ";
                print
                  "(minimum $THRESHOLD_MAX_LV) for volume group $vgname\n";
            }
        }

        if ( grep( /Max PV/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $maxpv ) = split( /\s+/, $_ );
            chomp($maxpv);
            $MAXPV{$vgname} = $maxpv;
            if ( $maxpv < $THRESHOLD_MAX_PV ) {
                print "$WARNSTR Max PV ($maxpv) below the threshold ";
                print "($THRESHOLD_MAX_PV) for volume group $vgname\n";
                push(@CHECKARR, "\n$WARNSTR Max PV ($maxpv) below the threshold ");
                push(@CHECKARR, "($THRESHOLD_MAX_PV) for volume group $vgname\n");
                $warnings++;
            }
            else {
                print "$PASSSTR Max PV ($maxpv) satisfies the threshold ";
                print
                  "(minimum $THRESHOLD_MAX_PV) for volume group $vgname\n";
            }
        }

        if ( grep( /Cur PV/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $curpv ) = split( /\s+/, $_ );
            chomp($curpv);
            $curpv =~ s/\s+$//g;

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
                print "$WARNSTR Current PV ($curpv) reached 90% of Max PV ";
                print "($maxpv) in volume group $vgname\n";
                push(@CHECKARR,
"\n$WARNSTR Current PV ($curpv) reached 90% of Max PV ");
                push(@CHECKARR, "($maxpv) in volume group $vgname\n");
                $warnings++;
            }
            elsif ( $pvthresh > $THRESHOLD ) {
                print "$WARNSTR Current PV ($curpv) exceeds 90% of Max PV ";
                print "($maxpv) in volume group $vgname\n";
                push(@CHECKARR,
"\n$WARNSTR Current PV ($curpv) exceeds 90% of Max PV ");
                push(@CHECKARR, "($maxpv) in volume group $vgname\n");
                $warnings++;
            }
            else {
                print "$PASSSTR Current PV ($curpv) below 90% of Max PV ";
                print "($maxpv) in volume group $vgname\n";
            }
        }

        if ( grep( /Act PV/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $actpv ) = split( /\s+/, $_ );
            chomp($actpv);
            if ( $actpv == 0 ) {
                print "$ERRSTR There are no active PVs\n";
                push(@CHECKARR, "\n$ERRSTR There are no active PVs\n");
                $warnings++;
            }
            $VGpeact{$vgname} = $actpv;
        }

        if ( "$actpv" ) {
	    if ($pvcnt == 0) {
                if ( $curpv != $actpv ) {
                    print
"$INFOSTR Current PV number ($curpv) not equal to active PV number ($actpv) in volume group $vgname\n";
                }
                else {
                    print
"$PASSSTR Current PV number ($curpv) is equal to active PV number ($actpv) in volume group $vgname\n";
	        }
            }
	    $pvcnt++;
        }

        if ( grep( /Max PE per PV/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, undef, undef, $pepv ) = split( /\s+/, $_ );
            chomp($pepv);
            $PEPV{$vgname} = $pepv;
            if ( $pepv < $THRESHOLD_MAX_PE ) {
                print "$WARNSTR Max PE per PV ($pepv) below the threshold ";
                print "($THRESHOLD_MAX_PE) for volume group $vgname\n";
                push(@CHECKARR,
"\n$WARNSTR Max PE per PV ($pepv) below the threshold ");
                push(@CHECKARR, "($THRESHOLD_MAX_PE) for volume group $vgname\n");
                $warnings++;
            }
            else {
                print
                  "$PASSSTR Max PE per PV ($pepv) satisfies the threshold ";
                print
                  "(minimum $THRESHOLD_MAX_PE) for volume group $vgname\n";
            }
        }

        if ( grep( /^Free PE/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $freepe ) = split( /\s+/, $_ );
            chomp($freepe);
            $freepe =~ s/\s+$//g;
            if ( $freepe == 0 ) {
                print "$ERRSTR No free PEs available in volume group $vgname\n";
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

        if ( grep( /PE Size/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, undef, $pesize ) = split( /\s+/, $_ );
            chomp($pesize);
            $pesize =~ s/\s+$//g;
            $VGpes{$vgname} = $pesize;
        }

        if ( grep( /Total PE/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $totpe ) = split( /\s+/, $_ );
            chomp($totpe);
            $totpe =~ s/\s+$//g;
            $VGpetot{$vgname} = $totpe;
        }

        if ( grep( /Total Spare PVs in use/, $_ ) ) {
            $Freevg{$vgname} = $VGfpe{$vgname} * $VGpes{$vgname};
            if ( "$Freevg{$vgname}" > 0 ) {
                print "\n$INFOSTR Unallocated space in VG $vgname is ";
            }
            else {
                print "\n$ERRSTR Unallocated space in VG $vgname is ";
                push(@CHECKARR,
"\n$ERRSTR Unallocated space in VG $vgname is $Freevg{$vgname} MB\n");
            }
            print "$Freevg{$vgname} MB\n";
            undef $Freevg{$vgname};
        }

        if ( grep( /VG Version/, $_ ) ) {
            $_ =~ s/^\s+//g;
            ( undef, undef, $VGVER ) = split( /\s+/, $_ );
            $VGVER =~ s/\s+$//g;
            chomp($VGVER);
            if ( "$VGVER" ) {
                print "$INFOSTR Volume group version for $vgname is $VGVER\n";
                #
                # In VG version 1.0, it is 256
                # In VG version 2.0 it is 512
                # In VG version 2.1 it is 2048
                #
                if ( $VGVER == "1.0" ) {
                    $MAXVGSVX = 256;
                }
                elsif ( $VGVER == "2.1" ) {
                    $MAXVGSVX = 512;
                }
                else {
                    $MAXVGSVX = 2048;
                }
            }

            $VGverc{$vgname} = $VGVER;
        }

        if ( grep( /PV Name/, $_ ) ) {
            $_ =~ s/^\s+//g;

            if ( grep( /Alternate link/i, $_ ) ) {
                ( undef, undef, $altpvdisk, undef ) = split( /\s+/, $_ );
                push(@VGPATH, "VG $vgname using PV alternate path $altpvdisk\n");
            }
            else {
                ( undef, undef, $pvdisk ) = split( /\s+/, $_ );
                push(@VGPATH, "VG $vgname using PV primary path $pvdisk\n");
            }

            push( @pvlist, $pvdisk );
        }

        if ( grep( /LV Name/, $_ ) ) {
            $_ =~ s/^\s+//g;
            my $lvdisk = q{};
            ( undef, undef, $lvdisk ) = split( /\s+/, $_ );
            push( @lvlist, $lvdisk );
        }

        if ( grep( /LV Status/, $_ ) ) {
            $_ =~ s/^\s+//g;
        }

        if ( grep( /LV Size/, $_ ) ) {
            $_ =~ s/^\s+//g;
        }

        if ( grep( /Current LE/, $_ ) ) {
            $_ =~ s/^\s+//g;
        }

        if ( grep( /Allocated PE/, $_ ) ) {
            $_ =~ s/^\s+//g;
        }

        if ( grep( /Used PV/, $_ ) ) {
            $_ =~ s/^\s+//g;
        }

        if ( grep( /PV Status/, $_ ) ) {
            if ( grep( /unavailable/, $_ ) ) {
                $PVcount{$vgname}++;
                push( @BADPV, "$ERRSTR PV $pvdisk unavailable in VG $vgname\n");
                push( @CHECKARR, "$ERRSTR PV $pvdisk unavailable in VG $vgname\n");
                $warnings++;
            }
        }
    }
    close(NN);

    if ( @ALLVGS ) {
        print "\n$INFOSTR Volume groups\n";
        print "@ALLVGS";
    }

    if ( @BADPV ) {
        print "\n";
        print "@BADPV\n";
    }

    open( NN2, "vgdisplay -vF 2>/dev/null |" ) || warn "$WARNSTR Cannot run vgdisplay\n";
    print "\n$INFOSTR Formatted LVM status (includes deactivated VGs)\n";
    while (<NN2>) {
        print $_;
        chomp;
        next if ( grep( /^$/, $_ ) );
        $_ =~ s/^\s+//g;
        if ( grep( /^vg_name/, $_ ) ) {
            my @VGFORM = split( /:/, $_ );
            my @VGstat2 = split( /=/, ${VGFORM}[1] );
            my @VGnm = split( /=/, ${VGFORM}[0] );
            if ( "$VGstat2[1]" eq 'deactivated' ) {
                my $fink = sprintf "%-20s              %-23s\n",
                    $VGnm[1],
                    $VGstat2[1];
                push(@DEACTTARR, "$fink");
            }
        }
    }
    close(NN2);

    print "\n";
    foreach my $VGelement (keys %PVcount) {
        print "$ERRSTR VG $VGelement has $PVcount{$VGelement} unavailable disks\n";
        push(@CHECKARR, "$ERRSTR VG $VGelement has $PVcount{$VGelement} unavailable disks\n");
        $warnings++;
    }

    my @union = my @intersection = my @difference = ();
    my %count = ();
    push(@ALLVGLVMTAB, @ALLVGLVMTABL2);
    foreach my $element (sort @ACTIVEVGARRAY, sort @ALLVGLVMTAB) { chomp($element); $count{$element}++; }
    foreach $element (keys %count) {
        push @union, $element;
        push @{ $count{$element} > 1 ? \@intersection : \@difference }, $element;
    }

    if ( @difference ) {
        print "$WARNSTR Some volume groups are not activated\n";
        print " @difference\n";
        push(@CHECKARR, "\n$WARNSTR Some volume groups are not activated\n");
        push(@CHECKARR, " @difference\n");
        $warnings++;
    }
    else {
        print "$PASSSTR All volume groups are activated\n";
    }

    if ( $DUPLICATE_GRNO > 0 ) {
        print "\n$ERRSTR Some VG group files have non-unique minor numbers\n";
        push(@CHECKARR,
"\n$ERRSTR Some VG group files have non-unique minor numbers\n");
    }
    else {
        print "\n$PASSSTR All VG group files have unique minor numbers\n";
    }

    if ( "$Minor$Patch" >= 1131 ) {
        # In VG version 1.0, it is 256
        # In VG version 2.0 it is 512
        # In VG version 2.1 it is 2048
        #
        $MAXVGS = $MAXVGSVX;
    }
    
    chomp($MAXVGS);

    print "\n$INFOSTR Designed maximum number of VGs is $MAXVGS\n";

    if ( "$Minor$Patch" >= 1120 ) {
        $MAXVGSC = `kctune maxvgs 2>/dev/null | awk '/^maxvgs/ && ! /awk/ {print \$2}'`;
    }
    else {
        $MAXVGSC = `kmtune -q maxvgs 2>/dev/null | awk '/maxvgs/ && ! /awk/ {print \$2}'`;
    }

    if ( "$MAXVGSC" ) {
        print "\n$INFOSTR Current maximum number of VGs in kernel is $MAXVGSC\n";
    }

    datecheck();
    print_trailer("*** END CHECKING PHYSICAL, LOGICAL, AND VOLUME AVAILABILITY $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING PHYSICAL VOLUMES $datestring ***");

    my @VGinfo = `vginfo -v 2>/dev/null`;
    if ( @VGinfo ) {
        print "$INFOSTR Vginfo\n";
        print @VGinfo;
        print "\n";
    }

    if ( "$Minor$Patch" >= 1131 ) {
        $VGSCAN_FLAG = "-N";
    }
    
    if ( open( VGSCAN, "vgscan -p $VGSCAN_FLAG 2>&1 |" ) ) {
        print "\n$INFOSTR Vgscan\n";
        while (<VGSCAN>) {
            next if ( grep( /^$/, $_ ) );
            print $_;
            if ( grep( /was not matched with any Physical Volumes/, $_ ) ) {
                $_ =~ s/The Volume Group //g;
                chomp($_);
                ($badVG, undef) = split(/\s+/, $_);
                push(@BADVG, $badVG);
            }
        }
        close(VGSCAN);
    }

    my @pvlist2 = @pvlist;

    my @importable = `importablevgs 2>/dev/null`;
    if ( "@importable" ) {
        print "\n$INFOSTR Importable volume groups\n";
        print @importable;
    }

    foreach $a (@pvlist) {
        if ( open( VTB, "pvdisplay $a 2>/dev/null |" ) ) {
            $PESIZE = $FREEPE = q{};
            print "\n$INFOSTR Physical volume $a\n";
            while (<VTB>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;
                if ( grep( /PV Status/, $_ ) ) {
                    ( undef, undef, my $LVALUE ) = split( /\s+/, $_ );
                    chomp($LVALUE);
                    if ("$LVALUE") {
                        if ( "$LVALUE" eq "available" ) {
                            push(@PVARR, "\n$PASSSTR PV $a available\n");
                            my $b = $a;
                            $b =~ s/\/dsk\//\/rdsk\//g;

                            if ( "$Minor$Patch" >= 1131 ) {
                                $b =~ s/_p2//g;
                                $b =~ s/\/disk\//\/rdisk\//g;
                            }

                            my @scsictl = `scsictl -a $b 2>/dev/null`;
                            if ( @scsictl != 0 ) {
                                push(@PVARR, "$INFOSTR PV $a queue depth\n");
                                push(@PVARR, @scsictl);
                            }

                            my @scsitgt = `scsictl -c get_target_parm $b 2>/dev/null |awk NF`;
                            if ( @scsitgt != 0 ) {
                                push(@PVARR, "$INFOSTR PV $a SCSI target speed\n");
                                push(@PVARR, @scsitgt);
                            }

                            my @diskinfo = `diskinfo -v $b 2>/dev/null`;
                            push(@ALLSRVPV, @diskinfo);
                            push(@ALLSRVPV, "\n");
                        }
                        else {
                            push(@BADDISK, $a);
                            push(@NOTLVMARR, $a);
                            push(@PVARR, "\n$WARNSTR PV $a not available\n");
                            push(@CHECKARR, "\n$WARNSTR PV $a not available\n");
                            $warnings++;
                        }
                        $LVALUE =~ s/\s+$//g;
                        $PVAL{$a} = $LVALUE;
                    }
                }

                if ( grep( /^VG Name/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    ( undef, undef, $PVGNAME ) = split( /\s+/, $_ );
                    chomp($PVGNAME);
                    $PVGN{$a} = $PVGNAME;
                }

                if ( grep( /^PE Size/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    ( undef, undef, undef, $PESIZE ) = split( /\s+/, $_ );
                    chomp($PESIZE);
                    $PVSIZE{$a} = $PESIZE;
                }

                if ( grep( /^Allocated PE/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    ( undef, undef, $ALLOCPE ) = split( /\s+/, $_ );
                    chomp($ALLOCPE);
                    $PVALOC{$a} = $ALLOCPE;
                }

                if ( grep( /^Free PE/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    ( undef, undef, $FREEPE ) = split( /\s+/, $_ );
                    chomp($FREEPE);
                    $PVFREE{$a} = $FREEPE;
                
                    if ( "$PESIZE" > 0 ) {
                        my $FREEMB = $FREEPE * $PESIZE;
                        push(@PVARR,
"$INFOSTR PV $a has $FREEMB MB free physical extents\n");
                    }
                    else {
                        push(@PVARR, "$INFOSTR PV $a no free physical extents\n");
                        push(@CHECKARR, "$INFOSTR PV $a no free physical extents\n");
                        $warnings++;
                    }
                }

                if ( grep( /^Stale PE/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    ( undef, undef, $STALEPE ) = split( /\s+/, $_ );
                    chomp($STALEPE);

                    if ( "$STALEPE" > 0 ) {
                        push(@PVARR,
"$WARNSTR PV $a has $STALEPE stale physical extents\n");
                        push(@CHECKARR,
"$WARNSTR PV $a has $STALEPE stale physical extents\n");
                        $warnings++;
                    }
                    else {
                        push(@PVARR,
"$PASSSTR PV $a has no stale physical extents\n");
                    }
                }

                if ( grep( /Alternate Link/, $_ ) ) {
                    ( undef, undef, $ALTLINK, undef, undef ) = split( /\s+/, $_ );
                    chomp($ALTLINK);
                    if ("$ALTLINK") {
                        push(@PVARR,
"$INFOSTR PV $a has alternate link $ALTLINK\n");
                    }
                    else {
                        push(@PVARR,
"$INFOSTR PV $a does not have alternate link\n");
                        $warnings++;
                    }
                }
            }
            close(VTB);
        }
        else {
            push(@PVARR,
"$WARNSTR PV $a seems not initialised in LVM or unavailable\n");
            push(@CHECKARR,
"\n$WARNSTR PV $a seems not initialised in LVM or unavailable\n");
            push(@NOTLVMARR, "$a");
            $warnings++;
        }

	push(@LVMARR, "PV		PVID		VGID\n");

        if ( $LVMTAB_FLAG == 0 ) {
            my @lvmtabcheck = `strings $LVMTAB | egrep $a`;
            if ( @lvmtabcheck != 0 ) {
                push(@PVARR, "$PASSSTR PV $a defined in LVM ($LVMTAB)\n");

                next if ( grep( /\Q$a\E/, @BADDISK ) );

                # xd may fail to read from raw disks if UNIX95 is set
                #
                if ( "$ENV{'UNIX95'}" == 1 ) {
                    $ENV{'UNIX95'} = '';
                }
          
                if ( open( VGPV, "xd -An -j8200 -N16 -tx $a |" ) ) {
                    while (<VGPV>) {
                        next if ( grep( /^$/, $_ ) );
                        $_ =~ s/^\s+//g;
                        chomp;
                        ($PVID1, $PVID2, $VGID1, $VGID2) = split( /\s+/, $_ );
                        $PVID = "$PVID1$PVID2";
                        $VGID = "$VGID1$VGID2";
                    }
                    close(VGPV);
                }

                if ( "$PVID" ) {
                    push(@PVARR, "$INFOSTR PV $a has PVID $PVID\n");
                }

                if ( "$VGID" ) {
                    push(@PVARR, "$INFOSTR PV $a is in volume group VGID $VGID\n");
                }

                push(@LVMARR, "$a	$PVID	$VGID\n");

                if ( "$Hardware" eq "ia64" ) {
                    foreach my $myidisk ( @Bootconfdsk ) {
                        if ( $a eq $myidisk ) {
                            chomp($a);
                            $a =~ s/s2//g;
                            $a =~ s/\/dsk\//\/rdsk\//g;
                            if ( "$Minor$Patch" >= 1131 ) {
                                $a =~ s/_p2//g;
                                $a =~ s/\/disk\//\/rdisk\//g;
                            }
                            my @idisk = `idisk $a`;
                            if ( @idisk != 0 ) {
                                push(@PVARR,
"\n$INFOSTR Listing of Itanium-based PV $a partitions\n");
                                push(@PVARR, @idisk);
                            }
                        }
                    }
                }
            }
            else {
                push(@PVARR,
"$WARNSTR PV $a seemingly unused and not defined in LVM ($LVMTAB)\n");
                push(@CHECKARR,
"\n$WARNSTR PV $a seemingly unused and not defined in ");
                push(@CHECKARR, "LVM ($LVMTAB)\n");
                $warnings++;
            }
            print "\n";
        }
    }

    if ( @PVARR ) {
        print "\n$INFOSTR PV status\n";
        print @PVARR;
    }

    if ( "@LVMARR" ) {
        print "\n$INFOSTR PVID and VGID summary\n";
        print @LVMARR;
    }

    if ( @ALLSRVPV ) {
        print "\n$INFOSTR PV descriptions\n";
        print @ALLSRVPV;
    }

    datecheck();
    print_trailer("*** END CHECKING PHYSICAL VOLUMES $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING CONTROLLER LOAD STATUS $datestring ***");

    my $scarr = scalar(@Allcontrollers);

    printf "$INFOSTR Server has %d disk controller%s\n", $scarr,
      $scarr == 1 ? "" : "s";

    foreach $svctrl ( keys %ctrllist ) {
        if ("$svctrl") {
            printf
              "\n$INFOSTR $svctrl contains %d physical volume%s\n\t%s",
              scalar( @{ $ctrllist{$svctrl} } ),
              scalar( @{ $ctrllist{$svctrl} } ) == 1 ? "" : "s";
            print "@{$ctrllist{$svctrl}}\n";
        }
    }

    if ( @VGPATH ) {
        print "\n$INFOSTR Volume group PV primary and alternate path usage\n";
        print @VGPATH;
    }

    datecheck();
    print_trailer("*** END CHECKING CONTROLLER LOAD STATUS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING PHYSICAL VOLUME TIMEOUTS $datestring ***");

    print "$NOTESTR Recommended values for disks and LUNs/VDISKs:
            XP/Hitachi          60 seconds
            EVA                180 seconds
            EMC                180 seconds
            all other          180 seconds\n\n";

    foreach my $a (@pvlist2) {
        $ACTUAL_VALUE =
          `pvdisplay $a 2>/dev/null | awk '/IO Timeout/ && ! /awk/ {print \$4}'`;
        chomp($ACTUAL_VALUE);
        if ( grep( /$a/, @Bootconfdsk ) ) {
            if ( "$VGSAN" eq "ALL" ) {
                if ( "$ACTUAL_VALUE" == $TIMEOUT ) {
                    print "$PASSSTR PV timeout for $a set to $TIMEOUT seconds\n";
                }
                elsif ( "$ACTUAL_VALUE" < $MINPVTIMEOUT ) {
                    print
"$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (recommended minimum of $MINPVTIMEOUT seconds)\n";
                    push(@CHECKARR,
"\n$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (recommended minimum of $MINPVTIMEOUT seconds)\n");
                    $warnings++;
                }
                else {
                    print
"$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (not $TIMEOUT seconds)\n";
                    push(@CHECKARR,
"\n$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (not $TIMEOUT seconds)\n");
                    $warnings++;
                }
            }
            elsif ( "$VGSAN" eq "NONVG0" ) {
                print
"$INFOSTR PV timeout for boot disk $a set to $TIMEOUT seconds\n";
            }
            elsif ( "$ACTUAL_VALUE" < $MINPVTIMEOUT ) {
                print
"$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (recommended minimum of $MINPVTIMEOUT seconds)\n";
                push(@CHECKARR,
"\n$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (recommended minimum of $MINPVTIMEOUT seconds)\n");
                $warnings++;
            }
            else {
                print
"$INFOSTR PV timeout for boot disk $a set to $TIMEOUT seconds\n";
            }
        }
        else {
            if ( "$ACTUAL_VALUE" == $TIMEOUT ) {
                print
                  "$PASSSTR PV timeout for $a set to $TIMEOUT seconds\n";
            }
            elsif ( "$ACTUAL_VALUE" < $MINPVTIMEOUT ) {
                print
"$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (recommended minimum of $MINPVTIMEOUT seconds)\n";
                push(@CHECKARR,
"\n$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (recommended minimum of $MINPVTIMEOUT seconds)\n");
                $warnings++;
            }
            else {
                print
"$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (not $TIMEOUT seconds)\n";
                push(@CHECKARR,
"\n$WARNSTR PV timeout for $a set to $ACTUAL_VALUE (not $TIMEOUT seconds)\n");
                $warnings++;
            }
        }
    }

    datecheck();
    print_trailer("*** END CHECKING PHYSICAL VOLUME TIMEOUTS $datestring ***");

    if ( ! @vxdctl0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING BAD BLOCK RELOCATION, MIRRORING, AND IO TIMEOUTS FOR LOGICAL VOLUMES $datestring ***");

        if ( "$Minor$Patch" < 1131 ) {
            print "$NOTESTR It should be set to OFF for BOOT/ROOT/SWAP/DUMP\n";
            print "$NOTESTR It should be set to ON for other VG00 lvols\n";
            print "$NOTESTR It should be set to $BBR for all non VG00 lvols\n\n";
        }
        else {
            print "$NOTESTR BBR is deprecated on HP-UX 11.31 and higher\n\n";
        }

        print "$NOTESTR LV timeout should be set to (2 x PVtimeout + 15) for a PV with PVLinks\n";
        print "$NOTESTR LV timeout should be set to PVtimeout for a PV without PVLinks\n\n";

        ( $bgval, undef ) = split( /\s+/, splice( @Boot, 0, 1 ) );
        ( $rgval, undef ) = split( /\s+/, splice( @Root, 0, 1 ) );
        ( $sgval, undef ) = split( /\s+/, splice( @Swap, 0, 1 ) );

        foreach $z (@lvlist) {
            if ( open( NN, "lvdisplay -v $z 2>/dev/null |" ) ) {
                my $stripesize = q{};
                my $stripeno   = q{};

                while (<NN>) {
                    push( @LVarr, "$_" );
                    next if ( grep( /^$/, $_ ) );
                    $_ =~ s/^\s+//g;
                    chomp;

                    @LVTOT = split( /\//, $z );
                    $lvreal = $LVTOT[-1];

                    my @swpgr = split( /\s+/, $_ );
                    if ( grep( /^\/dev\/dsk|^\/dev\/disk/, $swpgr[0] ) ) {
                        my $vals = $swpgr[0];
                        push( @{ $disklist{$vals} }, $z );
                    }

                    if ( grep( /^LV Status/, $_ ) ) {
                        ( undef, undef, $lvsst ) = split( /\s+/, $_ );
                        $LVSSTAT{$z} = $lvsst;
                    }

                    if ( grep( /^Mirror copies/, $_ ) ) {
                        ( undef, undef, $mirrno ) = split( /\s+/, $_ );
                        $LVMIRR{$z} = $mirrno;
                    }

                    if ( grep( /^LV Permission/, $_ ) ) {
                        ( undef, undef, $lvperm ) = split( /\s+/, $_ );
                        $LVPERMIS{$z} = $lvperm;
                    }

                    if ( grep( /^Bad block/, $_ ) ) {
                        ( undef, undef, $bblock ) = split( /\s+/, $_ );
                    }

                    if ( grep( /^Stripes/, $_ ) ) {
                        ( undef, $stripeno ) = split( /\s+/, $_ );
                        $LVSTRIPE{$z} = $stripeno;
                    }

                    if ( grep( /^Stripe Size/, $_ ) ) {
                        ( undef, undef, undef, $stripesize ) = split( /\s+/, $_ );
                    }

                    if ( ( $stripeno > 0 ) && ( $stripesize > 0 ) ) {
                        if ( ! grep(/\Q$z\E/, @STRIPEDVOLS ) ) {
                            push(@STRIPEDVOLS,
"Logical Volume $z has $stripeno stripes with stripe size $stripesize KB\n");
                        }
                    }

                    if ( grep( /^Allocation/, $_ ) ) {
                        ( undef, $allct ) = split( /\s+/, $_ );
                        $LVALOC{$z} = $allct;
                    }

                    if ( grep( /^IO Timeout/, $_ ) ) {
                        ( undef, undef, undef, $iotout ) = split( /\s+/, $_ );
                        if ( $iotout eq "default" ) {
                            print
"$PASSSTR LV $z has default timeout (\"default\")\n";
                        }
                        else {
                            print
"$WARNSTR LV $z has non-default timeout (\"$iotout\" instead of \"default\")\n";
                            push(@CHECKARR,
"$WARNSTR LV $z has non-default timeout (\"$iotout\" instead of \"default\")\n");
                            $warnings++;
                            if ( "$iotout" < $MINPVTIMEOUT ) {
                                print
"$WARNSTR LV timeout for $z set to non-default timeout $iotout (recommended minimum of $MINPVTIMEOUT seconds)\n";
                                push(@CHECKARR,
"$WARNSTR LV timeout for $z set to non-default timeout $iotout (recommended minimum of $MINPVTIMEOUT seconds)\n");
                                $warnings++;
                            }
                        }
                    }

                    if ( grep( /^LV Size/, $_ ) ) {
                        ( undef, undef, undef, $lvsize ) = split( /\s+/, $_ );
                        $LVSZ{$z} = $lvsize;
                    }

                    if ( grep( /stale/i, $_ ) ) {
                        print "$WARNSTR LV $z has stale extents\n";
                        push(@CHECKARR, "\n$WARNSTR LV $z has stale extents\n");
                        print "$_\n";
                        $warnings++;
                    }

                    if ( grep( /PX_NOPV/i, $_ ) ) {
                        print "$WARNSTR LV $z has corrupt extents\n";
                        push(@CHECKARR, "\n$WARNSTR LV $z has corrupt extents\n");
                        print "$_\n";
                        $warnings++;
                    }
                }
                close(NN);

                foreach my $hfsentry (@HFSARR) {
                    if ( "$hfsentry" eq "$z" ) {
                        $VXFSFLAG = "-F hfs";
                    }
                    else {
                        $VXFSFLAG = "-F vxfs -t 20";
                    }
                }

                my @LVOLRAW = split(/\//, $z);
                $LVOLRAW[$#LVOLRAW] = "r$LVOLRAW[$#LVOLRAW]";
                my $rawz = join("/", @LVOLRAW);
                my $justvg = "$LVOLRAW[0]/$LVOLRAW[1]";

                # fstyp(1) hangs if logical volume is gone:
                # Simple check to avoid it is to use fsadm:
                #
                # fsadm /dev/vghpvm/rhpvm0
                # fsadm: /etc/default/fs used for determining the file system type
                # UX:vxfs fsadm: ERROR: V-3-20275: cannot open /dev/vghpvm/rhpvm0
                #
                if ( ! grep(/\b$justvg\b/, @BADVG ) ) {
                    my @lvfsadm = `fsadm $VXFSFLAG $rawz 2>/dev/null`;
                    if ( @lvfsadm ) {
                        my @lvfstyp = `fstyp -v $z 2>/dev/null`;
                        if ( @lvfstyp ) {
                            push(@LVALLFSTYP, "File system $z:\n");
                            push(@LVALLFSTYP, @lvfstyp);
                            push(@LVALLFSTYP, "\n");
                        }

                        my @lvfsdb = `echo "8192B.p S" | fsdb $z 2>/dev/null`;
                        if ( @lvfsdb ) {
                            push(@LVALLFSTYP, "Super block status for $z:\n");
                            push(@LVALLFSTYP, @lvfsdb);
                            push(@LVALLFSTYP, "\n");
                        }
                    }
                }
            }
            else {
                print "$ERRSTR Cannot run lvdisplay for LV $z\n";
                push(@CHECKARR, "\n$ERRSTR Cannot run lvdisplay for LV $z\n");
                $warnings++;
            }

            my @PPP = split( /\//, $z );
            my $aln = "$PPP[$PPP - 1]";
            chomp($aln);

            if ( grep(/\b$aln\b/, @Dumplvol) ) {
                if ( "$mirrno" < 1 ) {
                    print "$PASSSTR LV $z has no mirrors (DUMP volume)\n";
                }
            }
            else {
                if ( grep(/\Q$z\E/, @STRIPEDVOLS) ) {
                    print "$INFOSTR LV $z is striped (RAID-0)\n";
                } elsif ( "$mirrno" < 1 ) {
                    print "$WARNSTR LV $z has no mirrors\n";
                    push(@CHECKARR, "\n$INFOSTR LV $z has no mirrors\n");
                    $warnings++;
                }
                elsif ( "$mirrno" == 1 ) {
                    print "$PASSSTR LV $z has one ($mirrno) mirror\n";
                }
                else {
                    print "$PASSSTR LV $z has $mirrno mirrors\n";
                }
            }

            print "$INFOSTR LV $z has size $lvsize MB\n";

            if ( grep( /\/dev\/vg00\//i, $z ) ) {
                if ( grep( /\b$bgval\b/, $z ) ) {
                    if ( "$allct" ne "$VG00ALLOCCONT" ) {
                        print
"$INFOSTR LV $z has non-default allocation policy ";
                        print "(\"$allct\" instead of \"$VG00ALLOCCONT\")\n";
                        $warnings++;
                    }
                    else {
                        print
"$PASSSTR LV $z has default allocation \"$allct\"\n";
                    }

                    if ( "$Minor$Patch" < 1131 ) {
                        if ( grep(/\b$aln\b/, @Dumplvol) ) {
                            if ( "$bblock" eq "$VG00BBR" ) {
                                print "$INFOSTR LV $z BBR has default ";
                                print "value (DUMP))\n\n";
                            }
                        }
                        else {
                            if ( "$bblock" ne "$VG00BBR" ) {
                                print "$INFOSTR LV $z BBR has non-default ";
                                print "value (\"$bblock\" instead of \"$VG00BBR\")\n\n";
                                $warnings++;
                            }
                            else {
                                print "$PASSSTR LV $z BBR has correct value ";
                                print "\"$bblock\"\n\n";
                            }
                        }
                    }
                }
                elsif ( grep( /\b$rgval\b/, $z ) ) {
                    if ( "$allct" ne "$VG00ALLOCCONT" ) {
                        print
                          "$INFOSTR LV $z has non-default allocation policy ";
                        print "(\"$allct\" instead of \"$VG00ALLOCCONT\")\n";
                        $warnings++;
                    }
                    else {
                        print
                          "$PASSSTR LV $z has default allocation \"$allct\"\n";
                    }
    
                    if ( "$Minor$Patch" < 1131 ) {
                        if ( "$bblock" ne "$VG00BBR" ) {
                            print "$INFOSTR Root LV $z BBR has non-default ";
                            print "value (\"$bblock\" instead of \"$VG00BBR\")\n\n";
                            $warnings++;
                        }
                        else {
                            print "$PASSSTR Root LV $z BBR has correct value ";
                            print "\"$bblock\"\n\n";
                        }
                    }
                }
                elsif ( grep( /\b$sgval\b/, $z ) ) {
                    if ( "$allct" ne "$VG00ALLOCCONT" ) {
                        print
"$INFOSTR LV $z has non-default allocation policy ";
                        print "(\"$allct\" instead of \"$VG00ALLOCCONT\")\n";
                        $warnings++;
                    }
                    else {
                        print
                          "$PASSSTR LV $z has default allocation \"$allct\"\n";
                    }

                    if ( "$Minor$Patch" < 1131 ) {
                        if ( "$bblock" ne "$VG00BBR" ) {
                            print "$INFOSTR Swap LV $z BBR has non-default ";
                            print "value (\"$bblock\" instead of \"$VG00BBR\")\n\n";
                            $warnings++;
                        }
                        else {
                            print "$PASSSTR Swap LV $z BBR has correct value ";
                            print "\"$bblock\"\n\n";
                        }
                    }
                }
                elsif ( grep( /\b$aln\b/, $z ) ) {
                    if ( "$allct" ne "$VG00ALLOCCONT" ) {
                        print
                          "$PASSSTR LV $z has default allocation \"$allct\"\n";
                    }
                    else {
                        print
                          "$INFOSTR LV $z has non-default allocation policy ";
                        print "(\"$allct\" instead of \"$VG00ALLOCNONCONT\")\n";
                        $warnings++;
                    }

                    if ( "$Minor$Patch" < 1131 ) {
                        if ( "$bblock" eq "$VG00BBR" ) {
                            print "$INFOSTR LV $z BBR has non-default ";
                            print "value (\"$bblock\" instead of \"$VG00BBR\")\n\n";
                            $warnings++;
                        }
                        else {
                            print "$PASSSTR LV $z BBR has correct value ";
                            print "\"$bblock\"\n\n";
                        }
                    }
                }
                elsif ( "$bblock" ne "on" ) {
                    if ( "$allct" ne "$VG00ALLOCNONCONT" ) {
                        print
"$INFOSTR LV $z has non-default allocation policy ";
                        print "(\"$allct\" instead of \"$VG00ALLOCNONCONT\")\n";
                        $warnings++;
                    }
                    else {
                        print
                          "$PASSSTR LV $z has default allocation \"$allct\"\n";
                    }

                    if ( "$Minor$Patch" < 1131 ) {
                        print "$WARNSTR LV $z BBR has non-default value ";
                        print "(\"$bblock\" instead of \"on\")\n\n";
                        push(@CHECKARR, "\n$WARNSTR LV $z BBR has non-default value ");
                        push(@CHECKARR, "(\"$bblock\" instead of \"on\")\n\n");
                        $warnings++;
                    }
                }
                else {
                    if ( "$allct" ne "$VG00ALLOCNONCONT" ) {
                        print
                          "$INFOSTR LV $z has non-default allocation policy ";
                        print "(\"$allct\" instead of \"$VG00ALLOCNONCONT\")\n";
                        $warnings++;
                    }
                    else {
                        print
                          "$PASSSTR LV $z has default allocation \"$allct\"\n";
                    }

                    if ( "$Minor$Patch" < 1131 ) {
                        print
                          "$PASSSTR VG00 LV $z BBR has default value \"on\"\n\n";
                    }
                }
            }
            else {
                if ( grep(/\Q$z\E/, @SWAPARRAY) ) {
                    if ( "$allct" eq "$VG00ALLOCCONT" ) {
                        print
"$PASSSTR LV $z has default allocation \"$allct\" (recommended for swap)\n";
                    }
                    else {
                        print "$INFOSTR LV $z has non-default allocation policy ";
                        print
"(\"$allct\" instead of \"$VG00ALLOCCONT\" as recommended for swap)\n";
                        $warnings++;
                    }

                    if ( "$Minor$Patch" < 1131 ) {
                        if ( "$bblock" ne "$BBR" ) {
                            print
"$PASSSTR LV $z BBR has default value \"$BBR\" (recommended for swap)\n\n";
                        }
                        else {
                            print "$INFOSTR LV $z BBR has non-default value ";
                            print
"(\"$bblock\" instead of \"$BBR\" as recommended for swap)\n\n";
                            $warnings++;
                        }
                    }
                }
                else {
                    if ( "$allct" ne "$VG00ALLOCNONCONT" ) {
                        print "$INFOSTR LV $z has non-default allocation policy ";
                        print "(\"$allct\" instead of \"$VG00ALLOCNONCONT\")\n";
                        $warnings++;
                    }
                    else {
                        print "$PASSSTR LV $z has default allocation \"$allct\"\n";
                    }

                    if ( "$Minor$Patch" < 1131 ) {
                        if ( "$bblock" ne "$BBR" ) {
                            print "$INFOSTR LV $z BBR has non-default value ";
                            print "(\"$bblock\" instead of \"$BBR\")\n\n";
                            $warnings++;
                        }
                        else {
                            print "$PASSSTR LV $z BBR has default value \"$BBR\"\n\n";
                        }
                    }
                }
            }
        }

        datecheck();
        print_trailer("*** END CHECKING BAD BLOCK RELOCATION, MIRRORING, AND IO TIMEOUTS FOR LOGICAL VOLUMES $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING LOGICAL VOLUMES $datestring ***");

    if ( @LVarr != 0 ) {
        print "$INFOSTR Logical volumes defined\n";
        print @LVarr;
    }
    else {
        print "$INFOSTR No logical volumes defined\n";
    }

    my @LVinfo = `lvlist -pn 2>/dev/null`;
    if ( @LVinfo ) {
        print "\n$INFOSTR Lvlist\n";
        print @LVinfo;
        print "\n";
    }

    if ( @STRIPEDVOLS ) {
        print @STRIPEDVOLS;
    }
    else {
        print "\n$INFOSTR There are no striped (RAID-0) logical volumes\n";
    }

    if ( @LVALLFSTYP ) {
        print "\n$INFOSTR Checking file system type for logical volumes\n";
        print @LVALLFSTYP;
    }

    foreach $servdsk ( sort keys %disklist ) {
        print
"\n$INFOSTR Physical volume $servdsk contains logical volumes @{$disklist{$servdsk}}\n";
    }

    datecheck();
    print_trailer("*** END CHECKING LOGICAL VOLUMES $datestring ***");

    datecheck();
    print_header("*** BEGIN LVM SUMMARY $datestring ***");

    print "PV                    VG                    Status            PVSize     PVFree\n";
    foreach my $PVkey (@pvlist) {
        chomp($PVkey);
        printf "%-20s  %-20s  %-15s  %6.2fGB  %6.2fGB\n",
                $PVkey,
                $PVGN{$PVkey},
                $PVAL{$PVkey},
                ( $PVALOC{$PVkey} * $PVSIZE{$PVkey} ) / 1024,
                ( $PVFREE{$PVkey} * $PVSIZE{$PVkey} ) / 1024;
    }

    print "\nLV                    Status               LVSize      Permissions     Mirrors  Stripes      Allocation\n";
    foreach my $LVkey (@lvlist) {
        chomp($LVkey);
        printf "%-20s  %-15s  %8.2fGB  %14s         %-3d      %-3d     %-s\n",
                $LVkey,
                $LVSSTAT{$LVkey},
                $LVSZ{$LVkey} / 1024,
                $LVPERMIS{$LVkey},
                $LVMIRR{$LVkey},
                $LVSTRIPE{$LVkey},
                $LVALOC{$LVkey}; 
    }

        
    print "\nVG                   PVs   LVs    Status                  VGVer    VGSize    VGFree\n";
    foreach my $VGkey (@ACTIVEVGARRAY) {
        chomp($VGkey);

        if ( "$Minor$Patch" == 1111 ) {
            $VGverc{$VGkey} = "1.0";
        }

        if ( grep(/deactivated/i, $VGstatus{$VGkey}) ) {
            printf "%-20s  %-4d  %-4d  %-23s\n",
                    $VGkey,
                    $VGpeact{$VGkey},
                    $VGcurLV{$VGkey},
                    $VGstatus{$VGkey};
        }
        else {
            printf "%-20s  %-4d  %-4d  %-23s  %-4.1f  %6.2fGB  %6.2fGB\n",
                    $VGkey,
                    $VGpeact{$VGkey},
                    $VGcurLV{$VGkey},
                    $VGstatus{$VGkey},
                    $VGverc{$VGkey},
                    ( $VGpes{$VGkey} * $VGpetot{$VGkey} ) / 1024,
                    ( $VGpes{$VGkey} * $VGfpe{$VGkey} ) / 1024;
        }
    }

    if ( @DEACTTARR ) {
        print @DEACTTARR;
    }

    datecheck();
    print_trailer("*** END LVM SUMMARY $datestring ***");
}

# Subroutine to check basic performance
#
sub PERFORMANCE_BASICS {
    datecheck();
    print_header("*** BEGIN CHECKING BASIC PERFORMANCE $datestring ***");

    if ( "$Minor$Patch" <= 1123 ) {
        if ( $swapmemflag == 0 ) {
            print "$INFOSTR Kernel parameter \"swapmem_on\" is set to 0\n";
            print
"$INFOSTR swapinfo(1M) will not show \"memory\" in the report\n";
        }
        else {
            if ( ! "$swapmemflag" ) {
                print
"$NOTESTR swapinfo(1M) will not show \"memory\" in the report if kernel parameter \"swapmem_on\" is set to 0\n\n";
            }
        }
    }

    my @SWUSED = `swapinfo -ta`;

    if ( @SWUSED ) {
        print "\n$INFOSTR Swap usage\n";
        print @SWUSED;
    }
    else {
       if ( @ALLSWAPINFO ) {
           print "\n$INFOSTR Swap usage\n";
           print @ALLSWAPINFO;
       }
    }

    my $USED = `swapinfo -ta | awk '/total/ && ! /awk/ {print \$5}'`;
    chomp($USED);
    $USED =~ s/%//g;
    my $FREESPACE = 100 - $USED;
    if ( "$FREESPACE" < "$SWAP_THRESHOLD" ) {
        print
"\n$WARNSTR Swap free below $SWAP_THRESHOLD% (current usage $USED%)\n";
        push(@CHECKARR,
"\n$WARNSTR Swap free below $SWAP_THRESHOLD% (current usage $USED%)\n");
        $warnings++;
    }
    else {
        print
"$PASSSTR Swap free over $SWAP_THRESHOLD% (current usage $USED%)\n";
    }

    my @VMSTATS = `vmstat -s 2>/dev/null`;
    if ( "@VMSTATS" ) {
        print "\n$INFOSTR Virtual memory counters\n";
        print @VMSTATS;
    }

    my @VMSTAT = `vmstat $DELAY $ITERATIONS 2>/dev/null`;
    if ( @VMSTAT ) {
        print "\n$INFOSTR Virtual memory statistics\n";
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

    if ( "$Minor$Patch" >= 1131 ) {
        $READFLAG="R";
    }

    my @SARD = `sar -d${READFLAG} $DELAY $ITERATIONS 2>/dev/null`;
    if ( @SARD ) {
        print "\n$INFOSTR Disk activity\n";
        print @SARD;
    }

    my @SARL = `sar -L $DELAY $ITERATIONS 2>/dev/null`;
    if ( @SARL ) {
        print "\n$INFOSTR Lunpath activity\n";
        print @SARL;
    }

    my @SARH = `sar -H $DELAY $ITERATIONS 2>/dev/null`;
    if ( @SARH ) {
        print "\n$INFOSTR Controller activity\n";
        print @SARH;
    }

    if ( @vxdctl0 ) {
        my @vxmemstat = `vxmemstat 2>/dev/null`;
        if ( @vxmemstat ) {
            print "\n$INFOSTR VxVM memory status\n";
            print @vxmemstat;
        }
    }

    foreach my $fsc ( sort @MAU ) {
        chomp($fsc);
        my @vxfsstat = `vxfsstat -i $fsc 2>/dev/null`;
        if ( @vxfsstat ) {
            print "\n$INFOSTR VxFS statistics for file system $fsc\n";
            print @vxfsstat;
        }
    }

    my @TOP1 = `top -w -P -d 1 2>/dev/null`;
    if ( @TOP1 ) {
        print "\n$INFOSTR Basic top(1M) report\n";
        print @TOP1;
        print "\n";
    }

#    my @GLANCE1 = `glance -j 20 -advisor_only -iterations 1 2>/dev/null`;
#    if ( @GLANCE1 ) {
#        print "\n$INFOSTR Basic glance(1M) report\n";
#        print @GLANCE1;
#    }


    my @PSSORT = `$XPG4VAR ps -e -o vsz,sz,cpu,state,pid,ppid,time,user,args | sort -rn 2>/dev/null`;
    if ( @PSSORT ) {
        print "\n$INFOSTR Extended ps(1M) report with top memory usage ($XPG4VAR variable enabled)\n";
        print @PSSORT;
    }

    my @PSSORT2 = `$XPG4VAR ps -e -o pcpu,pid,ruser,args | sort -rn 2>/dev/null`;
    if ( @PSSORT2 ) {
        print "\n$INFOSTR Extended ps(1M) report with top CPU usage ($XPG4VAR variable enabled)\n";
        print @PSSORT2;
    }

    my @CALIPER1 = `caliper fprof -w -e60 2>/dev/null`;
    if ( @CALIPER1 ) {
        print "\n$INFOSTR Caliper flat profile report\n";
        print @CALIPER1;
    }

    my @CALIPER4 = `caliper cpu -w -e60 2>/dev/null`;
    if ( @CALIPER4 ) {
        print "\n$INFOSTR Caliper CPU report\n";
        print @CALIPER4;
    }

    my @CALIPER2 = `caliper dcache -w -e60 2>/dev/null`;
    if ( @CALIPER2 ) {
        print "\n$INFOSTR Caliper data cache report\n";
        print @CALIPER2;
    }

    my @CALIPER3 = `caliper dtlb -w -e60 2>/dev/null`;
    if ( @CALIPER3 ) {
        print "\n$INFOSTR Caliper data translation lookaside buffer (TLB) report\n";
        print @CALIPER3;
    }

    my @KMEMINFO1 = `kmeminfo 2>/dev/null`;
    if ( @KMEMINFO1 ) {
        print "\n$INFOSTR Kmeminfo report\n";
        print @KMEMINFO1;
    }

    my @KMEMINFO2 = `kmeminfo -arena 2>/dev/null`;
    if ( @KMEMINFO2 ) {
        print "\n$INFOSTR Kmeminfo report\n";
        print @KMEMINFO2;
    }

    datecheck();
    print_trailer("*** END CHECKING BASIC PERFORMANCE $datestring ***");
}

# Subroutine to check Performance Agents 
#
sub MWA_STATUS {
    datecheck();
    print_header("*** BEGIN CHECKING PERFORMANCE AGENTS (GLANCE/MEASUREWARE) $datestring ***");

    my @MWAproc = (
        "scopeux",    "midaemon", "ttd", "alarmgen",
        "agdbserver", "perflbd",  "rep_server",
	"ovcd", "ovbbccb", "coda", "perfalarm",
    );

    if ( -s "$GLANCECF" ) {
        my @glancecat = `awk NF $GLANCECF 2>/dev/null`;
        if ( @glancecat ) {
            print "$INFOSTR Configuration file $GLANCECF\n";
            print @glancecat;
            print "\n";
        }
    }

    my @mmu = `mwa status 2>/dev/null`;
    if ( @mmu ) {
        foreach my $u (@MWAproc) {
            if ( grep( /Running $u/i, @mmu ) ) {
                print "$PASSSTR Performance Agent process $u running\n";
            }
            else {
		if ( "$u" eq "coda" ) {
		    $CODAWARN++;
                }
                print "$WARNSTR Performance Agent process $u not running\n";
                push(@CHECKARR, "\n$WARNSTR Performance Agent process $u not running\n");
                $warnings++;
            }
        }

        my @utilitys = `utility -xs 2>&1`;
        if ( @utilitys ) {
            print "\n$INFOSTR Performance Agent utility summary report\n";
            print @utilitys;
        }

	if ( $CODAWARN == 0 ) {
            my @utility = `utility -D -xc 2>&1`;
            if ( @utility ) {
                print "\n$INFOSTR Performance Agent utility check report\n";
                print @utility;
            }

            my @utilitya = `utility -xa -D 2>&1`;
            if ( @utilitya ) {
                print "\n$INFOSTR Performance Agent alarm analysis\n";
                print @utilitya;
            }
        }

        my @perfst = `perfstat -c 2>/dev/null`;
        if ( @perfst ) {
            print "\n$INFOSTR Perfstat system configuration report\n";
            print @perfst;
        }

        my @perfsp = `perfstat -p 2>/dev/null`;
        if ( @perfsp ) {
            print "\n$INFOSTR Perfstat active performance tool processes\n";
            print @perfsp;
        }

        my @perfste = `perfstat -e 2>/dev/null`;
        if ( @perfste ) {
            print "\n$INFOSTR Perfstat warnings and errors from status files\n";
            print @perfste;
        }

        my @perfstv = `perfstat -v 2>/dev/null`;
        if ( @perfstv ) {
            print "\n$INFOSTR Perfstat permissions and version strings for key performance tools\n";
            print @perfstv;
        }

        my @perfstf = `perfstat -f 2>/dev/null`;
        if ( @perfstf ) {
            print "\n$INFOSTR Perfstat size of status files\n";
            print @perfstf;
        }

        my @agsysdb = `agsysdb -l 2>/dev/null`;
        if ( @agsysdb ) {
            print "\n$INFOSTR PA alarming status\n";
            print @agsysdb;
        }
    }
    else {
        print "$WARNSTR  Performance Agents possibly not installed or corrupt\n";
        push(@CHECKARR, "\n$WARNSTR Performance Agent possibly not installed or corrupt\n");
    }

    datecheck();
    print_trailer("*** END CHECKING PERFORMANCE AGENTS (GLANCE/MEASUREWARE) $datestring ***");
}

# Subroutine to check syslog
#
sub SYSLOG_LOGGING {
    datecheck();
    print_header("*** BEGIN CHECKING SYSLOG OPERATIONAL $datestring ***");

    if ( $SYSLOG_FLAG == 0 ) {
        print "$WARNSTR Syslog daemon (syslogd or syslog-ng) not running\n";
        push(@CHECKARR,
"\n$WARNSTR Syslog daemon (syslogd or syslog-ng) not running\n");
        print "\n";
    }

    -s "$syslogng_conf1"      ? $syslogng_conf = $syslogng_conf1
       : -s "$syslogng_conf2" ? $syslogng_conf = $syslogng_conf2
       : print "$INFOSTR Syslog-NG seemingly not installed\n";

    if ( -s "$syslogng_conf" ) {
        if ( open( SYSNG, "egrep -v ^# $syslogng_conf |" ) ) {
            print "\n$INFOSTR File $syslogng_conf\n";
            while (<SYSNG>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /info/, $_ ) ) {
                    ( undef, $RSYSLOG ) = split( /\s+/, $_ );
                }
                print $_;
            }
        }
        else {
            print "\n$WARNSTR Cannot open $syslogng_conf\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $syslogng_conf\n");
            $warnings++;
        }
        close(SYSNG);
    }

    my $DDate  = rand();
    my $LOGSTR = "AUTOMATED TEST MESSAGE $DDate FOR OAT. PLEASE IGNORE";
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

    if ( @WARNSLOGARR ) {
        print "\n";
        print @WARNSLOGARR;
    }
    else {
        print "\n$PASSSTR Syslog file $syslog_conf contains TABS as separator\n";
    }

    if ( "$Secure_SYSLOGD" == 1 ) {

        #  use Sys::Syslog qw(:DEFAULT setlogsock);
        #  setlogsock("stream") || die "Error: Cannot open setlogsock\n";
        system("logger $LOGSTR 2>/dev/null");
    }
    else {
        if ( eval "require Sys::Syslog" ) {
            import Sys::Syslog;
            use Sys::Syslog;
            openlog( '$SYSLOG', 'ndelay', 'daemon' );
            syslog( 'info', "$LOGSTR" );
            closelog();
        }
        else {
            system("logger $LOGSTR 2>/dev/null");
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

    my @logfind = `awk '/PX_NOVG|[Nn]ospace|full|[Rr]eset|[Ee]rror|[Ff]ail|[Ww]arn|[Cc]rit|died/ && ! /awk/ {print}' $SYSLOG`;
    if (@logfind) {
        print "\n$INFOSTR Recent syslog entries of interest\n";
        print @logfind;
    }

    if ( $STAND_FLAG > 0 ) {
        my @dmesglog = `dmesg 2>/dev/null`;
        if (@dmesglog) {
            print "\n$INFOSTR Recent dmesg entries\n";
            print @dmesglog;

            my @dmesge = grep(/error|fail|warn|crit/i, @dmesglog);
            if (@dmesge) {
                print "\n$INFOSTR Recent dmesg entries of interest (errors, faults, warnings)\n";
                print @dmesge;
            }
        }
    }
    else {
        print
          "\n$WARNSTR /stand possibly not mounted! Dmesg check not valid\n";
        push(@CHECKARR,
          "\n$WARNSTR /stand possibly not mounted! Dmesg check not valid\n");
        $warnings++;
    }

    if ( -s "$btmplog" ) {
        my @btmp = `lastb 2>/dev/null | awk NF`;
        if (@btmp) {
            print "\n$INFOSTR Recent unsuccessful login attempts\n";
            print @btmp;
        }

        my $bdev     = 0;
        my $bino     = 0;
        my $bmode    = 0;
        my $bnlink   = 0;
        my $buid     = 0;
        my $bgid     = 0;
        my $brdev    = 0;
        my $bsize    = 0;
        my $batime   = 0;
        my $bmtime   = 0;
        my $bctime   = 0;
        my $bblksize = 0;
        my $bblocks  = 0;

        ( $bdev,   $bino,     $bmode, $bnlink, $buid,
          $bgid,   $brdev,    $bsize, $batime, $bmtime,
          $bctime, $bblksize, $bblocks,
        ) = stat($btmplog);

        my $bfile_perms = $bmode & 0777;
        my $boct_perms = sprintf "%lo", $bfile_perms;

        if ( ( $boct_perms != "400" ) && ( $boct_perms != "600" ) ) {
            print
"\n$WARNSTR Security risk: $btmplog permissions not 600 or 400 ($boct_perms)\n";
            push(@CHECKARR,
"\n$WARNSTR Security risk: $btmplog permissions not 600 or 400 ($boct_perms)\n");
            $warnings++;
        }
        else {
            print "\n$PASSSTR $btmplog permissions are 400\n";
        }

        if ( "$buid" == 0 ) {
            print "\n$PASSSTR $btmplog owned by UID $buid\n";
        }
        else {
            print "\n$WARNSTR $btmplog not owned by UID 0 ($buid)\n";
            push(@CHECKARR, "\n$WARNSTR $btmplog not owned by UID 0 ($buid)\n");
            $warnings++;
        }

        if ( $bblocks >= $WTMP_THRESHOLD ) {
            print
"$WARNSTR $btmplog large (threshold is 50 MB)\n";
            if ( $bsize > 0 ) {
                print "$INFOSTR $btmplog is ", $bblocks, " KB\n";
            }
            push(@CHECKARR,
"\n$WARNSTR $btmplog large (threshold is 50 MB)\n");
            $warnings++;
            print "\n";
        }
        else {
            print
"$PASSSTR $btmplog smaller than threshold 50 MB\n";
            if ( $bsize > 0 ) {
                print
"$INFOSTR $btmplog size is ", $bblocks, " KB\n";
            }
            print "\n";
        }
    }
    else {
        print "\n$WARNSTR Bad login attempts not logged in $btmplog\n";
        push(@CHECKARR, "\n$WARNSTR Bad login attempts not logged in $btmplog\n");
        $warnings++;
    }

    if ( -s "$wtmpfile" ) {
        my $bdev     = 0;
        my $bino     = 0;
        my $bmode    = 0;
        my $bnlink   = 0;
        my $buid     = 0;
        my $bgid     = 0;
        my $brdev    = 0;
        my $bsize    = 0;
        my $batime   = 0;
        my $bmtime   = 0;
        my $bctime   = 0;
        my $bblksize = 0;
        my $bblocks  = 0;

        ( $bdev,   $bino,     $bmode, $bnlink, $buid,
          $bgid,   $brdev,    $bsize, $batime, $bmtime,
          $bctime, $bblksize, $bblocks,
        ) = stat($wtmpfile);

        my $bfile_perms = $bmode & 0777;
        my $boct_perms = sprintf "%lo", $bfile_perms;

        if ( "$buid" == 0 ) {
            print "\n$PASSSTR $wtmpfile owned by UID $buid\n";
        }
        else {
            print "\n$WARNSTR $wtmpfile not owned by UID 0 ($buid)\n";
            push(@CHECKARR, "\n$WARNSTR $wtmpfile not owned by UID 0 ($buid)\n");
            $warnings++;
        }

        if ( $bblocks >= $WTMP_THRESHOLD ) {
            print
"$WARNSTR $wtmpfile large (threshold is 50 MB)\n";
            if ( $bsize > 0 ) {
                print "$INFOSTR $wtmpfile is ", $bblocks, " KB\n";
            }
            push(@CHECKARR,
"\n$WARNSTR $wtmpfile large (threshold is 50 MB)\n");
            $warnings++;
            print "\n";
        }
        else {
            print
"$PASSSTR $wtmpfile smaller than threshold 50 MB\n";
            if ( $bsize > 0 ) {
                print
"$INFOSTR $wtmpfile size is ", $bblocks, " KB\n";
            }
            print "\n";
        }
    }
    else {
        print "\n$WARNSTR Login attempts not logged in $wtmpfile (file missing or empty)\n";
        push(@CHECKARR, "\n$WARNSTR Login attempts not logged in $wtmpfile (file missing or empty)\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING SYSLOG OPERATIONAL $datestring ***");
}

# Subroutine to check Integrity VMs 
#
sub DIAG_CHECK_BOOT_LIF {
    if ( "$Hardware" eq "ia64" ) {
        datecheck();
        print_header("*** BEGIN CHECKING INTEGRITY VIRTUAL MACHINES $datestring ***");

        @VMcheck = `hpvminfo -V -v 2>/dev/null`;
        if ( @VMcheck ) {
            print "$INFOSTR VM information\n";
	    print "$NOTESTR If running on an HPVM host, no other application or software should be running as best practice\n";
            print @VMcheck;
        }

        my @VMcheck2 = `hpvminfo -S 2>/dev/null`;
        if ( @VMcheck2 ) {
            print "\n$INFOSTR VM ident information\n";
            print @VMcheck2;
        }

        my @linkinfo = `linkinfo HPVM -s vsp 2>/dev/null`;
        if ( "@linkinfo" ) {
            print "\n$INFOSTR Linkinfo status for HPVM on VSP\n";
            print @linkinfo;
        }

        if ( ( @VMcheck2 ) && ( $HPVM_FLAG > 0 ) ) {
            my @VMstatus0 = `hpvmstatus 2>/dev/null`;
            if ( @VMstatus0 ) {
                print "\n$INFOSTR VM status\n";
                print @VMstatus0;
            }

            my @HPVMARR = `hpvmstatus -M 2>/dev/null | cut -d: -f1`;
            foreach my $hpvmguest (@HPVMARR) {
                chomp($hpvmguest);
                my @VMstatusP = `hpvmstatus -P $hpvmguest -V 2>/dev/null`;
                if (@VMstatusP) {
                    print "\n$INFOSTR VM guest $hpvmguest status\n";
                    print @VMstatusP;
                }

                my @VMstatusD = `hpvmstatus -P $hpvmguest -D 2>/dev/null`;
                if (@VMstatusD) {
                    print "\n$INFOSTR VM guest $hpvmguest deferred resource assignment (activated after next boot)\n";
                    print @VMstatusD;
                }

                my @VMnvram = `hpvmnvram -P $hpvmguest -l 2>/dev/null | awk NF`;
                if (@VMnvram) {
                    print "\n$INFOSTR VM guest $hpvmguest boot options\n";
                    print @VMnvram;
                }

                if ( open( HPVMD, "hpvmstatus -d -P $hpvmguest -v 2>/dev/null | awk NF |" ) ) {
                    print "\n$INFOSTR VM guest $hpvmguest device list in command-line format\n";
                    while (<HPVMD>) {
                        print $_;
                        chomp($_);
                        if ( grep(/^disk|^network|^dvd/, $_) ) {
                            push(@IVD, "$_\n");
                        }
                    }
                    close(HPVMD);
                }

                if ("@IVD") {
	      	    print "\n$INFOSTR VM guest $hpvmguest drivers\n";
                    if ( "$Minor$Patch" >= 1131 ) {
	      	        print "$NOTESTR With HP-UX 11iv3 and above, AVIO drivers are strongly recommended as best practice\n";
	      	        print "$NOTESTR With HP-UX 11iv3 and above, Agile DSFs (avoid Legacy DSFs) are strongly recommended as best practice\n";
                    }
		    print @IVD;
	        }
            }
    
            if ( open( HPVMM, "hpvmstatus -v -V 2>/dev/null |" ) ) {
                while (<HPVMM>) {
                    chomp($_);
                    if ( grep(/^Version/, $_) ) {
                        (undef, $HPVMVERSION) = split(/\s+/, $_);
                        (undef, $HPVMVERSION2, undef) = split(/\./, $HPVMVERSION);
                    }
                }
                close(HPVMM);
            }

            my @VMstatuss = `hpvmstatus -s 2>/dev/null`;
            if (@VMstatuss) {
                print "\n$INFOSTR VM host resource status\n";
                print @VMstatuss;
            }

            my @VMstatus2 = `hpvmstatus -S 2>/dev/null`;
            if (@VMstatus2) {
                print "\n$INFOSTR VM host gWLM resource status\n";
                print @VMstatus2;
            }

            my @VMstatus3 = `hpvmstatus -m 2>/dev/null`;
            if (@VMstatus3) {
                print "\n$INFOSTR VM Serviceguard status\n";
                print @VMstatus3;
            }

            my @VMstatus4 = `hpvmstatus -C 2>/dev/null`;
            if (@VMstatus4) {
                print "\n$INFOSTR VM memory allocation\n";
                print @VMstatus4;
            }

            my @VMdevmgt = `hpvmdevmgmt -V -l all 2>/dev/null`;
            if (@VMdevmgt) {
                print "\n$INFOSTR VM device management\n";
                print @VMdevmgt;
            }

            my @VMnet = `hpvmnet -V 2>/dev/null`;
            if (@VMnet) {
                print "\n$INFOSTR VM vswitch status\n";
                print @VMnet;
            }

            my @vmmgmt = `hpvmmgmt -V 2>/dev/null`;
            if (@vmmgmt) {
                print "\n$INFOSTR Dynamic data within VM guest environment\n";
                print @vmmgmt;
            }

            my @VMdioc = `hpvmhwmgmt -p dio -l 2>/dev/null`;
            if (@VMdioc) {
                print "\n$INFOSTR VM host DIO capabilities\n";
                print @VMdioc;
            }

            my @VMdio = `hpvmdiomgmt 2>/dev/null`;
            if (@VMdio) {
                print "\n$INFOSTR VM DIO status\n";
                print @VMdio;
            }

            my @VMhw = `hpvmhwmgmt -p cpu -l 2>/dev/null`;
            if (@VMhw) {
                print "\n$INFOSTR VM CPU avilability\n";
                print @VMhw;
            }

            my @VMsar = `DISPLAY=""; export DISPLAY ; hpvmsar -s 5 -n 10 -M -A 2>/dev/null`;
            if (@VMsar) {
                print "\n$INFOSTR VM system accounting status\n";
                print @VMsar;
            }

            my @iodebuggvsd = `iodebug -gvsd 2>/dev/null`;
            if ( @iodebuggvsd ) {
                print
"\n$INFOSTR WTEC iodebug for guest side AVIO Virtual Storage Driver gvsd\n";
                print @iodebuggvsd;
            }

            my @iodebughvsd = `iodebug -hvsd 2>/dev/null`;
            if ( @iodebughvsd ) {
                print
"\n$INFOSTR WTEC iodebug for host side AVIO Virtual Storage Driver gvsd\n";
                print @iodebughvsd;
            }
        }
        else {
            print "$INFOSTR VM seemingly not in use or installed\n";
        }
    }

    if ( ( @VMcheck ) && ( $HPVM_FLAG > 0 ) ) {
        if ( "$HPVMVERSION2" < 4 ) {
            print "\n$INFOSTR Checking VM physical memory requirements\n";

            my $fixed750 = int($MEM_MBYTE - 750);
            my $sp75pc = int($fixed750 - ($fixed750 * 0.075));
            my $sevp = int($sp75pc - ($sp75pc * 0.075));
            my $VMm = $sevp % 64;
            my $VMval = int( $sevp / 64 );
            my $VMSIZE = $VMval * 64;

            if ( $VMm > 0 ) {
                $VMSIZE = ( $VMval * 64 ) + 64;
            }

            print
"\tPhysical memory:                                      $MEM_MBYTE MB\n";
            print
"\tLess Fixed 750 MB host requirement:                   $fixed750 MB\n";
            print
"\tLess 7.5% of remaining physical memory:               $sp75pc MB\n";
            print
"\tMaximum guest assignment allowing for 7% overhead:    $sevp MB\n";
            print
"\tMaximum guest assignment allowing for 64 MB rounding: $VMSIZE MB\n";

            print
"\nTypical example: allocate minimum of 3 GB for an HP-UX guest\n";
            print
"(guest requires 2 GB, plus 1 GB operating system)\n";
        }

        datecheck();
        print_trailer("*** END CHECKING INTEGRITY VIRTUAL MACHINES $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING DIAGNOSTICS ENVIRONMENT (ODE) ON BOOT DISKS $datestring ***");
   
    if ( ! @Boot) {
        print "$ERRSTR Boot disks undefined in lvlnboot!\n\n";
        push(@CHECKARR, "\n$ERRSTR Boot disks undefined in lvlnboot\n");
        $warnings++;
    }

    if ( "$Hardware" eq "ia64" ) {
        foreach $f (@Boot) {
            #
            # The boot disk of Itanium servers has four partitions:
            # s0 - entire disk
            # s1 - EFI
            # s2 - OS
            # s3 - HP support tools (service partition)
            #
            my $f2 = $f;
            $f2 =~ s/_p2/_p3/g;
            $f2 =~ s/s2/s3/g;

            $f =~ s/_p2/_p1/g;
            $f =~ s/s2/s1/g;

            if ( ! grep(/\s+/, $f2) ) {
                my @lifls2 = `efi_ls -d $f2 2>&1 | awk NF`;
                if ( @lifls2 ) {
                    print "\n$INFOSTR HPSP partition $f2\n";
                    print @lifls2;
                }
            }

            my @es = `efi_ls -d $f2 /EFI/HP/DIAG/ODE 2>/dev/null`;
            if ( @es ) {
                print
"$INFOSTR Service Partition (HPSP) contents in /EFI/HP/DIAG/ODE on boot disk $f2\n";
                print @es;
            }

            my $HPSPTMP = "/tmp/hpspversion-OAT.txt";
            `efi_cp -d $f2 -u /EFI/HP/DIAG/DOCUMENTATION/version.txt $HPSPTMP 2>/dev/null`;
            if ( -s "$HPSPTMP" ) {
                my $ishpsp = `awk '/^Current Version/ {print \$3, \$4, \$5}' $HPSPTMP 2>/dev/null`;
                if ( "$ishpsp" ) {
                    print "$INFOSTR Service Partition (HPSP) ODE release\n";
                    print $ishpsp;
                }
            }
        }
    }
    else {
        foreach $f (@Boot) {
            if ( grep( /\//, $f ) ) {
                if ( $y = `lifls $f | grep ODE` ) {
                    $y =~ s/\s+//g;
                    if ( grep( /ODE/, $y ) ) {
                        print
"$PASSSTR LIF volume on boot disk $f contains ODE\n";
                    }
                    else {
                        print
"$INFOSTR LIF volume on boot disk $f does not have ODE\n";
                    }
                }
                else {
                    print
"$INFOSTR LIF volume on boot disk $f does not have ODE\n";
                }
            }
        }
    }

    datecheck();
    print_trailer("*** END CHECKING DIAGNOSTICS ENVIRONMENT (ODE) ON BOOT DISKS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING LIF AND QUORUM STATUS ON BOOT DISKS $datestring ***");

    if ( ! @Boot) {
        print "$ERRSTR Boot disks undefined in lvlnboot!\n\n";
        push(@CHECKARR, "\n$ERRSTR Boot disks undefined in lvlnboot\n");
        $warnings++;
    }

    if ( "$LVBDISK" > 1 ) {
        foreach $f (@Boot) {
            next if ( ! grep( /^\/dev\/dsk\/|^\/dev\/disk\//, $f ) );
            if ( "$Hardware" eq "ia64" ) {
                #
                # The boot disk of Itanium servers has four partitions:
                # s0 - entire disk
                # s1 - EFI
                # s2 - OS
                # s3 - HP support tools (service partition)
                #
                $f =~ s/s2/s1/g;
                $f =~ s/_p2/_p1/g;
   
                if ( -s "$eficptest" ) {
                    unlink $eficptest;
                }

                @lifls = `efi_ls -d $f 2>&1| awk NF`;
                `efi_cp -d $f -u /EFI/HPUX/AUTO $eficptest 2>/dev/null`;
                @lifcp = `cat $eficptest 2>/dev/null`;
            }
            else {
                @lifls = `lifls -l $f 2>&1| awk NF`;
                @lifcp = `lifcp $f:AUTO - 2>/dev/null`;
            }

            if ( @lifls != 0 ) {
                print "$INFOSTR LIF status for boot disk $f\n";
                print @lifls;
            }
            else {
                print "$WARNSTR Undefined LIF status for boot disk $f\n";
                push(@CHECKARR, "\n$WARNSTR Undefined LIF status for boot disk $f\n");
                $warnings++;
            }

            if ( @lifcp ) {
                if ( !grep( /-lq/, @lifcp ) ) {
                    print
"\n$WARNSTR Boot disk $f does not have low-quorum set\n";
                    push(@CHECKARR,
"\n$WARNSTR Boot disk $f does not have low-quorum set\n");
                }
                else {
                    print "\n$PASSSTR Boot disk $f has low-quorum set\n";
                }
                print "@lifcp\n";
            }
            else {
                print "\n$WARNSTR Undefined quorum status for boot disk $f\n\n";
                push(@CHECKARR,
"\n$WARNSTR Undefined quorum status for boot disk $f\n");
                $warnings++;
            }
        }
    }
    else {
        print "\n$INFOSTR Quorum status not important for single boot disk\n";
    }

    datecheck();
    print_trailer("*** END CHECKING LIF AND QUORUM STATUS ON BOOT DISKS $datestring ***");
}

# Subroutine to check Unix password and group databases
#
sub pwdbcheck {
    datecheck();
    print_header("*** BEGIN CHECKING CURRENT AND GHOST LOGIN SESSIONS $datestring ***");

    my $whocur = `who -q 2>/dev/null`;
    if ( "$whocur" ) {
        print "$INFOSTR Current login sessions\n";
        print "$whocur";
    }
    else {
        print "$INFOSTR No active login sessions\n";
    }

    my $wholog = `who -u 2>/dev/null`;
    if ( "$wholog" ) {
        print
          "\n$INFOSTR Login sessions (verify those with \"old\" entries!)\n";
        print "$wholog";
    }

    my $whodo = `whodo 2>/dev/null`;
    if ( "$whodo" ) {
        print
          "\n$INFOSTR Current login command execution\n";
        print "$whodo";
    }

    datecheck();
    print_trailer("*** END CHECKING CURRENT AND GHOST LOGIN SESSIONS $datestring ***");

    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING USERDB DATABASE $datestring ***");

	if ( -f "$DISABLEUSERDB" ) {
            print "$INFOSTR Userdb disabled because file $DISABLEUSERDB exists\n";
	} else {
            my @userdbck = `userdbck 2>/dev/null`;
            my @userdbcka = `userdbck -a -u 2>/dev/null`;

            if ( "$Minor$Patch" >= 1131 ) {
                if ( ( -s $SECURITYDSC ) && ( -T $SECURITYDSC ) ) {
                    my @secdsc = `cat $SECURITYDSC 2>/dev/null`;
                    if ( @secdsc ) {
                        print "$INFOSTR Configuration file $SECURITYDSC\n";
                        print "@secdsc";
                        print "\n";
                    }
                }
            }

            if ( @userdbcka ) {
                print "$INFOSTR Verifying userdb attributes\n";
                print "@userdbcka";
            }

            if ( @userdbck ) {
                print "\n$INFOSTR Checking $USERDB\n";
                print "@userdbck";

                my @userdbget = `userdbget -a 2>/dev/null`;
                if ( @userdbget ) {
                    print "\n$INFOSTR Checking userdb accounts\n";
                    print "@userdbget";
                }
            }
            else {
                print "\n$INFOSTR Userdb database $USERDB is zero-length or not in use\n";
            }
        }

        datecheck();
        print_trailer("*** END CHECKING USERDB DATABASE $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING UNIX PASSWORD AND GROUP DATABASES $datestring ***");

    (
        $pdev,   $pino,     $pmode, $pnlink, $puid,
        $pgid,   $prdev,    $psize, $patime, $pmtime,
        $pctime, $pblksize, $pblocks,
    ) = stat($PASSFILE);

    if ( "$pnlink" > 1 ) {
        print "$WARNSTR $PASSFILE has $pnlink hard links\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE has $pnlink hard links\n");
        $warnings++;
    }
    else {
        print "$PASSSTR $PASSFILE has one hard link only\n";
    }

    my $pfile_perms = $pmode & 0777;
    my $poct_perms = sprintf "%lo", $pfile_perms;

    if ( "$pblocks" == 0 ) {
        print "\n$WARNSTR $PASSFILE is zero-length\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE is zero-length\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR $PASSFILE not zero-length\n";
    }

    if ( "$puid" == 0 ) {
        print "\n$PASSSTR $PASSFILE owned by UID $puid\n";
    }
    else {
        print "\n$WARNSTR $PASSFILE not owned by UID 0 ($puid)\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE not owned by UID 0 ($puid)\n");
        $warnings++;
    }

    if ( "$pgid" == 3 ) {
        print "\n$PASSSTR $PASSFILE owned by GID $pgid\n";
    }
    else {
        print "\n$WARNSTR $PASSFILE not owned by GID 3 ($pgid)\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE not owned by GID 3 ($pgid)\n");
        $warnings++;
    }

    if ( $poct_perms != "444" ) {
        print "\n$WARNSTR $PASSFILE permissions not 444 ($poct_perms)\n";
        push(@CHECKARR, "\n$WARNSTR $PASSFILE permissions not 444 ($poct_perms)\n");
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

    if ( "$Minor$Patch" == 1131 ) {
        my $logextend = `getconf _SC_EXTENDED_LOGIN_NAME 2>/dev/null`;
        chomp($logextend);
        if ( "$logextend" == 1 ) {
            print
"\n$INFOSTR _SC_EXTENDED_LOGIN_NAME set to 1 (Trusted System Password database cannot be used)\n";
        }
        else {
            if ( -f "$UGCONF" ) {
                print
"\n$INFOSTR Trusted System Password database cannot be used ($UGCONF exists)\n";
            }
        }
    }

    if ( "$Minor$Patch" < 1131 ) {
        if ( (! "$TCB") && (! "$TCB2") ) {
            print "\n$PASSSTR Trusted System Password database used\n";
        }
    }
    elsif ( (! "$TCB") && (! "$TCB2") ) {
        print "\n$INFOSTR Trusted System Password database used\n";
        print
"$NOTESTR Trusted System Password database deprecated and not supported beyond 11i v3\n";
    }

    if ( (! "$TCB") && (! "$TCB2") ) {
        my @acheck = `authck -p`;
        print @acheck;

        if ( (-s "$tcbdef" ) && ( -T "$tcbdef" ) ) {
            print "\n$INFOSTR Default configuration file $tcbdef\n";
            my @tcblist = `cat $tcbdef`;
            print @tcblist;
        }

        if ( (-s "$tcbttys" ) && ( -T "$tcbttys" ) ) {
            print "\n$INFOSTR Configuration file $tcbttys\n";
            my @tcbt = `cat $tcbttys`;
            print @tcbt;
        }
        else {
            print "\n$WARNSTR Configuration file $tcbttys is zero-length or missing\n";
            push(@CHECKARR,
"\n$WARNSTR Configuration file $tcbttys is zero-length or missing\\n");
            $warnings++;
        }
    }
    else {
        if ( !-s "$Shadow" ) {
            if ( -f "$Shadow" ) {
                print "\n$ERRSTR Shadow password database seemingly used but $Shadow file is zero-length\n";
                push(@CHECKARR, "\n$ERRSTR Shadow password database seemingly used but $Shadow file is zero-length\n");
                $warnings++;
            }
            else {
                print "\n$ERRSTR Shadow password database not used\n";
                push(@CHECKARR, "\n$ERRSTR Shadow password database not used\n");
                $warnings++;
                print "\n$WARNSTR Standard password database used\n\n";
                push(@CHECKARR, "\n$WARNSTR Standard password database used\n");
            }
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

                if ( @SHADWARN ) {
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

            if ( ( "$Minor$Patch" >= 1120 ) && ( "$Minor$Patch" <= 1123 ) ) {
                if ( -f "$SHADOWNROUND" ) {
                    print "\n$INFOSTR File $SHADOWNROUND exists\n";
                    print
"$NOTESTR For HP-UX 11.23, if patch PHCO_36426or later is installed,\n";
                    print
"$NOTESTR then for systems using shadow passwords the rounding of password\n";
                    print
"$NOTESTR aging arguments can be suppressed by creating file $SHADOWROUND.\n";
                    print
"$NOTESTR If the file exists, then the password command does not round\n";
                    print
"$NOTESTR the \"-x\", \"-n\", and \"-w\" values to a multiple of a week.\n";
                    print
"$NOTESTR The use of this file is specific to this release. New releases\n";
                    print
"$NOTESTR will change the password command to never round aging values\n";
                    print
"$NOTESTR for systems that are using shadow passwords.\n";
                }
            }
        }

        my @passck   = `pwck 2>&1 | awk NF`;
        my @grpck    = `grpck 2>&1 | awk NF`;

        my @loginsnp = `logins -p -d 2>&1 | awk NF`;

        print "\n$INFOSTR Pwck(1) verification\n";
        if (@passck) {
            print @passck;
        }
        else {
            print "$PASSSTR Pwck clean\n";
        }

        print "\n$INFOSTR Grpck(1) verification\n";
        if (@grpck) {
            print @grpck;
        }
        else {
            print "$PASSSTR Grpck clean\n";
        }

        if (@loginsnp) {
            print "\n$INFOSTR Logins with zero-length passwords or duplicate UIDs\n";
            if ( "$domname" ) {
                print "$NOTESTR NIS/YP seemingly configured (that is possibly the reason for duplicate login names)\n";
            }
            print @loginsnp;
        }
        else {
            print "\n$PASSSTR No logins with zero-length passwords or duplicate UIDs\n";
        }
    }

    my @pwget = `pwget 2>/dev/null | sort`;
    if ( @pwget ) {
        print "\n$INFOSTR Unix account listings (all databases)\n";
        print @pwget;
    }

    if ( -f "$nologinf" ) {
        print "\n$INFOSTR File \"$nologinf\" exists\n";
        print "$NOTESTR Non-root logins might be affected by the \"$nologinf\" file\n";
    }
    else {
        print "\n$INFOSTR File \"$nologinf\" does not exist\n";
    }

    if ( "$Minor$Patch" >= 1131 ) {
        my @userstat = `userstat -a 2>/dev/null`;
        if ( @userstat ) {
            print "\n$INFOSTR Abnormal status for local accounts\n";
            print @userstat;
        }

        if ( grep(/expacct|exppw/, @userstat) ) {
            print
"\n$WARNSTR There are expired accounts and/or passwords (check abnormal status)\n";
            push(@CHECKARR,
"\n$WARNSTR There are expired accounts and/or passwords (check abnormal status)\n");
            $warnings++;
        }
    }

    if ( "$Minor$Patch" >= 1123 ) {
        my @pwgrstat = `echo q | pwgr_stat 2>/dev/null | awk NF`;
        if ( @pwgrstat ) {
            print "\n$INFOSTR Password and Group hashing and caching statistics\n";
            print @pwgrstat;
        }
    }

    if ( "$Minor$Patch" >= 1131 ) {
        if ( $NUMUSRGRP_FLAG > 0 ) {
            print
"\n$INFOSTR Software product \"Numeric User Group Name\" installed\n";
        }
        else {
            print
"\n$INFOSTR Software product \"Numeric User Group Name\" not installed\n";
        }
    }

    if ( !-s "$privgrp" ) {
        print
"\n$WARNSTR Ownership change command not restricted (file $privgrp missing)\n";
        push(@CHECKARR,
"\n$WARNSTR Ownership change command not restricted (file $privgrp missing)\n");
        $warnings++;
    }
    else {
        print "\n$PASSSTR Ownership change command restricted through $privgrp\n";
        my @privent = `cat $privgrp`;
        print @privent;
        print "\n$INFOSTR Default group privileges\n";
        my @grpprivent = `getprivgrp 2>/dev/null`;
        print @grpprivent;
        print "\n";
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
            if ( ( -s "$racent" ) && ( -T "$racent" ) ) {
                print "\n$WARNSTR Username $entry[0] has $raccess\n";
                push(@CHECKARR, "\n$WARNSTR Username $entry[0] has $raccess\n");
                my @aent = `cat $racent`;
                print @aent;
            }
        }

        my $epmode = (stat($entry[7]))[2];

        if ( $epmode & 0020 ) {
            print
"\n$WARNSTR Home directory for $entry[0] ($entry[7]) group-writable\n";
            push(@CHECKARR,
"\n$WARNSTR Home directory for $entry[0] ($entry[7]) group-writable\n");
        }

        if ( $epmode & 0002 ) {
            print
"\n$WARNSTR Home directory for $entry[0] ($entry[7]) world-writable\n";
            push(@CHECKARR,
"\n$WARNSTR Home directory for $entry[0] ($entry[7]) world-writable\n");
            $warnings++;
        }

        if ( length($entry[8]) > $PASS_SHELL_LENGTH ) {
            print
"\n$WARNSTR Default Shell for $entry[0] ($entry[8]) exceeds $PASS_SHELL_LENGTH characters\n";
            print
"$NOTESTR Results are unpredictable if this password field is longer than the limit specified\n";
            push(@CHECKARR,
"\n$WARNSTR Default Shell for $entry[0] ($entry[8]) exceeds $PASS_SHELL_LENGTH characters\n");
            $warnings++;
        }

        if ( length($entry[7]) > $PASS_HOMEDIR_LENGTH ) {
            print
"\n$WARNSTR Home directory for $entry[0] ($entry[7]) exceeds $PASS_HOMEDIR_LENGTH characters\n";
            print
"$NOTESTR Results are unpredictable if this password field is longer than the limit specified\n";
            push(@CHECKARR,
"\n$WARNSTR Home directory for $entry[0] ($entry[7]) exceeds $PASS_HOMEDIR_LENGTH characters\n");
            $warnings++;
        }

        if ( $entry[0] eq "ermclnt" ) {
            $ERMflag++;
        }

        # Do not check logins that have non-alpha characters
        # in login names (like #usera)
        #
        if ( "$Minor$Patch" >= 1131 ) {
            if ( $NUMUSRGRP_FLAG > 0 ) {
                if ( ! ( substr($entry[0],0,1) =~ /^[a-zA-Z0-9]+$/ ) ) {
                    print
"\n$WARNSTR Username \"$entry[0]\" starts with non-alpha characters\n";
                    push(@CHECKARR,
"\n$WARNSTR Username \"$entry[0]\" starts with non-alpha characters\n");
                    $warnings++;
                }
            }
            else {
                if ( ! ( substr($entry[0],0,1) =~ /^[a-zA-Z]+$/ ) ) {
                    print
"\n$WARNSTR Username \"$entry[0]\" starts with non-alpha or numeric characters\n";
                    push(@CHECKARR,
"\n$WARNSTR Username \"$entry[0]\" starts with non-alpha or numeric characters\n");
                    $warnings++;
                }
            }
        }
        else {
            if ( ! ( substr($entry[0],0,1) =~ /^[a-zA-Z]+$/ ) ) {
                print
"\n$WARNSTR Username \"$entry[0]\" starts with non-alpha or numeric characters\n";
                push(@CHECKARR, 
"\n$WARNSTR Username \"$entry[0]\" starts with non-alpha or numeric characters\n");
                $warnings++;
            }
        }

        if ( $entry[0] =~ /^[a-zA-Z0-9]+$/ ) {
            if ( (! "$TCB") && (! "$TCB2") ) {
                my $tcblockent = `getprpw -r -m lockout $entry[0] 2>/dev/null`;
                chomp($tcblockent);
                if ( "$tcblockent" == "0000000" ) {
                    print "\n$INFOSTR Username $entry[0] not locked\n";
                }
                else {
                    my @tcbbits = unpack( "C*", $tcblockent );
                    my $TCBCOUNT = 1;
                    foreach my $VV ( reverse @tcbbits ) {
                        my $TCBbinary = substr( dec2bin($VV), -1 );
                        $TCBCOUNT++;

                        if ( $TCBCOUNT == 1 ) {
                            my $LOCKstat =
                              ( "$TCBbinary" == 1 )
                              ? "\n$INFOSTR Username $entry[0] locked due to past password lifetime\n"
                              : "";
                        }

                        if ( $TCBCOUNT == 2 ) {
                            my $LOCKstat =
                              ( "$TCBbinary" == 1 )
                              ? "\n$INFOSTR Username $entry[0] locked due to past last login time (inactive account)\n"
                              : "";
                        }

                        if ( $TCBCOUNT == 3 ) {
                            my $LOCKstat =
                              ( "$TCBbinary" == 1 )
                              ? "\n$INFOSTR Username $entry[0] locked due to past absolute account lifetime\n"
                              : "";
                        }

                        if ( $TCBCOUNT == 4 ) {
                            my $LOCKstat =
                              ( "$TCBbinary" == 1 )
                              ? "\n$INFOSTR Username $entry[0] locked due to exceeded unsuccessful login attempts\n"
                              : "";
                        }

                        if ( $TCBCOUNT == 5 ) {
                            my $LOCKstat =
                              ( "$TCBbinary" == 1 )
                              ? "\n$INFOSTR Username $entry[0] locked due to password required and a null password\n"
                              : "";
                        }

                        if ( $TCBCOUNT == 6 ) {
                            my $LOCKstat =
                              ( "$TCBbinary" == 1 )
                              ? "\n$INFOSTR Username $entry[0] locked due to admin lock\n"
                              : "";
                        }

                        if ( $TCBCOUNT == 7 ) {
                            my $LOCKstat =
                              ( "$TCBbinary" == 1 )
                              ? "\n$INFOSTR Username $entry[0] locked due password is a \"*\"\n"
                              : "";
                        }
                    }
                }

                # The following tests inspired by Shell script by Bill Hassel
                #
                my @tcbmintm = `getprpw -r -m mintm $entry[0] 2>/dev/null`;
                if ( @tcbmintm ) {
                    print
"\n$INFOSTR Minimum time between password changes for username $entry[0]\n";
                    print @tcbmintm;
                }

                my @tcbexptm = `getprpw -r -m exptm $entry[0] 2>/dev/null`;
                if ( @tcbexptm ) {
                    print
"\n$INFOSTR Password expiration time for username $entry[0]\n";
                    print @tcbexptm;
                }

                my @tcblftm = `getprpw -r -m lftm $entry[0] 2>/dev/null`;
                if ( @tcblftm ) {
                    print
"\n$INFOSTR Password lifetime for username $entry[0]\n";
                    print @tcblftm;
                }

                my @tcbacctexp = `getprpw -r -m acctexp $entry[0] 2>/dev/null`;
                if ( @tcbacctexp ) {
                    print
"\n$INFOSTR Account expires for username $entry[0]\n";
                    print @tcbacctexp;
                }

                my @tcblastpass = `getprpw -r -m spwchg $entry[0] 2>/dev/null`;
                if ( @tcblastpass ) {
                    print
"\n$INFOSTR Last password change for username $entry[0]\n";
                    print @tcblastpass;
                }
                else {
                    my @tcblastpass = `passwd -s $entry[0]`;
                    if ( @tcblastpass ) {
                        print
"\n$INFOSTR Last password change for username $entry[0]\n";
                        print @tcblastpass;
                    }
                }

                my @tcblastlog = `getprpw -r -m llog $entry[0] 2>/dev/null`;
                if ( @tcblastlog ) {
                    print
"\n$INFOSTR Last successful login for username $entry[0]\n";
                    print @tcblastlog;
                }

                my @tcblastulog = `getprpw -r -m ulogint $entry[0] 2>/dev/null`;
                if ( @tcblastulog ) {
                    print
"\n$INFOSTR Last unsuccessful login for username $entry[0]\n";
                    print @tcblastulog;
                }
            }
            else {
                my @tcblastpass = `passwd -s $entry[0]`;
                if ( @tcblastpass ) {
                    print "\n$INFOSTR Last password change for username $entry[0]\n";
                    print @tcblastpass;
                }
            }
        }
        else {
            print "\n$ERRSTR Username \"$entry[0]\" contains invalid characters\n";
            push(@CHECKARR, "\n$ERRSTR Username \"$entry[0]\" contains invalid characters\n");
            $warnings++;
        }

        if ( grep( /^\+:/, @entry ) ) {
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

    if ( -s "$pwgrdconf" ) {
        if ( open( PWGRD, "egrep -v ^# $pwgrdconf |" ) ) {
            print "\n$PASSSTR Password and Group hashing and caching daemon config in $pwgrdconf\n";
            while (<PWGRD>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                if ( grep( /^PWGR=/, $_ ) ) {
                    ( undef, $PWGR_FLAG ) = split( /=/, $_ );
                    chomp($PWGR_FLAG);
                }
            }
            close(PWGRD);
        }
        else {
            print "\n$INFOSTR Cannot open $pwgrdconf\n";
        }
    }
    else {
        print "\n$INFOSTR File $pwgrdconf does not exist or is zero-length\n";
    }

    if ( $passno <= $PASSWD_THRESHOLD ) {
        if ( "$PWGR_FLAG" == 1 ) {
            print "\n$INFOSTR Password file relatively small\n";
            print "$NOTESTR Recommended to disable PWGR socket in $pwgrdconf\n";
            print "$NOTESTR Recommended to remove directory $pwgrdir\n";
        }
        else {
            print "\n$INFOSTR Password file relatively small\n";
            print "$PASSSTR PWGR socket disabled in $pwgrdconf\n";
            if ( -d "$pwgrdir" ) {
                print "$WARNSTR Directory $pwgrdir exists\n";
                push(@CHECKARR, "\n$WARNSTR Directory $pwgrdir exists\n");
                print "$NOTESTR Recommended to remove directory $pwgrdir\n";
                $warnings++;
            }
            else {
                print "$PASSSTR Directory $pwgrdir does not exists\n";
            }
        }
    }
    else {
        print "$INFOSTR Password file relatively large\n";
        print "$INFOSTR Recommended to review PWGR socket in $pwgrdconf\n";
        print "$INFOSTR Recommended to remove directory $pwgrdir\n";
    }

    if ( @PassWdarr != 0 ) {
        print "\n$INFOSTR Entries in Unix password file\n";
        print @PassWdarr;
    }

    if ( @Grarr != 0 ) {
        print "\n$INFOSTR Entries in Unix group file\n";
        print @Grarr;
    }

    datecheck();
    print_trailer("*** END CHECKING UNIX PASSWORD AND GROUP DATABASES $datestring ***");
}

# Subroutine to check ICoD
#
sub icod {
    datecheck();
    print_header("*** BEGIN CHECKING INSTANT CAPACITY ON DEMAND (ICoD and iCAP) $datestring ***");

    if ( "$Minor$Patch" >= 1131 ) {
        my @icapstatus = `icapstatus -s 2>/dev/null`;
        if ( @icapstatus ) {
            print "$INFOSTR iCAP snapshot status\n";
            print @icapstatus;

            if ( open( IST, "icapstatus 2>&1 |" ) ) {
               print "$INFOSTR iCAP status\n";
               while (<IST>) {
                  print $_;
                  chomp($_);
                  next if ( grep( /^$/, $_ ) );

                  if ( grep( /^System contact/, $_ ) ) {
                     ( undef, undef, undef, @realemail ) = split( /\s+/, $_ );
                     if ( grep(/Not/, @realemail)) {
                        push (@ICAPARR,
"\n$ERRSTR iCAP complex contact e-mail is not set\n");
                        push(@CHECKARR,
"\n$ERRSTR iCAP complex contact e-mail is not set\n");
                        $warnings++;
                     }
                  }

                  if ( grep( /^Temporary capacity available/, $_ ) ) {
                     ( undef, undef, undef, @realcap ) = split( /\s+/, $_ );
                     if ( grep(/\(negative\)/, @realcap)) {
                        push (@ICAPARR,
"\n$ERRSTR iCAP complex has negative temporary capacity balance: @realcap\n");
                        push(@CHECKARR,
"\n$ERRSTR iCAP complex has negative temporary capacity balance: @realcap\n");
                        $warnings++;
                     }
                  }

                  if ( grep( /^Projected temporary capacity/, $_ ) ) {
                     ( undef, undef, undef, undef, @realproj ) = split( /\s+/, $_ );
                     if ( ! grep(/N\/A/, @realproj)) {
                        push (@ICAPARR,
"\n$ERRSTR iCAP complex temporary capacity is about to expire: @realproj\n");
                        push(@CHECKARR,
"\n$ERRSTR iCAP complex temporary capacity is about to expire: @realproj\n");
                        $warnings++;
                     }
                  }

                  if ( grep( /^Exception status/, $_ ) ) {
                     ( undef, undef, @realexcept ) = split( /\s+/, $_ );
                     if ( ! grep(/No/, @realexcept) ) {
                        push (@ICAPARR,
"\n$ERRSTR iCAP complex is in an exception state: @realexcept\n");
                        push(@CHECKARR,
"\n$ERRSTR iCAP complex is in an exception state: @realexcept\n");
                        $warnings++;
                     }
                  }
               }
            }
            close(IST);

            if ( "@ICAPARR" ) {
               print "@ICAPARR\n";
            }
        }
        else {
            print "$INFOSTR iCAP not running or not supported on this class of system\n";
        }

        my @icapmanage = `icapmanage -sv 2>/dev/null`;
        if ( @icapmanage ) {
            print "$INFOSTR iCAP management status\n";
            print @icapmanage;
        }
    }
    else {
        if ( open( QL, "icod_stat 2>&1 |" ) ) {
            while (<QL>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /not supported/, $_ ) ) {
                    print "$INFOSTR ICoD not supported on this platform\n";
                }
                else {
                    print $_;
                }
            }
            close(QL);
        
            my @icodu = `icod_stat -u 2>/dev/null`;
            if ( @icodu ) {
                print "\n$INFOSTR ICoD log events\n";
                print @icodu;
            }
        }
        else {
            print "$INFOSTR ICoD not configured or installed\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING INSTANT CAPACITY ON DEMAND (ICoD and iCAP) $datestring ***");
}

# Subroutine to check codewords
#
sub codewrd {
    datecheck();
    print_header("*** BEGIN CHECKING CODEWORDS AND LICENSE FILES $datestring ***");

    if ( (-s "$glancecw" ) && ( -T "$glancecw" ) ) {
        print "\n$INFOSTR Glance file $glancecw exists\n";
        my @GCW = `cat $glancecw`;
        print @GCW;
    }
    else {
        print "\n$INFOSTR Glance file $glancecw does not exist or is zero-length\n";
    }

    if ( (-s "$glancecw1" ) && ( -T "$glancecw1" ) ) {
        print "\n$INFOSTR Glance file $glancecw1 exists\n";
        my @GCW1 = `cat $glancecw1`;
        print @GCW1;
    }
    else {
        print "\n$INFOSTR Glance file $glancecw1 does not exist or is zero-length\n";
    }

    if ( (-s "$pwkey" ) && ( -T "$pwkey" ) ) {
        print "\n$INFOSTR PerfView file $pvkey exists\n";
        my @PWKEY = `cat $pwkey`;
        print @PWKEY;
    }
    else {
        print "\n$INFOSTR PerfView file $pvkey does not exist or is zero-length\n";
    }

    if ( (-s "$mwakey" ) && ( -T "$mwakey" ) ) {
        print "\n$INFOSTR MeasureWare file $mwakey exists\n";
        my @MWAKEY = `cat $mwakey`;
        print @MWAKEY;
    }
    else {
        print "\n$INFOSTR PerfView file $pvkey does not exist or is zero-length\n";
    }

    if ( -s "$cw" ) {
        print "\n$INFOSTR Codewords file $cw exists\n";
        my @CW = `cat $cw`;
        print @CW;
    }
    else {
        print "\n$INFOSTR Codewords file $cw does not exist or is zero-length\n";
    }

    if ( (-s "$ovnnmlic" ) && ( -T "$ovnnmlic" ) ) {
        print "\n$INFOSTR Network Node Manager file $ovnnmlic exists\n";
        my @NNMLIC = `cat $ovnnmlic`;
        print @NNMLIC;
    }
    else {
        print "\n$INFOSTR Network Node Manager $ovnnmlic does not exist or is zero-length\n";
    }

    my @NNMEXTLIC = `nnmprintextensionverinfo.ovpl 2>/dev/null`;
    if ( @NNMEXTLIC ) {
        print "\n$INFOSTR Network Node Manager extensions license info\n";
        print @NNMEXTLIC;
    }

    my @oalicense   = `oalicense -get -all 2>/dev/null`;
    my @oalicenseld = `oalicense -listdefinedlicenses 2>/dev/null`;

    if ( @oalicense != 0 ) {
        print "\n$PASSSTR OAlicense status\n";
        print @oalicense;
    }

    if ( @oalicenseld != 0 ) {
        print "\n$PASSSTR OAlicense status of defined licenses\n";
        print @oalicenseld;
    }

    if ( (-s "$ovnnmlic2" ) && ( -T "$ovnnmlic2" ) ) {
        print "\n$INFOSTR Network Node Manager file $ovnnmlic2 exists\n";
        my @NNMLIC2 = `cat $ovnnmlic2`;
        print @NNMLIC2;
    }
    else {
        print "\n$INFOSTR Network Node Manager $ovnnmlic2 does not exist or is zero-length\n";
    }

    if ( (-s "$ldaplic" ) && ( -T "$ldaplic" ) ) {
        print "\n$INFOSTR LDAP file $ldaplic exists\n";
        my @LDAPLIC = `cat $ldaplic`;
        print @LDAPLIC;
    }
    else {
        print "\n$INFOSTR LDAP file $ldaplic does not exist or is zero-length\n";
    }

    my @gwlmlic = `gwlm license 2>/dev/null`;
    if ( @gwlmlic ) {
        print "\n$INFOSTR gWLM licensing\n";
        print @gwlmlic;
    }

    if ( (-s "$wlmlic1") && (-T "$wlmlic1") ) {
        print "\n$INFOSTR WLM JfreeChart file $wlmlic1 exists\n";
        my @WLMLIC1 = `cat $wlmlic1`;
        print @WLMLIC1;
    }
    else {
        print "\n$INFOSTR WLM JFreeChart file $wlmlic1 does not exist or is zero-length\n";
    }

    if ( (-s "$wlmlic2" ) && (-T "$wlmlic2") ) {
        print "\n$INFOSTR WLM libxml2 file $wlmlic2 exists\n";
        my @WLMLIC2 = `cat $wlmlic2`;
        print @WLMLIC2;
    }
    else {
        print "\n$INFOSTR WLM libxml2 file $wlmlic2 does not exist or is zero-length\n";
    }

    my @extractlic = `extract -licheck 2>&1 | awk NF`;
    if ( @extractlic ) {
        print "\n$INFOSTR Performance Agent licensing\n";
        print @extractlic;
    }

    if ( @ARMLICENSE ) {
        print "\n$INFOSTR VA7100 licensing\n";
        print @ARMLICENSE;
    }

    my @X25LIC = `x25checklicense 2>/dev/null`;
    if ( @X25LIC ) {
        print "\n$INFOSTR X25 licensing\n";
        print @X25LIC;
    }
   
    if ( "$OMNI_FLAG" > 0 ) {
        my @DPCW = `omnicc -check_licenses -detail 2>/dev/null`;
        if ( @DPCW ) {
            print "\n$INFOSTR Data Protector licenses\n";
            print @DPCW;
        }
        else {
            print
"\n$INFOSTR Data Protector installed but unlicensed (or not configured)\n";
        }
    }

    if ("$NETBCKDIR") {
        $ENV{'PATH'} = "$ENV{PATH}:$NETBCKDIR/netbackup/bin/admincmd";
        $ENV{'PATH'} = "$ENV{PATH}:$NETBCKDIR/netbackup/bin/goodies";

        if ( open( VV, "bpminlicense -list_keys |" ) ) {
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

    if ( "$Hardware" eq "ia64" ) {
        $AnsiCcw = "/opt/ansic/newconfig/ansic.cwd";
    }

    if ( -s "$AnsiCcw" ) {
        print "\n$INFOSTR Ansi C file $AnsiCcw exists\n";
        my @ACCW = `cat $AnsiCcw`;
        print @ACCW;
    }
    else {
        print "\n$INFOSTR Ansi C file $AnsiCcw does not exist or is zero-length\n";
    }

    if ( -s "$AnsiCpluscw" ) {
        print "\n$INFOSTR Ansi C++ file $AnsiCpluscw exists\n";
        my @ACPCW = `cat $AnsiCpluscw`;
        print @ACPCW;
    }
    else {
        print "\n$INFOSTR Ansi C++ file $AnsiCpluscw does not exist or is zero-length\n";
    }

    if ( -s "$SoftBenchcw" ) {
        print "\n$INFOSTR SoftBench file $SoftBenchcw exists\n";
        my @SBCW = `cat $SoftBenchcw`;
        print @SBCW;
    }
    else {
        print "\n$INFOSTR SoftBench file $SoftBenchcw does not exist or is zero-length\n";
    }

    my @Vrtsf = `ls $Vrtslicdir/*.lic 2>/dev/null`;
    if ( @Vrtsf != 0 ) {
        foreach my $vlcfile (@Vrtsf) {
            my @Vrtsep = `cat $vlcfile`;
            print "\n$INFOSTR VxFS license file $vlcfile\n";
            print @Vrtsep;
        }
    }

    if ( $SVA_FLAG > 0 ) {
        if ( -s "$svalic" ) {
            my @svacat = `cat $svalic`;
            if ( @svacat != 0 ) {
                print
"\n$INFOSTR Scalable Virtualisation Array license file $svalic exists\n";
                print @svacat;
            }
        }
    }

    print "\n$INFOSTR Other applications might have their codewords ";
    print "in other files\n";

    my @swprot = `swlist -l bundle -a is_protected 2>/dev/null`;
    if ( @swprot ) {
        print "\n$INFOSTR Software bundles that require a codeword\n";
        print @swprot;
    }

    datecheck();
    print_trailer("*** END CHECKING CODEWORDS AND LICENSE FILES $datestring ***");
}

# Subroutine to check superdaemon inetd setup
#
sub inetdchk {
    datecheck();
    print_header("*** BEGIN CHECKING INTERNET SERVICES $datestring ***");

    my @SIS = `inetsvcs_sec status 2>/dev/null`;
    if ( @SIS != 0 ) {
        print "$INFOSTR @SIS";
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
                my @ckconfig = `ckconfig -V`;
                if ( @ckconfig ) {
                    print
"$INFOSTR Verify path names of FTP configuration files(ckconfig)\n";
                    print @ckconfig;
                    print "\n";
                }

                if ( !-s "$ftpusers" ) {
                    print
"\n$ERRSTR FTP configuration file $ftpusers missing\n";
                    push(@CHECKARR,
"\n$ERRSTR FTP configuration file $ftpusers missing\n");
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
                        push(@CHECKARR, "\n$ERRSTR Cannot open $ftpusers\n");
                        $warnings++;
                    }
                }

                if ( !-s "$ftpacc" ) {
                    print
                      "\n$ERRSTR FTP configuration file $ftpacc missing\n";
                    push(@CHECKARR,
                      "\n$ERRSTR FTP configuration file $ftpacc missing\n");
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
                    push(@CHECKARR,
"\n$ERRSTR FTP configuration file $ftphosts missing\n");
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
                        push(@CHECKARR, "\n$WARNSTR Cannot open $ftphosts\n");
                        $warnings++;
                    }
                }
            }
        }
        close(I);
    }
    else {
        print "$ERRSTR Cannot open $INETD\n";
        push(@CHECKARR, "\n$ERRSTR Cannot open $INETD\n");
        $warnings++;
    }

    if ( !-f "$INETDSEC" && !-s "$INETDSEC" ) {
        print
"\n$ERRSTR Inetd not managed through ACLs ($INETDSEC not used)\n";
        push(@CHECKARR,
"\n$ERRSTR Inetd not managed through ACLs ($INETDSEC not used)\n");
        $warnings++;
    }
    else {
        my $stpermi = (stat($INETDSEC))[2] & 07777;
        my $inetaw = (stat($INETDSEC))[4];
        my $octi = sprintf "%lo", $stpermi;

        if ( "$inetaw" == 0 ) {
            print "\n$PASSSTR $INETDSEC owned by UID $inetaw\n";
        }
        else {
            print "\n$WARNSTR $INETDSEC not owned by UID 0 ($inetaw)\n";
            push(@CHECKARR, "\n$WARNSTR $INETDSEC not owned by UID 0 ($inetaw)\n");
            $warnings++;
        }

        if ( ($octi != 444) && ($octi != 644) ) {
           print "\n$WARNSTR Permissions for $INETDSEC incorrect ($octi)\n";
           push(@CHECKARR, "\n$WARNSTR Permissions for $INETDSEC incorrect ($octi)\n");
           $warnings++;
           print "$NOTESTR Permissions for $INETDSEC should be 444 or 644\n";
        }
        else {
           print "\n$PASSSTR Permissions for $INETDSEC correct ($octi)\n";
           print "$NOTESTR Permissions for $INETDSEC should be 444 or 644\n";
        }

        print "\n$PASSSTR Inetd managed through ACLs ($INETDSEC used)\n";
        print "$NOTESTR Multiple allow or deny lines for each service are not supported.\n";
        print "$NOTESTR If there are multiple allow or deny lines for a particular service,\n";
        print "$NOTESTR all but the last line are ignored\n";
        if ( open( V, "egrep -v ^# $INETDSEC |" ) ) {
            print "\n$INFOSTR Active services in $INETDSEC\n";
            while (<V>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                if ( "$SGRUN" >= 1 ) {
                    foreach my $sgprotocol ( @SGPROTS ) {
                        if ( ! grep( /^\b$sgprotocol\b/, $_ ) ) {
                            push(@CHECKARR,
"\n$WARNSTR Serviceguard in use but $sgprotocol not protected through ACLs in $INETDSEC\n");
                            push(@SGARR,
"\n$WARNSTR Serviceguard in use but $sgprotocol not protected through ACLs in $INETDSEC\n");
                            $warnings++;
                        }
                    }
                }

                my @SECARR = split(/\s+/, $_);
                if ( $iines{$SECARR[0]} ) {
                    push(@INETSWARN, "\n$WARNSTR Entry for service $SECARR[0] exists more than once in $INETDSEC\n");
                    push(@CHECKARR, "\n$WARNSTR Entry for service $SECARR[0] exists more than once in $INETDSEC\n");
                    $warnings++;
                }
                else {
                    $iines{$SECARR[0]} = 1;
                }
            }
            close(V);

            if ( @INETSWARN ) {
                print @INETSWARN;
            }

            if ( @SGARR ) {
                print @SGARR;
            }
 
        }
        else {
            print "\n$WARNSTR Cannot open $INETDSEC\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $INETDSEC\n");
            $warnings++;
        }
    }

    my @Harray = ( "$hostallow", "$hostdeny", );

    foreach my $Hdir (@Harray) {
        if ( -s "$Hdir" ) {
            my @Hlist = `cat $Hdir`;
            if (@Hlist) {
                print "\n$INFOSTR $Hdir listing\n";
                print @Hlist;
            }
            else {
                print "\n$INFOSTR $Hdir is zero-length\n";
            }
        }
        else {
            print "\n$INFOSTR $Hdir is zero-length\n";
        }
    }

    my @tcpdchk = `tcpdchk -v 2>/dev/null | awk NF `;
    if ( @tcpdchk ) {
        print "\n$INFOSTR TCP Wrappers check\n";
        print @tcpdchk;
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
        print "\n$PASSSTR $hostequiv does not exist or is is zero-length\n";
    }

    if ( -s "$Shells" ) {
        if ( open( SHL, "egrep -v ^# $Shells 2>/dev/null |" ) ) {
            print "\n$INFOSTR Active Shells in $Shells\n";
            while (<SHL>) {
                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                print $_;
                chomp($_);
                if ( -e $_ && -x $_ && -s $_ ) {
                    push(@SHELLARR, "$PASSSTR Valid Shell $_\n");
                }
                else {
                    push(@SHELLARR, "$INFOSTR Invalid Shell $_\n");
                }
            }
            close(SHL);

            if ( @SHELLARR ) {
                print "\n";
                print @SHELLARR;
            }
        }
        else {
            print "\n$INFOSTR $Shells not in use\n";
            $warnings++;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING INTERNET SERVICES $datestring ***");
}

# Subroutine to check defined protocols and services
#
sub protchk {
    datecheck();
    print_header("*** BEGIN CHECKING DEFINED SERVICES AND PROTOCOLS $datestring ***");

    my @SRR = ();

    my $ztperm = (stat($SERVICES))[2] & 07777;
    my $zctp = sprintf "%lo", $ztperm;

    if ( ($zctp != 444) && ($zctp != 644) ) {
       print "\n$WARNSTR Permissions for $SERVICES incorrect ($zctp)\n";
       push(@CHECKARR, "\n$WARNSTR Permissions for $SERVICES incorrect ($zctp)\n");
       $warnings++;
    }

    if ( -s "$SERVICES" ) {
        if ( open( SE, "awk NF $SERVICES |" ) ) {
            print "$INFOSTR Active services in $SERVICES\n";
            while (<SE>) {
                if ( grep( /echo\s+/, $_ ) ) {
                    $_ =~ s/^\s+//g;
                    if ( grep( /^#/, $_ ) ) {
                        push(@SRR,
"$ERRSTR $SERVICES has \"echo\" line commented out\n");
                        push(@SRR,
"$NOTESTR Perl Module Net::Ping depends on it\n");
                        push(@CHECKARR,
"\n$ERRSTR $SERVICES has \"echo\" line commented out\n");
                        push(@CHECKARR,
"$NOTESTR Perl Module Net::Ping depends on it\n");
                        $warnings++;
                    }
                }
                if ( "$Minor$Patch" >= 1131 ) {
                    if ( grep( /domain\s+/, $_ ) ) {
                        $_ =~ s/^\s+//g;
                        if ( grep( /^#/, $_ ) ) {
                            push(@SRR,
"$ERRSTR $SERVICES has \"domain\" line commented out\n");
                            push(@SRR,
"$NOTESTR HP-UX 11.31 uses POSIX standard getaddrinfo() and getnameinfo(),\n");
                            push(@SRR,
"and requires \"domain\" lines (HP DocID emr_na-c01160960-1)\n");
                            push(@CHECKARR,
"\n$ERRSTR $SERVICES has \"domain\" line commented out\n");
                            push(@CHECKARR,
"$NOTESTR HP-UX 11.31 uses POSIX standard getaddrinfo() and getnameinfo(),\n");
                            push(@CHECKARR,
"and requires \"domain\" lines (HP DocID emr_na-c01160960-1)\n");
                            $warnings++;
                        }
                    }
                }
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

    if ( @SRR ) {
        print "\n@SRR\n";
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
    print_trailer("*** END CHECKING DEFINED SERVICES AND PROTOCOLS $datestring ***");
}

# Subroutine to check SMTP setup
#
sub smtpchk {
    datecheck();
    print_header("*** BEGIN CHECKING EMAIL SERVICES $datestring ***");

    @port = (25);

    my @POSTFIXARR = ( '/etc/postfix/main.cf', '/etc/postfix/master.cf', );

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
    }

    if ( $EXIM_FLAG > 0 ) {
        print "\n$INFOSTR Mail Transfer Agent is seemingly Exim\n";
        my @exiwhat = `exiwhat 2>/dev/null`;
        if ( @exiwhat != 0 ) {
            print "@exiwhat\n";
        }
    }

    if ( $SENDMAIL_FLAG > 0 ) {
        print "\n$INFOSTR Mail Transfer Agent is seemingly Sendmail\n";
    }

    if ( ( -s "$SMTPD" ) && ( -T "$SMTPD" ) ) {
        if ( open( ALS, "cat $SMTPD |" ) ) {
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

    if ( @PRIVACY != 0 ) {
        if (   ( grep( /noexpn/, @PRIVACY ) )
            && ( grep( /novrfy/, @PRIVACY ) ) )
        {
            print "\n$INFOSTR SMTPD privacy options defined\n";
        }
        else {
            print "\n$WARNSTR SMTPD privacy options not fully defined\n";
            push(@CHECKARR, "\n$WARNSTR SMTPD privacy options not fully defined\n");
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
                print "$WARNSTR Check hostname resolution for server \"$host\"\n";
                push(@CHECKARR,
"\n$WARNSTR Check hostname resolution for server \"$host\"\n");
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
        print "\n$INFOSTR SMTP Smart Host not defined (not applicable if email services not used)\n";
        push(@CHECKARR, "\n$INFOSTR SMTP Smart Host not defined (not applicable if email services not used)\n");
    }

    my @mailqcheck = `mailq | egrep -vi "empty|Total requests: 0"`;
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
        push(@CHECKARR, "\n$WARNSTR Email statistics not defined\n");
        $warnings++;
    }
    else {
        print "\n$INFOSTR Email statistics\n";
        print @mailstat;
    }

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
    print_trailer("*** END CHECKING EMAIL SERVICES $datestring ***");
}

# Subroutine to check RPC
#
sub rpcchk {
    datecheck();
    print_header("*** BEGIN CHECKING REMOTE PROCEDURE CALLS $datestring ***");

    my @rpcinfo = `rpcinfo -s 2>/dev/null`;
    if ( @rpcinfo != 0 ) {
        print @rpcinfo;

        my @rpccp = `rpccp show mapping 2>/dev/null`;
        if ( @rpccp != 0 ) {
            print "\n$INFOSTR RPC control program status\n";
            print @rpccp;
        }

        my @rpcinfom = `rpcinfo -m 2>/dev/null`;
        if ( @rpcinfom != 0 ) {
            print "\n$INFOSTR RPC statistics\n";
            print @rpcinfom;
        }

        my @rpcinfop = `rpcinfo -p 2>/dev/null`;
        if ( @rpcinfop != 0 ) {
            print "\n$INFOSTR RPC registered programs";
            print @rpcinfop;
        }
    }
    else {
        print "$INFOSTR RPC seemingly not used\n";
    }

    datecheck();
    print_trailer("*** END CHECKING REMOTE PROCEDURE CALLS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING DISTRIBUTED COMPUTING ENVIRONMENT $datestring ***");

    my @dcecp = `dcecp -c host show 2>/dev/null`;
    if ( @dcecp != 0 ) {
        print @dcecp;
    }
    else {
        print "$INFOSTR DCE seemingly not used\n";
    }

    datecheck();
    print_trailer("*** END CHECKING DISTRIBUTED COMPUTING ENVIRONMENT $datestring ***");
}

# Subroutine to check users excluded from removal via SAM
#
sub SAMrmchk {
    if ( "$Minor$Patch" <= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING USERS EXCLUDED FROM REMOVAL VIA SAM $datestring ***");

        if ( -s "$SAMEXUSR" ) {
            my @rmusersam = `cat $SAMEXUSR 2>/dev/null`;
            if ( @rmusersam != 0 ) {
                print "$INFOSTR $SAMEXUSR defined\n";
                print @rmusersam;
            }
            else {
                print "$INFOSTR $SAMEXUSR seemingly not defined or is zero-length\n";
            }
        }
        else {
            print "$INFOSTR $SAMEXUSR seemingly not defined or is zero-length\n";
        }
    
        if ( -s "$SAMEXFILE" ) {
            my @rmusersam = `cat $SAMEXFILE 2>/dev/null`;
            if ( @rmusersam != 0 ) {
                print "\n$INFOSTR $SAMEXFILE defined\n";
                print @rmusersam;
            }
            else {
                print "\n$INFOSTR $SAMEXFILE seemingly not defined or is zero-length\n";
            }
        }
        else {
            print "\n$INFOSTR $SAMEXFILE seemingly not defined or is zero-length\n";
        }

        if ( -s "$SAMEXGRP" ) {
            my @rmgrpsam = `cat $SAMEXGRP 2>/dev/null`;
            if ( @rmgrpsam != 0 ) {
                print "\n$INFOSTR $SAMEXGRP defined\n";            
                print @rmgrpsam;
            }
            else {
                print "\n$INFOSTR $SAMEXGRP seemingly not defined or is zero-length\n";
            }
        }
        else {
            print "\n$INFOSTR $SAMEXGRP seemingly not defined or is zero-length\n";
        }

        datecheck();
        print_trailer("*** END CHECKING USERS EXCLUDED FROM REMOVAL VIA SAM $datestring ***");

        datecheck();
        print_header("START SAM LOG FILE VIEWER $datestring ***");

        my @samlog = `samlog_viewer -n 2>/dev/null`;
        if ( @samlog != 0 ) {
            print @samlog;
        }
        else {
            print "$INFOSTR samlog_viewer does not provide any log report\n";
        }

        datecheck();
        print_header("*** END SAM LOG FILE VIEWER $datestring ***");

        datecheck();
        print_header("*** BEGIN CHECKING RESTRICTED SAM $datestring ***");

        if ( -s "$RESTRSAM" ) {
            my @samrusers = `cat $RESTRSAM 2>/dev/null`;
            if ( @samrusers != 0 ) {
                print @samrusers;
            }
            else {
                print "$INFOSTR $RESTRSAM seemingly not defined or is zero-length\n";
            }
        }
        else {
            print "$INFOSTR $RESTRSAM seemingly not defined or is zero-length\n";
        }

        datecheck();
        print_trailer("*** END CHECKING RESTRICTED SAM $datestring ***");
    }

    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING HP SYSTEM MANAGEMENT HOMEPAGE (SMH) $datestring ***");

        my @smhconf = `smhstartconfig 2>/dev/null`;
        if ( @smhconf != 0 ) {
            print @smhconf;
        }
        else {
            print "$INFOSTR SMH smhstartconfig not activated or command missing\n";
        }
       
        if ( "$Minor$Patch" >= 1123 ) {
            $SMHASSISTFLAG = "-v";
        }

        my @smhassist = `smhassist $SMHASSISTFLAG 2>/dev/null`;
        if ( @smhassist != 0 ) {
            print "$INFOSTR SMH smhassist status\n";
            print @smhassist;

        }

        if ( (-s "$SMHXML") && (-T "$SMHXML") ) {
            my @smhcat = `cat $SMHXML 2>/dev/null`;
            if ( @smhcat ) {
                print "\n$INFOSTR SMH configuration file $SMHXML\n";
                print @smhcat;
                print "\n";
            }
        } 

        my $smhperm = (stat($SMHDIR))[2] & 0777;
        my $smhmask = sprintf "%lo", $smhperm;
        if ( ( $smhmask == "755" ) || ( $smhmask == "555" ) ) {
            print "\n$PASSSTR Correct permissions for directory $SMHDIR ($smhmask)\n";
        }
        else {
            print "\n$WARNSTR Incorrect permissions for directory $SMHDIR ($smhmask)\n";
            print "$NOTESTR \"Access denied\" problems can occur\n";
            push(@CHECKARR, "\n$WARNSTR Incorrect permissions for directory $SMHDIR ($smhmask)\n");
            $warnings++;
        }

        if ( -d "$SMHCONFDIR" ) {
            my @smhfdir = `ls $SMHCONFDIR 2>/dev/null`;
            foreach my $smhfile ( @smhfdir ) {
                chomp($smhfile);
                my @smhdarr = `awk NF $SMHCONFDIR/$smhfile 2>/dev/null`;
                if ( @smhdarr ) {
                    print "\n$INFOSTR SMH configuration file $SMHCONFDIR/$smhfile\n";
                    print @smhdarr;
                }
            }
        }

        datecheck();
        print_trailer("*** END CHECKING HP SYSTEM MANAGEMENT HOMEPAGE (SMH) $datestring ***");
    }
}

# Subroutine to check DNS
#
sub dnschk {
    datecheck();
    print_header("*** BEGIN CHECKING DOMAIN NAME SERVICES $datestring ***");

    if ( ! @DNSRUN ) {
        print "$INFOSTR DNS server (named) not running\n";
    }
    else {
        print "$INFOSTR DNS server (named) running\n";
        foreach my $dnsfile (@DNSarray) {
            if ( ( -s "$dnsfile" ) && ( -T "$dnsfile" ) ) {
                print "\n$INFOSTR Contents of $dnsfile\n";
                if ( open( XY, "egrep -v ^# $dnsfile | awk NF |" ) ) {
                    while (<XY>) {
                        print $_;
                    }
                    close(XY);
                }
                else {
                   print
"\n$INFOSTR Cannot open $dnsfile or is in non-standard location\n";
                }
            }

            my @namedconf = `named-checkconf $dnsfile`;
            if ( @namedconf ) {
                print "\n$PASSSTR Seemingly syntax errors found in $dnsfile\n";
                print @namedconf;
            }
            else {
                print "\n$PASSSTR Seemingly no syntax errors in $dnsfile\n";
            }
        }

        my @rndcs = `rndc status 2>/dev/null`;
        if ( @rndcs ) {
            print "\n$INFOSTR Name Server control status rndc(1M)\n";
            print @rndcs;
        }
    }

    if ( open( YX, "egrep -v ^# $NAMEDCONF 2>/dev/null | awk NF |" ) ) {
        print "\n$INFOSTR Checking $NAMEDCONF\n";
        while (<YX>) {
            next if ( grep( /^$/, $_ ) );

            if ( grep( /KEYSERV_OPTIONS/, $_ ) && !grep( /-d/, $_ ) ) {
                push(@NAMARR,
"$WARNSTR KEYSERV_OPTIONS should have \"-d\" option ");
                push(@NAMARR, "for disabling secure RPC access to nobody\n");
                push(@CHECKARR,
"\n$WARNSTR KEYSERV_OPTIONS should have \"-d\" option for disabling\n");
                push(@CHECKARR, "secure RPC access to nobody in $NAMEDCONF\n");
            }

            if ( grep( /^NIS_MASTER_SERVER=/, $_ ) ) {
                ( undef, $NISserver ) = split( /=/, $_ );
                chomp($NISserver);
            }

            if ( grep( /^NIS_SLAVE_SERVER=/, $_ ) ) {
                ( undef, $NISslave ) = split( /=/, $_ );
                chomp($NISslave);
            }

            if ( grep( /^NIS_CLIENT=/, $_ ) ) {
                ( undef, $NISclient ) = split( /=/, $_ );
                chomp($NISclient);
            }

            if ( grep( /^NISPLUS_SERVER=/, $_ ) ) {
                ( undef, $NISPLUSserver ) = split( /=/, $_ );
                chomp($NISPLUSserver);
                $NISPLUS_FLAG++;
            }

            if ( grep( /^NISPLUS_CLIENT=/, $_ ) ) {
                ( undef, $NISPLUSclient ) = split( /=/, $_ );
                chomp($NISPLUSclient);
                $NISPLUS_FLAG++;
            }

            print $_;
        }
        close(YX);
    }
    else {
        print "\n$WARNSTR Cannot open $NAMEDCONF\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $NAMEDCONF\n");
    }

    if ( @NAMARR ) {
        print "\n";
        print @NAMARR;
    }

    if ( -s "$NAMED" ) {
        if ( open( I, "egrep -v ^# $NAMED | awk NF |" ) ) {
            print "\n$INFOSTR DNS resolver configuration ($NAMED):\n";
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
                push(@CHECKARR,
"\n$WARNSTR Default domain entry missing in $NAMED\n");
                $warnings++;
            }

            if ( "$SEARCHCOUNT" > 1 ) {
                print "\n$WARNSTR Multiple \"search\" keywords found in $NAMED\n";
                print
"$INFOSTR When more than one instance of the keyword is present, the last instance overrides\n";
                push(@CHECKARR,
"\n$WARNSTR Multiple \"search\" keywords found in $NAMED\n");
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
                print
"$NOTESTR When more than one instance of the keyword is present, the last instance overrides\n";
                push(@CHECKARR,
"\n$WARNSTR Multiple \"domain\" keywords found in $NAMED\n");
                $warnings++;
            }
            elsif ( "$DOMCOUNT" == 1 ) {
                print "\n$PASSSTR One \"domain\" keyword found in $NAMED\n";
            }
            else {
                print "\n$INFOSTR No \"domain\" keyword found in $NAMED\n";
            }

            if ( @MYDNSSRV ) {
                foreach my $ztm (@MYDNSSRV) {
                    &openport($ztm, '53', 'udp');
                    &openport($ztm, '53', 'tcp');
                }
            }

            print "\n$INFOSTR Found $DNS_NO \"nameserver\" entries in $NAMED\n";

            if ( $DNS_NO > $MAXDNSSRV ) {
                print
"$INFOSTR Normally, resolver library is limited to $MAXDNSSRV entires\n";
            }
        }
        else {
            print "\n$WARNSTR Cannot open $NAMED\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $NAMED\n");
            $warnings++;
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
        print "\n$WARNSTR $NAMED is zero-length or does not exist\n";
        push(@CHECKARR, "\n$WARNSTR $NAMED is zero-length or does not exist\n");
        $warnings++;
    }

    print "\n$INFOSTR Checking hostname resolution order\n";
    if ( ( -s "$NSSWITCH" ) && ( -T "$NSSWITCH") ) {
        if ( open( NPAD, "egrep -v ^# $NSSWITCH |" ) ) {
            print "$INFOSTR Configuration file $NSSWITCH exists\n";
            while (<NPAD>) {
                next if grep( /^$/, $_ );
                if ( grep( /^ipnodes/, $_ ) ) {
                    $IPNODES_FLAG++;
                }

                if ( grep( /^hosts/, $_ ) ) {
                    if ( grep( /#/, $_ ) ) {
                        $HOSTS_FLAG++;
                    }
                }

                print $_;
            }
            close(NPAD);

            if ( $IPNODES_FLAG == 0 ) {
                print "\n$WARNSTR Missing entry for ipnodes in $NSSWITCH\n";
                print "$NOTESTR Ipnodes is important for IPv4 and IPv6\n";
                push(@CHECKARR,
"\n$WARNSTR Missing entry for ipnodes in $NSSWITCH\n");
                $warnings++;
            }
            else {
                print "\n$PASSSTR Entry for ipnodes in $NSSWITCH is defined\n";
            }

            if ( $HOSTS_FLAG > 1 ) {
                print "\n$WARNSTR Entry for hosts in $NSSWITCH contains comment character\n";
                print "$NOTESTR Refer to defect QXCR1001074942\n";
                push(@CHECKARR,
"\n$WARNSTR Entry for hosts in $NSSWITCH contains comment character (refer to defect QXCR1001074942)\n");
                $warnings++;
            }
        } 
        else {
            print "\n$WARNSTR Cannot open $NSSWITCH\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $NSSWITCH\n");
            $warnings++;
        }

        my $stperms = (stat($NSSWITCH))[2] & 07777;
        my $rootows = (stat($NSSWITCH))[4];
        my $octps = sprintf "%lo", $stperms;

        if ( "$rootows" == 0 ) {
            print "\n$PASSSTR $NSSWITCH owned by UID $rootows\n";
        }
        else {
            print "\n$WARNSTR $NSSWITCH not owned by UID 0 ($rootows)\n";
            push(@CHECKARR, "\n$WARNSTR $NSSWITCH not owned by UID 0 ($rootows)\n");
            $warnings++;
        }

        if ( ($octps != 444) && ($octps != 644) ) {
           print "\n$WARNSTR Permissions for $NSSWITCH incorrect ($octps)\n";
           push(@CHECKARR, "\n$WARNSTR Permissions for $NSSWITCH incorrect ($octps)\n");
           $warnings++;
           print "$NOTESTR Permissions for $NSSWITCH should be 444 or 644\n";
        }
        else {
           print "\n$PASSSTR Permissions for $NSSWITCH correct ($octps)\n";
           print "$NOTESTR Permissions for $NSSWITCH should be 444 or 644\n";
        }
    }
    else {
        print "$WARNSTR Configuration file $NSSWITCH does not exist\n";
        push(@CHECKARR, "\n$WARNSTR Configuration file $NSSWITCH does not exist\n");
        $warnings++;
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

            if ( @HOSTWARN ) {
                print @HOSTWARN;
            }
            else {
                 print "\n$PASSSTR All entries in $HOSTS are unique\n";
            }
        }
        else {
            print "\n$ERRSTR Cannot open $HOSTS\n";
            push(@CHECKARR, "\n$ERRSTR Cannot open $HOSTS\n");
            $warnings++;
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
    print_trailer("*** END CHECKING DOMAIN NAME SERVICES $datestring ***");
}

# Subroutine to check NIS/YP
#
sub nischk {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK INFORMATION SERVICES (NIS/YP) $datestring ***");

    if ( (! "$TCB") && (! "$TCB2") ) {
        print
"$PASSSTR NIS not available on Trusted System Password database servers\n";
    }
    else {
        $domname = `domainname | awk NF`;

        if ("$domname") {
            my $ypwhich = `ypwhich 2>/dev/null`;
            chomp($ypwhich);

            if ( $NISserver == 1 ) {
                print "$INFOSTR $Hostname defined as NIS master in $NAMEDCONF\n";
            }

            if ( $NISslave == 1 ) {
                print
                  "$INFOSTR $Hostname defined as NIS slave in $NAMEDCONF\n";
            }

            if ( $NISclient == 1 ) {
                print "$INFOSTR $Hostname defined as NIS client in $NAMEDCONF\n";
            }

            if ( $NISPLUSserver == 1 ) {
                print "$INFOSTR $Hostname defined as NIS+ server in $NAMEDCONF\n";
            }

            if ( $NISPLUSslave == 1 ) {
                print "$INFOSTR $Hostname defined as NIS+ slave in $NAMEDCONF\n";
            }

            if ( $NISPLUS_FLAG > 0 ) {
                my @nisdefs = `nisdefaults`;
                if ( @nisdefs != 0 ) {
                    print "$INFOSTR NIS+ default values\n";
                    print @nisdefs;
                }
            }

            if ("$ypwhich") {
                print
                  "$INFOSTR NIS domain $domname (bound to server $ypwhich)\n";

                # Use yppoll to check if NIS master is responding.
                # Otherwise, other NIS commands like ypcat might be hung
                #
                my @yppoll = `yppoll hosts 2>&1 | grep -i "timed out"`;
                if ( @yppoll == 0 ) {
                    my @ypalias = `ypcat -x 2>/dev/null`;
                    if ( @ypalias != 0 ) {
                        print "\n$INFOSTR NIS map aliases\n";
                        print @ypalias;
                    }
                }

                if ( -s "$secnets" ) {
                    my @sn = `egrep -v ^# $secnets 2>/dev/null`;
                    if ( @sn != 0 ) {
                        print "\n$INFOSTR File $secnets\n";
                        print @sn;
                    }
                    else {
                        print "\n$INFOSTR File $secnets not set\n";
                        $warnings++;
                    }
                }
                else {
                    print "\n$INFOSTR File $secnets does not exist\n";
                    $warnings++;
                }

                if ( -s "$secservers" ) {
                    my @sn1 = `egrep -v ^# $secservers 2>/dev/null`;
                    if ( @sn1 != 0 ) {
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
                print "$INFOSTR NIS not active\n";
            }
        }
        else {
            print "$INFOSTR NIS not set\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING NETWORK INFORMATION SERVICES (NIS/YP) $datestring ***");

    if ( $NISLDAP_FLAG > 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING NIS TO LDAP GATEWAY SERVICES $datestring ***");

        print "$INFOSTR NIS to LDAP gateway processes seemingly running\n";

        my @ypldapdv = `ypldapd -v`;
        if ( @ypldapdv ) {
            print "$INFOSTR Configuration file $NISLDAPRC\n";
            print @ypldapdv;
        }

        if ( -s "$NISLDAPRC" ) {
            my @nisldaprc = `egrep -v ^# $NISLDAPRC 2>/dev/null | awk NF`;
            if ( @nisldaprc ) {
                print "$INFOSTR Configuration file $NISLDAPRC\n";
                print @nisldaprc;
            }
        }
        else {
            print "$INFOSTR Configuration file $NISLDAPRC does not exist or is zero-length\n";
        }

        if ( -s "$NISLDAPCONTXT" ) {
            my @niscontexts = `awk NF $NISLDAPCONTXT 2>/dev/null`;
            if ( @niscontexts ) {
                print "\n$INFOSTR Configuration file $NISLDAPCONTXT\n";
                print @niscontexts;
            }
        }
        else {
            print
"\n$INFOSTR Configuration file $NISLDAPCONTXT does not exist or is zero-length\n";
        }

        if ( -s "$NISLDAPCONF" ) {
            my @nisldapconf = `awk NF $NISLDAPCONF 2>/dev/null`;
            if ( @nisldapconf ) {
                print "\n$INFOSTR Configuration file $NISLDAPCONF\n";
                print @nisldapconf;
            }
        }
        else {
            print
"\n$INFOSTR Configuration file $NISLDAPCONF does not exist or is zero-length\n";
        }

        datecheck();
        print_trailer("*** END CHECKING NIS TO LDAP GATEWAY SERVICES $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING DHCP SERVICES $datestring ***");

    DHCPservchk();

    if ( ! -s "$dhcpcl" ) {
        print "\n$INFOSTR $dhcpcl is zero-length or missing\n";
    }
    else {
        my @dhcpclcat = `strings $dhcpcl`;
        if ( @dhcpclcat ) {
            print "\n$INFOSTR DHCP client file $dhcpcl\n";
            print @dhcpclcat;
        }
        else {
            print
"\n$INFOSTR DHCP client file $dhcpcl does not contain valid data\n";
        }
    }

    if ( ! -s "$dhcpv6cl" ) {
        print "\n$INFOSTR $dhcpv6cl is zero-length or missing\n";
    }

    if ( -d "$bootigndir" ) {
        my @ignls = `ls $bootigndir`;
        print "\n$INFOSTR Listing of $bootigndir\n";
        print @ignls;
    }
    else {
        print "\n$INFOSTR $bootigndir does not exist\n";
    }

    my @dhcpclient = `dhcpdb2conf 2>&1 | awk NF`;

    if ( @dhcpclient ) {
        print "\n$INFOSTR Dhcpdb2conf status\n";
        print "@dhcpclient";
    }

    if ( "$Minor$Patch" >= 1123 ) {
        my @dhcpv6client = `dhcpv6db2conf 2>&1 | awk NF`;

        if ( @dhcpv6client ) {
            print "\n$INFOSTR Dhcpv6db2conf status\n";
            print "@dhcpv6client";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING DHCP SERVICES $datestring ***");
}

# Subroutine to check RAM/swap
#
sub ramswapcheck {
    if ( "$Stand" ) {
        $KERN = "$Stand";
    }

    if ( "$Kmemdev" ) {
        $KMEM = "$Kmemdev";
    }

    if ( ! -r "$KMEM" ) {
        print "$ERRSTR Cannot read $KMEM\n";
        push(@CHECKARR, "\n$ERRSTR Cannot read $KMEM\n");
        $warnings++;
    }
    else {
        if ( grep( /\.10\./, $Maj ) ) {
            $SYMBOL = "physmem";
            $MEM_BLOCK =
              `echo \"$SYMBOL/D\" | adb $KERN $KMEM | awk 'NF==2 {print \$2}'`;
        }
        elsif ( "$Minor$Patch" >= 1120 ) {
            $SYMBOL = "memory_installed_in_machine";
            $MEM_BLOCK =
`echo \"phys_mem_pages /2D\" | adb -o $KERN $KMEM | grep [0-9] | awk '{print \$3}'`;
            $MEM_BLOCK2 = `echo \"phys_mem_pages/A\" | adb -o $KERN $KMEM | tail +2 | awk '{print \$2}'`;
            $ACTIVECPUNO =
`echo \"active_processor_count/D\" | adb -o $KERN $KMEM | awk 'NF==2 {print \$2}'`;
            chomp($ACTIVECPUNO);
        }
        elsif ( grep( /\.11\.00/, $Maj ) ) {
            $SYMBOL = "memory_installed_in_machine";
            $MEM_BLOCK =
              `echo \"$SYMBOL/D\" | adb -k $KERN $KMEM | awk 'NF==2 {print \$2 * 4}'`;
            $ACTIVECPUNO =
`echo \"processor_count/D\" | adb -k $KERN $KMEM | awk 'NF==2 && /processor_count/ {print \$2}'`;
            chomp($ACTIVECPUNO);
        }
        elsif ( grep( /\.11\./, $Maj ) ) {
            $SYMBOL = "memory_installed_in_machine";
            $MEM_BLOCK =
              `echo \"$SYMBOL/D\" | adb $KERN $KMEM | awk 'NF==2 {print \$2}'`;
            $ACTIVECPUNO =
`echo \"processor_count/D\" | adb $KERN $KMEM | awk 'NF==2 && /processor_count/ {print \$2}'`;
            chomp($ACTIVECPUNO);
        }
        else {
            next;
        }
    }

    if ( "$MEM_BLOCK2" ) {
        chomp($MEM_BLOCK2);
        $MEM_MBYTE = `echo \"$MEM_BLOCK2=D\" | adb -o $KERN $KMEM`;
        $MEM_MBYTE = int( ($MEM_MBYTE * $pgsize ) / 1048576 );
    }
    else {
        if ( "$MEM_BLOCK" ) {
            chomp($MEM_BLOCK);
            $MEM_MBYTE = int( $MEM_BLOCK * $pgsize / 1048576 );
        }
    }

    if ( open( MXB, "swapinfo |" ) ) {
        while (<MXB>) {
            push(@ALLSWAPINFO, "$_");
            chomp;
            if ( grep( /^dev/, $_ ) ) {
                (
                    undef,        $tswap,        $swapused,
                    $swapfree,    $swappctused,  $swapstart,
                    $swapreserve, $swappriority, $swapdev
                ) = split( /\s+/, $_ );
                $tswapall += $tswap;
                $tswapall2 += $tswap;
                $SWAP_DEV_NO++;
                push( @SWAPARRAY, $swapdev );
                push( @ALLSWAPVAL, $tswap );
            }
            elsif ( grep( /^fs/, $_ ) ) {
                (
                    undef,        $tswap,        $swapused,
                    $swapfree,    $swappctused,  $swapstart,
                    $swapreserve, $swappriority, $swapdev
                ) = split( /\s+/, $_ );
                $tswapall += $tswap;
                $tswapall2 += $tswap;
                $SWAP_FS_NO++;
                push( @ALLSWAPVAL, $tswap );
            }
            elsif ( grep( /^localfs/, $_ ) ) {
                (
                    undef,        $tswap,        $swapused,
                    $swapfree,    $swappctused,  $swapstart,
                    $swapreserve, $swappriority, $swapdev
                ) = split( /\s+/, $_ );
                $tswapall += $tswap;
                $tswapall2 += $tswap;
                $SWAP_LOCALFS_NO++;
                push( @ALLSWAPVAL, $tswap );
            }
            elsif ( grep( /^network/, $_ ) ) {
                (
                    undef,        $tswap,        $swapused,
                    $swapfree,    $swappctused,  $swapstart,
                    $swapreserve, $swappriority, $swapdev
                ) = split( /\s+/, $_ );
                $tswapall += $tswap;
                $tswapall2 += $tswap;
                $SWAP_NETWORK_NO++;
                push( @ALLSWAPVAL, $tswap );
            }
        }
        close(MXB);
    }
    else {
        print "$ERRSTR Cannot run swapinfo\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run swapinfo\n");
        $warnings++;
    }

    if ( $tswapall2 > 0 ) {
        $tswapall2 = $tswapall2 / 1024;
    }
}

# Subroutine to check RAM and swap
#
sub swapcheck {
    datecheck();
    print_header("*** BEGIN CHECKING PHYSICAL MEMORY AND SWAP $datestring ***");

    print "$NOTESTR Recommended to set MWC to off for primary mirrored swap\n";
    print "\n";
    print
"$NOTESTR It is also highly recommended to use separate dump device(s).\n";
    print "$NOTESTR Dedicated dump device will not shorten the time required\n";
    print "$NOTESTR to write from memory to the dump volume during the crash,\n";
    print
"$NOTESTR but will shorten the reboot time. This is because the crash image\n";
    print "$NOTESTR is not at risk being overwritten by page or swap activity\n";
    print
"$NOTESTR and savecrash can run in background to save the crash files into\n";
    print "$NOTESTR the crash dump directory.\n";
    print
"$NOTESTR If the dump device is also configured as one of the swap devices\n";
    print "$NOTESTR the device cannot be enabled for paging until savecrash has\n";
    print "$NOTESTR saving the image from the device to the crash dump directory.\n";
    print "$NOTESTR This extra time will be even greater if vPars are configured\n";
    print "$NOTESTR because multiple dump images may have to be saved.\n";
    print "$NOTESTR When dump and swap areas are separated, there is no need to\n";
    print "$NOTESTR utilize /var/adm/crash to save crash images -\n";
    print "$NOTESTR therefore savecrash(1) can be disabled\n";
    print "\n";

    my @DIMMLOC = `echo "selclass qualifier memory; info; wait;infolog;done;quit;OK" | cstm 2>/dev/null | awk '/^ / {print}'`;
    if ( @DIMMLOC ) {
        print "\n$INFOSTR DIMM locations\n";
        print "@DIMMLOC\n";
    }

    if ( @ALLSWAPINFO ) {
        print "$INFOSTR Swap space\n";
        print @ALLSWAPINFO;
    }

    my @paginglist = `paginglist 2>/dev/null`;
    if ( @paginglist ) {
        print "\n$INFOSTR Swap space (paging list) in machine format\n";
        print "@paginglist\n";
    }

    undef %saw;
    my @out = grep(!$saw{$_}++, @ALLSWAPVAL);

    if ( (($#out + 1) > 1) && (($#ALLSWAPVAL + 1) > 1) ) {
        print "\n$WARNSTR Swap devices not same size:\n";
        print "$INFOSTR @ALLSWAPVAL (KB)\n";
        print "\n$INFOSTR For best performance, swap devices should be same size\n";
        push(@CHECKARR, "\n$WARNSTR Swap devices not of same size\n");
        $warnings++;
    }


    foreach my $swpdev (@SWAPARRAY) {
        if ( ! @vxdctl0 ) {
            if ( open( NNN, "lvdisplay -v $swpdev 2>/dev/null |" ) ) {
                print "\n$INFOSTR Swap Logical Volume $swpdev\n";
                my $mirrnum = 0;
                my $MWC = q{};
                while (<NNN>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                    $_ =~ s/^\s+//g;
                    chomp;

                    if ( grep( /^\/dev\/dsk\/|^\/dev\/disk\//, $_ ) ) {
                        ( $realswappv, undef ) = split( /\s+/, $_ );
                    }

                    if ( grep( /^Mirror copies/, $_ ) ) {
                        ( undef, undef, $mirrnum ) = split( /\s+/, $_ );
                        if ( $mirrnum == 0 ) {
                            push(@ALLSWPDSP, "\n$WARNSTR $swpdev has no mirrors\n");
                            $warnings++;
                        }
                        else {
                            push(@ALLSWPDSP, "\n$INFOSTR $swpdev is mirrored\n");
                            $mirrnum++;
                        }
                    }

                    if ( grep( /^Consistency Recovery/, $_ ) ) {
                        ( undef, undef, $MWC ) = split( /\s+/, $_ );
                        foreach my $swlst ( @PrimSwap ) {
                            if ( grep(/\b$swlst\b/, $swpdev ) ) {
                                if ( $mirrnum > 0 ) {
                                    if ( "$MWC" eq "MWC" ) {
                                        push(@ALLSWPDSP,
"$WARNSTR $swpdev has Mirror Consistency Recovery enabled, with Mirror Write Cache set to \"$MWC\" for primary mirrored swap device\n");
                                        push(@CHECKARR,
"\n$WARNSTR $swpdev has Mirror Consistency Recovery enabled, with Mirror Write Cache set to \"$MWC\" for primary mirrored swap device\n");
                                    }
                                    elsif ( "$MWC" eq "NOMWC" ) {
                                        push(@ALLSWPDSP,
"$WARNSTR $swpdev has Mirror Consistency Recovery enabled, with Mirror Write Cache set to \"$MWC\" for primary mirrored swap device\n");
                                        push(@CHECKARR,
"\n$WARNSTR $swpdev has Mirror Consistency Recovery enabled, with Mirror Write Cache set to \"$MWC\" for primary mirrored swap device\n");
                                        $warnings++;
                                    }
                                    else {
                                        push(@ALLSWPDSP,
"$PASSSTR $swpdev has Mirror Consistency Recovery disabled, with Mirror Write Cache set to \"$MWC\" for primary mirrored swap device\n");
                                    }
                                }
                                else {
                                    push(@ALLSWPDSP,
"$INFOSTR $swpdev has Mirror Consistency Recovery with Mirror Write Cache set to \"$MWC\" for primary non-mirrored swap device\n");
                                    push(@CHECKARR,
"\n$INFOSTR $swpdev has Mirror Consistency Recovery with Mirror Write Cache set to \"$MWC\" for primary non-mirrored swap device\n");
                                }
                            }
                            else {
                                if ( $mirrnum > 0 ) {
                                    if ( "$MWC" ne "MWC" ) {
                                        push(@ALLSWPDSP,
"$WARNSTR $swpdev has Mirror Consistency Recovery disabled, with Mirror Write Cache set to \"$MWC\" for secondary mirrored swap device\n");
                                        push(@CHECKARR,
"\n$WARNSTR $swpdev has Mirror Consistency Recovery disabled, with with Mirror Write Cache set to \"$MWC\" for secondary mirrored swap device\n");
                                        $warnings++;
                                    }
                                    else {
                                        push(@ALLSWPDSP,
"$PASSSTR $swpdev has Mirror Consistency Recovery enabled, with with Mirror Write Cache set to \"$MWC\" for secondary mirrored swap device\n");
                                    }
                                }
                                else {
                                    push(@ALLSWPDSP,
"$INFOSTR $swpdev has Mirror Consistency Recovery with Mirror Write Cache set to \"$MWC\" for secondary non-mirrored swap device\n");
                                    push(@CHECKARR,
"\n$INFOSTR $swpdev has Mirror Consistency Recovery with Mirror Write Cache set to \"$MWC\" for secondary non-mirrored swap device\n");
                                }
                            }
                        }
                    }
                }
                close(NNN);
            }
        }

        my $servdsk2 = q{}; 
        foreach $servdsk2 ( sort keys %disklist ) {
            if ( grep(/\Q$swpdev\E/, @{$disklist{$servdsk2}}) ) {
                print
"\n$INFOSTR Physical volume $servdsk2 contains swap device $swpdev\n";
                $swcount{$servdsk2} += 1;
                if ( $swcount{$servdsk2} > 1 ) {
                    if (! grep(/Physical volume $servdsk2 contains/, @BADSWAPARR )) {
                        push(@BADSWAPARR,
"\n$ERRSTR Physical volume $servdsk2 contains multiple device-based paging spaces\n");
                        push(@CHECKARR,
"\n$ERRSTR Physical volume $servdsk2 contains multiple device-based paging spaces\n");
                        $warnings++;
                    }
                }
            }
        }
    }

    if ( @ALLSWPDSP ) {
        print @ALLSWPDSP;
    }

    if ( $tswapall > 0 ) {
        $tswapall = $tswapall / 1024;

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
"\n$ERRSTR Physical volume $servdsk contains multiple device-based paging spaces\n"
              : print
"\n$PASSSTR Physical volume $servdsk contains 1 (single) device-based paging space\n";
        }

        print "\n";

        printf
"$INFOSTR Server has %d paging space%s on mass storage (device-based)\n\n",
        $SWAP_DEV_NO, $SWAP_DEV_NO == 1 ? "" : "s";

        if ( "$SWAP_LOCALFS_NO" > 0 ) {
            printf
"$WARNSTR Server has %d paging space%s in local file system storage (file system based)\n\n",
            $SWAP_LOCALFS_NO, $SWAP_LOCALFS_NO == 1 ? "" : "s";
            push(@CHECKARR, "\n$WARNSTR Server has $SWAP_LOCALFS_NO paging spaces in local file system storage (file system based)\n");
            $warnings++;
        }

        if ( "$SWAP_NETWORK_NO" > 0 ) {
            printf
"$WARNSTR Server has %d paging space%s in remote file system storage (network file system based)\n",
            $SWAP_NETWORK_NO, $SWAP_NETWORK_NO == 1 ? "" : "s";
            push(@CHECKARR, "\n$WARNSTR Server has $SWAP_NETWORK_NO paging spaces in remote file system storage (network file system based)\n");
            $warnings++;
        }

        if ( $SWAP_DEV_NO >= $MAXNSWAPDEV ) {
            print "\n$WARNSTR Maximum number of device-based paging spaces reached ";
            print "(current number is $SWAP_DEV_NO whilst maximum number is $MAXNSWAPDEV)\n";
            push(@CHECKARR, "\n$WARNSTR Maximum number of device-based paging spaces reached ");
            push(@CHECKARR, "(current number is $SWAP_DEV_NO whilts maximum number is $MAXNSWAPDEV)\n");
            $warnings++;
        }
        else {
            print "\n$PASSSTR Maximum number of device-based paging spaces not reached ";
            print "(current number is $SWAP_DEV_NO whilst maximum number is $MAXNSWAPDEV)\n";
        }

        # Minimum swap size (as per Unix Build Standard)
        #
        if ( "$opts{w}" == 1 ) {
            $minswap = 4096;
        }

        print "\n";

        if ( $tswapall < $minswap ) {
            print "$WARNSTR Swap space is less than minimum ";
            print "(Swap=$tswapall MB, minumum=$minswap MB)\n";
            push(@CHECKARR, "\n$WARNSTR Swap space is less than minimum ");
            push(@CHECKARR, "(Swap=$tswapall MB, minumum=$minswap MB)\n");
            $warnings++;
        }

        if ( $tswapall < $MEM_MBYTE ) {
            print "$INFOSTR Swap space is smaller than RAM ";
            print "(Memory=$MEM_MBYTE MB, Swap=$tswapall MB)\n";
        }
        else {
            print "$INFOSTR Swap space is at least RAM size ";
            print "(Memory=$MEM_MBYTE MB, Swap=$tswapall MB)\n";
        }

        if ( $maxuswap < $MEM_MBYTE ) {
            print "\n$WARNSTR Maximum usable swap space is smaller than RAM ";
            print "(Memory=$MEM_MBYTE MB, Maximum_Usable_Swap=$maxuswap MB)\n";
            push(@CHECKARR,
"\n$WARNSTR Maximum usable swap space is smaller than RAM ");
            push(@CHECKARR, "(Memory=$MEM_MBYTE MB, Maximum_Usable_Swap=$maxuswap MB)\n");
            $warnings++;
        }
        else {
            print "\n$INFOSTR Maximum usable swap space is equal to or larger than RAM ";
            print "(Memory=$MEM_MBYTE MB, Maximum_Usable_Swap=$maxuswap MB)\n";
        }

        if ( $MEM_MBYTE < $tswapall ) {
            print "$INFOSTR Swap space is larger than physical memory ";
            print "(Memory=$MEM_MBYTE MB, Swap=$tswapall MB)\n";
        }

        if ( ( @VMcheck ) && ( $HPVM_FLAG > 0 ) ) {
            if ( "$HPVMVERSION2" < 4 ) {
                if ( $tswapall < ( 4096 + $MEM_MBYTE ) ) {
                    print
"\n$INFOSTR Swap space is smaller than 4 GB + RAM\n";
                    print
"(4 GB + RAM for swap space is recommended for HP Integrity Virtual Machines host when HPVM is at version 3.5 or below)\n";
                }
                else {
                    print
"\n$PASSSTR Swap space is larger or equal to 4 GB + RAM\n";
                    print
"(4 GB + RAM for swap space is recommended for HP Integrity Virtual Machines host when HPVM is at version 3.5 or below)\n";
                }
            }
        }

        if ( $swapdeviceno == 0 ) {
            $swapdeviceno =
            $SWAP_DEV_NO + $SWAP_FS_NO + $SWAP_LOCALFS_NO + $SWAP_NETWORK_NO;
        }

        if ( $swapdeviceno < $Minswapdevno ) {
            print
"\n$INFOSTR Less than recommended number of swap devices (minimum $Minswapdevno)\n";
        }
        else {
            print
"\n$PASSSTR Recommended number of swap devices satisfied (minimum $Minswapdevno, installed $swapdeviceno)\n";
        }

        print "\n";

        if ( ( $MEM_MBYTE + $tswapall ) < $INTLOGMIN ) {
            print
"$WARNSTR Sum of swap and physical memory is smaller than $INTLOGMIN MB\n";
            print
"$INFOSTR VxFS file system with 16384K intent log size cannot be cleaned\n";
            push(@CHECKARR,
"\n$WARNSTR Sum of swap and physical memory is smaller than $INTLOGMIN MB\n");
            $warnings++;
        }
        else {
            print
"$PASSSTR Sum of swap and physical memory is larger than $INTLOGMIN MB\n";
            print
"$INFOSTR VxFS file system with 16384K intent log size can be cleaned\n";
        }
    }
    else {
        print "$ERRSTR Cannot run swapinfo\n";
        push(@CHECKARR, "\n$ERRSTR Cannot run swapinfo\n");
        $warnings++;
    }

    my @swapinfos = `swapinfo -s 2>/dev/null`;

    if (@swapinfos) {
        print "\n$INFOSTR Swapinfo status for next boot\n";
        print @swapinfos;
    }

    my @memdetail = `memdetail 2>/dev/null`;

    if (@memdetail) {
        print "\n$INFOSTR Memdetail status\n";
        print @memdetail;
    }

    datecheck();
    print_trailer("*** END CHECKING PHYSICAL MEMORY AND SWAP $datestring ***");
}

# Subroutine to check Npars and Vpars
#
sub par_vpar {
    datecheck();
    print_header("*** BEGIN CHECKING GLOBALLY UNIQUE IDENTIFIER MANAGER GUIDMgr $datestring ***");

    if ( -f "$GUIDCONF" ) {
       my @guidconf = `cat $GUIDCONF 2>/dev/null`;
       if (@guidconf) {
           print "$INFOSTR GUID configuration file $GUIDCONF\n";
           print "@guidconf\n";
        }
    }

    if ( open( GCONF, "guidconfig -l 2>/dev/null |" ) ) {
        print "\n$INFOSTR GUIDimgr status\n";
        while (<GCONF>) {
            print $_;
            if ( grep( /^BE_LIBS not defined|^HOST not defined/, $_ ) ) {
                $GUID_WARN++;
                push(@CHECKARR, "\n$WARNSTR \"BE_LIBS\" or \"HOST\" not defined in GUIDmgr\n");
                $warnings++;
            }
        }
        close(GCONF);
    }

    if ( $GUID_WARN == 0 ) {
       eval {
           # On certain occasions, guidmgmt hangs, so we need to
           # manage how long it runs
           #
           local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - guidmgmt seemingly hung\n"};
           alarm 25;
           @guidmgmt = `guidmgmt -L wwn 2>/dev/null`;
           alarm 0;
        };

        if (@guidmgmt) {
           print "$INFOSTR GUIDmgmt status\n";
           print "@guidmgmt\n";
        }
    }
    else {
        print "$INFOSTR GUIDMgr seemingly not in use or applicable on this platform\n";
    }

    datecheck();
    print_trailer("*** END CHECKING GLOBALLY UNIQUE IDENTIFIER MANAGER GUIDMgr $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SERVER PARTITIONING $datestring ***");

    if (@Pararr) {
        print "$INFOSTR Physical partitioning set up on this platform\n";
        print @Pararr;
        $parset++;

        my @parsr = `parstatus -r 2>/dev/null`;

        if (@parsr) {
            print "\n$INFOSTR @parsr";
        }

        my @parsz = `parstatus -z 2>/dev/null | awk NF`;

        if (@parsz) {
            print "\n$INFOSTR Current partition specification (parspec) name associated with nPartitions\n";
            print @parsz;
        }

        my @parst = `parstatus -T 2>&1 | awk NF`;

        if (@parst) {
            print "\n$INFOSTR Current partition hyperthreading status\n";
            print @parst;
        }

        if ( open( PAR, "parstatus 2>/dev/null |" ) ) {
            print "\n$INFOSTR nPar status\n";
            while (<PAR>) {
                print $_;
                if ( grep( /\bFloat\b/, $_ ) ) {
                    $DYNPAR_FLAG++;
                    push(@DYPARARR, $_);
                }
            }
            close(PAR);
        }

        if ( open( PARS, "parstatus -P -M 2>/dev/null |" ) ) {
            print "\n$INFOSTR nPar status in machine-readable form\n";
            while (<PARS>) {
                print $_;
                if ( grep( /^partition:/, $_ ) ) {
                    my @NPARM = split(/\s+/, $_ );
                    if ( $NPARM[0] =~ m/[0-9.]/ ) { 
                        $partnum = $NPARM[0];
                    }
                    else {
                        $partnum = $NPARM[1];
                    }
                    chomp($partnum);
                    $partnum =~ s/^partition://g;
                    $partnum =~ s/^\s+//g;
                    $partnum =~ s/\s+$//g;
                    push(@NPARARR, $partnum);
                }
            }
            close(PARS);
        }

        foreach my $nparl (@NPARARR) {
            if ( open( PARN, "parstatus -V -p $nparl 2>/dev/null |" ) ) {
                print "\n$INFOSTR Status for nPar $nparl\n";
                while (<PARN>) {
                    print $_;

                    if ( grep( /Good Memory Size/, $_ ) ) {
                        my @NPARM = split(/:/, $_ );
                        $goodmem = $NPARM[1];
                        chomp($goodmem);
                        $goodmem =~ s/^\s+//g;
                        $GOODMEM{$nparl} = $goodmem;
                    }

                    if ( grep( /^Total Interleave Memory/, $_ ) ) {
                        my @NPARI = split(/:/, $_ );
                        $ILMmem = $NPARI[1];
                        chomp($ILMmem);
                        $ILMmem =~ s/^\s+//g;
                        $ILMMEM{$nparl} = $ILMmem;
                    }

                    if ( grep( /^Total Allocated CLM/, $_ ) ) {
                        my @NPARC = split(/:/, $_ );
                        $CLMmem = $NPARC[1];
                        chomp($CLMmem);
                        $CLMmem =~ s/^\s+//g;
                        $CLMMEM{$nparl} = $CLMmem;
                    }

                    if ( grep( /^Total SLM/, $_ ) ) {
                        my @NPARS = split(/:/, $_ );
                        $SLMmem = $NPARS[1];
                        chomp($SLMmem);
                        $SLMmem =~ s/^\s+//g;
                        $SLMMEM{$nparl} = $SLMmem;
                    }
                }
                close(PARN);
            }

            if ( "$GOODMEM{$nparl}" && ("$GOODMEM{$nparl}" > 0)) {
                if ("$CLMMEM{$nparl}" ) {
                    printf "\nnPar %-3s: %s total memory,
          %s interleaved memory (%3.2f%% of total)
          %s cell-local memory (%3.2f%% of total)\n",
                    $nparl,
                    $GOODMEM{$nparl},
                    $ILMMEM{$nparl},
                    ( $ILMMEM{$nparl} / $GOODMEM{$nparl} ) * 100,
                    $CLMMEM{$nparl},
                    ( $CLMMEM{$nparl} / $GOODMEM{$nparl} ) * 100;
                }

                if ("$SLMMEM{$nparl}" && ("$SLMMEM{$nparl}" > 0)) {
                    printf "\nnPar %-3s: %s total memory
          %s interleaved memory (%3.2f%% of total)
          %s socket-local memory (%3.2f%% of total)\n",
                    $nparl,
                    $GOODMEM{$nparl},
                    $ILMMEM{$nparl},
                    ( $ILMMEM{$nparl} / $GOODMEM{$nparl} ) * 100,
                    $SLMMEM{$nparl},
                    ( $SLMMEM{$nparl} / $GOODMEM{$nparl} ) * 100;
                }
            }

            my @parsz = `parstatus -p $nparl -Z 2>/dev/null | awk NF`;
            if (@parsz) {
                print "\n$INFOSTR nPar $nparl contents of the partition specification (parspec)\n";
                print @parsz;
            }

            my @parst = `parstatus -p $nparl -t 2>/dev/null | awk NF`;
            if (@parst) {
                print "\n$INFOSTR nPar $nparl tree of physical locations and resource paths\n";
                print @parst;
            }
        }

        my @paravail = `parstatus -A -C 2>/dev/null | awk NF`;
        if (@paravail) {
            print "\n$INFOSTR nPar unallocated resources\n";
            print @paravail;
        }
    }

    if ( "$parset" == 0 ) {
        print
          "\n$INFOSTR Physical partitioning not set or active on this platform\n";
    }
    else {
        print "\n$INFOSTR Physical partitioning supported on this ";
        print "platform and active\n";
    }

    if ( "$Minor$Patch" >= 1131 ) {
        my @locinfo = `locinfo 2>/dev/null | egrep -vi "System wide locality"`;
        if (@locinfo) {
            print "\n$INFOSTR System-wide locality info\n";
            print @locinfo;
        }

        my @parolradm = `echo q | parolrad -m 2>&1 | awk NF`;
        if (@parolradm) {
            print "\n$INFOSTR Dynamic nPar status\n";
            print @parolradm;
        }

        if ( $MEM_MBYTE < $RAM_TRESHOLD ) {
            $MINRAMBASECELL = int($MEM_MBYTE / 2);
            print
"\n$NOTESTR When total amount of physical memory is less that 8 GB\n";
            print
"$NOTESTR recommended minimum amount of memory on base cells is 1/2 RAM ($MINRAMBASECELL MB)\n";
        }
        elsif ( ( $MEM_MBYTE == $RAM_TRESHOLD ) || ( $MEM_MBYTE < ( $RAM_TRESHOLD * 2 ) ) ) {
            $MINRAMBASECELL = 4096;
            print
"\n$NOTESTR When total amount of physical memory is between 8 and 16 GB\n";
            print
"$NOTESTR recommended minimum amount of memory on base cells is $MINRAMBASECELL MB\n";
        }
        else {
            $MINRAMBASECELL = int($MEM_MBYTE / 4);
            print
"\n$NOTESTR When total amount of physical memory is larger than 16 GB\n";
            print
"$NOTESTR recommended minimum amount of memory on base cells is 1/4 RAM ($MINRAMBASECELL MB)\n";
        } 
    }

#    foreach my $np (@Models_with_vpar) {
#        if ( grep( /$np/, "$Model" ) ) {
#            $VPAR_FLAG++;
#        }
#    }

     my @VParr   = `vparstatus 2>/dev/null | awk '! /awk|^$|^#/ {print}'`;
     my @VParrvb = `vparstatus -v 2>/dev/null | awk '! /awk|^$|^#/ {print}'`;

     my $ret = system "vecheck 2>/dev/null";
     #my $RCVALUE = WEXITVALUE($?);
     my $RCVALUE = ( $ret >> 8 ) && 0xff;
     chomp($RCVALUE);
     if ( ("$RCVALUE" == 0) || (@VParr) ) {
        print
"\n$INFOSTR vecheck(1m) confirms server running in virtual partition (vPars) environment\n";

        print "\n$INFOSTR Virtual partitioning supported on this platform\n";
        print @VParr;
        print "\n$INFOSTR Virtual partitioning extended summary\n";
        print @VParrvb;

        my @Vparw = `vparstatus -w 2>/dev/null`;
        my $thisvpar = q{};
        if ( @Vparw ) {
            print "$INFOSTR @Vparw\n";

            $thisvpar = $Vparw[$#Vparw];
            chomp($thisvpar);
            $thisvpar =~ s/\.//g;
            my @VCPUcal = `vparstatus -p $thisvpar 2>/dev/null | tail -1 | awk NF`;
            if ( @VCPUcal ) {
                my $boundCPUs = $VCPUcal[3];
                my $unboundCPUs = $VCPUcal[4];
                print
"\n$INFOSTR Bound/unbound CPU ratio should be 1 at minimum (bound $boundCPUs, unbound $unboundCPUs)\n";
                if ( "$unboundCPUs" != 0 ) {
                    my $CPUval = int($boundCPUs / $unboundCPUs);
                    if ( $CPUval < 1 ) {
                        print
"$WARNSTR CPU ratio below minimum requirements (calculated value $CPUval)\n";
                    }
                    else {
                        print
"$PASSSTR CPU ratio satisfies minimum requirements (calculated value $CPUval)\n";
                    }
                }
                else {
                    print "$PASSSTR CPU ratio exceeds minimum requirements\n";
                }
            }
        }

        foreach my $vpardev (@VPARARRAY) {
            chomp($vpardev);
            if ( grep(/PA-RISC/i, $ARCH) ) {
                if ( ! -c "$vpardev" ) {
                    print "\n$WARNSTR $vpardev does not exist or vpmon not running\n";
                    push(@CHECKARR, "\n$WARNSTR $vpardev does not exist or vpmon not running\n");
                    $warnings++;
                }
            }
        }

        # Recommended to have 1 GB of RAM per installed CPU in each vPar
        #
        my $VPARRAM = 1024;
        if ( int($MEM_MBYTE / $PROCNO) >= $VPARRAM ) {
            print "\n$PASSSTR More than $VPARRAM MB per installed CPU\n";
        }
        else {
            print "\n$WARNSTR Less than $VPARRAM MB per installed CPU\n";
            print "$NOTESTR Recommended to have $VPARRAM MB per installed CPU in vPars\n";
            push(@CHECKARR, "\n$WARNSTR Less than $VPARRAM MB per installed CPU\n");
            $warnings++;
        }

        if ( -s "$vpard" ) {
            print "\n$INFOSTR Configuration file $vpard\n";
            my @vp1 = `awk NF $vpard`;
            print @vp1;
        }

        if ( -s "$vparhb" ) {
            print "\n$INFOSTR Configuration file $vparhb\n";
            my @vp2 = `awk NF $vparhb`;
            print @vp2;
        }

        if ( -s "$vparinit" ) {
            print "\n$INFOSTR Configuration file $vparinit\n";
            my @vp3 = `awk NF $vparinit`;
            print @vp3;
        }

        if ( open( VXV, "vparstatus -M 2>/dev/null |" ) ) {
            print
"\n$INFOSTR vPar attribute and resource status in machine format\n";
            while (<VXV>) {
                if ( $. == 1 ) {
                    ( $Vparcontrol, undef ) = split( /:/, $_ );
                    chomp($Vparcontrol);
                }
                print $_;
                $VPARCOUNT++;
            }
            close(VXV);
        }

        if ( "$VPARCOUNT" > $MAX_VPAR_PER_NPAR ) {
            print
"\n$WARNSTR vPar count ($VPARCOUNT) is greater than recommended value of $MAX_VPAR_PER_NPAR vPars per nPar\n";
            push(@CHECKARR,
"\n$WARNSTR vPar count ($VPARCOUNT) is greater than recommended value of $MAX_VPAR_PER_NPAR vPars per nPar\n");
            $warnings++;
        }
        else {
            print
"\n$PASSSTR vPar count ($VPARCOUNT) is lower than recommended maximum value of $MAX_VPAR_PER_NPAR vPars per nPar\n";
        }

        if ( "$Vparcontrol" ) {
            print "\n$INFOSTR vPar control server is $Vparcontrol\n";
        }

        my @Vparextract = `vparextract -l 2>/dev/null | awk NF`;
        if ( @Vparextract ) {
            print "\n$INFOSTR vPar extracts\n";
            print @Vparextract;
        }

        my @Vparm = `vparstatus -m 2>/dev/null | awk '! /Usage|Error/ && /:/ {print}'`;
        if ( @Vparm ) {
            print "\n$INFOSTR vPar paths\n";
            print @Vparm;
        }

        my @Vpard = `vparstatus -d 2>/dev/null | awk NF`;
        if ( @Vpard ) {
            print "\n$INFOSTR vPar assignment and dual-core CPU (siblings)\n";
            print @Vpard;
        }

        my @Vparadmin = `vparadmin -l 2>/dev/null | awk NF`;
        if ( @Vparadmin ) {
            print "\n$INFOSTR vPar secure admin status\n";
            print @Vparadmin;
        }

        my @Vpare = `vparstatus -e 2>/dev/null | awk '! /Usage|Error/ && /:/ {print}'`;
        if ( @Vpare ) {
            print "\n$INFOSTR vPar monitor log entries\n";
            print @Vpare;
        }

        my @Vpardbp = `vpardbprofile 2>/dev/null`;
        if ( @Vpardbp ) {
            print "\n$INFOSTR vPar DB profile\n";
            print @Vpardbp;
        }

        my @VPenv = `vparenv 2>/dev/null | awk NF`;

        if ( @VPenv != 0 ) {
            print "\n$INFOSTR vPar CLM and ILM assignment\n";
            print @VPenv;
        }

        if ( "$Hardware" eq "ia64" ) {
            my @VPefi = `vparefiutil 2>/dev/null | awk NF`;

            if ( @VPefi != 0 ) {
                print "\n$INFOSTR vPar efiutil\n";
                print @VPefi;
            }
        }

        my @Vparavail = `vparstatus -A 2>/dev/null`;
        if (@Vparavail) {
            print "\n$INFOSTR vPar unallocated resources\n";
            print @Vparavail;
        }

        if ( grep(/PA-RISC/i, $ARCH) ) {
            my @vparrelocstat = `vparreloc -f $Stand`;
            if (@vparrelocstat) {
                print "\n$INFOSTR Checking kernel relocatable\n";
                print @vparrelocstat;
            }
            else {
                print "\n$WARNSTR Cannot verify kernel relocatable\n";
                push(@CHECKARR, "\n$WARNSTR Cannot verify kernel relocatable\n");
                $warnings++;
            }
        } 

        if ( $VCONSD_FLAG > 0 ) {
            print "\n$INFOSTR Virtual console controlled by this server\n";
            print "(vconsd process running)\n";

            if ( @vconsmpsched ) {
                print "\n$INFOSTR Vconsd binding\n";
                print @vconsmpsched;
            }
        }
        else {
            print "\n$INFOSTR Virtual console not controlled by this server\n";
            print "(vconsd process not running or not supported on this platform)\n";
        }
     }
     else {
        if ( "$RCVALUE" == 255 ) {
            print "\n$INFOSTR Virtual partitioning not used on this platform\n";
            print
"\n$INFOSTR vecheck(1m) confirms server NOT running in virtual partition (vPars) environment\n";
        }
     }

    datecheck();
    print_trailer("*** END CHECKING SERVER PARTITIONING $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING NON UNIFORM MEMORY ACCESS (NUMA) $datestring ***");

    if ( $NUMACOUNT > 1 ) {
        print "$INFOSTR Non-uniform memory access enabled on this platform\n";
    }
    else {
        print
"$INFOSTR Non-uniform memory access disabled or not applicable on this platform\n";
    }

    datecheck();
    print_trailer("*** END CHECKING NON UNIFORM MEMORY ACCESS (NUMA) $datestring ***");
}

# Subroutine to check login banners
#
sub motd {
    datecheck();
    print_header("*** BEGIN CHECKING LOGIN BANNERS $datestring ***");

    if ( -s "$ISSUE" ) {
        print "$PASSSTR Login banner $ISSUE exists\n";
        my @catissue = `cat $ISSUE 2>/dev/null`;
        if ( grep(/Release|HP-UX/, @catissue) ) {
            print "$WARNSTR Login banner $ISSUE possibly not customised (Release version shown)\n";
            push(@CHECKARR,
"\n$WARNSTR Login banner $ISSUE possibly not customised (Release version shown)\n");
            $warnings++;
        }
        else {
            print "$INFOSTR Login banner $ISSUE seemingly customised\n";
        }

        if ( @catissue ) {
            print "\n@catissue\n";
        }
    }
    else {
        print "$WARNSTR Login banner $ISSUE does not exist\n";
        push(@CHECKARR, "\n$WARNSTR Login banner $ISSUE does not exist\n");
        $warnings++;
    }

    if ( -s "$MOTD" ) {
        print "\n$PASSSTR Login banner $MOTD exists\n";
        my @motdissue = `cat $MOTD 2>/dev/null`;
        if ( grep(/Release|HP-UX/, @motdissue) ) {
            print "\n$WARNSTR Login banner $MOTD possibly not customised ";
            print "(Release version shown)\n";
            push(@CHECKARR,
"\n$WARNSTR Login banner $MOTD possibly not customised (Release version shown)\n");
            $warnings++;
        }
        else {
            print "$INFOSTR Login banner $MOTD seemingly customised\n";
        }

        if ( @motdissue ) {
            print "\n@motdissue\n";
        }
    }
    else {
        print "\n$WARNSTR Login banner $MOTD does not exist\n";
        push(@CHECKARR, "\n$WARNSTR Login banner $MOTD does not exist\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING LOGIN BANNERS $datestring ***");
}

# Subroutine to check SAN configuration
#
sub SANchk {
    datecheck();
    print_header("*** BEGIN CHECKING SAN AND NAS CONFIGURATION $datestring ***");

    if ( $SECPATHAG > 0 ) {
        print "$INFOSTR Secure Path Agent running\n";
        @SPMGR = `spmgr display -a -v 2>/dev/null`;

        @AUTOPATH = `autopath display 2>/dev/null`;
        if ( @AUTOPATH != 0 ) {
            print "\n$INFOSTR SecurePath configured\n";
            print @AUTOPATH;
        }

        if ( @SPMGR != 0 ) {
            print "\n$INFOSTR EVA SAN seemingly connected\n";
            print @SPMGR;
            $ARRFLAG++;

            my @SPMGRLBAL = `spmgr display -r -v 2>/dev/null`;
            if ( @SPMGRLBAL != 0 ) {
                print "\n$INFOSTR EVA load balancing status\n";
                print @SPMGRLBAL;
            }
        }
    }
    else {
        print "$INFOSTR Secure Path Agent seemingly not running\n";
    }

    if ( "$Minor$Patch" >= 1131 ) {
        my @ioscl = `ioscan -C lunpath 2>/dev/null`;
        if ( @ioscl ) {
            print "\n$INFOSTR Ioscan lunpath status\n";
            print @ioscl;
            print "\n";
        } 
    }

    @SANLUN = `sanlun lun show -pvv all 2>/dev/null`;

    @XPINFO = `xpinfo 2>/dev/null| egrep -v "Scanning|No disk"| awk NF`;
    
    my @ESSCLI = `esscli list diskgroup 2>/dev/null | awk NF`;

    @IRDIAGARR = `irdisplay 2>/dev/null | egrep -v "no Internal RAID"`;

    @EMULEX = `showhba 2>/dev/null | awk NF`;

    if ( ! "@EVADISC" ) {
        @EVADISC = `evadiscovery -l 2>/dev/null | awk NF`;
    }

    if ( ! "@EVAINFO" ) {
        @EVAINFO = `evainfo -a -l 2>/dev/null | awk NF`;
    }

    if ( ! "@EVAINFOWWN" ) {
        @EVAINFOWWN = `evainfo -P -W 2>/dev/null | awk NF`;
    }

    if ( "$Minor$Patch" >= 1131 ) {
        $TDFLAG="dsf_map";
        $FCDFLAG="-dsf_map";
    }

    @TDLIST  = `tdlist $TDFLAG 2>/dev/null`;
    @FCDLIST = `fcdlist $FCDFLAG 2>/dev/null`;

    if ( @SANLUN ) {
        print "$INFOSTR NetApp NAS seemingly connected\n";
        print @SANLUN;
        print "\n";

        my @SANFCP = `sanlun fcp show adapter -v all`;
        if ( @SANFCP ) {
            print "\n$INFOSTR NetApp FCP adapter status\n";
            print @SANFCP;
        }

        my @ontapshow = `enable_ontap_pvlinks show`;
        if ( @ontapshow ) {
            print "\n$INFOSTR NetApp ONTAP LUN status\n";
            print @ontapshow;
        }
    }

    if ( @TDLIST ) {
        print "\n$INFOSTR Tachyon (td) devices\n";
        print @TDLIST;
    }

    if ( @FCDLIST ) {
        print "\n$INFOSTR FCD devices\n";
        print @FCDLIST;
    }

    if ( $SASDFLAG > 0 ) {
        @SASDINFO = `saslist get_info ctrl sasd 2>/dev/null`;
        @SASDLUN = `saslist get_info lun sasd 2>/dev/null`;
        if ( "$Minor$Patch" >= 1131 ) {
            $SASFLAG = "-N";
        }

        my @sasddev = `ls /dev/sasd* 2>/dev/null`;
        foreach my $sasd ( @sasddev ) {
            chomp($sasd);
            my @sasdarr = `sasmgr $SASFLAG get_info -D $sasd -q raid`;
            if ( @sasdarr ) {
                print "$INFOSTR SAS interface $sasd\n";
                print @sasdarr;
                print "\n";
            }

            my @saslun = `sasmgr $SASFLAG get_info -D $sasd -q lun=all`;
            if ( @saslun ) {
                print "$INFOSTR SAS device file assignments for $sasd\n";
                print @saslun;
                print "\n";
            }

            my @sasstat = `sasmgr get_stat -D $sasd -q phy=all`;
            if ( @sasstat ) {
                print "$INFOSTR SAS interface statistics $sasd\n";
                print @sasstat;
                print "\n";
            }
        }
    }

    @ARRAYDSP = `arraydsp -i 2>/dev/null`;

    if ( ! "@EMC" ) {
        @EMC = `syminq 2>/dev/null`;
    }

    @INTRAID =
      `irconcheck 2>/dev/null | egrep -vi "No Internal RAID adapters found"`;

    my @ARMDSP = `armdsp -i 2>/dev/null | awk NF`;

    my @ARMDIAG = `armdiag -W 2>/dev/null | awk NF`;

    my @ARMDSP2 = `armdsp -t 2>/dev/null | awk NF`;

    my @ARMTOPOLOGY = `armtopology $Hostname 2>/dev/null | awk NF`;

    if ( @EVADISC != 0 ) {
        print "\n$INFOSTR EVA SAN and DR seemingly configured\n";
        print @EVADISC;
    }

    if ( @EVAINFO != 0 ) {
        print "\n$INFOSTR EVA SAN information\n";
        print @EVAINFO;
    }

    if ( @EVAINFOWWN != 0 ) {
        print "\n$INFOSTR EVA SAN information with agile devices\n";
        print @EVAINFOWWN;
    }

    if ( @XPINFO != 0 ) {
        print "\n$INFOSTR XP SAN seemingly connected\n";
        print @XPINFO;
        $ARRFLAG++;
    }

    if ( @ARRAYDSP != 0 ) {
        print "\n$INFOSTR AutoRAID seemingly connected\n";
        print @ARRAYDSP;
        $ARRFLAG++;
    }

    if ( @ARMTOPOLOGY != 0 ) {
        print "\n$INFOSTR Virtual Array (VA) seemingly connected\n";
        print @ARMTOPOLOGY;
        $ARRFLAG++;
    }
    if ( @EMULEX != 0 ) {
        print "\n$INFOSTR Emulex driver seemingly installed\n";
        print @EMULEX;
        $ARRFLAG++;

        if ( ( -s "$LPFCCONF" ) && ( -T "$LPFCCONF" ) ) {
            my @lpfccat = `cat $LPFCCONF`;
        }

        my @emudrv = `ls /dev/lpfc* 2>/dev/null`;
        foreach my $emu ( @emudrv ) {
            my @emucat = `cat $emu`;
            if ( @emucat ) {
                print "\n$INFOSTR Emulex driver $emu\n";
                print @emucat;
            }
        }

        my @lputilver = `lputil version 2>/dev/null | awk NF`;
        if ( @lputilver ) {
            print "\n$INFOSTR Emulex lputil version\n";
            print @lputilver;
        }

        my @lputills = `lputil listhbas 2>/dev/null | awk NF`;
        if ( @lputills ) {
            print "\n$INFOSTR Emulex lputil list HBAs\n";
            print @lputills;
        }
    }

    if ( @ESSCLI != 0 ) {
        print "\n$INFOSTR IBM Enterprise Storage Server (ESS) seemingly connected\n";
        print @ESSCLI;
        $ARRFLAG++;

        my @RSLIST = `rsList2105.sh 2>/dev/null | awk NF`;
        if ( @RSLIST )  {
            print "\n$INFOSTR IBM ESS host disk mapping to 2105 serial number\n";
            print @RSLIST;
        }

        my @ESSCLIV = `esscli list volumeaccess 2>/dev/null | awk NF`;
        if ( @ESSCLIV )  {
            print "\n$INFOSTR IBM ESS volume access status\n";
            print @ESSCLIV;
        }

        my @ESSCLIS = `esscli list volumespace 2>/dev/null | awk NF`;
        if ( @ESSCLIS )  {
            print "\n$INFOSTR IBM ESS volume space status\n";
            print @ESSCLIS;
        }

        my @ESSCLIF = `esscli list featurecode 2>/dev/null | awk NF`;
        if ( @ESSCLIF )  {
            print "\n$INFOSTR IBM ESS feature code status\n";
            print @ESSCLIF;
        }

        my @ESSCLIW = `esscli list webuseraccount 2>/dev/null | awk NF`;
        if ( @ESSCLIW )  {
            print "\n$INFOSTR IBM ESS Web user account status\n";
            print @ESSCLIW;
        }

        my @ESSCLIP = `esscli list perfstats 2>/dev/null | awk NF`;
        if ( @ESSCLIP )  {
            print "\n$INFOSTR IBM ESS performance status\n";
            print @ESSCLIP;
        }

        my @ESSCLIE = `esscli list problem 2>/dev/null | awk NF`;
        if ( @ESSCLIE )  {
            print "\n$INFOSTR IBM ESS problem status\n";
            print @ESSCLIE;
        }
    }

    if ( @EMC != 0 ) {
        print "\n$INFOSTR EMC Symmetrix seemingly connected\n";
        print @EMC;
        $ARRFLAG++;

        if ( ! "@EMCCFG" ) {
            @EMCCFG = `symcfg list -v 2>/dev/null`;
        }

        if ( "@EMCCFG" ) {
            print "\n$INFOSTR EMC Symmetrix devices\n";
            print @EMCCFG;
        }

        if ( ! "@EMCGATE" ) {
            @EMCGATE = `symgate list 2>/dev/null`;
        }

        if ( "@EMCGATE" ) {
            print "\n$INFOSTR EMC Symmetrix gatekeepers\n";
            print @EMCGATE;
        }

        if ( ! "@SYMRDF" ) {
            @SYMRDF = `symrdf list -rdfa 2>/dev/null`;
        }

        if ( "@SYMRDF" ) {
            print "\n$INFOSTR EMC Symmetrix SRDF/async capabilities\n";
            print @SYMRDF;
        }

        if ( ! "@SYMPD" ) {
            @SYMPD = `sympd list 2>/dev/null`;
        }

        if ( "@SYMPD" ) {
            print "\n$INFOSTR EMC Symmetrix devices\n";
            print @SYMPD;
        }

        if ( "@SYMDG" ) {
            @SYMDG = `symdg list 2>/dev/null`;
        }

        if ( "@SYMDG" ) {
            print "\n$INFOSTR EMC Symmetrix symdb capabilities\n";
            print @SYMDG;
        }
    }

    if ( @INTRAID != 0 ) {
        print "\n$INFOSTR Internal RAID adapters seemingly connected\n";
        print @INTRAID;
    }

    if ( @CISS != 0 ) {
        $ARRFLAG++;
        foreach my $cissent (@CISS) {
            chomp($cissent);
            my @SAUTIL = `sautil $cissent 2>/dev/null`;
            if ( @SAUTIL ) {
                print "\n$INFOSTR SmartArray $cissent seemingly connected\n";
                print @SAUTIL;

                my @SAUTILF = `sautil $cissent stat 2>/dev/null`;
                if ( @SAUTILF ) {
                    print "\n$INFOSTR SmartArray $cissent statistics counters\n";
                    print @SAUTILF;
                }
 
                my @SAUTILB = `sautil $cissent get_trace_buf 2>/dev/null`;
                if ( @SAUTILB ) {
                    print "\n$INFOSTR SmartArray $cissent trace buffer status\n";
                    print @SAUTILB;
                }

                my @SAUTILC = `sautil $cissent get_fw_err_log 2>/dev/null`;
                if ( @SAUTILC ) {
                    print "\n$INFOSTR SmartArray $cissent firmware errorlog\n";
                    print @SAUTILC;
                }
            }

            my @saconfig = `saconfig $cissent 2>/dev/null`;
            if ( @saconfig ) {
                print "\n$INFOSTR SmartArray $cissent status\n";
                print @saconfig;
            }
        }
    }

    if ( @ARMDSP != 0 ) {
        print "\n$INFOSTR Virtual Array seemingly connected\n";
        print @ARMDSP;

        if ( @ARMDSP2 ) {
            print "\n";
            print @ARMDSP2;
            print "\n";
        }

        if ( @ARMDIAG ) {
            print "\n";
            print @ARMDIAG;
        }

        foreach my $armline (@ARMDSP) {
            chomp($armline);
            if ( grep( /Alias Name:/, $armline ) ) {
                ( undef, my $ARMALIAS ) = split( /:/, $armline );
                if ("$ARMALIAS") {
                    my @FULLARM = `armdsp -L $ARMALIAS 2>/dev/null`;
                    if ( @FULLARM != 0 ) {
                        print "\n$INFOSTR Virtual Array configuration\n";
                        print @FULLARM;
                    }

                    my @ARMRBLD = `armrbld -p $ARMALIAS 2>/dev/null`;
                    if ( @ARMRBLD != 0 ) {
                        print "\n$INFOSTR Virtual Array build status\n";
                        print @ARMRBLD;
                    }

                    my @ARMFEATURE = `armfeature -r $ARMALIAS 2>/dev/null`;
                    if ( @ARMFEATURE ) {
                        push(@ARMLICENSE, @ARMFEATURE);
                    }
                }
            }
        }
    }

    if ( @SASDINFO != 0 ) {
        print "\n$INFOSTR SAS devices seemingly connected\n";
        print @SASDINFO;
        print @SASDLUN;
    }

    if ( @IRDIAGARR != 0 ) {
        print "\n$INFOSTR RAID 4SI seemingly connected\n";
        print @IRDIAGARR;
        my @IRDIAG = `irdiag -v 2>/dev/null`;
        print "\n$INFOSTR RAID 4SI irdiag status\n";
        print @IRDIAG;
    }

    if ( -s "$RSMHACFG" ) {
        my @RSMCAT = `egrep -v ^# $RSMHACFG 2>/dev/null | awk NF`;
        if ( @RSMCAT ) {
            print
"\n$INFOSTR StorageWorks Replication Solutions Manager Software Host Agent (RSMHA) configuration file $RSMHACFG\n";
            print @RSMCAT;
        }
    }

    if ( $ARRFLAG == 0 ) {
        print
"\n$INFOSTR It seems no SAN connected or their support toolkits not installed correctly\n";
    }

    if ( @FCarray2 != 0 ) {
        foreach my $fa (@FCarray2) {
            chomp($fa);
            #
            # Better method to get rid of leading and trailing empty spaces
            #
            $fa =~ s{\A \s* | \s* \z}{}gxm;

            print "\n$INFOSTR fcmsutil $fa\n";
            my @printfc = `fcmsutil $fa 2>&1`;
            print "@printfc";

            my @fcmsnpiv = `fcmsutil $fa npiv_info 2>/dev/null`;
            if ( "@fcmsnpiv" ) {
                print "\n$INFOSTR fcdutil $fa N-Port ID Virtualization NPIV status\n";
                print "@fcmsnpiv";
            }

            print "\n$INFOSTR fcmsutil $fa get remote all\n";
            my @printfcall = `fcmsutil $fa get remote all 2>&1`;
            print "@printfcall";

            my @fcdutil = `fcdutil $fa stat 2>/dev/null`;
            if ( "@fcdutil" ) {
                print "\n$INFOSTR fcdutil $fa stat\n";
                print "@fcdutil";
            }
        }
    }

    if ( "$autopath" == 1 ) {
        print "\n$INFOSTR AutoPath seemingly installed\n";
        my @autop = `autopath display all | awk NF`;
        print @autop;
    }

    if ( "$EMSP_FLAG" > 0 ) {
        print "\n$INFOSTR EMC PowerPath seemingly installed\n";
        my @powermt = `powermt display dev=all`;
        print @powermt;
        my @powermtc = `echo q | powermt check`;
        print "\n";
        print @powermtc;
    }

    my @symdev = `symdev list 2>/dev/null`;
    if ( "@symdev" ) {
        print "\n$INFOSTR EMC TimeFinder Business Continuance Volumes (BCV)\n";
        print @symdev;
    }

    my @symbcv = `symbcv list 2>/dev/null`;
    if ( @symbcv ) {
        print "\n$INFOSTR EMC TimeFinder pairing\n";
        print @symbcv;
    }

    datecheck();
    print_trailer("*** END CHECKING SAN AND NAS CONFIGURATION $datestring ***");
}

# Subroutine to check VxVM
#
sub VXVM_CHECK {
    standck();

    datecheck();
    print_header("*** BEGIN CHECKING /STAND/ROOTCONF $datestring ***");
    standrt();
    datecheck();
    print_header("*** END CHECKING /STAND/ROOTCONF $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING VXVM STATUS $datestring ***");

    standbootck();

    my @vxiod = `vxiod 2>/dev/null`;
    if ( @vxiod ) {
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
        print "\n$WARNSTR $VXCONF is zero-length or does not exist\n";
        push(@CHECKARR, "\n$WARNSTR $VXCONF is zero-length or does not exist\n");
    }

    if ( open( VXD, "vxdisk -o alldgs list |" ) ) {
        print "\n$INFOSTR Vxdisk status\n";
        while (<VXD>) {
            next if ( grep( /^$/, $_ ) );
            print $_;

            if ( grep( /offline|fail|error|invalid/i, $_ ) ) {
                push(@VXERRARR, "$_ ");
            }

            if ( grep( /online invalid/i, $_ ) ) {
                push(@NOTVXARR, "$_ ");
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

        if ( @VXERRARR ) {
            print "\n$INFOSTR Non-VxVM (uninitialised) physical volumes\n";
            print @VXERRARR;
        }
    }
    else {
        print "\n$WARNSTR Cannot run vxdisk\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run vxdisk\n");
        $warnings++;
    }

    foreach my $vxdev (@VXALLDISK) {
        chomp($vxdev);
        my $vxfullpath = "/dev/rdsk/$vxdev";
        if ( grep( /disk/i, $vxdev ) ) {
            $vxfullpath = "/dev/rdisk/$vxdev";
        }

        if ( -c "$vxfullpath" ) {
            my @vxdmpinq = `vxdmpinq $vxfullpath 2>/dev/null | awk NF`;
            if ( @vxdmpinq ) {
                print "\n$INFOSTR Vxdumpinq for disk $vxdev\n";
                print @vxdmpinq;
            }

            my @vxdmpadm = `vxdmpadm getsubpaths dmpnodename=$vxdev 2>/dev/null | awk NF`;
            if ( @vxdmpadm ) {
                print "\n$INFOSTR Vxdmpadm getsubpaths for disk $vxdev\n";
                print @vxdmpadm;
            }

            my @privutilscan = `vxprivutil scan $vxfullpath 2>/dev/null | awk NF`;
            if ( @privutilscan ) {
                print "\n$INFOSTR Vxprivutil scan for disk $vxdev\n";
                print @privutilscan;
            }

            my @privutildump = `vxprivutil dumpconfig $vxfullpath 2>/dev/null |awk NF`;
            if ( @privutildump ) {
                print "\n$INFOSTR Vxprivutil dumpconfig for disk $vxdev\n";
                print @privutildump;
            }

            my @PVcheckV3c = `diskowner -FA $vxfullpath 2>&1 | egrep -v "not found"`;
            if ( @PVcheckV3c != 0 ) {
                print "\n$INFOSTR $vxdev status as per command diskowner\n";
                print "@PVcheckV3c\n";
            }
        }
    }

    my @vxcmdlog = `vxcmdlog -l 2>/dev/null`;
    if ( @vxcmdlog ) {
        print "\n$INFOSTR Current settings for command logging\n";
        print @vxcmdlog;
    }

    my @vxtranslog = `vxtranslog -l 2>/dev/null`;
    if ( @vxtranslog ) {
        print "\n$INFOSTR Current settings for transaction logging\n";
        print @vxtranslog;
    }

    my @vxdiskpath = `vxdisk path 2>/dev/null`;
    if ( @vxdiskpath ) {
        print "\n$INFOSTR Vxdisk path status\n";
        print @vxdiskpath;
    }

    my @vxdiske = `vxdisk -e list 2>/dev/null`;
    if ( @vxdiske ) {
        print "\n$INFOSTR Vxdisk status with WWNs\n";
        print @vxdiske;
    }

    my @vxdmpadm1 = `vxdmpadm listenclosure all 2>/dev/null`;
    if ( @vxdmpadm1 ) {
        print "\n$INFOSTR Disk enclosure status\n";
        print @vxdmpadm1;
    }

    my @vxdmpadm2 = `vxdmpadm listctlr all 2>/dev/null`;
    if ( @vxdmpadm2 ) {
        print "\n$INFOSTR Disk controller status\n";
        print @vxdmpadm2;
    }

    my @vxdmpadm3 = `vxdmpadm listapm all 2>/dev/null`;
    if ( @vxdmpadm3 ) {
        print "\n$INFOSTR Array Policy Modules (APM) status\n";
        print @vxdmpadm3;
    }

    my @vxassist = `vxassist help showattrs 2>/dev/null`;
    if ( @vxassist ) {
        print "\n$INFOSTR Default attributes in $VXDEFATTRS\n";
        print @vxassist;
    }

    if ( -f "$VXDBFILE" ) {
        print "\n$INFOSTR File $VXDBFILE exists (VxVM initialized)\n";
    }

    my @vxddladm0 = `vxddladm listsupport all 2>/dev/null`;
    if ( @vxddladm0 ) {
        print "\n$INFOSTR Supported array status\n";
        print @vxddladm0;
    }

    my @vxddladm = `vxddladm listjbod 2>/dev/null`;
    if ( @vxddladm ) {
        print "\n$INFOSTR Supported JBOD status\n";
        print @vxddladm;
    }

    if ( open( VXDG, "vxdg list |" ) ) {
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

        if ( @VXALLDG ) {
            foreach my $ndg (@VXALLDG) {
                my @NDy = `dgcfgrestore -n $ndg -l 2>/dev/null`;
                if ( @NDy ) {
                    print "\n$INFOSTR Disk group $ndg dgcfgrestore config\n";
                    print "@NDy";
                }
                else {
                    print "\n$WARNSTR Disk group $ndg missing dgcfgrestore config\n";
                }

                my @vxsplit = `vxsplitlines -g $ndg 2>/dev/null`;
                if ( @vxsplit ) {
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
                            push(@VXINFOARR,
"\n$ERRSTR VxFS volume not started correctly\n");
                            push(@VXINFOARR, "$_");
                            push(@CHECKARR,
"\n$ERRSTR VxFS volume not started correctly\n");
                            push(@CHECKARR, "$_");
                            $warnings++;
                        }
                        print $_;
                    }
                    close(VXI);
                }

                if ( @VXINFOARR ) {
                    print @VXINFOARR;
                }

                my @vxstats = `vxstat -i $DELAY -c $ITERATIONS -d 2>/dev/null`;
                if ( @vxstats ) {
                    print "\n$INFOSTR VxVM disk statistics\n";
                    print "@vxstats";
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
    if ( @vxdgf ) {
        print "\n$INFOSTR Free disk status\n";
        print @vxdgf;
    }

    my @vxdgs = `vxdg spare 2>/dev/null`;
    if ( @vxdgs ) {
        print "\n$INFOSTR Spare disk status\n";
        print @vxdgs;
    }

    my @vxsehost = `vxse_host 2>/dev/null`;
    if ( @vxsehost ) {
        print "\n$INFOSTR VxVM hostname check\n";
        print @vxsehost;
    }

    my @vxseraid5 = `vxse_raid5 2>/dev/null`;
    if ( @vxseraid5 ) {
        print "\n$INFOSTR VxVM RAID5 healthcheck\n";
        print @vxseraid5;
    }

    my @vxsestripes1 = `vxse_stripes1 2>/dev/null`;
    if ( @vxsestripes1 ) {
        print "\n$INFOSTR VxVM Striped volumes first healthcheck\n";
        print @vxsestripes1;
    }

    my @vxsestripes2 = `vxse_stripes2 2>/dev/null`;
    if ( @vxsestripes2 ) {
        print "\n$INFOSTR VxVM Striped volumes second healthcheck\n";
        print @vxsestripes2;
    }

    my @vxsevolplex = `vxse_volplex 2>/dev/null`;
    if ( @vxsevolplex ) {
        print "\n$INFOSTR VxVM Volumes and plexes healthcheck\n";
        print @vxsevolplex;
    }

    my @vxsedcfail = `vxse_dc_failures 2>/dev/null`;
    if ( @vxsedcfail ) {
        print "\n$INFOSTR VxVM Controller and disk healthcheck\n";
        print @vxsedcfail;
    }

    my @vxserootmir = `vxse_rootmir check 2>/dev/null`;
    if ( @vxserootmir ) {
        print "\n$INFOSTR VxVM Root mirror configuration healthcheck\n";
        print @vxserootmir;
    }

    my @vxsespare = `vxse_spares 2>/dev/null`;
    if ( @vxsespare ) {
        print "\n$INFOSTR VxVM Spare disk configuration healthcheck\n";
        print @vxsespare;
    }

    my @vxseredundancy = `vxse_redundancy 2>/dev/null`;
    if ( @vxseredundancy ) {
        print "\n$INFOSTR VxVM Redundancy configuration healthcheck\n";
        print @vxseredundancy;
    }

    my @vxsvcm = `vxsvc -m 2>&1`;
    if ( @vxsvcm ) {
        print "\n$INFOSTR VxVM VEA server status\n";
        print @vxsvcm;
    }

    my @vxparms = `vxparms 2>/dev/null`;
    if ( @vxparms ) {
        print "\n$INFOSTR Vxparms status\n";
        print @vxparms;
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

        if ( @CHECKVXVM ) {
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
    print_trailer("*** END CHECKING VXVM STATUS $datestring ***");
}

# Subroutine to check latest tombstone
#
sub tombstone {
    datecheck();
    print_header("*** BEGIN CHECKING LATEST TOMBSTONE STATUS $datestring ***");

    if ( -s "$tvs" ) {

        my @tsprint = `dos2ux $tvs |awk NF`;
        print @tsprint;
    }
    else {
        print "\n$INFOSTR File $tvs missing or is zero-length\n";
    }

    datecheck();
    print_trailer("*** END CHECKING LATEST TOMBSTONE STATUS $datestring ***");
}

# Subroutine to check possible crash leftovers
#
sub samchk {
    if ( "$Minor$Patch" <= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING FOR POSSIBLE SYSTEM ADMINISTRATION MANAGER CRASH $datestring ***");

        if ( -f "$samcrash" ) {
            print "$WARNSTR File $samcrash exists. Probable SAM crash\n";
            push(@CHECKARR, "\n$WARNSTR File $samcrash exists. Probable SAM crash\n");
            $warnings++;
        }
        elsif ( -f "$samcrash2" ) {
            print "$WARNSTR File $samcrash2 exists. Probable SAM crash\n";
            push(@CHECKARR, "\n$WARNSTR File $samcrash2 exists. Probable SAM crash\n");
            $warnings++;
        }
        else {
            print "$PASSSTR Files $samcrash and $samcrash2 do not exist\n";
        }

        datecheck();
        print_trailer("*** END CHECKING FOR POSSIBLE SYSTEM ADMINISTRATION MANAGER CRASH $datestring ***");
    }
}

# Subroutine to check SIR
#
sub SIRchk {
    datecheck();
    print_header("*** BEGIN CHECKING SYSTEM INFORMATION REPORTER (SIR) $datestring ***");

    if ( -s "$sircfg" ) {
        if ( open( SSIR, "awk '! /^#/ && ! /awk/ {print}' $sircfg |" ) ) {
            print "$INFOSTR SIR configuration:\n";
            while (<SSIR>) {
                next if ( grep( /^$/, $_ ) );
                if ( grep( /HOSTNAME=/, $_ ) ) {
                    if ( grep( /$Hostname/, $_ ) ) {
                        $goodsir++;
                    }
                }

                if ( grep( /SERIALNO=/, $_ ) ) {
                    if ( grep( /$serial/, $_ ) ) {
                        $goodserial++;
                    }
                }

                print $_;
            }
            close(SSIR);
        }
        else {
            print "$WARNSTR Cannot open $sircfg\n";
        }

        if ( $goodsir > 0 ) {
            print "\n$PASSSTR Hostname $Hostname listed in $sircfg\n";
        }
        else {
            print "\n$WARNSTR Hostname $Hostname NOT listed in $sircfg\n";
            $warnings++;
        }

        if ( $goodserial > 0 ) {
            print "$PASSSTR Serial number $serial listed in $sircfg\n";
        }

        if (open( SIRCRON,
            "crontab -l | awk '! /^#/ && /sir/ && ! /awk/ {print}'|" )) {
            while (<SIRCRON>) {
                foreach my $sy (@SIRjobs) {
                    if ( grep( /$sy/, $_ ) ) {
                        push( @goodsir, $sy );
                    }
                }
            }
            close(SIRCRON);
        }
        else {
            print "\n$WARNSTR Cannot open crontab\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open crontab\n");
        }

        foreach my $fy (@SIRjobs) {
            if ( grep( /$fy/, @goodsir ) ) {
                print "\n$INFOSTR SIR cron task $fy running\n";
            }
            else {
                print "\n$INFOSTR SIR cron task $fy not running\n";
            }
        }
    }
    else {
        print "$INFOSTR SIR configuration $sircfg is zero-length or missing\n";
        print "$NOTESTR SIR possibly not configured or used on this server\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SYSTEM INFORMATION REPORTER (SIR) $datestring ***");
}

# Subroutine to check Ignite setup
#
sub Ignitechk {
    if ( @tapes ) {
        datecheck();
        print_header("*** BEGIN CHECKING TAPE DRIVE CONTROLLER STATUS $datestring ***");

        foreach $element ( sort @tapecontrollers, sort @bootara ) { $tpc{$element}++ }
        foreach $element (keys %tpc) {
            push @{ $tpc{$element} > 1 ? \@tpint : \@tpdiff }, $element;
        }

        if ( @tpdiff ) {
            print
"$PASSSTR Tape drives and boot disks on different controllers\n";
            print "Boot disks are on @bootara\n";
            print "Tape drives are on @tapecontrollers\n";
        }
        else {
            print "$WARNSTR Tape drives on same controllers as boot disks\n";
            print "Boot disks are on @bootara\n";
            print "Tape drives are on @tapecontrollers\n";
            push(@CHECKARR,
"\n$WARNSTR Tape drives on same controllers as boot disks\n");
            push(@CHECKARR, "Boot disks are on @bootara\n");
            push(@CHECKARR, "Tape drives are on @tapecontrollers\n");
        }

        datecheck();
        print_trailer("*** END CHECKING TAPE DRIVE CONTROLLER STATUS $datestring ***");
    }

    if ( $IGNITE_FLAG > 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING IGNITE BOOT SERVICES $datestring ***");

        DHCPservchk();

        if ( ( -s "$confrec" ) && ( -T "$confrec" ) ) {
            if ( open( ZPAD, "egrep -v ^# $confrec |" ) ) {
                print "\n$INFOSTR Default Ignite save_config file $confrec\n";
                while (<ZPAD>) {
                    next if grep( /^$/, $_ );
                    print $_;
                }
                close(ZPAD);
            }
            else {
                print
"\n$INFOSTR Cannot open default Ignite save_config file $confrec\n";
            }
        }

        if ( $dsknohwcnt == 0 ) {
            eval {
                # On certain occasions (for example, when disks are in NO_HW
                # state), save_config hangs, so we need to
                # manage how long it runs
                #
                local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
                alarm 1800;

                my @save_config = `save_config -f - 2>/dev/null`;
                if ( @save_config != 0 ) {
                    print "\n$INFOSTR Current Ignite save_config status\n";
                    print @save_config;
                }

                alarm 0;
            };

            if ($@) {
                warn "\n$WARNSTR Command \"save_config\" timed out\n";
            }
        }

        my @instladm = `instl_adm -d 2>/dev/null | egrep -v ^#`;

        if ( @instladm != 0 ) {
            print
              "\n$INFOSTR Ignite network install server default parameters\n";
            print @instladm;

            my @zk = ();
            if ( "$Hardware" eq "ia64" ) {
                @zk = `egrep -v ^# $BOOTPTAB 2>/dev/null | awk NF`;
            }
            else {
                @zk = `egrep -v ^# $instlcfg 2>/dev/null | awk NF`;
            }

            if ( @zk != 0 ) {
                print "\n$INFOSTR Ignite clients in $instlcfg\n";
                print @zk;
            }
            else {
                print "\n$INFOSTR File $instlcfg not in use\n";
            }

            my @ignitecfgl = `ignite config list -m xml 2>/dev/null`;
            if ( @ignitecfgl ) {
                print "\n$INFOSTR Ignite client config\n";
                print @ignitecfgl;
            }

            my @igniteclls = `ignite client list -m xml 2>/dev/null`;
            if ( @igniteclls ) {
                print "\n$INFOSTR Ignite client listing\n";
                print @igniteclls;
            }
        }
        else {
            print
"\n$INFOSTR Server not set for client Ignite network install\n";
        }

        datecheck();
        print_trailer("*** END CHECKING IGNITE BOOT SERVICES $datestring ***");

        datecheck();
        print_header("*** BEGIN CHECKING IGNITE PUSH METHOD VIA BOOTSYS $datestring ***");

        if ( -f "$BOOTSYS_BLOCK" ) {
            if ( -s "$BOOTSYS_BLOCK" ) {
                print "$INFOSTR File $BOOTSYS_BLOCK exists and non-empty\n";
                my $BSCK = `awk 'NR==1 && /confirm/ {print}' $BOOTSYS_BLOCK 2>/dev/null`;
                if ( "$BSCK" ) {
                print
"$INFOSTR $BOOTSYS_BLOCK contains string \"confirm\" on the first line\n";
                print
"$PASSSTR User running Ignite push from remote server via bootsys will be prompted for confirmation before proceeding\n";
                }
                else {
                    print "$PASSSTR Ignite push from remote server via bootsys are blocked\n";
                    my @BSCK = `cat $BOOTSYS_BLOCK 2>/dev/null`;
                    print "@BSCK";
                }
            }
        }
        else {
            print "$INFOSTR File $BOOTSYS_BLOCK does not exists\n";
            print
"$WARNSTR Ignite push from remote server via bootsys is not blocked (might be a security risk)\n";
            push(@CHECKARR,
"\n$WARNSTR Ignite push from remote server via bootsys is not blocked (might be a security risk)\n");
            $warnings++;
        }

        datecheck();
        print_header("*** END CHECKING IGNITE PUSH METHOD VIA BOOTSYS $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING NATIVE O/S BACKUPS $datestring ***");

    if ( ( -s "$dumpdates" ) && ( -T "$dumpdates" ) ) {
        my @dumpdata = `egrep -v ^# $dumpdates | awk NF`;
        if ( @dumpdata ) {
            print "$INFOSTR Backups as recorded in $dumpdates\n";
            print @dumpdata;
        }
    }
    else {
        print "$INFOSTR No backups are seemingly recorded in $dumpdates\n";
    }

    print "\n";

    if ( "$vxdumpdates" ne "$dumpdates" ) {
        if ( ( -s "$vxdumpdates" ) && ( -T "$vxdumpdates" ) ) {
            my @vxdumpdata = `egrep -v ^# $vxdumpdates | awk NF`;
            if ( @vxdumpdata ) {
                print "$INFOSTR Backups as recorded in $vxdumpdates\n";
                print @vxdumpdata;
            }
        }
        else {
            print "$INFOSTR No backups are seemingly recorded in $vxdumpdates\n";
        }
    }

    if ( "$Minor$Patch" <= 1123 ) {
        if ( ( -s "$fbackupdates" ) && ( -T "$fbackupdates" ) ) {
            my @fbckdata = `egrep -v ^# $fbackupdates | awk NF`;
            if ( @fbckdata ) {
                print "\n$INFOSTR Fbackups as recorded in $fbackupdates\n";
                print @fbckdata;
            }
        }
        else {
            print "\n$INFOSTR No fbackups are seemingly recorded in $fbackupdates\n";
        }

        print
"\n$NOTESTR If SAM was used to schedule fbackup, you should have a
look at SAM's logfiles:

/var/sam/log/
/var/sam/log/bg_log
/var/sam/log/samlog\n";
    }

    datecheck();
    print_trailer("*** END CHECKING NATIVE O/S BACKUPS $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING IGNITE BACKUPS $datestring ***");

    if ( $IGNITE_FLAG == 0 ) {
        print
"$ERRSTR Ignite bundle missing. Disaster Recovery difficult!\n";
        push(@CHECKARR,
"\n$ERRSTR Ignite bundle missing. Disaster Recovery difficult!\n");
        if (@tapes) {
            print "\n$INFOSTR Tape drives detected\n";
            print @tapes;
        }
        $warnings++;
    }
    else {
        if ( ! "$Igniteversion" ) { 
            if ( open( IG, "swlist -l product Ignite-UX 2>&1 | awk NF |" ) ) {
                while (<IG>) {
                    next if ( grep( /^$/, $_ ) );
                    next if ( grep( /#/,  $_ ) );
                    #
                    # Get rid of leading and trailing empty spaces
                    #
                    $_ =~ s{\A \s* | \s* \z}{}gxm;
                    chomp($_);
                    if ( grep( /ERROR/, $_ ) ) {
                        $Igniteversion = q{};
                    }

                    if ( grep( /Ignite-UX/, $_ ) ) {
                        ( undef, $Igniteversion, undef ) = split( /\s+/, $_ );
                    }
                }
                close(IG);
            }
        }

        if ( "$Igniteversion" ) {
            print "$INFOSTR Ignite bundle $Igniteversion version\n";
            print "$INFOSTR Keep version information together with ";
            print "Disaster Recovery plans and media\n";

            ( my $Iglet, my $Igmaj, my $Igmin, undef ) =
              split( /\./, $Igniteversion );

            if ( grep( /^A\./, "$Igniteversion" ) ) {
                print "$ERRSTR Ignite bundle too old (EOS)\n";
                push(@CHECKARR, "\n$ERRSTR Ignite bundle too old (EOS)\n");
                $warnings++;
            }
            elsif ( grep( /^B\./, "$Igniteversion" ) ) {
                if ( grep( /1100/, "$Minor$Patch" ) ) {
                    print
                      "$INFOSTR Ignite bundle final for this O/S release\n";
                }
                else {
                    print "$ERRSTR Ignite bundle getting old\n";
                    push(@CHECKARR, "\n$ERRSTR Ignite bundle getting old\n");
                    $warnings++;
                }
            }
        }
        else {
            my @ignver2 = `ignite version -m xml 2>/dev/null`;
            if ( @ignver2 ) {
                print "$INFOSTR Keep Ignite version information together with ";
                print "Disaster Recovery plans and media\n";
                print @ignver2;
            }
        }

        if ( ( -s "$IGNINDEX" ) && ( -T "$IGNINDEX" ) ) {
            my @catindex = `egrep -v ^# $IGNINDEX | awk NF`;
            if ( @catindex ) {
                print "\n$INFOSTR Ignite-UX default index file $IGNINDEX\n";
                print @catindex;
            }
        }

        my @mindex = `manage_index -l 2>/dev/null`;
        if ( @mindex ) {
            print "\n$INFOSTR Ignite-UX INDEX cfg clauses\n";
            print @mindex;

            my @mindexdef = `manage_index -l -o 2>&1`;
            if ( @mindexdef ) {
                print "\n$INFOSTR Ignite-UX INDEX cfg default clause\n";
                print @mindexdef;
            }
        }

        if ( -s "$preview" ) {
            print "\n$INFOSTR Latest Ignite preview\n";
            my @pghost = `awk '! /awk|^$|^#/ {print}' $preview`;
            print @pghost;
            @lastpv = grep( /last_preview/, @pghost );

            if ( @lastpv != 0 ) {
                print "\n$INFOSTR Ignite make_tape_recovery backups last run ";
                print "(@lastpv)\n";
            }
        }
        else {
            print "\n$WARNSTR Ignite $preview missing\n";
            push(@CHECKARR, "\n$WARNSTR Ignite $preview missing\n");
            $warnings++;
        }

        if ( @tapes ) {
            print "\n$INFOSTR Tape drives detected. Make_tape_recovery ";
            print "possible\n";
            print @tapes;

            if ("$Igniteversion") {
                my $ckig =
`check_tape_recovery 2>/dev/null | awk '/^Summary:/ && ! /awk/ {print}'`;
                if ("$ckig") {
                    print "\n$INFOSTR Summary of changes since last ";
                    print "Ignite make_tape_recovery backups\n";
                    print $ckig;
                }
                else {
                    print
"\n$ERRSTR Ignite make_tape_recovery backups seemingly ";
                    print "not running or check_tape_recovery incorrect\n";
                    push(@CHECKARR,
"\n$ERRSTR Ignite make_tape_recovery backups seemingly ");
                    push(@CHECKARR, "not running or check_tape_recovery incorrect\n");
                    $warnings++;
                }
            }
        }
        else {
            print "\n$INFOSTR No local tape drives. Only Ignite ";
            print "make_net_recovery possible\n";
        }

        if ( grep(/PA-RISC/i, $ARCH) ) {
            print
"\n$INFOSTR Ensure that Core LAN is configured for PA-RISC servers\n";
            if (@LANCOREarray) {
                print " @LANCOREarray";
            }
            print "(virtual partitions do not necessarily have it)\n";
            print "(otherwise, remote Ignite recovery will probably fail)\n";
        }

        my @listexp = `list_expander -d -v 2>/dev/null`;
        if ( @listexp ) {
            print
"\n$INFOSTR Ignite-UX list of the essential recovery image files and directories\n";
            print @listexp;
        }

        if ( ( -s "$confinfo" ) && ( -T "$confinfo" ) ) {
            if ( open( CPAD, "egrep -v ^# $confinfo |" ) ) {
                print "\n$INFOSTR Ignite file $confinfo\n";
                while (<CPAD>) {
                    next if grep( /^$/, $_ );
                    print $_;
                }
                close(CPAD);
            }
            else {
                print "\n$WARNSTR Cannot open Ignite file $confinfo\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open Ignite file $confinfo\n");
                $warnings++;
            }
        }
        else {
            print "\n$WARNSTR Ignite file $confinfo missing\n";
            push(@CHECKARR, "\n$WARNSTR Ignite file $confinfo missing\n");
            $warnings++;
        }

        if ( -s "$hostinfo" ) {
            print "\n$INFOSTR Ignite file $hostinfo\n";
            my @ighost = `awk '! /awk|^$|^#/ {print}' $hostinfo`;
            print @ighost;
        }
        else {
            print "\n$WARNSTR Ignite file $hostinfo missing\n";
            push(@CHECKARR, "\n$WARNSTR Ignite file $hostinfo missing\n");
            $warnings++;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING IGNITE BACKUPS $datestring ***");
}

# Subroutine to check DHCP server 
#
sub DHCPservchk {
    my @dhcptab    = `egrep -v ^# $DHCPTAB 2>/dev/null | awk NF`;
    my @dhcpv6tab  = `egrep -v ^# $DHCPV6TAB 2>/dev/null | awk NF`;
    my @iscdhcptab = `egrep -v ^# $ISCDHCPTAB 2>/dev/null | awk NF`;
    my @bootptab   = `egrep -v ^# $BOOTPTAB 2>/dev/null | awk NF`;

    if ( @dhcptab != 0 ) {
        print "$INFOSTR DHCP $DHCPTAB\n";
        print @dhcptab;

        my @dhcpdeny   = `egrep -v ^# $DHCPDENY 2>/dev/null | awk NF`;

        if ( @dhcpdeny != 0 ) {
            print "\n$INFOSTR DHCP $DHCPDENY\n";
            print @dhcpdeny;
        }
        else {
            print "$INFOSTR DHCP $DHCPDENY seemingly not configured\n";
        }

        my @dhcptools  = `dhcptools -v 2>/dev/null`;
        if ( @dhcptools != 0 ) {
            print "\n$INFOSTR DHCP config verification\n";
            print @dhcptools;
        }
    }
    else {
        print "$INFOSTR DHCP $DHCPTAB seemingly not configured\n";
    }

    if ( @dhcpv6tab != 0 ) {
        print "\n$INFOSTR DHCPv6 $DHCPV6TAB\n";
        print @dhcpv6tab;
    }
    else {
        print "\n$INFOSTR DHCPv6 $DHCPV6TAB seemingly not configured\n";
    }

    if ( @iscdhcptab != 0 ) {
        print "\n$INFOSTR ISC DHCP $ISCDHCPTAB\n";
        print @iscdhcptab;
    }
    else {
        print "\n$INFOSTR ISC DHCP $ISCDHCPTAB seemingly not configured\n";
    }

    if ( @bootptab != 0 ) {
        print "\n$INFOSTR BOOTP $BOOTPTAB\n";
        print @bootptab;
    }
    else {
        print "\n$INFOSTR BOOTP $BOOTPTAB seemingly not configured\n";
    }
}

# Subroutine to check X25 
#
sub X25check {
    datecheck();
    print_header("*** BEGIN CHECKING X25 $datestring ***");

    my @X25STATC = `x25stat -c 2>/dev/null`;
    my @X25STAT  = `x25stat -a -p 2>/dev/null`;
    my $X29HOSTS = "/etc/x25/x29hosts";
    my $X3CONF   = "/etc/x25/x2config";
    my @X25ARRAY = ( $X29HOSTS, $X3CONF, );

    if ( @X25STATC ) {
        print "$INFOSTR X25 configuration\n";
        print @X25STATC;

        if ( @X25STAT ) {
            print "\n$INFOSTR X25 statistics\n";
            print @X25STAT;
        }

        foreach my $xcf (@X25ARRAY) {
            if ( -s "$xcf" ) {
                if ( open( PAD, "egrep -v ^# $xcf |" ) ) {
                    print "\n$INFOSTR PAD support configuration file $xcf\n";
                    while (<PAD>) {
                        next if grep( /^$/, $_ );
                        print $_;
                    }
                    close(PAD);
                }
            }
            else {
                print "\n$INFOSTR Cannot open $xcf\n";
            }
        }
    }
    else {
        print "$INFOSTR X25 seemingly not in use\n";
    }

    datecheck();
    print_trailer("*** END CHECKING X25 $datestring ***");
}

# Subroutine to check OSI NSAP 
#
sub osicheck {
    datecheck();
    print_header("*** BEGIN CHECKING OSI SETUP $datestring ***");

    my @otsstat = `otsstat 2>/dev/null`;
    if ( @otsstat ) {
        print "$INFOSTR OSI seemingly installed\n";
        print @otsstat;
        print "\n";

        my @otsnsap = `otsshownsaps 2>/dev/null`;
        if ( @otsnsap ) {
            print @otsnsap;
        }
    }
    else {
        print "$INFOSTR OSI seemingly not installed or configured\n";
    }

    datecheck();
    print_trailer("*** END CHECKING OSI SETUP $datestring ***");
}

# Subroutine to check LAN
#
sub lancheck {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK SETUP $datestring ***");

    if ( @LANarray != 0 ) {
        print "$INFOSTR LAN devices configured\n";
        print @LANarray;
    }

    my @LANinfo = `laninfo 2>/dev/null`;
    if ( @LANinfo ) {
        print "\n$INFOSTR Laninfo\n";
        print @LANinfo;
    }

    my @RDC = `rdc dump all 2>/dev/null`;
    if ( @RDC ) {
        print "\n$INFOSTR Routing Administration Manager (RDC) status\n";
        print @RDC;
    }

    if ( open( LAN, "netstat -rnv |" ) ) {
        print "\n$INFOSTR Routing table\n";
        while (<LAN>) {
            # Better method to get rid of leading and trailing empty spaces
            #
            $_ =~ s/^\s+//g;
            if ( grep( /default/i, $_ ) ) {
                print "\n$PASSSTR Default static route defined\n";
                ( undef, $gwip, undef, undef, undef, undef ) = split( /\s+/, $_ );
                chomp($gwip);
                push( @GWlist, $gwip );
                $lanok++;
            }
            print $_;
        }
        close(LAN);
    }
    else {
        print "\n$WARNSTR Cannot run netstat\n";
        push(@CHECKARR, "\n$WARNSTR Cannot run netstat\n");
        $warnings++;
    }

    my @gdcrun = `gdc running 2>&1`;
    if ( ! ( grep( /not running/, "@gdcrun" ) ) ) {
        $GATED_FLAG++;
    }

    if ( $GATED_FLAG > 0 ) {
        print "\n$INFOSTR Gateway Routing Daemon (gated) running\n";
        print @gdcrun;

        if ( "$gwip" ) {
            my @ripquery = `ripquery $gwip 2>/dev/null`;
            if ( @ripquery ) {
                print "\n$INFOSTR Gateway Routing Daemon RIP query\n";
                print @ripquery;
            }
        }

        my @gatedarr = `egrep -v ^# $GATED 2>/dev/null |awk NF`;

        if ( @gatedarr ) {
            print "\n$INFOSTR Configuration file $GATED\n";
            print @gatedarr;
        }

        my @gdcchk = `gdc checkconf 2>&1`;
        if ( @gdcchk ) {
            print "\n$INFOSTR Gateway Routing Daemon configuration file ($GATED) check\n";
            print @gdcchk;
        }

        my @gdcchkn = `gdc checknew 2>&1`;
        if ( @gdcchkn ) {
            print "\n$INFOSTR Gateway Routing Daemon new configuration file ($GATEDNEW) check\n";
            print @gdcchkn;
        }
    }
    else {
        print "\n$INFOSTR Gateway Routing Daemon (gated) not running\n";
    }

    if ( -c "$IPv6dev" ) {
        print "\n$INFOSTR $IPv6dev is a character device file\n";

        if ( -s "$NETCONFV6" ) {
            if ( open( NZ6, "egrep -v ^# $NETCONFV6 |" ) ) {
                print "\n$INFOSTR Customised network setup in $NETCONFV6\n";
                while (<NZ6>) {
                    next if grep( /^$/, $_ );
                    print $_;
                }
                close(NZ6);
            }
            else {
                print "\n$WARNSTR Cannot open $NETCONFV6\n";
                push(@CHECKARR, "\n$WARNSTR Cannot open $NETCONFV6\n");
            }
        }
        else {
            print "\n$INFOSTR $NETCONFV6 is zero-length\n";
        }

        if ( -s "$RTRADVD" ) {
            if ( open( RNZ, "cat $RTRADVD |" ) ) {
                print "\n$INFOSTR Customised Router Advertiser Daemon setup in $RTRADVD\n";
                while (<RNZ>) {
                    next if grep( /^$/, $_ );
                    print $_;
                }
                close(RNZ);
            }
        }
        else {
            print "\n$INFOSTR Router Advertiser Daemon $RTRADVD is zero-length\n";
        }

        my @ndp = `ndp -a -n 2>/dev/null`;
        if ( @ndp != 0 ) {
            print "\n$INFOSTR IPv6 Neigbour Discovery cache status\n";
            print @ndp;
        }

        @rtradvdC = `rtradvd -C 2>/dev/null`;
        if ( @rtradvdC ) {
            print "\n$INFOSTR Rtradvd configuration check\n";
            print @rtradvdC;
        }
    }
    else {
        print
"\n$INFOSTR $IPv6dev is not a character device or does not exist\n";
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
"\n$WARNSTR Check hostname resolution for server \"$host\"\n";
                push(@CHECKARR,
"\n$WARNSTR Check hostname resolution for server \"$host\"\n");
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

                # Check "Dead Gateway Detection"
                my $ddg = `ndd /dev/ip ip_ire_gw_probe`;
                chomp($ddg);
                if ( "$ddg" == 1 ) {
                    print
                      "$WARNSTR /dev/ip setting ip_ire_gw_probe is $ddg ";
                    print "(should be 0)\n";
                    push(@CHECKARR,
                      "\n$WARNSTR /dev/ip setting ip_ire_gw_probe is $ddg ");
                    push(@CHECKARR, "(should be 0)\n");
                    $warnings++;
                }
                else {
                    print
                      "$PASSSTR /dev/ip setting ip_ire_gw_probe is $ddg ";
                    print
                      "(important when ICMP blocked to default gateway)\n";
                }
            }
        }
    }

    if ( -s "$NDDCONF" ) {
        if ( open( NC, "egrep -v ^# $NDDCONF | awk NF |" ) ) {
            while (<NC>) {
                next if grep( /^$/, $_ );
                push( @NDset, $_ );
            }
            close(NC);
            if ( @NDset != 0 ) {
                print
                  "\n$INFOSTR Customised network parameters in $NDDCONF\n";
                print @NDset;
            }
            else {
                print
"\n$INFOSTR No customised network parameters in $NDDCONF\n";
            }
        }
        else {
            print "\n$WARNSTR Cannot open $NDDCONF\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $NDDCONF\n");
        }
    }
    else {
        print "$INFOSTR $NDDCONF is zero-length\n";
    }

    if ( -s "$NETCONF" ) {
        if ( open( NZ, "egrep -v ^# $NETCONF |" ) ) {
            print "\n$INFOSTR Customised network setup in $NETCONF\n";
            while (<NZ>) {
                next if grep( /^$/, $_ );
                print $_;
                if ( grep( /^HOSTNAME/, $_ ) ) {
                    ( undef, $RCHOSTNAME ) = split( /=/, $_ );
                    chomp($RCHOSTNAME);
                    $RCHOSTNAME =~ s/"//g;
                }

                if ( grep( /^NODENAME/, $_ ) ) {
                    ( undef, $RCNODENAME ) = split( /=/, $_ );
                    chomp($RCNODENAME);
                    $RCNODENAME =~ s/"//g;
                }
            }
            close(NZ);

            if ( "$RCHOSTNAME" ) {
                print "\n$INFOSTR Variable \"HOSTNAME\" in $NETCONF set to \"$RCHOSTNAME\"\n";
            }
            else {
                print "\n$WARNSTR Variable \"HOSTNAME\" not set in $NETCONF\n";
                push(@CHECKARR, "\n$WARNSTR Variable \"HOSTNAME\" not set in $NETCONF\n");
                $warnings++;
            }

            if ( "$RCNODENAME" ) {
                print "\n$INFOSTR Variable \"NODENAME\" in $NETCONF set to \"$RCNODENAME\"\n";
            }
            else {
                print "\n$INFOSTR Variable \"NODENAME\" not set in $NETCONF\n";
                push(@CHECKARR, "\n$INFOSTR Variable \"NODENAME\" not set in $NETCONF\n");
                $warnings++;
            }

            if ( "$RCHOSTNAME" && "$RCNODENAME" ) {
                if ( "$RCHOSTNAME" ne "$RCNODENAME" ) {
                    print "\n$INFOSTR Variables \"NODENAME\" and \"HOSTNAME\" set differently in $NETCONF\n";
                }
            }
        }
        else {
            print "\n$WARNSTR Cannot open $NETCONF\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open $NETCONF\n");
        }
    }
    else {
        print "\n$INFOSTR $NETCONF is zero-length\n";
    }

    my @nettl = `nettl -status 2>/dev/null`;
    if ( @nettl != 0 ) {
        print "\n$INFOSTR Network control tracing and logging status\n";
        print @nettl;
    }

    my @nettlconf = `nettlconf -s 2>/dev/null`;
    if ( @nettlconf != 0 ) {
        print "\n$INFOSTR Network control tracing and logging database\n";
        print @nettlconf;
    }

    if ( open( NETI, "netstat -a |" ) ) {
        print "\n$INFOSTR Active connections\n";
        while (<NETI>) {
            print $_;
            $_ =~ s/^\s+//g;
            chomp($_);
            if ( grep(/^tcp\s+/, $_) ) {
                my @tcparr = split( /\s+/, $_ );
                $tcpstate = $tcparr[ $#tcparr ];
                $tcpcount{$tcpstate}++;
                #
                # Each TCP connection not in TIME_WAIT state
                # requires approximately 12Kbytes of memory
                # in HP-UX, including memory for sockets,
                # STREAMS, and protocol data
                if ( ! grep(/TIME_WAIT/, $tcpstate) ) {
                    $tcptot++;
                }
            }
        }
        close(NETI);
        foreach my $tcpss ( sort keys %tcpcount ) {
            push(@TCPARRSTAT, sprintf("%-20s  %s\n", $tcpss, $tcpcount{$tcpss}));
        }
    }

    if ( @TCPARRSTAT) {
        print "\n$INFOSTR TCP connection states and counts\n";
        print @TCPARRSTAT;
        print "\n$NOTESTR Each TCP connection not in TIME_WAIT state
$NOTESTR requires approximately 12Kbytes of memory
$NOTESTR in HP-UX, including memory for sockets,
$NOTESTR STREAMS, and protocol data\n";
        printf("\n$INFOSTR Total memory usage for TCP connections is %d Kbytes\n", $tcpmemutl * $tcptot);
    }

    my @ARPARR = ();
    my @ARPWARN = ();

    if ( open( ARPA, "arp -a 2>/dev/null |" ) ) {
        print "\n$INFOSTR ARP cache table\n";
        while (<ARPA>) {
            push(@ARPARR, $_);
            $_ =~ s/^\s+//g;
            chomp($_);
            foreach $host (@GWlist) {
                if ( grep(/\b$host\b/, $_) ) {
                    if ( ! grep(/permanent/i, $_) ) {
                        push(@ARPWARN,
"\n$WARNSTR Default gateway $host does not have permanent entry in ARP cache to prevent the ARP spoofing\n");
                        push(@CHECKARR,
"\n$WARNSTR Default gateway $host does not have permanent entry in ARP cache to prevent the ARP spoofing\n");
                        $warnings++;
                    }
                } 
            }
        }
        close(ARPA);
    }

    if ( @ARPARR ) {
        print @ARPARR;
    }

    if ( @ARPWARN ) {
        print @ARPWARN;
    }

    my @arpcache = `ndd -get /dev/arp arp_cache_report 2>/dev/null`;
    if ( @arpcache != 0 ) {
        print "\n$INFOSTR ARP cache table per network interface\n";
        print @arpcache;
    }

    my @netstatp = `netstat -p tcp 2>/dev/null`;
    if ( @netstatp != 0 ) {
        print "\n$INFOSTR Network statistics for TCP\n";
        print @netstatp;
    }

    my @netstatu = `netstat -p udp 2>/dev/null`;
    if ( @netstatu != 0 ) {
        print "\n$INFOSTR Network statistics for UDP\n";
        print @netstatu;
    }

    if ( open( NETN, "netstat -in |" ) ) {
        print "\n$INFOSTR Network errors and collisions\n";
        while (<NETN>) {
            $_ =~ s/^\s+//g;
            print $_;
            my $Lierr = my $Loerr = 0;
            next if ( grep( /Mtu/, $_ ) );
            my @netvals = split( /\s+/, $_ );
            my $vsz = scalar @netvals;
            if ( $vsz == 9 ) {
                $Lname = $netvals[0];
                $Lmtu  = $netvals[1];
                $Lnet  = $netvals[2];
                $Laddr = $netvals[3];
                $Lipkt = $netvals[4];
                $Lierr = $netvals[5];
                $Lopkt = $netvals[6];
                $Loerr = $netvals[7];
                $Lcoll = $netvals[8];
            }
            else {
                $Lname = $netvals[0];
                $Lmtu  = $netvals[1];
                $Lnet  = $netvals[2];
                $Laddr = $netvals[3];
                $Lipkt = $netvals[4];
                $Lopkt = $netvals[5];
            }

            if ( grep( /^el/, $Lname ) ) {
                push(@ATMLANS, $Lname);
            }

            if ( "$Minor$Patch" >= 1131 ) {
                my @nwmgrinc = `nwmgr -q info -c $Lname 2>/dev/null`;
                if ( @nwmgrinc ) {
                    print "\n$INFOSTR nwmgr info for $Lname\n";
                    print @nwmgrinc;
                }

                my @nwmgrlan = `nwmgr -v -c $Lname 2>/dev/null`;
                if ( @nwmgrlan ) {
                    print "\n$INFOSTR nwmgr LAN status for $Lname\n";
                    print @nwmgrlan;
                }

                my @nwmgrmib = `nwmgr -g -c $Lname --st mib 2>/dev/null`;
                if ( @nwmgrmib ) {
                    print "\n$INFOSTR nwmgr LAN MIB status for $Lname\n";
                    print @nwmgrmib;
                }

                my @nwmgrvpd = `nwmgr -q vpd -c $Lname 2>/dev/null`;
                if ( @nwmgrvpd ) {
                    print "\n$INFOSTR nwmgr VPD status for $Lname\n";
                    print @nwmgrvpd;
                }

                my @nwmgrdps = `nwmgr -q dps_map -c $Lname 2>/dev/null`;
                if ( @nwmgrdps ) {
                    print "\n$INFOSTR nwmgr destination port steering map for $Lname\n";
                    print @nwmgrdps;
                }

                my @nwmgrinf = `nwmgr -q drv_coal -c $Lname 2>/dev/null`;
                if ( @nwmgrinf ) {
                    print "\n$INFOSTR nwmgr coalescence settings for $Lname\n";
                    print @nwmgrinf;
                }
            }

            if ( grep( /lan/, $Lname ) ) {
                if ( "$Lmtu" == $DefMTU ) {
                    push(@LANSTAT, "\n$PASSSTR Interface $Lname has default MTU ($DefMTU)\n");
                }
                else {
                    push(@LANSTAT,
"$WARNSTR Interface $Lname has non-default MTU ($Lmtu instead of $DefMTU)\n");
                    push(@CHECKARR,
"\n$WARNSTR Interface $Lname has non-default MTU ($Lmtu instead of $DefMTU)\n");
                    $warnings++;
                }
            }

            if ( "$Lcoll" > 0 ) {
                push(@LANSTAT, "$WARNSTR Collisions on interface $Lname\n");
                push(@CHECKARR, "\n$WARNSTR Collisions on interface $Lname\n");
                $warnings++;
            }
            else {
                push(@LANSTAT, "$PASSSTR No collisions on interface $Lname\n");
            }

            if ( "$Lierr" > 0 ) {
                push(@LANSTAT, "$WARNSTR Input errors on interface $Lname\n");
                push(@CHECKARR, "\n$WARNSTR Input errors on interface $Lname\n");
                $warnings++;
            }
            else {
                push(@LANSTAT, "$PASSSTR No input errors on interface $Lname\n");
            }

            if ( "$Loerr" > 0 ) {
                push(@LANSTAT, "$WARNSTR Output errors on interface $Lname\n\n");
                push(@CHECKARR, "\n$WARNSTR Output errors on interface $Lname\n");
                $warnings++;
            }
            else {
                push(@LANSTAT, "$PASSSTR No output errors on interface $Lname\n\n");
            }
        }
        close(NETN);
    }

    if ( @LANSTAT ) {
        print @LANSTAT;
    }

    my @NDDarrs =
      ( '/dev/tcp', '/dev/udp', '/dev/ip', '/dev/arp', '/dev/rawip', );

    my @nddskip = ();

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

        if ( @NDset != 0 ) {
            print "\n$INFOSTR $myndd network parameters\n";
            foreach my $ndz (@NDset) {
                my @NDz = `ndd $myndd $ndz 2>/dev/null`;
                print "$myndd $ndz: @NDz";
                if ( "$ndz" eq "ip_strong_es_model" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" > 0 ) { 
                        push(@CHECKARR, "\n$INFOSTR ip_strong_es_model set to non-default value $ipstrong (check if it is correct for your network setup)\n");
                        push(@IPARR, "\n$INFOSTR ip_strong_es_model set to non-default value $ipstrong (check if it is correct for your network setup)\n");
                    }
                }

                if ( "$ndz" eq "ip_respond_to_echo_broadcast" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_respond_to_echo_broadcast set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_respond_to_echo_broadcast not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_strong_es_model not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_send_redirects" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_send_redirects set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_send_redirects not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_send_redirects not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_send_source_quench" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_send_source_quench set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_send_source_quench not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_send_source_quench not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_respond_to_timestamp" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_respond_to_timestamp set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_respond_to_timestamp not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_respond_to_timestamp not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_forwarding" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_forwarding set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_forwarding not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_forwarding not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_check_subnet_addr" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 1 ) {
                        push(@IPARR, "\n$PASSSTR ip_check_subnet_addr set to 1 (enforces RFC1122 - subnet cannot be all zeros or all ones)\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_check_subnet_addr not set to 1 (current value $ipstrong, RFC1122 - subnet can be all zeros or all ones)\n");
                        push(@IPARR, "\n$INFOSTR ip_check_subnet_addr not set to 1 (current value $ipstrong, RFC1122 - subnet can be all zeros or all ones)\n");
		    }
                }

                if ( "$ndz" eq "ip_forward_src_routed" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_forward_src_routed set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_forward_src_routed not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_forward_src_routed not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_forward_directed_broadcasts" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_forward_directed_broadcasts set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_forward_directed_broadcasts not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_forward_directed_broadcasts not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_respond_to_address_mask_broadcast" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_respond_to_address_mask_broadcast set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_respond_to_address_mask_broadcast not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_forward_directed_broadcasts not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_respond_to_timestamp" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_respond_to_timestamp set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_respond_to_timestamp not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_respond_to_timestamp not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_respond_to_timestamp_broadcast" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 0 ) {
                        push(@IPARR, "\n$PASSSTR ip_respond_to_timestamp_broadcast set to 0\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_respond_to_timestamp_broadcast not set to 0 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_respond_to_timestamp_broadcast not set to 0 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "arp_cleanup_interval" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 60000 ) {
                        push(@IPARR, "\n$PASSSTR arp_cleanup_interval set to 60000\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR arp_cleanup_interval not set to 60000 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR arp_cleanup_interval not set to 60000 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "tcp_syn_rcvd_max" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" <= 1024 ) {
                        push(@IPARR, "\n$PASSSTR tcp_syn_rcvd_max is <= 1024 (current value $ipstrong)\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR tcp_syn_rcvd_max > 1024 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR tcp_syn_rcvd_max > 1024 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "tcp_conn_request_max" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 4096 ) {
                        push(@IPARR, "\n$PASSSTR tcp_conn_request_max set to 4096\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR tcp_conn_request_max not set to 4096 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR tcp_syn_rcvd_max not set to 1000 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "ip_pmtu_strategy" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" == 1 ) {
                        push(@IPARR, "\n$PASSSTR ip_pmtu_strategy set to 1\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR ip_pmtu_strategy not set to 1 (current value $ipstrong)\n");
                        push(@IPARR, "\n$INFOSTR ip_pmtu_strategy not set to 1 (current value $ipstrong)\n");
		    }
                }

                if ( "$ndz" eq "tcp_isn_passphrase" ) {
                    my @IPSTRONG = split( /\s+/, @NDz );
                    my $ipstrong = $IPSTRONG[0];
                    chomp($ipstrong);
                    if ( "$ipstrong" ne "" ) {
                        push(@IPARR, "\n$PASSSTR tcp_isn_passphrase is set to $ipstrong\n");
                    }
		    else {
                        push(@CHECKARR, "\n$INFOSTR tcp_isn_passphrase is not set\n");
                        push(@IPARR, "\n$INFOSTR tcp_isn_passphrase is not set\n");
		    }
                }
            }
        }
    }

    if ( @IPARR ) {
        print @IPARR;
    }

    datecheck();
    print_trailer("*** END CHECKING NETWORK SETUP $datestring ***");

    my @owners = `owners 2>/dev/null`;
    if ( @owners != 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING OWNERS OF CURRENT OUTGOING NETWORK CONNECTION $datestring ***");

        print @owners;

        datecheck();
        print_trailer("*** END CHECKING OWNERS OF CURRENT OUTGOING NETWORK CONNECTION $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING ASYNCHRONOUS TRANSFER MODE (ATM) $datestring ***");

    if ( @ATMarray ) {
        print "$INFOSTR ATM drivers seemingly installed\n";
        print @ATMarray; 

        if ( @ATMLANS ) {

            foreach my $atmint (@ATMLANS) {
                chomp($atmint);

                my @atmconfig = `atmconfig show -n $atmint 2>/dev/null`;
                if ( @atmconfig ) {
                    print
"\n$INFOSTR SVC traffic profile for ATM LAN Emulation interface $atmint\n";
                    print @atmconfig;
                }
                else {
                    print
"\n$INFOSTR Unknown SVC traffic profile for ATM LAN Emulation interface $atmint\n";
                }

                my @elstatv = `elstat -n $atmint -v 2>/dev/null`;
                if ( @elstatv ) {
                    print
"\n$INFOSTR Status for ATM LAN Emulation interface $atmint\n";
                    print @elstatv;
                }

                my @elstatm = `elstat -n $atmint -m 2>/dev/null`;
                if ( @elstatm ) {
                    print
"\n$INFOSTR Registered multicast MACs for ATM LAN Emulation interface $atmint\n";
                    print @elstatm;
                }

                my @elarp = `elarp -n $atmint 2>/dev/null`;
                if ( @elarp ) {
                    print
"\n$INFOSTR LE ARP cache table for ATM LAN Emulation interface $atmint\n";
                    print @elarp;
                }

                my @mpcstatc = `mpcstat -n $atmint -c 2>/dev/null`;
                if ( @mpcstatc ) {
                    print
"\n$INFOSTR Configuration and status information for MPC $atmint\n";
                    print @mpcstatc;
                }

                my @mpcstats = `mpcstat -n $atmint -s 2>/dev/null`;
                if ( @mpcstats ) {
                    print
"\n$INFOSTR Statistics for MPC $atmint\n";
                    print @mpcstats;
                }

                my @mpcstat = `mpcstat -n $atmint 2>/dev/null`;
                if ( @mpcstat ) {
                    print
"\n$INFOSTR Ingress and Egress cache, and MPS tables for MPC $atmint\n";
                    print @mpcstat;
                }
            }
        }
        else {
            print "$INFOSTR ATM seemingly not used or installed\n";
        }
    }
    else {
        print "$INFOSTR ATM drivers seemingly not installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING ASYNCHRONOUS TRANSFER MODE (ATM) $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING INFINIBAND $datestring ***");

    if ( @IBarray ) {
        print "$INFOSTR InfiniBand drivers seemingly installed\n";
        print @IBarray; 
    
        my @ITutil = `itutil 2>/dev/null`;
        if ( @ITutil ) {
            print "\n$INFOSTR InfiniBand status\n";
            print @ITutil;

            my @ITutils = `itutil -s 2>/dev/null`;
            if ( @ITutils ) {
                print "\n$INFOSTR InfiniBand statistics\n";
                print @ITutils;
            }

            my @ITutilc = `itutil -c 2>/dev/null`;
            if ( @ITutilc ) {
                print "\n$INFOSTR InfiniBand reliable connections\n";
                print @ITutilc;
            }

            my @ITutilT = `itutil -T 2>/dev/null`;
            if ( @ITutilT ) {
                print "\n$INFOSTR InfiniBand list of end-nodes\n";
                print @ITutilT;
            }
        }
        else {
            print "\n$INFOSTR InfiniBand seemingly not used or installed\n";
        }
    }
    else {
        print "$INFOSTR InfiniBand drivers seemingly not installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING INFINIBAND $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING SNA $datestring ***");

    my @SNAN = `snapadmin query_node 2>/dev/null`;
    if ( @SNAN ) {
        print "$INFOSTR SNA query node's definition and current status\n";
        print @SNAN;

        my @SNAP = `snapadmin query_pu 2>/dev/null`;
        if ( @SNAP ) {
            print "$INFOSTR SNA information on local PU\n";
            print @SNAP;
        }

        my @SNAD = `snapadmin query_defaults 2>/dev/null`;
        if ( @SNAD ) {
            print "$INFOSTR SNA defaults used by the node\n";
            print @SNAD;
        }

        my @SNAL = `snapadmin -d query_lu_pools 2>/dev/null`;
        if ( @SNAL ) {
            print "$INFOSTR SNA LUs and their pools\n";
            print @SNAL;
        }
    }
    else {
        print "$INFOSTR SNA seemingly not in use\n";
    }

    datecheck();
    print_header("*** END CHECKING SNA $datestring ***");
}

# Subroutine to check Unix systems accounting
#
sub sachk {
    datecheck();
    print_header("*** BEGIN CHECKING UNIX SYSTEM ACCOUNTING $datestring ***");

    if ( open( AC, "egrep -v ^# $ACCTCONF |" ) ) {
        while (<AC>) {
            chomp;
            next if ( grep( /^$/, $_ ) );
            if ( grep( /^START_ACCT=/, $_ ) ) {
                ( undef, $acctval ) = split( /=/, $_ );
                chomp($acctval);
                if ( $acctval == 0 ) {
                    print "$WARNSTR Acct not enabled in $ACCTCONF\n";
                    push(@CHECKARR, "\n$WARNSTR Acct not enabled in $ACCTCONF\n");
                    $warnings++;
                }
                else {
                    print "$PASSSTR Acct enabled in $ACCTCONF\n";
                }
            }
        }
        close(AC);
    }
    else {
        print "$WARNSTR Cannot open $ACCTCONF\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $ACCTCONF\n");
        $warnings++;
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
                $finalsa = $fileux;
            }
            closedir(SSDIR);

            if ( $accnomb == 0 ) {
                print "\n$WARNSTR System accounting not running\n";
                push(@CHECKARR, "\n$WARNSTR System accounting not running\n");
                $warnings++;
            }
            else {
                print "\n$PASSSTR System accounting seemingly running\n";

                ( $dev,   $ino,   $mode,    $nlink, $uid,
                  $gid,   $rdev,  $size,    $atime,
                  $mtime, $ctime, $blksize, $blocks,
                ) = stat("$UXSA/$finalsa");

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
        }
        else {
            print "\n$WARNSTR Cannot open directory $UXSA\n";
            push(@CHECKARR, "\n$WARNSTR Cannot open directory $UXSA\n");
        }
    }

    my $holflag =
`awk '! /^\\*/ && ! /awk/ && /$Year/ {print}' $accholidays 2>/dev/null`;
    if ("$holflag") {
        print "\n$PASSSTR File $accholidays customized for year $Year\n";
    }
    else {
        print "\n$WARNSTR File $accholidays not customized for year $Year\n";
        push(@CHECKARR, "\n$WARNSTR File $accholidays not customized for year $Year\n");
    }

    datecheck();
    print_trailer("*** END CHECKING UNIX SYSTEM ACCOUNTING $datestring ***");
}

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
        print "$INFOSTR Server is in timezone $tzcur\n";
    }

    if ( -s "$TZFILE" ) {
        if ( open( TZZ, "awk NF $TZFILE |" ) ) {
            print "\n$INFOSTR Timezone configuration file $TZFILE\n";
            while (<TZZ>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
                if ( grep(/^TZ=/, $_ ) ) {
                    ( undef, $TZHOME ) = split( /=/, $_ );
                    $TZHOME =~ s/^\s+//g;
                    $TZHOME =~ s/\s+$//g;
                    chomp($TZHOME);
                }
            }
        }
        close(TZZ);
    }

    if ( -s "$TZDEF" ) {
        if ( open( TZD, "awk NF $TZDEF |" ) ) {
            print "\n$INFOSTR Timezone configuration file $TZDEF\n";
            while (<TZD>) {
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^#/, $_ ) );
                print $_;
                if ( "$_" ) {
                    $TZHOME2 = $_;
                    $TZHOME2 =~ s/^\s+//g;
                    $TZHOME2 =~ s/\s+$//g;
                    chomp($TZHOME2);
                }
            }
        }
        close(TZD);
    }

    if ( ! "$TZHOME" ) {
        print "\n$WARNSTR Environment variable TZ not defined in $TZFILE\n";
        push(@CHECKARR, "\n$WARNSTR Environment variable TZ not defined in $TZFILE\n");
        $warnings++;
    }

    if ( ! "$TZHOME2" ) {
        print "\n$WARNSTR Timezone not defined in $TZDEF\n";
        push(@CHECKARR, "\n$WARNSTR Timezone not defined in $TZDEF\n");
        $warnings++;
    }

    if ( "$TZHOME" ne "$TZHOME2" ) {
        print "\n$WARNSTR Timezone definitions differ between $TZTAB and $TZDEF\n";
        push(@CHECKARR, "\n$WARNSTR Timezone definitions differ between $TZTAB and $TZDEF\n");
        $warnings++;
    }

    if ( ( -s "$TZTAB" ) && ( -T "$TZTAB" ) ) {
        print "\n$PASSSTR Timezone adjustment table $TZTAB exists\n";
        my @tzcat = `awk NF $TZTAB`;
        print @tzcat;
    }
    else {
        print
          "\n$WARNSTR Timezone adjustment table $TZTAB does not exist\n";
        push(@CHECKARR,
          "\n$WARNSTR Timezone adjustment table $TZTAB does not exist\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING TIMEZONE $datestring ***");
}

# Subroutine to check STM
#
sub cstm_info {
    if ( $ONLINEDIAG_FLAG == 1 ) {
        datecheck();
        print_header("*** BEGIN CHECKING SUPPORT TOOL MANAGER (STM) $datestring ***");

        if ( "$DIAGMOND" >= 1 ) {
            print "$INFOSTR STM daemon diagmond running\n";

            if ( $CSTM_FLAG == 0 ) {
                my @DIAGV = grep(/Sup\-Tool\-Mgr.+B\.11\.31\.(\d+)/, @SWarray);
                chomp @DIAGV;
                foreach my $dlink (@DIAGV) {
                    my @DIAGVARR = split(/\s+/, $dlink);
                    if ( "$DIAGVARR[1]" ) {
                        my @DIAGVER = split(/\./, $DIAGVARR[1]);
                        #
                        # On HP-UX 11.31, if Diag version is older than Sep 2009
                        # cstm info tool should not be started for tapes
                        # to prevent possible failure of running backups 
                        #
                        if ( int($DIAGVER[3]) >= 6 ) {
                            $CSTMCOMM =
"selall;uscl type Tape;info;vers;wait;infolog;Done;quit;OK";
                        }
                    }
                }

                if ( open( DUB, "echo '$CSTMCOMM' | cstm|" ) ) {
                    while (<DUB>) {
                        $_ =~ s/^\s+//g;
                        print $_;
                        grep( /UUT|Unit Under Test/, $_ )
                          ? print "$INFOSTR CSTM run failed\n"
                          : grep( /Failed to execute/, $_ )
                          ? print "$INFOSTR CSTM run failed\n"
                          : grep( /FAILED/, $_ )
                          ? print "$ERRSTR Device failed: $_\n"
                          : print "";
                    }
                    close(DUB);

                    my @cstmmem = `echo "gop cstmpager cat;ru l;vd;vda;" | cstm 2>/dev/null`;
                    if ( @cstmmem ) {
                        print "\n$INFOSTR SMT memory error logs\n";
                        print @cstmmem;
                    }
                }
                else {
                    print "$INFOSTR CSTM cannot run\n";
                }
            }
            else {
                print "$INFOSTR Another CSTM process already running\n";
            }
        }
        else {
            print "$INFOSTR STM daemon diagmond not running\n";
        }

        datecheck();
        print_trailer("*** END CHECKING SUPPORT TOOL MANAGER (STM) $datestring ***");
    }
}

# Subroutine to check HP Configuration Manager (old Radia)
#
sub CM_info {
    datecheck();
    print_header("*** BEGIN CHECKING HP CONFIGURATION MANAGER $datestring ***");

    my @whatinfo = `whatinfo 2>/dev/null`;
    if ( @whatinfo != 0 ) {
        print "$INFOSTR CM seemingly installed\n";
        print @whatinfo;
    }
    else {
        print "$INFOSTR CM seemingly not installed or configured\n";
    }

    datecheck();
    print_trailer("*** END CHECKING HP CONFIGURATION MANAGER $datestring ***");
}

# Subroutine to check SIM
#
sub sim_info {
    datecheck();
    print_header("*** BEGIN CHECKING SYSTEMS INSIGHT MANAGER (SIM) $datestring ***");

    my @vseassistc = `vseassist -c 2>/dev/null`;
    if ( @vseassistc != 0 ) {
        print "$INFOSTR Virtual Server Environment (VSE) Management Software\n";
        print @vseassistc;
    
        my @vseassistl = `vseassist -l -n $Hostname 2>/dev/null`;
        if ( @vseassistl != 0 ) {
            print "\n$INFOSTR VSE link verification\n";
            print @vseassistl;
        }

        print "\n";
    }

    my @mxinitconfig = `mxinitconfig -l 2>/dev/null`;
    if ( @mxinitconfig != 0 ) {
        print "$INFOSTR SIM seemingly installed\n";
        print "\n$INFOSTR SIM Current configuration status\n";
        print @mxinitconfig;
    }
    else {
        print "$INFOSTR SIM seemingly not active\n";
    }

    my @SIMarr = `mxnode -ld 2>/dev/null`;
    if ( @SIMarr != 0 ) {
        print "\n$INFOSTR SIM node listing\n";
        print @SIMarr;
    }

    my @mxgetdbinfo = `mxgetdbinfo -a 2>/dev/null`;
    if ( @mxgetdbinfo != 0 ) {
        print "\n$INFOSTR SIM database information\n";
        print @mxgetdbinfo;
    }

    if ( "$Minor$Patch" >= 1120 ) {
        my @mxconfigrepo = `mxconfigrepo -c 2>/dev/null`;
        if ( @mxconfigrepo != 0 ) {
            print "\n$INFOSTR SIM database integrity\n";
            print @mxconfigrepo;
        }
    }

    my @SIMuser = `mxuser -lt 2>/dev/null`;
    if ( @SIMuser != 0 ) {
        print "\n$INFOSTR SIM users in Service Control Manager\n";
        print @SIMuser;
    }

    my @mxauth = `mxauth -l 2>/dev/null`;
    if ( @mxauth != 0 ) {
        print "\n$INFOSTR SIM Trusted users in Service Control Manager\n";
        print @mxauth;
    }

    my @mxagentconfig = `mxagentconfig -l 2>/dev/null`;
    if ( @mxagentconfig != 0 ) {
        print "\n$INFOSTR SIM Command Management Server agents\n";
        print @mxagentconfig;
    }

    my @mxagentconfigc = `mxagentconfig -c 2>/dev/null`;
    if ( @mxagentconfigc != 0 ) {
        print "\n$INFOSTR SIM Command Management Server access\n";
        print @mxagentconfigc;
    }

    my @mxcert = `mxcert -ld 2>/dev/null`;
    if ( @mxcert != 0 ) {
        print "\n$INFOSTR SIM trusted certificates\n";
        print @mxcert;
    }

    my @mxcollection = `mxcollection -ln 2>/dev/null`;
    if ( @mxcollection != 0 ) {
        print "\n$INFOSTR SIM Collections listed in a hierarchical tree\n";
        print @mxcollection;
    }

    my @mxglobalp = `mxglobalprotocolsettings -ld 2>/dev/null`;
    if ( @mxglobalp != 0 ) {
        print "\n$INFOSTR SIM global protocol settings\n";
        print @mxglobalp;
    }

    my @mxglobals = `mxglobalsettings -ld 2>/dev/null`;
    if ( @mxglobals != 0 ) {
        print "\n$INFOSTR SIM global settings\n";
        print @mxglobals;
    }

    my @mxmib = `mxmib -l 2>/dev/null`;
    if ( @mxmib != 0 ) {
        print "\n$INFOSTR SIM registered MIBs\n";
        print @mxmib;
    }

    my @mxngroup = `mxngroup -lm 2>/dev/null`;
    if ( @mxngroup != 0 ) {
        print "\n$INFOSTR SIM member systems\n";
        print @mxngroup;
        my $mxl = @mxngroup;
        print "\n$INFOSTR There are $mxl SIM member systems\n";
    }

    my @mxnodesecurity = `mxnodesecurity -l 2>/dev/null`;
    if ( @mxnodesecurity != 0 ) {
        print "\n$INFOSTR SIM Command Management Server credentials\n";
        print @mxnodesecurity;
    }

    my @mxpassword = `mxpassword -l 2>/dev/null`;
    if ( @mxpassword != 0 ) {
        print "\n$INFOSTR passwords stored by SIM\n";
        print @mxpassword;
    }

    my @mxreport = `mxreport -l -x report 2>/dev/null`;
    if ( @mxreport != 0 ) {
        print "\n$INFOSTR SIM listing of all reports\n";
        print @mxreport;
    }

    my @mxstm = `mxstm -l 2>/dev/null`;
    if ( @mxstm != 0 ) {
        print "\n$INFOSTR SIM listing of system type manager rules\n";
        print @mxstm;
    }

    my @mxtask = `mxtask -lt 2>/dev/null`;
    if ( @mxtask != 0 ) {
        print "\n$INFOSTR SIM tasks currently registered\n";
        print @mxtask;
    }

    my @mxtool = `mxtool -ld 2>/dev/null`;
    if ( @mxtool != 0 ) {
        print "\n$INFOSTR SIM listing of tools\n";
        print @mxtool;
    }

    my @mxtoolbox = `mxtoolbox -lt 2>/dev/null`;
    if ( @mxtoolbox != 0 ) {
        print "\n$INFOSTR SIM listing of toolboxes\n";
        print @mxtoolbox;
    }

    my $retc = system "checkkernelparams 2>/dev/null";
    my $RCV = ( $retc >> 8 ) && 0xff;
    chomp($RCV);
    if ( "$RCV" == 0 ) {
       print "\n$PASSSTR Kernel parameters have been tuned for Java server processes (as recommended by checkkernelparams)\n";
    }
    elsif ( "$RCV" == 1 ) {
       print "\n$ERRSTR Some kernel parameters are less than required values for tuning Java server processes (as recommended by checkkernelparams)\n";
       push(@CHECKARR, "\n$ERRSTR Some kernel parameters are less than required values for tuning Java server processes (as recommended by checkkernelparams)\n");
       $warnings++; 
    }
    else {
       print "\n$WARNSTR Some kernel parameters are less than desired values for tuning Java server processes (as recommended by checkkernelparams)\n";
       push(@CHECKARR, "\n$WARNSTR Some kernel parameters are less than desired values for tuning Java server processes (as recommended by checkkernelparams)\n");
       $warnings++; 
    }

    my @osinfo = `osinfo 2>/dev/null`;
    if ( @osinfo != 0 ) {
        print "\n$INFOSTR WBEM O/S information\n";
        print @osinfo;
    }

    my @mxwbemsub = `mxwbemsub -l 2>/dev/null`;
    if ( @mxwbemsub != 0 ) {
        print "\n$INFOSTR SIM Listing of WBEM subscriptions\n";
        print @mxwbemsub;
    }

    eval {
        # On certain occasions, wbemassist hangs, so we need to
        # manage how long it runs
        #
        local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
        alarm 120;
        my @wbemassist = `wbemassist 2>/dev/null`;
        if (@wbemassist) {
            print "\n$INFOSTR WBEM installation and configuration status\n";
            print @wbemassist;
        }
        alarm 0;
    };

    if ($@) {
        warn "\n$WARNSTR Command \"wbemassist\" timed out\n";
    }

    my @wbemCheck = `wbemCheck 2>/dev/null`;
    if (@wbemCheck) {
        print "\n$INFOSTR WBEM - Provider compatibility status\n";
        print @wbemCheck;
    }

    my @wbemcheck = `wbem_check.sh 2>/dev/null`;
    if (@wbemcheck) {
        print "\n$INFOSTR WBEM wbem_check.sh results\n";
        print @wbemcheck;
    }

    if ( -s $SCRCONF ) {
        if ( open( SCRFROM, "egrep -v ^# $SCRCONF 2>/dev/null |" ) ) {
            print "\n$INFOSTR System Configuration Repository status\n";
            while (<SCRFROM>) {
                print $_;
                chomp($_);
                next if ( grep( /^$/, $_ ) );
                if ( grep( /^SCR_DAEMON/, $_ ) ) {
                    ( undef, $scrflag ) = split( /=/, $_ );
                    $scrflag =~ s/^\s+//g;
                    if ( $scrflag == 1 ) {
                        print
"\n$INFOSTR System Configuration Repository seemingly active\n";
                    }
                    else {
                        print
"\n$INFOSTR System Configuration Repository seemingly not active\n";
                    }
                }
            }
            close(SCRFROM);
        }
    }
    else {
        print
"\n$INFOSTR System Configuration Repository seemingly not active\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SYSTEMS INSIGHT MANAGER (SIM) $datestring ***");
}

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
            print "\n";
            print @SAMBAconf;
        }
    }
    else {
        print "$INFOSTR Samba seemingly not active\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SAMBA $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING CIFS $datestring ***");

    my @cifsclient = `cifsclient status 2>/dev/null`;

    my @cifslist = `cifslist 2>/dev/null`;

    if ( @cifsclient != 0 ) {
        print "$INFOSTR CIFS client seemingly installed\n";
        print @cifsclient;

        if ( -s "$CIFSCLFILE" ) {
            my @cifscat  = `awk NF $CIFSCLFILE`;
            if ( @cifscat ) {
                print "\n$INFOSTR CIFS file $CIFSCLFILE\n";
                print @cifscat;
            }
        }

        if ( @cifslist != 0 ) {
            print "\n$INFOSTR CIFS listing\n";
            print @cifslist;
        }
    }
    else {
        print "$INFOSTR CIFS client seemingly not active\n";
    }

    datecheck();
    print_trailer("*** END CHECKING CIFS $datestring ***");
}

# Subroutine to check standard Unix printing
#
sub lp_info {
    datecheck();
    print_header("*** BEGIN CHECKING STANDARD UNIX PRINTING $datestring ***");

    # On certain occasions, xd hangs, so we need to
    # manage how long it runs
    #
    local $SIG{ALRM} = sub {die "\n$WARNSTR Alarm - command interrupted\n"};
    alarm 20;
    my @CUPSlp  = `lpinfo -v 2>&1 | egrep -vi "not found"`;
    alarm 0;

    my @LPRnglp = `checkpc -V 2>&1 | egrep -vi "not found"`;

    if ( @CUPSlp != 0 ) {
        print "$INFOSTR CUPS printing seemingly installed\n";
        print @CUPSlp;
        $LPSTAND++;
    }

    if ( @LPRnglp != 0 ) {
        print "$INFOSTR LPRng printing seemingly installed\n";
        print @LPRnglp;
        $LPSTAND++;
    }

    if ( "$LPSTAND" == 0 ) {
        print "$INFOSTR Standard LP printing seemingly installed\n";
    }

    if ( "$LPSCHED" > 0 ) {
        my @LParr = `lpstat -a | egrep -vi "no entries"`;
        if ( @LParr != 0 ) {
            print "\n$INFOSTR Printing seemingly active\n";
            print @LParr;

            my @LParro = `lpstat -o 2>/dev/null`;
            if ( @LParro != 0 ) {
                print "\n$INFOSTR Print queue status\n";
                print @LParro;
            }

            if ( "$LPSTAND" == 0 ) {
                if ( -s "$lpanalyser" ) {
                    my @lpana = `lpana | awk NF`;
                    if ( @lpana != 0 ) {
                        print
"\n$INFOSTR Standard LP spooler performance analysis\n";
                        print @lpana;
                    }
                }
            }
        }
        else {
            print "$INFOSTR Printing enabled but queues not defined\n";
        }
    }
    else {
        print "$INFOSTR Printing seemingly not active\n";
    }

    datecheck();
    print_trailer("*** END CHECKING STANDARD UNIX PRINTING $datestring ***");
}

# Subroutine to check OpenView-based monitoring
#
sub OVchk {
    datecheck();
    print_header("*** BEGIN CHECKING NETWORK NODE MANAGER $datestring ***");

    if ( grep( /NNM|Network Node Manager/, @SWarray ) ) {
        print "\n$INFOSTR Network Node Manager bundles seemingly installed\n";

        my @OVcstatus = `ovcstatus 2>/dev/null`;
        if ( @OVcstatus != 0 ) {
            print "\n$INFOSTR OV Network Node Manager status\n";
            print @OVcstatus;
        }

        my @OVversion = `ovversion 2>/dev/null`;
        if ( @OVversion != 0 ) {
            print "\n$INFOSTR OV Network Node Manager version\n";
            print @OVversion;
        }
        else {
            my @OVversion = `nnmversion.ovpl 2>/dev/null`;
            if ( @OVversion != 0 ) {
                print "\n$INFOSTR OV Network Node Manager 8i version\n";
                print @OVversion;
            }
        }

        my @NNMV = `cat $NNMVer 2>/dev/null`;
        if ( @NNMV != 0 ) {
            print "\n$INFOSTR OV Network Node Manager installation info\n";
            print @NNMV;
        }

        my @OVconfget = `ovconfget 2>/dev/null`;
        if ( @OVconfget != 0 ) {
            print "\n$INFOSTR OV Network Node Manager configuration\n";
            print @OVconfget;
        }

        my @OVettopo = `ovet_topodump 2>/dev/null`;
        if ( @OVettopo != 0 ) {
            print "\n$INFOSTR OV Network Node Manager Extended Topology configuration\n";
            print @OVettopo;
        }

        my @OVettopof = `ovet_topodump -lfilt 2>/dev/null`;
        if ( @OVettopof != 0 ) {
            print "\n$INFOSTR OV Network Node Manager Extended Topology filters\n";
            print @OVettopof;
        }

        my @OVtopodump = `ovtopodump -s -l 2>/dev/null`;
        if ( @OVtopodump != 0 ) {
            print "\n$INFOSTR OV Network Node Manager server topology\n";
            print @OVtopodump;

            my @OVtopodump2 = `ovtopodump -s 2>/dev/null`;
            if ( @OVtopodump2 != 0 ) {
                print "\n$INFOSTR OV Network Node Manager whole topology\n";
                print @OVtopodump2;
            }

            my @OVtopodumpRISC = `ovtopodump -RISC 2>/dev/null`;
            if ( @OVtopodumpRISC != 0 ) {
                print "\n$INFOSTR OV Network Node Manager monitored objects\n";
                print @OVtopodumpRISC;
            }

            my @nnmAPAq = `ovet_apaConfig.ovpl -query APAPolling 2>/dev/null`;
            if ( @nnmAPAq != 0 ) {
                print "\n$INFOSTR OV Network Node Manager APA status\n";
                print @nnmAPAq;
            }

            my @OVreqsch = `request_list schedule 2>/dev/null`;
            if ( @OVreqsch != 0 ) {
                print "\n$INFOSTR OV Network Node Manager schedules\n";
                print @OVreqsch;
            }
        }
        else {
            my @nnmtopodump = `nnmtopodump.ovpl -u $NNM8USER -p $NNM8PASS -type node 2>/dev/null`;
            if ( @nnmtopodump != 0 ) {
                print "\n$INFOSTR OV Network Node Manager 8i node topology\n";
                print @nnmtopodump;
            }
        }

        my @nnmprtcnt = `nnmprintcounts.ovpl 2>/dev/null`;
        if ( @nnmprtcnt != 0 ) {
            print "\n$INFOSTR OV Network Node Manager 8i topology counts\n";
            print @nnmprtcnt;
        }

        my @nnmloadmib = `nnmloadmib -list 2>/dev/null`;
        if ( @nnmloadmib != 0 ) {
            print "\n$INFOSTR OV Network Node Manager 8i loaded MIBs\n";
            print @nnmloadmib;
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
    print_trailer("*** END CHECKING NETWORK NODE MANAGER $datestring ***");

    if ( "$opts{o}" == 1 ) { 
        datecheck();
        print_header("*** BEGIN CHECKING OPENVIEW MONITORING $datestring ***");

        my @OPVstatus = `opcsv -status 2>/dev/null`;
        if ( @OPVstatus != 0 ) {
            print "$PASSSTR OV server status\n";
            print @OPVstatus;
        }
        else {
            print "$INFOSTR OV server seemingly not running\n";
        }

        if ( -s $OVCONF ) {
            if ( open( OV, "egrep -v ^# $OVCONF 2>/dev/null |" ) ) {
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
                print "\n$WARNSTR Configuration file $OVCONF missing\n";
                push(@CHECKARR, "\n$WARNSTR Configuration file $OVCONF missing\n");
            }
        }
        else {
            print "\n$INFOSTR Configuration file $OVCONF is zero-length or missing\n";
        }

        if ( -s $OPCinfo ) {
            if ( open( OPCI, "egrep -v ^# $OPCinfo 2>/dev/null |" ) ) {
                print "\n$INFOSTR Configuration file $OPCinfo\n";
                while (<OPCI>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(OPCI);
            }
            else {
                print "\n$WARNSTR Configuration file $OPCinfo missing\n";
                push(@CHECKARR, "\n$WARNSTR Configuration file $OPCinfo missing\n");
                $warnings++;
            }
        }
        else {
            print "\n$INFOSTR Configuration file $OPCinfo is zero-length or missing\n";
        }

        if ( -s $NODEinfo ) {
            if ( open( NODEI, "egrep -v ^# $NODEinfo 2>/dev/null |" ) ) {
                print "\n$INFOSTR Configuration file $NODEinfo\n";
                while (<NODEI>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(NODEI);
            }
            else {
                print "\n$WARNSTR Configuration file $NODEinfo missing\n";
                push(@CHECKARR, "\n$WARNSTR Configuration file $NODEinfo missing\n");
                $warnings++;
            }
        }
        else {
            print "\n$INFOSTR Configuration file $NODEinfo is zero-length or missing\n";
        }

        if ( -s $MGRCONF ) {
            if ( open( MGRC, "egrep -v ^# $MGRCONF 2>/dev/null |" ) ) {
                print "\n$INFOSTR Configuration file $MGRCONF for NAT Management Server\n";
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
            print "\n$INFOSTR Configuration file $MGRCONF is zero-length or missing\n";
        }

        if ( -s $SMSPIconf ) {
            if ( open( SMI, "egrep -v ^# $SMSPIconf 2>/dev/null |" ) ) {
                print "\n$INFOSTR Configuration file $SMSPIconf\n";
                while (<SMI>) {
                    $_ =~ s/^ //g;
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
                close(SMI);
            }
            else {
                print "\n$WARNSTR Configuration file $SMSPIconf missing\n";
                push(@CHECKARR, "\n$WARNSTR Configuration file $SMSPIconf missing\n");
                $warnings++;
            }
        }
        else {
            print "\n$INFOSTR Configuration file $SMSPIconf is zero-length or missing\n";
        }

        my @OVver = `opcctla -type -verbose 2>/dev/null`;
        if ( @OVver != 0 ) {
            print "\n$INFOSTR OV Toolkit version\n";
            print @OVver;
        }

        my @OVstatus = `ovstatus -c 2>/dev/null`;
        my @OVstatus2 = `ovstatus -v -c 2>/dev/null`;
        if ( @OVstatus2 != 0 ) {
            print "\n$PASSSTR OV platforms daemon processes status\n";
            print @OVstatus2;
        }
        elsif ( @OVstatus != 0 ) {
            print "\n$PASSSTR OV platforms daemon processes status\n";
            print @OVstatus;
        }
        else {
            print "\n$INFOSTR OV platforms daemon processes not running\n";
        }

        @OVget = `opcagt -status 2>&1`;

        if ( @OVget != 0 ) {
            print "\n$PASSSTR OV Toolkit installed\n";
            print @OVget;
        }
        else {
            print "\n$WARNSTR OV Toolkit installed but not running or toolkit missing\n";
            push(@CHECKARR, "\n$WARNSTR OV Toolkit installed but not running or toolkit missing\n");
            $warnings++;
        }

        if ( "$opcflag" == 1 ) {
            print "\n$PASSSTR OV startup defined in $OVCONF\n";
        }
        else {
            print "\n$WARNSTR OV startup not defined in $OVCONF\n";
            push(@CHECKARR, "\n$WARNSTR OV startup not defined in $OVCONF\n");
            $warnings++;
        }

        print @OVset;

        # By default, itochecker_agt.conf is in the
        # same directory where the script resides, so
        #
        if ( (-d "$ITOdir") && (chdir "$ITOdir") ) {
            my @tocheck1 = `itochecker_agt -1 2>/dev/null`;
    
            if ( @tocheck1 ) {
                if ( -s "$ITOres" ) {
                    my @prITOres = `awk NF $ITOres`;
                    if ( @prITOres ) {
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
                    if ( @prITOres ) {
                        print "\n$INFOSTR OV Toolkit log and configuration check\n";
                        print @prITOres;
                    }
                }
            }
        }

        datecheck();
        print_trailer("*** END CHECKING OPENVIEW MONITORING $datestring ***");

        if ( @OVget != 0 ) {
            datecheck();
            print_header("*** BEGIN CHECKING OPENVIEW AND SMSPI TEST ALERTS $datestring ***");

            my @ovalert = `poptestticket 2>/dev/null`;
            my @smspialert = `smspi -test 2>/dev/null`;
            my @smspiver = `smspi -v 2>/dev/null`;

            if ( @smspiver ) {
                print "$INFOSTR SMSPI details\n";
                print @smspiver;
                print "\n";
            }

            print "$INFOSTR \"poptestticket\" and \"smspi -test\" were run\n";
            print "$NOTESTR Verify the Cases were raised on the back-end monitoring server\n";

            datecheck();
            print_trailer("*** END CHECKING OPENVIEW AND SMSPI TEST ALERTS $datestring ***");
        }
    }
}

#
# Omnistorage
#
sub checkOmnistorage {

    my @listp = `listp -m 2>/dev/null | awk NF`;
    if (@listp) {
        datecheck();
        print_header("*** BEGIN CHECKING OMNISTORAGE $datestring ***");

        print @listp;

        my @OMNILS = ( 
                     "/etc/opt/omnistorage/netcfg",
                     "/etc/opt/omnistorage/jmcfg",
                     "/etc/opt/omnistorage/jhosts",
                     "/etc/opt/omnistorage/FSID/agerconfig",
                     );

        foreach my $omnifile (@OMNILS) {
            if ( ( -s "$omnifile" ) && ( -T "$omnifile" ) ) {
                my @omnicat = `awk NF $omnifile`;
                print "\n$INFOSTR $omnifile exists\n";
                print @omnicat; 
            }
            else {
                print "\n$INFOSTR $omnifile does not exist or is zero-length\n";
            }
        }

        datecheck();
        print_trailer("*** END CHECKING OMNISTORAGE $datestring ***");
    }
}

# ISEE
#
sub checkISEE {
    datecheck();
    print_header("*** BEGIN CHECKING ISEE MONITORING $datestring ***");

    if ( $ISEE_FLAG > 0 ) {
        print "$INFOSTR ISEE installed\n";

        my @iseetest = `iseeConnectivityTest.sh | awk NF`;
        if (@iseetest) {
            print @iseetest;
        }

        if ( -s "$ISEEDEVINFO" ) {
            my @iseedev = `awk NF $ISEEDEVINFO`;
            print "\n$INFOSTR $ISEEDEVINFO exists\n";
            print @iseedev; 
        }
        else {
            print "\n$INFOSTR $ISEEDEVINFO does not exist or is zero-length\n";
        }
    }
    else {
        print "$INFOSTR ISEE not installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING ISEE MONITORING $datestring ***");
}

#
# Check Oracle instances
#
sub checkOracle {
    datecheck();
    print_header("*** BEGIN CHECKING ORACLE $datestring ***");

    if ( ( -s "$ORATAB" ) || ( $ORACLE_FLAG > 0 ) ) {
        print "$INFOSTR Oracle seemingly installed\n\n";
        print "$NOTESTR If the TZ variable is not set, each Oracle operation
requiring the TZ will open(), fstat(), read() and close()
the $TZDEF file\n";
        print "$NOTESTR Setting network packet size MTU=9000 bytes (Jumbo Frames)
is a standard recommendation for Oracle RAC Interconnect links\n\n";

        my @oratab = `awk NF $ORATAB 2>/dev/null`;
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

    my $ORANETMASK = q{};
    my $ORANETVIP = q{};

    if ( open( CRSS, "/bin/su - oracle -c \"crs_stat -p\" 2>/dev/null |" ) ) {
        while (<CRSS>) {
            push(@ORACRS, $_);
            if ( grep(/^NAME=/, $_ ) ) {
                $ORANETMASK = q{};
                $ORANETVIP = q{};
            }

            if ( grep(/^USR_ORA_NETMASK=/, $_ ) ) {
                ( undef, $ORANETMASK ) = split( /=/, $_ );
                chomp($ORANETMASK);
            }

            if ( grep(/^USR_ORA_VIP=/, $_ ) ) {
                ( undef, $ORANETVIP ) = split( /=/, $_ );
                chomp($ORANETVIP);
            }

            if ( "$ORANETMASK" && "$ORANETVIP" ) {
                if ( "$balanceIP{$ORANETVIP}" != "$ORANETMASK" ) {
                    push(@CHECKARR, "\n$ERRSTR Subnet masks for Oracle VIP address $ORANETVIP and LAN card do not match\n");
                    push(@ORAERRARR, "\n$ERRSTR Subnet masks for Oracle VIP address $ORANETVIP and LAN card do not match\n");
                    $warnings++;
                }
                else {
                    push(@GOODORA, "\n$PASSSTR Subnet masks for Oracle VIP address $ORANETVIP and LAN card identical\n");
                }
            }
        }
        close(CRSS);
       
        if ( @ORACRS ) { 
            print "\n$INFOSTR Oracle Cluster registry status\n";
            print @ORACRS;
        }

        if ( @ORAERRARR ) {
            print @ORAERRARR;
        }

        if ( @GOODORA ) {
            print @GOODORA;
        }
    }

    my $DEVODM  = "/dev/odm";
    my @devodms = `cat $DEVODM/stats 2>/dev/null`;
    if ( @devodms ) {
        print "\n$INFOSTR Oracle Disk Manager (ODM) seemingly running\n";
        print @devodms;

        my @devodmp = `kcmodule -P state odm 2>/dev/null`;
        if ( @devodmp ) {
            print "\n$INFOSTR Oracle Disk Manager kernel module status\n";
            print @devodmp;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING ORACLE $datestring ***");
}

# Subroutine to check cleanup of /tmp at boot
#
sub tmpcleanupcheck {
    datecheck();
    print_header("*** BEGIN CHECKING /tmp CLEANUP AT BOOT $datestring ***");

    if ( open( ZROM, "egrep -v ^# $TMPCLEAN |" ) ) {
        while (<ZROM>) {
            chomp;
            next if ( grep( /^$/, $_ ) );
            if ( grep( /^CLEAR_TMP=/, $_ ) ) {
                ( undef, $doittmp ) = split( /=/, $_ );
                "$doittmp" == 0
                  ? print "$WARNSTR File system /tmp not cleaned up at boot\n"
                  : "$doittmp" == 1
                  ? print "$PASSSTR File system /tmp CLEANED at boot\n"
                  : print
                  "$INFOSTR File system /tmp cleaning not specified at boot\n";
            }
        }
        close(ZROM);
    }
    else {
        print "$WARNSTR Cannot open $TMPCLEAN\n";
        push(@CHECKARR, "\n$WARNSTR Cannot open $TMPCLEAN\n");
    }

    datecheck();
    print_trailer("*** END CHECKING /tmp CLEANUP AT BOOT $datestring ***");
}

# Subroutine to check vendor backup configuration
#
sub vendorbck {
    datecheck();
    print_header("*** BEGIN CHECKING VENDOR-BASED BACKUPS $datestring ***");

    -d "$NETBCKDIR1"     ? $NETBCKDIR = $NETBCKDIR1
      : -d "$NETBCKDIR2" ? $NETBCKDIR = $NETBCKDIR2
      :   print "$INFOSTR NetBackup seemingly not installed\n";

    if ("$NETBCKDIR") {
        $NETBCKVER  = "$NETBCKDIR/netbackup/version";
        $NETBCKCONF = "$NETBCKDIR/netbackup/bp.conf";

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
        my @netwrkcfg = `egrep -v ^# $NETWKCONF 2>/dev/null | awk NF`;
        if ( "@netwrkcfg" ) {
            print "\n$INFOSTR NetWorker startup script $NETWKCONF exists\n";
            print @netwrkcfg;
        }

        my @nsrstat = `printf "show name;schedule;print type: NSR client\n" | nsradmin -i - 2>/dev/null`;
        if ( "@nsrstat" ) {
            print "\n$INFOSTR NetWorker seemingly installed\n";
            print @nsrstat;

            my @mminfo = `mminfo -m 2>/dev/null | awk NF`;
            if (@mminfo) {
                print "\n$INFOSTR NetWorker media status\n";
                print @mminfo;
            }

            my @nsrall = `printf "show;print type:nsr\n" | nsradmin -i - 2>/dev/null`;
            if (@nsrall) {
                print "\n$INFOSTR NetWorker status for NSR\n";
                print @nsrall;
            }

            my @nsrsch = `printf "show;print type:nsr schedule\n" | nsradmin -i - 2>/dev/null`;
            if (@nsrsch) {
                print "\n$INFOSTR NetWorker status for NSR schedule\n";
                print @nsrsch;
            }

            my @nsrpol = `printf "show;print type:nsr policy\n" | nsradmin -i - 2>/dev/null`;
            if (@nsrpol) {
                print "\n$INFOSTR NetWorker status for NSR policy\n";
                print @nsrpol;
            }

            my @nsrpool = `printf "show;print type:nsr pool\" | nsradmin -i - 2>/dev/null`;
            if (@nsrpool) {
                print "\n$INFOSTR NetWorker status for NSR pool\n";
                print @nsrpool;
            }

            my @nsrstage = `printf "show;print type:nsr stage\n" | nsradmin -i - 2>/dev/null`;
            if (@nsrstage) {
                print "\n$INFOSTR NetWorker status for NSR stage\n";
                print @nsrstage;
            }

            my @nsrdir = `printf "show;print type:nsr directive\n" | nsradmin -i - 2>/dev/null`;
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

        -d "$OMNIDIR1"     ? $OMNIDIR = $OMNIDIR1
          : -d "$OMNIDIR2" ? $OMNIDIR = $OMNIDIR2
          : print "$INFOSTR Data Protector home directory seemingly not installed\n";

        my @OMNIARR = ();
        if ( -s "$OMNIRC" ) {
            if ( open( ORC, "cat $OMNIRC 2>/dev/null | awk NF |" ) ) {
                print
"\n$INFOSTR Data Protector global configuration file $OMNIRC\n";
                while (<ORC>) {
                    print $_;
                    chomp($_);
                    if ( grep( /^M_ARENA_OPTS/, $_ ) ) {
                        push(@OMNIARR,
"\n$PASSSTR M_ARENA_OPTS defined in $OMNIRC (important to decrease Data Protector memory usage)\n");
                    }
                }
            }
        }
        else {
            print "\n$INFOSTR Data Protector global configuration file $OMNIRC missing or is zero-length\n";
        }

        if ( @OMNIARR ) {
            print @OMNIARR;
        }
        else {
            print
"\n$INFOSTR M_ARENA_OPTS not defined in $OMNIRC (important to decrease Data Protector memory usage)\n";
        }

        if ( "$OMNIDIR" ) {
            my $LIBTAB = "$OMNIDIR/.libtab";
            if ( -s "$LIBTAB" ) {
                my @libt = `awk NF $LIBTAB 2>/dev/null`;
                if ( @libt != 0 ) {
                    print "\n$INFOSTR Data Protector file $LIBTAB\n";
                    print @libt;
                }
            } 
        } 

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

        my @dpcko = `omnicellinfo -cell 2>/dev/null | awk NF`;
        if (@dpcko) {
            print "\n$INFOSTR Data Protector configuration status\n";
            print @dpcko;
        }

        my @omnicmm = `omnicellinfo -mm 2>/dev/null | awk NF`;
        if (@omnicmm) {
            print "\n$INFOSTR Data Protector pool and media status\n";
            print @omnicmm;
        }

        my @omnicdb = `omnicellinfo -db 2>/dev/null | awk NF`;
        if (@omnicdb) {
            print "\n$INFOSTR Data Protector DB status\n";
            print @omnicdb;
        }

        my @omnidbutil = `omnidbutil -show_cell_name 2>/dev/null`;
        if (@omnidbutil) {
            print "\n$INFOSTR Data Protector Cell Manager\n";
            print @omnidbutil;
        }

        my @omnisv = `omnisv status 2>/dev/null`;
        if ( @omnisv ) {
            print "\n$INFOSTR Data Protector Cell Manager services\n";
            print @omnisv;
        }

        my @dpck1 = `omnicc 2>/dev/null | awk NF`;
        if (@dpck1) {
            print "\n$INFOSTR Data Protector client configuration status\n";
            print @dpck1;
        }

        my @dptapeck = `devbra -dev 2>&1 | awk NF`;
        if (@dptapeck) {
            print "\n$INFOSTR Data Protector tape configuration status\n";
            print @dptapeck;
        }

        my @rac = `ls /dev/rac/* 2>/dev/null`;
        foreach my $racdev ( @rac ) {
            chomp($racdev);
            my @racdevarr = `mc -p $racdev -r IDSM 2>/dev/null`;
            if ( @racdevarr ) {
                print "\n$INFOSTR Status for $racdev\n";
                print @racdevarr;
            }
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

        my @omnimm = `omnimm -list_pools 2>/dev/null`;
        if (@omnimm) {
            print "\n$INFOSTR Data Protector pools\n";
            print @omnimm;
        }

        my @omnirptd = `omnirpt -report db_size 2>/dev/null`;
        if (@omnirptd) {
            print "\n$INFOSTR Data Protector internal DB status\n";
            print @omnirptd;
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

        my @omnidbutildc = `omnidbutil -list_dcdirs 2>/dev/null`;
        if (@omnidbutildc) {
            print "\n$INFOSTR Data Protector DC directories\n";
            print @omnidbutildc;
        }
    }
    else {
        print "\n$INFOSTR Data Protector seemingly not installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING VENDOR-BASED BACKUPS $datestring ***");
}

# Subroutine to check global PATH
#
sub pathcheck {
    datecheck();
    print_header("*** BEGIN CHECKING GLOBAL ENVIRONMENT VARIABLE PATH $datestring ***");

    my $pathf = "/etc/PATH";

    if ( -s "$pathf" ) {
        my $listpath = `cat $pathf`;
        if ( "$listpath" ) {
            print "$INFOSTR Global PATH in $pathf\n";
            print $listpath;

            my @PATHARR = split(/:/, $listpath);
            foreach my $pathl (@PATHARR) {
                chomp($pathl);
                my $stperm = (stat($pathl))[2] & 0777;
                if ( $stperm & 022 ) {
                    $BADDIR_FLAG++;
                    print
"\n$WARNSTR PATH variable contains group- and/or world-writable directory $pathl\n";
                    push(@CHECKARR,
"$WARNSTR PATH variable contains group- and/or world-writable directory $pathl\n");
                    $warnings++;
                }

                if ( ! -d $pathl ) {
                    print
"\n$WARNSTR PATH variable contains non-existent directory $pathl\n";
                    push(@CHECKARR,
"$WARNSTR PATH variable contains non-existent directory $pathl\n");
                    $warnings++;
                }

                if ( $pathl eq "." ) {
                    print
"\n$WARNSTR PATH variable contains \".\" in the search list (recommended to remove current directory from PATH)\n";
                    push(@CHECKARR,
"\n$WARNSTR PATH variable contains \".\" in the search list (recommended to remove current directory from PATH)\n");
                    $warnings++;
                }

                if ( -l $pathl ) {
                    if ( ! -e $pathl ) {
                        print "\n$WARNSTR Directory $pathl in PATH is invalid symbolic link\n";
                        push(@CHECKARR,
"\n$WARNSTR Directory $pathl in PATH is invalid symbolic link\n");
                        $warnings++;
                    }
                    else {
                        print "\n$WARNSTR Directory $pathl in PATH is a symbolic link\n";
                        push(@CHECKARR,
"\n$WARNSTR Directory $pathl in PATH is a symbolic link\n");
                        $warnings++;
                    }
                }

                if ($patharr{$pathl}) {
                    print "\n$WARNSTR Directory $pathl listed more than once in PATH\n";
                    push(@CHECKARR,
"\n$WARNSTR Directory $pathl listed more than once in PATH\n");
                    $warnings++;
                }
                else {
                    $patharr{$pathl} = 1;
                }
            }
        }

        if ( $BADDIR_FLAG == 0 ) {
            print "\n$PASSSTR PATH variable does not contain group and/or world-writable directories\n";
        }
    }
    else {
        print "$INFOSTR Global PATH in $pathf seemingly not installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING GLOBAL ENVIRONMENT VARIABLE PATH $datestring ***");
}

# Subroutine to check FRU power status
#
sub frucheck {
    datecheck();
    print_header("*** BEGIN CHECKING FRU POWER STATUS $datestring ***");

    my @fruce = `frupower -C 2>/dev/null`;
    my @fruch = `frupower -I 2>/dev/null`;

    if ( @fruce != 0 ) {
        print "$INFOSTR Status of power for cells\n";
        print @fruce;

        if ( @fruch != 0 ) {
            print "\n$INFOSTR Status of power for I/O chassis\n";
            print @fruch;
        }
    }
    else {
        print "$INFOSTR Unsupported platform\n";
    }

    if ( "$Minor$Patch" >= 1123 ) {
        my $softpower = `softpower`;
        chomp($softpower);

        if ( $softpower == 0 ) {
            print "\n$INFOSTR Softpower detected on this hardware (value 0)\n";
        } 
        elsif ( $softpower == 1 ) {
            print "\n$INFOSTR Softpower not detected on this hardware (value 1)\n";
        } 
        else {
            print "\n$INFOSTR Softpower not supported on this hardware\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING FRU POWER STATUS $datestring ***");
}

# Subroutine to check LOCALE
#
sub localecheck {
    datecheck();
    print_header("*** BEGIN CHECKING LOCALES $datestring ***");

    my @alllocales = `locale -a`;

    if ( @alllocales != 0 ) {
        print "$INFOSTR Available locales\n";
        print @alllocales;
    }

    my @loccur = `locale`;

    if ( @loccur != 0 ) {
        print "\n$INFOSTR Current system-wide LOCALE\n";
        print @loccur;
    }

    datecheck();
    print_trailer("*** END CHECKING LOCALES $datestring ***");
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

# Subroutine to check GSP (MP) status
#
sub GSPcheck {
    datecheck();
    print_header("*** BEGIN CHECKING CONSOLE (GUARDIAN SERVICE PROCESSOR, ILO) STATUS $datestring ***");

    my $GSPdiagdev = "/dev/GSPdiag1";

    my @getMPInfo = `getMPInfo.cgi 2>/dev/null | awk NF`;
    if ( @getMPInfo ) {
        print "$INFOSTR Checking console via System Management Homepage CGI script getMPInfo.cgi\n";
        print @getMPInfo;
        print "\n";
    }

    my @HPMPCIM = `CIMUtil -e root/cimv2 HP_ManagementProcessor 2>/dev/null | awk NF`;
    if ( @HPMPCIM ) {
        print "$INFOSTR Checking console via SFM CIMUtil\n";
        print @HPMPCIM;
        print "\n";
    }

    my @cpuprop = `cprop -summary -c "Management Processor" 2>/dev/null`;
    if ( @cpuprop ) {
        print @cpuprop;
        print "\n";
    }

    my @sysrev = `sysrev 2>/dev/null`;
    if ( @sysrev ) {
        print "$INFOSTR Firmware versions\n";
        print @sysrev;
        print "\n";
    }
    else {
        if ("$GSP_server") {
            my @modules = qw(Net::Telnet);
            foreach my $mod (@modules) {
                eval "require $mod";
                if ( !"$@" ) {
                    import Net::Telnet;
                    $rv++;
                }
                elsif ( grep( /Can't locate/, "$@" ) ) {
                    print "$INFOSTR Cannot find Perl module $mod\n";
                    print "\n";
                }
                else {
                    print "$INFOSTR Cannot load $mod: $@\n";
                    print "\n";
                }
            }
        }
    }

    if ("$Vparcontrol") {
        if ( "$Vparcontrol" eq "$Hostname" ) {
            if ( -c "$GSPdiagdev" ) {
                @gspstat = `stty +queryGSP <$GSPdiagdev 2>&1`;
            }
        }
    }
    else {
        if ( -c "$GSPdiagdev" ) {
            @gspstat = `stty +queryGSP <$GSPdiagdev 2>&1`;
        }
    }

    if ( @gspstat != 0 ) {
        if ( grep( /not permitted/, @gspstat ) ) {
            print "$INFOSTR GSP enquiry via stty(1) possibly not ";
            print "supported on this platform or misconfigured\n";
        }

        print "\n$INFOSTR GSP enquiry via stty(1)\n";
        print "@gspstat\n";
    }
    else {
        print "$INFOSTR GSP enquiry via stty(1) possibly not supported on this platform or misconfigured\n";
        if ("$Vparcontrol") {
            print "$NOTESTR In vPar environment, GSP enquiry can only run on vPar control server\n";
        }
    }

    if ( "$rv" == 1 ) {
        if ("$GSP_server") {
            push( @GSPsvrs, $GSP_server );
        }
        else {
            if ( (! @sysrev) && (! @getMPInfo) ) {
                print "$INFOSTR GSP server not defined on the command-line\n";
                print "$NOTESTR Check the console manually\n";
            }
            printresults();
            exit(0);
        }

        ( undef, undef, undef, undef, @haddrs ) = gethostbyname($Hostname);
        foreach my $ma (@haddrs) {
            $SrvHostIP       = join( '.', unpack( 'C4', $ma ) );
            $SrvHostIPsubnet = join( '.', unpack( 'C3', $ma ) );
        }

        foreach $host (@GSPsvrs) {
            my $PING = 0;
            ( undef, undef, undef, undef, @addrs ) = gethostbyname($host);

            foreach my $a (@addrs) {
                $HostIP       = join( '.', unpack( 'C4', $a ) );
                $HostIPsubnet = join( '.', unpack( 'C3', $a ) );
            }

            if ( !CheckIP($HostIP) ) {
                print "$WARNSTR Invalid or incomplete subnet for GSP\n";
            }
            else {
                if ( "$SrvHostIPsubnet" && "$HostIPsubnet" ) {
                    if ( "$SrvHostIPsubnet" eq "$HostIPsubnet" ) {
                        print "$WARNSTR Server $Hostname ($SrvHostIP) ";
                        print
"and its GSP $host on the same subnet $SrvHostIPsubnet\n";
                        $warnings++;
                    }
                    else {
                        print "$PASSSTR Server $Hostname ($SrvHostIP) and ";
                        print "its GSP $host on different subnet\n";
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
                    print
                      "$WARNSTR $host is NOT reachable (first type ICMP)\n";
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
                    print
                      "$PASSSTR $host is reachable (second type ICMP)\n";
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
                            print "$INFOSTR Factory-default GSP account ";
                            print "should always be changed\n";

                            foreach $username ( keys %GSPPASSARRAY ) {
                                $tel = new Net::Telnet(
                                    Timeout => 15,
                                    Errmode => \&loginerror
                                );
                                $tel->open("$host");

                                if ( !"$username" ) {
                                    $Visible = "\"\"";
                                }
                                else {
                                    $Visible = $username;
                                }

                                $USERPASS = $GSPPASSARRAY{$username};

                                print
"\n$INFOSTR Trying to log into GSP as user $Visible\n";
                                if ( $tel->waitfor("/\Q$GSPlpr\E/") ) {
                                    $tel->print("$username");
                                    if ( $tel->waitfor("/\Q$GSPppr\E/") ) {
                                        if ( $tel->print("$USERPASS") ) {
                                            while ( $blk = $tel->get ) {
                                                if (
                                                    grep( /Processor/, $blk )
                                                  )
                                                {
                                                    $blk =~ s/^$//g;
                                                    $blk =~ tr/\n/ /;
                                                    $blk =~ s/^.*Version//;
                                                    $blk =~ s{\A \s* | \s* \z}{}gxm;
                                                    print
"$INFOSTR Successfully logged into GSP as user \"$Visible\"\n";
                                                    push(@CHECKARR,
"\n$INFOSTR Successfully logged into GSP as user \"$Visible\" with password \"$USERPASS\"\n");
                                                    print
"$INFOSTR GSP firmware version reported as $blk\n";
                                                }
                                                elsif (
                                                    grep( /Version/, $blk ) )
                                                {
                                                    $blk =~ s{\A \s* | \s* \z}{}gxm;
                                                    print $blk;
                                                }
                                                elsif (
                                                    grep( /Revision/, $blk ) )
                                                {
                                                    $blk =~ s/^$//g;
                                                    $blk =~ tr/\n/ /;
                                                    $blk =~ s/^.*Revision//;
                                                    $blk =~ s{\A \s* | \s* \z}{}gxm;
                                                    print
"$INFOSTR Successfully logged into GSP as user \"$Visible\"\n";
                                                    print
"$INFOSTR GSP firmware version reported as $blk\n";
                                                }
                                                $buf .= $blk;
                                                last if $buf =~ /$GSPprompt/;
                                            }
                                            $tel->print("");
                                            if (
                                                $tel->waitfor(
                                                    "/\Q$GSPprompt\E/")
                                              )
                                            {
                                                $tel->print("cm");
                                                if (
                                                    $tel->waitfor(
                                                        "/\Q$GSPCMprompt\E/")
                                                  )
                                                {
                                                    $tel->print("ls");
                                                    while ( $blk1 =
                                                        $tel->get )
                                                    {
                                                        $blk1 =~ s/^\s+//g;
                                                        $blk1 =~ s/^ls\s+//g;
                                                        $blk1 =~ s/^LS\s+//g;
                                                        $blk1 =~ s/^$//g;
                                                        $blk1 =~
s/^LAN status.*${GSPCMprompt}//g;
                                                        $blk1 =~
s/^.*${GSPCMprompt}//g;
                                                        $blk1 =~
s/^${GSPCMprompt}//g;
                                                        $blk1 =~
s/^\s+${GSPCMprompt}//g;
                                                        $blk1 =~
s/ .*${GSPCMprompt}//g;
                                                        $blk1 =~ s/\s+$//g;
                                                        $blk1 =~ s/\r\n/\n/g;
                                                        next
                                                          if
                                                          grep( /$Hostname/,
                                                            $blk1 );
                                                        next
                                                          if
                                                          grep( /LAN status/,
                                                            $blk1 );
                                                        next
                                                          if
                                                          grep( /^$/, $blk1 );

                                                        if (
                                                            !grep(
/${GSPCMprompt}/,
                                                                $blk1 )
                                                          )
                                                        {
                                                            print $blk1;
                                                        }
                                                    }
                                                    $buf1 .= $blk1;
                                                    last
                                                      if $buf1 =~
                                                      /\Q$GSPCMprompt\E/;
                                                }

                                                $tel->print("sysrev");
                                                while ( $blk1 = $tel->get ) {
                                                    $blk1 =~ s/^\s+//g;
                                                    $blk1 =~ s/^sysrev\s+//g;
                                                    $blk1 =~ s/^SYSREV\s+//g;
                                                    $blk1 =~
                                                      s/^.*${GSPCMprompt}//g;
                                                    $blk1 =~
                                                      s/.*${GSPCMprompt}//g;
                                                    $blk1 =~ s{\A \s* | \s* \z}{}gxm;
                                                    $blk1 =~ s/\r\n/\n/g;
                                                    print $blk1;
                                                }
                                                $buf1 .= $blk1;
                                                last
                                                  if $buf1 =~
                                                  /\Q$GSPCMprompt\E/;
                                            }
                                        }
                                        else {
                                            $tel->print("");
                                        }
                                    }
                                    else {
                                        print
"$INFOSTR GSP not displaying password prompt ";
                                        print
"(or \"$GSPppr\" needs to be changed)\n";
                                        $tel->print("");
                                        next;
                                    }
                                }
                                else {
                                    print "$INFOSTR GSP not displaying ";
                                    print "login prompt ";
                                    print
"(or \"$GSPlpr\" needs to be changed)\n";
                                    $tel->print("");
                                    next;
                                }
                                $ok = $tel->close;
                            }

                            if ( !"$blk" ) {
                                print "$NOTESTR It is recommended to ";
                                print
                                  "check the GSP firmware version manually\n";
                            }
                        }
                        else {
                            print "$ERRSTR Port $n\@$host is INACTIVE ";
                            print "or FILTERED\n";
                            print "$NOTESTR It is recommended to check ";
                            print "the GSP firmware version manually\n";
                        }
                        print;
                    }
                }
            }
        }
    }

    datecheck();
    print_trailer("*** END CHECKING CONSOLE (GUARDIAN SERVICE PROCESSOR, ILO) STATUS $datestring ***");
}

# Subroutine to check IPSec
#
sub IPseccheck {
    datecheck();
    print_header("*** BEGIN CHECKING IPSEC $datestring ***");

    if ( open( IG, "swlist -l product IPSec 2>&1 | awk NF |" ) ) {
        while (<IG>) {
            next if ( grep( /^$/, $_ ) );
            next if ( grep( /#/,  $_ ) );
            $_ =~ s{\A \s* | \s* \z}{}gxm;
            chomp($_);
            if ( grep( /ERROR/, $_ ) ) {
                $IPsecversion = q{};
                print "$INFOSTR IPSec seemingly not installed\n";
            }
            elsif ( grep( /IPSec/, $_ ) ) {
                ( undef, $IPsecversion, undef ) = split( /\s+/, $_ );
            }
        }
        close(IG);

        if ("$IPsecversion") {
            print "$INFOSTR IPSec version $IPsecversion installed\n";
        }

        my @ipsec_admin  = `ipsec_admin -s 2>/dev/null`;
        my @ipsec_conf   = `ipsec_config show all 2>/dev/null`;
        my @ipsec_report = `ipsec_report -all 2>/dev/null`;

        if ( @ipsec_admin != 0 ) {
            print "\n$INFOSTR IPSec admin configuration\n";
            print @ipsec_admin;
        }

        if ( @ipsec_conf != 0 ) {
            print "\n$INFOSTR IPSec configuration\n";
            print @ipsec_conf;
        }

        if ( @ipsec_report != 0 ) {
            print "\n$INFOSTR IPSec report\n";
            print @ipsec_report;
        }
    }
    else {
        print "$INFOSTR IPSec seemingly not installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING IPSEC $datestring ***");
}

# Subroutine to check drivers
#
sub asyncdrvchk {
    datecheck();
    print_header("*** BEGIN CHECKING ASYNCDSK DRIVER SETUP $datestring ***");

    print "$INFOSTR Checking minor number for pseudo driver $ASYNCDRV (used to speed up I/O operations for databases)\n";
    print "\n$NOTESTR Minor number 0x000007 => Asyncdsk enabled for immediate reporting, flushing CPU cache after reads, and I/O to timeout\n";
    print "$NOTESTR Minor number 0x000005 => Asyncdsk enabled for immediate reporting and I/O to timeout\n";
    print "$NOTESTR Minor number 0x000004 => Asyncdsk enabled for I/O to timeout\n";
    print "$NOTESTR Minor number 0x000002 => Asyncdsk enabled for flushing CPU cache after reads\n";
    print "$NOTESTR Minor number 0x000001 => Asyncdsk enabled for immediate reporting\n";
    print "$NOTESTR Minor number 0x000000 => Asyncdsk set at default value\n\n";

    if ( -c $ASYNCDRV ) {
        my $aminor = `ls -als $ASYNCDRV | awk '{print \$7}'`;
        chomp($aminor);
        if ( "$aminor" ) {
            my $ACUR =
"$aminor" eq "0x000007" ? "$ASYNCDRV enabled for immediate reporting, flushing CPU cache after reads, and I/O to timeout"
: "$aminor" eq "0x000005" ? "$ASYNCDRV enabled for immediate reporting and I/O to timeout"
: "$aminor" eq "0x000004" ? "$ASYNCDRV enabled for I/O to timeout"
: "$aminor" eq "0x000002" ? "$ASYNCDRV enabled for flushing CPU cache after reads"
: "$aminor" eq "0x000001" ? "$ASYNCDRV enabled for immediate reporting"
: "$ASYNCDRV set at default value";
            if ( "$ACUR" ) {
                print "$INFOSTR $ACUR\n";
            }
        }
        else {
            print
"$INFOSTR Minor number for $ASYNCDRV not found or wrongly calculated\n";
        }
    }
    else {
        print "$INFOSTR $ASYNCDRV not found on this server\n";
    }

    datecheck();
    print_trailer("*** END CHECKING ASYNCDSK DRIVER SETUP $datestring ***");
}

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
        print "$ERRSTR Lsdev failed\n";
        push(@CHECKARR, "\n$ERRSTR Lsdev failed\n");
    }

    if ( "$Minor$Patch" < 1120 ) {
       my $MASTERD = "/usr/conf/master.d";
       if ( -d "$MASTERD" ) {
           my @kc_get_deps = `kc_get_deps $MASTERD/*`;
           if ( @kc_get_deps ) {
               print "\n$INFOSTR Driver dependencies\n";
               print @kc_get_deps;
           }
       }
    }

    datecheck();
    print_trailer("*** END CHECKING LSDEV (DRIVERS) $datestring ***");
}

# Subroutine to check OLA/R
#
sub olacheck {
    datecheck();
    print_header("*** BEGIN CHECKING ONLINE ADDITION AND REPLACEMENT I/O CARD STATUS (OLA/R) $datestring ***");

    if ( "$Hardware" eq "ia64" ) {
        @olack = `olrad -q 2>/dev/null`;
    }
    else {
        @olack = `rad -q 2>/dev/null`;
    }

    if (@olack) {
        print @olack;
    }
    else {
        print "$INFOSTR OLA/R not used or check failed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING ONLINE ADDITION AND REPLACEMENT I/O CARD STATUS (OLA/R) $datestring ***");
}

# Subroutine to check PDC
#
sub PDCcheck {
    datecheck();
    print_header("*** BEGIN CHECKING PROCESSOR-DEPEND CODE (PDC) $datestring ***");

    if ( "$Hardware" ne "ia64" ) {
        my @PDCstat =
          `echo y | /usr/sbin/diag/contrib/pdcinfo 2>/dev/null | awk NF`;

        if (@PDCstat) {
            print @PDCstat;
        }
        else {
            print "$INFOSTR PDC status not available\n";
        }
    }
    else {
        my $LAST_FPLLOG =
          `ls /var/stm/logs/os/fpl.log* 2>/dev/null|sort -n|tail -1`;
        if ( -s "$LAST_FPLLOG" ) {
            my @PDCstat = `slview -d -f $LAST_FPLLOG 2>/dev/null | awk NF`;

            if (@PDCstat) {
                print @PDCstat;
            }
            else {
                print "$INFOSTR PDC status not available\n";
            }
        }
        else {
            print "$INFOSTR PDC status not available\n";
        }
    }

    datecheck();
    print_trailer("*** END CHECKING PROCESSOR-DEPEND CODE (PDC) $datestring ***");
}

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
        print_trailer("*** END CHECKING THIRD-PARTY LICENSE MANAGERS $datestring ***");
    }

    my @vselicense = `vselicense -m -g -n $Hostname 2>/dev/null`;

    if (@vselicense) {
        datecheck();
        print_header("*** BEGIN CHECKING VSE MANAGEMENT LICENSES $datestring ***");

        print @vselicense;

        datecheck();
        print_trailer("*** END CHECKING VSE MANAGEMENT LICENSES $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING VERITAS LICENSES $datestring ***");

    if ( @vxlicrep ) {
        print @vxlicrep;
    }

    if ( @vxlicarr ) {
        print "\n@vxlicarr";
    }

    if ( @vxcom2 ) {
        print "\n@vxcom2";
    }

    if ( "$EMSP_FLAG" > 0 ) {

        my @emcpp = `emcpreg -list 2>/dev/null`;

        if ( @emcpp  ) {
            datecheck();
            print_header("*** BEGIN CHECKING POWERPATH LICENSES $datestring ***");
            print @emcpp;
            datecheck();
            print_trailer("*** END CHECKING POWERPATH LICENSES $datestring ***");
        }
    }

    datecheck();
    print_trailer("*** END CHECKING VERITAS LICENSES $datestring ***");

    my @tsmlic = `query license 2>/dev/null`;
    if (@tsmlic) {
        datecheck();
        print_header("*** BEGIN CHECKING TIVOLI STORAGE MANAGER LICENSES $datestring ***");

        print @tsmlic;

        datecheck();
        print_trailer("*** END CHECKING TIVOLI STORAGE MANAGER LICENSES $datestring ***");
    }

    my @nsrlic = `printf "show;print type:nsr license\n" | nsradmin -i - 2>/dev/null`;
    if (@nsrlic) {
        datecheck();
        print_header("*** BEGIN CHECKING NETWORKER LICENSES $datestring ***");

        print @nsrlic;

        datecheck();
        print_trailer("*** END CHECKING NETWORKER LICENSES $datestring ***");
    }

    my @uvlictool = `uvlictool report_lic 2>/dev/null`;

    if (@uvlictool) {
        datecheck();
        print_header("*** BEGIN CHECKING IBM UNIVERSE LICENSES $datestring ***");

        print @uvlictool;

        datecheck();
        print_trailer("*** END CHECKING IBM UNIVERSE LICENSES $datestring ***");
    }

    my @db2licm = `db2licm -l 2>/dev/null`;

    if (@db2licm) {
        datecheck();
        print_header("*** BEGIN CHECKING IBM DB2 LICENSES $datestring ***");

        print @db2licm;

        datecheck();
        print_trailer("*** END CHECKING IBM DB2 LICENSES $datestring ***");
    }

    my @lmgrd = `lmgrd status 2>/dev/null`;

    if (@lmgrd) {
        datecheck();
        print_header("*** BEGIN CHECKING FLEXLM LICENSES $datestring ***");

        print @lmgrd;

        datecheck();
        print_trailer("*** END CHECKING FLEXLM LICENSES $datestring ***");
    }

    my @i4adminp = `i4admin -l p 2>/dev/null`;
    my @i4admins = `i4admin -l s 2>/dev/null`;
    my @i4tv = `i4tv 2>/dev/null`;

    if (@i4adminp) {
        datecheck();
        print_header("*** BEGIN CHECKING LICENSEPOWER/IFOR LICENSES $datestring ***");

        if (@i4adminp) {
            print @i4adminp;
            print "\n";
        }

        if (@i4admins) {
            print @i4admins;
            print "\n";
        }

        if (@i4tv) {
            print @i4tv;
        }

        datecheck();
        print_trailer("*** END CHECKING LICENSEPOWER/IFOR LICENSES $datestring ***");
    }

    my @powermtlic = `powermt check_registration 2>/dev/null`;

    if (@powermtlic) {
        datecheck();
        print_header("*** BEGIN CHECKING POWERPATH LICENSES $datestring ***");

        print @powermtlic;

        datecheck();
        print_trailer("*** END CHECKING POWERPATH LICENSES $datestring ***");
    }
}

# Subroutine to check LDAP client
#
sub LDAPclientcheck {
    datecheck();
    print_header("*** BEGIN CHECKING LDAP CLIENT $datestring ***");

    if ( "$LDAPCLIENT" > 0 ) {

        my $ldapcld_conf = "/etc/opt/ldapux/ldapclientd.conf";
        my $ldap_conf    = "/etc/opt/ldapux/ldapux_client.conf";

        if ( -s "$ldapcld_conf" ) {
            if ( open( LDP, "egrep -v ^# $ldapcld_conf | awk NF |" ) ) {
                print "$INFOSTR LDAP client is running\n";
                print "\n$INFOSTR LDAP-UX client daemon config file $ldapcld_conf\n";
                while (<LDP>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
            }
            close(LDP);
        }
        else {
            print "$WARNSTR Cannot open LDAP-UX client daemon config file $ldapcld_conf\n";
        }

        if ( -s "$ldap_conf" ) {
            if ( open( LDC, "egrep -v ^# $ldap_conf | awk NF |" ) ) {
                print "\n$INFOSTR LDAP-UX client config file $ldap_conf\n";
                while (<LDC>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
            }
            close(LDC);
        }
        else {
            print "\n$WARNSTR Cannot open LDAP-UX client config file $ldap_conf\n";
        }
    }

    if ( -s "$LDAPAUTHZ" ) {
        my @ldapauth = `cat $LDAPAUTHZ 2>/dev/null`;
        if ( @ldapauth != 0 ) {
            print "\n$INFOSTR PAM_AUTHZ policy validator in file $LDAPAUTHZ\n";
            print @ldapauth;
        }
    }

    my @LDAPPROXY = `ldap_proxy_config -p 2>/dev/null`;
    if ( @LDAPPROXY ) {
        print "\n$INFOSTR LDAP-UX proxy user configuration\n";
        print @LDAPPROXY;
    
        my @LDAPPROXYVRF = `ldap_proxy_config -v 2>/dev/null`;
        if ( @LDAPPROXYVRF ) {
            print "\n$INFOSTR LDAP-UX proxy user verification\n";
            print @LDAPPROXYVRF;
        }
    }

    my @LDAPCACHE = `display_profile_cache 2>/dev/null`;
    if ( @LDAPCACHE ) {
        print "\n$INFOSTR LDAP-UX configuration profile\n";
        print @LDAPCACHE;
    }

    if ( chdir $LDAPDIR ) {
        my @LDAPCERT = `certutil -d . -L 2>/dev/null`;
        if ( @LDAPCERT ) {
            print "\n$INFOSTR LDAP-UX server certificates\n";
            print @LDAPCERT;
        }
    }

    if ( open( LDIR, "ls $LDAPDIR2/slapd-* 2>/dev/null |" ) ) {
        while (<LDIR>) {
            if ( (-s "$_" ) && ( -T "$_" ) ) {
                my @LDARR = `egrep -v ^# $_ 2>/dev/null`;
                if ( @LDARR ) {
                    print "\n$INFOSTR HP-UX Directory Server configuration file $_\n";
                    print @LDARR;
                }
            }
        }
        close(LDIR);
    }

    my @klistk = `klist -k 2>/dev/null`;
    if ( @klistk ) {
        print
"\n$INFOSTR LDAP with Microsoft Active Directory Services keytab entries\n";
        print @klistk;
    }

    datecheck();
    print_trailer("*** END CHECKING LDAP CLIENT $datestring ***");
}

# Subroutine to check LDAP server
#
sub LDAPservercheck {
    datecheck();
    print_header("*** BEGIN CHECKING LDAP SERVER $datestring ***");

    if ( "$LDAPSERVER" > 0 ) {
        if ( ($NSDIRSVR_FLAG > 0) || ($RHDIRSVR_FLAG > 0) ) {

            print "$INFOSTR Netscape/Red Hat LDAP server seemingly running\n";
            print @ldapdaemon;
        }
        else {
            if ( ( -s "$sldap_conf" ) && ( -T "$sldap_conf" ) ) {
                if ( open( SLDP, "awk NF $sldap_conf |" ) ) {
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
                if ( open( LDP, "awk NF $ldap2_conf |" ) ) {
                    print "\n$INFOSTR LDAP config file $ldap2_conf\n";
                    while (<LDP>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                    }
                }
                close(LDP);
            }
            else {
                print "\n$INFOSTR Cannot open LDAP daemon config file $ldap2_conf\n";
            }
        }
    }

    my @ldapsearch = `ldapsearch -x -Z 2>/dev/null`;
    if ( @ldapsearch ) {
        print "\n$INFOSTR OPENLDAP search\n";
        print @ldapsearch;
    }

    my @ldapsearch2 = `ldapsearch -x 2>/dev/null`;
    if ( @ldapsearch2 ) {
        print "\n$INFOSTR LDAP-UX search\n";
        print @ldapsearch2;
    }

    my @ldapsearch3 = `ldapsearch -h localhost -b "" -s base "objectclass=*" 2>/dev/null`;
    if ( @ldapsearch3 ) {
        print "\n$INFOSTR LDAP server verification search\n";
        print @ldapsearch3;
    }

    my @ldapsearch4 = `ldapsearch -h localhost -b "cn=schema" -s base "objectclass=*" 2>/dev/null`;
    if ( @ldapsearch4 ) {
        print "\n$INFOSTR LDAP schema\n";
        print @ldapsearch4;
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
        print "\n$INFOSTR Cannot open LDAP daemon config file $ldap_conf\n";
    }

    datecheck();
    print_trailer("*** END CHECKING LDAP SERVER $datestring ***");
}

# Subroutine to check shared memory and semaphores
#
sub IPCScheck {
    datecheck();
    print_header("*** BEGIN CHECKING INTERPROCESS COMMUNICATION FACILITIES $datestring ***");

    my @ipcsstat = `ipcs -a 2>/dev/null`;
    my $ipcstot = `ipcs -mpb | sed -n '/^m/p' | awk '{total+=\$(NF-2) } END {printf("%d\n", total)}' 2>/dev/null | sed -e 's/^-//g'`;
    chomp($ipcstot);

    # The total space for 32-bit shared memory (without using tricks)
    # is 1.75 GB on PA-RISC, 2 GB on IPF (you share this range with
    # memory mapped I/O as well, on PA-RISC MMIO has a reserved 256 MB).
    #
    # Using Memory Windows / shared Q2 will allow a little more for those
    # applications in the same window.
    #
    my $MAXSHMEM = 1879048192;  # 1.75 GB
    if ( ${KERNEL_BITS} == 32  ) {
        if ( grep(/PA-RISC/i, $ARCH) ) {
            $MAXSHMEM = 1879048192;  # 1.75 GB
        }
        else {
            if ( grep(/IA64/i, $ARCH) ) {
                $MAXSHMEM = 2147483648;  # 2 GB
            }
        }

        print
"$INFOSTR For ${KERNEL_BITS}-bit systems, current shared memory total is $ipcstot bytes (maximum is $MAXSHMEM bytes)\n";
        print "\n";
    }

    my @pipcs = `pipcs 2>/dev/null`;

    if ( @ipcsstat ) {
        print @ipcsstat;
    }
    else {
        print "$INFOSTR IPC seemingly not used\n";
    }
    
    if ( @pipcs ) {
        print "\n";
        print @pipcs;
    }

    datecheck();
    print_trailer("*** END CHECKING INTERPROCESS COMMUNICATION FACILITIES $datestring ***");
}

# Subroutine to check disk quotas
#
sub QUOTAcheck {
    datecheck();
    print_header("*** BEGIN CHECKING FILE SYSTEM QUOTAS $datestring ***");

    if ( "$Minor$Patch" >= 1123 ) {
        my @quotck = `quot -v -a 2>/dev/null`;
        if ( @quotck ) {
            print "$INFOSTR Summary of file system ownership\n";
            print @quotck;
            print "\n";
        }
    }

    @quotastat = `quotacheck -a 2>/dev/null`;

    if ( @quotastat != 0 ) {
        print "$INFOSTR Quotas seemingly active\n";
        print @quotastat;
    }
    else {
        print "$INFOSTR Quotas not active\n";
    }

    datecheck();
    print_trailer("*** END CHECKING FILE SYSTEM QUOTAS $datestring ***");
}

# Subroutine to check ulimits
#
sub ULIMITcheck {
    datecheck();
    print_header("*** BEGIN CHECKING ULIMIT $datestring ***");

    my @ulimitstat = `ulimit -a 2>/dev/null`;

    if ( @ulimitstat ) {
        print @ulimitstat;
    }
    else {
        print "$INFOSTR Cannot check ulimits\n";
    }

    datecheck();
    print_trailer("*** END CHECKING ULIMIT $datestring ***");
}

#
# Get system's CPU number
#
sub CPUcheck {
    datecheck();
    print_header("*** BEGIN CHECKING CPU STATUS $datestring ***");

    if ( ! @CPU_no ) {
        @CPU_no = "$cpucount";
    }

    print "@CPU_no\n";
    print @CPUarray;

    datecheck();
    print_trailer("*** END CHECKING CPU STATUS $datestring ***");
}

#
# System's healthcheck bundle
#
sub HEALTHcheck {
    if ( $shealth > 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING HEALTHCHECK BUNDLE $datestring ***");

        my @SHC = `shc -V`;

        if ( @SHC != 0 ) {
            print "$INFOSTR SHC summary\n";
            print "@SHC";
        }

        my @SHCrules = `shcctl -lr 2>&1`;

        if ( @SHCrules != 0 ) {
            print "\n$INFOSTR SHC rules\n";
            print "@SHCrules";
        }

        datecheck();
        print_trailer("*** END CHECKING HEALTHCHECK BUNDLE $datestring ***");
    }
}

#
# Check sticky bit on common directories
#
sub STICKYcheck {
    datecheck();
    print_header("*** BEGIN CHECKING STICKY BIT ON SHARED DIRECTORIES $datestring ***");

    foreach my $commdir (@Stickyarr) {
        if ( !-d "$commdir" ) {
            print "$INFOSTR Directory $commdir does not exist\n";
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
    print_trailer("*** END CHECKING STICKY BIT ON SHARED DIRECTORIES $datestring ***");
}

# Subroutine to check PAM
#
sub PAMcheck {
    datecheck();
    print_header("*** BEGIN CHECKING PAM CONFIGURATION $datestring ***");

    my $pamcount = 0;

    if ( -s "$pam_conf" ) {
        if ( open( PAM, "egrep -v ^# $pam_conf | awk NF |" ) ) {
            print "$INFOSTR PAM config file $pam_conf\n";
            while (<PAM>) {
                if ( grep( /^$/, $_ ) ) {
                    if ( "$Minor$Patch" < 1120 ) {
                        if ( $pamcount == 0 ) {
                            push(@PAMARR, "$ERRSTR $pam_conf contains blank line\n");
                            push(@PAMARR, "$NOTESTR SAM fails with error \"option must be registered\" (HP DocID emr_na-c01167895-1)\n");
                            push(@CHECKARR, "\n$ERRSTR $pam_conf contains blank line\n");
                            $warnings++;
                            $pamcount++;
                        }
                    }
                    else {
                        next;
                    }
                }

                if ( grep( /libpam_keystroke/, $_ ) ) {
                    push(@PAMARR, "\n$PASSSTR $pam_conf supports keystroke logging\n");
                }
                
                print $_;
            }
        }
        close(PAM);
    }
    else {
        print
"$WARNSTR PAM config file $pam_conf is zero-length, missing or in different directory\n";
    }

    if ( -s "$pamuser_conf" ) {
        if ( open( PAMU, "egrep -v ^# $pamuser_conf | awk NF |" ) ) {
            print "$INFOSTR PAM config file $pamuser_conf\n";
            while (<PAMU>) {
                print $_;
            }
        }
        close(PAMU);
    }
    else {
        print
"$INFOSTR PAM config file $pamuser_conf is zero-length, missing or in different directory\n";
    }
   
    if ( @PAMARR ) {
        print "\n@PAMARR\n";
    }

    datecheck();
    print_trailer("*** END CHECKING PAM CONFIGURATION $datestring ***");

    my @pamkrbval = ();
    my $archlc = "$Hardware" eq "ia64" ? "ia${KERNEL_BITS}" 
                 : grep( /9000/, "$Hardware" ) ? "pa${KERNEL_BITS}"
                 : "pa${KERNEL_BITS}";

    datecheck();
    print_header("*** BEGIN CHECKING PAM KERBEROS VALIDATION $datestring ***");

    if ( "$Minor$Patch" >= 1123 ) {
        if ( "$archlc" ) {
            @pamkrbval = `pamkrbval -a $archlc -v 2>/dev/null`;
        }
    }
    else {
        @pamkrbval = `pamkrbval -v 2>/dev/null`;
    }

    if ( @pamkrbval != 0 ) {
        print "\n$INFOSTR PAM Kerberos validation\n";
        print @pamkrbval;
    }

    datecheck();
    print_trailer("*** END CHECKING PAM KERBEROS VALIDATION $datestring ***");
}

# Subroutine to check Security Containment
#
sub SCRBACcheck {
    datecheck();
    print_header("*** BEGIN CHECKING SECURITY CONTAINMENT (RBAC) $datestring ***");

    if ( "$RBAC_FLAG" == 1 ) {
        my @rbacck = `rbacdbchk 2>/dev/null`;
        if ( @rbacck != 0 ) {
            print "$WARNSTR RBAC database syntax tool reports errors\n";
                print @rbacck;
                push(@CHECKARR, "\n$WARNSTR RBAC database syntax tool reports errors\n");
                $warnings++;
        }
        else {
            print "$PASSSTR RBAC database syntax tool reports no errors\n";
        }

        my $acps = "/etc/acps.conf";
        if ( -s "$acps" ) {
            if ( open( ACP, "egrep -v ^# $acps | awk NF |" ) ) {
                print "\n$INFOSTR ACPS configuration file $acps\n";
                while (<ACP>) {
                    next if ( grep( /^$/, $_ ) );
                    print $_;
                }
            }
            close(ACP);
        }

        my @rbaclist = `authadm list 2>/dev/null`;
        if ( @rbaclist != 0 ) {
            print "\n$INFOSTR RBAC authorisations\n";
            print @rbaclist;
        }
        else {
            print "\n$INFOSTR RBAC authorisations not defined\n";
        }

        my @roleadm = `roleadm list 2>/dev/null`;
        if ( @roleadm != 0 ) {
            print "\n$INFOSTR RBAC roles\n";
            print @roleadm;
        }
        else {
            print "\n$INFOSTR RBAC roles not defined\n";
        }

        my @RBACARR = `ls $RBACDIR 2>/dev/null`;
        my @MYRBARR = ();
        foreach my $rbacfile (@RBACARR) {
            chomp($rbacfile);

            if ( (-s "$RBACDIR/$rbacfile") && ( -T "$RBACDIR/$rbacfile") ) {
                if ( open( RBC, "egrep -v ^# $RBACDIR/$rbacfile | awk NF |" ) ) {
                    print "\n";
                    print "$INFOSTR RBAC configuration in $RBACDIR/$rbacfile\n";
                    while (<RBC>) {
                        next if ( grep( /^$/, $_ ) );
                        print $_;
                        $_ =~ s/^\s+//g;
                        if ( "$rbacfile" eq "rbac.conf" ) { 
                            if ( grep( /^KEY_STROKE_LOGGING/, $_ ) ) {
                                ( undef, $keystroke ) = split( /=/, $_ );
                                chomp($keystroke);
                                if ( "$keystroke" == 1 ) {
                                    push(@MYRBARR, "\n$PASSSTR RBAC configured to support keystroke logging via \"KEY_STROKE_LOGGING\" in $RBACDIR/$rbacfile\n");
                                }
                                else {
                                    push(@MYRBARR, "\n$INFOSTR RBAC not configured to support keystroke logging via \"KEY_STROKE_LOGGING\" in $RBACDIR/$rbacfile\n");
                                }
                            }

                            if ( grep( /^KEY_STROKE_LOGSIZE/, $_ ) ) {
                                ( undef, $keylimit ) = split( /=/, $_ );
                                chomp($keylimit);
                                if ( "$keylimit" ) {
                                    push(@MYRBARR, "\n$PASSSTR RBAC configured to limit per-login-session keystroke logging to $keybanner MB in $RBACDIR/$rbacfile\n");
                                }
                                else {
                                    push(@MYRBARR, "\n$INFOSTR RBAC configured to limit per-login-session keystroke logging to 1 MB in $RBACDIR/$rbacfile\n");
                                }
                            }

                            if ( grep( /^KEY_STROKE_BANNERPAGE_LOG_ENABLE/, $_ ) ) {
                                ( undef, $keybanner ) = split( /=/, $_ );
                                chomp($keybanner);
                                if ( "$keybanner" == 1 ) {
                                    push(@MYRBARR, "\n$PASSSTR RBAC configured to support keystroke banner page logging via \"KEY_STROKE_BANNERPAGE_LOG_ENABLE\" in $RBACDIR/$rbacfile\n");
                                }
                                else {
                                    push(@MYRBARR, "\n$INFOSTR RBAC not configured to support keystroke banner page logging via \"KEY_STROKE_BANNERPAGE_LOG_ENABLE\" in $RBACDIR/$rbacfile\n");
                                }
                            }
                        }
                    }
                }
                close(RBC);
            }
        }

        if ( @MYRBARR ) {
            print @MYRBARR;
        }
    }
    else {
        print "$INFOSTR RBAC seemingly not in use\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SECURITY CONTAINMENT (RBAC) $datestring ***");

    if ( "$Minor$Patch" >= 1131 ) {
       $GETRULES_FLAG = "-c";
    }

    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING COMPARTMENTS $datestring ***");

        my @cmpttune = `cmpt_tune -q 2>/dev/null`;
        if ( @cmpttune ) {
            print "$INFOSTR Current state of compartments (/stand/current kernel)\n";
            print @cmpttune;
        }
        else {
            print "$INFOSTR Compartments not used\n";
        }

        my @setrules = `setrules -p 2>/dev/null`;
        if ( @setrules ) {
            print "\n$INFOSTR Checking compartment configuration status\n";
            print @setrules;
        }

        my @cmpttune2 = `cmpt_tune -Q 2>/dev/null`;
        if ( @cmpttune2 ) {
            print "\n$INFOSTR Nextboot state of compartments (/stand/nextboot kernel)\n";
            print @cmpttune2;
        }
        
        my @getrules = `getrules $GETRULES_FLAG 2>/dev/null`;
        if ( @getrules ) {
            print "\n$INFOSTR Checking compartment rules\n";
            print @getrules;

            my @getrulesL = `getrules -L 2>/dev/null`;
            if ( @getrulesL ) {
                print
"\n$INFOSTR Compartment names associated with the logical interfaces\n";
                print @getrulesL;
            }

            my @getrulesn = `getrules -n 2>/dev/null`;
            if ( @getrulesn ) {
                print
"\n$INFOSTR Network system rules for the compartments\n";
                print @getrulesn;
            }

            my @getrulesf = `getrules -f 2>/dev/null`;
            if ( @getrulesf ) {
                print "\n$INFOSTR File system rules for the compartments\n";
                print @getrulesf;
            }

            my @getrulesi = `getrules -i 2>/dev/null`;
            if ( @getrulesi ) {
                print "\n$INFOSTR IPC system rules for the compartments\n";
                print @getrulesi;
            }

            my @getrulesp = `getrules -p 2>/dev/null`;
            if ( @getrulesp ) {
                print "\n$INFOSTR Privilege rules for the compartments\n";
                print @getrulesp;
            }

            if ( -s $CMPTHARDCFG ) {
                my @cmphard = `grep -v ^# $CMPTHARDCFG 2>/dev/null | awk NF`;
                if (@cmphard) {
                    print
"\n$INFOSTR Compartment hardlinks mountpoint file $CMPTHARDCFG\n";
                    print @cmphard;
                }
            }

            my @cmptfile = `ls $CMPTDIR/* 2>/dev/null`;
            foreach my $cmptf ( @cmptfile ) {
                chomp($cmptf);
                if ( -f "$cmptf" && -s "$cmptf" ) {
                    my @cmptarr = `awk NF $cmptf`;
                    if ( @cmptarr ) {
                        print "$INFOSTR Configuration file $cmptf\n";
                        print @cmptarr;
                        print "\n";
                    }
                }
            }

            my @vhardlinks = `vhardlinks 2>/dev/null`;
            if ( @vhardlinks ) {
                print "\n$INFOSTR Consistency check for compartment rules with multiple hard links\n";
                print @vhardlinks;
            }
        }
        else {
            print
"\n$INFOSTR Compartment rules seemingly not used on this platform\n";
        }

        my @getprocxsec = `getprocxsec -c 2>/dev/null`;
        if ( @getprocxsec ) {
            print "\n$INFOSTR Checking Security containment\n";
            print @getprocxsec;
        }

        my @srps = `srp -status 2>/dev/null`;
        if ( @srps ) {
            print "\n$INFOSTR Secure Resource Partitions (SRP) status\n";
            print @srps;
        }

        my @srpl = `srp -list -v 2>/dev/null`;
        if ( @srpl ) {
            print "$INFOSTR Secure Resource Partitions (SRP) listing\n";
            print @srpl;
        }

        my @srpsys = `srp_sys -list -v 2>/dev/null`; 
        if ( @srpsys ) {
            print "\n$INFOSTR Secure Resource Partitions (SRP) srp_sys status\n";
            print @srpsys;
        }

        if ( open( SRP, "srp -l 2>/dev/null |" ) ) {
            while (<SRP>) {
                print $_;
                next if ( grep( /^$/, $_ ) );
                next if ( grep( /^Compartment|----|____/, $_ ) );
                ( $COMPID, undef ) = split( /\s+/, $_ );
                if ( "$COMPID" ) {
                    chomp($COMPID);
                    push(@COMPARR, $COMPID);
                }
            }
            close(SRP);

            if ( @COMPARR ) {
                print "\n$INFOSTR Checking Secure Resource Partitions (SRP)\n";
                foreach my $CENT (@COMPARR) {
                    my @srpl = `srp -l $CENT -v 2>/dev/null`; 
                    if ( @srpl ) {
                        print "\n$INFOSTR Checking compartment $CENT\n";
                        print @srpl;
                    }
                }
            }

            if ( "$Minor$Patch" >= 1131 ) {
                if ( ("$ENV{'SW_ALLOW_LOCAL_SRP_OPS'}" == 1) || ("$ENV{'SW_ALLOW_LOCAL_SRP_OPS'}" eq 'TRUE') ) {
                    print "\n$INFOSTR Environment variable \"SW_ALLOW_LOCAL_SRP_OPS\" enabled\n";
                    print "\n$NOTESTR System container supports swinstall\n";
                } else {
                    print "\n$INFOSTR Environment variable \"SW_ALLOW_LOCAL_SRP_OPS\" not set to \"1\" or \"TRUE\"\n";
                    print "\n$NOTESTR System container does not support swinstall\n";
                }
            }
        }
        else {
            print "$INFOSTR Secure Resource Partitions not in use\n";
        }

        datecheck();
        print_trailer("*** END CHECKING COMPARTMENTS $datestring ***");
    }
}

# Subroutine to check Capacity Advisor
#
sub CAPADVcheck {
    datecheck();
    print_header("*** BEGIN CHECKING CAPACITY ADVISOR $datestring ***");

    if ( $CAPADV_FLAG ) {
        print "$INFOSTR Capacity Advisor seemingly installed\n\n";
        my $mxret = system "mxstatus 2>/dev/null";
        my $MXVALUE = ( $mxret >> 8 ) && 0xff;
        chomp($MXVALUE);
        if ( "$MXVALUE" == 0 ) {
            my @capprof = `capprofile -lv 2>/dev/null`;
            if (@capprof) {
                print "\n$INFOSTR Capacity Advisor profiles\n";
                print @capprof;
            
                my @capproft = `capprofile -lt 2>/dev/null`;
                if (@capproft) {
                    print "\n$INFOSTR Capacity Advisor profiles and time ranges of data stored\n";
                    print @capproft;
                }
            }
            else {
                print "$INFOSTR Capacity Advisor profiles seemingly not defined\n";
            }
        }
    }
    else {
        print "$INFOSTR Capacity Advisor seemingly not installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING CAPACITY ADVISOR $datestring ***");
}

# Subroutine to check WorkLoad Manager (WLM)
#
sub WLMcheck {
    datecheck();
    print_header("*** BEGIN CHECKING WORKLOAD MANAGER $datestring ***");

    if ( $WLMD_FLAG > 0 ) {
        print "$INFOSTR WLM seemingly configured\n";
    }
    else {
        print "$INFOSTR WLM seemingly not configured\n";
    }

    my @gwlmlist = `gwlm list 2>/dev/null`;
    if (@gwlmlist) {
        print "\n$INFOSTR gWLM seemingly configured\n";
        print @gwlmlist;
    }

    my @gwlmstatus2 = `gwlmstatus --verbose --timeout=2 2>/dev/null`;
    if (@gwlmstatus2) {
        print "\n$INFOSTR gWLM status for the managed node\n";
        print @gwlmstatus2;
    }

    my @gwlmlistkeys = `gwlmlistkeys 2>/dev/null`;
    if (@gwlmlistkeys) {
        print "\n$INFOSTR gWLM list keys\n";
        print @gwlmlistkeys;
    }

    my @gwlmmon = `gwlm monitor --count=1 2>/dev/null`;
    if (@gwlmmon) {
        print "\n$INFOSTR gWLM monitor\n";
        print @gwlmmon;
    }

    my @gwlmres = `gwlmreport resourceaudit 2>/dev/null`;
    if (@gwlmres) {
        print "\n$INFOSTR gWLM resource audit\n";
        print @gwlmres;
    }

    my @gwlmabn = `gwlmreport abnormalutil 2>/dev/null`;
    if (@gwlmabn) {
        print "\n$INFOSTR gWLM abnormal utilization status\n";
        print @gwlmabn;
    }

    my @gwlmtop = `gwlmreport topborrowers 2>/dev/null`;
    if (@gwlmtop) {
        print "\n$INFOSTR gWLM top borrowers status\n";
        print @gwlmtop;
    }

    if ( -s $GWLMPROP ) {
        my @GWLMprop = `grep -v ^# $GWLMPROP 2>/dev/null | awk NF`;
        if (@GWLMprop) {
            print "\n$INFOSTR gWLM properties file $GWLMPROP\n";
            print @GWLMprop;
        }
    }

    if ( -s $GWLMCMSPROP ) {
        my @GWLMlist = `grep -v ^# $GWLMCMSPROP 2>/dev/null | awk NF`;
        if (@GWLMlist) {
            print "\n$INFOSTR gWLM CMS properties file $GWLMCMSPROP\n";
            print @GWLMlist;
        }
    }

    if ( -s $GWLMAGTPROP ) {
        my @GWLMAGTlist = `grep -v ^# $GWLMAGTPROP 2>/dev/null | awk NF`;
        if (@GWLMAGTlist) {
            print "\n$INFOSTR gWLM agent properties file $GWLMAGTPROP\n";
            print @GWLMAGTlist;
        }
    }

    if ( -s $ADPROP ) {
        my @ADlist = `grep -v ^# $ADPROP 2>/dev/null | awk NF`;
        if (@ADlist) {
            print "\n$INFOSTR Application Discovery properties file $ADPROP\n";
            print @ADlist;
        }
    }

    if ( -s $MXPATHPROP ) {
        my @MXpathlist = `grep -v ^# $MXPATHPROP 2>/dev/null | awk NF`;
        if (@MXpathlist) {
            print "\n$INFOSTR SIM Audit log path properties file $MXPATHPROP\n";
            print @MXpathlist;
        }
    }

    if ( -s $SIMPROP ) {
        my @SIMlist = `grep -v ^# $SIMPROP 2>/dev/null | awk NF`;
        if (@SIMlist) {
            print "\n$INFOSTR SIM global properties file $SIMPROP\n";
            print @SIMlist;
        }
    }

    my @gwlmstatus = `gwlmstatus --verbose --timeout=2 2>/dev/null`;
    if (@gwlmstatus) {
        print "\n$INFOSTR gWLM status for the managed node\n";
        print @gwlmstatus;
    }

    if ( -s $WLMCONF ) {
        my @WLMlist = `grep -v ^# $WLMCONF 2>/dev/null | awk NF`;
        if (@WLMlist) {
            print "\n$INFOSTR Configuration file $WLMCONF\n";
            print @WLMlist;
        }
    }

    my @WLMhost = `wlminfo host 2>/dev/null`;
    if (@WLMhost) {
        print "\n$INFOSTR WLM hosts\n";
        print @WLMhost;
    }

    my @WLMslo = `wlminfo slo -v 2>/dev/null`;
    if (@WLMslo) {
        print "\n$INFOSTR WLM SLOs\n";
        print @WLMslo;
    }

    my @WLMingrp = `wlminfo group -v 2>/dev/null`;
    if (@WLMingrp) {
        print "\n$INFOSTR WLM info group\n";
        print @WLMingrp;
    }

    my @WLMmetric = `wlminfo metric 2>/dev/null`;
    if (@WLMmetric) {
        print "\n$INFOSTR WLM metric\n";
        print @WLMmetric;
    }

    my @WLMvpar = `wlminfo vpar 2>/dev/null`;
    if (@WLMvpar) {
        print "\n$INFOSTR WLM vPar\n";
        print @WLMvpar;
    }

    my @WLMpar = `wlminfo par 2>/dev/null`;
    if (@WLMpar) {
        print "\n$INFOSTR WLM Par\n";
        print @WLMpar;
    }

    datecheck();
    print_trailer("*** END CHECKING WORKLOAD MANAGER $datestring ***");
}

# Subroutine to check WBEM Common Information Model (CIM)
#
sub CIMcheck {
    datecheck();
    print_header("*** BEGIN CHECKING WBEM COMMON INFORMATION MODEL (CIM) $datestring ***");

    if ( $CIM_FLAG > 0 ) {
        print "$INFOSTR WBEM CIM server seemingly configured\n";
    }
    else {
        print "$INFOSTR WBEM CIM server seemingly not configured\n";
    }

    my @cimserver = `cimserver -v 2>/dev/null`;
    if (@cimserver) {
        print "\n$INFOSTR CIM server\n";
        print @cimserver;
    }

    my @cimconfig = `cimconfig -l -c 2>/dev/null`;
    if (@cimconfig) {
        print "\n$INFOSTR CIM current configuration\n";
        print @cimconfig;

        my @cimprovider = `cimprovider -l -s 2>/dev/null`;
        if (@cimprovider) {
            print "\n$INFOSTR Registered CIM providers and their current status\n";
            print @cimprovider;
        }

        my @cimauth = `cimauth -l -s 2>/dev/null`;
        if (@cimauth) {
            print "\n$INFOSTR CIM authorisations\n";
            print @cimauth;
        }

        my @amgrd = `amgrd -connectionstatus 2>/dev/null`;
        if (@amgrd) {
            print "\n$INFOSTR Application Discovery agent config status\n";
            print @amgrd;

            my @agent_config = `agent_config -c 2>/dev/null`;
            if (@agent_config) {
                print "\n$INFOSTR Application Discovery agent config status\n";
                print @agent_config;
            }

            my @agent_configm = `agent_config -amx 2>/dev/null`;
            if (@agent_configm) {
                print "\n$INFOSTR Application Discovery agent certificate status\n";
                print @agent_configm;
            }

            my @agent_configt = `agent_config -printAgentTrust 2>/dev/null`;
            if (@agent_configt) {
                print "\n$INFOSTR Application Discovery agent trust status\n";
                print @agent_configt;
            }
        }
        else {
            print "$INFOSTR Application Discovery status not available\n";
        }
    }

    my @HPCIMCL = `CIMUtil -e root/cimv2 HP_Cluster 2>/dev/null`;
    if ( @HPCIMCL ) {
        print "\n$INFOSTR Checking HP_Cluster with CIMUtil\n";
        print @HPCIMCL;
    }

    my @HPCIMNO = `CIMUtil -e root/cimv2 HP_Node 2>/dev/null`;
    if ( @HPCIMNO ) {
        print "\n$INFOSTR Checking HP_Node with CIMUtil\n";
        print @HPCIMNO;
    }

    my @HPCIMSGLOCK = `CIMUtil -e root/cimv2 HP_SGLockObject 2>/dev/null`;
    if ( @HPCIMSGLOCK ) {
        print "\n$INFOSTR Checking HP_SGLockObject with CIMUtil\n";
        print @HPCIMSGLOCK;
    }

    my @HPCIMST = `CIMUtil -e root/cimv2 CIM_StorageVolume 2>/dev/null`;
    if ( @HPCIMST ) {
        print "\n$INFOSTR Checking CIM_StorageVolume with CIMUtil\n";
        print @HPCIMST;
    }

    my @HPCIMSW = `CIMUtil -e root/cimv2 HP_ClusterSoftware 2>/dev/null`;
    if ( @HPCIMSW ) {
        print "\n$INFOSTR Checking HP_ClusterSoftware with CIMUtil\n";
        print @HPCIMSW;
    }

    my @HPCIMNI = `CIMUtil -e root/cimv2 HP_NodeIdentity 2>/dev/null`;
    if ( @HPCIMNI ) {
        print "\n$INFOSTR Checking HP_NodeIdentity with CIMUtil\n";
        print @HPCIMNI;
    }

    my @HPCIMCS = `CIMUtil -e root/cimv2 HP_ParticipatingCS 2>/dev/null`;
    if ( @HPCIMCS ) {
        print "\n$INFOSTR Checking HP_ParticipatingCS with CIMUtil\n";
        print @HPCIMCS;
    }

    my @HPCIMIPP = `CIMUtil -e root/cimv2 CIM_IPProtocolEndpoint 2>/dev/null`;
    if ( @HPCIMIPP ) {
        print "\n$INFOSTR Checking CIM_IPProtocolEndpoint with CIMUtil\n";
        print @HPCIMIPP;
    }

    my @HPCIMDEP = `CIMUtil -e root/cimv2 CIM_Dependency 2>/dev/null`;
    if ( @HPCIMDEP ) {
        print "\n$INFOSTR Checking CIM_Dependency with CIMUtil\n";
        print @HPCIMDEP;
    }

    my @HPCIMEL = `CIMUtil -e root/cimv2 CIM_LogicalElement 2>/dev/null`;
    if ( @HPCIMEL ) {
        print "\n$INFOSTR Checking CIM_LogicalElement with CIMUtil\n";
        print @HPCIMEL;
    }

    my @HPCIMAP = `CIMUtil -e root/cimv2 CIM_ServiceAccessPoint 2>/dev/null`;
    if ( @HPCIMAP ) {
        print "\n$INFOSTR Checking CIM_ServiceAccessPoint with CIMUtil\n";
        print @HPCIMAP;
    }

    my @HPCIMGS = `CIMUtil -e root/cimv2 HP_GroupSystemSpecificCollection 2>/dev/null`;
    if ( @HPCIMGS ) {
        print "\n$INFOSTR Checking HP_GroupSystemSpecificCollection with CIMUtil\n";
        print @HPCIMGS;
    }

    datecheck();
    print_trailer("*** END CHECKING WBEM COMMON INFORMATION MODEL (CIM) $datestring ***");

    if ( "$SFM_FLAG" > 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING EVWEB $datestring ***");

        print "$INFOSTR Event Archive Database service is running (daemon sfmdb)\n";

        my @evweblst = `evweb list -v 2>/dev/null | awk NF`;
        if (@evweblst) {
            print "$INFOSTR Internal event listing\n";
            print @evweblst;
            print "\n";
        }
        else {
            print "$INFOSTR No event listing\n";
            print "\n";
        }

        my @evwebint = `evweb subscribe -L -b internal 2>/dev/null | awk NF`;
        if (@evwebint) {
            print "$INFOSTR Internal event subscriptions\n";
            print @evwebint;
            print "\n";
        }
        else {
            print "$INFOSTR No internal event subscriptions\n";
            print "\n";
        }

        my @evwebext = `evweb subscribe -L -b external 2>/dev/null | awk NF`;
        if (@evwebext) {
            print "\n$INFOSTR External event subscriptions\n";
            print @evwebext;
            print "\n";
        }
        else {
            print "\n$INFOSTR No external event subscriptions\n";
            print "\n";
        }

        my @evwebview = `evweb eventviewer -L 2>/dev/null | awk NF`;
        if (@evwebview) {
            print "\n$INFOSTR Event viewer status\n";
            print @evwebview;
        }

        if ( -s "$EVWEBCONF" ) {
            my @evwebcat = `egrep -v ^# $EVWEBCONF 2>/dev/null | awk NF`;
            if (@evwebcat) {
                print "\n$INFOSTR Default configuration file $EVWEBCONF exists\n";
                print @evwebcat;
            }
        }

        datecheck();
        print_trailer("*** END CHECKING EVWEB $datestring ***");

        datecheck();
        print_header("*** BEGIN CHECKING EMS HARDWARE MONITORS $datestring ***");

        if ( "$Minor$Patch" >= 1120 ) {
            my @sfmconfig = `sfmconfig -w -q 2>/dev/null`;
            if (@sfmconfig) {
                print @sfmconfig;
                print "\n";
            }
        }

        my @sfmconfig2 = `sfmconfig -a -L 2>/dev/null`;
        if (@sfmconfig2) {
            print @sfmconfig2;
            print "\n";
        }

        my @monconfig = `echo q | monconfig 2>/dev/null | grep -i version`;
        if (@monconfig) {
            print @monconfig;
            print "\n";
        }

        my @moncheck = `moncheck 2>/dev/null`;
        if (@moncheck) {
            print "\n$INFOSTR EMS status\n";
            print @moncheck;
        }
        else {
            print "$INFOSTR EMS monitors seemingly disabled\n";
        }

        my @EMSARR = ();
        my $emsresid = q{};

        if ( open( EMSCLI, "emscli -l 2>/dev/null | " ) ) {
            print "\n$INFOSTR EMS list requests\n";
            while (<EMSCLI>) {
                print $_;
                next if grep( /Req ID/, $_ );
                chomp($_);
                ( $emsresid, undef ) = split( /\s+/, $_ );
                push(@EMSARR, $emsresid);
            }
            close(EMSCLI);

            if ( @EMSARR ) {
                foreach my $emsentry (@EMSARR) {
                    chomp($emsentry);
                    my @emsr = `emscli -v $emsentry 2>/dev/null`;
                    if ( @emsr ) {
                        print "\n$INFOSTR EMS request $emsentry\n";
                        print "@emsr\n";
                    }
                }
            }
        }

        my @resls = `resls / 2>/dev/null`;
        if (@resls) {
            print "\n$INFOSTR List configured resources\n";
            print @resls;
        }

        if ( -s $EMS_ULIMIT ) {
            print "\n$WARNSTR File $EMS_ULIMIT exists\n";
            push(@CHECKARR, "\n$WARNSTR File $EMS_ULIMIT exists\n");
            $warnings++;

            print
"$NOTESTR The EMS log files in /etc/opt/resmon/log are limited to 500 KB
in size and are then moved to <logfile>.old. The previous *.old
gets lost. The limit of 500 KB per logfile can be removed by creating
the file /etc/opt/resmon/unlimited_log.

Be careful with creating this file. Growing EMS log files
can easily fill up root file system.\n";
        }
    }
    else {
        print
"\n$INFOSTR Event Archive Database service is not running (daemon sfmdb missing)\n";
    }

    datecheck();
    print_header("*** END CHECKING EMS HARDWARE MONITORS $datestring ***");
}

# Subroutine to check Revision and Configuration Management (RCM)
#
sub RCMcheck {
    datecheck();
    print_header("*** BEGIN CHECKING REVISION AND CONFIGURATION MANAGEMENT $datestring ***");

    if ( $RCM_FLAG > 0 ) {
        print "$INFOSTR RCM seemingly installed\n";

        my @RCMVER = `rcmcollect -version 2>/dev/null`;
        if (@RCMVER) {
            print @RCMVER;
        }

        my @rcmstart = `grep -v ^# $RCMCONF 2>/dev/null | awk NF`; 
        if ( @rcmstart ) {
            print "\n$INFOSTR $RCMCONF exists\n";
            print @rcmstart;
        }
    }
    else {
        print "$INFOSTR RCM seemingly not installed\n";
    }

    datecheck();
    print_trailer("*** END CHECKING REVISION AND CONFIGURATION MANAGEMENT $datestring ***");
}

# Subroutine to check Process Resource Manager (PRM)
#
sub PRMcheck {
    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING REAL TIME EXTENSIONS FOR PROCESSOR SETS $datestring ***");

        my @psrset = `psrset -i 2>/dev/null`;
        if (@psrset) {
            print @psrset;

            my @psrsetp = `psrset -p 2>/dev/null`;
            if (@psrsetp) {
                print "\n$INFOSTR Processor set assignment\n";
                print @psrsetp;
            }
        }
        else {
            print "$INFOSTR Psrset seemingly not configured\n";
        }

        datecheck();
        print_trailer("*** END CHECKING REAL TIME EXTENSIONS FOR PROCESSOR SETS $datestring ***");
    }

    datecheck();
    print_header("*** BEGIN CHECKING PROCESS RESOURCE MANAGER $datestring ***");

    if ( $PRM_FLAG > 0 ) {
        print "$INFOSTR PRM seemingly configured\n";

        my @PRMrun = `prmconfig 2>/dev/null`;
        if (@PRMrun) {
            print "\n$INFOSTR Current PRM status\n";
            print @PRMrun;
        }

        my @PRMcs = `prmconfig -s 2>/dev/null`;
        if (@PRMcs) {
            print "\n$INFOSTR PRM config syntax check\n";
            print @PRMcs;
        }

        my @PRMlist = `prmlist 2>/dev/null`;
        if (@PRMlist) {
            print "\n$INFOSTR Current PRM configuration\n";
            print @PRMlist;
        }

        my @PRMmon = `prmmonitor 2>/dev/null`;
        if (@PRMmon) {
            print "\n$INFOSTR Current PRM monitor\n";
            print @PRMmon;
        }

        my @PRMavail = `prmavail 2>/dev/null`;
        if (@PRMavail) {
            print "\n$INFOSTR PRM resource availability\n";
            print @PRMavail;
        }

        my @PRMavailf = `prmavail -f 2>/dev/null`;
        if (@PRMavailf) {
            print "\n$INFOSTR PRM resource features availability\n";
            print @PRMavailf;
        }

        my @psP = `ps -efx -Pz 2>/dev/null`;
        if (@psP) {
            print "\n$INFOSTR Process information with PRM groups\n";
            print @psP;
        }

        my @acctcom = `acctcom -P 2>/dev/null`;
        if (@acctcom) {
            print "\n$INFOSTR PRM history information about all groups\n";
            print @acctcom;
        }
    }
    else {
        print "$INFOSTR PRM seemingly not running\n";
    }

    if ( -s $PRMCONF ) {
        my @PRMlist = `grep -v ^# $PRMCONF 2>/dev/null | awk NF`;
        if (@PRMlist) {
            print "\n$INFOSTR Configuration file $PRMCONF\n";
            print @PRMlist;
        }
    }

    if ( -s $PRMRUNCONF ) {
        my @PRMst = `grep -v ^# $PRMRUNCONF 2>/dev/null | awk NF`;
        if (@PRMst) {
            print "\n$INFOSTR Configuration file $PRMRUNCONF\n";
            print @PRMst;
        }
    }

    if ( -s $PRMRUNCONF2 ) {
        my @PRMst2 = `grep -v ^# $PRMRUNCONF2 2>/dev/null | awk NF`;
        if (@PRMst2) {
            print "\n$INFOSTR Configuration file $PRMRUNCONF2\n";
            print @PRMst2;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING PROCESS RESOURCE MANAGER $datestring ***");
}

# Subroutine to check Host Intrusion Detection System (HIDS)
#
sub HIDScheck {
    datecheck();
    print_header("*** BEGIN CHECKING HOST INTRUSION DETECTION SYSTEM $datestring ***");

    my $esmdirhost = "/esm/system/$Hostname";

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

    if ( $IDS_FLAG > 0 ) {
        if ( $iddsflag == 1 ) {
            my @idsadmcheck = `/bin/su - ids -c "/opt/ids/bin/idsadmin --status all -vv 2>/dev/null"`;
            if ( @idsadmcheck != 0 ) {
                print "$INFOSTR HIDS seemingly configured\n";
                print @idsadmcheck;
                if ( -s "$ids_conf" ) {
                    if ( open( IDS, "egrep -v ^# $ids_conf | awk NF |" ) ) {
                        print "\n$INFOSTR agent config file $ids_conf\n";
                        while (<IDS>) {
                            next if ( grep( /^$/, $_ ) );
                            print $_;
                        }
                    }
                    close(IDS);
                }
            }

            my @idscheck = `IDS_checkInstall 2>/dev/null | awk NF`;
            if ( @idscheck != 0 ) {
                print "\n$INFOSTR HIDS checkInstall\n";
                print @idscheck;
            }

            my @idscertcheck = `/bin/su - ids -c "/opt/ids/bin/IDS_checkAdminCert 2>/dev/null"`;
            if ( @idscertcheck != 0 ) {
                print "\n$INFOSTR HIDS checkAdminCert\n";
                print @idscertcheck;
            }

            my @idsAcertcheck = `/bin/su - ids -c "/opt/ids/bin/IDS_checkAgentCert 2>/dev/null"`;
            if ( @idsAcertcheck != 0 ) {
                print "\n$INFOSTR HIDS IDS_checkAgentCert\n";
                print @idsAcertcheck;
            }
        }
        else {
            print "$INFOSTR HP IDS seemingly not configured\n";
        }

        if ( -s "$aide_conf" ) {
            my @aidecheck =
              `awk '! /^#/ && ! /awk/ {print}' $aide_conf | awk NF`;
            if (@aidecheck) {
                print "\n$INFOSTR AIDE seemingly configured\n";
                print @aidecheck;

                my @aidev = `aide -v 2>&1 | egrep -v "command not found"`;
                if ( @aidev != 0 ) {
                    print "\n$INFOSTR AIDE seemingly configured\n";
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

        if ( "$ESMD_FLAG" > 0 ) {
            print
"\n$INFOSTR Symantec Enterprise Security Manager seemingly configured\n";
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
            my @esmstart = `cat $esmrc| awk NF`;
            print "\n$INFOSTR Symantec ESM startup file $esmrc\n";
            print @esmstart;
        }
    }
    else {
        print "$INFOSTR HIDS not in use\n";
    }

    datecheck();
    print_trailer("*** END CHECKING HOST INTRUSION DETECTION SYSTEM $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING BASTILLE $datestring ***");

    if ( $BASTILLE_FLAG > 0 ) {
        my @bastille = `bastille -l | awk NF`;
        if ( @bastille ) {
            print @bastille;
        }

        if ( -s "$BASTILLECONF" ) {
            my @bastillc = `awk NF $BASTILLECONF 2>/dev/null`;
            if ( @bastillc ) {
                print
"\n$INFOSTR Bastille configuration file $BASTILLECONF exists\n";
                print @bastillc;
            }
        }

        if ( -f "$BASTILLELOCK" ) {
            print "\n$INFOSTR Bastille lock $BASTILLELOCK exists\n";
            print "$NOTESTR It could be an obsolete lock - check it\n";
        }

        `bastille -assess 2>/dev/null`;

        if ( -s "$BASTILLEREP" ) {
            my @bastillrep = `awk NF $BASTILLEREP 2>/dev/null`;
            if ( @bastillrep ) {
                print
"\n$INFOSTR Bastille assessment report $BASTILLEREP exists\n";
                print @bastillrep;
            }
        }

        if ( -s "$BASTILLBASE" ) {
            my @bastillbase = `awk NF $BASTILLBASE 2>/dev/null`;
            if ( @bastillbase ) {
                print
"\n$INFOSTR Bastille baseline $BASTILLBASE exists\n";
                print @bastillbase;
            }
        }
    }
    else {
        print "$INFOSTR Bastille seemingly not installed or active\n";
    }

    datecheck();
    print_trailer("*** END CHECKING BASTILLE $datestring ***");

    datecheck();
    print_header("*** BEGIN CHECKING IPFILTER $datestring ***");

    if ( ( -s "$IPFRCCONF" ) && ( -T "$IPFRCCONF" ) ) {
        print "\n$INFOSTR $IPFRCCONF exists\n";
        my @ipfrc = `grep -v ^# $IPFRCCONF 2>/dev/null | awk NF`; 
        if ( @ipfrc ) {
            print @ipfrc;
        }
    }

    if ( ( -s "$IPFRPCCONF" ) && ( -T "$IPFRPCCONF" ) ) {
        print "\n$INFOSTR $IPFRPCCONF exists\n";
        my @ipfrpc = `grep -v ^# $IPFRPCCONF 2>/dev/null | awk NF`; 
        if ( @ipfrpc ) {
            print @ipfrpc;
        }
    }

    if ( ( -s "$IPFCONF" ) && ( -T "$IPFCONF" ) ) {
        print "\n$INFOSTR $IPFCONF exists\n";
        my @ipfconf = `grep -v ^# $IPFCONF 2>/dev/null | awk NF`; 
        if ( @ipfconf ) {
            print @ipfconf;
        }
    }

    if ( ( -s "$IPFNAT" ) && ( -T "$IPFNAT" ) ) {
        print "\n$INFOSTR $IPFNAT exists\n";
        my @ipfn = `grep -v ^# $IPFNAT 2>/dev/null | awk NF`; 
        if ( @ipfn ) {
            print @ipfn;
        }
    }

    my @ipf = `ipf -V 2>/dev/null`;
    if ( @ipf ) {
        print @ipf;
    
        my @ipfstat = `ipfstat -v 2>&1`;
        if ( @ipfstat ) {
        print "\n$INFOSTR IPFilter statistics\n";
            print @ipfstat;
        }

        my @ipfstatio = `ipfstat -io 2>&1`;
        if ( @ipfstatio ) {
        print "\n$INFOSTR IPFilter filter statistics and filter list\n";
            print @ipfstatio;
        }

        my @ipfstatg = `ipfstat -vg 2>&1`;
        if ( @ipfstatg ) {
        print "\n$INFOSTR IPFilter groups\n";
            print @ipfstatg;
        }

        my @ipfstats = `ipfstat -s 2>&1`;
        if ( @ipfstats ) {
        print "\n$INFOSTR IPFilter states\n";
            print @ipfstats;
        }

        my @ipfstatsl = `ipfstat -sl 2>&1`;
        if ( @ipfstatsl ) {
        print "\n$INFOSTR IPFilter states held in kernel\n";
            print @ipfstatsl;
        }

        if ( "$Minor$Patch" >= 1131 ) {
            my @ipfstatl = `ipfstat -v -L 2>&1`;
            if ( @ipfstatl ) {
                print "\n$INFOSTR IPFilter global limit statistics\n";
                print @ipfstatl;
            }

            my @ipfstatQ = `ipfstat -Q 2>&1`;
            if ( @ipfstatQ ) {
                print "\n$INFOSTR Interfaces protected by IPFilter\n";
                print @ipfstatQ;
            }

            my @ipfq = `ipf -m q`;
            if ( @ipfq ) {
                print
"\n$INFOSTR IPFilter Dynamic Connection Allocation (DCA) status\n";
                print @ipfq;
            }
        }

        my @ipfnat = `ipfnat -l 2>/dev/null`;
        if ( @ipfnat ) {
        print "\n$INFOSTR IPFilter NAT rules and active mappings\n";
            print @ipfnat;
        }
        else {
            my @ipnat = `ipnat -l 2>/dev/null`;
            if ( @ipnat ) {
                print "\n$INFOSTR IPFilter NAT rules and active mappings\n";
                print @ipnat;
            }
        }
    }
    else {
        print "$INFOSTR IPFilter seemingly not installed or active\n";
    }

    datecheck();
    print_trailer("*** END CHECKING IPFILTER $datestring ***");
}

sub liccalc {
    $LICENSE++;
    push( @licdaemon, $_ );
}

sub swcalc {
    my $acst2 = shift;
    print "$WARNSTR $acst2 not installed\n";
    push(@CHECKARR, "\n$WARNSTR $acst2 not installed\n");
    $warnings++;
}

sub ldapcalc {
    $LDAPSERVER++;
    push( @ldapdaemon, $_ );
}

sub openldapcalc {
    $LDAPSERVER++;
    push( @ldapdaemon, $_ );
}

sub vconsdcalc {
    $VCONSD_FLAG++;
    $_ =~ s/\^s+//g;
    chomp($_);

    (undef, undef, $vconspid, undef) = split(/\s+/, $_);
    if ( "$vconspid" ) {
        @vconsmpsched = `mpsched -q -p $vconspid 2>/dev/null`;
    }
}

sub nsadmcalc {
    $NSADMIN++;
    push( @ldapdaemon, $_ );
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

# Subroutine to check active processes
#
sub rawpscheck {
    # Under XPG4 (Unix95), "-H" flag option gives pstree-line results
    #
    if ( "$ENV{'UNIX95'}" == 1 ) {
        $pstreeflag = "H";
    }

    if ( open( KM, "ps -ef${pstreeflag} |" ) ) {
        while (<KM>) {
            push( @allprocesses, $_ );
            grep( /cmcld|cmclconfd|cmlvmd|cmlogd|cmcluster/, $_ ) ? $SGRUN++
              : grep( /lvmdevd|lvmattach/, $_ ) ? $LVM_FLAG++
              : grep(
                /emcpdaemon|emcpProcd|emspd|emcpstratd|emcpwdd|emcpdfd/i,
                $_ ) ? $EMSP_FLAG++
              : grep( /cstm/,                 $_ ) ? $CSTM_FLAG++
              : grep( /diagmond/,             $_ ) ? $DIAGMOND++
              : grep( /ldapclientd/,          $_ ) ? $LDAPCLIENT++
              : grep( /idsagent/,             $_ ) ? $IDS_FLAG++
              : grep( /ioscan/,               $_ ) ? $IOSCAN_FLAG++
              : grep( /sendmail/,             $_ ) ? $SENDMAIL_FLAG++
              : grep( /exim/,                 $_ ) ? $EXIM_FLAG++
              : grep( /syslogd|syslog-ng/,    $_ ) ? $SYSLOG_FLAG++
              : grep( /db_srv/,               $_ ) ? $AAA_FLAG++
              : grep( /postfix/,              $_ ) ? $POSTFIX_FLAG++
              : grep( /ppud/,                 $_ ) ? $PPU_FLAG++
              : grep( /cmhelmd/,              $_ ) ? $CMHELMD_FLAG++
              : grep( /gated/,                $_ ) ? $GATED_FLAG++
              : grep( /vconsd/,               $_ ) ? vconsdcalc()
              : grep( /ns-slapd/,             $_ ) ? ldapcalc()
              : grep( /slapd/,                $_ ) ? openldapcalc()
              : grep( /ns-admin/,             $_ ) ? nsadmcalc()
              : grep( /lmgrd|netlsd|i4lmd/,   $_ ) ? liccalc()
              : grep( /esmnetd|esmcifd|hpux-hppa\/esmd/, $_ ) ? esmcalc()
              : grep( /evmd/ && /sbin\/esmd/, $_ ) ? $ESMDM_FLAG++
              : grep( /spagent/,              $_ ) ? $SECPATHAG++
              : grep( /lpsched/,              $_ ) ? $LPSCHED++
              : grep( /wlmd/,                 $_ ) ? $WLMD_FLAG++
              : grep( /cimserverd/,           $_ ) ? $CIM_FLAG++
              : grep( /cmclrmond|cmclsentryd/,$_ ) ? $CCCLUSTER_FLAG++
              : grep( /horcmd/,$_                ) ? $HORCMD_FLAG++
              : grep( /\bbdf\b/,              $_ ) ? $BDF_FLAG++
              : grep( /ypldapd/,              $_ ) ? $NISLDAP_FLAG++
              : grep( /sfmdb/,                $_ ) ? $SFM_FLAG++
              : grep( /prm3d|prm2d/,          $_ ) ? $PRM_FLAG++
              : grep( /oracle|ora_|\s+pmon\s+/, $_ ) ? $ORACLE_FLAG++
              : grep( /emsagent/,             $_ ) ? $EMS_FLAG++
              : grep( /puppetmasterd/,        $_ ) ? $PUPPETMASTER++
              : grep( /puppetd/,              $_ ) ? $PUPPETCLIENT++
              : grep( /cfservd|cf-serverd/,   $_ ) ? $CFENGINEMASTER++
              : grep( /cfagent|cf-agent/,     $_ ) ? $CFENGINECLIENT++
              : grep( /named/,                $_ ) ? push( @DNSRUN, $_ )
              : grep( /squid/,                $_ ) ? push( @SQUIDRUN, "$_\n" )
              : grep( /httpd/,                $_ ) ? push( @HTTPDRUN, "$_\n" )
              : grep( /ntpd/,                 $_ ) ? push( @ntpdaemon, $_ )
              : grep( /nfsd/,                 $_ ) ? push( @nfsdaemon, $_ )
              : grep( /pbmasterd/,            $_ ) ? $POWERBROKERSRV_FLAG++
              : grep( /dsmc/,                 $_ ) ? $TSMCL_FLAG++
              : grep( /dsmserv/,              $_ ) ? $TSMSRV_FLAG++
              : grep( /clic/,                 $_ ) ? $CLIC_FLAG++
              : grep( /pblogd|pblocald/,      $_ ) ? $POWERBROKERCL_FLAG++
              : grep( /iscsi_resolvd|iradd|iswd|islpd/, $_ ) ? $iSCSIFLAG++
              : grep( /hpvmmonlogd|hpvmnetd|hpvmapp/,   $_ ) ? $HPVM_FLAG++
              : 1;
        }
    }
    else {
        print "$ERRSTR Cannot run ps (process list)\n";
        print "$NOTESTR Check if corruption of $PSDATA is causing it\n"; 
        push(@CHECKARR, "\n$ERRSTR Cannot run ps (process list)\n");
    }
    close(KM);
}

# Subroutine to check active processes
#
sub pscheck {
    datecheck();
    print_header("*** BEGIN CHECKING ACTIVE UNIX PROCESSES $datestring ***");

    if (@allprocesses) {
        print @allprocesses;
    }

    my @ptree = `ptree 2>/dev/null`;
    if ( @ptree ) {
        print "\n$INFOSTR Process tree hierarchy\n";
        print @ptree;
    }

    if ( ( -s "$DEFPS" ) && ( -T "$DEFPS" ) ) {
        my @defps = `cat $DEFPS | awk NF`;
        if ( @defps ) {
            print
"\n$INFOSTR $DEFPS configuration file (defines default length of the ps(1m) output)\n";
            print @defps;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING ACTIVE UNIX PROCESSES $datestring ***");
}

# Subroutine to list RC scripts
#
sub RCcheck {
    datecheck();
    print_header("*** BEGIN CHECKING RC SCRIPTS $datestring ***");

    my @RCarray = `ls -d /sbin/rc*.d 2>/dev/null`; 

    foreach my $RCdir (@RCarray) {
        chomp($RCdir);
        if ( -d "$RCdir" ) {
            my @RClist = `ls -1 $RCdir`;
            if ( @RClist ) {
                print "$INFOSTR $RCdir listing\n";
                print @RClist;
    
                foreach my $RCfile (@RClist) {
                    chomp($RCfile);
                    if ( ( -s "$RCdir/$RCfile" )  && ( -T "$RCdir/$RCfile" ) ) {
                        my @rcfilels = `awk NF $RCdir/$RCfile`;
                        print "\n$INFOSTR Configuration file $RCdir/$RCfile\n";
                        print @rcfilels;
                    }
                    else {
                        print
"\n$INFOSTR Configuration file $RCdir/$RCfile is zero-length or not ASCII\n";
                    }
                }
            }
            else {
                print "$INFOSTR $RCdir is zero-length\n";
            }
            print "\n";
        }
        else {
            print "$INFOSTR $RCdir unreadable or not a directory\n";
        }
        print "\n";
    }

    my @rcutilq = `rcutil -q 2>/dev/null`;
    if ( @rcutilq ) {
        print "\n$INFOSTR Status of parallelization of RC scripts\n";
        print @rcutilq;
    }

    datecheck();
    print_trailer("*** END CHECKING RC SCRIPTS $datestring ***");
}

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

    if ( -s "$SNMPmaster" ) {
        if ( open( LA, "egrep -v ^# $SNMPmaster | awk NF |" ) ) {
            print "\n$INFOSTR SNMP Master file $SNMPmaster\n";
            while (<LA>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
    }
    else {
        print "\n$INFOSTR SNMP Master file $SNMPmaster not defined\n";
    }
    close(LA);

    if ( -s "$SNMPHpunix" ) {
        if ( open( LB, "egrep -v ^# $SNMPHpunix | awk NF |" ) ) {
            print "\n$INFOSTR SNMP Master file $SNMPHpunix\n";
            while (<LB>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
    }
    else {
        print "\n$INFOSTR SNMP file $SNMPHpunix not defined\n";
    }
    close(LB);

    if ( -s "$SNMPMib2" ) {
        if ( open( LC, "egrep -v ^# $SNMPMib2 | awk NF |" ) ) {
            print "\n$INFOSTR SNMP MIB file $SNMPMib2\n";
            while (<LC>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
        }
    }
    else {
        print "\n$INFOSTR SNMP MIB file $SNMPMib2 not defined\n";
    }
    close(LC);

    if ( -s "$SNMPTrpDst" ) {
        if ( open( LD, "egrep -v ^# $SNMPTrpDst | awk NF |" ) ) {
            print "\n$INFOSTR SNMP Trap file $SNMPTrpDst\n";
            while (<LD>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
            }
            close(LD);
        }
    }
    else {
        print "\n$INFOSTR SNMP Trap file $SNMPTrpDst not defined\n";
    }

    if ( -s "$SNMPconf" ) {
        if ( open( SQ, "egrep -v ^# $SNMPconf | awk NF |" ) ) {
            print "\n$INFOSTR Active services in SNMP file $SNMPconf\n";
            while (<SQ>) {
                my $SNMPIPP    = q{};
                my $SNMPVIEWP  = q{};
                my $SNMPMIBP   = q{};
                my $SNMPIPARRP = q{};
                my $SNMPpubP   = q{};
                my $SNMPIPS    = q{};
                my $SNMPVIEWS  = q{};
                my $SNMPMIBS   = q{};
                my $SNMPIPARRS = q{};
                my $SNMPpubS   = q{};

                next if ( grep( /^$/, $_ ) );
                $_ =~ s/^\s+//g;
                $_ =~ s/\s+$//g;
                print $_;

                if ( grep( /^get-community-name|^set-community-name/, $_ ) ) {
                    (undef, $SNMPIPP, $SNMPVIEWP, $SNMPMIBP) = split(/:/, $_);

                    $SNMPIPP =~ s/^\s+//g;
                    $SNMPIPP =~ s/\s+$//g;
                    ($SNMPpubP, undef) = split(/\s+/, $SNMPIPP);
                    chomp($SNMPpubP);

                    if ( "$SNMPpubP" ) {
                        if ( "$SNMPpubP" eq "public" ) {
                            push(@SNMPINFO,
"\n$WARNSTR SNMP community string is \"$SNMPpubP\" (replace with more secure string)\n");
                        }
                    }

                    if ( grep(/IP:/, $SNMPIPP) ) {
                        ($SNMPIPARRP, undef) = split(/\s+/, $SNMPVIEWP);
                        $SNMPIPARRP =~ s/^\s+//g;
                        $SNMPIPARRP =~ s/\s+$//g;

                        if ( "$SNMPIPARRP" ) {
                            push(@SNMPINFO,
"\n$PASSSTR SNMP restricts \"$SNMPpubP\" community access through \"IP:\" option\n");
                        }
                        else {
                            push(@SNMPINFO,
"\n$WARNSTR SNMP does not restrict \"$SNMPpubP\" community access through \"IP:\" option\n");
                        }
                    }
                }
            }
            close(SQ);

            if ( @SNMPINFO ) {
                print @SNMPINFO;
            }
        }
        else {
            print "\n$ERRSTR SNMP file $SNMPconf is zero-length or cannot be opened\n";
            $warnings++;
        }
    }
    else {
        print "\n$INFOSTR SNMP file $SNMPconf not defined\n";
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
    print_trailer("*** END CHECKING SNMP $datestring ***");
}

#
# Check interesting files
#
sub BasSeccheck {
    datecheck();
    print_header("*** BEGIN CHECKING MAILBOX STATUS $datestring ***");

    foreach my $mmentry (@mailboxdir) {
        my @mailfile = `ls -alsb $mmentry 2>/dev/null`;
        if ( @mailfile ) {
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
    print_trailer("*** END CHECKING MAILBOX STATUS $datestring ***");
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
        if ( -d $File::Find::name ) {
            print "$WARNSTR Mailbox $File::Find::name is a directory\n";
            push(@CHECKARR, "\n$WARNSTR Mailbox $File::Find::name is a directory\n");
            $warnings++;
        } else {
            $mboxcount++;

            if ( ! "$userent[0]" ) {
                print
"$WARNSTR Username $mboxowner missing for mailbox $File::Find::name\n";
                push(@CHECKARR,
"\n$WARNSTR Username $mboxowner missing for mailbox $File::Find::name\n");
                print "$NOTESTR Mailbox $File::Find::name possibly obsolete\n";
                $warnings++;
            }
            else {
                print
"$PASSSTR Username $userent[0] valid for mailbox $File::Find::name\n";
                if ( "$userent[0]" ne "$mboxowner" ) {
                    print
"$WARNSTR Mailbox $File::Find::name owned by username $userent[0]\n";
                    push(@CHECKARR,
"\n$WARNSTR Mailbox $File::Find::name owned by username $userent[0]\n");
                    $warnings++;
                }
                else {
                    print "$PASSSTR Mailbox $File::Find::name owned by username $mboxowner\n";
                }
            }

            if ( ! -T $File::Find::name ) {
                print
"$WARNSTR Mailbox $File::Find::name not text (ASCII) file\n";
                push(@CHECKARR,
"\n$WARNSTR Mailbox $File::Find::name not text (ASCII) file\n");
                $warnings++;
            }

            if ( -z $File::Find::name ) {
                print "$INFOSTR Zero-size file: $File::Find::name\n";
                push(@CHECKARR, "\n$INFOSTR Zero-size file: $File::Find::name\n");
                $warnings++;
            }

            if ( (-l $File::Find::name) && (! -e $File::Find::name) ) {
                print "$WARNSTR Invalid symbolic link: $File::Find::name\n";
                push(@CHECKARR,
"\n$WARNSTR Invalid symbolic link: $File::Find::name\n");
                $warnings++;
            }

            if ( -l $File::Find::name ) {
                print "$INFOSTR $File::Find::name is a symbolic link\n";
                print "$NOTESTR It is important to check the directory
$NOTESTR ownership and permissions for the complete path of the
$NOTESTR symbolic links. A missing execute (x) permission means
$NOTESTR each new mail delivered might cause the entire mailbox
$NOTESTR to be recreated. This results in the potential loss of mail.\n\n";
            }

            my $DAYCK  = 365;
            my $HOWOLD = 24 * 3600 * $DAYCK; # 24 hours x 3600 minutes x 365 days
            if ( ( $EPOCHTIME - $mmtime ) > $HOWOLD ) {
                print "$WARNSTR $File::Find::name last modified more than $DAYCK ";
                print "days ago\n";
                push(@CHECKARR,
"\n$WARNSTR $File::Find::name last modified more than $DAYCK days ago\n");
                $warnings++;
            }

            if ( $mblocks >= $MBOX_THRESHOLD ) {
                print
"$WARNSTR Mailbox $File::Find::name large (threshold is 50 MB)\n";
                if ( $msize > 0 ) {
                    print "$INFOSTR Mailbox $File::Find::name is ", $mblocks, " KB\n";
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
                    print
"$INFOSTR Mailbox $File::Find::name size is ", $mblocks, " KB\n";
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

    my @devll = `ll -R /dev 2>/dev/null`;
    if ( @devll != 0 ) {
        print "$INFOSTR Recursive listing of /dev\n";
        print @devll;
        print "\n";
    }

    find( \&devsearch, "/dev" );

    if (@FINDUP) {
        print
"$INFOSTR Multiple devices with identical major/minor numbers\n";
        print " @FINDUP";
    }

    datecheck();
    print_trailer("*** END CHECKING DEVICE MAJOR AND MINOR NUMBER STATUS $datestring ***");

    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING PASS-THROUGH DEVICE SPECIAL FILES $datestring ***");

        my @PASSTHRUARR = ();
        @PASSTHRUARR    = `ls $PTDIR 2>/dev/null | grep pt_ 2>/dev/null`;
        my @MYRBARR     = ();

        foreach my $passdev (@PASSTHRUARR) {
            chomp($passdev);
            my $stmin1 = (stat("${PTDIR}/${passdev}"))[6];
            $passdev =~ s/pt_//g;
            my $minor1 = sprintf"0x%06.6x", $stmin1 & 0xffffff;

            if ( grep(/disk/, $passdev) ) {
                my $stmin2 = (stat("/dev/rdisk/${passdev}"))[6];
                my $minor2 = sprintf"0x%06.6x", $stmin2 & 0xffffff;

                if ( "$minor1" == "$minor2" ) {
                    print "$PASSSTR minor=$minor1 ($PTDIR/pt_$passdev) identical to minor=$minor2 (/dev/rdisk/$passdev)\n";
                }
                else {
                    print "$WARNSTR minor=$minor1 ($PTDIR/pt_$passdev) different from minor=$minor2 (/dev/rdisk/$passdev)\n";
                }
            }
            else {
                if ( grep(/disk/, $passdev) ) {
                    my $stmin2 = (stat("/dev/rtape/${passdev}"))[6];
                    my $minor2 = sprintf"0x%06.6x", $stmin2 & 0xffffff;

                    if ( "$minor1" == "$minor2" ) {
                        print "$PASSSTR minor=$minor1 ($PTDIR/pt_$passdev) identical to minor=$minor2 (/dev/rtape/$passdev)\n";
                    }
                    else {
                        print "$WARNSTR minor=$minor1 ($PTDIR/pt_$passdev) different from minor=$minor2 (/dev/rtape/$passdev)\n";
                    }
                }
            }
        }
    
        if ( ! "@PASSTHRUARR" ) {
            print "$INFOSTR There are no pass-through devices in $PTDIR\n";
        }

        datecheck();
        print_header("*** END CHECKING PASS-THROUGH DEVICE SPECIAL FILES $datestring ***");
    }
}

sub devsearch {
    (
        $sdev,   $sino,     $smode, $snlink, $suid,
        $sgid,   $srdev,    $ssize, $satime, $smtime,
        $sctime, $sblksize, $sblocks
    ) = stat($File::Find::name);

    -l && next;

    if ( ( -b "$File::Find::name" ) || ( -c "$File::Find::name" ) ) {
        my $st = `ls -als $File::Find::name | awk '{print \$6, \$7}'`;
        chomp($st);
        my ($major, $minr) = split(/\s+/, $st);
        my $minor = hex($minr);

        my @DEVARRDUP = grep( /\b$major $minor\b/, @MAJMIN );
        if ( ! @DEVARRDUP ) {
            push( @MAJMIN, "$major $minor $File::Find::name\n" );
        }
        else {
            push( @FINDUP, @DEVARRDUP );
            push( @FINDUP, "$major $minor $File::Find::name\n" );
        }
    }
}

sub dirsearch {
    (
        $sdev,   $sino,     $smode, $snlink, $suid,
        $sgid,   $srdev,    $ssize, $satime, $smtime,
        $sctime, $sblksize, $sblocks
    ) = stat($File::Find::name);

    if ( "$opts{n}" != 1 ) {
        if ( $sdev < 0 ) {
            $File::Find::prune = 1;
        }
    
        foreach my $grars (@NFSarr) {
            if ( grep(/^$grars/, $File::Find::name) ) {
                $File::Find::prune = 1;
            }
        }
    }

    if ( ( -f $File::Find::name ) && ( $_ eq 'core' ) ) {
        push(@FINDARR, "$INFOSTR Possibly a core file $File::Find::name\n");
    }

    -u && push(@FINDARR, "$INFOSTR SUID file: $File::Find::name\n");
    -g && push(@FINDARR, "$INFOSTR SGID file: $File::Find::name\n");

    if ( ! -l $File::Find::name ) {
        -z && push(@FINDARR, "$INFOSTR Zero-size file: $File::Find::name\n");
    }

    -l && !-e && push(@FINDARR, "$WARNSTR Invalid symbolic link: $File::Find::name\n");

    if ( !( grep( /\b$sgid\b/, @Grnumarr ) ) ) {
        push(@FINDARR, "$WARNSTR Missing group ownership: $File::Find::name\n");
        push(@CHECKARR, "\n$WARNSTR Missing group ownership: $File::Find::name\n");
    }

    my $suname  = getpwuid($suid);
    chomp($suname);
    if ( $suname eq "nobody" ) {
        push(@FINDARR, "$WARNSTR $File::Find::name owned by user \"nobody\" (Ignite image might not be used to recover the server)\n");
        push(@CHECKARR, "\n$WARNSTR $File::Find::name owned by user \"nobody\" (Ignite image might not be used to recover the server)\n");
    }

    my $sgname  = getgrgid($sgid);
    chomp($sgname);
    if ( $sgname eq "nogroup" ) {
        push(@FINDARR, "$WARNSTR $File::Find::name owned by group \"nogroup\" (Ignite image might not be used to recover the server)\n");
        push(@CHECKARR, "\n$WARNSTR $File::Find::name owned by group \"nogroup\" (Ignite image might not be used to recover the server)\n");
    }

    if ( !( grep( /\b$suid\b/, @Passnumarr ) ) ) {
        push(@FINDARR, "$WARNSTR Missing user ownership: $File::Find::name\n");
        push(@CHECKARR, "\n$WARNSTR Missing user ownership: $File::Find::name\n");
    }

    if ("$vxmaxflag") {
        if ( $snlink >= $vxmaxflag ) {
            push(@FINDARR,
"$WARNSTR $File::Find::name has too many links $snlink (maximum $vxmaxflag)\n");
            push(@CHECKARR,
"\n$WARNSTR $File::Find::name has too many links $snlink (maximum $vxmaxflag)\n");
        }
    }
}

sub basfilesec {
    if ( "$opts{c}" == 1 ) {
        datecheck();
        print_header("*** BEGIN CHECKING BASIC FILE SECURITY $datestring ***");

        find( \&dirsearch, @directories_to_search );
        if ( @FINDARR ) {
            print @FINDARR; 
        }
        else {
            print "$INFOSTR Listing is empty or containers disallow the search\n";
        }

        datecheck();
        print_trailer("*** END CHECKING BASIC FILE SECURITY $datestring ***");
    }
}

# Subroutine to check kernels
#
sub multikern {
    datecheck();
    print_header("*** BEGIN CHECKING KERNEL IMAGES AND CURRENT KERNEL $datestring ***");

    if ( "$Stand" ) {
        print "$INFOSTR Current kernel path is $Stand\n";

        my $newstanddir = $Stand;
        $newstanddir =~ s/\/vmunix$//g;
        my $kstandconf = "${newstanddir}/.config";
        if ( -f "$kstandconf" ) {
            my $stperm = (stat($kstandconf))[2] & 0777;
            my $octperm = sprintf "%lo", $stperm;
            if ( $octperm != "644" ) {
                print
"\n$WARNSTR $kstandconf has permissions $octperm (default is 644 so that ordinary users can run kctune command)\n";
                push(@CHECKARR,
"$WARNSTR $kstandconf has permissions $octperm (default is 644 so that ordinary users can run kctune command)\n");
                $warnings++;
            }
            else {
                print
"\n$PASSSTR $kstandconf has permissions 644 (ordinary users can run kctune command)\n";
            }
        }
    }

    if ( "$Minor$Patch" < 1120 ) {
        my @kernls = `ls -als /stand/vmunix* 2>/dev/null`;

        if ( @kernls != 0 ) {
            print @kernls;
        }
        else {
            print "\n$ERRSTR Kernel images missing in /stand\n";
            push(@CHECKARR, "\n$ERRSTR Kernel images missing in /stand\n");
            $warnings++;
        }
    }
    else {
        my @kconfig = `kconfig -v 2>&1`;
        if ( @kconfig ) {
            print "\n";
            print @kconfig;
        }
        else {
            print "\n$ERRSTR Kernel configurations missing\n";
            push(@CHECKARR, "\n$ERRSTR Kernel configurations missing\n");
            $warnings++;
        }

        my @kconfigw = `kconfig -w 2>&1`;
        if ( @kconfigw ) {
            print "\n";
            print @kconfigw;
        }
    }

    datecheck();
    print_trailer("*** END CHECKING KERNEL IMAGES AND CURRENT KERNEL $datestring ***");
}

# Subroutine to check Uninterruptible Power System monitor 
#
sub upscheck {
    datecheck();
    print_header("*** BEGIN CHECKING UPS MONITORING $datestring ***");

    my @upsarr = `egrep -v ^# $UPSTAB 2>/dev/null`;

    if ( @upsarr != 0 ) {
        print @upsarr;
    }
    else {
        print "$INFOSTR $UPSTAB does not exist on is zero-length\n";
    }

    datecheck();
    print_trailer("*** END CHECKING UPS MONITORING $datestring ***");
}

# Subroutine to check Essential Services Monitor
#
sub esmcheck {
    datecheck();
    print_header("*** BEGIN CHECKING ESSENTIAL SERVICES MONITOR $datestring ***");

    if ( "$ESMDM_FLAG" > 0 ) {
        print "$INFOSTR ESM seemingly configured and running (esmd and evmd)\n";
    }
    else {
        print "$INFOSTR ESM seemingly not configured or running\n";
    }

    my $ESMCONF = "/etc/init.d/esm";
    if ( ( -s "$ESMCONF" ) && ( -T "$ESMCONF" ) ) {
        my @esmcat = `egrep -v ^# $ESMCONF | awk NF`;
        if ( @esmcat ) {
            print "\n$INFOSTR Startup file $ESMCONF\n";
            print @esmcat;
        }
    }
    else {
        print "\n$INFOSTR $ESMCONF is zero-length or missing\n";
    }

    my $ESMSTATE = "/var/run/esm.state";

    if ( -s "$ESMSTATE" ) {
        print "\n$INFOSTR $ESMSTATE exists\n";
    }
    else {
        print "\n$INFOSTR $ESMSTATE is zero-length or missing (verify if required)\n";
        push(@CHECKARR, "\n$INFOSTR $ESMSTATE is zero-length or missing (verify if required)\n");
    }

    my @setfixed = `set_fixed -L 2>/dev/null`;
    if ( @setfixed ) {
        print "\n$INFOSTR Resource State Tool status (set_fixed)\n";
        print @setfixed;
    
        my @setfixedls = `set_fixed -l 2>/dev/null`;
        if ( @setfixedls ) {
            print "\n";
            print @setfixedls;
        }
    }

    my @evmgetl = `evmget -A -C evmlog 2>/dev/null`;
    if ( @evmgetl ) {
        print "\n$INFOSTR EVM get log status\n";
        print @evmgetl;
    }

    datecheck();
    print_trailer("*** END CHECKING ESSENTIAL SERVICES MONITOR $datestring ***");
}

# Subroutine to run print_manifest
#
sub printmfst {

    my @prtmfst = `print_manifest 2>/dev/null | awk NF`;

    if ( @prtmfst != 0 ) {
        datecheck();
        print_header("*** BEGIN CHECKING PRINT_MANIFEST $datestring ***");

        print @prtmfst;

        datecheck();
        print_trailer("*** END CHECKING PRINT_MANIFEST $datestring ***");
    }
}

# Subroutine to check ERM 
#
sub ERMcheck {
    datecheck();
    print_header("*** BEGIN CHECKING ENTERPRISE ROOT MODEL $datestring ***");

    if ( $ERMflag > 0 ) {
        print "$INFOSTR ERM client seemingly installed (username ermclnt exists)\n";
    }
    else {
        print "$WARNSTR ERM client not installed (username ermclnt missing)\n";
        push(@CHECKARR,
"\n$WARNSTR ERM client not installed (username ermclnt missing)\n");
    }

    if ( (! "$TCB") && (! "$TCB2") ) {
        my @ermacc = `cat /tcb/files/auth/e/ermclnt 2>/dev/null`;
        if ( @ermacc ) {
            print "\n$INFOSTR ERM username ermclnt exists in TCB database\n";
            $ERMflag++;
        }
    }

    my @ermarr = `update_client -V 2>&1 | grep Version`;

    if ( @ermarr ) {
        print @ermarr;
        my @ermcfg = `update_client -t 2>/dev/null`;
        print "\n$INFOSTR ERM client configuration\n";
        print @ermcfg;
    }
    else {
        print "$WARNSTR ERM client seemingly not installed\n";
        push(@CHECKARR, "\n$WARNSTR ERM client seemingly not installed\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING ENTERPRISE ROOT MODEL $datestring ***");
}

# Subroutine to check Pay Per Use (PPU)
#
sub PPUcheck {
    datecheck();
    print_header("*** BEGIN CHECKING PAY PER USE AND UTILITY METER $datestring ***");

    if ( $PPU_FLAG > 0 ) {
        print
"$INFOSTR PPU server seemingly running (ppud daemon active)\n";

        my @ppuconfig = `ppuconfig 2>/dev/null`;
        if ( @ppuconfig ) {
            print @ppuconfig;
            print "\n";
        }

        my @ppuconfigt = `ppuconfig -t 2>/dev/null`;
        if ( @ppuconfigt ) {
            print @ppuconfigt;
        }
    }
    else {
        print
"$INFOSTR PPU server seemingly not running (ppud daemon not active)\n";
    }

    if ( (-s "$UMETERCONF" ) && ( -T "$UMETERCONF" ) ) {
        print "\n$INFOSTR Utility Meter configuration file $UMETERCONF\n";
        my @umeter = `egrep -v ^# $UMETERCONF 2>/dev/null`;
        print @umeter;
    }

    my @monitorp = `monitor status 2>/dev/null`;
    if ( @monitorp ) {
        print
"\n$INFOSTR Utility Meter Software status\n";
        print @monitorp;
    }

    my @umeters = `umeter status 2>/dev/null`;
    if ( @umeters ) {
        print "\n$INFOSTR Utility Meter status\n";
        print @umeters;
    }

    datecheck();
    print_trailer("*** END CHECKING PAY PER USE AND UTILITY METER $datestring ***");
}

# Subroutine to check Radius AAA
#
sub AAAcheck {
    datecheck();
    print_header("*** BEGIN CHECKING RADIUS AAA $datestring ***");

    if ( $AAA_FLAG > 0 ) {
        print "$INFOSTR AAA server running (db_srv daemon active)\n";

        my $AAAdir = '/etc/opt/aaa';
        my $aaa = q{};
   
        if ( opendir( AADIR, "$AAAdir" ) ) {
            while ( defined($aaa = readdir(AADIR) ) ) {
                next if $aaa =~ /^\.\.?$/;

                if ( (-s "$aaa" ) && ( -T "$aaa" ) ) {
                    print "\n$INFOSTR AAA configuration file $aaa\n";
                    my @RADar = `egrep -v ^# $aaa 2>/dev/null`;
                    print @RADar;
                }
                else {
                    print 
"\n$INFOSTR AAA configuration file $aaa is zero-length or non-existent\n";
                }
            }
            closedir(AADIR);
        }
        else {
            print 
"\n$INFOSTR AAA configuration directory $AAAdir is zero-length or non-existent\n";
        }
    }
    else {
        print "$INFOSTR AAA server not running (db_srv daemon not active)\n";
    }

    datecheck();
    print_trailer("*** END CHECKING RADIUS AAA $datestring ***");
}

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
        push(@CHECKARR,
"\n$ERRSTR Cannot define file system mount order in $FSTAB\n");
        $warnings++;
    }

    datecheck();
    print_trailer("*** END CHECKING LOCAL FILE SYSTEMS MOUNT ORDER AT BOOT $datestring ***");
}

# Check Xwindows/CDE
#
sub Xcheck {
    datecheck();
    print_header("*** BEGIN CHECKING XWINDOWS, CDE AND DISPLAY STATUS $datestring ***");

    my @XARR = ();

    if ( ! -s "$XCONF" ) {
        push(@XARR, "$WARNSTR Configuration file $XCONF does not exist\n");
        push(@XARR, "$NOTESTR Therefore remote XDMCP is enabled\n");
        push(@CHECKARR, "\n$WARNSTR Configuration file $XCONF does not exist\n");
        $warnings++;
    }
    else {
        print "$PASSSTR Configuration file $XCONF exists\n";
        if ( open( XCONZ, "egrep -v ^# $XCONF |" ) ) {
            while (<XCONZ>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                chomp;
                if ( grep( /^Dtlogin.requestPort/, $_ ) ) {
                    ( undef, $xdmcpdef ) = split( /:/, $_ );
                    $xdmcpdef =~ s/^\s+//g;
                    $xdmcpdef =~ s/\s+$//g;
                    if ( "$xdmcpdef" == 1 ) {
                        push(@XARR, "\n$WARNSTR Remote XDMCP requests enabled in $XCONF\n");
                        push(@CHECKARR, "\n$WARNSTR Remote XDMCP requests enabled in $XCONF\n");
                        $warnings++;
		    }
		    else {
                        push(@XARR, "\n$PASSSTR Remote XDMCP requests disabled in $XCONF\n");
		    }
	        }
            }
            close(XCONZ);

            if ( ! "$xdmcpdef" ) {
                push(@XARR, "\n$WARNSTR Remote XDMCP requests enabled in $XCONF by default\n");
                push(@CHECKARR, "\n$WARNSTR Remote XDMCP requests enabled in $XCONF by default\n");
                $warnings++;
            }
        }
    }

    if ( -s "$XFONTCONF" ) {
        if ( open( XFS, "egrep -v ^# $XFONTCONF |" ) ) {
            print "\n$INFOSTR Configuration file $XFONTCONF\n";
            while (<XFS>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                chomp;
                if ( grep( /^RUN_X_FONT_SERVER/, $_ ) ) {
                    ( undef, $xfsval ) = split( /=/, $_ );
                    $xfsval =~ s/^\s+//g;
                    $xfsval =~ s/\s+$//g;
                }
            }
            close(XFS);

            if ( "$xfsval" == 1 ) {
                push(@XARR, "\n$WARNSTR X-font server enabled in $XFONTCONF\n");
                push(@CHECKARR, "\n$WARNSTR X-font server enabled in $XFONTCONF\n");
                $warnings++;
            }
            else {
                push(@XARR, "\n$PASSSTR X-font server disabled in $XFONTCONF\n");
                print "\n$PASSSTR X-font server disabled in $XFONTCONF\n";
            }
        }
        else {
            push(@XARR, "\n$WARNSTR Cannot open $XFONTCONF\n");
            push(@CHECKARR, "\n$WARNSTR Cannot open $XFONTCONF\n");
            $warnings++;
        }
    }

    if ( -s "$CDEDESKTOP" ) {
        if ( open( CDED, "egrep -v ^# $CDEDESKTOP |" ) ) {
            print "\n$INFOSTR Configuration file $CDEDESKTOP\n";
            while (<CDED>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                chomp;
                if ( grep( /^CDE/, $_ ) ) {
                    ( undef, $cded ) = split( /=/, $_ );
                    $cded =~ s/^\s+//g;
                    $cded =~ s/\s+$//g;
                    if ( "$cded" eq "CDE" ) {
                        push(@XARR, "\n$WARNSTR CDE enabled in $CDEDESKTOP\n");
                        push(@CHECKARR, "\n$WARNSTR CDE enabled in $CDEDESKTOP\n");
                        $warnings++;
                    }
                    else {
                        push(@XARR, "\n$PASSSTR CDE disabled in $CDEDESKTOP\n");
                    }
                }
	    }
	    close(CDED);
	}
    }

    if ( -s "$XVFBCONF" ) {
        if ( open( XVFB, "egrep -v ^# $XVFBCONF |" ) ) {
            print "\n$INFOSTR Configuration file $XVFBCONF\n";
            while (<XVFB>) {
                next if ( grep( /^$/, $_ ) );
                print $_;
                chomp;
                if ( grep( /^START_XVFB/, $_ ) ) {
                    ( undef, $xvfb ) = split( /=/, $_ );
                    $xvfb =~ s/^\s+//g;
                    $xvfb =~ s/\s+$//g;
                    if ( "$xvfb" == 1 ) {
                        push(@XARR, "\n$WARNSTR Xvfb enabled in $XVFBCONF\n");
                        push(@CHECKARR, "\n$WARNSTR Xvfb enabled in $XVFBCONF\n");
                        $warnings++;
                    }
                    else {
                        push(@XARR, "\n$PASSSTR Xvfb disabled in $XVFBCONF\n");
                    }
                }

                if ( grep( /^USE_XHP/, $_ ) ) {
                    my $xhp = 0;
                    ( undef, $xhp ) = split( /=/, $_ );
                    $xhp =~ s/^\s+//g;
                    $xhp =~ s/\s+$//g;
                    if ( "$xhp" == 1 ) {
                        push(@XARR, "\n$WARNSTR Xhp enabled in $XVFBCONF\n");
                        push(@CHECKARR, "\n$WARNSTR Xhp enabled in $XVFBCONF\n");
                        $warnings++;
                    }
                    else {
                        push(@XARR, "\n$PASSSTR Xhp disabled in $XVFBCONF\n");
                    }
                }
            }
            close(XVFB);
        }
        else {
            push(@XARR, "\n$WARNSTR Cannot open $XVFBCONF\n");
            push(@CHECKARR, "\n$WARNSTR Cannot open $XVFBCONF\n");
            $warnings++;
        }
    }

    if ( @XARR ) {
        print "\n";
        print @XARR;
    }

    if ( "$ENV{'DISPLAY'}" ne '' ) {
        print "\n$INFOSTR Environment variable DISPLAY set\n";
        print "$ENV{'DISPLAY'}\n";
    }

    my @dtconfig = `dtconfig -d 2>/dev/null`;
    if ( @dtconfig ) {
        print "\n$INFOSTR Desktop status\n";
        print @dtconfig;
    }

    my @graphinfo = `graphinfo 2>/dev/null`;
    if ( @graphinfo ) {
        print "\n$INFOSTR Graphinfo status\n";
        print @graphinfo;
    }

    my @setmon = `echo 1 | setmon -p 2>/dev/null | awk NF`;
    if ( @setmon ) {
        print "\n$INFOSTR Monitor configuration status\n";
        print @setmon;

        my @setmonr = `setmon -r 2>/dev/null | awk NF`;
        if ( @setmonr ) {
            print "\n$INFOSTR Available monitor configuration choices\n";
            print @setmonr;
        }
    }

    print "\n";
    checkActivePorts(6000);
    checkActivePorts(7000);

    datecheck();
    print_trailer("*** END CHECKING XWINDOWS, CDE AND DISPLAY STATUS $datestring ***");

    if ( "$opts{l}" == 1 ) {
        datecheck();
        print_header("*** BEGIN CHECKING PORT SCAN $datestring ***");

        my @TCPSCANTEST = `nmap -O -sS -p1-65535 $Hostname 2>/dev/null | awk NF`;
        my @UDPSCANTEST = `nmap -sU -p1-65535 $Hostname 2>/dev/null | awk NF`;

        if (@TCPSCANTEST) {
            print "$INFOSTR TCP port scan on interface $Hostname\n";
            print @TCPSCANTEST;
        }
        else {
            print "$INFOSTR Nmap not installed or TCP scan empty\n";
        }

        if (@UDPSCANTEST) {
            print "\n$INFOSTR UDP port scan on interface $Hostname\n";
            print @UDPSCANTEST;
        }
        else {
            print "$INFOSTR Nmap not installed or TCP scan empty\n";
        }

        if ( @SWarray ) {
            my @isnessus = grep(/ixNessus|nessus/, @SWarray);
            if ( @isnessus ) {
                print "\n$INFOSTR Nessus scanner seemingly not installed\n";
            }
            else {
                print "\n$PASSSTR Nessus scanner seemingly installed\n";
            }
        }

        datecheck();
        print_trailer("*** END CHECKING PORT SCAN $datestring ***");
    }
}

# Subroutine to compare two arrays
#
sub compare_arrays {
    my ($first, $second) = @_;
    no warnings;  # silence spurious -w undef complaints
    return 0 unless @$first == @$second;
    for (my $i = 0; $i < @$first; $i++) {
        return 0 if $first->[$i] ne $second->[$i];
    }
    return 1;
}

# Find the intersection between two arrays.
#
sub intersection {
    my ($first, $second) = @_;
}

# Dynamic Root Disk check (HP-UX 11.23 and above)
#
sub DynRootBootcheck {
    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING DYNAMIC ROOT DISK STATUS $datestring ***");

        if ( $DYNROOT_FLAG == 1 ) {
            print "$INFOSTR DRD bundle DynRootDisk installed\n";

            my @drdcheck = `drd activate -p 2>&1`;
            if ( @drdcheck != 0 ) {
                print "\n$INFOSTR DRD status via dry-run activation\n";
                print @drdcheck;

                my @drdmount = `drd mount -p 2>&1`;
                if ( @drdmount != 0 ) {
                    print "\n$INFOSTR DRD mount via dry-run\n";
                    print @drdmount;
                }

                my @drdstat = `drd status 2>&1`;
                if ( @drdstat != 0 ) {
                    print "\n$INFOSTR DRD status\n";
                    print @drdstat;
                }

                my @drdswlist = `drd runcmd swlist 2>&1`;
                if ( @drdswlist != 0 ) {
                    print "\n$INFOSTR DRD status of inactive clone\n";
                    print @drdswlist;
                }

                my @drdsync = `drd sync -p -v -v 2>&1`;
                if ( @drdsync != 0 ) {
                    print "\n$INFOSTR DRD sync status via dry-run\n";
                    print @drdsync;

                    if ( -s "$DRDSYNCP" ) {
                        my @catdrdsync = `cat $DRDSYNCP 2>/dev/null`;
                        if ( @catdrdsync != 0 ) {
                            print "\n$INFOSTR Files to be copied via DRD sync to inactive clone\n";
                            print @catdrdsync;
                        }
                    }
                }
            }
            else {
                print "$INFOSTR DRD seemingly not configured\n";
            }
        }
        else {
            print "$INFOSTR DRD bundle DynRootDisk not installed\n";
        }

        datecheck();
        print_trailer("*** END CHECKING DYNAMIC ROOT DISK STATUS $datestring ***");
    }
}

# Subroutine to check / 
#
sub checkTLDIR {
   datecheck();
   print_header("*** BEGIN CHECKING TOP LEVEL DIRECTORY (ROOT)$datestring ***");

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
        push(@CHECKARR,
"\n$WARNSTR Top-level directory \"$TLDIR\" not owned by UID 0 ($tuid)\n");
        $warnings++;
    }

    if ( "$tgid" == 0 ) {
        print "\n$PASSSTR Top-level directory \"$TLDIR\" owned by GID $tgid\n";
    }
    else {
        print
"\n$WARNSTR Top-level directory \"$TLDIR\" not owned by GID 0 ($tgid)\n";
        push(@CHECKARR,
"\n$WARNSTR Top-level directory \"$TLDIR\" not owned by GID 0 ($tgid)\n");
        $warnings++;
    }

    my @tldlist = `ls -alsb $TLDIR 2>/dev/null`;
    if ( @tldlist ) {
        print "\n$INFOSTR Top-level directory \"$TLDIR\" listing\n";
        print @tldlist;
    }

   datecheck();
   print_trailer("*** END CHECKING TOP LEVEL DIRECTORY (ROOT) $datestring ***");
}

# Subroutine to check Squid proxy
#
sub checkSquid {
   datecheck();
   print_header("*** BEGIN CHECKING SQUID PROXY $datestring ***");

   if ( ! @SQUIDRUN ) {
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
   print_trailer("*** END CHECKING SQUID PROXY $datestring ***");
}

# Subroutine to check envd
#
sub checkenvd {
    datecheck();
    print_header("*** BEGIN CHECKING SYSTEM PHYSICAL ENVIRONMENT DAEMON (ENVD) $datestring ***");

    if ( ( -s "$envconf" ) && ( -T "$envconf" ) ) {
        @envd = `egrep -v ^# $envconf | awk NF`;
        if ( @envd ) {
            print "$INFOSTR Configuration file $envconf\n";
            print @envd;
        }
    }
    else {
        print "$INFOSTR Configuration file $envconf missing or is zero-length\n";
    }

    datecheck();
    print_trailer("*** END CHECKING SYSTEM PHYSICAL ENVIRONMENT DAEMON (ENVD) $datestring ***");
}

# Subroutine to check Dynamic P-States feature,
# which reduces power consumption on systems 
# with Itanium 2 9100 series or later processors.
# PHCO_38669 is delivered in the March 2009 HP-UX 11.31
# OEUR as part of the FEATURE11i patch bundle.
#
sub PStates {
    if ( "$Minor$Patch" >= 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING DYNAMIC P-STATES $datestring ***");

        my $devpwr = "/dev/pwr";
        if ( -c $devpwr ) {
            print "$INFOSTR Dynamic P-States special device $devpwr exists\n";

            my @pstatectls = `pstatectl -v status 2>/dev/null`;
            if ( @pstatectls ) {
                print "\n$INFOSTR Dynamic P-States status\n";
                print @pstatectls;
            }

            my @pstatectli = `pstatectl -v info 2>/dev/null`;
            if ( @pstatectli ) {
                print "\n$INFOSTR Dynamic P-States status\n";
                print @pstatectli;
            }

            my @pstatectlg = `pstatectl -v getmaxpstate 2>/dev/null`;
            if ( @pstatectlg ) {
                print "\n$INFOSTR Dynamic P-States maximum level\n";
                print @pstatectlg;
            }
        }
        else {
            print "$INFOSTR Dynamic P-States special device $devpwr does not exist\n";
        }

        datecheck();
        print_trailer("*** END CHECKING DYNAMIC P-STATES $datestring ***");
    }
}

# Subroutine to check Apache and HP-UX Web Server Suite
#
sub checkApache {
   datecheck();
   print_header("*** BEGIN CHECKING WEB SERVER SUITE $datestring ***");

   if ( ! @HTTPDRUN ) {
       print "$INFOSTR HTTPD (Apache) seemingly not running\n";
   }
   else {
      print "$INFOSTR HTTPD (Apache) seemingly running\n";

      foreach my $apachefile (@APACHEarray) {
          if ( -s "$apachefile" ) {
              my @apachelist = `egrep -v ^# $apachefile | awk NF`;
              if ( @apachelist ) {
                  print "\n";
                  print "$INFOSTR Apache configuration in $apachefile\n";
                  print @apachelist;
              }
          }
      }
   }

   datecheck();
   print_trailer("*** END CHECKING WEB SERVER SUITE $datestring ***");
}

# Subroutine to check Center for Internet Security HP-UX Benchmark Scoring Tool 
#
sub checkCISSEC {
   datecheck();
   print_header("*** BEGIN CHECKING CENTER FOR INTERNET SECURITY BENCHMARK SCORING TOOL $datestring ***");

   if ( $CISSEC_FLAG > 0 ) {
       print "$PASSSTR CIS benchmark toolkit installed\n";
       my @cisscan = `cis-scan 2>/dev/null`; 
       if ( @cisscan ) {
           print @cisscan;
       }
   }
   else {
       print "$INFOSTR CIS benchmark toolkit not installed\n";
   }

   datecheck();
   print_trailer("*** END CHECKING CENTER FOR INTERNET SECURITY BENCHMARK SCORING TOOL $datestring ***");

    if ( "$Minor$Patch" == 1111 ) {
        datecheck();
        print_header("*** BEGIN CHECKING STRONG RANDOM GENERATOR ON HP-UX 11.11 $datestring ***");
 
        if ( grep( /KRNG11i/, @SWarray ) ) {
             print "$PASSSTR KRNG11i depot installed\n";
        }
        else {
             print "$WARNSTR KRNG11i depot not installed\n";
             push(@CHECKARR, "\n$WARNSTR KRNG11i depot not installed\n");
             $warnings++;
        }

        datecheck();
        print_trailer("*** END CHECKING STRONG RANDOM GENERATOR ON HP-UX 11.11 $datestring ***");
    }
}

# Subroutine to check STREAMS 
#
sub checkSTREAMS {
   datecheck();
   print_header("*** BEGIN CHECKING STREAMS $datestring ***");

   my @strvf = `strvf -v 2>/dev/null`;
   if ( @strvf ) {
       print "$INFOSTR HP STREAMS seemingly installed\n";
       print @strvf;
   }
   else {
       print "$INFOSTR HP STREAMS seemingly not installed or not operational\n";
   }

   datecheck();
   print_trailer("*** END CHECKING STREAMS $datestring ***");
}

# Subroutine to check whitelisting (WLI )
#
sub WLIcheck {
   datecheck();
   print_header("*** BEGIN CHECKING WHITELISTING $datestring ***");

   if ( "$WHITELIST_FLAG" > 0 ) {
      print "$INFOSTR Whitelisting seemingly installed\n";

      my @wlisyspolicy = `wlisyspolicy -g 2>/dev/null`;
      if ( @wlisyspolicy ) {
         print "\n$INFOSTR Whitelisting system policy\n";
         print @wlisyspolicy;
      }

      foreach my $wlifile (@WLICONFARR) {
         if ( -s "${WLIDIR}/$wlifile" ) {
            my @wlilist = `awk NF ${WLIDIR}/$wlifile`;
            if ( @wlilist ) {
                print "\n$INFOSTR Whitelisting configuration file ${WLIDIR}/$wlifile\n";
                print @wlilist;
            }
            else {
                print "\n$INFOSTR Whitelisting configuration file ${WLIDIR}/$wlifile is empty or does not exist\n";
            }
         }
      }

      my @wlicerts = `ls $WLICERTDIR 2>/dev/null`;
      if ( @wlicerts ) {
         print "\n$INFOSTR Whitelisting certificates in $WLICERTDIR\n";
         print @wlicerts;
      }
      else {
         print "\n$INFOSTR Whitelisting certificates do not exist in $WLICERTDIR\n";
      }

      my @wlikeys = `ls $WLIKEYDIR 2>/dev/null`;
      if ( @wlikeys ) {
         print "\n$INFOSTR Whitelisting certificates in $WLIKEYDIR\n";
         print @wlikeys;
      }
      else {
         print "\n$INFOSTR Whitelisting certificates do not exist in $WLIKEYDIR\n";
      }
   }
   else {
      print "$INFOSTR Whitelisting seemingly not installed\n";
   }

   datecheck();
   print_trailer("*** END CHECKING WHITELISTING $datestring ***");
}

# Subroutine to check ISO mount 
#
sub checkISOMOUNT {
   if ( "$Minor$Patch" < 1131 ) {
       datecheck();
       print_header("*** BEGIN CHECKING ISO IMAGE MOUNT ENHANCEMENT $datestring ***");

       if ( "$ISOIMAGE_FLAG" > 0 ) {
           print "$INFOSTR HP-UX ISOIMAGE-ENH bundle seemingly installed (module fspd exists)\n";
       }
       else {
           print "$INFOSTR HP-UX ISOIMAGE-ENH bundle seemingly not installed\n";
       }

       datecheck();
       print_trailer("*** END CHECKING ISO IMAGE MOUNT ENHANCEMENT $datestring ***");
   }
}

# Subroutine to check CFENGINE 
#
sub checkCFENGINE {
   datecheck();
   print_header("*** BEGIN CHECKING CONFIGURATION MANAGEMENT TOOL CFENGINE (DSAU) $datestring ***");

   if ( "$DSAU_FLAG" > 0 ) {
       print "$INFOSTR HP-UX Distributed Systems Administration Utilities (DSAU) seemingly installed\n";

       if ( "$CFENGINEMASTER" > 0 ) {
          print "\n$INFOSTR This server is seemingly an active CFEngine Server\n";
       }
       else {
          print "\n$INFOSTR This server is seemingly not an active CFEngine Server\n";
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
   }
   else {
       print "$INFOSTR HP-UX Distributed Systems Administration Utilities seemingly not installed\n";
   }

   datecheck();
   print_trailer("*** END CHECKING CONFIGURATION MANAGEMENT TOOL CFENGINE (DSAU) $datestring ***");
}

# Subroutine to check Chef
#
sub checkchef {
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

# Subroutine to check Puppet
#
sub checkpuppet {
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

# Subroutine to check IP Quality of Service
#
sub checkIPQoS {
    if ( "$Minor$Patch" < 1131 ) {
        datecheck();
        print_header("*** BEGIN CHECKING IP QUALITY OF SERVICE (IPQoS) $datestring ***");
   
        if ( grep( /IPQoS/i, @SWarray ) ) {
            print "$PASSSTR IPQoS depot installed\n";

            if ( ( -s "$IPQOSCONF" ) && ( -T "$IPQOSCONF" ) ) {
                print "\n$INFOSTR $IPQOSCONF exists\n";
                my @ipqos = `grep -v ^# $IPQOSCONF 2>/dev/null | awk NF`; 
                if ( @ipqos ) {
                    print @ipqos;
                }

                my @ipqosshowconf = `ipqosadmin -showconfig 2>/dev/null`; 
                if ( @ipqosshowconf ) {
                    print "\n$INFOSTR IPQoS configuration\n";
                    print @ipqosshowconf;
                }

                my @ipqosstate = `ipqosadmin -state 2>/dev/null`; 
                if ( @ipqosstate ) {
                    print "\n$INFOSTR IPQoS state\n";
                    print @ipqosstate;
                }

                my @ipqosstats = `ipqosadmin -showstats 2>/dev/null`; 
                if ( @ipqosstats ) {
                    print "\n$INFOSTR IPQoS statistics\n";
                    print @ipqosstats;
                }

                my @ipqoslog = `ipqosadmin -log 2>/dev/null`; 
                if ( @ipqoslog ) {
                    print "\n$INFOSTR IPQoS log level\n";
                    print @ipqoslog;
                }
            }
            else {
                print "\n$INFOSTR $IPQOSCONF does not exist or is zero-length\n";
            }
        }
        else {
            print "$INFOSTR IPQoS depot not installed\n";
        }

        datecheck();
        print_trailer("*** END CHECKING IP QUALITY OF SERVICE (IPQoS) $datestring ***");
    }
}

# Subroutine to check Mobile IPv4 
#
sub checkMobileIPv4 {
    if ( "$Minor$Patch" >= 1123 ) {
        datecheck();
        print_header("*** BEGIN CHECKING MOBILE IPV4 SERVICE $datestring ***");
   
        if ( grep( /Mobile IPv4|mipv4/i, @SWarray ) ) {
            print "$PASSSTR Mobile IPv4 depot installed\n";

            if ( ( -s "$MIPDCONF" ) && ( -T "$MIPDCONF" ) ) {
                print "\n$INFOSTR $MIPDCONF exists\n";
                my @mipdconf = `grep -v ^# $MIPDCONF 2>/dev/null | awk NF`;
                if ( @mipdconf ) {
                    print @mipdconf;
                }
            }
            else {
                print "\n$INFOSTR $MIPDCONF does not exist or is zero-length\n";
            }

            if ( ( -s "$AAAEYCONF" ) && ( -T "$AAAEYCONF" ) ) {
                print "\n$INFOSTR $AAAEYCONF exists\n";
                my @aaaeyconf = `grep -v ^# $AAAEYCONF 2>/dev/null | awk NF`;
                if ( @aaaeyconf ) {
                    print @aaaeyconf;
                }
            }
            else {
                print "\n$INFOSTR $AAAEYCONF does not exist or is zero-length\n";
            }

            my @mipadminconf = `mipadmin -configuration -all 2>/dev/null`;
            if ( @mipadminconf ) {
                print "\n$INFOSTR Mipadmin configuration\n";
                print @mipadminconf;
            }

            my @mipadmins = `mipadmin -status 2>/dev/null`;
            if ( @mipadmins ) {
                print "\n$INFOSTR Mipadmin status\n";
                print @mipadmins;
            }

            my @mipadminv = `mipadmin -version 2>/dev/null`;
            if ( @mipadminv ) {
                print "\n$INFOSTR Mipadmin version\n";
                print @mipadminv;
            }

            my @mipadminb = `mipadmin -bindings 2>/dev/null`;
            if ( @mipadminb ) {
                print "\n$INFOSTR Mipadmin bindings\n";
                print @mipadminb;
            }

            my @mipadminvs = `mipadmin -visitors 2>/dev/null`;
            if ( @mipadminvs ) {
                print "\n$INFOSTR Mipadmin visitors\n";
                print @mipadminvs;
            }

            my @mipadmint = `mipadmin -tunnels 2>/dev/null`;
            if ( @mipadmint ) {
                print "\n$INFOSTR Mipadmin tunnels\n";
                print @mipadmint;
            }

            my @mipadminse = `mipadmin -session 2>/dev/null`;
            if ( @mipadminse ) {
                print "\n$INFOSTR Mipadmin sessions\n";
                print @mipadminse;
            }

            my @mipadmina = `mipadmin -advertisements 2>/dev/null`;
            if ( @mipadmina ) {
                print "\n$INFOSTR Mipadmin advertisements\n";
                print @mipadmina;
            }

            my @mipadminr = `mipadmin -roinfo 2>/dev/null`;
            if ( @mipadminr ) {
                print "\n$INFOSTR Mipadmin routing optimization\n";
                print @mipadminr;
            }

            my @mipadmind = `mipadmin -dynamicaddr 2>/dev/null`;
            if ( @mipadmind ) {
                print "\n$INFOSTR Mipadmin dynamic address allocation\n";
                print @mipadmind;
            }

            my @mipadminle = `mipadmin -logevents 2>/dev/null`;
            if ( @mipadminle ) {
                print "\n$INFOSTR Mipadmin log events\n";
                print @mipadminle;
            }
        }
        else {
            print "$PASSSTR Mobile IPv4 depot installed\n";
        }

        datecheck();
        print_trailer("*** END CHECKING MOBILE IPV4 SERVICE $datestring ***");
    }
}

# Subroutine to check Mobile IPv6 
#
sub checkMobileIPv6 {
    if ( ( "$Minor$Patch" >= 1131 ) && ( "$Hardware" eq "ia64" ) ) {
        datecheck();
        print_header("*** BEGIN CHECKING MOBILE IPV6 SERVICE $datestring ***");
   
        if ( grep( /Mobile IPv6|mipv6|MobileIPv6/i, @SWarray ) ) {
            print "$PASSSTR Mobile IPv6 depot installed\n";

            if ( ( -s "$MIP6CONF" ) && ( -T "$MIP6CONF" ) ) {
                print "\n$INFOSTR $MIP6CONF exists\n";
                my @mip6conf = `grep -v ^# $MIP6CONF 2>/dev/null | awk NF`;
                if ( @mip6conf ) {
                    print @mip6conf;
                }
            }
            else {
                print "\n$INFOSTR $MIP6CONF does not exist or is zero-length\n";
            }

            if ( ( -s "$MIP6MOD" ) && ( -T "$MIP6MOD" ) ) {
                print "\n$INFOSTR $MIP6MOD exists\n";
                my @mip6mod = `grep -v ^# $MIP6MOD 2>/dev/null | awk NF`;
                if ( @mip6mod ) {
                    print @mip6mod;
                }
            }
            else {
                print "\n$INFOSTR $MIP6MOD does not exist or is zero-length\n";
            }

            my @mip6adminc = `mip6admin -getconfiguration 2>/dev/null`;
            if ( @mip6adminc ) {
                print "\n$INFOSTR Mip6admin configuration\n";
                print @mip6adminc;
            }

            my @mip6adminr = `mip6admin -report 2>/dev/null`;
            if ( @mip6adminr ) {
                print "\n$INFOSTR Mip6admin report\n";
                print @mip6adminr;
            }

            my @mip6adminp = `mip6admin -prefixes 2>/dev/null`;
            if ( @mip6adminp ) {
                print "\n$INFOSTR Mip6admin prefixes\n";
                print @mip6adminp;
            }

            my @mip6adminb = `mip6admin -bindings 2>/dev/null`;
            if ( @mip6adminb ) {
                print "\n$INFOSTR Mip6admin bindings\n";
                print @mip6adminb;
            }

            my @mip6adminh = `mip6admin -halist 2>/dev/null`;
            if ( @mip6adminh ) {
                print "\n$INFOSTR Mip6admin host agent listing\n";
                print @mip6adminh;
            }

            my @mip6admins = `mip6admin -statistics 2>/dev/null`;
            if ( @mip6admins ) {
                print "\n$INFOSTR Mip6admin statistics\n";
                print @mip6admins;
            }

            my @mip6adminrs = `mip6admin -rtradvstatistics 2>/dev/null`;
            if ( @mip6adminrs ) {
                print "\n$INFOSTR Mip6admin router advertisement statistics\n";
                print @mip6adminrs;
            }

            my @mip6adminle = `mip6admin -logevents 2>/dev/null`;
            if ( @mip6adminle ) {
                print "\n$INFOSTR Mip6admin log events\n";
                print @mip6adminle;
            }

            if ( @rtradvdC ) {
                print "\n$INFOSTR Rtradvd configuration check\n";
                print @rtradvdC;
            }
        }
        else {
            print "$INFOSTR Mobile IPv6 depot not installed\n";
        }

        datecheck();
        print_trailer("*** END CHECKING MOBILE IPV6 SERVICE $datestring ***");
    }
}

# Subroutine to check /etc/rc.config.d files 
#
sub checkRCconf {
   datecheck();
   print_header("*** BEGIN CHECKING $RCCONFDIR $datestring ***");

   my @rcls = `ls $RCCONFDIR 2>/dev/null`;
   my @ERRRCARR = ();

   if ( @rcls != 0 ) {
       print "$INFOSTR Listing of $RCCONFDIR\n";
       print sort(@rcls);
       print "\n";
       foreach my $rcfile (@rcls) {
           chomp($rcfile);
           if ( ( -s "$RCCONFDIR/$rcfile" )  && ( -T "$RCCONFDIR/$rcfile" ) ) {
               my @rcfilecat = `cat $RCCONFDIR/$rcfile`;
               print "$INFOSTR Configuration file $RCCONFDIR/$rcfile\n";
               print @rcfilecat;
               print "\n";
               if ( grep(/\.|-/, "$rcfile") ) {
                   if ( ! grep(/^\Q$rcfile\E$/, @RCVALARR) ) {
                       push(@CHECKARR, "\n$WARNSTR Configuration file $RCCONFDIR/$rcfile is seemingly not part of standard HP-UX installation\n");
                       push(@ERRRCARR, "$WARNSTR Configuration file $RCCONFDIR/$rcfile is seemingly not part of standard HP-UX installation\n");
                       $warnings++;
                   }
               }
           }
           else {
               print
"\n$INFOSTR Configuration file $RCCONFDIR/$rcfile is zero-length or not ASCII\n";
           }
       }
   }
   else {
      print "$WARNSTR Configuration directory $RCCONFDIR is zero-length\n";
      push(@CHECKARR, "\n$WARNSTR Configuration directory $RCCONFDIR is zero-length\n");
      $warnings++;
   }

   if ( @ERRRCARR ) {
       print @ERRRCARR;
   }

   datecheck();
   print_trailer("*** END CHECKING $RCCONFDIR $datestring ***");
}

sub NONVMdisks {
    datecheck();
    print_header("*** BEGIN CHECKING DISKS NOT CONFIGURED (UNINITIALISED) THROUGH VOLUME MANAGER $datestring ***");

    if ( ! @vxdctl0 ) {
        if ( @NOTLVMARR != 0 ) {
            print "\n$INFOSTR Non-LVM (uninitialised) physical volumes found\n";
            print @NOTLVMARR;
            push(@CHECKARR,
"\n$INFOSTR Non-LVM (uninitialised) physical volumes found\n");
            push(@CHECKARR, "@NOTLVMARR");
        }
        else {
            print
"\n$INFOSTR Non-LVM (uninitialised) physical volumes seemingly do not exist\n";
        }
    }
    else {
        if ( "$LVM_FLAG" > 0 ) {
            if ( @NOTLVMARR != 0 ) {
                print
"\n$INFOSTR Non-LVM (uninitialised) physical volumes found\n";
                print @NOTLVMARR;
                push(@CHECKARR,
"\n$INFOSTR Non-LVM (uninitialised) physical volumes found\n");
                push(@CHECKARR, "@NOTLVMARR");
            }
            else {
                print
"\n$INFOSTR Non-LVM (uninitialised) physical volumes seemingly do not exist\n";
            }

            if ( @NOTVXARR ) {
                print "$INFOSTR Non-VxVM (uninitialised) physical volumes found\n";
                print @NOTVXARR;
                push(@CHECKARR,
"\n$INFOSTR Non-VxVM (uninitialised) physical volumes found\n");
                push(@CHECKARR, "@NOTVXARR\n");
            }
            else {
                print
"$INFOSTR Non-VxVM (uninitialised) physical volumes seemingly do not exist\n";
            }
        }
        else {
            if ( @NOTVXARR ) {
                print "$INFOSTR Non-VxVM (uninitialised) physical volumes found\n";
                print @NOTVXARR;
                push(@CHECKARR,
"\n$INFOSTR Non-VxVM (uninitialised) physical volumes found\n");
                push(@CHECKARR, "@NOTVXARR\n");
            }
            else {
                print
"$INFOSTR Non-VxVM (uninitialised) physical volumes seemingly do not exist\n";
            }
        }
    }

    datecheck();
    print_trailer("*** END CHECKING DISKS NOT CONFIGURED (UNINITIALISED) THROUGH VOLUME MANAGER $datestring ***");
}

# Ordinalize the numbers
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

# Courtesy of Quester http://www.perlmonks.org/?node_id=676937
#
sub is_ipv6 {
    local $_ = $_[0];
    my $mask = defined($1) ? $1 : 128;
    # in 5.10: my $mask = $1 // 128;
    return 0
      if /:::/
      or /::.*::/
      or not /::/ and 7 != tr/:/:/;
    return ( 0 <= $mask and $mask <= 128 );
}

sub printresults {
    my $TIERK = "Tier 1 Basic";

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
    if ( "$Minor$Patch" >= 1131 ) {
        $TIER1MEMMIN = 2048;
    }
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
    if ( "$Minor$Patch" >= 1131 ) {
        $TIER2MEMMIN = 3072;
    }
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
    if ( "$Minor$Patch" >= 1131 ) {
        $TIER3MEMMIN = 4096;
    }
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
    if ( "$Minor$Patch" >= 1131 ) {
        $TIER4MEMMIN = 6144;
    }
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

    my $TIERP = ( $PROCNO >= $TIER4CPUMIN ) ? "Tier 4 Mission Critical"
            : ( $PROCNO >= $TIER3CPUMIN ) ? "Tier 3 High Availability"
            : ( $PROCNO >= $TIER2CPUMIN ) ? "Tier 2 Standard"
            : ( $PROCNO >= $TIER1CPUMIN ) ? "Tier 1 Basic"
            : "Tier 1 Basic";

    my $TIERC = q{};

    if ( grep( /LVM|VxVM/, "$Diskmgr" ) ) {
        if ( $SANbootdisk > 0 ) {
            $TIERC = "Tier 4 Mission Critical";
        }
        elsif ( $LVBDISK < $TIER1OSDISKMIN ) {
            $TIERC = "Tier 1 Basic";
        }
        elsif ( $LVBDISK >= $TIER4OSDISKMIN ) {
            $TIERC = "Tier 4 Mission Critical";
        }
        elsif ( $LVBDISK >= $TIER3OSDISKMIN ) {
            $TIERC = "Tier 3 High Availability";
        }
        elsif ( $LVBDISK >= $TIER2OSDISKMIN ) {
            $TIERC = "Tier 2 Standard";
        }
        else {
            $TIERC = "Tier 1 Basic";
        }

        if ( $bings == 0 ) {
            $TIERK = "Tier 4 Mission Critical";
        }
        elsif ( $SANbootdisk > 0 ) {
            $TIERK = "Tier 4 Mission Critical";
        }
        else {
            $TIERK = "Tier 1 Basic";
        }
    }
         
print "\n\nSUMMARY:

The Operations Acceptance Testing (OAT) assessment
reported $warnings warnings.
";

my $TTIERC = my $TTIERM = my $TTIERS = q{};
my $TTIERK = my $TTIERP = my $TTIERL = q{};
my $TTIERI = my $TTIERT = q{};

my $TIERI = "Tier 1 Basic";
my $TIERT = "Tier 1 Basic";

if ( $IGNITE_FLAG > 0 ) {
    $TIERI = "Tier 4 Mission Critical";
}

my $TIERS = "Tier 1 Basic";

if (@tapes) {
    $TIERT = "Tier 4 Mission Critical";

    if ( @tpdiff ) {
        $TIERS = "Tier 4 Mission Critical";
    }
}

if ( @CHECKARR ) {
    print @CHECKARR;
    print "\n";
}

print
"Estimate (based on highest Tier level that satisfies
most critical test conditions):

LAN redundancy                                    ... $TIERL
CPU redundancy                                    ... $TIERP
Minimum RAM                                       ... $TIERM
";

if ( grep( /LVM/, "$Diskmgr" ) ) {
    print
"O/S disk redundancy                               ... $TIERC
O/S controller redundancy                         ... $TIERK
";
}

print 
"Ignite bundle available                           ... $TIERI
Tape drive(s) available                           ... $TIERT
Tape drive(s)/boot disks on separate controllers  ... $TIERS
";

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
(undef, $TTIERI, undef) = split(/\s+/, $TIERI);
push(@ACCESSTIER, $TTIERI);
(undef, $TTIERT, undef) = split(/\s+/, $TIERT);
push(@ACCESSTIER, $TTIERT);
(undef, $TTIERS, undef) = split(/\s+/, $TIERS);
push(@ACCESSTIER, $TTIERS);

foreach my $TESTTIER (@ACCESSTIER) {
    if ($TESTTIER < $OVERALLTIER) {
        $OVERALLTIER = $TESTTIER;
    }
}

print "
Overall Tier (reviewed for this server as stand-alone) is $OVERALLTIER.
";

if ( "$opts{r}" == 1 ) {
    print "Since the server is part of a cluster or H/A group,
please assess the overall Tier by checking the whole environment\n";
}

print "\nIt is strongly recommended to evaluate all warnings.\n";
}

# Read in file with variables
#
if ( "$opts{t}" ) {
    if ( -s "$CONFFILE" ) {
        slurp($CONFFILE);
    }
    else {
        print "$ERRSTR Configuration file $CONFFILE does not exist or is not readable\n";
        exit(1);
    }
}

# Now, run all the tests, but firstly check RAM usage.
# if too high, abort and give chance to admins to check it.
#
my $memusage = `swapinfo -Mm 2>/dev/null |awk '/memory/ {print \$NF}' | sed -e 's/%//g'`;
chomp($memusage);
if ( "$opts{f}" == 0 ) {
    if ( "$memusage" > $HIGHMEMUSAGE ) {
        print "\n$WARNSTR HIGH MEMORY USAGE DETECTED ON THE SERVER ($memusage%)\n";
        print "$NOTESTR It is advisable to check it before running this script again, or \n";
        print "$NOTESTR if you want to ignore this condition, use flag \"-f\" to run the script\n";
        exit(1);
    }
}
else {
    print "\n$WARNSTR HIGH MEMORY USAGE DETECTED ON THE SERVER ($memusage%)\n";
    print "$NOTESTR Server might get hung or very unresponsive when certain tests within this script get executed\n\n";
}

if ( $opts{v} ) {
    print "$INFOSTR OAT script version $SCRIPT_VERSION\n";
    exit(0);
}

my @PSVHAND = `$XPG4VAR ps -e -o time,comm | sort -n -r | head -1 | grep vhand 2>/dev/null`;
if ( @PSVHAND ) {
   print "\n$INFOSTR Extended ps(1M) shows vhand as top longest-running process\n";
   print "$NOTESTR Server might get hung or very unresponsive when certain tests within this script get executed\n\n";
}

SYS_INFO();
printmfst();
IOSCAN_NO_HW();
INTCTL_SCAN();
ALLDISK_CHECK();
bootdev();

if ( "$opts{b}" == 1 ) {
    exit(0);
}

# Is Logical Volume Manager used?
#
if ( grep( /LVM/, "$Diskmgr" ) ) {
    LVM_PARAM_CHECK();
    bootpath();
    bootcheck();
    lvmtabck();
    lvmsynccheck();
    DIAG_CHECK_BOOT_LIF();
    if ( "$Diskmgrno" == 2 ) {
        VXVM_CHECK();
    }
    else {
        datecheck();
        print_trailer("*** BEGIN CHECKING VERITAS VOLUME MANAGER $datestring ***");

        Veritasop(); 

        datecheck();
        print_trailer("*** END CHECKING VERITAS VOLUME MANAGER $datestring ***");
    }
}
else {
    VXVM_CHECK();
}

protchk();
check_hostname_length();
swcheck();
check_usergroup_length();
pscheck();
sgcheck();
crashcheck();
livedump();
checkiSCSI();
CAPADVcheck();
WLMcheck();
CIMcheck();
PRMcheck();
RCMcheck();
frucheck();
PStates();
SANchk();
asyncdrvchk();

NONVMdisks();
Ignitechk();
initboot();
diskscrub();
DynRootBootcheck();
HyperFabriccheck();
DevFilecheck();
pathcheck();
basic_daemons();
nischk();
pwdbcheck();
basfilesec();
coreadm();
lancheck();
X25check();
osicheck();
audsys();
lan();
RCcheck();
checkRCconf();
start_shutdown_log();
checkPowerBroker();
checkkernel();
multikern();
swapcheck();
space();
patch();
rootacc();
defumask();
ntp_check();
CHECK_INITTAB();
checkmountorder();
CPUcheck();
dnschk();
nfs_check();
checknull();
inetdchk();
smtpchk();
SIRchk();
OVchk();
checkISEE();
cron_access();
DMESG_IN_CRON();
checkTLDIR();
ROOT_CRON();
PERFORMANCE_BASICS();
SYSLOG_LOGGING();
MWA_STATUS();
icod();
codewrd();
par_vpar();
motd();
tmpcleanupcheck();
timezone_info();
tombstone();
sachk();
samchk();
localecheck();
cstm_info();
sim_info();
CM_info();
lp_info();
samba_info();
IPseccheck();
checkIPQoS();
checkMobileIPv4();
checkMobileIPv6();
checkSTREAMS();
BasSeccheck();
WLIcheck();
lsdevcheck();
olacheck();
rpcchk();
SNMPcheck();
liccheck();
STICKYcheck();
HEALTHcheck();
esmcheck();
ULIMITcheck();
AAAcheck();
PAMcheck();
IPCScheck();
QUOTAcheck();
checkSquid();
checkApache();
checkenvd();
ERMcheck();
LDAPservercheck();
LDAPclientcheck();
HIDScheck();
checkCISSEC();
PDCcheck();
SCRBACcheck();
checkCFENGINE();
checkpuppet();
checkchef();
checkISOMOUNT();
Xcheck();
aries_check();
SAMrmchk();
upscheck();
vendorbck();
checkOmnistorage();
GSPcheck();
checkOracle();
printresults();

exit(0);
