# @(#) $Id: Makefile,v 1.0 2014/07/17 14:11:55 dusan Exp $ 

BASEDIR = /usr/local/bin
SOLOWNER = root:bin
HPUXOWNER = root:bin
LNXOWNER = root.root
PERMSD = 755 
PERMSF = 644

all: 
	i=`uname -s`; case $$i in HP-UX) make hp-ux;; Linux) make linux;; SunOS) make sunos;; *) make help;; esac

help:
	@echo "+----------------------------------------------+"
	@echo "|    Operations Acceptance Testing Makefile    |"
	@echo "|    ======================================    |"
	@echo "|    HP-UX: \"make hp-ux\"                       |"
	@echo "|    Linux: \"make linux\"                       |"
	@echo "|    SunOS: \"make sunos\"                       |"
	@echo "|    Help:  \"make help\"                        |"
	@echo "+----------------------------------------------+"

linux: Linux-check-OAT.pl
	@if [ ! -d ${BASEDIR} ]; then mkdir -p ${BASEDIR}; chmod ${PERMSD} ${BASEDIR}; \
        chown ${LNXOWNER} ${BASEDIR}; fi 
	@if [ -f Linux-check-OAT.pl ]; then cp -p Linux-check-OAT.pl ${BASEDIR}; \
	chmod ${PERMSF} ${BASEDIR}/Linux-check-OAT.pl; chown ${LNXOWNER} ${BASEDIR}/Linux-check-OAT.pl; fi
	echo "Installation done."

sunos: Solaris-check-OAT.pl
	@if [ ! -d ${BASEDIR} ]; then mkdir -p ${BASEDIR}; chmod ${PERMSD} ${BASEDIR}; \
        chown ${SOLOWNER} ${BASEDIR}; fi 
	@if [ -f Solaris-check-OAT.pl ]; then cp -p Solaris-check-OAT.pl ${BASEDIR}; \
	chmod ${PERMSF} ${BASEDIR}/Solaris-check-OAT.pl; chown ${SOLOWNER} ${BASEDIR}/Solaris-check-OAT.pl; fi
	echo "Installation done."

hp-ux: HP-UX-check-OAT.pl
	@if [ ! -d ${BASEDIR} ]; then mkdir -p ${BASEDIR}; chmod ${PERMSD} ${BASEDIR}; \
        chown ${HPUXOWNER} ${BASEDIR}; fi 
	@if [ -f HP-UX-check-OAT.pl ]; then cp -p HP-UX-check-OAT.pl ${BASEDIR}; \
	chmod ${PERMSF} ${BASEDIR}/Solaris-check-OAT.pl; chown ${HPUXOWNER} ${BASEDIR}/Solaris-check-OAT.pl; fi
	echo "Installation done."
