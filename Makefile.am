ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

sysconfdir = @sysconfdir@/$(PACKAGE)
sysconf_DATA = \
	data/camctl.html

###################################################################
## Create pristine directories to match exactly distributed files
###################################################################
cleanall: distclean
	@rm -rf autom4te.cache m4
	@rm -f config.h.in config.h.in~ aclocal.m4 config.sub ABOUT-NLS missing
	@rm -f compile config.guess config.rpath configure depcomp install-sh
	@rm -f Makefile.in src/Makefile.in 

