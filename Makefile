CC = gcc
CFLAGS = -std=c99  -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -pedantic
DIR_BIN=./bin
DIR_CFG=/etc/pam-onelogin
DIR_DEST=/usr/lib64
DIR_DEST_BIN=/usr/bin
DIR_DEST_PAM=/usr/lib64/security
DIR_SRC=./src
HEADERS = src/headers/config.h src/headers/onelogin.h src/headers/onelogin-mkcache.h src/headers/logging.h  src/headers/curler.h
LIBS = -lcurl -lpam -lpam_misc

COMMON_SRC = ${DIR_SRC}/config.c ${DIR_SRC}/logging.c ${DIR_SRC}/curler.c ${DIR_SRC}/onelogin.c
LIBNSS_ONELOGIN_NAME = libnss_onelogin.so.2
LIBNSS_ONELOGIN_NAME_SO = libnss_onelogin.so
PAM_ONELOGIN_SRC = ${DIR_SRC}/libs/pam_onelogin.c
PAM_ONELOGIN_NAME = pam_onelogin.so.2
PAM_ONELOGIN_NAME_SO = pam_onelogin.so
PAM_ONELOGIN_CFG = pam_onelogin.yaml
LIBNSS_ONELOGIN_SRC = ${DIR_SRC}/libs/libnss_onelogin.c
STANDALONE_NAME = onelogin
STANDALONE_SRC = ${DIR_SRC}/standalone.c

CACHER_NAME = onelogin-mkcache
CACHER_SRC = ${DIR_SRC}/onelogin-mkcache.c


# Build standalone binary
onelogin-mkdcache: ${DIR_BIN}/${CACHER_NAME}
${DIR_BIN}/${CACHER_NAME}: ${HEADERS} ${COMMON_SRC} ${CACHER_SRC}
	$(CC) $(CFLAGS) ${COMMON_SRC} ${CACHER_SRC} $(LIBS) -o $@

# Build nss library
libnss_onelogin: ${DIR_BIN}/${LIBNSS_ONELOGIN_NAME}
${DIR_BIN}/${LIBNSS_ONELOGIN_NAME}: ${HEADERS} ${COMMON_SRC} ${LIBNSS_ONELOGIN_SRC}
	$(CC) $(CFLAGS) ${COMMON_SRC} ${LIBNSS_ONELOGIN_SRC} $(LIBS) -fPIC -shared \
	-Wl,-soname,${LIBNSS_ONELOGIN_NAME} -o $@

# Build nss library
pam_onelogin: ${DIR_BIN}/${PAM_ONELOGIN_NAME}
${DIR_BIN}/${PAM_ONELOGIN_NAME}: ${HEADERS} ${COMMON_SRC} ${PAM_ONELOGIN_SRC}
	$(CC) $(CFLAGS) ${COMMON_SRC} ${PAM_ONELOGIN_SRC} $(LIBS) -fPIC -shared \
	-Wl,-soname,${PAM_ONELOGIN_NAME} -o $@

# Build everything
all: libnss_onelogin pam_onelogin onelogin-mkdcache

# Install library
install: ${DIR_DEST}/${LIBNSS_ONELOGIN_NAME}
${DIR_DEST}/${LIBNSS_ONELOGIN_NAME}: ${DIR_BIN}/${LIBNSS_ONELOGIN_NAME}	 		\
																		 ${DIR_DEST}/${LIBNSS_ONELOGIN_NAME_SO} \
																		 all
	install -d ${DIR_DEST}
	install -d ${DIR_CFG}
	install -m 0655 -b -S .bkp ${PAM_ONELOGIN_CFG} ${DIR_CFG}
	install -m 0755 ${DIR_BIN}/${CACHER_NAME} ${DIR_DEST_BIN}
	install -m 0755 ${DIR_BIN}/${LIBNSS_ONELOGIN_NAME} ${DIR_DEST}
	install -m 0755 ${DIR_BIN}/${PAM_ONELOGIN_NAME} ${DIR_DEST_PAM}/${PAM_ONELOGIN_NAME_SO}

# Link libraries (.so.2 -> .so)
${DIR_DEST}/${LIBNSS_ONELOGIN_NAME_SO}: ${DIR_BIN}/${LIBNSS_ONELOGIN_NAME}
	ln -sf ${DIR_DEST}/${LIBNSS_ONELOGIN_NAME} ${DIR_DEST}/${LIBNSS_ONELOGIN_NAME_SO}

# Remove libraries
uninstall:
	rm -fv ${DIR_DEST}/${LIBNSS_ONELOGIN_NAME} ${DIR_DEST}/${LIBNSS_ONELOGIN_NAME_SO} ${DIR_DEST_BIN}/${CACHER_NAME}

# Clean builds
clean:
	rm -fv ${DIR_BIN}/*
