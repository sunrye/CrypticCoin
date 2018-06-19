AM_CPPFLAGS =  $(INCLUDES) 
AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(SAN_LDFLAGS) $(HARDENED_LDFLAGS)

if EMBEDDED_LEVELDB
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/include
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/helpers/memenv
LIBLEVELDB += $(builddir)/leveldb/libleveldb.a
LIBMEMENV  += $(builddir)/leveldb/libmemenv.a

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
$(LIBLEVELDB): $(LIBMEMENV)

$(LIBLEVELDB) $(LIBMEMENV):
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
          OPT="$(CXXFLAGS) $(CPPFLAGS)"
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS) -std=c++11
BITCOIN_INCLUDES += -I$(srcdir)/snark
BITCOIN_INCLUDES += -I$(srcdir)/snark/libsnark

LIBBITCOIN_SERVER=libbitcoin_server.a
LIBBITCOIN_WALLET=libbitcoin_wallet.a
LIBBITCOIN_COMMON=libbitcoin_common.a
LIBBITCOIN_CRYPTO=crypto/libbitcoin_crypto.a
LIBSNARK=snark/libsnark.a
LIBZCASH=libzcash.a

LIBBITCOIN_UTIL=libbitcoin_util.a
if HAVE_SSE2
LIBBITCOIN_SSE2=libbitcoin_sse2.a
endif

LIBBITCOINQT=qt/libbitcoinqt.a

LIBSNARK_CXXFLAGS = -fPIC -DBINARY_OUTPUT -DNO_PT_COMPRESSION=1 -fstack-protector-all
LIBSNARK_CONFIG_FLAGS = CURVE=ALT_BN128 NO_PROCPS=1 NO_DOCS=1 STATIC=1 NO_SUPERCOP=1 FEATUREFLAGS=-DMONTGOMERY_OUTPUT NO_COPY_DEPINST=1 NO_COMPILE_LIBGTEST=1
if HAVE_OPENMP
LIBSNARK_CONFIG_FLAGS += MULTICORE=1
endif
if TARGET_DARWIN
LIBSNARK_CONFIG_FLAGS += PLATFORM=darwin
endif

$(LIBSNARK): $(wildcard snark/src/*)
	$(AM_V_at) CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O2 -march=x86-64"

noinst_LIBRARIES = \
  crypto/libbitcoin_crypto.a \
  libbitcoin_util.a \
  libbitcoin_common.a \
  libbitcoin_server.a \
  libzcash.a

if ENABLE_WALLET
BITCOIN_INCLUDES += $(BDB_CPPFLAGS)
noinst_LIBRARIES += libbitcoin_wallet.a
endif

if HAVE_SSE2
noinst_LIBRARIES += libbitcoin_sse2.a
endif

bin_PROGRAMS =
TESTS =

if BUILD_BITCOIND
  bin_PROGRAMS += CrypticCoind
endif

LIBZCASH_H = \
  zcash/IncrementalMerkleTree.hpp \
  zcash/NoteEncryption.hpp \
  zcash/Address.hpp \
  zcash/JoinSplit.hpp \
  zcash/Note.hpp \
  zcash/prf.h \
  zcash/Proof.hpp \
  zcash/util.h \
  zcash/Zcash.h

#.PHONY: FORCE
.PHONY: FORCE collate-libsnark
# bitcoin core #
BITCOIN_CORE_H = \
  addrman.h \
  alert.h \
  allocators.h \
	asyncrpcoperation.h \
  asyncrpcoperation_mergetoaddress.h \
  asyncrpcoperation_sendmany.h \
  asyncrpcoperation_shieldcoinbase.h \	
  base58.h \
  bloom.h \
  bignum.h \
  bitcoinrpc.h \
  checkpoints.h \
  clientversion.h \
  coincontrol.h \
  compat.h \
  consensus/consensus.h \
  consensus/upgrades.h \
  crypter.h \
  lz4/lz4.h \
  sph_groestl.h \
  sph_types.h \
  sph_blake.h \
  sph_bmw.h \
  sph_jh.h \
  sph_keccak.h \
  sph_skein.h \
  sph_luffa.h \
  sph_cubehash.h \
  sph_simd.h \
  sph_echo.h \
  sph_shavite.h \
  sph_sha2.h \
  sph_haval.h \
  hashgroestl.h \
  hashskein.h \
  hashqubit.h \
  hashquark.h \
  hashblake.h \
  hashx17.h \
  hashx13.h \
  hashx15.h \
  Lyra2RE.h \
  Lyra2.h \
  Sponge.h \
  blake2.h \
  blake2-impl.h \
  db.h \
  hash.h \
  txdb-leveldb.h \
  init.h \
  kernel.h \
  key.h \
  keystore.h \
  main.h \
  mruset.h \
  netbase.h \
  net.h \
  interpreter.h \
  primitives/transaction.h \
  protocol.h \
  script.h \
  scrypt.h \
  serialize.h \
  stealth.h \
  smessage.h \
  strlcpy.h \
  sync.h \
  ui_interface.h \
  uint256.h \
  uint252.h \
  util.h \
  version.h \
  xxhash/xxhash.h \
  walletdb.h \
  wallet.h

JSON_H = \
  json/json_spirit.h \
  json/json_spirit_error_position.h \
  json/json_spirit_reader.h \
  json/json_spirit_reader_template.h \
  json/json_spirit_stream_reader.h \
  json/json_spirit_utils.h \
  json/json_spirit_value.h \
  json/json_spirit_writer.h \
  json/json_spirit_writer_template.h

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libbitcoin_util_a-version.$(OBJEXT): obj/build.h

# server: shared between CrypticCoind and CrypticCoin-qt
libbitcoin_server_a_CPPFLAGS = -O0 -g $(BITCOIN_INCLUDES)
libbitcoin_server_a_SOURCES = \
  addrman.cpp \
  alert.cpp \
  bloom.cpp \
  checkpoints.cpp \
  init.cpp \
  db.cpp \
  txdb-leveldb.cpp \
  bitcoinrpc.cpp \
  keystore.cpp \
  main.cpp \
  noui.cpp \
  net.cpp \
  rpcblockchain.cpp \
  rpcmining.cpp \
  rpcnet.cpp \
  rpcrawtransaction.cpp \
  rpcsmessage.cpp \
  primitives/transaction.cpp \
  $(JSON_H) \
  $(BITCOIN_CORE_H)

# wallet: shared between CrypticCoind and CrypticCoin-qt, but only linked
# when wallet enabled
libbitcoin_wallet_a_CPPFLAGS = -O0 -g $(BITCOIN_INCLUDES)
libbitcoin_wallet_a_SOURCES = \
	base58.cpp \
  crypter.cpp \
  rpcdump.cpp \
  rpcwallet.cpp \
  rpcsmessage.cpp \
  asyncrpcoperation_mergetoaddress.cpp \
	asyncrpcoperation_sendmany.cpp \
  paymentdisclosure.cpp \
  paymentdisclosuredb.cpp \
  rpcdisclosure.cpp \	
  wallet.cpp \
  walletdb.cpp \
  stealth.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

  # crypto primitives library
crypto_libbitcoin_crypto_a_CPPFLAGS = -O0 -g $(BITCOIN_CONFIG_INCLUDES)
#crypto_libbitcoin_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_a_SOURCES = \
  crypto/common.h \
  crypto/sha256.cpp \
  crypto/sha256.h

# common: shared between CrypticCoind, and CrypticCoin-qt and non-server tools
libbitcoin_common_a_CPPFLAGS = -O0 -g $(BITCOIN_INCLUDES)
#libbitcoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_common_a_SOURCES = \
  base58.cpp \
  key.cpp \
  netbase.cpp \
  protocol.cpp \
  interpreter.cpp \
  script.cpp \
  hash.cpp \
  kernel.cpp \
  scrypt.cpp \
  smessage.cpp \
  stealth.cpp \
  groestl.c \
  blake.c \
  blake2s-ref.c \
  bmw.c \
  cubehash.c \
  consensus/upgrades.cpp \
  echo.c \
  jh.c \
  keccak.c \
  luffa.c \
  lz4/lz4.c \
  shavite.c \
  simd.c \
  skein.c \
  hamsi.c \
  whirlpool.c \
  shabal.c \
  fugue.c \
  sync.cpp \
  sha2.c \
  haval.c \
  Lyra2.c \
  Lyra2RE.c \
  Sponge.c \
  sph_sha2big.c \
  xxhash/xxhash.c \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libbitcoin_util_a_CPPFLAGS = -O0 -g $(BITCOIN_INCLUDES)
libbitcoin_util_a_SOURCES = \
  util.cpp \
  version.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

if GLIBC_BACK_COMPAT
libbitcoin_util_a_SOURCES += compat/glibc_compat.cpp
libbitcoin_util_a_SOURCES += compat/glibcxx_compat.cpp
endif

nodist_libbitcoin_util_a_SOURCES = $(srcdir)/obj/build.h
# CrypticCoind binary #
CrypticCoind_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBZCASH) \
  $(LIBSNARK) \
  $(LIBLEVELDB) \
  $(LIBMEMENV)

if HAVE_SSE2
libbitcoin_sse2_a_SOURCES = scrypt-sse2.cpp
libbitcoin_sse2_a_CPPFLAGS = $(BITCOIN_INCLUDES) -msse2 -mstackrealign
CrypticCoind_LDADD += libbitcoin_sse2.a
endif

if ENABLE_WALLET
CrypticCoind_LDADD += libbitcoin_wallet.a
endif
CrypticCoind_SOURCES = daemon.cpp

CrypticCoind_LDADD += \
  ../tor/src/or/libtor.a \
  ../tor/src/common/libor.a \
  ../tor/src/common/libor-ctime.a \
  ../tor/src/common/libor-crypto.a \
  ../tor/src/common/libor-event.a \
  ../tor/src/trunnel/libor-trunnel.a \
  ../tor/src/common/libcurve25519_donna.a \
  ../tor/src/ext/ed25519/donna/libed25519_donna.a \
  ../tor/src/ext/ed25519/ref10/libed25519_ref10.a \
  ../tor/src/ext/keccak-tiny/libkeccak-tiny.a \
  $(LIBEVENT_LIBS) \
  $(LIBSECCOMP_LIBS) \
  $(LIBCAP_LIBS) \
  $(ZLIB_LIBS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBZCASH_LIBS)

CrypticCoind_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(LIBEVENT_LDFLAGS) $(LIBSECCOMP_LDFLAGS) $(LIBCAP_LDFLAGS) $(ZLIB_LDFLAGS)
CrypticCoind_CPPFLAGS = -O0 -g $(BITCOIN_INCLUDES) $(LIBEVENT_CFLAGS) $(LIBSECCOMP_CFLAGS) $(LIBCAP_CFLAGS) $(ZLIB_CFLAGS)
CrypticCoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

# zcash protocol primitives #
libzcash_a_SOURCES = \
  zcash/IncrementalMerkleTree.cpp \
  zcash/NoteEncryption.cpp \
  zcash/Address.cpp \
  zcash/JoinSplit.cpp \
  zcash/Proof.cpp \
  zcash/Note.cpp \
  zcash/prf.cpp \
  zcash/util.cpp \
  zcash/circuit/commitment.tcc \
  zcash/circuit/gadget.tcc \
  zcash/circuit/merkle.tcc \
  zcash/circuit/note.tcc \
  zcash/circuit/prfs.tcc \
  zcash/circuit/utils.tcc

libzcash_a_CPPFLAGS = -fPIC -DBINARY_OUTPUT -DCURVE_ALT_BN128 -DBOOST_SPIRIT_THREADSAFE -DHAVE_BUILD_INFO -D__STDC_FORMAT_MACROS $(HARDENED_CPPFLAGS) $(HARDENED_CXXFLAGS) $(HARDENED_LDFLAGS) -pipe $(SAN_LDFLAGS) -O0 -g -Wstack-protector $(SAN_CXXFLAGS) -fstack-protector-all -fPIE -fvisibility=hidden -DSTATIC $(BITCOIN_INCLUDES)

libzcash_a_CXXFLAGS = $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) -fwrapv -fno-strict-aliasing

libzcash_a_LDFLAGS = $(SAN_LDFLAGS) $(HARDENED_LDFLAGS)

libzcash_a_CPPFLAGS += -DMONTGOMERY_OUTPUT

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb snark

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C snark clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(CXXFLAGS)  -c -o $@ $<

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_QT
include Makefile.qt.include
endif
