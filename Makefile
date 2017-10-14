include $(TOP_DIR)/rules.mk
include $(INCLUDE_DIR)/default.mk

SRC_DIR=src
ETC_DIR=etc
MAKE_PATH=src
CONFIGURE_PATH=src
BUILD_PATH=$(BUILD_DIR)/digger

#overide values
#CONFIGURE_VARS=
#CONFIGURE=configure
#DEF_CONFIGURE_VARS=--prefix=$(PKG_INSTALL_DIR)
#MAKE_INSTALL_FLAGS=
#MAKEFILE_NAME=Makefile
CC:=gcc
#CXX:=g++
#MAKE=make
EXT_CFLAGS += -I$(BUILD_DIR)/libmaxminddb-1.0/pkg-install/include -I$(PUBLIB_DIR)/include
EXT_LDFLAGS += -L$(BUILD_DIR)/libmaxminddb-1.0/pkg-install/lib -L$(PUBLIB_DIR)/lib


#define values
define Package/digger
  DEPENDS:=
  #libs/heartbeat third_party/libmaxminddb-1.0
endef

define Package/digger/Prepare
	@echo "pakcage prepare:"
	-mkdir -p $(BUILD_PATH)
	@if [ ! -d $(BUILD_PATH)/$(MAKE_PATH) ]; then \
		cp -r $(SRC_DIR) $(BUILD_PATH); \
		cp -r $(ETC_DIR) $(BUILD_PATH); \
	fi
endef

define Package/example/PreConfigure
	@echo "package PreConfigure"
endef

define Package/example/Install
	@echo "package install"
endef


$(eval $(call BuildPackage,digger))
