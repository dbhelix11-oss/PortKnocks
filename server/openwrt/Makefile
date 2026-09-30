# OpenWrt package definition for knockd. Copy (or symlink) this directory
# into the SDK's package/ tree, e.g. package/knockd/, with the server sources
# alongside in ./src (see README.md in this directory), then:
#   make package/knockd/compile V=s
include $(TOPDIR)/rules.mk

PKG_NAME:=knockd
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=custom
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/knockd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=PortKnocks server (HMAC/TOTP-style port knocking daemon)
  URL:=https://github.com/dbhelix11-oss/PortKnocks
  DEPENDS:=+libpcap +libopenssl +libstdcpp +nftables-json
endef

define Package/knockd/description
  Passive libpcap sniffer that verifies keyed port-knock sequences and opens
  nftables timed allow-sets. Runs next to fw4 without modifying it.
endef

define Package/knockd/conffiles
/etc/knockd/knockd.conf
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CXX="$(TARGET_CXX)" \
		CXXFLAGS="$(TARGET_CXXFLAGS) -std=c++17 -Wall" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		knockd
endef

define Package/knockd/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/knockd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/knockd $(1)/usr/sbin/knockd
	$(INSTALL_BIN) ./knockd.init $(1)/etc/init.d/knockd
	$(INSTALL_CONF) ./knockd.conf.example $(1)/etc/knockd/knockd.conf
endef

$(eval $(call BuildPackage,knockd))
