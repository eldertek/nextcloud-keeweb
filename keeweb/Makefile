# This file is licensed under the Affero General Public License version 3 or
# later. See the COPYING file.

app_name=$(notdir $(CURDIR))
build_tools_directory=$(CURDIR)/build/tools
source_build_directory=$(CURDIR)/build/artifacts/source
source_package_name=$(source_build_directory)/$(app_name)
appstore_build_directory=$(CURDIR)/build/artifacts/appstore
appstore_package_name=$(appstore_build_directory)/$(app_name)
npm=$(shell which npm 2> /dev/null)
composer=$(shell which composer 2> /dev/null)

all: build

.PHONY: build
build:
ifneq (,$(wildcard $(CURDIR)/composer.json))
	make composer
endif
ifneq (,$(wildcard $(CURDIR)/package.json))
	make npm
endif

.PHONY: composer
composer:
ifeq (, $(composer))
	mkdir -p $(build_tools_directory)
	curl -sS https://getcomposer.org/installer | php
	mv composer.phar $(build_tools_directory)
	php $(build_tools_directory)/composer.phar install --prefer-dist --no-dev
else
	composer install --prefer-dist --no-dev
endif

.PHONY: npm
npm:
	$(npm) ci && $(npm) run build

.PHONY: clean
clean:
	rm -rf ./build

.PHONY: distclean
distclean: clean
	rm -rf vendor
	rm -rf node_modules

.PHONY: dist
dist:
	make build
	make source
	make appstore

.PHONY: source
source:
	rm -rf $(source_build_directory)
	mkdir -p $(source_build_directory)
	tar --exclude-vcs \
	--exclude="../$(app_name)/build" \
	--exclude="../$(app_name)/node_modules" \
	--exclude="../$(app_name)/js/*.LICENSE.txt" \
	--exclude="../$(app_name)/js/*.map" \
	--exclude="../$(app_name)/*.log" \
	-cvzf $(source_package_name).tar.gz ../$(app_name)

.PHONY: appstore
appstore:
	rm -rf $(appstore_build_directory)
	mkdir -p $(appstore_build_directory)
	tar --exclude=".git" \
	--exclude="../$(app_name)/build" \
	--exclude="../$(app_name)/tests" \
	--exclude="../$(app_name)/src" \
	--exclude="../$(app_name)/Makefile" \
	--exclude="../$(app_name)/*.log" \
	--exclude="../$(app_name)/phpunit*xml" \
	--exclude="../$(app_name)/composer.*" \
	--exclude="../$(app_name)/node_modules" \
	--exclude="../$(app_name)/js/*.LICENSE.txt" \
	--exclude="../$(app_name)/js/*.map" \
	--exclude="../$(app_name)/package-lock.json" \
	--exclude="../$(app_name)/package.json" \
	--exclude="../$(app_name)/webpack.*" \
	--exclude="../$(app_name)/.*" \
	-cvzf $(appstore_package_name).tar.gz ../$(app_name)

.PHONY: test
test:
	$(npm) run test
